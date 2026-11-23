"""RFC 0002 变异覆盖引擎:在真实基线流上系统注入偏离,度量两层检测的构造性覆盖。

离线运行(不需要集群):输入 data/norm-<s>-baseline.jsonl + models/scenario-<s>,
输出覆盖矩阵。D1-D3/M8 确定性维度门槛覆盖率=1.0;D4-D5 统计维度门槛异常抬升≥1.2×;
M7/BLIND 如实报告。检测不足 = 缺口产出,不凑门槛。

用法:python scripts/mutation_coverage.py --scenarios coding data ops release \
        --out data/mutation-coverage.json [--n 30] [--seed 42]
"""

import argparse
import copy
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lstm.features import parse_ts  # noqa: E4202
from lstm.infer import StreamInferencer  # noqa: E4202

UNKNOWN_BINARIES = ["xmrig", "kdevtmpfsi", "evil", ".hidden", "kinsing"]
SENSITIVE_PATHS = ["/etc/shadow", "/root/.ssh/id_rsa", "/var/run/secrets/token", "/etc/sudoers"]
CRITICAL_PATH = "/workspace/release/transfer-service.yaml"
EXTERNAL_DEST = "203.0.113.9:4444"

PATHS = {
    "coding": ("data/norm-coding-baseline.jsonl", "models/scenario-coding"),
    "data": ("data/norm-data-baseline.jsonl", "models/scenario-data"),
    "ops": ("data/norm-ops-baseline.jsonl", "models/scenario-ops"),
    "release": ("data/norm-release-baseline.jsonl", "models/release"),
    "supply": ("data/norm-supply-baseline.jsonl", "models/scenario-supply"),
    "persist": ("data/norm-persist-baseline.jsonl", "models/scenario-persist"),
    "lateral": ("data/norm-lateral-baseline.jsonl", "models/scenario-lateral"),
}


def iso(ts: float) -> str:
    return (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def score(registry: str, events: list[dict]):
    inf = StreamInferencer(registry)
    for ev in events:
        inf.feed(ev)
    return inf


def flag_coverage(inf, truth_ids: set) -> float:
    recs = [r for r in inf.records if r["event_id"] in truth_ids]
    if not recs:
        return 0.0
    return sum(bool(r["risk_context"]) for r in recs) / len(recs)


def mutate_flags(events, rng, n, dim):
    evs = copy.deepcopy(events)
    truth = set()
    if dim == "M1":
        pool = [e for e in evs if e["process"].get("binary")]
        for e in rng.sample(pool, min(n, len(pool))):
            e["process"]["binary"] = rng.choice(UNKNOWN_BINARIES)
            truth.add(e["event_id"])
    elif dim in ("M2", "M3"):
        pool = [e for e in evs if e["event"]["type"] == "file_open"]
        for e in rng.sample(pool, min(n, len(pool))):
            e["event"]["resource"] = rng.choice(SENSITIVE_PATHS) if dim == "M2" else CRITICAL_PATH
            truth.add(e["event_id"])
    elif dim == "M4":
        pool = [e for e in evs if e["event"]["type"] == "network_connect"]
        for e in rng.sample(pool, min(n, len(pool))):
            e["event"]["resource"] = EXTERNAL_DEST
            truth.add(e["event_id"])
    elif dim == "M8":
        # 生存期内权限变化:exec_id 已存在的事件后插入 capability_change
        seen = set()
        pool = []
        for e in evs:
            if e["process"]["exec_id"] in seen:
                pool.append(e)
            seen.add(e["process"]["exec_id"])
        out = []
        for i, e in enumerate(evs):
            out.append(e)
        for i, e in enumerate(rng.sample(pool, min(n, len(pool)))):
            idx = evs.index(e)
            m = copy.deepcopy(e)
            m["event_id"] = f"mut-cap-{i}"
            m["event"] = {"category": "security", "type": "capability_change",
                          "operation": "credential_change", "resource_type": "credential",
                          "resource": ""}
            m["event_time"] = iso(parse_ts(e["event_time"]) + 0.001)
            out.insert(idx + 1 + i, m)
            truth.add(m["event_id"])
        evs = out
    return evs, truth


def affected_execs(events, rng, fraction=0.3):
    by_exec = {}
    for e in events:
        by_exec.setdefault(e["process"]["exec_id"], []).append(e)
    execs = [k for k, v in by_exec.items() if len(v) >= 4]
    return set(rng.sample(execs, max(1, int(len(execs) * fraction))))


def mutate_sequence(events, rng):
    targets = affected_execs(events, rng)
    kept = []
    counters = {}
    for e in events:
        eid = e["process"]["exec_id"]
        if eid in targets:
            counters[eid] = counters.get(eid, 0) + 1
            if counters[eid] % 3 == 0:  # 删除约 1/3
                continue
        kept.append(e)
    return kept, targets


def mutate_burst(events, rng):
    targets = affected_execs(events, rng)
    evs = copy.deepcopy(events)
    t0 = {}
    for e in evs:
        eid = e["process"]["exec_id"]
        if eid in targets:
            ts = parse_ts(e["event_time"])
            t0.setdefault(eid, ts)
            e["event_time"] = iso(t0[eid] + (ts - t0[eid]) * 0.01)
    return evs, targets


def mutate_reparent(events, rng, n):
    evs = copy.deepcopy(events)
    firsts = {}
    for e in evs:
        firsts.setdefault(e["process"]["exec_id"], e)
    births = [e for e in evs if e is firsts[e["process"]["exec_id"]]
              and e["process"].get("parent_exec_id")]
    live = list(firsts.keys())
    truth = set()
    for e in rng.sample(births, min(n, len(births))):
        e["process"]["parent_exec_id"] = rng.choice(live)
        truth.add(e["event_id"])
    return evs, truth


def run_scenario(name, n, seed):
    path, registry = PATHS[name]
    events = [json.loads(l) for l in open(path)]
    rng = random.Random(seed)

    base_inf = score(registry, events)
    base = base_inf.report()
    base_mean = base["mean_cross_entropy"]
    base_p90 = base["anomaly_score_p90"]
    base_by_exec = {}
    for r in base_inf.records:
        base_by_exec.setdefault(r["exec_id"], []).append(r["anomaly_score"])

    dims = {}
    for dim in ("M1", "M2", "M3", "M4", "M8"):
        evs, truth = mutate_flags(events, rng, n, dim)
        inf = score(registry, evs)
        dims[dim] = {"coverage": flag_coverage(inf, truth), "n": len(truth)}

    for dim, fn in (("M5", mutate_sequence), ("M6", mutate_burst)):
        evs, targets = fn(events, rng)
        inf = score(registry, evs)
        mut_scores = [r["anomaly_score"] for r in inf.records if r["exec_id"] in targets]
        base_scores = [s for k in targets for s in base_by_exec.get(k, [])]
        mean = lambda xs: sum(xs) / len(xs) if xs else 0.0
        elev = mean(mut_scores) / mean(base_scores) if mean(base_scores) > 0 else 0.0
        dims[dim] = {"elevation": round(elev, 3), "n": len(targets)}

    evs, truth = mutate_reparent(events, rng, n)
    inf = score(registry, evs)
    recs = [r for r in inf.records if r["event_id"] in truth]
    dims["M7"] = {
        "above_p90_ratio": sum(r["anomaly_score"] > base_p90 for r in recs) / len(recs) if recs else 0.0,
        "n": len(recs),
    }

    # BLIND:随机混合确定性维度变异,生成器自带 truth
    evs = copy.deepcopy(events)
    truth = set()
    pool = [e for e in evs if e["event"]["type"] in ("file_open", "network_connect")]
    for i, e in enumerate(rng.sample(pool, min(100, len(pool)))):
        kind = rng.choice(["M1", "M2", "M3", "M4"])
        if kind == "M1":
            e["process"]["binary"] = rng.choice(UNKNOWN_BINARIES)
        elif kind in ("M2", "M3"):
            if e["event"]["type"] != "file_open":
                continue
            e["event"]["resource"] = rng.choice(SENSITIVE_PATHS) if kind == "M2" else CRITICAL_PATH
        else:
            if e["event"]["type"] != "network_connect":
                continue
            e["event"]["resource"] = EXTERNAL_DEST
        truth.add(e["event_id"])
    inf = score(registry, evs)
    recs = [r for r in inf.records if r["event_id"] in truth]
    blind_rate = sum(bool(r["risk_context"]) or r["anomaly_score"] > base_p90 for r in recs) / len(recs) if recs else 0.0

    gates = {
        "deterministic_coverage_eq_1": all(dims[d]["coverage"] == 1.0 for d in ("M1", "M2", "M3", "M4", "M8")),
        "sequence_elevation_ge_1.2": dims["M5"]["elevation"] >= 1.2,
        "burst_elevation_ge_1.2": dims["M6"]["elevation"] >= 1.2,
    }
    return {
        "baseline_mean_anomaly": round(base_mean, 3),
        "baseline_p90": round(base_p90, 3),
        "dimensions": dims,
        "blind_detection_rate": round(blind_rate, 3),
        "gates": gates,
        "passed": all(gates.values()),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="+", default=["coding", "data", "ops", "release"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    result = {}
    for s in args.scenarios:
        if not Path(PATHS[s][0]).exists():
            print(f"skip {s}: no baseline ({PATHS[s][0]})")
            continue
        result[s] = run_scenario(s, args.n, args.seed)
        d = result[s]["dimensions"]
        print(f"{s}: M1-M4,M8 cov=" + ",".join(f"{d[k]['coverage']:.2f}" for k in ("M1", "M2", "M3", "M4", "M8"))
              + f" | M5 elev={d['M5']['elevation']} M6 elev={d['M6']['elevation']}"
              + f" M7>p90={d['M7']['above_p90_ratio']:.2f} | blind={result[s]['blind_detection_rate']}"
              + f" | passed={result[s]['passed']}")
    Path(args.out).write_text(json.dumps(result, indent=2))
    print("ALL PASSED" if all(v["passed"] for v in result.values()) else "GAPS FOUND (see report)")


if __name__ == "__main__":
    main()