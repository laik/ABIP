"""RFC 0001 场景评分:baseline 训练 Champion → attack 流推理 → 对照 ground truth 签名。

用法:python scripts/verify_scenarios.py --baseline norm-baseline.jsonl \
        --attack norm-attack.jsonl --registry models/scenario-X --out report.json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lstm.infer import StreamInferencer  # noqa: E4202
from lstm.train import run as train_run  # noqa: E4202

# RFC 0002 场景规格:签名按场景声明,验证器统一消费
SIGNATURES = {
    "default": {"paths": ["/etc/shadow", "/root/.ssh", "/var/run/secrets", "/etc/sudoers"],
                "binaries": ["nc"], "dests": ["203.0.113.9"]},
    "supply": {"paths": [], "binaries": ["evil"], "dests": ["203.0.113.9"]},
    "persist": {"paths": ["/etc/cron", "/root/.ssh"], "binaries": [".hidden"], "dests": []},
    "lateral": {"paths": ["/proc/net"], "binaries": ["nc"], "dests": []},
    "beacon": {"paths": [], "binaries": [], "dests": ["203.0.113.9"]},
    "mining": {"paths": [], "binaries": ["xmrig", "nc"], "dests": ["203.0.113.9"]},
    "inject": {"paths": [], "binaries": [], "dests": ["203.0.113.9"]},
    "escape": {"paths": ["/proc/sysrq", "release_agent"], "binaries": ["nsenter"], "dests": []},
}


def is_signature(ev: dict, sig: dict) -> bool:
    res = ev["event"].get("resource", "")
    binary = ev["process"].get("binary", "")
    return (
        any(s in res for s in sig["paths"])
        or any(res.startswith(d) for d in sig["dests"])
        or binary in sig["binaries"]
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--attack", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--scenario", default="default")
    args = ap.parse_args()
    sig = SIGNATURES.get(args.scenario, SIGNATURES["default"])

    train_run(args.baseline, args.registry)

    inf = StreamInferencer(args.registry)
    with open(args.baseline) as f:
        for line in f:
            inf.feed(json.loads(line))
    base = inf.report()
    n_base = len(inf.records)

    attack_evs = {}
    with open(args.attack) as f:
        for line in f:
            ev = json.loads(line)
            attack_evs[ev["event_id"]] = ev
            inf.feed(ev)
    attack_recs = inf.records[n_base:]

    sig_recs = [r for r in attack_recs if is_signature(attack_evs[r["event_id"]], sig)]
    chain_execs = [
        r for r in sig_recs
        if attack_evs[r["event_id"]]["process"].get("binary") in sig["binaries"]
        and attack_evs[r["event_id"]]["event"]["type"] == "process_exec"
    ]
    # 两层检测覆盖(RFC 0001):每个攻击签名事件至少被一层命中——
    # 确定性 Risk Context(sensitive/external/unknown_binary)或 LSTM 惊讶度 > 基线 p90。
    # 类别头区分不了 nc 与 ls 的 exec(都是 process_exec),nc 链靠 unknown_binary + external。
    detected = [
        r for r in sig_recs
        if r["risk_context"] or r["anomaly_score"] > base["anomaly_score_p90"]
    ]
    mean = lambda xs: sum(xs) / len(xs) if xs else 0.0

    # 误报对照:基线里读 /etc/passwd 等 config 不应被标 sensitive
    fp = 0
    with open(args.baseline) as f:
        base_evs = {json.loads(l)["event_id"]: json.loads(l) for l in f}
    for r in inf.records[:n_base]:
        ev = base_evs.get(r["event_id"])
        if ev and "/etc/passwd" in ev["event"].get("resource", ""):
            if "sensitive_resource" in r["risk_context"]:
                fp += 1

    report = {
        "baseline": {
            "events_scored": base["events_scored"],
            "top1": base["top1_accuracy"],
            "top3": base["top3_accuracy"],
            "mean_anomaly": base["mean_cross_entropy"],
            "anomaly_p90": base["anomaly_score_p90"],
        },
        "attack": {
            "events_scored": len(attack_recs),
            "top3": mean([r["top3_hit"] for r in attack_recs]),
            "signature_events_scored": len(sig_recs),
            "two_layer_coverage": mean([
                bool(r["risk_context"]) or r["anomaly_score"] > base["anomaly_score_p90"]
                for r in sig_recs
            ]),
            "risk_context_coverage": mean([bool(r["risk_context"]) for r in sig_recs]),
            "mean_anomaly_signature": mean([r["anomaly_score"] for r in sig_recs]),
            "chain_exec_anomaly": mean([r["anomaly_score"] for r in chain_execs]),
            "chain_exec_flags": [r["risk_context"] for r in chain_execs],
        },
        "false_positive_passwd_as_sensitive": fp,
        "gates": {},
    }
    g = report["gates"]
    g["baseline_top3_ge_0.80"] = base["top3_accuracy"] >= 0.80
    g["two_layer_coverage_eq_1"] = report["attack"]["two_layer_coverage"] == 1.0
    g["no_passwd_false_positive"] = fp == 0
    report["passed"] = all(g.values())

    Path(args.out).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()