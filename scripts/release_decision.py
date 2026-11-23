"""S4 决策生成(Decision Controller 最小预演,P3):确定性规则优先于模型判断。

用法:python scripts/release_decision.py --events norm.jsonl --registry models/release \
        --decision decision.json --evidence evidence.json
规则:critical_business(转账/支付类 manifest)→ block;否则 allow。
模型异常分与 Risk Context 全量记录为证据,供审计与后续 Jev 接入。
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lstm.infer import StreamInferencer  # noqa: E4202


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--decision", required=True)
    ap.add_argument("--evidence", required=True)
    args = ap.parse_args()

    inf = StreamInferencer(args.registry)
    evs = {}
    with open(args.events) as f:
        for line in f:
            ev = json.loads(line)
            evs[ev["event_id"]] = ev
            inf.feed(ev)

    flags = {}
    for r in inf.records:
        for fl in r["risk_context"]:
            flags.setdefault(fl, []).append(
                {"event_id": r["event_id"], "anomaly_score": round(r["anomaly_score"], 3)}
            )

    # 确定性禁止规则优先:关键业务资源一律阻断发布
    reasons = []
    if "critical_business" in flags:
        reasons.append("critical_business_resource")
    action = "block" if reasons else "allow"
    decision = {"action": action, "reason": reasons, "model_version": inf.version}
    Path(args.decision).write_text(json.dumps(decision))

    report = inf.report()
    evidence = {
        "decision": decision,
        "risk_flags": {k: len(v) for k, v in flags.items()},
        "flag_details": flags,
        "events_scored": report["events_scored"],
        "mean_anomaly": report["mean_cross_entropy"],
        "anomaly_p90": report["anomaly_score_p90"],
    }
    Path(args.evidence).write_text(json.dumps(evidence, indent=2))
    print(json.dumps(decision))


if __name__ == "__main__":
    main()