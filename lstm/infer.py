"""LSTM 在线推理:逐事件预测下一事件、与实际对比、异常分、状态管理与模型热切换。

用法:python -m lstm.infer --events data/events.jsonl --registry models/registry \
        --out data/predictions.jsonl --report data/report.json [--truth data/anomaly-truth.jsonl]

规则(v1.0 §6.4/§6.6):
- 每个 exec_id 独立 Hidden State + 最近 seq_len 事件环形缓冲。
- late 事件只记录、不更新 Hidden State。
- process_exit 后关闭状态(PID 重用走新 exec_id)。
- Champion 版本变化 → 加载新权重 → 用缓冲重放重建所有状态,旧状态不交给新模型。
"""

import argparse
import json
from collections import deque
from pathlib import Path

import torch

from .features import FeatureEngine, parse_ts
from .model import anomaly_score
from .registry import Registry


class ProcState:
    """双语义状态(RFC 0004):own(tree_context=0,进程自身流)与
    tree(tree_context=1,父树流,下一事件含子进程诞生)。
    同一"exec 之后"上下文在两种流中下一事件分布不同,角色位消除冲突。"""

    __slots__ = ("hidden", "pending", "htree", "ptree", "last_ts", "buffer", "is_root",
                 "owner_depth")

    def __init__(self, seq_len, is_root, owner_depth):
        self.hidden = None
        self.pending = None
        self.htree = None
        self.ptree = None
        self.last_ts = None
        self.buffer = deque(maxlen=seq_len)  # 基张量(tree/owner 位清零),ctx 重放用
        self.is_root = is_root
        self.owner_depth = owner_depth


class StreamInferencer:
    def __init__(self, registry_root: str, truth_path: str | None = None):
        self.engine = FeatureEngine()
        self.reg = Registry(registry_root, self.engine.schema)
        loaded = self.reg.champion()
        if loaded is None:
            raise SystemExit("registry 里没有 Champion,先运行 python -m lstm.train")
        self.model, self.meta = loaded
        self.version = self.meta["version"]
        self.type_names = self.engine.schema["categorical"]["event_type"]  # index → token
        self.states: dict[str, ProcState] = {}
        self.records = []
        self.late_skipped = 0
        self.rebuilds = 0
        self.switches = []
        self.truth = {}
        if truth_path:
            with open(truth_path) as f:
                for line in f:
                    t = json.loads(line)
                    self.truth[(t["exec_id"], t["event_time"])] = t["type"]

    def _maybe_switch(self):
        v = self.reg.champion_version()
        if v == self.version:
            return
        self.model, self.meta = self.reg.load(v)
        self.switches.append({"from": self.version, "to": v})
        self.version = v
        # 旧 Hidden State 不能交给新模型:用每个进程的事件缓冲重放重建(own/tree 双状态)。
        ti = self.engine.num_fields.index("tree_context")
        oi = self.engine.num_fields.index("owner_depth")
        for st in self.states.values():
            st.hidden = st.htree = None
            st.pending = st.ptree = None
            lg = lg1 = None
            for cat, num in st.buffer:
                n0 = num.clone()
                n0[oi] = st.owner_depth
                lg, st.hidden = self.model.step(cat, n0, st.hidden)
                n1 = num.clone()
                n1[ti] = 1.0
                n1[oi] = st.owner_depth
                lg1, st.htree = self.model.step(cat, n1, st.htree)
            if st.buffer:
                st.pending, st.ptree = lg, lg1
            self.rebuilds += 1

    def feed(self, ev: dict) -> dict | None:
        self._maybe_switch()
        exec_id = ev["process"]["exec_id"]
        kind = ev["event"]["type"]
        actual = self.engine.vocab["event_type"].get(kind, 0)
        ts = parse_ts(ev["event_time"])

        if ev.get("late"):
            self.late_skipped += 1
            return None

        st = self.states.get(exec_id)
        parent = self.states.get(ev["process"].get("parent_exec_id", ""))
        is_birth = st is None and parent is not None
        ti = self.engine.num_fields.index("tree_context")
        oi = self.engine.num_fields.index("owner_depth")
        od = min(ev["process"].get("depth", 0), 10) / 10.0
        if st is None:
            st = ProcState(self.engine.seq_len, is_root=parent is None, owner_depth=od)
            # 父进程最近 N 个事件从零重放初始化,own/tree 各一遍,
            # 角色位(tree/owner)按本进程设置——与训练样本构造逐位一致。
            if parent is not None and parent.buffer:
                ctx_n = self.engine.schema["training"].get("tree_context_events", 16)
                lg = lg1 = None
                for cat, num in list(parent.buffer)[-ctx_n:]:
                    n0 = num.clone()
                    n0[oi] = od
                    lg, st.hidden = self.model.step(cat, n0, st.hidden)
                    n1 = num.clone()
                    n1[ti] = 1.0
                    n1[oi] = od
                    lg1, st.htree = self.model.step(cat, n1, st.htree)
                st.pending, st.ptree = lg, lg1
            self.states[exec_id] = st
        record = None
        # 诞生评分用父 tree 语义;自身事件:根进程用 tree,子进程用 own。
        prior = parent.ptree if is_birth else (st.ptree if st.is_root else st.pending)
        if prior is not None:
            probs = torch.softmax(prior, dim=-1)
            top3 = probs.topk(min(3, probs.shape[-1])).indices.tolist()
            score = anomaly_score(prior, actual)
            # 确定性 Risk Context(v1.0 §7.2 风险触发信号):敏感资源/外联/权限变化
            # 不依赖 LSTM 惊讶度,确定性规则优先于模型判断。
            flags = []
            if kind == "capability_change":
                flags.append("capability_change")
            # 类别头只预测事件类别,区分不了 nc 和 ls(都是 process_exec);
            # profile 之外的未知二进制是确定性信号(RFC 0001)。
            if self.engine.vocab["binary"].get(ev["process"].get("binary", ""), 0) == 0:
                flags.append("unknown_binary")
            rc = self.engine.resource_class(ev)
            if rc == "sensitive":
                flags.append("sensitive_resource")
            if rc == "critical_business":
                flags.append("critical_business")
            if self.engine.dest_port_class(ev)[0] == "external":
                flags.append("external_destination")
            key = (exec_id, ev["event_time"])
            record = {
                "event_id": ev["event_id"],
                "exec_id": exec_id,
                "event_time": ev["event_time"],
                "actual": kind,
                "predicted": self.type_names[int(probs.argmax())],
                "top3": [self.type_names[i] for i in top3],
                "prob_actual": float(probs[actual]),
                "anomaly_score": score,
                "correct": int(probs.argmax()) == actual,
                "top3_hit": actual in top3,
                "model_version": self.version,
                "birth": is_birth,
                "risk_context": flags,
                "is_anomaly_truth": key in self.truth,
                "truth_type": self.truth.get(key),
            }
            self.records.append(record)

        cat, num = self.engine.tensors(ev, st.last_ts)
        num[oi] = st.owner_depth
        logits, st.hidden = self.model.step(cat, num, st.hidden)
        st.pending = logits
        num1 = num.clone()
        num1[ti] = 1.0
        logits1, st.htree = self.model.step(cat, num1, st.htree)
        st.ptree = logits1
        num[oi] = 0.0  # 缓冲存基张量,重放时按属主重新设位
        st.buffer.append((cat, num))
        st.last_ts = ts

        # 诞生事件推进父进程 tree 状态(owner=父 depth);缓冲存基张量。
        if is_birth and parent is not None:
            pcat, pnum = self.engine.tensors(ev, parent.last_ts)
            pnum1 = pnum.clone()
            pnum1[ti] = 1.0
            pnum1[oi] = parent.owner_depth
            plg, parent.htree = self.model.step(pcat, pnum1, parent.htree)
            parent.ptree = plg
            parent.buffer.append((pcat, pnum))
            parent.last_ts = ts

        if kind == "process_exit":
            del self.states[exec_id]  # 退出关闭状态
        return record

    def report(self) -> dict:
        scored = [r for r in self.records if r["prob_actual"] > 0]
        n = len(scored)
        anom = [r["anomaly_score"] for r in scored]
        anom_sorted = sorted(anom)
        p90 = anom_sorted[int(n * 0.9)] if n else 0.0
        truth_recs = [r for r in scored if r["is_anomaly_truth"]]
        truth_scores = [r["anomaly_score"] for r in truth_recs]
        normal_scores = [r["anomaly_score"] for r in scored if not r["is_anomaly_truth"]]
        mean = lambda xs: sum(xs) / len(xs) if xs else 0.0
        recall_by_type = {}
        for tt in {r["truth_type"] for r in truth_recs}:
            scores = [r["anomaly_score"] for r in truth_recs if r["truth_type"] == tt]
            recall_by_type[tt] = mean([s > p90 for s in scores])
        return {
            "events_scored": n,
            "top1_accuracy": mean([r["correct"] for r in scored]),
            "top3_accuracy": mean([r["top3_hit"] for r in scored]),
            "mean_cross_entropy": mean(anom),
            "anomaly_score_p90": p90,
            "anomaly_recall_at_p90": (
                mean([s > p90 for s in truth_scores]) if truth_scores else None
            ),
            "lstm_recall_by_anomaly_type": recall_by_type,
            # 确定性 Risk Context 覆盖率:敏感资源/外联/权限变化靠规则,不靠惊讶度
            "risk_context_coverage": mean([bool(r["risk_context"]) for r in truth_recs]),
            "mean_anomaly_truth": mean(truth_scores),
            "mean_anomaly_normal": mean(normal_scores),
            "late_skipped": self.late_skipped,
            "model_switches": self.switches,
            "states_rebuilt": self.rebuilds,
            "live_states": len(self.states),
            "final_model_version": self.version,
            "feature_schema": self.engine.version,
        }


def run(events_path, registry_root, out_path, report_path, truth_path=None):
    inf = StreamInferencer(registry_root, truth_path)
    with open(events_path) as f, open(out_path, "w") as out:
        for line in f:
            rec = inf.feed(json.loads(line))
            if rec:
                out.write(json.dumps(rec) + "\n")
    report = inf.report()
    Path(report_path).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--truth", default=None)
    args = ap.parse_args()
    run(args.events, args.registry, args.out, args.report, args.truth)