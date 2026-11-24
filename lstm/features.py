"""唯一 Feature Engine(feature-schema-v1)。

训练(data.py)和推理(infer.py)都必须经过这里编码;
Rust Collector 不做任何模型特征逻辑。词表/归一化参数来自 contracts/feature-schema.json。
"""

import json
import math
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "contracts" / "feature-schema.json"


def parse_ts(t: str) -> float:
    return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()


class FeatureEngine:
    def __init__(self, schema_path: Path = SCHEMA_PATH):
        self.schema = json.loads(Path(schema_path).read_text())
        self.version = self.schema["version"]
        self.seq_len = self.schema["sequence_length"]
        self.cat_fields = list(self.schema["categorical"])
        self.num_fields = list(self.schema["numeric"])
        self.vocab = {
            f: {tok: i for i, tok in enumerate(toks)}
            for f, toks in self.schema["categorical"].items()
        }
        self.cls = self.schema["classification"]

    # ---- 类别化(脱敏:原始路径/地址只进类别,不进模型) ----

    def uid_class(self, uid: int) -> str:
        if uid is None or uid < 0:
            return "unknown"
        if uid == 0:
            return "root"
        return "system" if uid < 1000 else "user"

    def resource_class(self, ev: dict) -> str:
        kind = ev["event"]["type"]
        if kind == "process_exec":
            return "binary"
        if kind in ("process_exit", "network_connect", "capability_change", "unknown"):
            return "none"
        path = ev["event"].get("resource", "")
        if not path:
            return "unknown"
        for m in self.cls.get("critical_business_markers", []):
            if m in path:
                return "critical_business"
        for p in self.cls["sensitive_paths"]:
            if p in path:
                return "sensitive"
        for prefix, label in (
            ("config_prefixes", "config"),
            ("workspace_prefixes", "workspace"),
            ("tmp_prefixes", "tmp"),
            ("binary_prefixes", "binary"),
        ):
            if any(path.startswith(p) for p in self.cls[prefix]):
                return label
        return "other"

    def dest_port_class(self, ev: dict) -> tuple[str, str]:
        if ev["event"]["type"] != "network_connect":
            return "none", "none"
        resource = ev["event"].get("resource", "")
        if not resource:
            return "unknown", "unknown"
        addr, _, port = resource.rpartition(":")
        if not addr:
            return "unknown", "unknown"
        if any(addr.startswith(p) for p in self.cls["loopback_prefixes"]):
            dest = "loopback"
        elif any(addr.startswith(p) for p in self.cls["internal_cidrs"]):
            dest = "internal"
        else:
            dest = "external"
        try:
            p = int(port)
            pc = "well_known" if p < 1024 else ("registered" if p < 49152 else "high")
        except ValueError:
            pc = "unknown"
        return dest, pc

    # ---- 编码 ----

    def _cat_idx(self, field: str, token: str) -> int:
        return self.vocab[field].get(token, 0)  # index 0 = UNK

    def encode(self, ev: dict, prev_ts: float | None = None) -> tuple[dict, dict]:
        """统一事件 → (类别特征 index dict, 归一化连续特征 dict)。"""
        p, e = ev["process"], ev["event"]
        ts = parse_ts(ev["event_time"])
        dest, port = self.dest_port_class(ev)
        cat = {
            "event_type": self._cat_idx("event_type", e["type"]),
            "event_category": self._cat_idx("event_category", e["category"]),
            "binary": self._cat_idx("binary", p.get("binary", "")),
            "parent_binary": self._cat_idx("parent_binary", p.get("parent_binary", "")),
            "uid_class": self._cat_idx("uid_class", self.uid_class(p.get("uid", -1))),
            "resource_class": self._cat_idx("resource_class", self.resource_class(ev)),
            "dest_class": self._cat_idx("dest_class", dest),
            "port_class": self._cat_idx("port_class", port),
            "hour_bucket": self._cat_idx(
                "hour_bucket", str(datetime.fromtimestamp(ts, tz=timezone.utc).hour)
            ),
        }
        depth = min(p.get("depth", 0), self.schema["numeric"]["process_depth"]["clip"])
        dt = 0.0 if prev_ts is None else max(0.0, ts - prev_ts)
        dt = min(dt, self.schema["numeric"]["time_delta"]["clip"])
        num = {
            # 角色位:父树流=1(下一事件含子进程诞生),子自身流=0。
            # 消除"exec 之后"在两种流中的语义冲突(RFC 0004 beacon 分析)。
            "tree_context": 0.0,
            # 流属主深度:区分父树流(owner=父 depth)与子树流(owner=子 depth),
            # 同一"exec 之后"上下文在不同属主流中下一事件语义不同。
            "owner_depth": 0.0,
            "process_depth": depth / self.schema["numeric"]["process_depth"]["scale"],
            "time_delta": math.log1p(dt) / self.schema["numeric"]["time_delta"]["scale"],
        }
        return cat, num

    def tensors(self, ev: dict, prev_ts: float | None = None):
        """编码 → (cat LongTensor[F], num FloatTensor[N]),字段顺序由 Schema 固定。"""
        import torch

        cat, num = self.encode(ev, prev_ts)
        return (
            torch.tensor([cat[f] for f in self.cat_fields], dtype=torch.long),
            torch.tensor([num[f] for f in self.num_fields], dtype=torch.float),
        )