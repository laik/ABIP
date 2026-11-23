"""Champion / Challenger 模型注册表:版本目录 + 原子指针切换。

Promotion = os.replace 写 champion.json(原子);Rollback = 指回旧版本。
"""

import json
import os
import time
from pathlib import Path

import torch

from .model import BehaviorLSTM


class Registry:
    def __init__(self, root: str, schema: dict):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.schema = schema
        self.pointer = self.root / "champion.json"

    def _read_pointer(self) -> dict | None:
        if self.pointer.exists():
            return json.loads(self.pointer.read_text())
        return None

    def champion_version(self) -> int | None:
        p = self._read_pointer()
        return p["version"] if p else None

    def load(self, version: int) -> tuple[BehaviorLSTM, dict]:
        d = self.root / f"v{version}"
        model = BehaviorLSTM(self.schema)
        model.load_state_dict(torch.load(d / "model.pt", map_location="cpu", weights_only=True))
        model.eval()
        return model, json.loads((d / "meta.json").read_text())

    def champion(self) -> tuple[BehaviorLSTM, dict] | None:
        v = self.champion_version()
        return self.load(v) if v is not None else None

    def save_version(self, version: int, model: BehaviorLSTM, meta: dict):
        d = self.root / f"v{version}"
        d.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), d / "model.pt")
        meta = {
            **meta,
            "version": version,
            "feature_schema": self.schema["version"],
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        (d / "meta.json").write_text(json.dumps(meta, indent=2))
        return meta

    def promote(self, version: int):
        """原子切换生产模型。"""
        tmp = self.pointer.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": version}))
        os.replace(tmp, self.pointer)

    def rollback(self, version: int):
        assert (self.root / f"v{version}" / "model.pt").exists(), f"v{version} 不存在"
        self.promote(version)

    def next_version(self) -> int:
        vs = [int(p.name[1:]) for p in self.root.glob("v*") if p.name[1:].isdigit()]
        return max(vs, default=0) + 1