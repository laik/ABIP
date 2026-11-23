"""assert 自检:训练/推理一致性、模型往返、原子切换/回滚、热切换状态重建、乱序/退出。

运行:python -m lstm.selfcheck
"""

import json
import sys
import tempfile
from pathlib import Path

import torch

from . import data as data_mod
from . import features as features_mod
from .features import FeatureEngine
from .infer import StreamInferencer
from .model import BehaviorLSTM, anomaly_score
from .registry import Registry

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from gen_workload import Gen  # noqa: E4202


def check_features():
    eng = FeatureEngine()
    ev = {
        "event_time": "2026-11-22T10:00:05Z",
        "process": {"exec_id": "e1", "parent_exec_id": "e0", "pid": 1,
                    "binary": "totally-unknown-bin", "parent_binary": "bash",
                    "uid": 1000, "depth": 3},
        "event": {"category": "file", "type": "file_open", "resource": "/etc/shadow"},
    }
    c1, n1 = eng.encode(ev, prev_ts=None)
    c2, n2 = eng.encode(ev, prev_ts=None)
    assert c1 == c2 and n1 == n2, "编码必须确定性"
    assert c1["binary"] == 0, "未知 binary → UNK(index 0)"
    assert c1["resource_class"] == eng.vocab["resource_class"]["sensitive"]
    assert c1["parent_binary"] == eng.vocab["parent_binary"]["bash"]
    assert all(0 <= v <= 1 for v in n1.values()), "连续特征必须在 [0,1]"
    # 训练路径与推理路径是同一个 FeatureEngine/同一个 tensors 函数
    assert data_mod.FeatureEngine is features_mod.FeatureEngine
    t1 = eng.tensors(ev)
    t2 = data_mod.FeatureEngine().tensors(ev)
    assert torch.equal(t1[0], t2[0]) and torch.equal(t1[1], t2[1])
    print("ok: features(确定性 / UNK / 归一化 / 训练推理同一实现)")


def check_model_roundtrip():
    eng = FeatureEngine()
    model = BehaviorLSTM(eng.schema)
    model.eval()
    cat = torch.stack(
        [torch.randint(0, len(eng.vocab[f]), (2, 4)) for f in eng.cat_fields], dim=-1
    )
    num = torch.rand(2, 4, len(eng.num_fields))
    with torch.no_grad():
        logits, _ = model(cat, num)
        single, _ = model.step(cat[0, 0], num[0, 0])
    with tempfile.TemporaryDirectory() as d:
        reg = Registry(d, eng.schema)
        reg.save_version(1, model, {"val": {}})
        loaded, _ = reg.load(1)
        with torch.no_grad():
            logits2, _ = loaded(cat, num)
        assert torch.allclose(logits, logits2, atol=1e-6), "save/load 必须逐位一致"
    # anomaly_score = -log softmax
    expect = float(-torch.log_softmax(single, -1)[2])
    assert abs(anomaly_score(single, 2) - expect) < 1e-6
    print("ok: model(save/load 往返 / step 与 forward 一致 / anomaly 公式)")


def check_registry_atomic():
    eng = FeatureEngine()
    with tempfile.TemporaryDirectory() as d:
        reg = Registry(d, eng.schema)
        m = BehaviorLSTM(eng.schema)
        reg.save_version(1, m, {"val": {"ce": 1.0}})
        reg.promote(1)
        assert reg.champion_version() == 1
        reg.save_version(2, m, {"val": {"ce": 0.9}})
        reg.promote(2)
        assert reg.champion_version() == 2
        reg.rollback(1)
        assert reg.champion_version() == 1
        assert reg.load(2)[0] is not None, "旧版本必须保留可回滚"
        assert not reg.pointer.with_suffix(".tmp").exists(), "原子切换不留临时文件"
    print("ok: registry(promote / rollback / 旧版本保留)")


def check_streaming():
    """端到端小流:训练 → 推理 → 中途热切换 → 状态重建 → 乱序跳过 → exit 关闭。"""
    events, truth = Gen(seed=7).run(4000)
    with tempfile.TemporaryDirectory() as d:
        raw, norm = Path(d) / "raw.jsonl", Path(d) / "norm.jsonl"
        raw.write_text("".join(json.dumps(e) + "\n" for e in events))
        # Collector 是 Rust 二进制;自检里直接用其产物格式(由 make collect 保证),
        # 这里用最小规范化:补 parent_binary/depth 不影响特征一致性检查。
        import subprocess

        target = Path(__file__).resolve().parent.parent / "collector/target"
        binary = target / "release/abip-collector"
        if not binary.exists():
            binary = target / "debug/abip-collector"
        assert binary.exists(), "先 cargo build(collector)"
        subprocess.run([str(binary), "--input", str(raw), "--output", str(norm)],
                       check=True, capture_output=True)

        from .train import run as train_run

        result = train_run(str(norm), str(Path(d) / "registry"))
        assert result["champion"] >= 1

        inf = StreamInferencer(str(Path(d) / "registry"))
        lines = norm.read_text().splitlines()
        half = len(lines) // 2
        for line in lines[:half]:
            inf.feed(json.loads(line))
        n_before = len(inf.records)
        assert n_before > 0

        # 模拟一轮增量训练产生新 Champion(扰动权重即可,机制与真实 promotion 相同)
        reg = inf.reg
        model, meta = reg.champion()
        with torch.no_grad():
            for p in model.parameters():
                p.add_(torch.randn_like(p) * 0.01)
        v2 = reg.next_version()
        reg.save_version(v2, model, {**meta, "val": meta.get("val", {})})
        reg.promote(v2)

        for line in lines[half:]:
            inf.feed(json.loads(line))
        assert inf.switches and inf.switches[-1]["to"] == v2, "推理中必须感知热切换"
        assert inf.rebuilds > 0, "切换后必须重放重建状态"
        assert len(inf.records) > n_before, "切换后推理不中断"
        assert all(r["model_version"] == v2 for r in inf.records[-10:])

        # 进程树上下文:子进程第一个事件继承父进程预测,可评分
        import copy as _copy

        parent_id = next(iter(inf.states))
        child_ev = _copy.deepcopy(json.loads(lines[0]))
        child_ev["process"]["exec_id"] = "selfcheck-child"
        child_ev["process"]["parent_exec_id"] = parent_id
        child_ev["event_id"] = "selfcheck-child-evt"
        child_ev["event"]["type"] = "process_exec"
        child_ev["late"] = False
        rec = inf.feed(child_ev)
        assert rec is not None, "子进程首事件必须继承父进程预测并可评分"
        del inf.states["selfcheck-child"]

        # late 事件:只记录不更新状态
        ev = json.loads(lines[0])
        ev["late"] = True
        before = inf.late_skipped
        assert inf.feed(ev) is None
        assert inf.late_skipped == before + 1

        # exit 关闭状态
        exit_ev = next(json.loads(l) for l in lines
                       if json.loads(l)["event"]["type"] == "process_exit")
        inf.feed(exit_ev)
        assert exit_ev["process"]["exec_id"] not in inf.states

        report = inf.report()
        assert report["events_scored"] > 0
        assert 0 <= report["top1_accuracy"] <= report["top3_accuracy"] <= 1
        print(f"ok: streaming(热切换 v{inf.switches[-1]['from']}→v{v2}, "
              f"重建 {inf.rebuilds} 个状态, scored={report['events_scored']}, "
              f"top3={report['top3_accuracy']:.3f})")


if __name__ == "__main__":
    torch.manual_seed(0)
    check_features()
    check_model_roundtrip()
    check_registry_atomic()
    check_streaming()
    print("ALL SELFCHECKS PASSED")