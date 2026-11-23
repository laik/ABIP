"""在线增量训练:Micro-batch 触发 → Challenger → 验证 → Promotion。

用法:python -m lstm.train --events data/events.jsonl --registry models/registry
冷启动训练 v1;之后每 micro_batch_trigger 条样本一轮,从 Champion 权重初始化 Challenger,
近期数据 + Replay Buffer 混合训练,验证通过(CE 改善且 Top-3 不降)才原子切换。
"""

import argparse
import copy
import json
import random

import torch
from torch import nn

from .data import ReplayBuffer, batches, build_samples, load_sequences, time_split
from .features import SCHEMA_PATH, FeatureEngine
from .model import BehaviorLSTM
from .registry import Registry


def evaluate(model, samples, batch_size):
    if not samples:
        return {"ce": float("inf"), "top1": 0.0, "top3": 0.0, "n": 0}
    ce_sum, top1, top3, n = 0.0, 0, 0, 0
    loss_fn = nn.CrossEntropyLoss(reduction="sum")
    with torch.no_grad():
        for cat, num, tgt, mask in batches(samples, batch_size):
            logits, _ = model(cat, num)
            m = mask.bool()
            lg, tg = logits[m], tgt[m]
            ce_sum += float(loss_fn(lg, tg))
            k = min(3, lg.shape[-1])
            topk = lg.topk(k, dim=-1).indices
            hit = topk == tg.unsqueeze(-1)
            top1 += int(hit[:, 0].sum())
            top3 += int(hit.any(-1).sum())
            n += int(m.sum())
    return {"ce": ce_sum / n, "top1": top1 / n, "top3": top3 / n, "n": n}


def train_epochs(model, samples, schema, epochs, rng):
    m = schema["model"]
    opt = torch.optim.AdamW(model.parameters(), lr=m["learning_rate"])
    loss_fn = nn.CrossEntropyLoss(reduction="sum")
    model.train()
    for _ in range(epochs):
        for cat, num, tgt, mask in batches(samples, m["batch_size"], rng):
            opt.zero_grad()
            logits, _ = model(cat, num)
            msk = mask.bool()
            loss = loss_fn(logits[msk], tgt[msk]) / msk.sum()
            loss.backward()
            opt.step()
    model.eval()


def run(events_path: str, registry_root: str, log_path: str | None = None):
    engine = FeatureEngine()
    schema = engine.schema
    t = schema["training"]
    rng = random.Random(42)
    torch.manual_seed(42)

    seqs = load_sequences(events_path)
    samples = build_samples(seqs, engine)
    train_pool, val = time_split(samples, t["validation_fraction"])
    if not train_pool or not val:
        raise SystemExit(f"样本不足: train={len(train_pool)} val={len(val)}")

    reg = Registry(registry_root, schema)
    replay = ReplayBuffer(t["replay_buffer_capacity"])
    trigger = t["micro_batch_trigger"]
    log = []

    # 冷启动 v1
    first, rest = train_pool[:trigger], train_pool[trigger:]
    model = BehaviorLSTM(schema)
    train_epochs(model, first, schema, epochs=3, rng=rng)
    metrics = evaluate(model, val, schema["model"]["batch_size"])
    version = reg.next_version()
    meta = reg.save_version(version, model, {"parent": None, "train_samples": len(first),
                                             "val": metrics, "stage": "cold-start"})
    reg.promote(version)
    replay.add(first)
    log.append({"round": 0, "version": version, "promoted": True, "val": metrics})
    print(f"[cold-start] v{version} promoted: val_ce={metrics['ce']:.4f} "
          f"top1={metrics['top1']:.3f} top3={metrics['top3']:.3f}")

    # 在线轮次:每 trigger 条新样本 → Challenger
    champ_model, champ_meta = reg.champion()
    for i in range(0, len(rest), trigger):
        chunk = rest[i : i + trigger]
        challenger = copy.deepcopy(champ_model)
        mix = chunk + replay.sample(len(chunk))
        train_epochs(challenger, mix, schema, epochs=t["epochs_per_round"], rng=rng)
        cm = evaluate(challenger, val, schema["model"]["batch_size"])
        base = champ_meta["val"]
        passed = cm["ce"] < base["ce"] and cm["top3"] >= base["top3"]
        version = reg.next_version()
        meta = reg.save_version(version, challenger,
                                {"parent": champ_meta["version"], "train_samples": len(mix),
                                 "val": cm, "stage": "incremental"})
        if passed:
            reg.promote(version)
            champ_model, champ_meta = challenger, meta
            decision = "promote"
        else:
            decision = "discard"  # Challenger 不达标,Champion 不动
        replay.add(chunk)
        log.append({"round": len(log), "version": version, "promoted": passed, "val": cm})
        print(f"[round {len(log)-1}] v{version} {decision}: "
              f"val_ce={cm['ce']:.4f} (champ {base['ce']:.4f}) "
              f"top3={cm['top3']:.3f} (champ {base['top3']:.3f})")

    result = {"champion": reg.champion_version(), "rounds": log,
              "samples_total": len(samples), "feature_schema": engine.version}
    if log_path:
        with open(log_path, "w") as f:
            json.dump(result, f, indent=2)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--log", default=None)
    args = ap.parse_args()
    run(args.events, args.registry, args.log)