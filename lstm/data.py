"""统一事件 JSONL → 按 exec_id 的行为序列 → 自监督窗口样本 + Replay Buffer。

自监督:输入 E1..En-1,标签 E2..En(下一事件类别)。绝不把模型预测当标签。
"""

import json
import random
from dataclasses import dataclass, field

import torch
from torch.nn.utils.rnn import pad_sequence

from .features import FeatureEngine, parse_ts


@dataclass
class Sample:
    cat: torch.Tensor  # [L,F]
    num: torch.Tensor  # [L,N]
    tgt: torch.Tensor  # [L] 下一事件类别 index
    mask: torch.Tensor  # [L] 1=有标签的位置
    end_ts: float


def load_sequences(path: str) -> dict[str, list[dict]]:
    """按 exec_id 分组、按时间排序。late 事件不进训练序列(乱序不能污染行为模型)。"""
    seqs: dict[str, list[dict]] = {}
    with open(path) as f:
        for line in f:
            ev = json.loads(line)
            if ev.get("late"):
                continue
            seqs.setdefault(ev["process"]["exec_id"], []).append(ev)
    for seq in seqs.values():
        seq.sort(key=lambda e: parse_ts(e["event_time"]))
    return seqs


def _encode(events, engine, prev=None):
    cats, nums, types, tss = [], [], [], []
    for ev in events:
        c, n = engine.tensors(ev, prev)
        cats.append(c)
        nums.append(n)
        types.append(engine.vocab["event_type"].get(ev["event"]["type"], 0))
        prev = parse_ts(ev["event_time"])
        tss.append(prev)
    return cats, nums, types, tss


def _windows(cats, nums, types, tss, engine, mask_prefix=0):
    samples = []
    n = len(cats)
    for start in range(0, n - 1, engine.seq_len):
        stop = min(start + engine.seq_len, n)
        if stop - start < 2:
            continue
        L = stop - start
        mask = torch.ones(L)
        mask[-1] = 0  # 窗口最后一个位置没有下一事件标签
        if start == 0 and mask_prefix:
            mask[:mask_prefix] = 0  # ctx 内部转移不在子样本里重复训练
        tgt = torch.tensor(types[start + 1 : stop] + [0])
        samples.append(
            Sample(
                cat=torch.stack(cats[start:stop]),
                num=torch.stack(nums[start:stop]),
                tgt=tgt,
                mask=mask,
                end_ts=tss[stop - 1],
            )
        )
    return samples


def build_samples(seqs: dict[str, list[dict]], engine: FeatureEngine) -> list[Sample]:
    """进程树序列 → ≤seq_len 窗口样本(与 infer.py 的树上下文逐位对齐)。

    父样本:自身事件 + 直接子进程的首事件(诞生)按时间 interleaved——
    父进程的"下一事件"分布真实包含子进程诞生,诞生评分才校准。
    子样本:父进程诞生前最近 ctx_n 个事件(含既往诞生)从零重放作上下文,
    只训练子进程内部转移(ctx 内部与边界标签已在父样本训练,不重复计入)。
    """
    ctx_n = engine.schema["training"].get("tree_context_events", 16)
    children_first: dict[str, list[dict]] = {}
    for seq in seqs.values():
        pid = seq[0]["process"].get("parent_exec_id", "")
        if pid in seqs:
            children_first.setdefault(pid, []).append(seq[0])

    merged: dict[str, list[dict]] = {}
    for eid, seq in seqs.items():
        merged[eid] = sorted(
            seq + children_first.get(eid, []), key=lambda e: parse_ts(e["event_time"])
        )

    samples = []
    for eid, seq in seqs.items():
        # 父/自身样本:interleaved 序列,全部位置有标签
        cats, nums, types, tss = _encode(merged[eid], engine)
        samples += _windows(cats, nums, types, tss, engine)
        # 子样本:ctx = 父 merged 中诞生前最近 ctx_n 个事件;只训子进程内部转移
        pid = seq[0]["process"].get("parent_exec_id", "")
        if pid in merged and len(seq) >= 2:
            birth_ts = parse_ts(seq[0]["event_time"])
            ctx = [e for e in merged[pid] if parse_ts(e["event_time"]) < birth_ts][-ctx_n:]
            if ctx:
                cc, cn, ct, tt = _encode(ctx, engine)
                sc, sn, st_, tt2 = _encode(seq, engine)  # 子进程首事件 delta=0
                samples += _windows(
                    cc + sc, cn + sn, ct + st_, tt + tt2, engine, mask_prefix=len(ctx)
                )
    samples.sort(key=lambda s: s.end_ts)
    return samples


def collate(batch: list[Sample]):
    """右侧 padding;真实位置不受 padding 影响,loss 用 mask 过滤。"""
    return (
        pad_sequence([s.cat for s in batch], batch_first=True),
        pad_sequence([s.num for s in batch], batch_first=True),
        pad_sequence([s.tgt for s in batch], batch_first=True),
        pad_sequence([s.mask for s in batch], batch_first=True),
    )


@dataclass
class ReplayBuffer:
    """reservoir 采样,容量固定;近期数据 + 历史混合,防增量训练遗忘。"""

    capacity: int
    items: list[Sample] = field(default_factory=list)
    seen: int = 0
    rng: random.Random = field(default_factory=lambda: random.Random(42))

    def add(self, samples: list[Sample]):
        for s in samples:
            self.seen += 1
            if len(self.items) < self.capacity:
                self.items.append(s)
            else:
                j = self.rng.randrange(self.seen)
                if j < self.capacity:
                    self.items[j] = s

    def sample(self, n: int) -> list[Sample]:
        if not self.items:
            return []
        return self.rng.sample(self.items, min(n, len(self.items)))


def time_split(samples: list[Sample], val_fraction: float):
    """按时间切分验证集,不随机打乱切分(避免未来信息泄漏)。"""
    cut = int(len(samples) * (1 - val_fraction))
    return samples[:cut], samples[cut:]


def batches(samples: list[Sample], batch_size: int, shuffle_rng=None):
    order = list(samples)
    if shuffle_rng:
        shuffle_rng.shuffle(order)
    for i in range(0, len(order), batch_size):
        yield collate(order[i : i + batch_size])