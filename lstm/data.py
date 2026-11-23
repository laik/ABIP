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


def build_samples(seqs: dict[str, list[dict]], engine: FeatureEngine) -> list[Sample]:
    """每个进程序列切成 ≤seq_len 的窗口;不足 2 个事件的序列没有监督信号,跳过。"""
    samples = []
    for seq in seqs.values():
        if len(seq) < 2:
            continue
        cats, nums, types, tss = [], [], [], []
        prev = None
        for ev in seq:
            c, n = engine.tensors(ev, prev)
            cats.append(c)
            nums.append(n)
            types.append(engine.vocab["event_type"].get(ev["event"]["type"], 0))
            prev = parse_ts(ev["event_time"])
            tss.append(prev)
        for start in range(0, len(seq) - 1, engine.seq_len):
            stop = min(start + engine.seq_len, len(seq))
            if stop - start < 2:
                continue
            L = stop - start
            mask = torch.ones(L)
            tgt = torch.tensor(types[start + 1 : stop] + [0])
            mask[-1] = 0  # 窗口最后一个位置没有下一事件标签
            samples.append(
                Sample(
                    cat=torch.stack(cats[start:stop]),
                    num=torch.stack(nums[start:stop]),
                    tgt=tgt,
                    mask=mask,
                    end_ts=tss[stop - 1],
                )
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