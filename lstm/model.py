"""唯一模型定义:共享 LSTM Encoder + Next Event Head。

异常分(Head B)是预测分布的函数 -log P(actual),不需要独立网络。
训练与推理都 import 这里;配置来自 feature-schema.json 的 model 段。
"""

import torch
from torch import nn


class BehaviorLSTM(nn.Module):
    def __init__(self, schema: dict):
        super().__init__()
        m = schema["model"]
        emb = schema["embedding_dim"]
        self.cat_fields = list(schema["categorical"])
        self.num_fields = list(schema["numeric"])
        self.embeddings = nn.ModuleDict(
            {
                f: nn.Embedding(len(schema["categorical"][f]), emb)
                for f in self.cat_fields
            }
        )
        in_dim = emb * len(self.cat_fields) + len(self.num_fields)
        self.input_proj = nn.Linear(in_dim, m["hidden_size"])
        self.lstm = nn.LSTM(
            m["hidden_size"], m["hidden_size"], m["lstm_layers"], batch_first=True
        )
        self.head = nn.Linear(m["hidden_size"], len(schema["categorical"]["event_type"]))
        self.event_type_vocab = schema["categorical"]["event_type"]

    def forward(self, cat, num, state=None):
        """cat [B,L,F] long, num [B,L,N] float → logits [B,L,V], new_state。"""
        x = torch.cat([self.embeddings[f](cat[..., i]) for i, f in enumerate(self.cat_fields)]
                      + [num], dim=-1)
        x = torch.tanh(self.input_proj(x))
        out, state = self.lstm(x, state)
        return self.head(out), state

    @torch.no_grad()
    def step(self, cat, num, state=None):
        """单事件流式推理:cat [F], num [N] → logits [V], new_state。"""
        logits, state = self.forward(cat.unsqueeze(0).unsqueeze(0),
                                     num.unsqueeze(0).unsqueeze(0), state)
        return logits[0, 0], state


def anomaly_score(logits: torch.Tensor, actual_idx: int) -> float:
    """预测惊讶度 -log P(actual)。只是异常信号,不等于恶意概率。"""
    logp = torch.log_softmax(logits, dim=-1)
    return float(-logp[actual_idx])