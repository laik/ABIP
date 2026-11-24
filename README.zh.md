# ABIP — Agent Behavioral Intelligence Platform (POC)

面向 Kubernetes 工作负载的运行时行为智能分析与决策平台。
Tetragon(观测)→ Rust Collector(进程树)→ LSTM(预测/异常)→ 增量训练 → Champion/Challenger 模型切换。

架构与边界见 [docs/architecture.zh.md](docs/architecture.zh.md) · 验收报告 [docs/poc-report.zh.md](docs/poc-report.zh.md) · English: [README.md](README.md)
当前实现 v1.0 方案的第一轮核心链路(P0–P2);Jev 决策与 Decision Controller 属 P3,未实现。

## 快速开始(macOS/Linux,无需集群)

```bash
make setup      # venv + torch(已装可跳过)
make demo       # 合成事件 → Collector → 训练/模型切换 → 推理 → data/report.json
make test       # cargo test + Python 自检(一致性/热切换/回滚/乱序/去重)
```

真实集群采集(需要 Linux + kind + helm):

```bash
make kind-up    # kind + Tetragon + TracingPolicy
make capture    # tetra getevents -o json → data/raw-events.jsonl(Ctrl-C 停止)
make collect train infer
```

## 产物

| 文件 | 内容 |
|---|---|
| `data/tree.json` | 进程树快照(exec_id 父子关系、存活状态、事件计数) |
| `data/events.jsonl` | 统一事件格式(contracts/behavior-event.schema.json) |
| `data/training-log.json` | 每轮 Challenger 验证指标与 promote/discard |
| `models/registry/` | 版本化模型 + champion.json 原子指针 |
| `data/predictions.jsonl` | 逐事件:预测 vs 实际、Top-3、异常分、确定性 Risk Context 标记、模型版本 |
| `data/report.json` | Top-1/Top-3 Accuracy、CE、LSTM 惊讶度 Recall(分异常类型)、Risk Context 覆盖率、热切换/重建计数 |

异常检测分两层(与 v1.0 方案一致):LSTM 惊讶度 `-log P(actual)` 捕捉**事件类别层面**的意外
(如 capability_change);敏感文件/异常外联在类别层面是正常事件,由确定性 Risk Context 标记
(`sensitive_resource` / `external_destination` / `capability_change`)——这是 P3 接 Jev 的风险触发信号。

## 状态

| 组件 | 状态 |
|---|---|
| Rust Collector(规范化/去重/进程树/乱序) | ✅ 11 个单元测试 |
| Feature Engine v1(训练/推理同一实现) | ✅ 自检 |
| LSTM 训练/推理/增量/Champion-Challenger | ✅ 自检 + demo |
| 热切换 + 状态重建 + 回滚 | ✅ 自检 |
| TracingPolicy(真实 Tetragon v1.8.0 / k8s v1.37 集群) | ✅ 2026-11-23 验证,真实流 Top-1 0.813 / Top-3 0.948 |
| OpenShell Agent 场景(RFC 0001/0002:coding/data/ops/supply/persist/lateral + 发布流水线拦截闭环) | ✅ 全过,Top-3 0.90+,攻击覆盖 1.0,转账发布被 BLOCKED |
| 变异覆盖引擎(RFC 0002:8 偏离维度 + 盲测,7 真实 profile) | ✅ 确定性维度 1.00,盲测 1.0;时间/序列缺口已记录 |
| 勒索式数据加锁拦截(RFC 0003 S8,真实事件建模) | ✅ 破坏前 BLOCKED,数据库完整(零损失) |
| 第二波场景(RFC 0004:beacon/mining/inject/escape + LOLBin) | ✅ 全过,own Top-3 0.86+,覆盖 1.0;双语义树模型 |
| kind 脚本 | ⚠️ 已提供,未实际使用(已有现成集群) |
| Jev / Decision Controller / 多租户 / OTEL | ⏭ P3/P4,未实现 |

## 目录

```
contracts/   事件 Schema + feature-schema-v1(唯一特征契约)
collector/   Rust:Tetragon JSONL → 统一事件 + 进程树
lstm/        Python:features / model / data / registry / train / infer / selfcheck
scripts/     合成 workload、kind 安装、事件采集
deployment/  TracingPolicy、kind 配置
tests/       Tetragon 事件夹具
```