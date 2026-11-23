# ABIP 架构设计(POC v0.1)

ABIP(Agent Behavioral Intelligence Platform):面向 Kubernetes 工作负载的运行时行为智能分析与决策平台。
本文档是 v1.0 完整方案的 POC 落地版:**目标架构不变,第一轮只实现核心闭环链路**。

核心闭环:Observe → Understand → Predict → Decide → Evaluate → Learn

English: [architecture.md](architecture.md)

## 1. 目标架构(v1.0,不变)

```
Tetragon(唯一 Runtime 行为入口)
   ↓
Rust Collector(校验/去重/元数据补全/租户绑定)
   ↓
Redpanda(事件流)
   ↓
Process Tree Engine + Feature Engine ──→ Redis(实时状态)
   ↓                                        ↓
LSTM Inference(下一事件预测 + 异常分)   Training Pipeline(Replay Buffer → 增量训练)
   ↓                                        ↓
Risk Context                            Model Validation → Registry → Promotion
   ↓
Jev Decision(/v1/systemone,Choice/Score/Noul)
   ↓
Decision Controller(Rust,确定性策略优先,置信度阈值,降级)
   ↓
Alert / Approval / Enforcement Recommendation → Audit / Feedback
```

职责边界(不可违反):

- Tetragon 只负责观测;事前拦截走预部署 TracingPolicy(路径 A),异步 LSTM/Jev 决策只做事后风险响应(路径 B)。
- Jev 不控制内核,输出不直接映射为执行动作;确定性禁止规则优先于模型判断。
- 训练与推理共用**同一份**模型定义、Feature Schema、类别字典、归一化参数。
- 在线训练只产生 Challenger,验证通过后原子切换 Champion;切换后旧 Hidden State 必须用新模型重放重建。
- 第一阶段全程 Monitoring Mode,不启用模型驱动的动态 Enforcement。

## 2. POC 范围(本仓库当前实现)

按 v1.0 方案的最终实施建议,第一轮打通:

```
Tetragon JSON 事件(真实采集 或 回放/合成)
   ↓
Rust Collector:Schema 校验 → 去重 → 进程树重建 → 统一事件格式
   ↓
LSTM 在线推理:逐事件预测下一事件类别,与实际事件对比,异常分 = -log P(actual)
   ↓
在线增量训练:自监督样本 + Replay Buffer + Micro-batch
   ↓
Champion/Challenger:验证 → 原子 Promotion → 推理端无中断切换 + 状态重建
```

**第一个技术里程碑是进程树重建**(进程身份、父子关系、事件排序、状态生命周期),
它错了后面 LSTM 学的就是错误序列。Collector 的测试重点覆盖这里。

### POC 简化与升级路径(明确记录的偏差)

| v1.0 组件 | POC 替代 | 升级路径 |
|---|---|---|
| Redpanda 事件流 | JSONL 文件(append-only) | Collector 输出端换成 producer,接口不变 |
| Redis 状态存储 | 推理进程内存(每 exec_id 状态 + 最近 64 事件环形缓冲) | state_manager 换成 Redis 实现,key 结构按 v1.0 §4.3 |
| Postgres 元数据/审计 | 决策/预测 JSONL + registry meta.json | 审计落库 |
| Jev Adapter / Decision Controller | 不实现;异常分 + 阈值报告代替 | P3 接入,questions 模板见 v1.0 §7.3 |
| 多租户 | 事件携带 tenant_id(= namespace),单租户运行 | 按 tenant 分 stream/模型/阈值 |
| OTEL / Helm / RBAC | 不实现;Makefile + kind 脚本 | P4 |
| ONNX 导出 | PyTorch CPU 直接推理(模型极小,够用) | 吞吐不够时再导 ONNX |

不实现但保留契约:prediction/decision 输出 Schema 见 `contracts/`,后续 Jev/Controller 直接消费。

## 3. 数据契约

- `contracts/behavior-event.schema.json` — 统一事件格式(v1.0 §3.3),Collector 输出、训练/推理输入。
- `contracts/feature-schema.json` — **feature-schema-v1**:类别字典 + 归一化参数,版本化。
  Python `lstm/features.py` 是唯一编码实现,训练和推理都调用它;Rust 端不做特征逻辑。

进程身份:`exec_id`(唯一)+ `parent_exec_id` + pid + start_time + container_id + pod_uid。
PID 重用防护:进程 exit 后关闭状态;新 exec_id 开新状态,不复用旧序列。

乱序处理:Collector 按 exec_id 跟踪 last_ts,超过最大乱序窗口(5s)的迟到事件打 `late: true`;
推理端对 late 事件**只记录、不更新 Hidden State**(v1.0 §6.4:不能无条件覆盖)。

## 4. 模型设计(v1.0 §6,参数一致)

一个共享 LSTM Encoder + Next Event Head(Head B 异常分是预测分布的函数,不需要独立网络):

- 离散特征 Embedding(每字段 16 维),连续特征 log/clip 归一化,未知 → UNK。
- LSTM 2 层,hidden 128,序列窗口 64,batch 128,AdamW lr 1e-4,CrossEntropy。
- 异常分 = -log P(实际事件类别)。这只是异常信号,不等于恶意概率。
- 训练样本自监督:E1..E63 → 预测 E2..E64;绝不把模型自身预测当标签。
- 进程树上下文(v1.0 §4):子进程用父进程最近 `tree_context_events`(16)个事件从零状态重放
  初始化——与训练样本构造完全一致,派生链(python→sh→nc)首事件即可用校准的预测评分。
  (直接克隆父进程全量历史 Hidden State 会造成训练/推理分布失配,RFC 0001 验证中实测并修复。)

### Champion / Challenger

```
models/registry/
  v1/{model.pt, meta.json}      # meta: 指标、样本数、feature_schema 版本、父版本
  v2/...
  champion.json                 # 原子指针,os.replace 写入
```

- 每积累 512 条新样本触发一轮:从 Champion 权重初始化 Challenger,
  近期数据 + Replay Buffer(容量 8192, reservoir 采样)混合训练,独立验证集(按时间切分,不泄漏)。
- Promotion 门槛:val CE 改善 且 Top-3 Accuracy 不下降;否则丢弃。
- 推理端轮询 champion.json,版本变化 → 加载新权重 → 用每 exec_id 的最近 64 事件缓冲重放重建 Hidden State。
- 回滚 = 把 champion.json 指回旧版本(原子)。

## 5. 模块与目录

```
ABIP/
├── docs/architecture.md          # 本文档
├── contracts/                    # 事件 Schema + feature-schema-v1
├── collector/                    # Rust:Tetragon JSONL → 统一事件 + 进程树
│   └── src/{main.rs, normalize.rs, tree.rs}
├── lstm/                         # Python:训练/推理共用模型与特征
│   ├── features.py               # 唯一 Feature Engine(读 feature-schema.json)
│   ├── model.py                  # 唯一模型定义
│   ├── data.py                   # JSONL → 按 exec_id 序列 → 窗口样本 + Replay Buffer
│   ├── registry.py               # Champion/Challenger 原子切换
│   ├── train.py                  # 增量训练 + 验证 + Promotion
│   ├── infer.py                  # 流式推理 + 异常分 + 状态重建 + 报告
│   └── selfcheck.py              # assert 自检(训练/推理一致性等)
├── scripts/gen_workload.py       # 合成 Tetragon 格式事件(正常 profile + 注入异常)
├── deployment/tetragon/          # TracingPolicy(文件/网络/权限)+ kind 配置
├── scripts/{kind-up.sh, capture-events.sh}
├── tests/fixtures/               # 真实形状的 Tetragon 事件夹具
└── Makefile                      # demo: gen → collect → train → infer → report
```

## 6. 真实数据采集(P0,需 Linux 集群)

Tetragon 默认只有进程生命周期事件;**文件/网络/权限必须显式 TracingPolicy**:

- `deployment/tetragon/file-network-security.yaml`:
  - `sys_openat` → file_open(路径来自 string arg)
  - `tcp_connect` → network_connect
  - `commit_creds` / `sys_setuid` → capability_change(credential 变化)
- `scripts/kind-up.sh`:kind 集群 + Helm 安装 Tetragon + 应用 TracingPolicy。
- `scripts/capture-events.sh`:`tetra getevents -o json` 落盘为 JSONL,喂给 Collector。

macOS 开发机无法运行 eBPF,本地开发/验收用回放与合成事件(`make demo`);
TracingPolicy 与 kind 脚本在 Linux 环境验证(当前未验证,见 README 状态表)。

## 7. POC 验收(v1.0 §15 的可执行子集)

`make demo` 输出 `data/report.json`:

| 指标 | 验收方式 |
|---|---|
| 进程树正确性 | cargo test:父子关系/exit 关闭/PID 重用/去重/乱序标记 |
| 训练/推理 Schema 一致 | selfcheck:同一事件两条路径编码逐位相等;模型定义单一来源 |
| Top-1 / Top-3 Accuracy | 合成正常 profile 上建立基准,训练后较初始模型改善 |
| 异常 Recall | 分两层:LSTM 惊讶度对 capability_change 类异常(事件类别层面的意外);敏感文件/异常外联在类别层面是正常事件,由确定性 Risk Context 标记(sensitive_resource / external_destination / capability_change)覆盖——对应 v1.0 中 Risk Context → Jev 的风险触发信号,确定性规则优先于模型判断 |
| Promotion / Rollback | 训练产生新版本并原子切换;推理无中断,状态重建;可指回旧版本 |
| 事件丢失/乱序 | Collector 计数:received / deduped / late / emitted |

不预设准确率目标;Jev 成本、吞吐压测、Redis 状态规模属于生产化前工作。

## 8. 阶段路线(对应 v1.0 P0–P4)

- **P0(本仓库)**:Collector + 进程树 + TracingPolicy + kind 脚本。
- **P1(本仓库)**:Feature Schema v1 + LSTM 推理 + 异常分 + 状态管理。
- **P2(本仓库)**:Replay Buffer + Micro-batch 增量训练 + Champion/Challenger + 状态重建。
- P3:Jev Adapter(风险触发,非逐事件)、置信度校准、低置信度降级、决策审计。
- P4:租户隔离、Policy 集成、告警/审批、Enforcement 策略发布控制、故障降级、OTEL/Helm/RBAC。