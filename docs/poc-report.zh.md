# ABIP POC 验收报告(第一轮核心链路)

日期:2026-11-22 · 环境:macOS arm64,CPU · 数据:合成 Tetragon 格式事件(seed=42,可复现)
复现:`make demo && make test` · English: [poc-report.md](poc-report.md)

## 1. 链路与规模

```
gen(20015 事件, 95 注入异常) → Rust Collector → 20005 统一事件
→ 增量训练 8 轮(v1 冷启动 + 7 轮 micro-batch) → Champion v8
→ 流式推理 15271 个可评分事件
```

Collector 计数:received=20015,invalid=0,**deduped=10**(注入的重复事件全部去除),
**late=5**(注入的乱序事件全部标记),emitted=20005。无丢失。

## 2. 进程树(第一里程碑)

- 11 个 Rust 单元测试全过:父子链深度、父后到仍挂链、exit 关闭状态、
  **PID 重用隔离**(同 pid 新 exec_id 独立序列)、去重、乱序窗口(5s)、时间解析。
- `data/tree.json`:python3 → bash → curl 链正确,curl depth=2、parent_binary=bash。

## 3. 训练 / 模型管理

| 轮次 | val CE | val Top-3 | 结果 |
|---|---|---|---|
| v1 冷启动 | 1.949 | 0.444 | promote |
| v2–v5 | 1.901→1.572 | 0.766→0.811 | promote |
| v6 | 1.457 | 0.805(< champ 0.811) | **discard**(Top-3 下降被拒) |
| v7–v8 | 1.450→1.390 | 0.907→0.934 | promote |

- CE 从 1.949(≈ln7,均匀分布)降到 1.390;Top-3 从 0.444 升到 0.934。
- 验证门槛(CE 改善且 Top-3 不降)真实拦截了一次退化(v6)。
- 切换为 champion.json 原子 os.replace;自检覆盖 promote/rollback/旧版本保留。

## 4. 推理与异常检测

| 指标 | 值 |
|---|---|
| Top-1 Accuracy(全流,含早期未训练阶段) | 0.499 |
| Top-3 Accuracy | **0.933** |
| Mean CE / 异常分 | 1.361 |
| LSTM 惊讶度 Recall@p90:capability_change | **0.643** |
| LSTM 惊讶度 Recall@p90:敏感 file_open / 外联 | 0.0(见下) |
| **确定性 Risk Context 覆盖率(全部注入异常)** | **1.000** |
| late 事件跳过状态更新 | 5/5 |

结论与 v1.0 设计一致:**事件类别层面的意外**(capability_change)由 LSTM 惊讶度捕捉;
敏感文件/异常外联在类别层面是正常事件,惊讶度无效,由确定性 Risk Context
(sensitive_resource / external_destination / capability_change)100% 覆盖——
这正是 P3 中 Risk Context → Jev 的风险触发信号,确定性规则优先于模型判断。

## 5. 热切换与状态重建(自检)

推理进行到一半时 promote 新 Champion:推理端感知切换(v2→v3)、
用事件缓冲重放重建全部活跃状态、后续记录全部使用新版本、无中断。
late 事件只计数不更新 Hidden State;process_exit 后状态关闭。

## 6. 训练/推理一致性(自检)

同一 FeatureEngine 实例路径、编码确定性、UNK→index 0、归一化 ∈ [0,1]、
模型 save/load 逐位一致、单步 step 与批量 forward 一致、异常分公式核对。

## 7. 真实集群验证(2026-11-23)

环境:现有 k8s v1.37.2 集群(Debian 12,kernel 6.12),Tetragon v1.8.0 已部署;
开发机 Ubuntu 24.04。ABIP TracingPolicy 按 pod 标签限定(`abip.io/observe=true`),
worker 节点上跑演示 workload pod(alpine sh/cat/ls/wget)。

- 采集(合并多次):2533 条原始事件 → **invalid=0,deduped=689**(同一 exec 被两个 policy 观测),
  输出 1844 条统一事件,覆盖全部四类:process_exec/exit、file_open(末次窗口 110)、
  network_connect、capability_change。
- 训练:冷启动 v1 val CE 2.93 / Top-1 0.549 → v2 **promote**(CE 2.64,Top-3 0.932)。
- 真实流推理:**Top-1 0.813,Top-3 0.948**,平均 CE 1.078。
  纯 exec 采集曾达 Top-1 0.960(短 exec→exit 链可预测性强);均为基准,不代表复杂工作负载。

接入过程中修复的问题(均已有测试覆盖):

1. 真实 kprobe `function_name` 带架构前缀(`__x64_sys_openat`)——normalize 已剥离。
2. tracepoint exec 事件用 `subsys`/`event` 字段,不是 `function_name`——已纳入采集。
3. 真实 payload 的 container 嵌在 `pod.container` 下——两种布局都兼容。
4. exec/exit 去重必须按 `exec_id`(不同 policy 对同一 exec 的时间戳不同,event_id 去重会漏)。
5. `matchWorkloads.podSelector` 匹配的是 **pod labels**,且标签需在 pod 创建时存在;
   `matchNamespaces` 选的是 Linux namespace,不是 k8s namespace。
6. 小样本采集需放大冷启动 epoch(保证 ~200 个梯度步),否则模型停在初始化状态。
7. **Tetragon v1.8.0 / kernel 6.12 上,`syscall: true` 的 kprobe 与 matchWorkloads selector
   组合不产生事件**。必须用内核函数 + `syscall: false`(`do_sys_openat2` 代替 `sys_openat`),
   仓库 policy 已更新。
8. `commit_creds` 在**每次 execve** 都触发(内核正常凭据设置),capability_change 计数以
   良性噪声为主——P3 风险触发需降权,依赖 sys_setuid 类信号。

## 8. 未验证 / 已知限制

- kind 脚本未实际使用(已有现成集群);该网络拉 Docker Hub 失败(DNS 污染)——
  用节点缓存镜像或可达 registry。
- file_write 未采集(sys_write 参数是缓冲区不是路径,需 fd→path 解析,已留 shortcut 注释)。
- 合成数据行为模式较强,指标不代表真实工作负载;真实数据接入后重新建立基准。
- 去重集到 200k 上限整体清空(极端吞吐下可能放过少量重复,已留 shortcut 注释)。
- Jev / Decision Controller / 多租户 / OTEL / Helm 属 P3/P4,未实现。