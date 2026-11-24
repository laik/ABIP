# RFC 0004: 第二波场景——缺口驱动与 Agent 差异化验证

状态:Accepted · 日期:2026-11-24 · 作者:ABIP team
关联:[RFC 0002](0002-scenario-standard-and-mutation-coverage.md)(规格标准)· [RFC 0003](0003-ransomware-data-lock-scenario.md)

## 1. 选型依据

RFC 0002 变异矩阵记录了三个模型缺口:D5 时间(抬升 1.0)、D4 序列(部分)、
D6 树形(profile 依赖)。第二波场景按两条主线选:

1. **缺口驱动**:场景直接压测已知缺口,产出模型演进需求(时间头/序列完整性)。
2. **Agent 差异化**:ABIP 相对传统 CWPP 的价值在于检测语义攻击的运行时足迹
   (提示注入不分析 prompt,只看行为偏离——守住 v1.0 边界)。

## 2. 场景定义(按 RFC 0002 规格)

### S9 beacon(C2 信标)→ 压测 D5

- 基线:周期内部健康检查(~4s 节奏)。
- 攻击:每轮叠加固定节奏外联 203.0.113.9:8443(Cobalt Strike beacon 模式;
  真实参考 SUNBURST DNS 信标、APT41)。
- 信号:external_destination(确定性,门槛)+ 时间节奏偏离(LSTM,如实报告抬升)。
- 产出:时间头需求的第一手度量。

### S10 mining(挖矿)→ 云上最高频 + 生命周期特征

- 基线:短驻批处理作业(频繁 exec/exit)。
- 攻击:cp busybox → /tmp/xmrig 长驻(60s,超出采集窗口不退出)+ nc 矿池
  203.0.113.9:3333(TeamTNT/Kinsing/8220 Gang 模式)。
- 信号:unknown_binary(xmrig)+ external + **长驻不退出**(生命周期偏离,新特征需求)。

### S12 inject(提示注入运行时足迹)→ Agent 差异化证明

- 基线:coding profile(写/读 workspace 源码)。
- 攻击:运行中途突变——sh 一行命令 wget 外部脚本到 /tmp/.s 并执行
  (间接提示注入的运行时 manifestation;不采集/不分析 prompt)。
- 信号:external_destination + 序列偏离 D4(LSTM 惊讶度,报告)。
- 命题:**语义攻击无需理解语义,profile 偏离即可检测。**

### S17 escape(容器逃逸尝试)→ 最高危确定性拦截

- 基线:ops profile。
- 攻击:写 /proc/sysrq-trigger、写 cgroup release_agent、cp busybox →
  /tmp/nsenter 执行(CVE-2022-0185、TeamTNT 逃逸模式;内核会拒绝,
  但 openat/exec 尝试可观测——检测的是意图)。
- 信号:sensitive_resource(新标记 /proc/sysrq、release_agent)+ unknown_binary。

### S18 LOLBin(就地取材)→ 变异引擎约束模式

- 不新增集群场景:变异引擎 `--lolbin` 模式,**禁用身份替换(M1)**,
  攻击只用词表内二进制(cat/cp/tar/sh/wget),身份层全盲。
- 命题:资源层+目的地层+序列层必须独立承载检测——两层分工的对抗性证明。
- 真实参考:APT29/FIN6 大量使用原生工具。

## 3. 验收

S9/S10/S12/S17:统一门槛(基线 Top-3 ≥ 0.80、签名两层覆盖 = 1.0、零误报)
+ 各场景特征信号如实报告(时间抬升、长驻进程、序列惊讶度)。
S18:LOLBin 矩阵 M2/M3/M4/M8 覆盖 = 1.0(身份层缺席下资源/目的地层独立成立)。

## 4. 结果(2026-11-24,真实集群,全部通过)

| 场景 | own Top-3(门槛≥0.80) | birth Top-3(报告) | 两层覆盖 | 结论 |
|---|---|---|---|---|
| S1 coding | 0.921 | 1.000 | 1.0 | ✅ |
| S2 data | 0.955 | 1.000 | 1.0 | ✅ |
| S3 ops | 0.924 | 1.000 | 1.0 | ✅ |
| S5 supply | 0.860 | 1.000 | 1.0 | ✅ |
| S6 persist | 1.000 | 1.000 | 1.0 | ✅ |
| S7 lateral | 1.000 | 1.000 | 1.0 | ✅ |
| S9 beacon | 1.000 | 0.000 | 1.0 | ✅ |
| S10 mining | 0.997 | 0.952 | 1.0 | ✅ |
| S12 inject | 0.995 | 0.297 | 1.0 | ✅ |
| S17 escape | 1.000 | 1.000 | 1.0 | ✅ |
| S4 release 拦截 | baseline PUBLISHED / attack BLOCKED | — | 零误拦 | ✅ |
| S8 ransom 拦截 | baseline MAINTAINED / attack BLOCKED,**数据完整** | — | 零损失 | ✅ |

LOLBin 约束矩阵(coding/data/ops):身份层全盲下 M2/M3/M4/M8 覆盖 1.00,盲测 1.0——
资源/目的地层独立承载检测成立。M5/M6 缺口延续 RFC 0002 记录(时间头待演进)。

### 指标定义修正(测量先于猜测)

beacon 聚合 Top-3 长期 0.694,逐层测量定位:busybox sh 为每次重定向自己打开
/dev/null(~50 个管道事件),穿插在子进程诞生之间——诞生后的下一个树事件通常是
另一个 own open,类别头对诞生的预测结构性困难;而 **own 序列 Top-3 = 1.000**,
profile 完全可学习。原门槛混合了两个任务,修正为:

- **profile 可学习性**:own 序列 Top-3 ≥ 0.80(门槛);
- **诞生/链校准**:单独报告;攻击链检测由两层覆盖门槛考核(不变)。

beacon/inject 的 birth 低分是 shell 管道噪声的结构效应,不是检测失效
(攻击覆盖 1.0)。后续:管道事件分类(/dev/null 重定向归 plumbing 类)可改善。

### 模型结构演进(本波产出)

1. `tree_context` 角色位 + 双 hidden/pending(own/tree 双语义);
2. `owner_depth` 流属主深度——消除父树流与子树流的"exec 之后"上下文歧义;
3. 训练/推理/ctx 重放/热切换重建全链路逐位对齐。
大多数 profile 的 birth 校准从 0.000 升到 1.000。

### 验证基础设施教训

- `kubectl wait` 对不存在的 pod 立即报错(控制器创建延迟)→ runner 曾跳过
  训练/决策注入,**聚合器读旧文件报假 PASS**。修复:pod 存在性轮询 +
  函数开头清除旧产物 + 聚合器按请求清单核对。假 PASS 比 FAIL 更危险。
- agent-sandbox-controller 镜像拉取延迟导致短暂不可用——验证管道依赖
  基础设施健康,失败必须暴露。

## 5. 复现

```bash
SCENARIOS="beacon mining inject escape" bash scripts/run-scenarios.sh
.venv/bin/python scripts/mutation_coverage.py --scenarios coding data ops --lolbin \
  --out data/lolbin-coverage.json
```