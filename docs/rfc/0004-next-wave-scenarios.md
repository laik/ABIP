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

## 4. 结果

(运行后填写)

## 5. 复现

```bash
SCENARIOS="beacon mining inject escape" bash scripts/run-scenarios.sh
.venv/bin/python scripts/mutation_coverage.py --scenarios coding data ops --lolbin \
  --out data/lolbin-coverage.json
```