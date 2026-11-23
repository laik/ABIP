# RFC 0002: 场景标准与变异覆盖——支撑未知攻击的安全验证工程

状态:Accepted · 日期:2026-11-23 · 作者:ABIP team
关联:[RFC 0001](0001-openshell-agent-behavior-scenarios.md) · [架构设计](../architecture.md)

## 1. 动机

RFC 0001 的 4 个场景证明了链路,但手工场景永远枚举不完攻击——安全工程的核心风险
是**人类未想象到的场景**。本 RFC 把场景验证升级为标准:

1. **场景规格标准**:任何新场景按统一规格声明,验证器自动消费,不写一次性代码。
2. **偏离分类学**:攻击不按名字枚举("挖矿""勒索"),按**相对 profile 的偏离维度**枚举。
3. **变异覆盖引擎**:在真实基线流上系统注入偏离,生成器自带 ground truth,
   离线、可复现、可跑成千上万变体——未知攻击的覆盖由构造保证,不靠想象力。

核心命题:**检测是 profile 相对的。任何显著偏离已学习行为模式的事件,
无论攻击者意图如何,都必须被至少一层命中。** 变异引擎验证的正是这个命题。

## 2. 场景规格标准

每个场景声明(见 `scripts/verify_scenarios.py` 的 SIGNATURES 与 ConfigMap 脚本):

```
scenario:
  id: <name>                    # 唯一标识
  carrier: Sandbox CR + pod 标签 abip.io/observe=true
  profile: <baseline 脚本>       # 正常行为定义(学习单元)
  attack: <attack 脚本>          # 注入偏离
  signatures:                   # ground truth 签名(验证器消费)
    paths: [...]                # 资源层:敏感/关键路径子串
    binaries: [...]             # 身份层:profile 外二进制
    dests: [...]                # 网络层:异常目的地前缀
  gates:                        # 验收门槛(全场景统一)
    - baseline Top-3 ≥ 0.80
    - 签名事件两层覆盖 = 1.0
    - 误报对照 = 0
```

新增场景 = 加一个脚本 + 一组签名,零验证代码改动。

## 3. 偏离分类学(6 维)

| 维度 | 偏离 | 检测层 | 攻击举例(仅为说明,不限于此) |
|---|---|---|---|
| D1 身份 | profile 外二进制 | 确定性 unknown_binary | 挖矿、下载执行、改名工具 |
| D2 资源 | 敏感/关键业务路径 | 确定性 sensitive/critical | 凭据窃取、转账业务、持久化 |
| D3 目的地 | profile 外网络目标 | 确定性 external_destination | 外传、C2、供应链投毒 |
| D4 序列 | 事件缺失/乱序/多余 | LSTM 惊讶度 | 跳过审核、注入步骤 |
| D5 时间 | 突发/慢速/周期偏离 | LSTM 时间特征 | 爆发执行、慢速渗出、信标 |
| D6 树形 | 异常派生关系/深度 | LSTM 树上下文 | 进程注入、异常孤儿、伪装父进程 |

D1–D3 是确定性层的**构造性覆盖**(规则按定义命中);D4–D6 是学习层的统计检测,
用异常分抬升度量。两层分工见 RFC 0001 §2。

## 4. 变异覆盖引擎

`scripts/mutation_coverage.py`:输入真实基线规范化流 + 场景 Champion,
输出变异流 + ground truth,离线评分(不需要集群,秒级跑数百变体)。

| 变异 | 操作 |  truth | 门槛 |
|---|---|---|---|
| M1 身份替换 | 随机事件的 binary → 未知名字 | 被改事件 | 覆盖率 = 1.0 |
| M2 敏感资源 | file_open resource → 敏感路径 | 被改事件 | 覆盖率 = 1.0 |
| M3 关键业务 | resource → transfer/payment manifest | 被改事件 | 覆盖率 = 1.0 |
| M4 外联 | network_connect dest → 外部地址 | 被改事件 | 覆盖率 = 1.0 |
| M5 序列缺失 | 删除序列中 30% 事件 | 受影响序列 | 平均异常分抬升 ≥ 1.2× |
| M6 时间压缩 | 时间间隔 ×0.01(爆发) | 受影响序列 | 平均异常分抬升 ≥ 1.2× |
| M7 树形重挂 | 子进程 parent → 无关进程 | 被改诞生事件 | 异常分 > 基线 p90 比例报告 |
| M8 权限注入 | 生存期内插入 capability_change | 插入事件 | 覆盖率 = 1.0 |
| BLIND | 随机混合 M1–M8,随机位置 | 生成器记录 | 总检出率报告 |

诚实原则:D4–D6 若当前模型检测不足,**如实报告为缺口**(后续工作:时间头、
树形头),不修改门槛凑通过。缺口本身是 RFC 的产出。

## 5. 新增手工场景(RFC 0001 扩展)

- **S5 supply-chain**(供应链/下载执行):基线从内部镜像拉包解包;
  攻击从外部拉二进制、cp 到 /tmp 改名执行(未知二进制 + 外联)。
- **S6 persistence**(持久化):基线写 workspace 状态;攻击写 /etc/cron.d、
  /root/.ssh/authorized_keys、隐藏二进制并执行。
- **S7 lateral**(横向移动):基线内部健康检查;攻击 nc 探测多个内部节点 22 端口、
  读 /proc/net/route(扫描模式)。

## 6. 结果

(运行后填写)

## 7. 复现

```bash
bash scripts/run-scenarios.sh                     # S1-S3
SCENARIOS="supply persist lateral" bash scripts/run-scenarios.sh   # S5-S7
bash scripts/run-release-scenario.sh              # S4
.venv/bin/python scripts/mutation_coverage.py \
  --scenarios coding data ops release \
  --out data/mutation-coverage.json               # 变异覆盖矩阵(离线)
```

## 8. 工程路线

- 变异引擎接入 CI:每次模型/Schema 变更跑覆盖矩阵,回归即失败。
- 缺口驱动模型演进:D5/D6 检出不足 → 增加时间/树形预测头(仍守同一契约原则)。
- 真实 OpenShell 会话接入后,基线流换成真实 Agent 行为,变异覆盖自动继承。
- 场景库持续扩充:每个真实安全事件复盘后,沉淀为规格化场景 + 变异维度。