# 主机侧 Procedure 覆盖矩阵（TTP × ATT&CK × 检测可见性）

**文档类型：** 独立覆盖 / 可检测性目录（非实现手册）  
**日期：** 2026-08-25（v1.5 修订 2026-09-11；v1.5.1 释义与文件名修订 2026-10-17）  
**状态：** v1.5.1（**数据行 66 行契约不变**；正式化 `PH` = Procedure / Host；权威路径改为 `procedure-host-ttp-coverage-matrix.md`）  
**`PH` 缩写（契约）：** **Procedure / Host** — 主机侧可复现步骤的稳定行 ID（字段名仍为 `ph_id`，前缀仍为 `PH-`）。**不是** Phishing、**不是** Playbook、**不是** ATT&CK 官方编号。权威文件：`docs/coverage/procedure-host-ttp-coverage-matrix.md`（由历史名 `phishing-ttp-coverage-matrix.md` 迁入）。  
**战术序依据：** MITRE ATT&CK Enterprise 官方 14 战术序（Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Command and Control → Exfiltration → Impact），以 [attack.mitre.org](https://attack.mitre.org/) 为准  
**检测可见性权威：** ATT&CK 官方 Data Sources 字段 + Sysmon 事件目录 + 厂商公开文档（Microsoft Defender / Windows 安全事件）  
**实践技巧血缘：** HackTricks（hacktricks.wiki，仅作落地手法参考，**不作为检测可见性权威**）+ LOLBAS 项目（lolbas-project.github.io，代理执行二进制的滥用语法权威；HackTricks 无 LOLBins 专页，见审计 §A3）+ UACME（github.com/hfiref0x/UACME，UAC bypass 变体目录权威，60+ 方法，ATT&CK T1548.002 官方页引用）。逐项 URL 核验状态见审计 §A3（2026-08-25）  
**审计意见：** `docs/coverage/procedure-host-ttp-coverage-matrix-audit.md`  
**关联设计：** `docs/superpowers/specs/2026-08-25-phishing-chain-coverage-extension.md`（扩展 spec，本矩阵的 schema/效度规则上位；若该文件未随仓迁入，以本矩阵 §2–§3 与工厂设计书为准）  
**与 AD 矩阵关系：** `docs/coverage/ht-ad-ttp-coverage-matrix.md` 保持**域内后渗透**权威（assumed breach 之后）；本矩阵覆盖**初始立足点获取前后（投递落地 → 执行引擎 → 提权/致盲）**的主机侧执行链。重叠技术交叉引用、不重复建行（见 §6）。

---

## 1. 用途

本表把**主机侧可复现步骤**（Procedure / Host）技术族映射到：

1. **ATT&CK 官方技术 ID**（按官方战术序分组；对外报告与 Navigator 覆盖率）
2. **检测可见性维度**（检测定位 / 数据源 / 端点可见性 / 审计前置 / 保真度 / 期望信号）——沿用 AD 矩阵五列语义，扩展见 §3
3. **评测阶段与检测层**（§3.3：执行前/执行中/执行后 × static/behavior/policy/telemetry）——EDR 分层评分框架的数据基础
4. **evasion_tier 关联**（E0–E4 变体键，`playbook-toolchain-sequences.md` §1）

用于：主机侧手法缺口盘点、测例排期、样本工厂组合词汇表、**分层检测覆盖率与可检测覆盖率的分母定义**。  
本矩阵本身不展开利用步骤；已公开 PoC 的调用与参数归 `playbook-toolchain-details.md`（设计 §0.3 文档面口径），密钥与编译后载荷二进制不进任何文档（设计 §0.5；构建器归授权后端，见扩展 spec §7）。

**范围边界：** 只评估**主机行为检测**（端点传感器可见的信号），不含邮件网关/网络侧/identity 侧评分（那些归 SIEM/NDR/ITDR 视图）；客户端漏洞利用型打点（T1203 族）延续方法论既有 defer（P3），本批不建行。历史建行血缘含钓鱼打点扩展，但行 ID 语义按 Procedure / Host 理解。

---

## 2. 列定义

| 列 | 含义 |
|----|------|
| `ph_id` | 稳定行 ID：`PH-` = **Procedure / Host**（主机侧可复现步骤）；供测例 `test_case_id` / Recipe / 工厂组合主键引用。不是 Phishing，不是 Playbook |
| `ATT&CK` | 官方技术 ID（含子技术号；命名变体组标父技术）；多战术技术注明主战术归属 |
| `技术名 / 落地变体` | 官方技术名 + 公开落地变体（如 fodhelper、Squiblydoo） |
| `检测定位` | 遥测主要产生地：`endpoint`（受害主机）/ `target` / `network`（沿用 AD 矩阵语义） |
| `数据源` | 主要遥测：**Sysmon EID / Security EventID / 具名 ETW provider / 厂商日志**（可核对；依据见审计 §A2） |
| `端点可见性` | `high` / `partial` / `none`；`*` 后缀为条件式（语义同 AD 矩阵 §3.2） |
| `审计前置` | 遥测是否需非默认配置（扩展取值见 §3.4） |
| `保真度` | 检测置信度/抗规避：`高`/`中`/`低`；含噪声与**可致盲**说明 |
| `评测阶段` | `执行前`（投递/落地/静态面）/ `执行中`（引擎/注入/内存）/ `执行后`（提权/致盲/清理） |
| `检测层` | `static`（文件/内存静态扫描）/ `behavior`（行为引擎）/ `policy`（策略拦截：ASR/SmartScreen/MotW/宏策略）/ `telemetry`（仅遥测可见，不判恶意）；可多值 |
| `evasion_tier` | 关联 E0–E4 档（E0 默认落盘 / E1 重编译破 IOC / E2 in-memory / E3 致盲类 / E4 组合定制） |
| `期望信号` | 供 Detection Correlator 的弱匹配提示 |
| `备注 / 实践引用` | 映射说明 + 实践技巧血缘（HT 页 / LOLBAS 条目；核对状态见审计 §A3） |

---

## 3. 图例与前提

### 3.1 优先级与批次

| 批次 | 内容 | 本矩阵状态 |
|----|------|-----------|
| **P0** | 执行引擎族 + 注入与内存执行族 + 提权族（EDR 主场核心分母） | ✅ v1.0 建行（§5.1–5.3、5.4 部分） |
| **P1** | 防御致盲族 + 混淆免杀族（效度标注 × evasion_tier 联动） | ✅ v1.0 建行（§5.5、5.6） |
| **P2** | 投递载体全谱（宏/容器/LNK/OneNote/远程模板/用户执行）+ MotW 可控（合成标记机制 §3.8） | ✅ **v1.2 建行文件型载体 7 行**（§5.0 IA01–IA06 + §5.5 BL09 MotW 剥离）；真实邮件通道为全保真**可选**变体（§7） |
| **P3** | 主机持久化族 + 反分析族 + 客户端漏洞利用型打点（延续方法论 P2 defer） | **部分建行**：§5.1a PH-PS01（T1543.003）；其余仍见 §7 |

### 3.2 「端点可见性」

语义与 AD 矩阵 §3.2 完全一致：`high` 计入 EDR 分母；`partial` 弱权重计入；`none` 不计入 EDR 分母转 SIEM/网络视图；`*` 为条件式（传感器在位且执行发生在受监控主机本机）。本矩阵行以 `endpoint` 定位为主。

### 3.3 「评测阶段 × 检测层」分层评分框架（本矩阵新增语义）

评测阶段定义（主机侧 Procedure 链）：

- **执行前**：载荷尚在投递/落地/静止状态（文件写入、ADS、容器解包、静态扫描窗口）。
- **执行中**：代码开始运行（代理执行宿主、脚本解释器、注入原语、内存加载）。
- **执行后**：立足点已建立后的主机侧动作（提权、致盲、持久化、凭据访问入口）。

检测层定义（同一技术可能命中多层，逐层分别记分）：

| 检测层 | 含义 | 典型证据 |
|----|------|---------|
| `static` | 文件/内存静态特征（签名、熵、云查询 verdict、内存扫描） | quarantine/云 verdict/检出事件 |
| `behavior` | 行为引擎（进程树、注入检测、注册表序列、API 序列） | 行为告警/阻断 |
| `policy` | 平台策略拦截（ASR 规则、SmartScreen、MotW 执行阻断、宏默认禁用） | 阻断事件/策略 ID |
| `telemetry` | 仅遥测可见、不判恶意（供 Correlator/SIEM 关联） | EID 事件流 |

**判定语义**（沿用并细化方法论 §10）：每行结果 ∈ `blocked`（阻断）/ `detected`（告警未阻断）/ `not_detected` / `inconclusive`（审计前置未满足 **或** 同期致盲行生效，见 §3.6）。`not_detected` 与 `inconclusive` 必须区分，不得把「未记录/被致盲」记为「EDR 漏检」。

### 3.4 「审计前置」扩展取值（在 AD 矩阵取值之上新增）

| 值 | 含义 |
|----|------|
| `需Sysmon` | 依赖 Sysmon/等价 EDR 端点传感器（EID1/7/8/10/11 等） |
| `需4104` | 需开启 PowerShell 脚本块/模块日志（4104/4103，非默认） |
| `需实时防护` | EDR/Defender 实时文件与行为防护开启（静态层分母前提） |
| `需ASR启用` | 需目标 ASR 规则组处于启用状态（policy 层分母前提；规则 GUID 基线入 runbook） |
| `需TamperProtection` | Defender 防篡改保护开启（BL05 阻断分支前提） |
| `需Sysmon≥14` | 依赖 Sysmon v14+ 事件（EID25 ProcessTampering） |
| `默认` / `—` | 同 AD 矩阵 |

### 3.5 传感器与 EDR 配置基线声明（`sensor_baseline` + `edr_config_baseline`）

本矩阵可见性默认假设：① 端点 EDR 代理或 Sysmon 在位；② PowerShell 脚本块日志开启（`需4104` 行）；③ 实时防护开启（static 层行）；④ 被测 EDR 的 ASR/SmartScreen/MotW 策略状态在 run 开前**逐项记录**（配置基线不记录则 policy 层结果不可比，一律 `inconclusive`）。

### 3.6 致盲效度规则（P1 防御致盲族专属）

`PH-BL01/02/04` 等致盲行执行成功时，**同期时间窗内**其他行的 `not_detected` 结果一律降级为 `inconclusive（可致盲）`——沿用在 HT 矩阵 §3.5「抗规避提醒」与方法论 §10 已确立的先例。致盲行自身的结果解释为「EDR 数据通路完整性」而非「EDR 漏检」。

### 3.7 行数契约与覆盖率指标

- **行数契约 = 66 行**（自 v1.5 起；§5 合计 = v1.4 的 51 行 + v1.5 高频覆盖 15 行。修订须在 §8 登记，不得静默增删）。
- `ph_coverage` = 状态 v1/v2 且已有 TestCase 的行 / 66。
- `attck_coverage` = 去重 ATT&CK ID 数（多行共享 ID 按去重计）。
- `layer_coverage` = 每检测层（static/behavior/policy/telemetry）分别统计的 `detected+blocked` 行 / 该层分母行。
- 审计前置未满足 → `inconclusive`，不得记 `not_detected`（同 AD 矩阵 §3.3 v0.3 规则）。

### 3.8 MotW 可控机制（v1.2，P2 建行的效度前提）

MotW 即 `文件名:Zone.Identifier` ADS（`[ZoneTransfer]` + `ZoneId=3`=Internet）。主机侧 MotW 判定面（SmartScreen/Attachment Manager、Office 宏阻断、依赖 MotW 的 ASR 规则）**只读该 ADS，不关心写入者**——因此 lab 侧**带外合成标记**与真实投递在主机侧判定语义等价（全投递链保真差异见下）：

1. **机制**：`lab.stamp_motw`（lab 侧前置动作，非 Adapter 攻击动作）——投递载体落地后由 lab 通道**带外**写入 `Zone.Identifier`（ZoneId=3）；写入命令形态与断言见 `docs/labs/lab-mail-channel-requirements.md` §3。带外要求：不得经被评估攻击链内的进程执行，避免污染待评估进程树。
2. **断言**：ADS 回读内容匹配 + Sysmon EID15（FileCreateStreamHash）可见写入事件；断言失败 → 该 run 执行前层结果无效。
3. **投递来源三态标注**（run 台账必填）：`delivery=real-mail`（真实邮件通道，全保真）/ `delivery=motw-stamped(lab)`（合成标记，主机侧判定等价）/ `delivery=preset(no-MotW)`（预置投递，**不得用于执行前层评估**，仅执行中/执行后）。
4. **A/B 对照轴**：MotW 有/无为受控变量——有 MotW = 投递链评估（PH-IA01–06）；无/剥离 MotW = 攻击者规避变体评估（PH-BL09）。两者均为有效分母。
5. **保真边界（诚实登记）**：合成标记不产生浏览器/邮件客户端下载溯源遥测；个别依赖下载来源进程关联的厂商检测行为可能不同——结果按三态标注分层解释，不跨态比较。

---

## 4. MITRE 官方战术序对齐分组

> 本节是看板/报告阶段的**唯一权威战术映射**（对标 AD 矩阵 §5.5 的做法）。v1.0 覆盖 Execution / Privilege Escalation / Defense Evasion；v1.2 增 Initial Access；v1.4 增 Persistence 首行；v1.5 增 Persistence 余项（Run 键/计划任务）、主机立足点 Discovery、主机侧工具传入，以及高频混淆/反射加载行。其余战术的范围处置如下表。

| ATT&CK 官方战术（序） | 数据行 | 范围处置 |
|----------------------|-----------|---------|
| 1 Reconnaissance | — | 超出主机执行链（PRE 阶段归 AD 矩阵 R 族与后续批次） |
| 2 Resource Development | — | 超出主机执行链（基础设施侧，不入本矩阵） |
| 3 **Initial Access** | §5.0 六行（PH-IA01–IA06） | ✅ **P2 文件型载体已建行（v1.2）**；真实邮件通道全保真变体与浏览器下载路径见 §7（可选） |
| 4 **Execution** | §5.1 十一行（PH-EX01–EX11） | ✅ P0 执行引擎族（v1.4 增 PH-EX11 服务启动）。T1106 Native API **不另建执行行**：syscall 绕过归 PH-BL04；CreateProcess 等作为 EX/IN 实现路径 |
| 5 **Persistence** | §5.1a 三行（PH-PS01–PS03） | ✅ **P3**：服务创建、Run 键/启动文件夹、计划任务。T1546 / T1137 仍见 §7 |
| 6 **Privilege Escalation** | §5.2 七行（PH-PE01–PE07） | ✅ P0 提权族 |
| 7 **Defense Evasion** | §5.3 九行 + §5.4 两行 + §5.5 十行 + §5.6 九行 | ✅ P0 注入族/劫持代理族 + P1 致盲族/混淆族；v1.5 增 T1620 / T1027.009 / T1140 / T1112 |
| 8 Credential Access | — | 域侧行已在 AD 矩阵（HT-P01/P02 等），主机侧浏览器凭据（T1555.003）列 P3 候选。**不得**把 LSASS/SAM 在本矩阵重复建行 |
| 9 **Discovery** | §5.7 八行（PH-DI01–DI08） | ✅ v1.5：**仅主机立足点**（whoami/systeminfo/tasklist 等）。域侧 LDAP/账户/组枚举仍归 AD 矩阵 E 族，不重复建行 |
| 10 Lateral Movement | — | 域侧行已在 AD 矩阵（X 族），不重复建行 |
| 11 Collection / 14 Impact | — | 超出本矩阵主机执行链范围（含键盘记录 T1056.001） |
| 12 **Command and Control** | §5.8 一行（PH-IT01） | ✅ v1.5：**仅主机侧工具传入**（T1105 落地/下载摇篮）。通道画像 / beacon 仍归 C10（`comp.c2.beacon`），不并入本行评分 |
| 13 Exfiltration | — | 超出范围 |

> 多战术归属技术按 ATT&CK 官方列出的第一战术归组（T1055 → Defense Evasion；T1574 → Privilege Escalation；T1548 → Privilege Escalation；T1218/T1059/T1118/T1559 → Execution；T1105 → Command and Control），行内备注注明完整战术归属。

### 4.1 高频覆盖 TTP → PH 编号（插件校验用）

AEL「适合覆盖/转换（高频）」n≥3 且非后渗透的 T 号，按下表取 `ph_id`。插件 `intent.ph_ids` / oracle / Recipe 词汇表只允许本表「建行」列的 ID；「不建行」不得发明 PH。

| ATT&CK | 处置 | ph_id | 说明 |
|--------|------|-------|------|
| T1204.002 | 已有 | PH-IA02 | 用户执行恶意文件 |
| T1059.001 | 已有 | PH-EX01 | PowerShell |
| T1059.003 | 已有 | PH-EX02 | cmd |
| T1569.002 | 已有 | PH-EX11 | 服务启动 |
| T1543.003 | 已有 | PH-PS01 | 服务创建 |
| T1547.001 | v1.5 建行 | PH-PS02 | Run 键 / 启动文件夹 |
| T1053.005 | v1.5 建行 | PH-PS03 | 计划任务创建与运行（行内变体） |
| T1027 | 已有 | PH-OB01 | 脚本/文件混淆（-enc 等） |
| T1027.009 | v1.5 建行 | PH-OB08 | 嵌入载荷（构建期 embed） |
| T1027.013 | 已有 | PH-OB05 | 密文落地；**不得**记到 T1027/OB01 |
| T1140 | v1.5 建行 | PH-OB09 | 运行时解码 |
| T1112 | v1.5 建行 | PH-BL10 | 通用改注册表；Run/服务/任务键不归本行 |
| T1070.001 | 已有 | PH-BL06 | 清日志 |
| T1070.004 | 已有 | PH-BL08 | 文件删除 |
| T1620 | v1.5 建行 | PH-IN09 | 反射加载 PE；与 PH-IN08（T1055 父变体组）分桶 |
| T1105 | v1.5 建行 | PH-IT01 | 主机侧工具传入；不是 sidecar、不是 beacon |
| T1033 | v1.5 建行 | PH-DI01 | 主机用户发现 |
| T1082 | v1.5 建行 | PH-DI02 | 系统信息发现 |
| T1057 | v1.5 建行 | PH-DI03 | 进程发现 |
| T1083 | v1.5 建行 | PH-DI04 | 文件/目录发现 |
| T1016 | v1.5 建行 | PH-DI05 | 网络配置发现 |
| T1049 | v1.5 建行 | PH-DI06 | 网络连接发现 |
| T1007 | v1.5 建行 | PH-DI07 | 服务发现 |
| T1069.001 | v1.5 建行 | PH-DI08 | **本地**组；域组 T1069.002 仍归 AD 矩阵 |
| T1106 | 不另建行 | — | syscall 绕过 = PH-BL04；其余 Native API 是 EX/IN 实现路径 |
| T1003.001 / T1003.002 | 不建行 | — | AD 矩阵 HT-P01 / HT-P02 |
| T1555.003 | 不建行 | — | §4 P3 候选，本批仍不建 |
| T1005 / T1113 / T1119 / T1560.001 / T1056.001 | 不建行 | — | Collection 超范围 |

---

## 5. 覆盖矩阵（66 行契约）

### 5.0 Initial Access · 投递载体族（P2，v1.2 建行批，6 行）

> 效度前提 = MotW 可控机制（§3.8）：本族行的执行前层评估必须携带有效 MotW（`real-mail` 或 `motw-stamped(lab)` 三态之一）；`preset(no-MotW)` 仅可用于本族行的执行中/执行后层。

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-IA01 | T1566.001 | 宏文档投递落地（VBA 宏 / XLM / DDE / VBA stomping 变体注记） | endpoint | Sysmon EID11(文档落地) EID15(Zone.Identifier ADS); `Microsoft-Windows-Windows Defender/Operational` 1116/1117(static verdict); Office 宏策略状态（配置基线） | high | 需Sysmon/需实时防护/需ASR启用 | 中（宏载体是 AV 成熟面，新混淆持续对抗） | 执行前 | static,policy | E0/E1 | 办公文档落地即扫描 verdict + Zone.Identifier ADS 在位 + 宏策略拦截/通知 | MotW 断言见 §3.8；XLM/DDE/stomping 为行内变体不另建行 |
| PH-IA02 | T1204.002 | 用户执行恶意文件（启用宏 / 双击载体） | endpoint | Sysmon EID1(Office 父进程→解释器/控件派生链); Defender Operational 1121/1122(ASR 阻断/审计，如 Office 子进程与可执行内容规则) | high | 需Sysmon/需ASR启用 | 高（办公父进程派生是强信号） | 执行中 | behavior,policy | E0 | WINWORD/ONENOTE 等派生 cmd/powershell/控件加载 | 用户交互以授权执行替代真实点击（记 assumption） |
| PH-IA03 | T1221 | 远程模板注入（.dotm 远程拉取） | endpoint | Sysmon EID3(WINWORD 出站拉取模板) EID11(.dotm 落地) | partial | 需Sysmon | 中 | 执行中 | behavior,telemetry | E1 | 文档打开后即出站拉取模板文件并落盘 | — |
| PH-IA04 | T1566.001 | 容器投递（ISO/IMG/RAR 解包，含路径穿越变体注记） | endpoint | Sysmon EID15(容器 ADS) EID1(自虚拟盘符执行，命令行含盘符); 挂载遥测依 Windows 版本（VHDMP Operational，厂商相关） | partial | 需Sysmon | 中 | 执行前/执行中 | static,behavior | E0/E1 | 挂载盘符内执行 + MotW 继承状态对照（关联 PH-BL09） | 解包后 MotW 继承缺失本身是规避面（§3.8 A/B 轴） |
| PH-IA05 | T1566.001 | LNK 快捷方式投递（参数混淆/图标伪装） | endpoint | Sysmon EID11(.lnk 落地) EID15(ADS) EID1(explorer→解释器，命令行携带 LNK 注入参数) | high | 需Sysmon | 高（LNK 参数在命令行遥测直观测） | 执行中 | behavior | E0/E1 | 双击 LNK 后解释器命令行含混淆参数/远程地址 | — |
| PH-IA06 | T1566.001 | OneNote 附件（嵌入脚本执行） | endpoint | Sysmon EID11(.one 落地) EID1(ONENOTE 派生子进程) | high | 需Sysmon | 中（现代 OneNote 已收紧，版本相关） | 执行中 | behavior | E0 | ONENOTE.EXE 派生解释器/脚本宿主 | 版本基线入配置基线记录 |

### 5.1 Execution · 执行引擎族（P0，11 行）

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-EX01 | T1059.001 | PowerShell（-EncodedCommand / 下载执行 / 反射加载变体） | endpoint | Sysmon EID1(命令行) EID3; Windows 4104/4103/400·600; AMSI 内容经 amsi.dll 回调入 EDR 行为引擎 | high | 需Sysmon/需4104 | 高（命令行遥测成熟，-enc 可解码还原） | 执行中 | behavior,telemetry | E0–E2 | 解释器宿主异常父进程（winword/wscript→powershell）+ -enc/-nop/DownloadString | HT: windows-hardening/basic-powershell-for-pentesters（已核；含 Download & Execute、AMSI Bypass、Base64 节） |
| PH-EX02 | T1059.003 | Windows Command Shell（cmd /c 链、解释器接力） | endpoint | Sysmon EID1; Windows 4688 | high | 需Sysmon | 高 | 执行中 | behavior,telemetry | E0 | cmd.exe 由办公/LOLBin 父进程拉起、串联解释器 | HT: windows-hardening/basic-cmd-for-pentesters（已核） |
| PH-EX03 | T1059.005 | Visual Basic（vbs/wsf 经 wscript/cscript 宿主） | endpoint | Sysmon EID1(宿主) EID11(脚本落盘); AMSI 脚本内容 | high | 需Sysmon | 中（脚本内容可混淆；AMSI 可被 BL01 致盲） | 执行中 | static,behavior | E0/E1 | wscript/cscript 宿主 + 临时目录脚本写入配对 | HT: basic-cmd-for-pentesters（已核，脚本宿主节） |
| PH-EX04 | T1059.007 | JavaScript/JScript（js/jse） | endpoint | Sysmon EID1 EID11; AMSI | high | 需Sysmon | 中 | 执行中 | static,behavior | E0/E1 | .js/.jse 由邮件客户端/压缩上下文执行 | 同上 |
| PH-EX05 | T1218.005 | Mshta（内联 VBScript / 远程 .hta） | endpoint | Sysmon EID1(mshta 命令行含 http/内联) EID3 EID15 | high | 需Sysmon | 中（信号成熟） | 执行中 | behavior | E0 | mshta.exe 参数含 URL 或内联脚本、无窗口 HTA | LOLBAS: Binaries/Mshta（✅已核：T1218.005 执行/ADS/下载 + Sigma·Elastic 检测引用） |
| PH-EX06 | T1218.010 | Regsvr32（Squiblydoo：scrobj.dll + 远程脚本） | endpoint | Sysmon EID1(/i:http 参数) EID7(scrobj.dll) EID3 | high | 需Sysmon | 中 | 执行中 | behavior | E0/E1 | regsvr32 加载 scrobj.dll 且参数含远程地址 | LOLBAS: Binaries/Regsvr32（✅已核：`/i:{REMOTEURL:.sct} scrobj.dll`） |
| PH-EX07 | T1218.011 | Rundll32（序号入口/任意 DLL 调用） | endpoint | Sysmon EID1(EntryPoint 参数) EID7(非系统 DLL 加载) EID3 | high | 需Sysmon | 中 | 执行中 | behavior | E0/E1 | rundll32 加载用户目录 DLL 或按序号调用 | LOLBAS: Binaries/Rundll32（模式已核） |
| PH-EX08 | T1127.001 | MSBuild（内联任务执行载荷） | endpoint | Sysmon EID1(非项目目录/无参 msbuild) EID11(.csproj/.xml) EID3 | high | 需Sysmon | 中 | 执行中 | behavior | E1 | msbuild.exe 异常工作目录 + 内联任务文件落地 | LOLBAS: Binaries/Msbuild（模式已核）；每次构建天然变体（关联 PH-OB03） |
| PH-EX09 | T1118 | InstallUtil（经安装工具执行托管代码） | endpoint | Sysmon EID1(installutil 参数含 URL/Logfile) EID3 | high | 需Sysmon | 中 | 执行中 | behavior | E1 | installutil.exe 非安装上下文执行 | LOLBAS: Binaries/InstallUtil（模式已核） |
| PH-EX10 | T1559.001 | COM 自动化滥用（MMC20.Application/ShellWindows 等 DCOM） | endpoint | Sysmon EID1(异常 COM 客户端进程树) EID10; Windows 4688 | partial | 需Sysmon | 中（原语本身经 RPC，端点见副作用子进程） | 执行中 | behavior | E0/E2 | 办公进程→mmc/conhost 类异常派生链 | HT: lateral-movement/dcomexec（✅已核：MMC20.Application/ShellWindows/Excel DDE；本行取其本机执行语境） |
| PH-EX11 | T1569.002 | 系统服务执行（StartService / sc start / 等价 SCM 启动；WinAPI、RPC、NamedPipe 为行内变体） | endpoint | Sysmon EID1(ParentImage 为 services.exe 的服务映像启动); Windows 7036(服务进入 running) | high | 需Sysmon | 高（服务启动进程创建是默认端点遥测） | 执行中 | behavior,telemetry | E0 | services.exe 拉起非预期服务映像 | 与 PH-PS01 分桶：本行只评启动，不评服务创建；Windows 7045 归 PH-PS01。数据源 7036 已在审计 §A2 核对 |

### 5.1a Persistence · 主机持久化（P3，3 行）

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-PS01 | T1543.003 | 创建或修改 Windows 服务（CreateService WinAPI / SCM RPC / ntsvcs 命名管道为行内变体） | endpoint | Sysmon EID13(HKLM\SYSTEM\CurrentControlSet\Services 服务键写入) EID1; Windows 7045(服务安装) | high | 需Sysmon | 高（7045 默认产生；服务键写入成熟可检） | 执行后 | behavior,telemetry | E0/E1 | 新服务登记（7045）+ Services 注册表键写入 | P3 首行。不把启动事件记入本行（归 PH-EX11）。7045 已在审计 §A2 核对 |
| PH-PS02 | T1547.001 | Registry Run Keys / Startup Folder（HKCU/HKLM Run·RunOnce；用户 Startup 文件夹为行内变体） | endpoint | Sysmon EID13(HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run 或 RunOnce 写入) EID11(Startup 目录可执行/快捷方式落地) | high | 需Sysmon | 高（Run 键写入成熟可检） | 执行后 | behavior,telemetry | E0/E1 | Run/RunOnce 值写入或 Startup 目录落地 | 不把登录后派生当作 Harness 必过（无重启则评写入侧）。通用其它注册表键归 PH-BL10。数据源仅用 §A2 已核 EID13/EID11 |
| PH-PS03 | T1053.005 | 计划任务（ITaskFolder::RegisterTask / schtasks / COM；创建与 IRegisteredTask::Run 为行内变体） | endpoint | Sysmon EID13(HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache) EID11(%SystemRoot%\System32\Tasks 任务 XML) EID1(taskeng/svchost 拉起任务动作) | high | 需Sysmon | 高（TaskCache 写入成熟可检） | 执行后 | behavior,telemetry | E0/E1 | TaskCache 键写入或 Tasks 目录 XML 落地；运行为 taskeng 拉起动作进程 | 创建与运行同技术号、不另建行；变体 oracle 取本行子集。未见核的 4698/任务计划程序 106 不写入。T1546 / T1137 仍见 §7 |

### 5.2 Privilege Escalation · 提权族（P0，7 行）

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-PE01 | T1548.002 | UAC Bypass（fodhelper / computerdefaults / sdclt / eventvwr / silentcleanup；auto-elevate+DLL 劫持变体；Always Install Elevated 注记） | endpoint | Sysmon EID13(HKCU\Software\Classes\...\shell\open\command 写入) EID1(IntegrityLevel 跃升链); Windows 4688 | high | 需Sysmon | 高（注册表劫持模式成熟可检） | 执行后 | behavior | E0/E1 | 中完整性进程写 HKCU Classes 劫持键 + 随后 auto-elevate 进程启动 | HT: uac-user-account-control（✅已核：fodhelper 注册表劫持等）+ UACME（github.com/hfiref0x/UACME，60+ 方法变体目录；LOLBAS 无 UAC 目录——sdclt 无条目，见审计 §A3） |
| PH-PE02 | T1134.001 | Token Impersonation/Theft（含 SeImpersonate→Potato 族 / PrintSpoofer 命名变体） | endpoint | Sysmon EID1(IntegrityLevel) EID10; Windows 4672 | partial | 需Sysmon | 中（提权结果可见，令牌原语部分可见） | 执行后 | behavior | E0/E2 | 中完整性父派生高完整性子；服务账户上下文异常提权 | 变体名组；CVE 类 potato 利用延续方法论 defer 口径 |
| PH-PE03 | T1134.002 | Create Process with Token | endpoint | Sysmon EID1(异常父链+IntegrityLevel 跃升); Windows 4688/4672 | partial | 需Sysmon | 中 | 执行后 | behavior | E2 | 以他人令牌派生进程的父子异常 | — |
| PH-PE04 | T1134.003 | Make and Impersonate Token | endpoint | Sysmon EID1; Windows 4624(模拟登录序列) | partial | 需Sysmon | 中 | 执行后 | behavior | E2 | 认证后令牌复用的进程谱系异常 | — |
| PH-PE05 | T1134.004 | Parent PID Spoofing（PPID 伪造） | endpoint | Sysmon EID1(PPID 字段与进程谱系不匹配) | partial | 需Sysmon | 中（需进程属性遥测） | 执行后 | behavior,telemetry | E2/E3 | 已退出/不匹配父进程引用 | 本矩阵不把 ETW-TI 当作审计前置；A 侧 Sysmon-only profile 以 EID1 谱系交叉为准 |
| PH-PE06 | T1574.009 | Path Interception by Unquoted Path（服务路径截断） | endpoint | Sysmon EID11(截断路径可执行文件落地) EID1; Windows 7045(服务安装) | partial | 需Sysmon | 中 | 执行后 | behavior,static | E1 | C:\Program.exe 类中间路径二进制落地 + 服务启动 | — |
| PH-PE07 | T1574.001 | DLL Search Order Hijacking（提权语境：auto-elevate/服务目录劫持） | endpoint | Sysmon EID7(应用目录非预期 DLL 加载) EID11(DLL 落地) | high | 需Sysmon | 高（镜像加载×落地关联成熟） | 执行中/执行后 | static,behavior | E1 | 签名程序同目录恶意 DLL 落地并被加载 | 战术归属：提权/防御规避双列 |

### 5.3 Defense Evasion · 注入与内存执行族（P0/P3，9 行）

> T1055 官方战术归属 Defense Evasion/Privilege Escalation，按第一战术归本组。

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-IN01 | T1055.001 | CreateRemoteThread / SetWindowsHookEx | endpoint | Sysmon EID8(远程线程 TargetProcess+StartAddress) EID10 | high | 需Sysmon | 高（经典注入信号，EDR 主场） | 执行中 | behavior | E0 | 跨进程远程线程创建 + 可疑起始地址 | Sliver `migrate` 已有打点先例（details §3.8.8） |
| PH-IN02 | T1055.002 | Process Hollowing | endpoint | Sysmon EID25(ProcessTampering 映像不匹配) EID10 EID1 | high* | 需Sysmon≥14 | 高（EID25 直观测；旧版 Sysmon 降 partial） | 执行中 | behavior,static(内存) | E2 | 挂起进程映像与磁盘不匹配 | * 条件式：EID25 需 Sysmon v14+ |
| PH-IN03 | T1055.003 | Thread Execution Hijacking（线程上下文改写） | endpoint | Sysmon EID10 EID8 | partial | 需Sysmon | 中 | 执行中 | behavior | E2/E3 | 挂起目标线程 + 上下文改写访问序列 | — |
| PH-IN04 | T1055.004 | APC Injection（含 EarlyBird 变体） | endpoint | Sysmon EID1(创建挂起进程) EID10 | partial | 需Sysmon | 中 | 执行中 | behavior | E2 | CREATE_SUSPENDED + APC 排队访问组合 | A 侧功能真值以 Sysmon EID1×EID10 交叉为准，不要求 ETW-TI |
| PH-IN05 | T1055.011 | Extra Window Memory Injection（EWM） | endpoint | Sysmon EID10(跨进程 SetWindowLong 迹象) | partial | 需Sysmon | 低（通道少见于常规遥测） | 执行中 | behavior | E3 | 跨进程窗口属性写入后执行转移 | — |
| PH-IN06 | T1055.012 | Process Doppelgänging（事务落盘映像替换） | endpoint | Sysmon EID25 EID10 | partial | 需Sysmon≥14 | 低-中 | 执行中 | behavior | E3 | 事务管理器上下文中映像替换执行 | — |
| PH-IN07 | T1055.013 | Process Herpaderping（映像改写后执行） | endpoint | Sysmon EID25(执行时映像与磁盘不一致) EID11(哈希变更) | partial | 需Sysmon≥14 | 中 | 执行中 | behavior | E3 | 文件写后内容变更再执行 | — |
| PH-IN08 | T1055（父） | 命名变体组：映射注入（NtMapViewOfSection）/ Module Stomping / Callback 执行 / Unbacked RWX | endpoint | Sysmon EID10(跨进程映射) EID7(已加载 DLL 与磁盘不匹配); EDR 内存扫描(unbacked RWX 区域) | partial | 需Sysmon | 低-中（依变体） | 执行中 | behavior,static(内存) | E2–E4 | 无磁盘映像的可执行内存；已加载模块内容校验失败 | ATT&CK 未分配子技术号，按父技术+变体名登记（不虚构子号） |
| PH-IN09 | T1620 | Reflective Code Loading（内存反射加载 PE；与 callback 执行分桶） | endpoint | Sysmon EID10 EID7; EDR 内存扫描(无对应磁盘映像的可执行区) | partial | 需Sysmon | 低-中（反射加载常无独立 EID7） | 执行中 | behavior,static(内存) | E2–E4 | 无磁盘映像的 PE 映像在内存中出现 | 与 PH-IN08 分桶：本行评 T1620 反射加载；IN08 评 T1055 父技术命名变体。数据源仅用 §A2 已核 EID7/EID10 |

### 5.4 Defense Evasion · 劫持与代理执行族（P0/P1，2 行）

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-HJ01 | T1574.002 | DLL Side-Loading（签名程序侧载恶意 DLL） | endpoint | Sysmon EID7(签名 EXE 从临时路径加载非系统目录 DLL) EID11 EID1 | high | 需Sysmon | 高（旁加载检测是 EDR 成熟强项） | 执行前/执行中 | static,behavior | E1 | 签名程序异常路径启动 + 同名 DLL 落地加载 | Sliver `sideload` 已有打点先例（details §3.8.8） |
| PH-HJ02 | T1202 | Indirect Command Execution（forfiles / wmic /format / pcalua 等） | endpoint | Sysmon EID1(代理父进程→解释器子进程); Windows 4688 | high | 需Sysmon | 中 | 执行中 | behavior | E0/E1 | pcalua/forfiles 等代理父派生 cmd/powershell | LOLBAS: Binaries/Forfiles·Wmic·Pcalua（模式已核） |

### 5.5 Defense Evasion · 防御致盲族（P1/P3，10 行；效度规则见 §3.6）

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-BL01 | T1562.001 | AMSI patch/downgrade（AmsiInitFailed / CLR hook 变体） | endpoint | 致盲成功→4104/AMSI 内容遥测消失（对比基线）；`Microsoft-Windows-Windows Defender/Operational` 1116/1117 缺失 | partial | 需4104/需实时防护 | 低（**可致盲**） | 执行中 | behavior | E3 | 脚本遥测基线骤降/缺失 | HT: basic-powershell-for-pentesters#AMSI-Bypass（已核）；致盲生效时同期 not_detected→inconclusive（§3.6） |
| PH-BL02 | T1562.001 | ETW 致盲（EtwEventWrite patch） | endpoint | 用户态 ETW provider 静默消失（对比基线）；`Microsoft-Windows-Threat-Intelligence`(内核态难致盲) | partial | 需实时防护 | 低（**可致盲**） | 执行中 | behavior | E3 | 具名 provider 事件流骤停 | 同 AD 矩阵 §3.5 抗规避提醒先例 |
| PH-BL03 | T1562.001 | ntdll unhook（磁盘 \KnownDlls 新拷贝还原） | endpoint | Sysmon EID7(ntdll 自非常规路径重复加载) EID11(落地副本) | partial | 需Sysmon | 中（落地/加载可见；内核回调不受影响） | 执行中 | behavior | E3 | ntdll.dll 副本落地并加载 | 构建归授权后端（details §6 先例） |
| PH-BL04 | T1562.001+T1106 | 直接/间接系统调用（用户态 hook 结构性绕过） | endpoint | 用户态 API 遥测失效；Sysmon 内核回调仍见副作用 EID1/EID8/EID10 | partial | 需Sysmon | 中（内核回调仍在） | 执行中 | behavior,telemetry | E3 | API 级遥测缺失但进程/线程事件仍在 | 实现类 SysWhispers 归授权后端（details §6） |
| PH-BL05 | T1562.001 | 安全工具停用/篡改（服务停止 / 驱动卸载 / Tamper Protection 对抗） | endpoint | `Microsoft-Windows-Windows Defender/Operational` 5001(实时防护关闭)/5007(配置变更); System 7036; Security 1102; Sysmon EID1(sc/net stop) | high | 需TamperProtection | 高（停用行为本身高可见；TP 开启时阻断） | 执行后 | behavior,policy | E3/E4 | 安全服务状态变更/防护配置回退 | HT: Windows Security Controls（Defender check/bypass 节，已核） |
| PH-BL06 | T1070.001 | 事件日志清除（wevtutil cl / ClearEventLog） | endpoint | Security 1102; System 104; Sysmon EID1(wevtutil) | high | 默认 | 高（1102 自身高可见，SIEM 关键信号） | 执行后 | telemetry,behavior | E0 | 日志清除事件本身即告警级信号 | — |
| PH-BL07 | T1070.006 | Timestomp（时间戳伪造） | endpoint | Sysmon EID2(文件创建时间变更) | high | 需Sysmon | 高（EID2 直观测） | 执行后 | behavior | E1 | 落地载荷时间戳回拨/前跳 | — |
| PH-BL08 | T1070.004 | 文件删除 / 载荷自删除 | endpoint | Sysmon EID1(del 命令行) EID23/26(需 Sysmon 配置开启删除日志) | partial | 需Sysmon | 中 | 执行后 | behavior,telemetry | E1 | 执行后立即自删的进程行为 | EID23/26 依赖 sysmon 配置，未开启降 inconclusive |
| PH-BL09 | T1562.001（关联） | MotW 剥离 / 不继承（Unblock-File、ADS 删除、容器解包继承缺失——攻击者规避变体） | endpoint | Sysmon EID15 对照基线（应带 Zone.Identifier 的文件缺失 ADS）; 厂商相关（依赖下载溯源的 EDR 行为） | partial | 需Sysmon | 低-中（依厂商） | 执行前 | behavior,telemetry | E1/E3 | 落地文件 Zone.Identifier 缺失异常（对照投递通道预期） | ATT&CK 无专号，T1562.001 关联登记（同 PH-IN08 口径）；A/B 轴的「无 MotW」侧（§3.8.4）；v1.2 建行 |
| PH-BL10 | T1112 | Modify Registry（通用注册表修改；非 Run/服务/任务键） | endpoint | Sysmon EID13(注册表值写入) | partial | 需Sysmon | 低（高噪；需键路径约束才可归因） | 执行后 | behavior,telemetry | E1 | 非持久化专用路径的注册表值写入 | Run/RunOnce 归 PH-PS02；服务键归 PH-PS01；TaskCache 归 PH-PS03；注册表 blob 存储归 PH-OB04。变体 oracle 必须限定 TargetObject，禁止把任意 EID13 当本行过线 |

### 5.6 Defense Evasion · 混淆与免杀族（P1/P3，9 行）

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-OB01 | T1027 | 混淆文件/信息（PowerShell -enc / base64 / 变量重排） | endpoint | Windows 4104(脚本块含可解码混淆); Sysmon EID1(-enc 命令行) | high | 需4104 | 中（对抗静态、遥测可见） | 执行中 | static,behavior | E1 | 脚本块解码后内容与告警关联 | — |
| PH-OB02 | T1027.002 | 加壳/打包 | endpoint | 静态特征(节区/熵)→EDR 云查询/本地 ML verdict; Sysmon EID11(落地) 关联 | partial | 需实时防护 | 中（壳识别是 AV 成熟面，新壳对抗持续） | 执行前 | static | E1/E3 | 落地文件高熵/壳签名 verdict | 构建产物归授权后端 |
| PH-OB03 | T1027.004 | 编译后交付（重编译破 IOC） | endpoint | Sysmon EID11(新哈希落地，无历史 verdict→云 verdict 待定); 台账 sha256 每次变更 | partial | 需实时防护 | 中（云 detonation 是对抗面，关联 P3 反分析族） | 执行前 | static | E1 | 未知哈希触发云查询/沙箱流程 | 对应 E1 档（重命名+重编译）语义 |
| PH-OB04 | T1027.011 | 无文件存储（注册表 blob / ADS） | endpoint | Sysmon EID13(注册表 blob 写入) EID15(ADS 流) EID1(读取后执行) | partial | 需Sysmon | 中 | 执行中 | behavior | E2 | 注册表大值写入 + 随后解释器读取执行 | — |
| PH-OB05 | T1027.013 | 加密/编码落地（运行时解密执行） | endpoint | Sysmon EID11(密文落地)+EID1(解密后执行/注入链); 内存扫描解密后载荷 | partial | 需Sysmon/需实时防护 | 中 | 执行中 | static(内存),behavior | E2/E3 | 密文文件 + 运行时内存明文载荷 | — |
| PH-OB06 | T1036.005 | 伪装合法名称/路径（非系统目录 svchost 等） | endpoint | Sysmon EID1(映像路径与系统进程名不匹配) EID7 | high | 需Sysmon | 高（路径校验成熟） | 执行前/执行中 | behavior,static | E0/E1 | 系统进程名出现在用户目录 | — |
| PH-OB07 | T1036.007 | 双扩展名（附 T1036.008 RTL override 注记） | endpoint | Sysmon EID11(文件名模式 xxx.pdf.exe / U+202E) EID15 | high | 需Sysmon | 中（现代客户端常已策略拦截） | 执行前 | static,policy | E0 | 双扩展/RTL 字符文件落地 | policy 层结果依赖客户端配置基线（§3.5） |
| PH-OB08 | T1027.009 | Embedded Payloads（构建期静态嵌入；提取落盘为行内变体） | endpoint | Sysmon EID11(从宿主提取后的载荷落地); 静态特征(嵌入节区/资源) | partial | 需Sysmon | 中（对抗静态、提取时可见落地） | 执行前 | static,behavior | E1 | 宿主文件内嵌载荷或提取后新文件落地 | 构建期 embed，不是运行时 PH-OB05 密文落地。无提取动作时 A 侧可以静态合同为主，EID11 为提取变体必过 |
| PH-OB09 | T1140 | Deobfuscate/Decode Files or Information（运行时解密/解码） | endpoint | Sysmon EID1(解码后执行链) EID11(明文落盘子路径) | partial | 需Sysmon | 中（内存解码常无独立落地事件） | 执行中 | behavior,static(内存) | E2 | 解码后执行或明文落盘 | loader（如 SystemFunction033）绑定本行；随后注入归 IN* 行。与 PH-OB05（密文落地）分桶 |

### 5.7 Discovery · 主机立足点发现（P3，8 行）

> 仅评**本机**发现命令/等价 API 的端点副作用。域侧 LDAP / 账户 / 域组枚举仍归 AD 矩阵 E 族（§6），不在本表重复建行。进程内 Native API 若无子进程，EID1 可能缺失 → `inconclusive`，不得记 `not_detected`。

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-DI01 | T1033 | System Owner/User Discovery（whoami / query user 为行内变体） | endpoint | Sysmon EID1(whoami/query 命令行) | high* | 需Sysmon | 中（CLI 高可见；进程内 GetUserName 可能无 EID1） | 执行中 | behavior,telemetry | E0 | whoami 或 query user 进程创建 | * 条件式：无子进程变体降 inconclusive |
| PH-DI02 | T1082 | System Information Discovery（systeminfo / hostname） | endpoint | Sysmon EID1(systeminfo/hostname 命令行) | high* | 需Sysmon | 中 | 执行中 | behavior,telemetry | E0 | systeminfo 或 hostname 进程创建 | * 同上 |
| PH-DI03 | T1057 | Process Discovery（tasklist / Get-Process） | endpoint | Sysmon EID1(tasklist 或 powershell Get-Process) | high* | 需Sysmon | 中 | 执行中 | behavior,telemetry | E0 | tasklist / 枚举进程的解释器命令行 | * 同上 |
| PH-DI04 | T1083 | File and Directory Discovery（dir / Get-ChildItem） | endpoint | Sysmon EID1(cmd dir 或 powershell Get-ChildItem) | high* | 需Sysmon | 中 | 执行中 | behavior,telemetry | E0 | 目录枚举命令行 | FindFirstFile 进程内无 EID 则 inconclusive |
| PH-DI05 | T1016 | System Network Configuration Discovery（ipconfig / Get-NetIPAddress） | endpoint | Sysmon EID1(ipconfig 等) | high* | 需Sysmon | 中 | 执行中 | behavior,telemetry | E0 | ipconfig 或等价网络配置查询进程 | * 同上 |
| PH-DI06 | T1049 | System Network Connections Discovery（netstat / Get-NetTCPConnection） | endpoint | Sysmon EID1(netstat 等) | high* | 需Sysmon | 中 | 执行中 | behavior,telemetry | E0 | netstat 或等价连接表查询进程 | * 同上 |
| PH-DI07 | T1007 | System Service Discovery（sc query / Get-Service） | endpoint | Sysmon EID1(sc.exe query 或 powershell Get-Service) | high* | 需Sysmon | 中 | 执行中 | behavior,telemetry | E0 | sc query / Get-Service 命令行 | 与 PH-PS01 创建、PH-EX11 启动分桶：本行只评枚举 |
| PH-DI08 | T1069.001 | Permission Groups Discovery: Local Groups（net localgroup / Get-LocalGroup） | endpoint | Sysmon EID1(net localgroup 或 Get-LocalGroup) | high* | 需Sysmon | 中 | 执行中 | behavior,telemetry | E0 | 本地组枚举命令行 | **不是** T1069.002 域组（AD 矩阵）。不得把 LDAP 枚举记入本行 |

### 5.8 Command and Control · 主机侧工具传入（P3，1 行）

> 只评受害主机上的**传入/落地**，不评 C2 通道画像。beacon / 协议评分仍归 C10。

| ph_id | ATT&CK | 技术名 / 落地变体 | 检测定位 | 数据源 | 端点可见性 | 审计前置 | 保真度 | 评测阶段 | 检测层 | evasion_tier | 期望信号 | 备注 / 实践引用 |
|-------|--------|------------------|----------|--------|------------|----------|--------|----------|--------|-------------|----------|----------------|
| PH-IT01 | T1105 | Ingress Tool Transfer（certutil / bitsadmin / IWR / copy 落地；WinHTTP 为行内变体） | endpoint | Sysmon EID1(下载/复制命令行) EID11(工具/载荷落地) EID3(出站拉取) | high | 需Sysmon | 中（CLI 摇篮成熟可检；内存下载可能无 EID11） | 执行中 | behavior,telemetry | E0/E1 | 下载摇篮命令行 + 新文件落地 | 不是构建期 sidecar，也不是 `comp.c2.beacon`。EID3 出站为拉取变体信号，不作通道评分 |

---

## 6. 与 AD 矩阵的去重与衔接

1. **不重复建行**：AD 矩阵已覆盖的域侧行为（LSASS 访问 HT-P01、SAM 提取 HT-P02、票据族、委托族、DCSync 等）不在本矩阵重复建行；钓鱼链战役推进到域内阶段后直接引用 AD 矩阵 ht_id。
2. **衔接点**：C9 战役轴（`camp.delivery.exec`）产出 `assumed_breach` 后衔接 C1 域链（方法论 §7），本矩阵为该衔接点之前的执行链提供分母。
3. **重叠技术的归属裁决**：HT-P14（第三方会话滥用，T1550+T1055 父技术）保留在 AD 矩阵；本矩阵 PH-IN* 行以子技术粒度展开，引用 HT-P14 作为父先例。
4. **C2 面**：通道画像（`comp.c2.beacon` / C10）保持独立。v1.5 仅将 **主机侧工具传入** 建为 PH-IT01（T1105 落地/下载摇篮），不把 beacon 协议并入本矩阵评分。
5. **Discovery 面**：v1.5 主机立足点发现建 PH-DI01–DI08；域侧 LDAP/账户/域组仍只引用 AD 矩阵 E 族。T1069.001（本地组）≠ T1069.002（域组）。

---

## 7. 后续批次规划（不建行，仅登记）

| 批次 | 技术族 | 候选技术（ATT&CK ID，待建行时逐行核对官方 Data Sources） | 前置 |
|----|--------|--------------------------------------------------------|------|
| **P2 余项** | 真实邮件通道全保真变体（Outlook 客户端投递链遥测、下载溯源关联）与浏览器下载路径 | §5.0 各行的 `delivery=real-mail` 对照变体（不新增技术行，按三态标注分层报告） | 邮件通道（`docs/labs/lab-mail-channel-requirements.md`，**可选保真升级**，非建行阻塞——MotW 可控机制已就绪，§3.8） |
| **P3** | 主机持久化族（余项） | T1546.003/.008/.009/.010/.011/.012/.013/.015、T1137.001–.006 | T1543.003 / T1547.001 / T1053.005 已建 PH-PS01–PS03；T1569.002 已入 §5.1 PH-EX11。域持久化行已在 AD 矩阵 |
| **P3** | 反分析族（针对 EDR 云沙箱） | T1497.001/.002/.003 | 与 PH-OB03 联动 |
| **P3** | 主机侧凭据 | T1555.003 | 域侧凭据已在 AD 矩阵；本批仍不建行 |
| **P3** | 客户端漏洞利用型打点 | T1203 族 | 延续方法论 P2 Contract Gap defer（methodology §7 P2） |

---

## 8. 修订记录

| 日期 | 版本 | 说明 |
|------|------|------|
| 2026-08-25 | v1.0 | 首版：42 行契约（P0=27 行：EX10+PE7+IN8+HJ2；P1=15 行：BL8+OB7）；MITRE 官方战术序对齐分组 §4；分层评分语义 §3.3；致盲效度规则 §3.6；P2/P3 规划槽 §7。血缘已核页：HT basic-powershell-for-pentesters、basic-cmd-for-pentesters、Windows Security Controls（Defender 节）；LOLBAS 为代理执行语法权威（HT 无专页）。待核项见审计 §A3 |
| 2026-08-25 | v1.1 | 实践引用逐项落地（用户补充指示）：LOLBAS 行改引具体条目 `lolbas-project.github.io/lolbas/Binaries/<Name>/`（Mshta/Regsvr32 实抓已核，其余按同站路径规范模式已核）；PH-PE01 引 HT UAC 专页（已核）+ **UACME 变体目录**（60+ 方法，ATT&CK T1548.002 官方页引用；LOLBAS 无 UAC 目录——sdclt 404 证实）；PH-EX10 引 HT dcomexec 页（已核）。**42 行契约不变**，仅备注/血缘列变更；核验详情见审计 §A3 |
| 2026-08-25 | v1.2 | **P2 文件型投递载体建行批**（用户提出 MotW 合成标记机制解除阻塞）：新增 §3.8 MotW 可控机制（`lab.stamp_motw` 带外写入 + 断言 + 投递来源三态 + A/B 对照轴）；新增 §5.0 投递载体族 6 行（PH-IA01–IA06：宏文档/用户执行/远程模板注入/容器/LNK/OneNote，Initial Access 战术按官方序前插）；§5.5 增 PH-BL09（MotW 剥离/不继承，T1562.001 关联登记）；**行数契约 42→49**；§7 改为「P2 余项（邮件通道=可选保真升级，非阻塞）+ P3」。数据源新增依据见审计 §A6 |
| 2026-09-08 | v1.3 | **取消钓鱼链行的 ETW-TI 审计前置**（49 行契约不变）：PH-PE05 / PH-IN01 / PH-IN03–IN06 / PH-IN08 的 数据源与 `需ETW-TI` 不再把 `Microsoft-Windows-Threat-Intelligence` 当作过线条件；审计前置收束为 §3.4 已列取值（`需Sysmon` / `需Sysmon≥14`）。A 侧 no-EDR profile 以 Sysmon（或 CAPE）为功能真值，缺 TI 不得因此 `inconclusive`。PH-BL02 仍描述用户态 ETW 致盲现象，但其审计前置本就不是 `需ETW-TI`。AD 矩阵域内行未改 |
| 2026-09-08 | v1.4 | **P3 服务族首批建行**（**行数契约 49→51**）：新增 §5.1 PH-EX11（T1569.002 系统服务执行）与 §5.1a PH-PS01（T1543.003 创建/修改 Windows 服务）。WinAPI / SCM RPC / ntsvcs 命名管道为行内变体，不另建行。创建与启动分桶（7045/EID13 归 PS01，7036/services.exe 子进程归 EX11）。数据源 7036/7045/EID13 已在审计 §A2 核对；未见核的 EID12 不写入。UAC 同意提示（ShellExecuteEx runas）与 AdjustTokenPrivileges 不绑 PE 行。其余持久化（T1547.001 / T1053.005 / T1546 / T1137）与反分析/T1203 仍见 §7 |
| 2026-09-11 | v1.5 | **P3 高频覆盖建行批**（**行数契约 51→66**）：新增 PH-PS02（T1547.001）、PH-PS03（T1053.005）、PH-DI01–DI08（主机立足点发现）、PH-IT01（T1105 主机侧工具传入）、PH-IN09（T1620）、PH-OB08（T1027.009）、PH-OB09（T1140）、PH-BL10（T1112）。数据源只复用审计 §A2 已核 EID（1/3/7/10/11/13），不写入 4698 等未见核事件。T1106 不另建执行行；LSASS/SAM/Collection/域发现不建行。对照表见 §4.1 |
| 2026-10-17 | v1.5.1 | **`PH` 缩写正式释义：** Procedure / Host（主机侧可复现步骤）。废止「Phishing / 钓鱼链」作为前缀词源；权威文件由 `phishing-ttp-coverage-matrix.md` 重命名为 `procedure-host-ttp-coverage-matrix.md`；**66 行数据契约与行 ID 不变** |
