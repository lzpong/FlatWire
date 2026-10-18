# FlatWire Protocol v4.4 —— fw-c 实现协议一致性审查报告

- 审查对象：`d:\E\FlatWire\implementations\fw-c\`（38 个 C/H 源文件 + tests + examples）
- 规范唯一事实来源：`FlatWire Protocol (FW) Design.v4.md`（v4.4，全文 1379 行逐节核对）
- 一致性基准：`FlatWire Protocol (FW) Test Cases.v4.md`（9 大类逐条对照）
- 行为基准：`implementations\fw-nodejs`（同名模块逐个交叉对照）
- 审查日期：2026-10-18
- 审查角色：协议一致性审查工程师（只读审查，未改动仓库任何源文件）

---

## 1. 总览

### 1.1 审查范围与方法

- **全量源码通读**：include/fw/fw.h、src/fw_int.h、frame/、codec/（crc/codec/schema）、transport/（tcp/udp）、platform/、sd/（discovery/entries）、rpc/（rpc/retransmit）、events/、strm、idlstore、stack、json、value、logger 全部读完。
- **条款核对**：15 项高危条款逐条与规范原文对照，给出 文件:行号 证据。
- **跨栈对照**：fw-nodejs 的 frame.js / tcp.js / udp.js / stack.js / discovery.js（onSubscribe/unsubscribe/onRen/fetchIdl/onOffer/onFind）/ rpc.js / events.js / udp.js 与 C 同名模块逐段比对。
- **实测验证**：验证程序写入 `%TEMP%\fw_review\`（未触碰仓库），链接 `build\libfw.a`（`gcc -I include -lws2_32`），四轮运行：
  - V1 反复 subscribe/unsubscribe 130 轮 → 检测控制 StrmID 池耗尽；
  - V2 服务端 70 实例 + 客户端晚启动（只靠批量 Offer/Find 响应）→ 检测发现完整性；
  - V3 `fw_encode_payload`：接口 `max_payload=20` + `crc=true` + Data 恰 20B → 检查最终 payload 长度；
  - V4 `fw_frame_encode` 无 mask_key 时观测 MSK key 实际字节形态。
- **测试覆盖评估**：tests/ 11 套件 60 个 TEST_BEGIN 与基准 9 大类逐条对照。

### 1.2 基线确认

构建 0 警告、ctest 全过（11 套件）、C↔C 六链路、C↔JS 互通与本报告结论不冲突；本报告新发现的问题均在既有测试盲区。

### 1.3 结论先行

- **P0：无**（无协议级致命违反、无数据损坏路径、无必然崩溃）。
- **P1：2 项**（unsubscribe 会话 StrmID 泄漏；批量 SD Entry 接收截断）——均实测复现。
- **P2：6 项、P3：12 项**。
- 15 项高危条款：13 项符合、2 项"部分"（第 7 条 StrmID 生命周期受 P1-1 破坏；第 8/13 条受 P1-2/P2-1 边缘影响，主体符合）。
- **建议：先修复 2 项 P1 与 P2-1/P2-2，再补充 E 节测试缺口（GetIDL 场景矩阵与订阅确认链路几乎无 C 测试）。**

---

## 2. 15 项高危条款逐条核对表

| # | 条款 | 结论 | 证据（文件:行号）与说明 |
|---|------|------|------------------------|
| 1 | CRC-16/CCITT-FALSE | **符合** | [crc.c](d:\E\FlatWire\implementations\fw-c\src\codec\crc.c#L15-L27)：poly=0x1021/init=0xFFFF/refin=refout=false/xorout=0；自检 0x29B1（tests/t_crc.c 1.31 通过）。仅数据帧 + 接口契约 `crc` 启用（[schema.c:262](d:\E\FlatWire\implementations\fw-c\src\codec\schema.c#L262)、[codec.c:516-521](d:\E\FlatWire\implementations\fw-c\src\codec\codec.c#L516-L521)）；发送先 CRC（2B 大端）后整体 XOR（[codec.c:517-521](d:\E\FlatWire\implementations\fw-c\src\codec\codec.c#L517-L521) + frame.c encode），接收相反且校验先于字段解码（[codec.c:532-538](d:\E\FlatWire\implementations\fw-c\src\codec\codec.c#L532-L538)）。CRC 覆盖范围 = Data Fields ✓。**边缘偏差见 P2-1（max_payload 校验在 CRC 附加前）** |
| 2 | 控制帧固定 MSK=0、不附加 CRC | **符合** | 解析侧 [frame.c:134-138](d:\E\FlatWire\implementations\fw-c\src\frame\frame.c#L134-L138)（CTR=1 且 MSK=1 → RST(0x00)，测试 2.29）；发送侧全部控制帧构造均未置 msk（discovery/rpc/stack 各帧构造点），控制帧 payload 无 CRC 附加路径 |
| 3 | §4.3 十步解析顺序 | **符合** | [frame.c:106-260](d:\E\FlatWire\implementations\fw-c\src\frame\frame.c#L106-L260) 按序：VER（组播静默/单播 0x22）→ REN/CTR → 控制帧 MSK → REN TYP/Code → ACK/RST Code+PLB → TCP 禁 CON/ACK → UDP 禁 GetIDL(0x04) → SvcID/IfID → InstID/StrmID 范围与语义（含 RST 豁免、ACK(0x00) 取消确认回显会话 StrmID 例外，L200-223）→ Length/max_payload_len(0x23) → Mask → Data。测试 2.6~2.21/2.29、5.15、5.25 全覆盖。两处实现裁定（对齐 fw-nodejs）：RST 帧 StrmID 豁免（L200-204，防互射风暴）、UDP 组播启发式（udp.c L138，平台无法读目的地址） |
| 4 | TCP 半帧两阶段 | **符合** | [tcp.c:391-417](d:\E\FlatWire\implementations\fw-c\src\transport\tcp.c#L391-L417)：阶段一（帧头不完整）RST(0x26)+关连接；阶段二 RST(0x26)+[fw_sp_enter_drop_mode](d:\E\FlatWire\implementations\fw-c\src\frame\frame.c#L474-L484)（R=L−已收，收满恢复/EOF 随连接/兜底 2×tcp_frame_timeout_ms 且 conn_read 每收字节刷新 L334）。发送端收 RST(0x26)：rpc.c on_data_rst 标记失败（FW_ERR_RST）不再重传（retransmit_cancel L434），TCP 字节流机械发完（无法撤销）。测试 2.5/2.22~2.28 全覆盖（t_tcp.c/t_stream.c） |
| 5 | UDP CON 重传时间线 | **符合** | [retransmit.c:66-83](d:\E\FlatWire\implementations\fw-c\src\rpc\retransmit.c#L66-L83)：next=interval×2^retries → 实测时间线 0/200/600/1400ms、3000ms 静默清理（tests/t_retrans.c 3.10~3.12 验证）。response_timeout_ms=2000 唯一终态（rpc.c fw_rpc_tick L693-711）。去重键 `(peer,svc,inst,StrmID)`（rpc.c key 构造）。服务端重复 CON 重发缓存响应不重执行（[rpc.c:491-502](d:\E\FlatWire\implementations\fw-c\src\rpc\rpc.c#L491-L502)）；客户端重复响应按 StrmID 丢弃且 CON 仍回 ACK（[rpc.c:368-371](d:\E\FlatWire\implementations\fw-c\src\rpc\rpc.c#L368-L371)） |
| 6 | TCP 全 NON + 心跳 | **符合** | 解析层拒绝 TCP CON/ACK（frame.c L162-166）；心跳 [tcp.c:420-439](d:\E\FlatWire\implementations\fw-c\src\transport\tcp.c#L420-L439)：空闲超 period 发 Ping、收 Ping 不回（stack.c 分发 default 静默）、2×period 未收帧判死；last_send_ms 由 fw_tcp_conn_write 刷新（有业务流量不发 Ping）。**测试缺口：3.19~3.23 无任何用例（见 §5）** |
| 7 | StrmID 规则 | **部分** | 分配/回绕/冷却/隔离符合（[strm.c](d:\E\FlatWire\implementations\fw-c\src\strm.c)，测试 4.1/4.2/4.5、冷却语义用例通过）；控制帧 0x01~0x7F 同池（ctrl_pool L114-130）、连接级帧 StrmID≠0 → RST(0x00)（frame.c L214-222）、数据帧 0x01~0xFE（L228）。**违反点：P1-1 unsubscribe 后会话 StrmID 不释放/不冷却，破坏 §6.1"取消确认到达后释放/冷却"生命周期（实测 130 轮后池耗尽）** |
| 8 | SD Entry 布局 | **部分** | [entries.c](d:\E\FlatWire\implementations\fw-c\src\sd\entries.c)：Offer 6B/Find 4B/Subscribe 7B/GetIDL 3B、大端、GetIDL 无 InstID、Subscribe 组合校验（discovery.c L565、stack.c L621）全部符合（测试 5.5/5.6）；Offer 拆帧按 1400 满装、Entry 粒度 (SvcID,InstID)（[discovery.c:138-157](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L138-L157)，测试 5.11）。**违反点：P1-2 接收端 Entry 解析 64/32 上限 < 拆帧上限 233/帧，批量 Entry 被静默丢弃（实测 70 实例仅发现 63）** |
| 9 | GetIDL 仅 TCP 单播 | **符合** | 传输绑定违规由解析层拒绝（frame.c L167-172，UDP → RST(0x00)，测试 5.25）；服务端按 (SvcID,MajorVer) 匹配**已加载定义**、与实例在线无关（[discovery.c:676-685](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L676-L685)，5.23/5.35 语义）；Payload≠3B 或 SvcID=0 → RST(0x20)（L669-675）；响应回显 StrmID、Payload=IDL JSON 原文（L686-696）；查询超时复用 response_timeout_ms（L1110-1111）、失败上抛不重发（fw_disc_fetch_idl L1206-1215，对齐 JS 定案）；发现缓存无在线实例不发起（query_start L1154-1160 / fw_disc_query_attach L1366-1373）；同 (SvcID,MajorVer) 并发合并（L1146-1153）；迟到的 0x11/RST 按非活跃 StrmID 静默丢弃（L1061、L996） |
| 10 | 纯动态架构/双角色统一拉取 | **符合** | 启动扫描 [store.c:99-125](d:\E\FlatWire\implementations\fw-c\src\idlstore\store.c#L99-L125)（损坏文件跳过不阻塞）；call 状态机自动拉取（rpc.c L169-187）、订阅预拉取（stack.c ensure_idl_for_subscribe L532-539，后台化对齐 JS）、register_service 自动拉取（[stack.c:476-498](d:\E\FlatWire\implementations\fw-c\src\stack.c#L476-L498)）；响应自含 svc_id/major_ver 校验（discovery.c L1010-1030）；落盘持久化、失败降级内存（[store.c:155-173](d:\E\FlatWire\implementations\fw-c\src\idlstore\store.c#L155-L173)）；本地命中不重复查询（rpc.c L170 `fw_idl_get` 命中即用）；无 get_service_idl API ✓；测试 5.21/5.28 覆盖主链路 |
| 11 | 订阅确认 | **符合** | Subscribe(TTL>0) 有/无缓存一律 ACK(0x10)（[discovery.c:617-620](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L617-L620)，`is_con` 分支不依赖缓存）；重复 CON 重发缓存确认不重推全量（L521-533 + 6.10 语义）；TTL=0 → ACK(0x00) 回显会话 StrmID（L619、send_sub_ack L467）；全量推送纯数据分发（L621-624 → fw_events_push_cached_for）；合并 Subscribe 逐 Entry、无效 Entry 丢弃+日志、整帧不可解析 RST(0x20)（L508-514、L562-571）；tcp-event 须预建连接否则 RST(0x24)（L548-558）、按订阅者源 IP 匹配连接（events.c push_to_one L72-82）、断连订阅不失效（conn_closed_notify 注释 + 不清 subs） |
| 12 | 订阅登记清除仅两路径 | **符合** | 显式 unsubscribe（fw_disc_unsubscribe）∪ 对端 REN（fw_disc_on_ren L1252-1291 同步清 session+subs+ack）；过期自动重订阅用新 StrmID（pause_sessions_of 释放旧 strm → transition_found 重分配，L160-173/L271-311）；Offer TTL 刷新为实例级（fw_disc_on_offer L359-367）；TTL=0/归零延迟到 tick 移除（fw_disc_tick L201-256） |
| 13 | 错误码两层两码 | **部分** | 帧级 max_payload_len 仅 UDP → 0x23（frame.c L236-240，测试 2.8）；IDL 级违约统一映射 0x20（fw_int.h FW_DEC_* → rpc.c send_rst(FW_RST_BAD_REQUEST)，TCP/UDP 一致）；服务不存在 0x24、处理异常 0x30、Code 不支持 0x25（rpc.c L522-529）；RST Code ∈{0x00}∪0x20~0x3F（frame.c L155-161，测试 2.20）；数据帧 0x11~0x1F 保留（stack.c CTR=0 default 静默）。**边缘偏差：P2-1 接口级 max_payload 语义（含 CRC 后的总 Payload）未闭环** |
| 14 | 恒定宽度编码 | **符合** | [codec.c](d:\E\FlatWire\implementations\fw-c\src\codec\codec.c)：signed/unsigned low4==size（L341/L362 SizeMismatch，测试 1.32）、low4=0 非法（L339/L360，1.9/1.10）、大端；null 仅 optional（L327 UnexpectedNull，1.33）、bool 严格（L333，1.6）、float low4∈{1,2}（80bit 不支持，README 偏差 6 与 JS 一致）、fixed_len 恰等（check_len L85-89，1.18/1.19/1.21/1.35）、编码不自动补齐空位（§9.2 构造方实例化 N 长语义）、解码容忍末尾新增字段（struct 分支 L313，测试 9.1）、timestamp 高 4bit+低 40bit（L185-192，1.13）、数组 0~14 内联/15 扩展（L435-456）。size>8 不支持（FW_INT_SIZE_MAX，README 偏差 6；JS BigInt 支持——跨栈差异已声明） |
| 15 | 部署语义 | **符合** | REN×3 组播间隔 ~100ms 先发后关（[stack.c:248-270](d:\E\FlatWire\implementations\fw-c\src\stack.c#L248-L270)，测试 4.6 语义、集成 8.4）；收 REN 清服务缓存+活跃表+重传记录+订阅登记（fw_stack_on_frame L348-356 → disc/rpc/events/strm 四模块）；组播 224.0.1.187（IP_MULTICAST_TTL 未显式设置=系统默认 1 ✓）、IP_MULTICAST_LOOP 开启（udp.c L35/L53）；单实例（部署约束）；启动立即发空 Payload Find 预热（[stack.c:235-242](d:\E\FlatWire\implementations\fw-c\src\stack.c#L235-L242)，5.36）；SD 单播应答/确认恒走 main socket（on_find 响应/send_sub_ack/事件推送/响应帧均 which=1，源端口=5400）；客户端 socket 绑临时端口（udp.c L41-51）；组播不可用降级（Expired 窗口单播 Find，60×period，README 偏差 2）。**边缘缺陷：P2-2 REN 清确认缓存的前缀匹配无 ':' 界定** |

---

## 3. 问题清单

严重级定义：P0=协议违反/崩溃/数据损坏；P1=功能错误/边界缺陷；P2=健壮性/一致性偏差；P3=卫生/可维护性。

### P1（功能错误，均实测复现）

#### P1-1 unsubscribe 后订阅会话 StrmID 永不释放，反复订阅/取消导致控制 StrmID 池耗尽

- **位置**：[discovery.c:883-900](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L883-L900)（fw_disc_unsubscribe）与 [discovery.c:949-965](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L949-L965)（fw_disc_on_unsubscribe_ack）
- **问题**：unsubscribe 中先 `send_subscribe(TTL=0, CON)` 并设置 `s->cancel_deadline`，随后**立即**执行 `sessions[i] = sessions[nsubs-1]; nsess--` 把该会话从数组移除——`cancel_deadline` 写在即将被覆盖的槽位上，等于从未设置。结果：① 服务端回的 ACK(0x00) 到达时 `fw_disc_on_unsubscribe_ack` 在 sessions 数组中匹配不到任何 `cancel_deadline` 非零的会话 → `fw_strm_release_ctrl` 永不执行；② `fw_disc_session_tick` 的取消兜底（L914-928）同样匹配不到。会话 StrmID 既不释放也不冷却。
- **规范出处**：§6.1"取消确认（传输 ACK Code=0x00）到达后释放/冷却"；§7.2 会话 StrmID 规则；测试 6.5"客户端收确认后释放会话 StrmID"。
- **跨栈差异**：fw-nodejs 用 `cancelPending` Map 保留取消等待直到 ACK 或 `setTimeout` 兜底释放（discovery.js L671-705），行为正确；C 版为同类机制的正确意图 + 错误实现。
- **验证**（实测，`%TEMP%\fw_review\verify.c`）：同进程双栈（127.0.0.1:26400 / 127.0.0.2:26400），B 对 A 的服务连续 subscribe→established→unsubscribe 130 轮，stderr 出现 4 次 `"control StrmID pool exhausted"`（池 0x01~0x7F 共 127 个，泄漏 127 次后耗尽）；JS 版同场景无泄漏。
- **建议修复**：unsubscribe 时不立即移除会话，改置 `state=CANCELING` + `cancel_deadline`；`fw_disc_on_unsubscribe_ack` 匹配到后释放 StrmID 并移除；`fw_disc_session_tick` 兜底到期释放并移除；`fw_disc_on_ren`/`pause_sessions_of` 覆盖 CANCELING 态清理。或最小改动：把 `cancel_deadline`/`session_strm` 暂存局部变量并在移除前登记到一个独立的 cancel-pending 小表（对齐 JS cancelPending）。

#### P1-2 批量 SD Entry 接收截断：接收端 Entry 数组上限（64/64/32）远小于发送端拆帧上限（233/帧）

- **位置**：
  - [discovery.c:332-333](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L332-L333) `fw_offer_entry_t es[64]; fw_decode_offer_entries(pl, len, es, 64)`（Offer 处理）
  - [discovery.c:391-411](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L391-L411) `fw_offer_entry_t resp[64]`（Find 响应构造，`nr < 64` 截断）+ `fw_find_entry_t qs[64]`（Find 请求）
  - [discovery.c:515-516](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L515-L516) `fw_sub_entry_t es[32]`（Subscribe 处理）
  - 对照发送端：`fw_disc_build_offers` 每帧满装 `max_payload_len/6 = 233` Entry（discovery.c L139）
- **问题**：发送端按 §7.2 拆帧策略单帧可装 233 个 Offer Entry，接收端却只解码前 64 个（`fw_decode_offer_entries` 按 max 截断返回，无任何日志），其余 Entry 静默丢弃。单节点注册 >64 实例时，**错过逐实例注册立即广播的对端**（或经 Find 预热发现的对端）永远发现不了第 65+ 个实例（Find 响应侧同样在 64 处截断）。Subscribe 32 上限同理（当前客户端 API 单 Entry 发送，风险低）。
- **规范出处**：§7.2 Offer 拆帧策略"每个 Offer 帧自包含、逐帧独立处理：客户端收到任一帧即按其中的 Entry 更新注册表"；§7.6 场景 2。
- **跨栈差异**：fw-nodejs `decodeOfferEntries`/`onFind`/`subscribersOf` 均无上限（JS 数组动态扩展）。
- **验证**（实测）：A 注册 svc=1000 的 inst=1..70 后 B 才启动（错过单 Entry 立即广播），B 仅发现 **63/70**（预热 Find 响应 64 Entry 截断 + 周期 Offer 70 Entry 截断叠加）；作为对照，B 先于注册启动时因逐实例单 Entry 广播而 70/70。
- **建议修复**：接收侧改为堆分配/分段解码循环（按 `len/ENTRY_SIZE` 全量解码），至少提升上限到 233 并对截断记 Error 日志；Find 响应构造侧改用与 `fw_disc_build_offers` 相同的满装拆帧循环（当前 resp[64] 上限 + 拆帧逻辑并存但受 64 截断）。同时修正 `fw_disc_on_find`/`fw_disc_on_offer`/`fw_disc_on_subscribe` 的栈数组容量与发送端口径一致。

### P2（健壮性/一致性偏差）

#### P2-1 接口级 max_payload 校验发生在 CRC 附加之前，最终 Payload（含 CRC）可超限 2 字节

- **位置**：[codec.c:513-521](d:\E\FlatWire\implementations\fw-c\src\codec\codec.c#L513-L521)（fw_encode_payload：先 `out->len > max_payload` 校验，后附加 2B CRC）
- **规范出处**：§3.1"Payload Length = Data Fields + 契约级附加字段（CRC16）之和"；§2/§11.1 `max_payload` 约束"该接口单帧 Payload 字节上限"——上限对象是含 CRC 的 Payload。
- **验证**（实测）：IDL `max_payload=20, crc=true`，string(18B) → Data=20B 通过校验，最终 payload=22B（>20）编码成功返回 FW_OK。
- **影响**：UDP 上恰边界帧比声明上限大 2B；接收端按帧级 `max_payload_len` 只看 1400 总量，IDL 级约束失准。程度轻（2B），定 P2。
- **建议修复**：把 `max_payload` 校验移到 CRC 附加之后（校验 `out->len + (crc?2:0) <= max_payload`），或附加后复检一次。

#### P2-2 REN 清理确认缓存用 IP 前缀匹配且无 ':' 界定，可误清其他对端的确认缓存

- **位置**：[discovery.c:1284-1290](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L1284-L1290)（fw_disc_on_ren 步骤 3：`strncmp(key, ip, strlen(ip))`，key 格式 `"ip:port|strm"`）
- **问题**：对端 IP `1.2.3.4` 与 `1.2.3.45` 前缀撞车时，`1.2.3.4` 的 REN 会误删 `1.2.3.45` 的确认缓存（重复 CON 重发判定失效 → 可能重复建订阅 + 重复全量推送）。同函数其他清理（rpc.c fw_rpc_on_ren 用 `"%s:"`、events.c/fw_strm_reset_peer/discovery.c on_tcp_closed 均 ':' 或逐字段比对）只有此处遗漏。
- **跨栈差异**：JS `key.startsWith(`${ip}:`)`（discovery.js L844-846）带冒号界定。
- **验证**：静态论证（代码比对 + 前缀撞车反例构造），未复现（需特定 IP 部署）；定性 P2。
- **建议修复**：改为 `strncmp(key, ip, strlen(ip)) == 0 && key[strlen(ip)] == ':'`。

#### P2-3 fw_disc_find 的同步等待不被 Offer 到达唤醒，find_service 至少阻塞满 timeout

- **位置**：[discovery.c:759-797](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L759-L797)（fw_disc_find：waiter `kind=FW_W_FIND`，`ctx=&done`）+ [stack.c:116-126](d:\E\FlatWire\implementations\fw-c\src\stack.c#L116-L126)（fw_waiters_fire 仅处理 FW_W_CALL/FW_W_REG，**FW_W_FIND 无分支**）
- **问题**：Offer 到达 → transition_found → fw_waiters_fire 遍历时对 FW_W_FIND 等待者不做任何事，`done` 不置位 → 同步泵只能等满 deadline（默认 2000ms）后 `fw_disc_get_discovered` 再查。功能结果正确，但对新服务的 `fw_find_service` 恒延迟满超时（实例 10ms 内被发现也要等 2s）。
- **跨栈差异**：JS pendingFind 为 Promise，`_resolvePendingFind` 立即 resolve（discovery.js L451-460）。
- **验证**：静态论证（两处代码路径比对）；fw_disc_fetch_idl 因循环条件含 `!q->done` 兜底不受影响。
- **建议修复**：waiter 回调统一化（如 FW_W_FIND 也走 ctx 指向的 done 标志），或 fw_disc_find 泵循环改为直接轮询 `fw_disc_get_discovered`（命中即退），删除 done 标志依赖。

#### P2-4 同步泵期间 pend_find/queries 数组 realloc 使外层 p/q 指针悬空（潜在 UAF）

- **位置**：
  - [discovery.c:795-797](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L795-L797)（fw_disc_find 泵结束后解引用 `p->waiters` 摘除 waiter）
  - [discovery.c:1203-1205](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L1203-L1205)（fw_disc_fetch_idl 同上摘除 `q->waiters`）+ 泵循环条件读取 `q->done`（L1196）
- **问题**：泵循环 `fw_stack_poll` 处理帧期间，应用回调若再发起 call/find（回调内 fw_call 被 BUSY 拒绝，但 **fw_call_async / fw_find_service 之外的状态机推进路径**——如 `fw_call_async` 不检查 dispatch，直接 fw_call_advance → find_start/query_attach → `realloc(pf/queries)`）会使外层 `p`/`q` 指向已释放/搬移的旧数组内存，泵结束后对悬空指针的摘除/读取为 UB。
- **验证**：静态论证（realloc 语义 + 调用图分析；复现需"事件回调内 fw_call_async 触发 IDL 拉取 + 同线程外层同步泵"的特定时序）。定 P2（触发窗口窄，但属内存安全类）。
- **建议修复**：泵结束后按 `(svc_id, inst_id)` / `(svc_id, major_ver)` 重新查找数组条目再摘除；或把 waiter 摘除交给统一入口（ctx 析构时 fw_call_detach 式遍历已覆盖 conn/pf/queries 三处——`fw_disc_find`/`fw_disc_fetch_idl` 改用同款摘除函数，其内部按索引重查）。另建议 `fw_call_async` 在 `dispatch>0` 时也允许（当前允许）但内部对 realloc 敏感路径加索引重查。

#### P2-5 on_notification 交付循环持 sessions 数组索引，回调内修改会话表可导致错配/漏配

- **位置**：[events.c:291-346](d:\E\FlatWire\implementations\fw-c\src\events\events.c#L291-L346)（matched[] 存 sessions 下标，循环内 `s->on_event(...)`）
- **问题**：应用在事件回调里调用 `fw_unsubscribe`/`fw_subscribe` 会 swap-remove/追加 sessions 数组，后续迭代的 `matched[i]` 索引错位 → 事件交付给错误会话或漏交付（on_event 指针从错位槽位读取，可能读到 NULL 被跳过，或读到已语义变化的会话）。无内存越界（nmatched≤16 且 nsess 只增不减到 0 之外时仍可能越界：若回调内 unsubscribe 使 nsess 缩小，`sessions[matched[i]]` 可越界读）。
- **跨栈差异**：JS matched 存对象引用，天然稳定。
- **验证**：静态论证（swap-remove + 索引缓存组合反推）；定 P2（越界读风险 + 交付错配）。
- **建议修复**：matched 存 `fw_session_t*` 指针并在每次迭代前校验该指针仍在表中（线性比对）；或改为两遍：先快照 (handle,on_event,ud) 三元组，再逐个通过 handle 重查后交付。

#### P2-6 事件解码/接口查找固定取 IDL 库最高版本，多版本并存时可能按错误 MajorVer 解码

- **位置**：[events.c:315](d:\E\FlatWire\implementations\fw-c\src\events\events.c#L315)（on_notification 用 `fw_idl_get_highest`）、[discovery.c:499-503](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L499-L503)（lookup_interface 同）
- **问题**：5.30 版本升级后新旧定义并存（规范要求"并存不覆盖"）。此时 v1 实例推送的事件会被 v2 schema 解码（Major 不兼容时解码失败丢事件）；tcp-event 订阅的 transport 判定同样可能取错版本。发现缓存中该实例的 `major_ver` 未被用于选择定义。
- **跨栈对照**：JS onNotification 同样 getHighest，但在 IDL 缺失分支有 `fetchIdl(svcId, rec.major_ver)`（按实例版本拉取）；C 版直接丢弃 + 异步拉最高版。JS `_lookupInterface` 遍历"任一版本"（首个命中），C 取最高——多版本时两侧选择都可能偏离实例实际版本。
- **验证**：静态论证（5.30 并存语义 + get_highest 选择逻辑）。定 P2（版本混部为部署异常场景，规范 §7.2"同一 SvcID 跨 MajorVer 并存属部署异常"）。
- **建议修复**：事件解码按帧对应实例的发现缓存 `major_ver` 选 `fw_idl_get(svc, major)`，缺失再退 get_highest；lookup_interface 同理。

### P3（卫生/可维护性）

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| P3-1 | [frame.c:66-68](d:\E\FlatWire\implementations\fw-c\src\frame\frame.c#L66-L68) | MSK 随机 key 用时钟生成：实测 key 形如 `2F CF BE 00`——最高字节恒 0x00、第三字节长时间窗口内恒定，模式可预测，削弱 §10"规避中间设备误识别"用途（JS 用 crypto.randomBytes） | 换用平台随机（BCryptGenRandom/rand_s），保持 JS 对齐 |
| P3-2 | [tcp.c:355](d:\E\FlatWire\implementations\fw-c\src\transport\tcp.c#L355) | fw_tcp_poll 对每个 connecting 连接每轮 poll 打 INFO 日志 `"reuse connecting conn"`（poll 间隔 20ms）→ 建连期间日志风暴 | 降为 DEBUG 或仅在状态跳变时打 |
| P3-3 | [stack.c:317-321](d:\E\FlatWire\implementations\fw-c\src\stack.c#L317-L321) | POLLOUT flush 用 poll 前记录的 conns 数组下标访问 `st->conns[idx[i]]`，本轮内连接关闭 swap 后可能 flush 到另一连接（对象仍合法，多 flush 无害但逻辑错位） | idx 存 fd 或 conn 指针并校验 |
| P3-4 | [stack.c:50-79](d:\E\FlatWire\implementations\fw-c\src\stack.c#L50-L79) | fw_config_validate 缺 `ver <= 3` 校验：ver>3 时编码 `(ver & 0x03)` 截断，本端自发自收解析失败且难以排查 | 校验 ver≤3 |
| P3-5 | [stack.c:413-441](d:\E\FlatWire\implementations\fw-c\src\stack.c#L413-L441) | fw_reg_ctx_t/fw_reg_advance 为死代码（register 自动拉取实际走 fw_disc_fetch_idl 同步泵） | 删除或注明保留原因 |
| P3-6 | [schema.c:81-158](d:\E\FlatWire\implementations\fw-c\src\codec\schema.c#L81-L158)、[codec.c:296-316](d:\E\FlatWire\implementations\fw-c\src\codec\codec.c#L296-L316) | ① resolve 允许循环引用（cache 命中自引用），decode_field_opt 无深度限制——损坏/恶意 IDL 触发编解码无限递归栈溢出；② enum_vals 依赖 `fw_typedef_t.vals` 与 tdesc 内布局一致的脆弱耦合（注释已声明） | decode 加 depth 参数（复用 resolve 32 上限思路）；enum_vals 改为拷贝 |
| P3-7 | [udp.c:89-103](d:\E\FlatWire\implementations\fw-c\src\transport\udp.c#L89-L103) | UDP 帧编码栈缓冲 2048B：payload>2040 时 `fw_frame_encode` 返回 0 → FW_ERR_PARAM（错误语义应为 ENCODE；IDL 级上限缺失时才可达） | 对齐 rpc.c 的堆回退模式或返回 FW_ERR_ENCODE |
| P3-8 | [frame.c:343-356](d:\E\FlatWire\implementations\fw-c\src\frame\frame.c#L343-L356)、[frame.c:440-447](d:\E\FlatWire\implementations\fw-c\src\frame\frame.c#L440-L447) | sp_feed realloc 失败静默丢 chunk（仅半帧超时兜底）；scratch realloc 失败放弃交付但缓冲状态保留（依赖后续 feed 重试） | 失败路径记 Error 日志；返回状态供连接层决策 |
| P3-9 | [events.c:293](d:\E\FlatWire\implementations\fw-c\src\events\events.c#L293)、[events.c:631](d:\E\FlatWire\implementations\fw-c\src\sd\discovery.c#L631) | 事件多会话匹配上限 16、订阅者快照 static[64]、Offer/Find 解析 64——容量硬编码，超限静默截断（订阅者 >64 时推送漏发） | 动态化或超限记日志 |
| P3-10 | [store.c:62-77](d:\E\FlatWire\implementations\fw-c\src\idlstore\store.c#L62-L77) | load_text 同 (svc,major) 重复加载会 `entry_free` 旧 schema——若 local/handler 持有旧 schema 指针则悬空（当前调用点均先 `fw_idl_has` 防覆盖，防御性弱） | load_text 加"已存在则拒绝"或注释固化前置条件 |
| P3-11 | [stack.c:183-190](d:\E\FlatWire\implementations\fw-c\src\stack.c#L183-L190) | 自我回环过滤地址集仅 bind 地址或 127.0.0.1/2——非 bind 部署时本机组播回环帧不被过滤（README 已声明，JS 用 networkInterfaces 全量） | 用平台接口枚举补全 |
| P3-12 | [stack.c:264-266](d:\E\FlatWire\implementations\fw-c\src\stack.c#L264-L266) | fw_stack_stop 时挂起的 async call ctx 被 fw_rpc_free 直接释放，完成回调永不触发（应用侧异步等待无终态通知） | stop 前 flush pending：对未完成 ctx 触发 cb(err=FW_ERR_STATE) |

### 已核对且排除的疑点（避免后续重复排查）

- **frame.c `received` 字段在分包后续 feed 中不更新的怀疑**：排除。帧头收齐后每次 feed 重新 parse OK 且 payload 不足路径都会 `received = len`（frame.c L419-421），JS 同构；丢弃模式 R 计算正确（t_tcp 2.22/2.23 实测过）。
- **sp_loop 违规帧后清空缓冲丢后续帧**：与 JS 逐行同构的定界尝试（可定界跳过/不可定界清空），属两端一致的实现裁定。
- **fw_waiters_fire 链表摘空设计**：`*head=NULL` 后遍历使 waiter 自动脱离原挂接点，call 状态机 find→query 换挂点不会双重挂接（排除一处疑似双重挂接）。
- **fw_stack_stop 顺序**（rpc_free 先于 tcp_stop）：tcp_stop 的 conn_closed_notify 触达已清零的 rpc/disc 结构为空操作，安全。
- **心跳超时硬编码 2×period**：与附录 A `heartbeat_timeout_ms = 2 × heartbeat_period_ms` 固定关系一致（JS 可配置但默认等值）。
- **fw_tcp_conn_close 发送缓冲未 flush 即 close**：Windows/POSIX 默认 linger 语义下内核会继续发送已 send 的数据；仅用户态 sbuf 残留会丢（对端不收的极端场景，JS end(rst) 同样依赖内核缓冲）。

---

## 4. 测试覆盖缺口（对照 Test Cases.v4.md 9 大类）

已覆盖（60 用例）：1.1~1.19/1.21~1.35（1.20 部分）、2.1~2.29 全部、3.7/3.10~3.12、4.1/4.2/4.4(部分)/4.5、5.5/5.6/5.11/5.15/5.21/5.25/5.28、6.1/6.5(部分)、7.1~7.5(间接)、8.1~8.4(部分)、9.1。

**未被任何 C 测试覆盖的用例**（风险高→低）：

| 缺口 | 用例编号 | 风险评估 |
|------|----------|----------|
| GetIDL 场景矩阵（仅 5.21/5.25/5.28 有） | **5.22/5.23/5.24/5.26/5.27/5.29/5.30/5.31/5.32/5.33/5.34/5.35/5.36** | **高**：按需拉取是 v4.4 核心新特性，服务端 0x24/0x20 路径、注册自动拉取（5.33/5.34 双角色）、版本升级并存（5.30）、启动预热（5.36）全部无回归保护。本次审查的 P1-2/P2-6 均在此盲区附近 |
| 订阅确认链路（仅 6.1/6.5 间接） | **6.2/6.3/6.4/6.6~6.19**（无缓存确认、保活不回、组订阅展开、多客户端、会话 StrmID 复用、确认丢失恢复、重传不重推全量、Found 容错、自动重订阅、REN 清登记、重启窗口幂等、合并订阅、Entry 组合非法、tcp-event 两态、被拒迁移） | **高**：本次 P1-1（unsubscribe 释放）正处于 6.5 的深水区——正是无显式断言"ACK 后 StrmID 释放"才漏网 |
| 心跳五条 | **3.19/3.20/3.21/3.22/3.23** | **高**：tcp.c 心跳代码 0 测试（含 2×period 判死路径）；改动 tcp.c 时无保护 |
| 超时终态/晚于停止重传 | **3.13/3.14** | 中：fw_rpc_tick deadline 路径无测试（含"3000ms 后仍等响应"窗口） |
| 去重与迟到帧 | **3.15/3.16/3.17/3.18** | 中：服务端响应缓存重发逻辑存在但无测试；非活跃 StrmID ACK/RST 丢弃无测试 |
| TYP 语义显式断言 | **3.1~3.6/3.8/3.9** | 中：集成测试隐含覆盖 TCP 侧；UDP CON/ACK 匹配、NON 不回 ACK 无显式断言 |
| REN 发送规则/双角色 | **4.6/4.7** | 中：stop 路径的 REN×3 时序（间隔、先发后关、客户端角色也发）无断言 |
| SD TTL/配置 | **5.7/5.8/5.9/5.10** | 中：5.10（ttl<2×period 拒绝）fw_config_validate 已实现但无测试；TTL=0 延迟 tick 无测试 |
| SD 状态机与边界 | **5.12/5.13/5.14/5.16/5.17/5.18/5.19/5.20** | 中：实例冲突保留先到（5.14）、并发 CON 会话（5.18）、控制帧去重按会话（5.19）等均无测试——P1-2 与 P2-2 都在此区域 |
| 服务层 | **7.6/7.7/7.9/7.10/7.11/7.15/7.16/7.17** | 中低：7.9 重复注册、7.16 subscribe 先于发现、7.17 析构取消无测试 |
| 大数据 | **7.12/7.13/7.14** | 低：TCP 1MB 单帧（TCP 发送缓冲半写恢复路径无覆盖） |
| 端到端 | **8.5/8.6/8.7/8.8** | 低 |
| 兼容性 | **9.2~9.8** | 低：9.7/9.8 与解码容忍相关，codec 层单测部分间接覆盖 |

---

## 5. 与 fw-nodejs 行为差异清单

| # | 差异 | C 侧 | JS 侧 | 影响 |
|---|------|------|-------|------|
| 1 | **unsubscribe 会话生命周期**（对应 P1-1） | 立即删除会话，cancel_deadline 被覆盖，StrmID 泄漏 | cancelPending Map 保留至 ACK/setTimeout 兜底释放 | C 长跑订阅/取消应用池耗尽 |
| 2 | **批量 Entry 解析上限**（对应 P1-2） | Offer/Find 64、Subscribe 32 硬上限 | 无上限 | C↔JS 互通：JS 服务端 >64 实例的批量 Offer 在 C 客户端截断 |
| 3 | REN 清确认缓存前缀（对应 P2-2） | `strncmp(key, ip, len)` 无 ':' | `startsWith("ip:")` | IP 前缀撞车时 C 误清 |
| 4 | find_service 唤醒时机（对应 P2-3） | 等满 timeout 后再查缓存 | Promise 立即 resolve | C 的 find_service 延迟显著（~2s） |
| 5 | 事件 IDL 缺失处理（README 偏差 4，已声明） | 异步拉取 + 丢弃当前事件 | await 拉取（按实例 major_ver）后交付 | 首事件丢失窗口；JS 补偿更完整 |
| 6 | MSK key 来源（对应 P3-1） | 时钟值（高字节恒 0） | crypto.randomBytes | 线格式兼容；混淆强度不同 |
| 7 | 本机地址集（README 偏差相关） | 仅 bind 地址或 127.0.0.1/2 | networkInterfaces 全量 IPv4 | 非 bind 部署时 C 的自我回环过滤失效 |
| 8 | 多版本接口查找 | get_highest | _lookupInterface 取首个命中版本 | 多版本并存时两侧选择都可能偏离实例版本（P2-6 关联） |
| 9 | heartbeat_timeout | 硬编码 2×period | 可配置 heartbeat_timeout_ms（默认同值） | 无行为差异 |
| 10 | TCP 阶段一半帧关连接 | write RST 后立即 close（依赖内核 linger） | socket.end(rstBuf) 保证 RST flush 后 FIN | 极端发送积压时 C 的 RST 可能丢（对端无 0x26 通知） |
| 11 | 组播成员接口 | 统一挂默认接口（INADDR_ANY，README 偏差 1） | 按 bind_address 指定 | 跨机等价；同机回环组播 C 侧反而更可达 |
| 12 | 组播降级 | Expired 记录 60×period 单播 Find 兜底 | 无 | C 更健壮（README 偏差 2） |

---

## 6. 结论

1. **总体判定：基本符合 v4.4 规范，存在 2 项 P1 功能缺陷与若干边缘偏差，尚未达到"可发布"标准，需要一轮修复。**
2. 15 项高危条款中 13 项完全符合；第 7 条（StrmID 生命周期）因 P1-1 记"部分"；第 8 条（SD Entry）因 P1-2 记"部分"——两者都是**客户端侧资源/数据处理缺陷**，服务端协议语义（确认、拆帧、去重）本身正确。
3. **无 P0**：未发现必然崩溃、数据损坏或协议级致命违反；C↔C/C↔JS 既有互通基线不受影响。
4. **修复优先级建议**：P1-1 → P1-2 → P2-1/P2-2（小改动、高确定性）→ P2-3/P2-4/P2-5/P2-6 → 视资源处理 P3。
5. **修复后必须补测**：6.5 的"取消确认后 StrmID 释放"显式断言（防 P1-1 回归）、5.11 的"批量 Offer 端到端发现"（防 P1-2 回归）、3.19~3.23 心跳组、5.22~5.36 GetIDL 矩阵——当前测试对这四块的覆盖为零或近零。
6. 设计文档方面：§7.2 的"Entry 级失败不逐项反馈"与测试 6.19"单 Entry 指向不存在实例 → RST(0x24)"存在内在张力（实现以"单 Entry 帧 RST、多 Entry 逐项丢弃"调和，两端一致），建议总策划在规范 §7.2 补一句明确，避免后续实现分歧。

### 实测验证记录（复现归档于 %TEMP%\fw_review\）

| 项 | 方法 | 结果 |
|----|------|------|
| V1（P1-1） | 双栈 127.0.0.1:26400 / 127.0.0.2:26400，B 连续 subscribe→established→unsubscribe 130 轮 | stderr 出现 4 次 `control StrmID pool exhausted`；JS 对照无泄漏 |
| V2（P1-2） | A 注册 70 实例后 B 晚启动（仅靠批量 Offer/Find 响应发现） | B 仅发现 63/70 |
| V3（P2-1） | max_payload=20 + crc=true + Data 恰 20B 调 fw_encode_payload | 返回 FW_OK，最终 payload=22B |
| V4（P3-1） | fw_frame_encode 无 mask_key 连续编码 3 帧 | key=`2F CF BE 00`/`3B CF BE 00`/`4B CF BE 00`（高字节恒 0） |
