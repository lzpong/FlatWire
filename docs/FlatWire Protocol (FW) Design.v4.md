# FlatWire Protocol (FW)

## 0. 变更历史

| 版本 | 变更概况 |
|------|---------|
| v4 | 全文重构：修正 `low4=0` 编码矛盾、`Code=0x00` 双义冲突、删除不可达的 `HalfClosed` 状态、补全错误码表与参数定义；删除设计动机、实现细节与冗余表述；一致性要求抽离为独立测试用例文档 |
| v3 | 服务实例唯一性规则、TTL 静态比值（去宽限期）、心跳去 Pong、RPC/FF 默认 CON、SD Entry 去 IfID、嵌套类型支持 |

---

## 1. 概述与范围

### 1.1 定位

本文档为 FlatWire Protocol（FW）的**规范性协议设计文档**，定义线格式、交互语义与服务契约。

- FW 是**应用层协议**：不定义 TCP 连接状态机（TCP 由操作系统管理）
- TCP/UDP 共用预定义端口（默认 5400），由 SvcID/IfID 实现多路复用
- 本文档**不包含**设计动机、实现指导与测试用例。文中"必须/禁止/应"为规范性要求
- FW 面向**可信网络**，协议层不提供安全保证（见 §2）

### 1.2 设计原则

| 原则 | 说明 |
|------|------|
| 应用层协议 | 仅定义帧格式、交互语义与服务契约 |
| 统一端口 | TCP/UDP 共用预定义端口，由 SvcID/IfID 多路复用 |
| 双角色节点 | 一个节点可同时作为服务端与客户端，两套状态独立维护 |
| 服务契约驱动 | 服务注册后自动广播 Offer；接口集合由 IDL 静态定义 |
| 扁平编码 | 协议数据始终为碾平后的字段序列，无嵌套边界标记 |

### 1.3 超时与保活

| 类别 | 默认值 | 作用 |
|------|--------|------|
| 应用层响应超时 | 2s | 调用的**唯一终态**判定；每次调用可单独覆盖 |
| TTL 有效期 | 4s | 服务/订阅生命周期（见 §7.5） |
| TCP 半帧超时 | 5000ms | 帧接收未完成时的连接保护（见 §4.1） |
| TCP 心跳超时 | 60s | 半开连接检测（见 §5.7） |

### 1.4 关键约束

- **可靠性分层**：CON/ACK 为 **UDP 专用**送达保证；TCP 由协议自身保障，不使用 CON/ACK（所有帧 TYP=NON）
- **TTL=0 延迟移除**：收到 TTL=0 后不立即删除条目，统一延迟到下一次 tick 清理（见 §7.5）
- **协议版本与服务版本独立**：VER 为传输协议版本（帧格式级），MajorVer/MinorVer 为服务版本（接口语义级）
- **`(SvcID, InstID)` 跨节点唯一**：由部署规划保证的运行前提；协议层不提供冲突检测或仲裁（见 §3.5）

---

## 2. 传输层约定

TCP/UDP 共用端口 5400。传输协议按接口类型绑定（IDL 声明）：rpc/ff 默认走 TCP，event 默认走 UDP。

SD 使用 UDP 组播（224.0.1.187 / ff02::1:BB），Find 响应用 UDP 单播。

**周期与 TTL**：Offer 与 Subscribe 共用同一组配置，须满足：

```
ttl >= 2 * period
```

| 参数 | 默认值 |
|------|--------|
| `period` | 2s |
| `ttl` | 4s |

**最大载荷**：`max_payload_len` 定义单帧 Payload 上限，默认 **1400** 字节。超过时编码报错、接收方回 RST(0x23)（见 §3.8、§9.2）。

**协议版本（VER 字段）**：

- VER 表示传输协议版本（帧格式级），**不同 VER 即不同方案，无协商降级语义**
- VER=0：当前版本，所有实现必须支持
- 发送端始终以本地支持的 VER 发送所有帧（数据帧和控制帧）
- **通信前提：双方 VER 必须相等**。VER 不一致则不可通信：
  - 组播帧（Offer / Find / Subscribe）：静默丢弃
  - 单播帧（数据帧 / 控制帧）：回 RST(0x22) 并丢弃
- 对端 VER 由 SD Offer 携带，客户端仅在 VER 相等时才认为服务可用

**安全边界**：VER=0 **不提供鉴权、完整性、机密性**保护。MSK（见 §10）仅为载荷混淆，不是安全机制。需要安全保证的部署应由环境层提供（封闭网络、VPN、链路加密或上层安全协议）。

**字节序与扩展**：所有多字节整数统一大端序。压缩/加密/CRC 由服务契约约定，不在帧头标志。

---

## 3. 帧格式

### 3.1 帧整体结构

```
 +0              +1              +2              +3
 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0
+-------+-------+-------+-------+-------+-------+-------+-------+
|CTR|REN|VER|MSK|PLB|TYP | Code |        Service ID (2B)        |
+-------+-------+-------+-------+-------+-------+-------+-------+
|      Interface ID (2B)        |  Instance ID  |   Stream ID   |
+-------+-------+-------+-------+-------+-------+-------+-------+
|                     Payload Length                            |  <- PLB 决定 Length 字段字节数
+-------+-------+-------+-------+-------+-------+-------+-------+
|                       [Masking Key (4B)]                      |  <- MSK=1 时存在
+-------+-------+-------+-------+-------+-------+-------+-------+
|                   Structured Data Fields                      |
|                   ...                                         |
+-------+-------+-------+-------+-------+-------+-------+-------+
```

固定头 8B：byte0/byte1（2B 控制头）+ SvcID/IfID（4B）+ InstID/StrmID（2B）。

解析顺序：byte0 → byte1 → SvcID → IfID → InstID → StrmID → Length（PLB>0 时）→ Mask（MSK=1 时 4B）→ Data

**Payload Length 定义**：Data Fields 字节数 + 契约级附加字段（CRC16 等）之和，**不含 Masking Key**。

控制帧（CTR=1）与数据帧（CTR=0）格式相同，仅 Code 语义不同。

### 3.2 byte0 定义

```
CTR:1 | REN:1 | VER:2 | MSK:1 | PLB:3

 76543210
 x....... CTR  是否是控制帧
 .x...... REN  重启标志（仅 CTR=1 时有效，CTR=0 时恒为 0）：
                1=发送方已重启，对端应重置该节点服务缓存
 ..xx.... VER  版本号（0=当前版本；双方必须相等，见 §2）
 ....x... MSK  是否有掩码（1 时于 Payload Length 后插入 4B XOR 密钥）
 .....xxx PLB  payload length 字段实际占用的字节数（0~7）
```

空 payload：PLB=0，无 Length 字段，帧大小最小 8B。

### 3.3 byte1 定义

```
TYP:2 | Code:6

 76543210
 xx...... TYP  传输类型（见 §3.7）
 ..xxxxxx Code  消息编码（见 §3.4）
```

### 3.4 Code 编码

| Code (CTR=0) | 语义 |
|-------------|------|
| 0x00 | 空确认（TYP=ACK 时）／协议违规（TYP=RST 时） |
| 0x01 | Request（需响应） |
| 0x02 | Fire-Forget |
| 0x03 | Notification |
| 0x04~0x0F | 保留 |
| 0x10~0x1F | 成功响应（0x10=OK, 0x11=Created, 0x12=Accepted）|
| 0x20~0x2F | 客户端错误（见 §12.1）|
| 0x30~0x3F | 服务端错误（见 §12.1）|

| Code (CTR=1) | 语义 |
|-------------|------|
| 0x00 | 连接级控制（REN=1 时=重启通知；REN=0 时=心跳 Ping） |
| 0x01 | SD Offer（TTL=0 表示停止提供）|
| 0x02 | SD Find |
| 0x03 | SD Subscribe（TTL=0 表示取消订阅） |
| 0x04~0x0F | 保留 |
| 0x10~0x1F | SD 成功响应（0x10 保留）|
| 0x20~0x2F | SD 客户端错误 |
| 0x30~0x3F | SD 服务端错误 |

> `Code=0x00` 语义由 TYP 与 CTR 共同决定：`TYP=ACK` → 空确认；`TYP=RST` → 协议违规；`CTR=1 且 REN=0` → 心跳 Ping；`CTR=1 且 REN=1` → 重启通知。

> 错误码语义与恢复策略以 §12.1 为唯一权威表。

### 3.5 消息标识符

| 字节 | 字段 | 数据帧 (CTR=0) | 控制帧 (CTR=1) |
|------|------|---------------|---------------|
| 2~3 | SvcID | 0x0001~0xFFFF | 固定 0x0000 |
| 4~5 | IfID | 0x0001~0x7FFF=rpc/ff，0x8000~0xFFFF=event | 固定 0x0000 |
| 6 | InstID | 0x01~0xFF | 固定 0x00 |
| 7 | StrmID | 0x01~0x7F 客户端流 / 0x80~0xFE 服务端流 | 0x00 |

**ID=0 通配规则**：SvcID=0x0000 / IfID=0x0000 / InstID=0x00 仅在 SD 查询/订阅场景中表示"任意/全匹配"（见 §7.2），数据帧中禁止出现。

**IfID 语义分区**：0x0001~0x7FFF 用于 rpc/ff 接口，0x8000~0xFFFF 用于 event 接口。同一服务内 IfID 唯一。

StrmID 用途：请求-响应匹配、多路复用（同一对端并发多请求）、CON 去重（见 §5.5）。数据帧不携带**服务版本**（MajorVer/MinorVer）；协议版本见帧头 VER。

**服务实例唯一性规则**：

| 层级 | 唯一性范围 | 说明 |
|------|-----------|------|
| `SvcID` | 全局唯一 | 服务标识，各节点共享同一份 IDL |
| `(SvcID, InstID)` | 全局唯一（跨节点） | 唯一标识一个服务实例 |
| `(SvcID, IfID, InstID)` | 全局唯一（由上一行推导） | 唯一标识一个接口端点 |

- 同一节点内，同一 `SvcID` 可以注册多个 `InstID`（多实例部署）
- `(SvcID, InstID)` 跨节点唯一是**运行前提**，由部署规划保证；违反时行为未定义
- 客户端可用 `(SvcID, InstID)` 直接定位服务实例，不依赖源地址
- 同一 `(SvcID, InstID)` 的所有接口必然来自同一源地址

### 3.6 REN 重启标志

REN=1 时 CTR 必须为 1，数据帧 REN 恒为 0。REN=1 的帧固定：TYP=NON，StrmID=0x00，Code=0x00。

收到 REN=1：清除该节点的所有服务缓存，清空该对端的全部活跃 Stream 与待确认重传记录，重置 StrmID 分配游标，等待 SD Offer 重建。REN 仅影响该对端节点。

StrmID 不在该对端活跃表中时，ACK/RST 直接丢弃。

### 3.7 TYP 传输语义

| TYP | 名称 | 语义 | 允许的 Code | 适用场景 |
|-----|------|------|-----------|---------|
| 00 | NON | 不确认，尽力投递 | 任意 | TCP 上所有帧；UDP 上的周期事件、日志、SD |
| 01 | CON | 需 ACK 确认（仅 UDP） | 任意 | UDP 上的 Request、Fire-Forget、可靠事件、Subscribe 首次/取消 |
| 10 | ACK | 传输层确认（仅 UDP） | 仅 0x00 | 空确认，不承载应用数据 |
| 11 | RST | 拒绝/重置 | 错误码 | 未知服务、拒绝连接；Code 指明原因 |

**规则**：

- 收到 CON 帧（UDP）后，回一个空确认 ACK
- 收到 NON 帧，不回任何确认
- TCP 上不使用 CON/ACK，所有帧为 NON

### 3.8 大数据传输约束

协议层**不提供分段/重组机制**。大数据由服务契约在 IDL 阶段约束：

| 场景 | 策略 |
|------|------|
| 常规 UDP 接口 | IDL 声明 `max_len`（建议 ≤ 1400），编解码层强制校验，超限拒绝 |
| 大数据接口（> MTU） | IDL 声明 `transport: "TCP"`，由 TCP 流式传输保障 |
| 应用层分块（可选） | 若需在 UDP 上分块，由应用语义自行定义块序号与重组（协议栈不感知），并应保证块级幂等或可重传 |

超限帧的处理：编码侧报错；接收侧丢弃并回 RST(0x23)。协议栈不做运行时自动降级或拆分。

---

## 4. 帧解析

### 4.1 TCP 流式解析

- 帧边界由 Payload Length 确定，无额外帧分隔符
- 解析状态：`IDLE → READ_HEADER(4B) → READ_SVCID_IFID(4B) → READ_LENGTH(plb,条件) → READ_MASK(4B,条件) → READ_PAYLOAD(length) → FRAME_COMPLETE → IDLE`
- **分包**：任何阶段（含 Length 字段本身、Masking Key、Payload Data）数据不足时，保存当前解析状态并等待后续数据，不得丢弃已读字节
- **粘包**：一次接收含多帧时，逐帧解析并在每帧完整后立即交付
- **半帧超时**：一个帧开始接收后超过 `tcp_frame_timeout_ms`（默认 5000ms）仍未收完，回 RST(0x26) 并丢弃残缺帧

### 4.2 UDP 报文解析

- 每个 UDP 数据报承载一帧，无粘包问题
- 数据报长度 < 最小帧长度（8B）→ 丢弃
- 数据报长度 ≠ 帧头声明长度（多余或不足）→ 一律视为错误并丢弃（不做截断）
- Payload 超过 `max_payload_len` 或 IDL `max_len` → 丢弃并回 RST(0x23)

### 4.3 解析流程

```
1. 读 byte0 → CTR/REN/VER/MSK/PLB
   校验 VER 与本端相等（不等按 §2 处理）
   校验 CTR/REN 一致性：REN=1 时 CTR 必须为 1
   校验失败 → 回 RST(0x00) 并丢弃
2. 读 byte1 → TYP/Code
   校验 REN=1 时 TYP=NON 且 Code=0x00
   校验 TYP=ACK 时 Code=0x00
   校验失败 → 回 RST(0x00) 并丢弃
3. 读 SvcID/IfID
   校验控制帧为 0x0000、数据帧非 0x0000
4. 读 InstID/StrmID
   校验控制帧 InstID=0、REN=1 时 StrmID=0、数据帧 InstID≠0x00
5. 若 PLB>0 读 Payload Length(plb 字节)；PLB=0 时 Length=0
   超 max_payload_len → 回 RST(0x23)
6. 若 MSK=1 读 4B Masking Key
7. 读 Payload Data；MSK=1 则 XOR 还原
8. 组装 Frame 交付
```

### 4.4 解析错误处理

| 错误场景 | 处理方式 |
|---------|---------|
| VER 与本端不一致 / CTR/REN 不一致 / SvcID/IfID 越界 | 回 RST(0x00)，丢弃帧（组播帧静默丢弃） |
| TCP 数据不足（半帧/分包） | 保存状态，等待更多数据 |
| UDP 数据报长度 ≠ 声明帧长度 | 丢弃数据报（不截断） |
| Payload 超过 max_payload_len 或 IDL max_len | 回 RST(0x23)，丢弃帧 |
| TCP 帧间接收超时（半帧超时） | 回 RST(0x26)，丢弃残缺帧 |

---

## 5. 交互语义与时序

### 5.1 Request-Response

```
客户端 --- Request(StrmID=0x01) ---> 服务端
客户端 <--- Response(StrmID=0x01) --- 服务端
```

| 传输 | Request TYP | Response TYP |
|------|------------|-------------|
| TCP | NON | NON |
| UDP | CON | CON（对端回空确认 ACK） |

**Response 必须回显请求的 StrmID**；服务端流（0x80~0xFE）仅用于服务端主动发起的 Notification。

**Response 不使用 TYP=ACK**：响应是应用数据，ACK 是纯传输层确认。

客户端启动应用层响应超时定时器（默认 2s，可逐次覆盖），收到 Response 即取消。

### 5.2 Fire-Forget

```
客户端 --- Fire-Forget ---> 服务端
```

| 传输 | TYP |
|------|-----|
| TCP | NON |
| UDP | CON（对端回空确认 ACK） |

FF 无应用层响应，无应用层超时；送达保证由传输层 CON/ACK 承担（仅 UDP）。

### 5.3 事件推送（Notification）

```
服务端 --- Notification(TYP=NON) ---> 客户端A  (UDP, 尽力投递)
服务端 --- Notification(TYP=CON) ---> 客户端B  (UDP, 需送达保证)
```

- TCP：`TYP=NON`
- UDP 常规事件：`TYP=NON`，无 ACK
- UDP 可靠事件：`TYP=CON`，客户端回空确认 ACK，超时重传（见 §5.5）

多客户端推送同一事件，每个客户端独立分配 StrmID。CON 模式需每个客户端独立 ACK，去重键 = `(peer, svc_id, inst_id, StrmID)`。

### 5.4 RST 触发场景矩阵

| 场景 | 触发方 | RST 内容 | 接收方动作 |
|------|--------|---------|-----------|
| 未知服务/接口 | 服务端 | TYP=RST, Code=0x24 | 记录错误，释放 Stream |
| 不支持的操作码 | 服务端 | TYP=RST, Code=0x25 | 记录错误，释放 Stream |
| 请求格式错误 | 服务端 | TYP=RST, Code=0x20 | 记录错误，释放 Stream |
| 版本不支持 | 接收方 | TYP=RST, Code=0x22 | 报错，不可通信 |
| 协议违规 | 接收方 | TYP=RST, Code=0x00 | 记录错误 |

### 5.5 CON/ACK 可靠性（仅 UDP）

| 传输协议 | 可靠性来源 | 丢失处理 |
|---------|-----------|---------|
| TCP | TCP 协议自身 | 无需处理 |
| UDP | CON + ACK + 指数退避重传 | 最多 4 次发送（1 次原始 + 3 次重传） |

**重传参数**：

| 参数 | 默认值 |
|------|--------|
| `interval_ms` | 200ms |
| `max_retry` | 3（不含首次） |
| 退避公式 | `interval * 2^retry` |
| 末次发送后等待 | `interval * 2^max_retry` = 1600ms |

**发送与重传时间线**：

| 事件 | 时刻 |
|------|------|
| 首次发送 | 0ms（同时启动应用层响应超时） |
| 重传 1 | 200ms |
| 重传 2 | 600ms |
| 重传 3（末次） | 1400ms |
| 停止重传 | 3000ms（静默停止，不报错） |

**重传耗尽语义**：

- 重传耗尽仅表示停止重发，不代表响应不会到达
- 请求成败由应用层响应超时统一判定，传输层不产生独立错误
- 响应超时触发时，若该 StrmID 仍有待确认重传，一并取消
- 若响应超时大于停止重传时刻（3000ms），3000ms 后进入"不再重传但仍等待响应"状态，超时前收到响应仍算成功

**重传范围**：UDP 上所有 TYP=CON 的帧（数据帧 Request、Notification CON；控制帧 Subscribe 首次/TTL=0）均走重传。NON 帧与 SD 周期帧不需要。非 Request 的 CON 无应用层响应超时，由 TTL 与保活机制兜底。

**去重语义（幂等保障）**：StrmID 是重传去重键，去重需收发双方配合：

| 角色 | 规则 |
|------|------|
| 发送方 | 同一 `(peer, svc_id, inst_id, StrmID)` 的待确认帧只允许一个；重传使用同一 StrmID 和完全相同的字节 |
| 服务端 | 收到与当前活跃 StrmID 相同的请求（即重传）时，直接重发上次缓存的响应，不重新执行处理逻辑 |
| 服务端 | 响应缓存按 `(peer, svc_id, inst_id, StrmID)` 保存，随 Stream 释放（收到 ACK / 超时 / RST）一并清除 |
| 客户端 | 重复收到同一响应时，按 StrmID 判定为重复并丢弃，只交付首个 |

### 5.6 TCP 连接策略

- 连接建立：客户端主动发起 TCP 连接到服务端 (IP, Port)，按 (IP, Port) 建立唯一长连接
- 多路复用：同一 TCP 连接承载所有 SvcID/IfID 的数据帧，StrmID 实现多路复用
- 服务端：启动时 bind + listen，accept 新连接后纳入帧解析
- 连接断开：清理该连接的所有 Stream 和订阅关系，通知应用层
- 自动重连：客户端检测到连接断开后重连；重连成功后重新触发 SD 流程

### 5.7 心跳（Ping，仅 TCP）

**目的**：检测 TCP 半开连接、保持 NAT 映射。

**Ping 帧**：CTR=1, REN=0, TYP=NON, Code=0x00, SvcID=0x0000, IfID=0x0000, InstID=0x00, StrmID=0x00, Payload 空

**规则**：

| 规则 | 说明 |
|------|------|
| 空闲时发 Ping | 见下方"空闲"定义；收到 Ping 不回任何帧 |
| 存活计时 | 收到任意帧（数据帧或控制帧）即刷新；超过 `2 × heartbeat_period` 未收到任何帧，标记连接失效 |
| 对称策略 | 双角色节点执行同一策略：各自按空闲条件主动发 Ping，各自靠接收判定对端存活，无需回应 |

**"空闲"定义**：自本端上次发出任意帧（数据帧或控制帧）起，超过 `heartbeat_period`（默认 30s）未发送任何帧，则发送一次 Ping。

**UDP 场景**：不需要心跳（无连接状态），SD Offer/Subscribe 的周期报文已提供等价的可达性探测。

---

## 6. Stream

### 6.1 StrmID 空间

| 范围 | 语义 | 分配方 | 用途 |
|------|------|--------|------|
| 0x00 | 连接级控制 | 双方 | REN 帧（见 §3.6）、心跳 Ping（见 §5.7） |
| 0x01~0x7F | 客户端流 | 客户端 | 客户端发起的 Request、Fire-Forget |
| 0x80~0xFE | 服务端流 | 服务端 | 服务端主动推送的 Notification |
| 0xFF | 保留 | — | 未来扩展 |

Response 不占用服务端流：Response 必须回显请求的 StrmID（见 §5.1），属于客户端流编号空间。

### 6.2 Stream 生命周期

```
       +----------------+
  +--->|    Closed      |
  |    | (初始/释放后)  |
  |    +--------+-------+
  |             |    alloc_client_stream / alloc_server_stream
  |             v
  |    +--------+-------+
  +----|    Active      |
       | (可收发数据)   |
       +----------------+
```

| 当前状态 | 事件 | 下一状态 |
|---------|------|---------|
| Closed | 分配 StrmID | Active |
| Active | 收到/发送 RST | Closed |
| Active | 本地主动关闭 | Closed |
| Active | Request 收到 Response | Closed |
| Active | Notification 发送完成 | Closed |

### 6.3 StrmID 管理规则

- StrmID 按 `(peer, svc_id, inst_id)` 隔离；每个组合内 client(0x01~0x7F) 与 server(0x80~0xFE) 各 127 个，独立循环分配
- `peer` 用于连接级隔离：同一 peer 内同一 `(svc_id, inst_id)` 只对应一个实例（见 §3.5）
- 目标 StrmID 仍活跃时跳过，寻找下一个空闲
- 收到 REN=1 时清除该对端全部序列
- 分配应优先选用未用过或已冷却的 StrmID

---

## 7. 服务发现（SD）

控制帧（CTR=1）承载服务发现协议，使用 UDP 组播，帧格式与数据帧完全相同。

统一规则：

- 帧头 SvcID/IfID 固定为 0x0000/0x0000，所有服务信息在 Payload Entry 中
- SD 仅承载**实例在线信息**（是否在线、在哪个源地址）；接口集合由 IDL 静态定义（见 §7.2）

### 7.1 SD Entry 格式

```
  Offer Entry (6B):       Find Entry (5B):      Subscribe Entry (7B):
    uint16  SvcID           uint16  SvcID         uint16  SvcID
    uint8   InstID          uint8   InstID        uint16  IfID
    uint8   MajorVer        uint8   MajorVer      uint8   InstID
    uint8   MinorVer        uint8   MinorVer      uint8   GrpId
    uint8   TTL(0=停止)                           uint8   TTL(0=取消)
```

- **Offer / Find Entry 不含 IfID**：服务在线与否是实例级 `(SvcID, InstID)` 事实，与提供哪些接口无关
- **Subscribe Entry 保留 IfID**：订阅是接口级行为（订阅某个具体 event 接口或事件组），需指明 IfID 或 GrpId

**GrpId 语义**：服务内 8bit 组号（0x00=不使用组，按 IfID 单接口订阅；0x01~0xFF=组号）。用 GrpId 订阅时 IfID 必须为 0x0000，服务端展开为组内所有 event 接口。组定义在 IDL `event_groups` 中声明（见 §11.1）。

### 7.2 SD 操作语义

| 操作 | Code | Payload | 传输 | 语义 |
|------|------|---------|------|------|
| Offer | 0x01 | N × Offer Entry | UDP 组播，周期 `period` | TTL=0 表示停止提供；不携带 Endpoint（IP 由 socket 源地址获取）|
| Find | 0x02 | 空 或 N × Find Entry | UDP 组播 | 空 Payload = 查询所有服务；带 Entry 时必须指定 SvcID（非零），InstID 可 0x00 通配<br>SvcID 非通配时 MajorVer 参与精确匹配，MinorVer 不参与匹配<br>响应帧格式与 Offer 相同（Code=0x01），由服务端 UDP 单播发送 |
| Subscribe | 0x03 | N × Subscribe Entry | UDP 单播，首次 CON / 取消（TTL=0）CON / 保活 NON，周期 `period` | Entry 携带 TTL(秒)，TTL=0 表示取消订阅（延迟到下次 tick 移除）；首次 CON 的服务端回应见 §8.1；重复收到视为保活刷新；TTL 倒计时归零视为离线 |

**SD Offer 帧大小约束**：编码后总字节数（含帧头 + SD 头 + N×Entry）应 ≤ `max_payload_len`。

**SD Offer 拆帧策略**：

- 若 Entry 总数导致 Payload 超过阈值，按 UDP MTU 最大满装拆分为多个 Offer 帧，同周期内连续发送
- 每个 Offer 帧自包含、逐帧独立处理：客户端收到任一帧即按其中的 Entry 更新注册表
- Entry 粒度 = `(SvcID, InstID)`，即一个实例一条 Entry
- 部分 Offer 帧丢失由 TTL 机制兜底（下一周期重新广播）

**实例冲突处理**：客户端按 `(SvcID, InstID)` 记录实例与源地址：

| 场景 | 客户端行为 |
|------|-----------|
| 源地址 == 该实例已记录源地址 | 正常刷新 TTL |
| 源地址 ≠ 已记录源地址 | 记录 Error 级日志（含 `(svc_id, inst_id)` 与两个源地址），保留先到的实例记录不变，忽略后到的 Entry |

冲突属部署配置错误，协议层不做仲裁或自动切换。

### 7.3 服务端视角 — 服务生命周期

```
      +----------------+
      |   NotOffered   |
      | (未注册到本地) |
      +--------+-------+
                | register_service()
                v
      +--------+-------+
  +-->|    Offering    |
  |   | (周期广播Offer) |
  |   +--------+-------+
  |            |
  |            | unregister_service()
  |            v
  |   +--------+-------+
  +---|    Stopped     |
      | (已发TTL=0 Offer,|
      |  本地资源已清理) |
      +--------+-------+
               |
               | 本地清理完成（同步）
               v
      +--------+-------+
      |   NotOffered   |
      +----------------+
```

| 当前状态 | 事件 | 下一状态 | 动作 |
|---------|------|---------|------|
| NotOffered | register_service() | Offering | 开始周期广播 Offer |
| Offering | 收到 Find | Offering | 单播响应（格式同 Offer） |
| Offering | unregister_service() | Stopped | 发送 TTL=0 Offer 一次，停止广播 |
| Stopped | 本地清理完成 | NotOffered | 清理本地资源 |

**注册粒度为实例级**：状态机作用对象是 `(SvcID, InstID)` 实例。同一 `SvcID` 的多个 `InstID` 各自独立走该状态机，互不影响。

### 7.4 客户端视角 — 服务发现生命周期

```
            +----------------+
  +-------->|    Unknown     |
  |         | (未知服务状态) |
  |         +--------+-------+
  |                  | send Find / 收到 Offer
  |                  v
  |         +--------+-------+
  |         |     Found      |
  |   +-----|(已知服务,未订阅)|
  |   |     +--------+-------+
  |   | Offer 过期   | send Subscribe
  |   |              v
  |   |     +--------+-------+
  |   |     |   Subscribed   |
  |   |     |(已订阅,接收事件)|
  |   |     +--------+-------+
  |   |              | send Subscribe(TTL=0) / TTL过期
  |   |              v
  |   |     +--------+-------+
  |   |     |  Unsubscribed  |
  |   |     |(已知服务,未订阅)|
  |   |     +--------+-------+
  |   |              | Offer TTL=0 / Offer 过期
  |   |              v
  |   |     +--------+-------+
  |   +---->|    Expired     |
  +---------| (服务不可用了) |
  重新Find  +--------+-------+
```

| 当前状态 | 事件 | 下一状态 | 动作 |
|---------|------|---------|------|
| Unknown | 收到 Offer (TTL>0) | Found | 按 (svc_id,inst_id) 加入注册表，启动 TTL 倒计时 |
| Unknown | 主动 Find 收到响应 | Found | 同上 |
| Found | 发送 Subscribe，服务端首次确认 | Subscribed | 记录订阅关系，接收全量数据 |
| Subscribed | 收到事件推送 | Subscribed | 交付应用层 |
| Subscribed | 发送 Subscribe(TTL=0)，收到 ACK | Unsubscribed | 移除本地订阅关系 |
| Found | TTL 倒计时归零 | Expired | 从注册表移除 |
| Subscribed | TTL 倒计时归零 | Expired | 从注册表移除，停止接收 |
| Unsubscribed | Offer TTL=0 或 TTL 倒计时归零 | Expired | 从注册表移除 |
| Expired | 重新收到 Offer (TTL>0) | Found | 重新加入注册表 |
| Any | 收到 REN=1 | Unknown | 清除该节点（源地址）的所有实例缓存 |

状态机作用对象为**实例** `(SvcID, InstID)`；同一实例的多个 IfID 共享一条注册记录与一个 TTL 倒计时。

### 7.5 TTL 机制

**统一规则**：TTL=0（显式停止/取消）与 TTL 归零，都不立即删除条目，而是标记为待移除，在下一次 tick 时统一清理。

**条目状态**：

| state | 含义 | tick 行为 | 触发条件 |
|-------|------|----------|---------|
| Active | 正常有效 | 剩余 TTL 递减 1；归零 → 转 Expired | 收到 TTL>0 |
| Expired | 待移除 | 在下一次 tick 时删除条目 | TTL 归零 / 收到 TTL=0 |

**发送方（Offer 广播 / Subscribe 保活）**：每 `period` 发送一次，Entry 中携带固定的 `ttl` 值，不递减。

**接收方（对端 Offer / 对端 Subscribe）**：

- 收到 TTL>0：剩余 TTL 置为 TTL，state = Active（重置而非累加）
- 收到 TTL=0：state = Expired
- 每秒 tick：按上表推进状态；Expired 条目在本次 tick 删除

Offer 与 Subscribe 两侧规则完全一致：客户端维护远端实例的 Offer TTL，服务端维护订阅者的 Subscribe TTL。

### 7.6 SD 交互时序

```
场景1 主动发现:  客户端 --- SD Find ---> 服务端
                  客户端 <--- SD Offer --- 服务端

场景2 被动发现:  客户端 <--- SD Offer (周期组播) --- 服务端

场景3 订阅事件:  客户端 --- SD Subscribe (TTL>0, 首次 CON，后续 NON，周期 period) ---> 服务端 (单播)
                  服务端首次收到建立订阅：有缓存推送全量 Notification；无缓存回空 ACK（见 §8.1）
                  服务端 <-- ACK --- 客户端 (首次 CON 的传输层确认)

场景4 取消订阅:  客户端 --- SD Subscribe(TTL=0, CON) ---> 服务端 (单播)
                  服务端置 Expired，延迟到下次 tick 移除订阅关系

场景5 服务停止:  客户端 <--- SD Offer(TTL=0, TYP=NON) --- 服务端
                  客户端置 Expired，延迟到 tick 检查移除

场景6 节点重启:  客户端 <--- REN=1 --- 服务端
                  客户端按源地址清空该节点的所有实例缓存
                  客户端 <--- SD Offer --- 服务端 (重新发现)
```

---

## 8. 事件推送（Notifier）

### 8.1 订阅管理

- **收到 Subscribe**：TTL>0 时加入订阅列表/保活刷新（state=Active）；TTL=0 时置 Expired；首次收到时推送全量数据
- **GrpId 语义**：见 §7.1
- **订阅健康检查**：按 §7.5 状态机推进，Expired 条目在 tick 时删除

**全量推送**：服务端首次收到某客户端 Subscribe 时，直接推送接口缓存的最新数据。服务注册后应主动 `notify` 初始化缓存；后续数据变化时 `notify` 更新缓存并分发给所有订阅者。

**订阅确认语义**：服务端对首次 Subscribe（TTL>0）必须明确回应，客户端据此从 Found 进入 Subscribed：

| 情况 | 服务端回应 |
|------|-----------|
| 有缓存 | 推送全量 Notification（TYP=CON 或 NON，按接口配置） |
| 无缓存 | 回空确认 ACK（TYP=ACK, Code=0x00），同时表示"订阅已建立，暂无数据" |
| 后续 TTL 刷新（保活） | Subscribe 走 NON，不回 ACK |

### 8.2 多客户端推送

- 按 `(svc_id, if_id, inst_id)` 查订阅者列表
- 每个客户端独立分配 StrmID，按需编码后逐个发送
- 每个客户端 ACK 独立匹配 `(peer, svc_id, inst_id, StrmID)`

---

## 9. 结构化数据字段

### 9.1 字段类型编码

字段头（1 字节）：高 4bit（b7-b4）为字段类型（0~8），低 4bit（b3-b0）用途因类型而异。

```
 二进制类型   低4bit用途       C类型        数据长度限制
+-----------+-----------------+------------+------------------------------------+
|0 0000 0000| —              | null       | 空值（Payload Length决定字段边界）
|1 0001 000x| 内联值(bool)    | bool       | 0=false, 1=true
|2 0010 xxxx| 长度(字节数)    | signed     | n byte size of payload (1~15, 0=非法)
|3 0011 xxxx| 长度(字节数)    | unsigned   | n byte size of payload (1~15, 0=非法)
|4 0100 xxxx| 子类型          | float      | 1=32bit(IEEE754), 2=64bit(IEEE754), 3=80bit(x87)
|5 0101 xxxx| 内联值(高4bit)  | timestamp  | 低4bit=值的高4bit + 5B payload=低40bit, 共44bit
|6 0110 xxxx| 长度块字节数    | string     | 长度字段占 n+1 字节 (n=low4)，值为实际字节数，UTF-8
|7 0111 xxxx| 长度块字节数    | byte[]     | 长度字段占 n+1 字节 (n=low4)，值为实际字节数
|8 1000 xxxx| 内联长度/扩展   | array      | X=0~14 为元素个数；X=15 后跟2字节长度(0~65535)
+-----------+-----------------+------------+------------------------------------+
```

**timestamp**：字段头 `0x50 | t[43:40]`，payload 5B `t[39:0]`，基准 2000/1/1 UTC，精度毫秒，44bit 约 557 年。

**signed/unsigned 的 low4=0 为非法编码**：字段长度由 IDL `size` 决定，值为 0 时长度仍为 `size`，故 low4=0 不可达。解码遇 low4=0 抛解码错误。

### 9.2 长度语义

**统一规则**：字段头中携带的长度（signed/unsigned 的字节数、string/bytes 的长度块、array 的元素个数）**一律为该字段的实际长度**，由编码方按实际值填写。

| 字段类型 | 长度含义 | 取值来源 | 长度字段宽度 |
|---------|---------|---------|------------|
| signed / unsigned | 实际占用字节数（1~15） | IDL `size` | low4 本身 |
| string / bytes | 实际字节数 | 运行时内容长度 | low4+1 字节（1~16） |
| array | 实际元素个数（0~65535） | 运行时元素个数 | low4≤14 内联；low4=15 时 2 字节 |

**定长类型（`fixed_len`）**：线格式与变长完全一致——长度字段照旧传输与校验，仅长度值恒定：

| IDL 声明 | 长度字段 | 长度值 | 内容 |
|---------|---------|--------|------|
| 无 `fixed_len`/`max_len` | 有 | 实际长度 | 实际内容 |
| `max_len = N` | 有 | 实际长度（≤ N） | 实际内容 |
| `fixed_len = N` | 有 | 恒为 N | 按 N 原样占位，不做压缩 |

**约束校验**：

- **编码**：写入实际长度；`fixed_len` 时校验 `实际长度 == fixed_len`；`max_len` 时校验 `实际长度 ≤ max_len`；超 `max_payload_len` 时拒绝（UDP 场景返回 0x23）
- **解码**：读出长度后按同一规则校验，越界抛解码错误

### 9.3 结构体、数组与嵌套

**结构体**：N 个字段的有序组合，按字段顺序连续编码，无额外边界标记。

**数组**：类型标记为 `0x8X`，长度字段始终存在，后跟元素：

```
[0x8 | len] [元素1] [元素2] ... [元素N]          // len=0~14，直接为元素个数
[0x8F] [长度: 2字节] [元素1] ... [元素N]          // len>=15 时用扩展，2 字节为元素个数
```

**嵌套**：IDL 定义的数据类型可以任意嵌套（结构体含结构体/数组、数组元素为结构体/数组、多维数组）。嵌套按 schema 递归编码，每层自带长度字段，无额外边界标记。

### 9.4 解码流程

```
decode_fields(buf, schema):
  result = []
  while buf.has_remaining():
    type_byte = buf.read_u8()
    type_id = type_byte >> 4      // 高 4bit
    low4 = type_byte & 0x0F       // 低 4bit
    switch type_id:
      0x0: result.push(Null)
      0x1: result.push(Bool((low4 & 0x01) == 1))
      0x2: byte_len = low4
           if byte_len == 0: 抛 DecodeError::InvalidSignedLength
           result.push(Signed(buf.read_int_be(byte_len)))
      0x3: byte_len = low4
           if byte_len == 0: 抛 DecodeError::InvalidUnsignedLength
           result.push(Unsigned(buf.read_uint_be(byte_len)))
      0x4: switch low4:
             1: Float32(read_f32_be)
             2: Float64(read_f64_be)
             3: Float80(read_bytes(10))
             否则: 抛 DecodeError::UnsupportedFloatType
      0x5: t = (low4 << 40) | buf.read_uint_be(5)
           result.push(Timestamp(t))
      0x6: len = buf.read_uint_be(low4 + 1)
           check_len(len, schema)
           result.push(String(buf.read_bytes(len).to_utf8_string()))
      0x7: len = buf.read_uint_be(low4 + 1)
           check_len(len, schema)
           result.push(Bytes(buf.read_bytes(len)))
      0x8: array_len = low4 <= 14 ? low4 : buf.read_u16_be()
           check_len(array_len, schema)
           elems = []
           for _ in 0..<array_len: elems.push(decode_field(buf, schema.element_type))
           result.push(Array(elems))
      否则: 抛 DecodeError::UnknownFieldType
  return result
```

`check_len`：

| IDL 声明 | 校验 |
|---------|------|
| 无 `fixed_len`/`max_len` | 不校验（仅受 `max_payload_len` 约束） |
| `max_len = N` | 实际长度 ≤ N |
| `fixed_len = N` | 实际长度 == N |

### 9.5 字段编码示例

| 字段 | 编码字节 | 说明 |
|------|---------|------|
| `null` | `00` | — |
| `bool true` / `bool false` | `11` / `10` | — |
| `signed(1) -128` | `21 80` | low4=1 为字节数 |
| `unsigned(1) 255` | `31 FF` | — |
| `float32 3.14159` | `41 40 49 0F D0` | low4=1 为 32bit |
| `timestamp t=0x0000000001` | `50 00 00 00 00 01` | 高 4bit=0，低 40bit=1 |
| `string "hi"` | `60 02 68 69` | low4=0 → 长度字段 1 字节，值=2 |
| `string fixed_len=4 "abcd"` | `60 04 61 62 63 64` | 长度恒为 4，内容恰好 4 字节 |
| `bytes [0x00,0xFF]` | `70 02 00 FF` | — |
| `array<unsigned(1)> [1,2]` | `82 31 01 31 02` | low4=2 为元素个数 |
| `array fixed_len=10`（10 个 unsigned(1) 元素，值均为 1） | `8A 31 01 ×10` | 长度恒为 10，占位 10 个元素 |

### 9.6 CRC 校验

CRC 作为服务契约约定，不改帧格式。需要 CRC 的接口在 payload 末尾 2 字节放 CRC16，不需要的不放。CRC 校验由契约级编解码负责，通用帧解析层不感知 CRC 存在与否。

---

## 10. MSK 掩码机制

MSK=1 时，Payload Length 后插入 4B Masking Key，对 Data Fields 逐字节循环 XOR：

```
encoded[i] = payload[i] XOR maskingKey[i % 4]
```

- 每帧随机生成 4B Key；仅 XOR Data Fields（帧头与 Length 不处理），编解码对称
- MSK=0 明文传输
- **用途**：规避中间设备对载荷的误识别；**不是加密机制**，安全保证由环境层提供（见 §2）
- **CRC 与 MSK 顺序**：先算 CRC16 附加在 Data 末尾，再对整体（Data + CRC）应用 MSK XOR

---

## 11. IDL 与版本兼容

IDL 采用 JSON 格式。

### 11.1 IDL 语法

```json
{
  "version": "1.0",
  "service": {
    "name": "VehicleStateService",
    "svc_id": 0x1000,
    "major_ver": 1,
    "minor_ver": 0,
    "interfaces": [
      { "name": "GetState",     "if_id": 0x0001, "type": "rpc",   "transport": "TCP", "input": [], "output": "VehicleState" },
      { "name": "UpdateState",  "if_id": 0x0002, "type": "ff",    "transport": "TCP", "input": ["VehicleState"] },
      { "name": "UploadBlob",   "if_id": 0x0003, "type": "ff",    "transport": "TCP", "input": ["Blob"], "max_len": 1048576 },
      { "name": "StateChanged", "if_id": 0x8001, "type": "event", "transport": "UDP", "output": "VehicleState" }
    ],
    "event_groups": [
      { "name": "VehicleStateGroup", "grp_id": 1, "members": [0x8001, 0x8002] }
    ]
  },
  "type_def": {
    "structs": {
      "VehicleState": [
        { "name": "veh_md",     "type": "unsigned", "size": 1 },
        { "name": "usg_md",     "type": "unsigned", "size": 1 },
        { "name": "sys_pwr_md", "type": "signed",   "size": 1 },
        { "name": "timestamp",  "type": "timestamp" },
        { "name": "timestr",    "type": "string",   "fixed_len": 20 },
        { "name": "status_msg", "type": "string",   "max_len": 64 }
      ],
      "Blob": [
        { "name": "vin",     "type": "bytes", "fixed_len": 17 },
        { "name": "payload", "type": "bytes", "max_len": 64000 }
      ]
    },
    "enums": {
      "PowerMode": {
        "type": "unsigned", "size": 1,
        "values": { "Off": 0, "Accessory": 1, "Run": 2, "CrankRequest": 3 }
      }
    },
    "arrays": {
      "VehicleStateArray":  { "type": "array", "fixed_len": 10, "element_type": "VehicleState" },
      "VehicleStateArray2": { "type": "array", "max_len": 100,  "element_type": "VehicleState" }
    }
  }
}
```

**字段说明**：

| 字段 | 说明 |
|------|------|
| `svc_id` | 服务标识，全局唯一，各节点共享同一份 IDL |
| `if_id` | 接口标识，同一服务内唯一。0x0001~0x7FFF 用于 rpc/ff，0x8000~0xFFFF 用于 event |
| `type` | `rpc`（请求-响应）、`ff`（无响应调用）、`event`（事件推送） |
| `transport` | 传输协议绑定，`tcp` 或 `udp`，省略时按类型默认（rpc/ff=tcp，event=udp） |
| `input`/`output` | 参数/返回值类型，引用 `structs`/`arrays` 中定义的类型名 |
| `fixed_len` | 定长：string/bytes 的字节数、array 的元素个数。长度字段值恒为该值，内容完整占位（见 §9.2） |
| `max_len` | 变长上限：字段字节数或数组元素个数上限。UDP 接口建议 ≤ 1400；超限时编码报错、接收方回 0x23 |
| `element_type` | 数组元素类型，可为 struct 或 array（支持任意嵌套，见 §9.3） |
| `grp_id` / `members` | 服务内 8bit 组号（1~255）与该组包含的 event `if_id` 列表（见 §7.1） |
| `type` / `size` / `values` | enum 的底层类型、字节数与名称到整数的映射 |

**类型定义的三处位置**：`structs`（结构体）、`arrays`（数组类型）、`enums`（枚举），均可在 `input`/`output`/`element_type` 中被引用，支持任意层级嵌套。

`inst_id` 由运行时注册服务时提供，不在 IDL 中声明。`(SvcID, InstID)` 的跨节点唯一性属部署规划问题，不在协议与 IDL 职责范围内（见 §3.5）。

**IDL 工具链输出**：目标语言的数据结构定义与编解码实现、服务端/客户端 Stub、`transport` 绑定信息（供协议栈路由）。

### 11.2 版本兼容规则

| 变更类型 | MajorVersion | MinorVersion | 兼容性 |
|---------|-------------|-------------|--------|
| 新增字段（末尾） | 不变 | +1 | 向后兼容 |
| 新增可选字段 | 不变 | +1 | 向后兼容 |
| 删除字段 | +1 | 0 | 不兼容 |
| 修改字段类型 | +1 | 0 | 不兼容 |
| 新增接口 | 不变 | +1 | 向后兼容 |
| 删除接口 | +1 | 0 | 不兼容 |

**服务版本匹配规则**：

- SD Offer 携带 MajorVersion + MinorVersion
- SD Find Entry 携带 MajorVersion（MinorVersion 不参与匹配）
- 仅 MajorVersion 精确匹配即视为服务兼容；MinorVersion 由客户端自行判断
- MajorVersion 不匹配 → 服务不可用，客户端不得发起调用

区分两个层级：**协议版本 VER（帧格式级，见 §2，双方必须相等）** 与 **服务版本 Major/Minor（接口语义级，见本节）**，两者独立演化。

---

## 12. 错误处理与恢复

### 12.1 错误码总表

| 错误码 | 名称 | 触发条件 | 恢复策略 |
|--------|------|---------|---------|
| 0x00 | Protocol Violation | 帧头一致性校验失败（CTR/REN 组合非法、REN=1 时 TYP≠NON 或 Code≠0x00、ACK 时 Code≠0x00、SvcID/IfID/InstID 越界） | 丢弃帧，不响应（组播）；单播回 RST(0x00) |
| 0x20 | Bad Request | Payload 字段类型/顺序与契约不符、控制帧格式错误 | 应用层修正请求格式 |
| 0x21 | — | 保留 | — |
| 0x22 | Unsupported Version | VER 与本端不一致 | 双方需使用相同 VER |
| 0x23 | Payload Too Large | Payload 超过 max_payload_len 或 IDL max_len | 减小 Payload 或改用 TCP 接口 |
| 0x24 | Not Found | SvcID/IfID 无对应处理者 | 检查服务是否已注册/发现 |
| 0x25 | Method Not Allowed | Code 不支持（如服务端收到 Notification） | 检查请求类型 |
| 0x26 | Frame Timeout | TCP 帧间接收超时 | 检查网络/对端状态 |
| 0x27~0x2F | — | 保留 | — |
| 0x30 | Internal Error | 处理逻辑执行异常 | 服务端排查，客户端可重试 |
| 0x31 | Not Implemented | 请求的接口功能未实现 | 等待服务端实现 |
| 0x32 | — | 保留 | — |
| 0x33 | Service Unavailable | 服务临时不可用（如过载） | 客户端退避重试 |
| 0x34~0x3F | — | 保留 | — |

### 12.2 控制帧错误

控制帧错误码仅用于 SD 单播交互（Subscribe 失败响应）。组播 SD 操作（Offer/Find）不发送错误响应，不匹配时静默丢弃。

| 错误码 | 名称 | 触发条件 | 恢复策略 |
|--------|------|---------|---------|
| 0x20 | Bad Request (SD) | SD Entry 格式错误 | 忽略或记录日志 |
| 0x22 | Unsupported Version | VER 与本端不一致 | 忽略或记录日志（组播不回应） |
| 0x24 | Not Found (SD) | Find 查询的服务/实例不存在 | 无（组播 Find 不强制回应） |

### 12.3 传输层错误

| 场景 | 检测方式 | 恢复策略 |
|------|---------|---------|
| TCP 连接断开 | 连接不可用 | 清理该连接的所有 Stream 和订阅关系，通知应用层 |
| TCP 半帧超时 | 帧开始接收后超过 tcp_frame_timeout_ms | 回 RST(0x26)，丢弃残缺帧 |
| UDP 报文丢失 | 无检测（NON）或 ACK 超时（CON） | NON 不恢复；CON 重传至 max_retry |
| 服务端 REN=1 | 收到 REN 控制帧 | 清空该节点服务缓存 + 该对端全部 Stream/重传记录，等待 SD Offer 重建 |
| 响应超时（Request） | 应用层定时器触发 | 报应用层 RequestTimeout，同时取消该 StrmID 的待确认重传 |
| 重传耗尽（UDP CON） | 末次后等待 1600ms | 静默停止重传，清理待确认记录，不报错；请求成败由响应超时判定 |
| 重传到达（服务端） | 收到相同 StrmID 的重复请求 | 重发缓存响应，不重复执行处理逻辑 |

### 12.4 日志格式

```
[{Timestamp}][{level}][{svc_id:04X},{if_id:04X},{inst_id:02X}] {Tx|Rx},{addr} {strm_id:02X}, Code=0x{code:02X}, Msg={msg}
```

其中 `Msg` 取 §12.1 / §12.2 中的错误码名称（如 `Not Found`、`Payload Too Large`）。

---

## 13. 公共 API 契约

以下为应用层接口的语义契约。具体签名与语言绑定由各实现决定。

### 13.1 服务端

| 接口 | 语义 | 前置条件 | 失败条件 |
|------|------|---------|---------|
| `register_service(svc_id, inst_id, handler)` | 注册服务实例，进入 Offering 状态 | handler 覆盖该实例的全部 IfID | 本地 `(svc_id, inst_id)` 已被占用 |
| `unregister_service(svc_id, inst_id)` | 注销实例，停止 Offer 广播 | 实例已注册 | — |
| `notify(svc_id, inst_id, if_id, payload)` | 更新接口缓存并推送给所有订阅者 | 实例已注册 | 实例未注册 |

### 13.2 客户端

| 接口 | 语义 |
|------|------|
| `call(svc_id, inst_id, if_id, payload, timeout)` | 同步调用，阻塞至收到响应或超时；`timeout` 缺省取全局默认，可逐次指定 |
| `call_async(svc_id, inst_id, if_id, payload, timeout)` | 异步调用，立即返回；`timeout` 语义同 `call` |
| `fire_forget(svc_id, inst_id, if_id, payload)` | 无响应调用 |
| `subscribe(svc_id, inst_id, if_id, grp_id, on_event)` | 订阅事件；`if_id` 与 `grp_id` 二选一（整组订阅时 `if_id=0x0000`） |
| `unsubscribe(handle)` | 取消订阅（内部发送 Subscribe(TTL=0)） |
| `is_available(svc_id, inst_id)` | 查询实例可用性（本地缓存状态）：注册表中存在该实例、TTL 处于 Active、VER 与本端相等 |
| `find_service(svc_id, inst_id, timeout)` | 主动发现（触发 SD Find，刷新本地缓存）；返回该实例的在线信息（源地址、版本），不返回接口列表 |

### 13.3 服务端处理契约

| 接口 | 语义 |
|------|------|
| `on_request(if_id, payload)` | 处理 rpc 请求，返回响应字段序列或错误 |
| `on_fire_forget(if_id, payload)` | 处理 ff 调用，无返回值 |
| `push_policy()` | 推送策略：OnChange（数据变化时推送）或 Periodic(ms)（周期推送） |
| `on_notification(svc_id, if_id, inst_id, payload)` | 客户端侧：处理收到的事件推送 |

---

## 附录 A：配置参数默认值

| 参数 | 默认值 | 约束 |
|------|--------|------|
| `port` | 5400 | 1~65535 |
| `multicast_ipv4` | 224.0.1.187 | — |
| `multicast_ipv6` | ff02::1:BB | — |
| `period` | 2s | — |
| `ttl` | 4s | `ttl >= 2 * period` |
| `response_timeout_ms` | 2000 | > 0；可逐次调用覆盖 |
| `retransmit_interval_ms` | 200 | — |
| `retransmit_max` | 3 | 不含首次 |
| `tcp_frame_timeout_ms` | 5000 | > 0 |
| `heartbeat_period_ms` | 30000 | — |
| `heartbeat_timeout_ms` | 60000 | = 2 × heartbeat_period |
| `max_payload_len` | 1400 | > 0；UDP 接口另受 IDL `max_len` 约束 |

---

## 附录 B：术语对照表

| 术语 | 说明 |
|------|------|
| FW | FlatWire Protocol |
| CTR | Control Frame Flag（控制帧标志） |
| REN | Reboot Notification Flag（重启通知标志） |
| VER | Version（协议版本，双方必须相等） |
| MSK | Masking Flag（掩码标志） |
| PLB | Payload Length Block size（Length 字段字节数） |
| TYP | Transmission Type（CON/NON/ACK/RST） |
| CON | 需送达确认的帧，UDP 专用；TCP 上所有帧为 NON |
| ACK | 仅空确认（Code=0x00），UDP 专用，不承载应用数据 |
| RST | 拒绝/重置帧 |
| SD | Service Discovery（服务发现） |
| SvcID | Service ID（全局唯一） |
| IfID | Interface ID（服务内唯一） |
| InstID | Instance ID（与 SvcID 组成实例标识，跨节点唯一） |
| 服务实例 | `(SvcID, InstID)`，全局唯一标识一个部署实例 |
| StrmID | Stream ID（连接级流标识） |
| GrpID | Event Group ID（事件组号） |
| TTL | Time To Live（秒） |
| Peer | 对端节点地址（IP:Port），StrmID/重传记录隔离维度 |
| TtlState | TTL 条目状态：Active / Expired（见 §7.5） |
| period / ttl | Offer 与 Subscribe 共用的发送周期与有效期（`ttl >= 2 * period`） |
| fixed_len | IDL 定长声明：长度字段值恒为该值，内容完整占位 |
| max_len | IDL 变长上限：字段字节数或数组元素个数不得超过 |
| 去重键 | `(peer, svc_id, inst_id, StrmID)`，用于 CON 重传幂等判定 |
| 响应缓存 | 服务端按去重键缓存的上次响应，重传到达时直接重发 |
| 心跳 / Ping | 仅 TCP，空闲时发送的空帧；收到不回，无 Pong |
