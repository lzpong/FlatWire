# FlatWire Protocol (FW) 一致性测试用例

对应规范：`FlatWire Protocol (FW) Design.v5.md`
用途：一致性判定基准。每条用例均对应规范中的一条可验证要求。

## 0. 变更历史

| 版本 | 变更概况 |
|------|---------|
| v5.0 | 与规范 v5.0 同步：线格式改为**裸字节编码**（无字段头/类型标记，字段按 IDL 顺序裸值大端连续编码）；IDL 类型独立化为 u8/u16/u32/u64、i8/i16/i32/i64、f32/f64/f80（取消 size/width）；**删除 optional/null**（全字段必填）；string/bytes/array 强制声明 fixed_len 或 max_len（否则 IDL 加载失败），fixed_len 无长度前缀、max_len 前缀宽度按 ≤255→1B / ≤65535→2B / >65535→4B 推导；timestamp 6B；enum 改用 base（默认 u8，可 i8 支持负值），未知值透传；CRC 缺省关闭（接口 `"crc": true` 开启）；§1 用例组全组重写（1.1~1.38），§9 兼容性同步调整 |

**判定**：全部用例通过 = 实现满足 FW v5.0 一致性要求。

---

## 1. 帧与编解码

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 1.1 | 帧头往返 | 全字段组合（CTR/REN/VER/MSK/PLB/TYP/Code/SvcID/IfID/InstID/StrmID） | 解码后字段值一致 |
| 1.2 | VER 不等拒绝 | VER ≠ 本端 | 组播静默丢弃；单播回 RST(0x22) |
| 1.3 | PLB 边界 | PLB=0 / PLB=7 | PLB=0 无 Length 字段；PLB=7 支持最大 Length |
| 1.4 | Payload Length 编码 | 0 / 1 / 255 / 65535 / 2^56-1 | 0→PLB=0；超大值→PLB=7 |
| 1.5 | **IDL 变长字段强制声明** | string/bytes/array 既无 `fixed_len` 也无 `max_len` | **IDL 加载失败**（该定义被拒绝，其他定义不受影响） |
| 1.6 | Bool 严格解码 | `0x00` / `0x01` / `0x02` | `0x00`→false、`0x01`→true；`0x02` 抛 `InvalidBoolEncoding` |
| 1.7 | Signed 边界（裸字节） | i8 -128/0/127；i64 值 10 | 1B/8B 大端补码正确；**值 10 仍占满 8B**（恒定宽度，不压缩） |
| 1.8 | Unsigned 边界（裸字节） | u8 0/255；u64 值 10 | 1B/8B 大端正确；**值 10 仍占满 8B** |
| 1.9 | **字段字节不足** | 声明 u32 的字段，payload 仅剩 3B | 解码失败 → 数据帧回 RST(0x20) |
| 1.10 | **整型值域越界** | u8 编码值 300；i8 编码值 128 | 编码报错（值域校验） |
| 1.11 | Float32/64 | 3.14159；NaN / +Inf / -Inf | IEEE754 大端编码；往返一致 |
| 1.12 | f80 可选支持 | IDL 声明 `f80` | 本端支持 → 10B 往返一致；不支持 → **IDL 加载失败** |
| 1.13 | Timestamp 边界 | 0 / 2^48-1 | 6B 大端往返一致（2000 基准毫秒） |
| 1.14 | String 变长 | `"hello"` / `""` / `"中文"`，`max_len=64` | 1B 长度前缀（UTF-8 字节数）+ 内容 |
| 1.15 | Bytes 变长 | `[0x00,0xFF]` / 空，`max_len=64` | 1B 长度前缀 + 原始字节 |
| 1.16 | **长度前缀宽度推导** | `max_len` = 255 / 256 / 65535 / 65536 | 前缀宽度依次为 1B / 2B / 2B / 4B（大端） |
| 1.17 | **array 变长** | `max_len=100`，0 / 2 / 100 个元素 | 1B 元素个数前缀 + 裸元素（元素无类型头） |
| 1.18 | **定长 string 无前缀** | `fixed_len=4`，内容 `"abcd"` | 裸 4B 内容，**无长度字段** |
| 1.19 | **定长 string 长度不符** | `fixed_len=4`，传入 3 字节 / 5 字节 | 编码报错（输入必须恰为 4） |
| 1.20 | **定长 array 无前缀** | `fixed_len=20`，传入 20 个元素（12 个业务值，其余默认值） | 裸 20 个元素，**无长度字段**，空位填充默认值（数值 0 / bool 0x00） |
| 1.21 | **定长 array 长度不符** | `fixed_len=20`，传入 19 个元素 | 编码报错 |
| 1.22 | max_len 超限 | `max_len=64`，传入 65 字节 | 编码报错；接收方解码校验失败回 0x20（TCP/UDP 一致） |
| 1.23 | **嵌套：结构体含结构体** | 内层字段按序裸排 | 往返一致（无边界标记） |
| 1.24 | **嵌套：结构体含数组** | 数组按自身声明编码 | 往返一致 |
| 1.25 | **嵌套：数组元素为结构体** | 逐个元素裸排 | 往返一致 |
| 1.26 | **嵌套：多维数组** | 外层 `fixed_len=3`、内层 `fixed_len=4`；外层 `max_len=3`、内层 `max_len=4` | 定长层无前缀、变长层有前缀；往返一致 |
| 1.27 | **enum 负值** | `base: "i8"`，值 -1 / -128 | 编码 `FF` / `80`，解码回 -1 / -128 |
| 1.28 | **enum 未知值透传** | `base: "u8"`，收到 IDL 未声明的值 200 | 不报错，按整型保留 200 交付应用（MinorVer 兼容） |
| 1.29 | **enum 值域校验** | `base: "u8"`，编码值 300；`values` 内重复值 | 编码报错 / IDL 加载失败 |
| 1.30 | Masking XOR | payload + 4B key | 两次 XOR 还原；4B 对齐/不对齐均正确 |
| 1.31 | CRC + MSK 顺序 | 同时启用 | 先算 **CRC-16/CCITT-FALSE**，2 字节**大端**附加，再整体 XOR；解码顺序相反 |
| 1.32 | 空 payload | PLB=0 | 帧大小 8B |
| 1.33 | **CRC 标准自检值** | `CRC-16/CCITT-FALSE("123456789")` | 结果 = `0x29B1` |
| 1.34 | **CRC 缺省关闭** | 接口未声明 `"crc": true` | payload 末尾**无** 2B CRC，字段序列原样 |
| 1.35 | **CRC 开启与校验** | 接口 `"crc": true`，正常 / 篡改 1 字节 | 正常：末尾 2B CRC 通过；篡改：回 RST(0x20) |
| 1.36 | **末尾新增字段忽略** | 旧解码器 + 新端在末尾新增字段 | 旧端按 schema 解完既有字段后忽略剩余字节，不报错 |
| 1.37 | **类型错配探测** | 两端 IDL 宽度不一致（u8 ↔ u16），接口启用 CRC | CRC 校验失败 → RST(0x20)（不静默错解） |
| 1.38 | **大端统一** | u16 值 0x1234；i16 值 -2 | `12 34`；`FF FE` |

---

## 2. 帧解析

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 2.1 | TCP 粘包 | 一次接收含 3 帧 | 3 帧全部正确解析并交付 |
| 2.2 | TCP 分包 | 1 帧按 1 字节/次分多次写入 | 完整重组，无丢失/错位 |
| 2.3 | **Length 字段跨包** | Length 字段被拆分到两次接收 | 正确重组 |
| 2.4 | **Masking Key 跨包** | 4B Key 被拆分 | 正确重组 |
| 2.5 | TCP 半帧超时——帧头不完整（<8B） | 写入部分帧头字节（<8B）后停止发送 | `tcp_frame_timeout_ms` 后回 RST(0x26) 并**关闭连接**（帧总长不可知，无法重同步；客户端按 §5.6 自动重连） |
| 2.6 | UDP 长度不符 | 数据报长度 ≠ 声明帧长度 | 丢弃，不截断 |
| 2.7 | UDP 过短 | 数据报 < 8B | 丢弃 |
| 2.8 | UDP 超限 | UDP Payload > max_payload_len | 回 RST(0x23)（`max_payload_len` 仅适用 UDP；TCP 不做此校验） |
| 2.9 | **REN=1 且 CTR=0** | 非法组合 | 回 RST(0x00) 并丢弃 |
| 2.10 | **REN=1 且 TYP≠NON** | 非法组合 | 回 RST(0x00) 并丢弃 |
| 2.11 | **REN=1 且 Code≠0x00** | 非法组合 | 回 RST(0x00) 并丢弃 |
| 2.12 | **TYP=ACK 且 Code 非法** | 数据帧 ACK Code≠0x00；控制帧 ACK Code∉{0x00, 0x10} | 回 RST(0x00) 并丢弃 |
| 2.13 | 控制帧 SvcID/IfID 非 0 | 非法 | 回 RST(0x00) 并丢弃 |
| 2.14 | 数据帧 SvcID=0 | 非法 | 回 RST(0x00) 并丢弃 |
| 2.15 | 数据帧 InstID=0 | 非法 | 回 RST(0x00) 并丢弃 |
| 2.16 | **ACK/RST PLB>0** | TYP=ACK 或 RST 且 PLB>0 | 回 RST(0x00) 并丢弃 |
| 2.17 | **控制帧 StrmID 校验（范围 + 语义）** | REN 帧 StrmID≠0 / Subscribe·GetIDL 帧 StrmID=0x00 / Subscribe·GetIDL 帧 StrmID∈0x01~0x7F / 连接级帧（Offer/Find/Ping）StrmID≠0 | REN 帧 StrmID≠0 → RST(0x00)；Subscribe/GetIDL 携带 0x00 → RST(0x00)；携带 0x01~0x7F 合法（见 §3.5/§7.2）；连接级帧携带 0x01~0x7F → 单播 RST(0x00)、组播静默丢弃（语义级校验，见 §4.3 步骤 4） |
| 2.18 | **数据帧 StrmID 越界** | 数据帧 StrmID=0x00 / StrmID=0xFF | 回 RST(0x00) 并丢弃（数据帧 StrmID ∈ 0x01~0xFE） |
| 2.19 | **数据帧 IfID=0** | 数据帧 SvcID≠0 但 IfID=0x0000 | 回 RST(0x00) 并丢弃（ID=0 通配仅 SD Entry 场景） |
| 2.20 | **RST Code 非法** | TYP=RST 且 Code=0x01（非错误码） | 回 RST(0x00) 并丢弃（RST Code ∈ {0x00} ∪ 0x20~0x3F） |
| 2.21 | **TCP 收 CON/ACK** | TCP 连接上收到 TYP=CON 或 ACK 帧 | 回 RST(0x00) 并丢弃（TCP 不使用 CON/ACK） |
| 2.22 | **TCP 半帧超时——帧头完整** | 写入完整帧头（≥8B，帧总长 L 已知，含 Length/Masking Key）后停止发送 | `tcp_frame_timeout_ms` 后回 RST(0x26)，进入**丢弃模式**：按帧头声明精确丢弃剩余 R = L − 已收字节，**不关闭连接** |
| 2.23 | **丢弃模式——收满恢复** | 进入丢弃模式后继续发完剩余 R 字节，随后发送正常新帧 | 收满 R 字节即恢复正常接收（`IDLE`），新帧正确解析交付，**连接继续复用不重建** |
| 2.24 | **丢弃模式——字节刷新计时** | 丢弃模式中慢速发送剩余字节：相邻字节间隔 < 兜底超时，总时长超过兜底超时 | 每收到任意字节刷新兜底计时，不触发超时断连，收满 R 后恢复正常 |
| 2.25 | **丢弃模式——对端 EOF** | 进入丢弃模式后发送端关闭连接（EOF/RST） | 随连接关闭一并处理，无悬挂丢弃状态（进程死亡时 OS 必然关闭连接，接收端立即感知，不依赖超时） |
| 2.26 | **丢弃模式——兜底超时** | 进入丢弃模式后完全停止发送 | `2 × tcp_frame_timeout_ms` 后关闭连接（协议固定倍率，不新增配置项） |
| 2.27 | **发送端收 RST(0x26) 语义** | 发送帧过程中收到对端 RST(0x26) | 将本次请求/推送**标记失败**（不等响应、不再重传），仍**机械发完当前帧剩余字节**（TCP 字节流无法取消已排队数据） |
| 2.28 | **反向 RST 不污染正向流** | 接收端在丢弃模式中回 RST(0x26) 后继续接收 | RST(0x26) 为反向独立帧，正向字节流对齐不受影响；发送端后续正常帧无误位 |
| 2.29 | **控制帧 MSK 违规** | 控制帧（CTR=1）MSK=1 | 回 RST(0x00) 并丢弃（控制帧固定 MSK=0、不附加 CRC，见 §10/§9.6——跨实现互操作硬性约定） |

---

## 3. 传输语义与可靠性

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 3.1 | **RPC 的 TYP（UDP）** | 发送 Request | TYP=CON |
| 3.2 | **RPC 的 TYP（TCP）** | 发送 Request | TYP=NON |
| 3.3 | **FF 的 TYP（UDP）** | 发送 Fire-Forget | TYP=CON |
| 3.4 | **FF 的 TYP（TCP）** | 发送 Fire-Forget | TYP=NON |
| 3.5 | **Response TYP** | UDP 收到 Response | TYP=CON（非 ACK） |
| 3.6 | **Response 回显 StrmID** | 发送 Request(StrmID=0x05) | Response 的 StrmID=0x05 |
| 3.7 | CON→ACK | UDP 发送 CON，等待 ACK | ACK 按 `(peer, svc, inst, StrmID)` 匹配，待确认记录清除 |
| 3.8 | NON 不回 ACK | UDP 发送 NON | 对端不回任何确认 |
| 3.9 | **TCP 无 CON/ACK** | TCP 上发送任意帧 | TYP=NON，协议栈不重传 |
| 3.10 | 重传时间线 | 模拟 ACK 丢失 | 发送 4 次（1 原始 + 3 重传），时刻 0/200/600/1400ms |
| 3.11 | 指数退避 | 多次重传 | 间隔 200ms / 400ms / 800ms |
| 3.12 | 停止重传 | 末次后 | 1600ms 后静默停止，不报错 |
| 3.13 | **超时终态** | 响应超时 2000ms 先触发 | 报 RequestTimeout，取消重传，不再报其他错误 |
| 3.14 | **超时晚于停止重传** | 响应超时配置 > 3000ms | 3000ms 后不再重传但仍等待；超时前收到响应算成功 |
| 3.15 | **重传去重** | 服务端收到同一 StrmID 的重复请求 | 重发缓存响应，处理逻辑仅执行 1 次 |
| 3.16 | **响应重传去重** | 客户端重复收到同一响应 | 按 StrmID 判定为重复，只交付首个 |
| 3.17 | RST 处理 | 发送无效请求 | 收到 RST，Stream 释放 |
| 3.18 | 非活跃 StrmID 的 ACK/RST | 收到未知 StrmID 的 ACK/RST | 直接丢弃 |
| 3.19 | **心跳无风暴** | 收到 Ping | 不回任何帧；链路不产生循环帧 |
| 3.20 | **心跳空闲判定** | 距上次发送任意帧超过 heartbeat_period | 发送一次 Ping |
| 3.21 | **心跳不叠加** | 有业务流量 | 不发送 Ping |
| 3.22 | **心跳存活判定** | 收到任意帧 | 刷新存活计时 |
| 3.23 | **心跳超时** | 2 × heartbeat_period 未收帧 | 标记连接失效 |

---

## 4. Stream 与 REN

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 4.1 | StrmID 循环 | 单对端分配 128 次 | 从 0x01 回绕到 0x01 |
| 4.2 | StrmID 隔离 | 两个对端同时分配 | 各自独立，无冲突 |
| 4.3 | Stream 生命周期 | 分配 → 收到 Response | Active → Closed |
| 4.4 | **REN 处理** | 收到 REN=1 | 清该对端服务缓存 + 活跃表 + 重传记录；其他节点不受影响 |
| 4.5 | **REN 后旧 ACK 丢弃** | REN=1 后收到延迟的旧 ACK | 因查不到对应 Stream 而被丢弃 |
| 4.6 | **REN 发送规则** | graceful shutdown | 经 UDP 组播**连发 3 次** REN（TYP=NON，间隔 ~100ms），**先发后关**（先发完 3 次再释放资源/关闭 TCP 连接） |
| 4.7 | **双角色 REN** | 纯订阅方（客户端）重启 | 同样组播发送 REN ×3；服务端收到后加速清理该订阅者 |

---

## 5. 服务发现

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 5.1 | Offer 广播 | 注册服务 | 每 `period_ms` 收到组播 Offer |
| 5.2 | Find 空查询 | 空 Payload | 返回所有本地服务 |
| 5.3 | Find 指定 SvcID | SvcID 非零 | 只返回匹配的实例 |
| 5.4 | **Find 指定实例** | (SvcID, InstID) | 只返回该唯一实例 |
| 5.5 | **Entry 不含 IfID** | Offer / Find Entry | 仅含 SvcID/InstID/MajorVer/TTL（Find 为 **4B**，MinorVer 已删；Offer 为 6B） |
| 5.6 | **Subscribe Entry 含 IfID** | Subscribe Entry | 含 SvcID/IfID/InstID/GrpId/TTL（7B） |
| 5.7 | TTL 倒计时 | 停止 Offer 后等待 | TTL 秒归零，下次 tick 移除 |
| 5.8 | **TTL=0 延迟移除** | 发送 TTL=0 | 本周期不移除，下次 tick 才移除 |
| 5.9 | **抖动容忍** | `period_ms`=2000、`ttl_ms`=4000，连续丢 1 个 Offer | 不误判离线 |
| 5.10 | **周期/TTL 约束** | `ttl_ms < 2 * period_ms` | 拒绝配置 |
| 5.11 | Offer 拆帧 | Entry 数超单帧容量 | 按 `max_payload_len`（1400，**仅 UDP**）满装拆多帧，逐帧独立解析 |
| 5.12 | 拆帧丢包兜底 | 部分 Offer 帧丢失 | 下一周期重新广播 |
| 5.13 | **同 SvcID 多 InstID** | 单节点注册 svc=0x1000 的 inst=1、2 | 两实例独立可用，互不覆盖 |
| 5.14 | **实例全局唯一** | 两节点报同一 (svc_id, inst_id) | 客户端记 Error 日志，保留先到，忽略后到 |
| 5.15 | VER 不等 | 对端 VER ≠ 本端 | 组播静默丢弃；单播回 RST(0x22) |
| 5.16 | 服务端状态机 | register → unregister | NotOffered → Offering → Stopped → NotOffered |
| 5.17 | 客户端状态机 | Unknown → Found → Subscribed → Unsubscribed → Expired | 按 §7.4 转换表 |
| 5.18 | **并发控制 CON 不串行** | 同一对端并发订阅两个服务（不同会话 StrmID） | 两个 Subscribe(CON) 各自独立重传与确认（去重键 `(peer,0,0,StrmID)` 按会话区分），互不阻塞 |
| 5.19 | **控制帧去重按会话** | 同一会话 StrmID 的重复 Subscribe(CON) 到达 | 判定为重传，重发该会话确认，不重复建立订阅 |
| 5.20 | **常规 Offer 刷新** | Found/Subscribed 期间收到该实例 Offer(TTL>0) | 实例发现缓存 TTL 刷新，状态不变（实例级维护，与订阅 TTL 无关） |
| 5.21 | **GetIDL 按需自动触发** | 客户端调用本地 IDL 库中不存在该 (SvcID, MajorVer) 的服务（如 call），SD 发现缓存有在线实例 | 协议栈**自动**发起 GetIDL(Code=0x04, TCP, StrmID=栈内分配) → 服务端回 `Code=0x11` **回显该 StrmID**，Payload=完整 IDL JSON → 协议栈校验 svc_id/major_ver 与请求一致 → **落盘写入 IDL 库** → 加载 → 调用继续并成功（全程应用无感知，见 §7.2/§11.1） |
| 5.22 | **发现缓存无实例不查询** | 调用本地 IDL 库不存在的 SvcID，但 SD 发现缓存无该服务在线实例 | **不发起 GetIDL**，调用直接失败（服务不可用），错误上抛应用 |
| 5.23 | **GetIDL 定义不存在** | GetIDL(SvcID=S, MajorVer) 到达服务端，本地 IDL 库中无该 (SvcID, MajorVer) 已加载定义（从未部署 / 定义已卸载 / 版本不匹配） | 回 RST(0x24)（回显 StrmID），客户端调用失败上抛，IDL 库状态不变 |
| 5.24 | **GetIDL MajorVer 不匹配** | GetIDL Entry 的 MajorVer ≠ 服务端已加载 IDL 的 MajorVer | 回 RST(0x24)（回显 StrmID），客户端调用失败上抛 |
| 5.25 | **UDP 收 GetIDL 拒绝** | UDP 单播发送 GetIDL(Code=0x04) | 回 RST(0x00)（传输绑定违规，GetIDL 仅 TCP 单播）；组播帧静默丢弃 |
| 5.26 | **大 IDL TCP 承载** | 服务端 IDL JSON > 1400B，客户端按需拉取 | 响应单帧完整承载（TCP 无 max_payload_len 约束，不拆帧不报 0x23），落盘加载成功 |
| 5.27 | **GetIDL Payload ≠3B** | Payload <3B 或 >3B（非 1×Entry）或 Entry SvcID=0 | 回 RST(0x20)（回显 StrmID），客户端调用失败上抛 |
| 5.28 | **拉取落盘持久化** | 5.21 拉取成功后重启客户端协议栈，再次调用同 (SvcID, MajorVer) | 本地 IDL 库命中（文件仍在），**不发起 GetIDL** 直接编解码调用成功 |
| 5.29 | **本地命中不查询** | IDL 库已有该 (SvcID, MajorVer) 时调用/订阅 | 不产生 GetIDL 帧，直接动态编解码；监听确认链路上无 Code=0x04 |
| 5.30 | **版本升级重新拉取** | 服务端 MajorVer 1→2（重新注册），客户端 IDL 库仅有 v1；客户端经 Offer 获知 v2 后调用 | 本地无 (SvcID, 2) → 协议栈自动 GetIDL(MajorVer=2) → 拉取落盘（与 v1 并存不覆盖）→ 调用成功 |
| 5.31 | **并发拉取关联与去重** | 同一 TCP 连接并发调用两个本地无 IDL 的服务（SvcID=A/B）；同一 SvcID 并发多次首调 | 两个 GetIDL 各自回显 StrmID 正确关联不串扰；同一 (SvcID, MajorVer) 的并发首调建议合并为单次查询（实现建议，见 §7.2） |
| 5.32 | **超时重发幂等** | GetIDL 查询超时后协议栈重发（新 StrmID） | 服务端无状态正常响应，两次结果一致；首次迟到响应按 StrmID 已释放被丢弃 |
| 5.33 | **服务端注册自动拉取** | 节点 A 本地 IDL 库无 SvcID=S 的定义，`register_service(S, inst, handler)`；SD 发现缓存有节点 B 的 S 在线实例 | 协议栈自动 GetIDL(S, MajorVer=发现缓存版本) → 落盘加载 → 注册继续进入 Offering（**新节点部署只需 handler，IDL 自动从集群同步**）；B 的 Offer/服务不受影响 |
| 5.34 | **注册拉取失败** | 节点 A 注册 SvcID=S，本地无定义且发现缓存无在线实例（或 GetIDL 拉取 0x24/超时） | 注册失败上抛应用，IDL 库状态不变（不写入失败结果）；**应用可重试**——发现缓存随启动 Find 与周期 Offer 更新后重试可成功（见 §13.1） |
| 5.35 | **实例注销但定义在库** | 服务端 S 的最后实例 unregister 后（IDL 定义文件仍在库中且已加载），收到 GetIDL(S, MajorVer) | 正常回 0x11（IDL 为服务级事实，与实例在线无关，见 §7.2）——集群 IDL 同步在服务瞬时下线窗口内仍可完成 |
| 5.36 | **启动 Find 预热** | 协议栈启动（单实例部署约束，见规范 §2） | 立即发送一次 Find（空 Payload，查询所有服务）加速发现缓存预热；后续 register/call 的 IDL 按需拉取在启动早期即可命中在线实例 |

---

## 6. 事件推送

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 6.1 | Subscribe 首次（有缓存） | 首次 Subscribe(TTL>0, CON)，服务端有缓存 | 建立订阅 + 回 `ACK(Code=0x10)`（订阅建立确认）+ **随后**推送全量 Notification（数据分发，非确认信号）；客户端收到 0x10 进入 Subscribed |
| 6.2 | **Subscribe 首次（无缓存）** | 首次 Subscribe 且无缓存 | 回 `CTR=1, TYP=ACK, Code=0x10`（订阅已建立，兼作传输确认），客户端 Found→Subscribed |
| 6.3 | Subscribe 保活 | 周期 Subscribe(TTL>0, NON) | 服务端刷新 TTL，**不回任何确认** |
| 6.4 | Subscribe 离线 | 停止 Subscribe 后等待 | TTL 归零后停止推送 |
| 6.5 | Subscribe(TTL=0) | 发送取消订阅（CON，同会话 StrmID） | 服务端回 `ACK(Code=0x00)`（回显会话 StrmID），下次 tick 移除订阅关系；客户端收确认后释放会话 StrmID |
| 6.6 | GrpId 整组订阅 | IfID=0x0000 且 GrpId>0 | 服务端展开为组内所有 event 接口 |
| 6.7 | 多客户端推送 | 多个订阅者 | 各自独立 StrmID 与 ACK 匹配 |
| 6.8 | **会话 StrmID 复用** | 同一订阅的首次/保活/取消 | 全程复用客户端分配的同一 StrmID（0x01~0x7F）；确认帧回显该 StrmID |
| 6.9 | **确认丢失恢复** | 无缓存场景，0x10 确认在 UDP 上丢失 | 客户端重传 Subscribe(CON) → 服务端按重传判定**重发 Code=0x10** → 客户端进入 Subscribed（无永久卡死路径） |
| 6.10 | **重传不重推全量** | 有缓存场景，Subscribe(CON) 重传到达（订阅已存在） | 服务端**重发 `ACK(Code=0x10)`，不重新执行、不重推全量**（确认与数据解耦，见 §8.1） |
| 6.11 | **Found 收推送容错** | 客户端处于 Found 时收到事件推送 | 容错交付事件（不因状态机严格模式丢弃），状态视确认到达情况迁移 |
| 6.12 | **自动重订阅** | 订阅有效期内实例 Expired→Found（订阅登记仍存在） | 协议栈自动重新 Subscribe（分配新会话 StrmID），无需应用层介入 |
| 6.13 | **REN 清订阅登记** | 收到服务端 REN=1 | 该对端订阅登记清除，不自动重订阅（等待 SD Offer 重建后由应用重新订阅） |
| 6.14 | **重启窗口幂等** | 服务端重启后收到客户端重传的 Subscribe(CON) | 服务端无该会话缓存 → 按新订阅处理（从无到有，全量推送） |
| 6.15 | **合并订阅部分无效** | 一个 Subscribe 帧携带 2×Entry，Entry1 有效、Entry2 服务不存在 | Entry1 订阅生效；Entry2 丢弃 + Error 日志；仍回 `ACK(Code=0x10)`（订阅建立确认）；整帧无法解析才回 RST(0x20) |
| 6.16 | **Entry 组合非法** | Subscribe Entry IfID=0 且 GrpId=0（既非单接口也非组） | 该 Entry 丢弃 + Error 日志，不整帧拒绝 |
| 6.17 | **tcp-event 无连接订阅** | 订阅 transport=tcp 的 event，客户端未预建 TCP 连接 | 服务端回 RST(0x24)，订阅不建立 |
| 6.18 | **tcp-event 断连不失效** | tcp-event 订阅建立后 TCP 连接断开 | 订阅记录保留（按 TTL 维护），推送暂停不补发；客户端重连后推送自动恢复 |
| 6.19 | **订阅被拒状态迁移** | Subscribe(CON) 指向不存在服务 | 收到 RST(0x24)：客户端停止重传、释放会话 StrmID、停留 Found 并报订阅失败 |

---

## 7. 服务层与集成

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 7.1 | Request-Response | 发送 Request | 响应字段正确，StrmID 回显 |
| 7.2 | 响应超时 | 服务端不响应 | 定时器到期后报 RequestTimeout（唯一终态） |
| 7.3 | **超时可单独设置** | 单次调用传入 timeout_ms | 覆盖全局默认 |
| 7.4 | Fire-Forget | 发送 FF | 服务端处理，无响应 |
| 7.5 | Notification | 订阅后触发事件 | 客户端收到推送 |
| 7.6 | 未知服务 | 请求未注册服务 | 回 RST(0x24) |
| 7.7 | 处理异常 | 处理逻辑抛异常 | 回 RST(0x30) |
| 7.8 | 多路复用 | 并发 10 个 Request | 各 Stream 独立，响应匹配正确 |
| 7.9 | 重复注册 | 本地重复注册同 (svc_id, inst_id) | 第二次返回 Err，不覆盖原处理者 |
| 7.10 | **find_service 返回** | 调用 find_service | 只返回在线信息（源地址、版本），不返回接口列表 |
| 7.11 | **is_available 判定** | 实例存在且 TTL=Active 且 VER 相等 | 返回 true |
| 7.12 | 大数据接口 | 声明 transport=TCP，传 1MB | 正常传输 |
| 7.13 | 大数据超限 | UDP 接口传 > max_len | 编码报错 / 接收方回 0x20（IDL 级超限归解码错误；帧级 `max_payload_len` 超限才回 0x23，见 §12.1） |
| 7.14 | **TCP 不受 max_payload_len 约束** | TCP 接口单帧传 > 1400 字节（如 1MB） | 正常传输（`max_payload_len` 仅 UDP；TCP 仅受 IDL `max_payload`/`max_len` 约束） |
| 7.15 | **subscribe 返回 handle** | 调用 subscribe | 返回订阅句柄；`unsubscribe(handle)` 使用该句柄取消对应订阅会话 |
| 7.16 | **subscribe 先于发现** | 实例尚未 Found 时调用 subscribe | 协议栈登记订阅意图，收到该实例 Offer 后进入 Found，随后自动发起 Subscribe（见 §13.2） |
| 7.17 | **实例析构主动取消** | 应用实例析构/删除持有订阅句柄 | 协议栈主动发送 unsubscribe（Subscribe TTL=0），不等待 TTL 自然过期（见 §13.2） |

---

## 8. 端到端集成

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 8.1 | 双节点发现 | NodeA 注册，NodeB 发现 | B 能发现 A 的服务 |
| 8.2 | 请求响应 | B 向 A 发送 Request | A 响应，B 收到正确数据 |
| 8.3 | 事件推送 | A 推送事件 | 所有订阅者收到 |
| 8.4 | 节点重启 | A 重启 | B 收 REN=1 并重新发现 |
| 8.5 | 网络分区 | 断开 5s 后恢复 | 服务 TTL 过期后重新发现 |
| 8.6 | 双角色 | 节点同时为服务端与客户端 | 两套状态互不干扰 |
| 8.7 | 多实例发现 | A 注册 svc=0x1000 的 inst=1，C 注册 inst=2 | B 可分别定位，地址各自正确 |
| 8.8 | 实例迁移 | 实例迁到新节点 | 旧实例 TTL 过期后由新地址 Offer 重建 |

---

## 9. 兼容性

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 9.1 | 新增字段兼容 | MinorVer+1，末尾新增字段 | 旧客户端忽略，新客户端正常解析 |
| 9.2 | 新增接口兼容 | MinorVer+1，新增 event 接口 | 旧客户端不订阅，不影响已有功能 |
| 9.3 | 删除接口不兼容 | MajorVer+1，删除 rpc 接口 | 旧客户端调用返回 0x24 |
| 9.4 | 字段类型变更不兼容 | MajorVer+1，Signed→Unsigned | 双方 MajorVer 不匹配，无法通信 |
| 9.5 | VER 相等性 | 对端 VER ≠ 本端 | 组播静默丢弃；单播回 RST(0x22) |
| 9.6 | 跨实现互操作 | 不同语言实现使用相同 IDL | 帧级二进制一致（含 bool 规范编码、恒定宽度、CRC-16/CCITT-FALSE） |
| 9.7 | **新增 IDL 类型不兼容** | MinorVer 不变，字段使用新类型名（非既有白名单） | 违反兼容规则：**新增类型 = Major 不兼容变更**（旧解码器无对应宽度，无法定界跳过） |
| 9.8 | **enum 未知值 Minor 兼容** | MinorVer+1，enum 新增取值 | 旧客户端按 base 整型透传未知值，不报错，既有字段正常解析 |
