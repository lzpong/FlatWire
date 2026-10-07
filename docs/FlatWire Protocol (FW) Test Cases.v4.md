# FlatWire Protocol (FW) 一致性测试用例

对应规范：`FlatWire Protocol (FW) Design.v4.md`
用途：一致性判定基准。每条用例均对应规范中的一条可验证要求。

**判定**：全部用例通过 = 实现满足 FW v4 一致性要求。

---

## 1. 帧与编解码

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 1.1 | 帧头往返 | 全字段组合（CTR/REN/VER/MSK/PLB/TYP/Code/SvcID/IfID/InstID/StrmID） | 解码后字段值一致 |
| 1.2 | VER 不等拒绝 | VER ≠ 本端 | 组播静默丢弃；单播回 RST(0x22) |
| 1.3 | PLB 边界 | PLB=0 / PLB=7 | PLB=0 无 Length 字段；PLB=7 支持最大 Length |
| 1.4 | Payload Length 编码 | 0 / 1 / 255 / 65535 / 2^56-1 | 0→PLB=0；超大值→PLB=7 |
| 1.5 | Null | — | `00` |
| 1.6 | Bool | true / false | `11` / `10` |
| 1.7 | Signed 边界 | -128 / 0 / 127（1B） | 大端编码正确 |
| 1.8 | Unsigned 边界 | 0 / 255 / 65535 | 大端编码正确 |
| 1.9 | **Signed low4=0 非法** | 字段头 `0x20` | 抛 `InvalidSignedLength` |
| 1.10 | **Unsigned low4=0 非法** | 字段头 `0x30` | 抛 `InvalidUnsignedLength` |
| 1.11 | Float32/64 | 3.14159 | IEEE754 编码正确；NaN/Inf 往返一致 |
| 1.12 | Float 子类型非法 | low4=0 / low4≥4 | 抛 `UnsupportedFloatType` |
| 1.13 | Timestamp 边界 | 0 / 2^44-1 | 高 4bit + 低 40bit 拆分正确 |
| 1.14 | String | `"hello"` / `""` / `"中文"` | UTF-8 + 长度前缀（实际字节数） |
| 1.15 | Bytes | `[0x00,0xFF]` / 空 | 长度前缀 + 原始数据 |
| 1.16 | Array 内联长度 | 0~14 个元素 | `0x8X` 直接表示元素个数 |
| 1.17 | Array 扩展长度 | 15 / 65535 个元素 | `0x8F` + 2 字节长度 |
| 1.18 | **定长 string** | `fixed_len=4`，内容 `"abcd"` | 长度字段=4，内容占 4 字节 |
| 1.19 | **定长 string 长度不符** | `fixed_len=4`，传入 3 字节 | 报编码错误 |
| 1.20 | **定长 array 原样传输** | `fixed_len=20`，仅 12 个元素有值 | 长度字段=20，占位 20 个元素，不压缩 |
| 1.21 | **定长 array 长度不符** | `fixed_len=20`，传入 19 个元素 | 报编码错误 |
| 1.22 | max_len 超限 | `max_len=64`，传入 65 字节 | 报编码错误（UDP 场景返回 0x23） |
| 1.23 | **嵌套：结构体含结构体** | 内层字段按序展开 | 往返一致 |
| 1.24 | **嵌套：结构体含数组** | 数组带长度字段 | 往返一致 |
| 1.25 | **嵌套：数组元素为结构体** | 逐个元素按结构体编码 | 往返一致 |
| 1.26 | **嵌套：多维数组** | 逐层递归，每层带长度字段 | 往返一致 |
| 1.27 | UnknownFieldType | type_id = 0x9~0xF | 抛 `UnknownFieldType` |
| 1.28 | Masking XOR | payload + 4B key | 两次 XOR 还原；4B 对齐/不对齐均正确 |
| 1.29 | CRC + MSK 顺序 | 同时启用 | 先算 CRC16 附加，再整体 XOR；解码顺序相反 |
| 1.30 | 空 payload | PLB=0 | 帧大小 8B |

---

## 2. 帧解析

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 2.1 | TCP 粘包 | 一次接收含 3 帧 | 3 帧全部正确解析并交付 |
| 2.2 | TCP 分包 | 1 帧按 1 字节/次分多次写入 | 完整重组，无丢失/错位 |
| 2.3 | **Length 字段跨包** | Length 字段被拆分到两次接收 | 正确重组 |
| 2.4 | **Masking Key 跨包** | 4B Key 被拆分 | 正确重组 |
| 2.5 | TCP 半帧超时 | 写入帧头后停止 | `tcp_frame_timeout_ms` 后回 RST(0x26) |
| 2.6 | UDP 长度不符 | 数据报长度 ≠ 声明帧长度 | 丢弃，不截断 |
| 2.7 | UDP 过短 | 数据报 < 8B | 丢弃 |
| 2.8 | UDP 超限 | Payload > max_payload_len | 回 RST(0x23) |
| 2.9 | **REN=1 且 CTR=0** | 非法组合 | 回 RST(0x00) 并丢弃 |
| 2.10 | **REN=1 且 TYP≠NON** | 非法组合 | 回 RST(0x00) 并丢弃 |
| 2.11 | **REN=1 且 Code≠0x00** | 非法组合 | 回 RST(0x00) 并丢弃 |
| 2.12 | **TYP=ACK 且 Code≠0x00** | 非法组合 | 回 RST(0x00) 并丢弃 |
| 2.13 | 控制帧 SvcID/IfID 非 0 | 非法 | 回 RST(0x00) 并丢弃 |
| 2.14 | 数据帧 SvcID=0 | 非法 | 回 RST(0x00) 并丢弃 |
| 2.15 | 数据帧 InstID=0 | 非法 | 回 RST(0x00) 并丢弃 |

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

---

## 5. 服务发现

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 5.1 | Offer 广播 | 注册服务 | 每 `period` 收到组播 Offer |
| 5.2 | Find 空查询 | 空 Payload | 返回所有本地服务 |
| 5.3 | Find 指定 SvcID | SvcID 非零 | 只返回匹配的实例 |
| 5.4 | **Find 指定实例** | (SvcID, InstID) | 只返回该唯一实例 |
| 5.5 | **Entry 不含 IfID** | Offer / Find Entry | 仅含 SvcID/InstID/MajorVer/MinorVer/TTL（Find 为 5B，Offer 为 6B） |
| 5.6 | **Subscribe Entry 含 IfID** | Subscribe Entry | 含 SvcID/IfID/InstID/GrpId/TTL（7B） |
| 5.7 | TTL 倒计时 | 停止 Offer 后等待 | TTL 秒归零，下次 tick 移除 |
| 5.8 | **TTL=0 延迟移除** | 发送 TTL=0 | 本周期不移除，下次 tick 才移除 |
| 5.9 | **抖动容忍** | `period`=2s、`ttl`=4s，连续丢 1 个 Offer | 不误判离线 |
| 5.10 | **周期/TTL 约束** | `ttl < 2 * period` | 拒绝配置 |
| 5.11 | Offer 拆帧 | Entry 数超 max_payload_len | 按 MTU 满装拆多帧，逐帧独立解析 |
| 5.12 | 拆帧丢包兜底 | 部分 Offer 帧丢失 | 下一周期重新广播 |
| 5.13 | **同 SvcID 多 InstID** | 单节点注册 svc=0x1000 的 inst=1、2 | 两实例独立可用，互不覆盖 |
| 5.14 | **实例全局唯一** | 两节点报同一 (svc_id, inst_id) | 客户端记 Error 日志，保留先到，忽略后到 |
| 5.15 | VER 不等 | 对端 VER ≠ 本端 | 组播静默丢弃；单播回 RST(0x22) |
| 5.16 | 服务端状态机 | register → unregister | NotOffered → Offering → Stopped → NotOffered |
| 5.17 | 客户端状态机 | Unknown → Found → Subscribed → Unsubscribed → Expired | 按 §7.4 转换表 |

---

## 6. 事件推送

| # | 用例 | 输入 | 期望 |
|---|------|------|------|
| 6.1 | Subscribe 首次（有缓存） | 首次 Subscribe(TTL>0) | 推送全量 Notification |
| 6.2 | **Subscribe 首次（无缓存）** | 首次 Subscribe 且无缓存 | 回空 ACK（Code=0x00），客户端进入 Subscribed |
| 6.3 | Subscribe 保活 | 周期 Subscribe(TTL>0) | 服务端刷新计时（NON，不回 ACK） |
| 6.4 | Subscribe 离线 | 停止 Subscribe 后等待 | TTL 归零后停止推送 |
| 6.5 | Subscribe(TTL=0) | 发送取消订阅 | 下次 tick 移除订阅关系 |
| 6.6 | GrpId 整组订阅 | IfID=0x0000 且 GrpId>0 | 服务端展开为组内所有 event 接口 |
| 6.7 | 多客户端推送 | 多个订阅者 | 各自独立 StrmID 与 ACK 匹配 |

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
| 7.13 | 大数据超限 | UDP 接口传 > max_len | 编码报错 / 接收方回 0x23 |

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
| 9.6 | 跨实现互操作 | 不同语言实现使用相同 IDL | 帧级二进制一致 |
