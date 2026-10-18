# fw-nodejs —— FlatWire Protocol (FW) v4.4 协议栈（JavaScript/Node.js 实现）

FlatWire Protocol v4.4 车辆软件 RPC/事件推送协议栈的 Node.js 参考实现。

- **零第三方依赖**：仅使用 `node:` 内置模块（dgram / net / fs / crypto / events）
- **纯动态架构**（§11.1）：协议栈不内置任何 IDL、无代码生成、无 Stub——服务定义全部运行时从 IDL 库（本地文件夹）加载，编解码由协议栈按已加载 IDL 动态执行
- **ESM**（`"type": "module"`），要求 Node.js >= 18

## 运行

```powershell
# 单元测试（66 项：codec / frame / transport / sd-rpc）
npm test

# 示例（两个终端分别运行；NodeB 空 IDL 库起步，自动 GetIDL 落盘后调用成功）
node examples/node-a.js          # 服务端：注册 VehicleState（svc_id=4096）
node examples/node-b.js          # 客户端：发现 → call → fire_forget → subscribe → 收推送
```

示例细节见 `examples/node-a.js` / `examples/node-b.js` 头部注释（支持 `--run-for <ms>` 自动退出与环境变量 `FW_PORT` / `FW_BIND` / `FW_IDL_DIR` / `FW_LOG`）。

## 目录结构

```
fw-nodejs/
├── src/
│   ├── stack.js            协议栈入口：组装 + 应用 API（§13）+ 帧分发总线 + 生命周期
│   ├── errors.js           错误类型 + RST 错误码表（§12）
│   ├── logger.js           日志器（[模块] 描述：参数 格式；frame 级 Tx/Rx 日志）
│   ├── strm.js             StrmID 管理：数据帧池 + 控制帧统一池（§6，释放含冷却）
│   ├── codec/
│   │   ├── crc.js          CRC-16/CCITT-FALSE（§9.6，自检值 0x29B1）
│   │   ├── types.js        §9 全类型编解码（恒定宽度/optional/null/CRC/MSK-XOR）
│   │   └── schema.js       IDL 解析 + 接口级 payload 编解码（§11.1/§13）
│   ├── frame/
│   │   └── frame.js        8B 帧头编解码 + §4.3 十步解析 + §4.1 TCP 流式解析（半帧两阶段）
│   ├── transport/
│   │   ├── udp.js          §2 UDP 组播双 socket（main bind 5400 / client 临时端口）
│   │   └── tcp.js          TCP 长连接管理（帧超时两阶段/丢弃模式/心跳/复用）
│   ├── idlstore/
│   │   └── store.js        IDL 库：启动扫描 / GetIDL 落盘持久化 / 损坏跳过 / 内存降级
│   ├── sd/
│   │   ├── entries.js      §7.1 SD Entry 编解码（Offer 6B / Find 4B / Subscribe 7B / GetIDL 3B）
│   │   └── discovery.js    §7 SD 四操作 + 发现缓存状态机 + 订阅会话 + GetIDL 双角色触发
│   ├── rpc/
│   │   ├── retransmit.js   §5.5 UDP CON 重传时间线（0/200/600/1400ms）
│   │   └── rpc.js          §5.1 请求-响应 + 响应缓存去重 + §5.2 fire_forget
│   └── events/
│       └── events.js       §8 事件推送（接口缓存/全量推送/CON 推送重传/tcp-event）
├── examples/               示例（规范 §11.1 VehicleState IDL，实现计划 §5 场景）
└── test/                   node:test 单元测试（对齐《Test Cases.v4.md》编号）
```

## 规范章节 ↔ 模块映射

| 规范章节 | 内容 | 实现位置 |
| --- | --- | --- |
| §2 帧格式/部署 | 8B 帧头、PLB、MSK、组播双 socket、IP_MULTICAST_LOOP | `frame/frame.js`（编码）、`transport/udp.js`（部署） |
| §3.2~3.7 帧头字段/Code/TYP | CTR/REN/VER/MSK/PLB、TYP 传输类型、Code 码表 | `frame/frame.js` |
| §4.1 TCP 流式传输 | 半帧两阶段：帧头不完整→RST(0x26)+关连接；Payload 不完整→RST(0x26)+丢弃模式（R=L−已收精确丢弃，收满恢复，兜底=2×tcp_frame_timeout_ms） | `frame/frame.js`（StreamParser）+ `transport/tcp.js` |
| §4.3 解析流程 | 十步解析矩阵（MSK=0/VER/REN/TYP/Code/ID/StrmID 语义校验/0x23） | `frame/frame.js`（parseDatagram） |
| §4.4 RST | 回显触发帧标识、组播静默 | `frame/frame.js`（makeRst/echoPartial） |
| §5.1 请求-响应 | Request/Response（OK 0x10）、响应回显 StrmID | `rpc/rpc.js` |
| §5.2 fire_forget | 无响应调用（TCP/UDP 同为 NON） | `rpc/rpc.js` |
| §5.3 事件推送 | Notification（UDP NON/CON、TCP NON）、服务端流 0x80~0xFE | `events/events.js` |
| §5.5 重传与幂等 | CON 重传 0/200/600/1400ms、重复 CON 重发缓存响应/确认 | `rpc/retransmit.js` + `rpc/rpc.js` + `sd/discovery.js` |
| §5.6 TCP 连接 | 长连接复用、心跳（仅 TCP，30s Ping） | `transport/tcp.js` |
| §5.7 心跳 | Code=0x00 Ping 不回帧 | `transport/tcp.js` |
| §6 StrmID | 数据帧 0x01~0xFE；控制帧 0x00/0x01~0x7F 同池；释放冷却 | `strm.js` |
| §7.1~7.2 SD | 四操作 Entry、Offer 拆帧、Find 响应、GetIDL（仅 TCP、落盘持久化、双角色统一触发、启动 Find 预热） | `sd/entries.js` + `sd/discovery.js` + `idlstore/store.js` |
| §7.4~7.5 状态机/TTL | Unknown→Found→Subscribed→Expired；订阅/发现 TTL tick；自动重订阅 | `sd/discovery.js` |
| §8 订阅管理 | Subscribe(CON/NON)、ACK(0x10)/ACK(0x00)、全量推送、tcp-event 预建连接、逐 Entry 处理 | `sd/discovery.js` + `events/events.js` |
| §9 编解码 | 恒定宽度、CRC-16/CCITT-FALSE、optional/null、fixed_len 填 0、末尾新增字段容忍 | `codec/types.js` |
| §10 Masking | MSK=1 XOR（先 CRC 后 XOR）、控制帧禁 MSK | `codec/types.js` + `frame/frame.js` |
| §11.1 IDL | 纯动态加载、type_def 顶层、transport 绑定、事件组 | `codec/schema.js` + `idlstore/store.js` |
| §12 错误码 | 两层两码：帧级 0x23（仅 UDP）/IDL 级 0x20；RST 码表 | `errors.js` + 各模块 |
| §13 应用 API | register_service/call/fire_forget/notify/subscribe/find_service 等 | `stack.js` |
| §3.6 生命周期 | stop 发 REN×3（间隔 100ms）先发后关；REN 清缓存/重传记录/StrmID 序列 | `stack.js` + `sd/discovery.js` + `rpc/rpc.js` + `events/events.js` |
| 附录 A 参数 | 全部配置项默认值（时间单位 ms） | `stack.js`（DEFAULT_CONFIG） |

## 配置参数（附录 A 默认值）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `port` | 5400 | UDP/组播端口；TCP 监听同端口 |
| `multicast_ipv4` | 224.0.1.187 | 组播地址 |
| `period_ms` / `ttl_ms` | 2000 / 4000 | Offer 周期 / TTL（硬约束 ttl_ms ≥ 2×period_ms） |
| `response_timeout_ms` | 2000 | 响应/GetIDL 查询超时 |
| `retransmit_interval_ms` / `retransmit_max` | 200 / 3 | CON 重传间隔/次数（0/200/600/1400ms） |
| `tcp_frame_timeout_ms` | 5000 | TCP 半帧超时（丢弃模式兜底 = 2×） |
| `heartbeat_period_ms` | 30000 | TCP 心跳周期（仅 TCP） |
| `max_payload_len` | 1400 | UDP 帧级 Payload 上限（超限 → RST(0x23)） |
| `ver` | 0 | 协议版本 VER（不匹配 → RST(0x22)） |
| `idl_dir` | ./idl | IDL 库文件夹（`{svc_id}_v{major_ver}.json`） |
| `tcp_enabled` | true | TCP 监听开关（同机双栈演示时客户端角色栈关闭） |
| `bind_address` / `multicast_interface` | 空（全接口/系统选路） | 绑定地址与组播出口接口（多网卡/同机演示用） |
| `log_level` | info | debug/info/warn/error |

## 有意偏差与实现裁定

以下为规范未定义/规范内部矛盾处的保守实现选择（已在代码注释标注条款出处）：

1. **半帧 RST(0x26) 帧形态**（§4.1 未定义帧形态）：按 CTR=1 控制帧形态发送（全 0 标识——§4.3 步骤 3 数据帧 SvcID 必须≠0，故控制帧形态是唯一合法选择）；StrmID 仅在 0x01~0x7F 时回显否则置 0。
2. **RST 帧豁免控制帧 StrmID 校验**：RST 的 StrmID 是 §5.4 回显字段（数据帧触发时可达 0xFF）。若按 §4.3 步骤 4 语义校验，将形成「RST 判违规 → 回 RST → 对端再判违规」的互射风暴（实测验证过该风暴）。
3. **ACK(Code=0x00) 允许回显会话 StrmID（0x01~0x7F）**：§3.7 专项定案「Subscribe(TTL=0) 取消按一般 CON 回空确认 ACK(Code=0x00，回显会话 StrmID)」与 §4.3 步骤 4 一般规则「Code∈{0x00,0x01,0x02} → StrmID=0x00」存在规范内部矛盾；实现取专项定案（更具体、更晚定案）。**建议后续规范修订消除该矛盾**。
4. **控制帧 CON 形态仅 Subscribe 合法**：分发层对 CTR=1+TYP=CON 仅处理 Code=0x03，其余组合静默丢弃（解析层已校验 TCP 禁 CON/ACK、ACK/RST 码界）。
5. **组播启发式**（§4.4 平台限制）：Node.js dgram 无法获知数据报目的地址，UDP 上解析违规且 Code∈{0x01,0x02}（Offer/Find）的帧按组播帧静默丢弃，其余单播回 RST。
6. **Subscribe 单 Entry RST(0x24) 调和**（6.17/6.19）：单 Entry 帧指向本地完全不存在 (svc,inst) → RST(0x24)；多 Entry 帧逐 Entry 丢弃仍回确认（§7.2 Entry 级处理）。
7. **自我回环过滤**：指定 `bind_address` 时按该地址过滤本 socket 回环帧；未指定时按全部本机 IPv4 地址。同机双栈演示利用 127/8 多回环地址（A=127.0.0.1 / B=127.0.0.2）+ 共用端口避免 Windows 同端口单播投递竞争。
8. **接口级 `crc` 字段**：IDL 接口可声明 `"crc": true` 启用接口级 CRC（§9.6「CRC 作为服务契约约定」的实现落点）；省略 = 不启用。

## 测试

`npm test` 运行 66 项单元测试（`node:test`，对齐《Test Cases.v4.md》用例编号）：

- **codec（26）**：CRC 自检值 0x29B1、§9 全类型往返/边界/非法编码、MSK-XOR
- **frame（22）**：§4.3 解析矩阵（非法组合 → 正确 RST Code）、RST 回显形态
- **transport（8）**：TCP 粘包/分包/跨包、半帧两阶段全场景（精确丢弃/恢复/EOF/反向 RST 不污染正向流）
- **sd-rpc（10）**：重传时间线 200/600/1400ms、响应缓存去重、双栈真实回环集成（发现/GetIDL 拉取落盘/调用往返/订阅确认链路/事件推送/全量推送/取消确认/REN 清缓存）

集成冒烟（`examples/` 双进程真实回环）已验证：发现 → 空 IDL 库自动 GetIDL 落盘 → rpc 往返（含 optional/定长字段）→ fire_forget → 订阅确认 ACK(0x10) → 全量推送/实时推送 → 服务端优雅退出（REN×3）→ 客户端感知缓存清空 → 服务端重启后重新发现。
