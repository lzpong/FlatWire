# FlatWire Protocol v4.4 — MoonBit 实现

FlatWire Protocol v4.4 协议栈的 MoonBit 实现，编译目标为 JavaScript（Node.js 运行时）。
纯动态架构：协议栈不内置任何 IDL，服务定义运行时从 IDL 库（本地文件夹）加载，
客户端缺失定义时经 GetIDL 从集群自动拉取并持久化落盘（§7.2）。

## 构建 / 测试 / 运行

```powershell
# 工具链要求：moon（moonc v0.10.15+），JS 后端
$env:Path = "C:\Users\Ong\.moon\bin;$env:Path"   # moon 不在默认 PATH 时

cd implementations\fw-moonbit

# 运行全部单元测试（100 用例；必须显式指定 js 目标——extern "js" 不支持默认 wasm 后端）
moon test --target js

# 构建示例（产物位于 _build\js\debug\build\examples\...）
moon build --target js

# 启动服务端节点（预置 IDL：examples/node_a/idl/4096_v1.json）
node "_build\js\debug\build\examples\node_a\node_a.js" --run-for 45000

# 启动客户端节点（另一终端；IDL 库留空，验证 GetIDL 自动拉取落盘）
$env:FW_BIND = "127.0.0.2"
node "_build\js\debug\build\examples\node_b\node_b.js" --run-for 55000
```

双进程冒烟验证点（node_b 输出 `[VERIFY-N]` 标记）：

1. 服务发现（Offer/Find，发现缓存记录对端 udp_port）
2. GetIDL 自动拉取并落盘（本地库命中后重启不再重复查询）
3. rpc call 往返（GetState 返回 VehicleState 结构）
4. fire_forget（UpdateState / UploadBlob，TCP 全 NON）
5. 订阅确认（ACK 0x10）+ 事件推送交付（按接口 output 解码）
6. 服务端 REN 退出 → 客户端发现缓存清理（is_available 变 false）

环境变量：`FW_PORT`（UDP 端口，默认 5400）、`FW_BIND`（绑定地址，默认
NodeA=127.0.0.1 / NodeB=127.0.0.2，同机演示按回环 IP 区分单播投递）、
`FW_IDL_DIR`（IDL 库目录）。

## 模块结构

```
src/
  codec/     编码层（§9）：CRC-16/CCITT-FALSE（§9.1）、掩码（§9.2）、
             全类型 V* 编解码（恒定宽度规则、null 仅限 optional、定长空位填 0）
  frame/     帧层（§3/§4）：帧头（§3）、UDP 十步解析（§4.3）、
             TCP 半帧两阶段超时（§4.1 帧头不完整关连接 / Payload 不完整精确丢弃）
  errors/    错误码表（§11）：两层两码——帧级 0x23 / IDL 契约级 0x20（§8.1）
  strm/      StrmID 管理（§6）：控制帧池（订阅会话+GetIDL 查询，含释放冷却）/
             数据帧池（rpc/events 共享实例，client/server 子池独立）
  transport/ 传输层（§5.2/§5.6/§5.7）：UDP 双 socket（server=组播+5400 单播收 /
             client=临时端口）、TCP listen/connect/心跳、半帧超时 tick
  idlstore/  IDL 库（§11.1）：JSON 解析校验 + 文件落盘（GetIDL 持久化）
  sd/        服务发现（§7）：Offer/Find/REN/GetIDL 四操作、状态机（§7.6）、
             客户端订阅会话（§8.1）、服务端订阅登记（§8.2）
  rpc/       RPC（§5.1/§5.2/§5.5/§6.2）：call/fire_forget 客户端（CON 重传链
             0/200/600/1400ms + 响应超时、TCP 全 NON）+ 服务端分发
  events/    事件（§8.2）：tcp-event 推送（按订阅者源 IP 匹配连接）、
             UDP/组播推送、重复 CON 去重不重推全量
  stack/     协议栈组装（§2 单实例）：帧路由（CTR/Code 分流）、应用 API（§13.2）、
             IDL 编解码（stack_codec：FWValue ↔ 线缆格式，含 transport 绑定路由）
examples/
  node_a/    服务端示例：注册 VehicleStateService（4096 v1），提供
             GetState/UpdateState/UploadBlob 接口与 StateChanges 事件
  node_b/    客户端示例：发现 → GetIDL → call/ff → 订阅 → REN 感知（冒烟主脚本）
```

## FFI 边界（仅 js 后端）

MoonBit 与 Node.js 的边界位于各模块 `*_ffi.mbt`，通过 `extern "js"` 内联 JS 实现：

- **运行时上下文**：`globalThis.__fw` 承载 dgram/net 模块、UDP socket 表、TCP 连接
  Map、定时器表（进程内幂等初始化）。
- **数据表示**：MoonBit `Bytes` 在 JS 后端编译为 `Uint8Array`；发送侧 `Buffer.from`
  转换，接收侧 `new Uint8Array(buf)` 包装。
- **回调约定**：MoonBit 闭包编译为普通 JS 函数，可被 JS 事件回调直接调用；
  被 JS 侧异步长期持有的回调（收包/定时器/连接事件）标注 `#owned`，
  同步消费的 String/Bytes 参数标注 `#borrow`（函数级属性行，如
  `#borrow(dir, name)`——新版 moonc 对未注解 FFI 报 unannotated_ffi error）。
- **定时器**：句柄由 JS 侧 Map 托管返回自增 Int，规避 node Timeout 对象跨边界失配。
- **IDL 库落盘**：`idlstore/ffi` 封装 node:fs（mkdirSync/existsSync/读写），
  落盘失败降级为内存加载 + Error 日志（§7.2）。

## 规范 ↔ 模块对照

| 规范章节 | 实现位置 |
|---|---|
| §2 端口/地址语义 | `transport`（双 socket）+ `stack`（应答帧恒走 server socket） |
| §3 帧头 / §4.3 UDP 解析 | `frame/frame.mbt` `frame/parse.mbt` |
| §4.1 TCP 半帧两阶段 | `frame/tcp.mbt`（解析器）+ `transport`（tick 超时驱动） |
| §5.1/§5.2 call / fire_forget | `rpc/rpc_client.mbt` `rpc/rpc_server.mbt` |
| §5.5 CON 重传链 | `rpc/rpc.mbt`（interval × 2^retries） |
| §5.6 TCP 长连接复用 | `transport`（outbound 幂等键）+ `rpc`（连接等待队列） |
| §5.7 心跳 / 存活 | `transport`（tick 500ms 粒度检查） |
| §6 StrmID 管理 | `strm/strm.mbt` |
| §7 SD 四操作 / §7.6 状态机 | `sd/sd.mbt` `sd/entry.mbt` `sd/peer.mbt` |
| §7.2 GetIDL 双角色 | `sd/getidl.mbt`（客户端拉取）+ `sd/sd.mbt`（服务端应答） |
| §8.1/§8.2 订阅/事件 | `sd/sub_client.mbt` `sd/sub_server.mbt` `events/events.mbt` |
| §9 编码层 | `codec/` |
| §11 IDL 库 | `idlstore/` |
| §13.2 应用 API | `stack/stack_api.mbt` |

## 有意偏差（实现层决策，非协议变更）

1. **call 为回调式**：`Stack::call` 按响应回调返回结果（§13.2 call_async 语义）。
   MoonBit 无跨异步边界的阻塞等待原语；"同步 call" 由应用层在回调上实现。
2. **IDL 编解码位于 stack 层**（`stack/stack_codec.mbt`）：rpc/events 层只收发
   `Bytes`；FWValue ↔ 线缆格式的编解码与 transport 绑定路由集中在 stack 层完成。
3. **应用侧值为按序数组**：示例应用以 `@codec.V*` 值的数组按 IDL 字段序构造
   请求/事件负载（FWValue 无按名寻址）。
4. **tick 粒度 500ms**：半帧超时（§4.1）与心跳（§5.7）检查以 500ms 周期轮询驱动，
   超时判定按协议常量（tcp_frame_timeout_ms / 2×heartbeat_period_ms），粒度仅影响
   检查时刻精度，不影响判定阈值。
5. **UDP 应答帧 socket 固定**：服务端角色的应答帧（Offer、Subscribe 确认、SD RST、
   FF ACK、事件 UDP 推送）恒走 server socket（源端口 = fw_udp_port），保证对端
   发现缓存记录正确实例地址（§2）；客户端主动请求帧走 client socket。

## 依赖

- 工具链：moon / moonc（JS 后端），运行时：Node.js ≥ 18（dgram/net/fs）
- 无第三方包依赖；node 版参考实现（`../fw-nodejs`）仅作行为对齐，不参与构建
