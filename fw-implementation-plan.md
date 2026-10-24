# FlatWire Protocol v5.0 协议栈实现计划（三语言）

本文档是 JavaScript/Node.js、MoonBit 与 C 三个实现的**共享契约**。协议行为的唯一事实来源是规范原文——本文件仅定义模块划分、接口对应关系与技术决策，不复制规范细节。

## 0. 规范与基准文件

| 文件 | 角色 |
|------|------|
| `docs/FlatWire Protocol (FW) Design.v5.md` | **规范全文（v5.0，唯一事实来源）** |
| `docs/FlatWire Protocol (FW) Test Cases.v5.md` | 一致性测试基准（9 大类） |

> **部署约束：全网协议栈必须采用同一线格式版本**（裸字节编码）。不同线格式的实现不得混部。

## 1. 目录结构（三实现一一对应）

```
d:\E\FlatWire\
├── docs/                       # 规范与测试基准
├── fw-nodejs/                  # JavaScript/Node.js 实现
├── fw-moonbit/                 # MoonBit 实现（编译到 JS 后端运行）
├── fw-c/                       # C11 实现（CMake 跨平台）
└── fw-implementation-plan.md   ← 本文件
```

三实现内部模块划分保持一一对应：

```
src/
├── codec/      # §9  裸字节编解码：类型白名单 / 大端定宽 / 长度前缀推导 / CRC-16/CCITT-FALSE / MSK
├── frame/      # §3/§4 帧头 / §4.3 解析流程 / §4.1 半帧两阶段
├── transport/  # §2/§5 UDP 组播双 socket / TCP 长连接管理 / 心跳
├── sd/         # §7  SD 四操作：Offer / Find / Subscribe / GetIDL + 发现缓存 + 客户端状态机
├── idlstore/   # §11.1 IDL 库：加载 / 落盘 / 纯动态架构
├── rpc/        # §5  RPC / Fire-Forget：重传 / 超时 / 响应缓存去重
├── events/     # §8  事件推送：订阅确认 0x10 / 全量推送 / tcp-event 通道
├── errors      # §12 错误码（两层两码）
├── strm        # §6  StrmID 管理：分配 / 冷却 / 回绕
└── stack       # §13 协议栈入口（应用 API）
```

## 2. 公共接口契约（§13，三语言签名对应）

客户端侧：

| API | 语义 |
|-----|------|
| `register_service(svc_id, inst_id, idl, handlers)` | 注册服务实例；本地 IDL 库无定义时协议栈自动 GetIDL（§7.2 双角色） |
| `unregister_service(svc_id, inst_id)` | 注销（发 REN） |
| `call(svc_id, inst_id, if_id, payload, timeout?)` | 同步调用；拉取发生在发送前（§5.1） |
| `call_async(...)` | 异步调用 |
| `fire_forget(svc_id, inst_id, if_id, payload)` | FF 调用 |
| `subscribe(svc_id, inst_id, if_id|grp_id, on_event)` | 返回订阅句柄 handle（关联会话 StrmID） |
| `unsubscribe(handle)` | 发 Subscribe(TTL=0) |
| `is_available(svc_id, inst_id)` | 本地缓存判定 |
| `find_service(svc_id, inst_id, timeout?)` | 主动发现，返回在线信息（源地址/版本） |

服务端处理契约：`on_request(if_id, payload)` / `on_fire_forget(if_id, payload)` / `push_policy()` / `on_notification(svc_id, if_id, inst_id, payload)`（客户端侧事件回调）。

## 3. 技术决策

### 3.1 JavaScript/Node.js 版（fw-nodejs）

- Node.js >= 18，ESM（`"type": "module"`），**零第三方依赖**
- 仅用内置模块：`node:dgram` / `node:net` / `node:fs` / `node:path` / `node:test` / `node:events`
- 字节操作统一 `Buffer`；测试框架 `node:test`
- u64/i64 超出 `Number.MAX_SAFE_INTEGER` 时解码返回 BigInt（范围内返回 Number）

### 3.2 MoonBit 版（fw-moonbit）

- moon 构建系统，**target js**（`moon build --target js` 后以 node 运行）
- **核心逻辑纯 MoonBit**（codec/frame/sd/rpc/events/strm/errors 均不碰 FFI）
- **FFI 边界尽量窄**：仅传输层（绑定 node:dgram/node:net）+ 文件系统（IDL 库落盘/加载）+ 定时器，经 `extern "js"` 声明
- FFI 数据映射在边界层完成（Bytes ↔ Uint8Array 辅助转换）
- 遵循 MoonBit v0.9~v0.10.x 惯用法（`derive(Debug)`、显式 `pub extend`、`Repr(x)`、`Map([], capacity=N)`、`length()`）
- 工具链不可用时：交付完整源码 + 构建说明，如实报告验证状态

### 3.3 C 版（fw-c）

- **C11** + **CMake >= 3.15**，**零第三方依赖**（自带迷你 JSON 解析器）
- 单线程非阻塞事件循环（`poll` / `WSAPoll` 平台封装）
- 平台适配层：Winsock2 / POSIX（socket、monotonic 时间、目录扫描）
- 本机验收：MinGW-w64 gcc + Ninja（MSVC 编译选项已适配，未实测）

## 4. 关键规范索引（实现前必读原文，按此顺序）

1. **§3 帧格式** —— 8B 帧头字段布局（CTR/REN/VER/MSK/PLB、TYP/Code、SvcID/IfID、InstID/StrmID）、PLB 语义、Length 编码（v5 未改动）
2. **§4.3 解析流程** —— 十步校验顺序（步骤 1 含控制帧 MSK=0 校验；步骤 2 含 UDP GetIDL 拒绝；步骤 4 含 StrmID 语义级校验）
3. **§4.1 TCP 半帧两阶段** —— 帧头 <8B → RST(0x26)+关连接；帧头完整 → 丢弃模式（精确丢弃 R=L−已收；退出三条件；兜底 2×tcp_frame_timeout_ms 且每字节刷新计时）
4. **§9 裸字节编解码** —— 无字段头/类型标记；类型白名单 `u8/u16/u32/u64`、`i8/i16/i32/i64`、`f32/f64/f80`、`bool`、`timestamp`(6B)、`enum`(base)、`string/bytes/array`（必须 `fixed_len` 或 `max_len`；fixed 无前缀，max 前缀宽 ≤255→1B / ≤65535→2B / >65535→4B）；全字段必填（无 optional/null）；CRC 缺省关闭、接口 `crc: true` 开启；解码忽略末尾新增字段
5. **§5 传输语义** —— UDP CON 重传时间线（0/200/600/1400ms）、response_timeout_ms=2000、去重键 `(peer,svc,inst,StrmID)`、TCP 全 NON 无 CON/ACK、心跳仅 TCP
6. **§6 StrmID** —— 数据帧 0x01~0xFE；控制帧 0x00 连接级 / 0x01~0x7F 订阅会话+GetIDL 查询同池（按 peer、释放含冷却）
7. **§7 SD** —— Offer Entry 6B / Find Entry 4B / Subscribe Entry 7B / **GetIDL Entry 3B（无 InstID）**；GetIDL 仅 TCP 单播（UDP 收到 → RST(0x00)，组播静默）；触发双角色统一（调用/订阅/注册）；服务端匹配=库中已加载定义（与实例在线无关）；Payload≠3B → 0x20；服务不存在 → 0x24；落盘持久化（失败降级内存）；启动立即发 Find 预热
8. **§8 事件** —— Subscribe(TTL>0) 一律回 ACK(Code=0x10)（有/无缓存一致，重传重发 0x10 不重推全量）；取消 TTL=0 回 ACK(0x00) 回显会话 StrmID；tcp-event 须预建连接（否则 0x24）；断连订阅不失效；合并 Subscribe 逐 Entry 处理
9. **§12 错误码** —— 两层两码：帧级 `max_payload_len`（仅 UDP）→ 0x23；IDL 级字节契约违约（字段越界/截断、fixed_len 不符、max_len 超限、bool 非法、enum 超值域、CRC 失败）→ 0x20
10. **§2 部署** —— 单实例；组播 224.0.1.187 / ff02::1:BB，端口 5400；客户端 socket 临时端口；IP_MULTICAST_LOOP 开启；REN 组播 ×3 间隔 ~100ms 先发后关

## 5. 示例服务与 IDL

三实现共用同一业务示例（各自目录内自含副本，语义一致）：取规范 §11.1 的 **VehicleState IDL**（svc_id=4096, major_ver=1），覆盖：`u8/i8/timestamp/fixed_len string/max_len string/f64/bytes(fixed_len)/bytes(max_len)/enum(base)/fixed_len array/max_len array`。示例场景：

- NodeA：注册 VehicleState 服务实例（含 rpc/ff/event 接口 handler）
- NodeB：发现 → call → fire_forget → subscribe → 收推送；B 初始无 IDL → 自动 GetIDL 落盘 → 调用成功（验证 5.21/5.28）
- NodeA 重启 → REN ×3 → B 重新发现（验证 4.6/8.4）

## 6. 测试与验收

| 层级 | 内容 | 对应测试基准 |
|------|------|-------------|
| 单元 | CRC 自检值 0x29B1；§9 裸字节全类型编解码往返（定长无前缀、变长前缀宽度、值域/字节不足/超限抛错） | 1.1~1.38、2.9~2.21 |
| 半帧 | TCP 半帧两阶段全场景 | 2.5、2.22~2.29 |
| 传输 | 重传时间线 0/200/600/1400ms；超时终态；去重；心跳 | 3.1~3.23 |
| SD/GetIDL | 按需拉取/落盘持久化/本地命中/版本升级/双角色注册拉取/启动预热 | 5.1~5.36 |
| 事件 | 订阅确认链路/取消确认/合并订阅/tcp-event | 6.1~6.19 |
| 端到端 | 双进程发现→rpc→事件→GetIDL→REN 重启 | 8.1~8.8 |

**跨实现互操作**（v5 必测）：三向两两组合，至少验证 C↔JS、C↔MoonBit 双向全链路（发现/GetIDL/rpc/ff/订阅推送）。

## 7. 代码规范

- 代码注释使用**中文**，并标注规范条款出处（如 `// §4.3 步骤 4：控制帧 StrmID 语义校验`）
- 三实现的同名模块行为必须一致（逻辑可交叉对照）
- 不修改本语言 `fw-xxx/` 之外的任何文件；不修改任何规范/测试 md 文档
