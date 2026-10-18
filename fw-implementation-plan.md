# FlatWire Protocol v4.4 协议栈实现计划（双语言）

本文档是 JavaScript/Node.js 与 MoonBit 两个实现的**共享契约**。协议行为的唯一事实来源是规范原文——本文件仅定义模块划分、接口对应关系与技术决策，不复制规范细节。

## 0. 规范与基准文件

| 文件 | 角色 |
|------|------|
| `FlatWire Protocol (FW) Design.v4.md` | **规范全文（v4.4 终版，唯一事实来源）** |
| `FlatWire Protocol (FW) Test Cases.v4.md` | 一致性测试基准（9 大类） |
| `FlatWire Protocol (FW) Design.v4.4 终审报告.md` | 终审结论（实现就绪度已确认） |

## 1. 目录结构（两实现一一对应）

```
implementations/
├── fw-implementation-plan.md   ← 本文件
├── fw-nodejs/                  ← JavaScript/Node.js 实现
└── fw-moonbit/                 ← MoonBit 实现（编译到 JS 后端运行）
```

两实现内部模块划分保持一一对应：

```
src/
├── codec/      # §9  编解码：类型系统 / 恒定宽度 / CRC-16/CCITT-FALSE / MSK / null 语义
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

## 2. 公共接口契约（§13，两语言签名对应）

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

### 3.2 MoonBit 版（fw-moonbit）

- moon 构建系统，**target js**（`moon build --target js` 后以 node 运行）
- **核心逻辑纯 MoonBit**（codec/frame/sd/rpc/events/strm/errors 均不碰 FFI）
- **FFI 边界尽量窄**：仅传输层（绑定 node:dgram/node:net）+ 文件系统（IDL 库落盘/加载）+ 定时器，经 `extern "js"` 声明
- FFI 数据映射在边界层完成（Bytes ↔ Uint8Array 辅助转换）
- 工具链不可用时：交付完整源码 + 构建说明，如实报告验证状态

## 4. 关键规范索引（实现前必读原文，按此顺序）

1. **§3 帧格式** —— 8B 帧头字段布局（CTR/REN/VER/MSK/PLB、TYP/Code、SvcID/IfID、InstID/StrmID）、PLB 语义、Length 编码
2. **§4.3 解析流程** —— 十步校验顺序（步骤 1 含控制帧 MSK=0 校验；步骤 2 含 UDP GetIDL 拒绝；步骤 4 含 StrmID 语义级校验）
3. **§4.1 TCP 半帧两阶段** —— 帧头 <8B → RST(0x26)+关连接；帧头完整 → 丢弃模式（精确丢弃 R=L−已收；退出三条件；兜底 2×tcp_frame_timeout_ms 且每字节刷新计时）
4. **§9 编解码** —— 恒定宽度（low4==size 校验位）、CRC-16/CCITT-FALSE（自检值 0x29B1，先 CRC 后 XOR）、null 仅 optional、bool 严格解码、fixed_len 空位填 0x00、解码容忍末尾新增字段
5. **§5 传输语义** —— UDP CON 重传时间线（0/200/600/1400ms）、response_timeout_ms=2000、去重键 `(peer,svc,inst,StrmID)`、TCP 全 NON 无 CON/ACK、心跳仅 TCP
6. **§6 StrmID** —— 数据帧 0x01~0xFE；控制帧 0x00 连接级 / 0x01~0x7F 订阅会话+GetIDL 查询同池（按 peer、释放含冷却）
7. **§7 SD** —— Offer Entry 6B / Find Entry 4B / Subscribe Entry 7B / **GetIDL Entry 3B（无 InstID）**；GetIDL 仅 TCP 单播（UDP 收到 → RST(0x00)，组播静默）；触发双角色统一（调用/订阅/注册）；服务端匹配=库中已加载定义（与实例在线无关）；Payload≠3B → 0x20；服务不存在 → 0x24；落盘持久化（失败降级内存）；启动立即发 Find 预热
8. **§8 事件** —— Subscribe(TTL>0) 一律回 ACK(Code=0x10)（有/无缓存一致，重传重发 0x10 不重推全量）；取消 TTL=0 回 ACK(0x00) 回显会话 StrmID；tcp-event 须预建连接（否则 0x24）；断连订阅不失效；合并 Subscribe 逐 Entry 处理
9. **§12 错误码** —— 两层两码：帧级 `max_payload_len`（仅 UDP）→ 0x23；IDL 级（max_payload/max_len/fixed_len/SizeMismatch/UnexpectedNull）→ 0x20
10. **§2 部署** —— 单实例；组播 224.0.1.187 / ff02::1:BB，端口 5400；客户端 socket 临时端口；IP_MULTICAST_LOOP 开启；REN 组播 ×3 间隔 ~100ms 先发后关

## 5. 示例服务与 IDL

两实现共用同一业务示例（各自目录内自含副本）：取规范 §11.1 的 **VehicleState IDL**（svc_id=4096, major_ver=1），覆盖全部类型特性：signed/unsigned/timestamp/fixed_len string/max_len string/optional/float64/bytes/fixed_len bytes/enum/fixed_len array/max_len array。示例场景：

- NodeA：注册 VehicleState 服务实例（含 rpc/ff/event 接口 handler）
- NodeB：发现 → call → fire_forget → subscribe → 收推送；B 初始无 IDL → 自动 GetIDL 落盘 → 调用成功（验证 5.21/5.28）
- NodeA 重启 → REN ×3 → B 重新发现（验证 4.6/8.4）

## 6. 测试与验收

| 层级 | 内容 | 对应测试基准 |
|------|------|-------------|
| 单元 | CRC 自检值 0x29B1；§9 全类型编解码往返（含边界/非法编码抛错）；§4.3 解析矩阵（非法组合 → 正确 RST Code） | 1.1~1.35、2.9~2.21 |
| 半帧 | TCP 半帧两阶段全场景 | 2.5、2.22~2.29 |
| 传输 | 重传时间线 0/200/600/1400ms；超时终态；去重 | 3.10~3.16 |
| SD/GetIDL | 按需拉取/落盘持久化/本地命中/版本升级/双角色注册拉取/启动预热 | 5.1~5.36 |
| 事件 | 订阅确认链路/取消确认/合并订阅/tcp-event | 6.1~6.19 |
| 端到端 | 双进程发现→rpc→事件→GetIDL→REN 重启 | 8.1~8.8 |

## 7. 代码规范

- 代码注释使用**中文**，并标注规范条款出处（如 `// §4.3 步骤 4：控制帧 StrmID 语义校验`）
- 两实现的同名模块行为必须一致（逻辑可交叉对照）
- 不修改本语言 `fw_xxx/` 之外的任何文件；不修改任何规范/测试 md 文档
