# FlatWire Protocol (FW)

> 扁平编码 · 统一端口 · 服务契约驱动 —— 面向可信网络的应用层通信协议

FlatWire Protocol（FW）是一个**扁平化、契约驱动、轻量**的应用层协议，为分布式系统（尤其是车联网、物联网、嵌入式等资源受限场景）提供一套统一的**服务发现、服务调用与事件推送**通信模型。它不定义传输层的连接状态机，而是专注于**线格式、交互语义与服务契约**，让同一套代码逻辑可以在 TCP / UDP 之间平滑复用。

***

## 特性

- **扁平线格式**：固定 8 字节帧头，`Payload Length` 定界，协议数据始终为碾平后的字段序列，无嵌套边界标记。解析状态机简单，特别适合 MCU / 嵌入式环境。
- **统一端口复用**：TCP / UDP 共用预定义端口（默认 `5400`），通过 `SvcID / IfID / StrmID` 实现多路复用，无需为每种接口单独开端口。
- **双角色节点**：一个节点可同时作为服务端与客户端，两套状态独立维护，天然支持 P2P / 网关 / 设备互联。
- **内置服务发现（SD）**：基于 UDP 组播的 `Offer / Find / Subscribe`，周期广播 + TTL 生命周期管理，无需中心注册中心即可发现与订阅服务。
- **三种调用语义**：`rpc`（请求-响应）、`ff`（fire-and-forget，无响应调用）、`event`（事件推送），覆盖绝大多数分布式通信需求。
- **分层可靠性**：UDP 上由 `CON / ACK + 指数退避重传` 提供送达保证；TCP 由协议自身保障，不使用 CON/ACK。
- **IDL 驱动 + 纯动态架构**：JSON 格式 IDL 定义服务契约（接口、类型、传输绑定、版本）；协议栈**不内置 IDL、无代码生成、无 Stub**——服务定义运行时从 IDL 库加载（支持 GetIDL 按需拉取落盘），编解码由协议栈按已加载 IDL 动态执行，含明确的**服务版本兼容规则**。
- **裸字节类型系统**（v5.0）：`u8/u16/u32/u64`、`i8/i16/i32/i64`、`f32/f64`、`bool`、`timestamp`、`enum`、`string / bytes / array`，字段按 IDL 顺序**裸值大端连续编码**（无字段头、无类型标记），支持任意层级嵌套（结构体、数组、多维数组）。
- **载荷掩码（MSK）**：可选 4 字节 XOR 掩码，规避中间设备对载荷的误识别（注意：仅为混淆，**非加密机制**）。
- **Length 64 位语义**：`PLB` 取 0\~7，最长 7 字节大端 `Payload Length`，协议上限 2^56−1；各实现可设更低的实际承载上限，但**不得截断 Length 解析宽度**（见下"实现承载上限"）。
- **面向受限环境**：UDP 默认 `max_payload_len = 1400`，协议栈不提供分块重组（大数据走 TCP 接口），资源占用可控；TCP 无 `max_payload_len` 限制，单帧仅受协议上限与 IDL `max_payload`/`max_len` 约束。
- **发送背压（实现限制，非协议语义）**：TCP 数据帧走有界发送队列（单连接 256KB / 全栈 64MB），控制帧（RST/Ping/GetIDL 请求，CTR=1 且帧总长 ≤1024B）直写不入队；队列满时该帧**一字节不写**并返回"不可写"，调用方负责回滚/重试；自首次拒写持续满 2×`heartbeat_period_ms` 主动断连。

***

## 设计原则

| 原则 | 说明 |
| --- | --- |
| 应用层协议 | 仅定义帧格式、交互语义与服务契约，不干预 TCP 状态机 |
| 统一端口 | TCP / UDP 共用预定义端口，由 `SvcID / IfID` 多路复用 |
| 双角色节点 | 节点可同时作服务端与客户端，两套状态独立维护 |
| 契约驱动 | 服务注册后自动广播 Offer；接口集合由 IDL 定义（纯动态运行时加载） |
| 裸字节编码 | 字段按 IDL 顺序裸值连续编码：无字段头、无类型标记、无结构边界（v5.0） |
| IfID 分区仅建议 | 建议 `0x0001~0x7FFF` 用于 rpc/ff、`0x8000~0xFFFF` 用于 event（SHOULD）；实现**不得**因 IfID 落在另一区间而拒绝帧或拒绝加载 IDL，只要求 IfID ∈ `0x0001~0xFFFF` |
| 可信网络假设 | 协议层不提供安全保证，安全由环境层（封闭网络 / VPN / 链路加密）提供 |

***

## 快速开始

### 1. 定义服务契约（IDL）

以 JSON 描述服务、接口与数据类型，例如：

```json
{
  "service": {
    "name": "VehicleStateService",
    "svc_id": 4096,
    "major_ver": 1,
    "minor_ver": 0,
    "interfaces": [
      { "name": "GetState",    "if_id": 1,     "type": "rpc",   "transport": "tcp", "output": "VehicleState" },
      { "name": "StateChanged","if_id": 32769, "type": "event", "transport": "udp", "output": "VehicleState" }
    ]
  },
  "type_def": {
    "structs": {
      "VehicleState": [
        { "name": "veh_md",     "type": "u8" },
        { "name": "timestamp",  "type": "timestamp" }
      ]
    }
  }
}
```

### 2. 服务端注册并推送

```c
register_service(svc_id, inst_id, handler);   // 进入 Offering，自动广播 Offer
notify(svc_id, inst_id, if_id, payload);      // 更新缓存并推送给所有订阅者
```

### 3. 客户端发现与调用

```c
find_service(svc_id, inst_id, timeout);       // 主动发现
resp = call(svc_id, inst_id, if_id, payload); // 同步 RPC
subscribe(svc_id, inst_id, if_id, on_event);  // 订阅事件
```

> 具体 API 签名与语言绑定由各实现决定，详见规范 §13「公共 API 契约」。

***

## 仓库结构

```
flatwire-protocol/
├── README.md                # 本文件（项目简介）
├── LICENSE                  # 开源许可证
├── fw-implementation-plan.md    # 三实现共享契约（模块划分 / API 对应 / 技术决策）
├── docs/
│   ├── FlatWire Protocol (FW) Design.v5.md       # 当前规范（裸字节编码）
│   └── FlatWire Protocol (FW) Test Cases.v5.md   # 一致性测试基准
├── scripts/
│   └── interop.mjs          # 跨栈互通编排（六组两两组合，Windows/Linux 通用）
├── fw-nodejs/               # JavaScript/Node.js 实现（零依赖 ESM）
├── fw-moonbit/              # MoonBit 实现（JS 后端）
└── fw-c/                    # C11 实现（CMake 跨平台，零依赖）
```

***

## 实现状态

### 实现层资源上限（非协议语义，可配置）

| 项 | 默认 | fw-c | fw-nodejs | fw-moonbit |
| --- | --- | --- | --- | --- |
| 单连接发送队列 | 256KB | `max_send_queue_bytes` | `max_send_queue_bytes` | `__fw.q.connMax` |
| 全栈发送预算 | 64MB | `send_queue_budget_bytes` | `send_queue_budget_bytes` | `__fw.q.budget` |
| TCP 连接数上限 | 1024 | `max_conns`（入/出站统一计数） | `max_tcp_connections`（每侧独立） | **未实现**（不限制） |
| Strm 池空闲回收 | 300s | `strm_pool_idle_ms` | `strm_pool_idle_ms` | **未实现** |
| 心跳失效阈值 | 2×period | 固定 2×period | `heartbeat_timeout_ms` 可替换 | 固定 2×period |

### 解析约定（三栈一致）

- **TYP=RST 豁免步骤 3/4 的 ID 校验**：RST 的 `SvcID/IfID/InstID/StrmID` 是回显字段，取值来自触发帧，可能越界；接收方解析**任何** TYP=RST 帧时都跳过 §4.3 步骤 3/4，**不区分 CTR**（RST 自身也可能是数据帧）。RST 的形态与 Code 值域仍在步骤 2 校验。若仍校验会形成"RST 判违规 → 回 RST → 对端再判违规"的回环风暴。
- **数据帧 ACK 不豁免**：ACK 的回显 ID 必须落在合法范围，仍执行步骤 3/4，违规回 RST(0x00)。控制帧 ACK(Code=0x00) 回显会话 StrmID 是步骤 4 的明文例外。

### 实现承载上限（协议上限 2^56−1）

| 实现 | 单帧实际承载上限 | 依据 |
| --- | --- | --- |
| fw-c | 2^32−1（交付结构 `payload_len` 为 uint32；解析/丢弃计数按 64 位） | 64 位平台上解析器可完整表示 2^56−1 |
| fw-nodejs | 2^53−1（JS 安全整数，超出按实现上限拒绝：UDP 0x23 / TCP 0x00）；实际分配另受 `Buffer` 上限约束 | JS `Number` 精确整数范围 |
| fw-moonbit | 无显式单帧上限（TCP 按声明长度缓冲，实际受 JS 数组/内存约束）；Length 声明与丢弃计数按 `Int64` 计算，UDP 先经 Int64 比较再转 Int 交付 | `frame/parse.mbt` + `frame/tcp.mbt` |

### 测试命令与数字（本机实测）

| 实现 | 命令 | 数字 |
| --- | --- | --- |
| fw-c | `cmake -B build -G Ninja && cmake --build build && ctest --test-dir build`（或 `build\fw_tests.exe`） | 12 个套件 / 99 项用例，全部通过 |
| fw-nodejs | `npm test`（`node --test`） | 105 项：codec 32 / frame 44 / transport 16 / sd-rpc 11 / self-offer 2，全部通过 |
| fw-moonbit | `moon test --target js` | 138 项，全部通过；背压实测 `moon run examples/bp_probe --target js` |

### 跨栈互通自动化（`scripts/interop.mjs`）

验证三套实现在**不同语言之间**仍可互通（单栈单测覆盖不到该维度）。

```powershell
# 前置构建（Node 免构建）
cmake --build fw-c/build --config Release --target fw_node_a fw_node_b
cd fw-moonbit; moon build --target js; cd ..

# 六组两两组合：C/Node/MoonBit 分别作 A 与 B
node scripts/interop.mjs
```

- 每组独立 `FW_PORT`（5450 起，组间 +2），A 绑 `127.0.0.1`、B 绑 `127.0.0.2`（同机同端口不能绑同一回环地址），B 的 `FW_IDL_DIR` 指向空目录以强制 GetIDL 拉取。
- 判定口径：B 退出码 0 且 `[VERIFY-1]`~`[VERIFY-5]` 齐全；A 必须由 `--run-for` **自然退出**（非强杀），以验证优雅退出（REN×3）不留脏进程。
- 超时兜底：等待 A 输出 `stack started` 25s、B 45s；超时清理整棵子进程树并判该组失败。日志在 `tmp/interop/<组>/`。

***

## 文档

- **规范文档**：[`docs/FlatWire Protocol (FW) Design.v5.md`](./docs/FlatWire%20Protocol%20(FW)%20Design.v5.md)

    - 帧格式与解析（§3 / §4）
    - 交互语义与时序（§5）
    - 服务发现与 TTL 机制（§7）
    - 事件推送 / Notifier（§8）
    - 结构化数据字段与类型系统（§9）
    - IDL 语法与版本兼容（§11）
    - 错误码与恢复策略（§12，含 §12.6 发送背压等实现限制）
    - 公共 API 契约（§13）
    - 配置参数与术语对照表（附录 A / B）

- **一致性测试**：[`docs/FlatWire Protocol (FW) Test Cases.v5.md`](./docs/FlatWire%20Protocol%20(FW)%20Test%20Cases.v5.md)（9 大类一致性判定基准）

***

## 状态与路线图

- [x] 协议规范 v5.0（裸字节编码：无字段头；帧格式、SD、Notifier、IDL、错误码）
- [ ] IDL 工具链（生成编解码 / Stub / 传输绑定）——纯动态架构下不需要代码生成
- [x] 参考实现（fw-nodejs / fw-moonbit / fw-c 三语言协议栈）
- [x] 一致性测试套件（三实现单测，用例编号对齐 Test Cases.v5.md：C 99 / Node 105 / MoonBit 138）
- [x] 跨栈互通自动化（`scripts/interop.mjs`：六组两两组合，B 退出码 + VERIFY 标记 + A 自然退出三重判定）
- [ ] 多语言绑定

***

## 许可证

[LICENSE](./LICENSE)（MIT，待补充版权信息）

***

## 贡献

欢迎通过 Issue 与 Pull Request 参与。涉及协议语义的改动请以规范文档为唯一权威，并同步更新一致性测试用例。