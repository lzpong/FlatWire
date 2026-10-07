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
- **IDL 驱动开发**：JSON 格式 IDL 静态定义服务契约（接口、类型、传输绑定、版本），自动生成目标语言的编解码与 Stub，含明确的**服务版本兼容规则**。
- **扁平类型系统**：`null / bool / signed / unsigned / float / timestamp / string / bytes / array`，支持任意层级嵌套（结构体、数组、多维数组）。
- **载荷掩码（MSK）**：可选 4 字节 XOR 掩码，规避中间设备对载荷的误识别（注意：仅为混淆，**非加密机制**）。
- **面向受限环境**：默认 `max_payload_len = 1400`，协议栈不提供分块重组（大数据走 TCP 接口），资源占用可控。

***

## 设计原则

| 原则 | 说明 |
| --- | --- |
| 应用层协议 | 仅定义帧格式、交互语义与服务契约，不干预 TCP 状态机 |
| 统一端口 | TCP / UDP 共用预定义端口，由 `SvcID / IfID` 多路复用 |
| 双角色节点 | 节点可同时作服务端与客户端，两套状态独立维护 |
| 契约驱动 | 服务注册后自动广播 Offer；接口集合由 IDL 静态定义 |
| 扁平编码 | 协议数据始终为碾平字段序列，无嵌套边界标记 |
| 可信网络假设 | 协议层不提供安全保证，安全由环境层（封闭网络 / VPN / 链路加密）提供 |

***

## 快速开始

### 1. 定义服务契约（IDL）

以 JSON 描述服务、接口与数据类型，例如：

```json
{
  "service": {
    "name": "VehicleStateService",
    "svc_id": 0x1000,
    "major_ver": 1,
    "minor_ver": 0,
    "interfaces": [
      { "name": "GetState",    "if_id": 0x0001, "type": "rpc",   "transport": "TCP", "output": "VehicleState" },
      { "name": "StateChanged","if_id": 0x8001, "type": "event", "transport": "UDP", "output": "VehicleState" }
    ]
  },
  "type_def": {
    "structs": {
      "VehicleState": [
        { "name": "veh_md",     "type": "unsigned", "size": 1 },
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
└── docs/
    └── FlatWire Protocol (FW) Design.v4.md   # 规范性协议设计文档
```

***

## 文档

- **规范文档**：[`docs/FlatWire Protocol (FW) Design.v4.md`](./docs/FlatWire%20Protocol%20(FW)%20Design.v4.md)

    - 帧格式与解析（§3 / §4）
    - 交互语义与时序（§5）
    - 服务发现与 TTL 机制（§7）
    - 事件推送 / Notifier（§8）
    - 结构化数据字段与类型系统（§9）
    - IDL 语法与版本兼容（§11）
    - 错误码与恢复策略（§12）
    - 公共 API 契约（§13）
    - 配置参数与术语对照表（附录 A / B）

- **一致性测试**：规范中的一致性要求将抽离为独立测试用例文档（规划中）。

***

## 状态与路线图

- [x] 协议规范 v4（帧格式、SD、Notifier、IDL、错误码）
- [ ] IDL 工具链（生成编解码 / Stub / 传输绑定）
- [ ] 参考实现（服务端 / 客户端协议栈）
- [ ] 一致性测试套件
- [ ] 多语言绑定

***

## 许可证

[LICENSE](./LICENSE)（MIT，待补充版权信息）

***

## 贡献

欢迎通过 Issue 与 Pull Request 参与。涉及协议语义的改动请以规范文档为唯一权威，并同步更新一致性测试用例。