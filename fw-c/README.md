# fw-c —— FlatWire Protocol (FW) v4.4 协议栈（C 语言实现）

FlatWire Protocol v4.4 车辆软件 RPC/事件推送协议栈的 C11 跨平台实现。

- **C11**（`-std=c11`）：MSVC VS2019+ / GCC / Clang 均可编译；**零第三方依赖**
- **单线程非阻塞事件循环**（poll/WSAPoll 平台封装），无多线程/锁
- **纯动态架构**（§11.1）：协议栈不内置任何 IDL、无代码生成、无 Stub——服务定义全部运行时从 IDL 库（本地文件夹）加载，编解码由协议栈按已加载 IDL 动态执行
- 自带迷你 JSON 解析器（仅解析 IDL schema：对象/数组/字符串含转义/数字/bool/null）；GetIDL 响应直接回 IDL 库文件原文字节（不做序列化往返）
- 自写轻量测试框架（assert 宏 + 用例计数），挂 CTest

## 构建与运行

### Windows（MinGW-w64，本机验证环境）

```powershell
# 本机工具链：gcc 16.1.0（MSYS2 mingw64）+ Ninja（C:\msys64\mingw64\bin）
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="C:/msys64/mingw64/bin/gcc.exe"
cmake --build build
ctest --test-dir build          # 或直接运行 build\fw_tests.exe

# 双进程冒烟（两个终端，或如下一次性编排）
cd build
.\fw_node_a.exe 5400            # 服务端：注册 VehicleState（svc_id=4096），默认 bind 127.0.0.1
.\fw_node_b.exe 5400            # 客户端：发现 → call → fire_forget → subscribe，默认 bind 127.0.0.2
```

> **MSVC**：`cmake -B build-msvc -G "Visual Studio 17 2022"` 后 `cmake --build build-msvc --config Release`（已通过 `/W4` 编译选项适配）。
>
> **MinGW Makefiles 生成器**：本机无 `mingw32-make`，MSYS2 `/usr/bin/make` 与该生成器不兼容（路径转义问题），故以 Ninja 验证；安装 `mingw32-make` 后 `cmake -B build -G "MinGW Makefiles"` 等价可用。

### Linux / macOS

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build
```

### ARM 交叉编译示例

```bash
cmake -B build-arm \
  -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
  -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-arm -j
```

平台适配层：`src/platform/win.c`（Winsock2 / WSAStartup / QueryPerformanceCounter / FindFirstFile / Sleep）与 `src/platform/posix.c`（close/fcntl/opendir/clock_gettime/nanosleep）双实现，按 `_WIN32` 自动选择。

## 目录结构（与 fw-nodejs 模块一一对应）

```
fw-c/
├── CMakeLists.txt
├── include/fw/fw.h            # 唯一公共头：§13 应用 API + 内部模块契约（测试共用）
├── src/
│   ├── platform/              # 平台适配：sockets / time / fs / dir_scan（win.c + posix.c）
│   ├── codec/                 # §9：crc.c（CRC-16/CCITT-FALSE）、codec.c（类型编解码/MSK/CRC 附加）、
│   │                            #     schema.c（IDL 解析）、json.c（迷你 JSON，src/json.c）
│   ├── frame/frame.c          # §3/§4：帧头编解码、§4.3 十步解析、§4.1 TCP 半帧两阶段
│   ├── transport/             # §2/§5：udp.c（组播双 socket）/ tcp.c（长连接/半帧/心跳）
│   ├── sd/                    # §7：entries.c（SD Entry）/ discovery.c（四操作+状态机+订阅+GetIDL）
│   ├── idlstore/store.c       # §11.1：IDL 库加载/落盘/版本并存
│   ├── rpc/                   # §5：retransmit.c（重传时间线）/ rpc.c（call/ff/响应缓存去重）
│   ├── events/events.c        # §8：订阅确认 0x10/全量推送/tcp-event 通道
│   ├── strm.c                 # §6：StrmID 分配/冷却/回绕
│   ├── errors/logger/value/json/stack.c
├── tests/                     # 单测（CTest）：CRC/编解码/解析矩阵/半帧/重传时间线/双栈集成
└── examples/                  # node_a.c / node_b.c + vehicle-state.idl.json（规范 §11.1）
```

## 规范章节 ↔ 模块映射

| 规范章节 | 内容 | 实现位置 |
| --- | --- | --- |
| §2 部署 | 组播双 socket、IP_MULTICAST_LOOP、客户端临时端口、启动 Find 预热、组播不可用单播 Find 降级 | `transport/udp.c` + `stack.c` + `sd/discovery.c` |
| §3 帧格式 | 8B 帧头（CTR/REN/VER/MSK/PLB、TYP/Code、SvcID/IfID、InstID/StrmID）、PLB/Length 大端 | `frame/frame.c` |
| §4.1 TCP 流式 | 半帧两阶段（<8B 关连接 / 丢弃模式 R=L−已收、字节刷新计时、兜底 2×） | `frame/frame.c`（stream parser）+ `transport/tcp.c` |
| §4.2/§4.3 解析 | UDP 报文长度校验、十步解析矩阵（MSK=0/VER/REN/TYP/Code/ID/StrmID 语义/0x23） | `frame/frame.c`（parse_header/datagram） |
| §5.1/§5.2 RPC | Request/Response（回显 StrmID）、fire_forget、TCP 全 NON | `rpc/rpc.c` |
| §5.5 重传 | CON 重传 0/200/600/1400ms、3000ms 静默停止、响应缓存去重、重复 CON 重发确认 | `rpc/retransmit.c` + `rpc/rpc.c` + `sd/discovery.c` |
| §5.6/§5.7 TCP | 长连接复用、心跳（仅 TCP、30s Ping、2×period 失效）、自动重连 | `transport/tcp.c` |
| §6 StrmID | 数据帧 0x01~0xFE / 控制帧 0x00+0x01~0x7F 同池、释放冷却、回绕、REN 清对端 | `strm.c` |
| §7 SD | 四操作 Entry（Offer 6B/Find 4B/Subscribe 7B/GetIDL 3B）、Offer 拆帧、Find 响应、状态机、自动重订阅 | `sd/entries.c` + `sd/discovery.c` |
| §7.2 GetIDL | 仅 TCP 单播、双角色统一触发、落盘持久化、Payload≠3B→0x20、无定义→0x24 | `sd/discovery.c` + `idlstore/store.c` |
| §8 事件 | Subscribe(CON/NON)、ACK(0x10)/ACK(0x00)、全量推送、tcp-event 预建连接、逐 Entry 处理 | `sd/discovery.c` + `events/events.c` |
| §9 编解码 | 恒定宽度（low4==size 校验位）、CRC-16/CCITT-FALSE、null 仅 optional、fixed_len 空位 0x00、末尾新增字段容忍、MSK-XOR | `codec/codec.c` + `codec/crc.c` |
| §10 MSK | 先 CRC 后 XOR、控制帧禁 MSK | `codec/codec.c` + `frame/frame.c` |
| §11.1 IDL | 纯动态加载、type_def 三处定义、transport 绑定、事件组、损坏文件跳过 | `codec/schema.c` + `idlstore/store.c` |
| §12 错误码 | 两层两码：帧级 0x23（仅 UDP）/ IDL 级 0x20；RST 码表与名称 | `logger.c`（fw_rst_name）+ 各模块 |
| §13 应用 API | register_service/call/call_async/fire_forget/subscribe/unsubscribe/notify/find_service/is_available | `stack.c` |
| §3.6 生命周期 | stop 发 REN×3（间隔 100ms）先发后关；REN 清缓存/重传记录/StrmID 序列 | `stack.c` + 各模块 |
| 附录 A 参数 | 全部配置默认值（时间 ms） | `stack.c`（fw_config_defaults）+ `fw.h`（fw_config_t） |

## 测试

`ctest --test-dir build`（或 `build\fw_tests.exe`）——11 个套件、约 300 项断言，用例编号对齐《Test Cases.v4.md》：

| 套件 | 覆盖 |
| --- | --- |
| t_crc | 1.29/1.31：CRC 自检值 0x29B1、CRC+MSK 顺序 |
| t_value_json | fw_value 生命周期、迷你 JSON（转义/\uXXXX/数字/嵌套/非法输入） |
| t_codec | 1.5~1.35：§9 全类型往返、恒定宽度、low4=0 非法、SizeMismatch、bool 严格、timestamp 44bit、定长/嵌套/UnknownFieldType/MSK |
| t_frame | 1.1/1.3/1.4/1.30 帧头往返 + 2.6~2.21/2.29 解析矩阵（REN/ACK/RST/SvcID/StrmID 语义/VER/UDP GetIDL/MSK=1） |
| t_stream | 2.1~2.4 粘包/分包/Length·Mask 跨包 + 2.22~2.24 丢弃模式（解析器层） |
| t_strm | 4.1/4.2 StrmID 循环/隔离/冷却/REN 重置 |
| t_entries | 5.5/5.6 SD Entry 编解码与容量 |
| t_schema | §11.1 IDL 解析、optional/enum/定长/嵌套往返、9.1 末尾新增字段容忍 |
| t_retrans | 3.10~3.12 重传时间线（注入时钟）、3.7 取消、4.5 REN 清记录 |
| t_tcp | 2.5/2.22/2.23/2.26/2.28：真实 socket 半帧两阶段全场景 |
| t_integration | 8.1~8.3/5.21/5.28/6.1/6.5/4.4：单进程双栈回环全链路（发现→GetIDL 落盘→call→ff→订阅确认→推送→取消→REN 清缓存→重启本地命中） |

## 示例

`examples/node_a.c`（服务端）与 `examples/node_b.c`（客户端）覆盖规范 §11.1 VehicleState（svc_id=4096, major_ver=1, inst_id=1）的全部类型特性。NodeB 空 IDL 库起步，验证点输出带 `[VERIFY-n]` 标记：

1. `[VERIFY-1]` 服务发现（组播 Offer + 启动 Find 预热）
2. `[VERIFY-2]` GetIDL 自动拉取落盘（空库 → 拉取 → `.idl-b/4096_v1.json`）
3. `[VERIFY-3]` rpc GetState 往返（含 optional/定长/float64）
4. `[VERIFY-4]` fire_forget UpdateState/UploadBlob（TCP）
5. `[VERIFY-5]` 订阅确认（ACK 0x10）+ 事件推送交付

参数：`fw_node_a [port] [bind]` / `fw_node_b [port] [bind]`（默认 5400 / 127.0.0.1·127.0.0.2，同机演示绑定不同回环地址）。NodeA 支持 `Ctrl+C` 优雅退出（REN×3 后释放资源）。

## 配置参数（附录 A 默认值）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `port` | 5400 | UDP/组播端口；TCP 监听同端口 |
| `multicast_ipv4` | 224.0.1.187 | 组播地址 |
| `bind_address` | NULL（全接口） | 绑定地址（同机演示绑回环） |
| `period_ms` / `ttl_ms` | 2000 / 4000 | Offer 周期 / TTL（硬约束 ttl_ms ≥ 2×period_ms） |
| `response_timeout_ms` | 2000 | 响应/GetIDL 查询超时（调用的唯一终态） |
| `retransmit_interval_ms` / `retransmit_max` | 200 / 3 | CON 重传（0/200/600/1400ms） |
| `tcp_frame_timeout_ms` | 5000 | TCP 半帧超时（丢弃模式兜底 = 2×） |
| `heartbeat_period_ms` | 30000 | TCP 心跳（仅 TCP） |
| `max_payload_len` | 1400 | UDP 帧级 Payload 上限（超限 → RST(0x23)） |
| `ver` | 0 | 协议版本 VER（不匹配 → RST(0x22)） |
| `idl_dir` | ./idl | IDL 库文件夹（`{svc_id}_v{major_ver}.json`） |
| `tcp_enabled` | 1 | TCP 监听开关（客户端角色栈可关） |
| `log_level` | FW_LOG_INFO | ERROR/WARN/INFO/DEBUG |

## 与 fw-nodejs（行为基准）的偏差清单

以下为 C 实现有意/无奈的行为差异（已在代码注释标注条款出处）：

1. **组播成员挂默认接口（INADDR_ANY）**：Windows 绑定回环地址（127.0.0.x）的接口无法承载组播，成员关系统一挂默认接口（否则组播帧无法本机投递）；fw-nodejs 按 `bind_address` 指定成员接口。跨机部署两者等价。
2. **组播不可用时的单播 Find 降级窗口**：Expired 记录保留 60×period 期间向最近已知地址周期单播 Find（§2 认可的降级路径，行为与组播发现等价）；fw-nodejs 无此兜底（依赖组播）。
3. **单进程双栈集成测试的调用模式**：`fw_call`/`fw_fire_forget` 等同步 API 的内部泵只驱动本栈（被叫栈需自身事件循环）——单进程双栈场景须用 `fw_call_async` + 双栈泵（fw-nodejs 的 Promise 模型天然无此限制）。fw_stack_poll 每轮无条件驱动收发与连接管理（Windows WSAPoll 对非阻塞 connect 完成不报告就绪）。
4. **事件到达时 IDL 缺失的处理**：发起异步 GetIDL 并丢弃当前事件（记 Error 日志）；fw-nodejs await 拉取后交付。仅影响"订阅预拉取竞态"窗口，正常路径 schema 已就绪。
5. **订阅预拉取一律后台化**：fw_subscribe 的 IDL 预拉取为异步（失败仅日志）；fw-nodejs 在主线程场景同步等待拉取完成。
6. **整型 size>8 不支持**：signed/unsigned 线上宽度 >8 字节（int64/uint64 承载之外）编解码报错（规范允许 1~15）；fw-nodejs 用 BigInt 完整支持。float 80bit 扩展两侧一致不支持。
7. **跨栈互通注意事项**：C 栈的 TCP 出站连接源地址由系统选路（可能为 127.0.0.1），与 UDP 绑定地址（127.0.0.2）不同——tcp-event 按源 IP 匹配连接的场景（本示例 IDL 未使用）需部署时保证两侧地址口径一致（fw-nodejs 同样存在该现象）。
8. **日志级别为进程级全局**（`fw_log_set_level`）：多栈共用；fw-nodejs 每栈独立 logger。

## 已知问题与遗留

- 首轮跨栈互通（JS-B → C-A）曾出现一次 ff UpdateState 解码失败（RST 0x20），复跑多轮未再现；怀疑为 A 侧注册完成前的时序竞争（ff 尽力而为语义，应用可重试）。如复现可打开 `FW_LOG_DEBUG` 定位。
- `MinGW Makefiles` 生成器未在本机验证（缺 mingw32-make），见构建说明。
- IPv6 组播（ff02::1:BB）未实现（fw-nodejs 同样仅 IPv4）。
