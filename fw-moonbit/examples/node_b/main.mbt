// ============================================================
// node_b —— 示例客户端：发现 → GetIDL 自动拉取 → 调用 → 订阅（实现计划 §5 场景）
//
// 验证点（输出带 [VERIFY] 标记，冒烟脚本检查）：
//   1. 服务发现：is_available(4096,1) → true（启动预热 Find + 组播 Offer，§7.2/§7.4）
//   2. GetIDL 自动拉取落盘：本地 IDL 库为空 → call 触发协议栈内部 GetIDL（§7.2）
//      → 库内出现 4096_v1.json（重启后本地命中不重复拉取）
//   3. rpc call 往返：GetState 返回 VehicleState 结构（[VArray(7 字段值)]，§9.4）
//   4. fire_forget：UpdateState / UploadBlob 到达（TCP 全 NON 无确认，§5.2）
//   5. 订阅确认链路 + 事件推送：Subscribe(CON) → ACK(0x10) → 交付推送（§8.1）
//   6. REN 感知：服务端优雅退出（REN×3）→ is_available 变 false（§3.6/§4.6）
//
// 运行：node <build>/examples/node_b/node_b.js [--run-for 55000]
// 环境变量：FW_PORT(默认 5400) / FW_BIND(默认 127.0.0.2) / FW_IDL_DIR(默认 <cwd>/examples/node_b/idl)
//   FW_BIND 默认 127.0.0.2：同机演示与 NodeA（127.0.0.1）区分，避免同端口单播投递竞争
// ============================================================

// ---- 示例编排 FFI（与 node_a 同款模式；extern "js" 包级私有）----
// 调用约定注解（函数级属性行，参数名引用）：同步消费的 String → #borrow；
// JS 异步持有的回调闭包 → #owned
#borrow(msg)
extern "js" fn app_log(msg : String) -> Unit = "(msg) => { console.log(msg); }"
#borrow(key)
extern "js" fn app_env(key : String) -> String =
  "(k) => { const v = process.env[k]; return v === undefined ? '' : String(v); }"
extern "js" fn app_cwd(_x : Int) -> String = "(_) => process.cwd()"
extern "js" fn app_argc(_x : Int) -> Int = "(_) => process.argv.length"
extern "js" fn app_arg(i : Int) -> String = "(i) => String(process.argv[i] ?? '')"
#borrow(s)
extern "js" fn app_parse_int(s : String, fallback : Int) -> Int =
  "(s, fb) => { const n = parseInt(s, 10); return Number.isFinite(n) ? (n | 0) : fb; }"
/// 毫秒时钟（timestamp 字段值 / 轮询计时，§9.1）
extern "js" fn app_now_ms(_x : Int) -> Double = "(_) => Date.now()"
#owned(fn_cb)
extern "js" fn app_on_sigint(fn_cb : (Int) -> Unit) -> Unit =
  "(cb) => { process.on('SIGINT', () => { try { cb(0); } catch (e) { console.error(e); } }); }"
extern "js" fn app_exit(_x : Int) -> Unit = "(_) => process.exit(0)"
#owned(fn_cb)
extern "js" fn app_set_timeout(fn_cb : (Int) -> Unit, ms : Int) -> Int =
  "(cb, ms) => setTimeout(() => { try { cb(0); } catch (e) { console.error(e); } }, ms | 0)"
/// 创建目录（recursive；空 IDL 库起步 §11.1）
#borrow(dir)
extern "js" fn app_mkdir(dir : String) -> Unit =
  "(dir) => { try { require('node:fs').mkdirSync(dir, { recursive: true }); } catch (e) {} }"
/// 判定 IDL 库文件是否已落盘（GetIDL 落盘验证，§7.2）
#borrow(dir, name)
extern "js" fn app_file_exists(dir : String, name : String) -> Bool =
  "(dir, name) => require('node:fs').existsSync(require('node:path').join(dir, name))"
/// UTF-8 字符串 → Bytes（Blob.vin 17B 定长构造）
#borrow(s)
extern "js" fn app_utf8_bytes(s : String) -> Bytes = "(s) => new Uint8Array(Buffer.from(s, 'utf8'))"
/// 十六进制文本 → Bytes（Blob.payload 构造）
#borrow(h)
extern "js" fn app_hex_bytes(h : String) -> Bytes =
  "(h) => new Uint8Array((h.match(/.{2}/g) || []).map((x) => parseInt(x, 16)))"

/// 读环境变量（缺省取默认值）
fn env_or(key : String, fallback : String) -> String {
  let v = app_env(key)
  if v.length() == 0 {
    fallback
  } else {
    v
  }
}

/// 解析 --run-for <ms> 参数（缺省 55000，node 版对齐）
fn run_for_ms() -> Int {
  let n = app_argc(0)
  for i in 0..<n {
    if app_arg(i) == "--run-for" && i + 1 < n {
      return app_parse_int(app_arg(i + 1), 55000)
    }
  }
  55000
}

/// 轮询等待（递归 timeout 链，100ms 间隔；deadline 到期回 on_timeout）
fn wait_for(
  label : String,
  deadline_ms : Int,
  start_ms : Int,
  check : () -> Bool,
  on_ok : () -> Unit,
  on_timeout : () -> Unit
) -> Unit {
  if check() {
    on_ok()
  } else if app_now_ms(0).to_int() - start_ms > deadline_ms {
    app_log("[NodeB] timeout waiting: \{label}")
    on_timeout()
  } else {
    let _ = app_set_timeout(fn(_x) {
      wait_for(label, deadline_ms, start_ms, check, on_ok, on_timeout)
    }, 100)
  }
}

/// 主流程（is-main 入口）
fn main {
  let port = app_parse_int(env_or("FW_PORT", "5400"), 5400)
  let bind = env_or("FW_BIND", "127.0.0.2")
  let idl_dir = env_or("FW_IDL_DIR", "\{app_cwd(0)}/examples/node_b/idl")
  let run_for = run_for_ms()
  // 空 IDL 库起步（纯动态架构：客户端按需拉取，§11.1/§7.2）
  app_mkdir(idl_dir)
  // ---- 协议栈启动：纯客户端角色（tcp_enabled=false 不监听；GetIDL/rpc 走出站连接）----
  let cfg : @stack.StackConfig = {
    udp_port: port,
    tcp_port: 5400, // §2 TCP/UDP 共用端口 5400（规范 §2）
    bind_address: bind,
    tcp_enabled: false,
    idl_dir,
    max_payload_len: 1400,
    tcp_frame_timeout_ms: 5000L,
    heartbeat_period_ms: 30000L,
    period_ms: 2000,
    ttl_sec: 4,
    response_timeout_ms: 2000L,
    retransmit_interval_ms: 200L,
    retransmit_max: 3,
  }
  let stack = @stack.Stack::new(cfg)
  stack.start()
  app_log("[NodeB] stack started: port=\{port} bind=\{bind} idl_dir=\{idl_dir}")
  // ---- 1. 服务发现（§7.4：启动预热 Find + 对端周期 Offer 建立发现缓存）----
  // 订阅句柄槽（subscribe on_ok 异步回填；退出时 unsubscribe 凭据，§13.2）
  let handle_slot : Array[@stack.SubHandle?] = [None]
  let t0 = app_now_ms(0).to_int()
  wait_for("service 4096/1 available", 10000, t0, fn() { stack.is_available(4096, 1) },
    fn() {
      app_log("[VERIFY-1] discovery: svc 4096/1 available = true")
      // 主动发现（§13.2：触发 Find 刷新 + 返回缓存在线信息）
      match stack.find_service(4096, 1) {
        Some(info) =>
          app_log("[NodeB] found: \{info.peer}:\{info.port} major_ver=\{info.major_ver}")
        None => app_log("[NodeB] found: none")
      }
      // ---- 2+3. rpc call：本地无 IDL → 协议栈自动 GetIDL（TCP 单播）→ 落盘 → 编解码（§7.2）----
      let idl_name = "4096_v1.json"
      app_log("[NodeB] local IDL store empty: \{!app_file_exists(idl_dir, idl_name)}")
      stack.call(4096, 1, 1, [], 0, fn(vs) {
        // GetState 无输入；响应 = [VArray(VehicleState 7 字段值)]（§9.4）
        app_log("[VERIFY-2] GetIDL persisted: \{app_file_exists(idl_dir, idl_name)}")
        app_log("[VERIFY-3] rpc GetState -> \{Repr(vs)}")
        // ---- 4. fire_forget（TCP 全 NON，无传输确认，§5.2）----
        // UpdateState：input=[VehicleState] → [VArray(7 字段值)]（v5.0 全部字段必填，无 optional）
        stack.fire_forget(4096, 1, 2, [
          @codec.VArray([
            @codec.VUInt(1), // veh_md
            @codec.VUInt(2), // usg_md
            @codec.VSInt(3L), // sys_pwr_md
            @codec.VTimestamp(app_now_ms(0).to_int64()), // timestamp
            @codec.VString("2026-10-13T12:30:00Z"), // timestr（fixed 20B）
            @codec.VString("updated by NodeB"), // status_msg
            @codec.VFloat(0.717), // ratio
          ]),
        ], fn(e) { app_log("[NodeB] ff UpdateState error: \{Repr(e)}") })
        // UploadBlob：input=[Blob] → [VArray([VBytes(17B 定长 vin), VBytes(payload)])]
        stack.fire_forget(4096, 1, 3, [
          @codec.VArray([
            @codec.VBytes(app_utf8_bytes("LFV3A23C8K3123456")), // 17B 定长 bytes
            @codec.VBytes(app_hex_bytes("0102030405")), // 5B 变长 bytes
          ]),
        ], fn(e) { app_log("[NodeB] ff UploadBlob error: \{Repr(e)}") })
        app_log("[VERIFY-4] fire_forget UpdateState/UploadBlob sent (tcp)")
        // ---- 5. 订阅：Subscribe(CON) → ACK(0x10) 确认 → 事件推送交付（§8.1）----
        // 交付回调按接口 output 解码后收到 [VArray(...)]（§13 payload 语义）
        stack.subscribe(4096, 1, 32769, 0, fn(if_id, vs) {
          app_log("[VERIFY-5] event push if=\{if_id}: \{Repr(vs)}")
        }, fn(h) {
          handle_slot[0] = Some(h) // 句柄回填（退出时 unsubscribe 凭据，§13.2）
          app_log("[NodeB] subscribed (StateChanges if=32769)")
        }, fn(e) { app_log("[NodeB] subscribe failed: \{Repr(e)}") })
      }, fn(e) { app_log("[NodeB] call GetState error: \{Repr(e)}") })
    },
    fn() { app_exit(1) }) // 发现超时 → 非零退出（冒烟判败）
  // ---- 6. REN 感知观察：500ms 周期监视可用性变化（§3.6 服务端 REN×3 → 缓存清空）----
  let last : Array[Bool] = [false]
  // 递归周期链：闭包绑定 + 自引用盒（MoonBit let fn 不可直接递归）
  let watch_box : Array[(Int) -> Unit] = [fn(_x) { () }]
  watch_box[0] = fn(_x) -> Unit {
    let cur = stack.is_available(4096, 1)
    if cur != last[0] {
      // 变化方向标注：true=重新发现 / false=对端 REN 清缓存（§3.6）
      let tag = if cur { "rediscovered" } else { "REN cleared" }
      app_log("[VERIFY-6] availability changed: \{last[0]} -> \{cur} (\{tag})")
      last[0] = cur
    }
    if !app_exit_flag[0] {
      let _ = app_set_timeout(watch_box[0], 500)
    }
  }
  let _ = app_set_timeout(watch_box[0], 500)
  // ---- 自动退出（--run-for，默认 55s）：unsubscribe → stop（§8.1 场景 4）----
  app_on_sigint(fn(_x) { do_exit(stack, handle_slot) })
  let _ = app_set_timeout(fn(_x) { do_exit(stack, handle_slot) }, run_for)
}

/// 退出收尾（幂等）：unsubscribe（句柄就绪时，§13.2 显式取消）→ stop 释放资源；
/// app_exit_flag 防止 SIGINT 与 run-for 双触发
let app_exit_flag : Array[Bool] = [false]

fn do_exit(stack : @stack.Stack, handle_slot : Array[@stack.SubHandle?]) -> Unit {
  if app_exit_flag[0] {
    return
  }
  app_exit_flag[0] = true
  // 订阅已建立 → 显式取消（发 Subscribe(TTL=0)，§8.1 场景 4）
  match handle_slot[0] {
    Some(h) => stack.unsubscribe(h, fn() { app_log("[NodeB] unsubscribed") })
    None => ()
  }
  app_log("[NodeB] done, stopping ...")
  stack.stop()
  let _ = app_set_timeout(fn(_x) { app_exit(0) }, 600)
}
