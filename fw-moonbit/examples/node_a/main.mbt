// ============================================================
// node_a —— 示例服务端：注册 VehicleState 服务实例（实现计划 §5）
//
// 场景（与 fw-nodejs/examples/node-a.js 行为对齐）：
//   - 注册 svc_id=4096（规范 §11.1 VehicleState IDL）实例 inst_id=1
//     IDL 从本地库 examples/node_a/idl/4096_v1.json 启动加载（§11.1 纯动态架构）
//   - 提供 rpc GetState(if=1) / ff UpdateState(if=2) + UploadBlob(if=3) 的 handler
//   - 周期 notify StateChanged(32769) / PowerModeChanged(32770)（§8.2）
//   - 优雅退出（stop 发 REN×3 组播，§3.6）：SIGINT 或 --run-for <ms> 到期
//
// 运行（moon build --target js 产物）：
//   node <build>/examples/node_a/node_a.js [--run-for 25000]
// 环境变量：FW_PORT(默认 5400) / FW_BIND(默认 127.0.0.1) / FW_IDL_DIR(默认 <cwd>/examples/node_a/idl)
//
// payload 语义（§13）：应用操作 Array[FWValue]（按 IDL 字段顺序）；
// struct 值以 VArray(字段值序列) 表示（§9.3，见 stack_codec.mbt）
// ============================================================

// ---- 示例编排 FFI（进程/文件系统；extern "js" 包级私有）----
// 调用约定注解（函数级属性行，参数名引用）：同步消费的 String → #borrow；
// JS 异步持有的回调闭包 → #owned
/// 标准输出日志
#borrow(msg)
extern "js" fn app_log(msg : String) -> Unit = "(msg) => { console.log(msg); }"
/// 读环境变量（缺省回空串，由 MoonBit 侧取默认值）
#borrow(key)
extern "js" fn app_env(key : String) -> String =
  "(k) => { const v = process.env[k]; return v === undefined ? '' : String(v); }"
/// 进程工作目录（idl_dir 默认值推导）
extern "js" fn app_cwd(_x : Int) -> String = "(_) => process.cwd()"
/// 命令行参数个数 / 第 i 个参数（--run-for 解析）
extern "js" fn app_argc(_x : Int) -> Int = "(_) => process.argv.length"
extern "js" fn app_arg(i : Int) -> String = "(i) => String(process.argv[i] ?? '')"
/// 十进制字符串 → Int（失败回退 fallback——示例编排参数由调用方保证格式）
#borrow(s)
extern "js" fn app_parse_int(s : String, fallback : Int) -> Int =
  "(s, fb) => { const n = parseInt(s, 10); return Number.isFinite(n) ? (n | 0) : fb; }"
/// 毫秒时钟（timestamp 字段值，§9.1）
extern "js" fn app_now_ms(_x : Int) -> Double = "(_) => Date.now()"
/// 注册 SIGINT 处理（优雅退出触发；回调长期持有 → owned）
#owned(fn_cb)
extern "js" fn app_on_sigint(fn_cb : (Int) -> Unit) -> Unit =
  "(cb) => { process.on('SIGINT', () => { try { cb(0); } catch (e) { console.error(e); } }); }"
/// 退出进程（延迟调用——等待 REN×3 发送与 socket 关闭收尾）
extern "js" fn app_exit(_x : Int) -> Unit = "(_) => process.exit(0)"
/// 一次性定时器（轮询/延迟退出；与 transport FFI 同款句柄模式；回调长期持有 → owned）
#owned(fn_cb)
extern "js" fn app_set_timeout(fn_cb : (Int) -> Unit, ms : Int) -> Int =
  "(cb, ms) => setTimeout(() => { try { cb(0); } catch (e) { console.error(e); } }, ms | 0)"

/// 读环境变量（缺省取默认值）
fn env_or(key : String, fallback : String) -> String {
  let v = app_env(key)
  if v.length() == 0 {
    fallback
  } else {
    v
  }
}

/// 解析 --run-for <ms> 参数（缺省 -1 = 不自动退出）
fn run_for_ms() -> Int {
  let n = app_argc(0)
  for i in 0..<n {
    if app_arg(i) == "--run-for" && i + 1 < n {
      return app_parse_int(app_arg(i + 1), -1)
    }
  }
  -1
}

/// 车辆状态业务模型（§11.1 VehicleState 8 字段：veh_md/usg_md/sys_pwr_md/timestamp/
/// timestr/status_msg/diag_note(optional)/ratio；mut 字段由 handler/周期推送更新）
priv struct VState {
  mut veh_md : Int64 // unsigned(1)（FWValue 无符号值统一 Int64 承载，§9.2）
  mut usg_md : Int64 // unsigned(1)
  mut sys_pwr_md : Int64 // signed(1)
  mut ts : Int64 // timestamp（毫秒，§9.1）
  mut ratio : Double // float64
  mut diag_note : String // optional 字段："" 编码为 null（§9.2；UpdateState 可写回）
}

/// 状态 → FWValue 字段值序列（8 字段按 IDL 顺序；§9.3 struct 值 = VArray）
fn veh_values(st : VState) -> Array[@codec.FWValue] {
  [
    @codec.VUnsigned(st.veh_md),
    @codec.VUnsigned(st.usg_md),
    @codec.VSigned(st.sys_pwr_md),
    @codec.VTimestamp(st.ts),
    @codec.VString("2026-10-13T12:00:00Z"), // fixed_len=20，恰 20 字节
    @codec.VString("all systems nominal"), // max_len=64
    // optional 字段：空串 → null（1B 空头，§9.2）；非空 → VString
    if st.diag_note.length() == 0 {
      @codec.VNull
    } else {
      @codec.VString(st.diag_note)
    },
    @codec.VFloat(st.ratio),
  ]
}

/// 周期推送 tick（3000ms 递归 timeout 链；§8.2 事件分发）
/// stopped[0] 停止标志（shutdown 置 false 后链终止）
fn push_tick(
  stack : @stack.Stack,
  state : VState,
  seq_slot : Array[Int],
  stopped : Array[Bool]
) -> Unit {
  if stopped[0] {
    return
  }
  let seq = seq_slot[0]
  state.ts = app_now_ms(0).to_int64()
  state.ratio = (seq % 10).to_double() * 0.1
  stack.notify(4096, 1, 32769, [@codec.VArray(veh_values(state))]) // event output=VehicleState
  stack.notify(4096, 1, 32770, [@codec.VUnsigned(2)]) // event output=PowerMode（enum 线格式=底层整型 2=Run，§11.1）
  seq_slot[0] = seq + 1
  let _ = app_set_timeout(fn(_x) { push_tick(stack, state, seq_slot, stopped) }, 3000)
}

/// 主流程（is-main 入口）
fn main {
  let port = app_parse_int(env_or("FW_PORT", "5400"), 5400)
  let bind = env_or("FW_BIND", "127.0.0.1")
  let idl_dir = env_or("FW_IDL_DIR", "\{app_cwd(0)}/examples/node_a/idl")
  let run_for = run_for_ms()
  // ---- 协议栈启动（§13.1；StackConfig 全字段手工构造——bind/tcp_enabled 属部署事实）----
  let cfg : @stack.StackConfig = {
    udp_port: port,
    tcp_port: 5400, // §2 TCP/UDP 共用端口 5400（规范 §2）
    bind_address: bind, // 组播出口接口与绑定地址一致（回环演示场景）
    tcp_enabled: true, // 服务端监听 TCP（rpc/GetIDL/tcp-event 入站）
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
  app_log("[NodeA] stack started: port=\{port} bind=\{bind} idl_dir=\{idl_dir}")
  // ---- 业务状态：演示用内存态（§11.1 字段序）----
  let state : VState = {
    veh_md: 1L,
    usg_md: 2L,
    sys_pwr_md: 2L,
    ts: app_now_ms(0).to_int64(),
    ratio: 0.618,
    diag_note: "",
  }
  // ---- 注册服务（§13.1：本地 IDL 命中 → 同步注册 → Offering）----
  // handler 值语义：on_request 返回 [VArray(8 字段值)]（output=VehicleState struct，§9.3）
  stack.register_service(4096, 1, {
    on_request: fn(if_id, _args) {
      if if_id == 1 {
        // GetState：刷新 timestamp 后返回当前状态（node 版 { ...state } 对齐）
        state.ts = app_now_ms(0).to_int64()
        app_log("[NodeA] rpc GetState <- replying current state")
        Ok([@codec.VArray(veh_values(state))])
      } else {
        Err(0x24) // 未声明接口（§12.1 Not Found）
      }
    },
    on_ff: fn(if_id, args) {
      if if_id == 2 {
        // UpdateState：args = [VArray(8 字段值)]（input=[VehicleState]，§9.3 struct 参数）
        match args.get(0) {
          Some(@codec.VArray(vals)) =>
            if vals.length() == 8 {
              // 写回本地状态（字段序按 §11.1：0 veh_md / 1 usg_md / 2 sys_pwr_md / 6 diag_note / 7 ratio）
              match vals[0] {
                @codec.VUnsigned(v) => state.veh_md = v
                _ => ()
              }
              match vals[1] {
                @codec.VUnsigned(v) => state.usg_md = v
                _ => ()
              }
              match vals[2] {
                @codec.VSigned(v) => state.sys_pwr_md = v
                _ => ()
              }
              match vals[6] {
                @codec.VString(s) => state.diag_note = s
                @codec.VNull => state.diag_note = ""
                _ => ()
              }
              match vals[7] {
                @codec.VFloat(v) => state.ratio = v
                _ => ()
              }
              state.ts = app_now_ms(0).to_int64()
              app_log("[NodeA] ff UpdateState: sys_pwr_md=\{state.sys_pwr_md}")
              // 状态变更即推送（§8.2）
              stack.notify(4096, 1, 32769, [@codec.VArray(veh_values(state))])
            }
          Some(_) => app_log("[NodeA] ff UpdateState: unexpected payload shape")
          None => app_log("[NodeA] ff UpdateState: empty args")
        }
      } else if if_id == 3 {
        app_log("[NodeA] ff UploadBlob: \{args.length()} arg(s) received")
      }
    },
  }, fn() {
    app_log("[NodeA] service 4096/1 registered (VehicleStateService) -> Offering")
  }, fn(e) { app_log("[NodeA] register failed: \{Repr(e)}") })
  // ---- 周期事件推送启动（StateChanged + PowerModeChanged，node 版 3000ms 对齐）----
  let seq_slot : Array[Int] = [0]
  let stopped : Array[Bool] = [false]
  let _ = app_set_timeout(fn(_x) { push_tick(stack, state, seq_slot, stopped) }, 3000)
  // ---- 优雅退出（§7.6：stop 发 REN×3 组播后延迟释放；exit 再等 600ms 确保收尾）----
  // 闭包绑定（MoonBit 局部 fn 定义不捕获环境变量，须以 let fn 形式捕获 stack/stopped）
  let shutdown = fn(reason : String) -> Unit {
    if stopped[0] {
      return // 幂等（SIGINT 与 run-for 可能双触发）
    }
    stopped[0] = true
    app_log("[NodeA] stopping (\{reason}) -> sending REN x3 ...")
    stack.stop()
    let _ = app_set_timeout(fn(_x) {
      app_log("[NodeA] stopped")
      app_exit(0)
    }, 600)
  }
  app_on_sigint(fn(_x) { shutdown("SIGINT") })
  if run_for >= 0 {
    let _ = app_set_timeout(fn(_x) { shutdown("--run-for \{run_for}ms elapsed") }, run_for)
  }
}
