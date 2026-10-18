// 协议栈层 FFI：一次性定时器（stop 延迟关传输层，§7.6 REN 先发完再释放）
//
// 与 transport/sd/rpc 包同款 JS 实现（extern "js" 包级私有，跨包不可见故重复声明）；
// __fw 惰性初始化：真实运行时 ffi_transport_init 先行建立（跳过）；单测环境自动建最小上下文；
// 调用约定注解（函数级属性行，参数名引用）：JS 异步持有的回调闭包 → #owned；
// 同步消费的 String → #borrow

#owned(fn_cb)
extern "js" fn st_set_timeout(fn_cb : (Int) -> Unit, ms : Int) -> Int =
  "(fn_cb, ms) => { const g = globalThis.__fw || (globalThis.__fw = { udp: [], tcp: new Map(), server: null, closed: new Set(), timers: new Map(), timerSeq: 0 }); g.timerSeq = (g.timerSeq | 0) + 1; const id = g.timerSeq; g.timers.set(id, setTimeout(() => { g.timers.delete(id); try { fn_cb(0); } catch (e) { console.error('[fw-ffi] timeout callback error', e && e.message); } }, ms | 0)); return id; }"

/// Error 级日志（§12.4；codec 桥接失败 / 示例编排使用；msg 同步消费 → borrow）
#borrow(msg)
extern "js" fn st_log_error(msg : String) -> Unit = "(msg) => { console.error(msg); }"
