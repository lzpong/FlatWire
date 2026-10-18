// SD 层 FFI：定时器 / 日志 / UTF-8 转换（Node.js 运行时，仅 js target）
//
// 与 transport 包同款 JS 实现（extern "js" 函数包级私有，跨包不可见故重复声明）；
// 句柄语义一致：定时器由 globalThis.__fw.timers 托管（ffi_transport_init 建立的上下文）；
// 调用约定注解（函数级属性行，参数名引用）：同步消费的 String/Bytes → #borrow；
// JS 异步持有的回调闭包 → #owned

/// 周期定时器（订阅保活 / 1s tick / Offer 广播；回调长期持有 → owned）
#owned(fn_cb)
extern "js" fn sd_set_interval(fn_cb : (Int) -> Unit, ms : Int) -> Int =
  "(fn_cb, ms) => { const g = globalThis.__fw; g.timerSeq = (g.timerSeq | 0) + 1; const id = g.timerSeq; g.timers.set(id, setInterval(() => { try { fn_cb(0); } catch (e) { console.error('[fw-ffi] interval callback error', e && e.message); } }, ms | 0)); return id; }"

/// 取消周期定时器
extern "js" fn sd_clear_interval(id : Int) -> Unit =
  "(id) => { const g = globalThis.__fw; const t = g.timers.get(id); if (t !== undefined) { clearInterval(t); g.timers.delete(id); } }"

/// 一次性定时器（CON 重传链 / GetIDL 查询超时 / REN 连发间隔；回调长期持有 → owned）
#owned(fn_cb)
extern "js" fn sd_set_timeout(fn_cb : (Int) -> Unit, ms : Int) -> Int =
  "(fn_cb, ms) => { const g = globalThis.__fw; g.timerSeq = (g.timerSeq | 0) + 1; const id = g.timerSeq; g.timers.set(id, setTimeout(() => { g.timers.delete(id); try { fn_cb(0); } catch (e) { console.error('[fw-ffi] timeout callback error', e && e.message); } }, ms | 0)); return id; }"

/// 取消一次性定时器
extern "js" fn sd_clear_timeout(id : Int) -> Unit =
  "(id) => { const g = globalThis.__fw; const t = g.timers.get(id); if (t !== undefined) { clearTimeout(t); g.timers.delete(id); } }"

/// Error 级日志（§12.4；msg 同步消费 → borrow）
#borrow(msg)
extern "js" fn sd_log_error(msg : String) -> Unit = "(msg) => { console.error(msg); }"

/// Bytes → UTF-8 字符串（GetIDL 响应 Payload = IDL JSON 全文，§7.2；data 同步消费 → borrow）
#borrow(data)
extern "js" fn sd_bytes_to_utf8(data : Bytes) -> String =
  "(b) => Buffer.from(b).toString('utf8')"

/// UTF-8 字符串 → Bytes（GetIDL 响应发送，§7.2 Payload = 完整 IDL JSON 文本；text 同步消费 → borrow）
#borrow(text)
extern "js" fn sd_utf8_to_bytes(text : String) -> Bytes =
  "(t) => new Uint8Array(Buffer.from(t, 'utf8'))"
