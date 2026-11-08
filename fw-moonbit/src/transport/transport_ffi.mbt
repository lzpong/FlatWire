// §5 传输层 FFI：Node.js dgram / net 绑定（仅 js target）
//
// 实现要点（均经冒烟验证 / 编译产物确认）：
// - MoonBit Bytes 在 JS backend 编译为 Uint8Array——JS 侧 new Uint8Array(buf) 传入 / Buffer.from(data) 发出
// - MoonBit 闭包在 JS backend 编译为普通箭头函数——JS 侧可直接 fn(args) 调用
// - 所有 extern 函数声明 ≥1 个参数（规避零参 extern 被编译为 IIFE 立即求值的陷阱）
// - require 依赖 moon 产物以 CJS 解析（生成目录 package.json 无 type 字段）
// - 定时器句柄由 JS 侧 Map 托管并返回自增 Int（规避 node Timeout 对象与 MoonBit Int 类型失配）
// - globalThis.__fw 为进程级运行时上下文：udp socket 数组 / tcp 连接 Map / 定时器表
// - 调用约定注解（函数级属性行，参数名引用）：同步消费的 String/Bytes 标 #borrow
//   （JS 侧仅调用期读取）；被 JS 侧异步持有的回调闭包标 #owned（JS 长期持有引用）
//
// 发送背压记账（§12.6，O(1) 增量计数）：
// - q.used = 全栈数据帧未发字节（预算判定唯一依据；入队加 / drain 归还 / 连接关闭扣减）
// - 每连接 dataB / ctrlB 两个桶：数据帧增量进 dataB 并同步 q.used；控制帧只进 ctrlB（不占配额）
// - 对账恒等式：q.used + ΣctrlB - Σlag == Σ socket.writableLength（lag = 部分 flush 已发出但未同步的量；控制帧直写确实进入水位）
//   q.check 开启时每次关键记账变更后校验，漂移立即抛错（仅测试/调试用）

/// 初始化 globalThis.__fw 运行时上下文（进程内幂等，重复调用不重建）
/// 同时初始化发送背压状态（§12.6 实现限制）：默认单连接 256KB / 全栈 64MB，控制帧直写阈值 1024B；
/// 计数器仅内部使用（q.rejects/q.peak/q.closedFull），不对外暴露 API，依靠 console.warn 日志观测。
extern "js" fn ffi_transport_init(_x : Int) -> Unit =
  "(x) => { const g = globalThis; if (!g.__fw) { g.__fw = { dgram: require('node:dgram'), net: require('node:net'), udp: [], tcp: new Map(), server: null, closed: new Set(), timers: new Map(), timerSeq: 0, q: { connMax: 262144, budget: 67108864, ctrlMax: 1024, rejects: 0, peak: 0, closedFull: 0, used: 0, check: false } }; const f = g.__fw; f.qstate = (s) => (s.__fwq || (s.__fwq = { rejects: 0, peak: 0, fullSince: 0, ctrl: 0, accounted: 0, dataB: 0, ctrlB: 0 })); f.qsum = () => { let t = 0; for (const s of f.tcp.values()) { t += (s.writableLength || 0); } return t; }; f.qrelease = (s) => { const q = f.qstate(s); if (q.dataB) { f.q.used -= q.dataB; } q.dataB = 0; q.ctrlB = 0; q.accounted = 0; }; f.qaccount = (s, isCtrl) => { const q = f.qstate(s); const w = s.writableLength || 0; const d = w - q.accounted; q.accounted = w; if (isCtrl) { q.ctrlB += d; } else { q.dataB += d; f.q.used += d; } if (f.q.check) { f.qcheck(); } }; f.qctrlsum = () => { let t = 0; for (const s of f.tcp.values()) { t += (f.qstate(s).ctrlB || 0); } return t; }; f.qcheck = () => { let t = 0, c = 0, lag = 0; for (const s of f.tcp.values()) { const w = s.writableLength || 0; const q = f.qstate(s); t += w; c += (q.ctrlB || 0); if (q.accounted > w) { lag += q.accounted - w; } } const n = f.q.used + c - lag; if (t !== n) { const m = '[fw-ffi] sendq accounting drift: counted=' + n + 'B (data=' + f.q.used + 'B ctrl=' + c + 'B lag=' + lag + 'B) traversal=' + t + 'B'; console.error(m); throw new Error(m); } }; f.qattach = (sock) => { f.qstate(sock); if (!sock.__fwqBound) { sock.__fwqBound = true; sock.on('drain', () => { f.qrelease(sock); sock.__fwq.fullSince = 0; if (f.q.check) { f.qcheck(); } }); } }; f.qreject = (s, pending, why) => { const q = f.qstate(s); q.rejects++; f.q.rejects++; if (pending > q.peak) { q.peak = pending; } if (!q.fullSince) { q.fullSince = Date.now(); } if (q.rejects <= 3 || q.rejects % 100 === 0) { console.warn('[fw-ffi] tcp send queue full (' + why + ', pending=' + pending + 'B, rejects=' + q.rejects + ')'); } return false; }; } }"

/// 单调毫秒时钟（Date.now；返回 Double 由 MoonBit 侧转 Int64，避免 Int64 跨 FFI 边界）
extern "js" fn ffi_now_ms(_x : Int) -> Double = "(x) => Date.now()"

/// 设置周期定时器（返回 JS 侧托管的句柄 id；回调闭包由 JS 定时器长期持有 → owned）
#owned(fn_cb)
extern "js" fn ffi_set_interval(fn_cb : (Int) -> Unit, ms : Int) -> Int =
  "(fn_cb, ms) => { const g = globalThis.__fw; g.timerSeq = (g.timerSeq | 0) + 1; const id = g.timerSeq; g.timers.set(id, setInterval(() => { try { fn_cb(0); } catch (e) { console.error('[fw-ffi] interval callback error', e && e.message); } }, ms | 0)); return id; }"

/// 取消周期定时器
extern "js" fn ffi_clear_interval(id : Int) -> Unit =
  "(id) => { const g = globalThis.__fw; const t = g.timers.get(id); if (t !== undefined) { clearInterval(t); g.timers.delete(id); } }"

/// 设置一次性定时器（返回 JS 侧托管的句柄 id；回调闭包由 JS 定时器长期持有 → owned）
#owned(fn_cb)
extern "js" fn ffi_set_timeout(fn_cb : (Int) -> Unit, ms : Int) -> Int =
  "(fn_cb, ms) => { const g = globalThis.__fw; g.timerSeq = (g.timerSeq | 0) + 1; const id = g.timerSeq; g.timers.set(id, setTimeout(() => { g.timers.delete(id); try { fn_cb(0); } catch (e) { console.error('[fw-ffi] timeout callback error', e && e.message); } }, ms | 0)); return id; }"

/// 打开 UDP socket（§5.2 双 socket）：
/// - port=0 → 绑定临时端口（client socket）；multicast=true → bind 后加入组播组 224.0.1.187 并开组播环回
/// - bind_host：绑定地址（"" = 全接口；同机多实例演示按 IP 区分单播投递，node 版同款方案）
/// - 返回 socket 句柄（JS 侧数组索引）；on_bound(实际端口) / on_error(消息) 异步回调（owned）
#borrow(bind_host)
#owned(on_msg, on_bound, on_error)
extern "js" fn ffi_udp_open(
  port : Int,
  bind_host : String,
  multicast : Bool,
  on_msg : (Bytes, String, Int) -> Unit,
  on_bound : (Int) -> Unit,
  on_error : (String) -> Unit
) -> Int =
  "(port, bind_host, multicast, on_msg, on_bound, on_error) => { const g = globalThis.__fw; const s = g.dgram.createSocket({ type: 'udp4', reuseAddr: true }); const idx = g.udp.length; g.udp.push(s); s.on('message', (buf, rinfo) => { try { on_msg(new Uint8Array(buf), String(rinfo.address), rinfo.port | 0); } catch (e) { console.error('[fw-ffi] udp message error', e && e.message); } }); s.on('error', (e) => { try { on_error(String(e && e.message ? e.message : e)); } catch (x) {} }); s.bind(port | 0, bind_host || undefined, () => { if (multicast) { try { s.addMembership('224.0.1.187', bind_host || undefined); s.setMulticastLoopback(true); if (bind_host) { s.setMulticastInterface(bind_host); } } catch (e) { console.error('[fw-ffi] multicast setup error', e && e.message); } } try { on_bound(s.address().port | 0); } catch (e) { console.error('[fw-ffi] udp bound error', e && e.message); } }); return idx; }"

/// UDP 单播发送（node send 参数顺序为 (msg, port, address)，此处已适配）；
/// 运行时上下文未初始化（未 start）时静默跳过——发送方语义为尽力而为。
/// data/host 同步消费（Buffer.from / send 立即发出）→ borrow
#borrow(data, host)
extern "js" fn ffi_udp_send(idx : Int, data : Bytes, host : String, port : Int) -> Unit =
  "(idx, data, host, port) => { const g = globalThis.__fw; if (!g) { return; } const s = g.udp[idx]; if (s) { try { s.send(Buffer.from(data), port | 0, host); } catch (e) { console.error('[fw-ffi] udp send error', e && e.message); } } }"

/// 关闭 UDP socket（幂等；关闭后句柄位记 null）
extern "js" fn ffi_udp_close(idx : Int) -> Unit =
  "(idx) => { const s = globalThis.__fw.udp[idx]; if (s) { try { s.close(); } catch (e) {} globalThis.__fw.udp[idx] = null; } }"

/// 启动 TCP 服务端 listen（§5.6）：
/// - bind_host：监听地址（"" = 全接口）；客户端角色（tcp_enabled=false）由 MoonBit 侧不调用本函数
/// - accept 新连接 → next_id(0) 分配 conn_id → 注册到 JS 侧连接表
/// - on_event(conn_id, ev, host, port, data)：ev 1=数据到达 / 2=连接建立（accept 场景带对端地址）/ 3=连接关闭
///   （回调由 JS 服务器长期持有 → owned）
#borrow(bind_host)
#owned(next_id, on_event)
extern "js" fn ffi_tcp_listen(
  port : Int,
  bind_host : String,
  next_id : (Int) -> Int,
  on_event : (Int, Int, String, Int, Bytes) -> Unit
) -> Int =
  "(port, bind_host, next_id, on_event) => { const g = globalThis.__fw; const srv = g.net.createServer((sock) => { let cid = 0; try { cid = next_id(0) | 0; } catch (e) { console.error('[fw-ffi] tcp accept next_id error', e && (e.message || String(e))); return; } g.tcp.set(cid, sock); g.qattach(sock); sock.on('data', (buf) => { try { on_event(cid, 1, '', 0, new Uint8Array(buf)); } catch (e) { console.error('[fw-ffi] tcp data error', e && e.message); } }); sock.on('error', () => {}); sock.on('close', () => { if (g.closed.has(cid)) { return; } g.closed.add(cid); g.qrelease(sock); g.tcp.delete(cid); try { on_event(cid, 3, '', 0, new Uint8Array(0)); } catch (e) { console.error('[fw-ffi] tcp close error', e && e.message); } }); try { on_event(cid, 2, String(sock.remoteAddress || ''), sock.remotePort | 0, new Uint8Array(0)); } catch (e) { console.error('[fw-ffi] tcp accept error', e && e.message); } }); g.server = srv; srv.on('error', (e) => { console.error('[fw-ffi] tcp server error', e && e.message); }); try { srv.listen(port | 0, bind_host || undefined); } catch (e) { console.error('[fw-ffi] tcp listen error', e && e.message); } return 0; }"

/// 发起 TCP 出站连接（§5.6；conn_id 由 MoonBit 侧预分配）：
/// - 连接成功 → on_event(conn_id, 2, 对端地址, 对端端口, 空)；失败 → error 吞掉后 close → on_event(conn_id, 3, ...)
/// - 重连复用同一 conn_id：先从 closed 集合移除，保证关闭事件可再次回调（回调长期持有 → owned）
#borrow(host)
#owned(on_event)
extern "js" fn ffi_tcp_connect(
  host : String,
  port : Int,
  conn_id : Int,
  on_event : (Int, Int, String, Int, Bytes) -> Unit
) -> Unit =
  "(host, port, conn_id, on_event) => { const g = globalThis.__fw; g.closed.delete(conn_id); let sock = null; try { sock = g.net.createConnection({ host: host, port: port | 0 }, () => { g.tcp.set(conn_id, sock); g.qattach(sock); try { on_event(conn_id, 2, String(sock.remoteAddress || host), sock.remotePort | 0, new Uint8Array(0)); } catch (e) { console.error('[fw-ffi] tcp connected error', e && e.message); } }); } catch (e) { console.error('[fw-ffi] tcp connect error', e && e.message); return; } sock.on('data', (buf) => { try { on_event(conn_id, 1, '', 0, new Uint8Array(buf)); } catch (e) { console.error('[fw-ffi] tcp data error', e && e.message); } }); sock.on('error', () => {}); sock.on('close', () => { if (g.closed.has(conn_id)) { return; } g.closed.add(conn_id); g.qrelease(sock); g.tcp.delete(conn_id); try { on_event(conn_id, 3, '', 0, new Uint8Array(0)); } catch (e) { console.error('[fw-ffi] tcp close error', e && e.message); } }); }"

/// TCP 发送字节流（发送背压，§12.6 实现限制）。
/// 返回 true = 已写入 socket（控制帧直写）或已受理进入有界数据队列；
/// 返回 false = 本帧**未写入任何字节**（数据队列满 / 连接不存在或已失效）。
/// 控制帧（CTR=1 且帧总长 ≤1024B：RST/Ping/GetIDL 请求）直写，不检查队列容量、不占配额；
/// 数据帧以 socket.writableLength 为水位：单连接上限按本连接水位判定；全栈预算按
/// **O(1) 增量计数**（q.used：数据帧入队加 / drain 归还 / 连接关闭扣减残留）判定。
/// 超限即拒写（不调用 socket.write）。q.check 开启时每次记账变更与遍历求和对账（漂移抛错）。
/// data 同步消费（write 立即发出）→ borrow
#borrow(data)
extern "js" fn ffi_tcp_write(conn_id : Int, data : Bytes) -> Bool =
  "(conn_id, data) => { const g = globalThis.__fw; if (!g || !g.q) { return false; } const s = g.tcp.get(conn_id); if (!s) { return false; } const buf = Buffer.from(data); let ctrl = false; if (buf.length >= 8 && (buf[0] & 0x80) !== 0) { const plb = buf[0] & 7; let total = 8 + plb + ((buf[0] & 8) ? 4 : 0); if (plb > 0) { let n = 0; for (let i = 0; i < plb; i++) { n = n * 256 + buf[8 + i]; } total += n; } ctrl = total <= g.q.ctrlMax; } const q = g.qstate(s); if (ctrl) { q.ctrl = (q.ctrl | 0) + 1; try { s.write(buf); g.qaccount(s, true); return true; } catch (e) { console.error('[fw-ffi] tcp write error', e && e.message); return false; } } const pending = s.writableLength || 0; if (pending > 0) { if (g.q.connMax > 0 && pending + buf.length > g.q.connMax) { return g.qreject(s, pending, 'conn limit ' + g.q.connMax + 'B'); } if (g.q.budget > 0 && g.q.used + buf.length > g.q.budget) { return g.qreject(s, pending, 'stack budget ' + g.q.budget + 'B'); } } try { s.write(buf); } catch (e) { console.error('[fw-ffi] tcp write error', e && e.message); return false; } g.qaccount(s, false); const w = s.writableLength || 0; if (w > q.peak) { q.peak = w; } if (w > g.q.peak) { g.q.peak = w; } return true; }"

/// 发送背压配置（同 C/Node 默认：单连接 256KB、全栈 64MB；0=不限制）
extern "js" fn ffi_sendq_config(max_conn : Int, budget : Int) -> Unit =
  "(max_conn, budget) => { const g = globalThis.__fw; if (!g || !g.q) { return; } g.q.connMax = max_conn | 0; g.q.budget = budget | 0; }"

/// 连接「持续满」起点（Date.now 毫秒；0 = 当前未处于队列满状态，drain 后归零）
extern "js" fn ffi_tcp_sendq_full_since(conn_id : Int) -> Double =
  "(conn_id) => { const g = globalThis.__fw; if (!g) { return 0.0; } const s = g.tcp.get(conn_id); return (s && s.__fwq && s.__fwq.fullSince) ? s.__fwq.fullSince : 0.0; }"

/// 持续满断连计数 +1（内部观测，无公开 API）
extern "js" fn ffi_sendq_note_closed(_x : Int) -> Unit =
  "(x) => { const g = globalThis.__fw; if (g && g.q) { g.q.closedFull = (g.q.closedFull | 0) + 1; } }"

/// 立即销毁 TCP 连接（JS 侧记入 closed 集合，不再回调关闭事件——由 MoonBit 侧自行收尾）；
/// 销毁前归还该连接计入全栈预算的数据帧残留量（§12.6，防计数漂移）
extern "js" fn ffi_tcp_destroy(conn_id : Int) -> Unit =
  "(conn_id) => { const g = globalThis.__fw; g.closed.add(conn_id); const s = g.tcp.get(conn_id); if (s) { try { g.qrelease(s); s.destroy(); } catch (e) {} g.tcp.delete(conn_id); } }"

/// 关闭 TCP 服务端（停止 accept 新连接）
extern "js" fn ffi_tcp_server_close(_x : Int) -> Unit =
  "(x) => { const srv = globalThis.__fw.server; if (srv) { try { srv.close(); } catch (e) {} globalThis.__fw.server = null; } }"

/// 错误日志（§12.4 格式由调用方保证；msg 同步消费 → borrow）
#borrow(msg)
extern "js" fn ffi_log_error(msg : String) -> Unit = "(msg) => { console.error(msg); }"
