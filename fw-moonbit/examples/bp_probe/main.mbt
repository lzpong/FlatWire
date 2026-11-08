// ============================================================
// bp_probe —— §12.6 发送背压实测（真实 socket 拥塞，非注入）
//
// 两条真实黑洞连接（本进程 Node net server，accept 后 pause 不读）：
//   阶段 1：c1 打满单连接上限（256KB）→ send_tcp_frame=false 且本帧未写入；再写仍 false；
//           数据队列满时 Ping 控制帧仍直写。
//   阶段 2：c2 写入直到撞「全栈预算」（budget 调小为 384KB = 1.5×单连接上限）：
//           自身水位仅约 128KB（< 256KB）却拒写 → 单独证明预算分支，而非单连接上限；
//           同时开启记账对账（q.check）：每次数据帧入队 / drain / 关系变更后，
//           增量计数 q.used 必须等于「遍历各连接 writableLength 求和」，漂移立即抛错。
//   阶段 3：两条连接持续重试写入维持满状态 → 持续满 ≥ 2×心跳（500ms → 1000ms）→ 断连。
//
// 运行：moon run examples/bp_probe --target js
// ============================================================

// ---- 编排 FFI（示例私有）----
#borrow(msg)
extern "js" fn bp_log(msg : String) -> Unit = "(msg) => { console.log(msg); }"

/// 构造 1400B payload（内容无关，仅用于压满发送队列）
extern "js" fn bp_payload(len : Int) -> Bytes =
  "(n) => { const b = new Uint8Array(n | 0); b.fill(0x41); return b; }"

/// 黑洞服务端：accept 后 pause（应用层不读 → 接收窗口耗尽 → 本端可写空间耗尽）
/// 每 300ms 发送一个合法 Ping 控制帧（8B, CTR=1）：让客户端心跳有输入，
/// 从而把断连归因锁定在「持续满」而非「2×心跳无可收帧」
extern "js" fn bp_start_blackhole(port : Int) -> Unit =
  "(port) => { const net = require('node:net'); const ping = Buffer.from([0x80, 0, 0, 0, 0, 0, 0, 0]); const srv = net.createServer((s) => { s.pause(); s.on('error', () => {}); const t = setInterval(() => { try { s.write(ping); } catch (e) {} }, 300); s.on('close', () => { clearInterval(t); }); }); srv.on('error', (e) => { console.error('[BP] blackhole server error', e && e.message); }); try { srv.listen(port | 0, '127.0.0.1'); console.log('[BP] blackhole listening 127.0.0.1:' + (port | 0)); } catch (e) { console.error('[BP] blackhole listen error', e && e.message); } }"

/// 本连接水位（与 ffi_tcp_write 判定同口径：socket.writableLength）
extern "js" fn bp_pending(conn_id : Int) -> Int =
  "(cid) => { const g = globalThis.__fw; const s = g && g.tcp.get(cid); return (s && s.writableLength) || 0; }"

/// 全栈预算增量计数（q.used，O(1) 判定值）
extern "js" fn bp_used(_x : Int) -> Int =
  "(_) => { const g = globalThis.__fw; return (g && g.q) ? (g.q.used | 0) : 0; }"

/// 遍历所有连接 writableLength 求和（仅对账用）
extern "js" fn bp_sum(_x : Int) -> Int =
  "(_) => { const g = globalThis.__fw; return (g && g.qsum) ? (g.qsum() | 0) : 0; }"

/// 各连接控制帧桶之和（对账口径：控制帧不占预算，但确实进入 writableLength）
extern "js" fn bp_ctrl(_x : Int) -> Int =
  "(_) => { const g = globalThis.__fw; return (g && g.qctrlsum) ? (g.qctrlsum() | 0) : 0; }"

/// 内部计数器（JSON 文本：connMax/budget/rejects/peak/closedFull/used）
extern "js" fn bp_stats(_x : Int) -> String =
  "(_) => { const g = globalThis.__fw; if (!g || !g.q) { return '(no __fw)'; } const q = g.q; return 'connMax=' + q.connMax + 'B budget=' + q.budget + 'B rejects=' + q.rejects + ' peak=' + q.peak + 'B closedFull=' + q.closedFull + ' used=' + (q.used | 0) + 'B'; }"

/// 开启记账对账（漂移立即抛错）——必须在 start 之后调用（__fw 已初始化）
extern "js" fn bp_check(_x : Int) -> Unit =
  "(_) => { const g = globalThis.__fw; if (g && g.q) { g.q.check = true; } }"

#owned(fn_cb)
extern "js" fn bp_set_timeout(fn_cb : (Int) -> Unit, ms : Int) -> Int =
  "(cb, ms) => { return setTimeout(() => { try { cb(0); } catch (e) { console.error('[BP] timer error', e && e.message); } }, ms | 0); }"

extern "js" fn bp_exit(_x : Int) -> Unit = "(_) => process.exit(0)"

/// 持续写数据帧直到被拒：返回（受理帧数, 是否被拒）
fn bp_fill(
  t : @transport.Transport,
  cid : Int,
  spec : @frame.FrameSpec,
  payload : Bytes
) -> (Int, Bool) {
  let mut written = 0
  while written < 60000 {
    if t.send_tcp_frame(cid, spec, payload) {
      written = written + 1
    } else {
      return (written, true)
    }
  }
  (written, false)
}

/// 持续重试写入以维持队列满状态（真实产生端持续有数据；drain 会短暂归零持续满计时），
/// 每 100ms 批量尝试 200 帧，直到连接关闭或流程结束
fn bp_hold(
  t : @transport.Transport,
  cid : Int,
  spec : @frame.FrameSpec,
  payload : Bytes,
  done : Array[Bool]
) -> Unit {
  let _ = bp_set_timeout(fn(_) {
    if done[0] || !t.is_alive(cid) {
      return
    }
    let mut n = 0
    while n < 200 {
      if t.send_tcp_frame(cid, spec, payload) {
        n = n + 1
      } else {
        break
      }
    }
    bp_hold(t, cid, spec, payload, done)
  }, 100)
}

fn main {
  let p1 : Int = 5410
  let p2 : Int = 5412
  let _ = bp_start_blackhole(p1)
  let _ = bp_start_blackhole(p2)
  let budget : Int = 393216 // 384KB：> 单连接上限 256KB、< 2×（保证第二阶段预算先触发）
  let cfg : @transport.TransportConfig = {
    udp_port: 5411, // 避免与常规 5400 实例冲突（本示例仅用 TCP）
    tcp_port: p1,
    bind_address: "127.0.0.1",
    tcp_enabled: false, // 仅客户端角色：不监听 TCP
    local_ver: 0,
    max_payload_len: 1400,
    tcp_frame_timeout_ms: 5000L,
    // 缩短心跳周期让「持续满断连」可在秒级观测（窗口 = 2×500ms）
    heartbeat_period_ms: 500L,
    max_send_queue_bytes: 262144, // §12.6 默认：单连接 256KB（不改语义）
    send_queue_budget_bytes: budget,
  }
  let payload = bp_payload(1400)
  let spec = @frame.data_spec(@frame.Non, 0x03, 4096, 1, 1, 1)
  let cid1 : Array[Int] = [-1]
  let cid2 : Array[Int] = [-1]
  let phase : Array[Int] = [0]
  let done : Array[Bool] = [false]
  let closedOnce : Array[Bool] = [false]
  // 闭包不能捕获自身初始化表达式中的 t → 用槽位延迟填充（构造完成后 push）
  let t_slot : Array[@transport.Transport] = []
  let finish : Array[(Int) -> Unit] = [fn(_x) { () }]
  let t = @transport.Transport::new(cfg, fn(ev) {
    match ev {
      @transport.TcpConnected(c, _host, p) => {
        bp_log("[BP] connected cid=\{c} remotePort=\{p}")
        if p == p1 {
          cid1[0] = c
          // 阶段 1：单连接上限（256KB）
          let (n1, rej1) = bp_fill(t_slot[0], c, spec, payload)
          bp_log(
            "[BP] stage1 conn-limit: accepted=\{n1} rejected=\{rej1} pending=\{bp_pending(c)}B used=\{bp_used(0)}B",
          )
          // 拒写语义：再写仍 false，且水位不增长（一字节未写入）
          let before = bp_pending(c)
          let again = t_slot[0].send_tcp_frame(c, spec, payload)
          bp_log("[BP] stage1 retry: ok=\{again} pendingBefore=\{before} pendingAfter=\{bp_pending(c)}")
          // 控制帧（Ping，CTR=1）在数据队列满时仍直写
          let ctrl = t_slot[0].send_tcp_frame(c, @frame.ctrl_spec(@frame.Non, 0x00, 0), b"")
          bp_log("[BP] stage1 control-frame: ok=\{ctrl}")
          phase[0] = 1
          let _ = t_slot[0].tcp_connect("127.0.0.1", p2)
        } else if p == p2 && phase[0] == 1 {
          cid2[0] = c
          // c2 建连期间 c1 可能被内核吸收部分积压 → 先重新灌满 c1，再压 c2
          let (r1, _rej1) = bp_fill(t_slot[0], cid1[0], spec, payload)
          let used1 = bp_used(0)
          bp_log("[BP] stage2 refill-c1: accepted=\{r1} pending1=\{bp_pending(cid1[0])}B used=\{used1}B")
          let (n2, rej2) = bp_fill(t_slot[0], c, spec, payload)
          let pend2 = bp_pending(c)
          let used2 = bp_used(0)
          bp_log(
            "[BP] stage2 budget: accepted=\{n2} rejected=\{rej2} pending2=\{pend2}B usedBefore=\{used1}B used=\{used2}B budget=\{budget}B",
          )
          // 预算分支证据：c2 自身水位远低于单连接上限，而全栈计数已逼近预算
          bp_log(
            "[BP] stage2 check: pending2<262144=\{pend2 < 262144} used+1410>budget=\{used2 + 1410 > budget}",
          )
          // 预算满时控制帧仍直写（不占配额）
          let ctrl2 = t_slot[0].send_tcp_frame(c, @frame.ctrl_spec(@frame.Non, 0x00, 0), b"")
          bp_log("[BP] stage2 control-frame: ok=\{ctrl2}")
          // 对账：判定用数据桶 used，控制帧桶 ctrl 与水位同口径（used + ctrl == 遍历求和）
          // q.check 已在每次记账变更时断言；此处再打印三量便于人工核对
          bp_log(
            "[BP] reconcile: used=\{bp_used(0)}B ctrl=\{bp_ctrl(0)}B counted=\{bp_used(0) + bp_ctrl(0)}B traversal=\{bp_sum(0)}B",
          )
          phase[0] = 2
          // 阶段 3：两条连接持续重试 → 持续满 ≥ 2×心跳 → 断连
          bp_hold(t_slot[0], cid1[0], spec, payload, done)
          bp_hold(t_slot[0], c, spec, payload, done)
        }
      }
      @transport.TcpClosed(c, _host, p) => {
        bp_log("[BP] closed cid=\{c} remotePort=\{p} stats=\{bp_stats(0)}")
        done[0] = true
        if !closedOnce[0] {
          closedOnce[0] = true
          let _ = bp_set_timeout(finish[0], 300)
        }
      }
      _ => ()
    }
  })
  t_slot.push(t)
  t.start()
  bp_check(0) // 开启记账对账（漂移立即抛错）
  let cid = t.tcp_connect("127.0.0.1", p1)
  bp_log("[BP] connecting cid=\{cid} -> 127.0.0.1:\{p1} (heartbeat=500ms, budget=\{budget}B)")
  finish[0] = fn(_x) {
    bp_log(
      "[BP] final: alive1=\{t.is_alive(cid1[0])} alive2=\{t.is_alive(cid2[0])} used=\{bp_used(0)}B ctrl=\{bp_ctrl(0)}B traversal=\{bp_sum(0)}B stats=\{bp_stats(0)}",
    )
    t.stop()
    let _ = bp_set_timeout(fn(_) { bp_exit(0) }, 200)
  }
  // 兜底：8s 后无论如何汇总退出（断连应在持续满 1~1.5s 内发生）
  let _ = bp_set_timeout(fn(_) {
    if !done[0] {
      bp_log("[BP] timeout waiting for full-queue disconnect")
      finish[0](0)
    }
  }, 8000)
}
