// ============================================================
// transport.test.js —— 测试基准 §2.5/2.22~2.28 TCP 半帧两阶段 + §3.9 TCP 无 CON/ACK
// 使用真实 socket（net.connect ↔ TcpTransport listen）与短超时加速。
// ============================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { performance } from 'node:perf_hooks';
import { TcpTransport, TcpConn } from '../src/transport/tcp.js';
import { UdpTransport } from '../src/transport/udp.js';
import { TYP, CODE, encodeFrame, makeRst, parseDatagram } from '../src/frame/frame.js';
import { RST_CODE } from '../src/errors.js';

const PORT = 45400;
const FRAME_TIMEOUT = 300; // 短半帧超时（加速测试）

/** 启动监听服务端，返回 { transport, frames, conns, close } */
async function startServer() {
  const t = new TcpTransport({
    port: PORT, ver: 0, tcpFrameTimeoutMs: FRAME_TIMEOUT,
    heartbeatPeriodMs: 60000, heartbeatTimeoutMs: 120000,
    logger: { info() {}, warn() {}, error() {}, frame() {}, debug() {} },
  });
  const frames = [];
  const conns = [];
  t.on('frame', (conn, frame) => frames.push(frame));
  t.on('conn', (conn) => conns.push(conn));
  await t.listen();
  return { t, frames, conns };
}

/** 连接服务端的原始 socket，返回 { sock, rxRst, rxAll, closed } */
function connectRaw() {
  const state = { rxRst: [], rxAll: [], closed: false, closeAt: 0 };
  const sock = net.connect({ host: '127.0.0.1', port: PORT });
  sock.setNoDelay(true);
  let buf = Buffer.alloc(0);
  sock.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    // 逐帧解析收到的字节（服务端响应帧均无 MSK）
    for (;;) {
      if (buf.length < 8) break;
      const plb = buf[0] & 0x07;
      const headerLen = 8 + plb;
      if (buf.length < headerLen) break;
      let plen = 0;
      for (let i = 0; i < plb; i++) plen = plen * 256 + buf[8 + i];
      const total = headerLen + plen;
      if (buf.length < total) break;
      const r = parseDatagram(buf.subarray(0, total), { ver: 0, isUdp: false });
      if (r.ok) {
        state.rxAll.push(r.frame);
        if (r.frame.typ === TYP.RST) state.rxRst.push(r.frame);
      }
      buf = buf.subarray(total);
    }
  });
  sock.on('close', () => { state.closed = true; state.closeAt = Date.now(); });
  return { sock, state, ready: new Promise((res) => sock.once('connect', res)) };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('2.5 半帧超时——帧头不完整(<8B) → RST(0x26)+关连接', async () => {
  const srv = await startServer();
  try {
    const { sock, state, ready } = connectRaw();
    await ready;
    // 3B < 8B 帧头不完整（byte0=0x01→PLB=1 数据帧、byte1=0x01→NON/REQUEST，
    // 前缀不触发 §4.3 任何即时校验，仅卡在帧头不完整）
    sock.write(Buffer.from([0x01, 0x01, 0x10]));
    await sleep(FRAME_TIMEOUT + 250);
    assert.equal(state.rxRst.length, 1);
    assert.equal(state.rxRst[0].code, RST_CODE.FRAME_TIMEOUT);
    assert.equal(state.closed, true); // 帧总长不可知 → 关闭连接（§4.1 阶段一）
    sock.destroy();
  } finally {
    await srv.t.stop();
  }
});

test('2.22/2.23 帧头完整 → RST(0x26)+丢弃模式；收满 R 恢复复用连接', async () => {
  const srv = await startServer();
  try {
    const { sock, state, ready } = connectRaw();
    await ready;
    // 完整帧头（帧总长 L=8+1+3=12B）只发 10B → 帧头完整、Payload 不完整
    const half = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 1, payload: Buffer.from([9, 9, 9]),
    });
    sock.write(half.subarray(0, 10));
    await sleep(FRAME_TIMEOUT + 250);
    assert.equal(state.rxRst.length, 1);
    assert.equal(state.rxRst[0].code, RST_CODE.FRAME_TIMEOUT);
    assert.equal(state.closed, false); // 丢弃模式：连接不关闭（§4.1 阶段二）

    // 发完剩余 R=2 字节 → 恢复 IDLE；随后发正常新帧 → 正确解析交付（连接复用）
    sock.write(half.subarray(10));
    await sleep(80);
    const next = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 2, payload: Buffer.from([7]),
    });
    sock.write(next);
    await sleep(120);
    const data = srv.frames.filter((fr) => fr.code === CODE.REQUEST);
    assert.equal(data.length, 1);       // 半帧作废不交付，新帧交付
    assert.equal(data[0].strm_id, 2);
    assert.equal(state.closed, false);  // 连接继续复用不重建（§2.23）
    sock.destroy();
  } finally {
    await srv.t.stop();
  }
});

test('2.24 丢弃模式字节刷新计时：慢速发送不触发兜底断连', async () => {
  const srv = await startServer();
  try {
    const { sock, state, ready } = connectRaw();
    await ready;
    const frame = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 1, payload: Buffer.alloc(40, 5),
    });
    const headLen = 8 + (frame[0] & 0x07);
    sock.write(frame.subarray(0, headLen)); // 帧头完整
    await sleep(FRAME_TIMEOUT + 250);       // 进入丢弃模式（R = L - headLen）
    assert.equal(state.closed, false);
    // 慢速逐字节发送剩余：相邻间隔 250ms < 兜底 600ms；总时长 > 600ms（超过兜底）
    for (let i = headLen; i < frame.length; i++) {
      sock.write(Buffer.from([frame[i]]));
      await sleep(200);
    }
    await sleep(80);
    assert.equal(state.closed, false); // 每字节刷新兜底计时 → 不断连（§2.24）
    // 恢复后新帧正常
    srv.frames.length = 0;
    sock.write(encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 3, payload: Buffer.alloc(0),
    }));
    await sleep(120);
    assert.equal(srv.frames.length, 1);
    sock.destroy();
  } finally {
    await srv.t.stop();
  }
}, { timeout: 15000 });

test('2.26 丢弃模式兜底超时：完全停止发送 → 2×超时后关连接', async () => {
  const srv = await startServer();
  try {
    const { sock, state, ready } = connectRaw();
    await ready;
    const frame = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 1, payload: Buffer.alloc(20, 1),
    });
    sock.write(frame.subarray(0, 9)); // 帧头完整后停止
    const dropStart = Date.now();
    await sleep(FRAME_TIMEOUT + 200); // RST(0x26) 已回
    assert.equal(state.rxRst.length, 1);
    // 兜底 = 2 × 300 = 600ms；等至 >700ms
    await sleep(700);
    assert.equal(state.closed, true);
    assert.ok(state.closeAt - dropStart >= 2 * FRAME_TIMEOUT - 50); // ≥ 兜底倍率
    sock.destroy();
  } finally {
    await srv.t.stop();
  }
});

test('2.25 丢弃模式对端 EOF：关闭即终止，无悬挂状态', async () => {
  const srv = await startServer();
  try {
    const { sock, state, ready } = connectRaw();
    await ready;
    const frame = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 1, payload: Buffer.alloc(20, 1),
    });
    sock.write(frame.subarray(0, 9));
    await sleep(FRAME_TIMEOUT + 200); // 进入丢弃模式
    sock.end();                       // EOF
    await sleep(150);
    // 服务端连接随 EOF 关闭（connClosed 由 mgr 内部处理；无崩溃即通过）
    assert.equal(srv.t.serverConns.size, 0);
    sock.destroy();
  } finally {
    await srv.t.stop();
  }
});

test('2.27/2.28 反向 RST(0x26) 不污染正向流：RST 后同连接正常帧无误位', async () => {
  const srv = await startServer();
  try {
    const { sock, state, ready } = connectRaw();
    await ready;
    const half = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 1, payload: Buffer.from([1, 2, 3]),
    });
    sock.write(half.subarray(0, 10)); // 半帧 → RST(0x26)（反向独立帧）
    await sleep(FRAME_TIMEOUT + 250);
    assert.equal(state.rxRst.length, 1);
    // 发完剩余 + 后续两个正常帧 → 字节流对齐不受 RST 影响（§2.28）
    sock.write(half.subarray(10));
    const f2 = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 2, payload: Buffer.from([4]),
    });
    const f3 = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 3, payload: Buffer.from([5, 6]),
    });
    sock.write(Buffer.concat([f2, f3]));
    await sleep(150);
    const data = srv.frames.filter((fr) => fr.code === CODE.REQUEST);
    assert.deepEqual(data.map((fr) => fr.strm_id), [2, 3]); // 后续帧无误位
    sock.destroy();
  } finally {
    await srv.t.stop();
  }
});

test('3.9 TCP 上收到 CON/ACK → RST(0x00)（§3.7）', async () => {
  const srv = await startServer();
  try {
    const { sock, state, ready } = connectRaw();
    await ready;
    // TCP 上发 CON 帧（解析层拒绝：TCP 不使用 CON/ACK）
    const con = Buffer.from([0x00, (TYP.CON << 6) | 0x01, 0, 1, 0, 1, 1, 1]);
    sock.write(con);
    await sleep(150);
    assert.equal(state.rxRst.length, 1);
    assert.equal(state.rxRst[0].code, 0x00);
    sock.destroy();
  } finally {
    await srv.t.stop();
  }
});

test('2.30 粘包交付若干帧后进入半帧：RST(0x26) 回显该半帧 StrmID（§5.4）', async () => {
  const srv = await startServer();
  try {
    const { sock, state, ready } = connectRaw();
    await ready;
    // 一次写入：2 个完整帧（strm=1、2）+ 第 3 帧只给帧头（strm=7，Payload 不完整）
    const f1 = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 1, payload: Buffer.from([0x11]),
    });
    const f2 = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 2, payload: Buffer.from([0x22]),
    });
    const f3 = encodeFrame({
      ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
      svc_id: 1, if_id: 1, inst_id: 1, strm_id: 7, payload: Buffer.from([1, 2, 3]),
    });
    sock.write(Buffer.concat([f1, f2, f3.subarray(0, 9)])); // 第 3 帧缺 2B payload
    await sleep(150);
    assert.deepEqual(srv.frames.filter((fr) => fr.code === CODE.REQUEST).map((fr) => fr.strm_id), [1, 2]);
    // 半帧超时 → RST(0x26)；回显必须是当前半帧的 StrmID=7，
    // 若按缓冲绝对下标取 byte7 会回显已消费帧的 1 或 2（第 3 轮容量缓冲重构的回归点）
    await sleep(FRAME_TIMEOUT + 250);
    assert.equal(state.rxRst.length, 1);
    assert.equal(state.rxRst[0].code, RST_CODE.FRAME_TIMEOUT);
    assert.equal(state.rxRst[0].strm_id, 7);
    sock.destroy();
  } finally {
    await srv.t.stop();
  }
});

/** 活跃 Socket 句柄数（Node 内部 API，仅用于泄漏对比；server 监听句柄非 Socket 不计入） */
function socketHandles() {
  return process._getActiveHandles().filter((h) => h instanceof net.Socket).length;
}

/** 连接指定端口的原始 socket（同 connectRaw，可自定义端口） */
function connectRawTo(port) {
  const state = { rxRst: [], rxAll: [], closed: false };
  const sock = net.connect({ host: '127.0.0.1', port });
  sock.setNoDelay(true);
  sock.on('close', () => { state.closed = true; });
  const ready = new Promise((res, rej) => {
    sock.once('connect', res);
    sock.once('error', rej);
  });
  return { sock, state, ready };
}

test('R3-8 入站连接上限：超限立即销毁，登记数不突破上限（maxConns=2）', async () => {
  const t = new TcpTransport({
    port: PORT + 1, ver: 0, tcpFrameTimeoutMs: FRAME_TIMEOUT,
    heartbeatPeriodMs: 60000, heartbeatTimeoutMs: 120000, maxConns: 2,
    logger: { info() {}, warn() {}, error() {}, frame() {}, debug() {} },
  });
  const conns = [];
  t.on('conn', (c) => conns.push(c));
  await t.listen();
  try {
    const s1 = connectRawTo(PORT + 1); await s1.ready;
    const s2 = connectRawTo(PORT + 1); await s2.ready;
    await sleep(120);
    assert.equal(t.serverConns.size, 2);
    // 第 3 条：服务端立即销毁，不创建 TcpConn（解析器/定时器/fd 均不占用）
    const s3 = connectRawTo(PORT + 1); await s3.ready;
    await sleep(180);
    assert.equal(t.serverConns.size, 2);
    assert.equal(conns.length, 2);
    assert.equal(s3.state.closed, true);
    s1.sock.destroy(); s2.sock.destroy();
    await sleep(200);
    assert.equal(t.serverConns.size, 0); // 断开后登记全部回收
  } finally {
    await t.stop();
  }
});

test('R3-8 100 并发建连/断开：登记与句柄全部回收（无 fd 泄漏）', async () => {
  const srv = await startServer();
  try {
    const before = socketHandles();
    const list = [];
    for (let i = 0; i < 100; i++) list.push(connectRaw());
    await Promise.all(list.map((x) => x.ready));
    await sleep(300);
    assert.equal(srv.t.serverConns.size, 100); // 上限 1024，全部接受
    for (const x of list) x.sock.destroy();
    await sleep(600);
    assert.equal(srv.t.serverConns.size, 0);   // 全部清理
    const after = socketHandles();
    assert.ok(after <= before + 3, `socket 句柄泄漏：before=${before} after=${after}`);
  } finally {
    await srv.t.stop();
  }
});

test('TcpTransport 连接复用与 connClosed 清理（§5.6）', async () => {
  const srv = await startServer();
  try {
    const conn1 = await srv.t.getConn('127.0.0.1', PORT);
    const conn2 = await srv.t.getConn('127.0.0.1', PORT);
    assert.equal(conn1, conn2); // 同 (IP,Port) 唯一长连接
    conn1.close();
    await sleep(120);
    assert.equal(srv.t.clientConns.size, 0); // 关闭后登记清理
  } finally {
    await srv.t.stop();
  }
});

test('轮B 心跳超时临界（timeout-1 / timeout+1）与单调时钟', () => {
  // 构造无网络 TcpConn（假 socket + 事件宿主），直接驱动私有检查函数。
  // 时钟跳变本身无法在同进程注入系统时钟，此处以 performance.now() 单调时钟保证
  //（实现已由 Date.now 切至单调时钟）+ 超时临界值验证判定边界。
  class FakeSock extends EventEmitter {
    constructor() {
      super();
      this.remoteAddress = '127.0.0.1';
      this.remotePort = 1;
      this.destroyed = false;
    }
    setNoDelay() {}
    write() { return true; }
    destroy() { this.destroyed = true; this.emit('close'); }
  }
  const sock = new FakeSock();
  const mgr = new EventEmitter();
  const c = new TcpConn(sock, {
    ver: 0, heartbeatPeriodMs: 1e9, heartbeatTimeoutMs: 3000,
    logger: { warn() {} },
  }, mgr);
  // timeout - 1ms：未达阈值，连接仍存活（可能顺带发空闲 Ping，不影响存活）
  c.lastRecvAt = performance.now() - (3000 - 1);
  c._heartbeatCheck();
  assert.equal(c.alive, true);
  // timeout + 1ms：判失效并销毁（>= 阈值语义）
  c.lastRecvAt = performance.now() - (3000 + 1);
  c._heartbeatCheck();
  assert.equal(c.alive, false);
  assert.equal(sock.destroyed, true);
  clearInterval(c._hbTimer);
});

// ============================================================
// 发送背压（§12.6 实现限制）——真实 socket 拥塞路径：
// 对端「接受连接但不读取」（socket.pause()），发送侧持续写 1400B Payload 数据帧，
// 由内核/Node 内部缓冲自然积压触发队列上限（不注入任何内部状态）。
// ============================================================

const BP_LOGGER = { info() {}, warn() {}, error() {}, frame() {}, debug() {} };

/** 「黑洞」服务端：接受连接后暂停读取（对端不读），返回控制/关闭句柄 */
function startBlackhole(port) {
  const socks = new Set();
  const server = net.createServer((s) => {
    s.pause(); // 关键：不读取 → 接收窗口关闭 → 发送侧真实拥塞
    socks.add(s);
    s.on('close', () => socks.delete(s));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, () => resolve({
      server,
      sockets: socks,
      resume() { for (const s of socks) s.resume(); },
      async close() {
        for (const s of socks) s.destroy();
        await new Promise((r) => server.close(r));
      },
    }));
  });
}

/** 构造一个 1400B Payload 的 TCP 数据帧（CTR=0，编码后总长 1410B） */
function dataFrame(strmId) {
  return {
    ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
    svc_id: 1, if_id: 1, inst_id: 1, strm_id: strmId, payload: Buffer.alloc(1400, 0x5a),
  };
}

test('BP-1(Node) 数据发送队列满：write 返回 false 且未写入；拒绝计数增长；控制帧仍可直写', async () => {
  const port = PORT + 10;
  const bh = await startBlackhole(port);
  const t = new TcpTransport({
    port: 0, ver: 0, tcpFrameTimeoutMs: FRAME_TIMEOUT,
    heartbeatPeriodMs: 60000, heartbeatTimeoutMs: 120000,
    logger: BP_LOGGER,
  });
  try {
    const conn = await t.getConn('127.0.0.1', port);
    // 真实路径：持续写数据帧直至队列拒写（单连接默认上限 256KB）
    let frames = 0;
    while (frames < 60000) {
      const ok = conn.write(dataFrame((frames % 200) + 1));
      frames += 1;
      if (!ok) break;
    }
    assert.ok(conn.qRejects > 0, `未触发队列上限：连续写入 ${frames} 帧仍全部成功`);
    assert.ok(conn.alive);

    const pendingBefore = conn.socket.writableLength;
    assert.ok(pendingBefore + 1410 > 262144, `拒写时水位未达单连接上限：${pendingBefore}B`);

    // 语义收紧：返回 false = 本帧未写入任何字节（水位不变）
    assert.equal(conn.write(dataFrame(9)), false);
    assert.equal(conn.socket.writableLength, pendingBefore, '拒写后水位变化 → 说明仍写入了字节');
    assert.ok(conn.qRejects >= 2, `拒写计数未增长：${conn.qRejects}`);
    assert.ok(t.sendqRejects >= 2, `全栈拒写计数未增长：${t.sendqRejects}`);
    assert.ok(conn.qPeak > 0 && conn.qPeak <= pendingBefore + 20000, `峰值异常：${conn.qPeak}B`);

    // 数据队列满时控制帧（RST，8B，CTR=1）仍直写：返回 true 且水位 +8B（不占配额）
    const ctrlOk = conn.write(makeRst(RST_CODE.SERVICE_UNAVAILABLE, { ctr: 1, strm_id: 7 }));
    assert.equal(ctrlOk, true);
    assert.equal(conn.socket.writableLength, pendingBefore + 8, '控制帧未直写成功');

    // 队列排空后可恢复（不因一次拒写永久锁死；心跳周期 60s 不触发持续满断连）
    const t0 = performance.now();
    while (conn.qFullSince !== 0 && performance.now() - t0 < 2000) await sleep(20);
    assert.equal(conn.qFullSince, 0, '队列排空后持续满计时未归零');
    assert.equal(conn.write(dataFrame(10)), true);
    conn.close();
  } finally {
    await bh.close();
    await t.stop();
  }
}, { timeout: 15000 });

test('BP-2(Node) 数据队列持续满超过 2×心跳周期 → 主动断连；内部计数增长', async () => {
  const port = PORT + 11;
  const bh = await startBlackhole(port);
  // 心跳周期 50ms → 持续满窗口 100ms；存活超时放宽（60s）避免与心跳超时混淆
  const t = new TcpTransport({
    port: 0, ver: 0, tcpFrameTimeoutMs: FRAME_TIMEOUT,
    heartbeatPeriodMs: 50, heartbeatTimeoutMs: 60000,
    logger: BP_LOGGER,
  });
  try {
    const conn = await t.getConn('127.0.0.1', port);
    // 反复填满并让事件循环推进：若只是 Node 内部短时积压会在 sleep 内排空（drain 归零），
    // 只有真实内核拥塞才会让 qFullSince 跨事件循环轮次持续存在。
    let fullSince = 0;
    const start = performance.now();
    while (conn.alive && performance.now() - start < 4000) {
      for (let i = 0; i < 4000; i++) {
        if (!conn.write(dataFrame((i % 200) + 1))) break;
      }
      if (conn.qFullSince !== 0) fullSince = conn.qFullSince;
      await sleep(20);
    }
    assert.equal(conn.alive, false, '队列持续满超过 2×心跳周期未断连');
    await sleep(100); // 等 socket 'close' 事件完成登记清理
    assert.equal(t.sendqClosedFull, 1, `持续满断连计数异常：${t.sendqClosedFull}`);
    assert.ok(t.sendqRejects > 0);
    assert.equal(t.clientConns.size, 0); // 断连后登记回收
    const fullMs = performance.now() - fullSince;
    assert.ok(fullMs >= 90, `持续满时长不足 2×心跳周期（${fullMs}ms < 100ms）`);
  } finally {
    await bh.close();
    await t.stop();
  }
}, { timeout: 15000 });

test('BP-4(Node) 全栈预算分支：O(1) 增量计数触发、计数与遍历求和一致（真实 socket 拥塞）', async () => {
  const p1 = PORT + 12;
  const p2 = PORT + 13;
  const bh1 = await startBlackhole(p1);
  const bh2 = await startBlackhole(p2);
  // 采集拒写原因日志（_rejectDataWrite 首次拒写时输出 why，用于区分 conn limit / stack budget）
  const logs = [];
  const logger = { ...BP_LOGGER, warn: (...a) => logs.push(a.join(' ')), error: (...a) => logs.push(a.join(' ')) };
  // 单连接上限保持默认 256KB；预算调小为 384KB（> 单连接上限、< 2×单连接上限）：
  // 第一条连接先打满单连接上限，第二条连接在自身水位约 128KB 时先撞全栈预算，
  // 从而单独证明「预算分支」而非复用「单连接上限分支」
  const t = new TcpTransport({
    port: 0, ver: 0, tcpFrameTimeoutMs: FRAME_TIMEOUT,
    heartbeatPeriodMs: 60000, heartbeatTimeoutMs: 120000,
    maxSendQueueBytes: 262144,
    sendQueueBudgetBytes: 393216,
    checkSendqAccounting: true, // 对账开关：每次记账变更后断言「增量计数 == 遍历求和」
    logger,
  });
  try {
    // 对账口径：数据桶 sendqBytes + 各连接控制桶 qCtrl（控制帧直写字节）
    // 减去「部分 flush 但尚未同步」的滞后量 lag，必须等于遍历 writableLength 求和。
    // 控制帧不占预算，但确实进入水位；关闭/漏减不会残留 accounted，故 lag 不影响漏扣检测。
    const counted = () => {
      let ctrl = 0, lag = 0;
      for (const c of [...t.clientConns.values(), ...t.serverConns]) {
        if (!c.alive) continue;
        const w = c.socket.writableLength ?? 0;
        ctrl += c.qCtrl;
        if (c.qAccounted > w) lag += c.qAccounted - w;
      }
      return t.sendqBytes + ctrl - lag;
    };
    // 第一条连接：真实路径打满单连接上限
    const c1 = await t.getConn('127.0.0.1', p1);
    let f1 = 0;
    while (f1 < 60000) {
      if (!c1.write(dataFrame((f1 % 200) + 1))) break;
      f1 += 1;
    }
    assert.ok(c1.qRejects > 0, '第一条连接未打满单连接上限');
    assert.ok(logs.some((m) => m.includes('conn limit')), '第一条连接未命中单连接上限分支');

    // 建立第二条连接（期间 c1 的积压可能被内核吸收 → 重新灌满后再验证预算）
    const c2 = await t.getConn('127.0.0.1', p2);
    f1 = 0;
    while (f1 < 60000) {
      if (!c1.write(dataFrame((f1 % 200) + 1))) break;
      f1 += 1;
    }
    const usedBefore = t.sendqBytes;
    assert.ok(usedBefore >= 254000, `重灌后第一条连接入账不足：${usedBefore}B`);
    assert.equal(counted(), t._sumWritableLengths(), '阶段1：增量计数与遍历求和不一致');

    logs.length = 0;
    let f2 = 0;
    while (f2 < 60000) {
      if (!c2.write(dataFrame((f2 % 200) + 1))) break;
      f2 += 1;
    }
    assert.ok(c2.qRejects > 0, '第二条连接未触发拒写');
    assert.ok(c2.alive);
    // 预算分支证据：第二条连接自身水位远低于单连接上限，且全栈计数已逼近预算
    const p2Pending = c2.socket.writableLength;
    assert.ok(p2Pending < 262144, `第二条连接在单连接上限处被拒（${p2Pending}B），未覆盖预算分支`);
    assert.ok(t.sendqBytes + 1410 > 393216, `全栈计数未达预算阈值：${t.sendqBytes}B`);
    assert.ok(logs.some((m) => m.includes('stack budget')), `未命中预算分支日志：${logs.join(' | ')}`);
    assert.equal(counted(), t._sumWritableLengths(), '阶段2：增量计数与遍历求和不一致');

    // 预算满时控制帧（RST，8B，CTR=1）仍直写，不占配额
    assert.equal(c2.write(makeRst(RST_CODE.SERVICE_UNAVAILABLE, { ctr: 1, strm_id: 7 })), true);
    // 控制帧写入也会进入 writableLength：控制桶必须同步，否则对账漂移（本轮修复的回归点）
    assert.equal(counted(), t._sumWritableLengths(), '控制帧直写后：控制桶未同步');

    // 关闭时扣减各连接残留量：对端销毁触发本端真实 close 路径（end() 单独不会立即关闭）
    c1.close();
    c2.close();
    await bh1.close();
    await bh2.close();
    await sleep(300);
    assert.equal(counted(), t._sumWritableLengths(), '关闭后：残留量未扣减');
    t._assertSendqAccounting(); // 全部关闭完成后对账（瞬时态已消失）
  } finally {
    await bh1.close();
    await bh2.close();
    await t.stop();
  }
}, { timeout: 20000 });

// ============================================================
// §5.38 / 设计 §7.2：自身 Offer 必须跳过
// Node 的过滤点在传输层（udp.js _onMessage）：源 IP ∈ 本 socket 地址集
// 且源端口 == 本 socket 端口 → 丢弃（自身组播回环）；另一 socket 的回环帧不过滤，
// 「双角色同栈共享发现缓存」的设计保持不变。
// ============================================================
test('5.38 自身端口的组播回环帧在传输层被丢弃（§7.2 自身 Offer 跳过）', () => {
  const t = new UdpTransport({ port: 45500, bindHost: '127.0.0.1', logger: BP_LOGGER });
  const got = [];
  t.on('frame', (f, meta) => got.push(meta));
  // 1×Offer Entry（6B）：SvcID=4096 InstID=1 MajorVer=1 MinorVer=0 TTL=4
  // 控制帧头 ID 必须全 0（§4.3 步骤 3/4），SvcID 在 Payload Entry 内
  const offer = encodeFrame({
    ctr: 1, typ: TYP.CON, code: CODE.SD_OFFER,
    svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0,
    payload: Buffer.from([0x10, 0x00, 0x01, 0x01, 0x00, 0x04]),
  });
  const mainSock = { address: () => ({ address: '127.0.0.1', port: 45500 }) };
  // ① 自身 main socket 发出的 Offer 回环（源端口 == main 端口）→ 丢弃，不建自身条目
  t._onMessage(mainSock, offer, { address: '127.0.0.1', port: 45500 }, 'main');
  assert.equal(got.length, 0);
  // ② 同机 client socket 临时端口的回环 → 放行（双 socket 共享发现缓存不变）
  t._onMessage(mainSock, offer, { address: '127.0.0.1', port: 60123 }, 'client');
  assert.equal(got.length, 1);
  // ③ 同端口但非本机地址（真实远端节点）→ 放行
  t._onMessage(mainSock, offer, { address: '10.1.2.3', port: 45500 }, 'main');
  assert.equal(got.length, 2);
});

