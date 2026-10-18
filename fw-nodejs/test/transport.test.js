// ============================================================
// transport.test.js —— 测试基准 §2.5/2.22~2.28 TCP 半帧两阶段 + §3.9 TCP 无 CON/ACK
// 使用真实 socket（net.connect ↔ TcpTransport listen）与短超时加速。
// ============================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { TcpTransport } from '../src/transport/tcp.js';
import { TYP, CODE, encodeFrame, parseDatagram } from '../src/frame/frame.js';
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
