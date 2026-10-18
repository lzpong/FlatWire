// ============================================================
// frame.test.js —— 测试基准 §1.1/1.3/1.4/1.30 帧编码 + §2.1~2.4/2.9~2.21/2.29 帧解析
// ============================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TYP, CODE, encodeFrame, parseHeader, parseDatagram, TcpStreamParser, calcPlb, makeRst } from '../src/frame/frame.js';
import { RST_CODE } from '../src/errors.js';

const UDP_OPT = { ver: 0, maxPayloadLen: 1400, isUdp: true };

/** 快捷构造帧并编码 */
function f(partial) {
  return encodeFrame({
    ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
    svc_id: 0x1000, if_id: 0x0001, inst_id: 1, strm_id: 1,
    payload: Buffer.alloc(0), ...partial,
  });
}
/** 控制帧快捷 */
function cf(partial) {
  return encodeFrame({
    ctr: 1, typ: TYP.NON, code: CODE.SD_OFFER,
    svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0,
    payload: Buffer.alloc(0), ...partial,
  });
}

// ---- 1.1 帧头往返 ----
test('1.1 帧头全字段往返', () => {
  const cases = [
    { ctr: 0, ren: 0, ver: 0, msk: 0, typ: TYP.CON, code: 0x01, svc_id: 0xffff, if_id: 0x7fff, inst_id: 0xff, strm_id: 0xfe },
    { ctr: 1, ren: 0, ver: 3, msk: 0, typ: TYP.NON, code: 0x03, svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0x7f },
    { ctr: 1, ren: 1, ver: 0, msk: 0, typ: TYP.NON, code: 0x00, svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0 },
  ];
  for (const c of cases) {
    const buf = encodeFrame({ ...c, payload: Buffer.from([1, 2, 3]) });
    const h = parseHeader(buf, 0, { ver: c.ver, isUdp: true });
    assert.equal(h.state, 'ok');
    assert.equal(h.ctr, c.ctr);
    assert.equal(h.ren, c.ren);
    assert.equal((buf[0] >> 4) & 0x03, c.ver);
    assert.equal(h.typ, c.typ);
    assert.equal(h.code, c.code);
    assert.equal(h.svcId, c.svc_id);
    assert.equal(h.ifId, c.if_id);
    assert.equal(h.instId, c.inst_id);
    assert.equal(h.strmId, c.strm_id);
    const r = parseDatagram(buf, { ver: c.ver, isUdp: true, maxPayloadLen: 1400 });
    assert.ok(r.ok);
    assert.equal(r.frame.typ, c.typ);
  }
});

// ---- 1.3/1.4 PLB 边界 ----
test('1.3/1.4 PLB 边界与 Payload Length 编码', () => {
  assert.equal(calcPlb(0), 0);
  assert.equal(calcPlb(1), 1);
  assert.equal(calcPlb(255), 1);
  assert.equal(calcPlb(65535), 2);
  assert.equal(calcPlb(2 ** 48 - 1), 6);
  assert.equal(calcPlb(2 ** 53 - 1), 7); // Number 可精确表示范围内的 PLB=7 边界
  // PLB=0：无 Length 字段，帧大小 8B（1.30）
  const empty = f({ payload: Buffer.alloc(0) });
  assert.equal(empty.length, 8);
  // PLB=7：最大 Length
  const big = f({ payload: Buffer.alloc(100) });
  assert.equal(big[0] & 0x07, 1);
  // Length 字段大端逐字节
  const p65535 = f({ payload: Buffer.alloc(65535) });
  assert.equal(p65535[0] & 0x07, 2);
  assert.equal(p65535.readUInt16BE(8), 65535);
});

// ---- 1.2 VER 不等 ----
test('1.2 VER 不等：单播 RST(0x22) / 组播静默', () => {
  const buf = f({ ver: 1 });
  const r1 = parseDatagram(buf, UDP_OPT); // 单播（非组播操作码）
  assert.equal(r1.ok, false);
  assert.equal(r1.rst.code, RST_CODE.UNSUPPORTED_VERSION);
  // 组播启发式：Offer 操作码 → 静默
  const m = cf({ ver: 1 });
  const r2 = parseDatagram(m, { ...UDP_OPT, multicastLike: true });
  assert.equal(r2.ok, false);
  assert.equal(r2.rst, undefined);
});

// ---- 2.9~2.11 REN 一致性 ----
test('2.9 REN=1 且 CTR=0 → RST(0x00)', () => {
  const buf = Buffer.from([(0 << 7) | (1 << 6), (TYP.NON << 6) | 0x00, 0, 0, 0, 0, 0, 0]);
  const r = parseDatagram(buf, UDP_OPT);
  assert.equal(r.rst.code, 0x00);
});
test('2.10 REN=1 且 TYP≠NON → RST(0x00)', () => {
  const buf = Buffer.from([(1 << 7) | (1 << 6), (TYP.CON << 6) | 0x00, 0, 0, 0, 0, 0, 0]);
  assert.equal(parseDatagram(buf, UDP_OPT).rst.code, 0x00);
});
test('2.11 REN=1 且 Code≠0x00 → RST(0x00)', () => {
  const buf = Buffer.from([(1 << 7) | (1 << 6), (TYP.NON << 6) | 0x01, 0, 0, 0, 0, 0, 0]);
  assert.equal(parseDatagram(buf, UDP_OPT).rst.code, 0x00);
});

// ---- 2.12 ACK Code 校验 ----
test('2.12 ACK Code 非法 → RST(0x00)', () => {
  // 数据帧 ACK Code≠0x00
  const d = Buffer.from([0 << 7, (TYP.ACK << 6) | 0x01, 0, 0, 0, 0, 0, 0]);
  assert.equal(parseDatagram(d, UDP_OPT).rst.code, 0x00);
  // 控制帧 ACK Code∉{0x00,0x10}
  const c = Buffer.from([1 << 7, (TYP.ACK << 6) | 0x11, 0, 0, 0, 0, 0, 0]);
  assert.equal(parseDatagram(c, UDP_OPT).rst.code, 0x00);
  // 控制帧 ACK Code=0x10 合法
  const ok = Buffer.from([1 << 7, (TYP.ACK << 6) | 0x10, 0, 0, 0, 0, 0, 0x05]);
  assert.equal(parseDatagram(ok, UDP_OPT).ok, true);
});

// ---- 2.13/2.14 SvcID/IfID ----
test('2.13 控制帧 SvcID/IfID 非 0 → RST(0x00)', () => {
  const buf = cf({ svc_id: 1, if_id: 1 });
  assert.equal(parseDatagram(buf, UDP_OPT).rst.code, 0x00);
});
test('2.14/2.19 数据帧 SvcID=0 / IfID=0 → RST(0x00)', () => {
  assert.equal(parseDatagram(f({ svc_id: 0 }), UDP_OPT).rst.code, 0x00);
  assert.equal(parseDatagram(f({ if_id: 0 }), UDP_OPT).rst.code, 0x00);
});

// ---- 2.15 InstID=0 ----
test('2.15 数据帧 InstID=0 → RST(0x00)', () => {
  assert.equal(parseDatagram(f({ inst_id: 0 }), UDP_OPT).rst.code, 0x00);
});

// ---- 2.16 ACK/RST PLB>0 ----
test('2.16 ACK/RST 带 Payload → RST(0x00)', () => {
  // ACK PLB>0：byte0 的 PLB 位非 0（ACK 无 Length 字段语义，仍可校验）
  const a = Buffer.from([0x01, (TYP.ACK << 6), 0x10, 0, 0, 0, 0, 0x01, 0x00]);
  assert.equal(parseDatagram(a, UDP_OPT).rst.code, 0x00);
  // RST PLB>0
  const r = Buffer.from([0x01, (TYP.RST << 6) | 0x24, 0x10, 0, 0, 0, 0, 0x01, 0x00]);
  assert.equal(parseDatagram(r, UDP_OPT).rst.code, 0x00);
});

// ---- 2.17 控制帧 StrmID 校验 ----
test('2.17 控制帧 StrmID 范围 + 语义校验', () => {
  // REN 帧 StrmID≠0 → RST(0x00)
  const ren = Buffer.from([(1 << 7) | (1 << 6), 0x00, 0, 0, 0, 0, 0, 0x01]);
  assert.equal(parseDatagram(ren, UDP_OPT).rst.code, 0x00);
  // Subscribe StrmID=0x00 → RST(0x00)（单播回 RST）
  assert.equal(parseDatagram(cf({ code: CODE.SD_SUBSCRIBE, strm_id: 0 }), UDP_OPT).rst.code, 0x00);
  // Subscribe StrmID=0x01~0x7F 合法
  assert.equal(parseDatagram(cf({ code: CODE.SD_SUBSCRIBE, strm_id: 0x7f }), UDP_OPT).ok, true);
  // 连接级帧（Offer）StrmID≠0 → 单播 RST(0x00)
  assert.equal(parseDatagram(cf({ strm_id: 5 }), UDP_OPT).rst.code, 0x00);
  // 组播场景（Offer 操作码）→ 静默丢弃
  assert.equal(parseDatagram(cf({ strm_id: 5 }), { ...UDP_OPT, multicastLike: true }).rst, undefined);
  // 控制帧 StrmID>0x7F → RST(0x00)
  assert.equal(parseDatagram(cf({ code: CODE.SD_SUBSCRIBE, strm_id: 0x80 }), UDP_OPT).rst.code, 0x00);
});

// ---- 2.18 数据帧 StrmID 越界 ----
test('2.18 数据帧 StrmID=0x00 / 0xFF → RST(0x00)', () => {
  assert.equal(parseDatagram(f({ strm_id: 0 }), UDP_OPT).rst.code, 0x00);
  assert.equal(parseDatagram(f({ strm_id: 0xff }), UDP_OPT).rst.code, 0x00);
  // 0x01~0xFE 合法
  assert.equal(parseDatagram(f({ strm_id: 0xfe }), UDP_OPT).ok, true);
});

// ---- 2.20 RST Code 非法 ----
test('2.20 RST Code=0x01（非错误码）→ RST(0x00)', () => {
  const buf = Buffer.from([0, (TYP.RST << 6) | 0x01, 0, 0, 0, 0, 0, 0]);
  assert.equal(parseDatagram(buf, UDP_OPT).rst.code, 0x00);
  // 合法：CTR=1 回显控制帧场景 RST(0x24)（控制帧全 0 标识合法）
  const ok = Buffer.from([0x80, (TYP.RST << 6) | 0x24, 0, 0, 0, 0, 0, 0]);
  assert.equal(parseDatagram(ok, UDP_OPT).ok, true);
});

// ---- 2.29 控制帧 MSK=1 ----
test('2.29 控制帧 MSK=1 → RST(0x00)（§10 硬性约定）', () => {
  const buf = Buffer.from([(1 << 7) | (1 << 3), (TYP.NON << 6) | 0x01, 0, 0, 0, 0, 0, 0]);
  assert.equal(parseDatagram(buf, UDP_OPT).rst.code, 0x00);
});

// ---- 2.6/2.7/2.8 UDP 长度校验 ----
test('2.6/2.7 UDP 长度不符 / 过短 → 丢弃', () => {
  assert.equal(parseDatagram(Buffer.from([1, 2, 3]), UDP_OPT).ok, false); // <8B
  const frame = f({ payload: Buffer.from([1, 2, 3]) });
  const truncated = frame.subarray(0, frame.length - 1);
  assert.equal(parseDatagram(truncated, UDP_OPT).ok, false); // 不足
  const extra = Buffer.concat([frame, Buffer.from([9])]);
  assert.equal(parseDatagram(extra, UDP_OPT).ok, false);     // 多余（不截断）
});
test('2.8 UDP Payload > max_payload_len → RST(0x23)', () => {
  const buf = f({ payload: Buffer.alloc(1401) });
  const r = parseDatagram(buf, UDP_OPT);
  assert.equal(r.ok, false);
  assert.equal(r.rst.code, RST_CODE.PAYLOAD_TOO_LARGE);
  // TCP 不做此校验
  const h = parseHeader(buf, 0, { ver: 0, isUdp: false });
  assert.equal(h.state, 'ok');
});

// ---- 2.1/2.2/2.3/2.4 TCP 粘包/分包/Length 跨包/Mask 跨包 ----
test('2.1 TCP 粘包：一次接收含 3 帧全部交付', () => {
  const frames = [
    f({ payload: Buffer.from([1]) }),
    f({ strm_id: 2, payload: Buffer.from([2, 2]) }),
    f({ strm_id: 3, payload: Buffer.alloc(50, 7) }),
  ];
  const parser = new TcpStreamParser({ ver: 0 });
  const got = [];
  parser.opts.onFrame = (fr) => got.push(fr);
  parser.feed(Buffer.concat(frames));
  assert.equal(got.length, 3);
  assert.equal(got[2].strm_id, 3);
  assert.equal(got[2].payload.length, 50);
});

test('2.2 TCP 分包：1 帧按 1 字节/次写入正确重组', () => {
  const frame = f({ payload: Buffer.from([0xde, 0xad, 0xbe, 0xef]) });
  const parser = new TcpStreamParser({ ver: 0 });
  const got = [];
  parser.opts.onFrame = (fr) => got.push(fr);
  for (const byte of frame) parser.feed(Buffer.from([byte]));
  assert.equal(got.length, 1);
  assert.equal(got[0].payload.toString('hex'), 'deadbeef');
});

test('2.3/2.4 Length 字段与 Masking Key 跨包', () => {
  // PLB=2（Length 跨包：两字节分两次到达）+ MSK=1（4B Key 跨包）
  const payload = Buffer.alloc(300, 0xAB); // 需 PLB=2
  const frame = encodeFrame({
    ctr: 0, typ: TYP.NON, code: CODE.REQUEST, msk: 1,
    svc_id: 1, if_id: 1, inst_id: 1, strm_id: 9, payload,
  });
  const parser = new TcpStreamParser({ ver: 0 });
  const got = [];
  parser.opts.onFrame = (fr) => got.push(fr);
  // 逐段切割：帧头前 9B / 1B（Length 第 2 字节）/ 2B（Key 前 2）/ 2B（Key 后 2）/ 其余
  const cuts = [9, 10, 12, 14];
  let prev = 0;
  for (const c of cuts) {
    parser.feed(frame.subarray(prev, c));
    prev = c;
  }
  parser.feed(frame.subarray(prev));
  assert.equal(got.length, 1);
  assert.deepEqual([...got[0].payload], [...payload]); // XOR 已还原
});

// ---- MSK 往返（UDP 数据帧） ----
test('MSK=1 数据帧 UDP 编解码往返（§10）', () => {
  const frame = {
    ctr: 0, typ: TYP.NON, code: CODE.REQUEST, msk: 1,
    svc_id: 1, if_id: 1, inst_id: 1, strm_id: 5,
    payload: Buffer.from([1, 2, 3, 4, 5, 6, 7]),
  };
  const buf = encodeFrame(frame);
  // 帧头后紧跟 PLB(1B) + Key(4B)
  assert.equal(buf[0] & 0x08, 0x08); // MSK 位
  assert.equal(buf[0] & 0x07, 1);    // PLB=1
  const r = parseDatagram(buf, UDP_OPT);
  assert.ok(r.ok);
  assert.equal(r.frame.msk, 1);
  assert.deepEqual([...r.frame.payload], [...frame.payload]);
});

// ---- makeRst 形态 ----
test('RST 帧形态：PLB=0 + 回显标识（§5.4）', () => {
  const rst = makeRst(RST_CODE.NOT_FOUND, { ctr: 0, svc_id: 2, if_id: 3, inst_id: 4, strm_id: 5 });
  assert.equal(rst.typ, TYP.RST);
  assert.equal(rst.payload.length, 0);
  assert.equal(rst.svc_id, 2);
  assert.equal(rst.strm_id, 5);
  const buf = encodeFrame(rst);
  assert.equal(buf.length, 8);
  const r = parseDatagram(buf, UDP_OPT);
  assert.ok(r.ok);
  assert.equal(r.frame.code, RST_CODE.NOT_FOUND);
});
