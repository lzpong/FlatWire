// ============================================================
// frame.test.js —— 测试基准 §1.1/1.3/1.4/1.30 帧编码 + §2.1~2.4/2.9~2.21/2.29 帧解析
// ============================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TYP, CODE, encodeFrame, parseHeader, parseDatagram, TcpStreamParser, calcPlb, makeRst } from '../src/frame/frame.js';
import { RST_CODE } from '../src/errors.js';
import { StrmManager } from '../src/strm.js';
import { isMulticastLike } from '../src/transport/udp.js';

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

// ---- §4.3 方案 A：TYP=RST 豁免步骤 3/4 的 ID 校验 ----
test('§4.3 TYP=RST 携带任意/越界 ID 仍解析成功', () => {
  // CTR=1、TYP=RST、Code=0x24：SvcID/IfID/InstID 非 0、StrmID=0xFE（数据帧回显值）
  const buf = Buffer.from([0x80, (TYP.RST << 6) | 0x24, 0x12, 0x34, 0x56, 0x78, 0xab, 0xfe]);
  const r = parseDatagram(buf, UDP_OPT);
  assert.equal(r.ok, true);
  assert.equal(r.frame.svc_id, 0x1234);
  assert.equal(r.frame.if_id, 0x5678);
  assert.equal(r.frame.inst_id, 0xab);
  assert.equal(r.frame.strm_id, 0xfe);
  // 仅豁免 ID：形态校验仍生效（RST 带 Payload，PLB=1 → RST(0x00)）
  const bad = Buffer.from([0x81, (TYP.RST << 6) | 0x24, 0x12, 0x34, 0x56, 0x78, 0xab, 0xfe, 0x00]);
  assert.equal(parseDatagram(bad, UDP_OPT).rst.code, 0x00);
});

// ---- §4.3 方案 A 扩展：数据帧 RST（CTR=0）同样豁免步骤 3/4 ----
test('§4.3 数据帧 RST（CTR=0）携带非法 ID 仍解析成功', () => {
  // CTR=0、TYP=RST、Code=0x24：SvcID=0/IfID=0（数据帧非法）、InstID=0、
  // StrmID=0xFF（保留值）——回显数据帧触发帧时可能出现，必须解析成功
  const buf = Buffer.from([0x00, (TYP.RST << 6) | 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
  const r = parseDatagram(buf, UDP_OPT);
  assert.equal(r.ok, true);
  assert.equal(r.frame.ctr, 0);
  assert.equal(r.frame.svc_id, 0);
  assert.equal(r.frame.if_id, 0);
  assert.equal(r.frame.inst_id, 0);
  assert.equal(r.frame.strm_id, 0xff);
  // 步骤 2 约束仍生效：RST Code=0x01 非法 → RST(0x00)
  const badCode = Buffer.from([0x00, (TYP.RST << 6) | 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
  assert.equal(parseDatagram(badCode, UDP_OPT).rst.code, 0x00);
  // 步骤 2 约束仍生效：RST PLB>0 → RST(0x00)
  const badPlb = Buffer.from([0x01, (TYP.RST << 6) | 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00]);
  assert.equal(parseDatagram(badPlb, UDP_OPT).rst.code, 0x00);
});

// ---- §4.3/§5.4：数据帧 ACK 不豁免步骤 3/4（严格口径） ----
test('§4.3 数据帧 ACK 回显非法 ID → RST(0x00)；合法 ACK 正常解析', () => {
  // SvcID=0 / IfID=0 / StrmID=0xFF：数据帧 ID 越界，ACK 不豁免 → RST(0x00)
  const bad = Buffer.from([0x00, TYP.ACK << 6, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff]);
  assert.equal(parseDatagram(bad, UDP_OPT).rst.code, 0x00);
  // 仅 StrmID 越界（其余 ID 合法）：步骤 4 单独命中 → RST(0x00)
  const badStrm = Buffer.from([0x00, TYP.ACK << 6, 0x00, 0x01, 0x00, 0x02, 0x03, 0xff]);
  assert.equal(parseDatagram(badStrm, UDP_OPT).rst.code, 0x00);
  // 合法数据帧 ACK：SvcID≠0、IfID≠0、InstID≠0、StrmID∈0x01~0xFE
  const ok = Buffer.from([0x00, TYP.ACK << 6, 0x00, 0x01, 0x00, 0x02, 0x03, 0xfe]);
  const r = parseDatagram(ok, UDP_OPT);
  assert.equal(r.ok, true);
  assert.equal(r.frame.typ, TYP.ACK);
  assert.equal(r.frame.strm_id, 0xfe);
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

// ---- §3.6/§6.3 REN 清理：上层传入 "ip:" 前缀也必须命中数据池与控制池 ----
test('§3.6/§6.3 REN 按来源 IP 前缀重置 StrmID 池', () => {
  const m = new StrmManager();
  assert.equal(m.allocClientStream('10.0.0.1:5400', 1, 1), 0x01);
  assert.equal(m.allocControlStrm('10.0.0.1:5400'), 0x01);
  assert.equal(m.allocClientStream('10.0.0.10:5400', 1, 1), 0x01); // 相似前缀的另一节点

  m.resetPeer('10.0.0.1:'); // stack 收到 REN 时传入的正是 "ip:" 前缀

  assert.equal(m.isControlStrmActive('10.0.0.1:5400', 0x01), false);
  assert.equal(m.allocClientStream('10.0.0.1:5400', 1, 1), 0x01); // 重置后从池首分配
  // 相似前缀节点不受影响：0x01 仍活跃 → 分配 0x02
  assert.equal(m.allocClientStream('10.0.0.10:5400', 1, 1), 0x02);
});

// ---- §4.4 组播启发式：只覆盖 Offer/Find/REN，数据帧不得被误判 ----
test('§4.4 UDP 组播启发式不误判数据帧与 REN', () => {
  assert.equal(isMulticastLike(cf({ code: 0x01 })), true); // Offer
  assert.equal(isMulticastLike(cf({ code: 0x02 })), true); // Find
  assert.equal(isMulticastLike(cf({ ren: 1, code: 0x00 })), true); // REN
  assert.equal(isMulticastLike(cf({ code: 0x00 })), false); // Ping（单播）
  assert.equal(isMulticastLike(cf({ code: 0x03 })), false); // Subscribe
  assert.equal(isMulticastLike(cf({ code: 0x04 })), false); // GetIDL
  assert.equal(isMulticastLike(f({ typ: TYP.CON, code: 0x01 })), false); // 数据 Request
  assert.equal(isMulticastLike(f({ typ: TYP.CON, code: 0x02 })), false); // 数据 FF
});

// ---- §3.2 Length 64 位语义：PLB=7 声明长度不得被 32 位截断 ----
test('§3.2 Length 64 位语义（PLB=7）', () => {
  // 手工构造数据帧头（PLB=7）：8B 帧头 + 7B Length
  const hdr7 = (len) => {
    const b = Buffer.alloc(15);
    b[0] = 0x07; // CTR=0 REN=0 VER=0 MSK=0 PLB=7
    b[1] = (TYP.NON << 6) | CODE.REQUEST;
    b[2] = 0x10; b[3] = 0x00; // SvcID=0x1000
    b[4] = 0x00; b[5] = 0x01; // IfID=1
    b[6] = 0x01; b[7] = 0x01; // InstID=1 StrmID=1
    let v = BigInt(len);
    for (let i = 6; i >= 0; i--) { b[8 + i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  };

  // 2^40（远超 32 位，但在 Number 精确整数范围内）→ 原样保留
  const h1 = parseHeader(hdr7(2n ** 40n), 0, { ver: 0, isUdp: false });
  assert.equal(h1.state, 'ok');
  assert.equal(h1.payloadLen, 2 ** 40);
  assert.equal(h1.expectedTotal, 15 + 2 ** 40);

  // 2^56−1（协议上限）超出 JS 精确整数范围 → 按实现承载上限拒绝，不截断
  const h2 = parseHeader(hdr7(2n ** 56n - 1n), 0, { ver: 0, isUdp: false });
  assert.equal(h2.state, 'invalid');
  assert.equal(h2.rst.code, RST_CODE.PROTOCOL_VIOLATION); // TCP 语义

  const h3 = parseHeader(hdr7(2n ** 56n - 1n), 0, { ver: 0, isUdp: true, maxPayloadLen: 1400 });
  assert.equal(h3.state, 'invalid');
  assert.equal(h3.rst.code, RST_CODE.PAYLOAD_TOO_LARGE); // UDP 帧级超限 0x23
});
