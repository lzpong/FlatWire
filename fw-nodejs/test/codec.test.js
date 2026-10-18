// ============================================================
// codec.test.js —— 测试基准 §1 帧与编解码（1.1~1.35）
// ============================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc16, crc16SelfCheck } from '../src/codec/crc.js';
import { encodeField, decodeField, decodeStructFields, applyMask } from '../src/codec/types.js';
import { Schema } from '../src/codec/schema.js';
import {
  InvalidBoolEncoding, InvalidSignedLength, InvalidUnsignedLength, SizeMismatch,
  UnexpectedNull, UnknownFieldType, UnsupportedFloatType, MaxLenExceeded, FixedLenMismatch,
} from '../src/errors.js';

// ---- 1.31 CRC 标准自检值 ----
test('1.31 CRC-16/CCITT-FALSE 自检值 0x29B1', () => {
  assert.equal(crc16(Buffer.from('123456789', 'ascii')), 0x29B1);
  assert.equal(crc16SelfCheck(), true);
});

test('1.29 CRC+MSK 顺序：先 CRC 后 XOR，解码相反', () => {
  // 构造：payload + CRC(2B 大端) → 整体 XOR；两次 XOR 还原
  const payload = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  const crc = Buffer.alloc(2);
  crc.writeUInt16BE(crc16(payload), 0);
  const key = Buffer.from([0xAA, 0xBB, 0xCC, 0xDD]);
  const masked = applyMask(Buffer.concat([payload, crc]), key);
  const restored = applyMask(masked, key); // 二次 XOR 还原
  assert.deepEqual([...restored], [...Buffer.concat([payload, crc])]);
  // 大端序验证
  assert.equal(crc[0], crc16(payload) >> 8);
});

// ---- 1.7/1.8 signed/unsigned 恒定宽度 ----
test('1.7 Signed 1B 边界与 8B 恒定宽度', () => {
  const f = { type: 'signed', size: 1 };
  assert.deepEqual([...encodeField(f, -128)], [0x21, 0x80]);
  assert.deepEqual([...encodeField(f, 0)], [0x21, 0x00]);
  assert.deepEqual([...encodeField(f, 127)], [0x21, 0x7f]);
  const f8 = { type: 'signed', size: 8 };
  const enc = encodeField(f8, 10); // 值 10 占 8 字节（§1.7 恒定宽度）
  assert.equal(enc.length, 9);
  assert.equal(decodeField(enc, 0, f8).value, 10);
});

test('1.8 Unsigned 1B 边界与 8B 恒定宽度', () => {
  const f = { type: 'unsigned', size: 1 };
  assert.deepEqual([...encodeField(f, 0)], [0x31, 0x00]);
  assert.deepEqual([...encodeField(f, 255)], [0x31, 0xff]);
  const f8 = { type: 'unsigned', size: 8 };
  const enc = encodeField(f8, 10);
  assert.equal(enc.length, 9); // byte_len 恒等 size（§1.8）
  assert.equal(decodeField(enc, 0, f8).value, 10);
});

// ---- 1.9/1.10 low4=0 非法 ----
test('1.9 Signed low4=0 非法 → InvalidSignedLength', () => {
  assert.throws(() => decodeField(Buffer.from([0x20, 0x00]), 0, { type: 'signed', size: 8 }), InvalidSignedLength);
});
test('1.10 Unsigned low4=0 非法 → InvalidUnsignedLength', () => {
  assert.throws(() => decodeField(Buffer.from([0x30, 0x00]), 0, { type: 'unsigned', size: 8 }), InvalidUnsignedLength);
});

// ---- 1.32 SizeMismatch ----
test('1.32 线上宽度 ≠ IDL size → SizeMismatch', () => {
  // 8B 字段收到 byte_len=1
  assert.throws(() => decodeField(Buffer.from([0x31, 0x0a]), 0, { type: 'unsigned', size: 8 }), SizeMismatch);
  assert.throws(() => decodeField(Buffer.from([0x21, 0x0a]), 0, { type: 'signed', size: 2 }), SizeMismatch);
});

// ---- 1.6 Bool 严格解码 ----
test('1.6 bool 严格解码：合法值与非法字段头', () => {
  assert.equal(decodeField(Buffer.from([0x11]), 0, { type: 'bool' }).value, true);
  assert.equal(decodeField(Buffer.from([0x10]), 0, { type: 'bool' }).value, false);
  assert.throws(() => decodeField(Buffer.from([0x12]), 0, { type: 'bool' }), InvalidBoolEncoding);
});

// ---- 1.5/1.33/1.34 null 语义 ----
test('1.5/1.33 非 optional 遇 null → UnexpectedNull', () => {
  assert.throws(() => encodeField({ type: 'null' }, null), UnexpectedNull);
  // 解码侧：非 optional 字段收到 null 编码（0x00）→ UnexpectedNull
  const f = { type: 'signed', size: 2, optional: false };
  assert.throws(() => decodeField(Buffer.from([0x00]), 0, f), UnexpectedNull);
});

test('1.34 optional 往返：空 → null；有值正常', () => {
  const f = { type: 'signed', size: 2, optional: true };
  assert.deepEqual([...encodeField(f, null)], [0x00]); // 空：`00`
  assert.equal(decodeField(Buffer.from([0x00]), 0, f).value, null);
  const enc = encodeField(f, 42);
  assert.equal(decodeField(enc, 0, f).value, 42);
});

// ---- 1.11/1.12 Float ----
test('1.11 Float32/64 往返（含 NaN/Inf）', () => {
  const f32 = { type: 'float', width: 32 };
  assert.equal(decodeField(encodeField(f32, 3.14159), 0, f32).value, Math.fround(3.14159));
  const f64 = { type: 'float', width: 64 };
  assert.equal(decodeField(encodeField(f64, 3.14159), 0, f64).value, 3.14159);
  assert.ok(Number.isNaN(decodeField(encodeField(f64, NaN), 0, f64).value));
  assert.equal(decodeField(encodeField(f64, Infinity), 0, f64).value, Infinity);
});
test('1.12 Float 子类型非法 → UnsupportedFloatType', () => {
  assert.throws(() => encodeField({ type: 'float', width: 80 }, 1.0), UnsupportedFloatType);
  assert.throws(() => decodeField(Buffer.from([0x40, 0, 0, 0, 0]), 0, { type: 'float', width: 80 }), UnsupportedFloatType);
  // low4=0（80bit）解码非法
  assert.throws(() => decodeField(Buffer.from([0x40, 0, 0, 0, 0]), 0, { type: 'float', width: 32 }), UnsupportedFloatType);
});

// ---- 1.13 Timestamp 44bit ----
test('1.13 Timestamp 边界 0 / 2^44-1', () => {
  const f = { type: 'timestamp' };
  assert.equal(decodeField(encodeField(f, 0), 0, f).value, 0);
  const max = 2 ** 44 - 1;
  assert.equal(decodeField(encodeField(f, max), 0, f).value, max);
  // 高 4bit + 低 40bit：字段头 0x50 + 5B 大端
  const enc = encodeField(f, max);
  assert.equal(enc[0], 0x5f);
  assert.equal(enc.length, 6);
});

// ---- 1.14/1.15 String/Bytes ----
test('1.14 String UTF-8 + 长度前缀', () => {
  const f = { type: 'string' };
  const enc = encodeField(f, 'hello');
  assert.equal(decodeField(enc, 0, f).value, 'hello');
  assert.equal(decodeField(encodeField(f, ''), 0, f).value, '');
  assert.equal(decodeField(encodeField(f, '中文'), 0, f).value, '中文');
  assert.equal(encodeField(f, '中文').length, 1 + 1 + Buffer.byteLength('中文', 'utf8'));
});
test('1.15 Bytes 长度前缀 + 原始数据', () => {
  const f = { type: 'bytes' };
  const enc = encodeField(f, Buffer.from([0x00, 0xff]));
  assert.equal(decodeField(enc, 0, f).value.toString('hex'), '00ff');
  assert.equal(decodeField(encodeField(f, Buffer.alloc(0)), 0, f).value.length, 0);
});

// ---- 1.16/1.17 Array 长度 ----
test('1.16/1.17 Array 内联/扩展长度', () => {
  const f = { type: 'array', element: { type: 'unsigned', size: 1 } };
  for (let n = 0; n <= 14; n++) {
    const enc = encodeField(f, Array.from({ length: n }, (_, i) => i));
    assert.equal(enc[0], 0x80 | n); // 0x8X 直接表示元素个数
    assert.equal(decodeField(enc, 0, f).value.length, n);
  }
  const big = encodeField(f, Array.from({ length: 15 }, () => 1));
  assert.equal(big[0], 0x8f); // 0x8F + 2B 长度（大端）
  assert.equal(big.readUInt16BE(1), 15);
  const big65535 = encodeField(f, Array.from({ length: 65535 }, () => 1));
  assert.equal(big65535[0], 0x8f);
  assert.equal(big65535.readUInt16BE(1), 65535);
});

// ---- 1.18~1.21/1.35 定长 ----
test('1.18 定长 string：长度字段=4 内容占 4B', () => {
  const f = { type: 'string', fixed_len: 4 };
  const enc = encodeField(f, 'abcd');
  assert.equal(enc.length, 1 + 1 + 4);
  assert.equal(enc[1], 4); // 长度字段=4
  assert.equal(decodeField(enc, 0, f).value, 'abcd');
});
test('1.19/1.35 定长 string 长度不符 → 编码错误', () => {
  assert.throws(() => encodeField({ type: 'string', fixed_len: 4 }, 'abc'), FixedLenMismatch);
  assert.throws(() => encodeField({ type: 'string', fixed_len: 4 }, 'abcde'), FixedLenMismatch);
});
test('1.20 定长 array：空位填充不压缩', () => {
  // fixed_len=20：传入 20 个元素（12 个业务有效值，其余默认值 0，§1.20）
  const f = { type: 'array', element: { type: 'unsigned', size: 1 }, fixed_len: 20 };
  const vals = Array.from({ length: 20 }, (_, i) => (i < 12 ? i + 1 : 0));
  const enc = encodeField(f, vals);
  assert.equal(enc[0], 0x8f);       // 扩展长度（20 > 14）
  assert.equal(enc.readUInt16BE(1), 20); // 长度字段=20
  assert.equal(enc.length, 3 + 20 * 2); // 占位 20 个元素（每元素 2B：字段头+1B 体），不压缩
  const dec = decodeField(enc, 0, f).value;
  assert.equal(dec.length, 20);
  for (let i = 12; i < 20; i++) assert.equal(dec[i], 0); // 空位为默认 0
});
test('1.21 定长 array 长度不符 → 编码错误', () => {
  const f = { type: 'array', element: { type: 'unsigned', size: 1 }, fixed_len: 20 };
  assert.throws(() => encodeField(f, Array.from({ length: 19 }, () => 0)), FixedLenMismatch);
});

// ---- 1.22 max_len 超限 ----
test('1.22 max_len 超限 → 编码错误（IDL 级归 0x20）', () => {
  assert.throws(() => encodeField({ type: 'string', max_len: 64 }, 'x'.repeat(65)), MaxLenExceeded);
});

// ---- 1.27 UnknownFieldType ----
test('1.27 type_id 0x9~0xF → UnknownFieldType', () => {
  for (const hi of [0x9, 0xa, 0xc, 0xf]) {
    assert.throws(() => decodeField(Buffer.from([(hi << 4) | 1]), 0, { type: 'string' }), UnknownFieldType);
  }
});

// ---- 1.28 Masking XOR ----
test('1.28 Masking XOR：4B 对齐/不对齐均正确', () => {
  const key = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  for (const len of [4, 5, 7, 8]) { // 对齐 4 / 不对齐
    const data = Buffer.from(Array.from({ length: len }, (_, i) => i));
    const masked = applyMask(data, key);
    assert.deepEqual([...applyMask(masked, key)], [...data]); // 两次 XOR 还原
  }
});

// ---- 1.30 空 payload ----
test('1.30 PLB=0 空 payload（frame 层验证放 frame.test）', () => {
  // 该用例在 frame 层覆盖（encodeFrame 空 payload → 8B 帧）
  assert.ok(true);
});

// ---- 1.23~1.26 嵌套结构（经 Schema 全链路） ----
const NESTED_IDL = {
  service: {
    svc_id: 100, major_ver: 1, name: 'Nested',
    interfaces: [{
      name: 'report', if_id: 1, type: 'rpc',
      input: ['Report'], output: 'Ack',
    }],
  },
  type_def: {
    structs: {
      Report: [
        { name: 'id', type: 'unsigned', size: 2 },
        { name: 'name', type: 'string', max_len: 32 },
        { name: 'inner', type: 'Inner' },              // 结构体含结构体（1.23）
        { name: 'tags', type: 'array', element_type: 'Str' }, // 结构体含数组（1.24）
        { name: 'points', type: 'PointArr' },           // 数组元素为结构体（1.25）
        { name: 'matrix', type: 'array', element_type: 'RowArr' }, // 多维数组（1.26）
      ],
      Inner: [{ name: 'x', type: 'signed', size: 4 }, { name: 'ok', type: 'bool' }],
      Point: [{ name: 'px', type: 'float', width: 64 }, { name: 'py', type: 'float', width: 64 }],
      Str: [{ name: 's', type: 'string', max_len: 8 }],
      Row: [{ name: 'v', type: 'unsigned', size: 1 }],
    },
    arrays: {
      PointArr: { type: 'array', max_len: 10, element_type: 'Point' },
      RowArr: { type: 'array', max_len: 3, element_type: 'Row' },
    },
    enums: {},
  },
};

test('1.23~1.26 嵌套结构体/数组/多维数组往返', () => {
  const schema = new Schema(NESTED_IDL);
  const iface = schema.getInterface(1);
  const value = {
    id: 7,
    name: '测试',
    inner: { x: -5, ok: true },
    tags: [{ s: 'a' }, { s: '' }],
    points: [{ px: 1.5, py: -2.5 }, { px: 0, py: 0 }],
    matrix: [[{ v: 1 }, { v: 2 }], [{ v: 3 }, { v: 4 }], [{ v: 5 }, { v: 6 }]],
  };
  const buf = schema.encodePayload(iface, 'input', value);
  const dec = schema.decodePayload(iface, 'input', buf);
  assert.equal(dec.id, 7);
  assert.equal(dec.name, '测试');
  assert.deepEqual({ ...dec.inner }, { x: -5, ok: true });
  assert.equal(dec.tags.length, 2);
  assert.ok(Math.abs(dec.points[0].px - 1.5) < 1e-9 && Math.abs(dec.points[0].py - -2.5) < 1e-9);
  assert.equal(dec.matrix[2][1].v, 6);
});

// ---- 解码容忍末尾新增字段（§9.4） ----
test('解码容忍末尾新增字段', () => {
  const f1 = { type: 'unsigned', size: 1, name: 'v' };
  const enc = encodeField(f1, 5);
  const extended = Buffer.concat([enc, Buffer.from([0x33, 0x99])]); // 附加未知字段字节
  const { value } = decodeStructFields(extended, 0, [f1]);
  assert.equal(value.v, 5); // 前置字段正常解码，末尾多余字节忽略
});
