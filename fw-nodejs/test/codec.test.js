// ============================================================
// codec.test.js —— 测试基准 v5.0 §1 帧与编解码（裸字节编码）
//
// 覆盖：1.5 强制长度声明、1.6 bool 严格、1.7/1.8 恒定宽度、1.9 字节不足、
//      1.10 值域、1.11 float、1.12 f80 可选、1.13 timestamp、1.14/1.15 变长、
//      1.16 前缀宽度、1.17 array 变长、1.18~1.21 定长无前缀、1.22 超限、
//      1.23~1.26 嵌套、1.27~1.29 enum、1.30 掩码、1.31 CRC+MSK 顺序、
//      1.32 空 payload（frame 层覆盖）、1.33 CRC 自检、1.34/1.35 CRC 缺省/开启、
//      1.36 末尾新增字段忽略、1.38 大端
// ============================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { crc16, crc16SelfCheck } from '../src/codec/crc.js';
import { encodeField, decodeField, decodeStructFields, applyMask } from '../src/codec/types.js';
import { Schema } from '../src/codec/schema.js';
import { IdlStore } from '../src/idlstore/store.js';
import {
  InvalidBoolEncoding, UnsupportedFloatType, BufferUnderrun, MaxLenExceeded,
  FixedLenMismatch, ValueRangeExceeded, CrcMismatch, InvalidArgument,
} from '../src/errors.js';

// 构造最小 IDL（service.interfaces 省略，仅做类型定义校验）
const mkIdl = (typeDef) => ({
  service: { svc_id: 1, major_ver: 1, minor_ver: 0, interfaces: [] },
  type_def: typeDef,
});

// ============================================================
// 1.33 CRC 标准自检值
// ============================================================
test('1.33 CRC-16/CCITT-FALSE 自检值 0x29B1', () => {
  assert.equal(crc16(Buffer.from('123456789', 'ascii')), 0x29B1);
  assert.equal(crc16SelfCheck(), true);
});

// ---- 1.31 CRC + MSK 顺序：先 CRC 后整体 XOR，解码顺序相反 ----
test('1.31 CRC 附加（大端）后再 MSK XOR，解码先 XOR 后校验', () => {
  const body = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  const crc = Buffer.alloc(2);
  crc.writeUInt16BE(crc16(body), 0); // 2B 大端附加于字段序列末尾
  const framed = Buffer.concat([body, crc]);
  const key = Buffer.from([0xAA, 0xBB, 0xCC, 0xDD]);
  const masked = applyMask(framed, key);       // 整体 XOR（含 CRC）
  const restored = applyMask(masked, key);     // 接收端先 XOR 还原
  assert.deepEqual([...restored], [...framed]);
  // 剥离并校验 CRC
  assert.equal(restored.readUInt16BE(restored.length - 2), crc16(restored.subarray(0, restored.length - 2)));
  assert.equal(crc[0], crc16(body) >> 8); // 大端高字节在前
});

// ============================================================
// 1.7 / 1.8 恒定宽度（裸字节，无字段头）
// ============================================================
test('1.7 Signed 边界与恒定宽度（i8 1B / i64 8B 补码大端）', () => {
  const f8 = { type: 'i8' };
  assert.deepEqual([...encodeField(f8, -128)], [0x80]);
  assert.deepEqual([...encodeField(f8, 0)], [0x00]);
  assert.deepEqual([...encodeField(f8, 127)], [0x7f]);
  assert.equal(decodeField(Buffer.from([0x80]), 0, f8).value, -128);

  const f64 = { type: 'i64' };
  const enc = encodeField(f64, 10);
  assert.equal(enc.length, 8); // 值 10 仍占满 8B（恒定宽度，不压缩）
  assert.deepEqual([...enc], [0, 0, 0, 0, 0, 0, 0, 10]);
  assert.equal(decodeField(enc, 0, f64).value, 10);
  assert.deepEqual([...encodeField({ type: 'i16' }, -1)], [0xff, 0xff]);
});

test('1.8 Unsigned 边界与恒定宽度（u8 1B / u64 8B 大端）', () => {
  const f8 = { type: 'u8' };
  assert.deepEqual([...encodeField(f8, 0)], [0x00]);
  assert.deepEqual([...encodeField(f8, 255)], [0xff]);
  assert.equal(decodeField(Buffer.from([0xff]), 0, f8).value, 255);

  const f64 = { type: 'u64' };
  const enc = encodeField(f64, 10);
  assert.equal(enc.length, 8); // 值 10 仍占满 8B
  assert.deepEqual([...enc], [0, 0, 0, 0, 0, 0, 0, 10]);
  assert.equal(decodeField(enc, 0, f64).value, 10);
  // u64 上限：BigInt 输入/输出不丢精度
  const max = (1n << 64n) - 1n;
  const encMax = encodeField(f64, max);
  assert.deepEqual([...encMax], [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
  assert.equal(decodeField(encMax, 0, f64).value, max);
});

// ============================================================
// 1.9 字段字节不足 → 解码失败（帧层回 RST 0x20）
// ============================================================
test('1.9 字段字节不足 → BufferUnderrun（u32 仅 3B / 字符串体截断）', () => {
  assert.throws(() => decodeField(Buffer.from([0x00, 0x00, 0x01]), 0, { type: 'u32' }), BufferUnderrun);
  assert.throws(() => decodeField(Buffer.alloc(0), 0, { type: 'u16' }), BufferUnderrun);
  // 变长字符串：前缀声明 3B，实际仅 2B
  assert.throws(
    () => decodeField(Buffer.from([0x03, 0x61, 0x62]), 0, { type: 'string', max_len: 64 }),
    BufferUnderrun,
  );
});

// ============================================================
// 1.10 整型值域越界 → 编码报错
// ============================================================
test('1.10 整型值域校验：u8 300 / i8 128 / u8 -1', () => {
  assert.throws(() => encodeField({ type: 'u8' }, 300), ValueRangeExceeded);
  assert.throws(() => encodeField({ type: 'i8' }, 128), ValueRangeExceeded);
  assert.throws(() => encodeField({ type: 'u8' }, -1), ValueRangeExceeded);
  assert.throws(() => encodeField({ type: 'i16' }, 1.5), ValueRangeExceeded);
  assert.throws(() => encodeField({ type: 'u64' }, 1n << 64n), ValueRangeExceeded);
});

// ============================================================
// 1.6 bool 严格解码
// ============================================================
test('1.6 bool：0x00→false / 0x01→true / 0x02→InvalidBoolEncoding', () => {
  assert.equal(decodeField(Buffer.from([0x00]), 0, { type: 'bool' }).value, false);
  assert.equal(decodeField(Buffer.from([0x01]), 0, { type: 'bool' }).value, true);
  assert.throws(() => decodeField(Buffer.from([0x02]), 0, { type: 'bool' }), InvalidBoolEncoding);
  assert.throws(() => decodeField(Buffer.from([0xff]), 0, { type: 'bool' }), InvalidBoolEncoding);
  // 编码恒为 0x00/0x01
  assert.deepEqual([...encodeField({ type: 'bool' }, true)], [0x01]);
  assert.deepEqual([...encodeField({ type: 'bool' }, false)], [0x00]);
});

// ============================================================
// 1.11 Float32/64
// ============================================================
test('1.11 f32/f64 IEEE754 大端往返（含 NaN / ±Inf）', () => {
  const f32 = { type: 'f32' };
  assert.equal(decodeField(encodeField(f32, 3.14159), 0, f32).value, Math.fround(3.14159));
  const f64 = { type: 'f64' };
  assert.equal(decodeField(encodeField(f64, 3.14159), 0, f64).value, 3.14159);
  assert.ok(Number.isNaN(decodeField(encodeField(f64, NaN), 0, f64).value));
  assert.equal(decodeField(encodeField(f64, Infinity), 0, f64).value, Infinity);
  assert.equal(decodeField(encodeField(f64, -Infinity), 0, f64).value, -Infinity);
  assert.equal(encodeField(f32, 1).length, 4);
  assert.equal(encodeField(f64, 1).length, 8);
});

// ============================================================
// 1.12 f80 可选支持（本端不支持 → IDL 加载失败）
// ============================================================
test('1.12 f80 本端不支持 → IDL 加载失败 / 编码抛错', () => {
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 'x', type: 'f80' }] } })),
    UnsupportedFloatType,
  );
  assert.throws(() => encodeField({ type: 'f80' }, 1.0), UnsupportedFloatType);
});

// ============================================================
// 1.13 Timestamp 6B（48bit，2000 基准）
// ============================================================
test('1.13 timestamp 边界 0 / 2^48-1 → 6B 大端', () => {
  const f = { type: 'timestamp' };
  const enc0 = encodeField(f, 0);
  assert.equal(enc0.length, 6);
  assert.deepEqual([...enc0], [0, 0, 0, 0, 0, 0]);
  const max = 2 ** 48 - 1;
  const encMax = encodeField(f, max);
  assert.equal(encMax.length, 6);
  assert.deepEqual([...encMax], [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
  assert.equal(decodeField(encMax, 0, f).value, max);
  assert.equal(decodeField(encodeField(f, 1), 0, f).value, 1);
  assert.deepEqual([...encodeField(f, 1)], [0, 0, 0, 0, 0, 1]);
  assert.throws(() => encodeField(f, -1), ValueRangeExceeded);
});

// ============================================================
// 1.14 / 1.15 String / Bytes 变长（max_len 前缀）
// ============================================================
test('1.14 string max_len=64：1B 前缀（UTF-8 字节数）+ 内容', () => {
  const f = { type: 'string', max_len: 64 };
  const enc = encodeField(f, 'hello');
  assert.deepEqual([...enc], [0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
  assert.equal(decodeField(enc, 0, f).value, 'hello');
  assert.deepEqual([...encodeField(f, '')], [0x00]); // 空串长度 0
  const zh = encodeField(f, '中文');
  assert.equal(zh[0], Buffer.byteLength('中文', 'utf8')); // 长度 = 字节数而非字符数
  assert.equal(decodeField(zh, 0, f).value, '中文');
});

test('1.15 bytes max_len=64：1B 前缀 + 原始字节', () => {
  const f = { type: 'bytes', max_len: 64 };
  const enc = encodeField(f, Buffer.from([0x00, 0xff]));
  assert.deepEqual([...enc], [0x02, 0x00, 0xff]);
  assert.equal(decodeField(enc, 0, f).value.toString('hex'), '00ff');
  const empty = encodeField(f, Buffer.alloc(0));
  assert.deepEqual([...empty], [0x00]);
  assert.equal(decodeField(empty, 0, f).value.length, 0);
});

// ============================================================
// 1.16 长度前缀宽度推导：255/256/65535/65536 → 1B/2B/2B/4B
// ============================================================
test('1.16 max_len 255/256/65535/65536 → 前缀 1B/2B/2B/4B（大端）', () => {
  const cases = [
    { max_len: 255,   prefix: [0x01] },
    { max_len: 256,   prefix: [0x00, 0x01] },
    { max_len: 65535, prefix: [0x00, 0x01] },
    { max_len: 65536, prefix: [0x00, 0x00, 0x00, 0x01] },
  ];
  for (const { max_len, prefix } of cases) {
    const f = { type: 'string', max_len };
    const enc = encodeField(f, 'a');
    assert.deepEqual([...enc.subarray(0, prefix.length)], prefix, `max_len=${max_len} prefix`);
    assert.equal(enc.length, prefix.length + 1);
    assert.equal(decodeField(enc, 0, f).value, 'a');
  }
});

// ============================================================
// 1.17 array 变长：1B 元素个数前缀 + 裸元素
// ============================================================
test('1.17 array max_len=100：0/2/100 个元素（前缀为元素个数）', () => {
  const f = { type: 'array', element: { type: 'u8' }, max_len: 100 };
  for (const n of [0, 2, 100]) {
    const vals = Array.from({ length: n }, (_, i) => i % 256);
    const enc = encodeField(f, vals);
    assert.equal(enc[0], n); // 1B 前缀 = 元素个数
    assert.equal(enc.length, 1 + n);
    assert.deepEqual(decodeField(enc, 0, f).value, vals);
  }
  // 元素无类型头：u16 元素 2 个 → 1B 前缀 + 4B
  const f16 = { type: 'array', element: { type: 'u16' }, max_len: 10 };
  const enc16 = encodeField(f16, [0x0102, 0x0304]);
  assert.deepEqual([...enc16], [0x02, 0x01, 0x02, 0x03, 0x04]);
});

// ============================================================
// 1.18 / 1.19 定长 string 无前缀
// ============================================================
test('1.18/1.19 fixed_len=4：裸 4B 内容，长度不符 → 编码报错', () => {
  const f = { type: 'string', fixed_len: 4 };
  const enc = encodeField(f, 'abcd');
  assert.equal(enc.length, 4);
  assert.deepEqual([...enc], [0x61, 0x62, 0x63, 0x64]); // 无长度前缀
  assert.equal(decodeField(enc, 0, f).value, 'abcd');
  assert.throws(() => encodeField(f, 'abc'), FixedLenMismatch);
  assert.throws(() => encodeField(f, 'abcde'), FixedLenMismatch);
  // 解码侧不足 4B → 失败
  assert.throws(() => decodeField(Buffer.from([0x61, 0x62, 0x63]), 0, f), BufferUnderrun);
});

// ============================================================
// 1.20 / 1.21 定长 array 无前缀 + 空位默认值
// ============================================================
test('1.20 fixed_len=20：裸 20 个元素，无长度字段，空位默认 0', () => {
  const f = { type: 'array', element: { type: 'u8' }, fixed_len: 20 };
  const vals = Array.from({ length: 20 }, (_, i) => (i < 12 ? i + 1 : 0));
  const enc = encodeField(f, vals);
  assert.equal(enc.length, 20); // 无前缀
  assert.deepEqual([...enc], vals);
  const dec = decodeField(enc, 0, f).value;
  assert.equal(dec.length, 20);
  for (let i = 12; i < 20; i++) assert.equal(dec[i], 0);
  // bool 元素空位默认 0x00
  const fb = { type: 'array', element: { type: 'bool' }, fixed_len: 3 };
  assert.deepEqual([...encodeField(fb, [true, false, false])], [0x01, 0x00, 0x00]);
});

test('1.21 fixed_len=20 传入 19 个元素 → 编码报错', () => {
  const f = { type: 'array', element: { type: 'u8' }, fixed_len: 20 };
  assert.throws(() => encodeField(f, Array.from({ length: 19 }, () => 0)), FixedLenMismatch);
  assert.throws(() => encodeField(f, Array.from({ length: 21 }, () => 0)), FixedLenMismatch);
});

// ============================================================
// 1.22 max_len 超限
// ============================================================
test('1.22 max_len 超限：编码报错 / 解码校验失败', () => {
  const f = { type: 'string', max_len: 64 };
  assert.throws(() => encodeField(f, 'x'.repeat(65)), MaxLenExceeded);
  // 解码：前缀声明 65 > max_len=64
  const bad = Buffer.concat([Buffer.from([65]), Buffer.alloc(65, 0x61)]);
  assert.throws(() => decodeField(bad, 0, f), MaxLenExceeded);
  // array 同理
  const fa = { type: 'array', element: { type: 'u8' }, max_len: 4 };
  assert.throws(() => encodeField(fa, [1, 2, 3, 4, 5]), MaxLenExceeded);
  assert.throws(() => decodeField(Buffer.from([5, 1, 2, 3, 4, 5]), 0, fa), MaxLenExceeded);
});

// ============================================================
// 1.23~1.26 嵌套（结构体含结构体 / 含数组 / 数组元素为结构体 / 多维数组）
// ============================================================
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
        { name: 'id', type: 'u16' },
        { name: 'name', type: 'string', max_len: 32 },
        { name: 'inner', type: 'Inner' },                                    // 1.23 结构体含结构体
        { name: 'tags', type: 'array', element_type: 'Str', max_len: 8 },    // 1.24 结构体含数组
        { name: 'points', type: 'PointArr' },                                // 1.25 数组元素为结构体
        { name: 'matrix', type: 'array', element_type: 'RowArr', max_len: 3 }, // 1.26 变长外层
        { name: 'grid', type: 'FixedGrid' },                                 // 1.26 定长外层/内层
      ],
      Inner: [{ name: 'x', type: 'i32' }, { name: 'ok', type: 'bool' }],
      Point: [{ name: 'px', type: 'f64' }, { name: 'py', type: 'f64' }],
      Str: [{ name: 's', type: 'string', max_len: 8 }],
      Row: [{ name: 'v', type: 'u8' }],
      Ack: [{ name: 'ok', type: 'bool' }],
    },
    arrays: {
      PointArr: { max_len: 10, element_type: 'Point' },
      RowArr: { max_len: 4, element_type: 'Row' },
      FixedRow: { fixed_len: 4, element_type: 'u8' },
      FixedGrid: { fixed_len: 3, element_type: 'FixedRow' },
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
    grid: [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
  };
  const buf = schema.encodePayload(iface, 'input', value);
  const dec = schema.decodePayload(iface, 'input', buf);
  assert.equal(dec.id, 7);
  assert.equal(dec.name, '测试');
  assert.deepEqual({ ...dec.inner }, { x: -5, ok: true });
  assert.equal(dec.tags.length, 2);
  assert.ok(Math.abs(dec.points[0].px - 1.5) < 1e-9 && Math.abs(dec.points[0].py - -2.5) < 1e-9);
  assert.equal(dec.matrix[2][1].v, 6);
  assert.deepEqual(dec.grid, value.grid);

  // 定长层无前缀：FixedGrid = 3×4 个 u8 → 12B 裸排
  const fixedGrid = schema.resolveType('FixedGrid');
  assert.deepEqual([...encodeField(fixedGrid, value.grid)], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
  // 变长层有前缀：[外层 2 个][内层 RowArr 长度 2：元素 2 个][内层 RowArr 长度 1]
  const rowArr = schema.resolveType('RowArr');
  assert.deepEqual([...encodeField(rowArr, [{ v: 1 }, { v: 2 }])], [0x02, 0x01, 0x02]);
});

// ============================================================
// 1.27~1.29 enum：负值 / 未知值透传 / 值域 + 重复值
// ============================================================
test('1.27 enum base=i8：-1 → FF，-128 → 80，解码还原', () => {
  const schema = new Schema(mkIdl({ enums: { Mode: { base: 'i8', values: { Off: -1, Min: -128, Run: 5 } } } }));
  const mode = schema.resolveType('Mode');
  assert.deepEqual([...encodeField(mode, -1)], [0xff]);
  assert.deepEqual([...encodeField(mode, -128)], [0x80]);
  assert.equal(decodeField(Buffer.from([0xff]), 0, mode).value, -1);
  assert.equal(decodeField(Buffer.from([0x80]), 0, mode).value, -128);
  // 名称输入映射
  assert.deepEqual([...encodeField(mode, 'Run')], [0x05]);
});

test('1.28 enum 未知值透传（base=u8，收到 200 不报错）', () => {
  const schema = new Schema(mkIdl({ enums: { Mode: { values: { Off: 0, Run: 2 } } } }));
  const mode = schema.resolveType('Mode');
  assert.equal(decodeField(Buffer.from([200]), 0, mode).value, 200); // IDL 未声明值，按 u8 保留
  assert.deepEqual([...encodeField(mode, 200)], [200]);
  assert.equal(mode.base, 'u8'); // base 缺省 u8
});

test('1.29 enum 值域校验 / values 重复值 → IDL 加载失败', () => {
  const schema = new Schema(mkIdl({ enums: { Mode: { values: { Off: 0 } } } }));
  const mode = schema.resolveType('Mode');
  assert.throws(() => encodeField(mode, 300), ValueRangeExceeded);
  assert.throws(() => encodeField(mode, 'UnknownName'), ValueRangeExceeded);
  // 重复值 → 构造期失败
  assert.throws(
    () => new Schema(mkIdl({ enums: { Bad: { values: { A: 1, B: 1 } } } })),
    InvalidArgument,
  );
  // 值超出 base 值域 → 构造期失败
  assert.throws(
    () => new Schema(mkIdl({ enums: { Bad: { base: 'i8', values: { A: 200 } } } })),
    InvalidArgument,
  );
});

// ============================================================
// 1.30 Masking XOR
// ============================================================
test('1.30 Masking XOR：4B 对齐/不对齐均正确', () => {
  const key = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  for (const len of [4, 5, 7, 8]) {
    const data = Buffer.from(Array.from({ length: len }, (_, i) => i));
    const masked = applyMask(data, key);
    assert.deepEqual([...applyMask(masked, key)], [...data]);
  }
});

// ============================================================
// 1.34 / 1.35 CRC 缺省关闭 / 开启与校验
// ============================================================
const CRC_IDL = {
  service: {
    svc_id: 2, major_ver: 1,
    interfaces: [
      { name: 'withCrc', if_id: 1, type: 'rpc', input: ['Data'], output: 'Data', crc: true },
      { name: 'noCrc', if_id: 2, type: 'rpc', input: ['Data'], output: 'Data' },
    ],
  },
  type_def: {
    structs: {
      Data: [
        { name: 'v', type: 'u16' },
        { name: 's', type: 'string', max_len: 8 },
      ],
    },
  },
};

test('1.34 CRC 缺省关闭：payload 末尾无 2B CRC', () => {
  const schema = new Schema(CRC_IDL);
  const iface = schema.getInterface(2); // 未声明 crc
  const buf = schema.encodePayload(iface, 'input', { v: 0x1234, s: 'ab' });
  // 字段序列：u16(2B) + 1B 前缀 + 2B = 5B，无额外 CRC
  assert.equal(buf.length, 5);
  assert.deepEqual([...buf], [0x12, 0x34, 0x02, 0x61, 0x62]);
  assert.deepEqual(schema.decodePayload(iface, 'input', buf), { v: 0x1234, s: 'ab' });
});

test('1.35 CRC 开启：末尾 2B 大端校验；篡改 → CrcMismatch', () => {
  const schema = new Schema(CRC_IDL);
  const iface = schema.getInterface(1); // "crc": true
  const body = { v: 0x1234, s: 'ab' };
  const buf = schema.encodePayload(iface, 'input', body);
  assert.equal(buf.length, 7); // 5B 字段 + 2B CRC
  assert.equal(buf.readUInt16BE(5), crc16(buf.subarray(0, 5))); // 大端附加
  assert.deepEqual(schema.decodePayload(iface, 'input', buf), body);
  // 篡改 1 字节 → CRC 失败
  const bad = Buffer.from(buf);
  bad[0] ^= 0xff;
  assert.throws(() => schema.decodePayload(iface, 'input', bad), CrcMismatch);
  // payload < 2B（连 CRC 都不够）
  assert.throws(() => schema.decodePayload(iface, 'input', Buffer.from([0x01])), BufferUnderrun);
});

// ============================================================
// 1.36 末尾新增字段忽略（MinorVer 兼容）
// ============================================================
test('1.36 旧解码器解完既有字段后忽略剩余字节', () => {
  const schema = new Schema(CRC_IDL);
  const iface = schema.getInterface(2);
  const base = schema.encodePayload(iface, 'input', { v: 7, s: 'ab' });
  const extended = Buffer.concat([base, Buffer.from([0xde, 0xad, 0xbe, 0xef])]); // 新端末尾新增字段
  assert.deepEqual(schema.decodePayload(iface, 'input', extended), { v: 7, s: 'ab' });
  // 直接走字段层同样成立
  const f = { type: 'u16', name: 'v' };
  const r = decodeStructFields(Buffer.concat([encodeField(f, 5), Buffer.from([0x33, 0x99])]), 0, [f]);
  assert.equal(r.value.v, 5);
});

// ============================================================
// 1.38 大端统一
// ============================================================
test('1.38 大端统一：u16 0x1234 → 12 34；i16 -2 → FF FE', () => {
  assert.deepEqual([...encodeField({ type: 'u16' }, 0x1234)], [0x12, 0x34]);
  assert.deepEqual([...encodeField({ type: 'i16' }, -2)], [0xff, 0xfe]);
  assert.equal(decodeField(Buffer.from([0x12, 0x34]), 0, { type: 'u16' }).value, 0x1234);
  assert.equal(decodeField(Buffer.from([0xff, 0xfe]), 0, { type: 'i16' }).value, -2);
});

// ============================================================
// 1.5 变长字段强制声明 + v5 语法拒绝（optional/size/width/legacy type）
// ============================================================
test('1.5 string/bytes/array 缺 fixed_len/max_len → IDL 加载失败', () => {
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 's', type: 'string' }] } })),
    InvalidArgument,
  );
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 'b', type: 'bytes' }] } })),
    InvalidArgument,
  );
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 'a', type: 'array', element_type: 'u8' }] } })),
    InvalidArgument,
  );
  // arrays 条目同样强制
  assert.throws(
    () => new Schema(mkIdl({ arrays: { A: { element_type: 'u8' } } })),
    InvalidArgument,
  );
  // fixed_len 与 max_len 互斥
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 's', type: 'string', fixed_len: 4, max_len: 8 }] } })),
    InvalidArgument,
  );
  // 合法声明可通过
  const ok = new Schema(mkIdl({ structs: { S: [{ name: 's', type: 'string', max_len: 8 }] } }));
  assert.equal(ok.resolveType('S').fields[0].type, 'string');
});

test('1.5 v5 语法：optional / size / width / legacy type / arrays.type 均拒绝', () => {
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 's', type: 'string', max_len: 8, optional: true }] } })),
    InvalidArgument,
  );
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 'u', type: 'unsigned', size: 1 }] } })),
    InvalidArgument,
  );
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 'f', type: 'float', width: 64 }] } })),
    InvalidArgument,
  );
  assert.throws(
    () => new Schema(mkIdl({ structs: { S: [{ name: 'u', type: 'u8', size: 1 }] } })),
    InvalidArgument,
  );
  assert.throws(
    () => new Schema(mkIdl({ arrays: { A: { type: 'array', fixed_len: 2, element_type: 'u8' } } })),
    InvalidArgument,
  );
  // v4 enum 用 type/size → 拒绝；v5 用 base
  assert.throws(
    () => new Schema(mkIdl({ enums: { E: { type: 'unsigned', size: 1, values: { A: 0 } } } })),
    InvalidArgument,
  );
});

test('1.5 IDL 库：非法定义文件跳过，其他定义不受影响', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-idl-'));
  const log = { error() {}, info() {}, warn() {}, debug() {}, frame() {} };
  try {
    fs.writeFileSync(path.join(dir, 'bad.json'), JSON.stringify({
      service: { svc_id: 10, major_ver: 1, interfaces: [] },
      type_def: { structs: { Bad: [{ name: 's', type: 'string' }] } }, // 缺长度声明
    }));
    fs.writeFileSync(path.join(dir, 'good.json'), JSON.stringify({
      service: { svc_id: 11, major_ver: 1, interfaces: [] },
      type_def: { structs: { Good: [{ name: 's', type: 'string', max_len: 8 }] } },
    }));
    const store = new IdlStore(dir, log);
    await store.loadAll();
    assert.equal(store.has(10, 1), false); // 非法文件被跳过
    assert.equal(store.has(11, 1), true);  // 合法文件正常加载
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================
// 1.32 空 payload（frame 层覆盖 8B 帧；此处验证接口无输入时编码为空）
// ============================================================
test('1.32 无 input 类型 → payload 0B；crc 开启则恰 2B', () => {
  const idl = {
    service: {
      svc_id: 3, major_ver: 1,
      interfaces: [
        { name: 'empty', if_id: 1, type: 'rpc' },
        { name: 'emptyCrc', if_id: 2, type: 'rpc', crc: true },
      ],
    },
  };
  const schema = new Schema(idl);
  assert.equal(schema.encodePayload(schema.getInterface(1), 'input', undefined).length, 0);
  assert.equal(schema.encodePayload(schema.getInterface(2), 'input', undefined).length, 2);
  assert.equal(schema.decodePayload(schema.getInterface(1), 'input', Buffer.alloc(0)), undefined);
  assert.equal(schema.decodePayload(schema.getInterface(2), 'input', schema.encodePayload(schema.getInterface(2), 'input', undefined)), undefined);
});
