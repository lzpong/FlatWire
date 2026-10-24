// ============================================================
// types.js —— §9 结构化数据字段（v5.0 裸字节编码）
//
// v5 线格式要点（§9.1~§9.4）：
//   - 无字段头、无类型标记、无结构边界、无 null/optional 标记
//   - 字段按 IDL schema 顺序裸值连续编码，多字节一律大端
//   - 类型/宽度/长度前缀宽度全部由 IDL 静态确定（编解码不依赖线上类型信息）
//   - string/bytes/array：fixed_len=N → 无前缀（恰 N）；max_len=N → 前缀宽 w(N)
//       w(N)：N≤255→1B，N≤65535→2B，N>65535→4B（大端）
//   - 解码按 schema 顺序读取，任一字段字节不足 → BufferUnderrun（帧层回 RST 0x20）
//   - schema 字段耗尽后的剩余字节 = 对端新增末尾字段 → 由调用方忽略（§11.2）
//
// f80（10B x87 扩展精度）为可选扩展（§9.2）：本实现不支持，IDL 加载期拒绝（schema.js）。
// ============================================================

import {
  InvalidBoolEncoding, UnsupportedFloatType, BufferUnderrun, MaxLenExceeded,
  FixedLenMismatch, ValueRangeExceeded, UnknownFieldType, UnexpectedNull, InvalidArgument,
} from '../errors.js';

// 整型宽度（字节，§9.2）
export const INT_WIDTH = Object.freeze({
  u8: 1, u16: 2, u32: 4, u64: 8,
  i8: 1, i16: 2, i32: 4, i64: 8,
});

// 浮点宽度（字节，§9.2）：f80 为可选扩展，本实现不提供
export const FLOAT_WIDTH = Object.freeze({ f32: 4, f64: 8 });

// 标量类型白名单（不含 string/bytes/array/struct/enum 引用）
export const SCALAR_TYPES = Object.freeze(new Set([
  ...Object.keys(INT_WIDTH), 'f32', 'f64', 'f80', 'bool', 'timestamp',
]));

// timestamp：6B / 48bit 无符号（2000-01-01 起毫秒，§9.2）
const TS_BITS = 48n;
const TS_MAX = (1n << TS_BITS) - 1n;

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);

// ---------- 内部工具 ----------

/** 读取前校验剩余字节，不足抛 BufferUnderrun（截断数据，§9.1） */
function need(buf, offset, n, what) {
  if (offset + n > buf.length) {
    throw new BufferUnderrun(`need ${n} byte(s) for ${what} at offset ${offset}, have ${buf.length - offset}`);
  }
}

/** 值 → BigInt（整型/枚举编码入口）；非整数或类型不符 → 值域错误 */
function toBigInt(value, label) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isInteger(value)) return BigInt(value);
  throw new ValueRangeExceeded(`${label}: value ${String(value)} is not an integer`);
}

/** BigInt → JS Number（超出 ±2^53-1 时保留 BigInt，避免精度丢失） */
function toJsInt(v) {
  return (v >= MIN_SAFE && v <= MAX_SAFE) ? Number(v) : v;
}

/** 长度前缀宽度 w(N)（§9.3）：N≤255→1B，N≤65535→2B，N>65535→4B */
export function lenPrefixWidth(maxLen) {
  if (maxLen <= 255) return 1;
  if (maxLen <= 65535) return 2;
  return 4;
}

/** 写大端长度前缀 */
function writeLen(width, n) {
  const b = Buffer.alloc(width);
  let v = n;
  for (let i = width - 1; i >= 0; i--) {
    b[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  return b;
}

/** 读大端长度前缀 */
function readLen(buf, offset, width) {
  let v = 0;
  for (let i = 0; i < width; i++) v = v * 256 + buf[offset + i];
  return v;
}

/** 定长/变长声明校验：字符串/字节/数组必须恰有一种声明（schema 已保证，此处防御） */
function lenDecl(field, kind) {
  if (field.fixed_len !== undefined) return { mode: 'fixed', n: field.fixed_len };
  if (field.max_len !== undefined) return { mode: 'max', n: field.max_len };
  throw new InvalidArgument(`${kind} "${field.name ?? '?'}" must declare fixed_len or max_len (v5)`);
}

// ---------- 整型 / 枚举基类型（§9.2） ----------

/** 按类型编码整型（补码大端），并做值域校验 */
function encodeInt(type, value, label = type) {
  const w = INT_WIDTH[type];
  if (w === undefined) throw new UnknownFieldType(`unknown integer type "${type}"`);
  const v = toBigInt(value, label);
  const bits = BigInt(8 * w);
  const signed = type[0] === 'i';
  const lo = signed ? -(1n << (bits - 1n)) : 0n;
  const hi = signed ? (1n << (bits - 1n)) - 1n : (1n << bits) - 1n;
  if (v < lo || v > hi) {
    throw new ValueRangeExceeded(`${label}: value ${v} out of range [${lo}, ${hi}]`);
  }
  const u = BigInt.asUintN(8 * w, v); // 补码表示
  const out = Buffer.alloc(w);
  for (let i = 0; i < w; i++) out[w - 1 - i] = Number((u >> BigInt(8 * i)) & 0xffn);
  return out;
}

/** 按类型解码整型（补码大端） */
function decodeInt(type, buf, offset) {
  const w = INT_WIDTH[type];
  if (w === undefined) throw new UnknownFieldType(`unknown integer type "${type}"`);
  need(buf, offset, w, `${type} value`);
  let u = 0n;
  for (let i = 0; i < w; i++) u = (u << 8n) | BigInt(buf[offset + i]);
  const v = type[0] === 'i' ? BigInt.asIntN(8 * w, u) : u;
  return toJsInt(v);
}

// ---------- 编码 ----------

/**
 * 按字段定义编码一个值，返回 Buffer（裸字节，无字段头）。
 * field 的规范形态见 schema.js（type 为标量名 / string / bytes / array / struct / enum）。
 * @param {object} field 字段定义
 * @param {*} value 业务值
 * @returns {Buffer}
 */
export function encodeField(field, value) {
  const t = field.type;

  // 整型（含 unsigned/signed 独立类型，§9.2）
  if (INT_WIDTH[t] !== undefined) return encodeInt(t, value, field.name ?? t);

  switch (t) {
    case 'f32': {
      if (typeof value !== 'number') throw new ValueRangeExceeded(`f32 requires number, got ${typeof value}`);
      const b = Buffer.alloc(4);
      b.writeFloatBE(value, 0); // IEEE754 单精度大端
      return b;
    }

    case 'f64': {
      if (typeof value !== 'number') throw new ValueRangeExceeded(`f64 requires number, got ${typeof value}`);
      const b = Buffer.alloc(8);
      b.writeDoubleBE(value, 0); // IEEE754 双精度大端
      return b;
    }

    case 'f80':
      // 可选扩展：本实现不支持 → IDL 加载期已拒绝（schema.js），此处防御
      throw new UnsupportedFloatType('f80 (x87 80-bit) is not supported by this implementation');

    case 'bool': {
      // §9.2：0x00=false / 0x01=true（编码仅产出合法值；容忍 0/1 数值输入）
      if (value === true || value === 1) return Buffer.from([0x01]);
      if (value === false || value === 0) return Buffer.from([0x00]);
      throw new ValueRangeExceeded(`bool "${field.name ?? '?'}" accepts only boolean/0/1, got ${String(value)}`);
    }

    case 'timestamp': {
      // §9.2：6B 48bit 无符号大端（2000-01-01 UTC 起毫秒）
      const v = toBigInt(value, field.name ?? 'timestamp');
      if (v < 0n || v > TS_MAX) {
        throw new ValueRangeExceeded(`timestamp ${v} out of range [0, 2^48-1]`);
      }
      const b = Buffer.alloc(6);
      for (let i = 0; i < 6; i++) b[5 - i] = Number((v >> BigInt(8 * i)) & 0xffn);
      return b;
    }

    case 'string': {
      const raw = Buffer.from(String(value ?? ''), 'utf8'); // 长度 = UTF-8 字节数（§9.3）
      const decl = lenDecl(field, 'string');
      if (decl.mode === 'fixed') {
        // fixed_len：无长度前缀，输入必须恰为 N 字节
        if (raw.length !== decl.n) {
          throw new FixedLenMismatch(`string fixed_len=${decl.n} but content is ${raw.length} byte(s)`);
        }
        return raw;
      }
      if (raw.length > decl.n) {
        throw new MaxLenExceeded(`string max_len=${decl.n} but content is ${raw.length} byte(s)`);
      }
      const w = lenPrefixWidth(decl.n);
      return Buffer.concat([writeLen(w, raw.length), raw]);
    }

    case 'bytes': {
      const raw = Buffer.isBuffer(value) ? value : Buffer.from(value);
      const decl = lenDecl(field, 'bytes');
      if (decl.mode === 'fixed') {
        if (raw.length !== decl.n) {
          throw new FixedLenMismatch(`bytes fixed_len=${decl.n} but content is ${raw.length} byte(s)`);
        }
        return raw;
      }
      if (raw.length > decl.n) {
        throw new MaxLenExceeded(`bytes max_len=${decl.n} but content is ${raw.length} byte(s)`);
      }
      const w = lenPrefixWidth(decl.n);
      return Buffer.concat([writeLen(w, raw.length), raw]);
    }

    case 'array': {
      if (!Array.isArray(value)) throw new ValueRangeExceeded('array value must be a JS array');
      const decl = lenDecl(field, 'array');
      if (decl.mode === 'fixed') {
        // fixed_len：无长度前缀，恰 N 个元素裸排（§9.4）
        if (value.length !== decl.n) {
          throw new FixedLenMismatch(`array fixed_len=${decl.n} but got ${value.length} element(s)`);
        }
        return Buffer.concat(value.map((el) => encodeField(field.element, el)));
      }
      if (value.length > decl.n) {
        throw new MaxLenExceeded(`array max_len=${decl.n} but got ${value.length} element(s)`);
      }
      // max_len：前缀为元素个数（非字节数），宽度按 N 静态推导
      const w = lenPrefixWidth(decl.n);
      const parts = [writeLen(w, value.length)];
      for (const el of value) parts.push(encodeField(field.element, el));
      return Buffer.concat(parts);
    }

    case 'struct': {
      // N 个字段按 schema 顺序裸排，无边界标记；v5 全字段必填（无 optional/null）
      if (value === null || value === undefined || typeof value !== 'object') {
        throw new UnexpectedNull(`struct "${field.name ?? '?'}" value is null/undefined`);
      }
      const parts = [];
      for (const f of field.fields) {
        const v = value[f.name];
        if (v === undefined || v === null) {
          throw new UnexpectedNull(`missing/null field "${f.name}" (v5: all fields required)`);
        }
        parts.push(encodeField(f, v));
      }
      return Buffer.concat(parts);
    }

    case 'enum': {
      // 线格式 = base 整型裸值（默认 u8）；名称输入按 values 映射
      let v = value;
      if (typeof value === 'string') {
        if (!Object.prototype.hasOwnProperty.call(field.values ?? {}, value)) {
          throw new ValueRangeExceeded(`unknown enum name "${value}" (enum "${field.name ?? '?'}")`);
        }
        v = field.values[value];
      }
      return encodeInt(field.base ?? 'u8', v, `enum ${field.name ?? ''}`.trim());
    }

    default:
      throw new UnknownFieldType(`unknown field type "${t}"`);
  }
}

// ---------- 解码 ----------

/**
 * 从 buf 的 offset 处解码一个字段值（裸字节，按 schema 顺序消费）。
 * @returns {{ value: *, offset: number }} value 为解码结果；offset 为解码后的新位置
 */
export function decodeField(buf, offset, field) {
  const t = field.type;

  if (INT_WIDTH[t] !== undefined) {
    return { value: decodeInt(t, buf, offset), offset: offset + INT_WIDTH[t] };
  }

  switch (t) {
    case 'f32': {
      need(buf, offset, 4, 'f32');
      return { value: buf.readFloatBE(offset), offset: offset + 4 };
    }

    case 'f64': {
      need(buf, offset, 8, 'f64');
      return { value: buf.readDoubleBE(offset), offset: offset + 8 };
    }

    case 'f80':
      throw new UnsupportedFloatType('f80 (x87 80-bit) is not supported by this implementation');

    case 'bool': {
      // §9.2 bool 严格解码：仅 0x00/0x01 合法，其他 → InvalidBoolEncoding
      need(buf, offset, 1, 'bool');
      const b = buf[offset];
      if (b > 1) throw new InvalidBoolEncoding(`bool byte 0x${b.toString(16)} is not 0x00/0x01`);
      return { value: b === 1, offset: offset + 1 };
    }

    case 'timestamp': {
      // §9.2：6B 48bit 无符号大端
      need(buf, offset, 6, 'timestamp');
      let v = 0;
      for (let i = 0; i < 6; i++) v = v * 256 + buf[offset + i];
      return { value: v, offset: offset + 6 };
    }

    case 'string': {
      const decl = lenDecl(field, 'string');
      if (decl.mode === 'fixed') {
        // fixed_len：无前缀，恰 N 字节（读出长度恒为 N）
        need(buf, offset, decl.n, 'fixed string');
        return { value: buf.toString('utf8', offset, offset + decl.n), offset: offset + decl.n };
      }
      const w = lenPrefixWidth(decl.n);
      need(buf, offset, w, 'string length prefix');
      const len = readLen(buf, offset, w);
      if (len > decl.n) throw new MaxLenExceeded(`string max_len=${decl.n} but got ${len} byte(s)`);
      const p = offset + w;
      need(buf, p, len, 'string body');
      return { value: buf.toString('utf8', p, p + len), offset: p + len };
    }

    case 'bytes': {
      const decl = lenDecl(field, 'bytes');
      if (decl.mode === 'fixed') {
        need(buf, offset, decl.n, 'fixed bytes');
        return { value: buf.subarray(offset, offset + decl.n), offset: offset + decl.n };
      }
      const w = lenPrefixWidth(decl.n);
      need(buf, offset, w, 'bytes length prefix');
      const len = readLen(buf, offset, w);
      if (len > decl.n) throw new MaxLenExceeded(`bytes max_len=${decl.n} but got ${len} byte(s)`);
      const p = offset + w;
      need(buf, p, len, 'bytes body');
      return { value: buf.subarray(p, p + len), offset: p + len };
    }

    case 'array': {
      const decl = lenDecl(field, 'array');
      let n;
      let p = offset;
      if (decl.mode === 'fixed') {
        // fixed_len：无前缀，恰 N 个元素
        n = decl.n;
      } else {
        // max_len：前缀为元素个数，宽度按 N 静态推导
        const w = lenPrefixWidth(decl.n);
        need(buf, offset, w, 'array length prefix');
        n = readLen(buf, offset, w);
        if (n > decl.n) throw new MaxLenExceeded(`array max_len=${decl.n} but got ${n} element(s)`);
        p = offset + w;
      }
      const elems = [];
      for (let i = 0; i < n; i++) {
        const r = decodeField(buf, p, field.element);
        elems.push(r.value);
        p = r.offset;
      }
      return { value: elems, offset: p };
    }

    case 'struct':
      // 无边界标记：按字段列表顺序消费（嵌套 struct 与数组元素 struct 同此入口）
      return decodeStructFields(buf, offset, field.fields);

    case 'enum': {
      // 线格式 = base 整型裸值；未知值透传（MinorVer 兼容，§11.2）
      const base = field.base ?? 'u8';
      return { value: decodeInt(base, buf, offset), offset: offset + INT_WIDTH[base] };
    }

    default:
      throw new UnknownFieldType(`unknown field type "${t}"`);
  }
}

/**
 * 按 schema 字段列表解码一"层"字段序列（§9.1）。
 * schema 字段耗尽后的剩余字节 = 对端新增的末尾字段 → 忽略（§11.2）。
 * @returns {{ value: object, offset: number }} value 为 { fieldName: v } 对象
 */
export function decodeStructFields(buf, offset, fields) {
  const result = {};
  let p = offset;
  for (const f of fields) {
    const r = decodeField(buf, p, f);
    result[f.name] = r.value;
    p = r.offset;
  }
  return { value: result, offset: p };
}

// ---------- MSK 掩码（§10） ----------

/**
 * 对 Data Fields 逐字节循环 XOR（§10：encoded[i] = payload[i] ^ key[i % 4]）。
 * 编解码对称，同一函数双向使用；CRC 与 MSK 顺序为先 CRC 后整体 XOR（§9.6）。
 */
export function applyMask(data, key) {
  const out = Buffer.from(data); // 拷贝，不改变原缓冲
  for (let i = 0; i < out.length; i++) out[i] ^= key[i % 4];
  return out;
}
