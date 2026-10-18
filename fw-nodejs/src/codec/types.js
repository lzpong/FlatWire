// ============================================================
// types.js —— §9 结构化数据字段编解码（类型系统 / 恒定宽度 / null 语义）
//
// 字段头（1 字节）：高 4bit=类型（0~8），低 4bit 用途因类型而异（§9.1）。
// 解码错误一律抛 DecodeError 子类（§9.4）；解码不做部分交付（§9.4 末尾）。
// ============================================================

import {
  InvalidBoolEncoding, InvalidSignedLength, InvalidUnsignedLength, SizeMismatch,
  UnexpectedNull, UnknownFieldType, UnsupportedFloatType, BufferUnderrun,
  MaxLenExceeded, FixedLenMismatch, ValueRangeExceeded,
} from '../errors.js';

// 字段类型 ID（字段头高 4bit，§9.1）
export const FT = Object.freeze({
  NULL: 0x0, BOOL: 0x1, SIGNED: 0x2, UNSIGNED: 0x3, FLOAT: 0x4,
  TIMESTAMP: 0x5, STRING: 0x6, BYTES: 0x7, ARRAY: 0x8,
});

// timestamp 基准：2000/1/1 UTC，精度毫秒，44bit（§9.1）
const TS_LIMIT = 2 ** 44; // 2^44

// ---------- 内部工具 ----------

function need(buf, offset, n, what) {
  // 读取前校验剩余字节，不足抛 BufferUnderrun（截断数据）
  if (offset + n > buf.length) {
    throw new BufferUnderrun(`need ${n} byte(s) for ${what} at offset ${offset}, have ${buf.length - offset}`);
  }
}

// 长度块字节数：值 len 需要多少字节表示（string/bytes 长度块占 low4+1 字节，1~16，§9.2）
function lenBlockWidth(len) {
  let w = 1;
  while (w < 16 && len >= 256 ** w) w++;
  return w;
}

// fixed_len / max_len 解码校验（§9.4 check_len 表）
function checkLen(len, field) {
  if (field.fixed_len !== undefined && field.fixed_len !== null && len !== field.fixed_len) {
    throw new FixedLenMismatch(`fixed_len=${field.fixed_len} but got ${len}`);
  }
  if (field.max_len !== undefined && field.max_len !== null && len > field.max_len) {
    throw new MaxLenExceeded(`max_len=${field.max_len} but got ${len}`);
  }
}

// fixed_len / max_len 编码校验（§9.2 约束校验）
function checkLenEncode(len, field, kind) {
  if (field.fixed_len !== undefined && field.fixed_len !== null && len !== field.fixed_len) {
    throw new FixedLenMismatch(`${kind} fixed_len=${field.fixed_len} but content is ${len} byte(s)/elem(s)`);
  }
  if (field.max_len !== undefined && field.max_len !== null && len > field.max_len) {
    throw new MaxLenExceeded(`${kind} max_len=${field.max_len} but content is ${len} byte(s)/elem(s)`);
  }
}

// ---------- 编码 ----------

/**
 * 按字段定义编码一个值，返回 Buffer。
 * 字段定义 field 的规范形态见 schema.js。
 * @param {object} field 字段定义
 * @param {*} value 业务值
 */
export function encodeField(field, value) {
  // §9.2：null 仅 optional 字段可编码（1B 字段头 0x00）；非 optional 遇 null/undefined 抛 UnexpectedNull
  if (value === null || value === undefined) {
    if (field.optional) return Buffer.from([FT.NULL << 4]);
    throw new UnexpectedNull(`null on non-optional field "${field.name ?? '?'}"`);
  }
  const t = field.type;
  switch (t) {
    case 'null':
      // §9.1：空值仅 1B 字段头；仅 optional 字段可编码 null（§9.2）
      if (!field.optional) throw new UnexpectedNull('null value on non-optional field');
      return Buffer.from([FT.NULL << 4]);

    case 'bool':
      // §9.1：0=false, 1=true（编码仅产出合法值）
      return Buffer.from([(FT.BOOL << 4) | (value ? 1 : 0)]);

    case 'signed': {
      // §9.2：线上宽度恒等于 IDL size，low4 恒等于 size（校验位）
      const size = field.size;
      if (!(size >= 1 && size <= 15)) throw new ValueRangeExceeded(`signed size must be 1~15, got ${size}`);
      const lo = -(2 ** (8 * size - 1));
      const hi = 2 ** (8 * size - 1) - 1;
      if (!Number.isInteger(value) || value < lo || value > hi) {
        throw new ValueRangeExceeded(`signed(size=${size}) value ${value} out of range [${lo}, ${hi}]`);
      }
      const head = Buffer.from([(FT.SIGNED << 4) | size]);
      const body = Buffer.alloc(size);
      for (let i = 0; i < size; i++) body[size - 1 - i] = Number((BigInt.asIntN(8 * size, BigInt(value)) >> BigInt(8 * i)) & 0xffn);
      return Buffer.concat([head, body]);
    }

    case 'unsigned': {
      const size = field.size;
      if (!(size >= 1 && size <= 15)) throw new ValueRangeExceeded(`unsigned size must be 1~15, got ${size}`);
      const hi = 2 ** (8 * size) - 1;
      if (!Number.isInteger(value) || value < 0 || value > hi) {
        throw new ValueRangeExceeded(`unsigned(size=${size}) value ${value} out of range [0, ${hi}]`);
      }
      const head = Buffer.from([(FT.UNSIGNED << 4) | size]);
      const body = Buffer.alloc(size);
      for (let i = 0; i < size; i++) body[size - 1 - i] = Math.floor(value / 256 ** i) % 256;
      return Buffer.concat([head, body]);
    }

    case 'enum': {
      // §11.1：enum 线格式 = 底层整型（按 signed/unsigned 恒定宽度规则编码）
      let v = value;
      if (typeof value === 'string') {
        if (!(value in field.values)) throw new ValueRangeExceeded(`unknown enum name "${value}"`);
        v = field.values[value];
      }
      return encodeField({ type: field.base, size: field.size }, v);
    }

    case 'float': {
      // §9.1：1=32bit, 2=64bit, 3=80bit(x87 可选扩展)
      if (field.width === 32) {
        const b = Buffer.alloc(5);
        b[0] = (FT.FLOAT << 4) | 1;
        b.writeFloatBE(value, 1);
        return b;
      }
      if (field.width === 64) {
        const b = Buffer.alloc(9);
        b[0] = (FT.FLOAT << 4) | 2;
        b.writeDoubleBE(value, 1);
        return b;
      }
      // 80bit 扩展：本实现不支持（编码与解码一致地抛 UnsupportedFloatType）
      throw new UnsupportedFloatType(`float width ${field.width} not supported (80bit is optional extension)`);
    }

    case 'timestamp': {
      // §9.1：字段头 0x50|t[43:40]，payload 5B = t[39:0]，共 44bit
      if (!Number.isFinite(value) || value < 0 || value >= TS_LIMIT || !Number.isInteger(value)) {
        throw new ValueRangeExceeded(`timestamp ${value} out of range [0, 2^44-1]`);
      }
      const high = Math.floor(value / 2 ** 40); // t[43:40]
      const low = value % 2 ** 40;              // t[39:0]
      const b = Buffer.alloc(6);
      b[0] = (FT.TIMESTAMP << 4) | high;
      for (let i = 0; i < 5; i++) b[1 + i] = Math.floor(low / 256 ** (4 - i)) % 256;
      return b;
    }

    case 'string': {
      // §9.2：长度块占 low4+1 字节，值为实际字节数，UTF-8
      const raw = Buffer.from(value, 'utf8');
      checkLenEncode(raw.length, field, 'string');
      const w = lenBlockWidth(raw.length);
      const b = Buffer.alloc(1 + w);
      b[0] = (FT.STRING << 4) | (w - 1);
      for (let i = 0; i < w; i++) b[1 + i] = Math.floor(raw.length / 256 ** (w - 1 - i)) % 256;
      return Buffer.concat([b, raw]);
    }

    case 'bytes': {
      const raw = Buffer.isBuffer(value) ? value : Buffer.from(value);
      checkLenEncode(raw.length, field, 'bytes');
      const w = lenBlockWidth(raw.length);
      const b = Buffer.alloc(1 + w);
      b[0] = (FT.BYTES << 4) | (w - 1);
      for (let i = 0; i < w; i++) b[1 + i] = Math.floor(raw.length / 256 ** (w - 1 - i)) % 256;
      return Buffer.concat([b, raw]);
    }

    case 'array': {
      // §9.3：0x8X，X=0~14 内联元素个数；X=15 后跟 2 字节长度（0~65535）
      if (!Array.isArray(value)) throw new ValueRangeExceeded('array value must be a JS array');
      checkLenEncode(value.length, field, 'array');
      if (value.length > 65535) throw new MaxLenExceeded('array length exceeds 65535');
      const parts = [];
      if (value.length <= 14) {
        parts.push(Buffer.from([(FT.ARRAY << 4) | value.length]));
      } else {
        parts.push(Buffer.from([(FT.ARRAY << 4) | 15]));
        const lb = Buffer.alloc(2);
        lb.writeUInt16BE(value.length, 0);
        parts.push(lb);
      }
      for (const el of value) parts.push(encodeField(field.element, el));
      return Buffer.concat(parts);
    }

    case 'struct': {
      // §9.3：N 个字段按顺序连续编码，无边界标记；值为 JS 对象
      if (value === null || value === undefined) {
        throw new UnexpectedNull('struct value is null/undefined');
      }
      const parts = [];
      for (const f of field.fields) {
        const v = value[f.name];
        if (v === undefined && f.optional) {
          // optional 字段缺省 → 编码为 null（§9.2）
          parts.push(encodeField({ type: 'null', optional: true }, null));
        } else if (v === undefined) {
          throw new UnexpectedNull(`missing non-optional field "${f.name}"`);
        } else if (v === null && !f.optional) {
          throw new UnexpectedNull(`null on non-optional field "${f.name}"`);
        } else {
          parts.push(encodeField(f, v));
        }
      }
      return Buffer.concat(parts);
    }

    default:
      throw new UnknownFieldType(`unknown field type "${t}"`);
  }
}

// ---------- 解码 ----------

/**
 * 从 buf 的 offset 处解码一个字段值。
 * @returns {{ value: *, offset: number }} value 为解码结果；offset 为解码后的新位置
 */
export function decodeField(buf, offset, field) {
  // §9.3：struct 无外层字段头——解码 = 按字段列表顺序消费字段序列
  //（嵌套 struct 字段与"数组元素为结构体"场景统一经此入口）
  if (field.type === 'struct') {
    // optional 结构体遇 null（1B 空头 0x00，§9.2）：与编码端 null 分支优先于 struct 分支对称，
    // 先窥探首字节确认 null 再消费——否则 0x00 会被误当作首个成员的字段头（数据错位/误报）。
    // 非 optional 不窥探：0x00 属对端违约，由内层字段按 UnexpectedNull 报错（§9.4）
    if (field.optional && offset < buf.length && buf[offset] === 0x00) {
      return { value: null, offset: offset + 1 };
    }
    return decodeStructFields(buf, offset, field.fields);
  }
  need(buf, offset, 1, 'field head');
  const typeByte = buf[offset];
  const typeId = typeByte >> 4;      // §9.4：高 4bit
  const low4 = typeByte & 0x0f;      // 低 4bit
  let p = offset + 1;

  switch (typeId) {
    case FT.NULL:
      // §9.4：仅 optional 字段遇 null 合法 → 缺省值；否则抛 UnexpectedNull
      if (!field.optional) throw new UnexpectedNull(`null on non-optional field "${field.name ?? '?'}"`);
      return { value: null, offset: p };

    case FT.BOOL:
      // §9.4：low4 > 1 → InvalidBoolEncoding
      if (low4 > 1) throw new InvalidBoolEncoding(`bool head low4=${low4}`);
      return { value: low4 === 1, offset: p };

    case FT.SIGNED: {
      // §9.4：low4=0 → InvalidSignedLength；byte_len != size → SizeMismatch（§9.2 恒定宽度）
      if (low4 === 0) throw new InvalidSignedLength('signed head low4=0');
      if (field.size === undefined) throw new SizeMismatch('signed field without size in schema');
      if (low4 !== field.size) throw new SizeMismatch(`signed byte_len=${low4} != IDL size=${field.size}`);
      need(buf, p, low4, 'signed body');
      let v = 0;
      for (let i = 0; i < low4; i++) v = v * 256 + buf[p + i];
      // 符号位展开（大端，最高字节最高位为符号）
      const signBit = 2 ** (8 * low4 - 1);
      if (v >= signBit) v -= 2 ** (8 * low4);
      return { value: v, offset: p + low4 };
    }

    case FT.UNSIGNED: {
      if (low4 === 0) throw new InvalidUnsignedLength('unsigned head low4=0');
      if (field.size === undefined) throw new SizeMismatch('unsigned field without size in schema');
      if (low4 !== field.size) throw new SizeMismatch(`unsigned byte_len=${low4} != IDL size=${field.size}`);
      need(buf, p, low4, 'unsigned body');
      let v = 0;
      for (let i = 0; i < low4; i++) v = v * 256 + buf[p + i];
      return { value: v, offset: p + low4 };
    }

    case FT.FLOAT:
      // §9.4：low4=1→f32, 2→f64, 3→80bit（可选扩展，本实现不支持），否则非法
      if (low4 === 1) {
        need(buf, p, 4, 'float32');
        return { value: buf.readFloatBE(p), offset: p + 4 };
      }
      if (low4 === 2) {
        need(buf, p, 8, 'float64');
        return { value: buf.readDoubleBE(p), offset: p + 8 };
      }
      throw new UnsupportedFloatType(`float subtype low4=${low4} not supported`);

    case FT.TIMESTAMP: {
      // §9.1：t = (low4 << 40) | read_uint_be(5)，44bit
      need(buf, p, 5, 'timestamp body');
      let t = low4;
      for (let i = 0; i < 5; i++) t = t * 256 + buf[p + i];
      return { value: t, offset: p + 5 };
    }

    case FT.STRING: {
      // §9.4：len = read_uint_be(low4 + 1)，长度块 1~16 字节
      need(buf, p, low4 + 1, 'string length block');
      let len = 0;
      for (let i = 0; i < low4 + 1; i++) len = len * 256 + buf[p + i];
      p += low4 + 1;
      checkLen(len, field);
      need(buf, p, len, 'string body');
      const s = buf.toString('utf8', p, p + len);
      return { value: s, offset: p + len };
    }

    case FT.BYTES: {
      need(buf, p, low4 + 1, 'bytes length block');
      let len = 0;
      for (let i = 0; i < low4 + 1; i++) len = len * 256 + buf[p + i];
      p += low4 + 1;
      checkLen(len, field);
      need(buf, p, len, 'bytes body');
      return { value: buf.subarray(p, p + len), offset: p + len };
    }

    case FT.ARRAY: {
      // §9.4：array_len = low4 <= 14 ? low4 : read_u16_be()
      let n;
      if (low4 <= 14) {
        n = low4;
      } else {
        need(buf, p, 2, 'array extended length');
        n = buf.readUInt16BE(p);
        p += 2;
      }
      checkLen(n, field);
      const elems = [];
      for (let i = 0; i < n; i++) {
        const r = decodeField(buf, p, field.element);
        elems.push(r.value);
        p = r.offset;
      }
      return { value: elems, offset: p };
    }


    default:
      // §9.4：type_id = 0x9~0xF → UnknownFieldType（新增类型 = Major 不兼容变更）
      throw new UnknownFieldType(`unknown field type id 0x${typeId.toString(16)} (head 0x${typeByte.toString(16)})`);
  }
}

/**
 * 按 schema 字段列表解码一"层"字段序列（§9.4 decode_fields）。
 * schema 字段耗尽后的剩余字节 = 对端新增的末尾字段 → 忽略（§9.4，Minor 向后兼容）。
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
  // 剩余字节忽略：新增末尾字段向后兼容（§9.4 注）
  return { value: result, offset: p };
}

// ---------- MSK 掩码（§10） ----------

/**
 * 对 Data Fields 逐字节循环 XOR（§10：encoded[i] = payload[i] ^ key[i % 4]）。
 * 编解码对称，同一函数双向使用。
 */
export function applyMask(data, key) {
  const out = Buffer.from(data); // 拷贝，不改变原缓冲
  for (let i = 0; i < out.length; i++) out[i] ^= key[i % 4];
  return out;
}
