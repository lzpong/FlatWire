// ============================================================
// schema.js —— IDL 解析与接口级编解码（v5.0 §11.1 / §13 payload 语义）
//
// v5 解析要点：
//   - 类型白名单：u8/u16/u32/u64、i8/i16/i32/i64、f32/f64、f80（可选，本端不支持）、
//     bool、timestamp、string、bytes、array、struct/enum/array 类型名引用
//   - 禁止非白名单类型：`unsigned`/`signed`/`float`/`null`、`size`/`width` 属性、`optional`
//   - string/bytes/array 必须声明 `fixed_len` 或 `max_len`（且不可同时声明），
//     否则 IDL 加载失败（§9.3）
//   - enum 基类型改用 `base`（默认 u8），支持 i8 等有符号基类型；values 值域/重复校验
//   - arrays 条目不再写 `"type": "array"`，形如 { fixed_len|max_len, element_type }
//   - 构造期即全量解析（eager），保证非法定义在加载时被拒绝，而不是推迟到首次使用
//   - 接口级 CRC：`"crc": true` 时在字段序列末尾附加 2B CRC-16/CCITT-FALSE（§9.6）
//
// 纯动态架构（§11.1）：协议栈不内置 IDL，编解码由协议栈按已加载的 IDL 动态执行。
// ============================================================

import { encodeField, decodeField, INT_WIDTH, SCALAR_TYPES } from './types.js';
import { crc16 } from './crc.js';
import {
  MaxLenExceeded, UnknownFieldType, InvalidArgument, UnsupportedFloatType,
  CrcMismatch, BufferUnderrun,
} from '../errors.js';

// 基础标量类型名（IDL 字段 type / element_type 直接可用的，不含 string/bytes/array）
const BASIC_TYPES = new Set([...SCALAR_TYPES].filter((t) => t !== 'f80'));

// 非白名单类型（出现即 IDL 加载失败）
const LEGACY_TYPES = new Set(['unsigned', 'signed', 'float', 'null']);

// enum base 允许的整型集合（§11.1）
const ENUM_BASES = new Set(Object.keys(INT_WIDTH));

/** 解析后的 Schema：service 信息 + 类型索引 */
export class Schema {
  /**
   * @param {object} idl 已 JSON.parse 的 IDL 对象（§11.1 语法）
   */
  constructor(idl) {
    if (!idl || typeof idl !== 'object') throw new InvalidArgument('IDL must be an object');
    const svc = idl.service;
    if (!svc || typeof svc !== 'object' || typeof svc.svc_id !== 'number') {
      throw new InvalidArgument('IDL missing service.svc_id');
    }

    this.raw = idl;
    this.svcId = svc.svc_id;
    this.majorVer = svc.major_ver;
    this.minorVer = svc.minor_ver ?? 0;
    this.serviceName = svc.name ?? '';

    // 类型定义（三处位置：structs / arrays / enums，§11.1）
    this.structs = idl.type_def?.structs ?? {};
    this.arrays = idl.type_def?.arrays ?? {};
    this.enums = idl.type_def?.enums ?? {};

    // 接口索引：if_id → 接口定义（transport 省略时按类型默认：rpc/ff=tcp，event=udp，§11.1）
    this.interfaces = new Map();
    for (const iface of svc.interfaces ?? []) {
      if (!iface || typeof iface !== 'object') throw new InvalidArgument('IDL interface must be an object');
      if (typeof iface.if_id !== 'number') throw new InvalidArgument(`IDL interface "${iface.name}" missing if_id`);
      if (!['rpc', 'ff', 'event'].includes(iface.type)) {
        throw new InvalidArgument(`IDL interface "${iface.name}" has invalid type "${iface.type}"`);
      }
      if (iface.crc !== undefined && typeof iface.crc !== 'boolean') {
        throw new InvalidArgument(`IDL interface "${iface.name}" crc must be boolean`);
      }
      const def = {
        name: iface.name,
        if_id: iface.if_id,
        type: iface.type, // rpc | ff | event
        transport: iface.transport ?? (iface.type === 'event' ? 'udp' : 'tcp'),
        reliable: iface.reliable ?? false,
        max_payload: iface.max_payload,   // 接口级单帧 Payload 上限（TCP/UDP 均适用，§2）
        crc: iface.crc ?? false,          // true 时 payload 末尾附加 2B CRC（§9.6，缺省关闭）
        input: iface.input ?? [],         // 类型名数组
        output: iface.output ?? null,     // 单类型名
        push_policy: iface.push_policy ?? null,
      };
      if (!Array.isArray(def.input)) throw new InvalidArgument(`interface "${iface.name}" input must be array`);
      this.interfaces.set(iface.if_id, def);
    }

    // 事件组：grp_id → members(if_id 列表)（§7.1/§11.1）
    this.eventGroups = new Map();
    for (const g of svc.event_groups ?? []) {
      this.eventGroups.set(g.grp_id, g.members ?? []);
    }

    this._typeCache = new Map(); // 类型名 → 规范化字段定义（含递归展开）

    // ---- 构造期全量解析：非法定义在加载时即被拒绝（IDL 库跳过该文件，§11.1） ----
    for (const name of Object.keys(this.structs)) this.resolveType(name);
    for (const name of Object.keys(this.arrays)) this.resolveType(name);
    for (const name of Object.keys(this.enums)) this.resolveType(name);
    for (const iface of this.interfaces.values()) {
      for (const n of iface.input) this.resolveType(n);
      if (iface.output) this.resolveType(iface.output);
    }
  }

  /** 获取接口定义；不存在返回 undefined */
  getInterface(ifId) {
    return this.interfaces.get(ifId);
  }

  /** 按名称取规范化的类型定义（struct/array/enum 递归展开） */
  resolveType(name) {
    if (typeof name !== 'string') throw new InvalidArgument(`type reference must be string, got ${typeof name}`);
    if (this._typeCache.has(name)) return this._typeCache.get(name);

    let def;
    if (this.structs[name]) {
      // 结构体：N 个字段的有序组合（§9.4）
      def = {
        type: 'struct',
        name,
        fields: this.structs[name].map((f) => this._resolveField(f, `struct "${name}"`)),
      };
    } else if (this.enums[name]) {
      def = this._resolveEnum(name, this.enums[name]);
    } else if (this.arrays[name]) {
      def = this._resolveArray(name, this.arrays[name]);
    } else {
      throw new UnknownFieldType(`type "${name}" not defined in IDL (structs/arrays/enums)`);
    }
    this._typeCache.set(name, def);
    return def;
  }

  /** 解析 enum 定义：base（默认 u8）+ values（值域/重复校验，§9.2/§11.1） */
  _resolveEnum(name, e) {
    if (e.type !== undefined || e.size !== undefined || e.width !== undefined) {
      throw new InvalidArgument(`enum "${name}": v5 uses "base" only (type/size/width removed)`);
    }
    const base = e.base ?? 'u8';
    if (!ENUM_BASES.has(base)) {
      throw new InvalidArgument(`enum "${name}": base "${base}" must be one of ${[...ENUM_BASES].join('/')}`);
    }
    if (!e.values || typeof e.values !== 'object') {
      throw new InvalidArgument(`enum "${name}" missing values`);
    }
    // 值域校验 + 重复值校验（重复值 → IDL 加载失败，测试 1.29）
    const [lo, hi] = intRange(base);
    const seen = new Map(); // 值 → 名称
    for (const [k, v] of Object.entries(e.values)) {
      if (!Number.isInteger(v)) throw new InvalidArgument(`enum "${name}" value "${k}" must be integer`);
      const bv = BigInt(v);
      if (bv < lo || bv > hi) {
        throw new InvalidArgument(`enum "${name}" value "${k}"=${v} out of range [${lo}, ${hi}]`);
      }
      if (seen.has(v)) {
        throw new InvalidArgument(`enum "${name}" duplicate value ${v} ("${seen.get(v)}" / "${k}")`);
      }
      seen.set(v, k);
    }
    return { type: 'enum', name, base, values: e.values };
  }

  /** 解析 arrays 条目：{ element_type, fixed_len|max_len }（不写 "type": "array"） */
  _resolveArray(name, a) {
    if (a.type !== undefined) {
      throw new InvalidArgument(`arrays "${name}": v5 不再写 "type": "array"`);
    }
    if (typeof a.element_type !== 'string') {
      throw new InvalidArgument(`arrays "${name}" missing element_type`);
    }
    return {
      type: 'array',
      name,
      element: this._resolveTypeRef(a.element_type, `arrays "${name}".element_type`),
      ...lenDecl(a, `array "${name}"`),
    };
  }

  /** 解析单个字段定义（基础类型或类型名引用） */
  _resolveField(f, where) {
    if (!f || typeof f !== 'object') throw new InvalidArgument(`${where}: field must be an object`);
    if (typeof f.name !== 'string' || f.name === '') throw new InvalidArgument(`${where}: field missing name`);
    // v5 删除 optional（全字段必填，无 null 编码，§11.1）
    if (f.optional !== undefined) {
      throw new InvalidArgument(`${where}: field "${f.name}": "optional" is not allowed in v5`);
    }
    // 类型独立化：size/width 属性不属于 v5 IDL（§11.1）
    if (f.size !== undefined || f.width !== undefined) {
      throw new InvalidArgument(`${where}: field "${f.name}": "size"/"width" are not allowed (use u8/u16/...)`);
    }
    if (typeof f.type !== 'string') throw new InvalidArgument(`${where}: field "${f.name}" missing type`);
    if (LEGACY_TYPES.has(f.type)) {
      throw new InvalidArgument(`${where}: field "${f.name}": type "${f.type}" is not allowed`);
    }

    if (f.type === 'string' || f.type === 'bytes') {
      return { name: f.name, type: f.type, ...lenDecl(f, `${where} field "${f.name}"`) };
    }
    if (BASIC_TYPES.has(f.type)) {
      // 标量（含 bool/timestamp/f32/f64/整型）：不接受长度声明
      if (f.fixed_len !== undefined || f.max_len !== undefined) {
        throw new InvalidArgument(`${where}: field "${f.name}": fixed_len/max_len only valid for string/bytes/array`);
      }
      return { name: f.name, type: f.type };
    }
    if (f.type === 'f80') {
      // 可选扩展：本端不支持 → IDL 加载失败（§9.2）
      throw new UnsupportedFloatType(`${where}: field "${f.name}": f80 is not supported by this implementation`);
    }
    if (f.type === 'array') {
      // 内联数组字段（element_type 引用类型名）
      if (typeof f.element_type !== 'string') {
        throw new InvalidArgument(`${where}: field "${f.name}" array missing element_type`);
      }
      return {
        name: f.name,
        type: 'array',
        element: this._resolveTypeRef(f.element_type, `${where}.${f.name}.element_type`),
        ...lenDecl(f, `${where} field "${f.name}"`),
      };
    }
    // 类型名引用（struct/enum/array 定义名）——展开并保留字段名
    return { ...this.resolveType(f.type), name: f.name };
  }

  /** 解析 element_type 引用：标量（整型/浮点/bool/timestamp）或具名类型 */
  _resolveTypeRef(t, where) {
    if (t === 'f80') throw new UnsupportedFloatType(`${where}: f80 is not supported by this implementation`);
    if (t === 'string' || t === 'bytes' || t === 'array') {
      throw new InvalidArgument(`${where}: "${t}" requires its own fixed_len/max_len declaration`);
    }
    if (BASIC_TYPES.has(t)) return { type: t };
    return this.resolveType(t);
  }

  // ---------- 接口级编解码（§13 payload 语义） ----------

  _typesOf(iface, direction) {
    const names = direction === 'input' ? iface.input : (iface.output ? [iface.output] : []);
    return names.map((n) => this.resolveType(n));
  }

  /**
   * 编码接口 payload → 线格式字节。
   * input 多类型时 payload 为值数组；单类型时为单值；无类型时忽略。
   * 接口 `"crc": true` 时在字段序列末尾附加 2B CRC16（大端，§9.6）。
   */
  encodePayload(iface, direction, payload) {
    const types = this._typesOf(iface, direction);
    let buf;
    if (types.length === 0) {
      buf = Buffer.alloc(0);
    } else if (types.length === 1) {
      buf = encodeField(types[0], payload);
    } else {
      if (!Array.isArray(payload) || payload.length !== types.length) {
        throw new InvalidArgument(`interface ${iface.name} expects ${types.length} argument(s) as array`);
      }
      buf = Buffer.concat(types.map((t, i) => encodeField(t, payload[i])));
    }
    // 契约级 CRC（缺省关闭；仅数据帧接口可声明，控制帧不附加，§9.6）
    if (iface.crc) {
      const c = Buffer.alloc(2);
      c.writeUInt16BE(crc16(buf), 0); // 2B 大端附加于字段序列末尾
      buf = Buffer.concat([buf, c]);
    }
    // 接口级 max_payload 校验（§2：TCP/UDP 均适用；IDL 级超限归解码错误 0x20）
    if (iface.max_payload !== undefined && iface.max_payload !== null && buf.length > iface.max_payload) {
      throw new MaxLenExceeded(`interface ${iface.name} max_payload=${iface.max_payload} but payload is ${buf.length} byte(s)`);
    }
    return buf;
  }

  /**
   * 解码线格式字节 → 接口 payload。
   * 接口启用 CRC 时：先校验末尾 2B CRC（不匹配 → CrcMismatch，帧层回 0x20），再剥离解码。
   * 解码容忍末尾新增字段（§11.2：schema 字段耗尽后忽略剩余字节）。
   */
  decodePayload(iface, direction, buf) {
    const body = iface.crc ? this._verifyCrc(iface, buf) : buf;
    const types = this._typesOf(iface, direction);
    if (types.length === 0) return undefined;
    if (types.length === 1) return decodeField(body, 0, types[0]).value;
    // 多参数：逐类型解码为值数组
    const out = [];
    let p = 0;
    for (const t of types) {
      const r = decodeField(body, p, t);
      out.push(r.value);
      p = r.offset;
    }
    return out;
  }

  /** 校验并剥离末尾 2B CRC（§9.6：接收方先校验再解码字段） */
  _verifyCrc(iface, buf) {
    if (buf.length < 2) {
      throw new BufferUnderrun(`interface ${iface.name} crc enabled but payload is ${buf.length} byte(s)`);
    }
    const body = buf.subarray(0, buf.length - 2);
    const expect = buf.readUInt16BE(buf.length - 2);
    const actual = crc16(body);
    if (actual !== expect) {
      throw new CrcMismatch(`interface ${iface.name} CRC mismatch (expect 0x${expect.toString(16)}, got 0x${actual.toString(16)})`);
    }
    return body;
  }
}

// ---------- 模块内工具 ----------

/** 长度声明校验：fixed_len / max_len 必须恰有一个（§9.3） */
function lenDecl(def, where) {
  const hasFixed = def.fixed_len !== undefined;
  const hasMax = def.max_len !== undefined;
  if (!hasFixed && !hasMax) {
    throw new InvalidArgument(`${where}: must declare fixed_len or max_len (v5)`);
  }
  if (hasFixed && hasMax) {
    throw new InvalidArgument(`${where}: fixed_len and max_len are mutually exclusive`);
  }
  const n = hasFixed ? def.fixed_len : def.max_len;
  if (!Number.isInteger(n) || n < 0) {
    throw new InvalidArgument(`${where}: length must be non-negative integer, got ${n}`);
  }
  // 前缀宽度上限 4B（w(N)，§9.3）——超出则线上长度不可表示
  if (hasMax && n > 0xffffffff) {
    throw new InvalidArgument(`${where}: max_len ${n} exceeds 4B prefix capacity`);
  }
  return hasFixed ? { fixed_len: n } : { max_len: n };
}

/** 整型类型值域 [lo, hi]（BigInt，§9.2） */
function intRange(type) {
  const w = INT_WIDTH[type];
  const bits = BigInt(8 * w);
  if (type[0] === 'i') return [-(1n << (bits - 1n)), (1n << (bits - 1n)) - 1n];
  return [0n, (1n << bits) - 1n];
}
