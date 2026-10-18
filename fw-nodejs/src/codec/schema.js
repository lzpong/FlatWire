// ============================================================
// schema.js —— IDL 解析与接口级编解码（§11.1 / §13 payload 语义）
//
// 纯动态架构（§11.1）：协议栈不内置 IDL，编解码由协议栈按已加载的
// IDL 动态执行。应用传入/接收的 payload 为按 IDL 定义的结构化字段值
// 集合（JS 对象/数组/标量），协议栈负责线格式转换。
// ============================================================

import { encodeField, decodeField, decodeStructFields } from './types.js';
import { MaxLenExceeded, UnknownFieldType, InvalidArgument } from '../errors.js';

// 基础字段类型名（IDL 字段 type 直接使用的）
const BASIC_TYPES = new Set(['null', 'bool', 'signed', 'unsigned', 'float', 'timestamp', 'string', 'bytes']);

/** 解析后的 Schema：service 信息 + 类型索引 */
export class Schema {
  /**
   * @param {object} idl 已 JSON.parse 的 IDL 对象（§11.1 语法）
   */
  constructor(idl) {
    if (!idl || typeof idl !== 'object') throw new InvalidArgument('IDL must be an object');
    const svc = idl.service;
    if (!svc || typeof svc.svc_id !== 'number') throw new InvalidArgument('IDL missing service.svc_id');

    this.raw = idl;
    this.svcId = svc.svc_id;
    this.majorVer = svc.major_ver;
    this.minorVer = svc.minor_ver ?? 0;
    this.serviceName = svc.name ?? '';

    // 接口索引：if_id → 接口定义（transport 省略时按类型默认：rpc/ff=tcp，event=udp，§11.1）
    this.interfaces = new Map();
    for (const iface of svc.interfaces ?? []) {
      const def = {
        name: iface.name,
        if_id: iface.if_id,
        type: iface.type, // rpc | ff | event
        transport: iface.transport ?? (iface.type === 'event' ? 'udp' : 'tcp'),
        reliable: iface.reliable ?? false,
        max_payload: iface.max_payload,   // 接口级单帧 Payload 上限（TCP/UDP 均适用，§2）
        crc: iface.crc ?? false,          // 实现约定扩展：接口契约级 CRC（§9.6 "CRC 作为服务契约约定"）
        input: iface.input ?? [],         // 类型名数组
        output: iface.output ?? null,     // 单类型名
        push_policy: iface.push_policy ?? null,
      };
      this.interfaces.set(iface.if_id, def);
    }

    // 事件组：grp_id → members(if_id 列表)（§7.1/§11.1）
    this.eventGroups = new Map();
    for (const g of svc.event_groups ?? []) {
      this.eventGroups.set(g.grp_id, g.members ?? []);
    }

    this.structs = idl.type_def?.structs ?? {};
    this.arrays = idl.type_def?.arrays ?? {};
    this.enums = idl.type_def?.enums ?? {};

    this._typeCache = new Map(); // 类型名 → 规范化字段定义（含递归展开）
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
      // 结构体：N 个字段的有序组合（§9.3）
      def = {
        type: 'struct',
        name,
        fields: this.structs[name].map((f) => this._resolveField(f)),
      };
    } else if (this.enums[name]) {
      // 枚举：线格式 = 底层整型（§11.1）
      const e = this.enums[name];
      def = {
        type: 'enum',
        name,
        base: e.type,       // 'unsigned' | 'signed'
        size: e.size,
        values: e.values,   // 名称 → 整数
      };
    } else if (this.arrays[name]) {
      // 数组类型：element_type 可为 struct/array/enum（任意嵌套，§9.3/§11.1）
      const a = this.arrays[name];
      def = {
        type: 'array',
        name,
        element: this.resolveType(a.element_type),
        fixed_len: a.fixed_len,
        max_len: a.max_len,
      };
    } else {
      throw new UnknownFieldType(`type "${name}" not defined in IDL (structs/arrays/enums)`);
    }
    this._typeCache.set(name, def);
    return def;
  }

  /** 解析单个字段定义（基础类型或类型名引用） */
  _resolveField(f) {
    const t = f.type;
    if (BASIC_TYPES.has(t)) {
      return {
        name: f.name,
        type: t,
        optional: f.optional ?? false,
        size: f.size,
        width: f.width,
        fixed_len: f.fixed_len,
        max_len: f.max_len,
      };
    }
    if (t === 'array') {
      // 内联数组字段定义（element_type 引用其他类型）
      return {
        name: f.name,
        type: 'array',
        optional: f.optional ?? false,
        element: this.resolveType(f.element_type),
        fixed_len: f.fixed_len,
        max_len: f.max_len,
      };
    }
    // 类型名引用（struct/enum/array 定义名）——展开并保留字段名与 optional
    const resolved = this.resolveType(t);
    return { ...resolved, name: f.name, optional: f.optional ?? false };
  }

  // ---------- 接口级编解码（§13 payload 语义） ----------

  _typesOf(iface, direction) {
    const names = direction === 'input' ? iface.input : (iface.output ? [iface.output] : []);
    return names.map((n) => this.resolveType(n));
  }

  /**
   * 编码接口 payload → 线格式字节。
   * input 多类型时 payload 为值数组；单类型时为单值；无类型时忽略。
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
    // 接口级 max_payload 校验（§2：TCP/UDP 均适用；IDL 级超限归解码错误 0x20）
    if (iface.max_payload !== undefined && iface.max_payload !== null && buf.length > iface.max_payload) {
      throw new MaxLenExceeded(`interface ${iface.name} max_payload=${iface.max_payload} but payload is ${buf.length} byte(s)`);
    }
    return buf;
  }

  /**
   * 解码线格式字节 → 接口 payload。
   * 解码容忍末尾新增字段（§9.4：schema 字段耗尽后忽略剩余字节）。
   */
  decodePayload(iface, direction, buf) {
    const types = this._typesOf(iface, direction);
    if (types.length === 0) return undefined;
    if (types.length === 1) {
      const [t] = types;
      if (t.type === 'struct') {
        // struct 顶层：字段序列无外层头（§9.3 扁平编码）
        return decodeStructFields(buf, 0, t.fields).value;
      }
      return decodeField(buf, 0, t).value;
    }
    // 多参数：逐类型解码为值数组
    const out = [];
    let p = 0;
    for (const t of types) {
      if (t.type === 'struct') {
        const r = decodeStructFields(buf, p, t.fields);
        out.push(r.value);
        p = r.offset;
      } else {
        const r = decodeField(buf, p, t);
        out.push(r.value);
        p = r.offset;
      }
    }
    return out;
  }
}
