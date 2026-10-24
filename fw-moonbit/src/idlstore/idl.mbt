// §11.1 IDL JSON → 运行时定义解析
//
// 纯动态架构：协议栈不内置任何 IDL、无代码生成/无 Stub——
// 全部服务定义运行时从 IDL 库 JSON 文本解析；接口 transport 绑定声明内嵌于 IDL，
// 协议栈运行时解析用于路由；自定义类型引用在解析时递归内联展开为 codec CType 树。
//
// Json 类型位于 moonbitlang/core/builtin（True/False 独立变体）；parse 函数在 core/json。

/// IDL 解析/契约错误（解析失败的文件跳过并记 Error 日志，§11.1）
pub(all) suberror IdlError {
  IdlError(String)
} derive(Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）；
// Show 已废弃（v0.9.2 core 迁移），调试表示统一走 Debug
pub extend IdlError with @moonbitlang/core/debug.Debug::{to_repr}

/// 接口类型（§11.1 interfaces[].type）
pub(all) enum IfKind {
  IfRpc
  IfFf
  IfEvent
} derive(Eq, Debug)

pub extend IfKind with Eq::{not_equal, equal}
pub extend IfKind with @moonbitlang/core/debug.Debug::{to_repr}

/// 接口定义（§11.1 字段说明）
pub(all) struct IdlInterface {
  name : String
  if_id : Int // 1~0x7FFF=rpc/ff、0x8000~0xFFFF=event（§11.1）
  kind : IfKind
  tcp : Bool // transport 绑定（省略时 rpc/ff=tcp、event=udp，§11.1）
  max_payload : Int // 接口级 Payload 上限（0=未声明；TCP/UDP 均适用，§11.1）
  reliable : Bool // event 推送可靠性：UDP 上 true=CON 重传；TCP 恒 NON（§11.1）
  crc : Bool // 接口级 CRC 开关（§9.6）：true 时 payload 末尾附加 2B CRC，缺省关闭
  input : Array[@codec.CType] // 参数类型（内联展开；"input": [] → 空数组）
  output : @codec.CType? // 返回值类型（缺省 None）
} derive(Eq)

pub extend IdlInterface with Eq::{not_equal, equal}

/// 事件组定义（§11.1 event_groups；Subscribe GrpId 展开依据，§7.1）
pub(all) struct IdlGroup {
  name : String
  grp_id : Int // 1~255（§7.1）
  members : Array[Int] // 组内 event if_id 列表
} derive(Eq)

pub extend IdlGroup with Eq::{not_equal, equal}

/// 服务定义（解析结果；raw 保留原文供 GetIDL 响应直传，§7.2）
pub(all) struct IdlDef {
  name : String
  svc_id : Int
  major_ver : Int
  minor_ver : Int
  interfaces : Array[IdlInterface]
  groups : Array[IdlGroup]
  raw : String
} derive(Eq)

pub extend IdlDef with Eq::{not_equal, equal}

/// 按接口号定位接口定义（订阅 tcp-event 预建连接检查等场景）
pub fn IdlDef::find_interface(self : IdlDef, if_id : Int) -> IdlInterface? {
  for it in self.interfaces {
    if it.if_id == if_id {
      return Some(it)
    }
  }
  None
}

/// 按组号定位事件组定义（组订阅展开，§7.1）
pub fn IdlDef::find_group(self : IdlDef, grp_id : Int) -> IdlGroup? {
  for g in self.groups {
    if g.grp_id == grp_id {
      return Some(g)
    }
  }
  None
}

/// 类型解析上下文（structs/enums/arrays 三处定义保留原始 JSON，递归展开时按需取用）
priv struct TypeCtx {
  structs : Map[String, Json]
  enums : Map[String, Json]
  arrays : Map[String, Json]
}

/// IDL JSON 文本 → IdlDef（解析/契约错误以 IdlError 上抛，由调用方决定跳过或失败）
pub fn parse_idl(text : String) -> IdlDef raise IdlError {
  let root = try @json.parse(text) catch { e => raise IdlError("JSON parse error: \{e}") }
  let svc = match obj_get(root, "service") {
    Some(s) => s
    None => raise IdlError("missing \"service\"")
  }
  // §11.1 type_def：三处类型定义（structs/enums/arrays）
  let ctx : TypeCtx = {
    structs: json_str_map(root, "type_def", "structs"),
    enums: json_str_map(root, "type_def", "enums"),
    arrays: json_str_map(root, "type_def", "arrays"),
  }
  let name = match obj_get(svc, "name") {
    Some(String(s)) => s
    _ => raise IdlError("missing service.name")
  }
  let svc_id = num_field(svc, "svc_id")
  let major = num_field(svc, "major_ver")
  let minor = num_field(svc, "minor_ver")
  guard svc_id > 0 && svc_id <= 0xFFFF else { raise IdlError("svc_id out of range") }
  guard major >= 0 && major <= 0xFF else { raise IdlError("major_ver out of range") }
  let interfaces : Array[IdlInterface] = []
  match obj_get(svc, "interfaces") {
    Some(Array(items)) =>
      for it in items {
        interfaces.push(parse_interface(it, ctx))
      }
    _ => raise IdlError("missing service.interfaces")
  }
  let groups : Array[IdlGroup] = []
  match obj_get(svc, "event_groups") {
    Some(Array(items)) =>
      for it in items {
        groups.push(parse_group(it))
      }
    // event_groups 可省略（服务无事件组）
    _ => ()
  }
  IdlDef::{ name, svc_id, major_ver: major, minor_ver: minor, interfaces, groups, raw: text }
}

/// 解析接口项
fn parse_interface(j : Json, ctx : TypeCtx) -> IdlInterface raise IdlError {
  let name = match obj_get(j, "name") {
    Some(String(s)) => s
    _ => raise IdlError("interface missing name")
  }
  let if_id = num_field(j, "if_id")
  guard if_id >= 1 && if_id <= 0xFFFF else { raise IdlError("\{name}: if_id out of range") }
  let kind = match obj_get(j, "type") {
    Some(String("rpc")) => IfRpc
    Some(String("ff")) => IfFf
    Some(String("event")) => IfEvent
    _ => raise IdlError("\{name}: invalid interface type")
  }
  // §11.1：transport 省略时按类型默认（rpc/ff=tcp，event=udp）
  let tcp = match obj_get(j, "transport") {
    Some(String("tcp")) => true
    Some(String("udp")) => false
    _ =>
      match kind {
        IfEvent => false
        _ => true
      }
  }
  // §11.1：max_payload 接口级上限（可省略 → 0）
  let max_payload = match obj_get(j, "max_payload") {
    Some(Number(d, ..)) => d.to_int()
    _ => 0
  }
  // §11.1：reliable 仅 event UDP 有意义（省略 false）
  let reliable = match obj_get(j, "reliable") {
    Some(True) => true
    _ => false
  }
  // §9.6：接口级 CRC 缺省关闭，声明 "crc": true 才在字段序列末尾附加 2B CRC
  let crc = match obj_get(j, "crc") {
    Some(True) => true
    _ => false
  }
  // input: [] 或 ["TypeName"]——引用名数组，逐个展开
  let input : Array[@codec.CType] = []
  match obj_get(j, "input") {
    Some(Array(items)) =>
      for it in items {
        match it {
          String(tname) => input.push(resolve_type(tname, ctx, 0))
          _ => raise IdlError("\{name}: input must be string array")
        }
      }
    // input 可省略（无参接口）
    _ => ()
  }
  // output: "TypeName" 字符串或缺省
  let output : @codec.CType? = match obj_get(j, "output") {
    Some(String(tname)) => Some(resolve_type(tname, ctx, 0))
    _ => None
  }
  IdlInterface::{ name, if_id, kind, tcp, max_payload, reliable, crc, input, output }
}

/// 解析事件组项
fn parse_group(j : Json) -> IdlGroup raise IdlError {
  let name = match obj_get(j, "name") {
    Some(String(s)) => s
    _ => raise IdlError("group missing name")
  }
  let grp_id = num_field(j, "grp_id")
  guard grp_id >= 1 && grp_id <= 0xFF else { raise IdlError("\{name}: grp_id out of range") }
  let members : Array[Int] = []
  match obj_get(j, "members") {
    Some(Array(items)) =>
      for it in items {
        match it {
          Number(d, ..) => members.push(d.to_int())
          _ => raise IdlError("\{name}: members must be number array")
        }
      }
    _ => raise IdlError("\{name}: missing members")
  }
  IdlGroup::{ name, grp_id, members }
}

/// 标量类型白名单（§11.1）：u8/u16/u32/u64、i8/i16/i32/i64、f32/f64、bool、timestamp
fn scalar_ctype(tname : String) -> @codec.CType? {
  match tname {
    "u8" => Some(@codec.CUInt(1))
    "u16" => Some(@codec.CUInt(2))
    "u32" => Some(@codec.CUInt(4))
    "u64" => Some(@codec.CUInt(8))
    "i8" => Some(@codec.CInt(1))
    "i16" => Some(@codec.CInt(2))
    "i32" => Some(@codec.CInt(4))
    "i64" => Some(@codec.CInt(8))
    "f32" => Some(@codec.CFloat(32))
    "f64" => Some(@codec.CFloat(64))
    "bool" => Some(@codec.CBool)
    "timestamp" => Some(@codec.CTimestamp)
    _ => None
  }
}

/// 长度声明合法性（§9.3）：fixed_len 与 max_len 必须恰声明其一且非负
fn check_len_decl(fixed_len : Int?, max_len : Int?, what : String) -> Unit raise IdlError {
  match (fixed_len, max_len) {
    (Some(n), None) =>
      if n < 0 {
        raise IdlError("\{what}: fixed_len must be non-negative")
      }
    (None, Some(n)) =>
      if n < 0 {
        raise IdlError("\{what}: max_len must be non-negative")
      }
    (None, None) =>
      // §9.3 强制约束：无上界则长度前缀宽度无法静态确定 → IDL 加载失败
      raise IdlError("\{what}: must declare fixed_len or max_len")
    (Some(_), Some(_)) =>
      raise IdlError("\{what}: fixed_len and max_len are mutually exclusive")
  }
}

/// v5.0 类型独立化：拒绝已取消的 size/width 属性（§11.1）
fn reject_legacy_attrs(j : Json, what : String) -> Unit raise IdlError {
  match obj_get(j, "size") {
    Some(_) => raise IdlError("\{what}: \"size\" is not allowed in v5.0 (use u8/u16/u32/u64/i8/...)")
    None => ()
  }
  match obj_get(j, "width") {
    Some(_) => raise IdlError("\{what}: \"width\" is not allowed in v5.0 (use f32/f64)")
    None => ()
  }
}

/// enum base → 底层整型 CType（§9.2/§11.1：默认 u8，可 i8 等支持负值）
fn enum_base_ctype(base : String, tname : String) -> @codec.CType raise IdlError {
  match base {
    "u8" => @codec.CUInt(1)
    "u16" => @codec.CUInt(2)
    "u32" => @codec.CUInt(4)
    "u64" => @codec.CUInt(8)
    "i8" => @codec.CInt(1)
    "i16" => @codec.CInt(2)
    "i32" => @codec.CInt(4)
    "i64" => @codec.CInt(8)
    _ => raise IdlError("enum \{tname}: unsupported base \{base}")
  }
}

/// enum values 校验（§11.1）：值必须在 base 值域内且互不重复
fn check_enum_values(j : Json, base : @codec.CType, tname : String) -> Unit raise IdlError {
  let (signed, width) = match base {
    @codec.CUInt(n) => (false, n)
    @codec.CInt(n) => (true, n)
    _ => raise IdlError("enum \{tname}: invalid base type")
  }
  match obj_get(j, "values") {
    Some(Object(m)) => {
      let seen : Array[Int] = []
      for _k, v in m {
        let n = match v {
          Number(d, ..) => d.to_int()
          _ => raise IdlError("enum \{tname}: value must be a number")
        }
        // 值域校验（§9.2；u64/i64 全值域仅校验符号侧）
        let bits = width * 8
        let in_range = if signed {
          if bits == 64 {
            true
          } else {
            n >= -(1 << (bits - 1)) && n <= (1 << (bits - 1)) - 1
          }
        } else if bits == 64 {
          n >= 0
        } else {
          n >= 0 && n <= (1 << bits) - 1
        }
        guard in_range else {
          raise IdlError("enum \{tname}: value \{n} out of base range")
        }
        // 重复值检测（§11.1 values 互不重复）
        let mut dup = false
        for s in seen {
          if s == n {
            dup = true
          }
        }
        guard !dup else {
          raise IdlError("enum \{tname}: duplicate value \{n}")
        }
        seen.push(n)
      }
    }
    Some(_) => raise IdlError("enum \{tname}: values must be an object")
    None => ()
  }
}

/// 类型名解析（structs/enums/arrays 引用 + 标量白名单；depth 防循环引用）
fn resolve_type(tname : String, ctx : TypeCtx, depth : Int) -> @codec.CType raise IdlError {
  guard depth <= 32 else { raise IdlError("type nesting too deep (cyclic reference?): \{tname}") }
  // §11.1 标量类型白名单（v5.0 类型独立化，无 size/width）
  match scalar_ctype(tname) {
    Some(t) => return t
    None => ()
  }
  // f80 为可选扩展：本实现不支持 → IDL 加载失败（§9.2/测试 1.12）
  match tname {
    "f80" => raise IdlError("f80: unsupported on this implementation")
    // 非白名单类型名（§11.1）
    "unsigned" | "signed" | "float" =>
      raise IdlError("\{tname}: type is not allowed (use u8/u16/u32/u64/i8/i16/i32/i64/f32/f64)")
    // string/bytes/array 必须由字段/数组定义携带长度声明，不能作为裸引用
    "string" | "bytes" | "array" =>
      raise IdlError("\{tname}: must declare fixed_len or max_len at field/array definition")
    _ => ()
  }
  // enums：线格式 = base 声明的整型裸值（§9.2），未知值透传
  match ctx.enums.get(tname) {
    Some(j) => {
      reject_legacy_attrs(j, "enum \{tname}")
      // v5.0：enum 基类型改由 base 声明（默认 u8），旧 "type"/"size" 格式不再允许
      match obj_get(j, "type") {
        Some(_) => raise IdlError("enum \{tname}: use \"base\" instead of \"type\" in v5.0")
        None => ()
      }
      let base = match obj_get(j, "base") {
        Some(String(s)) => s
        _ => "u8"
      }
      let ct = enum_base_ctype(base, tname)
      check_enum_values(j, ct, tname)
      return ct
    }
    None => ()
  }
  // arrays：{ fixed_len / max_len, element_type }（v5.0 不再写 "type":"array"）
  match ctx.arrays.get(tname) {
    Some(j) => {
      let fixed = opt_num(j, "fixed_len")
      let maxl = opt_num(j, "max_len")
      check_len_decl(fixed, maxl, "array \{tname}")
      let elem = match obj_get(j, "element_type") {
        Some(String(en)) => resolve_type(en, ctx, depth + 1)
        _ => raise IdlError("array \{tname}: missing element_type")
      }
      return @codec.CArray(elem, fixed, maxl)
    }
    None => ()
  }
  // structs：字段数组 → CStruct 内联展开
  match ctx.structs.get(tname) {
    Some(j) => {
      let fields : Array[@codec.CField] = []
      match j {
        Array(items) =>
          for it in items {
            fields.push(parse_field(it, ctx, depth + 1))
          }
        _ => raise IdlError("struct \{tname}: must be field array")
      }
      return @codec.CStruct(fields)
    }
    None => ()
  }
  // 未知的类型引用
  raise IdlError("unknown type: \{tname}")
}

/// 解析 struct 字段对象 → CField（type 为标量白名单类型名或自定义类型引用）
fn parse_field(j : Json, ctx : TypeCtx, depth : Int) -> @codec.CField raise IdlError {
  let name = match obj_get(j, "name") {
    Some(String(s)) => s
    _ => raise IdlError("field missing name")
  }
  // §11.1 v5.0：全部字段必填，IDL 中出现 optional → schema 错误
  match obj_get(j, "optional") {
    Some(_) => raise IdlError("\{name}: optional is not supported in v5.0")
    None => ()
  }
  reject_legacy_attrs(j, name)
  let tname = match obj_get(j, "type") {
    Some(String(s)) => s
    _ => raise IdlError("\{name}: missing type")
  }
  let ctype = match tname {
    // §9.3 string/bytes：必须声明 fixed_len 或 max_len
    "string" => {
      let fixed = opt_num(j, "fixed_len")
      let maxl = opt_num(j, "max_len")
      check_len_decl(fixed, maxl, name)
      @codec.CString(fixed, maxl)
    }
    "bytes" => {
      let fixed = opt_num(j, "fixed_len")
      let maxl = opt_num(j, "max_len")
      check_len_decl(fixed, maxl, name)
      @codec.CBytes(fixed, maxl)
    }
    // §9.4 内联数组字段：{ "type":"array", fixed_len/max_len, element_type }
    "array" => {
      let fixed = opt_num(j, "fixed_len")
      let maxl = opt_num(j, "max_len")
      check_len_decl(fixed, maxl, name)
      let elem = match obj_get(j, "element_type") {
        Some(String(en)) => resolve_type(en, ctx, depth + 1)
        _ => raise IdlError("\{name}: missing element_type")
      }
      @codec.CArray(elem, fixed, maxl)
    }
    // 标量白名单 + 自定义类型引用（struct/enum/array 递归展开；§9.4 任意嵌套）
    _ => resolve_type(tname, ctx, depth)
  }
  @codec.CField::{ name, ctype }
}

/// JSON 对象取键（非对象 → None）
fn obj_get(j : Json, key : String) -> Json? {
  match j {
    Object(map) => map.get(key)
    _ => None
  }
}

/// 取数字字段（缺失/非数字 → 报错）
fn num_field(j : Json, key : String) -> Int raise IdlError {
  match obj_get(j, key) {
    Some(Number(d, ..)) => d.to_int()
    _ => raise IdlError("missing or invalid number field: \{key}")
  }
}

/// 取可选数字字段
fn opt_num(j : Json, key : String) -> Int? {
  match obj_get(j, key) {
    Some(Number(d, ..)) => Some(d.to_int())
    _ => None
  }
}

/// 取 type_def.<key> 下的字符串键映射表（structs/enums/arrays；缺失 → 空表）
fn json_str_map(root : Json, section : String, key : String) -> Map[String, Json] {
  let m : Map[String, Json] = Map([], capacity=8)
  match obj_get(root, section) {
    Some(sec) =>
      match obj_get(sec, key) {
        Some(Object(entries)) => {
          for k, v in entries {
            m[k] = v
          }
        }
        _ => ()
      }
    None => ()
  }
  m
}
