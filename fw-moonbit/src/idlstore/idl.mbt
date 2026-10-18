// §11.1 IDL JSON → 运行时定义解析
//
// 纯动态架构（v4.4 定案）：协议栈不内置任何 IDL、无代码生成/无 Stub——
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
  IdlInterface::{ name, if_id, kind, tcp, max_payload, reliable, input, output }
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

/// 类型名解析（structs/enums/arrays 引用 + 基础类型内联；depth 防循环引用）
fn resolve_type(tname : String, ctx : TypeCtx, depth : Int) -> @codec.CType raise IdlError {
  guard depth <= 32 else { raise IdlError("type nesting too deep (cyclic reference?): \{tname}") }
  // 基础类型（§9.1 类型系统）
  match tname {
    "bool" => return @codec.CBool
    "timestamp" => return @codec.CTimestamp
    _ => ()
  }
  // enums：线格式 = 底层整型（§11.1），解析为恒定宽度整型
  match ctx.enums.get(tname) {
    Some(j) =>
      return match obj_get(j, "type") {
        Some(String("signed")) => @codec.CSigned(num_field(j, "size"))
        Some(String("unsigned")) => @codec.CUnsigned(num_field(j, "size"))
        _ => raise IdlError("enum \{tname}: invalid base type")
      }
    None => ()
  }
  // arrays：{ type:"array", fixed_len/max_len, element_type }
  match ctx.arrays.get(tname) {
    Some(j) => {
      // 模式位置匹配 Json.String 变体（表达式位置 String 构造不可用）；guard 条件中的 match 需括号包裹
      guard (match obj_get(j, "type") {
        Some(String("array")) => true
        _ => false
      }) else {
        raise IdlError("array \{tname}: type must be \"array\"")
      }
      let elem = match obj_get(j, "element_type") {
        Some(String(en)) => resolve_type(en, ctx, depth + 1)
        _ => raise IdlError("array \{tname}: missing element_type")
      }
      let fixed = opt_num(j, "fixed_len")
      let maxl = opt_num(j, "max_len")
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

/// 解析 struct 字段对象 → CField（type 为基础类型名或自定义类型引用）
fn parse_field(j : Json, ctx : TypeCtx, depth : Int) -> @codec.CField raise IdlError {
  let name = match obj_get(j, "name") {
    Some(String(s)) => s
    _ => raise IdlError("field missing name")
  }
  let tname = match obj_get(j, "type") {
    Some(String(s)) => s
    _ => raise IdlError("\{name}: missing type")
  }
  let optional = match obj_get(j, "optional") {
    Some(True) => true
    _ => false
  }
  let ctype = match tname {
    // §9.1 基础类型内联（size/fixed_len/max_len/width 由字段携带）
    "bool" => @codec.CBool
    "signed" => @codec.CSigned(num_field(j, "size"))
    "unsigned" => @codec.CUnsigned(num_field(j, "size"))
    "float" =>
      @codec.CFloat(
        match opt_num(j, "width") {
          Some(w) => w
          None => 64
        },
      )
    "timestamp" => @codec.CTimestamp
    "string" => @codec.CString(opt_num(j, "fixed_len"), opt_num(j, "max_len"))
    "bytes" => @codec.CBytes(opt_num(j, "fixed_len"), opt_num(j, "max_len"))
    // 自定义类型引用（struct/enum/array 递归展开；§9.3 任意嵌套）
    _ => resolve_type(tname, ctx, depth)
  }
  @codec.CField::{ name, ctype, optional }
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
