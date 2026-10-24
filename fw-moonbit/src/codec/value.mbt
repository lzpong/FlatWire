/// §9 结构化数据字段 —— v5.0 值模型与类型 Schema
///
/// v5.0 裸字节编码（§9.1）：字段按 IDL schema 顺序裸值连续编码——
/// 无字段头、无类型标记、无 null/optional 标记；宽度与长度前缀由 IDL 静态确定。
///
/// 应用层 payload 的统一表示：协议栈按本地 IDL 库动态编解码（§13 payload 语义），
/// 应用不直接操作线格式字节。

/// 协议数据字段值（§9.2 类型编码的运行时表示）
pub(all) enum FWValue {
  /// bool：线格式 0x00 / 0x01（§9.2）
  VBool(Bool)
  /// u8/u16/u32/u64：无符号大端；以 Int64 位模式承载（u64 全值域按位模式表示）
  VUInt(Int64)
  /// i8/i16/i32/i64：二进制补码大端
  VSInt(Int64)
  /// f32/f64：IEEE754 大端（f80 可选扩展，本实现不支持）
  VFloat(Double)
  /// timestamp：6B 48bit 毫秒，基准 2000-01-01 00:00:00 UTC（§9.2）
  VTimestamp(Int64)
  /// string：UTF-8 + 长度前缀（max_len）/ 裸 N 字节（fixed_len）（§9.3）
  VString(String)
  /// bytes：长度前缀 + 原始数据 / 裸 N 字节（§9.3）
  VBytes(Bytes)
  /// array：长度前缀（元素个数）/ 裸 N 元素（§9.4）
  VArray(Array[FWValue])
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）；
// Show 已废弃（v0.9.2 core 迁移），调试表示统一走 Debug
pub extend FWValue with Eq::{not_equal, equal}
pub extend FWValue with @moonbitlang/core/debug.Debug::{to_repr}

/// 字段类型（由 IDL 类型定义展开而来；引用在 IDL 加载时完成解析）
pub(all) enum CType {
  CBool
  /// u8/u16/u32/u64：宽度 1/2/4/8（§9.2）
  CUInt(Int)
  /// i8/i16/i32/i64：宽度 1/2/4/8（补码，§9.2）
  CInt(Int)
  /// f32/f64（4/8 字节）；f80（10）为可选扩展，本实现加载期拒绝（§9.2）
  CFloat(Int)
  /// 6B 48bit 毫秒（2000 基准，§9.2）
  CTimestamp
  /// string：fixed_len（无前缀）/ max_len（前缀宽度 w(N)），二者恰一（§9.3）
  CString(Int?, Int?)
  /// bytes：同上
  CBytes(Int?, Int?)
  /// array：元素类型 + fixed_len（元素个数）/ max_len（§9.4）
  CArray(CType, Int?, Int?)
  /// 结构体引用（IDL 加载时内联展开字段组；字段裸排无边界，§9.4）
  CStruct(Array[CField])
} derive(Eq, Debug)

pub extend CType with Eq::{not_equal, equal}
pub extend CType with @moonbitlang/core/debug.Debug::{to_repr}

/// 结构体字段定义（§11.1 IDL 字段说明；v5.0 全部字段必填，无 optional）
pub(all) struct CField {
  name : String
  ctype : CType
} derive(Eq, Debug)

pub extend CField with Eq::{not_equal, equal}
pub extend CField with @moonbitlang/core/debug.Debug::{to_repr}

/// §9.3 长度前缀宽度 w(N)：N≤255→1B，N≤65535→2B，N>65535→4B
pub fn len_prefix_width(max_len : Int) -> Int {
  if max_len <= 0xFF {
    1
  } else if max_len <= 0xFFFF {
    2
  } else {
    4
  }
}

/// 长度声明合法性（§9.3 强制约束）：fixed_len 与 max_len 必须恰声明其一
fn len_decl_error(what : String) -> Result[Unit, String] {
  Err("\{what}: must declare exactly one of fixed_len / max_len")
}

/// 定长/变长上限约束的编解码校验（§9.3）
///
/// - `fixed_len=N`：长度值必须恰为 N（无前缀）
/// - `max_len=N`：实际长度 ≤ N（前缀宽度 w(N)）
/// - 二者都缺（或同时声明）→ 契约错误（IDL 加载期已拦截，此处兜底）
pub fn check_len_constraint(
  len : Int,
  fixed_len : Int?,
  max_len : Int?,
  what : String
) -> Result[Unit, String] {
  match (fixed_len, max_len) {
    (Some(n), None) =>
      if n < 0 {
        Err("\{what}: fixed_len must be non-negative")
      } else if len != n {
        Err("\{what}: fixed_len mismatch, expect \{n}, got \{len}")
      } else {
        Ok(())
      }
    (None, Some(n)) =>
      if n < 0 {
        Err("\{what}: max_len must be non-negative")
      } else if len > n {
        Err("\{what}: max_len exceeded, limit \{n}, got \{len}")
      } else {
        Ok(())
      }
    _ => len_decl_error(what)
  }
}
