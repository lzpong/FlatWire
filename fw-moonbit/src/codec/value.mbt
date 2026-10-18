/// §9 结构化数据字段 —— 值模型与类型 Schema
///
/// 应用层 payload 的统一表示：协议栈按本地 IDL 库动态编解码（§13 payload 语义），
/// 应用不直接操作线格式字节。

/// 协议数据字段值（§9.1 字段类型的运行时表示）
pub(all) enum FWValue {
  /// null：仅 optional 字段合法（§9.1 类型 0）
  VNull
  /// bool：线格式 low4∈{0,1}（§9.1 类型 1）
  VBool(Bool)
  /// signed：恒定宽度，线上宽度恒等于 IDL size（§9.2）
  VSigned(Int64)
  /// unsigned：恒定宽度（§9.2）
  VUnsigned(Int64)
  /// float：width=32 时按 IEEE754 单精度编码，64 双精度（§9.1 类型 4）
  VFloat(Double)
  /// timestamp：44bit，基准 2000/1/1 UTC 毫秒（§9.1 类型 5）
  VTimestamp(Int64)
  /// string：UTF-8 + 长度前缀（§9.1 类型 6）
  VString(String)
  /// bytes：长度前缀 + 原始数据（§9.1 类型 7）
  VBytes(Bytes)
  /// array：长度字段 + 逐元素（§9.1 类型 8 / §9.3）
  VArray(Array[FWValue])
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）；
// Show 已废弃（v0.9.2 core 迁移），调试表示统一走 Debug
pub extend FWValue with Eq::{not_equal, equal}
pub extend FWValue with @moonbitlang/core/debug.Debug::{to_repr}

/// 字段类型（由 IDL 类型定义展开而来；引用在 IDL 加载时完成解析）
pub(all) enum CType {
  CBool
  /// signed(size 1~15)，恒定宽度校验位（§9.2）
  CSigned(Int)
  /// unsigned(size 1~15)
  CUnsigned(Int)
  /// float width ∈ {32, 64, 80}；80 为可选扩展（§9.1 类型 4）
  CFloat(Int)
  CTimestamp
  /// string：fixed_len 定长 / max_len 变长上限（§9.2 定长类型）
  CString(Int?, Int?)
  /// bytes：同上
  CBytes(Int?, Int?)
  /// array：元素类型 + fixed_len / max_len（元素个数）
  CArray(CType, Int?, Int?)
  /// 结构体引用（IDL 加载时内联展开字段组；§9.3 结构体 = 字段序列无额外标记）
  CStruct(Array[CField])
} derive(Eq, Debug)

pub extend CType with Eq::{not_equal, equal}
pub extend CType with @moonbitlang/core/debug.Debug::{to_repr}

/// 结构体字段定义（§11.1 IDL 字段说明）
pub(all) struct CField {
  name : String
  ctype : CType
  /// optional=true 时可编码为 null（§11.1 optional）
  optional : Bool
} derive(Eq, Debug)

pub extend CField with Eq::{not_equal, equal}
pub extend CField with @moonbitlang/core/debug.Debug::{to_repr}

/// 定长/变长上限约束的解码校验（§9.4 check_len）
pub fn check_len_constraint(
  len : Int,
  fixed_len : Int?,
  max_len : Int?,
  what : String
) -> Result[Unit, String] {
  match fixed_len {
    Some(n) =>
      if len != n {
        // §9.2 定长：长度值恒为 N，解码校验 实际长度 == N
        Err("\{what}: fixed_len mismatch, expect \{n}, got \{len}")
      } else {
        Ok(())
      }
    None =>
      match max_len {
        Some(n) =>
          if len > n {
            // §9.2 max_len：实际长度 ≤ N（IDL 级超限 → 0x20，测试用例 1.22）
            Err("\{what}: max_len exceeded, limit \{n}, got \{len}")
          } else {
            Ok(())
          }
        None => Ok(())
      }
  }
}
