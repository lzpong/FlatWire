// §9.1/§9.2/§9.3 字段编码器：按 CType schema 将 FWValue 序列化为线格式字节
//
// 编码规则要点：
// - signed/unsigned 恒定宽度：线上宽度恒等于 IDL size，low4 = size 作校验位（§9.2）
// - fixed_len 校验 实际长度 == N；max_len 校验 实际长度 ≤ N（§9.2 约束校验）
// - array：count ≤ 14 内联 0x8X；15~65535 用 0x8F + 2B 大端（§9.1 类型 8）
// - MSK/CRC 由 payload 级辅助函数处理（§9.6/§10），不混入字段编码

/// 编码错误（解码对称；边界转换由上层映射为 RST(0x20)）
pub(all) suberror CodecError {
  CodecError(String)
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend CodecError with Eq::{not_equal, equal}
pub extend CodecError with @moonbitlang/core/debug.Debug::{to_repr}

/// 约束校验失败统一转编码错误（前置 match，本版本不支持后置 match 语句）
fn check_or_raise(len : Int, fixed_len : Int?, max_len : Int?, name : String) -> Unit raise CodecError {
  match check_len_constraint(len, fixed_len, max_len, name) {
    Err(msg) => raise CodecError(msg)
    Ok(_) => ()
  }
}

/// 编码顶层字段序列（§9.4：顶层字段数固定，按 schema 顺序）
pub fn encode_fields(schema : Array[CField], values : Array[FWValue]) -> Bytes raise CodecError {
  // 字段数必须与 schema 一致（§9.4 顶层按序编码）
  guard schema.length() == values.length() else {
    raise CodecError("field count mismatch: schema=\{schema.length()} values=\{values.length()}")
  }
  let buf = @buffer.Buffer(size_hint=256)
  // raise 函数调用隐式向上传播（本版本无 `!` 后缀）
  for i, f in schema {
    encode_field(buf, values[i], f.ctype, f.optional, f.name)
  }
  buf.to_bytes()
}

/// 编码单个字段（含 1B 字段头 + payload）
pub fn encode_field(
  buf : @buffer.Buffer,
  value : FWValue,
  ctype : CType,
  optional : Bool,
  name : String
) -> Unit raise CodecError {
  match (value, ctype) {
    // §9.1 类型 0：null 仅 optional 字段合法（测试 1.5）
    (VNull, _) =>
      if optional {
        buf.write_byte(b'\x00')
      } else {
        raise CodecError("\{name}: null on non-optional field")
      }
    // §9.1 类型 1：bool 内联 low4（1.6：true=0x11 / false=0x10）
    (VBool(b), CBool) => buf.write_byte((0x10 | (if b { 1 } else { 0 })).to_byte())
    // §9.2 恒定宽度 signed：low4 = size 校验位（1.7）
    (VSigned(v), CSigned(n)) => {
      buf.write_byte((0x20 | n).to_byte())
      write_signed_be(buf, v, n)
    }
    // §9.2 恒定宽度 unsigned（1.8）
    (VUnsigned(v), CUnsigned(n)) => {
      buf.write_byte((0x30 | n).to_byte())
      write_unsigned_be(buf, v, n)
    }
    // §9.1 类型 4：float（80bit 为可选扩展，不支持编码）
    (VFloat(d), CFloat(w)) =>
      match w {
        32 => {
          buf.write_byte(b'\x41')
          buf.write_float_be(Float::from_double(d))
        }
        64 => {
          buf.write_byte(b'\x42')
          buf.write_double_be(d)
        }
        _ => raise CodecError("\{name}: unsupported float width \{w}")
      }
    // §9.1 类型 5：timestamp 高 4bit + 低 40bit（1.13）
    (VTimestamp(t), CTimestamp) => {
      let high = ((t >> 40) & 0xFL).to_int()
      buf.write_byte((0x50 | high).to_byte())
      write_uint_be64(buf, t, 5)
    }
    // §9.1 类型 6：string（UTF-8 + 长度前缀，1.14）
    (VString(s), CString(fixed_len, max_len)) => {
      let bytes = @utf8.encode(s)
      check_or_raise(bytes.length(), fixed_len, max_len, name)
      write_len_prefixed(buf, 0x60, bytes)
    }
    // §9.1 类型 7：bytes（1.15）
    (VBytes(b), CBytes(fixed_len, max_len)) => {
      check_or_raise(b.length(), fixed_len, max_len, name)
      write_len_prefixed(buf, 0x70, b)
    }
    // §9.1 类型 8 / §9.3：array（长度字段 + 逐元素，1.16/1.17/1.20/1.21）
    (VArray(arr), CArray(elem, fixed_len, max_len)) => {
      let n = arr.length()
      // 定长/上限校验（元素个数维度）
      check_or_raise(n, fixed_len, max_len, name)
      if n <= 14 {
        // 内联长度 0x8X
        buf.write_byte((0x80 | n).to_byte())
      } else if n <= 0xFFFF {
        // 扩展长度 0x8F + 2B 大端
        buf.write_byte(b'\x8F')
        buf.write_byte(((n >> 8) & 0xFF).to_byte())
        buf.write_byte((n & 0xFF).to_byte())
      } else {
        raise CodecError("\{name}: array count \{n} exceeds 65535")
      }
      for v in arr {
        // 数组元素按元素类型编码，无 optional 语义（§9.3）；元素为 struct 时展开字段序列
        match (v, elem) {
          (VArray(vals), CStruct(fields)) => encode_struct_fields(buf, fields, vals, name)
          _ => encode_field(buf, v, elem, false, name)
        }
      }
    }
    // §9.3 结构体值：字段序列连续编码（input/output 引用 struct 的顶层形态）
    (VArray(vals), CStruct(fields)) => encode_struct_fields(buf, fields, vals, name)
    // 值类型与 schema 不匹配
    _ => raise CodecError("\{name}: value \{Repr(value)} does not match type \{ctype_to_str(ctype)}")
  }
}

/// 编码结构体字段序列（值数与 schema 对齐；§9.3 结构体 = 字段连续编码无额外标记）
fn encode_struct_fields(
  buf : @buffer.Buffer,
  fields : Array[CField],
  vals : Array[FWValue],
  name : String
) -> Unit raise CodecError {
  guard fields.length() == vals.length() else {
    raise CodecError("\{name}: struct field count mismatch: schema=\{fields.length()} values=\{vals.length()}")
  }
  for i, f in fields {
    encode_field(buf, vals[i], f.ctype, f.optional, f.name)
  }
}

/// 写变长前缀字段（string/bytes 共用）：字段头 + 宽度 low4=w-1 的长度 + 内容（§9.2）
fn write_len_prefixed(buf : @buffer.Buffer, head_base : Int, data : Bytes) -> Unit {
  let n = data.length()
  let w = min_len_field_bytes(n)
  buf.write_byte((head_base | (w - 1)).to_byte())
  write_uint_be(buf, n, w)
  buf.write_bytes(data)
}

/// 长度字段最小宽度 1~4（§9.2：low4+1 字节；Int 上限 2^31-1，4 字节足够）
fn min_len_field_bytes(len : Int) -> Int {
  if len <= 0xFF {
    1
  } else if len <= 0xFFFF {
    2
  } else if len <= 0xFFFFFF {
    3
  } else {
    4
  }
}

/// 写 n 字节大端无符号（Int，n ≤ 8；纯计算不抛错）
fn write_uint_be(buf : @buffer.Buffer, v : Int, n : Int) -> Unit {
  let mut k = n - 1
  while k >= 0 {
    buf.write_byte(((v >> (8 * k)) & 0xFF).to_byte())
    k = k - 1
  }
}

/// 写 n 字节大端 Int64（n ≤ 8 用于 timestamp 低 40bit 等；纯计算不抛错）
fn write_uint_be64(buf : @buffer.Buffer, v : Int64, n : Int) -> Unit {
  let mut k = n - 1
  while k >= 0 {
    buf.write_byte(((v >> (8 * k)) & 0xFFL).to_byte())
    k = k - 1
  }
}

/// 写恒定宽度 signed：n 字节大端补码；n > 8 时高位为符号扩展（值域受限见 README 偏差说明）
fn write_signed_be(buf : @buffer.Buffer, v : Int64, n : Int) -> Unit {
  let mut k = n - 1
  while k >= 0 {
    buf.write_byte(((v >> (8 * k)) & 0xFFL).to_byte())
    k = k - 1
  }
}

/// 写恒定宽度 unsigned：n 字节大端；n > 8 时高位补 0（值 < 2^63 无损）
fn write_unsigned_be(buf : @buffer.Buffer, v : Int64, n : Int) -> Unit raise CodecError {
  guard v >= 0L else {
    raise CodecError("unsigned value is negative: \{v}")
  }
  let mut k = n - 1
  while k >= 0 {
    buf.write_byte(((v >> (8 * k)) & 0xFFL).to_byte())
    k = k - 1
  }
}

/// CType 的人读表示（错误信息用）
pub fn ctype_to_str(t : CType) -> String {
  match t {
    CBool => "bool"
    CSigned(n) => "signed(\{n})"
    CUnsigned(n) => "unsigned(\{n})"
    CFloat(w) => "float(\{w})"
    CTimestamp => "timestamp"
    CString(f, m) => "string(fixed=\{Repr(f)},max=\{Repr(m)})"
    CBytes(f, m) => "bytes(fixed=\{Repr(f)},max=\{Repr(m)})"
    CArray(_, f, m) => "array(fixed=\{Repr(f)},max=\{Repr(m)})"
    CStruct(_) => "struct"
  }
}
