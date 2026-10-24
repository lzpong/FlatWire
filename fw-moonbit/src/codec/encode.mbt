// §9 字段编码器（v5.0 裸字节编码）：按 CType schema 将 FWValue 序列化为线格式字节
//
// 编码规则要点（§9.1~§9.4）：
// - 无字段头/类型标记：字段按 schema 顺序裸值大端连续编码
// - u8~u64 / i8~i64 按 IDL 宽度恒定输出并校验值域（补码用于有符号）
// - bool 仅 0x00/0x01；timestamp 6B 48bit；f32/f64 IEEE754 大端（f80 不支持）
// - fixed_len：无长度前缀，输入必须恰为 N；max_len：前缀宽度 w(N) 大端
// - MSK/CRC 由 payload 级辅助函数处理（§9.6/§10），不混入字段编码

/// 编码错误（解码对称；边界转换由上层映射为 RST(0x20)）
pub(all) suberror CodecError {
  CodecError(String)
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend CodecError with Eq::{not_equal, equal}
pub extend CodecError with @moonbitlang/core/debug.Debug::{to_repr}

/// §9.2 timestamp 上限：2^48-1（2000 基准毫秒）
const TS_MAX : Int64 = 281474976710655L

/// 约束校验失败统一转编码错误（前置 match，本版本不支持后置 match 语句）
fn check_or_raise(len : Int, fixed_len : Int?, max_len : Int?, name : String) -> Unit raise CodecError {
  match check_len_constraint(len, fixed_len, max_len, name) {
    Err(msg) => raise CodecError(msg)
    Ok(_) => ()
  }
}

/// 宽度合法性（IDL 白名单：1/2/4/8 字节）
fn check_width(n : Int, name : String) -> Unit raise CodecError {
  guard n == 1 || n == 2 || n == 4 || n == 8 else {
    raise CodecError("\{name}: invalid integer width \{n}")
  }
}

/// 无符号值域校验（§9.2）：n<8 时 0 ≤ v < 2^(8n)；n=8 按 64bit 位模式承载全值域
fn check_uint_range(v : Int64, n : Int, name : String) -> Unit raise CodecError {
  check_width(n, name)
  if n < 8 {
    let max = (1L << (n * 8)) - 1L
    guard v >= 0L && v <= max else {
      raise CodecError("\{name}: u\{n * 8} out of range: \{v}")
    }
  }
}

/// 有符号值域校验（§9.2）：n<8 时 -2^(8n-1) ≤ v ≤ 2^(8n-1)-1；n=8 为 Int64 全值域
fn check_int_range(v : Int64, n : Int, name : String) -> Unit raise CodecError {
  check_width(n, name)
  if n < 8 {
    let bits = n * 8
    let min = -(1L << (bits - 1))
    let max = (1L << (bits - 1)) - 1L
    guard v >= min && v <= max else {
      raise CodecError("\{name}: i\{bits} out of range: \{v}")
    }
  }
}

/// 编码顶层字段序列（§9.1：字段按 schema 顺序裸排）
pub fn encode_fields(schema : Array[CField], values : Array[FWValue]) -> Bytes raise CodecError {
  // 字段数必须与 schema 一致（§9.1 顶层按序编码）
  guard schema.length() == values.length() else {
    raise CodecError("field count mismatch: schema=\{schema.length()} values=\{values.length()}")
  }
  let buf = @buffer.Buffer(size_hint=256)
  // raise 函数调用隐式向上传播（本版本无 `!` 后缀）
  for i, f in schema {
    encode_field(buf, values[i], f.ctype, f.name)
  }
  buf.to_bytes()
}

/// 编码单个字段（裸值，无字段头）
pub fn encode_field(
  buf : @buffer.Buffer,
  value : FWValue,
  ctype : CType,
  name : String
) -> Unit raise CodecError {
  match (value, ctype) {
    // §9.2 bool：0x00 / 0x01
    (VBool(b), CBool) => buf.write_byte(if b { b'\x01' } else { b'\x00' })
    // §9.2 无符号大端 + 值域校验（1.8）
    (VUInt(v), CUInt(n)) => {
      check_uint_range(v, n, name)
      write_i64_be(buf, v, n)
    }
    // §9.2 有符号补码大端 + 值域校验（1.7）
    (VSInt(v), CInt(n)) => {
      check_int_range(v, n, name)
      write_i64_be(buf, v, n)
    }
    // §9.2 IEEE754 大端（1.11）
    (VFloat(d), CFloat(32)) => buf.write_float_be(Float::from_double(d))
    (VFloat(d), CFloat(64)) => buf.write_double_be(d)
    // f80 可选扩展：本实现不支持（IDL 加载期已拒绝，此处兜底）
    (VFloat(_), CFloat(w)) => raise CodecError("\{name}: unsupported float width \{w}")
    // §9.2 timestamp：6B 48bit 大端（1.13）
    (VTimestamp(t), CTimestamp) => {
      guard t >= 0L && t <= TS_MAX else {
        raise CodecError("\{name}: timestamp out of 48bit range: \{t}")
      }
      write_i64_be(buf, t, 6)
    }
    // §9.3 string：fixed_len 裸 N 字节 / max_len 长度前缀 + 内容（1.14/1.18/1.19）
    (VString(s), CString(fixed_len, max_len)) =>
      write_var_bytes(buf, @utf8.encode(s), fixed_len, max_len, name)
    // §9.3 bytes：同上（1.15）
    (VBytes(b), CBytes(fixed_len, max_len)) =>
      write_var_bytes(buf, b, fixed_len, max_len, name)
    // §9.4 array：fixed_len 裸 N 元素 / max_len 元素个数前缀 + 裸元素（1.17/1.20/1.21）
    (VArray(arr), CArray(elem, fixed_len, max_len)) => {
      let n = arr.length()
      // 定长/上限校验（元素个数维度）
      check_or_raise(n, fixed_len, max_len, name)
      // §9.3：仅 max_len 声明时写长度前缀（元素个数，大端 w(N)）
      match max_len {
        Some(m) => write_uint_be(buf, n, len_prefix_width(m))
        None => ()
      }
      for v in arr {
        // 数组元素按元素类型编码，无边界标记；元素为 struct 时展开字段序列（§9.4）
        encode_field(buf, v, elem, name)
      }
    }
    // §9.4 结构体值：字段序列连续编码（input/output 引用 struct 的顶层形态）
    (VArray(vals), CStruct(fields)) => encode_struct_fields(buf, fields, vals, name)
    // 值类型与 schema 不匹配
    _ => raise CodecError("\{name}: value \{Repr(value)} does not match type \{ctype_to_str(ctype)}")
  }
}

/// 编码结构体字段序列（值数与 schema 对齐；§9.4 结构体 = 字段裸排无边界标记）
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
    encode_field(buf, vals[i], f.ctype, f.name)
  }
}

/// 写 string/bytes 字段：fixed_len 无前缀裸 N 字节；max_len 长度前缀（字节数）+ 内容（§9.3）
fn write_var_bytes(
  buf : @buffer.Buffer,
  data : Bytes,
  fixed_len : Int?,
  max_len : Int?,
  name : String
) -> Unit raise CodecError {
  let n = data.length()
  check_or_raise(n, fixed_len, max_len, name)
  // 仅 max_len 声明时写长度前缀（§9.3）
  match max_len {
    Some(m) => write_uint_be(buf, n, len_prefix_width(m))
    None => ()
  }
  buf.write_bytes(data)
}

/// 写 n 字节大端无符号（Int，n ≤ 4：长度前缀/计数用；纯计算不抛错）
fn write_uint_be(buf : @buffer.Buffer, v : Int, n : Int) -> Unit {
  let mut k = n - 1
  while k >= 0 {
    buf.write_byte(((v >> (8 * k)) & 0xFF).to_byte())
    k = k - 1
  }
}

/// 写 n 字节大端（Int64 位模式，n ≤ 8）：有符号即补码，无符号即高位原样（§9.2）
fn write_i64_be(buf : @buffer.Buffer, v : Int64, n : Int) -> Unit {
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
    CUInt(n) => "u\{n * 8}"
    CInt(n) => "i\{n * 8}"
    CFloat(w) => "f\{w}"
    CTimestamp => "timestamp"
    CString(f, m) => "string(fixed=\{Repr(f)},max=\{Repr(m)})"
    CBytes(f, m) => "bytes(fixed=\{Repr(f)},max=\{Repr(m)})"
    CArray(_, f, m) => "array(fixed=\{Repr(f)},max=\{Repr(m)})"
    CStruct(_) => "struct"
  }
}
