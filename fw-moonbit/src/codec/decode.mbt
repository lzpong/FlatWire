// §9 解码流程（v5.0 裸字节编码）：按 CType schema 将线格式字节解码为 FWValue 序列
//
// 要点：
// - 字段按 schema 顺序读取，任何字段字节不足 → 解码失败（上层回 RST(0x20)）
// - fixed_len：读出恰 N 字节 / N 元素（无前缀）；max_len：读 w(N) 前缀并校验 ≤ N
// - bool 严格解码仅 0x00/0x01（1.6）；u/i 按宽度补码/无符号（1.7/1.8）
// - schema 字段耗尽后剩余字节 = 对端末尾新增字段（MinorVer 兼容，§9.1/§11.2）→ 忽略

/// 线格式字节读取器
pub(all) struct Reader {
  data : Bytes
  mut pos : Int
}

/// 读取错误（越界）：构造后立即 raise（隐式传播，调用处不带 `!`）
fn eof_error(what : String) -> Unit raise CodecError {
  raise CodecError("unexpected EOF while reading \{what}")
}

/// 读 1 字节
pub fn Reader::read_u8(self : Reader) -> Int raise CodecError {
  if self.pos >= self.data.length() {
    eof_error("u8")
  }
  let b = self.data[self.pos].to_int()
  self.pos = self.pos + 1
  b
}

/// 读 n 字节
pub fn Reader::read_bytes(self : Reader, n : Int) -> Bytes raise CodecError {
  if n < 0 || self.pos + n > self.data.length() {
    eof_error("bytes(n=\{n})")
  }
  let out : Array[Byte] = []
  for i in 0..<n {
    out.push(self.data[self.pos + i])
  }
  self.pos = self.pos + n
  bytes_of_array(out)
}

/// 从字节数组构造 Bytes（包级 from_iter，非 Buffer 方法）
pub fn bytes_of_array(arr : Array[Byte]) -> Bytes {
  @buffer.from_iter(arr.iter()).to_bytes()
}

/// 读 n 字节大端无符号为 Int（n ≤ 4 保证不溢出；更大宽度调用方用 Int64 版本）
pub fn Reader::read_uint_be(self : Reader, n : Int) -> Int raise CodecError {
  guard n >= 1 && n <= 4 else {
    raise CodecError("read_uint_be width \{n} out of range (1..4)")
  }
  let mut v = 0
  for _i in 0..<n {
    v = (v << 8) | self.read_u8()
  }
  v
}

/// 读 n 字节大端无符号为 Int64 位模式（n ≤ 8；u64 全值域按位模式承载）
pub fn Reader::read_uint64_be(self : Reader, n : Int) -> Int64 raise CodecError {
  guard n >= 1 && n <= 8 else {
    raise CodecError("read_uint64_be width \{n} out of range (1..8)")
  }
  let mut v = 0L
  for _i in 0..<n {
    v = (v << 8) | self.read_u8().to_int64()
  }
  v
}

/// 读 n 字节大端补码为 Int64（§9.2；n<8 符号扩展，n=8 直接位模式）
fn Reader::read_int_be(self : Reader, n : Int) -> Int64 raise CodecError {
  let v = self.read_uint64_be(n)
  if n < 8 {
    let bits = n * 8
    if (v & (1L << (bits - 1))) != 0L {
      v - (1L << bits)
    } else {
      v
    }
  } else {
    v
  }
}

/// 剩余可读字节数
pub fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.pos
}

/// 解码顶层字段序列（§9.1）
pub fn decode_fields(data : Bytes, schema : Array[CField]) -> Array[FWValue] raise CodecError {
  let r = Reader::{ data, pos: 0 }
  let out : Array[FWValue] = []
  // raise 调用隐式传播（本版本无 `!` 后缀）
  for f in schema {
    out.push(decode_field(r, f.ctype, f.name))
  }
  // schema 字段耗尽后剩余字节忽略：对端新增末尾字段（MinorVer 兼容，§9.1）
  out
}

/// 解码单个字段（裸值，无字段头）
pub fn decode_field(r : Reader, ctype : CType, name : String) -> FWValue raise CodecError {
  match ctype {
    // §9.2 bool 严格解码（1.6）
    CBool => {
      let b = r.read_u8()
      guard b <= 1 else {
        raise CodecError("\{name}: InvalidBoolEncoding value=\{b}")
      }
      VBool(b == 1)
    }
    // §9.2 无符号大端（1.8）
    CUInt(n) => {
      check_width(n, name)
      VUInt(r.read_uint64_be(n))
    }
    // §9.2 有符号补码大端（1.7）
    CInt(n) => {
      check_width(n, name)
      VSInt(r.read_int_be(n))
    }
    // §9.2 IEEE754 大端（1.11）
    CFloat(32) => {
      // 32bit：读 4B 位模式，手动展开为 Double（纯 MoonBit，无 FFI）
      VFloat(f32_bits_to_double(r.read_uint_be(4)))
    }
    CFloat(64) => {
      let bits = r.read_uint64_be(8).reinterpret_as_uint64()
      VFloat(bits.reinterpret_as_double())
    }
    // f80 可选扩展：本实现不支持（IDL 加载期已拒绝，此处兜底）
    CFloat(w) => raise CodecError("\{name}: unsupported float width \{w}")
    // §9.2 timestamp 6B（1.13）
    CTimestamp => VTimestamp(r.read_uint64_be(6))
    // §9.3 string：fixed_len 裸 N 字节 / max_len 前缀 + 内容（1.14/1.18/1.22）
    CString(fixed_len, max_len) => {
      check_len_decl(fixed_len, max_len, name)
      let raw = read_var_bytes(r, fixed_len, max_len, name)
      // UTF-8 解码失败 → 解码错误（0x20）；try-catch 捕获 Malformed 转为 CodecError
      let s = try @utf8.decode(raw) catch {
        _ => raise CodecError("\{name}: invalid UTF-8 string content")
      }
      VString(s)
    }
    // §9.3 bytes（1.15/1.22）
    CBytes(fixed_len, max_len) => {
      check_len_decl(fixed_len, max_len, name)
      VBytes(read_var_bytes(r, fixed_len, max_len, name))
    }
    // §9.4 array：fixed_len 裸 N 元素 / max_len 元素个数前缀（1.17/1.20~1.26）
    CArray(elem, fixed_len, max_len) => {
      check_len_decl(fixed_len, max_len, name)
      let n = match (fixed_len, max_len) {
        (Some(f), None) => f
        (None, Some(m)) => {
          let len = r.read_uint64_be(len_prefix_width(m)).to_int()
          match check_len_constraint(len, None, Some(m), name) {
            Err(msg) => raise CodecError(msg)
            Ok(_) => ()
          }
          len
        }
        _ => raise CodecError("\{name}: must declare exactly one of fixed_len / max_len")
      }
      let elems : Array[FWValue] = []
      for _i in 0..<n {
        elems.push(decode_field(r, elem, name))
      }
      VArray(elems)
    }
    // §9.4 结构体：字段序列透明内联，无边界标记；struct 值以字段值序列 VArray 表示
    CStruct(fields) => {
      let vals : Array[FWValue] = []
      for f in fields {
        vals.push(decode_field(r, f.ctype, f.name))
      }
      VArray(vals)
    }
  }
}

/// 长度声明合法性（§9.3：fixed_len / max_len 恰声明其一）
fn check_len_decl(fixed_len : Int?, max_len : Int?, name : String) -> Unit raise CodecError {
  match (fixed_len, max_len) {
    (Some(_), None) | (None, Some(_)) => ()
    _ => raise CodecError("\{name}: must declare exactly one of fixed_len / max_len")
  }
}

/// 读 string/bytes 内容：fixed_len 恰 N 字节（无前缀）；max_len 前缀 + 校验 ≤ N（§9.3）
fn read_var_bytes(
  r : Reader,
  fixed_len : Int?,
  max_len : Int?,
  name : String
) -> Bytes raise CodecError {
  match (fixed_len, max_len) {
    (Some(n), None) => {
      guard n >= 0 else {
        raise CodecError("\{name}: fixed_len must be non-negative")
      }
      r.read_bytes(n)
    }
    (None, Some(m)) => {
      guard m >= 0 else {
        raise CodecError("\{name}: max_len must be non-negative")
      }
      // §9.3：长度 = 字节数，校验 ≤ max_len（超限 → 0x20）
      let len = r.read_uint64_be(len_prefix_width(m)).to_int()
      match check_len_constraint(len, None, Some(m), name) {
        Err(msg) => raise CodecError(msg)
        Ok(_) => ()
      }
      r.read_bytes(len)
    }
    _ => raise CodecError("\{name}: must declare exactly one of fixed_len / max_len")
  }
}

/// IEEE754 单精度位模式 → Double（纯 MoonBit 展开；避免 Float→Double 缺失的转换 API）
fn f32_bits_to_double(bits : Int) -> Double {
  // 符号位直接以 Int 符号判断（最高位为 1 即负，等价于 lsr(31)==1）
  let sign = if bits < 0 { -1.0 } else { 1.0 }
  let exp = (bits >> 23) & 0xFF
  let mant = bits & 0x7FFFFF
  if exp == 0 {
    // 非规格化数 / ±0：值 = mant × 2^-149
    sign * (mant.to_double() * 7.006492321600055e-46)
  } else if exp == 0xFF {
    // Inf / NaN
    if mant == 0 {
      sign * f64_infinity()
    } else {
      f64_nan()
    }
  } else {
    sign * ((mant.to_double() / 8388608.0 + 1.0) * pow2(exp - 127))
  }
}

/// +Infinity（IEEE754 f64 位模式构造，避免常量折叠问题）
fn f64_infinity() -> Double {
  (0x7FF0000000000000UL).reinterpret_as_double()
}

/// NaN（IEEE754 f64 位模式构造）
fn f64_nan() -> Double {
  (0x7FF8000000000000UL).reinterpret_as_double()
}

/// 2 的整数次幂（e 可为负，平方展开）
fn pow2(e : Int) -> Double {
  let mut result = 1.0
  let mut base = 2.0
  let mut k = if e < 0 { -e } else { e }
  while k > 0 {
    if (k & 1) == 1 {
      result = result * base
    }
    base = base * base
    k = k >> 1
  }
  if e < 0 {
    1.0 / result
  } else {
    result
  }
}
