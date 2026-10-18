// §9.4 解码流程：按 CType schema 将线格式字节解码为 FWValue 序列
//
// 要点：
// - schema 字段耗尽后剩余字节 = 对端末尾新增字段（MinorVer 向后兼容，§9.4）→ 忽略
// - 解码错误一律使该帧解析失败 → 上层回 RST(0x20)，不做部分交付
// - bool 严格解码 low4∈{0,1}（测试 1.6）；signed/unsigned low4=0 非法（测试 1.9/1.10）
// - SizeMismatch：byte_len ≠ IDL size（测试 1.32）；UnexpectedNull：非 optional 遇 null（测试 1.33）

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
  // 逐字节拷贝构造
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

/// 读 n 字节大端无符号为 Int64（n ≤ 8）
pub fn Reader::read_uint_be64(self : Reader, n : Int) -> Int64 raise CodecError {
  guard n >= 1 && n <= 8 else {
    raise CodecError("read_uint_be64 width \{n} out of range (1..8)")
  }
  let mut v = 0L
  for _i in 0..<n {
    v = (v << 8) | self.read_u8().to_int64()
  }
  v
}

/// 剩余可读字节数
pub fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.pos
}

/// 解码顶层字段序列（§9.4 decode_fields）
pub fn decode_fields(data : Bytes, schema : Array[CField]) -> Array[FWValue] raise CodecError {
  let r = Reader::{ data, pos: 0 }
  let out : Array[FWValue] = []
  // raise 调用隐式传播（本版本无 `!` 后缀）
  for f in schema {
    out.push(decode_field(r, f.ctype, f.optional, f.name))
  }
  // schema 字段耗尽后剩余字节忽略：对端新增末尾字段（MinorVer 兼容，§9.4）
  out
}

/// 解码单个字段
pub fn decode_field(r : Reader, ctype : CType, optional : Bool, name : String) -> FWValue raise CodecError {
  // §9.3 结构体无字段类型标记：字段序列透明内联（与 encode_field 的 (VArray, CStruct) 分支对称），
  // 须在读取类型字节之前按 schema 展开；struct 值以字段值序列 VArray(Array[FWValue]) 表示
  match ctype {
    CStruct(fields) => {
      // optional 结构体遇 null（0x00）：与编码端 VNull 分支优先于 CStruct 分支对称，
      // 先窥探首字节确认 null 再消费（非 optional 不窥探——0x00 属对端违约由内层字段报错）
      if optional && r.pos < r.data.length() && r.data[r.pos].to_int() == 0x00 {
        r.pos = r.pos + 1
        return VNull
      }
      let vals : Array[FWValue] = []
      for f in fields {
        vals.push(decode_field(r, f.ctype, f.optional, f.name))
      }
      return VArray(vals)
    }
    _ => ()
  }
  let tb = r.read_u8()
  let tid = tb >> 4
  let low4 = tb & 0x0F
  // 前置 match + 分支一律块形式（本版本不支持后置 match 语句 / 分支裸 guard）
  match tid {
    // §9.1 类型 0：null
    0x0 => {
      if optional {
        // optional 字段遇 null → 缺省值（VNull 表示，测试 1.34）
        VNull
      } else {
        // 非 optional 遇 null 抛 UnexpectedNull（测试 1.5/1.33）
        raise CodecError("\{name}: UnexpectedNull on non-optional field")
      }
    }
    // §9.1 类型 1：bool 严格解码（测试 1.6）
    0x1 => {
      if low4 > 1 {
        raise CodecError("\{name}: InvalidBoolEncoding low4=\{low4}")
      }
      VBool(low4 == 1)
    }
    // §9.1 类型 2：signed 恒定宽度
    0x2 => {
      // low4=0 为非法编码（§9.1：线上宽度恒等于 size，0 不可达；测试 1.9）
      if low4 == 0 {
        raise CodecError("\{name}: InvalidSignedLength low4=0")
      }
      let size = match ctype {
        CSigned(n) => n
        _ => raise CodecError("\{name}: schema is not signed")
      }
      // 恒定宽度校验位：byte_len == size（§9.2，测试 1.32）
      if low4 != size {
        raise CodecError("\{name}: SizeMismatch byte_len=\{low4} size=\{size}")
      }
      VSigned(read_signed_be(r, low4))
    }
    // §9.1 类型 3：unsigned 恒定宽度
    0x3 => {
      if low4 == 0 {
        raise CodecError("\{name}: InvalidUnsignedLength low4=0")
      }
      let size = match ctype {
        CUnsigned(n) => n
        _ => raise CodecError("\{name}: schema is not unsigned")
      }
      if low4 != size {
        raise CodecError("\{name}: SizeMismatch byte_len=\{low4} size=\{size}")
      }
      VUnsigned(read_unsigned_be64(r, low4))
    }
    // §9.1 类型 4：float
    0x4 =>
      match low4 {
        1 => {
          // 32bit IEEE754：读 4B 位模式，手动展开为 Double（纯 MoonBit，无 FFI）
          let bits = r.read_uint_be(4)
          VFloat(f32_bits_to_double(bits))
        }
        2 => {
          // 64bit IEEE754：位模式重解释
          let bits = r.read_uint_be64(8).reinterpret_as_uint64()
          VFloat(bits.reinterpret_as_double())
        }
        // 3=80bit 可选扩展：不支持时抛 UnsupportedFloatType（§9.1，测试 1.12）
        _ => raise CodecError("\{name}: UnsupportedFloatType low4=\{low4}")
      }
    // §9.1 类型 5：timestamp 高 4bit + 低 40bit（测试 1.13）
    0x5 => {
      let t = (low4.to_int64() << 40) | r.read_uint_be64(5)
      VTimestamp(t)
    }
    // §9.1 类型 6：string（测试 1.14/1.18/1.19/1.22）
    0x6 => {
      let w = low4 + 1
      let len = r.read_uint_be(w)
      match ctype {
        CString(fixed_len, max_len) => {
          match check_len_constraint(len, fixed_len, max_len, name) {
            Err(msg) => raise CodecError(msg)
            Ok(_) => ()
          }
        }
        _ => raise CodecError("\{name}: schema is not string")
      }
      let raw = r.read_bytes(len)
      // UTF-8 解码失败 → 解码错误（0x20）；try-catch 捕获 Malformed 转为 CodecError
      let s = try @utf8.decode(raw) catch {
        _ => raise CodecError("\{name}: invalid UTF-8 string content")
      }
      VString(s)
    }
    // §9.1 类型 7：bytes（测试 1.15/1.22）
    0x7 => {
      let w = low4 + 1
      let len = r.read_uint_be(w)
      match ctype {
        CBytes(fixed_len, max_len) => {
          match check_len_constraint(len, fixed_len, max_len, name) {
            Err(msg) => raise CodecError(msg)
            Ok(_) => ()
          }
        }
        _ => raise CodecError("\{name}: schema is not bytes")
      }
      VBytes(r.read_bytes(len))
    }
    // §9.1 类型 8：array（§9.3 嵌套按 schema 递归，测试 1.16/1.17/1.20/1.23~1.26）
    0x8 => {
      let n = if low4 <= 14 {
        low4
      } else {
        r.read_uint_be(2)
      }
      // 元素类型绑定 + 约束校验合并提取（elem 在 match 分支内绑定后返回）
      let elem = match ctype {
        CArray(elem, fixed_len, max_len) => {
          match check_len_constraint(n, fixed_len, max_len, name) {
            Err(msg) => raise CodecError(msg)
            Ok(_) => ()
          }
          elem
        }
        _ => raise CodecError("\{name}: schema is not array")
      }
      let elems : Array[FWValue] = []
      for _i in 0..<n {
        // 数组元素按元素类型解码，无 optional 语义（§9.3）；元素为 struct 时展开字段序列
        elems.push(decode_struct_or_field(r, elem, name))
      }
      VArray(elems)
    }
    // 类型头 0x9~0xF 未定义 → UnknownFieldType（十进制展示，测试 1.27/9.7）
    _ => raise CodecError("\{name}: UnknownFieldType type_id=\{tid}")
  }
}

/// 解码数组元素：元素类型为 struct 时按字段 schema 展开字段序列（§9.3 嵌套），
/// 否则按普通字段解码（struct 值以字段值序列 VArray(Array[FWValue]) 表示）；
/// CStruct 展开逻辑统一委托 decode_field（数组元素无 optional 语义，§9.3）
fn decode_struct_or_field(
  r : Reader,
  elem : CType,
  name : String
) -> FWValue raise CodecError {
  decode_field(r, elem, false, name)
}

/// 读 n 字节大端补码 signed（n ≤ 15；n > 8 要求高位为符号扩展）
fn read_signed_be(r : Reader, n : Int) -> Int64 raise CodecError {
  let mut v = 0L
  // n > 8 时高位字节必须全 0 或全 1（符号扩展），否则值域超出 Int64
  if n > 8 {
    let hi = r.read_bytes(n - 8)
    let first = hi[0].to_int()
    let allow0 = first == 0x00
    let allow1 = first == 0xFF
    for i in 1..<hi.length() {
      let b = hi[i].to_int()
      guard (allow0 && b == 0x00) || (allow1 && b == 0xFF) else {
        raise CodecError("signed value exceeds Int64 range")
      }
    }
    if allow1 {
      v = -1L
    }
  }
  let lo = r.read_bytes(if n > 8 { 8 } else { n })
  for i in 0..<lo.length() {
    v = (v << 8) | lo[i].to_int().to_int64()
  }
  v
}

/// 读 n 字节大端 unsigned（n ≤ 15；n > 8 要求高位字节全 0）
fn read_unsigned_be64(r : Reader, n : Int) -> Int64 raise CodecError {
  let mut v = 0L
  if n > 8 {
    let hi = r.read_bytes(n - 8)
    for i in 0..<hi.length() {
      guard hi[i].to_int() == 0x00 else {
        raise CodecError("unsigned value exceeds Int64 range")
      }
    }
  }
  let lo = r.read_bytes(if n > 8 { 8 } else { n })
  for i in 0..<lo.length() {
    v = (v << 8) | lo[i].to_int().to_int64()
  }
  v
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
