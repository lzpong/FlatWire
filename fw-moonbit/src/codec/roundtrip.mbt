// §9 编解码往返与非法编码测试（对应一致性测试用例 1.5~1.35 的编解码部分）
//
// 覆盖：
// - 全类型往返（bool/signed/unsigned/float/timestamp/string/bytes/array/null/optional）
// - 恒定宽度（1.7/1.8：byte_len 恒等于 IDL size）与 SizeMismatch（1.32）
// - 非法编码抛错：InvalidBoolEncoding(1.6)/InvalidSignedLength(1.9)/InvalidUnsignedLength(1.10)
//   /UnsupportedFloatType(1.12)/UnexpectedNull(1.33)/UnknownFieldType(1.27)
// - 定长约束（1.18~1.21）与 max_len 超限（1.22）
// - 嵌套往返（1.23~1.26）与 MinorVer 兼容（schema 耗尽后剩余字节忽略，§9.4）

/// 顶层往返：编码后解码，Ok(值序列) / Err(错误消息)
fn rt(schema : Array[CField], values : Array[FWValue]) -> Result[Array[FWValue], String] {
  try {
    Ok(decode_fields(encode_fields(schema, values), schema))
  } catch {
    CodecError(msg) => Err(msg)
  }
}

/// 期望解码抛 CodecError：返回错误消息；未抛则返回 "OK"
fn dec_err(data : Bytes, ctype : CType, optional : Bool) -> String {
  let r = Reader::{ data, pos: 0 }
  try {
    let _ = decode_field(r, ctype, optional, "f")
    "OK"
  } catch {
    CodecError(msg) => msg
  }
}

/// 期望编码抛 CodecError：返回错误消息；未抛则返回 "OK"
fn enc_err(value : FWValue, ctype : CType, optional : Bool) -> String {
  let buf = @buffer.Buffer(size_hint=16)
  try {
    encode_field(buf, value, ctype, optional, "f")
    "OK"
  } catch {
    CodecError(msg) => msg
  }
}

/// 测试 1.6：bool 往返 + 严格解码（0x11/0x10，low4∉{0,1} 抛错）
test "1.6 bool roundtrip & strict decode" {
  let schema = [{ name: "f", ctype: CBool, optional: false }]
  assert_eq(rt(schema, [VBool(true)]), Ok([VBool(true)]))
  assert_eq(rt(schema, [VBool(false)]), Ok([VBool(false)]))
  // 线格式验证：false=0x10 / true=0x11
  let enc = encode_fields(schema, [VBool(true)])
  assert_eq(enc[0], b'\x11')
  // low4=2 → InvalidBoolEncoding
  assert_eq(dec_err(b"\x12", CBool, false), "f: InvalidBoolEncoding low4=2")
}

/// 测试 1.7/1.8：恒定宽度——8B 字段值 10 占 8 字节（byte_len 恒等于 size）
test "1.7/1.8 constant width" {
  let schema = [{ name: "f", ctype: CSigned(8), optional: false }]
  let enc = encode_fields(schema, [VSigned(10L)])
  // 1B 字段头(0x28) + 8B 数据（值 10 大端 00..0A）
  assert_eq(enc.length(), 9)
  assert_eq(enc[0], b'\x28')
  assert_eq(enc[8], b'\x0A')
  assert_eq(rt(schema, [VSigned(10L)]), Ok([VSigned(10L)]))
  let uschema = [{ name: "f", ctype: CUnsigned(8), optional: false }]
  let uenc = encode_fields(uschema, [VUnsigned(10L)])
  assert_eq(uenc.length(), 9)
  assert_eq(uenc[0], b'\x38')
  assert_eq(rt(uschema, [VUnsigned(10L)]), Ok([VUnsigned(10L)]))
}

/// 测试 1.9/1.10/1.32：low4=0 非法 + SizeMismatch（byte_len ≠ IDL size）
test "1.9/1.10/1.32 length validation" {
  // signed low4=0 → InvalidSignedLength
  assert_eq(dec_err(b"\x20", CSigned(8), false), "f: InvalidSignedLength low4=0")
  // unsigned low4=0 → InvalidUnsignedLength
  assert_eq(dec_err(b"\x30", CUnsigned(8), false), "f: InvalidUnsignedLength low4=0")
  // byte_len=1 但 IDL size=8 → SizeMismatch
  assert_eq(dec_err(b"\x21\x01", CSigned(8), false), "f: SizeMismatch byte_len=1 size=8")
  assert_eq(dec_err(b"\x31\x01", CUnsigned(8), false), "f: SizeMismatch byte_len=1 size=8")
}

/// 测试 1.11：float32/64 往返（含 NaN/Inf 位模式一致）
test "1.11 float roundtrip" {
  let f64schema = [{ name: "f", ctype: CFloat(64), optional: false }]
  assert_eq(rt(f64schema, [VFloat(3.141592653589793)]), Ok([VFloat(3.141592653589793)]))
  let f32schema = [{ name: "f", ctype: CFloat(32), optional: false }]
  // f32 用可精确表示的 2.5 验证往返（3.14159 经 f32 量化后不等）
  assert_eq(rt(f32schema, [VFloat(2.5)]), Ok([VFloat(2.5)]))
  // NaN / Inf（f64）：位模式往返一致
  let nan_res = rt(f64schema, [VFloat((0x7FF8000000000000UL).reinterpret_as_double())])
  match nan_res {
    Ok(vals) =>
      match vals[0] {
        VFloat(d) => assert_eq(d.reinterpret_as_uint64(), 0x7FF8000000000000UL)
        _ => fail("not float")
      }
    Err(msg) => fail(msg)
  }
  let inf_res = rt(f64schema, [VFloat((0x7FF0000000000000UL).reinterpret_as_double())])
  match inf_res {
    Ok(vals) =>
      match vals[0] {
        VFloat(d) => assert_eq(d.reinterpret_as_uint64(), 0x7FF0000000000000UL)
        _ => fail("not float")
      }
    Err(msg) => fail(msg)
  }
}

/// 测试 1.12：float 非法宽度（low4=0 / low4≥3）→ UnsupportedFloatType
test "1.12 invalid float width" {
  assert_eq(dec_err(b"\x40", CFloat(64), false), "f: UnsupportedFloatType low4=0")
  assert_eq(dec_err(b"\x43", CFloat(64), false), "f: UnsupportedFloatType low4=3")
}

/// 测试 1.13：timestamp 0 / 2^44-1 边界（高 4bit + 低 40bit 拆分）
test "1.13 timestamp bounds" {
  let schema = [{ name: "f", ctype: CTimestamp, optional: false }]
  assert_eq(rt(schema, [VTimestamp(0L)]), Ok([VTimestamp(0L)]))
  // 2^44-1：高 4bit=0xF，低 40bit 全 1
  assert_eq(rt(schema, [VTimestamp(0xFFFFFFFFFFFL)]), Ok([VTimestamp(0xFFFFFFFFFFFL)]))
  // 线格式：2^44-1 → 字段头 0x5F + 5B 0xFF
  let enc = encode_fields(schema, [VTimestamp(0xFFFFFFFFFFFL)])
  assert_eq(enc[0], b'\x5F')
  assert_eq(enc[1], b'\xFF')
  assert_eq(enc.length(), 6)
}

/// 测试 1.14：string 往返（UTF-8 + 实际字节长度前缀）
test "1.14 string roundtrip" {
  let schema = [{ name: "f", ctype: CString(None, None), optional: false }]
  assert_eq(rt(schema, [VString("hello")]), Ok([VString("hello")]))
  assert_eq(rt(schema, [VString("")]), Ok([VString("")]))
  assert_eq(rt(schema, [VString("中文")]), Ok([VString("中文")]))
  // 线格式：0x60（长度宽度 1 → low4=w-1=0）+ 0x05 + "hello" UTF-8
  let enc = encode_fields(schema, [VString("hello")])
  assert_eq(enc[0], b'\x60')
  assert_eq(enc[1], b'\x05')
  assert_eq(enc.length(), 7)
}

/// 测试 1.18/1.19：定长 string——长度必须恰为 fixed_len
test "1.18/1.19 fixed_len string" {
  let schema = [{ name: "f", ctype: CString(Some(4), None), optional: false }]
  assert_eq(rt(schema, [VString("abcd")]), Ok([VString("abcd")]))
  // 线格式长度字段 = 4
  let enc = encode_fields(schema, [VString("abcd")])
  assert_eq(enc[1], b'\x04')
  // 3 字节 ≠ fixed_len → 编码错误
  assert_eq(enc_err(VString("abc"), CString(Some(4), None), false), "f: fixed_len mismatch, expect 4, got 3")
}

/// 测试 1.22：max_len 超限 → 编码错误（IDL 级约束，帧上回 0x20）
test "1.22 max_len exceeded" {
  // 构造 65 字节字符串
  let mut s = ""
  for _i in 0..<65 {
    s = s + "a"
  }
  assert_eq(
    enc_err(VString(s), CString(None, Some(64)), false),
    "f: max_len exceeded, limit 64, got 65",
  )
}

/// 测试 1.15：bytes 往返（含空）
test "1.15 bytes roundtrip" {
  let schema = [{ name: "f", ctype: CBytes(None, None), optional: false }]
  assert_eq(rt(schema, [VBytes(b"\x00\xFF")]), Ok([VBytes(b"\x00\xFF")]))
  assert_eq(rt(schema, [VBytes(b"")]), Ok([VBytes(b"")]))
}

/// 测试 1.16/1.17：array 内联长度（≤14）与扩展长度（0x8F + 2B）
test "1.16/1.17 array length encoding" {
  let schema = [{ name: "f", ctype: CArray(CUnsigned(1), None, None), optional: false }]
  // 内联：2 元素 → 0x82
  let enc2 = encode_fields(schema, [VArray([VUnsigned(1), VUnsigned(2)])])
  assert_eq(enc2[0], b'\x82')
  assert_eq(rt(schema, [VArray([VUnsigned(1), VUnsigned(2)])]), Ok([VArray([VUnsigned(1), VUnsigned(2)])]))
  // 空数组 → 0x80
  let enc0 = encode_fields(schema, [VArray([])])
  assert_eq(enc0[0], b'\x80')
  // 扩展：15 元素 → 0x8F + 0x000F
  let elems : Array[FWValue] = []
  for i in 0..<15 {
    elems.push(VUnsigned(i.to_int64()))
  }
  let enc15 = encode_fields(schema, [VArray(elems)])
  assert_eq(enc15[0], b'\x8F')
  assert_eq(enc15[1], b'\x00')
  assert_eq(enc15[2], b'\x0F')
  assert_eq(rt(schema, [VArray(elems)]), Ok([VArray(elems)]))
}

/// 测试 1.20/1.21：定长 array——长度必须恰为 fixed_len（空位由调用方填默认值）
test "1.20/1.21 fixed_len array" {
  let schema = [{ name: "f", ctype: CArray(CUnsigned(1), Some(20), None), optional: false }]
  // 20 元素（12 个有效值 + 8 个默认 0）→ 往返一致，长度字段 = 20
  let elems : Array[FWValue] = []
  for i in 0..<20 {
    elems.push(VUnsigned((if i < 12 { i } else { 0 }).to_int64()))
  }
  let enc = encode_fields(schema, [VArray(elems)])
  assert_eq(enc[0], b'\x8F')
  assert_eq(enc[1], b'\x00')
  assert_eq(enc[2], b'\x14')
  assert_eq(rt(schema, [VArray(elems)]), Ok([VArray(elems)]))
  // 19 元素 ≠ fixed_len=20 → 编码错误
  let short : Array[FWValue] = []
  for i in 0..<19 {
    short.push(VUnsigned(i.to_int64()))
  }
  assert_eq(enc_err(VArray(short), CArray(CUnsigned(1), Some(20), None), false), "f: fixed_len mismatch, expect 20, got 19")
}

/// 测试 1.5/1.33/1.34：null 语义——仅 optional 合法；非 optional 遇 null 抛 UnexpectedNull
test "1.5/1.33/1.34 null semantics" {
  // optional 空：编码 00，解码 VNull
  let oschema = [{ name: "f", ctype: CUnsigned(2), optional: true }]
  assert_eq(rt(oschema, [VNull]), Ok([VNull]))
  let enc = encode_fields(oschema, [VNull])
  assert_eq(enc[0], b'\x00')
  // optional 有值：正常编码往返
  assert_eq(rt(oschema, [VUnsigned(5)]), Ok([VUnsigned(5)]))
  // 非 optional 遇 null：编码报错 + 解码抛 UnexpectedNull
  assert_eq(enc_err(VNull, CUnsigned(2), false), "f: null on non-optional field")
  assert_eq(dec_err(b"\x00", CUnsigned(2), false), "f: UnexpectedNull on non-optional field")
}

/// 测试 1.27：未知类型头 0x9~0xF → UnknownFieldType
test "1.27 unknown field type" {
  assert_eq(dec_err(b"\x91\x01", CUnsigned(1), false), "f: UnknownFieldType type_id=9")
  assert_eq(dec_err(b"\xF1\x01", CUnsigned(1), false), "f: UnknownFieldType type_id=15")
}

/// 测试 1.23~1.26：嵌套往返——数组元素为数组（逐层长度字段，多维递归）
test "1.23-1.26 nested roundtrip" {
  // 多维数组：array of array of unsigned（1.26 逐层递归，每层带长度字段）
  let schema = [{ name: "f", ctype: CArray(CArray(CUnsigned(1), None, None), None, None), optional: false }]
  let vals = [VArray([VArray([VUnsigned(1), VUnsigned(2)]), VArray([VUnsigned(3)])])]
  assert_eq(rt(schema, vals), Ok(vals))
  // 线格式：外层 0x82 + 内层1 0x82 + 元素 + 内层2 0x81（布局 [0]外 [1]内1 [2..5]元素 [6]内2 [7..8]元素）
  let enc = encode_fields(schema, vals)
  assert_eq(enc[0], b'\x82')
  assert_eq(enc[1], b'\x82')
  assert_eq(enc[6], b'\x81')
}

/// §9.4：schema 字段耗尽后剩余字节忽略（对端 MinorVer 新增末尾字段兼容）
test "9.4 trailing bytes ignored" {
  // schema 仅 1 字段，数据含完整 2 字段
  let schema = [{ name: "a", ctype: CUnsigned(1), optional: false }]
  let full = encode_fields(
    [
      { name: "a", ctype: CUnsigned(1), optional: false },
      { name: "b", ctype: CUnsigned(1), optional: false },
    ],
    [VUnsigned(1), VUnsigned(2)],
  )
  // 解码按 schema 只取第 1 字段，剩余忽略
  assert_eq(decode_fields(full, schema), [VUnsigned(1)])
}

/// §9.4：顶层字段数与 schema 不一致 → 编码错误
test "9.4 field count mismatch" {
  let schema = [
    { name: "a", ctype: CUnsigned(1), optional: false },
    { name: "b", ctype: CUnsigned(1), optional: false },
  ]
  match rt(schema, [VUnsigned(1)]) {
    Err(_) => ()
    Ok(_) => fail("count mismatch should fail")
  }
}
