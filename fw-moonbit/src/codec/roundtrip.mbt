// §9 编解码往返与契约校验测试（v5.0 裸字节编码；对应一致性测试用例 §1）
//
// 覆盖：1.5（IDL 强制长度声明——见 idlstore 测试）/1.6/1.7/1.8/1.9/1.10/1.11/
// 1.13/1.14/1.15/1.16/1.17/1.18~1.21/1.22/1.23~1.26/1.27~1.29/1.31/1.33~1.36/1.38
//
// 核心规则（§9.1~§9.6）：
// - 无字段头/类型标记：字段按 schema 顺序裸值大端连续编码
// - fixed_len 无长度前缀；max_len 前缀宽度 w(N)：≤255→1B / ≤65535→2B / 否则 4B
// - 值域校验（u8..u64 / i8..i64）、bool 严格解码、timestamp 48bit
// - CRC 缺省关闭；启用时 2B 大端附加于字段序列末尾

/// 顶层往返：编码后解码，Ok(值序列) / Err(错误消息)
fn rt(schema : Array[CField], values : Array[FWValue]) -> Result[Array[FWValue], String] {
  try {
    Ok(decode_fields(encode_fields(schema, values), schema))
  } catch {
    CodecError(msg) => Err(msg)
  }
}

/// 期望解码抛 CodecError：返回错误消息；未抛则返回 "OK"
fn dec_err(data : Bytes, ctype : CType) -> String {
  let r = Reader::{ data, pos: 0 }
  try {
    let _ = decode_field(r, ctype, "f")
    "OK"
  } catch {
    CodecError(msg) => msg
  }
}

/// 期望编码抛 CodecError：返回错误消息；未抛则返回 "OK"
fn enc_err(value : FWValue, ctype : CType) -> String {
  let buf = @buffer.Buffer(size_hint=16)
  try {
    encode_field(buf, value, ctype, "f")
    "OK"
  } catch {
    CodecError(msg) => msg
  }
}

/// 测试 1.6：bool 裸字节 0x00/0x01 + 严格解码（其他值抛 InvalidBoolEncoding）
test "1.6 bool roundtrip & strict decode" {
  let schema = [{ name: "f", ctype: CBool }]
  assert_eq(rt(schema, [VBool(true)]), Ok([VBool(true)]))
  assert_eq(rt(schema, [VBool(false)]), Ok([VBool(false)]))
  // 线格式验证（裸 1B，无字段头）
  assert_eq(encode_fields(schema, [VBool(true)]), b"\x01")
  assert_eq(encode_fields(schema, [VBool(false)]), b"\x00")
  // 0x02 → InvalidBoolEncoding（1.6）
  assert_eq(dec_err(b"\x02", CBool), "f: InvalidBoolEncoding value=2")
}

/// 测试 1.7：有符号边界（i8 -128/0/127；i64 值 10 仍占满 8B，恒定宽度）
test "1.7 signed bounds & constant width" {
  let i8s = [{ name: "f", ctype: CInt(1) }]
  assert_eq(encode_fields(i8s, [VSInt(-128L)]), b"\x80")
  assert_eq(encode_fields(i8s, [VSInt(0L)]), b"\x00")
  assert_eq(encode_fields(i8s, [VSInt(127L)]), b"\x7F")
  assert_eq(rt(i8s, [VSInt(-128L)]), Ok([VSInt(-128L)]))
  // i16 -1 → FF FF（1.38）
  assert_eq(encode_fields([{ name: "f", ctype: CInt(2) }], [VSInt(-1L)]), b"\xFF\xFF")
  // i64 值 10 仍占满 8B（恒定宽度，不压缩）
  let i64s = [{ name: "f", ctype: CInt(8) }]
  let enc = encode_fields(i64s, [VSInt(10L)])
  assert_eq(enc.length(), 8)
  assert_eq(enc[7], b'\x0A')
  assert_eq(rt(i64s, [VSInt(10L)]), Ok([VSInt(10L)]))
}

/// 测试 1.8：无符号边界（u8 0/255；u64 值 10 仍占满 8B）
test "1.8 unsigned bounds & constant width" {
  let u8s = [{ name: "f", ctype: CUInt(1) }]
  assert_eq(encode_fields(u8s, [VUInt(0L)]), b"\x00")
  assert_eq(encode_fields(u8s, [VUInt(255L)]), b"\xFF")
  assert_eq(rt(u8s, [VUInt(255L)]), Ok([VUInt(255L)]))
  let u64s = [{ name: "f", ctype: CUInt(8) }]
  let enc = encode_fields(u64s, [VUInt(10L)])
  assert_eq(enc.length(), 8)
  assert_eq(enc[7], b'\x0A')
  assert_eq(rt(u64s, [VUInt(10L)]), Ok([VUInt(10L)]))
}

/// 测试 1.9：字段字节不足 → 解码失败（数据帧回 RST 0x20）
test "1.9 insufficient field bytes" {
  let msg = dec_err(b"\x01\x02\x03", CUInt(4))
  assert_eq(msg == "OK", false)
  assert_eq(dec_err(b"", CUInt(1)) == "OK", false)
  assert_eq(dec_err(b"", CTimestamp) == "OK", false)
}

/// 测试 1.10：整型值域越界 → 编码报错
test "1.10 integer value range" {
  assert_eq(enc_err(VUInt(300L), CUInt(1)), "f: u8 out of range: 300")
  assert_eq(enc_err(VSInt(128L), CInt(1)), "f: i8 out of range: 128")
  assert_eq(enc_err(VSInt(-129L), CInt(1)), "f: i8 out of range: -129")
  // 负值不能编码为无符号
  assert_eq(enc_err(VUInt(-1L), CUInt(1)), "f: u8 out of range: -1")
}

/// 测试 1.11：f32/f64 IEEE754 大端 + NaN/Inf 位模式往返
test "1.11 float roundtrip" {
  let f64s = [{ name: "f", ctype: CFloat(64) }]
  assert_eq(rt(f64s, [VFloat(3.141592653589793)]), Ok([VFloat(3.141592653589793)]))
  // f32：2.5 可精确表示 → 位模式 0x40200000
  let f32s = [{ name: "f", ctype: CFloat(32) }]
  assert_eq(encode_fields(f32s, [VFloat(2.5)]), b"\x40\x20\x00\x00")
  assert_eq(rt(f32s, [VFloat(2.5)]), Ok([VFloat(2.5)]))
  // NaN / +Inf / -Inf（f64）：位模式往返一致
  let nan_res = rt(f64s, [VFloat((0x7FF8000000000000UL).reinterpret_as_double())])
  match nan_res {
    Ok(vals) =>
      match vals[0] {
        VFloat(d) => assert_eq(d.reinterpret_as_uint64(), 0x7FF8000000000000UL)
        _ => fail("not float")
      }
    Err(msg) => fail(msg)
  }
  let inf_res = rt(f64s, [VFloat((0x7FF0000000000000UL).reinterpret_as_double())])
  match inf_res {
    Ok(vals) =>
      match vals[0] {
        VFloat(d) => assert_eq(d.reinterpret_as_uint64(), 0x7FF0000000000000UL)
        _ => fail("not float")
      }
    Err(msg) => fail(msg)
  }
  let ninf_res = rt(f64s, [VFloat((0xFFF0000000000000UL).reinterpret_as_double())])
  match ninf_res {
    Ok(vals) =>
      match vals[0] {
        VFloat(d) => assert_eq(d.reinterpret_as_uint64(), 0xFFF0000000000000UL)
        _ => fail("not float")
      }
    Err(msg) => fail(msg)
  }
  // f80 不支持：编解码均报错（IDL 加载期同样拒绝，见 idlstore 测试 1.12）
  assert_eq(enc_err(VFloat(1.0), CFloat(80)) == "OK", false)
  assert_eq(dec_err(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", CFloat(80)) == "OK", false)
}

/// 测试 1.13：timestamp 0 / 2^48-1，6B 大端（2000 基准毫秒）
test "1.13 timestamp bounds" {
  let schema = [{ name: "f", ctype: CTimestamp }]
  assert_eq(encode_fields(schema, [VTimestamp(0L)]), b"\x00\x00\x00\x00\x00\x00")
  assert_eq(encode_fields(schema, [VTimestamp(1L)]), b"\x00\x00\x00\x00\x00\x01")
  let max = 281474976710655L // 2^48-1
  assert_eq(encode_fields(schema, [VTimestamp(max)]), b"\xFF\xFF\xFF\xFF\xFF\xFF")
  assert_eq(rt(schema, [VTimestamp(0L)]), Ok([VTimestamp(0L)]))
  assert_eq(rt(schema, [VTimestamp(max)]), Ok([VTimestamp(max)]))
}

/// 测试 1.14：string max_len=64 → 1B 长度前缀（UTF-8 字节数）+ 内容
test "1.14 string variable length" {
  let schema = [{ name: "f", ctype: CString(None, Some(64)) }]
  assert_eq(rt(schema, [VString("hello")]), Ok([VString("hello")]))
  assert_eq(rt(schema, [VString("")]), Ok([VString("")]))
  assert_eq(rt(schema, [VString("中文")]), Ok([VString("中文")]))
  assert_eq(encode_fields(schema, [VString("hello")]), b"\x05hello")
  assert_eq(encode_fields(schema, [VString("")]), b"\x00")
  // "中文" = 6 个 UTF-8 字节
  let zh = encode_fields(schema, [VString("中文")])
  assert_eq(zh.length(), 7)
  assert_eq(zh[0], b'\x06')
}

/// 测试 1.15：bytes max_len=64 → 长度前缀 + 原始字节
test "1.15 bytes variable length" {
  let schema = [{ name: "f", ctype: CBytes(None, Some(64)) }]
  assert_eq(rt(schema, [VBytes(b"\x00\xFF")]), Ok([VBytes(b"\x00\xFF")]))
  assert_eq(rt(schema, [VBytes(b"")]), Ok([VBytes(b"")]))
  assert_eq(encode_fields(schema, [VBytes(b"\x00\xFF")]), b"\x02\x00\xFF")
  assert_eq(encode_fields(schema, [VBytes(b"")]), b"\x00")
}

/// 测试 1.16：max_len 前缀宽度推导（255→1B / 256→2B / 65535→2B / 65536→4B）
test "1.16 length prefix width derivation" {
  // 1B 前缀（N=255 ≤ 255）
  assert_eq(encode_fields([{ name: "f", ctype: CString(None, Some(255)) }], [VString("hi")]), b"\x02hi")
  // 2B 前缀（N=256）
  let e256 = encode_fields([{ name: "f", ctype: CString(None, Some(256)) }], [VString("hi")])
  assert_eq(e256, b"\x00\x02hi")
  // 2B 前缀（N=65535）
  let e65535 = encode_fields([{ name: "f", ctype: CString(None, Some(65535)) }], [VString("hi")])
  assert_eq(e65535, b"\x00\x02hi")
  // 4B 前缀（N=65536）
  let e65536 = encode_fields([{ name: "f", ctype: CString(None, Some(65536)) }], [VString("hi")])
  assert_eq(e65536, b"\x00\x00\x00\x02hi")
  // 解码对称
  assert_eq(rt([{ name: "f", ctype: CString(None, Some(65536)) }], [VString("hi")]),
    Ok([VString("hi")]))
}

/// 测试 1.17：array max_len=100 → 1B 元素个数前缀 + 裸元素（元素无类型头）
test "1.17 array variable length" {
  let schema = [{ name: "f", ctype: CArray(CUInt(1), None, Some(100)) }]
  assert_eq(encode_fields(schema, [VArray([])]), b"\x00")
  assert_eq(encode_fields(schema, [VArray([VUInt(1L), VUInt(2L)])]), b"\x02\x01\x02")
  let elems : Array[FWValue] = []
  for i in 0..<100 {
    elems.push(VUInt(i.to_int64()))
  }
  let enc = encode_fields(schema, [VArray(elems)])
  assert_eq(enc.length(), 101) // 1B 前缀 + 100B 元素
  assert_eq(enc[0], b'\x64')
  assert_eq(rt(schema, [VArray(elems)]), Ok([VArray(elems)]))
}

/// 测试 1.18/1.19：定长 string 无长度前缀；输入必须恰为 fixed_len
test "1.18/1.19 fixed_len string" {
  let schema = [{ name: "f", ctype: CString(Some(4), None) }]
  assert_eq(encode_fields(schema, [VString("abcd")]), b"abcd")
  assert_eq(rt(schema, [VString("abcd")]), Ok([VString("abcd")]))
  // 3 / 5 字节 ≠ fixed_len=4 → 编码错误
  assert_eq(enc_err(VString("abc"), CString(Some(4), None)), "f: fixed_len mismatch, expect 4, got 3")
  assert_eq(enc_err(VString("abcde"), CString(Some(4), None)), "f: fixed_len mismatch, expect 4, got 5")
}

/// 测试 1.20/1.21：定长 array 无长度前缀；元素数量必须恰为 fixed_len
test "1.20/1.21 fixed_len array" {
  let schema = [{ name: "f", ctype: CArray(CUInt(1), Some(20), None) }]
  // 12 个业务值 + 8 个默认值 0（空位默认值，§9.3）
  let elems : Array[FWValue] = []
  for i in 0..<20 {
    elems.push(VUInt((if i < 12 { i } else { 0 }).to_int64()))
  }
  let enc = encode_fields(schema, [VArray(elems)])
  assert_eq(enc.length(), 20) // 裸 20 元素，无长度字段
  assert_eq(enc[0], b'\x00')
  assert_eq(enc[11], b'\x0B')
  assert_eq(enc[12], b'\x00') // 空位填充默认值 0
  assert_eq(rt(schema, [VArray(elems)]), Ok([VArray(elems)]))
  // bool 空位默认 0x00（§9.3）
  let bschema = [{ name: "f", ctype: CArray(CBool, Some(2), None) }]
  assert_eq(encode_fields(bschema, [VArray([VBool(true), VBool(false)])]), b"\x01\x00")
  // 19 元素 ≠ fixed_len=20 → 编码错误
  let short : Array[FWValue] = []
  for i in 0..<19 {
    short.push(VUInt(i.to_int64()))
  }
  assert_eq(enc_err(VArray(short), CArray(CUInt(1), Some(20), None)), "f: fixed_len mismatch, expect 20, got 19")
}

/// 测试 1.22：max_len 超限 → 编码报错 / 解码校验失败（均映射 RST 0x20）
test "1.22 max_len exceeded" {
  let mut s = ""
  for _i in 0..<65 {
    s = s + "a"
  }
  assert_eq(enc_err(VString(s), CString(None, Some(64))), "f: max_len exceeded, limit 64, got 65")
  // 解码：1B 前缀 65 > max_len=64 → 解码失败
  let buf = @buffer.Buffer(size_hint=66)
  buf.write_byte(b'\x41')
  for _i in 0..<65 {
    buf.write_byte(b'a')
  }
  let msg = dec_err(buf.to_bytes(), CString(None, Some(64)))
  assert_eq(msg == "OK", false)
}

/// 测试 1.23：嵌套——结构体含结构体（字段按序裸排，无边界标记）
test "1.23 struct in struct" {
  let inner : CType = CStruct([
    { name: "a", ctype: CUInt(1) },
    { name: "b", ctype: CInt(1) },
  ])
  let schema = [
    { name: "x", ctype: CUInt(2) },
    { name: "in", ctype: inner },
  ]
  let vals = [VUInt(0x1234L), VArray([VUInt(1L), VSInt(-1L)])]
  assert_eq(encode_fields(schema, vals), b"\x12\x34\x01\xFF")
  assert_eq(rt(schema, vals), Ok(vals))
}

/// 测试 1.24：嵌套——结构体含数组（数组按自身声明编码）
test "1.24 struct with array" {
  let schema = [
    {
      name: "arr",
      ctype: CArray(CUInt(1), Some(3), None),
    },
  ]
  let vals = [VArray([VUInt(1L), VUInt(2L), VUInt(3L)])]
  assert_eq(encode_fields(schema, vals), b"\x01\x02\x03") // 定长数组无前缀
  assert_eq(rt(schema, vals), Ok(vals))
}

/// 测试 1.25：嵌套——数组元素为结构体（逐元素裸排）
test "1.25 array of struct" {
  let elem : CType = CStruct([
    { name: "a", ctype: CUInt(1) },
    { name: "b", ctype: CUInt(1) },
  ])
  let schema = [{ name: "f", ctype: CArray(elem, None, Some(10)) }]
  let vals = [VArray([
    VArray([VUInt(1L), VUInt(2L)]),
    VArray([VUInt(3L), VUInt(4L)]),
  ])]
  assert_eq(encode_fields(schema, vals), b"\x02\x01\x02\x03\x04")
  assert_eq(rt(schema, vals), Ok(vals))
}

/// 测试 1.26：嵌套——多维数组（定长层无前缀、变长层有前缀）
test "1.26 multi-dimensional arrays" {
  // 外层 fixed_len=3、内层 fixed_len=4 → 12 字节裸排
  let fixed : CType = CArray(CArray(CUInt(1), Some(4), None), Some(3), None)
  let fvals = [
    VArray([
      VArray([VUInt(1L), VUInt(2L), VUInt(3L), VUInt(4L)]),
      VArray([VUInt(5L), VUInt(6L), VUInt(7L), VUInt(8L)]),
      VArray([VUInt(9L), VUInt(10L), VUInt(11L), VUInt(12L)]),
    ]),
  ]
  let fschema = [{ name: "f", ctype: fixed }]
  assert_eq(encode_fields(fschema, fvals).length(), 12)
  assert_eq(rt(fschema, fvals), Ok(fvals))
  // 外层 max_len=3、内层 max_len=4 → 外层 1B 前缀 + 每内层 1B 前缀
  let vararr : CType = CArray(CArray(CUInt(1), None, Some(4)), None, Some(3))
  let vvals = [VArray([VArray([VUInt(1L)]), VArray([VUInt(2L)]), VArray([VUInt(3L)])])]
  let vschema = [{ name: "f", ctype: vararr }]
  assert_eq(encode_fields(vschema, vvals), b"\x03\x01\x01\x01\x02\x01\x03")
  assert_eq(rt(vschema, vvals), Ok(vvals))
}

/// 测试 1.27：enum 负值——base="i8" 解析为 CInt(1)，-1 → FF / -128 → 80
/// （IDL 层 base 解析见 idlstore 测试；此处验证线格式与透传）
test "1.27 enum negative values" {
  let schema = [{ name: "f", ctype: CInt(1) }]
  assert_eq(encode_fields(schema, [VSInt(-1L)]), b"\xFF")
  assert_eq(encode_fields(schema, [VSInt(-128L)]), b"\x80")
  assert_eq(rt(schema, [VSInt(-1L)]), Ok([VSInt(-1L)]))
  assert_eq(rt(schema, [VSInt(-128L)]), Ok([VSInt(-128L)]))
}

/// 测试 1.28：enum 未知值透传（按 base 整型保留原值，不报错）
test "1.28 enum unknown value passthrough" {
  let msg = dec_err(b"\xC8", CUInt(1)) // 200 未在 IDL values 中声明
  assert_eq(msg, "OK")
  let r = Reader::{ data: b"\xC8", pos: 0 }
  assert_eq(decode_field(r, CUInt(1), "f"), VUInt(200L))
}

/// 测试 1.29：enum 值域校验——编码值 300（base=u8）报错；重复值在 IDL 加载期拒绝
/// （重复值用例见 idlstore 测试）
test "1.29 enum value range" {
  assert_eq(enc_err(VUInt(300L), CUInt(1)), "f: u8 out of range: 300")
}

/// 测试 1.31：CRC + MSK 顺序——先附加 CRC-16/CCITT-FALSE（2B 大端），再整体 XOR；
/// 接收端先 XOR 还原 → 校验并剥离 CRC → 解码
test "1.31 CRC then masking order" {
  let schema = [{ name: "f", ctype: CUInt(2) }]
  let vals = [VUInt(0x1234L)]
  let body = encode_fields(schema, vals)
  // 发送端：CRC 附加 → XOR
  let with_crc = append_crc16(body)
  assert_eq(with_crc.length(), 4)
  let key = b"\xA5\x5A\x00\xFF"
  let masked = msk_xor(with_crc, key)
  assert_eq(masked.length(), 4)
  // 接收端：XOR 还原 → 校验剥离 → 解码
  let restored = msk_xor(masked, key)
  assert_eq(restored, with_crc)
  match verify_and_strip_crc(restored) {
    Ok(pure) => {
      assert_eq(pure, body)
      assert_eq(decode_fields(pure, schema), vals)
    }
    Err(_) => fail("crc verify failed")
  }
}

/// 测试 1.34：CRC 缺省关闭——未声明 crc 时字段序列后无 2B CRC
test "1.34 CRC disabled by default" {
  let schema = [
    { name: "a", ctype: CUInt(1) },
    { name: "b", ctype: CUInt(2) },
  ]
  let enc = encode_fields(schema, [VUInt(1L), VUInt(0x0203L)])
  assert_eq(enc, b"\x01\x02\x03") // 恰 3B 字段序列，无附加 CRC
}

/// 测试 1.35：CRC 开启与校验——正常通过；篡改 1 字节 → 校验失败（RST 0x20）
test "1.35 CRC enabled verify" {
  let body = encode_fields([{ name: "f", ctype: CUInt(4) }], [VUInt(0x12345678L)])
  let with_crc = append_crc16(body)
  assert_eq(with_crc.length(), body.length() + 2)
  match verify_and_strip_crc(with_crc) {
    Ok(pure) => assert_eq(pure, body)
    Err(_) => fail("crc verify failed")
  }
  // 篡改字段字节 → CRC 不匹配
  let tampered = @buffer.Buffer(size_hint=with_crc.length())
  tampered.write_byte(b'\x12')
  tampered.write_byte(b'\x34')
  tampered.write_byte(b'\x56')
  tampered.write_byte(b'\x79') // 0x78 → 0x79
  tampered.write_byte(with_crc[4])
  tampered.write_byte(with_crc[5])
  match verify_and_strip_crc(tampered.to_bytes()) {
    Ok(_) => fail("tampered crc should fail")
    Err(_) => ()
  }
}

/// 测试 1.36：末尾新增字段忽略——旧解码器按 schema 解完既有字段后忽略剩余字节
test "1.36 trailing new field ignored" {
  let old : Array[CField] = [{ name: "a", ctype: CUInt(1) }]
  let new_schema : Array[CField] = [
    { name: "a", ctype: CUInt(1) },
    { name: "b", ctype: CUInt(2) },
    { name: "c", ctype: CBool },
  ]
  let full = encode_fields(new_schema, [VUInt(1L), VUInt(0x0203L), VBool(true)])
  // 旧端只解第一个字段，剩余字节（新字段）忽略
  assert_eq(decode_fields(full, old), [VUInt(1L)])
}

/// 测试 1.38：大端统一（u16 0x1234 → 12 34；i16 -2 → FF FE）
test "1.38 big-endian encoding" {
  assert_eq(encode_fields([{ name: "f", ctype: CUInt(2) }], [VUInt(0x1234L)]), b"\x12\x34")
  assert_eq(encode_fields([{ name: "f", ctype: CInt(2) }], [VSInt(-2L)]), b"\xFF\xFE")
}

/// §9.1：顶层字段数与 schema 不一致 → 编码错误
test "field count mismatch" {
  let schema = [
    { name: "a", ctype: CUInt(1) },
    { name: "b", ctype: CUInt(1) },
  ]
  match rt(schema, [VUInt(1L)]) {
    Err(_) => ()
    Ok(_) => fail("count mismatch should fail")
  }
}

/// §9.3：固定长度声明非法（都缺 / 同时声明）→ 编解码均失败
test "length declaration validation" {
  assert_eq(enc_err(VString("x"), CString(None, None)) == "OK", false)
  assert_eq(enc_err(VBytes(b"x"), CBytes(Some(1), Some(1))) == "OK", false)
  assert_eq(dec_err(b"\x01", CString(None, None)) == "OK", false)
}
