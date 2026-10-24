// §10 MSK 掩码机制 + §9.6 CRC payload 级辅助
//
// - MSK：Payload Length 后 4B Key，对 Data Fields 逐字节循环 XOR（§10）
// - CRC：唯一变体 CRC-16/CCITT-FALSE，2B 大端附加于 Data 末尾（§9.6）
// - 顺序（发送端）：先附加 CRC，再整体 XOR；接收端相反（§9.6/§10）

/// MSK XOR：data 与 4B key 循环异或，返回新字节串（编解码对称）
pub fn msk_xor(data : Bytes, key : Bytes) -> Bytes {
  let n = data.length()
  let out = @buffer.Buffer(size_hint=n)
  for i in 0..<n {
    // §10：encoded[i] = payload[i] XOR maskingKey[i % 4]
    let k = key[i % 4].to_int()
    out.write_byte((data[i].to_int() ^ k).to_byte())
  }
  out.to_bytes()
}

/// 生成 4B 随机掩码 key（由传输层时间源驱动；MSK 非安全机制，§10）
pub fn msk_random_key(seed : Int) -> Bytes {
  let out = @buffer.Buffer(size_hint=4)
  let mut x = seed | 1
  for _ in 0..<4 {
    // xorshift 简易伪随机（仅混淆用途）
    x = (x ^ (x << 13)) & 0x7FFFFFFF
    x = (x ^ (x >> 17)) & 0x7FFFFFFF
    x = (x ^ (x << 5)) & 0x7FFFFFFF
    out.write_byte((x & 0xFF).to_byte())
  }
  out.to_bytes()
}

/// 附加 CRC-16/CCITT-FALSE：data + 2B 大端 CRC（§9.6，计入 Payload Length）
pub fn append_crc16(data : Bytes) -> Bytes {
  let crc = crc16_ccitt_false(data, 0, data.length())
  let out = @buffer.Buffer(size_hint=data.length() + 2)
  out.write_bytes(data)
  out.write_byte(((crc >> 8) & 0xFF).to_byte())
  out.write_byte((crc & 0xFF).to_byte())
  out.to_bytes()
}

/// 校验并剥离 CRC：输入 data+CRC（已 XOR 还原），成功返回纯 Data（§9.6 接收方顺序）
/// CRC 校验先于字段解码（§9.6）；不匹配按 0x20 Bad Request 处理（§12.1）
pub fn verify_and_strip_crc(payload : Bytes) -> Result[Bytes, Unit] {
  if payload.length() < 2 {
    return Err(())
  }
  let data_len = payload.length() - 2
  let expect = ((payload[data_len].to_int() << 8) & 0xFF00) | payload[data_len + 1].to_int()
  let actual = crc16_ccitt_false(payload, 0, data_len)
  if expect == actual {
    Ok(sub_bytes(payload, 0, data_len))
  } else {
    Err(())
  }
}

/// 字节串切片（[begin, end)）
pub fn sub_bytes(data : Bytes, begin : Int, end : Int) -> Bytes {
  let out = @buffer.Buffer(size_hint=end - begin)
  for i in begin..<end {
    out.write_byte(data[i])
  }
  out.to_bytes()
}

/// Bytes 拼接
pub fn concat_bytes(a : Bytes, b : Bytes) -> Bytes {
  let out = @buffer.Buffer(size_hint=a.length() + b.length())
  out.write_bytes(a)
  out.write_bytes(b)
  out.to_bytes()
}

/// 测试：MSK 两次 XOR 还原（测试用例 1.30）
test "masking xor roundtrip" {
  let data = b"\x01\x02\x03\x04\x05"
  let key = b"\xA5\x5A\x00\xFF"
  let masked = msk_xor(data, key)
  let restored = msk_xor(masked, key)
  assert_eq(restored, data)
}

/// 测试：CRC 附加与校验剥离往返（测试用例 1.31）
test "crc append & verify" {
  let data = b"123456789"
  let with_crc = append_crc16(data)
  assert_eq(with_crc.length(), data.length() + 2)
  match verify_and_strip_crc(with_crc) {
    Ok(rest) => assert_eq(rest, data)
    Err(_) => fail("crc verify failed")
  }
  // 篡改检测：数据末字节 '9'(0x39) → '8'(0x38)，携带的旧 CRC 不再匹配
  let good = append_crc16(b"123456789")
  let n = good.length()
  let out = @buffer.Buffer(size_hint=n)
  for i in 0..<n {
    // n-1/n-2 为 CRC 两字节，n-3 为最后一个数据字节
    if i == n - 3 {
      out.write_byte(b'\x38')
    } else {
      out.write_byte(good[i])
    }
  }
  match verify_and_strip_crc(out.to_bytes()) {
    Ok(_) => fail("tampered crc should fail")
    Err(_) => ()
  }
}
