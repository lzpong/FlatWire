/// §9.6 CRC-16/CCITT-FALSE
///
/// 唯一变体：poly=0x1021, init=0xFFFF, refin/refout=false, xorout=0x0000
/// 标准自检值：CRC-16/CCITT-FALSE("123456789") = 0x29B1（实现自检用，测试用例 1.33）

/// 逐字节计算 CRC-16/CCITT-FALSE（可链式续算）
pub fn crc16_ccitt_false_update(crc : Int, data : Bytes, offset : Int, len : Int) -> Int {
  let mut c = crc & 0xFFFF
  let mut i = offset
  let end = offset + len
  while i < end {
    // 大端位序（refin=false）：高字节在前，MSB 先行
    c = c ^ ((data[i].to_int() << 8) & 0xFFFF)
    let mut bit = 0
    while bit < 8 {
      if (c & 0x8000) != 0 {
        c = ((c << 1) ^ 0x1021) & 0xFFFF
      } else {
        c = (c << 1) & 0xFFFF
      }
      bit = bit + 1
    }
    i = i + 1
  }
  c
}

/// 一次性计算：init=0xFFFF 起步
pub fn crc16_ccitt_false(data : Bytes, offset : Int, len : Int) -> Int {
  crc16_ccitt_false_update(0xFFFF, data, offset, len)
}

/// 测试：标准自检值 0x29B1（§9.6 / 测试用例 1.33）
test "CRC-16/CCITT-FALSE self-check" {
  let input = b"123456789"
  assert_eq(crc16_ccitt_false(input, 0, input.length()), 0x29B1)
}

/// 测试：空串与单字节
test "CRC empty & single byte" {
  // 空串：无数据字节参与且无 xorout，结果 = init = 0xFFFF
  let empty = b""
  assert_eq(crc16_ccitt_false(empty, 0, 0), 0xFFFF)
  let single = b"A"
  // 已知参考值：CCITT-FALSE("A") = 0xB915
  assert_eq(crc16_ccitt_false(single, 0, 1), 0xB915)
}
