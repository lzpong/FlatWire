// §7.1 SD Entry 编解码测试（blackbox：仅 pub API）

/// Offer Entry roundtrip（6B 定长拼装 + 大端）
test "offer entry roundtrip" {
  let entries : Array[OfferEntry] = [
    { svc_id: 4096, inst_id: 7, major_ver: 1, minor_ver: 2, ttl: 4 },
    { svc_id: 1, inst_id: 0, major_ver: 0, minor_ver: 0, ttl: 0 },
  ]
  let bytes = encode_offer_entries(entries)
  assert_eq(bytes.length(), 12)
  match parse_offer_entries(bytes) {
    Some(out) => {
      assert_eq(out.length(), 2)
      assert_eq(out[0].svc_id, 4096)
      assert_eq(out[0].inst_id, 7)
      assert_eq(out[0].major_ver, 1)
      assert_eq(out[0].minor_ver, 2)
      assert_eq(out[0].ttl, 4)
      assert_eq(out[1].svc_id, 1)
      assert_eq(out[1].ttl, 0)
    }
    None => fail("expect parse ok")
  }
}

/// Find Entry roundtrip（4B：无 MinorVer，§7.1）
test "find entry roundtrip" {
  let bytes = encode_find_entries([{ svc_id: 0x1234, inst_id: 9, major_ver: 3 }])
  assert_eq(bytes.length(), 4)
  match parse_find_entries(bytes) {
    Some(out) => {
      assert_eq(out.length(), 1)
      assert_eq(out[0].svc_id, 0x1234)
      assert_eq(out[0].inst_id, 9)
      assert_eq(out[0].major_ver, 3)
    }
    None => fail("expect parse ok")
  }
}

/// Subscribe Entry roundtrip（7B：IfID 2B 大端）
test "subscribe entry roundtrip" {
  let bytes = encode_sub_entries([
    { svc_id: 100, if_id: 32769, inst_id: 2, grp_id: 0, ttl: 4 },
    { svc_id: 100, if_id: 0, inst_id: 2, grp_id: 1, ttl: 0 },
  ])
  assert_eq(bytes.length(), 14)
  match parse_sub_entries(bytes) {
    Some(out) => {
      assert_eq(out.length(), 2)
      assert_eq(out[0].if_id, 32769)
      assert_eq(out[0].grp_id, 0)
      assert_eq(out[0].ttl, 4)
      assert_eq(out[1].if_id, 0)
      assert_eq(out[1].grp_id, 1)
      assert_eq(out[1].ttl, 0)
    }
    None => fail("expect parse ok")
  }
}

/// GetIDL Entry：恒 3B（残缺 <3B / 多余 >3B 均拒绝，§7.2 RST(0x20) 判定基础）
test "getidl entry strict 3b" {
  let bytes = encode_getidl_entry({ svc_id: 4096, major_ver: 1 })
  assert_eq(bytes.length(), 3)
  match parse_getidl_entry(bytes) {
    Some(e) => {
      assert_eq(e.svc_id, 4096)
      assert_eq(e.major_ver, 1)
    }
    None => fail("expect parse ok")
  }
  // 残缺 / 多余
  assert_eq(parse_getidl_entry(b"\x10\x00") is None, true)
  assert_eq(parse_getidl_entry(b"\x10\x00\x01\x02") is None, true)
  assert_eq(parse_getidl_entry(b"") is None, true)
}

/// 非 6/4/7 整除 → None（整帧无法解析判定的数据基础）
test "entry misaligned parse none" {
  assert_eq(parse_offer_entries(b"\x10\x00\x01") is None, true) // 3B
  assert_eq(parse_offer_entries(b"\x10\x00\x01\x02\x03") is None, true) // 5B
  assert_eq(parse_find_entries(b"\x10\x00\x01") is None, true) // 3B
  assert_eq(parse_sub_entries(b"\x10\x00\x01\x02\x03\x04") is None, true) // 6B
  // 空 Payload = 0 Entry（合法）
  assert_eq(parse_offer_entries(b"").unwrap().length(), 0)
  assert_eq(parse_find_entries(b"").unwrap().length(), 0)
  assert_eq(parse_sub_entries(b"").unwrap().length(), 0)
}
