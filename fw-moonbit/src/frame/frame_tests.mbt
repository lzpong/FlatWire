// frame 包测试：帧头编解码往返 + §4.3 解析矩阵（测试用例 2.6~2.21）+ TCP 流式/半帧两阶段（2.1~2.5/2.22~2.26/2.29）

/// 测试辅助：UDP 解析（本地 VER=0 / max_payload_len=1400）
fn parse_udp(data : Bytes) -> ParseOutcome {
  parse_datagram(data, 0, 1400)
}

/// 测试辅助：全字段 FrameSpec（可构造违规组合）
fn spec(
  ctr : Bool,
  ren : Bool,
  typ : Typ,
  code : Int,
  svc : Int,
  ifid : Int,
  inst : Int,
  strm : Int
) -> FrameSpec {
  FrameSpec::{
    ctr,
    ren,
    ver: 0,
    typ,
    code,
    svc_id: svc,
    if_id: ifid,
    inst_id: inst,
    strm_id: strm,
  }
}

/// 测试辅助：编码空 payload 数据帧
fn df(typ : Typ, code : Int, svc : Int, ifid : Int, inst : Int, strm : Int) -> Bytes raise FrameError {
  encode_frame(data_spec(typ, code, svc, ifid, inst, strm), b"", None)
}

/// 测试辅助：断言事件为帧并取出
fn expect_frame(e : TcpEvent) -> Frame raise FrameError {
  match e {
    TcpFrame(f) => f
    _ => raise FrameError("expect TcpFrame event")
  }
}

/// 测试辅助：喂入并收集交付的帧（其他事件视为异常）
fn feed_frames(p : TcpFrameParser, data : Bytes, t : Int64) -> Array[Frame] raise FrameError {
  let out : Array[Frame] = []
  for e in p.feed(data, t) {
    out.push(expect_frame(e))
  }
  out
}

/// 帧编解码往返（含 MSK）
test "frame encode/parse roundtrip" {
  let payload = b"\x01\x02\x03\x04\x05"
  let key = b"\xA5\x5A\x00\xFF"
  let raw = encode_frame(data_spec(Con, 0x01, 0x0001, 0x0002, 0x03, 0x04), payload, Some(key))
  match parse_udp(raw) {
    Ok(f) => {
      assert_eq(f.ctr, false)
      assert_eq(f.ren, false)
      assert_eq(f.ver, 0)
      assert_eq(f.msk, true)
      assert_eq(f.typ, Con)
      assert_eq(f.code, 0x01)
      assert_eq(f.svc_id, 0x0001)
      assert_eq(f.if_id, 0x0002)
      assert_eq(f.inst_id, 0x03)
      assert_eq(f.strm_id, 0x04)
      // §10：MSK 已还原
      assert_eq(f.payload, payload)
    }
    _ => fail("expect Ok(frame)")
  }
}

/// 空 payload 帧 = 8B 纯帧头（§3.2：PLB=0 无 Length 字段）
test "empty payload frame is 8 bytes" {
  let raw = df(Non, 0x01, 1, 1, 1, 1)
  assert_eq(raw.length(), 8)
  match parse_udp(raw) {
    Ok(f) => assert_eq(f.payload, b"")
    _ => fail("expect Ok(frame)")
  }
}

/// MSK=0 明文帧往返
test "frame without mask roundtrip" {
  let payload = b"\xDE\xAD\xBE\xEF"
  let raw = encode_frame(data_spec(Non, 0x03, 0x1234, 0x8001, 0xAB, 0xFE), payload, None)
  match parse_udp(raw) {
    Ok(f) => {
      assert_eq(f.msk, false)
      assert_eq(f.svc_id, 0x1234)
      assert_eq(f.if_id, 0x8001)
      assert_eq(f.inst_id, 0xAB)
      assert_eq(f.strm_id, 0xFE)
      assert_eq(f.payload, payload)
    }
    _ => fail("expect Ok(frame)")
  }
}

/// §4.3 步骤 1：VER 不一致 → RST(0x22)（测试 2.x 版本校验）
test "version mismatch rejected with 0x22" {
  let raw = df(Non, 0x01, 1, 1, 1, 1)
  // 本地 VER=1，帧 VER=0 → 不一致
  match parse_datagram(raw, 1, 1400) {
    Reject(code, _) => assert_eq(code, 0x22)
    _ => fail("expect Reject(0x22)")
  }
}

/// 控制帧 MSK=1 违规（测试 2.29：控制帧固定 MSK=0）
test "control frame with mask rejected (2.29)" {
  let key = b"\x01\x02\x03\x04"
  let raw = encode_frame(ctrl_spec(Non, 0x01, 0), b"\xAA", Some(key))
  match parse_udp(raw) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("expect Reject(0x00)")
  }
}

/// REN 组合违规（测试 2.9/2.10/2.11）
test "ren combos rejected (2.9~2.11)" {
  // 2.9：REN=1 且 CTR=0
  match parse_udp(encode_frame(spec(false, true, Non, 0x00, 1, 1, 1, 1), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.9 expect Reject(0x00)")
  }
  // 2.10：REN=1 且 TYP=CON
  match parse_udp(encode_frame(spec(true, true, Con, 0x00, 0, 0, 0, 0), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.10 expect Reject(0x00)")
  }
  // 2.11：REN=1 且 Code≠0x00
  match parse_udp(encode_frame(spec(true, true, Non, 0x01, 0, 0, 0, 0), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.11 expect Reject(0x00)")
  }
  // REN 合法形态：CTR=1, TYP=NON, Code=0, StrmID=0（§3.6）
  match parse_udp(encode_frame(spec(true, true, Non, 0x00, 0, 0, 0, 0), b"", None)) {
    Ok(f) => {
      assert_eq(f.ren, true)
      assert_eq(f.ctr, true)
    }
    _ => fail("REN valid form expect Ok")
  }
}

/// ACK Code 合法性（测试 2.12）
test "ack code validation (2.12)" {
  // 数据帧 ACK Code≠0x00
  match parse_udp(encode_frame(spec(false, false, Ack, 0x10, 1, 1, 1, 1), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.12 data-ack expect Reject(0x00)")
  }
  // 控制帧 ACK Code∉{0x00, 0x10}
  match parse_udp(encode_frame(spec(true, false, Ack, 0x01, 0, 0, 0, 0), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.12 ctrl-ack expect Reject(0x00)")
  }
  // 控制帧 ACK Code=0x10（Subscribe 建立确认）合法
  match parse_udp(encode_frame(ctrl_spec(Ack, 0x10, 5), b"", None)) {
    Ok(f) => assert_eq(f.strm_id, 5)
    _ => fail("ctrl-ack 0x10 expect Ok")
  }
}

/// 控制帧 SvcID/IfID 非 0（测试 2.13）
test "control frame nonzero svc rejected (2.13)" {
  match parse_udp(encode_frame(spec(true, false, Non, 0x01, 1, 0, 0, 0), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.13 expect Reject(0x00)")
  }
}

/// 数据帧 SvcID=0 / IfID=0 / InstID=0 / StrmID 越界（测试 2.14/2.15/2.18/2.19）
test "data frame id validation (2.14/2.15/2.18/2.19)" {
  // 2.14：SvcID=0
  match parse_udp(encode_frame(spec(false, false, Con, 0x01, 0, 1, 1, 1), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.14 expect Reject(0x00)")
  }
  // 2.19：IfID=0
  match parse_udp(encode_frame(spec(false, false, Con, 0x01, 1, 0, 1, 1), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.19 expect Reject(0x00)")
  }
  // 2.15：InstID=0
  match parse_udp(encode_frame(spec(false, false, Con, 0x01, 1, 1, 0, 1), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.15 expect Reject(0x00)")
  }
  // 2.18：StrmID=0x00
  match parse_udp(encode_frame(spec(false, false, Con, 0x01, 1, 1, 1, 0), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.18 strm=0 expect Reject(0x00)")
  }
  // 2.18：StrmID=0xFF（保留）
  match parse_udp(encode_frame(spec(false, false, Con, 0x01, 1, 1, 1, 0xFF), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.18 strm=0xFF expect Reject(0x00)")
  }
}

/// ACK/RST 帧 PLB>0（测试 2.16）
test "ack/rst with payload rejected (2.16)" {
  // ACK PLB>0
  match parse_udp(encode_frame(spec(false, false, Ack, 0x00, 1, 1, 1, 1), b"\x01", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.16 ack expect Reject(0x00)")
  }
  // RST PLB>0
  match parse_udp(encode_frame(spec(false, false, Rst, 0x20, 1, 1, 1, 1), b"\x01", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.16 rst expect Reject(0x00)")
  }
}

/// 控制帧 StrmID 范围 + 语义校验（测试 2.17）
test "control frame strm_id semantics (2.17)" {
  // Subscribe(0x03) StrmID=0x00 → 违规
  match parse_udp(encode_frame(ctrl_spec(Con, 0x03, 0), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.17 subscribe strm=0 expect Reject(0x00)")
  }
  // 连接级帧（Find 0x02）StrmID=5 → 违规
  match parse_udp(encode_frame(ctrl_spec(Non, 0x02, 5), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.17 find strm=5 expect Reject(0x00)")
  }
  // 控制帧 StrmID=0x80（超出 0x00~0x7F）→ 违规
  match parse_udp(encode_frame(spec(true, false, Non, 0x10, 0, 0, 0, 0x80), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.17 strm=0x80 expect Reject(0x00)")
  }
  // Subscribe 携带 0x01~0x7F 合法
  match parse_udp(encode_frame(ctrl_spec(Con, 0x03, 5), b"", None)) {
    Ok(f) => assert_eq(f.strm_id, 5)
    _ => fail("2.17 subscribe strm=5 expect Ok")
  }
  // GetIDL(0x04) 携带 0x01~0x7F 合法（TCP 单播侧验证；UDP 侧拒绝由 "udp getidl rejected" 覆盖）
  let getidl_raw = encode_frame(ctrl_spec(Non, 0x04, 0x7F), b"\x10\x00\x01", None)
  match validate_header(parse_header(getidl_raw), 0, true) {
    None => ()
    Some(code) => fail("2.17 getidl strm=0x7F on TCP should be legal, got RST(0x\{code})")
  }
  // REN 帧 StrmID≠0 → 违规
  match parse_udp(encode_frame(spec(true, true, Non, 0x00, 0, 0, 0, 1), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.17 ren strm≠0 expect Reject(0x00)")
  }
}

/// RST Code 非法（测试 2.20：RST Code ∈ {0x00} ∪ 0x20~0x3F）
test "rst code validation (2.20)" {
  match parse_udp(encode_frame(spec(false, false, Rst, 0x01, 1, 1, 1, 1), b"", None)) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("2.20 expect Reject(0x00)")
  }
}

/// TCP 收 CON/ACK 违规（测试 2.21：TCP 不使用 CON/ACK）
test "tcp con/ack rejected (2.21)" {
  let raw = df(Con, 0x01, 1, 1, 1, 1)
  let h = parse_header(raw)
  match validate_header(h, 0, true) {
    Some(code) => assert_eq(code, 0x00)
    None => fail("2.21 expect violation on TCP")
  }
  let raw_ack = encode_frame(spec(false, false, Ack, 0x00, 1, 1, 1, 1), b"", None)
  match validate_header(parse_header(raw_ack), 0, true) {
    Some(code) => assert_eq(code, 0x00)
    None => fail("2.21 ack expect violation on TCP")
  }
}

/// UDP GetIDL 传输绑定违规（§4.3 步骤 2：GetIDL 仅 TCP 单播）
test "udp getidl rejected" {
  // GetIDL Entry 3B payload
  let raw = encode_frame(ctrl_spec(Non, 0x04, 5), b"\x10\x00\x01", None)
  match parse_udp(raw) {
    Reject(code, _) => assert_eq(code, 0x00)
    _ => fail("udp getidl expect Reject(0x00)")
  }
}

/// UDP 长度不符（测试 2.6：多余或不足一律丢弃，不截断）
test "udp length mismatch dropped (2.6)" {
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), b"\x01\x02\x03\x04\x05", None)
  // 不足：截掉 2 字节 payload
  match parse_udp(@codec.sub_bytes(raw, 0, raw.length() - 2)) {
    Drop => ()
    _ => fail("2.6 short expect Drop")
  }
  // 多余：附加 1 字节
  match parse_udp(@codec.concat_bytes(raw, b"\x00")) {
    Drop => ()
    _ => fail("2.6 extra expect Drop")
  }
}

/// UDP 过短（测试 2.7：数据报 < 8B 丢弃）
test "udp too short dropped (2.7)" {
  match parse_udp(b"\x01\x02\x03") {
    Drop => ()
    _ => fail("2.7 expect Drop")
  }
}

/// UDP 帧级超限（测试 2.8：Payload > max_payload_len → RST(0x23)）
test "udp payload too large (2.8)" {
  let big = @codec.bytes_of_array(Array::make(1401, b'\x00'))
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), big, None)
  match parse_udp(raw) {
    Reject(code, _) => assert_eq(code, 0x23)
    _ => fail("2.8 expect Reject(0x23)")
  }
  // TCP 无此帧级校验：validate 不含长度逻辑，由流式解析器不检查确认（§4.3 步骤 5）
}

/// TCP 粘包：一次接收含 3 帧（测试 2.1）
test "tcp coalescing three frames (2.1)" {
  let p = TcpFrameParser::new(0, 5000L)
  let f1 = df(Non, 0x01, 1, 1, 1, 1)
  let f2 = df(Non, 0x01, 1, 1, 1, 2)
  let f3 = df(Non, 0x01, 1, 1, 1, 3)
  let all = @codec.concat_bytes(@codec.concat_bytes(f1, f2), f3)
  let frames = feed_frames(p, all, 1000L)
  assert_eq(frames.length(), 3)
  assert_eq(frames[0].strm_id, 1)
  assert_eq(frames[1].strm_id, 2)
  assert_eq(frames[2].strm_id, 3)
}

/// TCP 分包：1 帧按 1 字节/次写入（测试 2.2）
test "tcp byte-by-byte (2.2)" {
  let p = TcpFrameParser::new(0, 5000L)
  let payload = b"\xAA\xBB\xCC"
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), payload, None)
  let got : Array[Frame] = []
  let mut t = 1000L
  for i in 0..<raw.length() {
    t = t + 1L
    for f in feed_frames(p, @codec.sub_bytes(raw, i, i + 1), t) {
      got.push(f)
    }
  }
  assert_eq(got.length(), 1)
  assert_eq(got[0].payload, payload)
}

/// Length 字段跨包（测试 2.3）
test "tcp length field split (2.3)" {
  let p = TcpFrameParser::new(0, 5000L)
  let payload = @codec.bytes_of_array(Array::make(200, b'\x5A'))
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), payload, None) // plb=2
  // 帧头 8B / Length 2B 分两次 / payload
  let _ = feed_frames(p, @codec.sub_bytes(raw, 0, 8), 1000L)
  let _ = feed_frames(p, @codec.sub_bytes(raw, 8, 9), 1001L)
  let frames = feed_frames(p, @codec.sub_bytes(raw, 9, raw.length()), 1002L)
  assert_eq(frames.length(), 1)
  assert_eq(frames[0].payload, payload)
}

/// Masking Key 跨包（测试 2.4）
test "tcp mask key split (2.4)" {
  let p = TcpFrameParser::new(0, 5000L)
  let payload = b"\x0F\xF0"
  let key = b"\xDE\xAD\xBE\xEF"
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), payload, Some(key)) // 8+1+4+2=15B
  let _ = feed_frames(p, @codec.sub_bytes(raw, 0, 8), 1000L) // 帧头
  let _ = feed_frames(p, @codec.sub_bytes(raw, 8, 9), 1001L) // Length
  let _ = feed_frames(p, @codec.sub_bytes(raw, 9, 11), 1002L) // Key 前 2B
  let _ = feed_frames(p, @codec.sub_bytes(raw, 11, 13), 1003L) // Key 后 2B
  let frames = feed_frames(p, @codec.sub_bytes(raw, 13, 15), 1004L) // Payload
  assert_eq(frames.length(), 1)
  // §10：XOR 已还原
  assert_eq(frames[0].payload, payload)
}

/// TCP 半帧超时——帧头不完整（<8B）→ RST(0x26) + 关连接（测试 2.5）
test "tcp half-frame stage1 header incomplete (2.5)" {
  let p = TcpFrameParser::new(0, 5000L)
  let raw = df(Non, 0x01, 1, 1, 1, 1)
  let _ = p.feed(@codec.sub_bytes(raw, 0, 4), 1000L) // 仅 4B
  let events = p.check_timeout(6500L) // 超过 tcp_frame_timeout_ms
  assert_eq(events.length(), 2)
  assert_eq(events[0], TcpRst26)
  assert_eq(events[1], TcpClose)
}

/// TCP 半帧超时——帧头完整 → RST(0x26) + 丢弃模式，不关连接（测试 2.22）
test "tcp half-frame stage2 drop mode (2.22)" {
  let p = TcpFrameParser::new(0, 5000L)
  let payload = @codec.bytes_of_array(Array::make(100, b'\x00'))
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), payload, None) // 8+1+100=109B
  let _ = p.feed(@codec.sub_bytes(raw, 0, 18), 1000L) // 帧头 8B + Length 1B + payload 9B
  let events = p.check_timeout(6500L)
  // 仅 RST(0x26)，不关连接
  assert_eq(events.length(), 1)
  assert_eq(events[0], TcpRst26)
  // 发完剩余 91B → 恢复正常接收（测试 2.23：连接继续复用）
  let rest = @codec.sub_bytes(raw, 18, raw.length())
  assert_eq(p.feed(rest, 7000L).length(), 0)
  let nf = df(Non, 0x01, 1, 1, 1, 2)
  let ev2 = p.feed(nf, 7100L)
  assert_eq(ev2.length(), 1)
  assert_eq(expect_frame(ev2[0]).strm_id, 2)
}

/// 丢弃模式——每字节刷新兜底计时（测试 2.24）
test "drop mode byte refresh (2.24)" {
  let p = TcpFrameParser::new(0, 5000L)
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), @codec.bytes_of_array(Array::make(50, b'\x01')), None)
  let _ = p.feed(@codec.sub_bytes(raw, 0, 9), 1000L) // 帧 8B + Length 1B + payload 1B
  let _ = p.check_timeout(6500L) // 进入丢弃模式 R=50-1=49
  // 每字节间隔 1500ms（< 兜底 10000ms），总时长远超兜底但每字节刷新
  let mut t = 6500L
  for i in 9..<raw.length() {
    t = t + 1500L
    let _ = p.feed(@codec.sub_bytes(raw, i, i + 1), t)
    // 每字节后检查：不得触发兜底超时
    assert_eq(p.check_timeout(t + 1600L).length(), 0)
  }
  // 收满恢复：新帧正常解析交付
  let ev = feed_frames(p, df(Non, 0x01, 1, 1, 1, 2), t + 2000L)
  assert_eq(ev.length(), 1)
  assert_eq(ev[0].strm_id, 2)
}

/// 丢弃模式——兜底超时关连接（测试 2.26：2 × tcp_frame_timeout_ms 完全停止发送）
test "drop mode floor timeout (2.26)" {
  let p = TcpFrameParser::new(0, 5000L)
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), @codec.bytes_of_array(Array::make(50, b'\x01')), None)
  let _ = p.feed(@codec.sub_bytes(raw, 0, 9), 1000L)
  let _ = p.check_timeout(6500L)
  // 兜底 = 2 × 5000 = 10000ms 无任意字节 → 关闭连接
  let events = p.check_timeout(16500L)
  assert_eq(events.length(), 1)
  assert_eq(events[0], TcpClose)
}

/// 半帧——帧头 ≥8B 但 Length 未收齐 → 帧总长不可知 → 阶段一关连接（§4.1 判据）
test "tcp half-frame length incomplete to stage1" {
  let p = TcpFrameParser::new(0, 5000L)
  let raw = encode_frame(data_spec(Non, 0x01, 1, 1, 1, 1), @codec.bytes_of_array(Array::make(10, b'\x01')), None)
  let _ = p.feed(@codec.sub_bytes(raw, 0, 8), 1000L) // 仅帧头 8B，Length 未收
  let events = p.check_timeout(6500L)
  assert_eq(events.length(), 2)
  assert_eq(events[0], TcpRst26)
  assert_eq(events[1], TcpClose)
}

/// 违规帧收完丢弃保持流对齐，后续合法帧正常交付
test "tcp violated frame keeps stream aligned" {
  let p = TcpFrameParser::new(0, 5000L)
  // 违规：数据帧 InstID=0（payload 3B）
  let bad = encode_frame(spec(false, false, Non, 0x01, 1, 1, 0, 1), b"\x01\x02\x03", None)
  let good = df(Non, 0x01, 1, 1, 1, 1)
  let events = p.feed(@codec.concat_bytes(bad, good), 1000L)
  // 事件：Reject(0x00)（bad 收完不交付）+ 帧（good）
  assert_eq(events.length(), 2)
  match events[0] {
    TcpReject(code, _) => assert_eq(code, 0x00)
    _ => fail("expect TcpReject(0x00)")
  }
  assert_eq(expect_frame(events[1]).strm_id, 1)
}

/// TCP 纯 8B 帧（PLB=0、MSK=0）立即交付
test "tcp zero-payload frame immediate" {
  let p = TcpFrameParser::new(0, 5000L)
  let frames = feed_frames(p, df(Non, 0x01, 1, 1, 1, 1), 1000L)
  assert_eq(frames.length(), 1)
  assert_eq(frames[0].payload, b"")
  assert_eq(frames[0].inst_id, 1)
}
