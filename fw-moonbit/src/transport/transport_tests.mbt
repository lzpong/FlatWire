// transport 包测试：仅覆盖纯函数（RST 构造 / Ping 帧）。
// 真 socket 收发 / 心跳 / 重连等异步行为在集成冒烟脚本验证——
// moon test 为同步执行块，无法等待 node 事件循环回调，busy-wait 会阻塞事件循环。

/// RST 回显触发帧 ID（§5.4；make_rst_frame 从 FrameHeader 构造回显）
test "make_rst_frame echoes trigger frame ids" {
  let raw_req = @frame.encode_frame(@frame.data_spec(@frame.Con, 0x01, 0x1234, 0x8001, 0xAB, 0xFE), b"\x01", None)
  let h = @frame.parse_header(raw_req)
  let raw = make_rst_frame(@errors.RST_BAD_REQUEST, Some(h))
  let f = @frame.parse_header(raw)
  assert_eq(f.ctr, false)
  assert_eq(f.typ, @frame.Rst)
  assert_eq(f.code, 0x20)
  assert_eq(f.svc_id, 0x1234)
  assert_eq(f.if_id, 0x8001)
  assert_eq(f.inst_id, 0xAB)
  assert_eq(f.strm_id, 0xFE)
  // RST 帧 PLB=0 无 Payload（§4.3 步骤 2 校验 + 帧 8B 长度隐含）
  assert_eq(raw.length(), 8)
}

/// 无帧头（半帧阶段一）→ 全 0 ID 的 RST（传输控制帧豁免 ID 校验）
test "make_rst_frame without header is all-zero ids" {
  let raw = make_rst_frame(@errors.RST_FRAME_TIMEOUT, None)
  let f = @frame.parse_header(raw)
  assert_eq(f.typ, @frame.Rst)
  assert_eq(f.code, 0x26)
  assert_eq(f.svc_id, 0)
  assert_eq(f.if_id, 0)
  assert_eq(f.inst_id, 0)
  assert_eq(f.strm_id, 0)
  assert_eq(raw.length(), 8)
}

/// §5.7 Ping 帧形态：CTR=1, REN=0, TYP=NON, Code=0x00, 全 ID=0, 空 Payload（8B 纯帧头）
test "ping frame form" {
  let raw = ping_frame()
  assert_eq(raw.length(), 8)
  let f = @frame.parse_header(raw)
  assert_eq(f.ctr, true)
  assert_eq(f.ren, false)
  assert_eq(f.typ, @frame.Non)
  assert_eq(f.code, 0x00)
  assert_eq(f.svc_id, 0)
  assert_eq(f.if_id, 0)
  assert_eq(f.inst_id, 0)
  assert_eq(f.strm_id, 0)
  assert_eq(raw.length(), 8)
}

/// Transport::new 初始状态（不触发 FFI，可安全单测）
test "transport initial state" {
  let cfg : TransportConfig = {
    udp_port: 5400,
    tcp_port: 5400, // §2 TCP/UDP 共用端口 5400（规范 §2）
    bind_address: "",
    tcp_enabled: true,
    local_ver: 0,
    max_payload_len: 1400,
    tcp_frame_timeout_ms: 5000L,
    heartbeat_period_ms: 30000L,
  }
  let t = Transport::new(cfg, fn(_e) { () })
  assert_eq(t.started, false)
  assert_eq(t.is_alive(1), false)
}
