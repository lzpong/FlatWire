﻿// transport 包测试：仅覆盖纯函数（RST 构造 / Ping 帧）。
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

/// §4.4 组播启发式 + 静默范围：必须与 Node/C 一致（R1-6 收口）
/// 组播候选 = CTR=1 且 (Offer/Find/REN)；只有 VER 不符、UDP-GetIDL、控制帧 StrmID 语义违规可静默，
/// 其余违规（如 SvcID 缺失、ACK 形态错误）一律回 RST。
test "multicast silent scope matches node/c" {
  // Offer（CTR=1, Code=0x01, StrmID=0）→ 组播候选
  let offer = @frame.FrameHeader::{
    ctr: true, ren: false, ver: 0, msk: false, plb: 0, typ: @frame.Non, code: 0x01,
    svc_id: 0x1234, if_id: 1, inst_id: 1, strm_id: 0,
  }
  assert_eq(is_multicast_like(offer), true)
  // 数据帧（CTR=0）永不视为组播
  let data = @frame.FrameHeader::{
    ctr: false, ren: false, ver: 0, msk: false, plb: 0, typ: @frame.Non, code: 0x01,
    svc_id: 0x1234, if_id: 1, inst_id: 1, strm_id: 1,
  }
  assert_eq(is_multicast_like(data), false)
  // VER 不符 → 组播候选静默
  assert_eq(is_silent_violation(offer, @errors.RST_UNSUPPORTED_VERSION), true)
  // UDP 上的 GetIDL（0x04，§7.2）→ 静默
  let getidl = @frame.FrameHeader::{
    ctr: true, ren: false, ver: 0, msk: false, plb: 0, typ: @frame.Non, code: 0x04,
    svc_id: 0x1234, if_id: 1, inst_id: 1, strm_id: 1,
  }
  assert_eq(is_silent_violation(getidl, @errors.RST_OK), true)
  // Subscribe 缺 StrmID（Code=0x03, StrmID=0）→ 静默
  let sub0 = @frame.FrameHeader::{
    ctr: true, ren: false, ver: 0, msk: false, plb: 0, typ: @frame.Non, code: 0x03,
    svc_id: 0x1234, if_id: 1, inst_id: 1, strm_id: 0,
  }
  assert_eq(is_silent_violation(sub0, @errors.RST_OK), true)
  // 连接级帧带 StrmID（Code=0x00, StrmID≠0）→ 静默
  let ping1 = @frame.FrameHeader::{
    ctr: true, ren: false, ver: 0, msk: false, plb: 0, typ: @frame.Non, code: 0x00,
    svc_id: 0x1234, if_id: 1, inst_id: 1, strm_id: 1,
  }
  assert_eq(is_silent_violation(ping1, @errors.RST_OK), true)
  // 取消确认 ACK(Code=0x00, TYP=ACK, StrmID≠0) → 合法，不属静默集合（§3.7/§8.1）
  let cancel_ack = @frame.FrameHeader::{
    ctr: true, ren: false, ver: 0, msk: false, plb: 0, typ: @frame.Ack, code: 0x00,
    svc_id: 0x1234, if_id: 1, inst_id: 1, strm_id: 1,
  }
  assert_eq(is_silent_violation(cancel_ack, @errors.RST_OK), false)
  // 控制帧 ACK(0x10) StrmID=0：口径定案后不判违规，不在静默集合
  let sub_ack = @frame.FrameHeader::{
    ctr: true, ren: false, ver: 0, msk: false, plb: 0, typ: @frame.Ack, code: 0x10,
    svc_id: 0x1234, if_id: 1, inst_id: 1, strm_id: 0,
  }
  assert_eq(is_silent_violation(sub_ack, @errors.RST_OK), false)
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
    max_send_queue_bytes: 262144, // §12.6 背压默认
    send_queue_budget_bytes: 67108864,
  }
  let t = Transport::new(cfg, fn(_e) { () })
  assert_eq(t.started, false)
  assert_eq(t.is_alive(1), false)
}

/// §12.6 背压：发送结果必须透传——连接不存在（未连接/已失效）返回 false，
/// 不得像旧版那样无论写入成败都返回 true（数据帧与控制帧分别验证）
test "send_tcp_frame reports not written for unknown conn" {
  let cfg : TransportConfig = {
    udp_port: 5400,
    tcp_port: 5400,
    bind_address: "",
    tcp_enabled: true,
    local_ver: 0,
    max_payload_len: 1400,
    tcp_frame_timeout_ms: 5000L,
    heartbeat_period_ms: 30000L,
    max_send_queue_bytes: 262144,
    send_queue_budget_bytes: 67108864,
  }
  let t = Transport::new(cfg, fn(_e) { () })
  // 未 start（globalThis.__fw 未初始化）+ conn_id 不存在 → false
  assert_eq(
    t.send_tcp_frame(999, @frame.data_spec(@frame.Non, 0x01, 1, 5, 1, 1), b""),
    false,
  )
  // 控制帧（Ping）同样不得伪造成功
  assert_eq(t.send_tcp_frame(999, @frame.ctrl_spec(@frame.Non, 0x00, 0), b""), false)
}
