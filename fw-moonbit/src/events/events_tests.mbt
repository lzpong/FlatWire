// 事件层 inline 测试（同包访问 priv 字段：cache / out_cons / recv_seen / client_subs）
//
// 服务端订阅记录经 sd 层真实入口建立（offer_start 注册本地实例 + Subscribe CON 控制帧
// → on_udp_ctrl → server_subs 登记 + SubEstablished 上抛），与集成路径一致；
// Transport::new / DataStrmPool::new 均为纯构造，未启动时发送静默跳过，状态可完整断言

/// 构造测试用 Events（Sd 事件捕获到数组供测试桥接）
fn make_events() -> (Events, @strm.DataStrmPool, Array[@sd.SdEvent]) {
  let tcfg : @transport.TransportConfig = {
    udp_port: 5400,
    tcp_port: 5400, // §2 TCP/UDP 共用端口 5400（规范 §2）
    bind_address: "",
    tcp_enabled: true,
    local_ver: 0,
    max_payload_len: 1400,
    tcp_frame_timeout_ms: 5000L,
    heartbeat_period_ms: 30000L,
  }
  let t = @transport.Transport::new(tcfg, fn(_e) { () })
  let pool = @strm.DataStrmPool::new()
  let store = @idlstore.IdlStore::new("unused_dir")
  let events : Array[@sd.SdEvent] = []
  let sd = @sd.Sd::new(@sd.SdConfig::default(), t, store, @strm.CtrlStrmPool::new(), fn(e) {
    events.push(e)
  })
  let ev = Events::new(t, pool, store, sd)
  (ev, pool, events)
}

/// 预置 event 接口定义（tcp=false；reliable 可选；组 1 含该接口）
fn put_event_iface(ev : Events, svc_id : Int, if_id : Int, reliable : Bool) -> Unit {
  let def : @idlstore.IdlDef = {
    name: "t",
    svc_id,
    major_ver: 1,
    minor_ver: 0,
    interfaces: [
      {
        name: "e",
        if_id,
        kind: @idlstore.IfEvent,
        tcp: false,
        max_payload: 0,
        reliable,
        input: [],
        output: None,
      },
    ],
    groups: [{ name: "g1", grp_id: 1, members: [if_id] }],
    raw: "{}",
  }
  let _ = ev.store.put(def)
}

/// 构造 Subscribe CON 控制帧（SubEntry 7B 大端：SvcID|IfID|InstID|GrpId|TTL，§7.1 同 encode_sub_entries）
fn sub_frame(svc_id : Int, inst_id : Int, if_id : Int, grp_id : Int, ttl : Int) -> @frame.Frame {
  // §7.1 SubEntry 字节序：SvcID(2B) + IfID(2B) + InstID + GrpId + TTL（恒定宽度大端）
  let buf = @buffer.Buffer(size_hint=8)
  buf.write_byte(((svc_id >> 8) & 0xFF).to_byte())
  buf.write_byte((svc_id & 0xFF).to_byte())
  buf.write_byte(((if_id >> 8) & 0xFF).to_byte())
  buf.write_byte((if_id & 0xFF).to_byte())
  buf.write_byte(inst_id.to_byte())
  buf.write_byte(grp_id.to_byte())
  buf.write_byte(ttl.to_byte())
  {
    ctr: true,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Con,
    code: 0x03,
    svc_id: 0,
    if_id: 0,
    inst_id: 0,
    strm_id: 5,
    payload: buf.to_bytes(),
  }
}

/// 经 sd 层真实入口建立服务端订阅（本地实例注册 → Subscribe CON → 登记 + 事件上抛）
/// 返回上抛的 SubEstablished 事件（供 on_sub_established 桥接测试）
fn setup_sub(
  ev : Events,
  events : Array[@sd.SdEvent],
  svc_id : Int,
  inst_id : Int,
  if_id : Int
) -> Unit {
  // 本地实例注册（服务端存在性检查前提，§7.2）
  ev.sd.offer_start(svc_id, inst_id, 1, 0)
  // Subscribe CON 经 pub 入口进入服务端处理（登记 + SubEstablished，§8.1）
  // from_server=true：模拟 server socket 收帧（该参数仅影响 Code=0x04 GetIDL 分支）
  ev.sd.on_udp_ctrl(sub_frame(svc_id, inst_id, if_id, 0, 4), "10.0.0.1", 5000, true)
  // SubEstablished 桥接 events 全量推送（stack 层职责，测试内手动桥接）
  for e in events {
    match e {
      @sd.SubEstablished(s) => ev.on_sub_established(s)
      _ => ()
    }
  }
}

/// notify：缓存更新 + NON 推送发完即释放 StrmID（§6.2 NON → Closed）
test "notify non releases strm" {
  let (ev, pool, _events) = make_events()
  put_event_iface(ev, 1, 0x8001, false)
  setup_sub(ev, _events, 1, 1, 0x8001)
  ev.notify(1, 1, 0x8001, b"\x01\x02")
  // 缓存已更新（§8.1 数据源；插值为十进制 0x8001=32769）
  assert_eq(ev.cache.get("1|1|32769") is Some(_), true)
  // NON 发送完成即释放（§6.2 NON → Closed）；0x80 刚释放处于冷却（§6.3）→ 下一分配 0x81
  assert_eq(pool.alloc_server("10.0.0.1", 1, 1), Some(0x81))
  // 无 CON 重传残留
  assert_eq(ev.out_cons.length(), 0)
}

/// reliable 事件：CON 推送进重传链 → ACK 到达清理（§5.3/§5.5/§6.2）
test "notify reliable con and ack" {
  let (ev, pool, _events) = make_events()
  put_event_iface(ev, 1, 0x8001, true)
  setup_sub(ev, _events, 1, 1, 0x8001)
  ev.notify(1, 1, 0x8001, b"\x01")
  // CON 保持 Active：server 首流 0x80 被占用 → 下一分配为 0x81（§6.2）
  assert_eq(pool.alloc_server("10.0.0.1", 1, 1), Some(0x81))
  let _ = pool.release("10.0.0.1", 1, 1, 0x81)
  // 重传记录登记（键 = peer|svc|inst|strm；0x80=128）
  assert_eq(ev.out_cons.contains("10.0.0.1|1|1|128"), true)
  // 客户端 ACK 到达 → 停链 + 释放 StrmID（§6.2）
  ev.on_udp_ack(
    {
      ctr: false,
      ren: false,
      ver: 0,
      msk: false,
      typ: @frame.Ack,
      code: 0x00,
      svc_id: 1,
      if_id: 0x8001,
      inst_id: 1,
      strm_id: 128,
      payload: b"",
    },
    "10.0.0.1",
  )
  assert_eq(ev.out_cons.length(), 0)
  // 0x80（ACK 释放）与 0x81（上一断言分配后释放）均在冷却（§6.3）→ 下一分配 0x82
  assert_eq(pool.alloc_server("10.0.0.1", 1, 1), Some(0x82))
}

/// 客户端接收：首个交付 + 重复 CON 去重（重复仍回 ACK，仅不重复交付，§8.2）
test "notification dedup" {
  let (ev, _pool, _events) = make_events()
  let mut deliveries = 0
  let _k = ev.reg_client(1, 0x8001, 0, fn(_if_id, _p) { deliveries = deliveries + 1 })
  let f : @frame.Frame = {
    ctr: false,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Con,
    code: 0x03,
    svc_id: 1,
    if_id: 0x8001,
    inst_id: 1,
    strm_id: 0x90,
    payload: b"\x07",
  }
  ev.on_udp_data(f, "10.0.0.9", 5000)
  ev.on_udp_data(f, "10.0.0.9", 5000)
  assert_eq(deliveries, 1)
  assert_eq(ev.recv_seen.contains("10.0.0.9|1|1|144"), true)
}

/// 组订阅交付：无精确回调时按接口归属组展开（§7.1/§8.2）
test "notification group delivery" {
  let (ev, _pool, _events) = make_events()
  put_event_iface(ev, 1, 0x8001, false)
  let mut hit_if = -1
  let _k = ev.reg_client(1, 0, 1, fn(if_id, _p) { hit_if = if_id })
  let f : @frame.Frame = {
    ctr: false,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Non,
    code: 0x03,
    svc_id: 1,
    if_id: 0x8001,
    inst_id: 1,
    strm_id: 0x91,
    payload: b"\x08",
  }
  ev.on_udp_data(f, "10.0.0.9", 5000)
  assert_eq(hit_if, 0x8001)
}

/// 全量推送（§8.1：订阅建立时有缓存 → 经 SubEstablished 桥接推送；reliable → CON 登记）
test "sub established pushes cache" {
  let (ev, _pool, _events) = make_events()
  put_event_iface(ev, 1, 0x8001, true)
  // 先缓存数据（notify 时无订阅者 → 仅缓存）
  ev.notify(1, 1, 0x8001, b"\xc0")
  ev.out_cons.clear()
  // 经真实入口建立订阅 → SubEstablished → 全量推送（setup_sub 内桥接）
  setup_sub(ev, _events, 1, 1, 0x8001)
  // reliable → CON 推送登记重传记录（StrmID=0x80=128）
  assert_eq(ev.out_cons.contains("10.0.0.1|1|1|128"), true)
}
