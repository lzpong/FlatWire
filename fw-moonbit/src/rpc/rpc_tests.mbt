// RPC 层 inline 测试（同包访问 priv 字段：pending / cons / resp_cache / ff_seen）
//
// Transport::new / DataStrmPool::new 均为纯构造（无 FFI 副作用）；
// 未调用 start 时 globalThis.__fw 未初始化 → 发送静默跳过（发送方尽力而为语义），
// 收发逻辑与状态迁移可在 moon test 环境完整验证

/// 构造测试用 Rpc（返回各组件供状态断言）
fn make_rpc() -> (Rpc, @strm.DataStrmPool) {
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
  let r = Rpc::new(RpcConfig::default(), t, pool, store)
  (r, pool)
}

/// 预置 UDP rpc 接口定义（tcp=false → call 走 UDP CON 路径）
fn put_udp_iface(r : Rpc, svc_id : Int, if_id : Int, reliable_ignore : Bool) -> Unit {
  let def : @idlstore.IdlDef = {
    name: "t",
    svc_id,
    major_ver: 1,
    minor_ver: 0,
    interfaces: [
      {
        name: "m",
        if_id,
        kind: @idlstore.IfRpc,
        tcp: false,
        max_payload: 0,
        reliable: reliable_ignore,
        input: [],
        output: None,
      },
    ],
    groups: [],
    raw: "{}",
  }
  let _ = r.store.put(def)
}

/// 构造 UDP CON Request 帧
fn req_frame(svc_id : Int, inst_id : Int, if_id : Int, strm_id : Int) -> @frame.Frame {
  {
    ctr: false,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Con,
    code: 0x01,
    svc_id,
    if_id,
    inst_id,
    strm_id,
    payload: b"\x01\x02",
  }
}

/// 构造 UDP CON FF 帧
fn ff_frame(svc_id : Int, inst_id : Int, if_id : Int, strm_id : Int) -> @frame.Frame {
  { ..req_frame(svc_id, inst_id, if_id, strm_id), code: 0x02 }
}

/// 服务端 Request 处理：执行 handler + 响应缓存建立 + 重传幂等（§5.1/§5.5）
test "serve request with resp cache" {
  let (r, _pool) = make_rpc()
  put_udp_iface(r, 1, 5, false)
  let mut exec_count = 0
  r.register_handler(1, 1, 1, {
    on_request: fn(_if_id, _p) {
      exec_count = exec_count + 1
      Ok(b"\xaa")
    },
    on_ff: fn(_if_id, _p) { () },
  })
  let f = req_frame(1, 1, 5, 7)
  r.serve_request(f, "10.0.0.1", 5400, -1)
  assert_eq(exec_count, 1)
  // 响应缓存建立（键 = peer|svc|inst|strm）且回显请求 StrmID
  assert_eq(r.resp_cache.contains("10.0.0.1|1|1|7"), true)
  assert_eq(r.resp_cache.get("10.0.0.1|1|1|7").unwrap().spec.strm_id, 7)
  assert_eq(r.resp_cache.get("10.0.0.1|1|1|7").unwrap().spec.code, 0x10)
  // 重传到达（同帧再收）→ 直接重发缓存响应，不重新执行（§5.5）
  r.serve_request(f, "10.0.0.1", 5400, -1)
  assert_eq(exec_count, 1)
  // ACK 到达 → 缓存清除（§5.5 随 Stream 释放清除）
  r.on_udp_ack(
    {
      ctr: false,
      ren: false,
      ver: 0,
      msk: false,
      typ: @frame.Ack,
      code: 0x00,
      svc_id: 1,
      if_id: 5,
      inst_id: 1,
      strm_id: 7,
      payload: b"",
    },
    "10.0.0.1",
  )
  assert_eq(r.resp_cache.contains("10.0.0.1|1|1|7"), false)
}

/// 服务端未知服务 → RST 0x24 路径（handler 不执行，§5.4）
test "serve request unknown service" {
  let (r, _pool) = make_rpc()
  put_udp_iface(r, 1, 5, false)
  let mut exec_count = 0
  r.register_handler(1, 1, 1, {
    on_request: fn(_if_id, _p) {
      exec_count = exec_count + 1
      Ok(b"")
    },
    on_ff: fn(_if_id, _p) { () },
  })
  // svc=2 未注册 handler → RST(0x24)，无响应缓存
  r.serve_request(req_frame(2, 1, 5, 7), "10.0.0.1", 5400, -1)
  assert_eq(exec_count, 0)
  assert_eq(r.resp_cache.length(), 0)
}

/// 服务端 FF CON 幂等（§5.5：重复 CON 重发确认不重复执行）
test "serve ff dedup" {
  let (r, _pool) = make_rpc()
  put_udp_iface(r, 1, 5, false)
  let mut ff_count = 0
  r.register_handler(1, 1, 1, {
    on_request: fn(_if_id, _p) { Ok(b"") },
    on_ff: fn(_if_id, _p) { ff_count = ff_count + 1 },
  })
  let f = ff_frame(1, 1, 5, 9)
  r.serve_fire_forget(f, "10.0.0.2", 5400, -1)
  assert_eq(ff_count, 1)
  assert_eq(r.ff_seen.contains("10.0.0.2|1|1|9"), true)
  // 重传到达 → 不重复执行
  r.serve_fire_forget(f, "10.0.0.2", 5400, -1)
  assert_eq(ff_count, 1)
}

/// 客户端 call UDP 路径：登记 → Response 交付 → 全清理（§5.1/§6.2）
test "call and response" {
  let (r, pool) = make_rpc()
  put_udp_iface(r, 1, 5, false)
  let mut got : Bytes = b""
  let mut errs = 0
  r.call("10.0.0.1", 5400, 1, 1, 5, 1, b"\x01", 0, fn(p) { got = p }, fn(_e) { errs = errs + 1 })
  // 客户端流 StrmID 首次分配 = 0x01；pending + cons 登记
  let key = "10.0.0.1|1|1|1"
  assert_eq(r.pending.contains(key), true)
  assert_eq(r.cons.contains(key), true)
  // 响应到达（回显 StrmID=1）→ 交付 + 清理 + StrmID 释放（§6.2）
  r.on_udp_data_resp(
    {
      ctr: false,
      ren: false,
      ver: 0,
      msk: false,
      typ: @frame.Non,
      code: 0x10,
      svc_id: 1,
      if_id: 5,
      inst_id: 1,
      strm_id: 1,
      payload: b"\xbe\xef",
    },
    "10.0.0.1",
    5400,
  )
  assert_eq(got, b"\xbe\xef")
  assert_eq(errs, 0)
  assert_eq(r.pending.contains(key), false)
  assert_eq(r.cons.contains(key), false)
  // StrmID 已释放但处于冷却（§6.3：隔 ≥2 次其它分配才优先复用）→ 下一分配 0x02
  assert_eq(pool.alloc_client("10.0.0.1", 1, 1), Some(2))
}

/// 客户端重复响应去重（§5.5：按 StrmID 判定重复丢弃，只交付首个）
test "response dedup" {
  let (r, _pool) = make_rpc()
  put_udp_iface(r, 1, 5, false)
  let mut got_count = 0
  r.call("10.0.0.1", 5400, 1, 1, 5, 1, b"\x01", 0, fn(_p) { got_count = got_count + 1 }, fn(_e) { () })
  let resp : @frame.Frame = {
    ctr: false,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Non,
    code: 0x10,
    svc_id: 1,
    if_id: 5,
    inst_id: 1,
    strm_id: 1,
    payload: b"\x01",
  }
  r.on_udp_data_resp(resp, "10.0.0.1", 5400)
  r.on_udp_data_resp(resp, "10.0.0.1", 5400)
  assert_eq(got_count, 1)
}

/// 响应超时：on_err(RequestTimeout) + 重传链与 StrmID 一并清理（§5.1/§5.5）
test "call timeout clears state" {
  let (r, pool) = make_rpc()
  put_udp_iface(r, 1, 5, false)
  let mut err_kind = ""
  r.call("10.0.0.1", 5400, 1, 1, 5, 1, b"\x01", 0, fn(_p) { () }, fn(e) { err_kind = e.message() })
  let key = "10.0.0.1|1|1|1"
  // 直接触发超时（模拟 resp_timer 到期）
  r.call_timeout(key)
  assert_eq(err_kind, "Request Timeout")
  assert_eq(r.pending.contains(key), false)
  assert_eq(r.cons.contains(key), false)
  // StrmID 已释放但处于冷却（§6.3）→ 下一分配 0x02
  assert_eq(pool.alloc_client("10.0.0.1", 1, 1), Some(2))
}

/// RST 到达：on_err(Remote(code))（§5.4：RST 回显 StrmID 据此匹配）
test "call rst" {
  let (r, _pool) = make_rpc()
  put_udp_iface(r, 1, 5, false)
  let mut remote_code = -1
  r.call("10.0.0.1", 5400, 1, 1, 5, 1, b"\x01", 0, fn(_p) { () }, fn(e) {
    match e {
      @errors.Remote(c) => remote_code = c
      _ => ()
    }
  })
  r.on_rst(
    {
      ctr: false,
      ren: false,
      ver: 0,
      msk: false,
      typ: @frame.Rst,
      code: 0x24,
      svc_id: 1,
      if_id: 5,
      inst_id: 1,
      strm_id: 1,
      payload: b"",
    },
    "10.0.0.1",
  )
  assert_eq(remote_code, 0x24)
  assert_eq(r.pending.contains("10.0.0.1|1|1|1"), false)
}
