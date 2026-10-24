// stack 包 inline 测试：帧分流（CTR/Code 路由）+ 栈级集成链（Offer→发现→call→交付）
//
// Stack::new 为纯构造（不 start：无 socket / 定时器），发送路径静默跳过；
// 各层状态断言经应用 API 副作用（回调记录）完成——rpc/events 内部 priv 字段跨包不可见

/// 构造测试栈（预置 svc=1 if=5 UDP rpc 接口 IDL；store 命中 → ensure_idl 同步回调）
fn make_stack() -> Stack {
  let s = Stack::new(StackConfig::default("unused_dir"))
  let def : @idlstore.IdlDef = {
    name: "t",
    svc_id: 1,
    major_ver: 1,
    minor_ver: 0,
    interfaces: [
      {
        name: "r",
        if_id: 5,
        kind: @idlstore.IfRpc,
        tcp: false,
        max_payload: 0,
        reliable: false,
        crc: false,
        input: [],
        output: None,
      },
    ],
    groups: [],
    raw: "{}",
  }
  let _ = s.store.put(def)
  s
}

/// 数据帧构造（§3 帧头字段全集；测试内恒定宽度形态）
fn data_frame(typ : @frame.Typ, code : Int, svc : Int, if_id : Int, inst : Int, strm : Int, payload : Bytes) -> @frame.Frame {
  {
    ctr: false,
    ren: false,
    ver: 0,
    msk: false,
    typ,
    code,
    svc_id: svc,
    if_id,
    inst_id: inst,
    strm_id: strm,
    payload,
  }
}

/// UDP Request CON 帧（Code=0x01）
fn req_frame(svc : Int, inst : Int, if_id : Int, strm : Int) -> @frame.Frame {
  data_frame(@frame.Con, 0x01, svc, if_id, inst, strm, b"\x01")
}

/// CTR=0 数据帧 Code=0x01 → rpc 服务端 handler 执行（§5.1）
test "route request to rpc handler" {
  let s = make_stack()
  let mut got_if = -1
  let mut got_p : Bytes = b""
  s.rpc.register_handler(1, 1, 1, {
    on_request: fn(if_id, p) {
      got_if = if_id
      got_p = p
      Ok(b"\xaa")
    },
    on_ff: fn(_i, _p) { () },
  })
  s.on_transport_event(@transport.UdpFrame(req_frame(1, 1, 5, 7), "10.0.0.1", 5400, false))
  assert_eq(got_if, 5)
  assert_eq(got_p, b"\x01")
}

/// CTR=0 数据帧 Code=0x03 → events 客户端交付 + 重复去重（§8.2 recv_seen）
test "route notification to events" {
  let s = make_stack()
  let mut got = 0
  let _k = s.events.reg_client(1, 5, 0, fn(_if, _p) { got = got + 1 })
  let f = data_frame(@frame.Non, 0x03, 1, 5, 1, 0x90, b"\x07")
  s.on_transport_event(@transport.UdpFrame(f, "10.0.0.9", 5000, false))
  s.on_transport_event(@transport.UdpFrame(f, "10.0.0.9", 5000, false)) // 重复 CON：仅不重复交付
  assert_eq(got, 1)
}

/// 栈级链路：对端 Offer → 发现缓存 → call（ensure_idl 本地命中）→ Response 交付（§5.1/§7.2）
test "offer discover then call delivers response" {
  let s = make_stack()
  // 对端 Offer 到达（server socket，§7.2 handle_offer）
  let offer : @frame.Frame = {
    ctr: true,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Non,
    code: 0x01,
    svc_id: 0,
    if_id: 0,
    inst_id: 0,
    strm_id: 0,
    payload: @sd.encode_offer_entries([{ svc_id: 1, inst_id: 1, major_ver: 1, minor_ver: 0, ttl: 4 }]),
  }
  s.on_transport_event(@transport.UdpFrame(offer, "10.0.0.9", 5400, true))
  assert_eq(s.is_available(1, 1), true)
  // call：locate_instance → ensure_idl（本地命中同步）→ rpc.call 登记 pending
  // （def 无 output → 空字段集编码 b""，响应空 payload 解码得空值数组）
  let mut ok_n = -1
  let mut errs = 0
  s.call(1, 1, 5, [], 0, fn(vs) { ok_n = vs.length() }, fn(_e) { errs = errs + 1 })
  // Response 到达（回显 StrmID=1 首流）→ on_ok 交付（§5.1）
  let resp = data_frame(@frame.Non, 0x10, 1, 5, 1, 1, b"")
  s.on_transport_event(@transport.UdpFrame(resp, "10.0.0.9", 5400, false))
  assert_eq(ok_n, 0)
  assert_eq(errs, 0)
}

/// 栈级编解码链路：call → input 编码 → 服务端 handler（input 解码/output 编码）→
/// Response → output 解码交付（§13 payload 语义全链路；CStruct ↔ VArray，§9.3）
test "call with struct codec roundtrip" {
  let s = Stack::new(StackConfig::default("unused_dir"))
  // 简化 VehicleState：u8 + timestamp + f64 三字段 struct（§11.1 v5.0 字段形态）
  let vs_t : @codec.CType = @codec.CStruct([
    { name: "veh_md", ctype: @codec.CUInt(1) },
    { name: "timestamp", ctype: @codec.CTimestamp },
    { name: "ratio", ctype: @codec.CFloat(64) },
  ])
  let def : @idlstore.IdlDef = {
    name: "t",
    svc_id: 1,
    major_ver: 1,
    minor_ver: 0,
    interfaces: [
      {
        name: "GetState",
        if_id: 5,
        kind: @idlstore.IfRpc,
        tcp: false,
        max_payload: 0,
        reliable: false,
        crc: false,
        input: [],
        output: Some(vs_t),
      },
    ],
    groups: [],
    raw: "{}",
  }
  let _ = s.store.put(def)
  // 对端 Offer → 发现缓存（§7.2 handle_offer）
  let offer : @frame.Frame = {
    ctr: true,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Non,
    code: 0x01,
    svc_id: 0,
    if_id: 0,
    inst_id: 0,
    strm_id: 0,
    payload: @sd.encode_offer_entries([{ svc_id: 1, inst_id: 1, major_ver: 1, minor_ver: 0, ttl: 4 }]),
  }
  s.on_transport_event(@transport.UdpFrame(offer, "10.0.0.9", 5400, true))
  // 注册服务端（本地命中同步注册）：handler 返回固定 VehicleState 值
  let mut reg_done = 0
  s.register_service(1, 1, {
    on_request: fn(_i, _args) {
      Ok([@codec.VArray([@codec.VUInt(3), @codec.VTimestamp(123456L), @codec.VFloat(0.5)])])
    },
    on_ff: fn(_i, _args) { () },
  }, fn() { reg_done = reg_done + 1 }, fn(_e) { () })
  assert_eq(reg_done, 1)
  // call → 手动投递同 schema 编码的 Response（transport 未启动，服务端响应不回环）
  let expect_body = @codec.encode_fields(
    [{ name: "ret", ctype: vs_t }],
    [@codec.VArray([@codec.VUInt(3), @codec.VTimestamp(123456L), @codec.VFloat(0.5)])],
  )
  let mut got : Array[@codec.FWValue] = []
  let mut errs = 0
  s.call(1, 1, 5, [], 0, fn(vs) { got = vs }, fn(_e) { errs = errs + 1 })
  let resp = data_frame(@frame.Non, 0x10, 1, 5, 1, 1, expect_body)
  s.on_transport_event(@transport.UdpFrame(resp, "10.0.0.9", 5400, false))
  assert_eq(errs, 0)
  // 解码结果 = 单元素顶层（ret）→ VArray 三字段值
  assert_eq(got.length(), 1)
  match got[0] {
    @codec.VArray(fs) => {
      assert_eq(fs.length(), 3)
      assert_eq(fs[0], @codec.VUInt(3))
      assert_eq(fs[1], @codec.VTimestamp(123456L))
      assert_eq(fs[2], @codec.VFloat(0.5)) // 0.5 IEEE754 无损
    }
    _ => abort("expect VArray") // 不可达：schema 恒产出 VArray
  }
}

/// TCP 路径：conn_peer 登记 → 数据帧/控制帧分流 → 关闭清理（§5.6/§7.2）
test "tcp route and conn tracking" {
  let s = make_stack()
  let mut got_if = -1
  s.rpc.register_handler(1, 1, 1, {
    on_request: fn(if_id, _p) {
      got_if = if_id
      Ok(b"")
    },
    on_ff: fn(_i, _p) { () },
  })
  s.on_transport_event(@transport.TcpConnected(3, "10.0.0.9", 5000))
  // TCP 数据帧 Request（NON，§5.1 TCP 不使用 CON/ACK）→ handler
  s.on_transport_event(@transport.TcpFrame(req_frame(1, 1, 5, 9), 3))
  assert_eq(got_if, 5)
  // TCP Response（无 pending 匹配 → no-op 不崩）
  s.on_transport_event(@transport.TcpFrame(data_frame(@frame.Non, 0x10, 1, 5, 1, 9, b""), 3))
  // TCP 控制帧 GetIDL 请求（§7.2：服务端 store 已有 svc=1 定义 → 回 0x11，发送静默）
  let gidl : @frame.Frame = {
    ctr: true,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Non,
    code: 0x04,
    svc_id: 0,
    if_id: 0,
    inst_id: 0,
    strm_id: 2,
    payload: @sd.encode_getidl_entry({ svc_id: 1, major_ver: 1 }),
  }
  s.on_transport_event(@transport.TcpFrame(gidl, 3))
  // 连接关闭：sd/rpc 清理路径（无 pending 查询/等待队列 → no-op）
  s.on_transport_event(@transport.TcpClosed(3, "10.0.0.9", 5000))
  assert_eq(got_if, 5)
}

/// register_service 全流程：本地命中同步注册 → 重复注册占用失败 → 注销（§13.1）
test "register service flow" {
  let s = make_stack()
  let mut done = 0
  s.register_service(1, 1, {
    on_request: fn(_i, _args) { Ok([]) },
    on_ff: fn(_i, _args) { () },
  }, fn() { done = done + 1 }, fn(_e) { () })
  assert_eq(done, 1)
  // 重复注册 → Local 失败（§13.1 前置条件：本地 (svc_id, inst_id) 已被占用）
  let mut err = false
  s.register_service(1, 1, {
    on_request: fn(_i, _args) { Ok([]) },
    on_ff: fn(_i, _args) { () },
  }, fn() { () }, fn(_e) { err = true })
  assert_eq(err, true)
  s.unregister_service(1, 1)
}

/// 测试 1.34/1.35：接口 crc=true 时响应末尾附加 2B CRC；篡改 → 解码失败（应用侧 on_err）
test "crc interface encode & decode" {
  let s = Stack::new(StackConfig::default("unused_dir"))
  let out_t : @codec.CType = @codec.CUInt(2)
  let def : @idlstore.IdlDef = {
    name: "t",
    svc_id: 1,
    major_ver: 1,
    minor_ver: 0,
    interfaces: [
      {
        name: "R",
        if_id: 5,
        kind: @idlstore.IfRpc,
        tcp: false,
        max_payload: 0,
        reliable: false,
        crc: true, // §9.6 接口级 CRC 开启
        input: [],
        output: Some(out_t),
      },
    ],
    groups: [],
    raw: "{}",
  }
  let _ = s.store.put(def)
  // 对端 Offer → 发现缓存（§7.2 handle_offer）
  let offer : @frame.Frame = {
    ctr: true,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Non,
    code: 0x01,
    svc_id: 0,
    if_id: 0,
    inst_id: 0,
    strm_id: 0,
    payload: @sd.encode_offer_entries([{ svc_id: 1, inst_id: 1, major_ver: 1, minor_ver: 0, ttl: 4 }]),
  }
  s.on_transport_event(@transport.UdpFrame(offer, "10.0.0.9", 5400, true))
  // 正常响应：字段 0x1234 + 2B CRC（大端附加，§9.6）
  let body = @codec.encode_fields([{ name: "ret", ctype: out_t }], [@codec.VUInt(0x1234L)])
  let with_crc = @codec.append_crc16(body)
  assert_eq(with_crc.length(), 4)
  let mut got : Array[@codec.FWValue] = []
  let mut errs = 0
  s.call(1, 1, 5, [], 0, fn(vs) { got = vs }, fn(_e) { errs = errs + 1 })
  s.on_transport_event(@transport.UdpFrame(data_frame(@frame.Non, 0x10, 1, 5, 1, 1, with_crc), "10.0.0.9", 5400, false))
  assert_eq(errs, 0)
  assert_eq(got[0], @codec.VUInt(0x1234L))
  // 篡改字段字节 → CRC 校验失败 → 应用侧 on_err（对应 RST 0x20 的上层映射）
  let tampered = @buffer.Buffer(size_hint=with_crc.length())
  for i in 0..<with_crc.length() {
    let b = if i == 1 {
      (with_crc[i].to_int() ^ 0x01).to_byte()
    } else {
      with_crc[i]
    }
    tampered.write_byte(b)
  }
  let mut errs2 = 0
  s.call(1, 1, 5, [], 0, fn(_vs) { () }, fn(_e) { errs2 = errs2 + 1 })
  s.on_transport_event(@transport.UdpFrame(data_frame(@frame.Non, 0x10, 1, 5, 1, 2, tampered.to_bytes()), "10.0.0.9", 5400, false))
  assert_eq(errs2, 1)
}
