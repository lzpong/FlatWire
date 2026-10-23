// SD 状态机 inline 测试（同包访问 priv 字段：发现缓存 / 服务端订阅表 / tick 推进）
//
// Transport::new / IdlStore::new / CtrlStrmPool::new 均为纯构造（无 FFI 副作用），
// tick 与收包处理不涉及真实网络——状态迁移可在 moon test 环境完整验证

/// 构造测试用 Sd（事件捕获到数组）
fn make_sd(events : Array[SdEvent]) -> Sd {
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
  Sd::new(
    SdConfig::default(),
    t,
    @idlstore.IdlStore::new("unused_dir"),
    @strm.CtrlStrmPool::new(),
    fn(e) { events.push(e) },
  )
}

/// 发现缓存 TTL 推进（§7.5：递减 → 归零转 Expired → 下一次 tick 删除）
test "disc ttl tick expiry" {
  let events : Array[SdEvent] = []
  let sd = make_sd(events)
  sd.discover["1|1|127.0.0.1"] = {
    svc_id: 1,
    inst_id: 1,
    peer: "127.0.0.1",
    port: 5400,
    major_ver: 1,
    minor_ver: 0,
    ttl_remaining: 2,
    expired: false,
  }
  // tick 1：2 → 1（Active）
  sd.tick()
  assert_eq(sd.discover.get("1|1|127.0.0.1").unwrap().ttl_remaining, 1)
  // tick 2：1 → 0 → Expired（保留待删）
  sd.tick()
  assert_eq(sd.discover.get("1|1|127.0.0.1").unwrap().expired, true)
  // tick 3：Expired → 删除
  sd.tick()
  assert_eq(sd.discover.get("1|1|127.0.0.1") is None, true)
  assert_eq(events.length(), 0) // 发现缓存不产生事件
}

/// 服务端订阅表 TTL 推进 + SubRemoved 事件（§7.5 两侧规则一致 + §8.1）
test "server sub tick expiry" {
  let events : Array[SdEvent] = []
  let sd = make_sd(events)
  sd.server_subs["127.0.0.1|1|1|5|0"] = {
    peer: "127.0.0.1",
    peer_port: 50000,
    svc_id: 1,
    inst_id: 1,
    if_id: 5,
    grp_id: 0,
    strm_id: 3,
    ttl_remaining: 1,
    expired: false,
  }
  // tick 1：1 → 0 → Expired（保留）
  sd.tick()
  assert_eq(sd.server_subs.get("127.0.0.1|1|1|5|0").unwrap().expired, true)
  // tick 2：删除 + SubRemoved
  sd.tick()
  assert_eq(sd.server_subs.length(), 0)
  assert_eq(events.length(), 1)
  match events[0] {
    SubRemoved(s) => {
      assert_eq(s.svc_id, 1)
      assert_eq(s.if_id, 5)
      assert_eq(s.strm_id, 3)
    }
    _ => fail("expect SubRemoved")
  }
}

/// Offer 接收：新实例插入 + 同源刷新（重置非累加）+ TTL=0 标记 + SvcID=0 丢弃（§7.2/§7.5）
test "handle offer update cache" {
  let events : Array[SdEvent] = []
  let sd = make_sd(events)
  // 新实例 Found
  sd.handle_offer(
    encode_offer_entries([{ svc_id: 4096, inst_id: 1, major_ver: 1, minor_ver: 0, ttl: 4 }]),
    "127.0.0.1",
    5400,
  )
  assert_eq(sd.is_available(4096, 1), true)
  assert_eq(sd.discover.get("4096|1|127.0.0.1").unwrap().ttl_remaining, 4)
  // 同源刷新：TTL 重置非累加
  sd.handle_offer(
    encode_offer_entries([{ svc_id: 4096, inst_id: 1, major_ver: 1, minor_ver: 0, ttl: 3 }]),
    "127.0.0.1",
    5400,
  )
  assert_eq(sd.discover.get("4096|1|127.0.0.1").unwrap().ttl_remaining, 3)
  // TTL=0 → 标记待移除（未删除）
  sd.handle_offer(
    encode_offer_entries([{ svc_id: 4096, inst_id: 1, major_ver: 1, minor_ver: 0, ttl: 0 }]),
    "127.0.0.1",
    5400,
  )
  assert_eq(sd.discover.get("4096|1|127.0.0.1").unwrap().expired, true)
  // tick 后删除
  sd.tick()
  assert_eq(sd.discover.get("4096|1|127.0.0.1") is None, true)
  // SvcID=0 丢弃
  sd.handle_offer(
    encode_offer_entries([{ svc_id: 0, inst_id: 1, major_ver: 1, minor_ver: 0, ttl: 4 }]),
    "127.0.0.1",
    5400,
  )
  assert_eq(sd.discover.length(), 0)
}

/// 实例源地址冲突：保留先到、忽略后到 + Error 日志（§7.2 冲突表）
test "offer source conflict keeps first" {
  let events : Array[SdEvent] = []
  let sd = make_sd(events)
  sd.handle_offer(
    encode_offer_entries([{ svc_id: 1, inst_id: 1, major_ver: 1, minor_ver: 0, ttl: 4 }]),
    "10.0.0.1",
    5400,
  )
  // 同 (svc, inst) 不同源端口 → 忽略后到（key 含 peer IP；冲突判定按 port）
  // 注：同 IP 不同端口 = 冲突场景；不同 IP 是不同 peer 键，不构成冲突
  sd.handle_offer(
    encode_offer_entries([{ svc_id: 1, inst_id: 1, major_ver: 2, minor_ver: 0, ttl: 4 }]),
    "10.0.0.1",
    6000,
  )
  let d = sd.discover.get("1|1|10.0.0.1").unwrap()
  assert_eq(d.port, 5400) // 保留先到
  assert_eq(d.major_ver, 1) // 版本未被后到覆盖
}

/// subs_for_event 推送目标筛选：单接口精确 + 组订阅展开 + 过滤 Expired（§8.2）
test "subs_for_event matching" {
  let events : Array[SdEvent] = []
  let sd = make_sd(events)
  // 三个订阅者：单接口 if=5 / 组 grp=1 / 其他接口 if=6（应排除）
  sd.server_subs["a|1|1|5|0"] = {
    peer: "10.0.0.1",
    peer_port: 50001,
    svc_id: 1,
    inst_id: 1,
    if_id: 5,
    grp_id: 0,
    strm_id: 3,
    ttl_remaining: 4,
    expired: false,
  }
  sd.server_subs["b|1|1|0|1"] = {
    peer: "10.0.0.2",
    peer_port: 50002,
    svc_id: 1,
    inst_id: 1,
    if_id: 0,
    grp_id: 1,
    strm_id: 4,
    ttl_remaining: 4,
    expired: false,
  }
  sd.server_subs["c|1|1|6|0"] = {
    peer: "10.0.0.3",
    peer_port: 50003,
    svc_id: 1,
    inst_id: 1,
    if_id: 6,
    grp_id: 0,
    strm_id: 5,
    ttl_remaining: 4,
    expired: false,
  }
  // if_id=5 且所属组 [1] → 命中 a（精确）+ b（组展开）
  let out = sd.subs_for_event(1, 1, 5, [1])
  assert_eq(out.length(), 2)
  // if_id=6 无组归属 → 仅 c
  let out2 = sd.subs_for_event(1, 1, 6, [])
  assert_eq(out2.length(), 1)
  assert_eq(out2[0].peer, "10.0.0.3")
  // Expired 过滤（expired 为 mut 字段，直接改 Map 内对象即可生效）
  let sub_a = sd.server_subs.get("a|1|1|5|0").unwrap()
  sub_a.expired = true
  let out3 = sd.subs_for_event(1, 1, 5, [1])
  assert_eq(out3.length(), 1)
  assert_eq(out3[0].peer, "10.0.0.2")
}

/// 自动重订阅判定：登记存在 + 实例重新 Found → 触发 ensure_idl 链（IDL 缺失 → 无在线实例时静默失败保留登记）
test "auto resubscribe registry kept" {
  let events : Array[SdEvent] = []
  let sd = make_sd(events)
  // 预置登记（模拟此前订阅、实例曾 Expired）
  sd.regs["1|1|10.0.0.9|5|0"] = {
    svc_id: 1,
    inst_id: 1,
    peer: "10.0.0.9",
    if_id: 5,
    grp_id: 0,
  }
  // 发现缓存无 (1, 1) 在线实例 → ensure_idl 走 NotAvailable → 登记保留
  sd.try_auto_resubscribe(1, 1, "10.0.0.9", 5400, 1)
  assert_eq(sd.regs.get("1|1|10.0.0.9|5|0") is Some(_), true)
  assert_eq(sd.sessions.length(), 0)
}

/// REN 处理：清该 peer 的会话登记与发现缓存 + 上抛 PeerRebooted（§7.4/§3.6）
test "ren clears peer state" {
  let events : Array[SdEvent] = []
  let sd = make_sd(events)
  // 预置：peer A 与 peer B 各一条发现缓存 + 登记
  sd.discover["1|1|10.0.0.1"] = {
    svc_id: 1,
    inst_id: 1,
    peer: "10.0.0.1",
    port: 5400,
    major_ver: 1,
    minor_ver: 0,
    ttl_remaining: 4,
    expired: false,
  }
  sd.discover["1|1|10.0.0.2"] = {
    svc_id: 1,
    inst_id: 1,
    peer: "10.0.0.2",
    port: 5400,
    major_ver: 1,
    minor_ver: 0,
    ttl_remaining: 4,
    expired: false,
  }
  sd.regs["1|1|10.0.0.1|5|0"] = {
    svc_id: 1,
    inst_id: 1,
    peer: "10.0.0.1",
    if_id: 5,
    grp_id: 0,
  }
  sd.regs["1|1|10.0.0.2|5|0"] = {
    svc_id: 1,
    inst_id: 1,
    peer: "10.0.0.2",
    if_id: 5,
    grp_id: 0,
  }
  sd.handle_ren("10.0.0.1")
  // 仅 peer A 的状态被清除
  assert_eq(sd.discover.get("1|1|10.0.0.1") is None, true)
  assert_eq(sd.regs.get("1|1|10.0.0.1|5|0") is None, true)
  assert_eq(sd.discover.get("1|1|10.0.0.2") is Some(_), true)
  assert_eq(sd.regs.get("1|1|10.0.0.2|5|0") is Some(_), true)
  // 上抛 PeerRebooted
  assert_eq(events.length(), 1)
  match events[0] {
    PeerRebooted(p) => assert_eq(p, "10.0.0.1")
    _ => fail("expect PeerRebooted")
  }
}

/// GetIDL 服务端请求分支判定（无定义 → 0x24 路径 / SvcID=0、Payload≠3B → 0x20 路径；
/// transport 未启动时发送静默失败，此处验证分支逻辑与状态不变）
test "getidl req server reply" {
  let events : Array[SdEvent] = []
  let sd = make_sd(events)
  // 库中无定义 → RST(0x24) 分支
  let f1 : @frame.Frame = {
    ctr: true,
    ren: false,
    ver: 0,
    msk: false,
    typ: @frame.Non,
    code: 0x04,
    svc_id: 0,
    if_id: 0,
    inst_id: 0,
    strm_id: 77,
    payload: b"\x10\x00\x01",
  }
  sd.handle_getidl_req(f1, 77, "10.0.0.1", 5400)
  // SvcID=0 → RST(0x20) 分支
  let f2 : @frame.Frame = { ..f1, strm_id: 78, payload: b"\x00\x00\x01" }
  sd.handle_getidl_req(f2, 78, "10.0.0.1", 5400)
  // Payload≠3B → RST(0x20) 分支
  let f3 : @frame.Frame = { ..f1, strm_id: 79, payload: b"\x10\x00" }
  sd.handle_getidl_req(f3, 79, "10.0.0.1", 5400)
  assert_eq(events.length(), 0)
}
