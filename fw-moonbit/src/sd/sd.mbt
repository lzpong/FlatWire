// §7 服务发现（SD）主体：发现缓存 / SD 四操作分发 / Offer 广播 / Find / REN / TTL tick
//
// 模块划分：
// - entry.mbt      §7.1 四种 Entry 编解码
// - sd.mbt         本文件：主体结构、启停、tick、UDP/TCP 控制帧分发、Offer 广播、Find、REN、发现缓存
// - sub_client.mbt 客户端订阅会话（首次 CON/保活 NON/取消/重传/自动重订阅，§7.4）
// - sub_server.mbt 服务端订阅表（§8.1 确认语义 + §7.5 TTL 状态机）
// - getidl.mbt     GetIDL 双角色（客户端拉取链 + 服务端响应，§7.2）
//
// 路由约定（与 transport 层一致）：
// - 组播帧（Offer 广播/Find/REN）与全部服务端角色应答帧（Find 响应 Offer / Subscribe
//   确认 / SD RST）恒从 server socket 发——§2 对端由帧源地址获知服务端地址，源端口
//   必须为 fw_udp_port（Find 响应 Offer 的源端口即成为对端发现缓存的实例单播地址）；
// - 客户端角色主动请求（Find 查询/Subscribe）从 client socket 发；
// - server socket 收到的帧不区分组播/单播（OS 不可判定目的地址）→ 解析类错误一律保守静默；
//   client socket 仅收单播 → 协议错误回 RST 回显（§5.4）

/// SD 配置（附录 A 参数）
pub(all) struct SdConfig {
  period_ms : Int // Offer 广播与 Subscribe 保活共用周期（2000）
  ttl_sec : Int // Offer/Subscribe Entry 携带 TTL（ttl_ms=4000 → 4 秒，uint8 秒）
  response_timeout_ms : Int64 // GetIDL 查询超时（2000，§7.2 复用 response_timeout_ms）
  retransmit_interval_ms : Int64 // UDP CON 重传间隔（200）
  retransmit_max : Int // 重传次数（3，不含首次）
} derive(Eq)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend SdConfig with Eq::{not_equal, equal}

/// 默认配置（附录 A）
pub fn SdConfig::default() -> SdConfig {
  {
    period_ms: 2000,
    ttl_sec: 4,
    response_timeout_ms: 2000L,
    retransmit_interval_ms: 200L,
    retransmit_max: 3,
  }
}

/// 本端注册实例（Offer 广播内容；§7.3 实例级状态机由 stack 层驱动注册/注销）
priv struct LocalInst {
  svc_id : Int
  inst_id : Int
  major_ver : Int
  minor_ver : Int
}

/// 发现缓存条目（§7.5：实例级 (SvcID, InstID, 源地址)；TTL 秒级递减，Expired 待 tick 删除）
priv struct DiscEntry {
  svc_id : Int
  inst_id : Int
  peer : String // 源 IP（Offer 源地址）
  port : Int // 源端口（Offer 源端口 = 对端 server socket 端口，Subscribe 单播目标）
  major_ver : Int
  minor_ver : Int
  mut ttl_remaining : Int // 剩余秒数（收到 TTL>0 重置非累加，§7.5）
  mut expired : Bool // 待移除标记（归零/TTL=0 置位，下一次 tick 删除）
}

/// 客户端订阅登记（§7.4：清除条件仅二——应用显式 unsubscribe / 对端 REN）
priv struct SubReg {
  svc_id : Int
  inst_id : Int
  peer : String
  if_id : Int // 单接口订阅（≠0 且 grp_id=0）
  grp_id : Int // 组订阅（≠0 且 if_id=0）
}

/// 客户端订阅会话（§7.2：首次 CON → 保活 NON → 取消 CON 全程复用同一 StrmID）
priv struct SubSession {
  svc_id : Int
  inst_id : Int
  peer : String
  port : Int // 单播目标端口（= 实例 Offer 源端口）
  if_id : Int
  grp_id : Int
  strm_id : Int // 会话 StrmID（0x01~0x7F，CtrlStrmPool 分配）
  mut confirmed : Bool // 已收到 0x10（Found→Subscribed 完成）
  mut cancelling : Bool // 取消流程进行中（TTL=0 已发出）
  mut retransmits : Int // 当前 CON 已重传次数（重传耗尽 → 失败，§5.1）
  mut retrans_timer : Int // 重传定时器句柄（-1 无）
  mut keep_timer : Int // 保活定时器句柄（-1 无）
  on_ok : (Int) -> Unit // 首订成功回调（参数 = 会话 StrmID）
  on_err : (@errors.FwError) -> Unit // 首订失败回调
  mut on_cancel : (() -> Unit)? // 取消完成回调（取消流程才挂）
}

/// SD 上抛事件（stack 层消费）
pub(all) enum SdEvent {
  PeerRebooted(String) // 收到 REN=1：stack 需清该 peer 全部 Ctrl/Data StrmID 序列（§3.6）
  SubEstablished(ServerSub) // 服务端新订阅建立（events 层随后推全量，§8.1）
  SubRemoved(ServerSub) // 服务端订阅删除（显式取消标记 / tick 过期清理，§7.5）
}

/// 服务发现主体
pub struct Sd {
  cfg : SdConfig
  transport : @transport.Transport
  store : @idlstore.IdlStore
  ctrl_pool : @strm.CtrlStrmPool
  priv on_event : (SdEvent) -> Unit
  priv discover : Map[String, DiscEntry] // 发现缓存，key "svc|inst|peer"
  priv regs : Map[String, SubReg] // 订阅登记，key "svc|inst|peer|ifid|grp"
  priv sessions : Map[String, SubSession] // 活跃会话，同登记键
  priv local_insts : Map[String, LocalInst] // 本端实例，key "svc|inst"（字段名避开保留字 local）
  priv server_subs : Map[String, ServerSub] // 服务端订阅表，key "peer|svc|inst|ifid|grp"
  priv idl_queries : Map[String, IdlQuery] // GetIDL 查询（WaitResp），key "conn|strm"
  priv idl_dedup : Map[String, IdlQuery] // GetIDL 并发合并，key "svc|major"
  priv mut tick_timer : Int
  priv mut offer_timer : Int
  priv mut started : Bool
  priv mut stopping : Bool
}

// ===== 键构造（内部统一，防拼装漂移） =====

fn disc_key(svc_id : Int, inst_id : Int, peer : String) -> String {
  "\{svc_id}|\{inst_id}|\{peer}"
}

fn reg_key(svc_id : Int, inst_id : Int, peer : String, if_id : Int, grp_id : Int) -> String {
  "\{svc_id}|\{inst_id}|\{peer}|\{if_id}|\{grp_id}"
}

fn local_key(svc_id : Int, inst_id : Int) -> String {
  "\{svc_id}|\{inst_id}"
}

fn server_key(peer : String, svc_id : Int, inst_id : Int, if_id : Int, grp_id : Int) -> String {
  "\{peer}|\{svc_id}|\{inst_id}|\{if_id}|\{grp_id}"
}

/// 创建 SD 实例（不启动；start 挂定时器并发预热 Find）
pub fn Sd::new(
  cfg : SdConfig,
  transport : @transport.Transport,
  store : @idlstore.IdlStore,
  ctrl_pool : @strm.CtrlStrmPool,
  on_event : (SdEvent) -> Unit
) -> Sd {
  {
    cfg,
    transport,
    store,
    ctrl_pool,
    on_event,
    discover: Map([], capacity=16),
    regs: Map([], capacity=8),
    sessions: Map([], capacity=8),
    local_insts: Map([], capacity=8),
    server_subs: Map([], capacity=8),
    idl_queries: Map([], capacity=4),
    idl_dedup: Map([], capacity=4),
    tick_timer: -1,
    offer_timer: -1,
    started: false,
    stopping: false,
  }
}

/// 启动 SD：1s TTL tick（§7.5 固定 1s）+ Offer 广播周期定时器 + 启动立即发 Find 预热
/// （§1.3/§7.2：空 Payload 查询所有服务，加速发现缓存预热）
pub fn Sd::start(self : Sd) -> Unit {
  if self.started || self.stopping {
    return
  }
  self.tick_timer = sd_set_interval(fn(_x) { self.tick() }, 1000)
  self.offer_timer = sd_set_interval(fn(_x) { self.broadcast_offers() }, self.cfg.period_ms)
  // 预热 Find（空 Payload = 查询所有服务，§7.2）
  self.send_find_all()
  self.started = true
}

/// 停止 SD：§7.6 场景 6——REN=1 组播 ×3（间隔 ~100ms），先发完所有 REN 再释放资源
pub fn Sd::stop(self : Sd) -> Unit {
  if !self.started || self.stopping {
    return
  }
  self.stopping = true
  sd_clear_interval(self.tick_timer)
  sd_clear_interval(self.offer_timer)
  self.tick_timer = -1
  self.offer_timer = -1
  // REN ×3：立即 → +100ms → +200ms；第 3 发后统一清理
  self.send_ren()
  let _ = sd_set_timeout(fn(_x) { self.send_ren() }, 100)
  let _ = sd_set_timeout(fn(_x) { self.stop_cleanup() }, 200)
}

/// stop 第 200ms 收尾：发第 3 个 REN → 清会话/查询/状态
fn Sd::stop_cleanup(self : Sd) -> Unit {
  self.send_ren()
  // 活跃会话清理（释放 strm、清定时器）
  let skeys : Array[String] = []
  for k, _s in self.sessions {
    skeys.push(k)
  }
  for k in skeys {
    match self.sessions.get(k) {
      Some(s) => {
        clear_session_timers(s)
        let _ = self.ctrl_pool.release(s.peer, s.strm_id)
        let _ = self.sessions.remove(k)
      }
      None => ()
    }
  }
  // GetIDL 查询全部失败回调（进程即将退出，应用可感知）
  let qkeys : Array[String] = []
  for k, _q in self.idl_dedup {
    qkeys.push(k)
  }
  for k in qkeys {
    match self.idl_dedup.get(k) {
      Some(q) => self.fail_query(q, @errors.Local("stack stopped"))
      None => ()
    }
  }
  let _ = self.discover.clear()
  let _ = self.regs.clear()
  self.started = false
  self.stopping = false
}

/// 发送 REN=1（§3.6/§7.6：CTR=1, REN=1, TYP=NON, Code=0x00，UDP 组播）
fn Sd::send_ren(self : Sd) -> Unit {
  let spec : @frame.FrameSpec = {
    ctr: true,
    ren: true,
    ver: 0,
    typ: @frame.Non,
    code: 0x00,
    svc_id: 0,
    if_id: 0,
    inst_id: 0,
    strm_id: 0,
  }
  let _ = self.transport.send_udp_frame(
    true,
    spec,
    b"",
    @transport.MULTICAST_ADDR,
    self.transport.cfg.udp_port,
  )
}

/// 周期 Offer 广播（§7.2：每 period 一次，Entry TTL 固定不递减，§7.5；多实例合并按 1400 拆帧）
fn Sd::broadcast_offers(self : Sd) -> Unit {
  if self.local_insts.length() == 0 {
    return
  }
  let entries : Array[OfferEntry] = []
  for _k, inst in self.local_insts {
    entries.push({
      svc_id: inst.svc_id,
      inst_id: inst.inst_id,
      major_ver: inst.major_ver,
      minor_ver: inst.minor_ver,
      ttl: self.cfg.ttl_sec,
    })
  }
  self.send_offer_frames(entries, @transport.MULTICAST_ADDR, self.transport.cfg.udp_port)
}

/// 发送 Offer 帧（拆帧阈值 1400B / 6B 每 Entry = 233 Entry/帧，§7.2 拆帧策略）。
/// 恒走 server socket（§2：对端由 Offer 的源地址获知服务端地址 → 源端口必须为
/// fw_udp_port；周期广播为组播、Find 响应为单播，二者同属服务端角色的 Offer 帧带）
fn Sd::send_offer_frames(self : Sd, entries : Array[OfferEntry], host : String, port : Int) -> Unit {
  let per_frame = 233
  let total = entries.length()
  let mut i = 0
  while i < total {
    let hi = if i + per_frame < total {
      i + per_frame
    } else {
      total
    }
    let chunk : Array[OfferEntry] = []
    let mut j = i
    while j < hi {
      chunk.push(entries[j])
      j = j + 1
    }
    let payload = encode_offer_entries(chunk)
    let _ = self.transport.send_udp_frame(
      true,
      @frame.ctrl_spec(@frame.Non, 0x01, 0),
      payload,
      host,
      port,
    )
    i = hi
  }
}

/// 发送 Find（空 Payload = 查询全部服务，§7.2）
pub fn Sd::send_find_all(self : Sd) -> Unit {
  let _ = self.transport.send_udp_frame(
    true,
    @frame.ctrl_spec(@frame.Non, 0x02, 0),
    b"",
    @transport.MULTICAST_ADDR,
    self.transport.cfg.udp_port,
  )
}

/// 发送定向 Find（find_service：指定 SvcID，InstID=0 通配，MajorVer 精确匹配）
pub fn Sd::send_find(self : Sd, svc_id : Int, inst_id : Int, major_ver : Int) -> Unit {
  let payload = encode_find_entries([{ svc_id, inst_id, major_ver }])
  let _ = self.transport.send_udp_frame(
    true,
    @frame.ctrl_spec(@frame.Non, 0x02, 0),
    payload,
    @transport.MULTICAST_ADDR,
    self.transport.cfg.udp_port,
  )
}

// ===== 本端实例注册（Offer 广播源；§7.3 状态迁移由 stack 层编排） =====

/// 登记本端实例开始广播（register_service → Offering）
pub fn Sd::offer_start(
  self : Sd,
  svc_id : Int,
  inst_id : Int,
  major_ver : Int,
  minor_ver : Int
) -> Unit {
  self.local_insts[local_key(svc_id, inst_id)] = {
    svc_id,
    inst_id,
    major_ver,
    minor_ver,
  }
}

/// 注销本端实例：移除广播列表 + 发 TTL=0 Offer 一次（§7.3 Offering→Stopped）
pub fn Sd::offer_stop(self : Sd, svc_id : Int, inst_id : Int) -> Unit {
  let key = local_key(svc_id, inst_id)
  let inst = match self.local_insts.get(key) {
    Some(v) => v
    None => return
  }
  let _ = self.local_insts.remove(key)
  // TTL=0 Offer（NON 组播单帧，§7.6 场景 5）
  let payload = encode_offer_entries([
    {
      svc_id: inst.svc_id,
      inst_id: inst.inst_id,
      major_ver: inst.major_ver,
      minor_ver: inst.minor_ver,
      ttl: 0,
    },
  ])
  let _ = self.transport.send_udp_frame(
    true,
    @frame.ctrl_spec(@frame.Non, 0x01, 0),
    payload,
    @transport.MULTICAST_ADDR,
    self.transport.cfg.udp_port,
  )
}

// ===== 发现缓存查询 API（stack 层 is_available/find_service/GetIDL 定位用） =====

/// 本地缓存判定服务实例是否在线（§13.2 is_available）
pub fn Sd::is_available(self : Sd, svc_id : Int, inst_id : Int) -> Bool {
  self.pick_instance(svc_id, inst_id) is Some(_)
}

/// 选择在线实例（inst_id=0 通配任一；返回首个非 Expired 匹配条目）
fn Sd::pick_instance(self : Sd, svc_id : Int, inst_id : Int) -> DiscEntry? {
  for _k, d in self.discover {
    if d.svc_id == svc_id && !d.expired && (inst_id == 0 || d.inst_id == inst_id) {
      return Some(d)
    }
  }
  None
}

/// 定位 (svc_id, major_ver) 的在线实例（GetIDL 客户端触发条件，§7.2）
fn Sd::find_instance(self : Sd, svc_id : Int, major_ver : Int) -> DiscEntry? {
  for _k, d in self.discover {
    if d.svc_id == svc_id && d.major_ver == major_ver && !d.expired {
      return Some(d)
    }
  }
  None
}

/// 集群该服务的任一在线版本（注册场景 MajorVer 取在线版本，建议最高，§7.2）
pub fn Sd::any_online_version(self : Sd, svc_id : Int) -> Int? {
  let mut best = -1
  for _k, d in self.discover {
    if d.svc_id == svc_id && !d.expired && d.major_ver > best {
      best = d.major_ver
    }
  }
  if best >= 0 {
    Some(best)
  } else {
    None
  }
}

// ===== 控制帧入口（stack 层按 CTR 分流后调用） =====

/// UDP 控制帧分发（§7.2 四操作 + 确认 + REN + RST）
pub fn Sd::on_udp_ctrl(
  self : Sd,
  f : @frame.Frame,
  host : String,
  port : Int,
  from_server : Bool
) -> Unit {
  if !f.ctr {
    return // 防御：数据帧由 stack 层分流至 rpc/events
  }
  match f.typ {
    // 对端 RST：本端 Subscribe CON 被拒等场景
    @frame.Rst => self.handle_udp_rst(f, host)
    // 确认帧：订阅建立 0x10 / 取消 0x00（回显会话 StrmID）
    @frame.Ack =>
      match f.code {
        0x10 => self.handle_sub_ack(f, host)
        0x00 => self.handle_cancel_ack(f, host)
        _ => ()
      }
    // NON/CON：Offer / Find / Subscribe / GetIDL(违规) / REN
    _ =>
      match f.code {
        0x01 => self.handle_offer(f.payload, host, port)
        0x02 => self.handle_find(f.payload, host, port)
        0x03 => self.handle_subscribe(f, host, port)
        0x04 =>
          // §7.2：GetIDL 仅 TCP 单播。client socket（必单播）收到 → RST(0x00)；
          // server socket 收到的可能是组播（目的地址不可判定）→ 保守静默
          if !from_server {
            self.send_rst_udp(@errors.RST_OK, f, host, port)
          }
        0x11 => () // 0x11 仅 TCP；UDP 防御性静默（响应不会定向到 UDP 端口）
        0x00 =>
          // REN=1：节点重启通知（§7.6 场景 6）；REN=0 心跳 Ping 连接级忽略
          if f.ren {
            self.handle_ren(host)
          }
        _ => () // 未知 Code 静默（组播场景保守，对端按超时处理）
      }
  }
}

/// TCP 控制帧分发（§7.2：GetIDL 请求 / 0x11 响应 / RST）
pub fn Sd::on_tcp_ctrl(
  self : Sd,
  f : @frame.Frame,
  conn_id : Int,
  peer : String,
  port : Int
) -> Unit {
  if !f.ctr {
    return // 防御：数据帧由 stack 层分流至 rpc/events
  }
  match f.typ {
    @frame.Rst => self.handle_tcp_rst(f, conn_id)
    _ =>
      match f.code {
        0x04 => self.handle_getidl_req(f, conn_id, peer, port)
        0x11 => self.handle_getidl_resp(f, conn_id)
        _ => () // 其他控制码 TCP 场景未定义，静默
      }
  }
}

/// stack 层转发：TCP 连接建立（GetIDL WaitConn 阶段查询此刻发出）
pub fn Sd::on_tcp_connected(self : Sd, conn_id : Int, _peer : String, _port : Int) -> Unit {
  let qs : Array[IdlQuery] = []
  for _k, q in self.idl_dedup {
    if !q.finished && q.conn_id == conn_id && q.strm_id == 0 {
      qs.push(q)
    }
  }
  for q in qs {
    self.send_getidl_query(q)
  }
}

/// stack 层转发：TCP 连接断开（该连接上的 pending GetIDL 查询全部失败，§7.2）
pub fn Sd::on_tcp_closed(self : Sd, conn_id : Int) -> Unit {
  let qs : Array[IdlQuery] = []
  for _k, q in self.idl_dedup {
    if !q.finished && q.conn_id == conn_id {
      qs.push(q)
    }
  }
  for q in qs {
    self.fail_query(q, @errors.Local("tcp connection closed"))
  }
}

/// UDP RST 发送（§5.4 回显触发帧 ID）。恒走 server socket：SD 层 RST 均为
/// 服务端角色对收到控制帧的应答（GetIDL 违规 / Subscribe 解析失败 / tcp-event 无连接），
/// 与 rpc 层 serve_rst 口径一致（服务端应答帧源端口 = fw_udp_port）
fn Sd::send_rst_udp(
  self : Sd,
  code : Int,
  f : @frame.Frame,
  host : String,
  port : Int
) -> Unit {
  let _ = self.transport.send_udp_frame(
    true,
    @frame.data_spec(@frame.Rst, code, f.svc_id, f.if_id, f.inst_id, f.strm_id),
    b"",
    host,
    port,
  )
}

// ===== Offer 接收（客户端视角：发现缓存维护） =====

/// 处理 Offer（§7.2 实例冲突处理 + §7.5 TTL 重置）
fn Sd::handle_offer(self : Sd, payload : Bytes, host : String, port : Int) -> Unit {
  match parse_offer_entries(payload) {
    None => () // 整帧无法解析：周期 Offer 重发兜底，静默（保守原则）
    Some(entries) =>
      for e in entries {
        // SvcID=0 无效 Entry 丢弃 + Error 日志（§7.2 Entry 级处理）
        if e.svc_id == 0 {
          sd_log_error("[sd] Offer Entry SvcID=0 丢弃: peer=\{host}")
          continue
        }
        let key = disc_key(e.svc_id, e.inst_id, host)
        if e.ttl == 0 {
          // TTL=0 停止提供：标记待移除（下一次 tick 删除，§7.5）
          match self.discover.get(key) {
            Some(d) => d.expired = true
            None => ()
          }
          continue
        }
        match self.discover.get(key) {
          Some(d) =>
            if d.port != port {
              // §7.2 实例冲突：保留先到实例记录，忽略后到 + Error 日志（协议层不仲裁）
              sd_log_error(
                "[sd] 实例源地址冲突，忽略后到 Entry: svc=\{e.svc_id} inst=\{e.inst_id} peer=\{host} known_port=\{d.port} new_port=\{port}",
              )
            } else {
              // §7.5：TTL 重置非累加；版本信息同步刷新（升级场景）
              // major_ver/minor_ver 为不可变字段 → 用更新语法整体替换 Map 值
              self.discover[key] = { ..d, ttl_remaining: e.ttl, major_ver: e.major_ver, minor_ver: e.minor_ver }
            }
          None => {
            // 新实例 Found：加入注册表并判定自动重订阅（§7.4）
            self.discover[key] = {
              svc_id: e.svc_id,
              inst_id: e.inst_id,
              peer: host,
              port,
              major_ver: e.major_ver,
              minor_ver: e.minor_ver,
              ttl_remaining: e.ttl,
              expired: false,
            }
            self.try_auto_resubscribe(e.svc_id, e.inst_id, host, port, e.major_ver)
          }
        }
      }
  }
}

/// 自动重订阅判定（§7.4）：实例 Expired→Found（或首次 Found）后，登记仍存在且无活跃会话
/// → 自动发起订阅（新会话、新 StrmID——服务端按首次处理回 0x10 并推全量）
fn Sd::try_auto_resubscribe(
  self : Sd,
  svc_id : Int,
  inst_id : Int,
  peer : String,
  port : Int,
  major_ver : Int
) -> Unit {
  let rkeys : Array[String] = []
  for k, reg in self.regs {
    if reg.svc_id == svc_id && reg.inst_id == inst_id && reg.peer == peer {
      rkeys.push(k)
    }
  }
  for k in rkeys {
    match self.regs.get(k) {
      Some(reg) =>
        if self.sessions.contains(k) {
          () // 会话已活跃（并发 Offer），跳过
        } else {
          // IDL 可能因落盘失败重启后缺失 → 走 ensure_idl 拉取链（§7.2 双角色统一）
          let reg_copy = reg
          self.ensure_idl(
            svc_id,
            major_ver,
            fn() {
              // 回调时可能已并发建立会话，再查一次
              if !(self.sessions.contains(k)) {
                let d : DiscEntry = {
                  svc_id,
                  inst_id,
                  peer,
                  port,
                  major_ver,
                  minor_ver: 0,
                  ttl_remaining: 0,
                  expired: false,
                }
                self.start_session(
                  d,
                  reg_copy.if_id,
                  reg_copy.grp_id,
                  fn(_strm) { () },
                  fn(err) {
                    sd_log_error("[sd] 自动重订阅失败: svc=\{svc_id} err=\{Repr(err)}")
                  },
                )
              }
            },
            fn(err) {
              sd_log_error(
                "[sd] 自动重订阅 IDL 拉取失败（登记保留，下次 Found 重试）: svc=\{svc_id} err=\{Repr(err)}",
              )
            },
          )
        }
      None => ()
    }
  }
}

// ===== Find 接收（服务端视角：单播响应 Offer） =====

/// 处理 Find（§7.2：空 Payload 查全部；带 Entry 按条件匹配；响应 = Offer 格式单播）
fn Sd::handle_find(self : Sd, payload : Bytes, host : String, port : Int) -> Unit {
  match parse_find_entries(payload) {
    None => () // Find 由协议栈构造，格式错误属对端实现缺陷，静默（对端按超时重发）
    Some(entries) => {
      let matched : Array[LocalInst] = []
      if entries.length() == 0 {
        // 空 Payload = 查询所有服务
        for _k, inst in self.local_insts {
          matched.push(inst)
        }
      } else {
        for fe in entries {
          // Entry 必须指定 SvcID（非零），否则丢弃（§7.2）
          if fe.svc_id == 0 {
            continue
          }
          for _k, inst in self.local_insts {
            if inst.svc_id != fe.svc_id {
              continue
            }
            // InstID=0 通配，否则精确匹配
            if fe.inst_id != 0 && inst.inst_id != fe.inst_id {
              continue
            }
            // MajorVer 精确匹配（MinorVer 不参与匹配，§7.1）
            if inst.major_ver != fe.major_ver {
              continue
            }
            matched.push(inst)
          }
        }
      }
      if matched.length() > 0 {
        let out : Array[OfferEntry] = []
        for inst in matched {
          out.push({
            svc_id: inst.svc_id,
            inst_id: inst.inst_id,
            major_ver: inst.major_ver,
            minor_ver: inst.minor_ver,
            ttl: self.cfg.ttl_sec,
          })
        }
        // 响应单播回 Find 源地址（§7.2：响应帧格式与 Offer 相同；恒走 server socket——
        // 对端将以此帧源端口作为该实例的单播地址，见 §2）
        self.send_offer_frames(out, host, port)
      }
    }
  }
}

// ===== REN 接收（§7.4 Any 状态：清除该源地址全部实例缓存与订阅登记） =====

fn Sd::handle_ren(self : Sd, peer : String) -> Unit {
  // 1. 活跃会话清理（定时器 + strm 释放）
  let skeys : Array[String] = []
  for k, s in self.sessions {
    if s.peer == peer {
      skeys.push(k)
    }
  }
  for k in skeys {
    match self.sessions.get(k) {
      Some(s) => {
        clear_session_timers(s)
        let _ = self.ctrl_pool.release(s.peer, s.strm_id)
        let _ = self.sessions.remove(k)
      }
      None => ()
    }
  }
  // 2. 订阅登记清除（§7.4 清除条件 ②：对端 REN）
  let rkeys : Array[String] = []
  for k, reg in self.regs {
    if reg.peer == peer {
      rkeys.push(k)
    }
  }
  for k in rkeys {
    let _ = self.regs.remove(k)
  }
  // 3. 发现缓存清除
  let dkeys : Array[String] = []
  for k, d in self.discover {
    if d.peer == peer {
      dkeys.push(k)
    }
  }
  for k in dkeys {
    let _ = self.discover.remove(k)
  }
  // 4. 上抛（stack 清该 peer 的 Ctrl/Data StrmID 序列，§3.6/§6.3）
  (self.on_event)(PeerRebooted(peer))
}

// ===== 1s tick（§7.5：固定 1s，非配置项） =====

fn Sd::tick(self : Sd) -> Unit {
  // 发现缓存：Expired 删除；Active 递减，归零转 Expired（下一次 tick 删除）
  let dkeys : Array[String] = []
  for k, d in self.discover {
    if d.expired {
      dkeys.push(k)
    } else {
      d.ttl_remaining = d.ttl_remaining - 1
      if d.ttl_remaining <= 0 {
        d.expired = true
      }
    }
  }
  for k in dkeys {
    let _ = self.discover.remove(k)
  }
  // 服务端订阅表同规则推进（§7.5 "两侧规则完全一致"）
  self.tick_server_subs()
}
