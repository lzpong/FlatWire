// 客户端订阅会话（§7.4 客户端状态机 + §7.2 Subscribe 传输机制）
//
// - 会话生命周期：首次 CON（TTL>0）→ 等 0x10（重传 200ms×3）→ Subscribed → 保活 NON
//   （每 period）→ 显式取消 CON（TTL=0）→ 等 0x00 → 全程复用会话 StrmID（§7.2）
// - 登记与分离：登记（SubReg）承载应用订阅意图（清除条件仅二：显式 unsubscribe / REN），
//   会话（SubSession）承载传输状态；实例 Expired→Found 后按登记自动重订阅（新 StrmID）
// - 首订失败（RST/重传耗尽）：会话与登记一并清除（订阅从未建立，应用重新 subscribe 即可）

/// 订阅（§13.2 subscribe：svc_id + inst_id(0=任一实例) + if_id/grp_id 二选一）
/// 成功回调参数 = 会话 StrmID；失败回调携带 §12.1 错误
pub fn Sd::subscribe(
  self : Sd,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  grp_id : Int,
  on_ok : (Int) -> Unit,
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  // §7.1 合法组合防御（stack 层已校验）
  if (if_id == 0 && grp_id == 0) || (if_id != 0 && grp_id != 0) {
    on_err(@errors.Local("invalid subscribe combination: if_id=\{if_id} grp_id=\{grp_id}"))
    return
  }
  // 发现缓存定位实例（无在线实例直接失败，§7.2 触发条件 2）
  match self.pick_instance(svc_id, inst_id) {
    None => on_err(@errors.NotAvailable)
    Some(d) => {
      let key = reg_key(d.svc_id, d.inst_id, d.peer, if_id, grp_id)
      if self.sessions.contains(key) {
        on_err(@errors.Local("already subscribed: \{key}"))
        return
      }
      // 订阅是 IDL 消费场景（事件解码需要定义）→ 先 ensure_idl（§7.2 客户端角色触发）
      self.ensure_idl(d.svc_id, d.major_ver, fn() { self.start_session(d, if_id, grp_id, on_ok, on_err) }, on_err)
    }
  }
}

/// 建立订阅会话：分配 StrmID → 登记 + 会话插入 → 发首次 CON → 启重传链
fn Sd::start_session(
  self : Sd,
  d : DiscEntry,
  if_id : Int,
  grp_id : Int,
  on_ok : (Int) -> Unit,
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  let key = reg_key(d.svc_id, d.inst_id, d.peer, if_id, grp_id)
  // 并发防御（ensure_idl 回调期可能已建立）
  if self.sessions.contains(key) {
    on_err(@errors.Local("already subscribed: \{key}"))
    return
  }
  let strm = match self.ctrl_pool.alloc(d.peer) {
    Some(s) => s
    None => {
      on_err(@errors.Local("StrmID exhausted for peer \{d.peer}"))
      return
    }
  }
  let session : SubSession = {
    svc_id: d.svc_id,
    inst_id: d.inst_id,
    peer: d.peer,
    port: d.port,
    if_id,
    grp_id,
    strm_id: strm,
    confirmed: false,
    cancelling: false,
    retransmits: 0,
    retrans_timer: -1,
    keep_timer: -1,
    on_ok,
    on_err,
    on_cancel: None,
  }
  self.sessions[key] = session
  self.regs[key] = {
    svc_id: d.svc_id,
    inst_id: d.inst_id,
    peer: d.peer,
    if_id,
    grp_id,
  }
  // 首次 Subscribe(TTL>0, CON)（§7.6 场景 3）
  let _ = self.send_sub_frame(session, @frame.Con, self.cfg.ttl_sec)
  // 重传链：200ms 间隔 ×3（附录 A；不含首次）
  let _ = self.arm_retrans(key)
}

/// 挂重传定时器（返回句柄）
fn Sd::arm_retrans(self : Sd, key : String) -> Int {
  sd_set_timeout(
    fn(_x) { self.sub_retrans_tick(key) },
    self.cfg.retransmit_interval_ms.to_int(),
  )
}

/// 发送 Subscribe 帧（§7.2：UDP 单播到实例 Offer 源地址；帧携带会话 StrmID）
fn Sd::send_sub_frame(self : Sd, s : SubSession, typ : @frame.Typ, ttl : Int) -> Bool {
  let payload = encode_sub_entries([
    {
      svc_id: s.svc_id,
      if_id: s.if_id,
      inst_id: s.inst_id,
      grp_id: s.grp_id,
      ttl,
    },
  ])
  self.transport.send_udp_frame(
    false,
    @frame.ctrl_spec(typ, 0x03, s.strm_id),
    payload,
    s.peer,
    s.port,
  )
}

/// 重传定时回调（§5.1：CON 未确认重传；耗尽 → 会话失败）
fn Sd::sub_retrans_tick(self : Sd, key : String) -> Unit {
  let s = match self.sessions.get(key) {
    Some(v) => v
    None => return
  }
  if s.confirmed {
    return
  }
  if s.retransmits >= self.cfg.retransmit_max {
    if s.cancelling {
      // 取消重传耗尽：释放 strm、清会话与登记（应用已显式 unsubscribe——登记清除条件 ①，§7.4）
      clear_session_timers(s)
      let _ = self.ctrl_pool.release(s.peer, s.strm_id)
      let _ = self.sessions.remove(key)
      let _ = self.regs.remove(key)
      // 服务端订阅记录靠订阅 TTL 自愈过期（§7.4）
      match s.on_cancel {
        Some(cb) => cb()
        None => ()
      }
    } else {
      // 首订重传耗尽：会话失败（登记一并清除——订阅从未建立）
      clear_session_timers(s)
      let _ = self.ctrl_pool.release(s.peer, s.strm_id)
      let _ = self.sessions.remove(key)
      let _ = self.regs.remove(key)
      (s.on_err)(@errors.RequestTimeout)
    }
    return
  }
  s.retransmits = s.retransmits + 1
  let ttl = if s.cancelling {
    0
  } else {
    self.cfg.ttl_sec
  }
  let _ = self.send_sub_frame(s, @frame.Con, ttl)
  s.retrans_timer = self.arm_retrans(key)
}

/// 保活定时回调（§7.2：每 period 发 NON(TTL>0) 刷新；§7.5 发送方携带固定 TTL 不递减）
fn Sd::sub_keepalive_tick(self : Sd, key : String) -> Unit {
  let s = match self.sessions.get(key) {
    Some(v) => v
    None => return
  }
  // 确认前不发保活（重传链负责）；取消中不发（取消重传链负责）
  if s.confirmed && !s.cancelling {
    let _ = self.send_sub_frame(s, @frame.Non, self.cfg.ttl_sec)
  }
}

/// 清会话定时器（不释放 strm、不移除记录；纯会话操作，不依赖 Sd 状态故为顶层函数）
fn clear_session_timers(s : SubSession) -> Unit {
  if s.retrans_timer != -1 {
    sd_clear_timeout(s.retrans_timer)
    s.retrans_timer = -1
  }
  if s.keep_timer != -1 {
    sd_clear_interval(s.keep_timer)
    s.keep_timer = -1
  }
}

/// 收订阅建立确认 0x10（§8.1：客户端据此 Found→Subscribed；确认与数据解耦，单一信号）
fn Sd::handle_sub_ack(self : Sd, f : @frame.Frame, host : String) -> Unit {
  let key = self.find_session_key(host, f.strm_id)
  match key {
    Some(k) =>
      match self.sessions.get(k) {
        Some(s) =>
          if !s.confirmed && !s.cancelling {
            s.confirmed = true
            s.retransmits = 0
            if s.retrans_timer != -1 {
              sd_clear_timeout(s.retrans_timer)
              s.retrans_timer = -1
            }
            // 启动保活（每 period，§7.2）
            s.keep_timer = sd_set_interval(
              fn(_x) { self.sub_keepalive_tick(k) },
              self.cfg.period_ms,
            )
            (s.on_ok)(s.strm_id)
          }
          // 重复 0x10（服务端对重传 CON 的重复确认）：幂等忽略
        None => ()
      }
    // 非活跃会话的迟到确认（StrmID 已冷却）：静默丢弃
    None => ()
  }
}

/// 收取消确认 0x00（§7.6 场景 4：完整清理会话与登记）
fn Sd::handle_cancel_ack(self : Sd, f : @frame.Frame, host : String) -> Unit {
  let key = self.find_session_key(host, f.strm_id)
  match key {
    Some(k) =>
      match self.sessions.get(k) {
        Some(s) =>
          if s.cancelling {
            clear_session_timers(s)
            let _ = self.ctrl_pool.release(s.peer, s.strm_id)
            let _ = self.sessions.remove(k)
            // 登记清除条件 ①：应用显式 unsubscribe（§7.4）
            let _ = self.regs.remove(k)
            match s.on_cancel {
              Some(cb) => cb()
              None => ()
            }
          }
        // 非取消会话收到 0x00：异常帧，忽略
        None => ()
      }
    None => ()
  }
}

/// 取消订阅（§13.2 unsubscribe：发 Subscribe(TTL=0) CON，同会话 StrmID；幂等）
pub fn Sd::unsubscribe(
  self : Sd,
  svc_id : Int,
  if_id : Int,
  grp_id : Int,
  on_done : () -> Unit
) -> Unit {
  // 登记键含 inst_id（subscribe 时确定），此处按 (svc, if, grp) 反查
  let found : Array[String] = []
  for k, reg in self.regs {
    if reg.svc_id == svc_id && reg.if_id == if_id && reg.grp_id == grp_id {
      found.push(k)
    }
  }
  if found.length() == 0 {
    on_done() // 无登记：幂等完成
    return
  }
  let key = found[0]
  match self.sessions.get(key) {
    None => {
      // 无活跃会话（RST 后残留登记）：直接清登记完成
      let _ = self.regs.remove(key)
      on_done()
    }
    Some(s) => {
      // 发 Subscribe(TTL=0, CON)（§7.6 场景 4），复用会话 StrmID
      s.cancelling = true
      s.on_cancel = Some(on_done)
      s.retransmits = 0
      if s.retrans_timer != -1 {
        sd_clear_timeout(s.retrans_timer)
      }
      if s.keep_timer != -1 {
        sd_clear_interval(s.keep_timer)
        s.keep_timer = -1
      }
      let _ = self.send_sub_frame(s, @frame.Con, 0)
      s.retrans_timer = self.arm_retrans(key)
    }
  }
}

/// 按 (peer, StrmID) 定位会话键（确认/RST 回显归属判定）
fn Sd::find_session_key(self : Sd, peer : String, strm_id : Int) -> String? {
  for k, s in self.sessions {
    if s.peer == peer && s.strm_id == strm_id {
      return Some(k)
    }
  }
  None
}

/// UDP RST 处理（客户端视角：Subscribe CON 被对端拒绝，§7.4）
fn Sd::handle_udp_rst(self : Sd, f : @frame.Frame, host : String) -> Unit {
  let key = self.find_session_key(host, f.strm_id)
  match key {
    Some(k) =>
      match self.sessions.get(k) {
        Some(s) =>
          if s.cancelling {
            // 取消被拒（§7.4：停止重传，释放会话 StrmID；登记保留——服务端记录靠 TTL 自愈）
            // 应用意图已表达：清登记避免自动重订阅复活（§7.4 清除条件 ①）
            clear_session_timers(s)
            let _ = self.ctrl_pool.release(s.peer, s.strm_id)
            let _ = self.sessions.remove(k)
            let _ = self.regs.remove(k)
            match s.on_cancel {
              Some(cb) => cb()
              None => ()
            }
          } else {
            // 首订被拒（0x20/0x24，§7.4 Found 表行：停止重传，释放 StrmID，报订阅失败）
            clear_session_timers(s)
            let _ = self.ctrl_pool.release(s.peer, s.strm_id)
            let _ = self.sessions.remove(k)
            let _ = self.regs.remove(k)
            (s.on_err)(@errors.Remote(f.code))
          }
        None => ()
      }
    None => ()
  }
}
