// RPC 客户端（§5.1 call / §5.2 fire_forget 发起；§5.5 重传与响应超时联动；重复响应去重）

/// 发起 RPC 调用（§13.2 call_async 语义；同步 call 由 stack 层经回调栅栏实现）
///
/// - major_ver：目标实例版本（stack 层自发现缓存取得，用于接口 transport 绑定查询）
/// - timeout_ms：应用层响应超时（≤0 取默认 response_timeout_ms）
/// - 传输：接口 tcp=true → TCP 长连接（NON，无重传）；否则 UDP（CON + 重传链）
pub fn Rpc::call(
  self : Rpc,
  host : String,
  port : Int,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  major_ver : Int,
  payload : Bytes,
  timeout_ms : Int,
  on_ok : (Bytes) -> Unit,
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  let iface = match self.iface_of(svc_id, major_ver, if_id) {
    Some(v) => v
    None => {
      on_err(@errors.IdlMissing("interface \{svc_id}.\{if_id} not found"))
      return
    }
  }
  let strm = match self.data_pool.alloc_client(host, svc_id, inst_id) {
    Some(s) => s
    None => {
      on_err(@errors.Local("client StrmID exhausted for peer \{host}"))
      return
    }
  }
  let key = rpc_key(host, svc_id, inst_id, strm)
  let timeout = if timeout_ms > 0 {
    timeout_ms
  } else {
    self.cfg.response_timeout_ms
  }
  let p : PendReq = {
    svc_id,
    inst_id,
    strm_id: strm,
    resp_timer: -1,
    on_ok,
    on_err,
  }
  self.pending[key] = p
  if iface.tcp {
    // §5.1：TCP Request = NON，可靠性由 TCP 承担；连接未就绪时排队（on_tcp_connected 排空）
    // TCP 目标端口 = §2 fw_tcp_port（发现端口仅 UDP 单播语义，§5.6/§7.2）
    let spec = @frame.data_spec(@frame.Non, 0x01, svc_id, if_id, inst_id, strm)
    self.tcp_send_or_wait(host, spec, payload)
  } else {
    // §5.1：UDP Request = CON → 重传链（0/200/600/1400ms，§5.5）
    let spec = @frame.data_spec(@frame.Con, 0x01, svc_id, if_id, inst_id, strm)
    let _ = self.transport.send_udp_frame(false, spec, payload, host, port)
    let o : OutCon = {
      peer: host,
      port,
      svc_id,
      inst_id,
      strm_id: strm,
      spec,
      payload,
      retries: 0,
      timer: -1,
      on_err: fn(_e) { () }, // call 的成败由响应超时/RST 判定，此处回调不挂接
    }
    self.cons[key] = o
    self.con_chain(o)
  }
  // 应用层响应超时（§5.1：唯一终态判定；触发时一并取消待确认重传，§5.5）
  p.resp_timer = rp_set_timeout(fn(_) { self.call_timeout(key) }, timeout)
}

/// 响应超时触发：清理 pending + 重传链 + StrmID，上抛 RequestTimeout（§5.1/§5.5）
fn Rpc::call_timeout(self : Rpc, key : String) -> Unit {
  match self.pending.get(key) {
    Some(p) => {
      let _ = self.pending.remove(key)
      self.cancel_con(key)
      self.data_pool.release(key_peer(key), p.svc_id, p.inst_id, p.strm_id)
      (p.on_err)(@errors.RequestTimeout)
    }
    None => ()
  }
}

/// 取消该键的 CON 重传链（幂等；不存在则忽略）
fn Rpc::cancel_con(self : Rpc, key : String) -> Unit {
  match self.cons.get(key) {
    Some(o) => {
      con_cancel(o)
      let _ = self.cons.remove(key)
    }
    None => ()
  }
}

/// 发起 Fire-Forget（§13.2；UDP=CON 重传保证送达 / TCP=NON 发完即关，§5.2/§6.2）
pub fn Rpc::fire_forget(
  self : Rpc,
  host : String,
  port : Int,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  major_ver : Int,
  payload : Bytes,
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  let iface = match self.iface_of(svc_id, major_ver, if_id) {
    Some(v) => v
    None => {
      on_err(@errors.IdlMissing("interface \{svc_id}.\{if_id} not found"))
      return
    }
  }
  let strm = match self.data_pool.alloc_client(host, svc_id, inst_id) {
    Some(s) => s
    None => {
      on_err(@errors.Local("client StrmID exhausted for peer \{host}"))
      return
    }
  }
  let key = rpc_key(host, svc_id, inst_id, strm)
  if iface.tcp {
    // §6.2：NON Fire-Forget 发送完成即 Closed → 立即释放 StrmID
    // TCP 目标端口 = §2 fw_tcp_port（发现端口仅 UDP 单播语义，§5.6/§7.2）
    let spec = @frame.data_spec(@frame.Non, 0x02, svc_id, if_id, inst_id, strm)
    self.tcp_send_or_wait(host, spec, payload)
    self.data_pool.release(host, svc_id, inst_id, strm)
  } else {
    // §5.5：CON FF 走重传链，Stream 保持 Active 至 ACK 收到或重传耗尽（§6.2）
    let spec = @frame.data_spec(@frame.Con, 0x02, svc_id, if_id, inst_id, strm)
    let _ = self.transport.send_udp_frame(false, spec, payload, host, port)
    let o : OutCon = {
      peer: host,
      port,
      svc_id,
      inst_id,
      strm_id: strm,
      spec,
      payload,
      retries: 0,
      timer: -1,
      on_err,
    }
    self.cons[key] = o
    self.con_chain(o)
  }
}

/// TCP 发送或排队（连接未就绪时入等待队列，on_tcp_connected 排空补发，§5.6）；
/// 目标端口恒 = §2 fw_tcp_port（host 参数为发现获得的对端 IP）
fn Rpc::tcp_send_or_wait(
  self : Rpc,
  host : String,
  spec : @frame.FrameSpec,
  payload : Bytes
) -> Unit {
  let conn_id = self.transport.tcp_connect(host, self.transport.cfg.tcp_port)
  if self.transport.is_alive(conn_id) {
    let _ = self.transport.send_tcp_frame(conn_id, spec, payload)
  } else {
    // 键 = host|fw_tcp_port（与 on_tcp_connected 排空侧一致：出站连接目标端口恒为 §2 fw_tcp_port）
    let key = "\{host}|\{self.transport.cfg.tcp_port}"
    let job = fn() { let _ = self.transport.send_tcp_frame(conn_id, spec, payload) }
    match self.conn_wait.get(key) {
      Some(q) => q.push(job)
      None => self.conn_wait[key] = [job]
    }
  }
}

// ===== 客户端收帧处理（stack 层桥接：Code=0x10 响应 / TYP=RST / TYP=ACK 分流） =====

/// 数据帧入口（Code=0x10 Response；其他 Code 忽略——0x01/0x02 走服务端，0x03 走 events）
pub fn Rpc::on_udp_data_resp(self : Rpc, f : @frame.Frame, host : String, port : Int) -> Unit {
  if f.code == 0x10 {
    self.handle_response(f, host, port)
  }
}

pub fn Rpc::on_tcp_data_resp(self : Rpc, f : @frame.Frame, host : String) -> Unit {
  if f.code == 0x10 {
    self.handle_response(f, host, 0)
  }
}

/// 处理 Response（§5.1：回显 StrmID 匹配 pending；§5.5 客户端重复响应按 StrmID 丢弃只交付首个）
fn Rpc::handle_response(self : Rpc, f : @frame.Frame, host : String, port : Int) -> Unit {
  let key = rpc_key(host, f.svc_id, f.inst_id, f.strm_id)
  match self.pending.get(key) {
    Some(p) => {
      // 响应到达：取消超时 + 重传链 + 释放 StrmID（§5.1/§6.2 Request 收到 Response → Closed）
      if p.resp_timer != -1 {
        rp_clear_timeout(p.resp_timer)
        p.resp_timer = -1
      }
      let _ = self.pending.remove(key)
      self.cancel_con(key)
      self.data_pool.release(host, f.svc_id, f.inst_id, f.strm_id)
      // §5.1：UDP Response=CON → 客户端回空确认（传输确认，与应用无关）
      if f.typ is @frame.Con {
        let _ = self.transport.send_udp_frame(
          false,
          @frame.data_spec(@frame.Ack, 0x00, f.svc_id, f.if_id, f.inst_id, f.strm_id),
          b"",
          host,
          port,
        )
      }
      (p.on_ok)(f.payload)
    }
    None => {
      // 重复响应（首响应 ACK 丢失触发服务端重传）：仅回确认，不重复交付（§5.5）
      if f.typ is @frame.Con {
        let _ = self.transport.send_udp_frame(
          false,
          @frame.data_spec(@frame.Ack, 0x00, f.svc_id, f.if_id, f.inst_id, f.strm_id),
          b"",
          host,
          port,
        )
      }
    }
  }
}

/// UDP ACK 入口（stack 层桥接：TYP=ACK Code=0x00 且 events 未匹配 → 这里）：
/// 命中客户端 FF 重传链（收到服务端确认，§6.2）或服务端响应缓存（Response CON 的客户端确认）
pub fn Rpc::on_udp_ack(self : Rpc, f : @frame.Frame, host : String) -> Unit {
  let key = rpc_key(host, f.svc_id, f.inst_id, f.strm_id)
  // 客户端视角：FF CON 被确认 → 停链 + 释放（§6.2 确认收到 → Closed）
  match self.cons.get(key) {
    Some(o) => {
      con_cancel(o)
      let _ = self.cons.remove(key)
      self.data_pool.release(host, o.svc_id, o.inst_id, o.strm_id)
      return
    }
    None => ()
  }
  // 服务端视角：Response CON 被确认 → 清响应缓存（§5.5 随 Stream 释放清除）
  match self.resp_cache.get(key) {
    Some(c) => {
      if c.timer != -1 {
        rp_clear_timeout(c.timer)
        c.timer = -1
      }
      let _ = self.resp_cache.remove(key)
    }
    None => ()
  }
}

/// RST 入口（stack 层桥接 TYP=RST 且 events 未匹配 → 这里）：
/// pending（Request）→ on_err(Remote)；cons（FF）→ 静默清理；resp_cache → 清除
pub fn Rpc::on_rst(self : Rpc, f : @frame.Frame, host : String) -> Unit {
  let key = rpc_key(host, f.svc_id, f.inst_id, f.strm_id)
  match self.pending.get(key) {
    Some(p) => {
      if p.resp_timer != -1 {
        rp_clear_timeout(p.resp_timer)
        p.resp_timer = -1
      }
      let _ = self.pending.remove(key)
      self.cancel_con(key)
      self.data_pool.release(host, f.svc_id, f.inst_id, f.strm_id)
      (p.on_err)(@errors.Remote(f.code))
      return
    }
    None => ()
  }
  match self.cons.get(key) {
    Some(o) => {
      con_cancel(o)
      let _ = self.cons.remove(key)
      self.data_pool.release(host, o.svc_id, o.inst_id, o.strm_id)
      // FF 失败回调：RST 表达服务端拒绝（如服务不存在 0x24）；call 场景回调为 no-op
      ;(o.on_err)(@errors.Remote(f.code))
      return
    }
    None => ()
  }
  match self.resp_cache.get(key) {
    Some(c) => {
      if c.timer != -1 {
        rp_clear_timeout(c.timer)
        c.timer = -1
      }
      let _ = self.resp_cache.remove(key)
    }
    None => ()
  }
}

/// 从 rpc 键提取 peer 段（键形如 "peer|svc|inst|strm"；peer 自身不含 '|'——IP 地址）
fn key_peer(key : String) -> String {
  match key.split("|").next() {
    Some(s) => s.to_owned() // StringView → owned String（v0.10：to_string 仅供 Show 展示）
    None => ""
  }
}
