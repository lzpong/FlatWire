// 事件推送层（§8：notify 缓存与多客户端推送 / 全量推送 / tcp-event 通道 / 客户端接收去重）
//
// 职责：
// - 服务端：notify 更新接口缓存 + 按 SubEstablished 之外的分发规则推送订阅者；
//   订阅建立（SubEstablished）→ 推全量（纯数据分发，§8.1）；CON Notify 重传链（§5.5）
// - 客户端：接收 Notification 去重交付（§8.2 接收记录）；CON 回空确认
//
// 传输规则（§8.2/§11.1）：接口 tcp=true → 复用订阅者 TCP 连接（NON，断连暂停不补发）；
// UDP reliable=true → CON（重传保证送达）；否则 NON 尽力而为

/// 服务端 CON Notify 重传记录（§5.5：键 (peer,svc,inst,strm)，重传同字节，随 ACK/RST 清除）
priv struct OutNotify {
  peer : String // 订阅者源 IP（推送目标）
  port : Int // 订阅者源端口（Subscribe 单播源端口）
  spec : @frame.FrameSpec
  payload : Bytes
  mut retries : Int
  mut timer : Int
}

/// 事件层主体
pub struct Events {
  transport : @transport.Transport
  data_pool : @strm.DataStrmPool // 与 rpc 共享实例（server 子池 0x80~0xFE 独立，§6.3）
  store : @idlstore.IdlStore
  sd : @sd.Sd // 订阅者查询（subs_for_event，§8.2）
  priv cache : Map[String, Bytes] // 接口缓存，key "svc|inst|if"
  priv out_cons : Map[String, OutNotify] // 服务端 CON Notify 重传链，key "peer|svc|inst|strm"
  priv recv_seen : Map[String, Int] // 客户端接收去重（值 = 清理 timer），key "peer|svc|inst|strm"
  priv client_subs : Map[String, (Int, Bytes) -> Unit] // 回调，key "i|svc|if" / "g|svc|grp"
  retrans_interval_ms : Int // CON 重传基准间隔（200，§5.5）
  max_retry : Int // 重传次数不含首次（3，§5.5）
}

/// 创建事件层（纯构造）
pub fn Events::new(
  transport : @transport.Transport,
  data_pool : @strm.DataStrmPool,
  store : @idlstore.IdlStore,
  sd : @sd.Sd
) -> Events {
  {
    transport,
    data_pool,
    store,
    sd,
    cache: Map([], capacity=8),
    out_cons: Map([], capacity=8),
    recv_seen: Map([], capacity=8),
    client_subs: Map([], capacity=8),
    retrans_interval_ms: 200,
    max_retry: 3,
  }
}

// ===== 键构造 =====

fn ev_cache_key(svc_id : Int, inst_id : Int, if_id : Int) -> String {
  "\{svc_id}|\{inst_id}|\{if_id}"
}

fn ev_out_key(peer : String, svc_id : Int, inst_id : Int, strm_id : Int) -> String {
  "\{peer}|\{svc_id}|\{inst_id}|\{strm_id}"
}

fn ev_sub_key(svc_id : Int, if_id : Int, grp_id : Int) -> String {
  if if_id != 0 {
    "i|\{svc_id}|\{if_id}"
  } else {
    "g|\{svc_id}|\{grp_id}"
  }
}

// ===== 客户端回调注册（§13.2 subscribe 的交付侧；Subscribe 帧由 sd 层发送） =====

/// 注册事件交付回调（单接口 if_id≠0 / 组订阅 grp_id≠0；返回键供注销比对）
pub fn Events::reg_client(
  self : Events,
  svc_id : Int,
  if_id : Int,
  grp_id : Int,
  on_event : (Int, Bytes) -> Unit
) -> String {
  let key = ev_sub_key(svc_id, if_id, grp_id)
  self.client_subs[key] = on_event
  key
}

/// 注销事件交付回调（unsubscribe 时调用；返回是否已移除）
pub fn Events::unreg_client(self : Events, key : String) -> Bool {
  if self.client_subs.contains(key) {
    let _ = self.client_subs.remove(key)
    true
  } else {
    false
  }
}

// ===== 接口/组辅助查询 =====

/// 查接口定义（本端任一版本——服务端推送按本端已注册定义，§11.1）
fn Events::iface_of(self : Events, svc_id : Int, if_id : Int) -> @idlstore.IdlInterface? {
  match self.store.get_any(svc_id) {
    Some(d) => d.find_interface(if_id)
    None => None
  }
}

/// 该 event 接口所属组号列表（组 members 含该 if_id，§7.1/§11.1）
fn Events::groups_of(self : Events, svc_id : Int, if_id : Int) -> Array[Int] {
  let out : Array[Int] = []
  match self.store.get_any(svc_id) {
    Some(d) =>
      for g in d.groups {
        for m in g.members {
          if m == if_id {
            out.push(g.grp_id)
            break
          }
        }
      }
    None => ()
  }
  out
}

// ===== 服务端推送 =====

/// 更新接口缓存并推送所有订阅者（§13.1 notify；§8.1 缓存同时是全量推送的数据源）
pub fn Events::notify(
  self : Events,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  payload : Bytes
) -> Unit {
  self.cache[ev_cache_key(svc_id, inst_id, if_id)] = payload
  self.dispatch(svc_id, inst_id, if_id, payload)
}

/// 按 §8.2 规则向该接口的全部订阅者推送（每客户端独立 StrmID，§5.3）
fn Events::dispatch(self : Events, svc_id : Int, inst_id : Int, if_id : Int, payload : Bytes) -> Unit {
  let subs = self.sd.subs_for_event(svc_id, inst_id, if_id, self.groups_of(svc_id, if_id))
  for s in subs {
    self.push_one(s, svc_id, inst_id, if_id, payload)
  }
}

/// 向单个订阅者推送（传输选择按接口绑定，§8.2）
fn Events::push_one(
  self : Events,
  s : @sd.ServerSub,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  payload : Bytes
) -> Unit {
  let iface = self.iface_of(svc_id, if_id)
  let tcp = match iface {
    Some(v) => v.tcp
    None => false
  }
  let reliable = match iface {
    Some(v) => v.reliable
    None => false
  }
  if tcp {
    // §8.2：tcp-event 复用订阅者 TCP 连接（按源 IP 匹配，TYP=NON）；断连暂停不补发（订阅保留）
    match self.transport.conn_id_by_peer(s.peer) {
      Some(cid) => {
        let strm = match self.data_pool.alloc_server(s.peer, svc_id, inst_id) {
          Some(v) => v
          None => {
            ev_log_error("[events] server StrmID 耗尽: peer=\{s.peer} svc=\{svc_id}")
            return
          }
        }
        let spec = @frame.data_spec(@frame.Non, 0x03, svc_id, if_id, inst_id, strm)
        let _ = self.transport.send_tcp_frame(cid, spec, payload)
        // §6.2：NON Notification 发送完成即 Closed
        self.data_pool.release(s.peer, svc_id, inst_id, strm)
      }
      None => () // 无活跃连接：推送暂停（§8.2，不补发不报错）
    }
  } else if reliable {
    // §5.3：UDP 可靠事件 = CON，等 ACK 或重传耗尽（§6.2 CON 保持 Active）
    let strm = match self.data_pool.alloc_server(s.peer, svc_id, inst_id) {
      Some(v) => v
      None => {
        ev_log_error("[events] server StrmID 耗尽: peer=\{s.peer} svc=\{svc_id}")
        return
      }
    }
    let spec = @frame.data_spec(@frame.Con, 0x03, svc_id, if_id, inst_id, strm)
    let _ = self.transport.send_udp_frame(true, spec, payload, s.peer, s.peer_port)
    let o : OutNotify = { peer: s.peer, port: s.peer_port, spec, payload, retries: 0, timer: -1 }
    self.out_cons[ev_out_key(s.peer, svc_id, inst_id, strm)] = o
    self.notify_chain(o)
  } else {
    // §5.3：UDP 常规事件 = NON 尽力而为，发送完成即释放（§6.2）
    let strm = match self.data_pool.alloc_server(s.peer, svc_id, inst_id) {
      Some(v) => v
      None => return // 无可用 StrmID：NON 尽力而为语义下静默放弃
    }
    let spec = @frame.data_spec(@frame.Non, 0x03, svc_id, if_id, inst_id, strm)
    let _ = self.transport.send_udp_frame(true, spec, payload, s.peer, s.peer_port)
    self.data_pool.release(s.peer, svc_id, inst_id, strm)
  }
}

/// Notify CON 重传链（0/200/600/1400ms，3000ms 静默停止并释放，§5.5）
fn Events::notify_chain(self : Events, o : OutNotify) -> Unit {
  o.timer = ev_set_timeout(fn(_) { self.notify_fire(o) }, self.retrans_interval_ms * (1 << o.retries))
}

fn Events::notify_fire(self : Events, o : OutNotify) -> Unit {
  if o.retries < self.max_retry {
    o.retries = o.retries + 1
    let _ = self.transport.send_udp_frame(true, o.spec, o.payload, o.peer, o.port)
    o.timer = ev_set_timeout(
      fn(_) { self.notify_fire(o) },
      self.retrans_interval_ms * (1 << o.retries),
    )
  } else {
    // 静默停止：释放 StrmID + 移除记录（§5.5 重传耗尽不报错；§6.2 重传耗尽 → Closed）
    o.timer = -1
    let key = ev_out_key(o.peer, o.spec.svc_id, o.spec.inst_id, o.spec.strm_id)
    let _ = self.out_cons.remove(key)
    self.data_pool.release(o.peer, o.spec.svc_id, o.spec.inst_id, o.spec.strm_id)
  }
}

/// 取消 Notify 重传链（ACK/RST 到达；幂等；释放 StrmID §6.2）
fn Events::notify_cancel(self : Events, o : OutNotify) -> Unit {
  if o.timer != -1 {
    ev_clear_timeout(o.timer)
    o.timer = -1
  }
  let _ = self.out_cons.remove(ev_out_key(o.peer, o.spec.svc_id, o.spec.inst_id, o.spec.strm_id))
  self.data_pool.release(o.peer, o.spec.svc_id, o.spec.inst_id, o.spec.strm_id)
}

// ===== 全量推送（§8.1：订阅记录从无到有时推接口缓存，纯数据分发，每条订阅仅一次） =====

/// SD 层 SubEstablished 事件桥接（stack 层调用）：按该订阅推送缓存数据
/// - 单接口订阅（if_id≠0）：推该接口缓存（若有）
/// - 组订阅（grp_id≠0）：推组内各接口的缓存（逐接口独立 StrmID）
pub fn Events::on_sub_established(self : Events, s : @sd.ServerSub) -> Unit {
  if s.if_id != 0 {
    match self.cache.get(ev_cache_key(s.svc_id, s.inst_id, s.if_id)) {
      Some(payload) => self.push_one(s, s.svc_id, s.inst_id, s.if_id, payload)
      None => () // 尚无缓存：应用注册后 notify 时按常规分发覆盖
    }
  } else {
    // 组订阅展开：遍历组 members 逐接口推送缓存（§7.1 组语义）
    match self.store.get_any(s.svc_id) {
      Some(d) =>
        match d.find_group(s.grp_id) {
          Some(g) =>
            for if_id in g.members {
              match self.cache.get(ev_cache_key(s.svc_id, s.inst_id, if_id)) {
                Some(payload) => self.push_one(s, s.svc_id, s.inst_id, if_id, payload)
                None => ()
              }
            }
          None => ()
        }
      None => ()
    }
  }
}

// ===== 服务端 ACK/RST 入口（stack 层桥接；rpc 层未匹配再交此处理） =====

/// UDP ACK（客户端对 CON Notify 的传输确认，§3.4）：停重传链 + 释放 StrmID（§6.2）
pub fn Events::on_udp_ack(self : Events, f : @frame.Frame, host : String) -> Unit {
  let key = ev_out_key(host, f.svc_id, f.inst_id, f.strm_id)
  match self.out_cons.get(key) {
    Some(o) => self.notify_cancel(o)
    None => ()
  }
}

/// RST（客户端拒收推送，§5.4）：停重传链 + 释放（订阅关系不受影响，§12.3）
pub fn Events::on_rst(self : Events, f : @frame.Frame, host : String) -> Unit {
  let key = ev_out_key(host, f.svc_id, f.inst_id, f.strm_id)
  match self.out_cons.get(key) {
    Some(o) => self.notify_cancel(o)
    None => ()
  }
}

// ===== 客户端接收（stack 层桥接：CTR=0 Code=0x03 Notification） =====

/// UDP 入口
pub fn Events::on_udp_data(self : Events, f : @frame.Frame, host : String, port : Int) -> Unit {
  if f.code == 0x03 {
    self.handle_notification(f, host, port)
  }
}

/// TCP 入口（tcp-event 通道，TYP=NON 无确认，§8.2）
pub fn Events::on_tcp_data(self : Events, f : @frame.Frame, host : String) -> Unit {
  if f.code == 0x03 {
    self.handle_notification(f, host, 0)
  }
}

/// 处理 Notification（§8.2：CON 回空确认；接收记录去重——重复 CON 仍回 ACK 仅不重复交付）
fn Events::handle_notification(self : Events, f : @frame.Frame, host : String, port : Int) -> Unit {
  // §5.3：CON → 回空确认（回显 StrmID）；重复到达（对端重传中）同样回确认
  if f.typ is @frame.Con {
    let _ = self.transport.send_udp_frame(
      false,
      @frame.data_spec(@frame.Ack, 0x00, f.svc_id, f.if_id, f.inst_id, f.strm_id),
      b"",
      host,
      port,
    )
  }
  // §8.2 接收去重：键 (peer,svc,inst,strm)；记录保留至 ≥ 重传窗口 3s + 余量
  let key = ev_out_key(host, f.svc_id, f.inst_id, f.strm_id)
  if self.recv_seen.contains(key) {
    return
  }
  self.recv_seen[key] = ev_set_timeout(fn(_) { let _ = self.recv_seen.remove(key) }, 3200)
  // 交付：单接口精确回调 → 组订阅回调（展开 if_id 归属组）
  match self.client_subs.get(ev_sub_key(f.svc_id, f.if_id, 0)) {
    Some(cb) => {
      cb(f.if_id, f.payload)
      return
    }
    None => ()
  }
  for grp_id in self.groups_of(f.svc_id, f.if_id) {
    match self.client_subs.get(ev_sub_key(f.svc_id, 0, grp_id)) {
      Some(cb) => {
        cb(f.if_id, f.payload)
        return
      }
      None => ()
    }
  }
}

