// §5 传输层：UDP 组播双 socket + TCP 连接管理（Node.js 运行时）
//
// - 双 socket（§5.2）：server socket 绑定 fw_udp_port 并加入组播组
//   （收组播 Offer/Find/REN + 发往该端口的单播）；client socket 绑定临时端口仅单播
//   （收响应/确认/RST）。单实例双 socket 自洽，client socket 不收组播不影响正确性。
// - 组播帧判定（§4.4"组播帧静默丢弃"）：OS 层（node dgram message 事件）不可得 UDP
//   目的地址 → server socket 上解析违规帧一律静默丢弃（保守实现，绝不向可能的组播回帧
//   引发风暴；代价为发往 5400 端口的违规单播帧不回 RST，对端按超时处理，不破坏正确性）；
//   client socket 仅收单播 → 违规帧回 RST（§5.4 回显触发帧 ID）
// - TCP（§4.1/§5.6/§5.7）：每连接持有独立半帧解析器；心跳空闲 heartbeat_period 发 Ping、
//   2×heartbeat_period 未收到任何帧判失效销毁；出站连接断开 1s 后自动重连（间隔为工程
//   决策，规范仅要求"自动重连"）；重连成功后由 stack 层响应 TcpClosed/TcpConnected 重触发 SD

/// 组播组地址（§2 fw_multicast；与 transport_ffi.mbt 中 addMembership 保持一致）
pub const MULTICAST_ADDR : String = "224.0.1.187"

/// 传输层配置（§2 参数）
pub(all) struct TransportConfig {
  udp_port : Int // §2 fw_udp_port（默认 5400）
  tcp_port : Int // §2 TCP/UDP 共用预定义端口（默认 5400，规范 §2）
  bind_address : String // 绑定地址（"" = 全接口；同机多实例演示按回环 IP 区分单播投递）
  tcp_enabled : Bool // 是否监听 TCP 服务端（客户端角色可关闭，出站连接不受影响）
  local_ver : Int // 本端协议版本（§4.3 步骤 1 校验基准）
  max_payload_len : Int // §2 max_payload_len（UDP 帧级超限 → 0x23，默认 1400）
  tcp_frame_timeout_ms : Int64 // §2 tcp_frame_timeout_ms（TCP 半帧超时，默认 5000）
  heartbeat_period_ms : Int64 // §2 heartbeat_period_ms（心跳周期，默认 30000；失效阈值=2×）
} derive(Eq)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend TransportConfig with Eq::{not_equal, equal}

/// 传输层上抛事件（stack 组装层消费）
pub(all) enum TransportEvent {
  UdpFrame(@frame.Frame, String, Int, Bool) // UDP 帧到达（帧, 源IP, 源端口, 是否 server socket 收到）
  TcpFrame(@frame.Frame, Int) // TCP 帧完整交付（帧, conn_id）
  TcpConnected(Int, String, Int) // 出站连接建立（conn_id, peer, port）
  TcpAccepted(Int, String, Int) // 入站连接接受（conn_id, peer, port）
  TcpClosed(Int, String, Int) // 连接关闭（conn_id, peer, port）——§5.6 stack 据此清理并重触发 SD
}

/// TCP 连接记录（每连接一个 §4.1 半帧解析器）
pub(all) struct TcpConn {
  conn_id : Int
  mut peer : String // 对端 IP（出站=connect 目标；入站=accept 回调填充）
  mut port : Int // 对端端口
  outbound : Bool // 是否出站连接（§5.6 自动重连判定）
  parser : @frame.TcpFrameParser
  mut last_recv_ms : Int64 // 最近收到数据时刻（§5.7 存活计时，收到任意数据刷新）
  mut last_send_ms : Int64 // 最近发出数据时刻（§5.7 空闲计时，发出任意帧刷新）
  mut alive : Bool // 连接是否已建立（connected/accepted 后为 true）
}

/// 传输层实例（单实例；FFI 句柄托管于 globalThis.__fw）
pub struct Transport {
  cfg : TransportConfig
  priv mut server_idx : Int // server socket 句柄（-1 未初始化）
  priv mut client_idx : Int // client socket 句柄
  priv conns : Map[Int, TcpConn] // conn_id → 连接记录
  priv outbound : Map[String, Int] // "host:port" → conn_id（§5.6 出站幂等复用）
  priv mut next_conn_id : Int // conn_id 分配器
  priv on_event : (TransportEvent) -> Unit
  priv mut tick_timer : Int // tick 定时器句柄（-1 未启动）
  priv mut started : Bool
  priv mut udp_server_cb : (Bytes, String, Int) -> Unit // server socket 收包回调
  priv mut udp_client_cb : (Bytes, String, Int) -> Unit // client socket 收包回调
  priv mut udp_err_cb : (String) -> Unit // UDP 错误回调
  priv mut udp_bound_cb : (Int) -> Unit // UDP 绑定完成回调
  priv mut tcp_ev_cb : (Int, Int, String, Int, Bytes) -> Unit // TCP 事件回调
  priv mut tcp_next_id_cb : (Int) -> Int // TCP accept conn_id 分配回调
  priv mut tick_cb : (Int) -> Unit // tick 定时回调
}

/// 单调毫秒时钟（Int64）
fn now_ms() -> Int64 {
  ffi_now_ms(0).to_int64()
}

/// 构造 §5.7 心跳 Ping 帧：CTR=1, REN=0, TYP=NON, Code=0x00, 全 ID=0, Payload 空
pub fn ping_frame() -> Bytes {
  try @frame.encode_frame(@frame.ctrl_spec(@frame.Non, 0x00, 0), b"", None) catch {
    _ => b"" // 不可达：常量 spec 恒合法
  }
}

/// 构造 RST 帧（§5.4：TYP=RST、Code=错误码、回显触发帧 SvcID/IfID/InstID/StrmID）：
/// hdr=None（TCP 半帧阶段一无帧头）时全 0——传输控制帧（CTR=0 且 TYP=RST）豁免 ID 校验
/// （见 frame/parse.mbt 顶部注释），全 0 ID 的 RST 合法
fn make_rst_frame(code : Int, hdr : @frame.FrameHeader?) -> Bytes {
  let svc = match hdr {
    Some(h) => h.svc_id
    None => 0
  }
  let ifid = match hdr {
    Some(h) => h.if_id
    None => 0
  }
  let inst = match hdr {
    Some(h) => h.inst_id
    None => 0
  }
  let strm = match hdr {
    Some(h) => h.strm_id
    None => 0
  }
  try @frame.encode_frame(@frame.data_spec(@frame.Rst, code, svc, ifid, inst, strm), b"", None) catch {
    _ => b"" // 不可达：code 已由调用方保证在 0x20~0x3F
  }
}

/// 创建传输层实例（不启动；start 挂接 FFI）
pub fn Transport::new(
  cfg : TransportConfig,
  on_event : (TransportEvent) -> Unit
) -> Transport {
  // 回调闭包捕获 self 前需 struct 已存在 → 先以占位构造，start 前统一挂接
  let dummy_udp : (Bytes, String, Int) -> Unit = fn(_d, _h, _p) { () }
  let dummy_err : (String) -> Unit = fn(_m) { () }
  let dummy_bound : (Int) -> Unit = fn(_p) { () }
  let dummy_tcp : (Int, Int, String, Int, Bytes) -> Unit = fn(_c, _e, _h, _p, _d) { () }
  let dummy_next : (Int) -> Int = fn(_x) { 0 }
  let dummy_tick : (Int) -> Unit = fn(_x) { () }
  {
    cfg,
    server_idx: -1,
    client_idx: -1,
    conns: Map([], capacity=8),
    outbound: Map([], capacity=8),
    next_conn_id: 1,
    on_event,
    tick_timer: -1,
    started: false,
    udp_server_cb: dummy_udp,
    udp_client_cb: dummy_udp,
    udp_err_cb: dummy_err,
    udp_bound_cb: dummy_bound,
    tcp_ev_cb: dummy_tcp,
    tcp_next_id_cb: dummy_next,
    tick_cb: dummy_tick,
  }
}

/// 启动传输层（幂等）：初始化 FFI → 双 UDP socket → TCP listen → 500ms tick
pub fn Transport::start(self : Transport) -> Unit {
  if self.started {
    return
  }
  ffi_transport_init(0)
  // 挂接真实回调（捕获 self；MoonBit 闭包编译为普通 JS 函数，可被 FFI 调用）
  self.udp_server_cb = fn(data, host, port) { self.handle_udp(true, data, host, port) }
  self.udp_client_cb = fn(data, host, port) { self.handle_udp(false, data, host, port) }
  self.udp_err_cb = fn(msg) { ffi_log_error("[transport] UDP socket 错误: \{msg}") }
  self.udp_bound_cb = fn(port) { ffi_log_error("[transport] UDP socket 绑定完成: port=\{port}") }
  self.tcp_ev_cb = fn(cid, ev, host, port, data) {
    self.handle_tcp_event(cid, ev, host, port, data)
  }
  self.tcp_next_id_cb = fn(_x) -> Int {
    let id = self.next_conn_id
    self.next_conn_id = id + 1
    id
  }
  self.tick_cb = fn(_x) { self.tick() }
  // §5.2 server socket：bind fw_udp_port + 加入组播组（收组播 + 发往该端口的单播）
  self.server_idx = ffi_udp_open(self.cfg.udp_port, self.cfg.bind_address, true, self.udp_server_cb, self.udp_bound_cb, self.udp_err_cb)
  // §5.2 client socket：临时端口、不加组播（仅单播收发）
  self.client_idx = ffi_udp_open(0, self.cfg.bind_address, false, self.udp_client_cb, self.udp_bound_cb, self.udp_err_cb)
  // §5.6 TCP 服务端 listen（客户端角色 tcp_enabled=false 跳过——出站连接不受影响）
  if self.cfg.tcp_enabled {
    let _ = ffi_tcp_listen(self.cfg.tcp_port, self.cfg.bind_address, self.tcp_next_id_cb, self.tcp_ev_cb)
  }
  // tick 驱动：半帧超时检查（§4.1）+ 心跳（§5.7）；500ms 粒度为工程决策
  self.tick_timer = ffi_set_interval(self.tick_cb, 500)
  self.started = true
}

/// 停止传输层：清定时器 → 销毁全部 TCP 连接（主动关闭不回调、不重连）→ 关服务端 → 关双 UDP
pub fn Transport::stop(self : Transport) -> Unit {
  if !self.started {
    return
  }
  ffi_clear_interval(self.tick_timer)
  self.tick_timer = -1
  let ids : Array[Int] = []
  for cid, _conn in self.conns {
    ids.push(cid)
  }
  for cid in ids {
    ffi_tcp_destroy(cid)
    let _ = self.conns.remove(cid)
  }
  let keys : Array[String] = []
  for k, _v in self.outbound {
    keys.push(k)
  }
  for k in keys {
    let _ = self.outbound.remove(k)
  }
  ffi_tcp_server_close(0)
  ffi_udp_close(self.server_idx)
  self.server_idx = -1
  ffi_udp_close(self.client_idx)
  self.client_idx = -1
  self.started = false
}

/// UDP 收包处理（§4.2/§4.3/§4.4）：解析 → 交付 / 回 RST / 静默丢弃
fn Transport::handle_udp(
  self : Transport,
  from_server : Bool,
  data : Bytes,
  host : String,
  port : Int
) -> Unit {
  match @frame.parse_datagram(data, self.cfg.local_ver, self.cfg.max_payload_len) {
    // §4.3 步骤 8：合法帧交付上层（from_server 标志供上层区分组播候选/单播）
    Ok(frame) => (self.on_event)(UdpFrame(frame, host, port, from_server))
    Reject(code, hdr) => {
      // §4.4：组播帧静默丢弃。server socket 可能收到组播帧（目的地址不可判定）→ 保守静默；
      // client socket 仅收单播 → 回 RST(code)，回显触发帧 ID（§5.4）
      if !from_server {
        let raw = make_rst_frame(code, hdr)
        if raw.length() > 0 {
          ffi_udp_send(self.client_idx, raw, host, port)
        }
      }
    }
    // §4.4：数据报过短 / 长度与声明不符 → 静默丢弃（不截断、不回帧）
    Drop => ()
  }
}

/// UDP 发送（上层指定 socket 与目标；MSK=0——UDP 掩码为可选，本实现统一明文）
pub fn Transport::send_udp_frame(
  self : Transport,
  from_server : Bool,
  spec : @frame.FrameSpec,
  payload : Bytes,
  host : String,
  port : Int
) -> Bool {
  let raw = try @frame.encode_frame(spec, payload, None) catch { err => {
    ffi_log_error("[transport] UDP 帧编码失败: \{Repr(err)}")
    b""
  } }
  if raw.length() == 0 {
    return false
  }
  ffi_udp_send(if from_server {
    self.server_idx
  } else {
    self.client_idx
  }, raw, host, port)
  true
}

/// TCP 出站连接（§5.6 按 (IP, Port) 唯一长连接：已有同键连接直接复用返回其 conn_id）
pub fn Transport::tcp_connect(self : Transport, host : String, port : Int) -> Int {
  let key = "\{host}:\{port}"
  match self.outbound.get(key) {
    Some(cid) => cid
    None => {
      let cid = self.next_conn_id
      self.next_conn_id = cid + 1
      let now = now_ms()
      // 解析器按连接持有（§4.1），半帧超时 = §2 tcp_frame_timeout_ms
      let conn : TcpConn = {
        conn_id: cid,
        peer: host,
        port,
        outbound: true,
        parser: @frame.TcpFrameParser::new(self.cfg.local_ver, self.cfg.tcp_frame_timeout_ms),
        last_recv_ms: now,
        last_send_ms: now,
        alive: false,
      }
      self.conns[cid] = conn
      self.outbound[key] = cid
      ffi_tcp_connect(host, port, cid, self.tcp_ev_cb)
      cid
    }
  }
}

/// TCP 发送帧（编码 + 写流 + 刷新空闲计时；返回是否成功编码）
pub fn Transport::send_tcp_frame(
  self : Transport,
  conn_id : Int,
  spec : @frame.FrameSpec,
  payload : Bytes
) -> Bool {
  let raw = try @frame.encode_frame(spec, payload, None) catch { err => {
    ffi_log_error("[transport] TCP 帧编码失败: \{Repr(err)}")
    b""
  } }
  if raw.length() == 0 {
    return false
  }
  ffi_tcp_write(conn_id, raw)
  match self.conns.get(conn_id) {
    Some(conn) => conn.last_send_ms = now_ms()
    None => ()
  }
  true
}

/// 主动关闭连接（不回调 TcpClosed、不自动重连——调用方自行知晓）
pub fn Transport::tcp_close(self : Transport, conn_id : Int) -> Unit {
  match self.conns.get(conn_id) {
    Some(conn) => {
      ffi_tcp_destroy(conn_id)
      let _ = self.conns.remove(conn_id)
      // 出站幂等键清理（仅当仍指向该连接）
      let key = "\{conn.peer}:\{conn.port}"
      match self.outbound.get(key) {
        Some(v) => if v == conn_id {
          let _ = self.outbound.remove(key)
        }
        None => ()
      }
    }
    None => ()
  }
}

/// 查询连接是否存活
pub fn Transport::is_alive(self : Transport, conn_id : Int) -> Bool {
  match self.conns.get(conn_id) {
    Some(conn) => conn.alive
    None => false
  }
}

/// 按对端 IP 查找活跃 TCP 连接（§7.2/§8.2：tcp-event 推送按订阅者源 IP 匹配；
/// 同 IP 多条连接取任一（首个命中）。GetIDL/rpc 的复用由 tcp_connect 幂等键覆盖）
pub fn Transport::conn_id_by_peer(self : Transport, host : String) -> Int? {
  for _cid, conn in self.conns {
    if conn.alive && conn.peer == host {
      return Some(conn.conn_id)
    }
  }
  None
}

/// TCP 事件分发（FFI 回调入口；ev 1=数据 / 2=连接建立 / 3=连接关闭）
fn Transport::handle_tcp_event(
  self : Transport,
  conn_id : Int,
  ev : Int,
  host : String,
  port : Int,
  data : Bytes
) -> Unit {
  match ev {
    1 =>
      // 数据到达：刷新存活计时（§5.7"收到任意帧即刷新"按字节粒度近似）→ 喂解析器
      match self.conns.get(conn_id) {
        Some(conn) => {
          conn.last_recv_ms = now_ms()
          let now = conn.last_recv_ms
          for e in conn.parser.feed(data, now) {
            match e {
              // §4.3 步骤 8：帧完整交付
              TcpFrame(f) => (self.on_event)(TcpFrame(f, conn_id))
              // 帧头校验违规 → 回 RST(code)（§5.4 回显触发帧 ID）
              TcpReject(code, hdr) => {
                let raw = make_rst_frame(code, hdr)
                if raw.length() > 0 {
                  ffi_tcp_write(conn_id, raw)
                  conn.last_send_ms = now_ms()
                }
              }
              // §4.1 半帧超时 → RST(0x26)（帧头不可知场景全 0 ID，见 make_rst_frame 注释）
              TcpRst26 => {
                let raw = make_rst_frame(@errors.RST_FRAME_TIMEOUT, None)
                if raw.length() > 0 {
                  ffi_tcp_write(conn_id, raw)
                  conn.last_send_ms = now_ms()
                }
              }
              // §4.1 阶段一超时 / 丢弃模式兜底 → 关闭连接（JS 侧尚未删除 → destroy 收尾）
              TcpClose => {
                ffi_tcp_destroy(conn_id)
                self.on_conn_closed(conn_id)
              }
            }
          }
        }
        // 已关闭连接的迟到数据 → 忽略
        None => ()
      }
    2 =>
      // 连接建立（出站 connected / 入站 accepted 同一事件，按 outbound 区分上抛）
      match self.conns.get(conn_id) {
        Some(conn) => {
          conn.alive = true
          // 入站连接此刻才获知对端地址；出站以 connect 目标为准
          if conn.peer.length() == 0 {
            conn.peer = host
          }
          if conn.port == 0 {
            conn.port = port
          }
          let now = now_ms()
          conn.last_recv_ms = now
          conn.last_send_ms = now
          if conn.outbound {
            (self.on_event)(TcpConnected(conn_id, conn.peer, conn.port))
          } else {
            (self.on_event)(TcpAccepted(conn_id, conn.peer, conn.port))
          }
        }
        // 入站 accept 场景：conn_id 由 JS 侧 next_id 分配，MoonBit 侧此前未登记
        // （conns 仅在出站 tcp_connect 预登记）→ 此刻补建连接记录（outbound=false），
        // 否则后续 ev=1 数据帧 / ev=3 关闭事件均查无记录被静默丢弃（§5.6 入站长连接）
        None => {
          let now = now_ms()
          let conn : TcpConn = {
            conn_id,
            peer: host,
            port,
            outbound: false, // 入站连接：无自动重连语义（§5.6 仅出站长连接重连）
            parser: @frame.TcpFrameParser::new(self.cfg.local_ver, self.cfg.tcp_frame_timeout_ms),
            last_recv_ms: now,
            last_send_ms: now,
            alive: true,
          }
          self.conns[conn_id] = conn
          (self.on_event)(TcpAccepted(conn_id, conn.peer, conn.port))
        }
      }
    3 =>
      // 连接关闭（对端关闭 / connect 失败）→ 清理 + 上抛 + 自动重连判定
      self.on_conn_closed(conn_id)
    _ => ()
  }
}

/// 连接关闭收尾：清理记录 → 上抛 TcpClosed → §5.6 出站自动重连（1s，工程决策间隔）
fn Transport::on_conn_closed(self : Transport, conn_id : Int) -> Unit {
  let conn = match self.conns.get(conn_id) {
    Some(c) => c
    None => return // 幂等：tick 失效与 FFI 关闭事件可能重复进入
  }
  let host = conn.peer
  let port = conn.port
  let outbound = conn.outbound
  let _ = self.conns.remove(conn_id)
  let key = "\{host}:\{port}"
  match self.outbound.get(key) {
    Some(v) => if v == conn_id {
      let _ = self.outbound.remove(key)
    }
    None => ()
  }
  (self.on_event)(TcpClosed(conn_id, host, port))
  // §5.6 自动重连：仅出站连接；入站连接由对端决定是否重连
  if outbound {
    let reconn : (Int) -> Unit = fn(_x) {
      let _ = self.tcp_connect(host, port)
      ()
    }
    let _ = ffi_set_timeout(reconn, 1000)
    ()
  }
}

/// 周期 tick（500ms）：半帧超时检查（§4.1）+ 心跳维持（§5.7）
fn Transport::tick(self : Transport) -> Unit {
  let now = now_ms()
  let closes : Array[Int] = []
  for cid, conn in self.conns {
    // §4.1 半帧超时检查（解析器内部按状态处理两阶段）
    for e in conn.parser.check_timeout(now) {
      match e {
        TcpFrame(f) => (self.on_event)(TcpFrame(f, cid))
        TcpReject(code, hdr) => {
          let raw = make_rst_frame(code, hdr)
          if raw.length() > 0 {
            ffi_tcp_write(cid, raw)
            conn.last_send_ms = now
          }
        }
        TcpRst26 => {
          let raw = make_rst_frame(@errors.RST_FRAME_TIMEOUT, None)
          if raw.length() > 0 {
            ffi_tcp_write(cid, raw)
            conn.last_send_ms = now
          }
        }
        TcpClose => closes.push(cid)
      }
    }
    // §5.7 失效判定：超过 2×heartbeat_period 未收到任何帧 → 标记连接失效销毁
    if now - conn.last_recv_ms >= self.cfg.heartbeat_period_ms * 2L {
      closes.push(cid)
      continue
    }
    // §5.7 空闲判定：超过 heartbeat_period 未发出任何帧 → 发送一次 Ping
    if now - conn.last_send_ms >= self.cfg.heartbeat_period_ms {
      ffi_tcp_write(cid, ping_frame())
      conn.last_send_ms = now
    }
  }
  // 统一销毁失效连接（on_conn_closed 幂等，重复 cid 无害）
  for cid in closes {
    match self.conns.get(cid) {
      Some(_) => {
        ffi_tcp_destroy(cid)
        self.on_conn_closed(cid)
      }
      None => ()
    }
  }
}
