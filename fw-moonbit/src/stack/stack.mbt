// §13 协议栈入口：组装 transport / sd / rpc / events + 帧路由 + 应用 API
//
// 组装关系（§2 单实例部署）：
// - Transport：UDP 双 socket（server=组播收 / client=单播收发）+ TCP listen/connect + 心跳，
//   全部事件上抛 stack 分流
// - Sd：控制帧（CTR=1）四操作 + 客户端订阅会话 + GetIDL 双角色；SdEvent 上抛 stack 桥接
// - Rpc / events：数据帧（CTR=0）按 Code 分流（0x01/0x02 服务端 / 0x03 事件接收 / 0x10 响应；
//   ACK/RST 各层按去重键幂等匹配，双投递安全）
// - 数据 StrmID 池 rpc/events 共享同一实例（client/server 子池独立，§6.3）

/// 协议栈配置（附录 A 默认值聚合；idl_dir 为 IDL 库落盘目录，§11.1）
pub(all) struct StackConfig {
  udp_port : Int // §2 fw_udp_port（5400）
  tcp_port : Int // §2 TCP/UDP 共用预定义端口（默认 5400，规范 §2"TCP/UDP 共用端口 5400"）
  bind_address : String // 绑定地址（"" = 全接口；同机多实例演示按回环 IP 区分）
  tcp_enabled : Bool // 是否监听 TCP 服务端（纯客户端角色可关闭，出站连接不受影响）
  idl_dir : String // IDL 库目录（§11.1 纯动态架构：服务定义运行时加载）
  max_payload_len : Int // UDP 帧级上限（1400，§2）
  tcp_frame_timeout_ms : Int64 // TCP 半帧超时（5000，§4.1）
  heartbeat_period_ms : Int64 // TCP 心跳周期（30000，§5.7）
  period_ms : Int // Offer 广播 / 订阅保活周期（2000，§7.2）
  ttl_sec : Int // Offer/Subscribe Entry TTL（4 秒，§7.5）
  response_timeout_ms : Int64 // 响应超时（2000，§5.1；GetIDL 复用）
  retransmit_interval_ms : Int64 // UDP CON 重传间隔（200，§5.5）
  retransmit_max : Int // 重传次数不含首次（3，§5.5）
}

/// 默认配置（附录 A；idl_dir 必填——IDL 库位置属部署事实，无协议默认值）
pub fn StackConfig::default(idl_dir : String) -> StackConfig {
  {
    udp_port: 5400,
    tcp_port: 5400, // §2 TCP/UDP 共用端口 5400（原 5401 违反规范，跨栈互通审查修正）
    bind_address: "",
    tcp_enabled: true,
    idl_dir,
    max_payload_len: 1400,
    tcp_frame_timeout_ms: 5000L,
    heartbeat_period_ms: 30000L,
    period_ms: 2000,
    ttl_sec: 4,
    response_timeout_ms: 2000L,
    retransmit_interval_ms: 200L,
    retransmit_max: 3,
  }
}

/// 订阅句柄（§13.2 subscribe 返回值：unsubscribe 凭据）
/// key = events 交付键（"i|svc|if" / "g|svc|grp"）；strm_id = 会话 StrmID（§7.2 关联）
pub(all) struct SubHandle {
  svc_id : Int
  inst_id : Int
  if_id : Int
  grp_id : Int
  key : String
  strm_id : Int
}

/// 协议栈主体（§2 单实例：每进程一个 Stack）
pub struct Stack {
  cfg : StackConfig
  transport : @transport.Transport
  store : @idlstore.IdlStore
  ctrl_pool : @strm.CtrlStrmPool // 控制帧 StrmID 池（订阅会话 + GetIDL 查询同池，§6.1）
  data_pool : @strm.DataStrmPool // 数据帧 StrmID 池（rpc/events 共享实例，§6.3）
  sd : @sd.Sd
  rpc : @rpc.Rpc
  events : @events.Events
  priv conn_peer : Map[Int, (String, Int)] // conn_id → (peer, port)（TcpFrame 帧不带地址，建连时记录）
  priv owned : Map[String, Bool] // 已注册实例 "svc|inst"（§13.1 占用检查）
}

/// 创建协议栈（不启动；start 挂定时器 / socket / 预热 Find）
pub fn Stack::new(cfg : StackConfig) -> Stack {
  let tcfg : @transport.TransportConfig = {
    udp_port: cfg.udp_port,
    tcp_port: cfg.tcp_port,
    bind_address: cfg.bind_address,
    tcp_enabled: cfg.tcp_enabled,
    local_ver: 0, // 本端协议版本：v4.4 固化设计无演进空间（§1.3），恒 0
    max_payload_len: cfg.max_payload_len,
    tcp_frame_timeout_ms: cfg.tcp_frame_timeout_ms,
    heartbeat_period_ms: cfg.heartbeat_period_ms,
  }
  let sdcfg : @sd.SdConfig = {
    period_ms: cfg.period_ms,
    ttl_sec: cfg.ttl_sec,
    response_timeout_ms: cfg.response_timeout_ms,
    retransmit_interval_ms: cfg.retransmit_interval_ms,
    retransmit_max: cfg.retransmit_max,
  }
  let rpcfg : @rpc.RpcConfig = {
    response_timeout_ms: cfg.response_timeout_ms.to_int(),
    retrans_interval_ms: cfg.retransmit_interval_ms.to_int(),
    max_retry: cfg.retransmit_max,
  }
  // 循环依赖解法：transport/sd 的回调需触达尚未构造完成的 Stack / Events → 槽位延迟填充
  // （构造为纯操作不触发回调，start 前槽位已填满）
  let self_slot : Array[Stack] = []
  // 传输层事件桥接（UDP/TCP 帧与连接生命周期 → 分流）
  let t = @transport.Transport::new(tcfg, fn(ev) {
    match self_slot.get(0) {
      Some(s) => s.on_transport_event(ev)
      None => () // 构造期不可达
    }
  })
  let store = @idlstore.IdlStore::new(cfg.idl_dir)
  let ctrl_pool = @strm.CtrlStrmPool::new()
  let data_pool = @strm.DataStrmPool::new()
  // SD 事件桥接（§3.6 / §8.1）
  let sd = @sd.Sd::new(sdcfg, t, store, ctrl_pool, fn(e) {
    match e {
      // 对端重启：清该 peer 全部 Ctrl/Data StrmID 序列（§3.6 PeerRebooted 语义）
      @sd.PeerRebooted(peer) => {
        let _ = data_pool.clear_peer(peer)
        ctrl_pool.clear_peer(peer)
      }
      // 服务端新订阅建立 → events 全量推送（§8.1：从无到有时推缓存）
      @sd.SubEstablished(s) =>
        match self_slot.get(0) {
          Some(st) => st.events.on_sub_established(s)
          None => ()
        }
      // 服务端订阅删除：events 缓存按接口维护（与订阅者解耦），无需清理
      @sd.SubRemoved(_s) => ()
    }
  })
  let rpc = @rpc.Rpc::new(rpcfg, t, data_pool, store)
  let events = @events.Events::new(t, data_pool, store, sd)
  let stack : Stack = {
    cfg,
    transport: t,
    store,
    ctrl_pool,
    data_pool,
    sd,
    rpc,
    events,
    conn_peer: Map([], capacity=8),
    owned: Map([], capacity=8),
  }
  self_slot.push(stack)
  stack
}

/// 启动协议栈：IDL 库加载（§11.1）→ 传输层（双 socket + TCP listen + 心跳）→
/// SD（1s tick + 周期 Offer + 启动预热 Find，§2/§7.2）
pub fn Stack::start(self : Stack) -> Unit {
  let _ = self.store.load_all()
  self.transport.start()
  self.sd.start()
}

/// 停止协议栈（§7.6 场景 6）：SD 先发 REN×3 组播（0/100/200ms）后收尾；
/// REN 发送依赖 socket 存活 → 传输层延迟关闭（先发完所有 REN 再释放资源）
pub fn Stack::stop(self : Stack) -> Unit {
  self.sd.stop()
  let t = self.transport
  let _ = st_set_timeout(fn(_x) { t.stop() }, 250)
}

// ===== 传输层事件分流 =====

/// 传输层事件桥接：控制帧（CTR=1）→ sd；数据帧（CTR=0）→ rpc/events 按 Code 分流
fn Stack::on_transport_event(self : Stack, ev : @transport.TransportEvent) -> Unit {
  match ev {
    @transport.UdpFrame(f, host, port, from_server) =>
      if f.ctr {
        self.sd.on_udp_ctrl(f, host, port, from_server)
      } else {
        self.route_data(f, host, port, -1)
      }
    @transport.TcpFrame(f, conn_id) =>
      match self.conn_peer.get(conn_id) {
        Some((host, port)) =>
          if f.ctr {
            self.sd.on_tcp_ctrl(f, conn_id, host, port)
          } else {
            self.route_data(f, host, port, conn_id)
          }
        None => () // 未登记连接的帧（异常），静默
      }
    @transport.TcpConnected(conn_id, host, port) => {
      // 出站连接建立（rpc 调用通道 / GetIDL 查询通道 / tcp-event 推送通道共用，§5.6 幂等复用）
      self.conn_peer[conn_id] = (host, port)
      self.sd.on_tcp_connected(conn_id, host, port) // GetIDL WaitConn 查询发出（§7.2）
      self.rpc.on_tcp_connected(host, port) // 排空 TCP 发送等待队列（§5.6）
    }
    @transport.TcpAccepted(conn_id, host, port) =>
      // 入站连接（服务端 TCP 请求 / tcp-event 推送源）；transport.conn_id_by_peer 按源 IP 匹配（§8.2）
      self.conn_peer[conn_id] = (host, port)
    @transport.TcpClosed(conn_id, host, port) => {
      let _ = self.conn_peer.remove(conn_id)
      self.sd.on_tcp_closed(conn_id) // 该连接 pending GetIDL 查询全部失败（§7.2）
      self.rpc.on_tcp_closed(host, port) // TCP 等待队列排空报错（§5.6）
    }
  }
}

/// 数据帧（CTR=0）分流：按 Code 语义确定归属（§3.4 Code 空间）
/// ACK/RST 双投递 rpc 与 events——各层按去重键 (peer,svc,inst,strm) 匹配，未命中为 no-op（§5.5）
fn Stack::route_data(
  self : Stack,
  f : @frame.Frame,
  host : String,
  port : Int,
  conn_id : Int
) -> Unit {
  match f.typ {
    @frame.Rst => {
      self.rpc.on_rst(f, host) // 请求被拒（0x24）/ Payload 违约（0x20）等
      self.events.on_rst(f, host) // Notify CON 被拒 → 客户端重传链清理
    }
    @frame.Ack => {
      // 数据帧 ACK 仅 UDP（§5.1 TCP 不使用 CON/ACK）：events 先试（Notify 确认），rpc 后试
      self.events.on_udp_ack(f, host)
      self.rpc.on_udp_ack(f, host)
    }
    _ =>
      match f.code {
        0x01 | 0x02 => // Request / FF → 服务端处理（§5.1/§5.2；TCP 场景 conn_id 供响应回程）
          if conn_id == -1 {
            self.rpc.on_udp_data(f, host, port)
          } else {
            self.rpc.on_tcp_data(f, conn_id, host)
          }
        0x03 => // Notification → 客户端接收交付（§8.2 去重 + 回调）
          if conn_id == -1 {
            self.events.on_udp_data(f, host, port)
          } else {
            self.events.on_tcp_data(f, host)
          }
        0x10 => // Response → 客户端交付（§5.1 回显 StrmID 匹配 pending）
          if conn_id == -1 {
            self.rpc.on_udp_data_resp(f, host, port)
          } else {
            self.rpc.on_tcp_data_resp(f, host)
          }
        _ => () // 0x11~0x1F 保留码空间，静默（§3.4）
      }
  }
}
