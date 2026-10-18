// RPC 层主体（§5.1 Request-Response / §5.2 Fire-Forget / §5.5 CON 重传与去重）
//
// 职责：
// - 客户端：call（UDP CON / TCP NON + 响应超时 + 重传链）/ fire_forget（UDP CON / TCP NON）
// - 服务端：Request/FF 处理 + 响应缓存重发（§5.5 幂等）+ RST 触发（§5.4）
// - 数据帧 StrmID 由 DataStrmPool 管理（客户端流 0x01~0x7F，§6.1），与 events 的服务端流共享实例
//
// 传输选择：按 IDL 接口 transport 绑定（tcp=true → TCP 长连接；否则 UDP 单播，§11.1）

/// 服务端处理契约（§13.3：on_request 返回响应 payload 或 RST Code；on_ff 无返回值）
pub(all) struct ServiceHandler {
  on_request : (Int, Bytes) -> Result[Bytes, Int] // if_id, payload → 响应 / Err(RST Code)
  on_ff : (Int, Bytes) -> Unit // if_id, payload → 处理（无返回值）
}

/// 客户端待响应请求（§5.1：响应超时统一判定成败；重传耗尽静默不报错）
priv struct PendReq {
  svc_id : Int
  inst_id : Int
  strm_id : Int
  mut resp_timer : Int // 应用层响应超时定时器（-1 无）
  on_ok : (Bytes) -> Unit // 响应到达回调
  on_err : (@errors.FwError) -> Unit // 超时 / RST 回调
}

/// UDP CON 出站重传记录（§5.5：同键唯一 + 重传同 StrmID 同字节；Request/FF 共用）
priv struct OutCon {
  peer : String
  port : Int
  svc_id : Int
  inst_id : Int
  strm_id : Int
  spec : @frame.FrameSpec // 重传使用同一 spec（恒定宽度编码确定性 → 同字节，§5.5）；IfID 由 spec 携带
  payload : Bytes
  mut retries : Int // 已重传次数（不含首次，§5.5 max_retry=3）
  mut timer : Int // 重传链当前节点定时器（-1 无）
  on_err : (@errors.FwError) -> Unit // FF 失败回调（RST 场景；call 场景传 no-op——成败由响应超时判定）
}

/// 服务端响应缓存（§5.5：按 (peer,svc,inst,strm) 保存，随 ACK/RST/重传耗尽清除；
/// 客户端重传请求到达时直接重发缓存响应，不重新执行处理逻辑）
priv struct CachedResp {
  peer : String
  port : Int
  spec : @frame.FrameSpec // Response 帧形态（CON，回显请求 StrmID，Code=0x10）
  payload : Bytes
  mut retries : Int
  mut timer : Int
}

/// RPC 层主体
pub struct Rpc {
  cfg : RpcConfig
  transport : @transport.Transport
  data_pool : @strm.DataStrmPool // 与 events 共享实例（client/server 子池独立，§6.3）
  store : @idlstore.IdlStore
  priv handlers : Map[String, HandlerEntry] // 服务端 handler，key "svc|inst"
  priv pending : Map[String, PendReq] // 客户端待响应，key "peer|svc|inst|strm"
  priv cons : Map[String, OutCon] // 客户端 UDP CON 重传链（Request/FF），同 pending 键
  priv resp_cache : Map[String, CachedResp] // 服务端响应缓存，key "peer|svc|inst|strm"
  priv ff_seen : Map[String, Int] // 服务端 FF 已处理记录（值 = 兜底清理 timer），key 同上
  priv conn_wait : Map[String, Array[() -> Unit]] // TCP 未就绪等待队列，key "host|port"
}

/// RPC 配置（§1.3/附录 A：时间参数毫秒；pub(all) 与 SdConfig/TransportConfig 一致，供 stack 层构造）
pub(all) struct RpcConfig {
  response_timeout_ms : Int // 应用层响应超时（默认 2000，§5.1；GetIDL 复用此值，第三轮定案）
  retrans_interval_ms : Int // CON 重传基准间隔（200，§5.5）
  max_retry : Int // 重传次数不含首次（3，§5.5）
}

/// 默认配置（附录 A）
pub fn RpcConfig::default() -> RpcConfig {
  { response_timeout_ms: 2000, retrans_interval_ms: 200, max_retry: 3 }
}

/// 服务端 handler 登记（stack 层 register_service 时调用；major_ver 用于定位本端 IDL 定义）
pub fn Rpc::register_handler(
  self : Rpc,
  svc_id : Int,
  inst_id : Int,
  major_ver : Int,
  h : ServiceHandler
) -> Unit {
  self.handlers["\{svc_id}|\{inst_id}"] = { major_ver, handler: h }
}

/// 注销服务端 handler（unregister_service）
pub fn Rpc::unregister_handler(self : Rpc, svc_id : Int, inst_id : Int) -> Unit {
  let _ = self.handlers.remove("\{svc_id}|\{inst_id}")
}

/// 创建 RPC 层（不启动任何定时器；纯构造）
pub fn Rpc::new(
  cfg : RpcConfig,
  transport : @transport.Transport,
  data_pool : @strm.DataStrmPool,
  store : @idlstore.IdlStore
) -> Rpc {
  {
    cfg,
    transport,
    data_pool,
    store,
    handlers: Map([], capacity=8),
    pending: Map([], capacity=8),
    cons: Map([], capacity=8),
    resp_cache: Map([], capacity=8),
    ff_seen: Map([], capacity=8),
    conn_wait: Map([], capacity=4),
  }
}

// ===== 键构造（内部统一，防拼装漂移；§5.5 去重键 (peer,svc,inst,strm)） =====

fn rpc_key(peer : String, svc_id : Int, inst_id : Int, strm_id : Int) -> String {
  "\{peer}|\{svc_id}|\{inst_id}|\{strm_id}"
}

fn handler_key(svc_id : Int, inst_id : Int) -> String {
  "\{svc_id}|\{inst_id}"
}

/// 服务端 handler 查找（含本端版本）
fn Rpc::handler_of(self : Rpc, svc_id : Int, inst_id : Int) -> HandlerEntry? {
  self.handlers.get(handler_key(svc_id, inst_id))
}

// ===== CON 重传链（§5.5 时间线 0/200/600/1400ms，3000ms 静默停止） =====

/// CON 首次发送后挂重传链（下一节点 = interval × 2^retries）
fn Rpc::con_chain(self : Rpc, o : OutCon) -> Unit {
  o.timer = rp_set_timeout(fn(_) { self.con_fire(o) }, self.cfg.retrans_interval_ms * (1 << o.retries))
}

/// 重传链节点触发：未耗尽 → 重发（同 spec 同字节）并推进；耗尽 → 静默停止清理（§5.5）
fn Rpc::con_fire(self : Rpc, o : OutCon) -> Unit {
  if o.retries < self.cfg.max_retry {
    o.retries = o.retries + 1
    let _ = self.transport.send_udp_frame(false, o.spec, o.payload, o.peer, o.port)
    o.timer = rp_set_timeout(
      fn(_) { self.con_fire(o) },
      self.cfg.retrans_interval_ms * (1 << o.retries),
    )
  } else {
    // 末次重传（1400ms）已发，等待 1600ms 后静默停止：释放 StrmID 并移除记录（§5.5 停止重传 3000ms）
    o.timer = -1
    let key = rpc_key(o.peer, o.svc_id, o.inst_id, o.strm_id)
    let _ = self.cons.remove(key)
    self.data_pool.release(o.peer, o.svc_id, o.inst_id, o.strm_id)
  }
}

/// 取消 CON 重传链（收到 ACK/响应/RST 或响应超时联动取消，§5.1/§5.5；仅操作记录本身，无需 Rpc 上下文）
fn con_cancel(o : OutCon) -> Unit {
  if o.timer != -1 {
    rp_clear_timeout(o.timer)
    o.timer = -1
  }
}

// ===== 接口契约查询辅助 =====

/// 查接口定义（含 transport 绑定 / max_payload / reliable）
/// 优先按本端注册版本；客户端方向由调用方传 major_ver（=0 时取库中任一版本）
fn Rpc::iface_of(
  self : Rpc,
  svc_id : Int,
  major_ver : Int,
  if_id : Int
) -> @idlstore.IdlInterface? {
  let def = if major_ver > 0 {
    self.store.get(svc_id, major_ver)
  } else {
    self.store.get_any(svc_id)
  }
  match def {
    Some(d) => d.find_interface(if_id)
    None => None
  }
}

// ===== TCP 连接就绪等待（§5.6：出站连接异步建立；就绪前排队的帧在建立后补发） =====

/// TCP 连接建立事件（stack 层桥接 TcpConnected）：就绪后排空等待队列
pub fn Rpc::on_tcp_connected(self : Rpc, host : String, port : Int) -> Unit {
  let key = "\{host}|\{port}"
  match self.conn_wait.get(key) {
    Some(q) => {
      let _ = self.conn_wait.remove(key)
      for job in q {
        job()
      }
    }
    None => ()
  }
}

/// TCP 连接断开事件（stack 层桥接 TcpClosed）：丢弃等待队列（调用方经响应超时感知失败）
pub fn Rpc::on_tcp_closed(self : Rpc, host : String, port : Int) -> Unit {
  let _ = self.conn_wait.remove("\{host}|\{port}")
}
