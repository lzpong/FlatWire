// RPC 服务端处理（§5.1 Request / §5.2 Fire-Forget / §5.5 去重与响应缓存 / §5.4 RST）

/// 本端 handler 登记（major_ver 定位本端 IDL 定义，接口契约校验用；归属键由 handlers 的 key 承载）
priv struct HandlerEntry {
  major_ver : Int
  handler : ServiceHandler
}

/// UDP 数据帧入口（stack 层桥接：CTR=0 且 Code∈{0x01,0x02} 的帧；其余交给 events/忽略）
pub fn Rpc::on_udp_data(self : Rpc, f : @frame.Frame, host : String, port : Int) -> Unit {
  match f.code {
    0x01 => self.serve_request(f, host, port, -1)
    0x02 => self.serve_fire_forget(f, host, port, -1)
    _ => ()
  }
}

/// TCP 数据帧入口（同上；conn_id≥0 标识 TCP 路径——Response 走 NON 无缓存重传）
pub fn Rpc::on_tcp_data(self : Rpc, f : @frame.Frame, conn_id : Int, host : String) -> Unit {
  match f.code {
    0x01 => self.serve_request(f, host, 0, conn_id)
    0x02 => self.serve_fire_forget(f, host, 0, conn_id)
    _ => ()
  }
}

/// 传输形态判定（conn_id≥0 → TCP）
fn is_tcp_conn(conn_id : Int) -> Bool {
  conn_id >= 0
}

/// 服务端发送（TCP → 连接定向；UDP → server socket 单播到请求源地址）
fn Rpc::serve_send(
  self : Rpc,
  spec : @frame.FrameSpec,
  payload : Bytes,
  host : String,
  port : Int,
  conn_id : Int
) -> Bool {
  if is_tcp_conn(conn_id) {
    self.transport.send_tcp_frame(conn_id, spec, payload)
  } else {
    self.transport.send_udp_frame(true, spec, payload, host, port)
  }
}

/// RST 回显触发帧 StrmID（§5.4；数据帧请求 svc/ifid/inst 按帧回显）
fn Rpc::serve_rst(
  self : Rpc,
  code : Int,
  f : @frame.Frame,
  host : String,
  port : Int,
  conn_id : Int
) -> Unit {
  let _ = self.serve_send(
    @frame.data_spec(@frame.Rst, code, f.svc_id, f.if_id, f.inst_id, f.strm_id),
    b"",
    host,
    port,
    conn_id,
  )
}

/// 处理 Request（§5.1：UDP=CON / TCP=NON；Response 回显 StrmID，形态随请求传输）
fn Rpc::serve_request(
  self : Rpc,
  f : @frame.Frame,
  host : String,
  port : Int,
  conn_id : Int
) -> Unit {
  let tcp = is_tcp_conn(conn_id)
  let key = rpc_key(host, f.svc_id, f.inst_id, f.strm_id)
  // §5.5 幂等：UDP CON 重传到达 → 直接重发缓存响应，不重新执行处理逻辑
  // （TCP NON 无重传语义，resp_cache 不启用）
  if !tcp {
    match self.resp_cache.get(key) {
      Some(c) => {
        let _ = self.serve_send(c.spec, c.payload, host, c.port, -1)
        return
      }
      None => ()
    }
  }
  // 服务实例存在性（§5.4：未知服务 → RST 0x24）
  let he = match self.handler_of(f.svc_id, f.inst_id) {
    Some(v) => v
    None => {
      rp_log_error("[rpc] Request 服务不存在: svc=\{f.svc_id} inst=\{f.inst_id} peer=\{host}")
      self.serve_rst(@errors.RST_NOT_FOUND, f, host, port, conn_id)
      return
    }
  }
  // 接口契约校验（§12：未知接口 → 0x24；超接口 max_payload → 0x20，两层两码之 IDL 级）
  let iface = match self.iface_of(f.svc_id, he.major_ver, f.if_id) {
    Some(v) => v
    None => {
      rp_log_error("[rpc] Request 接口不存在: svc=\{f.svc_id} if=\{f.if_id} peer=\{host}")
      self.serve_rst(@errors.RST_NOT_FOUND, f, host, port, conn_id)
      return
    }
  }
  if iface.max_payload > 0 && f.payload.length() > iface.max_payload {
    rp_log_error("[rpc] Request 超接口 max_payload: svc=\{f.svc_id} if=\{f.if_id} len=\{f.payload.length()}")
    self.serve_rst(@errors.RST_BAD_REQUEST, f, host, port, conn_id)
    return
  }
  // 执行处理逻辑（§13.3 on_request）
  match (he.handler.on_request)(f.if_id, f.payload) {
    Ok(resp) => {
      let spec = @frame.data_spec(
        if tcp {
          @frame.Non // §5.1：TCP Response = NON
        } else {
          @frame.Con // §5.1：UDP Response = CON（客户端回空确认）
        },
        0x10, // Response 唯一成功码（§3.4）
        f.svc_id,
        f.if_id,
        f.inst_id,
        f.strm_id, // 回显请求 StrmID（§5.1）
      )
      if tcp {
        let _ = self.transport.send_tcp_frame(conn_id, spec, resp)
      } else {
        // UDP：缓存响应进重传链（§5.5 CON 均走重传；随 ACK/RST/耗尽清除）
        let c : CachedResp = {
          peer: host,
          port,
          spec,
          payload: resp,
          retries: 0,
          timer: -1,
        }
        self.resp_cache[key] = c
        self.resp_chain(c)
      }
    }
    Err(code) => {
      // 服务端处理异常 → 按约定 Code 回 RST（§5.1：错误一律 RST 表达，不用数据帧承载）
      self.serve_rst(code, f, host, port, conn_id)
    }
  }
}

/// 处理 Fire-Forget（§5.2：UDP=CON 对端回确认 / TCP=NON；CON 重传到达不重复执行，§5.5）
fn Rpc::serve_fire_forget(
  self : Rpc,
  f : @frame.Frame,
  host : String,
  port : Int,
  conn_id : Int
) -> Unit {
  let tcp = is_tcp_conn(conn_id)
  let key = rpc_key(host, f.svc_id, f.inst_id, f.strm_id)
  if !tcp && f.typ is @frame.Con {
    // §5.5 幂等：重复 CON（重传）→ 重发确认，不重新执行
    if self.ff_seen.contains(key) {
      self.send_ff_ack(f, host, port)
      return
    }
    // 首次到达：登记 + 确认 + 执行；兜底清理 timer = 重传窗口 3s + 余量（§8.2 接收记录同策略）
    self.ff_seen[key] = rp_set_timeout(fn(_) { let _ = self.ff_seen.remove(key) }, 3200)
    self.send_ff_ack(f, host, port)
  }
  // 服务实例存在性（§5.4）
  let he = match self.handler_of(f.svc_id, f.inst_id) {
    Some(v) => v
    None => {
      rp_log_error("[rpc] FF 服务不存在: svc=\{f.svc_id} inst=\{f.inst_id} peer=\{host}")
      self.serve_rst(@errors.RST_NOT_FOUND, f, host, port, conn_id)
      return
    }
  }
  // 接口契约校验（同 Request）
  let iface = match self.iface_of(f.svc_id, he.major_ver, f.if_id) {
    Some(v) => v
    None => {
      rp_log_error("[rpc] FF 接口不存在: svc=\{f.svc_id} if=\{f.if_id} peer=\{host}")
      self.serve_rst(@errors.RST_NOT_FOUND, f, host, port, conn_id)
      return
    }
  }
  if iface.max_payload > 0 && f.payload.length() > iface.max_payload {
    self.serve_rst(@errors.RST_BAD_REQUEST, f, host, port, conn_id)
    return
  }
  (he.handler.on_ff)(f.if_id, f.payload)
}

/// FF 空确认（§3.4：TYP=ACK Code=0x00，回显 StrmID；UDP client→server 单播由 server socket 应答）
fn Rpc::send_ff_ack(self : Rpc, f : @frame.Frame, host : String, port : Int) -> Unit {
  let _ = self.transport.send_udp_frame(
    true,
    @frame.data_spec(@frame.Ack, 0x00, f.svc_id, f.if_id, f.inst_id, f.strm_id),
    b"",
    host,
    port,
  )
}

/// 响应缓存重传链（与客户端 CON 链同构：0/200/600/1400ms，3000ms 静默停止，§5.5）
fn Rpc::resp_chain(self : Rpc, c : CachedResp) -> Unit {
  c.timer = rp_set_timeout(fn(_) { self.resp_fire(c) }, self.cfg.retrans_interval_ms * (1 << c.retries))
}

fn Rpc::resp_fire(self : Rpc, c : CachedResp) -> Unit {
  if c.retries < self.cfg.max_retry {
    c.retries = c.retries + 1
    let _ = self.transport.send_udp_frame(true, c.spec, c.payload, c.peer, c.port)
    c.timer = rp_set_timeout(
      fn(_) { self.resp_fire(c) },
      self.cfg.retrans_interval_ms * (1 << c.retries),
    )
  } else {
    // 静默停止：清除缓存（客户端响应超时自会判定失败，§5.5 重传耗尽语义）
    c.timer = -1
    let key = rpc_key(c.peer, c.spec.svc_id, c.spec.inst_id, c.spec.strm_id)
    let _ = self.resp_cache.remove(key)
  }
}
