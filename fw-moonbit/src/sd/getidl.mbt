// GetIDL 双角色（§7.2：纯动态架构核心机制——协议栈内部行为，应用层无感知）
//
// - 客户端角色（调用/订阅/接收事件前 ensure_idl）：本地库缺失 + 发现缓存有在线实例
//   → TCP 单播 GetIDL → 响应校验自含 svc_id/major 一致 → 落盘持久化 → 继续原操作；
//   无在线实例不发起查询直接失败（NotAvailable）
// - 服务端角色（register_service 本地无定义）：MajorVer 取发现缓存在线版本，拉取后注册继续
// - 并发合并：同 (SvcID, MajorVer) 首次查询合并（实现建议，§7.2）
// - 超时复用 response_timeout_ms；失败上抛当前操作由应用决定重试（§7.2，不自动重发）

/// GetIDL 查询（pending 状态机：WaitConn → WaitResp → 完成/失败）
priv struct IdlQuery {
  key : String // "svc|major"（并发合并键）
  svc_id : Int
  major_ver : Int
  peer : String // 实例源 IP（GetIDL 走 TCP 到该节点的 tcp_port）
  mut conn_id : Int // -1 = 连接未建立
  mut strm_id : Int // 0 = 未分配（0x01~0x7F，与订阅会话共用 CtrlStrmPool）
  mut finished : Bool
  waiters : Array[((() -> Unit), ((@errors.FwError) -> Unit))] // 合并的等待者（on_ok, on_err）
  mut timeout_timer : Int
}

/// 确保 IDL 定义就绪（§7.2 双角色统一触发入口）：
/// 本地命中 → 同步回调；缺失 → 拉取链（发现缓存定位 → TCP 连接 → 0x04 → 0x11 → 落盘 → 回调）
pub fn Sd::ensure_idl(
  self : Sd,
  svc_id : Int,
  major_ver : Int,
  on_ok : () -> Unit,
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  // 本地命中：不重复查询（一致性判定项）
  if self.store.has(svc_id, major_ver) {
    on_ok()
    return
  }
  // 发现缓存定位在线实例；无实例不发起查询直接失败（§7.2 触发条件 2）
  match self.find_instance(svc_id, major_ver) {
    None => on_err(@errors.NotAvailable)
    Some(d) => {
      let key = "\{svc_id}|\{major_ver}"
      match self.idl_dedup.get(key) {
        Some(q) =>
          // 并发合并（实现建议 §7.2）：挂等待者，首个查询完成后统一回调
          q.waiters.push((on_ok, on_err))
        None => {
          let q : IdlQuery = {
            key,
            svc_id,
            major_ver,
            peer: d.peer,
            conn_id: -1,
            strm_id: 0,
            finished: false,
            waiters: [(on_ok, on_err)],
            timeout_timer: -1,
          }
          self.idl_dedup[key] = q
          // §5.6 复用 tcp_connect 幂等键（与 rpc/tcp-event 共用同一条长连接）
          let cid = self.transport.tcp_connect(d.peer, self.transport.cfg.tcp_port)
          q.conn_id = cid
          if self.transport.is_alive(cid) {
            // 连接已存活（复用）：直接发送
            self.send_getidl_query(q)
          }
          // 否则等 on_tcp_connected（stack 层转发）
        }
      }
    }
  }
}

/// 发送 GetIDL 请求（WaitConn → WaitResp：分配 StrmID → 发帧 → 挂响应索引 → 启超时）
fn Sd::send_getidl_query(self : Sd, q : IdlQuery) -> Unit {
  if q.finished {
    return
  }
  let strm = match self.ctrl_pool.alloc(q.peer) {
    Some(s) => s
    None => {
      self.fail_query(q, @errors.Local("StrmID exhausted for peer \{q.peer}"))
      return
    }
  }
  q.strm_id = strm
  // 请求帧形态（§7.2）：CTR=1, TYP=NON, Code=0x04, StrmID=查询 ID, Payload=3B Entry
  let payload = encode_getidl_entry({ svc_id: q.svc_id, major_ver: q.major_ver })
  let ok = self.transport.send_tcp_frame(
    q.conn_id,
    @frame.ctrl_spec(@frame.Non, 0x04, strm),
    payload,
  )
  if !ok {
    self.fail_query(q, @errors.Local("tcp send failed"))
    return
  }
  // 响应按 (conn, strm) 回显归属匹配（§7.2 并发查询关联）
  self.idl_queries["\{q.conn_id}|\{strm}"] = q
  // 查询超时复用 response_timeout_ms（§7.2）；超时直接失败上抛，重试由应用决定
  q.timeout_timer = sd_set_timeout(
    fn(_x) { self.fail_query(q, @errors.RequestTimeout) },
    self.cfg.response_timeout_ms.to_int(),
  )
}

/// 查询失败收尾：清理全部索引与定时器 → 所有等待者失败回调（IDL 库状态不变，§7.2）
fn Sd::fail_query(self : Sd, q : IdlQuery, err : @errors.FwError) -> Unit {
  if q.finished {
    return
  }
  q.finished = true
  if q.timeout_timer != -1 {
    sd_clear_timeout(q.timeout_timer)
    q.timeout_timer = -1
  }
  if q.strm_id != 0 {
    let _ = self.ctrl_pool.release(q.peer, q.strm_id)
  }
  let _ = self.idl_queries.remove("\{q.conn_id}|\{q.strm_id}")
  let _ = self.idl_dedup.remove(q.key)
  for w in q.waiters {
    (w.1)(err)
  }
}

/// 处理 GetIDL 响应 0x11（§7.2：回显 StrmID 匹配 → 校验一致 → 落盘 → 回调等待者）
fn Sd::handle_getidl_resp(self : Sd, f : @frame.Frame, conn_id : Int) -> Unit {
  let key = "\{conn_id}|\{f.strm_id}"
  match self.idl_queries.get(key) {
    // 非活跃查询 StrmID 的 0x11 静默丢弃（迟到帧规则）
    None => ()
    Some(q) => {
      if q.finished {
        return
      }
      // 落盘前校验：响应自含 svc_id/major_ver 与请求一致，不一致按查询失败（§7.2）
      match validate_idl_payload(f.payload, q.svc_id, q.major_ver) {
        Err(msg) => self.fail_query(q, @errors.Local("IDL 响应校验失败: \{msg}"))
        Ok(def) => {
          q.finished = true
          if q.timeout_timer != -1 {
            sd_clear_timeout(q.timeout_timer)
            q.timeout_timer = -1
          }
          let _ = self.ctrl_pool.release(q.peer, q.strm_id)
          let _ = self.idl_queries.remove(key)
          let _ = self.idl_dedup.remove(q.key)
          // 落盘持久化（协议要求 §7.2；落盘失败降级内存 + Error 日志——store.put 内部处理）
          let _ = self.store.put(def)
          for w in q.waiters {
            (w.0)()
          }
        }
      }
    }
  }
}

/// 处理 TCP RST（客户端视角：GetIDL 被拒 0x24/0x20 → 查询失败，§7.2 错误场景）
fn Sd::handle_tcp_rst(self : Sd, f : @frame.Frame, conn_id : Int) -> Unit {
  let key = "\{conn_id}|\{f.strm_id}"
  match self.idl_queries.get(key) {
    Some(q) => self.fail_query(q, @errors.Remote(f.code))
    None => () // 非活跃查询的 RST：静默
  }
}

/// 处理 GetIDL 请求（服务端视角，§7.2）：
/// Payload≠3B 或 SvcID=0 → RST(0x20)；库中无该 (SvcID, MajorVer) 已加载定义 → RST(0x24)；
/// 命中 → 0x11 回显 StrmID + IDL JSON 全文（与实例在线无关，§7.2/第三轮定案）
fn Sd::handle_getidl_req(
  self : Sd,
  f : @frame.Frame,
  conn_id : Int,
  _peer : String,
  _port : Int
) -> Unit {
  let entry = parse_getidl_entry(f.payload)
  let reply : Result[@idlstore.IdlDef, Int] = match entry {
    None => Err(@errors.RST_BAD_REQUEST) // Payload≠3B
    Some(e) =>
      if e.svc_id == 0 {
        Err(@errors.RST_BAD_REQUEST) // SvcID=0
      } else {
        match self.store.get(e.svc_id, e.major_ver) {
          Some(def) => Ok(def)
          None => Err(@errors.RST_NOT_FOUND) // 库中无定义 / MajorVer 不匹配
        }
      }
  }
  match reply {
    Ok(def) => {
      // 响应帧形态（§7.2）：CTR=1, TYP=NON, Code=0x11, 回显 StrmID, Payload=JSON 全文
      let _ = self.transport.send_tcp_frame(
        conn_id,
        @frame.ctrl_spec(@frame.Non, 0x11, f.strm_id),
        sd_utf8_to_bytes(def.raw),
      )
    }
    Err(code) => {
      // RST 回显请求 StrmID（§7.2 错误场景；请求帧 svc/ifid/inst 恒 0 → 全 0 回显）
      let _ = self.transport.send_tcp_frame(
        conn_id,
        @frame.data_spec(@frame.Rst, code, 0, 0, 0, f.strm_id),
        b"",
      )
    }
  }
}

/// 响应 Payload 校验 + 解析（§7.2：自含 svc_id/major_ver 与请求一致才落盘）
fn validate_idl_payload(
  payload : Bytes,
  svc_id : Int,
  major_ver : Int
) -> Result[@idlstore.IdlDef, String] {
  let text = sd_bytes_to_utf8(payload)
  let r : Result[@idlstore.IdlDef, @idlstore.IdlError] = try {
    Ok(@idlstore.parse_idl(text))
  } catch {
    e => Err(e)
  }
  match r {
    Err(e) => Err("\{Repr(e)}")
    Ok(def) =>
      if def.svc_id == svc_id && def.major_ver == major_ver {
        Ok(def)
      } else {
        Err("版本不一致: resp=\{def.svc_id}v\{def.major_ver} req=\{svc_id}v\{major_ver}")
      }
  }
}
