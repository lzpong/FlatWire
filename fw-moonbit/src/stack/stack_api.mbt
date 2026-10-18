// §13 应用层 API（服务端 13.1 / 客户端 13.2）
//
// payload 语义（§13，纯动态架构）：应用传入/接收的 payload 为按 IDL 定义的
// 结构化字段值集合（Array[FWValue]，顺序对应接口 input 参数 / output 单类型），
// 编解码由 stack 层按本地 IDL 库动态执行（stack_codec.mbt）
//
// 偏差说明（MoonBit 版）：JS 后端单线程回调模型，§13.2 的同步 call 以回调式
// call(on_ok, on_err) 提供——语义一致（响应超时统一判定成败，§5.1），阻塞栅栏
// 由应用经回调自行编排（详见 README）

// ===== §13.1 服务端 =====

/// register_service（§13.1）：IDL 就绪（本地命中或按发现缓存自动 GetIDL）→
/// handler 登记 → offer_start 进入 Offering（周期 Offer 广播由 sd 周期定时器承载）
/// 失败：本地 (svc_id, inst_id) 已被占用 / IDL 库无定义且集群无在线实例（可重试，§13.1）
pub fn Stack::register_service(
  self : Stack,
  svc_id : Int,
  inst_id : Int,
  handler : StackHandler,
  on_ok : () -> Unit,
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  // §13.1 前置：本地 (svc_id, inst_id) 占用检查
  let key = "\{svc_id}|\{inst_id}"
  if self.owned.contains(key) {
    on_err(@errors.Local("instance already registered: \{key}"))
    return
  }
  // 本地库已有定义：直接注册（§7.2 本地命中不重复查询）
  match self.store.get_any(svc_id) {
    Some(def) => {
      self.finish_register(def.major_ver, def.minor_ver, svc_id, inst_id, handler)
      on_ok()
    }
    None =>
      // 无定义：按发现缓存在线版本自动 GetIDL（§7.2 注册角色，MajorVer = 集群在线版本）
      match self.sd.any_online_version(svc_id) {
        Some(major) =>
          self.sd.ensure_idl(svc_id, major, fn() {
            // 拉取完成（已落盘）→ 继续注册；极端竞态（定义缺失）按失败上报，库状态不变
            match self.store.get_any(svc_id) {
              Some(def) => {
                self.finish_register(def.major_ver, def.minor_ver, svc_id, inst_id, handler)
                on_ok()
              }
              None => on_err(@errors.IdlMissing("svc \{svc_id} missing after fetch"))
            }
          }, on_err)
        None => on_err(@errors.NotAvailable) // 无在线实例（启动 Find 预热后重试可成功，§13.1）
      }
  }
}

/// 注册收尾：handler 编解码适配（FWValue ↔ Bytes）+ rpc 登记 + 实例广播登记
fn Stack::finish_register(
  self : Stack,
  major_ver : Int,
  minor_ver : Int,
  svc_id : Int,
  inst_id : Int,
  handler : StackHandler
) -> Unit {
  let adapted = self.adapt_handler(svc_id, major_ver, handler)
  self.rpc.register_handler(svc_id, inst_id, major_ver, adapted)
  self.sd.offer_start(svc_id, inst_id, major_ver, minor_ver)
  self.owned["\{svc_id}|\{inst_id}"] = true
}

/// unregister_service（§13.1）：停止 Offer 广播（含 TTL=0 Offer 单发，§7.6 场景 5）+ handler 移除
pub fn Stack::unregister_service(self : Stack, svc_id : Int, inst_id : Int) -> Unit {
  let _ = self.owned.remove("\{svc_id}|\{inst_id}")
  self.sd.offer_stop(svc_id, inst_id)
  self.rpc.unregister_handler(svc_id, inst_id)
}

/// notify（§13.1）：值按接口 output 编码 → 更新接口缓存并推送给所有订阅者
/// （§8.1 缓存同时是全量推送数据源；无定义/编码失败 → Error 日志，应用侧契约违约）
pub fn Stack::notify(
  self : Stack,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  values : Array[@codec.FWValue]
) -> Unit {
  match self.iface_of_any(svc_id, if_id) {
    None => st_log_error("[stack] notify: interface missing svc=\{svc_id} if=\{if_id}")
    Some(iface) =>
      try {
        let body = @codec.encode_fields(wrap_output(iface.output), values)
        self.events.notify(svc_id, inst_id, if_id, body)
      } catch {
        e => st_log_error("[stack] notify codec error: svc=\{svc_id} if=\{if_id} \{Repr(e)}")
      }
  }
}

// ===== §13.2 客户端 =====

/// call（§13.2；回调式偏差见文件头）：定位实例 → ensure_idl → input 编码 → rpc.call
/// （UDP CON 重传链 / TCP NON，传输按 IDL 接口绑定选择，§11.1；timeout ≤0 取默认 §5.1）
/// 响应按 output 解码后交付 on_ok（解码失败 → on_err Local，§13 payload 语义）
pub fn Stack::call(
  self : Stack,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  values : Array[@codec.FWValue],
  timeout_ms : Int,
  on_ok : (Array[@codec.FWValue]) -> Unit,
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  match self.sd.locate_instance(svc_id, inst_id) {
    None => on_err(@errors.NotAvailable) // 发现缓存无实例：直接失败（§7.2 触发条件 2 同源）
    Some(pi) =>
      self.sd.ensure_idl(svc_id, pi.major_ver, fn() {
        match self.iface_of(svc_id, pi.major_ver, if_id) {
          None => on_err(@errors.IdlMissing("interface \{svc_id}.\{if_id} not in IDL store"))
          Some(iface) =>
            try {
              let body = @codec.encode_fields(wrap_input(iface.input), values)
              self.rpc.call(
                pi.peer,
                pi.port,
                svc_id,
                inst_id,
                if_id,
                pi.major_ver,
                body,
                timeout_ms,
                fn(bytes) {
                  // 响应按 output 解码（iface CType 树不可变，安全捕获）
                  match decode_output(iface.output, bytes) {
                    Ok(vs) => on_ok(vs)
                    Err(msg) => on_err(@errors.Local(msg))
                  }
                },
                on_err,
              )
            } catch {
              e => on_err(@errors.Local("call encode input: \{Repr(e)}"))
            }
        }
      }, on_err)
  }
}

/// fire_forget（§13.2/§5.2）：无响应调用；流程同 call（input 编码，无响应解码环节）
pub fn Stack::fire_forget(
  self : Stack,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  values : Array[@codec.FWValue],
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  match self.sd.locate_instance(svc_id, inst_id) {
    None => on_err(@errors.NotAvailable)
    Some(pi) =>
      self.sd.ensure_idl(svc_id, pi.major_ver, fn() {
        match self.iface_of(svc_id, pi.major_ver, if_id) {
          None => on_err(@errors.IdlMissing("interface \{svc_id}.\{if_id} not in IDL store"))
          Some(iface) =>
            try {
              let body = @codec.encode_fields(wrap_input(iface.input), values)
              self.rpc.fire_forget(
                pi.peer,
                pi.port,
                svc_id,
                inst_id,
                if_id,
                pi.major_ver,
                body,
                on_err,
              )
            } catch {
              e => on_err(@errors.Local("ff encode input: \{Repr(e)}"))
            }
        }
      }, on_err)
  }
}

/// subscribe（§13.2）：交付回调立即登记（实例未 Found 也保留订阅意图，§13.2）→
/// sd 会话建立（定位 + ensure_idl + 首次 CON）后返回句柄（关联会话 StrmID）
/// 交付回调内按接口 output 解码（IDL 缺失/解码失败 → Error 日志丢弃该帧，§8.2 接收侧）
/// 失败：首订失败（RST/重传耗尽/无实例）→ 交付回调同步注销（会话与登记一并清除，§7.4）
pub fn Stack::subscribe(
  self : Stack,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  grp_id : Int,
  on_event : (Int, Array[@codec.FWValue]) -> Unit,
  on_ok : (SubHandle) -> Unit,
  on_err : (@errors.FwError) -> Unit
) -> Unit {
  // 交付回调包装：events 层 Bytes → 按 IDL output 解码 → 应用回调
  let deliver = fn(if_id : Int, bytes : Bytes) {
    match self.iface_of_any(svc_id, if_id) {
      None => st_log_error("[stack] event deliver: interface missing svc=\{svc_id} if=\{if_id}")
      Some(iface) =>
        match decode_output(iface.output, bytes) {
          Ok(vs) => on_event(if_id, vs)
          Err(msg) => st_log_error("[stack] event deliver codec error: if=\{if_id} \{msg}")
        }
    }
  }
  let key = self.events.reg_client(svc_id, if_id, grp_id, deliver)
  self.sd.subscribe(svc_id, inst_id, if_id, grp_id, fn(strm) {
    on_ok({ svc_id, inst_id, if_id, grp_id, key, strm_id: strm })
  }, fn(e) {
    let _ = self.events.unreg_client(key)
    on_err(e)
  })
}

/// unsubscribe（§13.2）：注销交付回调 + 发 Subscribe(TTL=0)（幂等；完成回调可感知确认）
pub fn Stack::unsubscribe(self : Stack, h : SubHandle, on_done : () -> Unit) -> Unit {
  let _ = self.events.unreg_client(h.key)
  self.sd.unsubscribe(h.svc_id, h.if_id, h.grp_id, on_done)
}

/// is_available（§13.2）：本地缓存判定（存在 + TTL Active + VER 相等，§7.5）
pub fn Stack::is_available(self : Stack, svc_id : Int, inst_id : Int) -> Bool {
  self.sd.is_available(svc_id, inst_id)
}

/// find_service（§13.2）：主动发现——触发 Find 刷新缓存（空 Payload 查询全部服务，
/// §7.2 拆帧策略免版本匹配难题）+ 返回当前缓存在线信息（异步 Offer 回达后下次调用可见）
pub fn Stack::find_service(self : Stack, svc_id : Int, inst_id : Int) -> @sd.PeerInst? {
  self.sd.send_find_all()
  self.sd.locate_instance(svc_id, inst_id)
}
