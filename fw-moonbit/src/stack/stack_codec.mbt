// stack 层 codec 桥接（§13 payload 语义：应用操作结构化字段值集合 FWValue，
// 编解码由协议栈按本地 IDL 库动态执行——纯动态架构 §11.1，无代码生成/无 Stub）
//
// 与 node 版行为对齐：node 版在 rpc 层编解码（rpc.js encodePayload/decode），
// 本实现在 stack 层桥接（rpc/events 保持 Bytes 内部通道）——编解码位置为实现细节，
// 线上行为一致（编码结果与方向语义相同）
//
// 顶层 payload 形态：input = 参数类型数组 → Array[FWValue] 逐项对应；
// output = 单类型 → 解码结果为单元素 Array[FWValue]（应用取 [0]）

/// 应用侧服务端处理契约（§13.3：on_request 返回响应值或 RST Code；on_ff 无返回值）
pub(all) struct StackHandler {
  on_request : (Int, Array[@codec.FWValue]) -> Result[Array[@codec.FWValue], Int]
  on_ff : (Int, Array[@codec.FWValue]) -> Unit
}

/// 定位接口定义（store 按 (svc, major) 精确查——call/注册场景版本已知）
fn Stack::iface_of(self : Stack, svc_id : Int, major_ver : Int, if_id : Int) -> @idlstore.IdlInterface? {
  match self.store.get(svc_id, major_ver) {
    Some(def) => def.find_interface(if_id)
    None => None
  }
}

/// 定位接口定义（版本通配——notify/订阅接收场景；多版本并存属部署异常取任一，v4.4 第三轮定案）
fn Stack::iface_of_any(self : Stack, svc_id : Int, if_id : Int) -> @idlstore.IdlInterface? {
  match self.store.get_any(svc_id) {
    Some(def) => def.find_interface(if_id)
    None => None
  }
}

/// input 参数类型 → 编码 schema（IDL 加载时已内联展开 CType 树；顶层参数无 optional 语义）
fn wrap_input(inputs : Array[@codec.CType]) -> Array[@codec.CField] {
  let out : Array[@codec.CField] = []
  let mut i = 0
  for t in inputs {
    out.push({ name: "arg\{i}", ctype: t, optional: false })
    i = i + 1
  }
  out
}

/// output 类型 → 编码 schema（None = 无返回 → 空字段集，编码得空 payload）
fn wrap_output(out : @codec.CType?) -> Array[@codec.CField] {
  match out {
    Some(t) => [{ name: "ret", ctype: t, optional: false }]
    None => []
  }
}

/// 按 output 方向解码响应/推送 payload（尾部新增字段容忍由 decode_fields 承载，§9.4）
fn decode_output(
  out : @codec.CType?,
  bytes : Bytes
) -> Result[Array[@codec.FWValue], String] {
  try {
    Ok(@codec.decode_fields(bytes, wrap_output(out)))
  } catch {
    e => Err("codec: \{Repr(e)}")
  }
}

/// StackHandler（FWValue 版）→ rpc.ServiceHandler（Bytes 版）适配：
/// 请求按 input 解码 → 应用处理 → 返回值按 output 编码；
/// 解码/编码失败 → RST(0x20)（IDL 级契约违约，§12.1 两层两码）；接口缺失 → RST(0x24)
fn Stack::adapt_handler(
  self : Stack,
  svc_id : Int,
  major_ver : Int,
  h : StackHandler
) -> @rpc.ServiceHandler {
  {
    on_request: fn(if_id, bytes) {
      match self.iface_of(svc_id, major_ver, if_id) {
        None => Err(0x24) // 接口不存在（§12.1 Not Found）
        Some(iface) =>
          try {
            let args = @codec.decode_fields(bytes, wrap_input(iface.input))
            match (h.on_request)(if_id, args) {
              Ok(vs) => Ok(@codec.encode_fields(wrap_output(iface.output), vs))
              Err(code) => Err(code) // 应用侧业务拒绝：RST Code 直通（§13.3）
            }
          } catch {
            e => {
              st_log_error("[stack] request codec error: svc=\{svc_id} if=\{if_id} \{Repr(e)}")
              Err(0x20)
            }
          }
      }
    },
    on_ff: fn(if_id, bytes) {
      // FF 解码失败静默丢弃（Error 日志）——无响应通道可回 RST，对端按超时判定（§5.2）
      match self.iface_of(svc_id, major_ver, if_id) {
        None => ()
        Some(iface) =>
          try {
            let args = @codec.decode_fields(bytes, wrap_input(iface.input))
            ;(h.on_ff)(if_id, args)
          } catch {
            e => st_log_error("[stack] ff codec error: svc=\{svc_id} if=\{if_id} \{Repr(e)}")
          }
      }
    },
  }
}
