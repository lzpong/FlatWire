// 服务端订阅表（§8.1 订阅管理 + §7.5 TTL 状态机 + §7.6 确认语义）
//
// - 主键 = Entry 内容 (peer, svc_id, inst_id, if_id/grp_id)（§7.2：StrmID 仅作会话跟踪，
//   重传 vs 新操作按 (peer, StrmID) 判定——客户端重启换新 StrmID 重订按 Entry 级刷新）
// - TTL 推进与发现缓存同规则（§7.5 "两侧规则完全一致"）：1s tick 递减，归零转 Expired，
//   下一次 tick 删除；TTL=0 取消立即置 Expired（延迟 tick 删除）
// - 确认语义（§8.1 表格）：CON 一律回确认（首次/重传一致）；NON 保活刷新 TTL 不回确认

/// 服务端订阅记录（events 层按 (svc_id, if_id, inst_id) 查询推送目标）
pub(all) struct ServerSub {
  peer : String // 订阅者源 IP
  peer_port : Int // 订阅者源端口（Subscribe 源端口；UDP 推送目标）
  svc_id : Int
  inst_id : Int
  if_id : Int // 单接口订阅（≠0 且 grp_id=0）
  grp_id : Int // 组订阅（≠0 且 if_id=0）
  strm_id : Int // 会话 StrmID（重复 CON 判定 + 推送 StrmID 分配无关）
  mut ttl_remaining : Int // 剩余秒数
  mut expired : Bool // 待移除标记
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend ServerSub with Eq::{not_equal, equal}
pub extend ServerSub with @moonbitlang/core/debug.Debug::{to_repr}

/// 服务端订阅表 tick 推进（Sd::tick 1s 调用；§7.5）
fn Sd::tick_server_subs(self : Sd) -> Unit {
  let doomed : Array[(String, ServerSub)] = []
  for k, s in self.server_subs {
    if s.expired {
      doomed.push((k, s))
    } else {
      s.ttl_remaining = s.ttl_remaining - 1
      if s.ttl_remaining <= 0 {
        s.expired = true
      }
    }
  }
  for pair in doomed {
    let _ = self.server_subs.remove(pair.0)
    (self.on_event)(SubRemoved(pair.1))
  }
}

/// 选择本端服务实例（订阅目标定位；inst_id=0 通配任一）
fn Sd::pick_local_instance(self : Sd, svc_id : Int, inst_id : Int) -> LocalInst? {
  for _k, inst in self.local_insts {
    if inst.svc_id == svc_id && (inst_id == 0 || inst.inst_id == inst_id) {
      return Some(inst)
    }
  }
  None
}

/// 判定订阅目标接口是否走 TCP 推送（§11.1 transport 绑定；组订阅 = 组内任一成员 tcp）
fn Sd::sub_requires_tcp(self : Sd, li : LocalInst, e : SubEntry) -> Bool {
  match self.store.get(li.svc_id, li.major_ver) {
    None => false // 无定义（异常部署）：按 UDP 处理，Entry 后续照常登记
    Some(def) =>
      if e.if_id != 0 {
        // 单接口订阅
        match def.find_interface(e.if_id) {
          Some(it) => it.tcp
          None => false
        }
      } else {
        // 组订阅：组内任一 event 接口声明 tcp → 需 TCP 连接
        match def.find_group(e.grp_id) {
          Some(g) => {
            let mut any_tcp = false
            for if_id in g.members {
              match def.find_interface(if_id) {
                Some(it) => if it.tcp {
                  any_tcp = true
                }
                None => ()
              }
            }
            any_tcp
          }
          None => false
        }
      }
  }
}

/// 发送订阅确认（§8.1：CTR=1, TYP=ACK, Code=0x10/0x00，回显会话 StrmID）。
/// 恒走 server socket：确认属服务端角色应答帧（对 Subscribe 请求的响应），与 rpc 层
/// send_ff_ack 口径一致——应答源端口统一为 fw_udp_port，客户端仅凭回显 StrmID 匹配会话
fn Sd::send_sub_ack(self : Sd, code : Int, strm_id : Int, host : String, port : Int) -> Unit {
  let _ = self.transport.send_udp_frame(
    true,
    @frame.ctrl_spec(@frame.Ack, code, strm_id),
    b"",
    host,
    port,
  )
}

/// 处理 Subscribe（服务端视角；§7.2 Entry 级处理 + §8.1 确认语义）
fn Sd::handle_subscribe(self : Sd, f : @frame.Frame, host : String, port : Int) -> Unit {
  match parse_sub_entries(f.payload) {
    None =>
      // §7.2：整帧 Payload 无法解析 → RST(0x20)。Subscribe 恒单播 → 源地址可达，回 RST 安全
      self.send_rst_udp(@errors.RST_BAD_REQUEST, f, host, port)
    Some(entries) => {
      let mut reject24 = false
      // Entry 级独立处理（§7.2：无效 Entry 丢弃 + Error 日志，不整帧拒绝）
      for e in entries {
        // §7.1 合法组合：单接口 IfID≠0 且 GrpId=0 / 组订阅 IfID=0 且 GrpId≠0；均 0 非法
        if e.if_id == 0 && e.grp_id == 0 {
          sd_log_error("[sd] Subscribe 非法组合 Entry 丢弃: svc=\{e.svc_id} peer=\{host}")
          continue
        }
        if e.svc_id == 0 {
          sd_log_error("[sd] Subscribe Entry SvcID=0 丢弃: peer=\{host}")
          continue
        }
        // 服务存在性：本端无该服务实例 → Entry 丢弃 + Error 日志（§7.2）
        let li = match self.pick_local_instance(e.svc_id, e.inst_id) {
          Some(v) => v
          None => {
            sd_log_error("[sd] Subscribe 服务不存在 Entry 丢弃: svc=\{e.svc_id} inst=\{e.inst_id} peer=\{host}")
            continue
          }
        }
        // tcp-event 预建连接检查（§7.2：无该客户端活跃 TCP 连接 → RST(0x24) 整帧拒绝）
        if self.sub_requires_tcp(li, e) && !(self.transport.conn_id_by_peer(host) is Some(_)) {
          sd_log_error("[sd] tcp-event 订阅无预建连接: svc=\{e.svc_id} if=\{e.if_id} grp=\{e.grp_id} peer=\{host}")
          reject24 = true
          break
        }
        let key = server_key(host, e.svc_id, li.inst_id, e.if_id, e.grp_id)
        if e.ttl > 0 {
          // 订阅建立 / 保活刷新（§8.1）
          match self.server_subs.get(key) {
            Some(s) => {
              // 已有记录：刷新 TTL（重置非累加，§7.5）；重传判定按 (peer, StrmID)（§7.2）
              let same_session = s.strm_id == f.strm_id
              s.ttl_remaining = e.ttl
              s.expired = false
              if !same_session {
                // 换新 StrmID 的 CON = 客户端重启重订：更新会话跟踪（Entry 级刷新，状态自洽 §7.2）
                // strm_id/peer_port 为不可变字段 → 用更新语法整体替换 Map 值
                self.server_subs[key] = { ..s, strm_id: f.strm_id, peer_port: port }
              }
              // NON 保活不回确认（§8.1）；CON 一律回确认（重复 CON 重发确认不重推全量，§8.1）
              if f.typ == @frame.Con {
                self.send_sub_ack(0x10, f.strm_id, host, port)
              }
            }
            None => {
              // 新订阅（从无到有）
              let s : ServerSub = {
                peer: host,
                peer_port: port,
                svc_id: e.svc_id,
                inst_id: li.inst_id,
                if_id: e.if_id,
                grp_id: e.grp_id,
                strm_id: f.strm_id,
                ttl_remaining: e.ttl,
                expired: false,
              }
              self.server_subs[key] = s
              // CON 回确认（§8.1：有/无缓存一致）；NON 新记录异常帧——仍登记但无确认
              if f.typ == @frame.Con {
                self.send_sub_ack(0x10, f.strm_id, host, port)
              }
              // 全量推送由 events 层执行（§8.1：数据分发行为，非确认信号）
              (self.on_event)(SubEstablished(s))
            }
          }
        } else {
          // TTL=0 取消（§8.1：置 Expired 延迟 tick 删除 + 回空确认）
          match self.server_subs.get(key) {
            Some(s) => {
              s.expired = true
              (self.on_event)(SubRemoved(s))
            }
            // 未订阅的取消：幂等忽略
            None => ()
          }
        }
      }
      if reject24 {
        self.send_rst_udp(@errors.RST_NOT_FOUND, f, host, port)
        return
      }
      // 会话级确认（§7.2"能正常解析帧即按会话回确认"）：CON 帧级一律回一次——
      // Entry 级已对"新记录 CON"回过确认，此处补"重复 CON/全无效 Entry CON"的确认。
      // 重复回确认幂等无害（客户端对重复 0x10 幂等忽略）。
      if f.typ == @frame.Con {
        let code = if entries.length() > 0 && entries[0].ttl > 0 {
          0x10
        } else {
          0x00
        }
        self.send_sub_ack(code, f.strm_id, host, port)
      }
    }
  }
}

/// 服务端订阅查询（events 层推送目标筛选：精确 if_id 匹配 + 组订阅展开）。
/// group_ids = 该 event 接口所属组号列表（由 events 层按 IDL 展开后传入）。
pub fn Sd::subs_for_event(
  self : Sd,
  svc_id : Int,
  inst_id : Int,
  if_id : Int,
  group_ids : Array[Int]
) -> Array[ServerSub] {
  let out : Array[ServerSub] = []
  for _k, s in self.server_subs {
    if s.svc_id != svc_id || s.expired {
      continue
    }
    // 实例匹配：订阅未指定实例（通配）或实例号一致
    if s.inst_id != 0 && s.inst_id != inst_id {
      continue
    }
    // 接口匹配：单接口订阅精确匹配；组订阅按组归属
    if s.if_id == if_id {
      out.push(s)
    } else if s.if_id == 0 {
      let mut hit = false
      for g in group_ids {
        if s.grp_id == g {
          hit = true
        }
      }
      if hit {
        out.push(s)
      }
    }
  }
  out
}
