// §6 StrmID 管理：分配 / 冷却 / 回绕 / REN 清除
//
// - 数据帧按 (peer, svc_id, inst_id) 隔离（§6.3），client(0x01~0x7F) / server(0x80~0xFE) 各 127 个独立循环分配
// - 控制帧 StrmID（订阅会话 + GetIDL 查询）按 (peer) 统一分配池（§6.1/§6.3），0x01~0x7F，同键内活跃唯一（§3.5）
// - 冷却定义（§6.3）：该 StrmID 距上次释放后，本组合内已累计 ≥2 次其它 StrmID 分配才优先复用——避免旧帧迟到时与新会话冲突
// - REN=1 时清除该对端全部序列（§6.3）
// - §6.2 状态机迁移事件（Response 收到 / 重传耗尽 / 本地关闭等）由 rpc/events 层判定后调用 release，本包只管号码分配与回收

/// 循环扫描分配 helper：从 cursor 起扫 n 个位置
/// 第一遍只取"已冷却"的空闲位（seq - 释放时序号 ≥ 2）；第二遍取任意空闲位；全满 → None
/// 返回 (strm_id, 新 cursor)
fn scan_alloc(
  active : Map[Int, Bool],
  cool : Map[Int, Int],
  seq : Int,
  lo : Int,
  n : Int,
  cursor : Int
) -> (Int, Int)? {
  for pass in 0..<2 {
    let mut i = 0
    while i < n {
      let idx = (cursor + i) % n
      let strm = lo + idx
      let is_active = match active.get(strm) {
        Some(_) => true
        None => false
      }
      if !is_active {
        if pass == 1 {
          // 第二遍：任意空闲位（空间紧张时放弃冷却等待，§6.3"目标仍活跃时跳过"之外不设额外限制）
          return Some((strm, (idx + 1) % n))
        }
        // 第一遍：冷却判定（§6.3：≥2 次其它分配后才优先复用）
        let released_at = match cool.get(strm) {
          Some(v) => v
          None => -1000 // 从未释放过：视为早已冷却
        }
        if seq - released_at >= 2 {
          return Some((strm, (idx + 1) % n))
        }
      }
      i = i + 1
    }
  }
  None
}

/// 数据帧 StrmID 组状态（每组 = 一个 (peer, svc_id, inst_id) 组合，§6.3）
priv struct DataGroup {
  peer : String
  svc_id : Int
  inst_id : Int
  mut client_cursor : Int // 0~126，StrmID = cursor + 0x01
  mut server_cursor : Int // 0~126，StrmID = cursor + 0x80
  client_active : Map[Int, Bool]
  server_active : Map[Int, Bool]
  client_cool : Map[Int, Int] // strm → 释放时的组内分配序号（冷却基准）
  server_cool : Map[Int, Int]
  mut seq : Int // 组内累计分配次数
}

fn DataGroup::new(peer : String, svc_id : Int, inst_id : Int) -> DataGroup {
  {
    peer,
    svc_id,
    inst_id,
    client_cursor: 0,
    server_cursor: 0,
    client_active: Map([], capacity=4),
    server_active: Map([], capacity=4),
    client_cool: Map([], capacity=4),
    server_cool: Map([], capacity=4),
    seq: 0,
  }
}

/// 数据帧 StrmID 池（§6.2/§6.3）
pub struct DataStrmPool {
  priv groups : Map[String, DataGroup]
}

/// 组键：(peer, svc_id, inst_id) 唯一组合（§6.3 按 peer + 组合隔离）
fn group_key(peer : String, svc_id : Int, inst_id : Int) -> String {
  "\{peer}|\{svc_id}|\{inst_id}"
}

/// 创建数据帧 StrmID 池
pub fn DataStrmPool::new() -> DataStrmPool {
  { groups: Map([], capacity=8) }
}

/// 取或创建组
fn DataStrmPool::get_or_create_group(
  self : DataStrmPool,
  peer : String,
  svc_id : Int,
  inst_id : Int
) -> DataGroup {
  let key = group_key(peer, svc_id, inst_id)
  match self.groups.get(key) {
    Some(g) => g
    None => {
      let g = DataGroup::new(peer, svc_id, inst_id)
      self.groups[key] = g
      g
    }
  }
}

/// 分配客户端流 StrmID（0x01~0x7F：客户端发起的 Request/FF，§6.1）
pub fn DataStrmPool::alloc_client(
  self : DataStrmPool,
  peer : String,
  svc_id : Int,
  inst_id : Int
) -> Int? {
  let g = self.get_or_create_group(peer, svc_id, inst_id)
  match scan_alloc(g.client_active, g.client_cool, g.seq, 0x01, 127, g.client_cursor) {
    Some((strm, next)) => {
      // 目标 StrmID 仍活跃时扫描已跳过（§6.3）
      g.client_cursor = next
      g.client_active[strm] = true
      g.seq = g.seq + 1
      Some(strm)
    }
    // 127 个客户端流全部活跃 → 分配失败（上层报错，§6.1 空间耗尽）
    None => None
  }
}

/// 分配服务端流 StrmID（0x80~0xFE：服务端主动推送 Notification，§6.1）
pub fn DataStrmPool::alloc_server(
  self : DataStrmPool,
  peer : String,
  svc_id : Int,
  inst_id : Int
) -> Int? {
  let g = self.get_or_create_group(peer, svc_id, inst_id)
  match scan_alloc(g.server_active, g.server_cool, g.seq, 0x80, 127, g.server_cursor) {
    Some((strm, next)) => {
      g.server_cursor = next
      g.server_active[strm] = true
      g.seq = g.seq + 1
      Some(strm)
    }
    None => None
  }
}

/// 释放 StrmID（§6.2 状态迁移至 Closed；记录冷却基准，§6.3）
/// 重复释放幂等（未活跃的 StrmID 忽略）
pub fn DataStrmPool::release(
  self : DataStrmPool,
  peer : String,
  svc_id : Int,
  inst_id : Int,
  strm_id : Int
) -> Unit {
  let key = group_key(peer, svc_id, inst_id)
  match self.groups.get(key) {
    Some(g) =>
      if strm_id >= 0x01 && strm_id <= 0x7F {
        match g.client_active.get(strm_id) {
          Some(_) => {
            g.client_active.remove(strm_id)
            g.client_cool[strm_id] = g.seq
          }
          None => ()
        }
      } else if strm_id >= 0x80 && strm_id <= 0xFE {
        match g.server_active.get(strm_id) {
          Some(_) => {
            g.server_active.remove(strm_id)
            g.server_cool[strm_id] = g.seq
          }
          None => ()
        }
      }
    // 组不存在：无活跃流，幂等忽略
    None => ()
  }
}

/// REN=1：清除该对端全部序列（§6.3），返回被清除的 (svc_id, inst_id, strm_id) 列表
/// 供 rpc/events 层同步清理该对端的活跃 Stream 与待确认重传记录（§3.6）
pub fn DataStrmPool::clear_peer(self : DataStrmPool, peer : String) -> Array[(Int, Int, Int)] {
  let out : Array[(Int, Int, Int)] = []
  let doomed : Array[String] = []
  for key, g in self.groups {
    if g.peer == peer {
      for strm, _ in g.client_active {
        out.push((g.svc_id, g.inst_id, strm))
      }
      for strm, _ in g.server_active {
        out.push((g.svc_id, g.inst_id, strm))
      }
      doomed.push(key)
    }
  }
  // 重置 StrmID 分配游标（§3.6：清除序列并重置游标）
  for key in doomed {
    self.groups.remove(key)
  }
  out
}

/// 控制帧 StrmID 子池状态（每 peer 一个，§6.3 统一分配池）
priv struct CtrlPool {
  mut cursor : Int // 0~126，StrmID = cursor + 0x01
  active : Map[Int, Bool]
  cool : Map[Int, Int]
  mut seq : Int
}

fn CtrlPool::new() -> CtrlPool {
  { cursor: 0, active: Map([], capacity=4), cool: Map([], capacity=4), seq: 0 }
}

/// 控制帧 StrmID 池（§6.1/§6.3：订阅会话 + GetIDL 查询按 (peer) 统一池，0x01~0x7F；
/// 与数据帧管理规则独立——控制帧键 (peer,0,0,StrmID) 与数据帧键天然不相交，§3.5）
pub struct CtrlStrmPool {
  priv pools : Map[String, CtrlPool]
}

/// 创建控制帧 StrmID 池
pub fn CtrlStrmPool::new() -> CtrlStrmPool {
  { pools: Map([], capacity=8) }
}

/// 取或创建 peer 子池
fn CtrlStrmPool::get_or_create_pool(self : CtrlStrmPool, peer : String) -> CtrlPool {
  match self.pools.get(peer) {
    Some(p) => p
    None => {
      let p = CtrlPool::new()
      self.pools[peer] = p
      p
    }
  }
}

/// 分配控制帧 StrmID（Subscribe 会话 / GetIDL 查询共用，同 peer 活跃唯一，§3.5/§7.2）
pub fn CtrlStrmPool::alloc(self : CtrlStrmPool, peer : String) -> Int? {
  let p = self.get_or_create_pool(peer)
  match scan_alloc(p.active, p.cool, p.seq, 0x01, 127, p.cursor) {
    Some((strm, next)) => {
      p.cursor = next
      p.active[strm] = true
      p.seq = p.seq + 1
      Some(strm)
    }
    // 127 个全部活跃 → 分配失败
    None => None
  }
}

/// 释放控制帧 StrmID（订阅取消确认到达 / GetIDL 响应·RST·超时后；含冷却防迟到 0x11 误配，§6.1/§6.3）
/// 重复释放幂等
pub fn CtrlStrmPool::release(self : CtrlStrmPool, peer : String, strm_id : Int) -> Unit {
  match self.pools.get(peer) {
    Some(p) =>
      if strm_id >= 0x01 && strm_id <= 0x7F {
        match p.active.get(strm_id) {
          Some(_) => {
            p.active.remove(strm_id)
            p.cool[strm_id] = p.seq
          }
          None => ()
        }
      }
    None => ()
  }
}

/// REN=1 / TCP 连接断开：清除该对端全部控制帧 StrmID（§3.6/§6.3）
pub fn CtrlStrmPool::clear_peer(self : CtrlStrmPool, peer : String) -> Unit {
  self.pools.remove(peer)
}
