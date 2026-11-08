// ============================================================
// strm.js —— §6 Stream / StrmID 管理：分配 / 冷却 / 回绕
//
// 空间划分（§6.1）：
//   0x00        连接级控制（REN/心跳/Offer/Find）
//   0x01~0x7F   客户端流（数据帧 Request/FF；控制帧 Subscribe 会话 + GetIDL 查询）
//   0x80~0xFE   服务端流（服务端主动 Notification）
//   0xFF        保留
//
// 隔离规则（§6.3）：
//   - 数据帧按 (peer, svc_id, inst_id) 隔离，client/server 各 127 个独立循环分配
//   - 控制帧（订阅会话 + GetIDL 查询）按 (peer) 统一分配池（§3.5：同键内活跃唯一）
//   - 冷却：距上次释放后本组合内已完整轮转分配过一轮（或 ≥2 次其它 StrmID 分配）
// ============================================================

/**
 * 单个 StrmID 循环分配池（[low, high] 共 127 个编号）。
 * 分配优先选用已冷却的 StrmID；活跃的跳过（§6.3）。
 */
export class StrmPool {
  /**
   * @param {number} low 最小编号（含）
   * @param {number} high 最大编号（含）
   */
  constructor(low, high) {
    this.low = low;
    this.high = high;
    this.size = high - low + 1;
    this.active = new Set();     // 当前活跃的 StrmID
    this.releaseSeq = new Map(); // strmId → 释放时的全局分配序号（冷却判定）
    this.allocSeq = 0;           // 全局分配序号（每次成功分配 +1）
    this.lastUsedMs = 0;         // 最近一次分配/释放时刻（R3-9 空闲回收判定）
  }

  /**
   * 分配一个空闲 StrmID。
   * 优先选"释放后已经过 ≥2 次其它分配"（已冷却）的编号；无冷却满足时退化为
   * 任意非活跃编号；全部活跃返回 null。
   * @returns {number|null}
   */
  alloc() {
    this.lastUsedMs = Date.now(); // R3-9：刷新池活跃时刻
    // 第一轮：优先已冷却的非活跃编号
    let fallback = null;
    for (let i = 0; i < this.size; i++) {
      const id = this.low + i;
      if (this.active.has(id)) continue; // §6.3：目标 StrmID 仍活跃时跳过
      const rel = this.releaseSeq.get(id);
      if (rel !== undefined && this.allocSeq - rel >= 2) {
        // 已冷却（距释放后 ≥2 次其它分配）
        this.active.add(id);
        this.allocSeq++;
        return id;
      }
      if (fallback === null) fallback = id;
    }
    if (fallback !== null) {
      // 无冷却满足：退化为第一个非活跃编号（§6.3 冷却为优先策略，非硬性拒绝）
      this.active.add(fallback);
      this.allocSeq++;
      return fallback;
    }
    return null; // 全部活跃
  }

  /** 释放（进入冷却：记录释放序号供冷却判定） */
  release(id) {
    this.lastUsedMs = Date.now(); // R3-9：刷新池活跃时刻
    if (this.active.delete(id)) {
      this.releaseSeq.set(id, this.allocSeq);
    }
  }

  /** 是否活跃 */
  isActive(id) { return this.active.has(id); }

  /** 收到 REN=1：清除该对端全部序列并重置分配游标（§3.6/§6.3） */
  reset() {
    this.active.clear();
    this.releaseSeq.clear();
    this.allocSeq = 0; // 游标归零，后续分配从池起点重新开始
  }

  /** 活跃数量（测试/观测用） */
  get activeCount() { return this.active.size; }
}

/**
 * StrmID 管理器：按 peer 维护数据帧 client/server 池与控制帧统一池。
 * peer 为对端标识字符串（如 "ip:port"）。
 */
export class StrmManager {
  constructor() {
    // 数据帧池：key = `${peer}|${svc}|${inst}|${base}`，client(0x01~0x7F)/server(0x80~0xFE) 各 127 个独立池
    this._dataPools = new Map();
    // 控制帧统一池（订阅会话 + GetIDL 查询）：key = peer（§3.5/§6.3）
    this._ctrlPools = new Map();
  }

  // 池键必须带角色基址：client(0x01~0x7F) 与 server(0x80~0xFE) 是**两套独立 127 池**（§6.1/§6.3）。
  // 若键只含 (peer,svc,inst)，先分配的 server 池（base=0x80）会被随后的 client 分配复用，
  // 导致 client 拿到 0x80+ 的 StrmID（越出 0x01~0x7F 范围）且两个角色互相耗尽/释放对方的流。
  _dataKey(peer, svcId, instId, base) { return `${peer}|${svcId}|${instId}|${base}`; }

  /** 数据帧客户端流分配（Request/FF 发起，§6.1） */
  allocClientStream(peer, svcId, instId) {
    return this._dataPool(peer, svcId, instId, 0x01).alloc();
  }

  /** 数据帧服务端流分配（Notification 推送，§6.1） */
  allocServerStream(peer, svcId, instId) {
    return this._dataPool(peer, svcId, instId, 0x80).alloc();
  }

  /** 控制帧 StrmID 分配（Subscribe 会话 / GetIDL 查询，按 peer 统一池，§6.3） */
  allocControlStrm(peer) {
    let pool = this._ctrlPools.get(peer);
    if (!pool) {
      pool = new StrmPool(0x01, 0x7f);
      this._ctrlPools.set(peer, pool);
    }
    return pool.alloc();
  }

  /** 数据帧 Stream 释放（收到 Response/ACK/RST、超时、发送完成等，§6.2） */
  releaseClientStream(peer, svcId, instId, strmId) {
    this._dataPool(peer, svcId, instId, 0x01).release(strmId);
  }

  releaseServerStream(peer, svcId, instId, strmId) {
    this._dataPool(peer, svcId, instId, 0x80).release(strmId);
  }

  /** 控制帧 StrmID 释放（订阅取消完成、GetIDL 完成/超时，含冷却语义 §6.1/§6.3） */
  releaseControlStrm(peer, strmId) {
    this._ctrlPools.get(peer)?.release(strmId);
  }

  isControlStrmActive(peer, strmId) {
    return this._ctrlPools.get(peer)?.isActive(strmId) ?? false;
  }

  /** 收到 REN=1：清除该对端全部序列并重置游标（§3.6）
   *  peer 可能是完整 "ip:port"，也可能是上层传入的 "ip:" 前缀（按节点清理）；
   *  因此统一用 startsWith(peer) 匹配数据池 key 与控制池 key，避免漏清。 */
  resetPeer(peer) {
    for (const key of this._dataPools.keys()) {
      if (key.startsWith(peer)) this._dataPools.get(key).reset();
    }
    for (const key of this._ctrlPools.keys()) {
      if (key.startsWith(peer)) this._ctrlPools.get(key).reset();
    }
  }

  _dataPool(peer, svcId, instId, base) {
    const key = this._dataKey(peer, svcId, instId, base);
    let pool = this._dataPools.get(key);
    if (!pool) {
      pool = new StrmPool(base, base + 0x7e); // 127 个：0x01~0x7F 或 0x80~0xFE
      pool.lastUsedMs = Date.now();
      this._dataPools.set(key, pool);
    }
    return pool;
  }

  /**
   * R3-9：回收空闲池。peer 前缀为空时回收全部空闲池；否则仅回收该对端的池。
   * 仅当池内无活跃 StrmID 且距最近一次分配/释放超过 idleMs 才回收（保留冷却/序列语义——
   * 回收的池已经空闲，重新请求时新建池即回到初始状态，与 §6.3 一致）。
   * @param {number} idleMs 空闲阈值（毫秒）
   * @param {string} [peerPrefix] 对端前缀（"ip:" 或 "ip:port"）；省略回收全部
   * @returns {number} 回收的池数
   */
  collectIdlePools(idleMs, peerPrefix) {
    const now = Date.now();
    const cutoff = now - idleMs;
    let removed = 0;
    const match = (key) => peerPrefix === undefined || peerPrefix === null || key.startsWith(peerPrefix);
    for (const [key, pool] of this._dataPools) {
      if (match(key) && pool.activeCount === 0 && pool.lastUsedMs <= cutoff) {
        this._dataPools.delete(key);
        removed++;
      }
    }
    for (const [key, pool] of this._ctrlPools) {
      if (match(key) && pool.activeCount === 0 && pool.lastUsedMs <= cutoff) {
        this._ctrlPools.delete(key);
        removed++;
      }
    }
    return removed;
  }
}
