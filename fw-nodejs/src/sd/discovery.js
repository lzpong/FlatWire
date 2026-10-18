// ============================================================
// discovery.js —— §7 服务发现（SD）+ §7.4 客户端状态机 + §8.1 订阅管理
//
// 服务端角色：注册表 / 周期 Offer（拆帧）/ Find 响应 / Subscribe 服务端处理
//             （ACK 0x10/0x00）/ GetIDL 服务端 / 订阅者 TTL 表
// 客户端角色：发现缓存 + 客户端状态机（Unknown→Found→Subscribed→Expired）/
//             主动 Find / 订阅会话（StrmID 复用、保活、取消、自动重订阅）/
//             GetIDL 客户端（双角色统一触发，§7.2）
// ============================================================

import { EventEmitter } from 'node:events';
import { TYP, CODE, encodeFrame, makeRst } from '../frame/frame.js';
import {
  encodeOfferEntries, decodeOfferEntries, encodeFindEntries, decodeFindEntries,
  encodeSubscribeEntries, decodeSubscribeEntries, encodeGetIdlEntry, decodeGetIdlEntry,
} from './entries.js';
import { RetransmitTable } from '../rpc/retransmit.js';
import { RST_CODE, RST_NAME, ServiceNotFound, GetIdlError } from '../errors.js';

const CLIENT_STATE = Object.freeze({
  UNKNOWN: 'Unknown', FOUND: 'Found', SUBSCRIBED: 'Subscribed',
  UNSUBSCRIBED: 'Unsubscribed', EXPIRED: 'Expired',
});

export class Discovery extends EventEmitter {
  /**
   * @param {object} ctx {
   *   config, log, strm, idlStore,
   *   sendUdpFrame(frameObj, address, port, from),  // 编码并单播发送
   *   sendUdpRaw(buf, address, port, from),
   *   sendMulticastFrame(frameObj|Buffer, which),
   *   getTcpConn(address, port),
   *   onSubscriptionAdded(sub),       // 服务端：订阅从无到有（全量推送钩子）
   * }
   */
  constructor(ctx) {
    super();
    this.ctx = ctx;
    this.cfg = ctx.config;
    this.log = ctx.log;
    this.strm = ctx.strm;
    this.idlStore = ctx.idlStore;

    // ---- 服务端角色 ----
    this.locals = new Map();   // `${svc}:${inst}` → { svc_id, inst_id, schema, handlers }
    this.subs = new Map();     // 订阅者表 key `${ip}|${port}|${svc}|${inst}|i${ifId}|g${grpId}`
    this._offerTimer = null;

    // ---- 客户端角色 ----
    this.discovered = new Map(); // `${svc}:${inst}` → 发现缓存记录（§7.4）
    this.sessions = new Map();   // handle → 订阅会话
    this.sessionIndex = new Map(); // `${peerStrm}` → session（0x10/RST 匹配）
    this.cancelPending = new Map(); // `${peerStrm}` → { timers… 取消中的会话 }
    this.pendingFind = new Map();   // `${svc}:${inst}` → [{ resolve, reject, timer }]
    this.pendingIdl = new Map();    // `${peerStrm}` → GetIDL 查询等待器
    this.idlInflight = new Map();   // `${svc}:${major}` → Promise（并发首调合并，§7.2 建议项）
    this._ackCache = new Map();     // `${ip}:${port}|${strm}` → { frame, req }（重复 CON 重发确认，§5.5）

    this._retrans = new RetransmitTable({ intervalMs: this.cfg.retransmit_interval_ms, maxRetry: this.cfg.retransmit_max });
    this._tickTimer = null;
    this._handleSeq = 0;
  }

  ttlSeconds() { return Math.floor(this.cfg.ttl_ms / 1000); }

  // ============================================================
  // 服务端角色（§7.3 生命周期）
  // ============================================================

  /** 注册服务实例 → Offering（开始周期广播 Offer，§7.3） */
  async registerService(svcId, instId, schema, handlers) {
    const key = `${svcId}:${instId}`;
    if (this.locals.has(key)) {
      // 7.9：本地重复注册同 (svc_id, inst_id) → Err，不覆盖原处理者
      throw new Error(`service instance ${key} already registered`);
    }
    this.locals.set(key, { svc_id: svcId, inst_id: instId, schema, handlers });
    this.log.info('sd', `register_service: svc=${svcId} inst=${instId} → Offering`);
    this._broadcastOffers(); // 立即广播一次（注册即 Offering）
    return this.locals.get(key);
  }

  /** 注销实例 → 发 TTL=0 Offer 一次，停止广播（§7.3） */
  unregisterService(svcId, instId) {
    const key = `${svcId}:${instId}`;
    const rec = this.locals.get(key);
    if (!rec) return false;
    this.locals.delete(key);
    // TTL=0 表示停止提供（§7.2 Offer）
    const entry = { svc_id: svcId, inst_id: instId, major_ver: schemaMajor(rec.schema), minor_ver: schemaMinor(rec.schema), ttl: 0 };
    for (const frame of buildOfferFrames([entry], this.cfg.max_payload_len)) {
      this.ctx.sendMulticastFrame(frame, 'main');
    }
    this.log.info('sd', `unregister_service: svc=${svcId} inst=${instId} → Stopped`);
    return true;
  }

  /** 本地实例记录 */
  getLocal(svcId, instId) { return this.locals.get(`${svcId}:${instId}`); }

  /** 启动周期 Offer 广播（period_ms，§7.2） */
  startOfferLoop() {
    this.stopOfferLoop();
    this._offerTimer = setInterval(() => this._broadcastOffers(), this.cfg.period_ms);
    this._offerTimer.unref?.();
  }

  stopOfferLoop() {
    if (this._offerTimer) { clearInterval(this._offerTimer); this._offerTimer = null; }
  }

  /** 构建并组播 Offer 帧（SD 拆帧策略：按 max_payload_len 满装，§7.2） */
  _broadcastOffers() {
    if (this.locals.size === 0) return;
    const ttl = this.ttlSeconds();
    const entries = [...this.locals.values()].map((r) => ({
      svc_id: r.svc_id, inst_id: r.inst_id,
      major_ver: schemaMajor(r.schema), minor_ver: schemaMinor(r.schema), ttl,
    }));
    for (const frame of buildOfferFrames(entries, this.cfg.max_payload_len)) {
      this.ctx.sendMulticastFrame(frame, 'main');
    }
    this.log.debug('sd', `Offer broadcast: ${entries.length} instance(s), ${frameCount(entries, this.cfg.max_payload_len)} frame(s)`);
  }

  /** 处理 Find（组播或降级单播）：匹配本地实例 → 单播响应（格式同 Offer，§7.2） */
  onFind(frame, meta) {
    let entries;
    const payload = frame.payload ?? Buffer.alloc(0);
    if (payload.length === 0) {
      // 空 Payload = 查询所有服务（§7.2）
      entries = this._allLocalEntries();
    } else {
      if (payload.length % 4 !== 0) {
        // 整帧无法解析 → 组播静默（单播降级场景回 RST(0x20) 也无法区分，保守静默）
        this.log.warn('sd', `Find payload not aligned (${payload.length}B), dropped`);
        return;
      }
      entries = [];
      for (const q of decodeFindEntries(payload)) {
        // 带 Entry 时必须指定 SvcID（非零）；无效 Entry 丢弃+日志（§7.2 Entry 级处理）
        if (q.svc_id === 0) { this.log.error('sd', `Find entry svc_id=0 invalid, dropped`); continue; }
        for (const r of this.locals.values()) {
          if (r.svc_id !== q.svc_id) continue;
          if (q.inst_id !== 0 && r.inst_id !== q.inst_id) continue; // InstID 0x00 通配
          // SvcID 非通配时 MajorVer 参与精确匹配（Entry major_ver=0 时不过滤版本）
          if (q.major_ver !== 0 && schemaMajor(r.schema) !== q.major_ver) continue;
          entries.push({
            svc_id: r.svc_id, inst_id: r.inst_id,
            major_ver: schemaMajor(r.schema), minor_ver: schemaMinor(r.schema), ttl: this.ttlSeconds(),
          });
        }
      }
    }
    if (entries.length === 0) {
      // Find 查询的服务/实例不存在：组播不强制回应（§12.2 Not Found (SD)）
      this.log.debug('sd', `Find matched no local instance, no response`);
      return;
    }
    // 响应帧格式与 Offer 相同（Code=0x01），UDP 单播发送；超限适用同一拆帧策略（§7.2）
    for (const f of buildOfferFrames(entries, this.cfg.max_payload_len)) {
      this.ctx.sendUdpFrame(f, meta.address, meta.port, 'main');
    }
  }

  _allLocalEntries() {
    const ttl = this.ttlSeconds();
    return [...this.locals.values()].map((r) => ({
      svc_id: r.svc_id, inst_id: r.inst_id,
      major_ver: schemaMajor(r.schema), minor_ver: schemaMinor(r.schema), ttl,
    }));
  }

  // ============================================================
  // 服务端：Subscribe 处理（§8.1 订阅管理）
  // ============================================================

  /**
   * 处理 Subscribe 帧（CTR=1, Code=0x03, StrmID=会话）。
   * 到达帧 → 服务端行为（§8.1 表）：
   *   首次 CON(TTL>0) → 建立订阅 + ACK(0x10) [+ 全量推送]
   *   重复 CON(同会话 StrmID) → 重发 ACK(0x10)，不重执行不重推全量
   *   取消 CON(TTL=0) → 置 Expired + ACK(0x00)
   *   NON 保活(TTL>0) → 刷新 TTL，不回确认
   */
  onSubscribe(frame, meta) {
    const payload = frame.payload ?? Buffer.alloc(0);
    if (payload.length === 0 || payload.length % 7 !== 0) {
      // 整帧 Payload 无法解析 → RST(0x20)（§7.2 Entry 级处理）
      this.ctx.sendUdpFrame(makeRst(RST_CODE.BAD_REQUEST, { ctr: 1, strm_id: frame.strm_id }), meta.address, meta.port, 'main');
      return;
    }
    const peerStrm = `${meta.address}:${meta.port}|${frame.strm_id}`;
    const entries = decodeSubscribeEntries(payload);
    const isCon = frame.typ === TYP.CON;
    this.log.debug('sd', `Subscribe Rx: peer=${meta.address}:${meta.port} strm=${frame.strm_id} con=${isCon} entries=${entries.length}`);

    // 同一会话 StrmID 的重复 CON 到达 = 重传判定 → 重发上次确认，不重新执行（§5.5/§8.1）
    if (isCon && entries.length > 0) {
      const curTtl0 = payload[6] === 0; // 取消帧（单 Entry 对齐已保证）
      const cached = this._ackCache.get(peerStrm);
      if (cached) {
        const cachedTtl0 = cached.req && cached.req.payload?.length === 7 && cached.req.payload[6] === 0;
        if (cachedTtl0 === curTtl0) {
          // 同类重复 CON：重发缓存确认（0x10 重发不重推全量，§8.1）
          this.ctx.sendUdpFrame(cached.frame, meta.address, meta.port, 'main');
          return;
        }
      }
    }

    // 6.19 调和：单 Entry 帧指向本地完全不存在 (svc,inst) 实例 → RST(0x24)
    //（多 Entry 帧逐 Entry 独立处理，§7.2 Entry 级丢弃——见 README 有意偏差说明）
    if (entries.length === 1) {
      const e = entries[0];
      const comboOk = (e.if_id !== 0 && e.grp_id === 0) || (e.if_id === 0 && e.grp_id !== 0);
      if (comboOk && e.svc_id !== 0 && e.inst_id !== 0 && !this.locals.has(`${e.svc_id}:${e.inst_id}`)) {
        this.ctx.sendUdpFrame(makeRst(RST_CODE.NOT_FOUND, { ctr: 1, strm_id: frame.strm_id }), meta.address, meta.port, 'main');
        return;
      }
    }
    // 6.17：tcp-event 订阅（transport=tcp 的 event 接口）须预建 TCP 连接 → 无连接 RST(0x24)
    for (const e of entries) {
      const iface = this._lookupInterface(e.svc_id, e.if_id);
      if (iface && iface.type === 'event' && iface.transport === 'tcp') {
        if (!this.ctx.findServerConnByIp?.(meta.address)) {
          this.log.warn('sd', `tcp-event subscribe without connection from ${meta.address} → RST(0x24)`);
          this.ctx.sendUdpFrame(makeRst(RST_CODE.NOT_FOUND, { ctr: 1, strm_id: frame.strm_id }), meta.address, meta.port, 'main');
          return;
        }
      }
    }

    let hasNew = false;
    let anyCancel = false;
    for (const e of entries) {
      // Entry 合法组合（§7.1）：单接口 IfID≠0 且 GrpId=0 / 组订阅 IfID=0 且 GrpId≠0
      const validCombo = (e.if_id !== 0 && e.grp_id === 0) || (e.if_id === 0 && e.grp_id !== 0);
      if (!validCombo || e.svc_id === 0 || e.inst_id === 0) {
        // 无效 Entry：丢弃 + Error 日志，不影响同帧其他 Entry（§7.2）
        this.log.error('sd', `Subscribe entry invalid (svc=${e.svc_id}, if=${e.if_id}, grp=${e.grp_id}), dropped`);
        continue;
      }
      if (this._applySubscribeEntry(e, meta, frame.strm_id)) hasNew = true;
      if (e.ttl === 0) anyCancel = true;
    }

    if (isCon) {
      // 服务端能正常解析帧即按会话回确认（§7.2）：TTL>0 → ACK(0x10)；TTL=0 → ACK(0x00)
      const ackCode = anyCancel ? 0x00 : 0x10;
      this._sendSubAck(ackCode, frame.strm_id, meta, frame);
    }
    if (hasNew) {
      // 订阅记录从无到有 → 全量推送（数据分发，非确认信号；每条订阅仅一次，§8.1）
      this.ctx.onSubscriptionAdded?.({
        meta,
        entries: entries.filter((e) => (e.if_id !== 0 && e.grp_id === 0) || (e.if_id === 0 && e.grp_id !== 0)),
      });
    }
  }

  /** 在本地 IDL 库中查接口定义（任一版本） */
  _lookupInterface(svcId, ifId) {
    for (const entry of this.idlStore.allEntries()) {
      if (entry.schema.svcId === svcId) return entry.schema.getInterface(ifId);
    }
    return null;
  }

  /** 应用一条订阅 Entry；返回是否"从无到有"建立 */
  _applySubscribeEntry(e, meta, sessionStrm) {
    const kind = e.if_id !== 0 ? 'i' : 'g';
    const key = `${meta.address}|${meta.port}|${e.svc_id}|${e.inst_id}|${kind}${e.if_id !== 0 ? e.if_id : e.grp_id}`;
    const existing = this.subs.get(key);
    if (e.ttl === 0) {
      // 取消：置 Expired，延迟到下次 tick 移除（§7.5）
      if (existing) { existing.state = 'Expired'; }
      return false;
    }
    if (existing) {
      // 已存在（重传或保活到达）：刷新 TTL（重置而非累加，§7.5）
      existing.ttlLeft = e.ttl;
      existing.state = 'Active';
      existing.sessionStrm = sessionStrm; // 会话跟踪（§7.2：主键仍为 Entry 内容）
      return false;
    }
    // 从无到有：建立订阅（state=Active，§8.1）
    this.subs.set(key, {
      key,
      svc_id: e.svc_id, inst_id: e.inst_id, if_id: e.if_id, grp_id: e.grp_id,
      peerIp: meta.address, peerPort: meta.port,
      sessionStrm,
      ttlLeft: e.ttl, state: 'Active',
    });
    return true;
  }

  /** 回订阅确认（ACK 0x10 建立确认 / 0x00 取消确认），缓存供重传重发（§8.1） */
  _sendSubAck(code, strmId, meta, reqFrame) {
    const ack = { ctr: 1, typ: TYP.ACK, code, strm_id: strmId, svc_id: 0, if_id: 0, inst_id: 0 };
    const peerStrm = `${meta.address}:${meta.port}|${strmId}`;
    // 确认帧回显会话 StrmID（§8.1）；缓存供同会话重复 CON 重发（不重执行，§5.5）
    this._ackCache.set(peerStrm, { frame: ack, req: reqFrame });
    // 确认缓存随会话生命周期保存，60s 兜底清理（防表膨胀）
    const t = setTimeout(() => this._ackCache.delete(peerStrm), 60000);
    t.unref?.();
    this.ctx.sendUdpFrame(ack, meta.address, meta.port, 'main');
  }

  /**
   * 查询订阅者（events 推送用，§8.2）。
   * 单接口订阅（if_id 精确）+ 组订阅（grp 展开包含 ifId）。
   */
  subscribersOf(svcId, instId, ifId) {
    const out = [];
    for (const s of this.subs.values()) {
      if (s.svc_id !== svcId || s.inst_id !== instId || s.state !== 'Active') continue;
      if (s.if_id === ifId) { out.push(s); continue; }
      if (s.if_id === 0 && s.grp_id !== 0) {
        // 组订阅：服务端展开为组内所有 event 接口（§7.1）
        const members = this._groupMembers(s.svc_id, s.grp_id);
        if (members.includes(ifId)) out.push(s);
      }
    }
    return out;
  }

  /** 查 IDL 事件组成员（本地库定义，§7.1） */
  _groupMembers(svcId, grpId) {
    for (const entry of this.idlStore.allEntries()) {
      if (entry.schema.svcId === svcId) return entry.schema.eventGroups.get(grpId) ?? [];
    }
    return [];
  }

  /** 服务端订阅 TTL tick：Active 递减 / Expired 移除（§7.5） */
  _tickSubs() {
    for (const [key, s] of this.subs) {
      if (s.state === 'Expired') { this.subs.delete(key); continue; } // 下一次 tick 删除
      s.ttlLeft -= 1;
      if (s.ttlLeft <= 0) s.state = 'Expired'; // 归零 → 转 Expired（下 tick 删除）
    }
  }

  // ============================================================
  // 服务端：GetIDL 处理（§7.2，仅 TCP 单播——传输绑定已由解析层保证）
  // ============================================================

  onGetIdl(frame, meta, conn) {
    const entry = decodeGetIdlEntry(frame.payload);
    if (!entry || entry.svc_id === 0) {
      // Payload ≠3B 或 SvcID=0 → RST(0x20)（§7.2）
      conn.write(makeRst(RST_CODE.BAD_REQUEST, { ctr: 1, strm_id: frame.strm_id }));
      return;
    }
    // 服务端匹配 = 本地 IDL 库已加载定义（与实例是否在线无关，§7.2）
    const def = this.idlStore.get(entry.svc_id, entry.major_ver);
    if (!def) {
      conn.write(makeRst(RST_CODE.NOT_FOUND, { ctr: 1, strm_id: frame.strm_id }));
      this.log.frame('warn', { svc_id: entry.svc_id, dir: 'Tx', addr: conn.addrKey, code: RST_CODE.NOT_FOUND, msg: 'GetIDL: no such (SvcID, MajorVer) loaded' });
      return;
    }
    // 响应：CTR=1, TYP=NON, Code=0x11, 回显请求 StrmID, Payload=IDL JSON 全文（§7.2）
    conn.write({
      ctr: 1, typ: TYP.NON, code: CODE.SD_GET_IDL_RESP,
      svc_id: 0, if_id: 0, inst_id: 0, strm_id: frame.strm_id,
      payload: Buffer.from(def.jsonText, 'utf8'),
    });
  }

  // ============================================================
  // 客户端角色：发现缓存与状态机（§7.4）
  // ============================================================

  /** 处理 Offer（周期组播与 Find 单播响应同格式同处理，§7.2） */
  onOffer(frame, meta) {
    const payload = frame.payload ?? Buffer.alloc(0);
    if (payload.length % 6 !== 0) {
      this.log.warn('sd', `Offer payload not aligned (${payload.length}B), dropped`);
      return;
    }
    for (const e of decodeOfferEntries(payload)) {
      this._applyOfferEntry(e, meta, frame.ver ?? 0);
    }
  }

  _applyOfferEntry(e, meta, ver) {
    const key = `${e.svc_id}:${e.inst_id}`;
    const rec = this.discovered.get(key);
    if (e.ttl === 0) {
      // Offer TTL=0：置 Expired，延迟到 tick 移除（§7.5）；Subscribed/Found → Expired（§7.4）
      if (rec) {
        rec.state = 'Expired';
        this._onInstanceExpired(rec);
      }
      return;
    }
    if (rec) {
      // 实例冲突：源地址 ≠ 已记录源地址 → Error 日志，保留先到，忽略后到（§7.2）
      if (rec.addr.address !== meta.address) {
        this.log.error('sd', `instance conflict: svc=${e.svc_id} inst=${e.inst_id} recorded@${rec.addr.address} vs ${meta.address}, keep first`);
        return;
      }
      // 常规刷新：实例发现缓存 TTL 重置（实例级维护，与订阅 TTL 无关，§7.4/§7.5）
      rec.ttlLeft = e.ttl;
      rec.state = 'Active';
      rec.major_ver = e.major_ver;
      rec.minor_ver = e.minor_ver;
      rec.ver = ver;
      if (rec.clientState === CLIENT_STATE.EXPIRED || rec.clientState === CLIENT_STATE.UNKNOWN) {
        this._transitionFound(rec);
      }
      return;
    }
    // Unknown → Found：加入注册表，启动 TTL 倒计时（§7.4）
    const fresh = {
      svc_id: e.svc_id, inst_id: e.inst_id,
      major_ver: e.major_ver, minor_ver: e.minor_ver,
      addr: { address: meta.address, port: meta.port },
      ver, ttlLeft: e.ttl, state: 'Active',
      clientState: CLIENT_STATE.UNKNOWN,
    };
    this.discovered.set(key, fresh);
    this._transitionFound(fresh);
  }

  /** 状态迁移 → Found；触发 pending 订阅登记自动发起（§7.4） */
  _transitionFound(rec) {
    rec.clientState = CLIENT_STATE.FOUND;
    this.emit('instanceFound', rec);
    this._tryPendingSessions(rec);
    this._resolvePendingFind(rec);
  }

  /** 实例 Expired：Subscribed 保留订阅登记供自动重订阅（§7.4） */
  _onInstanceExpired(rec) {
    const prev = rec.clientState;
    rec.clientState = CLIENT_STATE.EXPIRED;
    // 该实例的活跃订阅会话 → 停保活、释放会话 StrmID、登记转 pending（§7.4 自动重订阅）
    for (const session of this.sessions.values()) {
      if (session.svc_id === rec.svc_id && session.inst_id === rec.inst_id &&
          (session.state === 'active' || session.state === 'establishing')) {
        this._pauseSession(session);
      }
    }
    if (prev === CLIENT_STATE.SUBSCRIBED || prev === CLIENT_STATE.FOUND) {
      this.emit('instanceExpired', rec);
    }
  }

  _resolvePendingFind(rec) {
    const waiters = this.pendingFind.get(`${rec.svc_id}:${rec.inst_id}`);
    if (waiters) {
      for (const w of waiters) {
        clearTimeout(w.timer);
        w.resolve({ address: rec.addr.address, port: rec.addr.port, major_ver: rec.major_ver, minor_ver: rec.minor_ver });
      }
      this.pendingFind.delete(`${rec.svc_id}:${rec.inst_id}`);
    }
  }

  /** 查询发现缓存（Found 且 Active 视为可用） */
  getDiscovered(svcId, instId) {
    const rec = this.discovered.get(`${svcId}:${instId}`);
    return rec && rec.state === 'Active' && rec.clientState !== CLIENT_STATE.EXPIRED ? rec : null;
  }

  /** 该 svc 的任一在线实例版本（注册场景自动 GetIDL 的 MajorVer 取值，§7.2 双角色） */
  onlineMajorVer(svcId) {
    for (const rec of this.discovered.values()) {
      if (rec.svc_id === svcId && rec.state === 'Active') return rec.major_ver;
    }
    return null;
  }

  /** is_available（§13.2）：注册表存在 + TTL Active + VER 相等 */
  isAvailable(svcId, instId) {
    const rec = this.getDiscovered(svcId, instId);
    return !!rec && rec.ver === this.cfg.ver;
  }

  /**
   * find_service（§13.2）：主动发现，返回在线信息（源地址/版本，不返回接口列表）。
   * 先查缓存命中直接返回；否则发 Find（组播）等待 Offer。
   */
  async findService(svcId, instId, timeoutMs) {
    const rec = this.getDiscovered(svcId, instId);
    if (rec) {
      return { address: rec.addr.address, port: rec.addr.port, major_ver: rec.major_ver, minor_ver: rec.minor_ver };
    }
    // 发 Find（组播；带 Entry 指定 SvcID，InstID 通配或精确）
    const frame = {
      ctr: 1, typ: TYP.NON, code: CODE.SD_FIND,
      svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0,
      payload: encodeFindEntries([{ svc_id: svcId, inst_id: instId ?? 0, major_ver: 0 }]),
    };
    this.ctx.sendMulticastFrame(frame, 'client');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const waiters = this.pendingFind.get(`${svcId}:${instId}`);
        if (waiters) {
          const i = waiters.indexOf(w);
          if (i >= 0) waiters.splice(i, 1);
          if (waiters.length === 0) this.pendingFind.delete(`${svcId}:${instId}`);
        }
        reject(new ServiceNotFound(`find_service(${svcId},${instId}) timeout`));
      }, timeoutMs ?? this.cfg.response_timeout_ms);
      const w = { resolve, reject, timer };
      const list = this.pendingFind.get(`${svcId}:${instId}`) ?? [];
      list.push(w);
      this.pendingFind.set(`${svcId}:${instId}`, list);
    });
  }

  // ============================================================
  // 客户端角色：订阅会话（§7.2 会话 StrmID 规则 / §8.1 确认链路）
  // ============================================================

  /**
   * subscribe：登记订阅意图并立即返回 handle（§13.2）。
   * 实例未 Found 时仅登记，Found 后协议栈自动发起 Subscribe（§7.4）。
   */
  subscribe(svcId, instId, opts, onEvent) {
    const handle = ++this._handleSeq;
    const session = {
      handle, svc_id: svcId, inst_id: instId,
      if_id: opts.if_id ?? 0, grp_id: opts.grp_id ?? 0,
      onEvent, state: 'pending', // pending → establishing → active
      peer: null, addr: null, sessionStrm: 0,
      keepaliveTimer: null, retransKey: null,
    };
    this.sessions.set(handle, session);
    const rec = this.getDiscovered(svcId, instId);
    if (rec) this._startSession(session, rec); // 已 Found：立即发起
    return handle;
  }

  /** 实例 Found 时尝试发起全部 pending 会话（自动订阅/重订阅，§7.4） */
  _tryPendingSessions(rec) {
    for (const session of this.sessions.values()) {
      if (session.svc_id === rec.svc_id && session.inst_id === rec.inst_id && session.state === 'pending') {
        this._startSession(session, rec);
      }
    }
  }

  /** 发起 Subscribe（首次 CON，分配新会话 StrmID，§7.2/§8.1） */
  _startSession(session, rec) {
    session.addr = { ...rec.addr };
    session.peer = `${rec.addr.address}:${rec.addr.port}`;
    // 分配会话 StrmID（控制帧按 peer 统一池，§6.3）
    const strm = this.strm.allocControlStrm(session.peer);
    if (strm === null) {
      this.log.error('sd', `control StrmID pool exhausted for ${session.peer}`);
      this.emit('subscribeError', session, new Error('control StrmID pool exhausted'));
      return;
    }
    session.sessionStrm = strm;
    session.state = 'establishing';
    // 注册会话索引：0x10 确认 / RST 按 (peer, StrmID) 匹配会话（§8.1）
    this._registerSessionIndex(session);
    this._sendSubscribe(session, true);
  }

  /** 发送 Subscribe 帧（首次/重传 CON；保活 NON；取消 CON TTL=0，§7.2） */
  _sendSubscribe(session, isInitial) {
    const ttl = this.ttlSeconds();
    const frame = {
      ctr: 1,
      typ: isInitial ? TYP.CON : TYP.NON,
      code: CODE.SD_SUBSCRIBE,
      svc_id: 0, if_id: 0, inst_id: 0, strm_id: session.sessionStrm,
      payload: encodeSubscribeEntries([{
        svc_id: session.svc_id, if_id: session.if_id, inst_id: session.inst_id,
        grp_id: session.grp_id, ttl,
      }]),
    };
    const raw = encodeFrame(frame);
    this.log.debug('sd', `Subscribe Tx: peer=${session.peer} strm=${session.sessionStrm} ttl=${ttl}s initial=${isInitial}`);
    this.ctx.sendUdpRaw(raw, session.addr.address, session.addr.port, 'client');
    if (frame.typ === TYP.CON) {
      // 首次/取消 CON 走重传（§5.5 重传范围）；确认到达或耗尽停止
      const key = `ctrl-sub|${session.peer}|${session.sessionStrm}`;
      session.retransKey = key;
      this._retrans.start(key, raw, (buf) => this.ctx.sendUdpRaw(buf, session.addr.address, session.addr.port, 'client'));
    }
  }

  /** 保活定时器：周期发送 Subscribe(NON, TTL>0)，同会话 StrmID（§7.2） */
  _startKeepalive(session) {
    this._stopKeepalive(session);
    session.keepaliveTimer = setInterval(() => {
      if (session.state === 'active') this._sendSubscribe(session, false);
    }, this.cfg.period_ms);
    session.keepaliveTimer.unref?.();
  }

  _stopKeepalive(session) {
    if (session.keepaliveTimer) { clearInterval(session.keepaliveTimer); session.keepaliveTimer = null; }
  }

  /** 实例 Expired 时暂停会话：停保活、释放会话 StrmID、登记转 pending（§7.4） */
  _pauseSession(session) {
    this._stopKeepalive(session);
    if (session.retransKey) { this._retrans.cancel(session.retransKey); session.retransKey = null; }
    if (session.sessionStrm) {
      this.strm.releaseControlStrm(session.peer, session.sessionStrm);
      this.sessionIndex.delete(`${session.peer}|${session.sessionStrm}`);
      session.sessionStrm = 0;
    }
    session.state = 'pending'; // 保留登记，重新 Found 后自动重订阅（§7.4）
  }

  /** 收到订阅确认 ACK(Code=0x10)（§8.1）：取消重传，Found→Subscribed */
  onSubscribeAck(frame, meta) {
    const peer = `${meta.address}:${meta.port}`;
    const idx = `${peer}|${frame.strm_id}`;
    const session = this.sessionIndex.get(idx);
    if (!session) return; // 非活跃会话 StrmID 的迟到确认 → 丢弃（§3.6）
    if (session.retransKey) { this._retrans.cancel(session.retransKey); session.retransKey = null; }
    if (session.state === 'establishing') {
      session.state = 'active'; // Subscribed
      this._startKeepalive(session);
      this.log.info('sd', `subscribe established: svc=${session.svc_id} inst=${session.inst_id} strm=0x${session.sessionStrm.toString(16)}`);
    }
    // 重复 0x10（重传后补到）：忽略即可
  }

  /** 收到取消确认 ACK(Code=0x00)（§8.1）：释放会话 StrmID */
  onUnsubscribeAck(frame, meta) {
    const peer = `${meta.address}:${meta.port}`;
    const idx = `${peer}|${frame.strm_id}`;
    const cp = this.cancelPending.get(idx);
    if (cp) {
      this._retrans.cancel(cp.retransKey);
      this.strm.releaseControlStrm(peer, frame.strm_id);
      this.cancelPending.delete(idx);
      this.log.info('sd', `unsubscribe confirmed: peer=${peer} strm=0x${frame.strm_id.toString(16)}`);
    }
  }

  /** 收到控制帧 RST（订阅被拒 / GetIDL 失败）：按回显 StrmID 匹配（§5.4） */
  onControlRst(frame, meta) {
    const peer = `${meta.address}:${meta.port}`;
    const idx = `${peer}|${frame.strm_id}`;
    // 1) 订阅会话被拒（6.19）：停止重传、释放会话 StrmID、停留 Found、报订阅失败
    const session = this.sessionIndex.get(idx);
    if (session && session.state === 'establishing') {
      if (session.retransKey) { this._retrans.cancel(session.retransKey); session.retransKey = null; }
      this.strm.releaseControlStrm(peer, frame.strm_id);
      this.sessionIndex.delete(idx);
      session.sessionStrm = 0;
      session.state = 'pending'; // 登记保留（等待重试时机，§7.4）
      this.emit('subscribeError', session, new GetIdlError(`subscribe rejected: RST(0x${frame.code.toString(16)})`));
      return;
    }
    // 2) GetIDL 查询失败（0x24/0x20）→ 查询失败上抛（§7.2）
    const p = this.pendingIdl.get(idx);
    if (p) {
      clearTimeout(p.timer);
      this.pendingIdl.delete(idx);
      this.strm.releaseControlStrm(peer, frame.strm_id);
      p.reject(new GetIdlError(`GetIDL failed: RST(0x${frame.code.toString(16)}) ${RST_NAME[frame.code] ?? ''}`, frame.code));
    }
  }

  /**
   * unsubscribe（§13.2）：发 Subscribe(TTL=0)（CON）等待 ACK(0x00)；
   * 应用视角立即完成（登记删除），服务端订阅靠 TTL 自愈兜底。
   */
  unsubscribe(handle) {
    const session = this.sessions.get(handle);
    if (!session) return false;
    this.sessions.delete(handle); // 登记清除条件①：显式 unsubscribe（§7.4）
    session.state = 'pending';    // 会话转非活跃（取消确认 ACK(0x00) 后由 onUnsubscribeAck 释放 StrmID，§8.1 场景4）
    this._stopKeepalive(session);
    if (session.retransKey) { this._retrans.cancel(session.retransKey); session.retransKey = null; }
    if (session.sessionStrm && session.addr) {
      const idx = `${session.peer}|${session.sessionStrm}`;
      this.sessionIndex.delete(idx);
      // 发送取消（TTL=0, CON，同会话 StrmID，§8.1 场景4）
      const frame = {
        ctr: 1, typ: TYP.CON, code: CODE.SD_SUBSCRIBE,
        svc_id: 0, if_id: 0, inst_id: 0, strm_id: session.sessionStrm,
        payload: encodeSubscribeEntries([{
          svc_id: session.svc_id, if_id: session.if_id, inst_id: session.inst_id,
          grp_id: session.grp_id, ttl: 0,
        }]),
      };
      const raw = encodeFrame(frame);
      this.ctx.sendUdpRaw(raw, session.addr.address, session.addr.port, 'client');
      const key = `ctrl-unsub|${session.peer}|${session.sessionStrm}`;
      this.cancelPending.set(idx, { retransKey: key });
      this._retrans.start(key, raw, (buf) => this.ctx.sendUdpRaw(buf, session.addr.address, session.addr.port, 'client'));
      // 重传耗尽兜底：释放取消等待（服务端靠订阅 TTL 过期自愈）
      setTimeout(() => {
        if (this.cancelPending.get(idx)?.retransKey === key) {
          this._retrans.cancel(key);
          this.strm.releaseControlStrm(session.peer, session.sessionStrm);
          this.cancelPending.delete(idx);
        }
      }, this.cfg.retransmit_interval_ms * (2 ** (this.cfg.retransmit_max + 1)) + 100).unref?.();
    }
    return true;
  }

  // ============================================================
  // GetIDL 客户端（§7.2：协议栈内部行为，双角色统一）
  // ============================================================

  /**
   * 自动拉取服务 IDL：发现缓存无在线实例不查询直接失败（§7.2 触发条件）。
   * 同一 (SvcID, MajorVer) 并发首调合并为单次查询（实现建议，§7.2）。
   * @returns {Promise<{schema, jsonText}>}
   */
  async fetchIdl(svcId, majorVer) {
    const inflightKey = `${svcId}:${majorVer}`;
    if (this.idlInflight.has(inflightKey)) return this.idlInflight.get(inflightKey);
    const p = this._fetchIdlOnce(svcId, majorVer).finally(() => this.idlInflight.delete(inflightKey));
    this.idlInflight.set(inflightKey, p);
    return p;
  }

  async _fetchIdlOnce(svcId, majorVer) {
    // 1. 查 SD 发现缓存：存在该服务在线实例 → 向其发起 GetIDL（§7.2）
    let target = null;
    for (const rec of this.discovered.values()) {
      if (rec.svc_id === svcId && rec.state === 'Active') { target = rec; break; }
    }
    if (!target) {
      // 发现缓存无在线实例 → 不发起查询，当前操作直接失败（§7.2）
      throw new ServiceNotFound(`GetIDL aborted: svc=${svcId} has no online instance in discovery cache`);
    }
    // §7.2（v4.4 定案）：查询失败（超时/RST/连接断开）一律上抛当前操作（调用/订阅/注册），
    // 由应用决定重试——协议栈不自动重发（与 MoonBit 版 getidl.mbt 行为一致）
    return await this._doGetIdl(target, svcId, majorVer);
  }

  async _doGetIdl(rec, svcId, majorVer) {
    const peer = `${rec.addr.address}:${rec.addr.port}`;
    const strm = this.strm.allocControlStrm(peer);
    if (strm === null) throw new GetIdlError('control StrmID pool exhausted');
    // TCP 单播（复用 §5.6 连接策略，与 rpc/tcp-event 共用同一条长连接，§7.2）
    let conn;
    try {
      conn = await this.ctx.getTcpConn(rec.addr.address, rec.addr.port);
    } catch (e) {
      this.strm.releaseControlStrm(peer, strm);
      throw new GetIdlError(`GetIDL tcp connect failed: ${e.message}`);
    }
    // 请求帧：CTR=1, TYP=NON, Code=0x04, StrmID=栈内分配, Payload=3B Entry（§7.2）
    const frame = {
      ctr: 1, typ: TYP.NON, code: CODE.SD_GET_IDL,
      svc_id: 0, if_id: 0, inst_id: 0, strm_id: strm,
      payload: encodeGetIdlEntry({ svc_id: svcId, major_ver: majorVer }),
    };
    const idx = `${peer}|${strm}`;
    const p = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pendingIdl.get(idx) === waiter) {
          this.pendingIdl.delete(idx);
          this.strm.releaseControlStrm(peer, strm);
          // 超时：释放/冷却，查询失败上抛当前操作（§7.2 v4.4 定案：由应用决定重试）
          reject(new GetIdlError(`GetIDL timeout (svc=${svcId})`));
        }
      }, this.cfg.response_timeout_ms);
      const waiter = { resolve, reject: (e) => { clearTimeout(timer); reject(e); }, timer };
      this.pendingIdl.set(idx, waiter);
    });
    conn.write(frame);
    try {
      const jsonText = await p;
      // 响应校验：IDL 自含 svc_id/major_ver 须与请求一致（§7.2，落盘前校验）
      let idl;
      try { idl = JSON.parse(jsonText.toString('utf8')); } catch (e) {
        throw new GetIdlError(`GetIDL response is not valid JSON: ${e.message}`);
      }
      const svc = idl?.service;
      if (!svc || svc.svc_id !== svcId || svc.major_ver !== majorVer) {
        // 不一致按查询失败处理（IDL 库状态不变，§7.2/§11.1）
        throw new GetIdlError(`GetIDL response mismatch: got svc=${svc?.svc_id} v${svc?.major_ver}, want ${svcId} v${majorVer}`);
      }
      // 落盘持久化 → 解析加载（落盘失败降级内存由 idlStore.save 内处理，§7.2）
      await this.idlStore.save(svcId, majorVer, jsonText.toString('utf8'));
      const entry = this.idlStore.get(svcId, majorVer);
      return { schema: entry.schema, jsonText: entry.jsonText };
    } finally {
      this.pendingIdl.delete(idx);
      this.strm.releaseControlStrm(peer, strm); // 收到响应/超时后释放/冷却（§6.1）
    }
  }

  /** 收到 GetIDL 响应 0x11（回显 StrmID，§7.2） */
  onGetIdlResponse(frame, meta) {
    const idx = `${meta.address}:${meta.port}|${frame.strm_id}`;
    const p = this.pendingIdl.get(idx);
    if (!p) return; // 非活跃查询 StrmID 的迟到响应 → 静默丢弃（§3.6）
    this.pendingIdl.delete(idx);
    p.resolve(frame.payload);
  }

  /** TCP 连接断开：该对端 pending GetIDL 查询立即失败（§7.2；响应超时兜底冗余，对齐 MoonBit 版） */
  onTcpClosed(ip) {
    for (const key of [...this.pendingIdl.keys()]) {
      if (key.startsWith(`${ip}:`)) {
        const w = this.pendingIdl.get(key);
        clearTimeout(w?.timer);
        this.pendingIdl.delete(key);
        w?.reject?.(new GetIdlError(`GetIDL aborted: tcp connection closed (peer ${ip})`));
      }
    }
  }

  // ============================================================
  // 收到 REN=1（§3.6）：清除该节点所有服务缓存与订阅登记
  // ============================================================

  onRen(meta) {
    const ip = meta.address;
    this.log.info('sd', `REN received from ${ip}: clearing caches`);
    // 1) 发现缓存：清除该源 IP 的所有实例（§3.6）
    for (const [key, rec] of [...this.discovered]) {
      if (rec.addr.address === ip) {
        this.discovered.delete(key);
        // 订阅登记清除条件②：对端 REN → 登记同步清除，不自动重订阅（§7.4/6.13）
        for (const [h, s] of [...this.sessions]) {
          if (s.svc_id === rec.svc_id && s.inst_id === rec.inst_id) {
            this._stopKeepalive(s);
            if (s.retransKey) this._retrans.cancel(s.retransKey);
            if (s.sessionStrm) {
              this.strm.releaseControlStrm(s.peer, s.sessionStrm);
              this.sessionIndex.delete(`${s.peer}|${s.sessionStrm}`);
            }
            this.sessions.delete(h);
          }
        }
      }
    }
    // 2) 服务端：清除该对端订阅登记（§3.6）
    for (const [key, s] of [...this.subs]) {
      if (s.peerIp === ip) this.subs.delete(key);
    }
    // 3) 确认缓存 / 取消等待清理
    for (const key of [...(this._ackCache?.keys() ?? [])]) {
      if (key.startsWith(`${ip}:`)) this._ackCache.delete(key);
    }
  }

  /** 每秒 tick（§7.5）：远端实例 TTL 与服务端订阅表 TTL 推进 */
  tick() {
    // 发现缓存：Active 递减归零 → Expired；Expired 本次 tick 删除（§7.5）
    for (const [key, rec] of [...this.discovered]) {
      if (rec.state === 'Expired') {
        this.discovered.delete(key);
        continue;
      }
      rec.ttlLeft -= 1;
      if (rec.ttlLeft <= 0) {
        rec.state = 'Expired';
        this._onInstanceExpired(rec); // Found/Subscribed → Expired（§7.4）
      }
    }
    this._tickSubs();
  }

  startTick() {
    this.stopTick();
    this._tickTimer = setInterval(() => this.tick(), 1000); // tick 固定 1s（§7.5）
    this._tickTimer.unref?.();
  }

  stopTick() {
    if (this._tickTimer) { clearInterval(this._tickTimer); this._tickTimer = null; }
  }

  /** 注册会话索引（0x10/RST 按 (peer,strm) 匹配） */
  _registerSessionIndex(session) {
    if (session.peer && session.sessionStrm) {
      this.sessionIndex.set(`${session.peer}|${session.sessionStrm}`, session);
    }
  }

  /** 停止：清定时器与状态（graceful shutdown 的资源释放阶段） */
  stop() {
    this.stopOfferLoop();
    this.stopTick();
    for (const s of this.sessions.values()) this._stopKeepalive(s);
    this.sessions.clear();
    this.sessionIndex.clear();
    this.cancelPending.clear();
    this.pendingFind.clear();
    this.pendingIdl.clear();
    this.subs.clear();
    this.locals.clear();
    this.discovered.clear();
  }
}

// ---- 工具 ----
function schemaMajor(schema) { return schema.majorVer ?? 0; }
function schemaMinor(schema) { return schema.minorVer ?? 0; }

/** Offer Entry 拆帧（§7.2：按 max_payload_len 满装拆分，Entry 粒度 = (SvcID, InstID)） */
export function buildOfferFrames(entries, maxPayloadLen) {
  const maxEntries = Math.max(1, Math.floor(maxPayloadLen / 6));
  const frames = [];
  for (let i = 0; i < entries.length; i += maxEntries) {
    const chunk = entries.slice(i, i + maxEntries);
    frames.push({
      ctr: 1, typ: TYP.NON, code: CODE.SD_OFFER,
      svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0, // 连接级帧 StrmID=0（§4.3 步骤 4）
      payload: encodeOfferEntries(chunk),
    });
  }
  return frames;
}

function frameCount(entries, maxPayloadLen) {
  const maxEntries = Math.max(1, Math.floor(maxPayloadLen / 6));
  return Math.ceil(entries.length / maxEntries);
}
