// ============================================================
// events.js —— §8 事件推送（Notifier）/ §5.3 Notification 传输语义
//
// 服务端：notify（更新接口缓存 + 分发）/ 全量推送（订阅从无到有，§8.1）/
//         tcp-event 按订阅者源 IP 匹配连接推送（§8.2）/ CON 推送重传
// 客户端：onNotification 交付（UDP CON 回 ACK + 接收记录去重，§8.2）/
//         订阅会话匹配（单接口 + 组订阅展开，§7.1）
// ============================================================

import { EventEmitter } from 'node:events';
import { TYP, CODE, encodeFrame } from '../frame/frame.js';
import { RetransmitTable } from '../rpc/retransmit.js';
import { ServiceNotFound, InvalidArgument } from '../errors.js';

// 接收记录保留时长：≥ 重传窗口（3s）+ 单向延迟余量（§8.2）
const RECV_RECORD_TTL_MS = 4000;

export class EventsModule extends EventEmitter {
  /**
   * @param {object} ctx {
   *   config, log, strm, idlStore, discovery,
   *   sendUdpFrame(f, addr, port, from), sendUdpRaw(buf, addr, port, from),
   *   findServerConnByIp(ip),
   * }
   */
  constructor(ctx) {
    super();
    this.ctx = ctx;
    this.cfg = ctx.config;
    this.log = ctx.log;
    this.strm = ctx.strm;
    this.discovery = ctx.discovery;
    this.idlStore = ctx.idlStore;

    this._notifyCache = new Map();  // `${svc}:${inst}:${ifId}` → Buffer（接口缓存，§8.1 全量推送数据源）
    this._pushRetrans = new RetransmitTable({ // 推送 CON 重传（与 rpc 重传表独立，键格式同 (peer,svc,inst,strm)）
      intervalMs: this.cfg.retransmit_interval_ms,
      maxRetry: this.cfg.retransmit_max,
    });
    this._pushPending = new Map();  // `${peer}|${svc}|${inst}|${strm}` → CON 推送活跃记录（ACK/RST 匹配释放）
    this._recvRecords = new Map();  // `${peer}|${svc}|${inst}|${strm}` → 时间戳（接收记录去重，§8.2）
  }

  // ============================================================
  // 服务端（§13.1 notify）
  // ============================================================

  /** notify（§13.1）：更新接口缓存并推送给所有订阅者 */
  notify(svcId, instId, ifId, payload) {
    const rec = this.discovery.getLocal(svcId, instId);
    if (!rec) throw new ServiceNotFound(`instance ${svcId}:${instId} not registered`);
    const iface = rec.schema.getInterface(ifId);
    if (!iface || iface.type !== 'event') {
      throw new InvalidArgument(`if_id 0x${ifId.toString(16)} is not an event interface of svc=${svcId}`);
    }
    const buf = rec.schema.encodePayload(iface, 'output', payload); // 事件 payload 定义在 output 方向（§11.1）
    // 更新接口缓存（后续订阅者的全量推送取此数据，§8.1）
    this._notifyCache.set(`${svcId}:${instId}:${ifId}`, buf);
    // 分发给所有订阅者（单接口订阅 + 组订阅展开，§8.2）
    for (const sub of this.discovery.subscribersOf(svcId, instId, ifId)) {
      this._pushToOne(sub, svcId, instId, iface, buf);
    }
  }

  /** 全量推送钩子（订阅记录从无到有，纯数据分发非确认信号，§8.1） */
  onSubscriptionAdded({ meta, entries }) {
    for (const e of entries) {
      if (e.if_id !== 0) {
        this._pushCached(e.svc_id, e.inst_id, e.if_id, meta);
      } else if (e.grp_id !== 0) {
        // 组订阅：展开为组内所有 event 接口（§7.1/§8.1）
        for (const ifId of this.discovery._groupMembers(e.svc_id, e.grp_id)) {
          this._pushCached(e.svc_id, e.inst_id, ifId, meta);
        }
      }
    }
  }

  /** 推送某接口的缓存数据给订阅者（无缓存 = 应用未 notify 过 → 不推送） */
  _pushCached(svcId, instId, ifId, meta) {
    const buf = this._notifyCache.get(`${svcId}:${instId}:${ifId}`);
    if (!buf) return;
    const rec = this.discovery.getLocal(svcId, instId);
    const iface = rec?.schema.getInterface(ifId)
      ?? this.idlStore.getHighest(svcId)?.schema.getInterface(ifId);
    if (!iface || iface.type !== 'event') return;
    this._pushToOne({ peerIp: meta.address, peerPort: meta.port }, svcId, instId, iface, buf);
  }

  /**
   * 向单个订阅者推送一帧 Notification（§5.3/§8.2）：
   *   tcp-event：按源 IP 匹配活跃连接（TYP=NON）；断连期间推送暂停不补发，重连自动恢复
   *   UDP reliable：TYP=CON（重传保证送达）｜UDP 常规：TYP=NON（尽力而为）
   */
  _pushToOne(sub, svcId, instId, iface, buf) {
    const peer = `${sub.peerIp}:${sub.peerPort}`;
    const strm = this.strm.allocServerStream(peer, svcId, instId); // 每客户端独立 StrmID（§8.2）
    if (strm === null) {
      this.log.error('events', `server StrmID pool exhausted for ${peer}, push skipped`);
      return;
    }

    if (iface.transport === 'tcp') {
      const conn = this.ctx.findServerConnByIp?.(sub.peerIp);
      if (!conn) {
        // 断连期间推送暂停（订阅记录保留，重连后自动恢复，§8.2/§12.3）
        this.strm.releaseServerStream(peer, svcId, instId, strm);
        this.log.warn('events', `tcp-event push paused (no connection from ${sub.peerIp})`);
        return;
      }
      conn.write({
        ctr: 0, typ: TYP.NON, code: CODE.NOTIFICATION,
        svc_id: svcId, if_id: iface.if_id, inst_id: instId, strm_id: strm, payload: buf,
      });
      this.strm.releaseServerStream(peer, svcId, instId, strm); // TCP 自带可靠性，发完即释放
      return;
    }

    if (iface.reliable) {
      // UDP 可靠事件：TYP=CON，客户端回 ACK，超时重传（§5.3/§5.5）
      const raw = encodeFrame({
        ctr: 0, typ: TYP.CON, code: CODE.NOTIFICATION,
        svc_id: svcId, if_id: iface.if_id, inst_id: instId, strm_id: strm, payload: buf,
      });
      const key = `${peer}|${svcId}|${instId}|${strm}`;
      this._pushPending.set(key, { peer, svcId, instId, strm });
      const sendFn = (b) => this.ctx.sendUdpRaw(b, sub.peerIp, sub.peerPort, 'main');
      sendFn(raw);
      this._pushRetrans.start(key, raw, sendFn);
      // 重传耗尽兜底释放（无回调 → 定时器兜底；ACK 到达时提前释放）
      setTimeout(() => {
        if (this._pushPending.get(key)?.strm === strm) {
          this._pushRetrans.cancel(key);
          this.strm.releaseServerStream(peer, svcId, instId, strm);
          this._pushPending.delete(key);
        }
      }, this._pushRetrans.intervalMs * 2 ** (this._pushRetrans.maxRetry + 1) + 200).unref?.();
    } else {
      // UDP 常规事件：TYP=NON 尽力投递，无 ACK（§5.3）
      this.ctx.sendUdpFrame({
        ctr: 0, typ: TYP.NON, code: CODE.NOTIFICATION,
        svc_id: svcId, if_id: iface.if_id, inst_id: instId, strm_id: strm, payload: buf,
      }, sub.peerIp, sub.peerPort, 'main');
      this.strm.releaseServerStream(peer, svcId, instId, strm);
    }
  }

  /** 收到数据帧 ACK：CON 推送的传输确认 → 停重传 + 释放服务端流（§5.5/§6.2） */
  onAck(frame, meta) {
    const key = `${meta.address}:${meta.port}|${frame.svc_id}|${frame.inst_id}|${frame.strm_id}`;
    const rec = this._pushPending.get(key);
    if (rec) {
      this._pushRetrans.cancel(key);
      this.strm.releaseServerStream(rec.peer, rec.svcId, rec.instId, rec.strm);
      this._pushPending.delete(key);
    }
  }

  /** 收到数据帧 RST（推送被拒 §5.4）：释放该推送流 */
  onDataRst(frame, meta) {
    const key = `${meta.address}:${meta.port}|${frame.svc_id}|${frame.inst_id}|${frame.strm_id}`;
    const rec = this._pushPending.get(key);
    if (rec) {
      this._pushRetrans.cancel(key);
      this.strm.releaseServerStream(rec.peer, rec.svcId, rec.instId, rec.strm);
      this._pushPending.delete(key);
      this.log.frame('warn', {
        svc_id: frame.svc_id, if_id: frame.if_id, inst_id: frame.inst_id, strm_id: frame.strm_id,
        dir: 'Rx', addr: `${meta.address}:${meta.port}`, code: frame.code,
        msg: 'notification rejected (push stream released)',
      });
    }
  }

  // ============================================================
  // 客户端接收（§5.3/§8.2）
  // ============================================================

  /** 收到 Notification（CTR=0, Code=0x03）→ 匹配订阅会话并交付 */
  async onNotification(frame, meta) {
    const peer = `${meta.address}:${meta.port}`;
    const key = `${peer}|${frame.svc_id}|${frame.inst_id}|${frame.strm_id}`;

    // UDP CON：回 ACK（重复 CON 到达仍须回 ACK）+ 接收记录去重（仅交付首个，§8.2）
    if (meta.transport === 'udp' && frame.typ === TYP.CON) {
      this.ctx.sendUdpFrame({
        ctr: 0, typ: TYP.ACK, code: 0x00,
        svc_id: frame.svc_id, if_id: frame.if_id, inst_id: frame.inst_id, strm_id: frame.strm_id,
      }, meta.address, meta.port, 'client');
      if (this._recvRecords.has(key)) return; // 重复帧：不重复交付
      this._recvRecords.set(key, Date.now());
      const t = setTimeout(() => this._recvRecords.delete(key), RECV_RECORD_TTL_MS);
      t.unref?.();
    }

    // 匹配本地订阅会话（§7.4：0x10 前到达的事件按容错交付，不筛会话状态）
    const matched = [];
    for (const session of this.discovery.sessions.values()) {
      if (session.svc_id !== frame.svc_id || session.inst_id !== frame.inst_id) continue;
      if (session.if_id === frame.if_id) {
        matched.push(session);
      } else if (session.if_id === 0 && session.grp_id !== 0) {
        // 组订阅：帧 if_id ∈ 组成员（§7.1）
        const members = this._eventGroupMembers(frame.svc_id, session.grp_id);
        if (members.includes(frame.if_id)) matched.push(session);
      }
    }
    if (matched.length === 0) {
      this.log.debug('events', `notification for unsubscribed svc=${frame.svc_id} if=0x${frame.if_id.toString(16)}, dropped`);
      return;
    }

    // 解码（事件 payload 定义在 IDL output 方向，§11.1）
    const schema = await this._ensureSchema(frame.svc_id);
    if (!schema) return; // IDL 不可得：丢弃 + Error 日志（§7.2）
    const iface = schema.getInterface(frame.if_id);
    if (!iface) return;
    let payload;
    try {
      payload = schema.decodePayload(iface, 'output', frame.payload);
    } catch (e) {
      this.log.error('events', `notification decode failed if=0x${frame.if_id.toString(16)}: ${e.message}`);
      return;
    }
    // 交付（每个匹配会话独立回调，§8.2）
    for (const session of matched) {
      try {
        session.onEvent?.(payload);
      } catch (e) {
        this.log.error('events', `on_event callback error: ${e.message}`);
      }
    }
  }

  /** 事件组成员查询（本地库定义，§7.1） */
  _eventGroupMembers(svcId, grpId) {
    for (const entry of this.idlStore.allEntries()) {
      if (entry.schema.svcId === svcId) return entry.schema.eventGroups.get(grpId) ?? [];
    }
    return [];
  }

  /** 客户端侧惰性确保 schema（订阅时已尽力预拉，此处兜底，§7.2） */
  async _ensureSchema(svcId) {
    let entry = this.idlStore.getHighest(svcId);
    if (entry) return entry.schema;
    // 库中无该服务定义：查发现缓存在线实例 → 自动拉取（无在线实例不查询，§7.2）
    let rec = null;
    for (const r of this.discovery.discovered.values()) {
      if (r.svc_id === svcId && r.state === 'Active') { rec = r; break; }
    }
    if (!rec) return null;
    try {
      const fetched = await this.discovery.fetchIdl(svcId, rec.major_ver);
      return fetched.schema;
    } catch (e) {
      this.log.error('events', `auto GetIDL failed for svc=${svcId}: ${e.message}`);
      return null;
    }
  }

  /** 收到 REN=1：清该对端推送重传/活跃记录/接收记录（§3.6） */
  onRen(ip) {
    const prefix = `${ip}:`;
    this._pushRetrans.clearPeer(prefix);
    for (const key of [...this._pushPending.keys()]) {
      if (key.startsWith(prefix)) {
        const rec = this._pushPending.get(key);
        this.strm.releaseServerStream(rec.peer, rec.svcId, rec.instId, rec.strm);
        this._pushPending.delete(key);
      }
    }
    for (const key of [...this._recvRecords.keys()]) {
      if (key.startsWith(prefix)) this._recvRecords.delete(key);
    }
  }

  /** 停止清理 */
  stop() {
    this._pushRetrans.clearPeer('');
    this._pushPending.clear();
    this._recvRecords.clear();
    this._notifyCache.clear();
  }
}
