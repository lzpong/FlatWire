// ============================================================
// rpc.js —— §5.1 Request-Response / §5.2 Fire-Forget
//
// 客户端：call / call_async / fire_forget
//   - 发送前确保发现缓存与 IDL 就绪（拉取发生在发送前，§5.1/§7.2）
//   - TCP：TYP=NON，无重传（§3.7/§5.6）；UDP：TYP=CON + 重传时间线（§5.5）
//   - 应用层响应超时（§1.3）：收到 Response 取消，并一并取消该 StrmID 的待确认重传
// 服务端：onRequest / onFireForget
//   - 响应缓存去重（§5.5）：重复 CON Request → 重发缓存响应，处理逻辑仅执行 1 次
//   - 未知服务/接口 → RST(0x24)；类型不支持 → RST(0x25)；IDL 级解码失败 → RST(0x20)；
//     处理异常 → RST(0x30)（§5.4/§12.1）
// ============================================================

import { EventEmitter } from 'node:events';
import { TYP, CODE, encodeFrame, makeRst } from '../frame/frame.js';
import { RetransmitTable } from './retransmit.js';
import {
  RST_CODE, RST_NAME, RequestTimeout, ServiceNotFound, InvalidArgument, FwError, DecodeError,
} from '../errors.js';

export class RpcModule extends EventEmitter {
  /**
   * @param {object} ctx {
   *   config, log, strm, idlStore, discovery,
   *   sendUdpFrame(f, addr, port, from), sendUdpRaw(buf, addr, port, from),
   *   getTcpConn(addr, port),
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

    // UDP CON 重传表（请求 CON / 响应 CON 共用，键 (peer,svc,inst,strm) 不冲突：
    // 同进程双角色与不同对端通信时 peer 必不相同，§5.5）
    this._retrans = new RetransmitTable({
      intervalMs: this.cfg.retransmit_interval_ms,
      maxRetry: this.cfg.retransmit_max,
    });
    this._pending = new Map();   // `${peer}|${svc}|${inst}|${strm}` → call 等待器
    this._ffPending = new Map(); // 同键 → fire_forget 待确认记录（无应用层超时，§5.5）
    this._respCache = new Map(); // 同键 → 服务端响应缓存（去重重发，§5.5）
  }

  // ============================================================
  // 客户端（§5.1/§5.2/§13.2）
  // ============================================================

  /** 同步调用（§13.2 call：阻塞至收到响应或超时） */
  async call(svcId, instId, ifId, payload, timeoutMs) {
    return this.call_async(svcId, instId, ifId, payload, timeoutMs);
  }

  /** 异步调用（§13.2 call_async：立即返回 Promise） */
  async call_async(svcId, instId, ifId, payload, timeoutMs) {
    const { rec, schema, iface } = await this._resolveTarget(svcId, instId, ifId, 'rpc');
    const body = schema.encodePayload(iface, 'input', payload);
    const peer = `${rec.addr.address}:${rec.addr.port}`;
    const strm = this.strm.allocClientStream(peer, svcId, instId);
    if (strm === null) throw new FwError(`client StrmID pool exhausted for ${peer}`);
    const timeout = timeoutMs ?? this.cfg.response_timeout_ms;
    const key = `${peer}|${svcId}|${instId}|${strm}`;

    const finish = (err, value) => {
      const p = this._pending.get(key);
      if (p && p.done) return;
      if (p) p.done = true;
      clearTimeout(p?.timer);
      this._pending.delete(key);
      this._retrans.cancel(key); // §5.1：响应超时触发时一并取消该 StrmID 的待确认重传
      this.strm.releaseClientStream(peer, svcId, instId, strm); // §6.2 Stream 释放
      if (err) reject2(p, err); else p?.resolve(value);
    };

    const p = { schema, iface }; // onResponse 解码需要 schema/iface（§5.1 响应按 IDL output 方向解码）
    p.promise = new Promise((resolve, reject) => {
      p.resolve = resolve;
      p.reject = reject;
    });
    // 应用层响应超时（§1.3：调用的唯一终态判定；§5.1 默认 2000ms 可逐次覆盖）
    p.timer = setTimeout(() => finish(new RequestTimeout(`call svc=${svcId} if=0x${ifId.toString(16)} timeout (${timeout}ms)`)), timeout);
    this._pending.set(key, p);

    try {
      if (iface.transport === 'tcp') {
        // TCP：TYP=NON，协议栈不重传（§5.1/§3.7）
        const conn = await this.ctx.getTcpConn(rec.addr.address, rec.addr.port);
        conn.write({
          ctr: 0, typ: TYP.NON, code: CODE.REQUEST,
          svc_id: svcId, if_id: ifId, inst_id: instId, strm_id: strm, payload: body,
        });
      } else {
        // UDP：TYP=CON，首发 t=0 + 重传表（200/600/1400ms，3000ms 静默停止，§5.5）
        const raw = encodeFrame({
          ctr: 0, typ: TYP.CON, code: CODE.REQUEST,
          svc_id: svcId, if_id: ifId, inst_id: instId, strm_id: strm, payload: body,
        });
        const sendFn = (buf) => this.ctx.sendUdpRaw(buf, rec.addr.address, rec.addr.port, 'client');
        sendFn(raw);
        this._retrans.start(key, raw, sendFn);
      }
    } catch (e) {
      finish(e);
    }
    return p.promise;
  }

  /** 无响应调用（§13.2 fire_forget）：UDP 走 CON 传输确认（重传至 ACK），TCP 走 NON */
  async fire_forget(svcId, instId, ifId, payload) {
    const { rec, schema, iface } = await this._resolveTarget(svcId, instId, ifId, 'ff');
    const body = schema.encodePayload(iface, 'input', payload);
    const peer = `${rec.addr.address}:${rec.addr.port}`;
    const strm = this.strm.allocClientStream(peer, svcId, instId);
    if (strm === null) throw new FwError(`client StrmID pool exhausted for ${peer}`);
    const key = `${peer}|${svcId}|${instId}|${strm}`;

    if (iface.transport === 'tcp') {
      // TCP：TYP=NON（§5.2），发完即释放（传输可靠性由 TCP 保证）
      const conn = await this.ctx.getTcpConn(rec.addr.address, rec.addr.port);
      conn.write({
        ctr: 0, typ: TYP.NON, code: CODE.FIRE_FORGET,
        svc_id: svcId, if_id: ifId, inst_id: instId, strm_id: strm, payload: body,
      });
      this.strm.releaseClientStream(peer, svcId, instId, strm);
      return;
    }
    // UDP：TYP=CON（§5.2），等传输层 ACK；无应用层超时，重传耗尽静默停止（§5.5）
    const raw = encodeFrame({
      ctr: 0, typ: TYP.CON, code: CODE.FIRE_FORGET,
      svc_id: svcId, if_id: ifId, inst_id: instId, strm_id: strm, payload: body,
    });
    this._ffPending.set(key, { peer, svcId, instId, strm });
    const sendFn = (buf) => this.ctx.sendUdpRaw(buf, rec.addr.address, rec.addr.port, 'client');
    sendFn(raw);
    this._retrans.start(key, raw, sendFn);
    // 重传耗尽兜底释放（3000ms 静默 + 余量；ACK 到达时提前释放）
    setTimeout(() => {
      if (this._ffPending.get(key)?.strm === strm) {
        this._retrans.cancel(key);
        this.strm.releaseClientStream(peer, svcId, instId, strm);
        this._ffPending.delete(key);
      }
    }, this._retrans.intervalMs * 2 ** (this._retrans.maxRetry + 1) + 200).unref?.();
  }

  /** 解析调用目标：发现缓存 → 主动 Find → IDL 自动拉取（拉取发生在发送前，§5.1/§7.2） */
  async _resolveTarget(svcId, instId, ifId, wantType) {
    let rec = this.discovery.getDiscovered(svcId, instId);
    if (!rec) {
      // 缓存未命中 → 发 Find 等待 Offer（§7.2）
      await this.discovery.findService(svcId, instId);
      rec = this.discovery.getDiscovered(svcId, instId);
      if (!rec) throw new ServiceNotFound(`svc=${svcId} inst=${instId} not discovered`);
    }
    // IDL：本地库命中不查询；缺失 → 自动 GetIDL 拉取落盘（§7.2/5.21）
    const schema = await this._ensureSchema(svcId, rec);
    const iface = schema.getInterface(ifId);
    if (!iface) throw new ServiceNotFound(`if_id 0x${ifId.toString(16)} not found in svc=${svcId} v${schema.majorVer}`);
    if (iface.type !== wantType) {
      throw new InvalidArgument(`if_id 0x${ifId.toString(16)} is ${iface.type}, not ${wantType}`);
    }
    return { rec, schema, iface };
  }

  /** 确保 IDL schema：库中该版本缺失时自动拉取（版本升级自动重新拉取，§7.2） */
  async _ensureSchema(svcId, rec) {
    let entry = this.idlStore.get(svcId, rec.major_ver);
    if (!entry) {
      const fetched = await this.discovery.fetchIdl(svcId, rec.major_ver);
      entry = { schema: fetched.schema };
    }
    return entry.schema;
  }

  // ============================================================
  // 客户端接收（Response / ACK / RST）
  // ============================================================

  /** 收到 Response（CTR=0, Code=0x10，回显请求 StrmID，§5.1） */
  onResponse(frame, meta) {
    const peer = `${meta.address}:${meta.port}`;
    const key = `${peer}|${frame.svc_id}|${frame.inst_id}|${frame.strm_id}`;
    const isUdpCon = meta.transport === 'udp' && frame.typ === TYP.CON;
    const p = this._pending.get(key);
    if (!p) {
      // 重复/迟到响应（§5.5）：按 StrmID 判定为重复，只交付首个；UDP CON 仍须回 ACK
      if (isUdpCon) this._sendAck(frame, meta, 'client');
      return;
    }
    if (p.done) return;
    p.done = true;
    clearTimeout(p.timer);
    this._pending.delete(key);
    this._retrans.cancel(key); // §5.1：收到 Response 一并取消待确认重传
    this.strm.releaseClientStream(peer, frame.svc_id, frame.inst_id, frame.strm_id); // Active→Closed（§6.2）
    if (isUdpCon) this._sendAck(frame, meta, 'client');
    // 解码交付（解码容忍末尾新增字段，§9.4）
    try {
      const value = p.schema.decodePayload(p.iface, 'output', frame.payload);
      p.resolve(value);
    } catch (e) {
      p.reject(new FwError(`response decode failed: ${e.message}`, RST_CODE.BAD_REQUEST));
    }
  }

  /** 收到数据帧空确认 ACK（CTR=0, Code=0x00，§3.7）：取消待确认重传 / 清响应缓存 */
  onAck(frame, meta) {
    const key = `${meta.address}:${meta.port}|${frame.svc_id}|${frame.inst_id}|${frame.strm_id}`;
    this._retrans.cancel(key);
    // 服务端角色：客户端对 Response(CON) 的确认 → 响应缓存随 Stream 释放清除（§5.5）
    const cached = this._respCache.get(key);
    if (cached) {
      clearTimeout(cached.expiry);
      this._respCache.delete(key);
    }
    // 客户端角色：fire_forget 的传输确认 → 释放流（§6.2）
    const ff = this._ffPending.get(key);
    if (ff) {
      this.strm.releaseClientStream(ff.peer, ff.svcId, ff.instId, ff.strm);
      this._ffPending.delete(key);
    }
  }

  /** 收到数据帧 RST（§5.4：记录错误，释放 Stream） */
  onDataRst(frame, meta) {
    const peer = `${meta.address}:${meta.port}`;
    const key = `${peer}|${frame.svc_id}|${frame.inst_id}|${frame.strm_id}`;
    this._retrans.cancel(key);
    this._respCache.delete(key);
    const p = this._pending.get(key);
    if (p && !p.done) {
      p.done = true;
      clearTimeout(p.timer);
      this._pending.delete(key);
      this.strm.releaseClientStream(peer, frame.svc_id, frame.inst_id, frame.strm_id);
      const name = RST_NAME[frame.code] ?? `0x${frame.code.toString(16)}`;
      p.reject(rstToError(frame.code, `call rejected: RST(${name})`));
    }
    const ff = this._ffPending.get(key);
    if (ff) {
      this.strm.releaseClientStream(ff.peer, ff.svcId, ff.instId, ff.strm);
      this._ffPending.delete(key);
    }
    this.log.frame('warn', {
      svc_id: frame.svc_id, if_id: frame.if_id, inst_id: frame.inst_id, strm_id: frame.strm_id,
      dir: 'Rx', addr: peer, code: frame.code, msg: `RST received (rpc stream released)`,
    });
  }

  _sendAck(echoFrame, meta, from) {
    // 数据帧空确认 ACK：CTR=0, TYP=ACK, Code=0x00，回显四标识（§3.7）
    this.ctx.sendUdpFrame({
      ctr: 0, typ: TYP.ACK, code: 0x00,
      svc_id: echoFrame.svc_id, if_id: echoFrame.if_id, inst_id: echoFrame.inst_id, strm_id: echoFrame.strm_id,
    }, meta.address, meta.port, from);
  }

  // ============================================================
  // 服务端（§5.1/§5.2/§5.5 去重/§13.3 处理契约）
  // ============================================================

  /** 收到 Request（CTR=0, Code=0x01） */
  onRequest(frame, meta) {
    this._handleClientCall(frame, meta, 'rpc', CODE.REQUEST);
  }

  /** 收到 Fire-Forget（CTR=0, Code=0x02） */
  onFireForget(frame, meta) {
    this._handleClientCall(frame, meta, 'ff', CODE.FIRE_FORGET);
  }

  _handleClientCall(frame, meta, wantType, code) {
    const peer = `${meta.address}:${meta.port}`;
    const isUdp = meta.transport === 'udp';
    const key = `${peer}|${frame.svc_id}|${frame.inst_id}|${frame.strm_id}`;

    // ---- 响应缓存去重（§5.5 服务端规则：重复 CON 请求重发缓存响应，不重新执行） ----
    const cached = this._respCache.get(key);
    if (cached) {
      if (cached.done && cached.respRaw) {
        this.ctx.sendUdpRaw(cached.respRaw, meta.address, meta.port, 'main'); // 重发缓存响应
      } else if (cached.ackRaw) {
        this.ctx.sendUdpRaw(cached.ackRaw, meta.address, meta.port, 'main'); // 处理中：重发传输确认
      }
      return;
    }

    // UDP CON：回空确认 ACK（传输层确认，§3.7）——TCP 不使用 CON/ACK
    let ackRaw = null;
    if (isUdp && frame.typ === TYP.CON) {
      ackRaw = encodeFrame({
        ctr: 0, typ: TYP.ACK, code: 0x00,
        svc_id: frame.svc_id, if_id: frame.if_id, inst_id: frame.inst_id, strm_id: frame.strm_id,
      });
      this.ctx.sendUdpRaw(ackRaw, meta.address, meta.port, 'main');
    }

    // ---- 实例 / 接口校验（§5.4：未知服务/接口 → RST(0x24)；Code 不支持 → RST(0x25)） ----
    const rec = this.discovery.getLocal(frame.svc_id, frame.inst_id);
    const rstEcho = { ctr: 0, svc_id: frame.svc_id, if_id: frame.if_id, inst_id: frame.inst_id, strm_id: frame.strm_id };
    if (!rec || !rec.handlers) {
      this._sendRst(RST_CODE.NOT_FOUND, rstEcho, meta);
      return;
    }
    const iface = rec.schema.getInterface(frame.if_id);
    if (!iface) {
      this._sendRst(RST_CODE.NOT_FOUND, rstEcho, meta);
      return;
    }
    if (iface.type !== wantType) {
      this._sendRst(RST_CODE.METHOD_NOT_ALLOWED, rstEcho, meta);
      return;
    }

    // ---- 解码（IDL 级契约违约统一归 RST(0x20)，§12.1 两层两码） ----
    let payload;
    try {
      payload = rec.schema.decodePayload(iface, 'input', frame.payload);
    } catch (e) {
      this.log.error('rpc', `decode failed svc=${frame.svc_id} if=0x${frame.if_id.toString(16)}: ${e.message}`);
      this._sendRst(RST_CODE.BAD_REQUEST, rstEcho, meta);
      return;
    }

    // ---- 建立响应缓存（仅 UDP：重传去重；TCP 无重传无需缓存，§5.5） ----
    if (isUdp) {
      const entry = { done: false, ackRaw, respRaw: null, expiry: null };
      this._respCache.set(key, entry);
      entry.expiry = setTimeout(() => this._respCache.delete(key),
        this._retrans.intervalMs * 2 ** (this._retrans.maxRetry + 1) + this.cfg.response_timeout_ms).unref?.();
    }

    // ---- 执行处理逻辑（§13.3：on_request 返回响应 / on_fire_forget 无返回） ----
    Promise.resolve()
      .then(() => wantType === 'rpc' ? rec.handlers.on_request?.(frame.if_id, payload) : rec.handlers.on_fire_forget?.(frame.if_id, payload))
      .then((result) => {
        if (wantType === 'ff') return; // FF 无响应（§5.2）
        const respPayload = rec.schema.encodePayload(iface, 'output', result);
        const respFrame = {
          ctr: 0, typ: isUdp ? TYP.CON : TYP.NON, code: CODE.OK,
          svc_id: frame.svc_id, if_id: frame.if_id, inst_id: frame.inst_id, strm_id: frame.strm_id,
          payload: respPayload,
        };
        if (isUdp) {
          // UDP Response：TYP=CON（对端回空确认 ACK，§5.1）+ 重传（§5.5）
          const respRaw = encodeFrame(respFrame);
          const entry = this._respCache.get(key);
          if (entry) { entry.done = true; entry.respRaw = respRaw; }
          const sendFn = (buf) => this.ctx.sendUdpRaw(buf, meta.address, meta.port, 'main');
          sendFn(respRaw);
          this._retrans.start(key, respRaw, sendFn);
        } else {
          meta.conn.write(respFrame); // TCP Response：TYP=NON（§5.1）
        }
        this.log.frame('debug', {
          svc_id: frame.svc_id, if_id: frame.if_id, inst_id: frame.inst_id, strm_id: frame.strm_id,
          dir: 'Tx', addr: peer, code: CODE.OK, msg: 'Response',
        });
      })
      .catch((e) => {
        // 处理逻辑执行异常 → RST(0x30)（§12.1）；并清缓存防泄漏
        this.log.error('rpc', `handler error svc=${frame.svc_id} if=0x${frame.if_id.toString(16)}: ${e.message}`);
        const entry = this._respCache.get(key);
        if (entry) { clearTimeout(entry.expiry); this._respCache.delete(key); }
        this._sendRst(RST_CODE.INTERNAL_ERROR, rstEcho, meta);
      });
  }

  _sendRst(code, echo, meta) {
    const rst = makeRst(code, echo);
    if (meta.transport === 'tcp') {
      meta.conn.write(rst);
    } else {
      this.ctx.sendUdpFrame(rst, meta.address, meta.port, 'main');
    }
    this.log.frame('warn', {
      svc_id: echo.svc_id, if_id: echo.if_id, inst_id: echo.inst_id, strm_id: echo.strm_id,
      dir: 'Tx', addr: `${meta.address}:${meta.port}`, code, msg: RST_NAME[code] ?? 'Error',
    });
  }

  /** 收到 REN=1：清该对端重传/等待/响应缓存（§3.6） */
  onRen(ip) {
    this._retrans.clearPeer(`${ip}:`);
    for (const key of [...this._pending.keys()]) {
      if (key.startsWith(`${ip}:`)) {
        const p = this._pending.get(key);
        if (p && !p.done) {
          p.done = true;
          clearTimeout(p.timer);
          p.reject(new ServiceNotFound(`peer ${ip} restarted (REN)`));
        }
        this._pending.delete(key);
      }
    }
    for (const key of [...this._ffPending.keys()]) {
      if (key.startsWith(`${ip}:`)) this._ffPending.delete(key);
    }
    for (const key of [...this._respCache.keys()]) {
      if (key.startsWith(`${ip}:`)) {
        clearTimeout(this._respCache.get(key)?.expiry);
        this._respCache.delete(key);
      }
    }
  }

  /** TCP 连接断开：排空该对端 pending 调用等待（§5.6；响应超时兜底冗余，对齐 MoonBit 版） */
  onTcpClosed(ip) {
    for (const key of [...this._pending.keys()]) {
      if (key.startsWith(`${ip}:`)) {
        const p = this._pending.get(key);
        if (p && !p.done) {
          p.done = true;
          clearTimeout(p.timer);
          p.reject(new Error(`tcp connection closed (peer ${ip})`));
        }
        this._pending.delete(key);
      }
    }
  }

  /** 停止清理 */
  stop() {
    this._retrans.clearPeer(''); // 全清
    for (const p of this._pending.values()) { clearTimeout(p?.timer); }
    this._pending.clear();
    this._ffPending.clear();
    for (const c of this._respCache.values()) clearTimeout(c?.expiry);
    this._respCache.clear();
  }
}

function reject2(p, err) { p?.reject?.(err); }

/** RST 错误码 → 应用层错误映射（§5.4/§12.1） */
function rstToError(code, msg) {
  if (code === RST_CODE.NOT_FOUND) return new ServiceNotFound(msg);
  return new FwError(msg, code);
}
