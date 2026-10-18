// ============================================================
// tcp.js —— §5.6 TCP 长连接管理 + §4.1 半帧两阶段 + §5.7 心跳（Ping）
//
// - 连接建立：客户端按 (IP, Port) 建立唯一长连接并复用（§5.6）
// - 服务端 bind+listen，accept 后纳入帧解析（§5.6）
// - TCP 全帧 TYP=NON，不使用 CON/ACK（§3.7，解析层拒绝）
// - 半帧两阶段（§4.1）：
//     阶段一 帧头不完整（<8B）→ RST(0x26) + 关闭连接
//     阶段二 帧头完整 → RST(0x26) + 丢弃模式（精确丢弃 R=L−已收；退出三条件）
// - 心跳（§5.7）：距上次发送任意帧超过 heartbeat_period_ms 发 Ping；收到 Ping 不回；
//   2×heartbeat_timeout 未见帧标记连接失效
// ============================================================

import net from 'node:net';
import { EventEmitter } from 'node:events';
import { TcpStreamParser, TYP, encodeFrame, makeRst, CODE } from '../frame/frame.js';
import { RST_CODE, RST_NAME } from '../errors.js';

/** 单条 TCP 连接封装：帧解析 + 半帧定时器 + 丢弃模式 + 心跳计时 */
export class TcpConn {
  /**
   * @param {net.Socket} socket
   * @param {object} opts { ver, tcpFrameTimeoutMs=5000, heartbeatPeriodMs=30000,
   *                        heartbeatTimeoutMs=60000, logger, role: 'client'|'server' }
   * @param {TcpTransport} mgr 所属传输管理器
   */
  constructor(socket, opts, mgr) {
    this.socket = socket;
    this.opts = opts;
    this.mgr = mgr;
    this.log = opts.logger;
    this.role = opts.role ?? 'server';
    this.ver = opts.ver ?? 0;
    this.tcpFrameTimeoutMs = opts.tcpFrameTimeoutMs ?? 5000;
    this.heartbeatPeriodMs = opts.heartbeatPeriodMs ?? 30000;
    this.heartbeatTimeoutMs = opts.heartbeatTimeoutMs ?? 60000;

    this.remoteAddress = socket.remoteAddress;
    this.remotePort = socket.remotePort;
    this.addrKey = `${this.remoteAddress}:${this.remotePort}`;

    this.parser = new TcpStreamParser({
      ver: this.ver,
      onFrame: (frame) => this._onFrame(frame),
      onRst: (rst) => this._onRst(rst),
      onDropComplete: () => this._clearDropTimer(),
    });

    this.lastSendAt = Date.now(); // §5.7：上次发出任意帧时刻
    this.lastRecvAt = Date.now(); // §5.7：上次收到任意帧时刻
    this.alive = true;

    this._frameTimer = null;  // 半帧超时定时器（帧首字节到达时启动）
    this._dropTimer = null;   // 丢弃模式兜底定时器（2×tcp_frame_timeout_ms）
    this._hbTimer = setInterval(() => this._heartbeatCheck(), Math.min(1000, this.heartbeatPeriodMs));
    this._hbTimer.unref?.();

    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('error', (err) => this._onClosed(err));
    socket.on('close', () => this._onClosed());
    socket.setNoDelay(true);
  }

  // ---- 接收 ----

  _onData(chunk) {
    const wasReceiving = this.parser.isReceiving();
    this.parser.feed(chunk);
    this.lastRecvAt = Date.now(); // §5.7：收到任意帧（字节）即刷新存活计时

    if (this.parser.dropMode) {
      // 丢弃模式：每收到任意字节刷新兜底计时（§4.1 退出条件 3）
      this._startDropTimer();
      return;
    }
    if (!wasReceiving && this.parser.isReceiving()) {
      this._startFrameTimer(); // 新帧开始接收 → 启动半帧超时
    }
    if (!this.parser.isReceiving()) {
      this._clearFrameTimer(); // 帧已完整交付 → 停止半帧计时
    }
  }

  _onFrame(frame) {
    this._clearFrameTimer();
    this.mgr.emit('frame', this, frame);
  }

  /** TCP 上收到解析违规 → 回 RST(0x00)（§4.4；RST 帧本身仍为合法 NON 帧） */
  _onRst(rst) {
    this.write(rst);
    this.log?.frame('warn', {
      svc_id: rst.svc_id, if_id: rst.if_id, inst_id: rst.inst_id, strm_id: rst.strm_id,
      dir: 'Tx', addr: this.addrKey, code: rst.code, msg: RST_NAME[rst.code] ?? 'Protocol Violation',
    });
  }

  // ---- 半帧两阶段（§4.1） ----

  _startFrameTimer() {
    this._clearFrameTimer();
    this._frameTimer = setTimeout(() => this._onFrameTimeout(), this.tcpFrameTimeoutMs);
  }

  _clearFrameTimer() {
    if (this._frameTimer) { clearTimeout(this._frameTimer); this._frameTimer = null; }
  }

  _onFrameTimeout() {
    if (!this.parser.isReceiving() || this.parser.dropMode) return;
    if (this.parser.isHeaderComplete()) {
      // 阶段二：帧头完整、Payload 不完整 → RST(0x26) + 丢弃模式（连接不关闭，§4.1）
      const info = this.parser.getFrameInfo();
      // RST 以控制帧形态（CTR=1）发送——半帧场景标识字段可能未知，全 0 标识仅控制帧合法
      // （§4.3 步骤 3：数据帧 SvcID 必须≠0）；StrmID 仅在控制帧合法范围 0x01~0x7F 内回显
      const strmId = this._headerStrmId();
      const echoStrm = strmId >= 0x01 && strmId <= 0x7f ? strmId : 0;
      this.write(makeRst(RST_CODE.FRAME_TIMEOUT, { ctr: 1, strm_id: echoStrm }));
      this.log?.frame('warn', {
        strm_id: echoStrm, dir: 'Tx', addr: this.addrKey,
        code: RST_CODE.FRAME_TIMEOUT, msg: `Frame Timeout (payload incomplete, total=${info.total}, recv=${info.received})`,
      });
      this.parser.enterDropMode();
      this._startDropTimer();
    } else {
      // 阶段一：帧头不完整（<8B）→ RST(0x26) + 关闭连接（帧总长不可知，无法重同步，§4.1）
      // 用 socket.end(rstBuf) 保证 RST 字节先 flush 再 FIN（write 后立即 destroy 会丢弃待发数据）
      const rstBuf = encodeFrame(makeRst(RST_CODE.FRAME_TIMEOUT, { ctr: 1 }));
      this.log?.frame('warn', {
        dir: 'Tx', addr: this.addrKey, code: RST_CODE.FRAME_TIMEOUT,
        msg: 'Frame Timeout (header incomplete), closing connection',
      });
      this.alive = false; // 阻止后续 write
      this.socket.end(rstBuf); // 发送 RST 后 FIN 关闭；客户端按 §5.6 自动重连
    }
  }

  /** 从当前帧已收字节中尽力提取 StrmID（byte7，帧头完整时可得，§5.4 RST 回显） */
  _headerStrmId() {
    try {
      const buf = this.parser.buf;
      if (buf.length >= 8) return buf[7];
      return 0;
    } catch { return 0; }
  }

  _startDropTimer() {
    this._clearDropTimer();
    // 兜底超时 = 2 × tcp_frame_timeout_ms（协议固定倍率，§4.1 退出条件 3）
    this._dropTimer = setTimeout(() => {
      this.log?.warn('tcp', `drop mode fallback timeout, closing ${this.addrKey}`);
      this.socket.destroy();
    }, 2 * this.tcpFrameTimeoutMs);
  }

  _clearDropTimer() {
    if (this._dropTimer) { clearTimeout(this._dropTimer); this._dropTimer = null; }
  }

  // ---- 心跳（§5.7） ----

  _heartbeatCheck() {
    if (!this.alive) return;
    const now = Date.now();
    // 存活判定：超过 2 × heartbeat_period 未收到任何帧 → 标记失效（§5.7）
    if (now - this.lastRecvAt >= this.heartbeatTimeoutMs) {
      this.log?.warn('tcp', `heartbeat timeout (${now - this.lastRecvAt}ms since last frame), mark dead: ${this.addrKey}`);
      this.alive = false;
      this.socket.destroy(); // 触发 close → 上层清理 Stream/订阅
      return;
    }
    // 空闲判定：距上次发出任意帧超过 heartbeat_period → 发一次 Ping（§5.7）
    if (now - this.lastSendAt >= this.heartbeatPeriodMs) {
      // Ping 帧：CTR=1, REN=0, TYP=NON, Code=0x00, 全 0 标识, 空 Payload（§5.7）
      this.write({
        ctr: 1, ren: 0, typ: TYP.NON, code: 0x00,
        svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0, payload: Buffer.alloc(0),
      });
    }
  }

  // ---- 发送 ----

  /** 发送帧对象（内部编码；TCP 全帧 NON） */
  write(frame) {
    if (!this.alive) return false;
    const buf = Buffer.isBuffer(frame) ? frame : encodeFrame(frame);
    this.lastSendAt = Date.now(); // §5.7：发出任意帧刷新空闲计时
    return this.socket.write(buf);
  }

  /** 连接是否可用 */
  get connected() { return this.alive && !this.socket.destroyed; }

  _onClosed(err) {
    if (this._closed) return; // 幂等（无论主动/被动关闭均需执行一次清理）
    this._closed = true;
    this.alive = false;
    this._clearFrameTimer();
    this._clearDropTimer();
    clearInterval(this._hbTimer);
    this.mgr.emit('connClosed', this, err);
  }

  /** 主动关闭 */
  close() {
    this.alive = false;
    try { this.socket.end(); } catch { this.socket.destroy(); }
  }
}

// Code 常量补充：心跳 Ping 即控制帧 Code=0x00 且 REN=0（§5.7）
export const PING_CODE = 0x00;

/**
 * TCP 传输管理器：服务端 listen + 客户端按需建连（连接复用，§5.6）。
 * 事件：'frame'(conn, frame)、'connClosed'(conn, err)、'listening'
 */
export class TcpTransport extends EventEmitter {
  /**
   * @param {object} opts { port=5400, ver=0, tcpFrameTimeoutMs, heartbeatPeriodMs,
   *                        heartbeatTimeoutMs, logger }
   */
  constructor(opts = {}) {
    super();
    this.port = opts.port ?? 5400;
    this.opts = opts;
    this.log = opts.logger;
    this.server = null;
    this.clientConns = new Map(); // key 'ip:port' → TcpConn（客户端出站连接，按需复用 §5.6）
    this.serverConns = new Set(); // 服务端接受的入站连接
    this._connecting = new Map(); // key 'ip:port' → Promise<TcpConn>（并发建连合并，防重复 socket）
    this.on('connClosed', (conn) => this._removeConn(conn));
  }

  /** 启动服务端监听 */
  async listen() {
    this.server = net.createServer((socket) => {
      const conn = new TcpConn(socket, { ...this.opts, role: 'server' }, this);
      this.serverConns.add(conn);
      this.emit('conn', conn);
    });
    this.server.on('error', (err) => this.emit('error', err));
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, () => resolve());
    });
  }

  /**
   * 获取到 (address, port) 的客户端出站连接；不存在则建立（按需建连，§5.6）。
   * @returns {Promise<TcpConn>}
   */
  async getConn(address, port) {
    const key = `${address}:${port}`;
    const exist = this.clientConns.get(key);
    if (exist && exist.connected) return exist;

    // 并发建连合并：同一 (IP,Port) 进行中的建连 Promise 直接复用（幂等，§5.6 连接复用；
    // 对照 MoonBit 版 transport outbound Map——避免并发调用方各自触发一条重复长连接）
    const inflight = this._connecting.get(key);
    if (inflight) return inflight;
    const p = this._connectOne(address, port, key).finally(() => this._connecting.delete(key));
    this._connecting.set(key, p);
    return p;
  }

  /** 实际建立一条出站连接（仅由 getConn 调用，并发经 _connecting 合并） */
  async _connectOne(address, port, key) {
    // 建立新长连接（连接复用：同一 (IP,Port) 仅一条，§5.6）
    const socket = net.connect({ host: address, port });
    await new Promise((resolve, reject) => {
      const onErr = (e) => { cleanup(); reject(e); };
      const onConn = () => { cleanup(); resolve(); };
      const cleanup = () => {
        socket.removeListener('error', onErr);
        socket.removeListener('connect', onConn);
      };
      socket.once('error', onErr);
      socket.once('connect', onConn);
    });
    const conn = new TcpConn(socket, { ...this.opts, role: 'client' }, this);
    this.clientConns.set(key, conn);
    this.emit('conn', conn);
    return conn;
  }

  /** 查询已有出站连接（不建立） */
  peekConn(address, port) {
    const c = this.clientConns.get(`${address}:${port}`);
    return c && c.connected ? c : null;
  }

  /** 按远端 IP 查找服务端入站连接（tcp-event 推送按订阅者源 IP 匹配，§8.2） */
  findServerConnByIp(ip) {
    for (const conn of this.serverConns) {
      if (conn.connected && conn.remoteAddress === ip) return conn;
    }
    return null;
  }

  /** 停止监听并关闭全部连接 */
  async stop() {
    this._connecting.clear(); // 进行中的建连随 socket 一并放弃（其 error 回调自行 reject）
    for (const c of this.clientConns.values()) c.close();
    for (const c of this.serverConns) c.close();
    this.clientConns.clear();
    this.serverConns.clear();
    if (this.server) {
      await new Promise((r) => this.server.close(r));
      this.server = null;
    }
  }

  _removeConn(conn) {
    // 连接关闭后的登记清理（§5.6：清理该连接的所有 Stream 与订阅关系由上层完成）
    for (const [key, c] of this.clientConns) {
      if (c === conn) this.clientConns.delete(key);
    }
    this.serverConns.delete(conn);
  }
}
