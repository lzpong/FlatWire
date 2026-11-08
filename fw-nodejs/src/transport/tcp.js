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
import { performance } from 'node:perf_hooks';
import { TcpStreamParser, TYP, encodeFrame, makeRst, CODE } from '../frame/frame.js';
import { RST_CODE, RST_NAME } from '../errors.js';

// 单调毫秒时钟（R3-B）：心跳/空闲超时不得使用 Date.now()——系统时间回拨会让连接
// 永不失效、前跳会立即误判断连；performance.now() 不受系统时钟调整影响。
// C 侧对应 fw_now_ms()（QueryPerformanceCounter/CLOCK_MONOTONIC），三栈同口径。
const perfNow = () => performance.now();

// ---- 发送背压（§12.6「实现限制：发送背压」，非协议语义） ----
// 控制帧直写阈值：帧总长 ≤1024B 的控制帧（RST/Ping/GetIDL 请求）直接写 socket，
// 不占数据帧发送配额；因此数据队列满时 RST/Ping 仍可发出。
// GetIDL 响应（0x11）体积可达数十 KB，超过本阈值 → 按数据帧入队并受上限约束。
const CTRL_DIRECT_MAX = 1024;
const DEFAULT_MAX_SEND_QUEUE_BYTES = 262144;    // 单连接数据帧未发字节上限（256KB）
const DEFAULT_SEND_QUEUE_BUDGET_BYTES = 67108864; // 全栈数据帧未发字节总预算（64MB）

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

    // ---- 发送背压（§12.6 实现限制）----
    // maxSendQueueBytes：单连接「已入队未发出」数据帧字节上限（0=不限制）
    // sendQueueBudgetBytes：全栈所有连接数据帧未发字节合计预算（0=不限制）
    this.maxSendQueueBytes = opts.maxSendQueueBytes ?? DEFAULT_MAX_SEND_QUEUE_BYTES;
    this.sendQueueBudgetBytes = opts.sendQueueBudgetBytes ?? DEFAULT_SEND_QUEUE_BUDGET_BYTES;
    this.qBytes = 0;      // 当前水位（最近一次观测的 socket.writableLength）
    this.qPeak = 0;       // 本连接水位峰值
    this.qRejects = 0;    // 本连接累计因队列满拒写次数
    this.qCtrlWrites = 0; // 控制帧直写次数（不占配额，仅内部观测）
    this.qFullSince = 0;  // 首次拒写时刻（单调时钟 ms；队列 drain 清空时归零）
    this.qAccounted = 0;  // 本连接最近一次记账同步时的 writableLength 基准（§12.6 O(1) 预算）
    this.qData = 0;       // 本连接已计入 mgr.sendqBytes 的数据帧字节（入队加 / drain/close 减）
    this.qCtrl = 0;       // 本连接已写入但未发出的控制帧字节（仅用于对账口径，不占预算配额）

    this.parser = new TcpStreamParser({
      ver: this.ver,
      onFrame: (frame) => this._onFrame(frame),
      onRst: (rst) => this._onRst(rst),
      onDropComplete: () => this._clearDropTimer(),
    });

    this.lastSendAt = perfNow(); // §5.7：上次发出任意帧时刻（单调时钟）
    this.lastRecvAt = perfNow(); // §5.7：上次收到任意帧时刻（单调时钟）
    this.alive = true;

    this._frameTimer = null;  // 半帧超时定时器（帧首字节到达时启动）
    this._dropTimer = null;   // 丢弃模式兜底定时器（2×tcp_frame_timeout_ms）
    this._hbTimer = setInterval(() => this._heartbeatCheck(), Math.min(1000, this.heartbeatPeriodMs));
    this._hbTimer.unref?.();

    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('error', (err) => this._onClosed(err));
    socket.on('close', () => this._onClosed());
    // 内核缓冲排空 → 队列水位归零，持续满计时重置（§12.6 持续满断连的恢复条件）
    socket.on('drain', () => this._onDrain());
    socket.setNoDelay(true);
  }

  // ---- 接收 ----

  _onData(chunk) {
    this.parser.feed(chunk);
    this.lastRecvAt = perfNow(); // §5.7：收到任意帧（字节）即刷新存活计时（单调时钟）

    if (this.parser.dropMode) {
      // 丢弃模式：每收到任意字节刷新兜底计时（§4.1 退出条件 3）
      this._startDropTimer();
      return;
    }
    // 只要仍处于"接收中"就必须有半帧计时器。不能仅凭 feed 前的 receiving 判断：
    // 丢弃模式在同一批数据中收满 R 字节后可能立刻进入一个新半帧，此时 feed 前
    // wasReceiving 为 true，会漏启计时器导致半帧永久悬挂。
    if (this.parser.isReceiving()) {
      if (!this._frameTimer) this._startFrameTimer();
    } else {
      this._clearFrameTimer(); // 帧已完整交付 → 停止半帧计时
    }
  }

  _onFrame(frame) {
    this._clearFrameTimer();
    this.mgr.emit('frame', this, frame);
  }

  /** TCP 上收到解析违规 → 回 RST(0x00)（§4.4；RST 帧本身仍为合法 NON 帧） */
  _onRst(rst) {
    // RST 为控制帧（ctr=1 且帧总长 ≤1024B）→ write 走直写分支，不占发送配额（§12.6）。
    // 返回 false 仅表示连接已失效（帧未写入）；控制帧不重试、不排队，记录日志后放弃。
    if (!this.write(rst)) this.log?.debug('tcp', `RST tx skipped (connection closed): ${this.addrKey}`);
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
      // 控制帧直写（≤1024B）；false 仅表示连接已失效，本场景无需重试
      if (!this.write(makeRst(RST_CODE.FRAME_TIMEOUT, { ctr: 1, strm_id: echoStrm }))) {
        this.log?.debug('tcp', `RST tx skipped (connection closed): ${this.addrKey}`);
      }
      this.log?.frame('warn', {
        strm_id: echoStrm, dir: 'Tx', addr: this.addrKey,
        code: RST_CODE.FRAME_TIMEOUT, msg: `Frame Timeout (payload incomplete, total=${info.total}, recv=${info.received})`,
      });
      this.parser.enterDropMode();
      this._startDropTimer();
    } else {
      // 阶段一：帧头不完整（<8B）→ RST(0x26) + 关闭连接（帧总长不可知，无法重同步，§4.1）
      // 用 socket.end(rstBuf) 保证 RST 字节先 flush 再 FIN（write 后立即 destroy 会丢弃待发数据）。
      // 该 RST 帧为控制帧（8B），直接写 socket 不走数据队列——连接即将关闭，天然不受队列上限影响（§12.6）。
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
    // 必须由解析器按其有效区间起点（off）取址：同一缓冲内已消费帧后 off 不为 0，
    // 直接读 parser.buf[7] 会取到错误字节（第 3 轮容量缓冲重构后的回归点）。
    try { return this.parser.currentStrmId(); } catch { return 0; }
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
    const now = perfNow(); // 单调时钟：不受系统时间跳变影响（R3-B）
    // 存活判定：超过 heartbeat_timeout_ms（缺省 2 × heartbeat_period）未收到任何帧
    if (now - this.lastRecvAt >= this.heartbeatTimeoutMs) {
      this.log?.warn('tcp', `heartbeat timeout (${Math.round(now - this.lastRecvAt)}ms since last frame), mark dead: ${this.addrKey}`);
      this.alive = false;
      this.socket.destroy(); // 触发 close → 上层清理 Stream/订阅
      return;
    }
    // 背压持续满断连（§12.6）：自首次拒写起队列持续未清空且 >= 2×心跳周期 → 主动断连；
    // 期间若队列排空（drain）则 qFullSince 归零，不会误断连。
    if (this.qFullSince !== 0 && now - this.qFullSince >= 2 * this.heartbeatPeriodMs) {
      const fullMs = Math.round(now - this.qFullSince);
      this.log?.warn('tcp', `send queue full for ${fullMs}ms (>= 2*heartbeat_period_ms=${2 * this.heartbeatPeriodMs}ms), closing ${this.addrKey}`);
      this.mgr.sendqClosedFull = (this.mgr.sendqClosedFull ?? 0) + 1;
      this.alive = false;
      this.socket.destroy(); // 触发 close → 上层清理 Stream/订阅
      return;
    }
    // 空闲判定：距上次发出任意帧超过 heartbeat_period → 发一次 Ping（§5.7）
    if (now - this.lastSendAt >= this.heartbeatPeriodMs) {
      // Ping 帧：CTR=1, REN=0, TYP=NON, Code=0x00, 全 0 标识, 空 Payload（§5.7）
      // 控制帧直写（8B），不受数据队列上限影响（§12.6）
      if (!this.write({
        ctr: 1, ren: 0, typ: TYP.NON, code: 0x00,
        svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0, payload: Buffer.alloc(0),
      })) {
        this.log?.debug('tcp', `Ping tx skipped (connection closed): ${this.addrKey}`);
      }
    }
  }

  // ---- 发送 ----

  /**
   * 发送帧（内部编码；TCP 全帧 NON）。
   *
   * 返回值语义（⚠ 本轮收紧，见 §12.6 实现限制）：
   *   true  = 已写入 socket（控制帧直写）或已受理进入有界数据队列
   *   false = 本帧**未写入任何字节**（连接已失效，或数据帧发送队列已满被拒）
   *
   * 与旧实现的差异：旧实现直接返回 `socket.write()` 的 boolean——Node 中 false 仅表示
   * 内核/内部缓冲超过 highWaterMark，**帧仍被写入**；本实现改为显式有界队列，数据帧
   * 在写入前检查水位，满则**不调用 socket.write、不写入任何字节**并返回 false。
   * 调用方（尤其 rpc 客户端请求 / fire_forget）必须据此回滚等待记录与 StrmID。
   */
  write(frame) {
    if (!this.alive) return false;
    const buf = Buffer.isBuffer(frame) ? frame : encodeFrame(frame);

    // ---- 控制帧直写（§12.6 控制帧优先级）：不检查队列容量、不占配额 ----
    if (this._isCtrlDirect(buf, frame)) {
      this.qCtrlWrites += 1;
      this.lastSendAt = perfNow(); // §5.7：发出任意帧刷新空闲计时（单调时钟）
      try {
        this.socket.write(buf);
        // §12.6 控制帧记账（对账口径）：控制帧不占预算（不计入 sendqBytes），
        // 但它确实进入 writableLength；同步 accounted 并把差值归入控制桶，
        // 保证「数据桶 + 控制桶 == 遍历 writableLength 求和」恒成立。
        if (this.mgr) {
          const after = this.socket.writableLength ?? 0;
          this.qCtrl += after - this.qAccounted;
          this.qAccounted = after;
          this.mgr._assertSendqAccounting?.();
        }
        // 直写已写入：即使 socket.write 返回 false（仅表示需等 drain）也返回 true，
        // 避免调用方把「内核缓冲满」误判为「未写入」而回滚
        return true;
      } catch (e) {
        this.log?.warn('tcp', `control frame direct write failed: ${e.message}`);
        return false;
      }
    }

    // ---- 数据帧：有界发送队列（§12.6）----
    // 水位口径 = socket.writableLength（Node 内部「已入队未发出」字节数）。
    const pending = this.socket.writableLength ?? 0;
    if (pending > 0) {
      // 已有积压才检查上限；无积压时允许直写一帧（与 C 首帧直写一致）。
      // 极端情况下该帧部分未发会使水位短暂超过上限「至多一帧」，用于保证帧完整性。
      if (this.maxSendQueueBytes > 0 && pending + buf.length > this.maxSendQueueBytes) {
        return this._rejectDataWrite(pending, `conn limit ${this.maxSendQueueBytes}B`);
      }
      // §12.6 全栈预算：O(1) 增量计数（入队加 / drain 减 / 关闭扣减），不再遍历所有连接求和
      const used = this.mgr?.sendqBytes ?? 0;
      if (this.sendQueueBudgetBytes > 0 && used + buf.length > this.sendQueueBudgetBytes) {
        return this._rejectDataWrite(pending, `stack budget ${this.sendQueueBudgetBytes}B`);
      }
    }
    this.lastSendAt = perfNow();
    try {
      this.socket.write(buf);
    } catch (e) {
      this.log?.warn('tcp', `data frame write failed: ${e.message}`);
      return false;
    }
    // §12.6 全栈预算增量记账：只同步本连接 writableLength 的差值（O(1)，不遍历所有连接）。
    // 差值可能为负（自上次同步以来内核 flush 了字节），此时计入数据桶会让 sendqBytes 下降，
    // 属于记账滞后校正；不在此处 clamp 到 0——clamp 会破坏「数据桶 + 控制桶 == 遍历求和」恒等式。
    if (this.mgr) {
      const after = this.socket.writableLength ?? 0;
      const delta = after - this.qAccounted;
      this.qData += delta;
      this.mgr.sendqBytes += delta;
      this.qAccounted = after;
      this.mgr._assertSendqAccounting?.();
    }
    this._observeQueue();
    return true;
  }

  /**
   * 判断是否控制帧直写：帧总长 ≤ CTRL_DIRECT_MAX(1024B) 且 CTR=1。
   * 帧对象直接看 ctr；已编码 Buffer 按帧头自算总长（PLB/Length/MSK 开销）。
   */
  _isCtrlDirect(buf, frame) {
    if (!Buffer.isBuffer(frame)) {
      return !!frame?.ctr && buf.length <= CTRL_DIRECT_MAX;
    }
    if (buf.length < 8 || (buf[0] & 0x80) === 0) return false; // 帧头不足或 CTR=0（数据帧）
    const plb = buf[0] & 0x07;
    let total = 8 + plb + ((buf[0] & 0x08) ? 4 : 0); // MSK=1 时有 4B 掩码键
    if (plb > 0) {
      if (buf.length < 8 + plb) return false;
      let plen = 0;
      for (let i = 0; i < plb; i++) plen = plen * 256 + buf[8 + i];
      total += plen;
    }
    return total <= CTRL_DIRECT_MAX;
  }

  /** 记录本连接水位/峰值（统计用；判定以 socket.writableLength 实时值为准） */
  _observeQueue() {
    const q = this.socket.writableLength ?? 0;
    this.qBytes = q;
    if (q > this.qPeak) this.qPeak = q;
    if (this.mgr && q > (this.mgr.sendqPeak ?? 0)) this.mgr.sendqPeak = q;
  }

  /** 数据帧被拒：计数 + 日志 + 首次拒写开启「持续满」计时；返回 false（未写入） */
  _rejectDataWrite(pendingBytes, why) {
    this.qRejects += 1;
    if (this.mgr) this.mgr.sendqRejects = (this.mgr.sendqRejects ?? 0) + 1;
    this.qBytes = pendingBytes;
    if (pendingBytes > this.qPeak) this.qPeak = pendingBytes;
    const now = perfNow();
    if (this.qFullSince === 0) {
      this.qFullSince = now;
      this.log?.warn('tcp', `send queue full (${why}, pending=${pendingBytes}B), reject data frame: ${this.addrKey}`);
    }
    return false;
  }

  /** 内核缓冲排空：水位归零 + 持续满计时重置 + 全栈预算归还（§12.6） */
  _onDrain() {
    this.qBytes = 0;
    this._releaseQueueAccount(); // §12.6：缓冲清空 → 本连接计入量整体归还全栈预算
    this.mgr?._assertSendqAccounting?.(); // 对账：drain 后计数应等于遍历求和
    if (this.qFullSince !== 0) {
      const fullMs = Math.round(perfNow() - this.qFullSince);
      this.qFullSince = 0;
      this.log?.info('tcp', `send queue drained after ${fullMs}ms, resume: ${this.addrKey}`);
    }
  }

  /**
   * §12.6 全栈预算增量回收：把本连接已计入 sendqBytes 的数据帧字节整体归还（qData）。
   * drain（缓冲清空）与连接关闭（扣减残留量）两条路径调用；幂等。
   * 同时清空控制桶与同步基准：缓冲清空后两者都应为 0（关闭时连接被移除，不再参与对账）。
   * 不在此处对账：批量关闭时其他连接可能处于「已 destroyed、close 事件未处理」的瞬时态，
   * 对账由 drain 路径与测试在全部关闭完成后显式调用（见 _assertSendqAccounting）。
   */
  _releaseQueueAccount() {
    if (this.mgr && this.qData !== 0) {
      this.mgr.sendqBytes -= this.qData;
    }
    this.qData = 0;
    this.qCtrl = 0;
    this.qAccounted = 0;
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
    // §12.6：连接关闭扣减该连接残留的已计入字节（未发完的队列随连接销毁）
    this._releaseQueueAccount();
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
   *                        heartbeatTimeoutMs, maxConns=1024, logger }
   */
  constructor(opts = {}) {
    super();
    this.port = opts.port ?? 5400;
    this.opts = opts;
    this.log = opts.logger;
    // 连接上限（R3-8）：入站/出站各自不得超过该值，超限拒绝并释放，防止 fd/内存无界增长
    this.maxConns = opts.maxConns ?? 1024;
    // 发送背压内部计数（§12.6「观测量」）：本轮仅内部统计 + 日志，不提供公开 API。
    // 逐连接明细见 TcpConn.qBytes/qPeak/qRejects；此处为全栈汇总。
    this.sendqPeak = 0;      // 全栈水位峰值（任一连接观测到的最大未发字节数）
    this.sendqRejects = 0;   // 累计数据帧拒写次数
    this.sendqClosedFull = 0; // 累计因「队列持续满 > 2×心跳周期」断连次数
    // §12.6 全栈预算增量计数（O(1) 判定用）：入队加 / drain 减 / 连接关闭扣减
    this.sendqBytes = 0;
    // 测试/调试开关：每次关键记账变更后与「遍历求和」对账，漂移即抛错（默认关闭）
    this.checkSendqAccounting = !!opts.checkSendqAccounting;
    this.server = null;
    this.clientConns = new Map(); // key 'ip:port' → TcpConn（客户端出站连接，按需复用 §5.6）
    this.serverConns = new Set(); // 服务端接受的入站连接
    this._connecting = new Map(); // key 'ip:port' → Promise<TcpConn>（并发建连合并，防重复 socket）
    this.on('connClosed', (conn) => this._removeConn(conn));
  }

  /** 启动服务端监听 */
  async listen() {
    this.server = net.createServer((socket) => {
      // R3-8：入站连接达上限 → 立即销毁（不创建 TcpConn，不占用解析器/定时器/fd）
      if (this.serverConns.size >= this.maxConns) {
        this.log?.warn?.(`[tcp] reject inbound connection: limit ${this.maxConns} reached`);
        socket.destroy();
        return;
      }
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
    // R3-8：出站连接（含建连中）达上限 → 直接拒绝，不创建 socket（避免 fd 泄漏）
    if (this.clientConns.size + this._connecting.size >= this.maxConns) {
      throw new Error(`tcp outbound connection limit reached (${this.maxConns})`);
    }
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

  /**
   * 全栈数据帧未发字节**遍历求和**（仅对账/统计用；§12.6 判定已改为 O(1) 增量计数 sendqBytes）。
   * 口径 = 各活跃连接 socket.writableLength 之和（含控制帧字节，与历史口径一致）。
   */
  _sumWritableLengths() {
    let total = 0;
    for (const c of this.clientConns.values()) {
      if (c.alive) total += c.socket.writableLength ?? 0;
    }
    for (const c of this.serverConns) {
      if (c.alive) total += c.socket.writableLength ?? 0;
    }
    return total;
  }

  /** 全栈水位采样（更新 sendqPeak；不参与判定） */
  _pendingBytes() {
    const total = this._sumWritableLengths();
    if (total > this.sendqPeak) this.sendqPeak = total;
    return total;
  }

  /**
   * §12.6 记账对账（仅 checkSendqAccounting 开启时生效，测试用）：
   * 「数据帧桶 sendqBytes + 各连接控制帧桶之和」必须与「遍历各连接 writableLength 求和」一致。
   * 水位口径含控制帧直写字节，故对账需把控制桶一并计入；判定仍只用数据桶（控制帧不占配额）。
   * 漏减会让预算永不触发，多减会误拒合法流量——漂移即抛错，避免背着 bug 跑。
   */
  _assertSendqAccounting() {
    if (!this.checkSendqAccounting) return;
    let real = 0, ctrl = 0, lag = 0;
    const add = (c) => {
      if (!c.alive) return;
      const w = c.socket.writableLength ?? 0;
      real += w;
      ctrl += c.qCtrl;
      // 部分 flush 没有事件通知：accounted 仍大于当前水位时，差额是「已发出但未同步」的滞后，
      // 从计数侧一并扣除后再比较。关闭/漏减不会留下 accounted 残差，因此仍能被抓到。
      if (c.qAccounted > w) lag += c.qAccounted - w;
    };
    for (const c of this.clientConns.values()) add(c);
    for (const c of this.serverConns) add(c);
    const counted = this.sendqBytes + ctrl - lag;
    if (real !== counted) {
      const msg = `sendq accounting drift: counter=${counted}B (data=${this.sendqBytes}B ctrl=${ctrl}B lag=${lag}B) traversal=${real}B`;
      this.log?.error?.('tcp', msg);
      throw new Error(msg);
    }
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
