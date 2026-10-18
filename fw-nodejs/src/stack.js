// ============================================================
// stack.js —— §13 协议栈入口（应用 API）
//
// 组装：transport(UDP/TCP) → idlstore → sd(discovery) → rpc → events
// 帧分发总线：REN → 全模块清理；CTR=1 → SD 四操作/确认/RST；
//             CTR=0 → Request/FF/Notification/Response/ACK/RST
// 生命周期：start（启动即发 Find 预热发现缓存，§2 定案）/
//           stop（REN ×3 组播先发后关，§3.6/4.6）
// ============================================================

import { TYP, CODE, encodeFrame } from './frame/frame.js';
import { createLogger } from './logger.js';
import { StrmManager } from './strm.js';
import { UdpTransport } from './transport/udp.js';
import { TcpTransport } from './transport/tcp.js';
import { IdlStore } from './idlstore/store.js';
import { Discovery } from './sd/discovery.js';
import { RpcModule } from './rpc/rpc.js';
import { EventsModule } from './events/events.js';
import { InvalidArgument, ServiceNotFound, IdlUnavailable } from './errors.js';

// 附录 A：配置参数默认值（时间参数一律 ms，§1.3）
export const DEFAULT_CONFIG = Object.freeze({
  port: 5400,
  multicast_ipv4: '224.0.1.187',
  period_ms: 2000,
  ttl_ms: 4000,
  response_timeout_ms: 2000,
  retransmit_interval_ms: 200,
  retransmit_max: 3,
  tcp_frame_timeout_ms: 5000,
  heartbeat_period_ms: 30000,
  max_payload_len: 1400,
  ver: 0,          // 协议版本（§3.2 VER:2bit）
  idl_dir: './idl', // IDL 库文件夹（纯动态架构 §11.1）
  tcp_enabled: true, // TCP 监听开关（同机双进程测试时客户端角色栈关闭监听，仅保留出站连接能力）
  log_level: 'info',
});

export class FwStack {
  /**
   * @param {object} options 配置项（见 DEFAULT_CONFIG；ttl_ms >= 2*period_ms 硬约束 §7.2）
   */
  constructor(options = {}) {
    this.cfg = { ...DEFAULT_CONFIG, ...options };
    this._validateConfig();

    this.log = createLogger({ level: this.cfg.log_level });
    this.strm = new StrmManager();
    this.idlStore = new IdlStore(this.cfg.idl_dir, this.log);
    this.udp = new UdpTransport({
      port: this.cfg.port, multicastAddr: this.cfg.multicast_ipv4,
      multicastInterface: this.cfg.multicast_interface ?? null, // 组播出口接口（附录 A 可选配置）
      bindHost: this.cfg.bind_address ?? null, // 绑定地址（同机双栈测试模拟两台主机用）
      ver: this.cfg.ver, maxPayloadLen: this.cfg.max_payload_len, logger: this.log,
    });
    this.tcp = new TcpTransport({
      port: this.cfg.port, ver: this.cfg.ver,
      tcpFrameTimeoutMs: this.cfg.tcp_frame_timeout_ms,
      heartbeatPeriodMs: this.cfg.heartbeat_period_ms,
      heartbeatTimeoutMs: this.cfg.heartbeat_timeout_ms ?? this.cfg.heartbeat_period_ms * 2, // = 2×period（附录 A）
      logger: this.log,
    });

    // 共享上下文（模块间通过 ctx 互访，避免循环依赖）
    const ctx = {
      config: this.cfg, log: this.log, strm: this.strm, idlStore: this.idlStore,
      sendUdpFrame: (f, addr, port, from) => this.udp.sendUnicast(Buffer.isBuffer(f) ? f : encodeFrame(f), addr, port, from),
      sendUdpRaw: (buf, addr, port, from) => this.udp.sendUnicast(buf, addr, port, from),
      sendMulticastFrame: (f, which) => this.udp.sendMulticast(Buffer.isBuffer(f) ? f : encodeFrame(f), which),
      getTcpConn: (addr, port) => this.tcp.getConn(addr, port),
      findServerConnByIp: (ip) => this.tcp.findServerConnByIp(ip),
      onSubscriptionAdded: (sub) => this.events.onSubscriptionAdded(sub),
    };
    this.discovery = new Discovery({ ...ctx, discovery: null }); // 先建 discovery（自引用回填）
    ctx.discovery = this.discovery;
    this.rpc = new RpcModule(ctx);
    this.events = new EventsModule(ctx);

    this._started = false;
  }

  /** 配置校验（附录 A 约束列；5.10 拒绝配置） */
  _validateConfig() {
    const c = this.cfg;
    if (!Number.isInteger(c.port) || c.port < 1 || c.port > 65535) throw new InvalidArgument(`port must be 1~65535`);
    if (c.ttl_ms < 2 * c.period_ms) throw new InvalidArgument(`ttl_ms(${c.ttl_ms}) must be >= 2 * period_ms(${c.period_ms})`); // 5.10
    if (c.ttl_ms > 255000) throw new InvalidArgument(`ttl_ms must be <= 255000 (Entry TTL is uint8 seconds)`);
    if (c.response_timeout_ms <= 0) throw new InvalidArgument(`response_timeout_ms must be > 0`);
    if (c.tcp_frame_timeout_ms <= 0) throw new InvalidArgument(`tcp_frame_timeout_ms must be > 0`);
    if (c.max_payload_len <= 0) throw new InvalidArgument(`max_payload_len must be > 0`);
  }

  // ============================================================
  // 生命周期
  // ============================================================

  /** 启动协议栈：传输层 → 帧分发 → 周期 Offer/Tick → Find 预热（§2 定案） */
  async start() {
    if (this._started) return;
    await this.idlStore.loadAll(); // 纯动态架构：启动扫描 IDL 库（§11.1）
    await this.udp.start();
    // TCP 监听（服务端角色）；tcp_enabled=false 时跳过（客户端角色栈仅需出站连接，
    // 同机双进程测试场景下避免 TCP 端口冲突；正常部署单实例不受影响）
    if (this.cfg.tcp_enabled !== false) await this.tcp.listen();

    // 帧分发总线（UDP / TCP 双入口统一进入）
    this.udp.on('frame', (frame, meta) => this._onFrame(frame, meta));
    this.udp.on('error', (err, which) => this.log.error('stack', `udp ${which} socket error: ${err.message}`));
    this.tcp.on('frame', (conn, frame) => {
      // IPv4-mapped IPv6 地址规范化（::ffff:127.0.0.1 → 127.0.0.1，保证 TCP/UDP 地址口径一致）
      const addr = (conn.remoteAddress ?? '').replace(/^::ffff:/, '');
      this._onFrame(frame, { transport: 'tcp', address: addr, port: conn.remotePort, conn });
    });
    this.tcp.on('connClosed', (conn) => {
      // §5.6/§7.2：连接断开即时排空该对端 pending rpc 调用与 GetIDL 查询（响应超时兜底冗余，
      // 对齐 MoonBit 版 stack.mbt on_tcp_closed 双模块清理）；tcp-event 订阅保留（断连不失效 §8.2）
      this.log.info('stack', `tcp conn closed: ${conn.addrKey}`);
      const ip = (conn.remoteAddress ?? '').replace(/^::ffff:/, '');
      this.rpc.onTcpClosed(ip);
      this.discovery.onTcpClosed(ip);
    });
    this.tcp.on('error', (err) => this.log.error('stack', `tcp server error: ${err.message}`));

    this.discovery.startOfferLoop(); // 注册即 Offering + 周期广播（§7.3）
    this.discovery.startTick();      // 1s tick：TTL 推进（§7.5）

    // 启动立即发 Find（空 Payload）预热发现缓存（§2 定案：单实例，注册拉取失败可重试）
    this.udp.sendMulticast(encodeFrame({
      ctr: 1, typ: TYP.NON, code: CODE.SD_FIND,
      svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0, payload: Buffer.alloc(0),
    }), 'client');

    this._started = true;
    this.log.info('stack', `started: port=${this.cfg.port} ver=${this.cfg.ver} idl_dir=${this.cfg.idl_dir}`);
  }

  /** 停止：REN ×3 组播（间隔 ~100ms）先发后关，再释放资源（§3.6/4.6） */
  async stop() {
    if (!this._started) return;
    this._started = false;
    const ren = encodeFrame({
      ctr: 1, ren: 1, typ: TYP.NON, code: 0x00,
      svc_id: 0, if_id: 0, inst_id: 0, strm_id: 0, payload: Buffer.alloc(0),
    });
    for (let i = 0; i < 3; i++) {
      this.udp.sendMulticast(ren, 'main');
      if (i < 2) await new Promise((r) => setTimeout(r, 100)); // 间隔 ~100ms（协议固定值 §3.6）
    }
    this.log.info('stack', 'REN x3 sent (graceful shutdown)');
    this.discovery.stop();
    this.rpc.stop();
    this.events.stop();
    await this.tcp.stop();
    await this.udp.stop();
    this.log.info('stack', 'stopped');
  }

  // ============================================================
  // 帧分发总线
  // ============================================================

  _onFrame(frame, meta) {
    // ---- REN=1（§3.6）：清该对端服务缓存 + 活跃表 + 重传记录（4.4/4.5） ----
    if (frame.ren === 1) {
      this.log.frame('info', {
        dir: 'Rx', addr: `${meta.address}:${meta.port}`, code: 0, msg: 'REN received',
      });
      this.discovery.onRen(meta);
      this.rpc.onRen(meta.address);
      this.events.onRen(meta.address);
      this.strm.resetPeer(`${meta.address}:`); // 该对端全部 StrmID 序列重置（§6.3）
      return;
    }

    if (frame.ctr === 1) {
      // ---- 控制帧（CTR=1）→ SD 模块 ----
      // Subscribe 的 CON 形态（首次建立/取消/重传，§5.5 重传范围 + §8.1 到达帧行为：
      // CON 回确认，NON 保活仅刷新 TTL——onSubscribe 内部按 TYP 区分）
      if (frame.typ === TYP.CON) {
        if (frame.code === CODE.SD_SUBSCRIBE) this.discovery.onSubscribe(frame, meta); // 0x03 Subscribe(CON)
        return; // 其余控制帧 CON 组合非法定义（仅 Subscribe 使用 CON），静默丢弃
      }
      switch (frame.typ) {
        case TYP.NON:
          switch (frame.code) {
            case CODE.SD_OFFER: this.discovery.onOffer(frame, meta); return;      // 0x01 Offer / Find 响应
            case CODE.SD_FIND: this.discovery.onFind(frame, meta); return;        // 0x02 Find
            case CODE.SD_SUBSCRIBE: this.discovery.onSubscribe(frame, meta); return; // 0x03 Subscribe 保活（NON，§8.1）
            case CODE.SD_GET_IDL: this.discovery.onGetIdl(frame, meta, meta.conn); return; // 0x04 GetIDL（仅 TCP，解析层已保证）
            case CODE.SD_GET_IDL_RESP: this.discovery.onGetIdlResponse(frame, meta); return; // 0x11 GetIDL 响应（§7.2）
            default: return; // Code=0x00 心跳 Ping：不回任何帧（§5.7）；其余已由解析层拒绝
          }
        case TYP.ACK:
          if (frame.code === CODE.SD_SUBSCRIBE_ACK) this.discovery.onSubscribeAck(frame, meta);  // 0x10 订阅建立确认
          else if (frame.code === 0x00) this.discovery.onUnsubscribeAck(frame, meta);            // 0x00 取消确认
          return;
        case TYP.RST:
          this.discovery.onControlRst(frame, meta); // 订阅被拒 / GetIDL 失败（§5.4）
          return;
        default: return;
      }
    }

    // ---- 数据帧（CTR=0）→ RPC / Events ----
    switch (frame.typ) {
      case TYP.NON:
      case TYP.CON:
        switch (frame.code) {
          case CODE.REQUEST: this.rpc.onRequest(frame, meta); return;           // 0x01 Request
          case CODE.FIRE_FORGET: this.rpc.onFireForget(frame, meta); return;    // 0x02 Fire-Forget
          case CODE.NOTIFICATION: this.events.onNotification(frame, meta); return; // 0x03 Notification
          case CODE.OK: this.rpc.onResponse(frame, meta); return;               // 0x10 Response
          default: return; // 其余 Code 已由解析层/校验拒绝
        }
      case TYP.ACK: // 数据帧空确认（Code=0x00）：请求/FF/推送 CON 的传输确认
        this.rpc.onAck(frame, meta);
        this.events.onAck(frame, meta);
        return;
      case TYP.RST: // 数据帧 RST：释放对应 Stream（§5.4）
        this.rpc.onDataRst(frame, meta);
        this.events.onDataRst(frame, meta);
        return;
      default: return;
    }
  }

  // ============================================================
  // 应用 API —— 服务端（§13.1）
  // ============================================================

  /**
   * 注册服务实例（§13.1 register_service）。
   * @param {number} svc_id 服务 ID
   * @param {number} inst_id 实例 ID
   * @param {object|string|null} idl IDL 定义（对象或 JSON 文本）；
   *   提供且库中无该版本 → 校验落盘加载（服务端 IDL 进库供 GetIDL 响应，§7.2/§11.1）；
   *   未提供 → 库有 → 用最高版本；库无 → 发现缓存有在线实例 → 自动 GetIDL（集群同步，
   *   MajorVer 取在线版本，§7.2 注册场景）；无在线实例/拉取失败 → 注册失败上抛（IDL 库状态不变）
   * @param {object} handlers { on_request(if_id, payload), on_fire_forget(if_id, payload) }
   */
  async register_service(svc_id, inst_id, idl, handlers) {
    let schema;
    if (idl) {
      // 应用提供 IDL：校验自含 svc_id 一致后进库（重复注册同版本直接复用库内定义）
      let parsed;
      try {
        parsed = typeof idl === 'string' ? JSON.parse(idl) : idl;
      } catch (e) {
        throw new InvalidArgument(`idl is not valid JSON: ${e.message}`);
      }
      const svc = parsed?.service;
      if (!svc || typeof svc.svc_id !== 'number' || typeof svc.major_ver !== 'number') {
        throw new InvalidArgument('idl missing service.svc_id / service.major_ver');
      }
      if (svc.svc_id !== svc_id) {
        throw new InvalidArgument(`idl svc_id=${svc.svc_id} != argument svc_id=${svc_id}`);
      }
      if (!this.idlStore.has(svc_id, svc.major_ver)) {
        const jsonText = typeof idl === 'string' ? idl : JSON.stringify(parsed, null, 2);
        await this.idlStore.save(svc_id, svc.major_ver, jsonText); // 落盘失败降级内存（store 内处理 §7.2）
      }
      schema = this.idlStore.get(svc_id, svc.major_ver).schema;
    } else {
      // 未提供 IDL：库最高版本 → 自动拉取（发现缓存有在线实例时，§7.2/§13.1）
      let entry = this.idlStore.getHighest(svc_id);
      if (!entry) {
        const major = this.discovery.onlineMajorVer(svc_id);
        if (major === null) {
          // 库无定义且集群无在线实例 → 注册失败上抛（可由应用在发现缓存更新后重试，§13.1）
          throw new IdlUnavailable(`svc=${svc_id} not in local IDL store and no online instance to fetch from`);
        }
        const fetched = await this.discovery.fetchIdl(svc_id, major);
        entry = { schema: fetched.schema };
      }
      schema = entry.schema;
    }
    // handler 覆盖检查 + 进入 Offering（重复注册同 (svc,inst) → Err，7.9）
    return this.discovery.registerService(svc_id, inst_id, schema, handlers);
  }

  /** 注销实例（§13.1）：发 TTL=0 Offer 一次，停止广播（§7.3） */
  unregister_service(svc_id, inst_id) {
    return this.discovery.unregisterService(svc_id, inst_id);
  }

  /** notify（§13.1）：更新接口缓存并推送给所有订阅者（§8.1/§8.2） */
  notify(svc_id, inst_id, if_id, payload) {
    return this.events.notify(svc_id, inst_id, if_id, payload);
  }

  // ============================================================
  // 应用 API —— 客户端（§13.2）
  // ============================================================

  /** 同步调用（阻塞至响应/超时，§5.1） */
  call(svc_id, inst_id, if_id, payload, timeout) {
    return this.rpc.call(svc_id, inst_id, if_id, payload, timeout);
  }

  /** 异步调用（§13.2 call_async） */
  call_async(svc_id, inst_id, if_id, payload, timeout) {
    return this.rpc.call_async(svc_id, inst_id, if_id, payload, timeout);
  }

  /** 无响应调用（§5.2） */
  fire_forget(svc_id, inst_id, if_id, payload) {
    return this.rpc.fire_forget(svc_id, inst_id, if_id, payload);
  }

  /**
   * 订阅事件（§13.2 subscribe）：返回订阅句柄 handle。
   * if_id 与 grp_id 二选一（整组订阅 if_id=0x0000）。
   * 实例未 Found：登记订阅意图立即返回，Found 后自动发起（§7.4）。
   * 订阅触发 IDL 按需拉取（发现缓存有在线实例时，协议栈内部行为，§7.2/5.21）。
   */
  subscribe(svc_id, inst_id, opts = {}, on_event) {
    const if_id = opts.if_id ?? 0;
    const grp_id = opts.grp_id ?? 0;
    // Entry 合法组合（§7.1）：单接口 / 组订阅二选一
    if (!((if_id !== 0 && grp_id === 0) || (if_id === 0 && grp_id !== 0))) {
      throw new InvalidArgument('subscribe requires exactly one of if_id / grp_id');
    }
    this._ensureIdlBackground(svc_id); // 按需拉取（本地命中不查询，5.28）
    return this.discovery.subscribe(svc_id, inst_id, { if_id, grp_id }, on_event);
  }

  /** 取消订阅（§13.2）：发 Subscribe(TTL=0)（§8.1 场景4） */
  unsubscribe(handle) {
    return this.discovery.unsubscribe(handle);
  }

  /** is_available（§13.2）：注册表存在 + TTL Active + VER 相等（本地缓存判定） */
  is_available(svc_id, inst_id) {
    return this.discovery.isAvailable(svc_id, inst_id);
  }

  /** find_service（§13.2）：主动发现，返回在线信息（源地址/版本） */
  find_service(svc_id, inst_id, timeout) {
    return this.discovery.findService(svc_id, inst_id, timeout);
  }

  /** 订阅场景的 IDL 后台预拉取（协议栈内部行为，应用无感知，§7.2） */
  _ensureIdlBackground(svc_id) {
    if (this.idlStore.getHighest(svc_id)) return; // 本地命中不查询（5.28）
    const major = this.discovery.onlineMajorVer(svc_id);
    if (major === null) return; // 发现缓存无在线实例不发起（§7.2/5.30）
    this.discovery.fetchIdl(svc_id, major).catch((e) => {
      this.log.warn('stack', `background GetIDL failed for svc=${svc_id}: ${e.message}`); // 事件到达时兜底再拉
    });
  }
}
