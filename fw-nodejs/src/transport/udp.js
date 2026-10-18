// ============================================================
// udp.js —— §2 UDP 组播双 socket
//
// - main socket：bind 5400（服务端角色）——收组播 Find/REN/Offer、收单播请求、
//   收客户端数据帧；发周期 Offer、Find 响应、事件推送
// - client socket：bind 临时端口（客户端角色，避免与同主机服务端端口冲突，§2）——
//   发组播 Find/REN、单播 Request/FF/Subscribe；收单播响应/推送/确认与组播 Offer
// - IP_MULTICAST_LOOP 开启（§2）：本机组播回环；同主机进程间组播可达
// - 自我回环过滤：源 IP 为本机地址且源端口 == 本 socket 端口 → 丢弃
//   （本机另一 socket 的回环帧不过滤：双角色同栈共享发现缓存，见 README 偏差说明）
// ============================================================

import dgram from 'node:dgram';
import os from 'node:os';
import { EventEmitter } from 'node:events';
import { parseDatagram, encodeFrame } from '../frame/frame.js';

// 组播操作码集合：UDP 上这些 Code 的解析违规视为组播帧 → 静默丢弃
// （平台限制：dgram 无法获知数据报目的地址，以操作码启发式区分组播/单播，
//   见模块头与 README "有意偏差"）
const MULTICAST_LIKE_CODES = new Set([0x01, 0x02]); // SD Offer / SD Find

// 收集本机 IPv4 地址集合（自我回环过滤用）
function localIpv4Set() {
  const set = new Set(['127.0.0.1', 'localhost']);
  for (const list of Object.values(os.networkInterfaces())) {
    for (const ni of list ?? []) {
      if (ni.family === 'IPv4') set.add(ni.address);
    }
  }
  return set;
}

export class UdpTransport extends EventEmitter {
  /**
   * @param {object} opts {
   *   port=5400, multicastAddr='224.0.1.187', ver=0, maxPayloadLen=1400,
   *   logger
   * }
   */
  constructor(opts = {}) {
    super();
    this.port = opts.port ?? 5400;
    this.bindHost = opts.bindHost ?? null; // 绑定地址（同机双栈测试用不同 loopback IP 模拟两台主机；空 = 全接口）
    this.multicastAddr = opts.multicastAddr ?? '224.0.1.187';
    this.multicastInterface = opts.multicastInterface ?? null; // 组播出口接口（多网卡主机指定；空 = 系统选路）
    this.ver = opts.ver ?? 0;
    this.maxPayloadLen = opts.maxPayloadLen ?? 1400;
    this.log = opts.logger;
    this.mainSock = null;    // 服务端 socket（bind port）
    this.clientSock = null;  // 客户端 socket（临时端口）
    // 自我回环过滤的源地址集合：绑定指定地址（bindHost）时该地址是本 socket
    // 唯一可能源；全接口绑定时发出帧源 IP 由系统选路，取全部本机 IPv4 地址。
    // （按 socket 区分而非全机地址，避免同机双栈互发帧被误判为自我回环）
    this._localAddrs = this.bindHost ? new Set([this.bindHost]) : localIpv4Set();
  }

  /** 启动双 socket 并加入组播组 */
  async start() {
    // main socket：bind 5400（服务端角色）
    this.mainSock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.mainSock.on('message', (buf, rinfo) => this._onMessage(this.mainSock, buf, rinfo, 'main'));
    this.mainSock.on('error', (err) => this.emit('error', err, 'main'));
    await new Promise((resolve, reject) => {
      this.mainSock.once('error', reject);
      this.mainSock.bind(this.port, this.bindHost ?? undefined, () => resolve());
    });
    this.mainSock.setMulticastLoopback(true); // §2：IP_MULTICAST_LOOP 默认开启
    this.mainSock.setBroadcast(true);
    if (this.multicastInterface) this.mainSock.setMulticastInterface(this.multicastInterface);
    try { this.mainSock.addMembership(this.multicastAddr, this.multicastInterface ?? undefined); } catch (e) {
      this.log?.warn('udp', `addMembership failed on main socket: ${e.message}`);
    }

    // client socket：bind 临时端口（§2：客户端 UDP socket 不绑定 5400）
    this.clientSock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.clientSock.on('message', (buf, rinfo) => this._onMessage(this.clientSock, buf, rinfo, 'client'));
    this.clientSock.on('error', (err) => this.emit('error', err, 'client'));
    await new Promise((resolve, reject) => {
      this.clientSock.once('error', reject);
      this.clientSock.bind(0, this.bindHost ?? undefined, () => resolve());
    });
    this.clientSock.setMulticastLoopback(true);
    if (this.multicastInterface) this.clientSock.setMulticastInterface(this.multicastInterface);
    try { this.clientSock.addMembership(this.multicastAddr, this.multicastInterface ?? undefined); } catch (e) {
      this.log?.warn('udp', `addMembership failed on client socket: ${e.message}`);
    }
  }

  /** 停止：关闭双 socket（graceful shutdown 的资源释放阶段，REN 已由上层先发完 §3.6） */
  async stop() {
    for (const sock of [this.mainSock, this.clientSock]) {
      if (sock) {
        try { sock.dropMembership(this.multicastAddr); } catch { /* 忽略 */ }
        await new Promise((r) => sock.close(r));
      }
    }
    this.mainSock = null;
    this.clientSock = null;
  }

  // ---- 发送 ----

  /** 组播发送（Offer / Find / REN），从指定 socket 发出 */
  sendMulticast(buf, which = 'main') {
    const sock = which === 'main' ? this.mainSock : this.clientSock;
    if (!sock) return;
    sock.send(buf, this.port, this.multicastAddr);
  }

  /** 单播发送；from='client' 用客户端 socket，'main' 用服务端 socket */
  sendUnicast(buf, address, port, from = 'client') {
    const sock = from === 'main' ? this.mainSock : this.clientSock;
    if (!sock) return;
    sock.send(buf, port, address);
  }

  /** 客户端 socket 绑定的临时端口（发现缓存/推送地址观测用） */
  get clientPort() { return this.clientSock?.address().port ?? 0; }

  // ---- 接收 ----

  _onMessage(sock, buf, rinfo, which) {
    // 自我回环过滤：源 IP 是本机地址且源端口等于本 socket 端口 → 本 socket 发出的组播回环帧
    if (this._localAddrs.has(rinfo.address) && rinfo.port === sock.address().port) return;

    // 组播操作码启发式：Offer/Find 的解析违规按组播帧静默丢弃
    const multicastLike = buf.length >= 2 && ((buf[1] & 0x3f) === 0x01 || (buf[1] & 0x3f) === 0x02);
    const res = parseDatagram(buf, {
      ver: this.ver,
      maxPayloadLen: this.maxPayloadLen,
      multicastLike,
    });
    if (!res.ok) {
      // 解析失败：需要回 RST 时单播回源地址（§4.4）；否则静默丢弃
      if (res.rst) {
        this.sendUnicast(encodeFrame(res.rst), rinfo.address, rinfo.port, which === 'main' ? 'main' : 'client');
        this.log?.frame('warn', { dir: 'Tx', addr: `${rinfo.address}:${rinfo.port}`, code: res.rst.code, msg: `udp parse reject` });
      }
      return;
    }
    // 交付上层；meta 含源地址与接收 socket（单播响应路由用）
    this.emit('frame', res.frame, {
      transport: 'udp',
      address: rinfo.address,
      port: rinfo.port,
      socket: which,
    });
  }
}
