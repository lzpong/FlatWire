// ============================================================
// retransmit.js —— §5.5 CON/ACK 可靠性（仅 UDP）：重传时间线管理
//
// 时间线（interval=200ms, max_retry=3）：
//   首发由调用方完成（t=0）；重传 1@200ms、重传 2@600ms、重传 3@1400ms；
//   末次发送后等待 1600ms（t=3000ms）静默停止，不报错（§5.5）。
// 重传使用同一 StrmID 与完全相同的字节（§5.5 发送方规则）。
// 数据帧（Request/FF/Notification CON）与控制帧（Subscribe 首次/取消）共用本表。
// ============================================================

export class RetransmitTable {
  constructor(opts = {}) {
    this.intervalMs = opts.intervalMs ?? 200;
    this.maxRetry = opts.maxRetry ?? 3;
    this._entries = new Map(); // key → { buf, sendFn, timer }（链式单定时器）
    this._delayCache = null;   // 延迟序列只算一次（interval/maxRetry 不变）
  }

  /** 延迟序列：[i, i+i·2, i+i·2+i·4, …末次后 i·2^max]（§5.5 退避公式） */
  _delays() {
    if (this._delayCache) return this._delayCache;
    const d = [];
    let acc = 0;
    for (let r = 1; r <= this.maxRetry; r++) {
      acc += this.intervalMs * 2 ** (r - 1);
      d.push(acc);
    }
    d.push(acc + this.intervalMs * 2 ** this.maxRetry); // 静默停止时刻（清理）
    this._delayCache = d;
    return d;
  }

  /**
   * 登记重传（首发已由调用方完成）。
   * 每个待确认项只保留 **1 个** 活跃定时器（链式重排）：原实现按
   * 200/600/1400/3000ms 一次性创建 4 个 Timer，1000 条待确认即 4000 个
   * Timer 对象，事件循环与 GC 压力随并发线性放大 4 倍。
   * @param {string} key 去重键 `(peer,svc,inst,strm)` 字符串（控制帧为 `(peer,0,0,strm)`）
   * @param {Buffer} raw 重传使用的完全相同字节
   * @param {(buf: Buffer) => void} sendFn 发送函数
   */
  start(key, raw, sendFn) {
    this.cancel(key);
    const entry = { buf: raw, sendFn, timer: null };
    this._entries.set(key, entry);
    this._arm(key, entry, 0);
  }

  /** 链式定时器：idx 指向 delays 中的下一事件，任何时刻只排一个 setTimeout */
  _arm(key, entry, idx) {
    const delays = this._delays();
    const prev = idx > 0 ? delays[idx - 1] : 0;
    entry.timer = setTimeout(() => {
      if (this._entries.get(key) !== entry) return; // 已取消或被新登记替换
      if (idx < delays.length - 1) {
        entry.sendFn(entry.buf); // 重传 1..maxRetry（200/600/1400ms）
        this._arm(key, entry, idx + 1);
      } else {
        // 末次后等待到期：静默停止，清理待确认记录，不报错（§5.5 重传耗尽语义）
        this._entries.delete(key);
        entry.timer = null;
      }
    }, delays[idx] - prev);
  }

  /** 收到 ACK/响应：取消重传（§5.5） */
  cancel(key) {
    const e = this._entries.get(key);
    if (e) {
      if (e.timer) clearTimeout(e.timer);
      this._entries.delete(key);
      return true;
    }
    return false;
  }

  has(key) { return this._entries.has(key); }

  /** 收到 REN=1：清空该对端全部待确认重传记录（§3.6） */
  clearPeer(peerPrefix) {
    for (const key of [...this._entries.keys()]) {
      if (key.startsWith(peerPrefix)) this.cancel(key);
    }
  }

  get size() { return this._entries.size; }
}
