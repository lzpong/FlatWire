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
    this._entries = new Map(); // key → { buf, sendFn, timers:[], done }
  }

  /** 延迟序列：[i, i+i·2, i+i·2+i·4, …末次后 i·2^max]（§5.5 退避公式） */
  _delays() {
    const d = [];
    let acc = 0;
    for (let r = 1; r <= this.maxRetry; r++) {
      acc += this.intervalMs * 2 ** (r - 1);
      d.push(acc);
    }
    d.push(acc + this.intervalMs * 2 ** this.maxRetry); // 静默停止时刻（清理）
    return d;
  }

  /**
   * 登记重传（首发已由调用方完成）。
   * @param {string} key 去重键 `(peer,svc,inst,strm)` 字符串（控制帧为 `(peer,0,0,strm)`）
   * @param {Buffer} raw 重传使用的完全相同字节
   * @param {(buf: Buffer) => void} sendFn 发送函数
   */
  start(key, raw, sendFn) {
    this.cancel(key);
    const entry = { buf: raw, sendFn, timers: [] };
    this._entries.set(key, entry);
    const delays = this._delays();
    delays.forEach((delay, idx) => {
      const t = setTimeout(() => {
        if (this._entries.get(key) !== entry) return;
        if (idx < delays.length - 1) {
          sendFn(raw); // 重传 1..max_retry
        } else {
          // 末次后等待到期：静默停止，清理待确认记录，不报错（§5.5 重传耗尽语义）
          this._entries.delete(key);
        }
      }, delay);
      entry.timers.push(t);
    });
  }

  /** 收到 ACK/响应：取消重传（§5.5） */
  cancel(key) {
    const e = this._entries.get(key);
    if (e) {
      for (const t of e.timers) clearTimeout(t);
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
