// ============================================================
// frame.js —— §3 帧格式 / §4.3 解析流程 / §4.1 TCP 流式解析（半帧两阶段）
//
// 帧头 8B：byte0(byte1) 2B 控制头 + SvcID/IfID 4B + InstID/StrmID 2B。
// 解析顺序（§3.1）：byte0 → byte1 → SvcID → IfID → InstID → StrmID
//                  → Length(PLB>0) → Mask(MSK=1) → Data
// ============================================================

import crypto from 'node:crypto';
import { RST_CODE } from '../errors.js';

// TYP 传输类型（§3.7）
export const TYP = Object.freeze({ NON: 0, CON: 1, ACK: 2, RST: 3 });
export const TYP_NAME = Object.freeze({ 0: 'NON', 1: 'CON', 2: 'ACK', 3: 'RST' });

// Code 常量（§3.4）
export const CODE = Object.freeze({
  // 数据帧（CTR=0）
  REQUEST: 0x01,
  FIRE_FORGET: 0x02,
  NOTIFICATION: 0x03,
  OK: 0x10,            // Response 唯一成功码
  // 控制帧（CTR=1）
  SD_OFFER: 0x01,
  SD_FIND: 0x02,
  SD_SUBSCRIBE: 0x03,
  SD_GET_IDL: 0x04,
  SD_SUBSCRIBE_ACK: 0x10, // Subscribe 确认（订阅已建立）
  SD_GET_IDL_RESP: 0x11,  // GetIDL 响应
});

// 控制帧 StrmID 语义校验依据（§4.3 步骤 4）：
//   Code∈{0x03,0x04} → StrmID 必须 0x01~0x7F（会话/查询）
//   Code∈{0x00,0x01,0x02} → StrmID 必须 0x00（连接级）
const CTRL_STRM_SESSION_CODES = new Set([0x03, 0x04]);
const CTRL_STRM_CONN_CODES = new Set([0x00, 0x01, 0x02]);

// ---------- 帧构造 ----------

/** 计算 PLB：len=0 → 0；否则最小可表示字节数（1~7，§3.2） */
export function calcPlb(len) {
  if (len === 0) return 0;
  for (let n = 1; n <= 7; n++) {
    if (len < 256 ** n) return n;
  }
  throw new Error(`payload length ${len} exceeds PLB=7 limit (2^56-1)`); // 不可达（Number 上限内）
}

/**
 * 构造完整帧字节。
 * @param {object} f { ctr=0, ren=0, ver=0, msk=0, typ, code, svc_id=0, if_id=0,
 *                     inst_id=0, strm_id=0, payload=null(Buffer), maskKey=null(4B) }
 * @returns {Buffer}
 */
export function encodeFrame(f) {
  const ctr = f.ctr ? 1 : 0;
  const ren = f.ren ? 1 : 0;
  const ver = f.ver ?? 0;
  const msk = f.msk ? 1 : 0;
  const payload = f.payload ?? Buffer.alloc(0);
  const plb = calcPlb(payload.length);

  const head = Buffer.alloc(8);
  // §3.2 byte0：CTR:1 | REN:1 | VER:2 | MSK:1 | PLB:3
  head[0] = (ctr << 7) | (ren << 6) | ((ver & 0x03) << 4) | (msk << 3) | plb;
  // §3.3 byte1：TYP:2 | Code:6
  head[1] = ((f.typ & 0x03) << 6) | (f.code & 0x3f);
  head.writeUInt16BE(f.svc_id ?? 0, 2);
  head.writeUInt16BE(f.if_id ?? 0, 4);
  head[6] = (f.inst_id ?? 0) & 0xff;
  head[7] = (f.strm_id ?? 0) & 0xff;

  const parts = [head];
  if (plb > 0) {
    const lb = Buffer.alloc(plb);
    for (let i = 0; i < plb; i++) lb[plb - 1 - i] = Math.floor(payload.length / 256 ** i) % 256;
    parts.push(lb);
  }
  let data = payload;
  if (msk) {
    // §10：MSK=1 时于 Payload Length 后插入 4B Key，对 Data 逐字节循环 XOR
    const key = f.maskKey ?? crypto.randomBytes(4);
    parts.push(key);
    data = Buffer.from(data);
    for (let i = 0; i < data.length; i++) data[i] ^= key[i % 4];
  }
  if (data.length > 0) parts.push(data);
  return Buffer.concat(parts);
}

/** 构造 RST 帧：TYP=RST，回显触发帧的 CTR 与标识字段（§5.4：RST 回显触发帧的 StrmID） */
export function makeRst(code, echo = {}) {
  return {
    ctr: echo.ctr ? 1 : 0,
    typ: TYP.RST,
    code,
    svc_id: echo.svc_id ?? 0,
    if_id: echo.if_id ?? 0,
    inst_id: echo.inst_id ?? 0,
    strm_id: echo.strm_id ?? 0,
    payload: Buffer.alloc(0), // §3.7：RST 帧 PLB 必须为 0
  };
}

// ---------- 帧头解析（§4.3 步骤 1~6，含全部一致性校验） ----------

/**
 * 解析帧头（byte0 至 Masking Key）并执行 §4.3 步骤 1~5 校验。
 * 返回：
 *   { state:'need_more' }                         —— 字节不足（TCP 等待）
 *   { state:'invalid', rst }                      —— 校验失败，rst 为应回的 RST 帧
 *   { state:'silent' }                            —— 组播帧静默丢弃
 *   { state:'ok', head, headerLen, payloadLen, maskKey, expectedTotal }
 *
 * opts: { ver=0, maxPayloadLen=1400, isUdp=false, multicastLike=false }
 *   multicastLike：组播场景（VER 违规/StrmID 语义违规时静默丢弃而非回 RST）。
 *     注：UDP 报文无法从 socket API 获知目的地址是否组播（平台限制），由传输层
 *     以启发式提供——组播操作码（Offer/Find/REN）一律视为组播帧。
 */
export function parseHeader(buf, offset, opts = {}) {
  const ver = opts.ver ?? 0;
  const maxPayloadLen = opts.maxPayloadLen ?? 1400;
  const isUdp = !!opts.isUdp;
  const multicastLike = !!opts.multicastLike;

  // ---- 步骤 1：读 byte0 → CTR/REN/VER/MSK/PLB ----
  if (buf.length - offset < 2) return { state: 'need_more' }; // byte0+byte1 至少 2B
  const byte0 = buf[offset];
  const byte1 = buf[offset + 1];
  const ctr = (byte0 >> 7) & 1;
  const ren = (byte0 >> 6) & 1;
  const fver = (byte0 >> 4) & 0x03;
  const msk = (byte0 >> 3) & 1;
  const plb = byte0 & 0x07;
  const typ = (byte1 >> 6) & 0x03;
  const code = byte1 & 0x3f;

  // §4.3 步骤 1：VER 与本端必须相等；不等 → 单播 RST(0x22)、组播静默
  if (fver !== ver) {
    return multicastLike
      ? { state: 'silent' }
      : { state: 'invalid', rst: makeRst(RST_CODE.UNSUPPORTED_VERSION, echoPartial(buf, offset, ctr)) };
  }
  // REN=1 时 CTR 必须为 1（数据帧 REN 恒为 0，§3.6）→ RST(0x00)
  if (ren === 1 && ctr !== 1) {
    return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echoPartial(buf, offset, ctr)) };
  }
  // §4.3 步骤 1：控制帧固定 MSK=0 且不附加 CRC（§9.6/§10 跨实现硬性约定）→ RST(0x00)
  if (ctr === 1 && msk === 1) {
    return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echoPartial(buf, offset, ctr)) };
  }

  // ---- 步骤 2：读 byte1 → TYP/Code 校验 ----
  // REN=1 固定 TYP=NON 且 Code=0x00（§3.6）→ RST(0x00)
  if (ren === 1 && (typ !== TYP.NON || code !== 0x00)) {
    return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echoPartial(buf, offset, ctr)) };
  }
  // ACK：Code∈{0x00} ∪ {0x10 仅 CTR=1}（§3.7/§8.1）且 PLB=0（无 Payload）→ RST(0x00)
  if (typ === TYP.ACK) {
    const okCode = code === 0x00 || (ctr === 1 && code === 0x10);
    if (!okCode || plb > 0) {
      return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echoPartial(buf, offset, ctr)) };
    }
  }
  // RST：PLB=0 且 Code∈{0x00} ∪ 0x20~0x3F（§3.7）→ RST(0x00)
  if (typ === TYP.RST) {
    const okCode = code === 0x00 || (code >= 0x20 && code <= 0x3f);
    if (!okCode || plb > 0) {
      return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echoPartial(buf, offset, ctr)) };
    }
  }
  // TCP 不使用 CON/ACK（§3.7）→ RST(0x00)
  if (!isUdp && (typ === TYP.CON || typ === TYP.ACK)) {
    return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echoPartial(buf, offset, ctr)) };
  }
  // GetIDL 仅走 TCP 单播（§7.2）：UDP 上收到 → RST(0x00)，组播帧静默丢弃
  if (isUdp && ctr === 1 && code === 0x04) {
    return multicastLike
      ? { state: 'silent' }
      : { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echoPartial(buf, offset, ctr)) };
  }

  // ---- 步骤 3：SvcID/IfID 校验（ID=0 通配仅 SD Entry 场景，§3.5） ----
  if (buf.length - offset < 8) {
    // 步骤 3/4 需要完整 8B 帧头；先做可判定的字段再等待
    return { state: 'need_more', partial: { byte0, byte1, ctr, ren, msk, plb, typ, code } };
  }
  const svcId = buf.readUInt16BE(offset + 2);
  const ifId = buf.readUInt16BE(offset + 4);
  const instId = buf[offset + 6];
  const strmId = buf[offset + 7];
  const echo = { ctr, svc_id: svcId, if_id: ifId, inst_id: instId, strm_id: strmId };

  if (ctr === 1) {
    // 控制帧 SvcID=0x0000 且 IfID=0x0000（§4.3 步骤 3）
    if (svcId !== 0 || ifId !== 0) {
      return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
    }
  } else {
    // 数据帧 SvcID≠0 且 IfID≠0（§4.3 步骤 3）
    if (svcId === 0 || ifId === 0) {
      return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
    }
  }

  // ---- 步骤 4：InstID/StrmID 校验 ----
  if (ctr === 1) {
    // 控制帧 InstID=0、REN=1 时 StrmID=0（§4.3 步骤 4）
    if (instId !== 0) return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
    if (ren === 1 && strmId !== 0) return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
    if (typ === TYP.RST) {
      // RST 帧豁免 StrmID 校验（实现偏差，见 README）：StrmID 是 §5.4 的回显字段
      // （回显触发帧值，数据帧触发时可达 0xFF）——若按控制帧语义/范围校验，
      // 会形成"RST 判违规 → 回 RST → 对端再判违规"的互射风暴
    } else {
      // 控制帧 StrmID 范围：0x00（连接级）或 0x01~0x7F（会话/查询）→ 否则 RST(0x00)
      if (strmId > 0x7f) return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
      // 控制帧 StrmID 语义校验（§4.3 步骤 4）：
      //   Code∈{0x03,0x04} → StrmID∈0x01~0x7F；Code∈{0x00,0x01,0x02} → StrmID=0x00
      if (CTRL_STRM_SESSION_CODES.has(code) && strmId === 0) {
        return multicastLike ? { state: 'silent' } : { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
      }
      if (CTRL_STRM_CONN_CODES.has(code) && strmId !== 0) {
        // 例外（§3.7 专项定案优先）：取消确认 ACK(Code=0x00) 回显会话 StrmID（0x01~0x7F）；
        // 其余 Code=0x00 帧（心跳 Ping/REN）StrmID 仍必须 0x00
        if (!(typ === TYP.ACK && code === 0x00)) {
          return multicastLike ? { state: 'silent' } : { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
        }
      }
    }
  } else {
    // 数据帧 InstID≠0x00（§4.3 步骤 4）
    if (instId === 0) return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
    // 数据帧 StrmID∈0x01~0xFE（0x00 连接级禁用、0xFF 保留，§6.1）→ 越界 RST(0x00)
    if (strmId < 0x01 || strmId > 0xfe) {
      return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
    }
  }

  // ---- 步骤 5：读 Payload Length（plb 字节）；PLB=0 时 Length=0 ----
  const headerLen = 8 + plb + (msk ? 4 : 0);
  if (buf.length - offset < headerLen) return { state: 'need_more' };
  let payloadLen = 0;
  for (let i = 0; i < plb; i++) payloadLen = payloadLen * 256 + buf[offset + 8 + i];
  // UDP 帧级校验：超 max_payload_len → RST(0x23)（§4.3 步骤 5，仅 UDP）
  if (isUdp && payloadLen > maxPayloadLen) {
    return { state: 'invalid', rst: makeRst(RST_CODE.PAYLOAD_TOO_LARGE, echo) };
  }

  // ---- 步骤 6：MSK=1 读 4B Masking Key ----
  let maskKey = null;
  if (msk) {
    maskKey = Buffer.from(buf.subarray(offset + 8 + plb, offset + 8 + plb + 4));
  }

  const expectedTotal = headerLen + payloadLen;
  // ver 随帧交付（§3.2 byte0 VER:2bit）：供发现缓存记录帧版本（§7.2 Offer）与
  // is_available 的 VER 相等判定（§13.2）使用——此前缺失导致 rec.ver 恒为 0
  return { state: 'ok', ver: fver, headerLen, payloadLen, maskKey, expectedTotal, ctr, ren, msk, plb, typ, code, svcId, ifId, instId, strmId };
}

// 从（可能不完整的）帧头字节尽力提取回显字段（RST 回显用，§5.4）
function echoPartial(buf, offset, ctr) {
  const e = { ctr };
  if (buf.length - offset >= 8) {
    e.svc_id = buf.readUInt16BE(offset + 2);
    e.if_id = buf.readUInt16BE(offset + 4);
    e.inst_id = buf[offset + 6];
    e.strm_id = buf[offset + 7];
  } else if (buf.length - offset >= 4) {
    e.svc_id = buf.readUInt16BE(offset + 2);
  }
  return e;
}

/**
 * UDP 单报文解析（§4.2 + §4.3 十步）。
 * @returns { ok:true, frame } | { ok:false, rst? }   —— rst 缺省表示静默丢弃
 */
export function parseDatagram(buf, opts = {}) {
  // §4.2：数据报长度 < 最小帧长度（8B）→ 丢弃
  if (buf.length < 8) return { ok: false };

  const h = parseHeader(buf, 0, { ...opts, isUdp: true });
  if (h.state === 'need_more') return { ok: false };            // 声明字段读不全 → 长度不符 → 丢弃
  if (h.state === 'silent') return { ok: false };
  if (h.state === 'invalid') return { ok: false, rst: h.rst };

  // §4.2：数据报长度 ≠ 帧头声明长度（多余或不足）→ 一律丢弃（不做截断）
  if (buf.length !== h.expectedTotal) return { ok: false };

  // 步骤 7：读 Payload；MSK=1 则 XOR 还原
  let payload = buf.subarray(h.headerLen, h.expectedTotal);
  if (h.msk) payload = xorMask(payload, h.maskKey);

  // 步骤 8：组装 Frame 交付（ver 随帧传出，§3.2 —— 发现缓存/is_available VER 判定依赖）
  return {
    ok: true,
    frame: {
      ver: h.ver, ctr: h.ctr, ren: h.ren, msk: h.msk, typ: h.typ, code: h.code,
      svc_id: h.svcId, if_id: h.ifId, inst_id: h.instId, strm_id: h.strmId,
      payload,
    },
  };
}

function xorMask(data, key) {
  const out = Buffer.from(data);
  for (let i = 0; i < out.length; i++) out[i] ^= key[i % 4];
  return out;
}

// ============================================================
// TCP 流式解析器（§4.1）：IDLE → READ_CTRL_SVC → READ_IF_INST_STRM
//   → READ_LENGTH → READ_MASK → READ_PAYLOAD → FRAME_COMPLETE → IDLE
// 分包保存状态等待；粘包逐帧交付；半帧两阶段由连接管理层驱动。
// ============================================================

export class TcpStreamParser {
  /**
   * @param {object} opts { ver=0, onFrame(frame), onRst(rst), onDropComplete() }
   */
  constructor(opts = {}) {
    this.opts = opts;
    this.buf = Buffer.alloc(0);   // 待解析字节（分包不丢弃已读字节，§4.1）
    this.receiving = false;       // 是否有帧正在接收（帧首字节已到达且未交付）
    this.headerInfo = null;       // 当前帧已解析的头信息（帧头完整后非空）
    this.receivedBytes = 0;       // 当前帧已收总字节数（含帧头）
    // 丢弃模式（§4.1 阶段二）
    this.dropMode = false;
    this.dropRemaining = 0;       // 丢弃模式剩余待丢弃字节数（R = L − 已收）
  }

  /** 是否有帧正在接收（供半帧超时判定） */
  isReceiving() { return this.receiving || this.dropMode; }

  /** 当前帧帧头是否已收齐（≥8B 含 Length/Masking Key，§4.1 阶段判定） */
  isHeaderComplete() { return this.headerInfo !== null; }

  /** 当前帧声明总长 L 与已收字节数（供丢弃模式计算 R = L − 已收） */
  getFrameInfo() {
    return { total: this.headerInfo?.expectedTotal ?? 0, received: this.receivedBytes };
  }

  /**
   * 进入丢弃模式（帧头完整、Payload 不完整时由连接层调用，§4.1）。
   * 已收的当前帧字节（buf）立即全部丢弃（帧已作废）；剩余 R = L − 已收 字节
   * 从后续到达的字节中精确消耗，收满后恢复 IDLE。
   */
  enterDropMode() {
    if (!this.headerInfo) return;
    const info = this.headerInfo;
    this.dropMode = true;
    this.dropRemaining = info.expectedTotal - this.receivedBytes;
    this.receiving = false;
    this.headerInfo = null;
    this.receivedBytes = 0;
    this.buf = Buffer.alloc(0); // 已收的当前帧字节全部作废（receivedBytes 与 buf.length 恒等）
    this._consumeDrop();
  }

  /** 喂入字节块；触发 onFrame/onRst/onDropComplete 回调 */
  feed(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    this._loop();
  }

  _loop() {
    // 先消耗丢弃模式
    if (this.dropMode) {
      this._consumeDrop();
      if (this.buf.length === 0) return;
    }
    // 逐帧解析（粘包逐帧交付，§4.1）
    for (;;) {
      if (this.buf.length === 0) {
        // 缓冲耗尽：若尚未收到任何当前帧字节，退出接收状态（避免空帧误触半帧超时）
        if (!this.headerInfo && this.receivedBytes === 0) this.receiving = false;
        break;
      }
      if (!this.receiving) {
        // 新帧开始：首字节到达（§4.1 半帧计时起点由连接层依据 receiving 判定）
        this.receiving = true;
        this.receivedBytes = 0;
        this.headerInfo = null;
      }
      const h = parseHeader(this.buf, 0, { ver: this.opts.ver ?? 0 });
      if (h.state === 'need_more') break; // 分包：保存状态等待（§4.1）

      if (h.state === 'invalid') {
        // 违规帧：回 RST。若能读出声明帧总长则精确跳过该帧继续解析；无法定界则清空缓冲。
        this.opts.onRst?.(h.rst);
        const b0 = this.buf[0];
        const plb = b0 & 0x07;
        const hasMsk = ((b0 >> 3) & 1) === 1;
        const headLen = 8 + plb + (hasMsk ? 4 : 0);
        let skipped = false;
        if (this.buf.length >= headLen) {
          let plen = 0;
          for (let i = 0; i < plb; i++) plen = plen * 256 + this.buf[8 + i];
          const total = headLen + plen;
          if (this.buf.length >= total) {
            this.buf = this.buf.subarray(total); // 跳过违规帧，继续解析后续帧
            this.receiving = false;
            this.headerInfo = null;
            skipped = true;
          }
        }
        if (!skipped) {
          // 无法定界（Payload Length 值未到齐）：清空缓冲（违规帧尾无法重同步）
          this.buf = Buffer.alloc(0);
          this.receiving = false;
          this.headerInfo = null;
          break;
        }
        continue;
      }
      // h.state === 'ok'：帧头已解析，等 Payload
      this.headerInfo = h;
      if (this.buf.length < h.expectedTotal) {
        this.receivedBytes = this.buf.length; // 当前帧已收字节（此前帧均已消费）
        break; // 分包：保存状态等待（§4.1）
      }
      // 收齐：交付（ver 随帧传出，§3.2 —— 与 parseDatagram 交付口径一致）
      let payload = this.buf.subarray(h.headerLen, h.expectedTotal);
      if (h.msk) payload = xorMask(payload, h.maskKey);
      const frame = {
        ver: h.ver, ctr: h.ctr, ren: h.ren, msk: h.msk, typ: h.typ, code: h.code,
        svc_id: h.svcId, if_id: h.ifId, inst_id: h.instId, strm_id: h.strmId,
        payload,
      };
      this.buf = this.buf.subarray(h.expectedTotal);
      this.receiving = false;
      this.headerInfo = null;
      this.receivedBytes = 0;
      this.opts.onFrame?.(frame);
    }
  }

  /** 丢弃模式字节消耗（§4.1：精确丢弃 R 字节，收满恢复 IDLE） */
  _consumeDrop() {
    while (this.dropMode && this.dropRemaining > 0) {
      if (this.buf.length === 0) return; // 待丢弃字节未到齐，等待后续 feed
      const n = Math.min(this.dropRemaining, this.buf.length);
      this.buf = this.buf.subarray(n);   // 从 buf 头部精确消耗（后续 feed 字节持续追加）
      this.dropRemaining -= n;
    }
    if (this.dropMode && this.dropRemaining === 0) {
      // 退出条件 1：收满剩余 R 字节 → 恢复正常接收（连接继续复用，§4.1）
      this.dropMode = false;
      this.opts.onDropComplete?.();
      if (this.buf.length > 0) this._loop(); // 剩余字节属于后续帧，继续正常解析
    }
  }
}
