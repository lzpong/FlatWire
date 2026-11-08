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
  // GetIDL 查询(0x04) 与 GetIDL 响应(0x11) 仅走 TCP 单播（§7.2）：
  // UDP 上收到 → RST(0x00)，组播帧静默丢弃
  if (isUdp && ctr === 1 && (code === 0x04 || code === 0x11)) {
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

  // ---- 步骤 3/4 豁免：任何 TYP=RST 都不校验 ID（§4.3 步骤 3/4 / §5.4） ----
  // RST 的 SvcID/IfID/InstID/StrmID 是回显字段，取值来自触发帧，可能超出
  // 控制帧或数据帧的合法范围（数据帧触发时 StrmID 可达 0xFE、SvcID/IfID 可能
  // 为 0x0000）。RST 自身也可能是数据帧（CTR=0），回显越界 ID 同样合法，
  // 因此不区分 CTR=1（控制帧）/CTR=0（数据帧）。若仍按步骤 3/4 校验，双方会
  // "RST 判违规 → 回 RST → 对端再判违规"，形成 RST 回环风暴。
  // RST 的形态与 Code 值域已在步骤 2 校验，故此处仅豁免 ID 相关校验。
  if (typ !== TYP.RST) {
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
      // 控制帧 StrmID 范围：0x00（连接级）或 0x01~0x7F（会话/查询）→ 否则 RST(0x00)
      if (strmId > 0x7f) return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
      // 控制帧 StrmID 语义校验（§4.3 步骤 4）：
      //   Code∈{0x03,0x04} → StrmID∈0x01~0x7F；Code∈{0x00,0x01,0x02} → StrmID=0x00
      //   例外二（口径定案）：ACK(0x10)/GetIDL 响应(0x11) 不参与流绑定校验，StrmID=0 合法。
      //   二者不在上述两个集合内，故不做语义判定——此处仅保留注释，防止后续误加约束。
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
    } else {
      // 数据帧 InstID≠0x00（§4.3 步骤 4）
      if (instId === 0) return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
      // 数据帧 StrmID∈0x01~0xFE（0x00 连接级禁用、0xFF 保留，§6.1）→ 越界 RST(0x00)
      if (strmId < 0x01 || strmId > 0xfe) {
        return { state: 'invalid', rst: makeRst(RST_CODE.PROTOCOL_VIOLATION, echo) };
      }
    }
  }

  // ---- 步骤 5：读 Payload Length（plb 字节）；PLB=0 时 Length=0 ----
  const headerLen = 8 + plb + (msk ? 4 : 0);
  if (buf.length - offset < headerLen) return { state: 'need_more' };
  let payloadLen = 0;
  for (let i = 0; i < plb; i++) payloadLen = payloadLen * 256 + buf[offset + 8 + i];
  // §3.2 Length 语义：PLB=7 时协议上限 2^56−1；JS Number 仅 2^53−1 以内可精确表示。
  // 超出精确整数范围时，声明值无法可靠参与帧边界比较（会错位定界），按实现承载
  // 上限处理：UDP 视为帧级超限（RST 0x23），TCP 视为协议违规（RST 0x00）；
  // 绝不截断成小值后再定界。参考实现实际单帧上限另受 Buffer 容量约束。
  if (payloadLen > Number.MAX_SAFE_INTEGER) {
    return { state: 'invalid', rst: makeRst(
      isUdp ? RST_CODE.PAYLOAD_TOO_LARGE : RST_CODE.PROTOCOL_VIOLATION, echo) };
  }
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

// TCP 解析器空缓冲常量（_resetBuf 复用，避免逐帧分配空 Buffer）
const EMPTY_BUF = Buffer.alloc(0);

export class TcpStreamParser {
  /**
   * @param {object} opts { ver=0, onFrame(frame), onRst(rst), onDropComplete() }
   */
  constructor(opts = {}) {
    this.opts = opts;
    // 接收缓冲：底层容量缓冲 buf + 有效区间 [off, fill)。
    // 不再对每个到达的块做 Buffer.concat（那会每次重拷已缓冲字节 → 大帧分片 O(n²)）；
    // 追加为摊销 O(1)，消费仅移动 off，必要时按"消费过半"策略压实（摊销 O(n)）。
    this.buf = EMPTY_BUF;
    this.off = 0;                 // 未消费字节起点（当前帧首字节）
    this.fill = 0;                // 已填充字节终点
    this.cap = 0;                 // 缓冲容量（buf.length）
    this.receiving = false;       // 是否有帧正在接收（帧首字节已到达且未交付）
    this.headerInfo = null;       // 当前帧已解析的头信息（帧头完整后非空）
    this.receivedBytes = 0;       // 当前帧已收总字节数（含帧头）
    // 丢弃模式（§4.1 阶段二）
    this.dropMode = false;
    this.dropRemaining = 0;       // 丢弃模式剩余待丢弃字节数（R = L − 已收）
    // 违规帧定界状态（§4.1）：违规帧已回 RST，但其帧尾字节同样必须完整消费，
    // 否则残留字节会与后续帧首字节拼成"合法"帧（帧走私/边界错位）。
    this.invalidPending = false;  // 帧头（含 Length/Mask）未收齐，等待到齐后定界
    this.invalidHeadLen = 0;
    this.abandoned = false;       // 声明长度超出可精确表示范围，同步已丢失（等连接层超时关闭）
  }

  /** 是否有帧正在接收（供半帧超时判定） */
  isReceiving() { return this.receiving || this.dropMode || this.invalidPending || this.abandoned; }

  /** 当前帧帧头是否已收齐（≥8B 含 Length/Masking Key，§4.1 阶段判定） */
  isHeaderComplete() { return this.headerInfo !== null; }

  /** 当前帧声明总长 L 与已收字节数（供丢弃模式计算 R = L − 已收） */
  getFrameInfo() {
    return { total: this.headerInfo?.expectedTotal ?? 0, received: this.receivedBytes };
  }

  /**
   * 从当前帧已收字节中取 StrmID（字节 7）；未收满 8B 返回 0。
   * 供连接层半帧阶段二的 RST 回显使用（§5.4）。必须基于有效区间起点 off 取址——
   * 同一缓冲内可能已消费过多帧，绝对下标会读到上一帧或未消费区域的字节。
   */
  currentStrmId() {
    if (this._avail() < 8) return 0;
    return this.buf[this.off + 7];
  }

  /** 当前未消费字节数（有效区间长度） */
  _avail() { return this.fill - this.off; }

  /**
   * 清空有效区间（§4.1 消费完当前帧）。
   * 一律释放底层缓冲：空缓冲时 feed() 会零拷贝接管新块（见 feed 的 avail===0 分支），
   * 保留缓冲没有任何性能收益；反而会让已交付的 payload 视图（subarray 指向同一内存）
   * 在后续 feed 写回前部时被覆写（别名风险）。释放后视图仍指向旧 Buffer 对象，安全。
   */
  _resetBuf() {
    this.off = 0;
    this.fill = 0;
    this.buf = EMPTY_BUF;
    this.cap = 0;
  }

  /** 消费前 n 字节；必要时压实（消费过半才搬迁，搬迁总代价摊销 O(n)） */
  _consume(n) {
    this.off += n;
    if (this.off >= this.fill) { this._resetBuf(); return; }
    if (this.off >= 4096 && this.off >= this.fill - this.off) this._compact();
  }

  /** 压实：把未消费区间搬回缓冲起点（用独立缓冲，避免 Buffer.copy 重叠语义不确定） */
  _compact() {
    const avail = this.fill - this.off;
    if (avail === 0) { this._resetBuf(); return; }
    const nc = avail * 2 > 1024 ? avail * 2 : 1024; // 预留约一半尾部空间供后续追加
    const nb = Buffer.allocUnsafe(nc);
    this.buf.copy(nb, 0, this.off, this.fill);
    this.buf = nb;
    this.cap = nc;
    this.fill = avail;
    this.off = 0;
  }

  /** 进入丢弃模式（帧头完整、Payload 不完整时由连接层调用，§4.1）。
   * 已收的当前帧字节立即全部丢弃；剩余 R = L − 已收 从后续字节精确消耗，收满恢复 IDLE。 */
  enterDropMode() {
    if (!this.headerInfo) return;
    const info = this.headerInfo;
    this.dropMode = true;
    this.dropRemaining = info.expectedTotal - this.receivedBytes;
    this.receiving = false;
    this.headerInfo = null;
    this.receivedBytes = 0;
    this._resetBuf(); // 已收的当前帧字节全部作废（receivedBytes 与 avail 恒等）
    this._consumeDrop();
  }

  /** 喂入字节块；触发 onFrame/onRst/onDropComplete 回调 */
  feed(chunk) {
    if (this.abandoned) return; // 同步已丢失：不再缓冲（连接层半帧超时会关闭连接）
    if (chunk.length === 0) return;
    const avail = this._avail();
    if (avail === 0 && this.off === 0) {
      // 缓冲为空：直接接管本块（零拷贝，常见路径）
      this.buf = chunk;
      this.cap = chunk.length;
      this.fill = chunk.length;
      this.off = 0;
      this._loop();
      return;
    }
    if (this.fill + chunk.length > this.cap) {
      // 尾部空间不足：先压实腾出空间；仍不足则按需扩容（几何增长，摊销 O(1) 追加）
      if (this.off > 0) this._compact();
      if (this.fill + chunk.length > this.cap) {
        let nc = this.cap ? this.cap : 1024;
        while (nc < this.fill + chunk.length) nc *= 2;
        const nb = Buffer.allocUnsafe(nc);
        if (this.fill > 0) this.buf.copy(nb, 0, 0, this.fill);
        this.buf = nb;
        this.cap = nc;
      }
    }
    chunk.copy(this.buf, this.fill);
    this.fill += chunk.length;
    this._loop();
  }

  /**
   * 违规帧定界（§4.1）：违规帧已回 RST，但其帧尾字节必须完整消费——若直接清空
   * 缓冲，帧尾残留会与后续帧首字节拼成"合法"帧（帧走私/帧边界错位）。
   * 帧头（含 Length/Mask）到齐后按声明总长精确跳过；未收齐则进入丢弃模式。
   * @returns {boolean} true=已定界（可继续解析）；false=需等待更多字节/同步已丢失
   */
  _resolveInvalid() {
    const avail = this._avail();
    if (avail < this.invalidHeadLen) return false; // 帧头未齐：保留缓冲等待
    const b0 = this.buf[this.off];
    const plb = b0 & 0x07;
    let plen = 0;
    for (let i = 0; i < plb; i++) plen = plen * 256 + this.buf[this.off + 8 + i];
    const total = this.invalidHeadLen + plen;
    this.invalidPending = false;
    this.invalidHeadLen = 0;
    if (!Number.isSafeInteger(total)) {
      // 声明长度超出 JS 精确表示范围（§3.2 64 位语义）：无法定界且不得截断，
      // 置同步丢失——继续接收已无意义，交由连接层半帧超时按 §4.1 阶段一关闭连接。
      this._resetBuf();
      this.abandoned = true;
      this.receiving = false;
      this.headerInfo = null;
      this.receivedBytes = 0;
      return false;
    }
    if (avail >= total) {
      this._consume(total); // 跳过整个违规帧，继续解析后续帧
      this.receiving = false;
      this.headerInfo = null;
      this.receivedBytes = 0;
      return true;
    }
    // 帧尾未到齐：进入丢弃模式，剩余 R = L − 已收 从后续字节精确消耗（§4.1 阶段二）
    this.dropMode = true;
    this.dropRemaining = total - avail;
    this.receiving = false;
    this.headerInfo = null;
    this.receivedBytes = 0;
    this._resetBuf(); // 已收的当前帧字节全部作废
    return true;
  }

  _loop() {
    if (this.abandoned) return;
    // 先消耗丢弃模式
    if (this.dropMode) {
      this._consumeDrop();
      if (this._avail() === 0) return;
    }
    // 违规帧帧头到齐后定界（RST 已在首次判定时回复，此处不重复）
    if (this.invalidPending) {
      if (!this._resolveInvalid()) return;
      if (this.dropMode) {
        this._consumeDrop();
        if (this._avail() === 0) return;
      }
    }
    // 逐帧解析（粘包逐帧交付，§4.1）
    for (;;) {
      const avail = this._avail();
      if (avail === 0) {
        // 缓冲耗尽：若尚未收到任何当前帧字节，退出接收状态（避免空帧误触半帧超时）
        if (!this.headerInfo && this.receivedBytes === 0) this.receiving = false;
        return;
      }
      if (!this.receiving) {
        // 新帧开始：首字节到达（§4.1 半帧计时起点由连接层依据 receiving 判定）
        this.receiving = true;
        this.receivedBytes = 0;
        this.headerInfo = null;
      }
      // 交给解析器的是 [off, fill) 的视图（subarray 不复制，避免整段拷贝）
      const h = parseHeader(this.buf.subarray(this.off, this.fill), 0, { ver: this.opts.ver ?? 0 });
      if (h.state === 'need_more') break; // 分包：保存状态等待（§4.1）

      if (h.state === 'invalid') {
        // 违规帧：立即回 RST（同一违规帧只回一次）。随后必须按声明长度定界：
        // 帧头未齐先等待，到齐后跳过整帧或进入丢弃模式。
        this.opts.onRst?.(h.rst);
        const b0 = this.buf[this.off];
        this.invalidPending = true;
        this.invalidHeadLen = 8 + (b0 & 0x07) + (((b0 >> 3) & 1) === 1 ? 4 : 0);
        if (!this._resolveInvalid()) return;
        if (this.dropMode) {
          this._consumeDrop();
          if (this._avail() === 0) return;
        }
        continue;
      }
      // h.state === 'ok'：帧头已解析，等 Payload
      this.headerInfo = h;
      if (avail < h.expectedTotal) {
        this.receivedBytes = avail; // 当前帧已收字节（此前帧均已消费）
        break; // 分包：保存状态等待（§4.1）
      }
      // 收齐：交付（ver 随帧传出，§3.2 —— 与 parseDatagram 交付口径一致）
      let payload = this.buf.subarray(this.off + h.headerLen, this.off + h.expectedTotal);
      if (h.msk) payload = xorMask(payload, h.maskKey);
      const frame = {
        ver: h.ver, ctr: h.ctr, ren: h.ren, msk: h.msk, typ: h.typ, code: h.code,
        svc_id: h.svcId, if_id: h.ifId, inst_id: h.instId, strm_id: h.strmId,
        payload,
      };
      this._consume(h.expectedTotal);
      this.receiving = false;
      this.headerInfo = null;
      this.receivedBytes = 0;
      this.opts.onFrame?.(frame);
    }
  }

  /** 丢弃模式字节消耗（§4.1：精确丢弃 R 字节，收满恢复 IDLE） */
  _consumeDrop() {
    while (this.dropMode && this.dropRemaining > 0) {
      const avail = this._avail();
      if (avail === 0) return; // 待丢弃字节未到齐，等待后续 feed
      const n = Math.min(this.dropRemaining, avail);
      this._consume(n); // 从有效区间头部精确消耗（后续 feed 字节持续追加）
      this.dropRemaining -= n;
    }
    if (this.dropMode && this.dropRemaining === 0) {
      // 退出条件 1：收满剩余 R 字节 → 恢复正常接收（连接继续复用，§4.1）
      this.dropMode = false;
      this.opts.onDropComplete?.();
      if (this._avail() > 0) this._loop(); // 剩余字节属于后续帧，继续正常解析
    }
  }
}
