// ============================================================
// entries.js —— §7.1 SD Entry 格式编解码
//
//   Offer Entry (6B):     Find Entry (4B):      Subscribe Entry (7B):    GetIDL Entry (3B):
//     uint16  SvcID         uint16  SvcID         uint16  SvcID            uint16  SvcID
//     uint8   InstID        uint8   InstID        uint16  IfID             uint8   MajorVer
//     uint8   MajorVer      uint8   MajorVer      uint8   InstID
//     uint8   MinorVer                            uint8   GrpId
//     uint8   TTL(0=停止)                         uint8   TTL(0=取消,秒)
//
// 多字节整数统一大端（§2）。
// ============================================================

export const ENTRY_SIZE = Object.freeze({
  OFFER: 6,
  FIND: 4,
  SUBSCRIBE: 7,
  GET_IDL: 3,
});

// ---- Offer Entry（6B）：周期广播 / Find 响应（响应帧格式与 Offer 相同，§7.2） ----
export function encodeOfferEntries(entries) {
  const buf = Buffer.alloc(entries.length * ENTRY_SIZE.OFFER);
  entries.forEach((e, i) => {
    const o = i * 6;
    buf.writeUInt16BE(e.svc_id, o);
    buf[o + 2] = e.inst_id & 0xff;
    buf[o + 3] = e.major_ver & 0xff;
    buf[o + 4] = (e.minor_ver ?? 0) & 0xff;
    buf[o + 5] = e.ttl & 0xff; // TTL 以秒为单位携带（§7.1）
  });
  return buf;
}

export function decodeOfferEntries(payload) {
  const out = [];
  for (let o = 0; o + ENTRY_SIZE.OFFER <= payload.length; o += ENTRY_SIZE.OFFER) {
    out.push({
      svc_id: payload.readUInt16BE(o),
      inst_id: payload[o + 2],
      major_ver: payload[o + 3],
      minor_ver: payload[o + 4],
      ttl: payload[o + 5],
    });
  }
  return out;
}

// ---- Find Entry（4B）：请求查询格式（无 MinorVer：MinorVer 不参与匹配，§7.1） ----
export function encodeFindEntries(entries) {
  const buf = Buffer.alloc(entries.length * ENTRY_SIZE.FIND);
  entries.forEach((e, i) => {
    const o = i * 4;
    buf.writeUInt16BE(e.svc_id, o);
    buf[o + 2] = (e.inst_id ?? 0) & 0xff; // 0x00 通配
    buf[o + 3] = (e.major_ver ?? 0) & 0xff;
  });
  return buf;
}

export function decodeFindEntries(payload) {
  const out = [];
  for (let o = 0; o + ENTRY_SIZE.FIND <= payload.length; o += ENTRY_SIZE.FIND) {
    out.push({
      svc_id: payload.readUInt16BE(o),
      inst_id: payload[o + 2],
      major_ver: payload[o + 3],
    });
  }
  return out;
}

// ---- Subscribe Entry（7B）：订阅是接口级行为，保留 IfID（§7.1） ----
export function encodeSubscribeEntries(entries) {
  const buf = Buffer.alloc(entries.length * ENTRY_SIZE.SUBSCRIBE);
  entries.forEach((e, i) => {
    const o = i * 7;
    buf.writeUInt16BE(e.svc_id, o);
    buf.writeUInt16BE(e.if_id ?? 0, o + 2);
    buf[o + 4] = (e.inst_id ?? 0) & 0xff;
    buf[o + 5] = (e.grp_id ?? 0) & 0xff;
    buf[o + 6] = e.ttl & 0xff; // 秒
  });
  return buf;
}

export function decodeSubscribeEntries(payload) {
  const out = [];
  for (let o = 0; o + ENTRY_SIZE.SUBSCRIBE <= payload.length; o += ENTRY_SIZE.SUBSCRIBE) {
    out.push({
      svc_id: payload.readUInt16BE(o),
      if_id: payload.readUInt16BE(o + 2),
      inst_id: payload[o + 4],
      grp_id: payload[o + 5],
      ttl: payload[o + 6],
    });
  }
  return out;
}

// ---- GetIDL Entry（3B）：无 InstID——IDL 为服务级事实（§7.1） ----
export function encodeGetIdlEntry(entry) {
  const buf = Buffer.alloc(ENTRY_SIZE.GET_IDL);
  buf.writeUInt16BE(entry.svc_id, 0);
  buf[2] = entry.major_ver & 0xff;
  return buf;
}

export function decodeGetIdlEntry(payload) {
  if (payload.length !== ENTRY_SIZE.GET_IDL) return null; // ≠3B → RST(0x20)（§7.2）
  return { svc_id: payload.readUInt16BE(0), major_ver: payload[2] };
}
