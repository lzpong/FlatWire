// §7.1 SD Entry 格式编解码
//
// 四种 Entry 全部大端、定长拼装：
//   Offer     6B：SvcID(2B) + InstID + MajorVer + MinorVer + TTL(秒, 0=停止)
//   Find      4B：SvcID(2B) + InstID + MajorVer（无 MinorVer——不参与匹配，§7.1）
//   Subscribe 7B：SvcID(2B) + IfID(2B) + InstID + GrpId + TTL(秒, 0=取消)
//   GetIDL    3B：SvcID(2B) + MajorVer（无 InstID——IDL 是服务级事实，§7.1）
//
// 解析按 Payload 定长整除校验：不整除 = 整帧无法解析（调用方按 §7.2 回 RST(0x20) 或静默）

/// Offer Entry（§7.1）
pub(all) struct OfferEntry {
  svc_id : Int
  inst_id : Int
  major_ver : Int
  minor_ver : Int
  ttl : Int // 秒；0 = 停止提供
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend OfferEntry with Eq::{not_equal, equal}
pub extend OfferEntry with @moonbitlang/core/debug.Debug::{to_repr}

/// Find Entry（§7.1：SvcID 必填非 0，InstID=0 通配，MajorVer 精确匹配）
pub(all) struct FindEntry {
  svc_id : Int
  inst_id : Int
  major_ver : Int
} derive(Eq, Debug)

pub extend FindEntry with Eq::{not_equal, equal}
pub extend FindEntry with @moonbitlang/core/debug.Debug::{to_repr}

/// Subscribe Entry（§7.1 合法组合：单接口 IfID≠0 且 GrpId=0 / 组订阅 IfID=0 且 GrpId≠0）
pub(all) struct SubEntry {
  svc_id : Int
  if_id : Int
  grp_id : Int
  inst_id : Int
  ttl : Int // 秒；0 = 取消订阅
} derive(Eq, Debug)

pub extend SubEntry with Eq::{not_equal, equal}
pub extend SubEntry with @moonbitlang/core/debug.Debug::{to_repr}

/// GetIDL Entry（§7.1：SvcID 必填非 0 + MajorVer 精确匹配）
pub(all) struct GetIdlEntry {
  svc_id : Int
  major_ver : Int
} derive(Eq, Debug)

pub extend GetIdlEntry with Eq::{not_equal, equal}
pub extend GetIdlEntry with @moonbitlang/core/debug.Debug::{to_repr}

/// 编码 Offer Entry 序列（N×6B 拼装）
pub fn encode_offer_entries(entries : Array[OfferEntry]) -> Bytes {
  let buf = @buffer.Buffer(size_hint=6 * entries.length() + 8)
  for e in entries {
    buf.write_byte(((e.svc_id >> 8) & 0xFF).to_byte())
    buf.write_byte((e.svc_id & 0xFF).to_byte())
    buf.write_byte(e.inst_id.to_byte())
    buf.write_byte(e.major_ver.to_byte())
    buf.write_byte(e.minor_ver.to_byte())
    buf.write_byte(e.ttl.to_byte())
  }
  buf.to_bytes()
}

/// 编码 Find Entry 序列（N×4B 拼装）
pub fn encode_find_entries(entries : Array[FindEntry]) -> Bytes {
  let buf = @buffer.Buffer(size_hint=4 * entries.length() + 8)
  for e in entries {
    buf.write_byte(((e.svc_id >> 8) & 0xFF).to_byte())
    buf.write_byte((e.svc_id & 0xFF).to_byte())
    buf.write_byte(e.inst_id.to_byte())
    buf.write_byte(e.major_ver.to_byte())
  }
  buf.to_bytes()
}

/// 编码 Subscribe Entry 序列（N×7B 拼装）
pub fn encode_sub_entries(entries : Array[SubEntry]) -> Bytes {
  let buf = @buffer.Buffer(size_hint=7 * entries.length() + 8)
  for e in entries {
    buf.write_byte(((e.svc_id >> 8) & 0xFF).to_byte())
    buf.write_byte((e.svc_id & 0xFF).to_byte())
    buf.write_byte(((e.if_id >> 8) & 0xFF).to_byte())
    buf.write_byte((e.if_id & 0xFF).to_byte())
    buf.write_byte(e.inst_id.to_byte())
    buf.write_byte(e.grp_id.to_byte())
    buf.write_byte(e.ttl.to_byte())
  }
  buf.to_bytes()
}

/// 编码 GetIDL Entry（恒 3B，§7.2 请求 Payload = 1 × Entry）
pub fn encode_getidl_entry(e : GetIdlEntry) -> Bytes {
  let buf = @buffer.Buffer(size_hint=8)
  buf.write_byte(((e.svc_id >> 8) & 0xFF).to_byte())
  buf.write_byte((e.svc_id & 0xFF).to_byte())
  buf.write_byte(e.major_ver.to_byte())
  buf.to_bytes()
}

/// 解析 Offer Entry 序列（Payload 非 6 整除 → None = 整帧无法解析）
pub fn parse_offer_entries(payload : Bytes) -> Array[OfferEntry]? {
  let n = payload.length()
  if n % 6 != 0 {
    return None
  }
  let out : Array[OfferEntry] = []
  let mut i = 0
  while i < n {
    out.push({
      svc_id: (payload[i].to_int() << 8) | payload[i + 1].to_int(),
      inst_id: payload[i + 2].to_int(),
      major_ver: payload[i + 3].to_int(),
      minor_ver: payload[i + 4].to_int(),
      ttl: payload[i + 5].to_int(),
    })
    i = i + 6
  }
  Some(out)
}

/// 解析 Find Entry 序列（Payload 非 4 整除 → None）
pub fn parse_find_entries(payload : Bytes) -> Array[FindEntry]? {
  let n = payload.length()
  if n % 4 != 0 {
    return None
  }
  let out : Array[FindEntry] = []
  let mut i = 0
  while i < n {
    out.push({
      svc_id: (payload[i].to_int() << 8) | payload[i + 1].to_int(),
      inst_id: payload[i + 2].to_int(),
      major_ver: payload[i + 3].to_int(),
    })
    i = i + 4
  }
  Some(out)
}

/// 解析 Subscribe Entry 序列（Payload 非 7 整除 → None）
pub fn parse_sub_entries(payload : Bytes) -> Array[SubEntry]? {
  let n = payload.length()
  if n % 7 != 0 {
    return None
  }
  let out : Array[SubEntry] = []
  let mut i = 0
  while i < n {
    out.push({
      svc_id: (payload[i].to_int() << 8) | payload[i + 1].to_int(),
      if_id: (payload[i + 2].to_int() << 8) | payload[i + 3].to_int(),
      inst_id: payload[i + 4].to_int(),
      grp_id: payload[i + 5].to_int(),
      ttl: payload[i + 6].to_int(),
    })
    i = i + 7
  }
  Some(out)
}

/// 解析 GetIDL Entry（必须恰为 3B——残缺 <3B 或多余 >3B 均 RST(0x20)，§7.2）
pub fn parse_getidl_entry(payload : Bytes) -> GetIdlEntry? {
  if payload.length() != 3 {
    return None
  }
  Some({
    svc_id: (payload[0].to_int() << 8) | payload[1].to_int(),
    major_ver: payload[2].to_int(),
  })
}
