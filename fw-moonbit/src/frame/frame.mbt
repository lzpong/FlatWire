// §3 帧格式：Frame 结构、帧头编解码、帧组装
//
// - 固定头 8B：byte0(CTR|REN|VER|MSK|PLB) + byte1(TYP|Code) + SvcID(2B) + IfID(2B) + InstID(1B) + StrmID(1B)
// - PLB>0 时后随 plb 字节大端 Payload Length；MSK=1 时再后随 4B Masking Key（§3.1）
// - Payload Length = Data Fields 字节数 + 契约级附加字段（CRC16 等）之和，不含 Masking Key（§3.1）
// - CRC 由契约级编解码负责（§9.6），本层不感知；MSK XOR 在本层处理（§10）

/// TYP 传输类型（§3.7）：NON=00 / CON=01 / ACK=10 / RST=11
pub(all) enum Typ {
  Non
  Con
  Ack
  Rst
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend Typ with Eq::{not_equal, equal}
pub extend Typ with @moonbitlang/core/debug.Debug::{to_repr}

/// TYP → 2bit 线格式值（§3.3 byte1 高 2bit）
fn typ_bits(t : Typ) -> Int {
  match t {
    Non => 0
    Con => 1
    Ack => 2
    Rst => 3
  }
}

/// 2bit 线格式值 → TYP
fn typ_of(bits : Int) -> Typ {
  match bits {
    1 => Con
    2 => Ack
    3 => Rst
    _ => Non
  }
}

/// 解析后的完整帧（§3.1；payload 已 XOR 还原，不含 Masking Key；CRC 属契约级未剥离）
pub(all) struct Frame {
  ctr : Bool // CTR：是否控制帧
  ren : Bool // REN：重启标志（仅 CTR=1 有效）
  ver : Int // VER：协议版本（0~3）
  msk : Bool // MSK：是否曾掩码
  typ : Typ // TYP：传输类型
  code : Int // Code：消息编码（0~0x3F）
  svc_id : Int // SvcID（0~0xFFFF）
  if_id : Int // IfID（0~0xFFFF）
  inst_id : Int // InstID（0~0xFF）
  strm_id : Int // StrmID（0~0xFF）
  payload : Bytes // Data Fields（MSK 已还原）
} derive(Eq, Debug)

pub extend Frame with Eq::{not_equal, equal}
pub extend Frame with @moonbitlang/core/debug.Debug::{to_repr}

/// 帧头字段（前 8B 解析结果，校验用中间结构）
pub(all) struct FrameHeader {
  ctr : Bool
  ren : Bool
  ver : Int
  msk : Bool
  plb : Int // Payload Length 字段字节数（0~7，§3.2）
  typ : Typ
  code : Int
  svc_id : Int
  if_id : Int
  inst_id : Int
  strm_id : Int
} derive(Eq, Debug)

pub extend FrameHeader with Eq::{not_equal, equal}
pub extend FrameHeader with @moonbitlang/core/debug.Debug::{to_repr}

/// 发送侧帧描述（payload 单独给出；MSK 由 mask_key 参数是否提供决定）
pub(all) struct FrameSpec {
  ctr : Bool
  ren : Bool
  ver : Int
  typ : Typ
  code : Int
  svc_id : Int
  if_id : Int
  inst_id : Int
  strm_id : Int
} derive(Eq)

pub extend FrameSpec with Eq::{not_equal, equal}

/// 编码错误（域宽越界 / MSK key 缺失；本函数不做 §4.3 协议校验——发送侧由协议栈保证合法）
pub(all) suberror FrameError {
  FrameError(String)
} derive(Eq, Debug)

pub extend FrameError with Eq::{not_equal, equal}
pub extend FrameError with @moonbitlang/core/debug.Debug::{to_repr}

/// 编码帧（§3.1/§3.2/§10）：
/// - PLB 自动按 payload 长度选最小字节数（空 payload → PLB=0，无 Length 字段，§3.2）
/// - mask_key=Some(4B) → MSK=1：Length 不含 Masking Key，对 Data 整体 XOR（§10）
/// - 违规组合（如 REN=1 且 CTR=0）不拦截，仅供测试构造违规帧
pub fn encode_frame(
  spec : FrameSpec,
  payload : Bytes,
  mask_key : Bytes?
) -> Bytes raise FrameError {
  guard spec.ver >= 0 && spec.ver <= 3 else { raise FrameError("ver out of range 0..3") }
  guard spec.code >= 0 && spec.code <= 0x3F else { raise FrameError("code out of range 0..0x3F") }
  guard spec.svc_id >= 0 && spec.svc_id <= 0xFFFF else { raise FrameError("svc_id out of range") }
  guard spec.if_id >= 0 && spec.if_id <= 0xFFFF else { raise FrameError("if_id out of range") }
  guard spec.inst_id >= 0 && spec.inst_id <= 0xFF else { raise FrameError("inst_id out of range") }
  guard spec.strm_id >= 0 && spec.strm_id <= 0xFF else { raise FrameError("strm_id out of range") }
  let len = payload.length()
  // §3.2：PLB 0~7；Payload Length 在 Int 范围内，4B 足够
  let plb = if len == 0 {
    0
  } else if len <= 0xFF {
    1
  } else if len <= 0xFFFF {
    2
  } else if len <= 0xFFFFFF {
    3
  } else {
    4
  }
  // §10：MSK=1 必须提供 4B key
  let msk = match mask_key {
    Some(_) => true
    None => false
  }
  let key : Bytes = match mask_key {
    Some(k) => {
      guard k.length() == 4 else { raise FrameError("masking key must be 4B") }
      k
    }
    None => b""
  }
  let buf = @buffer.Buffer(size_hint=16 + len)
  // byte0：CTR|REN|VER|MSK|PLB（§3.2）
  let b0 = (if spec.ctr { 0x80 } else { 0 })
  | (if spec.ren { 0x40 } else { 0 })
  | (spec.ver << 4)
  | (if msk { 0x08 } else { 0 })
  | plb
  buf.write_byte(b0.to_byte())
  // byte1：TYP|Code（§3.3）
  buf.write_byte(((typ_bits(spec.typ) << 6) | spec.code).to_byte())
  // SvcID/IfID 大端 2B + InstID/StrmID 各 1B（§3.1）
  buf.write_byte(((spec.svc_id >> 8) & 0xFF).to_byte())
  buf.write_byte((spec.svc_id & 0xFF).to_byte())
  buf.write_byte(((spec.if_id >> 8) & 0xFF).to_byte())
  buf.write_byte((spec.if_id & 0xFF).to_byte())
  buf.write_byte(spec.inst_id.to_byte())
  buf.write_byte(spec.strm_id.to_byte())
  // Length（plb 字节大端；PLB=0 无此字段，§3.2）
  let mut k = plb - 1
  while k >= 0 {
    buf.write_byte(((len >> (8 * k)) & 0xFF).to_byte())
    k = k - 1
  }
  // §10：MSK=1 → 4B Key + XOR 后的 Data
  if msk {
    buf.write_bytes(key)
    buf.write_bytes(@codec.msk_xor(payload, key))
  } else {
    buf.write_bytes(payload)
  }
  buf.to_bytes()
}

/// 解析 8B 帧头（调用方保证 data ≥ 8B）
pub fn parse_header(data : Bytes) -> FrameHeader {
  let b0 = data[0].to_int()
  let b1 = data[1].to_int()
  FrameHeader::{
    ctr: ((b0 >> 7) & 1) == 1,
    ren: ((b0 >> 6) & 1) == 1,
    ver: (b0 >> 4) & 0x03,
    msk: ((b0 >> 3) & 1) == 1,
    plb: b0 & 0x07,
    typ: typ_of((b1 >> 6) & 0x03),
    code: b1 & 0x3F,
    svc_id: (data[2].to_int() << 8) | data[3].to_int(),
    if_id: (data[4].to_int() << 8) | data[5].to_int(),
    inst_id: data[6].to_int(),
    strm_id: data[7].to_int(),
  }
}

/// FrameHeader → Frame（payload 补齐，组装交付用，§4.3 步骤 8）
fn frame_of(h : FrameHeader, payload : Bytes) -> Frame {
  Frame::{
    ctr: h.ctr,
    ren: h.ren,
    ver: h.ver,
    msk: h.msk,
    typ: h.typ,
    code: h.code,
    svc_id: h.svc_id,
    if_id: h.if_id,
    inst_id: h.inst_id,
    strm_id: h.strm_id,
    payload,
  }
}

/// 数据帧 spec 便利构造（CTR=0，REN 恒 0，§3.6；ver 固定 0=当前版本）
pub fn data_spec(
  typ : Typ,
  code : Int,
  svc_id : Int,
  if_id : Int,
  inst_id : Int,
  strm_id : Int
) -> FrameSpec {
  FrameSpec::{
    ctr: false,
    ren: false,
    ver: 0,
    typ,
    code,
    svc_id,
    if_id,
    inst_id,
    strm_id,
  }
}

/// 控制帧 spec 便利构造（CTR=1，SvcID/IfID/InstID 恒 0，§3.5；ver 固定 0）
pub fn ctrl_spec(typ : Typ, code : Int, strm_id : Int) -> FrameSpec {
  FrameSpec::{
    ctr: true,
    ren: false,
    ver: 0,
    typ,
    code,
    svc_id: 0,
    if_id: 0,
    inst_id: 0,
    strm_id,
  }
}
