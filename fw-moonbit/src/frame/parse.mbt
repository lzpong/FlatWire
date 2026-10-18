// §4.2/§4.3/§4.4 帧解析：UDP 数据报解析 + §4.3 帧头校验（步骤 1~4）
//
// 校验顺序严格按 §4.3 步骤 1~4；步骤 5~8（Length/Mask/Payload）由各传输解析器执行
// - 违规返回 Reject(code)：单播帧回 RST(code)，组播帧由调用方静默丢弃（§4.4）
// - 传输控制帧（CTR=0 且 TYP∈{ACK,RST}）豁免步骤 3/4 的 ID 校验：
//   其 SvcID/IfID/InstID/StrmID 仅为回显归属（§5.4"RST 回显触发帧的 StrmID"），
//   对畸形帧的 RST 回复若含 0 值 ID 不应自我违规（避免 RST 循环）

/// UDP 数据报解析结果（§4.2/§4.4）
pub(all) enum ParseOutcome {
  Ok(Frame) // 合法帧，交付
  Reject(Int, FrameHeader?) // 回 RST(code)（单播；组播帧调用方静默丢弃）；hdr 用于 RST 回显归属（§5.4）
  Drop // 静默丢弃（UDP 过短 / 长度不符）
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend ParseOutcome with Eq::{not_equal, equal}
pub extend ParseOutcome with @moonbitlang/core/debug.Debug::{to_repr}

/// n 字节大端无符号读为 Int64（n ≤ 7；Length 字段最宽 7B，§3.2 PLB 0~7）
pub fn read_be_i64(data : Bytes, pos : Int, n : Int) -> Int64 {
  let mut v = 0L
  for i in 0..<n {
    v = (v << 8) | data[pos + i].to_int().to_int64()
  }
  v
}

/// §4.3 步骤 1~4 帧头校验：合法 → None；违规 → Some(RST code)
/// is_tcp：传输绑定相关校验（TCP 不使用 CON/ACK；GetIDL 仅 TCP 单播）
pub fn validate_header(h : FrameHeader, local_ver : Int, is_tcp : Bool) -> Int? {
  // §4.3 步骤 1：VER 与本端相等（不等 → 单播 RST(0x22) / 组播帧静默丢弃）
  if h.ver != local_ver {
    return Some(@errors.RST_UNSUPPORTED_VERSION)
  }
  // REN=1 时 CTR 必须为 1（§4.3 步骤 1，测试 2.9）
  if h.ren && !h.ctr {
    return Some(@errors.RST_OK)
  }
  // 控制帧固定 MSK=0、不附加 CRC（§4.3 步骤 1 / §10，测试 2.29）
  if h.ctr && h.msk {
    return Some(@errors.RST_OK)
  }
  // §4.3 步骤 2
  // REN=1 时 TYP=NON 且 Code=0x00（§3.6，测试 2.10/2.11）
  if h.ren && (h.typ != Non || h.code != 0) {
    return Some(@errors.RST_OK)
  }
  // TYP=ACK：Code 合法性（测试 2.12）+ PLB=0（§3.7"ACK 帧的 PLB 必须为 0"，测试 2.16）
  if h.typ == Ack {
    if h.ctr {
      // 控制帧 ACK：Code ∈ {0x00, 0x10（Subscribe 建立确认，§8.1）}
      if h.code != 0x00 && h.code != 0x10 {
        return Some(@errors.RST_OK)
      }
    } else {
      // 数据帧 ACK：仅空确认 0x00（测试 2.12）
      if h.code != 0x00 {
        return Some(@errors.RST_OK)
      }
    }
    if h.plb > 0 {
      return Some(@errors.RST_OK)
    }
  }
  // TYP=RST：PLB=0（测试 2.16）+ Code ∈ {0x00} ∪ 0x20~0x3F（测试 2.20）
  if h.typ == Rst {
    if h.plb > 0 {
      return Some(@errors.RST_OK)
    }
    if !@errors.is_valid_rst_code(h.code) {
      return Some(@errors.RST_OK)
    }
  }
  // TCP 不使用 CON/ACK（§3.7，测试 2.21）
  if is_tcp && (h.typ == Con || h.typ == Ack) {
    return Some(@errors.RST_OK)
  }
  // GetIDL 仅 TCP 单播：UDP 上 CTR=1 且 Code=0x04 → 传输绑定违规（§4.3 步骤 2 / §7.2）
  if !is_tcp && h.ctr && h.code == 0x04 {
    return Some(@errors.RST_OK)
  }
  // 传输控制帧（CTR=0 且 ACK/RST）豁免步骤 3/4 ID 校验（文件头注释）
  let is_ctrl_transport = !h.ctr && (h.typ == Ack || h.typ == Rst)
  if !is_ctrl_transport {
    // §4.3 步骤 3：SvcID/IfID
    if h.ctr {
      // 控制帧 SvcID=0x0000 且 IfID=0x0000（测试 2.13）
      if h.svc_id != 0 || h.if_id != 0 {
        return Some(@errors.RST_OK)
      }
    } else {
      // 数据帧 SvcID≠0 且 IfID≠0（ID=0 通配仅 SD Entry 场景，测试 2.14/2.19）
      if h.svc_id == 0 || h.if_id == 0 {
        return Some(@errors.RST_OK)
      }
    }
    // §4.3 步骤 4：InstID/StrmID
    if h.ctr {
      // 控制帧 InstID=0
      if h.inst_id != 0 {
        return Some(@errors.RST_OK)
      }
      // REN=1 时 StrmID=0（测试 2.17）
      if h.ren && h.strm_id != 0 {
        return Some(@errors.RST_OK)
      }
      // 控制帧 StrmID ∈ {0x00（连接级）} ∪ 0x01~0x7F（请求-响应型控制交互）
      if h.strm_id > 0x7F {
        return Some(@errors.RST_OK)
      }
      // 控制帧 StrmID 语义（§4.3 步骤 4，测试 2.17）：
      // Subscribe(0x03)/GetIDL(0x04) 必须 0x01~0x7F；连接级(0x00/0x01/0x02) 必须 0x00
      if (h.code == 0x03 || h.code == 0x04) && h.strm_id == 0 {
        return Some(@errors.RST_OK)
      }
      if (h.code == 0x00 || h.code == 0x01 || h.code == 0x02) && h.strm_id != 0 {
        return Some(@errors.RST_OK)
      }
    } else {
      // 数据帧 InstID≠0x00（测试 2.15）
      if h.inst_id == 0 {
        return Some(@errors.RST_OK)
      }
      // 数据帧 StrmID ∈ 0x01~0xFE（0x00=连接级禁用 / 0xFF 保留，测试 2.18）
      if h.strm_id == 0 || h.strm_id == 0xFF {
        return Some(@errors.RST_OK)
      }
    }
  }
  None
}

/// UDP 数据报解析（§4.2 + §4.3）：
/// - 数据报 < 最小帧长度 8B → Drop（测试 2.7）
/// - 帧头校验违规 → Reject(code)
/// - Length > max_payload_len → Reject(0x23)（帧级超限仅 UDP，两层两码，测试 2.8）
/// - 剩余长度 ≠ 声明 Length → Drop（不截断，测试 2.6）
pub fn parse_datagram(data : Bytes, local_ver : Int, max_payload_len : Int) -> ParseOutcome {
  // §4.2：数据报长度 < 最小帧长度 → 丢弃
  if data.length() < 8 {
    return Drop
  }
  let h = parse_header(data)
  // §4.3 步骤 1~4
  match validate_header(h, local_ver, false) {
    Some(code) => Reject(code, Some(h))
    None => {
      let mut pos = 8
      // §4.3 步骤 5：PLB>0 读 Payload Length（plb 字节大端）
      let length = if h.plb > 0 {
        if data.length() < pos + h.plb {
          return Drop
        }
        let v = read_be_i64(data, pos, h.plb)
        pos = pos + h.plb
        // 帧级超限（仅 UDP）→ RST(0x23)（§2/§4.2；TCP 无此校验）
        if v > max_payload_len.to_int64() {
          return Reject(@errors.RST_PAYLOAD_TOO_LARGE, Some(h))
        }
        v.to_int()
      } else {
        0
      }
      // §4.3 步骤 6：MSK=1 读 4B Masking Key
      let key = if h.msk {
        if data.length() < pos + 4 {
          return Drop
        }
        let k = @codec.sub_bytes(data, pos, pos + 4)
        pos = pos + 4
        k
      } else {
        b""
      }
      // §4.2：数据报长度 ≠ 帧头声明长度（多余或不足）→ 一律丢弃（不截断）
      if data.length() - pos != length {
        return Drop
      }
      // §4.3 步骤 7：读 Payload Data；MSK=1 则 XOR 还原
      let mut payload = @codec.sub_bytes(data, pos, data.length())
      if h.msk {
        payload = @codec.msk_xor(payload, key)
      }
      // §4.3 步骤 8：组装 Frame 交付
      Ok(frame_of(h, payload))
    }
  }
}
