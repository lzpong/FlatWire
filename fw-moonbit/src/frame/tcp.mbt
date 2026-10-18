// §4.1 TCP 流式解析：帧边界由 Payload Length 确定 + 半帧两阶段超时
//
// 状态机：IDLE → 8B 帧头 → READ_LENGTH(plb) → READ_MASK(4B) → READ_PAYLOAD → 帧完成 → IDLE
// - 分包：任何阶段数据不足保存状态等待，不丢弃已读字节
// - 粘包：一次接收含多帧时逐帧解析，每帧完整后立即交付
// - 半帧两阶段（§4.1，从帧开始接收起计 tcp_frame_timeout_ms）：
//   阶段一 帧头不完整（含 ≥8B 但 Length/Key 未收齐——帧总长不可知）→ RST(0x26) + 关连接
//   阶段二 帧头完整、Payload 不完整 → RST(0x26) + 丢弃模式（精确丢 R = L − 已收；连接不关闭）
//   丢弃模式退出三条件：①收满 R 恢复 IDLE ②对端 EOF/RST 随连接关闭 ③兜底超时关连接
//   兜底 = 2 × tcp_frame_timeout_ms（协议固定倍率），每收到任意字节刷新计时
// - 帧头校验失败的违规帧：回 RST 后仍按帧头声明收完本帧（保持字节流对齐）但不交付

/// TCP 解析器事件（供传输层执行）
pub(all) enum TcpEvent {
  TcpFrame(Frame) // §4.3 步骤 8：帧完整交付
  TcpReject(Int, FrameHeader?) // 帧头校验失败 → 回 RST(code)；hdr 用于 RST 回显归属（§5.4）
  TcpRst26 // §4.1 半帧超时 → 回 RST(0x26)
  TcpClose // §4.1 阶段一超时 / 丢弃模式兜底超时 → 关闭连接
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）
pub extend TcpEvent with Eq::{not_equal, equal}
pub extend TcpEvent with @moonbitlang/core/debug.Debug::{to_repr}

/// 内部解析状态（§4.1）
priv enum TcpState {
  Idle
  StHeader // 收集 8B 帧头
  StLength // 收集 plb 字节 Length
  StMask // 收集 4B Masking Key
  StPayload // 收集 Length 字节的 Payload
  StDropping(Int) // 丢弃模式：剩余 R 字节
}

/// TCP 流式帧解析器（每条 TCP 连接一个实例）
pub struct TcpFrameParser {
  local_ver : Int // 本端 VER（§4.3 步骤 1）
  frame_timeout_ms : Int64 // §2 tcp_frame_timeout_ms（默认 5000）
  priv mut state : TcpState
  priv header_buf : Array[Byte] // 已收帧头字节（<8B）
  priv length_buf : Array[Byte] // 已收 Length 字节
  priv mask_buf : Array[Byte] // 已收 Mask Key 字节
  priv payload_buf : Array[Byte] // 已收 Payload 字节
  priv mut hdr : FrameHeader? // 8B 收齐后的帧头
  priv mut cur_length : Int // Length 收齐后的声明 Payload 长度
  priv mut violated : Bool // 帧头校验失败：收完不交付（保流对齐）
  priv mut frame_start_ms : Int64 // 当前帧开始接收时刻（半帧计时起点）
  priv mut drop_last_ms : Int64 // 丢弃模式最后收字节时刻（兜底计时）
}

/// 创建解析器（每连接一个；frame_timeout_ms = §2 tcp_frame_timeout_ms）
pub fn TcpFrameParser::new(local_ver : Int, frame_timeout_ms : Int64) -> TcpFrameParser {
  {
    local_ver,
    frame_timeout_ms,
    state: Idle,
    header_buf: [],
    length_buf: [],
    mask_buf: [],
    payload_buf: [],
    hdr: None,
    cur_length: 0,
    violated: false,
    frame_start_ms: 0L,
    drop_last_ms: 0L,
  }
}

/// 喂入 TCP 收到的字节流（粘包/分包均可），返回产生的事件序列
pub fn TcpFrameParser::feed(
  self : TcpFrameParser,
  data : Bytes,
  now_ms : Int64
) -> Array[TcpEvent] {
  let events : Array[TcpEvent] = []
  for i in 0..<data.length() {
    self.feed_byte(data[i], now_ms, events)
  }
  events
}

/// 单字节推进状态机
fn TcpFrameParser::feed_byte(
  self : TcpFrameParser,
  b : Byte,
  now_ms : Int64,
  events : Array[TcpEvent]
) -> Unit {
  match self.state {
    // 帧开始接收：启动半帧计时（§4.1）
    Idle => {
      self.reset_frame()
      self.frame_start_ms = now_ms
      self.state = StHeader
      self.header_buf.push(b)
      if self.header_buf.length() == 8 {
        self.on_header_complete(events)
      }
    }
    StHeader => {
      self.header_buf.push(b)
      if self.header_buf.length() == 8 {
        self.on_header_complete(events)
      }
    }
    StLength => {
      self.length_buf.push(b)
      // StLength 仅在 plb>0 且帧头已解析时进入
      let plb = match self.hdr {
        Some(h) => h.plb
        None => 0
      }
      if self.length_buf.length() == plb {
        self.on_length_complete(events)
      }
    }
    StMask => {
      self.mask_buf.push(b)
      if self.mask_buf.length() == 4 {
        if self.cur_length == 0 {
          self.complete_frame(events)
        } else {
          self.state = StPayload
        }
      }
    }
    StPayload => {
      self.payload_buf.push(b)
      if self.payload_buf.length() == self.cur_length {
        self.complete_frame(events)
      }
    }
    // 丢弃模式：机械丢弃字节，每字节刷新兜底计时（§4.1 退出条件 3）
    StDropping(remain) => {
      self.drop_last_ms = now_ms
      if remain <= 1 {
        // 收满剩余 R → 恢复 IDLE，连接继续复用（§4.1 退出条件 1）
        self.state = Idle
        self.reset_frame()
      } else {
        self.state = StDropping(remain - 1)
      }
    }
  }
}

/// 8B 帧头收齐：§4.3 步骤 1~4 校验 + 进入 Length/Mask/Payload 阶段
fn TcpFrameParser::on_header_complete(self : TcpFrameParser, events : Array[TcpEvent]) -> Unit {
  let data = @codec.bytes_of_array(self.header_buf)
  let h = parse_header(data)
  self.hdr = Some(h)
  match validate_header(h, self.local_ver, true) {
    Some(code) => {
      // 校验失败 → 回 RST(code)；继续按声明收完本帧保持字节流对齐，但不交付
      events.push(TcpReject(code, Some(h)))
      self.violated = true
    }
    None => ()
  }
  if h.plb > 0 {
    self.state = StLength
  } else if h.msk {
    self.state = StMask
  } else {
    // 纯 8B 帧（PLB=0、MSK=0）：立即完成交付
    self.complete_frame(events)
  }
}

/// Length 字段收齐（TCP 不做 max_payload_len 帧级校验，§4.3 步骤 5）
fn TcpFrameParser::on_length_complete(self : TcpFrameParser, events : Array[TcpEvent]) -> Unit {
  let v = read_be_i64(@codec.bytes_of_array(self.length_buf), 0, self.length_buf.length())
  self.cur_length = v.to_int()
  match self.hdr {
    Some(h) => {
      if h.msk {
        self.state = StMask
      } else if self.cur_length == 0 {
        self.complete_frame(events)
      } else {
        self.state = StPayload
      }
    }
    // 不可达：StLength 必有帧头
    None => ()
  }
}

/// 帧收齐：MSK 还原 + 交付（违规帧静默丢弃），回到 IDLE
fn TcpFrameParser::complete_frame(self : TcpFrameParser, events : Array[TcpEvent]) -> Unit {
  match self.hdr {
    Some(h) => {
      let mut payload = @codec.bytes_of_array(self.payload_buf)
      // §4.3 步骤 7：MSK=1 则 XOR 还原
      if h.msk {
        payload = @codec.msk_xor(payload, @codec.bytes_of_array(self.mask_buf))
      }
      // 违规帧：收完即弃（不交付），保持字节流对齐
      if !self.violated {
        events.push(TcpFrame(frame_of(h, payload)))
      }
    }
    // 不可达：complete_frame 必有帧头
    None => ()
  }
  self.state = Idle
  self.reset_frame()
}

/// 清空当前帧的中间状态
fn TcpFrameParser::reset_frame(self : TcpFrameParser) -> Unit {
  self.header_buf.clear()
  self.length_buf.clear()
  self.mask_buf.clear()
  self.payload_buf.clear()
  self.hdr = None
  self.cur_length = 0
  self.violated = false
}

/// 半帧超时检查（传输层定时驱动；now_ms 单调毫秒时钟）
pub fn TcpFrameParser::check_timeout(self : TcpFrameParser, now_ms : Int64) -> Array[TcpEvent] {
  let events : Array[TcpEvent] = []
  match self.state {
    Idle => ()
    // 丢弃模式兜底超时（§4.1 退出条件 3）：2 × tcp_frame_timeout_ms 无任意字节 → 关连接
    StDropping(_) => {
      if now_ms - self.drop_last_ms >= self.frame_timeout_ms * 2L {
        events.push(TcpClose)
        self.state = Idle
        self.reset_frame()
      }
    }
    // 读取中：帧开始后 tcp_frame_timeout_ms 仍未收完 → 两阶段处理（§4.1）
    _ => {
      if now_ms - self.frame_start_ms >= self.frame_timeout_ms {
        // 帧头完整 = 8B 收齐 && Length 收齐（plb>0 时）&& Mask 收齐（msk 时）
        let header_complete = match self.hdr {
          None => false
          Some(h) =>
            (h.plb == 0 || self.length_buf.length() == h.plb) && (!h.msk || self.mask_buf.length() == 4)
        }
        if !header_complete {
          // 阶段一：帧总长不可知（含 ≥8B 但 Length/Key 未收齐），无法重同步 → RST(0x26) + 关连接
          events.push(TcpRst26)
          events.push(TcpClose)
          self.state = Idle
          self.reset_frame()
        } else {
          // 阶段二：帧头完整、Payload 不完整 → RST(0x26) + 丢弃模式（连接不关闭）
          events.push(TcpRst26)
          match self.hdr {
            Some(h) => {
              // 帧总长 L = 8 + Length 字节数 + Key 字节数 + Payload 长度；剩余 R = L − 已收
              let total = 8 + (if h.plb > 0 { h.plb } else { 0 }) + (if h.msk { 4 } else { 0 }) + self.cur_length
              let received = 8 + self.length_buf.length() + self.mask_buf.length() + self.payload_buf.length()
              let r = total - received
              self.drop_last_ms = now_ms
              if r <= 0 {
                self.state = Idle
                self.reset_frame()
              } else {
                self.state = StDropping(r)
              }
            }
            None => ()
          }
        }
      }
    }
  }
  events
}
