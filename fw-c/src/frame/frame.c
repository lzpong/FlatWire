// ============================================================
// frame.c —— §3 帧格式 / §4.3 解析流程 / §4.1 TCP 流式解析（半帧两阶段）
//
// 帧头 8B：byte0/byte1（2B 控制头）+ SvcID/IfID（4B）+ InstID/StrmID（2B）。
// 解析顺序（§3.1）：byte0 → byte1 → SvcID → IfID → InstID → StrmID
//                  → Length(PLB>0) → Mask(MSK=1) → Data
// ============================================================

#include "fw/fw.h"
#include "platform/platform.h"
#include <stdlib.h>
#include <string.h>

// 控制帧 StrmID 语义校验依据（§4.3 步骤 4）：
//   Code∈{0x03,0x04} → StrmID 必须 0x01~0x7F（会话/查询）
//   Code∈{0x00,0x01,0x02} → StrmID 必须 0x00（连接级；例外：取消确认 ACK(0x00) 回显会话 StrmID）
static int ctrl_strm_session_code(int code) { return code == 0x03 || code == 0x04; }
static int ctrl_strm_conn_code(int code)    { return code == 0x00 || code == 0x01 || code == 0x02; }

// ---------- 帧构造 ----------

// 计算 PLB：len=0 → 0；否则最小可表示字节数（1~7，§3.2）
int fw_calc_plb(uint64_t len) {
  if (len == 0) return 0;
  for (int n = 1; n <= 7; n++) {
    if (len < ((uint64_t)1 << (8 * n))) return n;
  }
  return -1; // 超过 2^56-1（调用方应先校验，运行时不可达）
}

uint32_t fw_frame_size(const fw_frame_desc_t *d) {
  int plb = fw_calc_plb(d->payload_len);
  if (plb < 0) return 0;
  return (uint32_t)(8 + plb + (d->msk ? 4 : 0) + d->payload_len);
}

uint32_t fw_frame_encode(uint8_t *buf, uint32_t cap, const fw_frame_desc_t *d) {
  int plb = fw_calc_plb(d->payload_len);
  if (plb < 0) return 0;
  uint32_t total = (uint32_t)(8 + plb + (d->msk ? 4 : 0) + d->payload_len);
  if (cap < total) return 0;

  // §3.2 byte0：CTR:1 | REN:1 | VER:2 | MSK:1 | PLB:3
  buf[0] = (uint8_t)(((d->ctr ? 1 : 0) << 7) | ((d->ren ? 1 : 0) << 6) |
                     ((d->ver & 0x03) << 4) | ((d->msk ? 1 : 0) << 3) | plb);
  // §3.3 byte1：TYP:2 | Code:6
  buf[1] = (uint8_t)(((d->typ & 0x03) << 6) | (d->code & 0x3F));
  buf[2] = (uint8_t)(d->svc_id >> 8);
  buf[3] = (uint8_t)(d->svc_id & 0xFF);
  buf[4] = (uint8_t)(d->if_id >> 8);
  buf[5] = (uint8_t)(d->if_id & 0xFF);
  buf[6] = d->inst_id;
  buf[7] = d->strm_id;

  uint32_t o = 8;
  // §3.2：PLB>0 时 Length 大端写入 plb 字节
  for (int i = 0; i < plb; i++)
    buf[o + i] = (uint8_t)((d->payload_len >> (8 * (plb - 1 - i))) & 0xFF);
  o += (uint32_t)plb;

  if (d->msk) {
    // §10：MSK=1 时于 Payload Length 后插入 4B Key，对 Data 逐字节循环 XOR
    uint8_t key[4];
    if (d->mask_key) {
      memcpy(key, d->mask_key, 4);
    } else {
      // [REVIEW P3-1] 平台 CSPRNG 生成（原实现取时钟字节：最高字节恒 0、低位窗口
      // 内恒定可预测，削弱 §10 规避中间设备误识别用途；JS 用 crypto.randomBytes）
      fw_plat_random_bytes(key, 4);
    }
    memcpy(buf + o, key, 4);
    o += 4;
    if (d->payload_len) {
      memcpy(buf + o, d->payload, d->payload_len);
      fw_mask_xor(buf + o, d->payload_len, key);
    }
  } else if (d->payload_len) {
    memcpy(buf + o, d->payload, d->payload_len);
  }
  return total;
}

// ---------- 解析工具 ----------

// 从（可能不完整的）帧头字节尽力提取回显字段（§5.4 RST 回显）
void fw_head_echo_partial(const uint8_t *buf, size_t avail, int ctr,
                          uint16_t *svc, uint16_t *if_id, uint8_t *inst, uint8_t *strm) {
  *svc = 0; *if_id = 0; *inst = 0; *strm = 0;
  if (avail >= 8) {
    *svc = (uint16_t)((buf[2] << 8) | buf[3]);
    *if_id = (uint16_t)((buf[4] << 8) | buf[5]);
    *inst = buf[6];
    *strm = buf[7];
  } else if (avail >= 4) {
    *svc = (uint16_t)((buf[2] << 8) | buf[3]);
  }
  (void)ctr;
}

static void fill_rst(fw_head_res_t *out, int code, const uint8_t *buf, size_t avail, int ctr) {
  out->state = FW_PARSE_INVALID;
  out->rst_code = code;
  out->rst_ctr = (uint8_t)(ctr ? 1 : 0);
  fw_head_echo_partial(buf, avail, ctr, &out->rst_svc, &out->rst_if, &out->rst_inst, &out->rst_strm);
}

// §4.3 步骤 1~6：解析帧头（buf[offset..] 至 Masking Key）
fw_parse_state_t fw_parse_header(const uint8_t *buf, size_t avail, size_t offset,
                                 const fw_parse_opts_t *o, fw_head_res_t *out) {
  memset(out, 0, sizeof(*out));
  buf += offset;
  avail = (avail > offset) ? (avail - offset) : 0;

  // ---- 步骤 1：读 byte0 → CTR/REN/VER/MSK/PLB ----
  if (avail < 2) return FW_PARSE_NEED_MORE; // byte0+byte1 至少 2B
  uint8_t byte0 = buf[0], byte1 = buf[1];
  int ctr = (byte0 >> 7) & 1;
  int ren = (byte0 >> 6) & 1;
  int fver = (byte0 >> 4) & 0x03;
  int msk = (byte0 >> 3) & 1;
  int plb = byte0 & 0x07;
  int typ = (byte1 >> 6) & 0x03;
  int code = byte1 & 0x3F;

  // §4.3 步骤 1：VER 与本端必须相等；不等 → 单播 RST(0x22)、组播静默
  if (fver != o->ver) {
    if (o->multicast_like) return FW_PARSE_SILENT;
    fill_rst(out, FW_RST_VERSION, buf, avail, ctr);
    return FW_PARSE_INVALID;
  }
  // REN=1 时 CTR 必须为 1（数据帧 REN 恒为 0，§3.6）→ RST(0x00)
  if (ren == 1 && ctr != 1) {
    fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
    return FW_PARSE_INVALID;
  }
  // §4.3 步骤 1：控制帧固定 MSK=0 且不附加 CRC（§9.6/§10 跨实现硬性约定）→ RST(0x00)
  if (ctr == 1 && msk == 1) {
    fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
    return FW_PARSE_INVALID;
  }

  // ---- 步骤 2：读 byte1 → TYP/Code 校验 ----
  // REN=1 固定 TYP=NON 且 Code=0x00（§3.6）→ RST(0x00)
  if (ren == 1 && (typ != FW_TYP_NON || code != 0x00)) {
    fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
    return FW_PARSE_INVALID;
  }
  // ACK：Code∈{0x00} ∪ {0x10 仅 CTR=1}（§3.7/§8.1）且 PLB=0（无 Payload）→ RST(0x00)
  if (typ == FW_TYP_ACK) {
    int ok = (code == 0x00) || (ctr == 1 && code == 0x10);
    if (!ok || plb > 0) {
      fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
      return FW_PARSE_INVALID;
    }
  }
  // RST：PLB=0 且 Code∈{0x00} ∪ 0x20~0x3F（§3.7）→ RST(0x00)
  if (typ == FW_TYP_RST) {
    int ok = (code == 0x00) || (code >= 0x20 && code <= 0x3F);
    if (!ok || plb > 0) {
      fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
      return FW_PARSE_INVALID;
    }
  }
  // TCP 不使用 CON/ACK（§3.7）→ RST(0x00)
  if (!o->is_udp && (typ == FW_TYP_CON || typ == FW_TYP_ACK)) {
    fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
    return FW_PARSE_INVALID;
  }
  // GetIDL 仅走 TCP 单播（§7.2）：UDP 上收到 → RST(0x00)，组播帧静默丢弃
  if (o->is_udp && ctr == 1 && code == 0x04) {
    if (o->multicast_like) return FW_PARSE_SILENT;
    fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
    return FW_PARSE_INVALID;
  }

  // ---- 步骤 3/4：SvcID/IfID/InstID/StrmID 校验（需完整 8B 帧头） ----
  if (avail < 8) return FW_PARSE_NEED_MORE;
  uint16_t svc = (uint16_t)((buf[2] << 8) | buf[3]);
  uint16_t ifc = (uint16_t)((buf[4] << 8) | buf[5]);
  uint8_t inst = buf[6];
  uint8_t strm = buf[7];

  if (ctr == 1) {
    // 控制帧 SvcID=0x0000 且 IfID=0x0000（§4.3 步骤 3）
    if (svc != 0 || ifc != 0) {
      fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
      return FW_PARSE_INVALID;
    }
  } else {
    // 数据帧 SvcID≠0 且 IfID≠0（ID=0 通配仅 SD Entry 场景，§3.5）
    if (svc == 0 || ifc == 0) {
      fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
      return FW_PARSE_INVALID;
    }
  }

  // ---- 步骤 4：InstID/StrmID 校验 ----
  if (ctr == 1) {
    // 控制帧 InstID=0、REN=1 时 StrmID=0（§4.3 步骤 4）
    if (inst != 0) { fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr); return FW_PARSE_INVALID; }
    if (ren == 1 && strm != 0) { fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr); return FW_PARSE_INVALID; }
    if (typ == FW_TYP_RST) {
      // RST 帧豁免 StrmID 校验（实现裁定，见 fw-nodejs README 偏差 2）：StrmID 是 §5.4
      // 回显字段（数据帧触发时可达 0xFF）——若按控制帧语义校验，会形成
      // "RST 判违规 → 回 RST → 对端再判违规"的互射风暴
    } else {
      // 控制帧 StrmID 范围：0x00（连接级）或 0x01~0x7F（会话/查询）→ 否则 RST(0x00)
      if (strm > 0x7F) { fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr); return FW_PARSE_INVALID; }
      // 控制帧 StrmID 语义校验（§4.3 步骤 4）：
      //   Code∈{0x03,0x04} → StrmID∈0x01~0x7F；Code∈{0x00,0x01,0x02} → StrmID=0x00
      if (ctrl_strm_session_code(code) && strm == 0) {
        if (o->multicast_like) return FW_PARSE_SILENT;
        fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
        return FW_PARSE_INVALID;
      }
      if (ctrl_strm_conn_code(code) && strm != 0) {
        // 例外（§3.7 专项定案优先，实现裁定 1）：取消确认 ACK(Code=0x00) 回显会话
        // StrmID（0x01~0x7F）；其余 Code=0x00 帧（心跳 Ping/REN）StrmID 仍必须 0x00
        if (!(typ == FW_TYP_ACK && code == 0x00)) {
          if (o->multicast_like) return FW_PARSE_SILENT;
          fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr);
          return FW_PARSE_INVALID;
        }
      }
    }
  } else {
    // 数据帧 InstID≠0x00（§4.3 步骤 4）
    if (inst == 0) { fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr); return FW_PARSE_INVALID; }
    // 数据帧 StrmID∈0x01~0xFE（0x00 连接级禁用、0xFF 保留，§6.1）→ 越界 RST(0x00)
    if (strm < 0x01 || strm > 0xFE) { fill_rst(out, FW_RST_VIOLATION, buf, avail, ctr); return FW_PARSE_INVALID; }
  }

  // ---- 步骤 5：读 Payload Length（plb 字节）；PLB=0 时 Length=0 ----
  uint32_t header_len = (uint32_t)(8 + plb + (msk ? 4 : 0));
  if (avail < header_len) return FW_PARSE_NEED_MORE;
  uint64_t payload_len = 0;
  for (int i = 0; i < plb; i++) payload_len = (payload_len << 8) | buf[8 + i];
  // UDP 帧级校验：超 max_payload_len → RST(0x23)（§4.3 步骤 5，仅 UDP）
  if (o->is_udp && payload_len > o->max_payload_len) {
    fill_rst(out, FW_RST_TOO_LARGE, buf, avail, ctr);
    return FW_PARSE_INVALID;
  }

  // ---- 步骤 6：MSK=1 读 4B Masking Key ----
  out->state = FW_PARSE_OK;
  out->ver = (uint8_t)fver;
  out->ctr = (uint8_t)ctr;
  out->ren = (uint8_t)ren;
  out->msk = (uint8_t)msk;
  out->plb = (uint8_t)plb;
  out->typ = (uint8_t)typ;
  out->code = (uint8_t)code;
  out->svc_id = svc;
  out->if_id = ifc;
  out->inst_id = inst;
  out->strm_id = strm;
  out->header_len = header_len;
  out->payload_len = (uint32_t)payload_len;
  out->expected_total = header_len + (uint32_t)payload_len;
  out->mask_key = msk ? (buf + 8 + plb) : NULL;
  return FW_PARSE_OK;
}

// §4.2 + §4.3：UDP 单报文解析
fw_parse_state_t fw_parse_datagram(uint8_t *buf, size_t len, const fw_parse_opts_t *o,
                                   fw_frame_t *frame, fw_head_res_t *rst) {
  // §4.2：数据报长度 < 最小帧长度（8B）→ 丢弃
  if (len < 8) return FW_PARSE_SILENT;

  fw_head_res_t h;
  fw_parse_opts_t oo = *o;
  oo.is_udp = 1;
  fw_parse_state_t st = fw_parse_header(buf, len, 0, &oo, &h);
  if (st != FW_PARSE_OK) {
    if (st == FW_PARSE_INVALID && rst) *rst = h;
    return st;
  }
  // §4.2：数据报长度 ≠ 帧头声明长度（多余或不足）→ 一律丢弃（不做截断）
  if (len != h.expected_total) return FW_PARSE_SILENT;

  // 步骤 7：读 Payload；MSK=1 则 XOR 还原（就地，§10 编解码对称）
  if (h.msk && h.payload_len) fw_mask_xor(buf + h.header_len, h.payload_len, h.mask_key);

  // 步骤 8：组装 Frame 交付（ver 随帧传出——发现缓存/is_available VER 判定依赖）
  memset(frame, 0, sizeof(*frame));
  frame->ver = h.ver;
  frame->ctr = h.ctr;
  frame->ren = h.ren;
  frame->msk = h.msk;
  frame->typ = h.typ;
  frame->code = h.code;
  frame->svc_id = h.svc_id;
  frame->if_id = h.if_id;
  frame->inst_id = h.inst_id;
  frame->strm_id = h.strm_id;
  frame->payload_len = h.payload_len;
  frame->payload = h.payload_len ? buf + h.header_len : NULL;
  return FW_PARSE_OK;
}

// ============================================================
// TCP 流式解析器（§4.1）：分包保存状态等待；粘包逐帧交付；
// 半帧两阶段（帧头 <8B → 关连接由连接层处理；帧头完整 → 丢弃模式）。
// ============================================================

void fw_sp_init(fw_stream_parser_t *p) {
  memset(p, 0, sizeof(*p));
}

void fw_sp_free(fw_stream_parser_t *p) {
  free(p->buf);
  p->buf = NULL;
  p->len = p->cap = 0;
  free(p->scratch); // 交付暂存缓冲（粘包解耦，§4.1）
  p->scratch = NULL;
  p->scratch_cap = 0;
}

static void sp_consume(fw_stream_parser_t *p, size_t n) {
  if (n >= p->len) {
    p->len = 0;
    return;
  }
  memmove(p->buf, p->buf + n, p->len - n);
  p->len -= n;
}

// 丢弃模式字节消耗（§4.1：精确丢弃 R 字节，收满恢复 IDLE）
static void sp_consume_drop(fw_stream_parser_t *p) {
  while (p->drop_mode && p->drop_remaining > 0) {
    if (p->len == 0) return; // 待丢弃字节未到齐，等待后续 feed
    size_t n = p->len < p->drop_remaining ? p->len : (size_t)p->drop_remaining;
    sp_consume(p, n); // 从 buf 头部精确消耗（后续 feed 字节持续追加）
    p->drop_remaining -= (uint32_t)n;
  }
  if (p->drop_mode && p->drop_remaining == 0) {
    // 退出条件 1：收满剩余 R 字节 → 恢复正常接收（连接继续复用，§4.1）
    p->drop_mode = 0;
    if (p->on_drop_complete) p->on_drop_complete(p->ud);
  }
}

static void sp_loop(fw_stream_parser_t *p);

// [REVIEW P3-8] 返回 FW_OK / FW_ERR_MEMORY：realloc 失败不再静默丢 chunk（返回状态
// 供连接层决策；旧调用点忽略返回值仍兼容——签名由 void 改 int）
int fw_sp_feed(fw_stream_parser_t *p, const uint8_t *chunk, size_t n) {
  // 追加到待解析缓冲（分包不丢弃已读字节，§4.1）
  if (p->len + n > p->cap) {
    size_t nc = p->cap ? p->cap : 1024;
    while (nc < p->len + n) nc *= 2;
    uint8_t *nb = (uint8_t *)realloc(p->buf, nc);
    if (!nb) {
      fw_log(FW_LOG_ERROR, "frame", "sp_feed realloc failed (%zu bytes buffered, %zu dropped)",
             p->len, n); // [REVIEW P3-8] 失败显式记日志（原静默丢弃仅半帧超时兜底）
      return FW_ERR_MEMORY;
    }
    p->buf = nb;
    p->cap = nc;
  }
  memcpy(p->buf + p->len, chunk, n);
  p->len += n;
  sp_loop(p);
  return FW_OK;
}

static void sp_loop(fw_stream_parser_t *p) {
  // 先消耗丢弃模式（§4.1 退出条件 1：收满 R 恢复）
  if (p->drop_mode) {
    sp_consume_drop(p);
    if (p->drop_mode) return; // 仍在丢弃模式且未收满
  }
  // 逐帧解析（粘包逐帧交付，§4.1）
  for (;;) {
    if (p->len == 0) {
      // 缓冲耗尽：若尚未收到任何当前帧字节，退出接收状态（避免空帧误触半帧超时）
      if (!p->header_done && p->received == 0) p->receiving = 0;
      return;
    }
    if (!p->receiving) {
      // 新帧开始：首字节到达（半帧计时起点由连接层依据 receiving 跳变记录）
      p->receiving = 1;
      p->received = 0;
      p->header_done = 0;
    }
    fw_parse_opts_t o;
    memset(&o, 0, sizeof(o));
    o.ver = p->ver;                  // 本端协议版本（§4.3 步骤 1）
    o.is_udp = 0;
    o.max_payload_len = 0xFFFFFFFFu; // TCP 无 max_payload_len 约束（§2）
    o.multicast_like = 0;
    fw_head_res_t h;
    fw_parse_state_t st = fw_parse_header(p->buf, p->len, 0, &o, &h);
    if (st == FW_PARSE_NEED_MORE) return; // 分包：保存状态等待（§4.1）

    if (st == FW_PARSE_INVALID) {
      // 违规帧：回 RST。若能读出声明帧总长则精确跳过该帧继续解析；无法定界则清空缓冲
      if (p->on_rst) p->on_rst(p->ud, h.rst_code, &h);
      uint8_t b0 = p->buf[0];
      int plb = b0 & 0x07;
      int has_msk = ((b0 >> 3) & 1) == 1;
      size_t head_len = (size_t)(8 + plb + (has_msk ? 4 : 0));
      int skipped = 0;
      if (p->len >= head_len) {
        uint64_t plen = 0;
        for (int i = 0; i < plb; i++) plen = (plen << 8) | p->buf[8 + i];
        size_t total = head_len + (size_t)plen;
        if (p->len >= total) {
          sp_consume(p, total); // 跳过违规帧，继续解析后续帧
          p->receiving = 0;
          p->header_done = 0;
          skipped = 1;
        }
      }
      if (!skipped) {
        // 无法定界（Payload Length 值未到齐）：清空缓冲（违规帧尾无法重同步）
        p->len = 0;
        p->receiving = 0;
        p->header_done = 0;
        return;
      }
      continue;
    }

    // FW_PARSE_OK：帧头已解析，等 Payload
    p->head = h;
    p->header_done = 1;
    if (p->len < h.expected_total) {
      p->received = (uint32_t)p->len; // 当前帧已收字节（此前帧均已消费）
      return; // 分包：保存状态等待（§4.1）
    }
    // 收齐：交付（ver 随帧传出，与 parse_datagram 交付口径一致）
    fw_frame_t f;
    memset(&f, 0, sizeof(f));
    f.ver = h.ver;
    f.ctr = h.ctr;
    f.ren = h.ren;
    f.msk = h.msk;
    f.typ = h.typ;
    f.code = h.code;
    f.svc_id = h.svc_id;
    f.if_id = h.if_id;
    f.inst_id = h.inst_id;
    f.strm_id = h.strm_id;
    f.payload_len = h.payload_len;
    if (h.payload_len) {
      // 交付前拷贝 payload 到暂存缓冲：sp_consume 的 memmove 会挪动解析缓冲，
      // 粘包时下一帧字节将覆盖未交付的当前帧 payload（交付数据与缓冲解耦）。
      if (p->scratch_cap < h.payload_len) {
        size_t nc = p->scratch_cap ? p->scratch_cap : 256;
        while (nc < h.payload_len) nc *= 2;
        uint8_t *ns = (uint8_t *)realloc(p->scratch, nc);
        if (!ns) {
          // [REVIEW P3-8] 失败记日志（原静默返回，依赖后续 feed 重试）
          fw_log(FW_LOG_ERROR, "frame", "sp scratch realloc failed (%uB frame abandoned)",
                 h.payload_len);
          return; // 内存不足：放弃本帧（连接层半帧超时兜底）
        }
        p->scratch = ns;
        p->scratch_cap = nc;
      }
      memcpy(p->scratch, p->buf + h.header_len, h.payload_len);
      if (h.msk) {
        // MSK=1：XOR 还原（在暂存副本上执行，§10 编解码对称）
        fw_mask_xor(p->scratch, h.payload_len, h.mask_key);
      }
      f.payload = p->scratch;
    }
    sp_consume(p, h.expected_total);
    p->receiving = 0;
    p->header_done = 0;
    p->received = 0;
    if (p->on_frame) p->on_frame(p->ud, &f);
  }
}

int fw_sp_receiving(const fw_stream_parser_t *p) { return p->receiving || p->drop_mode; }

int fw_sp_header_complete(const fw_stream_parser_t *p) { return p->header_done; }

void fw_sp_frame_info(const fw_stream_parser_t *p, uint32_t *total, uint32_t *recv) {
  *total = p->header_done ? p->head.expected_total : 0;
  *recv = p->received;
}

// 进入丢弃模式（帧头完整、Payload 不完整，§4.1 阶段二）。
// 已收的当前帧字节立即全部作废；剩余 R = L − 已收 从后续到达字节精确消耗。
uint32_t fw_sp_enter_drop_mode(fw_stream_parser_t *p, int64_t now_ms) {
  if (!p->header_done) return 0;
  p->drop_mode = 1;
  p->drop_remaining = p->head.expected_total - p->received;
  p->drop_last_ms = now_ms; // 兜底计时起点（每收字节刷新，§4.1 退出条件 3）
  p->receiving = 0;
  p->header_done = 0;
  p->received = 0;
  p->len = 0; // 已收的当前帧字节全部作废
  return p->drop_remaining;
}
