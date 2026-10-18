// ============================================================
// t_frame.c —— 测试基准 1.1/1.3/1.4/1.30 帧头编解码 + 2.6~2.21 解析矩阵
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

// 构造描述 helper
static fw_frame_desc_t fdesc(int ctr, int typ, int code, uint16_t svc, uint16_t ifc,
                             uint8_t inst, uint8_t strm, const uint8_t *pl, uint32_t plen) {
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = (uint8_t)ctr;
  d.typ = (uint8_t)typ;
  d.code = (uint8_t)code;
  d.ver = 0;
  d.svc_id = svc;
  d.if_id = ifc;
  d.inst_id = inst;
  d.strm_id = strm;
  d.payload = pl;
  d.payload_len = plen;
  return d;
}

static void opts(fw_parse_opts_t *o, int udp) {
  memset(o, 0, sizeof(*o));
  o->ver = 0;
  o->max_payload_len = 1400;
  o->is_udp = udp;
}

int suite_frame(void) {
  uint8_t buf[256];
  static const uint8_t dummy_payload[32] = {0}; // 1.1 循环用（防止 NULL+非零长度 memcpy）

  TEST_BEGIN("1.1 帧头往返（全字段组合）");
  for (int ctr = 0; ctr <= 1; ctr++)
  for (int typ = 0; typ <= 3; typ++)
  for (int plb = 0; plb <= 7; plb++) {
    uint32_t plen = plb == 0 ? 0 : 32; // 各 PLB 档位统一用 32B payload（避免 32 位移位 UB）
    if (typ == FW_TYP_ACK || typ == FW_TYP_RST) plen = 0; // ACK/RST PLB=0（§3.7）
    if (ctr && plen) continue; // 控制帧固定 MSK=0 且用例中控制帧 SvcID=0
    if (typ == FW_TYP_CON || typ == FW_TYP_ACK) continue; // CON/ACK 合法性随传输（UDP/TCP）而定，另行覆盖
    int code10 = (typ == FW_TYP_RST) ? 0x00 : 0x10; // RST Code ∈ {0x00}∪0x20~0x3F（§3.7）
    fw_frame_desc_t d = fdesc(ctr, typ, code10, ctr ? 0 : 1, ctr ? 0 : 1, ctr ? 0 : 1, ctr ? 0 : 1, dummy_payload, plen);
    uint32_t n = fw_frame_encode(buf, sizeof(buf), &d);
    CHECK(n > 0);
    fw_parse_opts_t o;
    opts(&o, 0);
    fw_head_res_t h;
    CHECK(fw_parse_header(buf, n, 0, &o, &h) == FW_PARSE_OK);
    CHECK_EQ_INT(h.ctr, d.ctr);
    CHECK_EQ_INT(h.typ, d.typ);
    CHECK_EQ_INT(h.plb, fw_calc_plb(plen));
    CHECK_EQ_U64(h.payload_len, plen);
  }
  TEST_END();

  TEST_BEGIN("1.3/1.4 PLB 边界与 Length 编码");
  // 0→PLB=0；255→1；65535→2；2^24-1→3；…；2^56-1→7
  CHECK_EQ_INT(fw_calc_plb(0), 0);
  CHECK_EQ_INT(fw_calc_plb(1), 1);
  CHECK_EQ_INT(fw_calc_plb(255), 1);
  CHECK_EQ_INT(fw_calc_plb(256), 2);
  CHECK_EQ_INT(fw_calc_plb(65535), 2);
  CHECK_EQ_INT(fw_calc_plb(65536), 3);
  CHECK_EQ_INT(fw_calc_plb(((uint64_t)1 << 56) - 1), 7);
  // PLB=0：无 Length 字段，帧大小最小 8B（测试 1.30）
  fw_frame_desc_t d0 = fdesc(0, FW_TYP_NON, FW_CODE_REQUEST, 1, 1, 1, 1, NULL, 0);
  CHECK_EQ_INT(fw_frame_size(&d0), 8);
  CHECK_EQ_INT(fw_frame_encode(buf, sizeof(buf), &d0), 8);
  TEST_END();

  TEST_BEGIN("2.6/2.7/2.8 UDP 长度不符/过短/超限");
  fw_parse_opts_t o;
  opts(&o, 1);
  fw_frame_t fr;
  fw_head_res_t rst;
  // 2.7：数据报 < 8B → 丢弃
  CHECK(fw_parse_datagram((uint8_t *)"\x01\x01\x00\x01", 4, &o, &fr, &rst) != FW_PARSE_OK);
  // 2.8：Payload 超 max_payload_len → RST(0x23)
  uint8_t big[16];
  memset(big, 0, sizeof(big));
  big[0] = 0x02; // PLB=2
  big[1] = (uint8_t)((FW_TYP_NON << 6) | FW_CODE_REQUEST);
  big[2] = 0; big[3] = 1; big[4] = 0; big[5] = 1; big[6] = 1; big[7] = 1;
  big[8] = 0x05; big[9] = 0x7A; // 声明 1402 > 1400
  fw_parse_state_t st = fw_parse_datagram(big, 10, &o, &fr, &rst);
  CHECK_EQ_INT(st, FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_TOO_LARGE);
  // 2.6：数据报长度 ≠ 声明（多余）→ 丢弃（不截断）
  fw_frame_desc_t d = fdesc(0, FW_TYP_NON, FW_CODE_REQUEST, 1, 1, 1, 1, (const uint8_t *)"\x09", 1);
  uint32_t n = fw_frame_encode(buf, sizeof(buf), &d);
  CHECK(fw_parse_datagram(buf, n + 1, &o, &fr, &rst) != FW_PARSE_OK); // 多 1 字节
  CHECK(fw_parse_datagram(buf, n - 1, &o, &fr, &rst) != FW_PARSE_OK); // 少 1 字节
  TEST_END();

  TEST_BEGIN("2.9/2.10/2.11 REN 非法组合 → RST(0x00)");
  opts(&o, 1);
  // 2.9 REN=1 且 CTR=0
  uint8_t r1[] = {0x40, 0x00, 0, 0, 0, 0, 0, 0}; // CTR=0 REN=1
  CHECK_EQ_INT(fw_parse_datagram(r1, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
  // 2.10 REN=1 且 TYP≠NON
  uint8_t r2[] = {0xC0, 0x40, 0, 0, 0, 0, 0, 0}; // CTR=1 REN=1 TYP=CON
  CHECK_EQ_INT(fw_parse_datagram(r2, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // 2.11 REN=1 且 Code≠0x00
  uint8_t r3[] = {0xC0, 0x01, 0, 0, 0, 0, 0, 0}; // REN=1 Code=0x01
  CHECK_EQ_INT(fw_parse_datagram(r3, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  TEST_END();

  TEST_BEGIN("2.12 ACK Code 非法 + 2.16 ACK/RST 带载荷");
  opts(&o, 1);
  // 数据帧 ACK Code=0x10（0x10 仅 CTR=1 合法，§3.7）
  uint8_t a1[] = {0x00, 0x40, 0, 0, 0, 0, 0, 0};
  CHECK_EQ_INT(fw_parse_datagram(a1, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // 控制帧 ACK Code∉{0x00,0x10}
  uint8_t a2[] = {0x80, 0x81, 0, 0, 0, 0, 0, 0}; // CTR=1 TYP=ACK Code=0x01
  CHECK_EQ_INT(fw_parse_datagram(a2, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // 2.16：ACK PLB>0
  uint8_t a3[] = {0x81, 0x80, 0, 0, 0, 0, 0, 0, 0x05}; // CTR=1 TYP=ACK PLB=1
  CHECK_EQ_INT(fw_parse_datagram(a3, 9, &o, &fr, &rst), FW_PARSE_INVALID);
  // 2.16：RST PLB>0
  uint8_t a4[] = {0x83, 0xC0, 0, 0, 0, 0, 0, 0, 0x05};
  CHECK_EQ_INT(fw_parse_datagram(a4, 9, &o, &fr, &rst), FW_PARSE_INVALID);
  TEST_END();

  TEST_BEGIN("2.13/2.14/2.19/2.15 SvcID/IfID/InstID 校验");
  opts(&o, 1);
  // 2.13 控制帧 SvcID≠0
  uint8_t c1[] = {0x80, 0x01, 0, 1, 0, 0, 0, 0};
  CHECK_EQ_INT(fw_parse_datagram(c1, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // 2.14 数据帧 SvcID=0
  uint8_t c2[] = {0x00, 0x01, 0, 0, 0, 1, 1, 1};
  CHECK_EQ_INT(fw_parse_datagram(c2, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // 2.19 数据帧 IfID=0
  uint8_t c3[] = {0x00, 0x01, 0, 1, 0, 0, 1, 1};
  CHECK_EQ_INT(fw_parse_datagram(c3, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // 2.15 数据帧 InstID=0
  uint8_t c4[] = {0x00, 0x01, 0, 1, 0, 1, 0, 1};
  CHECK_EQ_INT(fw_parse_datagram(c4, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  TEST_END();

  TEST_BEGIN("2.17 控制帧 StrmID 范围/语义校验");
  opts(&o, 1);
  // Subscribe(Code=0x03) 携带 StrmID=0x00 → RST(0x00)
  uint8_t s1[] = {0x80, 0x03, 0, 0, 0, 0, 0, 0};
  CHECK_EQ_INT(fw_parse_datagram(s1, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // Subscribe 携带 0x01~0x7F 合法
  uint8_t s2[] = {0x80, 0x03, 0, 0, 0, 0, 0, 0x05};
  CHECK_EQ_INT(fw_parse_datagram(s2, 8, &o, &fr, &rst), FW_PARSE_OK);
  // 连接级帧（Offer=0x01）携带 0x05 → RST(0x00)
  uint8_t s3[] = {0x80, 0x01, 0, 0, 0, 0, 0, 0x05};
  CHECK_EQ_INT(fw_parse_datagram(s3, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // 连接级帧携带 0x80+ → RST(0x00)（范围越界）
  uint8_t s4[] = {0x80, 0x01, 0, 0, 0, 0, 0, 0x80};
  CHECK_EQ_INT(fw_parse_datagram(s4, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // GetIDL(0x04) 带 0x7F 合法（+3B Entry）——仅 TCP 单播（fw_parse_datagram 恒按 UDP 处理，
  // UDP 上 GetIDL → RST(0x00) §7.2，见 5.25；TCP 形态用 fw_parse_header 验证）
  uint8_t s5[] = {0x80, 0x04, 0, 0, 0, 0, 0, 0x7F, 0x10, 0x00, 0x01};
  fw_parse_opts_t o_tcp;
  opts(&o_tcp, 0); // TCP 传输
  fw_head_res_t h5;
  CHECK_EQ_INT(fw_parse_header(s5, 11, 0, &o_tcp, &h5), FW_PARSE_OK);
  CHECK_EQ_INT(h5.code, FW_CODE_SD_GETIDL);
  TEST_END();

  TEST_BEGIN("2.18 数据帧 StrmID 越界（0x00/0xFF）");
  opts(&o, 1);
  uint8_t t1[] = {0x00, 0x01, 0, 1, 0, 1, 1, 0x00};
  CHECK_EQ_INT(fw_parse_datagram(t1, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  uint8_t t2[] = {0x00, 0x01, 0, 1, 0, 1, 1, 0xFF};
  CHECK_EQ_INT(fw_parse_datagram(t2, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // 0x80~0xFE 服务端流合法
  uint8_t t3[] = {0x00, 0x03, 0, 1, 0x80, 1, 1, 0x80};
  CHECK_EQ_INT(fw_parse_datagram(t3, 8, &o, &fr, &rst), FW_PARSE_OK);
  TEST_END();

  TEST_BEGIN("2.20 RST Code 非法（非 {0x00}∪0x20~0x3F）");
  opts(&o, 1);
  uint8_t x1[] = {0x80, 0xC1, 0, 0, 0, 0, 0, 0}; // RST Code=0x01
  CHECK_EQ_INT(fw_parse_datagram(x1, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  uint8_t x2[] = {0x80, 0xC0, 0, 0, 0, 0, 0, 0}; // RST Code=0x00 合法
  CHECK_EQ_INT(fw_parse_datagram(x2, 8, &o, &fr, &rst), FW_PARSE_OK);
  uint8_t x3[] = {0x80, 0xE4, 0, 0, 0, 0, 0, 0}; // RST Code=0x24 合法
  CHECK_EQ_INT(fw_parse_datagram(x3, 8, &o, &fr, &rst), FW_PARSE_OK);
  TEST_END();

  TEST_BEGIN("2.21 TCP 收 CON/ACK → RST(0x00) + 2.29 控制帧 MSK=1");
  // TCP 禁 CON/ACK 用 fw_parse_header（fw_parse_datagram 恒按 UDP 语义处理）
  fw_parse_opts_t o_t;
  opts(&o_t, 0); // TCP
  uint8_t w1[] = {0x00, 0x40, 0, 1, 0, 1, 1, 1}; // 数据帧 TYP=CON
  fw_head_res_t hw;
  CHECK_EQ_INT(fw_parse_header(w1, 8, 0, &o_t, &hw), FW_PARSE_INVALID);
  uint8_t w2[] = {0x00, 0x81, 0, 1, 0, 1, 1, 1}; // 数据帧 TYP=ACK
  CHECK_EQ_INT(fw_parse_header(w2, 8, 0, &o_t, &hw), FW_PARSE_INVALID);
  // 2.29：控制帧 MSK=1 → RST(0x00)（§10 跨实现硬性约定）
  opts(&o, 1);
  uint8_t w3[] = {0x88, 0x01, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}; // CTR=1 MSK=1
  CHECK_EQ_INT(fw_parse_datagram(w3, 12, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
  TEST_END();

  TEST_BEGIN("1.2/5.15 VER 不等：单播 RST(0x22)、组播静默");
  fw_parse_opts_t o2;
  opts(&o2, 1);
  o2.ver = 1; // 本端 VER=1
  uint8_t v1[] = {0x80, 0x02, 0, 0, 0, 0, 0, 0}; // 组播 Find（VER=0）→ 静默
  o2.multicast_like = 1;
  CHECK_EQ_INT(fw_parse_datagram(v1, 8, &o2, &fr, &rst), FW_PARSE_SILENT);
  o2.multicast_like = 0; // 单播
  CHECK_EQ_INT(fw_parse_datagram(v1, 8, &o2, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VERSION);
  TEST_END();

  TEST_BEGIN("5.25 UDP 收 GetIDL → RST(0x00)（仅 TCP 单播）");
  opts(&o, 1);
  o.multicast_like = 0;
  uint8_t g1[] = {0x80, 0x04, 0, 0, 0, 0, 0, 0x03, 0x10, 0, 1};
  CHECK_EQ_INT(fw_parse_datagram(g1, 11, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
  // 组播 GetIDL → 静默丢弃
  o.multicast_like = 1;
  CHECK_EQ_INT(fw_parse_datagram(g1, 11, &o, &fr, &rst), FW_PARSE_SILENT);
  TEST_END();

  TEST_BEGIN("MSK=1 数据帧解析（1.28 往返 + §10）");
  fw_parse_opts_t om;
  opts(&om, 1);
  uint8_t pl[3] = {0xAA, 0xBB, 0xCC};
  uint8_t mk[4] = {0x01, 0x02, 0x03, 0x04};
  fw_frame_desc_t dm = fdesc(0, FW_TYP_NON, FW_CODE_REQUEST, 1, 1, 1, 1, pl, 3);
  dm.msk = 1;
  dm.mask_key = mk;
  uint32_t n2 = fw_frame_encode(buf, sizeof(buf), &dm);
  CHECK_EQ_INT(n2, 8 + 1 + 4 + 3);
  fw_frame_t fr2;
  fw_head_res_t rm;
  CHECK_EQ_INT(fw_parse_datagram(buf, n2, &om, &fr2, &rm), FW_PARSE_OK);
  CHECK_EQ_INT(fr2.msk, 1);
  CHECK_EQ_MEM(fr2.payload, pl, 3); // XOR 还原一致
  TEST_END();

  return 0;
}