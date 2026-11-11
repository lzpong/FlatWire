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

  TEST_BEGIN("§3.2 Length 64 位语义：PLB=7 声明长度不被 32 位截断");
  {
    // 手工构造数据帧头（PLB=7）：声明 Payload = 2^40（远超 32 位），验证
    // payload_len / expected_total 原样保留；截断会使帧边界错位（回归防护）。
    fw_parse_opts_t o;
    opts(&o, 0); // TCP 语义：UDP 会先被 max_payload_len 拒绝
    // 含 2^32−1 / 2^32：交付上限附近取值必须原样保留（头部层等价覆盖 4GB 交付路径，
    // 不实际构造该路径）；2^56−1 为协议上限顶点
    const uint64_t cases[4] = {
      (uint64_t)1 << 40,
      0xFFFFFFFFULL,
      0x100000000ULL,
      (((uint64_t)1 << 56) - 1)
    };
    for (int k = 0; k < 4; k++) {
      uint8_t hb[15];
      memset(hb, 0, sizeof(hb));
      hb[0] = 0x07; // CTR=0 REN=0 VER=0 MSK=0 PLB=7
      hb[1] = (uint8_t)((FW_TYP_NON << 6) | FW_CODE_REQUEST);
      hb[2] = 0; hb[3] = 1; hb[4] = 0; hb[5] = 1; hb[6] = 1; hb[7] = 1;
      for (int i = 0; i < 7; i++)
        hb[8 + i] = (uint8_t)((cases[k] >> (8 * (6 - i))) & 0xFF);
      fw_head_res_t h;
      CHECK(fw_parse_header(hb, sizeof(hb), 0, &o, &h) == FW_PARSE_OK);
      CHECK_EQ_INT(h.plb, 7);
      CHECK_EQ_U64(h.payload_len, cases[k]);
      CHECK_EQ_U64(h.expected_total, (uint64_t)15 + cases[k]); // 8B 帧头 + 7B Length
    }
  }
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

  TEST_BEGIN("2.17b 控制帧 ACK(0x10)/GetIDL 响应(0x11) StrmID=0 不判违规（口径定案）");
  opts(&o, 1);
  // 控制帧没有"流"概念：StrmID=0 表示不绑定流（§4.3 步骤 4 例外二）
  // TYP=ACK(2) + Code=0x10 + CTR=1 + PLB=0 → byte1 = (2<<6)|0x10 = 0x90
  uint8_t ea1[] = {0x80, 0x90, 0, 0, 0, 0, 0, 0x00};
  CHECK_EQ_INT(fw_parse_datagram(ea1, 8, &o, &fr, &rst), FW_PARSE_OK);
  // 控制帧 ACK 的 StrmID 范围仍受限：0x80 保留 → RST(0x00)
  uint8_t ea2[] = {0x80, 0x90, 0, 0, 0, 0, 0, 0x80};
  CHECK_EQ_INT(fw_parse_datagram(ea2, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  // GetIDL 响应(0x11)：TCP 上 StrmID=0 合法（不绑定流）
  uint8_t er1[] = {0x80, 0x11, 0, 0, 0, 0, 0, 0x00};
  CHECK_EQ_INT(fw_parse_header(er1, 8, 0, &o_tcp, &h5), FW_PARSE_OK);
  CHECK_EQ_INT(h5.code, 0x11);
  // 同一帧在 UDP 上必须拒绝（传输绑定约束 §7.2，与 StrmID 校验无关）
  CHECK_EQ_INT(fw_parse_datagram(er1, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
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
  // §4.3 方案 A：TYP=RST 豁免步骤 3/4 → 任意/越界 ID 仍解析成功
  uint8_t x4[] = {0x80, 0xE4, 0x12, 0x34, 0x56, 0x78, 0xAB, 0xFE}; // RST Code=0x24
  CHECK_EQ_INT(fw_parse_datagram(x4, 8, &o, &fr, &rst), FW_PARSE_OK);
  CHECK_EQ_INT(fr.svc_id, 0x1234);
  CHECK_EQ_INT(fr.if_id, 0x5678);
  CHECK_EQ_INT(fr.inst_id, 0xAB);
  CHECK_EQ_INT(fr.strm_id, 0xFE);
  // 仅豁免 ID：形态校验仍生效（RST 带 Payload，PLB=1 → RST(0x00)）
  uint8_t x5[] = {0x81, 0xE4, 0x12, 0x34, 0x56, 0x78, 0xAB, 0xFE, 0x00};
  CHECK_EQ_INT(fw_parse_datagram(x5, 9, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
  // §4.3 方案 A 扩展：数据帧 RST（CTR=0）同样豁免步骤 3/4
  // SvcID=0/IfID=0（数据帧非法）、InstID=0、StrmID=0xFF（保留值）→ 仍解析成功
  uint8_t x6[] = {0x00, 0xE4, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF};
  CHECK_EQ_INT(fw_parse_datagram(x6, 8, &o, &fr, &rst), FW_PARSE_OK);
  CHECK_EQ_INT(fr.ctr, 0);
  CHECK_EQ_INT(fr.svc_id, 0);
  CHECK_EQ_INT(fr.if_id, 0);
  CHECK_EQ_INT(fr.inst_id, 0);
  CHECK_EQ_INT(fr.strm_id, 0xFF);
  // 步骤 2 约束仍生效：数据帧 RST Code=0x01 非法 → RST(0x00)
  uint8_t x7[] = {0x00, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF};
  CHECK_EQ_INT(fw_parse_datagram(x7, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
  // 步骤 2 约束仍生效：数据帧 RST PLB>0 → RST(0x00)
  uint8_t x8[] = {0x01, 0xE4, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00};
  CHECK_EQ_INT(fw_parse_datagram(x8, 9, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
  // §4.3/§5.4：数据帧 ACK 不豁免步骤 3/4（严格口径）
  // SvcID=0 / IfID=0 / StrmID=0xFF → 步骤 3/4 违规，回 RST(0x00)
  uint8_t x9[] = {0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF};
  CHECK_EQ_INT(fw_parse_datagram(x9, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
  // 仅 StrmID 越界（其余 ID 合法）：步骤 4 单独命中 → RST(0x00)
  uint8_t x11[] = {0x00, 0x80, 0x00, 0x01, 0x00, 0x02, 0x03, 0xFF};
  CHECK_EQ_INT(fw_parse_datagram(x11, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
  // 合法数据帧 ACK（ID 全在合法范围）正常解析
  uint8_t x10[] = {0x00, 0x80, 0x00, 0x01, 0x00, 0x02, 0x03, 0xFE};
  CHECK_EQ_INT(fw_parse_datagram(x10, 8, &o, &fr, &rst), FW_PARSE_OK);
  CHECK_EQ_INT(fr.typ, FW_TYP_ACK);
  CHECK_EQ_INT(fr.strm_id, 0xFE);
  // §3.7/§8.1 例外：Subscribe(TTL=0) 取消确认 ACK(Code=0x00, CTR=1) 回显会话 StrmID
  uint8_t x12[] = {0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
  CHECK_EQ_INT(fw_parse_datagram(x12, 8, &o, &fr, &rst), FW_PARSE_OK);
  CHECK_EQ_INT(fr.typ, FW_TYP_ACK);
  CHECK_EQ_INT(fr.strm_id, 0x05);
  // 心跳 Ping（CTR=1、TYP=NON、Code=0x00）携带 StrmID≠0 → 步骤 4 违规
  uint8_t x13[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
  CHECK_EQ_INT(fw_parse_datagram(x13, 8, &o, &fr, &rst), FW_PARSE_INVALID);
  CHECK_EQ_INT(rst.rst_code, FW_RST_VIOLATION);
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

  TEST_BEGIN("轮A MSK 全 FF 密钥 + 单字节帧 + ID 极值");
  {
    // 全 FF 密钥 + 1B payload + ID 极值（SvcID/IfID=0xFFFF、InstID=0xFF、StrmID=0xFE）
    // 0x00 ^ 0xFF = 0xFF 编码，解码须还原原文；单字节 payload 走 PLB=1 边界
    uint8_t pl1[1] = {0x00};
    uint8_t mf[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    fw_frame_desc_t d1 = fdesc(0, FW_TYP_NON, FW_CODE_REQUEST, 0xFFFF, 0xFFFF, 0xFF, 0xFE, pl1, 1);
    d1.msk = 1;
    d1.mask_key = mf;
    uint32_t n1 = fw_frame_encode(buf, sizeof(buf), &d1);
    CHECK_EQ_INT(n1, 8 + 1 + 4 + 1);
    fw_frame_t f1;
    fw_head_res_t r1;
    CHECK_EQ_INT(fw_parse_datagram(buf, n1, &om, &f1, &r1), FW_PARSE_OK);
    CHECK_EQ_INT(f1.svc_id, 0xFFFF);
    CHECK_EQ_INT(f1.if_id, 0xFFFF);
    CHECK_EQ_INT(f1.inst_id, 0xFF);
    CHECK_EQ_INT(f1.strm_id, 0xFE);
    CHECK_EQ_INT(f1.payload_len, 1);
    CHECK_EQ_INT(f1.payload[0], 0x00); // 全 FF 密钥 XOR 往返
  }
  TEST_END();

  return 0;
}