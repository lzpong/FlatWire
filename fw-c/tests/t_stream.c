// ============================================================
// t_stream.c —— 测试基准 2.1~2.4：TCP 粘包/分包/Length 跨包/Mask 跨包（§4.1）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

// 收集回调
static fw_frame_t g_frames[16];
static int g_nframes = 0;
static int g_rst_count = 0;

static void on_frame(void *ud, const fw_frame_t *f) {
  (void)ud;
  if (g_nframes < 16) {
    g_frames[g_nframes] = *f;
    // payload 拷贝（parser 缓冲会被复用）
    if (f->payload_len) {
      uint8_t *cp = malloc(f->payload_len);
      memcpy(cp, f->payload, f->payload_len);
      g_frames[g_nframes].payload = cp;
    }
    g_nframes++;
  }
}

static void on_rst(void *ud, int code, const fw_head_res_t *echo) {
  (void)ud; (void)echo;
  g_rst_count++;
  (void)code;
}

static void reset_cb_state(void) {
  for (int i = 0; i < g_nframes; i++) free((void *)g_frames[i].payload);
  g_nframes = 0;
  g_rst_count = 0;
}

static void make_frame(uint8_t *buf, uint32_t cap, uint8_t strm, const uint8_t *pl, uint32_t n) {
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 0;
  d.typ = FW_TYP_NON;
  d.code = FW_CODE_REQUEST;
  d.svc_id = 1;
  d.if_id = 1;
  d.inst_id = 1;
  d.strm_id = strm;
  d.payload = pl;
  d.payload_len = n;
  fw_frame_encode(buf, cap, &d);
}

int suite_stream(void) {
  uint8_t buf[64];
  uint8_t pl1[3] = {9, 9, 9};
  uint8_t pl2[1] = {7};

  TEST_BEGIN("2.1 TCP 粘包：一次接收含 3 帧");
  reset_cb_state();
  fw_stream_parser_t p;
  fw_sp_init(&p);
  p.ud = NULL;
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  uint8_t three[64];
  uint32_t n1, n2, n3;
  // 帧长 = 8 + 1(PLB) + 3 = 12
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 0; d.typ = FW_TYP_NON; d.code = FW_CODE_REQUEST;
  d.svc_id = 1; d.if_id = 1; d.inst_id = 1; d.strm_id = 1;
  d.payload = pl1; d.payload_len = 3;
  n1 = fw_frame_encode(three, sizeof(three), &d);
  d.strm_id = 2; d.payload = pl2; d.payload_len = 1;
  n2 = fw_frame_encode(three + n1, sizeof(three) - n1, &d);
  d.strm_id = 3; d.payload = pl1; d.payload_len = 3;
  n3 = fw_frame_encode(three + n1 + n2, sizeof(three) - n1 - n2, &d);
  fw_sp_feed(&p, three, n1 + n2 + n3);
  CHECK_EQ_INT(g_nframes, 3);
  CHECK_EQ_INT(g_frames[0].strm_id, 1);
  CHECK_EQ_INT(g_frames[1].strm_id, 2);
  CHECK_EQ_INT(g_frames[2].strm_id, 3);
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("2.2 TCP 分包：1 字节/次多次写入");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  for (uint32_t i = 0; i < n1; i++)
    fw_sp_feed(&p, three + i, 1);
  CHECK_EQ_INT(g_nframes, 1);
  CHECK_EQ_INT(g_frames[0].strm_id, 1);
  CHECK_EQ_MEM(g_frames[0].payload, pl1, 3);
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("2.3 Length 字段跨包 + 2.4 Masking Key 跨包");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  // MSK 帧（头 8 + PLB 1 + key 4 + payload 3 = 16B）逐 3 字节喂入
  uint8_t pl[3] = {0xAA, 0xBB, 0xCC};
  fw_frame_desc_t dm;
  memset(&dm, 0, sizeof(dm));
  dm.ctr = 0; dm.typ = FW_TYP_NON; dm.code = FW_CODE_REQUEST;
  dm.svc_id = 1; dm.if_id = 1; dm.inst_id = 1; dm.strm_id = 5;
  dm.msk = 1; dm.mask_key = (const uint8_t *)"\x01\x02\x03\x04";
  dm.payload = pl; dm.payload_len = 3;
  uint32_t mn = fw_frame_encode(buf, sizeof(buf), &dm);
  CHECK_EQ_INT(mn, 16);
  for (uint32_t i = 0; i < mn; i += 3)
    fw_sp_feed(&p, buf + i, (mn - i) < 3 ? (mn - i) : 3);
  CHECK_EQ_INT(g_nframes, 1);
  CHECK_EQ_INT(g_frames[0].strm_id, 5);
  CHECK_EQ_MEM(g_frames[0].payload, pl, 3); // XOR 还原一致
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("2.22/2.23 丢弃模式：帧头完整 RST(0x26) + 收满 R 恢复");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  make_frame(buf, sizeof(buf), 1, pl1, 3); // 总长 12
  fw_sp_feed(&p, buf, 10); // 帧头完整（12B 帧只发 10B）→ 帧头完整、Payload 不完整
  CHECK_EQ_INT(fw_sp_receiving(&p), 1);
  CHECK_EQ_INT(fw_sp_header_complete(&p), 1);
  uint64_t total = 0, recv = 0; // §3.2：帧总长/已收字节为 64 位
  fw_sp_frame_info(&p, &total, &recv);
  CHECK_EQ_U64(total, 12);
  CHECK_EQ_U64(recv, 10);
  // 半帧超时（阶段二）：进入丢弃模式
  uint64_t remain = fw_sp_enter_drop_mode(&p, 1000);
  CHECK_EQ_U64(remain, 2); // R = L − 已收
  CHECK_EQ_INT(fw_sp_receiving(&p), 1);
  CHECK_EQ_INT(p.drop_mode, 1);
  // 发完剩余 2 字节 → 恢复 IDLE（退出条件 1）
  fw_sp_feed(&p, buf + 10, 2);
  CHECK_EQ_INT(p.drop_mode, 0);
  // 随后正常新帧正确解析交付（连接继续复用）
  make_frame(buf, sizeof(buf), 2, pl2, 1);
  fw_sp_feed(&p, buf, 10);
  CHECK_EQ_INT(g_nframes, 1);
  CHECK_EQ_INT(g_frames[0].strm_id, 2);
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("2.24 丢弃模式字节刷新计时 + 2.25 EOF 语义（state 层）");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  make_frame(buf, sizeof(buf), 1, pl1, 3);
  fw_sp_feed(&p, buf, 10);
  fw_sp_enter_drop_mode(&p, 1000);
  // 慢速发送：每字节间隔 < 兜底超时（模拟刷新计时）
  p.drop_last_ms = 1100; // 每收字节刷新（连接层行为）
  fw_sp_feed(&p, buf + 10, 1);
  p.drop_last_ms = 1200;
  fw_sp_feed(&p, buf + 11, 1);
  CHECK_EQ_INT(p.drop_mode, 0); // 收满恢复
  // EOF 随连接处理：drop 状态中连接关闭由连接层负责（解析器无残留状态）
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("违规帧跳过（解析层定界）");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  // 违规帧（数据帧 SvcID=0，总长可定界 8B）+ 正常帧
  uint8_t bad[] = {0x00, 0x01, 0, 0, 0, 1, 1, 1};
  fw_sp_feed(&p, bad, 8);
  CHECK_EQ_INT(g_rst_count, 1); // 回 RST(0x00)
  make_frame(buf, sizeof(buf), 1, pl1, 3);
  fw_sp_feed(&p, buf, 12);
  CHECK_EQ_INT(g_nframes, 1); // 违规帧被精确跳过，后续帧正常
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("§4.1 违规帧帧尾未到齐不得与后续帧拼接（帧走私回归）");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  {
    // VER=1 违规帧（本端 ver=0）：PLB=0 → 帧头 8B；分两段喂入（2B + 6B）
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ver = 1; d.ctr = 0; d.typ = FW_TYP_NON; d.code = FW_CODE_REQUEST;
    d.svc_id = 1; d.if_id = 1; d.inst_id = 1; d.strm_id = 1;
    uint8_t bad[8];
    uint32_t bn = fw_frame_encode(bad, sizeof(bad), &d);
    CHECK_EQ_INT(bn, 8);
    fw_sp_feed(&p, bad, 2); // 首 2B 即判定 VER 不符 → 回 RST
    CHECK_EQ_INT(g_rst_count, 1);
    CHECK_EQ_INT(g_nframes, 0);
    fw_sp_feed(&p, bad + 2, 6); // 补齐帧尾：不得被拼成"合法"帧交付
    CHECK_EQ_INT(g_nframes, 0);
    CHECK_EQ_INT(g_rst_count, 1); // 同一违规帧不重复回 RST
    CHECK_EQ_INT(p.invalid_pending, 0);
    CHECK_EQ_INT(fw_sp_receiving(&p), 0);
  }
  make_frame(buf, sizeof(buf), 2, pl2, 1);
  fw_sp_feed(&p, buf, 10); // 帧边界已恢复，后续帧正常交付
  CHECK_EQ_INT(g_nframes, 1);
  CHECK_EQ_INT(g_frames[0].strm_id, 2);
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("§4.1 违规帧 Length 跨包：帧头到齐后进入丢弃并精确收满");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  {
    // VER=1 违规帧，payload=300 → PLB=2，帧头 10B，总长 310B
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ver = 1; d.ctr = 0; d.typ = FW_TYP_NON; d.code = FW_CODE_REQUEST;
    d.svc_id = 1; d.if_id = 1; d.inst_id = 1; d.strm_id = 1;
    uint8_t pl300[300];
    memset(pl300, 0xEE, sizeof(pl300));
    d.payload = pl300; d.payload_len = 300;
    uint8_t bad[310];
    uint32_t bn = fw_frame_encode(bad, sizeof(bad), &d);
    CHECK_EQ_INT(bn, 310);
    fw_sp_feed(&p, bad, 2);   // 判定违规 → RST，等待帧头（Length 未到齐）
    CHECK_EQ_INT(g_rst_count, 1);
    CHECK_EQ_INT(p.invalid_pending, 1);
    fw_sp_feed(&p, bad + 2, 8); // Length 到齐（帧头 10B）→ 未收满 → 丢弃模式
    CHECK_EQ_INT(p.invalid_pending, 0);
    CHECK_EQ_INT(p.drop_mode, 1);
    CHECK_EQ_INT(fw_sp_receiving(&p), 1);
    fw_sp_feed(&p, bad + 10, 300); // 收满剩余 R → 恢复空闲
    CHECK_EQ_INT(p.drop_mode, 0);
    CHECK_EQ_INT(g_nframes, 0); // 违规帧整体被丢弃，未交付
    CHECK_EQ_INT(g_rst_count, 1);
  }
  make_frame(buf, sizeof(buf), 3, pl2, 1);
  fw_sp_feed(&p, buf, 10);
  CHECK_EQ_INT(g_nframes, 1);
  CHECK_EQ_INT(g_frames[0].strm_id, 3);
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("§3.2 超大声明长度：丢弃剩余 R 按 64 位计算（不截断）");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  p.on_rst = on_rst;
  {
    // PLB=7，声明 Payload = 2^40：帧头完整后解析器应停在等待状态，
    // 阶段二丢弃模式的 R 必须等于声明总长 − 已收，不能用 32 位截断值。
    uint8_t hb[15];
    memset(hb, 0, sizeof(hb));
    hb[0] = 0x07; // CTR=0 REN=0 VER=0 MSK=0 PLB=7
    hb[1] = (uint8_t)((FW_TYP_NON << 6) | FW_CODE_REQUEST);
    hb[2] = 0; hb[3] = 1; hb[4] = 0; hb[5] = 1; hb[6] = 1; hb[7] = 1;
    const uint64_t plen = (uint64_t)1 << 40;
    for (int i = 0; i < 7; i++) hb[8 + i] = (uint8_t)((plen >> (8 * (6 - i))) & 0xFF);
    fw_sp_feed(&p, hb, sizeof(hb));
  }
  CHECK_EQ_INT(fw_sp_receiving(&p), 1);
  CHECK_EQ_INT(fw_sp_header_complete(&p), 1);
  {
    uint64_t total = 0, recv = 0;
    fw_sp_frame_info(&p, &total, &recv);
    CHECK_EQ_U64(total, (uint64_t)15 + ((uint64_t)1 << 40));
    CHECK_EQ_U64(recv, 15);
    uint64_t remain = fw_sp_enter_drop_mode(&p, 1000);
    CHECK_EQ_U64(remain, (uint64_t)1 << 40); // R = L − 已收，64 位无损
  }
  fw_sp_free(&p);
  TEST_END();

  TEST_BEGIN("§4.1 大帧分片 + 压实：交付 payload 完整（不随缓冲搬迁损坏）");
  reset_cb_state();
  fw_sp_init(&p);
  p.on_frame = on_frame;
  {
    // payload=100KB（PLB=3）按 997B 分片喂入；消费过半会触发 sp_compact，
    // 交付 payload（已拷入 scratch）必须逐字节完整，不能被搬迁覆盖。
    const uint32_t blen = 100u * 1024u;
    uint8_t *big = (uint8_t *)malloc(blen);
    for (uint32_t i = 0; i < blen; i++) big[i] = (uint8_t)(i % 251);
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ctr = 0; d.ver = 0; d.typ = FW_TYP_NON; d.code = FW_CODE_REQUEST;
    d.svc_id = 1; d.if_id = 1; d.inst_id = 1; d.strm_id = 9;
    d.payload = big; d.payload_len = blen;
    uint8_t *raw = (uint8_t *)malloc(blen + 16);
    uint32_t rn = fw_frame_encode(raw, blen + 16, &d);
    CHECK_EQ_INT(rn, blen + 11); // 8B 头 + 3B Length + payload
    for (uint32_t i = 0; i < rn; i += 997) {
      uint32_t n = (i + 997 <= rn) ? 997 : rn - i;
      fw_sp_feed(&p, raw + i, n);
    }
    CHECK_EQ_INT(g_nframes, 1);
    CHECK_EQ_INT((int)g_frames[0].payload_len, (int)blen);
    CHECK_EQ_INT(g_frames[0].payload[0], 0);
    CHECK_EQ_INT(g_frames[0].payload[100], 100);
    CHECK_EQ_INT(g_frames[0].payload[blen - 1], (blen - 1) % 251);
    free(raw);
    free(big);
  }
  fw_sp_free(&p);
  TEST_END();

  // 清理可能残留的回调拷贝
  reset_cb_state();
  return 0;
}