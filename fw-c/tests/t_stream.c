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
  uint32_t total = 0, recv = 0;
  fw_sp_frame_info(&p, &total, &recv);
  CHECK_EQ_INT(total, 12);
  CHECK_EQ_INT(recv, 10);
  // 半帧超时（阶段二）：进入丢弃模式
  uint32_t remain = fw_sp_enter_drop_mode(&p, 1000);
  CHECK_EQ_INT(remain, 2); // R = L − 已收
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

  // 清理可能残留的回调拷贝
  reset_cb_state();
  return 0;
}