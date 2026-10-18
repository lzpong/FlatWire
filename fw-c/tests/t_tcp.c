// ============================================================
// t_tcp.c —— 测试基准 2.5/2.22~2.28：TCP 半帧两阶段（真实 socket）
// 使用栈内置 TCP 监听 + 原始 socket 客户端，短超时加速。
// ============================================================

#include "test_util.h"
#include "../src/fw_int.h"
#include <stdio.h>

#define PORT 45430
#define FRAME_TIMEOUT 300 // 短半帧超时（ms）

static fw_stack_t *g_srv = NULL;


// 原始客户端：连接 → 收集 RST 帧
typedef struct {
  fw_fd_t fd;
  uint8_t buf[4096];
  int len;
  int rst_seen;
  int rst_codes[16]; // 已消费 RST 帧的 Code（raw_pump 解析即消费，须就地记录）
  int nrst;
  int closed;
} raw_client_t;

// 解析收到的字节（服务端响应帧均无 MSK），统计 RST
static int raw_pump(raw_client_t *c) {
  uint8_t tmp[2048];
  int n = (int)recv(c->fd, (char *)tmp, sizeof(tmp), 0);
  if (n <= 0) return n;
  if (c->len + n > (int)sizeof(c->buf)) return n;
  memcpy(c->buf + c->len, tmp, n);
  c->len += n;
  // 逐帧解析
  int off = 0;
  for (;;) {
    if (c->len - off < 8) break;
    uint8_t b0 = c->buf[off];
    int plb = b0 & 0x07;
    int has_msk = (b0 >> 3) & 1;
    int hl = 8 + plb + (has_msk ? 4 : 0);
    if (c->len - off < hl) break;
    uint32_t plen = 0;
    for (int i = 0; i < plb; i++) plen = (plen << 8) | c->buf[off + 8 + i];
    uint32_t total = (uint32_t)hl + plen;
    if ((uint32_t)(c->len - off) < total) break;
    uint8_t typ = (c->buf[off + 1] >> 6) & 3;
    if (typ == FW_TYP_RST) {
      c->rst_seen++;
      if (c->nrst < (int)(sizeof(c->rst_codes) / sizeof(c->rst_codes[0])))
        c->rst_codes[c->nrst++] = c->buf[off + 1] & 0x3F; // Code 6bit（byte1 低 6 位）
    }
    off += (int)total;
  }
  if (off > 0) {
    memmove(c->buf, c->buf + off, c->len - off);
    c->len -= off;
  }
  return n;
}

static int raw_connect(raw_client_t *c) {
  memset(c, 0, sizeof(*c));
  c->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (c->fd == FW_FD_INVALID) return -1;
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(PORT);
  sa.sin_addr.s_addr = inet_addr("127.0.0.1");
  if (connect(c->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
    fw_plat_close(c->fd);
    c->fd = FW_FD_INVALID;
    return -1;
  }
  // 阻塞读超时 50ms（轮询风格）
  int tv = 50;
  setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
  return 0;
}

static int wait_rst(raw_client_t *c, int loops) {
  for (int i = 0; i < loops; i++) {
    if (g_srv) fw_stack_poll(g_srv, 5); // 驱动服务端（收数据 + 半帧超时判定）
    raw_pump(c);
    if (c->rst_seen) return 1;
    fw_sleep_ms(20);
  }
  return c->rst_seen ? 1 : 0;
}

static int srv_start(void) {
  if (g_srv) return 0;
  fw_config_t cfg;
  fw_config_defaults(&cfg);
  cfg.port = PORT;
  cfg.bind_address = "127.0.0.1";
  cfg.tcp_frame_timeout_ms = FRAME_TIMEOUT;
  cfg.tcp_enabled = 1;
  cfg.idl_dir = ".idl-test-tcp";
  if (fw_stack_init(&g_srv, &cfg) != FW_OK) return -1;
  // 仅监听 TCP（不 start 完整栈，避免组播流量干扰其他测试）
  fw_plat_init();
  char err[128];
  if (fw_tcp_listen(g_srv, err, sizeof(err)) != FW_OK) return -1;
  g_srv->started = 1; // 仅 TCP 测试：手动置位以允许 fw_stack_poll 驱动（不开 UDP 避免组播干扰）
  return 0;
}

static void srv_stop(void) {
  if (g_srv) {
    g_srv->started = 0;
    fw_tcp_stop(g_srv);
    fw_stack_free(g_srv);
    g_srv = NULL;
  }
}

int suite_tcp(void) {
  TEST_BEGIN("2.5 半帧超时——帧头不完整(<8B) → RST(0x26)+关连接");
  CHECK_EQ_INT(srv_start(), 0);
  {
  raw_client_t c;
  CHECK_EQ_INT(raw_connect(&c), 0);
  // 3B < 8B 帧头不完整（前缀不触发 §4.3 即时校验，仅卡帧头不完整）
  uint8_t part[] = {0x01, 0x01, 0x10};
  send(c.fd, (const char *)part, 3, 0);
  CHECK_EQ_INT(wait_rst(&c, 20), 1);
  // 检查收到的 RST Code=0x26（raw_pump 解析即消费，从记录中查）
  int found26 = 0;
  for (int i = 0; i < c.nrst; i++)
    if (c.rst_codes[i] == 0x26) found26 = 1;
  CHECK_EQ_INT(found26, 1);
  // 连接被关闭（FIN）：recv 返回 0
  int eof = 0;
  for (int i = 0; i < 20 && !eof; i++) {
    if (g_srv) fw_stack_poll(g_srv, 5);
    int n = raw_pump(&c);
    if (n == 0) eof = 1;
    fw_sleep_ms(20);
  }
  CHECK_EQ_INT(eof, 1); // 帧总长不可知 → 关闭连接（§4.1 阶段一）
  fw_plat_close(c.fd);
  }
  TEST_END();

  TEST_BEGIN("2.22/2.23/2.28 帧头完整 → RST(0x26)+丢弃模式；收满 R 恢复复用");
  {
  raw_client_t c;
  CHECK_EQ_INT(raw_connect(&c), 0);
  // 完整帧（总长 8+1+3=12B）只发 10B → 帧头完整、Payload 不完整
  uint8_t half[12];
  half[0] = 0x01; // PLB=1
  half[1] = (FW_TYP_NON << 6) | FW_CODE_REQUEST;
  half[2] = 0; half[3] = 1; half[4] = 0; half[5] = 1; half[6] = 1; half[7] = 1;
  half[8] = 3;   // Length=3
  half[9] = 0xAA; half[10] = 0xBB; half[11] = 0xCC;
  send(c.fd, (const char *)half, 10, 0);
  CHECK_EQ_INT(wait_rst(&c, 20), 1);
  // 连接不关闭（丢弃模式，§4.1 阶段二）：50ms 内 recv 无 EOF
  int closed = 0;
  for (int i = 0; i < 6; i++) {
    if (g_srv) fw_stack_poll(g_srv, 5);
    int n = raw_pump(&c);
    if (n == 0) { closed = 1; break; }
    fw_sleep_ms(20);
  }
  CHECK_EQ_INT(closed, 0);
  // 发完剩余 R=2 字节 → 恢复 IDLE；随后发正常新帧 → 正确解析（连接复用）
  send(c.fd, (const char *)half + 10, 2, 0);
  // 完整新帧：strm=2, payload=[7]
  uint8_t next[10];
  next[0] = 0x01; next[1] = (FW_TYP_NON << 6) | FW_CODE_REQUEST;
  next[2] = 0; next[3] = 1; next[4] = 0; next[5] = 1; next[6] = 1; next[7] = 2;
  next[8] = 1; next[9] = 7;
  send(c.fd, (const char *)next, 10, 0);
  // 服务端是否收到新帧无法直接观测（栈未挂分发断言）——丢弃完成后连接可用性
  // 由"无 EOF + 无二次 RST"间接验证（2.23 连接复用 / 2.28 反向 RST 不污染正向流）
  fw_sleep_ms(100);
  raw_pump(&c);
  CHECK_EQ_INT(c.rst_seen, 1); // 仅半帧 RST(0x26) 一次（新帧未触发违规）
  CHECK_EQ_INT(closed, 0);
  fw_plat_close(c.fd);
  }
  TEST_END();

  TEST_BEGIN("2.26 丢弃模式兜底超时（2×tcp_frame_timeout）");
  // 真实时钟下兜底 = 2×300ms = 600ms：进入丢弃后完全停止发送 → 连接关闭
  {
  raw_client_t c;
  CHECK_EQ_INT(raw_connect(&c), 0);
  uint8_t half[10];
  half[0] = 0x01; half[1] = (FW_TYP_NON << 6) | FW_CODE_REQUEST;
  half[2] = 0; half[3] = 1; half[4] = 0; half[5] = 1; half[6] = 1; half[7] = 1;
  half[8] = 3; half[9] = 0x01; // 帧头完整（10/12B）
  send(c.fd, (const char *)half, 10, 0);
  CHECK_EQ_INT(wait_rst(&c, 20), 1); // RST(0x26) + 丢弃模式
  // 完全停止发送：600ms 兜底 → 关连接（EOF）
  int eof = 0;
  for (int i = 0; i < 60 && !eof; i++) {
    if (g_srv) fw_stack_poll(g_srv, 10);
    int n = raw_pump(&c);
    if (n == 0) eof = 1;
    fw_sleep_ms(30);
  }
  CHECK_EQ_INT(eof, 1); // 兜底超时关闭连接（协议固定倍率 2×）
  fw_plat_close(c.fd);
  }
  TEST_END();

  srv_stop();
  return 0;
}