// ============================================================
// t_tcp.c —— 测试基准 2.5/2.22~2.28：TCP 半帧两阶段（真实 socket）
// 使用栈内置 TCP 监听 + 原始 socket 客户端，短超时加速。
// ============================================================

#include "test_util.h"
#include "../src/fw_int.h"
#include <stdio.h>
#ifndef _WIN32
#include <dirent.h>
#endif

#define PORT 45430
#define FRAME_TIMEOUT 300 // 短半帧超时（ms）

static fw_stack_t *g_srv = NULL;

// 进程 fd/句柄总数：验证建连失败与并发断开路径不泄漏（Windows 句柄数 / POSIX /proc/self/fd）
static int proc_fd_count(void) {
#ifdef _WIN32
  DWORD n = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &n)) return -1;
  return (int)n;
#else
  DIR *d = opendir("/proc/self/fd");
  if (!d) return -1;
  int n = 0;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) if (e->d_name[0] != '.') n++;
  closedir(d);
  return n;
#endif
}

// realloc 失败桩：模拟扩容 OOM（不释放旧块，语义同真实 realloc 失败）
static void *fail_realloc(void *p, size_t n) { (void)p; (void)n; return NULL; }


// 原始客户端：连接 → 收集 RST 帧
typedef struct {
  fw_fd_t fd;
  uint8_t buf[4096];
  int len;
  int rst_seen;
  int rst_codes[16]; // 已消费 RST 帧的 Code（raw_pump 解析即消费，须就地记录）
  int rst_strms[16]; // 对应 RST 的 StrmID（验证半帧 RST 回显，§5.4/§4.1）
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
      if (c->nrst < (int)(sizeof(c->rst_codes) / sizeof(c->rst_codes[0]))) {
        c->rst_codes[c->nrst] = c->buf[off + 1] & 0x3F; // Code 6bit（byte1 低 6 位）
        c->rst_strms[c->nrst] = c->buf[off + 7];        // StrmID 回显值
        c->nrst++;
      }
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

// 可指定端口的原始连接（上限/并发用例需要独立监听端口，避免与 g_srv 互相干扰）
static int raw_connect_to(raw_client_t *c, uint16_t port) {
  memset(c, 0, sizeof(*c));
  c->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (c->fd == FW_FD_INVALID) return -1;
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = inet_addr("127.0.0.1");
  if (connect(c->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
    fw_plat_close(c->fd);
    c->fd = FW_FD_INVALID;
    return -1;
  }
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

// 独立 TCP 监听栈（连接表/上限/并发用例专用；不启动 UDP，避免组播流量干扰）
static fw_stack_t *mini_stack(uint16_t port, uint32_t max_conns) {
  fw_config_t cfg;
  fw_config_defaults(&cfg);
  cfg.port = port;
  cfg.bind_address = "127.0.0.1";
  cfg.tcp_frame_timeout_ms = FRAME_TIMEOUT;
  cfg.tcp_enabled = 1;
  cfg.max_conns = max_conns;
  cfg.idl_dir = ".idl-test-tcp";
  fw_plat_init();
  fw_stack_t *st = NULL;
  if (fw_stack_init(&st, &cfg) != FW_OK) return NULL;
  char err[128];
  if (fw_tcp_listen(st, err, sizeof(err)) != FW_OK) {
    fw_stack_free(st);
    return NULL;
  }
  st->started = 1; // 仅 TCP：手动置位以允许 fw_stack_poll 驱动（不开 UDP）
  return st;
}

static void mini_stop(fw_stack_t *st) {
  if (!st) return;
  st->started = 0;
  fw_tcp_stop(st);
  fw_stack_free(st);
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

  // ---- 2.25（C 侧补齐）：丢弃模式对端 EOF → 服务端立即终止，无悬挂连接 ----
  TEST_BEGIN("2.25 丢弃模式对端 EOF：关闭即终止，无悬挂状态");
  {
  // 先清空前序用例残留（驱动 TCP 轮询完成关闭清理）
  for (int i = 0; i < 30 && g_srv->nconn > 0; i++) { fw_stack_poll(g_srv, 5); fw_sleep_ms(5); }
  CHECK_EQ_INT(g_srv->nconn, 0);
  raw_client_t c;
  CHECK_EQ_INT(raw_connect(&c), 0);
  uint8_t half[10];
  half[0] = 0x01; half[1] = (FW_TYP_NON << 6) | FW_CODE_REQUEST;
  half[2] = 0; half[3] = 1; half[4] = 0; half[5] = 1; half[6] = 1; half[7] = 1;
  half[8] = 1; half[9] = 0; // 帧头完整（9/10B）→ 丢弃模式
  send(c.fd, (const char *)half, 9, 0);
  CHECK_EQ_INT(wait_rst(&c, 20), 1); // RST(0x26) 已回，进入丢弃模式
  fw_plat_close(c.fd);               // 对端 EOF（半关闭 → 关闭）
  for (int i = 0; i < 60 && g_srv->nconn > 0; i++) { fw_stack_poll(g_srv, 5); fw_sleep_ms(5); }
  CHECK_EQ_INT(g_srv->nconn, 0); // 连接随 EOF 移除（无悬挂状态/无 fd 残留）
  }
  TEST_END();

  // ---- 2.30（集成）：多帧粘包 → 交付完若干帧后进入半帧 → RST 回显该半帧 StrmID ----
  TEST_BEGIN("2.30 粘包交付后进入半帧：RST(0x26) 回显半帧 StrmID");
  {
  raw_client_t c;
  CHECK_EQ_INT(raw_connect(&c), 0);
  // 3 个完整帧（StrmID=1/2/3）+ 第 4 帧仅帧头（StrmID=0x2A，Payload 缺 1B）
  uint8_t buf[4 * 10];
  for (int k = 0; k < 3; k++) {
    uint8_t *p = buf + k * 10;
    p[0] = 0x01; p[1] = (FW_TYP_NON << 6) | FW_CODE_REQUEST;
    p[2] = 0; p[3] = 1; p[4] = 0; p[5] = 1; p[6] = 1; p[7] = (uint8_t)(k + 1);
    p[8] = 1; p[9] = (uint8_t)(0xA0 + k);
  }
  {
  uint8_t *h = buf + 30;
  h[0] = 0x01; h[1] = (FW_TYP_NON << 6) | FW_CODE_REQUEST;
  h[2] = 0; h[3] = 1; h[4] = 0; h[5] = 1; h[6] = 1; h[7] = 0x2A;
  h[8] = 1; h[9] = 0; // 帧头 9B 已发（完整），Payload 1B 未发 → 阶段二半帧
  }
  send(c.fd, (const char *)buf, 39, 0); // 30B 完整帧 + 9B 半帧帧头
  // 等 RST(0x26)（前 3 帧未注册服务会各自回 RST(0x24)，不能只看 rst_seen）
  int got26 = 0;
  for (int i = 0; i < 30 && !got26; i++) {
    fw_stack_poll(g_srv, 5);
    raw_pump(&c);
    for (int k = 0; k < c.nrst; k++) if (c.rst_codes[k] == 0x26) got26 = 1;
    if (!got26) fw_sleep_ms(20);
  }
  CHECK_EQ_INT(got26, 1);
  int idx26 = -1;
  for (int i = 0; i < c.nrst; i++) if (c.rst_codes[i] == 0x26) { idx26 = i; break; }
  CHECK(idx26 >= 0);
  if (idx26 >= 0) CHECK_EQ_INT(c.rst_strms[idx26], 0x2A); // 回显半帧 StrmID（非前帧 1/2/3）
  fw_plat_close(c.fd);
  }
  TEST_END();

  srv_stop();

  // ---- R3-6：conns_add 失败分支（注入式 mock） ----
  // 手法：用 fw_tcp_test_set_realloc_hook(fail_realloc) 让连接表扩容的 realloc 固定
  // 返回 NULL，稳定构造"扩容 OOM"（真实内存耗尽无法在单测可靠复现）。断言调用点
  // 已关闭 fd + conn_free：返回 NULL、连接表长度不变、进程句柄数不增；恢复钩子后
  // 同一栈仍可正常建连（证明 fd/内存均已释放，无"已建立但未注册"连接残留）。
  TEST_BEGIN("R3-6 conns_add 扩容失败注入：返回 NULL + 关 fd + conn_free（无泄漏）");
  {
  const uint16_t P = PORT + 1;
  fw_stack_t *st = mini_stack(P, 1024);
  CHECK(st != NULL);
  int before = proc_fd_count();
  fw_tcp_test_set_realloc_hook(fail_realloc); // 注入：首次扩容（0→8）必失败
  char err[160] = "";
  fw_tcpconn_t *c = fw_tcp_get_conn(st, "127.0.0.1", P, NULL, err, sizeof(err));
  CHECK(c == NULL);                  // 入表失败 → 建连失败返回 NULL
  CHECK_EQ_INT(st->nconn, 0);        // 未入表
  CHECK(strstr(err, "OOM") != NULL); // 错误信息说明失败原因（OOM/limit）
  // 连续 50 次失败建连：若调用点漏关 fd，句柄数将线性增长 ≥50；实测应基本持平。
  // （Windows GetProcessHandleCount 有少量平台噪声，故容差 3 ≪ 泄漏量）
  int repeated = 0;
  for (int i = 0; i < 50; i++) {
    char e[160] = "";
    if (fw_tcp_get_conn(st, "127.0.0.1", P, NULL, e, sizeof(e)) == NULL) repeated++;
  }
  fw_tcp_test_set_realloc_hook(NULL); // 恢复真实 realloc
  CHECK_EQ_INT(repeated, 50);
  CHECK_EQ_INT(st->nconn, 0);
  int after_fail = proc_fd_count();
  printf("  [INFO] R3-6 51 次失败建连：fd before=%d after=%d\n", before, after_fail);
  CHECK(after_fail <= before + 3);   // fd 已关闭（无泄漏）
  // 恢复后同栈可再次建连：失败路径未污染连接表、未耗尽 fd
  char err2[160] = "";
  fw_tcpconn_t *ok = fw_tcp_get_conn(st, "127.0.0.1", P, NULL, err2, sizeof(err2));
  CHECK(ok != NULL);
  CHECK_EQ_INT(st->nconn, 1);
  mini_stop(st);
  }
  TEST_END();

  // ---- R3-8：连接上限（入站路径：accept 后超限立即关闭并回收 fd） ----
  TEST_BEGIN("R3-8 连接上限 max_conns=2：第 3 条入站连接被拒并回收 fd");
  {
  const uint16_t P = PORT + 2;
  fw_stack_t *st = mini_stack(P, 2);
  CHECK(st != NULL);
  int before = proc_fd_count();
  raw_client_t c1, c2, c3;
  CHECK_EQ_INT(raw_connect_to(&c1, P), 0);
  CHECK_EQ_INT(raw_connect_to(&c2, P), 0);
  for (int i = 0; i < 60 && st->nconn < 2; i++) { fw_stack_poll(st, 5); fw_sleep_ms(5); }
  CHECK_EQ_INT(st->nconn, 2); // 前两条正常入表
  // 第 3 条：内核完成握手（backlog），服务端 accept 后因超限立即关闭
  CHECK_EQ_INT(raw_connect_to(&c3, P), 0);
  int eof3 = 0;
  for (int i = 0; i < 80 && !eof3; i++) {
    fw_stack_poll(st, 5);
    if (raw_pump(&c3) == 0) eof3 = 1; // recv==0 → 服务端已关闭该连接
    fw_sleep_ms(5);
  }
  CHECK_EQ_INT(eof3, 1);      // 超限连接被关闭（不留悬挂 fd）
  CHECK_EQ_INT(st->nconn, 2); // 不挤掉已建立的连接
  fw_plat_close(c1.fd);
  fw_plat_close(c2.fd);
  fw_plat_close(c3.fd);
  for (int i = 0; i < 120 && st->nconn > 0; i++) { fw_stack_poll(st, 5); fw_sleep_ms(5); }
  CHECK_EQ_INT(st->nconn, 0);
  int after = proc_fd_count();
  printf("  [INFO] R3-8 fd before=%d after=%d\n", before, after);
  CHECK(after <= before + 2);
  mini_stop(st);
  }
  TEST_END();

  // ---- R3-C：300 并发建连/断开压测（句柄回收 + 连接表归零 + 动态 pollfd 扩容） ----
  TEST_BEGIN("R3-C 300 并发建连/断开：无 fd 泄漏、连接表归零（>旧固定 280 pollfd 上限）");
  {
  static raw_client_t cl[300]; // static：避免 300×~4KB 占满测试栈
  const uint16_t P = PORT + 3;
  fw_stack_t *st = mini_stack(P, 1024);
  CHECK(st != NULL);
  int before = proc_fd_count();
  int okc = 0;
  // 每 8 条驱动一次 accept，避免 listen backlog(16) 被填满导致握手拒绝
  for (int i = 0; i < 300; i++) {
    if (raw_connect_to(&cl[i], P) == 0) okc++;
    if ((i + 1) % 8 == 0) fw_stack_poll(st, 1);
  }
  CHECK_EQ_INT(okc, 300);
  for (int i = 0; i < 300 && st->nconn < 300; i++) { fw_stack_poll(st, 5); fw_sleep_ms(2); }
  CHECK_EQ_INT(st->nconn, 300); // 全部入表（超过旧固定 280 pollfd 容量）
  for (int i = 0; i < 300; i++) fw_plat_close(cl[i].fd);
  for (int i = 0; i < 600 && st->nconn > 0; i++) { fw_stack_poll(st, 5); fw_sleep_ms(2); }
  CHECK_EQ_INT(st->nconn, 0); // EOF 后全部回收
  int after = proc_fd_count();
  printf("  [INFO] R3-C 300 并发：fd before=%d after=%d\n", before, after);
  CHECK(after <= before + 2);
  mini_stop(st);
  }
  TEST_END();

  // ============================================================
  // 发送背压（实现限制，非协议语义）
  // BP-1 上限/拒写/无 2 倍扩容；BP-2 满队列下控制帧直写；BP-3 持续满断连
  // ============================================================

  // 造「数据队列满」：对端不读，持续发送合法数据帧直到 FW_ERR_WOULDBLOCK
  TEST_BEGIN("BP-1 数据帧队列打满 → FW_ERR_WOULDBLOCK、拒绝计数增长、拒绝上限 +4KB 内（无 2 倍扩容）");
  {
    const uint16_t P = PORT + 4;
    fw_stack_t *st = mini_stack(P, 8);
    CHECK(st != NULL);
    st->cfg.max_send_queue_bytes = 8192;
    st->cfg.send_queue_budget_bytes = 65536;
    static uint8_t pl[2048];
    memset(pl, 0x33, sizeof(pl));
    raw_client_t c;
    CHECK_EQ_INT(raw_connect_to(&c, P), 0);
    for (int i = 0; i < 80 && st->nconn == 0; i++) { fw_stack_poll(st, 2); fw_sleep_ms(3); }
    CHECK_EQ_INT(st->nconn, 1);
    fw_tcpconn_t *s = st->conns[0];
    // 注入「部分发送后余量已入队」的等价积压状态——这正是 fw_tcp_conn_write 内部的真实状态。
    // 不用「真实写满 socket」构造：Windows SNDBUF 自适应可达数 MB，900×2KB 仍全部被内核接收，
    // 无法稳定触发；注入只绕过平台缓冲差异，上限判定/拒写/记账/控制帧分支均为真实代码路径。
    s->sbuf = (uint8_t *)malloc(2048);
    CHECK(s->sbuf != NULL);
    memset(s->sbuf, 0x33, 2048);
    s->slen = 2048; s->ssent = 0; s->scap = 2048;
    st->sendq_bytes = 2048;
    int rc = FW_OK, frames = 0;
    while (frames++ < 10) {
      fw_frame_desc_t d;
      memset(&d, 0, sizeof(d));
      d.ctr = 0; d.typ = FW_TYP_NON; d.code = 0x01; d.ver = 0;
      d.svc_id = 0xF00D; d.if_id = 1; d.inst_id = 1; d.strm_id = 1;
      d.payload = pl; d.payload_len = (uint32_t)sizeof(pl);
      rc = fw_tcp_send_frame(st, s, &d);
      if (rc == FW_ERR_WOULDBLOCK) break;
      CHECK_EQ_INT(rc, FW_OK);
    }
    fw_sendq_stats_t q;
    fw_stats_sendq(st, &q);
    printf("  [INFO] BP-1 frames=%d rc=%d queued=%llu peak=%llu rejects=%u scap=%llu\n",
           frames, rc, (unsigned long long)q.queued_bytes, (unsigned long long)q.peak_bytes,
           q.rejects, (unsigned long long)s->scap);
    CHECK_EQ_INT(rc, FW_ERR_WOULDBLOCK); // 满 → 暂不可写（未丢帧、未写半帧）
    CHECK(q.rejects > 0);
    CHECK(q.queued_bytes <= (size_t)st->cfg.max_send_queue_bytes + 2080); // 上限 + 至多一帧
    CHECK((size_t)s->scap <= (size_t)st->cfg.max_send_queue_bytes + 4096); // 4KB 块增长，无 2 倍

    // BP-2：数据队列仍满（pending>0）、socket 内核缓冲为空 → RST（8B 小控制帧）必须直写成功；
    // 若控制帧误入队，将因 pending+8B 超上限而返回 WOULDBLOCK。对端可立即解析收到该 RST。
    fw_frame_desc_t rst;
    fw_make_rst(&rst, 0x00, 1, 0xF00D, 1, 1, 0x2A);
    int crc = fw_tcp_send_frame(st, s, &rst);
    printf("  [INFO] BP-2 ctrl rc=%d (data queue pending=%llu)\n", crc,
           (unsigned long long)(s->slen - s->ssent));
    CHECK_EQ_INT(crc, FW_OK); // 数据队列满，控制帧仍可发出
    int got = 0;
    for (int i = 0; i < 20 && !got; i++) {
      if (raw_pump(&c) <= 0) fw_sleep_ms(3);
      for (int k = 0; k < c.nrst; k++)
        if (c.rst_codes[k] == 0x00) got = 1;
    }
    CHECK_EQ_INT(got, 1); // 对端实际收到 RST(0x00)
    fw_plat_close(c.fd);
    mini_stop(st);
  }
  TEST_END();

  TEST_BEGIN("BP-3 队列持续满超过 2×心跳周期 → 主动断连（conn_closed_full 增长）");
  {
    const uint16_t P = PORT + 5;
    fw_stack_t *st = mini_stack(P, 8);
    CHECK(st != NULL);
    st->cfg.heartbeat_period_ms = 20; // 2×=40ms（测试加速；不参与协议语义）
    st->cfg.max_send_queue_bytes = 4096;
    st->cfg.send_queue_budget_bytes = 32768;
    static uint8_t pl[2048];
    memset(pl, 0x44, sizeof(pl));
    raw_client_t c;
    CHECK_EQ_INT(raw_connect_to(&c, P), 0);
    for (int i = 0; i < 80 && st->nconn == 0; i++) { fw_stack_poll(st, 2); fw_sleep_ms(3); }
    CHECK_EQ_INT(st->nconn, 1);
    fw_tcpconn_t *s = st->conns[0];
    // 同上：注入 2048B 积压，使首个 2058B 数据帧即触发 4096B 上限
    s->sbuf = (uint8_t *)malloc(2048);
    CHECK(s->sbuf != NULL);
    memset(s->sbuf, 0x44, 2048);
    s->slen = 2048; s->ssent = 0; s->scap = 2048;
    st->sendq_bytes = 2048;
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ctr = 0; d.typ = FW_TYP_NON; d.code = 0x01; d.ver = 0;
    d.svc_id = 0xF00D; d.if_id = 1; d.inst_id = 1; d.strm_id = 1;
    d.payload = pl; d.payload_len = (uint32_t)sizeof(pl);
    int rc = fw_tcp_send_frame(st, s, &d);
    CHECK_EQ_INT(rc, FW_ERR_WOULDBLOCK);
    CHECK(s->q_full_since_ms != 0); // 拒写已启动「持续满」计时
    fw_sleep_ms(80);                // > 2×20ms
    fw_tcp_tick(st, fw_now_ms());   // 直接驱动 tick，避免 poll 里的 flush 清空队列
    fw_sendq_stats_t q;
    fw_stats_sendq(st, &q);
    printf("  [INFO] BP-3 closed_full=%u nconn=%d\n", q.conn_closed_full, st->nconn);
    CHECK(q.conn_closed_full >= 1);
    CHECK_EQ_INT(st->nconn, 0); // 连接已被主动关闭
    fw_plat_close(c.fd);
    mini_stop(st);
  }
  TEST_END();

  TEST_BEGIN("BP-4 全栈预算分支：O(1) 增量计数触发、计数与遍历求和对账一致（两条真实连接）");
  {
    const uint16_t P = PORT + 6;
    fw_stack_t *st = mini_stack(P, 8);
    CHECK(st != NULL);
    // 单连接上限 8192；全栈预算同为 8192：第二条连接在自身积压远低于单连接上限时先撞预算
    st->cfg.max_send_queue_bytes = 8192;
    st->cfg.send_queue_budget_bytes = 8192;
    static uint8_t pl[2048];
    memset(pl, 0x55, sizeof(pl));
    raw_client_t c1, c2;
    CHECK_EQ_INT(raw_connect_to(&c1, P), 0);
    CHECK_EQ_INT(raw_connect_to(&c2, P), 0);
    for (int i = 0; i < 120 && st->nconn < 2; i++) { fw_stack_poll(st, 2); fw_sleep_ms(3); }
    CHECK_EQ_INT(st->nconn, 2);
    CHECK_EQ_INT(fw_int_sendq_consistent(st), 1); // 空队列：增量计数与遍历求和一致
    fw_tcpconn_t *a = st->conns[0];
    fw_tcpconn_t *b = st->conns[1];
    // 注入「部分发送后余量已入队」的等价积压：判定/记账/预算分支均为真实代码路径
    // （Windows SNDBUF 自适应无法用真实灌满稳定构造，同 BP-1 注释）
    a->sbuf = (uint8_t *)malloc(2048);
    CHECK(a->sbuf != NULL);
    memset(a->sbuf, 0x55, 2048);
    a->slen = 2048; a->ssent = 0; a->scap = 2048;
    st->sendq_bytes += 2048;
    CHECK_EQ_INT(fw_int_sendq_consistent(st), 1);
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ctr = 0; d.typ = FW_TYP_NON; d.code = 0x01; d.ver = 0;
    d.svc_id = 0xF00D; d.if_id = 1; d.inst_id = 1; d.strm_id = 1;
    d.payload = pl; d.payload_len = (uint32_t)sizeof(pl); // 帧总长 2058B
    // 第 1 帧到 a：单连接 2048+2058=4106<=8192；全栈 2048+2058=4106<=8192 → 受理
    CHECK_EQ_INT(fw_tcp_send_frame(st, a, &d), FW_OK);
    CHECK_EQ_INT(fw_int_sendq_consistent(st), 1);
    // b 注入 2048 积压：全栈 4106+2048=6154
    b->sbuf = (uint8_t *)malloc(2048);
    CHECK(b->sbuf != NULL);
    memset(b->sbuf, 0x55, 2048);
    b->slen = 2048; b->ssent = 0; b->scap = 2048;
    st->sendq_bytes += 2048;
    CHECK_EQ_INT(fw_int_sendq_consistent(st), 1);
    // 预算分支证据：b 自身水位远低于单连接上限，本帧也不触发单连接上限，
    // 唯一的拒写原因只能是全栈预算（6154+2058=8212>8192）
    size_t pend_b = b->slen - b->ssent;
    CHECK(pend_b + 2058 <= (size_t)st->cfg.max_send_queue_bytes);
    CHECK(st->sendq_bytes + 2058 > (size_t)st->cfg.send_queue_budget_bytes);
    CHECK_EQ_INT(fw_tcp_send_frame(st, b, &d), FW_ERR_WOULDBLOCK); // 预算拒写，未写入任何字节
    CHECK_EQ_INT(fw_int_sendq_consistent(st), 1); // 拒写不改记账
    CHECK_EQ_INT(fw_tcp_send_frame(st, b, &d), FW_ERR_WOULDBLOCK); // 再拒仍一致
    CHECK_EQ_INT(fw_int_sendq_consistent(st), 1);
    // 预算满时控制帧（8B RST，CTR=1）仍直写：不入队、不占预算、不改记账
    fw_frame_desc_t rst;
    fw_make_rst(&rst, 0x00, 1, 0xF00D, 1, 1, 0x2A);
    CHECK_EQ_INT(fw_tcp_send_frame(st, b, &rst), FW_OK);
    CHECK_EQ_INT(fw_int_sendq_consistent(st), 1);
    fw_sendq_stats_t q;
    fw_stats_sendq(st, &q);
    printf("  [INFO] BP-4 queued=%llu budget=%u rejects=%u pending_a=%llu pending_b=%llu consistent=%d\n",
           (unsigned long long)q.queued_bytes, st->cfg.send_queue_budget_bytes, q.rejects,
           (unsigned long long)(a->slen - a->ssent), (unsigned long long)pend_b,
           fw_int_sendq_consistent(st));
    CHECK_EQ_INT(q.queued_bytes, 6154); // 4106(a) + 2048(b)：增量计数与遍历求和同值
    CHECK(q.rejects > 0);
    fw_plat_close(c1.fd);
    fw_plat_close(c2.fd);
    mini_stop(st);
  }
  TEST_END();

  return 0;
}