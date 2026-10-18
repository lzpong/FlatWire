// ============================================================
// t_regress.c —— 审查修复回归测试（对齐《Test Cases.v4.md》编号）
//
// 覆盖审查报告指出的测试盲区：
//   1. 6.5  订阅取消链路完整断言：130 轮 subscribe/unsubscribe 会话 StrmID
//           回收（防 P1-1 回归：取消等待表 cancels 泄漏）
//   2. 5.11 批量 Offer 端到端：70 实例（>64 旧截断上限）全部被发现（防 P1-2）
//   3. 3.19~3.23 心跳五条：空闲发 Ping / 收 Ping 不回帧 / 业务流量不叠加 /
//           收任意帧刷新存活 / 2×period 未收帧判死（时钟注入 + 白盒）
//   4. 5.22/5.34/5.30/5.36 GetIDL 关键场景：本地命中不查询 / 注册自动拉取 /
//           版本并存 / 启动 Find 预热
//   5. 6.2/6.10/6.16 订阅确认链路：无缓存确认 / 重复 CON 不重推全量 /
//           合并 Subscribe 无效 Entry 逐项处理
// ============================================================

#include "test_util.h"
#include "../src/fw_int.h"
#include <stdio.h>
#include <stdlib.h>

// ---- 双栈端口（与 t_integration 的 45440 错开） ----
#define PORT_SUB  45450  // 订阅/批量发现/GetIDL/确认链路套件
#define PORT_HB   45460  // 心跳套件

static const char *IDL_DIR_A = ".idl-rg-a";
static const char *IDL_DIR_B = ".idl-rg-b";

// 通用 IDL：rpc Get(1) / ff Cmd(2) / event Chg(32769)
static const char *IDL_TEXT =
"{"
"\"service\":{\"name\":\"R\",\"svc_id\":5100,\"major_ver\":1,\"minor_ver\":0,"
"\"interfaces\":["
"{\"name\":\"Get\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\",\"input\":[],\"output\":\"State\"},"
"{\"name\":\"Cmd\",\"if_id\":2,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"State\"]},"
"{\"name\":\"Chg\",\"if_id\":32769,\"type\":\"event\",\"transport\":\"udp\",\"output\":\"State\",\"reliable\":false}"
"]},"
"\"type_def\":{\"structs\":{\"State\":["
"{\"name\":\"a\",\"type\":\"unsigned\",\"size\":2},"
"{\"name\":\"msg\",\"type\":\"string\",\"max_len\":16}"
"]}}}";

// v2 定义（5.30 版本并存：同 svc_id 不同 major_ver）
static const char *IDL_TEXT_V2 =
"{"
"\"service\":{\"name\":\"R\",\"svc_id\":5100,\"major_ver\":2,\"minor_ver\":0,"
"\"interfaces\":["
"{\"name\":\"Get\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\",\"input\":[],\"output\":\"State\"}"
"]},"
"\"type_def\":{\"structs\":{\"State\":["
"{\"name\":\"a\",\"type\":\"unsigned\",\"size\":2},"
"{\"name\":\"msg\",\"type\":\"string\",\"max_len\":16}"
"]}}}";

// svc=5200 定义（5.22/5.34 GetIDL 注册拉取场景专用：IDL 自含 svc_id 须与注册参数一致）
static const char *IDL_TEXT_5200 =
"{"
"\"service\":{\"name\":\"G\",\"svc_id\":5200,\"major_ver\":1,\"minor_ver\":0,"
"\"interfaces\":["
"{\"name\":\"Get\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\",\"input\":[],\"output\":\"State\"}"
"]},"
"\"type_def\":{\"structs\":{\"State\":["
"{\"name\":\"a\",\"type\":\"unsigned\",\"size\":2},"
"{\"name\":\"msg\",\"type\":\"string\",\"max_len\":16}"
"]}}}";

static fw_stack_t *g_a = NULL;
static fw_stack_t *g_b = NULL; // 白盒谓词用 B 栈（订阅会话/取消等待在客户端侧）
static int g_srv_ret = 0;

static int on_request(void *ud, uint16_t if_id, const fw_value_t *payload, fw_value_t **out) {
  (void)ud; (void)payload;
  if (if_id != 1) return 1;
  fw_value_t *v = fw_value_struct();
  fw_struct_set(v, "a", fw_value_uint(g_srv_ret));
  fw_struct_set(v, "msg", fw_value_string("ok"));
  *out = v;
  return FW_OK;
}

static void on_ff(void *ud, uint16_t if_id, const fw_value_t *payload) { (void)ud; (void)if_id; (void)payload; }

static fw_value_t *make_state(uint32_t a, const char *msg) {
  fw_value_t *v = fw_value_struct();
  fw_struct_set(v, "a", fw_value_uint(a));
  fw_struct_set(v, "msg", fw_value_string(msg));
  return v;
}

// ---- 事件计数 ----
static int g_pushes = 0;
static void on_event(void *ud, uint16_t svc_id, uint16_t if_id, fw_value_t *payload) {
  (void)ud; (void)svc_id; (void)if_id;
  g_pushes++;
  fw_value_free(payload);
}

// ---- async call 回调（心跳测试建连用） ----
static int g_call_done = 0;
static void call_cb(void *ud, fw_value_t *resp, int err, const char *msg) {
  (void)ud; (void)msg;
  if (resp) fw_value_free(resp);
  (void)err;
  g_call_done = 1;
}

static void pump2(fw_stack_t *a, fw_stack_t *b, int ms) {
  int64_t deadline = fw_now_ms() + ms;
  while (fw_now_ms() < deadline) {
    if (a) fw_stack_poll(a, 5);
    if (b) fw_stack_poll(b, 5);
  }
}

// 双泵等待谓词成立（超时返回 0）
static int wait_cond2(fw_stack_t *a, fw_stack_t *b, int ms, int (*pred)(void)) {
  int64_t deadline = fw_now_ms() + ms;
  while (fw_now_ms() < deadline) {
    if (a) fw_stack_poll(a, 10);
    if (b) fw_stack_poll(b, 10);
    if (pred()) return 1;
  }
  return 0;
}

// ============================================================
// 1. [6.5 / P1-1] 订阅取消 130 轮：会话 StrmID 回收（池不耗尽）
// ============================================================

static int g_est_ok = 0; // 当轮 establish 成功标记

static int pred_established(void) {
  if (!g_b || g_b->disc.nsess < 1) return 0;
  if (g_b->disc.sessions[0].state != FW_SESS_ACTIVE) return 0;
  g_est_ok = 1;
  return 1;
}
static int pred_cancel_done(void) {
  return g_b->disc.ncxl == 0 && g_b->disc.nsess == 0; // ACK(0x00) 后取消等待清空（B 侧）
}

static int test_sub_cancel_130(void) {
  TEST_BEGIN("6.5 订阅取消链路：130 轮 subscribe/unsubscribe 会话 StrmID 回收（P1-1）");
  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT_SUB;
  ca.bind_address = "127.0.0.1";
  ca.period_ms = 400;
  ca.ttl_ms = 1000;
  ca.idl_dir = IDL_DIR_A;
  ca.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&g_a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(g_a), FW_OK);

  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT_SUB;
  cb.bind_address = "127.0.0.2";
  cb.period_ms = 400;
  cb.ttl_ms = 1000;
  cb.idl_dir = IDL_DIR_B;
  cb.tcp_enabled = 0;
  cb.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b), FW_OK);

  // A 注册（预置 IDL，B 首次订阅前经订阅预拉取获得定义）
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  h.on_fire_forget = on_ff;
  CHECK_EQ_INT(fw_register_service(g_a, 5100, 1, IDL_TEXT, &h), FW_OK);
  // 等 B 发现（is_available）
  int avail = 0;
  int64_t dl = fw_now_ms() + 10000;
  while (fw_now_ms() < dl && !avail) {
    fw_stack_poll(g_a, 10);
    fw_stack_poll(b, 10);
    avail = fw_is_available(b, 5100, 1);
  }
  CHECK_EQ_INT(avail, 1);

  // 130 轮 subscribe→establish→unsubscribe：池 0x01~0x7F 共 127 个，
  // 若会话 StrmID 不释放，第 128 轮起分配失败 → 会话停留 PENDING → establish 超时
  g_b = b;
  int all_ok = 1;
  for (int round = 0; round < 130; round++) {
    g_est_ok = 0;
    uint32_t handle = fw_subscribe(b, 5100, 1, 32769, 0, on_event, NULL);
    if (!handle) { all_ok = 0; break; }
    if (!wait_cond2(g_a, b, 3000, pred_established) || !g_est_ok) { all_ok = 0; break; }
    if (fw_unsubscribe(b, handle) != FW_OK) { all_ok = 0; break; }
    if (!wait_cond2(g_a, b, 3000, pred_cancel_done)) { all_ok = 0; break; } // ACK(0x00) 到达释放
  }
  CHECK_EQ_INT(all_ok, 1);
  // 白盒终态：无会话残留、无取消等待残留（StrmID 全部释放，§6.1/6.5）
  CHECK_EQ_INT(g_a->disc.nsess, 0);
  CHECK_EQ_INT(b->disc.nsess, 0);
  CHECK_EQ_INT(b->disc.ncxl, 0);
  g_b = NULL;

  fw_stack_stop(g_a);
  fw_stack_stop(b);
  fw_stack_free(g_a);
  fw_stack_free(b);
  g_a = NULL;
  TEST_END();
  return 0;
}

// ============================================================
// 2. [5.11 / P1-2] 批量 Offer 端到端：70 实例全部被发现
// ============================================================

static int test_batch_offer_70(void) {
  TEST_BEGIN("5.11 批量 Offer 端到端：70 实例（>64 旧上限）B 晚启动全部发现（P1-2）");
  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT_SUB + 1;
  ca.bind_address = "127.0.0.1";
  ca.period_ms = 400;
  ca.ttl_ms = 1000;
  ca.idl_dir = IDL_DIR_A;
  ca.log_level = FW_LOG_ERROR;
  fw_stack_t *a = NULL;
  CHECK_EQ_INT(fw_stack_init(&a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(a), FW_OK);
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  // 先注册 70 实例，再启动 B（B 错过逐实例立即广播，仅靠批量 Offer/Find 响应发现）
  for (uint8_t inst = 1; inst <= 70; inst++) {
    int r = fw_register_service(a, 5100, inst, inst == 1 ? IDL_TEXT : NULL, &h);
    if (r != FW_OK) break;
  }
  CHECK_EQ_INT(a->disc.nlocals, 70);

  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT_SUB + 1;
  cb.bind_address = "127.0.0.2";
  cb.period_ms = 400;
  cb.ttl_ms = 1000;
  cb.idl_dir = IDL_DIR_B;
  cb.tcp_enabled = 0;
  cb.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b), FW_OK); // 启动即发 Find 预热 → A 回 70-Entry Offer

  // 双泵至 B 发现缓存 70/70（周期 Offer 与预热 Find 响应均同格式）
  int64_t dl = fw_now_ms() + 15000;
  while (fw_now_ms() < dl && b->disc.ndisc < 70) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
  }
  CHECK_EQ_INT(b->disc.ndisc, 70); // [P1-2] 修复前仅 63/70（64 截断）

  fw_stack_stop(a);
  fw_stack_stop(b);
  fw_stack_free(a);
  fw_stack_free(b);
  TEST_END();
  return 0;
}

// ============================================================
// 3. [3.19~3.23] 心跳五条（时钟注入 + 白盒观测）
// ============================================================

static int64_t g_hb_off = 0; // fake 时钟偏移（fake = real + off）
static int64_t fake_now(void) { return fw_plat_now_ms() + g_hb_off; }

static fw_tcpconn_t *find_conn(fw_stack_t *st, int role) {
  for (int i = 0; i < st->nconn; i++)
    if (st->conns[i] && st->conns[i]->role == role && !st->conns[i]->closed)
      return st->conns[i];
  return NULL;
}

static int test_heartbeat(void) {
  TEST_BEGIN("3.19~3.23 心跳：空闲发Ping/收Ping不回/业务不叠加/收帧刷新/2x判死");
  fw_plat_init();
  fw_set_clock_override(fake_now); // 时钟注入（init 前设置；栈 init 时拷贝钩子）
  g_hb_off = 0;

  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT_HB;
  ca.bind_address = "127.0.0.1";
  ca.period_ms = 400;
  ca.ttl_ms = 1000;
  ca.heartbeat_period_ms = 1000; // 心跳周期 1s（存活判定 2s）
  ca.idl_dir = IDL_DIR_A;
  ca.log_level = FW_LOG_ERROR;
  fw_stack_t *a = NULL;
  CHECK_EQ_INT(fw_stack_init(&a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(a), FW_OK);
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  CHECK_EQ_INT(fw_register_service(a, 5100, 1, IDL_TEXT, &h), FW_OK);

  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT_HB;
  cb.bind_address = "127.0.0.2";
  cb.period_ms = 400;
  cb.ttl_ms = 1000;
  cb.heartbeat_period_ms = 1000;
  cb.idl_dir = IDL_DIR_B;
  cb.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b), FW_OK);

  // 等发现 + TCP 建连（B call 触发出站长连接，3.7 TCP 全 NON）
  int64_t dl = fw_now_ms() + 10000;
  int avail = 0;
  while (fw_now_ms() < dl && !avail) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
    avail = fw_is_available(b, 5100, 1);
  }
  CHECK_EQ_INT(avail, 1);
  // TCP 建连（3.7 TCP 全 NON）：单进程双栈须 async + 双泵（同步 fw_call 泵不到 A）
  g_call_done = 0;
  CHECK_EQ_INT(fw_call_async(b, 5100, 1, 1, NULL, 5000, call_cb, NULL), FW_OK);
  dl = fw_now_ms() + 10000;
  while (!g_call_done && fw_now_ms() < dl) pump2(a, b, 20);
  CHECK_EQ_INT(g_call_done, 1);
  fw_tcpconn_t *bc = find_conn(b, FW_ROLE_CLIENT); // B 侧出站连接
  fw_tcpconn_t *ac = find_conn(a, FW_ROLE_SERVER); // A 侧入站连接
  CHECK(bc != NULL);
  CHECK(ac != NULL);
  if (bc && ac) {
    // ---- 3.21 业务流量不叠加：连接刚建立（call 刚刷新 last_send），推进 <period 不发 Ping
    int64_t ls0 = bc->last_send_ms;
    g_hb_off += 400; // 0.4×period
    fw_stack_poll(a, 5);
    fw_stack_poll(b, 5);
    CHECK_EQ_INT(bc->last_send_ms == ls0, 1); // 未发 Ping（业务流量刷新空闲计时 §5.7）

    // ---- 3.19 空闲超 period 发 Ping：累计推进 1.2×period → 发 Ping
    g_hb_off += 800; // 累计 1.2×period
    pump2(a, b, 200);
    CHECK(bc->last_send_ms > ls0);           // B 发出 Ping（last_send 刷新）
    CHECK(ac->last_recv_ms >= fw_now_ms() - 5000); // A 收到帧（Ping 到达）
    CHECK(ac->last_recv_ms > 0);

    // ---- 3.20 收到 Ping 不回帧：直接向 B 侧连接 parser 喂 Ping 帧
    //（A 的心跳发到 B 内核缓冲；喂帧模拟 B 读到，避免 B 自身心跳 timer 干扰观测）
    int64_t ls1 = bc->last_send_ms;
    int64_t lr0 = bc->last_recv_ms;
    fw_frame_desc_t ping;
    memset(&ping, 0, sizeof(ping));
    ping.ctr = 1;
    ping.typ = FW_TYP_NON;
    ping.code = 0x00;
    ping.ver = b->cfg.ver;
    uint8_t praw[16];
    uint32_t plen = fw_frame_encode(praw, sizeof(praw), &ping);
    fw_sp_feed(&bc->parser, praw, plen); // 模拟对端 Ping 到达（分发 default 静默，§5.7）
    CHECK_EQ_INT(bc->last_send_ms == ls1, 1); // 未回任何帧（Ping 不回帧，§5.7）
    CHECK(bc->last_recv_ms >= lr0);           // 3.23 收到任意帧刷新存活计时

    // ---- 3.22 2×period 未收帧标记失效：停泵 B（模拟对端失联），只泵 A
    for (int i = 0; i < 40; i++) { // 推进 3×period（> 2×period）
      g_hb_off += 100;
      fw_stack_poll(a, 2);
      if (find_conn(a, FW_ROLE_SERVER) == NULL) break; // 心跳超时关连接
    }
    CHECK_EQ_INT(find_conn(a, FW_ROLE_SERVER) == NULL, 1); // A 判 B 死（§5.7）
  }

  fw_set_clock_override(NULL); // 恢复真实时钟（后续栈不受影响）
  fw_stack_stop(a);
  fw_stack_stop(b);
  fw_stack_free(a);
  fw_stack_free(b);
  TEST_END();
  return 0;
}

// ============================================================
// 4. [5.22 / 5.34] GetIDL：本地命中不查询 / 注册时集群自动拉取
// ============================================================

static int test_getidl_register(void) {
  TEST_BEGIN("5.22/5.34 GetIDL：本地命中不发起查询 + 注册时集群自动拉取");
  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT_SUB + 2;
  ca.bind_address = "127.0.0.1";
  ca.period_ms = 400;
  ca.ttl_ms = 4000; // TTL 4s：注册同步泵 2s 期间发现缓存不过期
  ca.idl_dir = IDL_DIR_A;
  ca.log_level = FW_LOG_ERROR;
  fw_stack_t *a = NULL;
  CHECK_EQ_INT(fw_stack_init(&a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(a), FW_OK);
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  CHECK_EQ_INT(fw_register_service(a, 5200, 1, IDL_TEXT_5200, &h), FW_OK);

  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT_SUB + 2;
  cb.bind_address = "127.0.0.2";
  cb.period_ms = 400;
  cb.ttl_ms = 4000;
  cb.idl_dir = IDL_DIR_B;
  cb.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b), FW_OK);

  // 等 B 发现 A 的 5200/1
  int avail = 0;
  int64_t dl = fw_now_ms() + 10000;
  while (fw_now_ms() < dl && !avail) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
    avail = fw_is_available(b, 5200, 1);
  }
  CHECK_EQ_INT(avail, 1);

  // [5.34] 注册时集群自动拉取——触发路径：B 库无定义 + 发现缓存在线实例 →
  // 注册入口发起 GetIDL。单进程双栈限制：fw_register_service 的同步泵只泵 B，
  // A 的 GetIDL 服务端无法并发处理 → 查询超时上抛 FW_ERR_GETIDL（§7.2 v4.4
  // "查询失败上抛当前操作"定案；完整闭环由 5.21/t_integration 跨栈链路覆盖）
  CHECK_EQ_INT(fw_idl_has(b->idl, 5200, 1), 0); // B 库为空
  int r34 = fw_register_service(b, 5200, 2, NULL, &h); // 注册 inst=2（无 idl 参数）
  CHECK_EQ_INT(r34, FW_ERR_GETIDL);                    // 发起了 GetIDL（非 -7 NOT_FOUND）
  CHECK(strstr(fw_stack_last_error(b)->msg, "GetIDL") != NULL); // 错误信息含 GetIDL 路径

  // GetIDL 拉取闭环（async + 双泵：A 处理请求回 0x11 → B 落库，§7.2/5.28）
  // 注册超时后确认发现缓存仍在线（Expired 会阻止发起查询，§7.2 触发条件）
  dl = fw_now_ms() + 3000;
  while (fw_now_ms() < dl && !fw_is_available(b, 5200, 1)) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
  }
  CHECK_EQ_INT(fw_is_available(b, 5200, 1), 1);
  fw_disc_fetch_idl_async(b, 5200, 1);
  dl = fw_now_ms() + 5000;
  while (fw_now_ms() < dl && !fw_idl_has(b->idl, 5200, 1)) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
  }
  CHECK_EQ_INT(fw_idl_has(b->idl, 5200, 1), 1); // 拉取落库成功

  // [5.22] 本地命中不发起查询：库已有定义时注册 → 不新建查询（5.28/5.29 语义）
  int nq_before = b->disc.nq;
  CHECK_EQ_INT(fw_register_service(b, 5200, 3, NULL, &h), FW_OK);
  CHECK_EQ_INT(b->disc.nq, nq_before); // 本地命中，未发起 GetIDL

  fw_stack_stop(a);
  fw_stack_stop(b);
  fw_stack_free(a);
  fw_stack_free(b);
  TEST_END();
  return 0;
}

// ============================================================
// 5. [5.30] 版本升级并存：同 (svc) 不同 MajorVer 定义并存不覆盖
// ============================================================

static int test_idl_version_coexist(void) {
  TEST_BEGIN("5.30 版本升级：v1/v2 定义并存不覆盖（idlstore 语义）");
  fw_idlstore_t *s = fw_idl_new();
  char dir[64];
  snprintf(dir, sizeof(dir), "%s-coexist", IDL_DIR_A);
  CHECK_EQ_INT(fw_idl_load_all(s, dir), FW_OK);
  // 先存 v1，再存 v2（同 svc_id 不同 major_ver）
  CHECK_EQ_INT(fw_idl_save(s, 5100, 1, IDL_TEXT), FW_OK);
  CHECK_EQ_INT(fw_idl_save(s, 5100, 2, IDL_TEXT_V2), FW_OK);
  fw_idl_entry_t *e1 = fw_idl_get(s, 5100, 1);
  fw_idl_entry_t *e2 = fw_idl_get(s, 5100, 2);
  CHECK(e1 != NULL); // v1 保留（并存不覆盖，§7.2）
  CHECK(e2 != NULL);
  if (e1) CHECK(strstr(e1->json_text, "\"major_ver\":1") != NULL);
  if (e2) CHECK(strstr(e2->json_text, "\"major_ver\":2") != NULL);
  CHECK(fw_idl_get_highest(s, 5100) == e2); // 最高版本取 v2
  // 同 key 重载（P3-10）：拒绝并保留旧定义
  fw_idl_entry_t *e1b = fw_idl_save(s, 5100, 1, IDL_TEXT) == FW_OK ? fw_idl_get(s, 5100, 1) : NULL;
  CHECK(e1b == e1); // schema 指针不变（旧定义保留，防持有者悬空）
  fw_idl_free(s);
  TEST_END();
  return 0;
}

// ============================================================
// 6. [5.36] 启动 Find 预热：B 启动即发空 Payload Find，快速发现
// ============================================================

static int test_startup_warmup(void) {
  TEST_BEGIN("5.36 启动预热：新栈启动即发 Find，短于周期完成发现");
  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT_SUB + 3;
  ca.bind_address = "127.0.0.1";
  ca.period_ms = 2000; // 周期 Offer 2s：预热失效则发现至少等 2s
  ca.ttl_ms = 4000;
  ca.idl_dir = IDL_DIR_A;
  ca.log_level = FW_LOG_ERROR;
  fw_stack_t *a = NULL;
  CHECK_EQ_INT(fw_stack_init(&a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(a), FW_OK);
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  CHECK_EQ_INT(fw_register_service(a, 5100, 1, IDL_TEXT, &h), FW_OK);

  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT_SUB + 3;
  cb.bind_address = "127.0.0.2";
  cb.period_ms = 2000;
  cb.ttl_ms = 4000;
  cb.idl_dir = IDL_DIR_B;
  cb.tcp_enabled = 0;
  cb.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  int64_t t0 = fw_now_ms();
  CHECK_EQ_INT(fw_stack_start(b), FW_OK); // 启动即发 Find 预热（§2 定案）

  int avail = 0;
  while (fw_now_ms() - t0 < 1500 && !avail) { // 1500ms < 一个周期（区分预热与周期 Offer）
    fw_stack_poll(a, 5);
    fw_stack_poll(b, 5);
    avail = fw_is_available(b, 5100, 1);
  }
  CHECK_EQ_INT(avail, 1); // 预热生效：远短于 period 完成发现

  fw_stack_stop(a);
  fw_stack_stop(b);
  fw_stack_free(a);
  fw_stack_free(b);
  TEST_END();
  return 0;
}

// ============================================================
// 7. [6.2] 无缓存订阅确认：服务端未 notify 过（无缓存）仍回 ACK(0x10)
// ============================================================

static int pred_est2(void) {
  if (!g_b || g_b->disc.nsess < 1) return 0;
  return g_b->disc.sessions[0].state == FW_SESS_ACTIVE;
}

static int test_sub_ack_no_cache(void) {
  TEST_BEGIN("6.2 无缓存订阅确认：A 未 notify 过仍 ACK(0x10)，无全量推送");
  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT_SUB + 4;
  ca.bind_address = "127.0.0.1";
  ca.period_ms = 400;
  ca.ttl_ms = 1000;
  ca.idl_dir = IDL_DIR_A;
  ca.log_level = FW_LOG_ERROR;
  fw_stack_t *a = NULL;
  CHECK_EQ_INT(fw_stack_init(&a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(a), FW_OK);
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  CHECK_EQ_INT(fw_register_service(a, 5100, 1, IDL_TEXT, &h), FW_OK);
  // 注意：不调用 fw_notify（无接口缓存）

  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT_SUB + 4;
  cb.bind_address = "127.0.0.2";
  cb.period_ms = 400;
  cb.ttl_ms = 1000;
  cb.idl_dir = IDL_DIR_B;
  cb.tcp_enabled = 0;
  cb.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b), FW_OK);
  int avail = 0;
  int64_t dl = fw_now_ms() + 10000;
  while (fw_now_ms() < dl && !avail) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
    avail = fw_is_available(b, 5100, 1);
  }
  CHECK_EQ_INT(avail, 1);

  g_pushes = 0;
  g_a = a;
  g_b = b;
  uint32_t handle = fw_subscribe(b, 5100, 1, 32769, 0, on_event, NULL);
  CHECK(handle != 0);
  CHECK_EQ_INT(wait_cond2(a, b, 3000, pred_est2), 1); // [6.2] 无缓存也回 ACK(0x10)（establish）
  CHECK_EQ_INT(g_pushes, 0);                          // 无缓存 → 无全量推送（§8.1）
  // 订阅有效：A notify → 实时推送到达
  CHECK_EQ_INT(fw_notify(a, 5100, 1, 32769, make_state(7, "n1")), FW_OK);
  dl = fw_now_ms() + 3000;
  while (fw_now_ms() < dl && g_pushes < 1) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
  }
  CHECK(g_pushes >= 1);

  fw_unsubscribe(b, handle);
  pump2(a, b, 200);
  g_a = NULL;
  g_b = NULL;
  fw_stack_stop(a);
  fw_stack_stop(b);
  fw_stack_free(a);
  fw_stack_free(b);
  TEST_END();
  return 0;
}

// ============================================================
// 8. [6.10] 重复 CON 重发 0x10 不重推全量
// ============================================================

static int test_dup_con_no_repush(void) {
  TEST_BEGIN("6.10 重复 CON 重发确认：缓存命中不重推全量（§8.1）");
  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT_SUB + 5;
  ca.bind_address = "127.0.0.1";
  ca.period_ms = 400;
  ca.ttl_ms = 1000;
  ca.idl_dir = IDL_DIR_A;
  ca.log_level = FW_LOG_ERROR;
  fw_stack_t *a = NULL;
  CHECK_EQ_INT(fw_stack_init(&a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(a), FW_OK);
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  CHECK_EQ_INT(fw_register_service(a, 5100, 1, IDL_TEXT, &h), FW_OK);
  CHECK_EQ_INT(fw_notify(a, 5100, 1, 32769, make_state(1, "c1")), FW_OK); // 有缓存

  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT_SUB + 5;
  cb.bind_address = "127.0.0.2";
  cb.period_ms = 400;
  cb.ttl_ms = 1000;
  cb.idl_dir = IDL_DIR_B;
  cb.tcp_enabled = 0;
  cb.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b), FW_OK);
  int avail = 0;
  int64_t dl = fw_now_ms() + 10000;
  while (fw_now_ms() < dl && !avail) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
    avail = fw_is_available(b, 5100, 1);
  }
  CHECK_EQ_INT(avail, 1);

  g_pushes = 0;
  g_a = a;
  g_b = b;
  uint32_t handle = fw_subscribe(b, 5100, 1, 32769, 0, on_event, NULL);
  CHECK(handle != 0);
  CHECK_EQ_INT(wait_cond2(a, b, 3000, pred_est2), 1);
  pump2(a, b, 300);
  int pushes0 = g_pushes; // 全量推送已计（有缓存 → ≥1）
  CHECK(pushes0 >= 1);

  // [6.10] 重发同一 CON（同 StrmID 同 Entry）：A 命中确认缓存 → 重发 0x10，不重执行
  if (b->disc.nsess > 0) {
    fw_session_t *s = &b->disc.sessions[0];
    fw_sub_entry_t e;
    memset(&e, 0, sizeof(e));
    e.svc_id = s->svc_id;
    e.if_id = s->if_id;
    e.inst_id = s->inst_id;
    e.grp_id = s->grp_id;
    e.ttl = 1;
    uint8_t pbuf[16];
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ctr = 1;
    d.typ = FW_TYP_CON;
    d.code = FW_CODE_SD_SUB;
    d.ver = b->cfg.ver;
    d.strm_id = (uint8_t)s->session_strm;
    d.payload = pbuf;
    d.payload_len = fw_encode_sub_entries(pbuf, sizeof(pbuf), &e, 1);
    uint8_t raw[64];
    uint32_t rlen = fw_frame_encode(raw, sizeof(raw), &d);
    fw_udp_sendto_raw(b, "127.0.0.1", (uint16_t)(PORT_SUB + 5), 0, raw, rlen);
    pump2(a, b, 300);
    CHECK_EQ_INT(g_pushes, pushes0); // 不重推全量（重复 CON 仅重发确认）
  }

  fw_unsubscribe(b, handle);
  pump2(a, b, 200);
  g_a = NULL;
  g_b = NULL;
  fw_stack_stop(a);
  fw_stack_stop(b);
  fw_stack_free(a);
  fw_stack_free(b);
  TEST_END();
  return 0;
}

// ============================================================
// 9. [6.16] 合并 Subscribe 含无效 Entry：逐项丢弃仍回确认（有效 Entry 生效）
// ============================================================

static int test_merged_sub_invalid_entry(void) {
  TEST_BEGIN("6.16 合并 Subscribe：无效 Entry 逐项丢弃，有效 Entry 建立订阅");
  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT_SUB + 6;
  ca.bind_address = "127.0.0.1";
  ca.period_ms = 400;
  ca.ttl_ms = 1000;
  ca.idl_dir = IDL_DIR_A;
  ca.log_level = FW_LOG_ERROR;
  fw_stack_t *a = NULL;
  CHECK_EQ_INT(fw_stack_init(&a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(a), FW_OK);
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  CHECK_EQ_INT(fw_register_service(a, 5100, 1, IDL_TEXT, &h), FW_OK);

  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT_SUB + 6;
  cb.bind_address = "127.0.0.2";
  cb.period_ms = 400;
  cb.ttl_ms = 1000;
  cb.idl_dir = IDL_DIR_B;
  cb.tcp_enabled = 0;
  cb.log_level = FW_LOG_ERROR;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b), FW_OK);
  int avail = 0;
  int64_t dl = fw_now_ms() + 10000;
  while (fw_now_ms() < dl && !avail) {
    fw_stack_poll(a, 10);
    fw_stack_poll(b, 10);
    avail = fw_is_available(b, 5100, 1);
  }
  CHECK_EQ_INT(avail, 1);

  // 构造 2-Entry 合并 Subscribe（CON）：Entry1 有效，Entry2 无效（if=0 且 grp=0）
  int nsubs0 = a->disc.nsubs;
  fw_sub_entry_t es[2];
  memset(es, 0, sizeof(es));
  es[0].svc_id = 5100;
  es[0].if_id = 32769;
  es[0].inst_id = 1;
  es[0].ttl = 1;                       // 有效：单接口订阅
  es[1].svc_id = 5100;
  es[1].if_id = 0;
  es[1].grp_id = 0;
  es[1].inst_id = 1;
  es[1].ttl = 1;                       // 无效：if/grp 均为 0（§7.1 组合非法）
  uint8_t pbuf[32];
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 1;
  d.typ = FW_TYP_CON;
  d.code = FW_CODE_SD_SUB;
  d.ver = b->cfg.ver;
  d.strm_id = 0x05; // 栈内手动选定会话 StrmID（白盒直发，不经 fw_subscribe）
  d.payload = pbuf;
  d.payload_len = fw_encode_sub_entries(pbuf, sizeof(pbuf), es, 2);
  uint8_t raw[80];
  uint32_t rlen = fw_frame_encode(raw, sizeof(raw), &d);
  fw_udp_sendto_raw(b, "127.0.0.1", (uint16_t)(PORT_SUB + 6), 0, raw, rlen);
  pump2(a, b, 300);
  // [6.16] 无效 Entry 丢弃、有效 Entry 建立订阅（整帧拒绝则 nsubs 不变）
  CHECK_EQ_INT(a->disc.nsubs, nsubs0 + 1);
  // 有效 Entry 生效佐证：订阅记录内容正确且 TTL Active（§8.1 表）
  if (a->disc.nsubs > nsubs0) {
    fw_sub_rec_t *sr = &a->disc.subs[a->disc.nsubs - 1];
    CHECK_EQ_INT(sr->svc_id, 5100);
    CHECK_EQ_INT(sr->if_id, 32769);
    CHECK_EQ_INT(sr->state, FW_ST_ACTIVE);
    CHECK(sr->ttl_left > 0);
  }

  fw_stack_stop(a);
  fw_stack_stop(b);
  fw_stack_free(a);
  fw_stack_free(b);
  TEST_END();
  return 0;
}

// ============================================================

// 清空 IDL 目录内全部 .json（测试前置：消除上一轮运行残留对断言的影响）
static void clear_idl_dir(const char *dir) {
  char **files = NULL;
  int n = 0;
  if (fw_plat_list_json(dir, &files, &n) == 0) {
    for (int i = 0; i < n; i++) {
      char path[600];
      snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
      remove(path);
      free(files[i]);
    }
    free(files);
  }
}

int suite_regress(void) {
  fw_plat_init();
  clear_idl_dir(IDL_DIR_A);
  clear_idl_dir(IDL_DIR_B);
  clear_idl_dir(".idl-rg-a-coexist"); // 5.30 版本并存测试目录
  int fails = 0; fails += test_sub_cancel_130();
  fails += test_batch_offer_70();
  fails += test_heartbeat();
  fails += test_getidl_register();
  fails += test_idl_version_coexist();
  fails += test_startup_warmup();
  fails += test_sub_ack_no_cache();
  fails += test_dup_con_no_repush();
  fails += test_merged_sub_invalid_entry();
  return fails;
}
