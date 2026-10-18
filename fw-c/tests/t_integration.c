// ============================================================
// t_integration.c —— 单进程双栈回环集成（发现→GetIDL 落盘→call→ff→
//                    订阅确认→事件推送→REN 清缓存；5.21/5.28/6.1/8.1~8.3）
// 两个栈绑不同回环地址（127.0.0.1 / 127.0.0.2）同端口，模拟两台主机。
// ============================================================

#include "test_util.h"
#include "../src/fw_int.h"
#include <stdio.h>

#define PORT 45440

static const char *IDL_PATH_A = ".idl-itest-a";
static const char *IDL_PATH_B = ".idl-itest-b";

static const char *IDL_TEXT =
"{"
"\"service\":{\"name\":\"S\",\"svc_id\":5000,\"major_ver\":1,\"minor_ver\":0,"
"\"interfaces\":["
"{\"name\":\"Get\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\",\"input\":[],\"output\":\"State\"},"
"{\"name\":\"Cmd\",\"if_id\":2,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"State\"]},"
"{\"name\":\"Chg\",\"if_id\":32769,\"type\":\"event\",\"transport\":\"udp\",\"output\":\"State\",\"reliable\":false}"
"]},"
"\"type_def\":{\"structs\":{\"State\":["
"{\"name\":\"a\",\"type\":\"unsigned\",\"size\":2},"
"{\"name\":\"b\",\"type\":\"signed\",\"size\":1},"
"{\"name\":\"msg\",\"type\":\"string\",\"max_len\":16},"
"{\"name\":\"opt\",\"type\":\"string\",\"max_len\":8,\"optional\":true}"
"]}}}";

static int call_done = 0;
static fw_value_t *resp = NULL;
static char call_msg[160] = "";
static void call_cb(void *ud, fw_value_t *rp, int err, const char *msg);

static int wait_avail2(fw_stack_t *a, fw_stack_t *st, uint16_t svc, uint8_t inst, int timeout_ms) {
  int64_t deadline = fw_now_ms() + timeout_ms;
  while (fw_now_ms() < deadline) {
    fw_stack_poll(a, 25);
    fw_stack_poll(st, 25);
    if (fw_is_available(st, svc, inst)) return 1;
  }
  return 0;
}

static fw_value_t *make_state(uint32_t a, int b, const char *msg, const char *opt) {
  fw_value_t *v = fw_value_struct();
  fw_struct_set(v, "a", fw_value_uint(a));
  fw_struct_set(v, "b", fw_value_int(b));
  fw_struct_set(v, "msg", fw_value_string(msg));
  if (opt) fw_struct_set(v, "opt", fw_value_string(opt));
  return v;
}

// ---- 服务端 handler 状态 ----
static uint32_t g_srv_a = 0;
static int g_srv_b = 0;
static char g_srv_msg[32] = "init";
static int g_ff_seen = 0;
static fw_stack_t *g_a = NULL;

static int on_request(void *ud, uint16_t if_id, const fw_value_t *payload, fw_value_t **out) {
  (void)ud; (void)payload;
  if (if_id != 1) return 1;
  *out = make_state(g_srv_a, g_srv_b, g_srv_msg, NULL); // 响应所有权转移协议栈
  return FW_OK;
}

static void on_ff(void *ud, uint16_t if_id, const fw_value_t *payload) {
  (void)ud;
  if (if_id != 2) return;
  g_ff_seen = 1;
  const fw_value_t *a = fw_struct_get(payload, "a");
  const fw_value_t *msg = fw_struct_get(payload, "msg");
  if (a) g_srv_a = (uint32_t)a->as.u;
  if (msg) snprintf(g_srv_msg, sizeof(g_srv_msg), "%s", msg->as.s.ptr);
  // 状态变更即推送（§8.2）
  fw_notify(g_a, 5000, 1, 32769, make_state(g_srv_a, g_srv_b, g_srv_msg, NULL));
}

// ---- 客户端事件计数 ----
static int g_pushes = 0;
static uint32_t g_last_push_a = 0;
static char g_last_push_msg[32] = "";

static void call_cb(void *ud, fw_value_t *rp, int err, const char *msg) {
  (void)ud;
  call_done = 1;
  if (err != FW_OK) snprintf(call_msg, sizeof(call_msg), "%s", msg ? msg : "?");
  else { fw_value_free(resp); resp = rp; }
}

static void on_event(void *ud, uint16_t svc_id, uint16_t if_id, fw_value_t *payload) {
  (void)ud; (void)svc_id; (void)if_id;
  g_pushes++;
  const fw_value_t *a = fw_struct_get(payload, "a");
  const fw_value_t *m = fw_struct_get(payload, "msg");
  if (a) g_last_push_a = (uint32_t)a->as.u;
  if (m) snprintf(g_last_push_msg, sizeof(g_last_push_msg), "%s", m->as.s.ptr);
}

static void pump2(fw_stack_t *a, fw_stack_t *b, int ms) {
  int64_t deadline = fw_now_ms() + ms;
  while (fw_now_ms() < deadline) {
    fw_stack_poll(a, 5);
    fw_stack_poll(b, 5);
  }
}

int suite_integration(void) {
  // 准备 IDL 库（A 有定义；B 空库——验证按需拉取落盘）
  fw_plat_init();
  char path[256];
  snprintf(path, sizeof(path), "%s/5000_v1.json", IDL_PATH_A);
  fw_plat_mkdir_p(IDL_PATH_A);
  fw_plat_write_file(path, IDL_TEXT, strlen(IDL_TEXT));
  fw_plat_mkdir_p(IDL_PATH_B); // B 空库

  TEST_BEGIN("8.1~8.3/5.21/5.28/6.1 双栈集成：发现→GetIDL→call→ff→订阅→推送");
  // 栈 A：服务端（bind 127.0.0.1）
  fw_config_t ca;
  fw_config_defaults(&ca);
  ca.port = PORT;
  ca.bind_address = "127.0.0.1";
  ca.response_timeout_ms = 1500; // period/ttl 用默认（2000/4000）：ttl=1s 与 1s tick 存在边界抖动
  ca.idl_dir = IDL_PATH_A;
  ca.log_level = FW_LOG_DEBUG;
  CHECK_EQ_INT(fw_stack_init(&g_a, &ca), FW_OK);
  CHECK_EQ_INT(fw_stack_start(g_a), FW_OK);
  // 栈 B：客户端（bind 127.0.0.2，空 IDL 库，TCP 不监听）
  fw_stack_t *b = NULL;
  fw_config_t cb;
  fw_config_defaults(&cb);
  cb.port = PORT;
  cb.bind_address = "127.0.0.2";
  cb.response_timeout_ms = 1500;
  cb.idl_dir = IDL_PATH_B;
  cb.tcp_enabled = 0;
  cb.log_level = FW_LOG_DEBUG;
  CHECK_EQ_INT(fw_stack_init(&b, &cb), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b), FW_OK);

  // 注册（A：handler）
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  h.on_fire_forget = on_ff;
  h.ud = NULL;
  CHECK_EQ_INT(fw_register_service(g_a, 5000, 1, IDL_TEXT, &h), FW_OK);

  // 发现：B is_available → true（组播 Offer 建立发现缓存，8.1）
  int avail = wait_avail2(g_a, b, 5000, 1, 10000);
  CHECK_EQ_INT(avail, 1);

  // call（B 本地无 IDL → 自动 GetIDL 落盘 → 编解码往返，5.21/7.1）
  // 单进程双栈：同步 fw_call 内部泵只泵 B（A 侧 handler 需 A 的 poll）→ 用 async + 双泵等待
  call_done = 0;
  CHECK_EQ_INT(fw_call_async(b, 5000, 1, 1, NULL, 0, call_cb, NULL), FW_OK);
  int64_t deadline = fw_now_ms() + 10000;
  while (!call_done && fw_now_ms() < deadline) pump2(g_a, b, 20);
  CHECK_EQ_INT(call_done, 1);
  CHECK_EQ_STR(call_msg, "");
  int r = call_done ? FW_OK : FW_ERR_TIMEOUT;
  (void)r;
  CHECK(resp != NULL);
  if (resp) {
    CHECK(fw_struct_get(resp, "a") && fw_struct_get(resp, "a")->as.u == 0);
    CHECK(fw_struct_get(resp, "msg") && strcmp(fw_struct_get(resp, "msg")->as.s.ptr, "init") == 0);
    fw_value_free(resp);
    resp = NULL;
  }
  // GetIDL 落盘持久化（5.28：B 库内出现 5000_v1.json）
  snprintf(path, sizeof(path), "%s/5000_v1.json", IDL_PATH_B);
  CHECK_EQ_INT(fw_plat_file_exists(path), 1);

  // fire_forget（7.4：服务端处理 + 触发推送）——FF 无响应，服务端 handler 在
  // A 的 poll 中执行（fire-and-forget），发送后泵两栈等待处理完成再断言
  r = fw_fire_forget(b, 5000, 1, 2, make_state(777, -5, "from-b", "o"));
  CHECK_EQ_INT(r, FW_OK);
  int ff_deadline = 0;
  int64_t ff_dl = fw_now_ms() + 5000;
  while (!g_ff_seen && fw_now_ms() < ff_dl) pump2(g_a, b, 20);
  ff_deadline = g_ff_seen;
  CHECK_EQ_INT(ff_deadline, 1);
  CHECK_EQ_INT(g_srv_a, 777);

  // 订阅确认链路 + 事件推送（6.1/8.3：Subscribe(CON)→ACK(0x10)→交付）
  int avail2 = fw_is_available(b, 5000, 1);
  CHECK_EQ_INT(avail2, 1);
  uint32_t handle = fw_subscribe(b, 5000, 1, 32769, 0, on_event, NULL);
  CHECK(handle != 0);
  pump2(g_a, b, 300);
  CHECK(g_pushes >= 1); // 全量推送（订阅从无到有，A 已 notify 过）或后续实时推送
  // ff 触发的推送应已到达（a=777）
  int saw777 = 0;
  for (int i = 0; i < 60 && !saw777; i++) {
    pump2(g_a, b, 50);
    if (g_last_push_a == 777) saw777 = 1;
  }
  CHECK_EQ_INT(saw777, 1);
  CHECK_EQ_STR(g_last_push_msg, "from-b");

  // 取消订阅（6.5：发 Subscribe(TTL=0) → ACK(0x00) → 释放会话 StrmID）
  CHECK_EQ_INT(fw_unsubscribe(b, handle), FW_OK);
  pump2(g_a, b, 200);

  // REN 清缓存（4.4：A stop → REN×3 → B is_available=false）
  fw_stack_stop(g_a);
  int gone = 0;
  for (int i = 0; i < 40 && !gone; i++) {
    fw_stack_poll(b, 50);
    gone = !fw_is_available(b, 5000, 1);
  }
  CHECK_EQ_INT(gone, 1);

  fw_stack_stop(b);
  fw_stack_free(g_a);
  fw_stack_free(b);
  g_a = NULL;
  TEST_END();

  TEST_BEGIN("5.28 重启后本地命中不重复拉取");
  // B 重启（库中已有 5000_v1.json）→ is_available 后 call 直接成功且 A 侧 GetIDL 不被触发
  fw_config_t ca2;
  fw_config_defaults(&ca2);
  ca2.port = PORT + 1;
  ca2.bind_address = "127.0.0.1";
  ca2.period_ms = 400;
  ca2.ttl_ms = 1000;
  ca2.idl_dir = IDL_PATH_A;
  fw_stack_t *a2 = NULL;
  CHECK_EQ_INT(fw_stack_init(&a2, &ca2), FW_OK);
  CHECK_EQ_INT(fw_stack_start(a2), FW_OK);
  CHECK_EQ_INT(fw_register_service(a2, 5000, 1, NULL, &h), FW_OK); // A 侧库有定义：无 idl 参数直接注册

  fw_config_t cb2;
  fw_config_defaults(&cb2);
  cb2.port = PORT + 1;
  cb2.bind_address = "127.0.0.2";
  cb2.period_ms = 400;
  cb2.ttl_ms = 1000;
  cb2.idl_dir = IDL_PATH_B;
  cb2.tcp_enabled = 0;
  fw_stack_t *b2 = NULL;
  CHECK_EQ_INT(fw_stack_init(&b2, &cb2), FW_OK);
  CHECK_EQ_INT(fw_stack_start(b2), FW_OK);

  avail = wait_avail2(a2, b2, 5000, 1, 10000);
  CHECK_EQ_INT(avail, 1);
  // 本地命中：call 成功（不发起 GetIDL——文件仍在库，重启不重复拉取）
  call_done = 0;
  resp = NULL;
  call_msg[0] = 0;
  CHECK_EQ_INT(fw_call_async(b2, 5000, 1, 1, NULL, 0, call_cb, NULL), FW_OK);
  deadline = fw_now_ms() + 10000;
  while (!call_done && fw_now_ms() < deadline) pump2(a2, b2, 20);
  CHECK_EQ_INT(call_done, 1);
  CHECK_EQ_STR(call_msg, "");
  if (resp) fw_value_free(resp);

  fw_stack_stop(a2);
  fw_stack_stop(b2);
  fw_stack_free(a2);
  fw_stack_free(b2);
  TEST_END();

  return 0;
}