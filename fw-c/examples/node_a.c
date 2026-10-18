// ============================================================
// node_a.c —— 示例服务端：注册 VehicleState 服务实例（实现计划 §5）
//
// 场景：
//   - 注册 svc_id=4096（规范 §11.1 VehicleState IDL）实例 inst_id=1
//   - 提供 rpc GetState / ff UpdateState + UploadBlob 的 handler
//   - 周期 notify StateChanged(32769) / PowerModeChanged(32770)
//   - 优雅退出（stop 发 REN×3 组播，§3.6）：--run-for <ms> 到期或 Ctrl+C
//
// 运行：fw_node_a [port] [bind]
//   port 默认 5400；bind 默认 127.0.0.1（同机演示）
// ============================================================

#include "fw/fw.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ---- 业务状态：演示用内存态 ----
static struct {
  unsigned veh_md, usg_md;
  int sys_pwr_md;
  char timestr[32];
  char status_msg[64];
  double ratio;
} g_state = {1, 2, 2, "2026-10-13T12:00:00Z", "all systems nominal", 0.618};

static fw_stack_t *g_stack = NULL;
static int g_run = 1;

static uint64_t now_unix_ms(void) { return (uint64_t)time(NULL) * 1000; }

// rpc：请求-响应（GetState if_id=1：无输入，返回 VehicleState 结构）
static int on_request(void *ud, uint16_t if_id, const fw_value_t *payload, fw_value_t **out) {
  (void)ud; (void)payload;
  if (if_id == 1) {
    printf("[NodeA] rpc GetState <- replying current state\n");
    fw_value_t *v = fw_value_struct();
    fw_struct_set(v, "veh_md", fw_value_uint(g_state.veh_md));
    fw_struct_set(v, "usg_md", fw_value_uint(g_state.usg_md));
    fw_struct_set(v, "sys_pwr_md", fw_value_int(g_state.sys_pwr_md));
    fw_struct_set(v, "timestamp", fw_value_uint(now_unix_ms()));
    fw_struct_set(v, "timestr", fw_value_string(g_state.timestr)); // fixed_len=20 恰 20 字节
    fw_struct_set(v, "status_msg", fw_value_string(g_state.status_msg));
    // diag_note optional 缺省 → null（§9.2）
    fw_struct_set(v, "ratio", fw_value_float(g_state.ratio));
    *out = v; // 响应所有权转移协议栈
    return FW_OK;
  }
  return 1; // 未预期接口 → RST(0x30)
}

// ff：无响应调用（UpdateState if_id=2 / UploadBlob if_id=3）
static void on_fire_forget(void *ud, uint16_t if_id, const fw_value_t *payload) {
  (void)ud;
  if (if_id == 2) {
    const fw_value_t *pwr = fw_struct_get(payload, "sys_pwr_md");
    const fw_value_t *msg = fw_struct_get(payload, "status_msg");
    if (pwr) g_state.sys_pwr_md = (int)pwr->as.i;
    if (msg) snprintf(g_state.status_msg, sizeof(g_state.status_msg), "%s", msg->as.s.ptr);
    printf("[NodeA] ff UpdateState: sys_pwr_md=%d status=\"%s\"\n", g_state.sys_pwr_md, g_state.status_msg);
    // 状态变更即推送（§8.2；diag_note 保持缺省 null）
    fw_value_t *ev = fw_value_struct();
    fw_struct_set(ev, "veh_md", fw_value_uint(g_state.veh_md));
    fw_struct_set(ev, "usg_md", fw_value_uint(g_state.usg_md));
    fw_struct_set(ev, "sys_pwr_md", fw_value_int(g_state.sys_pwr_md));
    fw_struct_set(ev, "timestamp", fw_value_uint(now_unix_ms()));
    fw_struct_set(ev, "timestr", fw_value_string(g_state.timestr));
    fw_struct_set(ev, "status_msg", fw_value_string(g_state.status_msg));
    fw_struct_set(ev, "ratio", fw_value_float(g_state.ratio));
    fw_notify(g_stack, 4096, 1, 32769, ev); // 事件 payload 按 output 方向编码（§11.1）
  } else if (if_id == 3) {
    const fw_value_t *vin = fw_struct_get(payload, "vin");
    const fw_value_t *pl = fw_struct_get(payload, "payload");
    printf("[NodeA] ff UploadBlob: payload=%uB\n", pl ? pl->as.by.len : 0);
    (void)vin;
  }
}

int main(int argc, char **argv) {
  unsigned port = argc > 1 ? (unsigned)atoi(argv[1]) : 5400;
  const char *bind = argc > 2 ? argv[2] : "127.0.0.1";

  // 读取 IDL（examples/vehicle-state.idl.json）
  char idl[16384];
  FILE *f = fopen("vehicle-state.idl.json", "rb");           // 运行目录
  if (!f) f = fopen("examples/vehicle-state.idl.json", "rb"); // 仓库根
  if (!f) f = fopen("../examples/vehicle-state.idl.json", "rb"); // build/ 目录
  if (!f) {
    fprintf(stderr, "[NodeA] cannot open vehicle-state.idl.json\n");
    return 1;
  }
  size_t n = fread(idl, 1, sizeof(idl) - 1, f);
  fclose(f);
  idl[n] = 0;

  fw_config_t cfg;
  fw_config_defaults(&cfg);
  cfg.port = (uint16_t)port;
  cfg.bind_address = bind;
  cfg.period_ms = 1000; // 演示加速（Offer/保活周期）
  cfg.ttl_ms = 2000;
  cfg.idl_dir = ".idl-a";
  cfg.log_level = FW_LOG_INFO;

  if (fw_stack_init(&g_stack, &cfg) != FW_OK) {
    fprintf(stderr, "[NodeA] stack init failed: %s\n", fw_stack_last_error(g_stack)->msg);
    return 1;
  }
  if (fw_stack_start(g_stack) != FW_OK) {
    fprintf(stderr, "[NodeA] stack start failed\n");
    return 1;
  }
  printf("[NodeA] stack started: port=%u bind=%s\n", port, bind);

  // 注册服务（§13.1：register_service）
  fw_handlers_t h;
  memset(&h, 0, sizeof(h));
  h.on_request = on_request;
  h.on_fire_forget = on_fire_forget;
  h.ud = NULL;
  if (fw_register_service(g_stack, 4096, 1, idl, &h) != FW_OK) {
    fprintf(stderr, "[NodeA] register failed: %s\n", fw_stack_last_error(g_stack)->msg);
    return 1;
  }
  printf("[NodeA] service 4096/1 registered (VehicleStateService) -> Offering\n");

  // 周期事件推送：StateChanged(32769) + PowerModeChanged(32770, enum=2 Run)
  int seq = 0;
  int64_t last_push = fw_now_ms();
  while (g_run) {
    fw_stack_poll(g_stack, 50);
    if (fw_now_ms() - last_push >= 2000) {
      last_push = fw_now_ms();
      g_state.ratio = (seq % 10) * 0.1;
      // StateChanged（output=VehicleState）
      fw_value_t *ev = fw_value_struct();
      fw_struct_set(ev, "veh_md", fw_value_uint(g_state.veh_md));
      fw_struct_set(ev, "usg_md", fw_value_uint(g_state.usg_md));
      fw_struct_set(ev, "sys_pwr_md", fw_value_int(g_state.sys_pwr_md));
      fw_struct_set(ev, "timestamp", fw_value_uint(now_unix_ms()));
      fw_struct_set(ev, "timestr", fw_value_string(g_state.timestr));
      fw_struct_set(ev, "status_msg", fw_value_string(g_state.status_msg));
      fw_struct_set(ev, "ratio", fw_value_float(g_state.ratio));
      fw_notify(g_stack, 4096, 1, 32769, ev);
      // PowerModeChanged（output=PowerMode；enum 线格式 = 底层整型，§11.1）
      fw_notify(g_stack, 4096, 1, 32770, fw_value_uint(2));
      seq++;
    }
  }
  // 优雅退出：stop 发 REN×3 组播后释放资源（§3.6）
  printf("[NodeA] stopping -> sending REN x3 ...\n");
  fw_stack_stop(g_stack);
  fw_stack_free(g_stack);
  printf("[NodeA] stopped\n");
  return 0;
}