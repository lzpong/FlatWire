// ============================================================
// node_b.c —— 示例客户端：发现 → 调用 → 订阅（实现计划 §5 场景）
//
// 验证点（输出带 [VERIFY-n] 标记，冒烟脚本检查）：
//   1. 服务发现：is_available(4096,1) → true（组播 Offer 建立发现缓存）
//   2. GetIDL 自动拉取落盘：本地 IDL 库为空 → 调用触发协议栈内部 GetIDL
//      （§7.2/5.21）→ 库内出现 4096_v1.json（重启后本地命中不重复拉取，5.28）
//   3. rpc call 往返：GetState 返回 VehicleState 结构
//   4. fire_forget：UpdateState / UploadBlob 到达（TCP 全 NON 无确认）
//   5. 订阅确认链路 + 事件推送：Subscribe(CON) → ACK(0x10) → 交付推送
//
// 运行：fw_node_b [port] [bind]
//   port 默认 5400；bind 默认 127.0.0.2（同机演示时与 NodeA 区分）
// ============================================================

#include "fw/fw.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static fw_stack_t *g_stack = NULL;
static int g_pushes = 0;
static char g_last_push[512] = "";

// 客户端事件回调（payload 所有权转移给回调，用完 fw_value_free）
static void on_event(void *ud, uint16_t svc_id, uint16_t if_id, fw_value_t *payload) {
  (void)ud; (void)svc_id; (void)if_id;
  g_pushes++;
  // VehicleState 结构字段提取
  const fw_value_t *pwr = fw_struct_get(payload, "sys_pwr_md");
  const fw_value_t *msg = fw_struct_get(payload, "status_msg");
  const fw_value_t *ratio = fw_struct_get(payload, "ratio");
  snprintf(g_last_push, sizeof(g_last_push),
           "push #%d: sys_pwr_md=%lld status=\"%s\" ratio=%.3f",
           g_pushes,
           pwr ? (long long)pwr->as.i : -1,
           msg ? msg->as.s.ptr : "?",
           ratio ? ratio->as.f : 0.0);
  printf("[VERIFY-5] event %s\n", g_last_push);
  fw_value_free(payload);
}

static int wait_avail(fw_stack_t *st, uint16_t svc, uint8_t inst, int timeout_ms) {
  int64_t deadline = fw_now_ms() + timeout_ms;
  while (fw_now_ms() < deadline) {
    fw_stack_poll(st, 50);
    if (fw_is_available(st, svc, inst)) return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  unsigned port = argc > 1 ? (unsigned)atoi(argv[1]) : 5400;
  const char *bind = argc > 2 ? argv[2] : "127.0.0.2";

  fw_config_t cfg;
  fw_config_defaults(&cfg);
  cfg.port = (uint16_t)port;
  cfg.bind_address = bind;
  cfg.period_ms = 1000;
  cfg.ttl_ms = 2000;
  cfg.idl_dir = ".idl-b"; // 空 IDL 库起步（纯动态架构 §11.1 客户端按需拉取）
  cfg.tcp_enabled = 0;    // 客户端角色不监听 TCP（GetIDL/rpc 走出站连接）
  cfg.log_level = FW_LOG_INFO;

  if (fw_stack_init(&g_stack, &cfg) != FW_OK) return 1;
  if (fw_stack_start(g_stack) != FW_OK) return 1;
  printf("[NodeB] stack started: port=%u bind=%s idl_dir=%s\n", port, bind, cfg.idl_dir);

  // 1. 服务发现（§7.4 客户端状态机：启动即发 Find 预热 + 组播 Offer 周期刷新）
  if (!wait_avail(g_stack, 4096, 1, 15000)) {
    fprintf(stderr, "[NodeB] timeout waiting service 4096/1\n");
    return 1;
  }
  printf("[VERIFY-1] discovery: svc 4096/1 available = true\n");

  // 2+3. rpc call：本地无 IDL → 协议栈自动 GetIDL（TCP 单播）→ 落盘 → 编解码（§7.2）
  fw_value_t *resp = NULL;
  if (fw_call(g_stack, 4096, 1, 1, NULL, 0, &resp) != FW_OK) {
    fprintf(stderr, "[NodeB] call failed: %s\n", fw_stack_last_error(g_stack)->msg);
    return 1;
  }
  if (resp) {
    const fw_value_t *pwr = fw_struct_get(resp, "sys_pwr_md");
    const fw_value_t *msg = fw_struct_get(resp, "status_msg");
    const fw_value_t *ratio = fw_struct_get(resp, "ratio");
    printf("[VERIFY-3] rpc GetState -> sys_pwr_md=%lld status=\"%s\" ratio=%.3f\n",
           pwr ? (long long)pwr->as.i : -1,
           msg ? msg->as.s.ptr : "?",
           ratio ? ratio->as.f : 0.0);
    fw_value_free(resp);
  }
  // GetIDL 落盘持久化（5.28：库文件出现 4096_v1.json）
  {
    FILE *f = fopen(".idl-b/4096_v1.json", "rb");
    printf("[VERIFY-2] GetIDL persisted: %s\n", f ? "true (.idl-b/4096_v1.json)" : "false");
    if (!f) {
      fprintf(stderr, "[NodeB] GetIDL not persisted!\n");
      return 1;
    }
    fclose(f);
  }

  // 4. fire_forget（TCP 全 NON，无传输确认，§5.2）
  fw_value_t *st1 = fw_value_struct();
  fw_struct_set(st1, "veh_md", fw_value_uint(1));
  fw_struct_set(st1, "usg_md", fw_value_uint(2));
  fw_struct_set(st1, "sys_pwr_md", fw_value_int(3));
  fw_struct_set(st1, "timestamp", fw_value_uint(0));
  fw_struct_set(st1, "timestr", fw_value_string("2026-10-13T12:30:00Z"));
  fw_struct_set(st1, "status_msg", fw_value_string("updated by NodeB"));
  fw_struct_set(st1, "diag_note", fw_value_string("demo")); // optional 有值
  fw_struct_set(st1, "ratio", fw_value_float(0.717));
  if (fw_fire_forget(g_stack, 4096, 1, 2, st1) != FW_OK) {
    fprintf(stderr, "[NodeB] fire_forget UpdateState failed: %s\n", fw_stack_last_error(g_stack)->msg);
    return 1;
  }
  // UploadBlob（Blob：vin bytes fixed_len=17 / payload bytes max_len=64000）
  fw_value_t *blob = fw_value_struct();
  fw_struct_set(blob, "vin", fw_value_bytes((const uint8_t *)"LFV3A23C8K3123456", 17));
  fw_struct_set(blob, "payload", fw_value_bytes((const uint8_t *)"\x01\x02\x03\x04\x05", 5));
  if (fw_fire_forget(g_stack, 4096, 1, 3, blob) != FW_OK) {
    fprintf(stderr, "[NodeB] fire_forget UploadBlob failed: %s\n", fw_stack_last_error(g_stack)->msg);
    return 1;
  }
  printf("[VERIFY-4] fire_forget UpdateState/UploadBlob sent (tcp)\n");

  // 5. 订阅：Subscribe(CON) → ACK(0x10) 确认 → 事件推送交付（§8.1）
  uint32_t handle = fw_subscribe(g_stack, 4096, 1, 32769, 0, on_event, NULL);
  if (!handle) {
    fprintf(stderr, "[NodeB] subscribe failed\n");
    return 1;
  }
  printf("[NodeB] subscribed (handle=%u), waiting pushes ...\n", handle);
  // 等待至少 2 次推送（全量推送 + 实时推送）
  int64_t deadline = fw_now_ms() + 20000;
  while (g_pushes < 2 && fw_now_ms() < deadline)
    fw_stack_poll(g_stack, 50);
  if (g_pushes < 1) {
    fprintf(stderr, "[NodeB] no event push received\n");
    return 1;
  }

  // 取消订阅（§13.2 unsubscribe → Subscribe(TTL=0)）
  fw_unsubscribe(g_stack, handle);
  printf("[NodeB] done: %d push(es) received, unsubscribed, stopping ...\n", g_pushes);
  fw_stack_stop(g_stack);
  fw_stack_free(g_stack);
  printf("[NodeB] stopped\n");
  return 0;
}