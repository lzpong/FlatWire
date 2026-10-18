// ============================================================
// t_retrans.c —— 测试基准 3.10/3.11/3.12：重传时间线（注入时钟；
//                发送经未启动栈的无效 socket 静默丢弃，观测条目状态推进）
// ============================================================

#include "test_util.h"
#include "../src/fw_int.h"

static int64_t g_now = 1000;

static int64_t fake_clock(void) { return g_now; }

// 构造最小栈（未 start：socket 无效 → 发送静默失败，不产生网络流量）
static fw_stack_t *stub_stack(void) {
  fw_stack_t *st = (fw_stack_t *)calloc(1, sizeof(fw_stack_t));
  st->udp_main = FW_FD_INVALID;
  st->udp_client = FW_FD_INVALID;
  st->clock_override = fake_clock;
  st->cfg.retransmit_interval_ms = 200;
  st->cfg.retransmit_max = 3;
  return st;
}

int suite_retrans(void) {
  TEST_BEGIN("3.10/3.11/3.12 重传时间线 0/200/600/1400ms + 3000ms 静默停止");
  {
  fw_stack_t *st = stub_stack();
  fw_retrans_table_t t;
  fw_retransmit_init(&t, 200, 3);
  uint8_t buf[4] = {1, 2, 3, 4};
  // 首发 t=0 由调用方完成（此处仅登记，next = t+200）
  fw_retransmit_start(&t, "k", buf, 4, "1.1.1.1", 5400, 0, g_now);
  CHECK_EQ_INT(t.n, 1);
  CHECK_EQ_INT(t.items[0].retries, 0);
  // 199ms：无动作
  g_now = 1000 + 199;
  fw_retransmit_tick(&t, st, g_now);
  CHECK_EQ_INT(t.items[0].retries, 0);
  // 重传 1 @200ms
  g_now = 1000 + 200;
  fw_retransmit_tick(&t, st, g_now);
  CHECK_EQ_INT(t.items[0].retries, 1);
  // 重传 2 @600ms（退避：200→+400）
  g_now = 1000 + 599;
  fw_retransmit_tick(&t, st, g_now);
  CHECK_EQ_INT(t.items[0].retries, 1);
  g_now = 1000 + 600;
  fw_retransmit_tick(&t, st, g_now);
  CHECK_EQ_INT(t.items[0].retries, 2);
  // 重传 3（末次）@1400ms（退避：+800）
  g_now = 1000 + 1399;
  fw_retransmit_tick(&t, st, g_now);
  CHECK_EQ_INT(t.items[0].retries, 2);
  g_now = 1000 + 1400;
  fw_retransmit_tick(&t, st, g_now);
  CHECK_EQ_INT(t.items[0].retries, 3);
  CHECK_EQ_INT(t.n, 1);
  // 3000ms：末次后等待 1600ms → 静默停止，条目删除不报错（§5.5 重传耗尽语义）
  g_now = 1000 + 2999;
  fw_retransmit_tick(&t, st, g_now);
  CHECK_EQ_INT(t.n, 1);
  g_now = 1000 + 3000;
  fw_retransmit_tick(&t, st, g_now);
  CHECK_EQ_INT(t.n, 0);
  fw_retransmit_free(&t);
  free(st);
  }
  TEST_END();

  TEST_BEGIN("3.7 重传取消：ACK 到达即停");
  {
  fw_stack_t *st = stub_stack();
  fw_retrans_table_t t;
  fw_retransmit_init(&t, 200, 3);
  uint8_t buf[4] = {1};
  fw_retransmit_start(&t, "k", buf, 1, "1.1.1.1", 5400, 0, g_now);
  fw_retransmit_cancel(&t, "k");
  CHECK_EQ_INT(t.n, 0);
  g_now += 10000;
  fw_retransmit_tick(&t, st, g_now); // 无崩溃、无动作
  CHECK_EQ_INT(t.n, 0);
  fw_retransmit_free(&t);
  free(st);
  }
  TEST_END();

  TEST_BEGIN("4.5 REN 清空该对端重传记录（§3.6）");
  {
  fw_stack_t *st = stub_stack();
  fw_retrans_table_t t;
  fw_retransmit_init(&t, 200, 3);
  uint8_t buf[4] = {1};
  fw_retransmit_start(&t, "1.1.1.1:5400|1|1|1", buf, 1, "1.1.1.1", 5400, 0, g_now);
  fw_retransmit_start(&t, "2.2.2.2:5400|1|1|1", buf, 1, "2.2.2.2", 5400, 0, g_now);
  CHECK_EQ_INT(t.n, 2);
  fw_retransmit_clear_peer(&t, "1.1.1.1:");
  CHECK_EQ_INT(t.n, 1); // 仅该对端被清，其他节点不受影响（4.4）
  fw_retransmit_free(&t);
  free(st);
  }
  TEST_END();

  return 0;
}