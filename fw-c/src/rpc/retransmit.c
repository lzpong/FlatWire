// ============================================================
// retransmit.c —— §5.5 CON/ACK 可靠性（仅 UDP）：重传时间线管理
//
// 时间线（interval=200ms, max_retry=3）：
//   首发由调用方完成（t=0）；重传 1@200ms、重传 2@600ms、重传 3@1400ms；
//   末次发送后等待 1600ms（t=3000ms）静默停止，不报错（§5.5 重传耗尽语义）。
// 重传使用同一 StrmID 与完全相同的字节（§5.5 发送方规则）。
// 数据帧（Request/FF/Notification CON）与控制帧（Subscribe 首次/取消）共用本表。
// ============================================================

#include "../fw_int.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void fw_retransmit_init(fw_retrans_table_t *t, uint32_t interval_ms, int max_retry) {
  memset(t, 0, sizeof(*t));
  t->interval_ms = interval_ms;
  t->max_retry = max_retry;
}

void fw_retransmit_free(fw_retrans_table_t *t) {
  for (int i = 0; i < t->n; i++) free(t->items[i].buf);
  free(t->items);
  memset(t, 0, sizeof(*t));
}

// 登记重传（首发已由调用方完成；next = now + interval，§5.5 退避公式）
void fw_retransmit_start(fw_retrans_table_t *t, const char *key, const uint8_t *buf, uint32_t len,
                         const char *addr, uint16_t port, int which, int64_t now) {
  fw_retransmit_cancel(t, key);
  if (t->n == t->cap) {
    int nc = t->cap ? t->cap * 2 : 8;
    void *np = realloc(t->items, (size_t)nc * sizeof(fw_retrans_t));
    if (!np) return;
    t->items = np;
    t->cap = nc;
  }
  fw_retrans_t *e = &t->items[t->n++];
  memset(e, 0, sizeof(*e));
  snprintf(e->key, sizeof(e->key), "%s", key);
  e->buf = (uint8_t *)malloc(len ? len : 1);
  if (!e->buf) { t->n--; return; }
  memcpy(e->buf, buf, len);
  e->len = len;
  e->retries = 0;
  e->next_ms = now + t->interval_ms; // 重传 1 时刻（首发 t=0 已完成）
  snprintf(e->addr, sizeof(e->addr), "%s", addr);
  e->port = port;
  e->which = which;
}

// 收到 ACK/响应：取消重传（§5.5）
void fw_retransmit_cancel(fw_retrans_table_t *t, const char *key) {
  for (int i = 0; i < t->n; i++) {
    if (strcmp(t->items[i].key, key) == 0) {
      free(t->items[i].buf);
      t->items[i] = t->items[t->n - 1];
      t->n--;
      return;
    }
  }
}

// 到期发送 / 耗尽清理（时间驱动，由 stack tick 调用）
void fw_retransmit_tick(fw_retrans_table_t *t, fw_stack_t *st, int64_t now) {
  for (int i = 0; i < t->n; ) {
    fw_retrans_t *e = &t->items[i];
    if (now < e->next_ms) { i++; continue; }
    if (e->retries < t->max_retry) {
      // 重传 1..max_retry：同一 StrmID 与完全相同的字节（§5.5）
      fw_udp_sendto_raw(st, e->addr, e->port, e->which, e->buf, e->len);
      e->retries++;
      e->next_ms = now + t->interval_ms * (1 << e->retries); // 退避：interval * 2^retry
      i++;
    } else {
      // 末次后等待 interval * 2^max_retry 到期：静默停止，清理待确认记录，不报错（§5.5）
      free(e->buf);
      t->items[i] = t->items[t->n - 1];
      t->n--;
    }
  }
}

// 收到 REN=1：清空该对端全部待确认重传记录（§3.6）
void fw_retransmit_clear_peer(fw_retrans_table_t *t, const char *peer_prefix) {
  for (int i = 0; i < t->n; ) {
    if (strncmp(t->items[i].key, peer_prefix, strlen(peer_prefix)) == 0) {
      free(t->items[i].buf);
      t->items[i] = t->items[t->n - 1];
      t->n--;
    } else {
      i++;
    }
  }
}
