// ============================================================
// strm.c —— §6 Stream / StrmID 管理：分配 / 冷却 / 回绕
//
// 空间划分（§6.1）：
//   0x00        连接级控制（REN/心跳/Offer/Find）
//   0x01~0x7F   客户端流（数据帧 Request/FF；控制帧 Subscribe 会话 + GetIDL 查询）
//   0x80~0xFE   服务端流（服务端主动 Notification）
//   0xFF        保留
//
// 隔离规则（§6.3）：
//   - 数据帧按 (peer, svc_id, inst_id) 隔离，client/server 各 127 个独立循环分配
//   - 控制帧（订阅会话 + GetIDL 查询）按 (peer) 统一分配池（§3.5：同键内活跃唯一）
//   - 冷却：距上次释放后本组合内已完整轮转分配过一轮（或 ≥2 次其它 StrmID 分配）
// ============================================================

#include "fw/fw.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 单个 StrmID 循环分配池（[low, high] 共 127 个编号）
typedef struct {
  uint8_t low, high;
  uint8_t active[128];       // 当前活跃标记
  int32_t release_seq[128];  // 释放时的全局分配序号（冷却判定；-1=从未释放）
  int32_t alloc_seq;         // 全局分配序号（每次成功分配 +1）
} fw_pool_t;

struct fw_strm_mgr {
  // 数据帧池：key = "peer|svc|inst"，client(0x01~0x7F)/server(0x80~0xFE) 独立
  struct { char key[160]; fw_pool_t client, server; } *data;
  int ndata, datacap;
  // 控制帧统一池（订阅会话 + GetIDL 查询）：key = peer（§3.5/§6.3）
  struct { char peer[80]; fw_pool_t pool; } *ctrl;
  int nctrl, ctrlcap;
};

static void pool_init(fw_pool_t *p, uint8_t low, uint8_t high) {
  memset(p, 0, sizeof(*p));
  p->low = low;
  p->high = high;
  for (int i = 0; i < 128; i++) p->release_seq[i] = -1;
}

// 分配一个空闲 StrmID：优先选"释放后已经过 ≥2 次其它分配"（已冷却）的编号（§6.3）
static int pool_alloc(fw_pool_t *p) {
  int size = p->high - p->low + 1;
  int fallback = -1;
  for (int i = 0; i < size; i++) {
    int id = p->low + i;
    if (p->active[id]) continue; // §6.3：目标 StrmID 仍活跃时跳过
    int32_t rel = p->release_seq[id];
    if (rel >= 0 && p->alloc_seq - rel >= 2) {
      // 已冷却（距释放后 ≥2 次其它分配）→ 优先选用
      p->active[id] = 1;
      p->alloc_seq++;
      return id;
    }
    if (fallback < 0) fallback = id;
  }
  if (fallback >= 0) {
    // 无冷却满足：退化为第一个非活跃编号（冷却为优先策略，非硬性拒绝）
    p->active[fallback] = 1;
    p->alloc_seq++;
    return fallback;
  }
  return -1; // 全部活跃
}

static void pool_release(fw_pool_t *p, int id) {
  if (id < p->low || id > p->high) return;
  if (p->active[id]) {
    p->active[id] = 0;
    p->release_seq[id] = p->alloc_seq; // 进入冷却：记录释放序号供冷却判定
  }
}

static void pool_reset(fw_pool_t *p) {
  for (int i = 0; i < 128; i++) p->active[i] = 0;
}

fw_strm_mgr_t *fw_strm_new(void) {
  return (fw_strm_mgr_t *)calloc(1, sizeof(fw_strm_mgr_t));
}

void fw_strm_free(fw_strm_mgr_t *m) {
  if (!m) return;
  free(m->data);
  free(m->ctrl);
  free(m);
}

static fw_pool_t *data_pool(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst, int server) {
  char key[160];
  snprintf(key, sizeof(key), "%s|%u|%u", peer, svc, inst);
  for (int i = 0; i < m->ndata; i++) {
    if (strcmp(m->data[i].key, key) == 0) return server ? &m->data[i].server : &m->data[i].client;
  }
  if (m->ndata == m->datacap) {
    int nc = m->datacap ? m->datacap * 2 : 8;
    void *np = realloc(m->data, (size_t)nc * sizeof(*m->data));
    if (!np) return NULL;
    m->data = np;
    m->datacap = nc;
  }
  memset(&m->data[m->ndata], 0, sizeof(m->data[m->ndata]));
  snprintf(m->data[m->ndata].key, sizeof(m->data[m->ndata].key), "%s", key);
  pool_init(&m->data[m->ndata].client, 0x01, 0x7F);   // 客户端流 127 个（§6.1）
  pool_init(&m->data[m->ndata].server, 0x80, 0xFE);   // 服务端流 127 个
  m->ndata++; // 登记（缺失将导致每次分配都重建池、active 状态丢失）
  return server ? &m->data[m->ndata - 1].server : &m->data[m->ndata - 1].client;
}

static fw_pool_t *ctrl_pool(fw_strm_mgr_t *m, const char *peer) {
  for (int i = 0; i < m->nctrl; i++) {
    if (strcmp(m->ctrl[i].peer, peer) == 0) return &m->ctrl[i].pool;
  }
  if (m->nctrl == m->ctrlcap) {
    int nc = m->ctrlcap ? m->ctrlcap * 2 : 8;
    void *np = realloc(m->ctrl, (size_t)nc * sizeof(*m->ctrl));
    if (!np) return NULL;
    m->ctrl = np;
    m->ctrlcap = nc;
  }
  memset(&m->ctrl[m->nctrl], 0, sizeof(m->ctrl[m->nctrl]));
  snprintf(m->ctrl[m->nctrl].peer, sizeof(m->ctrl[m->nctrl].peer), "%s", peer);
  pool_init(&m->ctrl[m->nctrl].pool, 0x01, 0x7F); // 会话/查询同池（§6.1/§6.3）
  m->nctrl++; // 登记（同 data_pool：缺失将导致每次分配都重建池）
  return &m->ctrl[m->nctrl - 1].pool;
}

int fw_strm_alloc_client(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst) {
  fw_pool_t *p = data_pool(m, peer, svc, inst, 0);
  return p ? pool_alloc(p) : -1;
}

int fw_strm_alloc_server(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst) {
  fw_pool_t *p = data_pool(m, peer, svc, inst, 1);
  return p ? pool_alloc(p) : -1;
}

int fw_strm_alloc_ctrl(fw_strm_mgr_t *m, const char *peer) {
  fw_pool_t *p = ctrl_pool(m, peer);
  return p ? pool_alloc(p) : -1;
}

void fw_strm_release_client(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst, int strm) {
  fw_pool_t *p = data_pool(m, peer, svc, inst, 0);
  if (p) pool_release(p, strm);
}

void fw_strm_release_server(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst, int strm) {
  fw_pool_t *p = data_pool(m, peer, svc, inst, 1);
  if (p) pool_release(p, strm);
}

void fw_strm_release_ctrl(fw_strm_mgr_t *m, const char *peer, int strm) {
  for (int i = 0; i < m->nctrl; i++) {
    if (strcmp(m->ctrl[i].peer, peer) == 0) {
      pool_release(&m->ctrl[i].pool, strm);
      return;
    }
  }
}

// 收到 REN=1：清除该对端（peer 前缀）全部序列并重置游标（§3.6/§6.3）
void fw_strm_reset_peer(fw_strm_mgr_t *m, const char *peer_prefix) {
  size_t pl = strlen(peer_prefix);
  for (int i = 0; i < m->ndata; i++) {
    if (strncmp(m->data[i].key, peer_prefix, pl) == 0) {
      pool_reset(&m->data[i].client);
      pool_reset(&m->data[i].server);
    }
  }
  for (int i = 0; i < m->nctrl; i++) {
    // ctrl 池键为 "ip:port"，REN 前缀为 "ip:" → 前缀匹配（§3.6 清该对端全部序列）
    if (strncmp(m->ctrl[i].peer, peer_prefix, pl) == 0) pool_reset(&m->ctrl[i].pool);
  }
}
