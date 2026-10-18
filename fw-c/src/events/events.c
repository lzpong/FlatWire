// ============================================================
// events.c —— §8 事件推送（Notifier）/ §5.3 Notification 传输语义
//
// 服务端：notify（更新接口缓存 + 分发）/ 全量推送（订阅从无到有，§8.1）/
//         tcp-event 按订阅者源 IP 匹配连接推送（§8.2）/ CON 推送重传
// 客户端：onNotification 交付（UDP CON 回 ACK + 接收记录去重，§8.2）/
//         订阅会话匹配（单接口 + 组订阅展开，§7.1）
// ============================================================

#include "../fw_int.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 接收记录保留时长：≥ 重传窗口（3s）+ 单向延迟余量（§8.2）
#define RECV_RECORD_TTL_MS 4000

static int64_t now_ms(fw_stack_t *st) {
  return st->clock_override ? st->clock_override() : fw_now_ms();
}

void fw_events_init(fw_stack_t *st) {
  memset(&st->ev, 0, sizeof(st->ev));
  fw_retransmit_init(&st->ev.retrans, st->cfg.retransmit_interval_ms, st->cfg.retransmit_max);
}

void fw_events_free(fw_stack_t *st) {
  fw_retransmit_free(&st->ev.retrans);
  for (int i = 0; i < st->ev.nnc; i++) free(st->ev.ncache[i].buf);
  free(st->ev.ncache);
  free(st->ev.push);
  free(st->ev.recv);
  memset(&st->ev, 0, sizeof(st->ev));
}

void fw_events_stop(fw_stack_t *st) {
  fw_retransmit_free(&st->ev.retrans);
  fw_retransmit_init(&st->ev.retrans, st->cfg.retransmit_interval_ms, st->cfg.retransmit_max);
  st->ev.npush = 0;
  st->ev.nrecv = 0;
}

// ============================================================
// 服务端（§13.1 notify）
// ============================================================

// 向单个订阅者推送一帧 Notification（§5.3/§8.2）：
//   tcp-event：按源 IP 匹配活跃连接（TYP=NON）；断连期间推送暂停不补发，重连自动恢复
//   UDP reliable：TYP=CON（重传保证送达）｜UDP 常规：TYP=NON（尽力而为）
static void push_to_one(fw_stack_t *st, const fw_sub_rec_t *sub, uint16_t svc_id,
                        uint8_t inst_id, fw_iface_t *iface, const uint8_t *buf, uint32_t len) {
  char peer[80];
  snprintf(peer, sizeof(peer), "%s:%u", sub->peer_ip, sub->peer_port);
  // 每客户端独立 StrmID（§8.2）
  int strm = fw_strm_alloc_server(st->strm, peer, svc_id, inst_id);
  if (strm < 0) {
    fw_log(FW_LOG_ERROR, "events", "server StrmID pool exhausted for %s, push skipped", peer);
    return;
  }
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 0;
  d.code = FW_CODE_NOTIFY;
  d.ver = st->cfg.ver;
  d.svc_id = svc_id;
  d.if_id = iface->if_id;
  d.inst_id = inst_id;
  d.strm_id = (uint8_t)strm;
  d.payload = buf;
  d.payload_len = len;

  if (iface->transport == FW_TR_TCP) {
    fw_tcpconn_t *c = fw_tcp_find_server_by_ip(st, sub->peer_ip);
    if (!c) {
      // 断连期间推送暂停（订阅记录保留，重连后自动恢复，§8.2/§12.3）
      fw_strm_release_server(st->strm, peer, svc_id, inst_id, strm);
      fw_log(FW_LOG_WARN, "events", "tcp-event push paused (no connection from %s)", sub->peer_ip);
      return;
    }
    fw_tcp_send_frame(st, c, &d); // TYP=NON（TCP 全 NON，§5.3）
    fw_strm_release_server(st->strm, peer, svc_id, inst_id, strm); // TCP 自带可靠性，发完即释放
    return;
  }
  if (iface->reliable) {
    // UDP 可靠事件：TYP=CON，客户端回 ACK，超时重传（§5.3/§5.5）
    uint8_t raw[1700];
    uint32_t rlen = fw_frame_encode(raw, sizeof(raw), &d);
    if (!rlen) { fw_strm_release_server(st->strm, peer, svc_id, inst_id, strm); return; }
    char key[224];
    snprintf(key, sizeof(key), "%s|%u|%u|%d", peer, svc_id, inst_id, strm);
    if (st->ev.npush == st->ev.pushcap) {
      int nc = st->ev.pushcap ? st->ev.pushcap * 2 : 8;
      void *np = realloc(st->ev.push, (size_t)nc * sizeof(fw_push_pending_t));
      if (!np) { fw_strm_release_server(st->strm, peer, svc_id, inst_id, strm); return; }
      st->ev.push = np;
      st->ev.pushcap = nc;
    }
    fw_push_pending_t *p = &st->ev.push[st->ev.npush++];
    memset(p, 0, sizeof(*p));
    snprintf(p->key, sizeof(p->key), "%s", key);
    snprintf(p->peer, sizeof(p->peer), "%s", peer);
    p->svc_id = svc_id;
    p->inst_id = inst_id;
    p->strm = strm;
    snprintf(p->addr, sizeof(p->addr), "%s", sub->peer_ip);
    p->port = sub->peer_port;
    fw_udp_sendto_raw(st, sub->peer_ip, sub->peer_port, 1, raw, rlen);
    fw_retransmit_start(&st->ev.retrans, key, raw, rlen, sub->peer_ip, sub->peer_port, 1, now_ms(st));
    // 重传耗尽兜底释放（ACK 到达时提前释放）
    p->deadline = now_ms(st) +
      (int64_t)st->cfg.retransmit_interval_ms * (1 << (st->cfg.retransmit_max + 1)) + 200;
    return;
  }
  // UDP 常规事件：TYP=NON 尽力投递，无 ACK（§5.3）
  fw_udp_send_frame(st, &d, sub->peer_ip, sub->peer_port, 1);
  fw_strm_release_server(st->strm, peer, svc_id, inst_id, strm); // NON 发送完成即关（§6.2）
}

// 更新接口缓存（§8.1 全量推送数据源）
static void cache_put(fw_stack_t *st, const char *ck, const uint8_t *data, uint32_t len) {
  for (int i = 0; i < st->ev.nnc; i++) {
    if (strcmp(st->ev.ncache[i].key, ck) == 0) {
      free(st->ev.ncache[i].buf);
      st->ev.ncache[i].buf = (uint8_t *)malloc(len ? len : 1);
      if (st->ev.ncache[i].buf) {
        memcpy(st->ev.ncache[i].buf, data, len);
        st->ev.ncache[i].len = len;
      }
      return;
    }
  }
  if (st->ev.nnc == st->ev.nccap) {
    int nc = st->ev.nccap ? st->ev.nccap * 2 : 8;
    void *np = realloc(st->ev.ncache, (size_t)nc * sizeof(fw_notify_cache_t));
    if (!np) return;
    st->ev.ncache = np;
    st->ev.nccap = nc;
  }
  fw_notify_cache_t *e = &st->ev.ncache[st->ev.nnc++];
  memset(e, 0, sizeof(*e));
  snprintf(e->key, sizeof(e->key), "%s", ck);
  e->buf = (uint8_t *)malloc(len ? len : 1);
  if (e->buf) {
    memcpy(e->buf, data, len);
    e->len = len;
  }
}

static const uint8_t *cache_get(fw_stack_t *st, const char *ck, uint32_t *len) {
  for (int i = 0; i < st->ev.nnc; i++) {
    if (strcmp(st->ev.ncache[i].key, ck) == 0 && st->ev.ncache[i].buf) {
      *len = st->ev.ncache[i].len;
      return st->ev.ncache[i].buf;
    }
  }
  *len = 0;
  return NULL;
}

// notify（§13.1）：更新接口缓存并推送给所有订阅者
void fw_events_notify(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                      fw_value_t *payload) {
  fw_local_t *rec = fw_disc_get_local(st, svc_id, inst_id);
  if (!rec) {
    fw_value_free(payload);
    fw_stack_fail(st, FW_ERR_NOT_FOUND, 0, "instance %u:%u not registered", svc_id, inst_id);
    return;
  }
  fw_iface_t *iface = fw_schema_iface(rec->schema, if_id);
  if (!iface || iface->type != FW_IF_EVENT) {
    fw_value_free(payload);
    fw_stack_fail(st, FW_ERR_PARAM, 0, "if_id 0x%04X is not an event interface of svc=%u", if_id, svc_id);
    return;
  }
  // 事件 payload 定义在 IDL output 方向（§11.1）
  fw_buf_t body;
  fw_buf_init(&body);
  char eerr[128];
  int r = fw_encode_payload(rec->schema, iface, 1, payload, &body, eerr, sizeof(eerr));
  fw_value_free(payload);
  if (r != FW_OK) {
    fw_buf_free(&body);
    fw_stack_fail(st, FW_ERR_ENCODE, 0, "encode event payload failed: %s",
                  eerr[0] ? eerr : fw_rst_name(-r));
    return;
  }
  // 更新接口缓存（后续订阅者的全量推送取此数据，§8.1）
  char ck[96];
  snprintf(ck, sizeof(ck), "%u:%u:%u", svc_id, inst_id, if_id);
  cache_put(st, ck, body.p, (uint32_t)body.len);
  // 分发给所有订阅者（单接口订阅 + 组订阅展开，§8.2）
  // [REVIEW P3-9] 订阅者快照改堆分配（原 static[64] 截断）
  fw_sub_rec_t *subs = NULL;
  int ns = 0;
  fw_disc_subscribers_of(st, svc_id, inst_id, if_id, &subs, &ns);
  for (int i = 0; i < ns; i++)
    push_to_one(st, &subs[i], svc_id, inst_id, iface, body.p, (uint32_t)body.len);
  free(subs); // [REVIEW P3-9]
  fw_buf_free(&body);
}

// 全量推送钩子（订阅记录从无到有，纯数据分发非确认信号，§8.1）
void fw_events_push_cached_for(fw_stack_t *st, const fw_meta_t *meta,
                               const fw_sub_entry_t *entries, int n) {
  for (int i = 0; i < n; i++) {
    const fw_sub_entry_t *e = &entries[i];
    if (e->if_id != 0) {
      // 单接口订阅：推送该接口缓存（无缓存 = 应用未 notify 过 → 不推送）
      char ck[96];
      snprintf(ck, sizeof(ck), "%u:%u:%u", e->svc_id, e->inst_id, e->if_id);
      uint32_t len = 0;
      const uint8_t *buf = cache_get(st, ck, &len);
      if (!buf) continue;
      fw_local_t *rec = fw_disc_get_local(st, e->svc_id, e->inst_id);
      fw_iface_t *iface = rec ? fw_schema_iface(rec->schema, e->if_id) : NULL;
      if (!iface && rec == NULL) {
        // 实例已注销：取 IDL 库最高版本定义（§8.1 全量推送按库定义编码）
        fw_idl_entry_t *ent = fw_idl_get_highest(st->idl, e->svc_id);
        iface = ent ? fw_schema_iface(ent->schema, e->if_id) : NULL;
      }
      if (iface && iface->type == FW_IF_EVENT) {
        fw_sub_rec_t sub;
        memset(&sub, 0, sizeof(sub));
        snprintf(sub.peer_ip, sizeof(sub.peer_ip), "%s", meta->address);
        sub.peer_port = meta->port;
        push_to_one(st, &sub, e->svc_id, e->inst_id, iface, buf, len);
      }
    } else if (e->grp_id != 0) {
      // 组订阅：展开为组内所有 event 接口（§7.1/§8.1）
      // [REVIEW P3-9] 组成员列表改堆分配（原固定 out[64]）
      uint16_t *members = NULL;
      int mn = 0;
      fw_disc_group_members(st, e->svc_id, e->grp_id, &members, &mn);
      for (int k = 0; k < mn; k++) {
        char ck[96];
        snprintf(ck, sizeof(ck), "%u:%u:%u", e->svc_id, e->inst_id, members[k]);
        uint32_t len = 0;
        const uint8_t *buf = cache_get(st, ck, &len);
        if (!buf) continue;
        fw_local_t *rec = fw_disc_get_local(st, e->svc_id, e->inst_id);
        fw_iface_t *iface = rec ? fw_schema_iface(rec->schema, members[k]) : NULL;
        if (iface && iface->type == FW_IF_EVENT) {
          fw_sub_rec_t sub;
          memset(&sub, 0, sizeof(sub));
          snprintf(sub.peer_ip, sizeof(sub.peer_ip), "%s", meta->address);
          sub.peer_port = meta->port;
          push_to_one(st, &sub, e->svc_id, e->inst_id, iface, buf, len);
        }
      }
      free(members); // [REVIEW P3-9]
    }
  }
}
// ============================================================
// 客户端接收（§5.3/§8.2）
// ============================================================

// 会话是否匹配帧的 (svc, inst, if_id)（单接口精确 + 组订阅展开，§7.1/§7.4）
// [REVIEW P2-5] 提取为独立判定（匹配收集与交付前复核共用，防回调内会话表变更后错配）
static int sess_matches_frame(fw_stack_t *st, const fw_session_t *s, const fw_frame_t *f) {
  if (s->svc_id != f->svc_id || s->inst_id != f->inst_id) return 0;
  if (s->if_id == f->if_id) return 1;
  if (s->if_id == 0 && s->grp_id != 0) {
    // 组订阅：帧 if_id ∈ 组成员（§7.1）
    uint16_t *members = NULL;
    int mn = 0;
    fw_disc_group_members(st, f->svc_id, s->grp_id, &members, &mn); // [REVIEW P3-9] 动态
    int hit = 0;
    for (int k = 0; k < mn; k++)
      if (members[k] == f->if_id) { hit = 1; break; }
    free(members);
    return hit;
  }
  return 0;
}

// 收到 Notification（CTR=0, Code=0x03）→ 匹配订阅会话并交付
static void on_notification(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  char peer[80];
  snprintf(peer, sizeof(peer), "%s:%u", meta->address, meta->port);
  char key[224];
  snprintf(key, sizeof(key), "%s|%u|%u|%u", peer, f->svc_id, f->inst_id, f->strm_id);

  // UDP CON：回 ACK（重复 CON 到达仍须回 ACK）+ 接收记录去重（仅交付首个，§8.2）
  if (meta->transport == 0 && f->typ == FW_TYP_CON) {
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ctr = 0;
    d.typ = FW_TYP_ACK;
    d.code = 0x00;
    d.ver = st->cfg.ver;
    d.svc_id = f->svc_id;
    d.if_id = f->if_id;
    d.inst_id = f->inst_id;
    d.strm_id = f->strm_id;
    fw_udp_send_frame(st, &d, meta->address, meta->port, 0);
    for (int i = 0; i < st->ev.nrecv; i++) {
      if (strcmp(st->ev.recv[i].key, key) == 0) return; // 重复帧：不重复交付
    }
    if (st->ev.nrecv == st->ev.recvcap) {
      int nc = st->ev.recvcap ? st->ev.recvcap * 2 : 16;
      void *np = realloc(st->ev.recv, (size_t)nc * sizeof(fw_recv_rec_t));
      if (!np) return;
      st->ev.recv = np;
      st->ev.recvcap = nc;
    }
    st->ev.recv[st->ev.nrecv].key[0] = 0;
    snprintf(st->ev.recv[st->ev.nrecv].key, sizeof(st->ev.recv[st->ev.nrecv].key), "%s", key);
    st->ev.recv[st->ev.nrecv].expiry = now_ms(st) + RECV_RECORD_TTL_MS;
    st->ev.nrecv++;
  }

  // 匹配本地订阅会话（§7.4：0x10 前到达的事件按容错交付，不筛会话状态）
  // [REVIEW P2-5] 原实现存 sessions 下标：回调内 fw_unsubscribe/fw_subscribe 触发
  // swap-remove/追加会使后续迭代索引错位（错配/漏配/越界读）。改为快照
  // (handle, on_event, ud) 三元组 + 交付前按 handle 重查并复核匹配条件（两遍交付）
  int cap = st->disc.nsess > 0 ? st->disc.nsess : 1;
  struct { uint32_t handle; fw_event_cb cb; void *ud; } *ms =
    (void *)malloc((size_t)cap * sizeof(*ms));
  if (!ms) { fw_log(FW_LOG_ERROR, "events", "notification match snapshot OOM"); return; }
  int nmatched = 0;
  for (int i = 0; i < st->disc.nsess; i++) {
    fw_session_t *s = &st->disc.sessions[i];
    if (sess_matches_frame(st, s, f)) {
      ms[nmatched].handle = s->handle;
      ms[nmatched].cb = s->on_event;
      ms[nmatched].ud = s->ud;
      nmatched++;
    }
  }
  if (nmatched == 0) {
    free(ms);
    fw_log(FW_LOG_DEBUG, "events", "notification for unsubscribed svc=%u if=0x%04X, dropped",
           f->svc_id, f->if_id);
    return;
  }

  // 解码（事件 payload 定义在 IDL output 方向，§11.1）
  // [REVIEW P2-6] 按帧对应实例的发现缓存 MajorVer 取已加载定义（多版本并存时避免
  // 固定取最高版解码错配），实例不在缓存/版本未加载再退最高版本
  fw_idl_entry_t *e = NULL;
  fw_disc_rec_t *dr = fw_disc_get_discovered(st, f->svc_id, f->inst_id);
  if (dr) e = fw_idl_get(st->idl, f->svc_id, dr->major_ver);
  if (!e) e = fw_idl_get_highest(st->idl, f->svc_id);
  if (!e) {
    // 库中无该服务定义：查发现缓存在线实例 → 自动拉取（无在线实例不查询，§7.2）
    //（[REVIEW P2-6] 拉取版本按实例记录，缺失时取任一在线版本）
    int major = dr ? dr->major_ver : fw_disc_online_major_ver(st, f->svc_id);
    if (major >= 0) {
      fw_disc_fetch_idl_async(st, f->svc_id, (uint8_t)major);
      fw_log(FW_LOG_WARN, "events", "notification svc=%u: IDL missing, async fetch started (event dropped)", f->svc_id);
    } else {
      fw_log(FW_LOG_ERROR, "events", "notification svc=%u: IDL unavailable, dropped", f->svc_id);
    }
    free(ms);
    return; // IDL 不可得：丢弃 + 日志（§7.2；README 偏差：C 版不等待后交付）
  }
  fw_iface_t *iface = fw_schema_iface(e->schema, f->if_id);
  if (!iface) { free(ms); return; }
  fw_value_t *payload = NULL;
  char eerr[128];
  int r = fw_decode_payload(e->schema, iface, 1, f->payload, f->payload_len, &payload,
                            eerr, sizeof(eerr));
  if (r != FW_OK) {
    fw_log(FW_LOG_ERROR, "events", "notification decode failed if=0x%04X: %s",
           f->if_id, eerr[0] ? eerr : fw_rst_name(-r));
    free(ms);
    return;
  }
  // 交付（每个匹配会话独立回调，§8.2；payload 所有权转移给回调——
  // 多会话场景：前面的会话收克隆，最后一个会话移交原值）
  // [REVIEW P2-5] 按 handle 重查 + 复核匹配条件（回调内增删会话表时仍准确交付）
  int delivered = 0;
  for (int i = 0; i < nmatched; i++) {
    fw_session_t *s = NULL;
    for (int k = 0; k < st->disc.nsess; k++) {
      if (st->disc.sessions[k].handle == ms[i].handle) {
        s = &st->disc.sessions[k];
        break;
      }
    }
    if (!s || !ms[i].cb) continue;                 // 会话已移除：跳过（防悬空）
    if (!sess_matches_frame(st, s, f)) continue;   // 会话语义已变：不错配交付
    fw_value_t *pv = (delivered == nmatched - 1) ? payload : fw_value_clone(payload);
    if (!pv) break;
    delivered++;
    ms[i].cb(ms[i].ud, f->svc_id, f->if_id, pv);
  }
  free(ms);
  if (payload && delivered < nmatched) fw_value_free(payload); // 未全部交付：释放余值
}

// ============================================================
// 帧入口 / 定时 / REN
// ============================================================

void fw_events_on_frame(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  switch (f->typ) {
    case FW_TYP_NON:
    case FW_TYP_CON:
      if (f->code == FW_CODE_NOTIFY) on_notification(st, f, meta);
      return;
    case FW_TYP_ACK: {
      // 收到数据帧 ACK：CON 推送的传输确认 → 停重传 + 释放服务端流（§5.5/§6.2）
      char key[224];
      snprintf(key, sizeof(key), "%s:%u|%u|%u|%u", meta->address, meta->port,
               f->svc_id, f->inst_id, f->strm_id);
      fw_retransmit_cancel(&st->ev.retrans, key);
      for (int i = 0; i < st->ev.npush; i++) {
        if (strcmp(st->ev.push[i].key, key) == 0) {
          fw_strm_release_server(st->strm, st->ev.push[i].peer, st->ev.push[i].svc_id,
                                 st->ev.push[i].inst_id, st->ev.push[i].strm);
          st->ev.push[i] = st->ev.push[st->ev.npush - 1];
          st->ev.npush--;
          return;
        }
      }
      return;
    }
    case FW_TYP_RST: {
      // 收到数据帧 RST（推送被拒 §5.4）：释放该推送流
      char key[224];
      snprintf(key, sizeof(key), "%s:%u|%u|%u|%u", meta->address, meta->port,
               f->svc_id, f->inst_id, f->strm_id);
      fw_retransmit_cancel(&st->ev.retrans, key);
      for (int i = 0; i < st->ev.npush; i++) {
        if (strcmp(st->ev.push[i].key, key) == 0) {
          fw_strm_release_server(st->strm, st->ev.push[i].peer, st->ev.push[i].svc_id,
                                 st->ev.push[i].inst_id, st->ev.push[i].strm);
          st->ev.push[i] = st->ev.push[st->ev.npush - 1];
          st->ev.npush--;
          fw_log_frame(FW_LOG_WARN, f->svc_id, f->if_id, f->inst_id, f->strm_id,
                       "Rx", meta->address, f->code, "notification rejected (push stream released)");
          return;
        }
      }
      return;
    }
  }
}

// tick：CON 推送重传耗尽兜底释放 + 接收记录过期清理（§8.2）
void fw_events_tick(fw_stack_t *st, int64_t now) {
  for (int i = 0; i < st->ev.npush; ) {
    if (now >= st->ev.push[i].deadline) {
      fw_strm_release_server(st->strm, st->ev.push[i].peer, st->ev.push[i].svc_id,
                             st->ev.push[i].inst_id, st->ev.push[i].strm);
      st->ev.push[i] = st->ev.push[st->ev.npush - 1];
      st->ev.npush--;
      continue;
    }
    i++;
  }
  for (int i = 0; i < st->ev.nrecv; ) {
    if (now > st->ev.recv[i].expiry) {
      st->ev.recv[i] = st->ev.recv[st->ev.nrecv - 1];
      st->ev.nrecv--;
    } else i++;
  }
}

// 收到 REN=1：清该对端推送重传/活跃记录/接收记录（§3.6）
void fw_events_on_ren(fw_stack_t *st, const char *ip) {
  char prefix[64];
  snprintf(prefix, sizeof(prefix), "%s:", ip);
  fw_retransmit_clear_peer(&st->ev.retrans, prefix);
  for (int i = 0; i < st->ev.npush; ) {
    if (strncmp(st->ev.push[i].key, prefix, strlen(prefix)) == 0) {
      fw_strm_release_server(st->strm, st->ev.push[i].peer, st->ev.push[i].svc_id,
                             st->ev.push[i].inst_id, st->ev.push[i].strm);
      st->ev.push[i] = st->ev.push[st->ev.npush - 1];
      st->ev.npush--;
    } else i++;
  }
  for (int i = 0; i < st->ev.nrecv; ) {
    if (strncmp(st->ev.recv[i].key, prefix, strlen(prefix)) == 0) {
      st->ev.recv[i] = st->ev.recv[st->ev.nrecv - 1];
      st->ev.nrecv--;
    } else i++;
  }
}