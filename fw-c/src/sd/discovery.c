// ============================================================
// discovery.c —— §7 服务发现（SD）+ §7.4 客户端状态机 + §8.1 订阅管理
//
// 服务端角色：注册表 / 周期 Offer（拆帧）/ Find 响应 / Subscribe 服务端处理
//             （ACK 0x10/0x00）/ GetIDL 服务端 / 订阅者 TTL 表
// 客户端角色：发现缓存 + 状态机（Unknown→Found→Subscribed→Expired）/
//             主动 Find / 订阅会话（StrmID 复用、保活、取消、自动重订阅）/
//             GetIDL 客户端（双角色统一触发，§7.2）
// ============================================================

#include "../fw_int.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int64_t now_ms(fw_stack_t *st) {
  return st->clock_override ? st->clock_override() : fw_now_ms();
}

static int ttl_seconds(fw_stack_t *st) { return (int)(st->cfg.ttl_ms / 1000); }

#define ARR_PUSH(arr, n, cap, type) do { \
  if ((n) == (cap)) { \
    int nc_ = (cap) ? (cap) * 2 : 8; \
    void *np_ = realloc((arr), (size_t)nc_ * sizeof(type)); \
    if (!np_) return; \
    (arr) = np_; (cap) = nc_; \
  } \
} while (0)

static void disc_rec_init(fw_disc_rec_t *r, const fw_offer_entry_t *e, const fw_meta_t *meta, uint8_t ver) {
  memset(r, 0, sizeof(*r));
  r->svc_id = e->svc_id;
  r->inst_id = e->inst_id;
  r->major_ver = e->major_ver;
  r->minor_ver = e->minor_ver;
  snprintf(r->addr, sizeof(r->addr), "%s", meta->address);
  r->port = meta->port;
  r->ver = ver;
  r->ttl_left = e->ttl;
  r->state = FW_ST_ACTIVE;
  r->client_state = FW_CS_UNKNOWN;
}

// ============================================================
// 初始化 / 释放
// ============================================================

void fw_disc_init(fw_stack_t *st) {
  memset(&st->disc, 0, sizeof(st->disc));
  fw_retransmit_init(&st->disc.retrans, st->cfg.retransmit_interval_ms, st->cfg.retransmit_max);
}

void fw_disc_free(fw_stack_t *st) {
  fw_retransmit_free(&st->disc.retrans);
  free(st->disc.locals); free(st->disc.subs);
  free(st->disc.disc); free(st->disc.sessions);
  free(st->disc.cancels); // [REVIEW P1-1] 取消等待表随模块释放
  free(st->disc.pf); free(st->disc.queries); free(st->disc.ack);
  memset(&st->disc, 0, sizeof(st->disc));
}

void fw_disc_stop(fw_stack_t *st) {
  fw_retransmit_free(&st->disc.retrans);
  fw_retransmit_init(&st->disc.retrans, st->cfg.retransmit_interval_ms, st->cfg.retransmit_max);
  st->disc.nsubs = 0;
  st->disc.nsess = 0;
  st->disc.ncxl = 0; // [REVIEW P1-1] 清空取消等待
  st->disc.npf = 0;
  st->disc.nq = 0;
  st->disc.nack = 0;
  st->disc.nlocals = 0;
  st->disc.ndisc = 0;
}

// ============================================================
// 服务端角色（§7.3 生命周期）
// ============================================================

fw_local_t *fw_disc_get_local(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id) {
  for (int i = 0; i < st->disc.nlocals; i++) {
    if (st->disc.locals[i].svc_id == svc_id && st->disc.locals[i].inst_id == inst_id)
      return &st->disc.locals[i];
  }
  return NULL;
}

// 注册服务实例 → Offering（开始周期广播 Offer，§7.3；7.9 重复注册 Err）
int fw_disc_register(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                     fw_schema_t *schema, const fw_handlers_t *handlers, char *err, int errsz) {
  if (fw_disc_get_local(st, svc_id, inst_id)) {
    snprintf(err, (size_t)errsz, "service instance %u/%u already registered", svc_id, inst_id);
    return FW_ERR_BUSY; // 7.9：重复注册不覆盖原处理者
  }
  if (st->disc.nlocals == st->disc.locals_cap) {
    int nc = st->disc.locals_cap ? st->disc.locals_cap * 2 : 8;
    void *np = realloc(st->disc.locals, (size_t)nc * sizeof(fw_local_t));
    if (!np) { snprintf(err, (size_t)errsz, "out of memory"); return FW_ERR_MEMORY; }
    st->disc.locals = np;
    st->disc.locals_cap = nc;
  }
  fw_local_t *r = &st->disc.locals[st->disc.nlocals++];
  memset(r, 0, sizeof(*r));
  r->svc_id = svc_id;
  r->inst_id = inst_id;
  r->schema = schema;
  if (handlers) r->handlers = *handlers;
  fw_log(FW_LOG_INFO, "sd", "register_service: svc=%u inst=%u -> Offering", svc_id, inst_id);
  // 注册即 Offering：立即广播一次
  fw_offer_entry_t e;
  memset(&e, 0, sizeof(e));
  e.svc_id = svc_id;
  e.inst_id = inst_id;
  e.major_ver = schema->major_ver;
  e.minor_ver = schema->minor_ver;
  e.ttl = (uint8_t)ttl_seconds(st);
  fw_disc_build_offers(st, &e, 1, 1);
  return FW_OK;
}

// 注销实例 → 发 TTL=0 Offer 一次，停止广播（§7.3；IDL 定义保留在库中 §7.2）
int fw_disc_unregister(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id) {
  fw_local_t *r = fw_disc_get_local(st, svc_id, inst_id);
  if (!r) return FW_ERR_NOT_FOUND;
  fw_offer_entry_t e;
  memset(&e, 0, sizeof(e));
  e.svc_id = svc_id;
  e.inst_id = inst_id;
  e.major_ver = r->schema->major_ver;
  e.minor_ver = r->schema->minor_ver;
  e.ttl = 0; // TTL=0 表示停止提供（§7.2 Offer）
  fw_disc_build_offers(st, &e, 1, 1);
  *r = st->disc.locals[st->disc.nlocals - 1];
  st->disc.nlocals--;
  fw_log(FW_LOG_INFO, "sd", "unregister_service: svc=%u inst=%u -> Stopped", svc_id, inst_id);
  return FW_OK;
}

// Offer 拆帧（§7.2：按 max_payload_len 满装拆分，Entry 粒度 = (SvcID, InstID)）
int fw_disc_build_offers(fw_stack_t *st, const fw_offer_entry_t *entries, int n, int which) {
  int max_entries = (int)(st->cfg.max_payload_len / FW_ENTRY_OFFER);
  if (max_entries < 1) max_entries = 1;
  uint8_t buf[1536];
  for (int i = 0; i < n; i += max_entries) {
    int cnt = (n - i) < max_entries ? (n - i) : max_entries;
    uint32_t plen = fw_encode_offer_entries(buf, sizeof(buf), entries + i, cnt);
    if (!plen) continue;
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ctr = 1;
    d.typ = FW_TYP_NON;
    d.code = FW_CODE_SD_OFFER;
    d.ver = st->cfg.ver;
    d.payload = buf;
    d.payload_len = plen; // 连接级帧 StrmID=0（§4.3 步骤 4）
    fw_udp_send_mcast_frame(st, &d, which);
  }
  return FW_OK;
}

// 实例 Expired 处理：该实例的活跃订阅会话 → 停保活、释放会话 StrmID、登记转 pending（§7.4）
static void pause_sessions_of(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id) {
  for (int k = 0; k < st->disc.nsess; k++) {
    fw_session_t *s = &st->disc.sessions[k];
    if (s->svc_id == svc_id && s->inst_id == inst_id &&
        (s->state == FW_SESS_ACTIVE || s->state == FW_SESS_ESTABLISHING)) {
      if (s->retrans_key[0]) { fw_retransmit_cancel(&st->disc.retrans, s->retrans_key); s->retrans_key[0] = 0; }
      if (s->session_strm) {
        fw_strm_release_ctrl(st->strm, s->peer, s->session_strm);
        s->session_strm = 0;
      }
      s->state = FW_SESS_PENDING; // 保留登记，重新 Found 后自动重订阅（§7.4）
    }
  }
}
// 周期 Offer 广播（period_ms，§7.2）+ 1s TTL tick（§7.5）
void fw_disc_tick(fw_stack_t *st, int64_t now) {
  // 周期广播（有本地实例时）
  if (st->disc.nlocals > 0 && now - st->last_offer_ms >= (int64_t)st->cfg.period_ms) {
    st->last_offer_ms = now;
    int n = st->disc.nlocals;
    fw_offer_entry_t *es = (fw_offer_entry_t *)malloc((size_t)n * sizeof(fw_offer_entry_t));
    if (es) {
      for (int i = 0; i < n; i++) {
        fw_local_t *r = &st->disc.locals[i];
        memset(&es[i], 0, sizeof(es[i]));
        es[i].svc_id = r->svc_id;
        es[i].inst_id = r->inst_id;
        es[i].major_ver = r->schema->major_ver;
        es[i].minor_ver = r->schema->minor_ver;
        es[i].ttl = (uint8_t)ttl_seconds(st);
      }
      fw_disc_build_offers(st, es, n, 1);
      free(es);
    }
  }
  // 1s tick（§7.5：TTL 推进；TTL=0 与归零都延迟到 tick 清理）
  if (now - st->last_tick_ms >= 1000) {
    st->last_tick_ms = now;
    // 发现缓存：Active 递减归零 → Expired；Expired 延迟 3×period 删除（§7.5 + §2 降级窗口：
    // 组播不可用环境（WiFi/回环绑定）下，Expired 期间向最近已知地址周期单播 Find 兜底，
    // 行为与组播发现等价——服务恢复后经单播 Offer 重建）
    for (int i = 0; i < st->disc.ndisc; ) {
      fw_disc_rec_t *r = &st->disc.disc[i];
      if (r->state == FW_ST_EXPIRED) {
        // §2 降级：向最近已知地址周期单播 Find（指定 SvcID，InstID 精确）
        if (r->expire_at == 0) r->expire_at = now;
        if (now - r->expire_at < (int64_t)st->cfg.period_ms * 60) { // 降级窗口 60×period（README 偏差说明）
          if (now - r->last_ufind_ms >= (int64_t)st->cfg.period_ms) {
            r->last_ufind_ms = now;
            fw_find_entry_t q;
            memset(&q, 0, sizeof(q));
            q.svc_id = r->svc_id;
            q.inst_id = r->inst_id;
            q.major_ver = 0;
            uint8_t fb[8];
            fw_frame_desc_t d;
            memset(&d, 0, sizeof(d));
            d.ctr = 1;
            d.typ = FW_TYP_NON;
            d.code = FW_CODE_SD_FIND;
            d.ver = st->cfg.ver;
            d.payload = fb;
            d.payload_len = fw_encode_find_entries(fb, sizeof(fb), &q, 1);
            fw_udp_send_frame(st, &d, r->addr, r->port, 0);
            fw_log(FW_LOG_DEBUG, "sd", "multicast fallback: unicast Find to %s:%u (svc=%u)",
                   r->addr, r->port, r->svc_id);
          }
          i++;
          continue;
        }
        st->disc.disc[i] = st->disc.disc[st->disc.ndisc - 1];
        st->disc.ndisc--;
        continue;
      }
      r->ttl_left--;
      if (r->ttl_left <= 0) {
        int prev = r->client_state;
        r->state = FW_ST_EXPIRED;
        r->client_state = FW_CS_EXPIRED;
        pause_sessions_of(st, r->svc_id, r->inst_id); // Subscribed 保留登记（§7.4）
        if (prev == FW_CS_SUBSCRIBED || prev == FW_CS_FOUND)
          fw_log(FW_LOG_INFO, "sd", "instance expired: svc=%u inst=%u", r->svc_id, r->inst_id);
      }
      i++;
    }
    // 服务端订阅表 TTL tick（§7.5）
    for (int i = 0; i < st->disc.nsubs; ) {
      fw_sub_rec_t *s = &st->disc.subs[i];
      if (s->state == FW_ST_EXPIRED) {
        st->disc.subs[i] = st->disc.subs[st->disc.nsubs - 1];
        st->disc.nsubs--;
        continue;
      }
      s->ttl_left--;
      if (s->ttl_left <= 0) s->state = FW_ST_EXPIRED; // 归零 → Expired（下 tick 删除）
      i++;
    }
    // ACK 缓存 60s 兜底清理（防表膨胀）
    for (int i = 0; i < st->disc.nack; ) {
      if (now - st->disc.ack[i].expiry > 60000) {
        st->disc.ack[i] = st->disc.ack[st->disc.nack - 1];
        st->disc.nack--;
      } else i++;
    }
  }
}

// ============================================================
// 实例 Found：触发 pending 订阅自动发起（§7.4）与 find 等待者
// ============================================================

static void transition_found(fw_stack_t *st, fw_disc_rec_t *r) {
  r->client_state = FW_CS_FOUND;
  // 实例 Found 时尝试发起全部 pending 会话（自动订阅/重订阅，§7.4）
  for (int i = 0; i < st->disc.nsess; i++) {
    fw_session_t *s = &st->disc.sessions[i];
    if (s->svc_id == r->svc_id && s->inst_id == r->inst_id && s->state == FW_SESS_PENDING) {
      snprintf(s->addr, sizeof(s->addr), "%s", r->addr);
      s->port = r->port;
      snprintf(s->peer, sizeof(s->peer), "%s:%u", r->addr, r->port);
      // 分配会话 StrmID（控制帧按 peer 统一池，§6.3；自动重订阅分配新 StrmID §7.4）
      int strm = fw_strm_alloc_ctrl(st->strm, s->peer);
      if (strm < 0) {
        fw_log(FW_LOG_ERROR, "sd", "control StrmID pool exhausted for %s", s->peer);
        continue;
      }
      s->session_strm = strm;
      s->state = FW_SESS_ESTABLISHING;
      fw_sub_entry_t e;
      memset(&e, 0, sizeof(e));
      e.svc_id = s->svc_id;
      e.if_id = s->if_id;
      e.inst_id = s->inst_id;
      e.grp_id = s->grp_id;
      e.ttl = (uint8_t)ttl_seconds(st);
      uint8_t buf[16];
      fw_frame_desc_t d;
      memset(&d, 0, sizeof(d));
      d.ctr = 1;
      d.typ = FW_TYP_CON; // 首次 CON（§8.1）
      d.code = FW_CODE_SD_SUB;
      d.ver = st->cfg.ver;
      d.strm_id = (uint8_t)strm;
      d.payload = buf;
      d.payload_len = fw_encode_sub_entries(buf, sizeof(buf), &e, 1);
      uint8_t raw[64];
      uint32_t rlen = fw_frame_encode(raw, sizeof(raw), &d);
      fw_udp_sendto_raw(st, s->addr, s->port, 0, raw, rlen);
      snprintf(s->retrans_key, sizeof(s->retrans_key), "ctrl-sub|%s|%d", s->peer, strm);
      fw_retransmit_start(&st->disc.retrans, s->retrans_key, raw, rlen, s->addr, s->port, 0, now_ms(st));
      fw_log(FW_LOG_DEBUG, "sd", "Subscribe Tx: peer=%s strm=%d initial=1", s->peer, strm);
    }
  }
  // find 等待者唤醒（§7.4 Unknown→Found）
  for (int i = 0; i < st->disc.npf; i++) {
    fw_pend_find_t *p = &st->disc.pf[i];
    if (p->svc_id == r->svc_id && (p->inst_id == 0 || p->inst_id == r->inst_id))
      fw_waiters_fire(st, &p->waiters);
  }
}

// ============================================================
// Offer 处理（周期组播与 Find 单播响应同格式同处理，§7.2）
// ============================================================

void fw_disc_on_offer(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  const uint8_t *pl = f->payload;
  uint32_t len = f->payload_len;
  if (len == 0 || len % FW_ENTRY_OFFER != 0) {
    fw_log(FW_LOG_WARN, "sd", "Offer payload not aligned (%uB), dropped", len);
    return;
  }
  // [REVIEW P1-2] 接收端全量解码：上限 = 帧内实际 Entry 数（发送端拆帧满装 233/帧，
  // 原 es[64] 硬上限静默丢弃第 65+ 个 Entry，违反 §7.2"逐帧独立处理"；对齐 JS 无上限）
  int cap = (int)(len / FW_ENTRY_OFFER);
  fw_offer_entry_t *es = (fw_offer_entry_t *)malloc((size_t)cap * sizeof(fw_offer_entry_t));
  if (!es) { fw_log(FW_LOG_ERROR, "sd", "Offer decode out of memory (%d entries)", cap); return; }
  int n = fw_decode_offer_entries(pl, len, es, cap);
  for (int i = 0; i < n; i++) {
    fw_offer_entry_t *e = &es[i];
    fw_disc_rec_t *r = NULL;
    for (int k = 0; k < st->disc.ndisc; k++) {
      if (st->disc.disc[k].svc_id == e->svc_id && st->disc.disc[k].inst_id == e->inst_id) {
        r = &st->disc.disc[k];
        break;
      }
    }
    if (e->ttl == 0) {
      // Offer TTL=0：置 Expired，延迟到 tick 移除（§7.5）；Subscribed 保留登记（§7.4）
      if (r) {
        r->state = FW_ST_EXPIRED;
        r->client_state = FW_CS_EXPIRED;
        pause_sessions_of(st, r->svc_id, r->inst_id);
      }
      continue;
    }
    if (r) {
      // 实例冲突：源地址 ≠ 已记录源地址 → Error 日志，保留先到，忽略后到（§7.2）
      if (strcmp(r->addr, meta->address) != 0) {
        fw_log(FW_LOG_ERROR, "sd", "instance conflict: svc=%u inst=%u recorded@%s vs %s, keep first",
               e->svc_id, e->inst_id, r->addr, meta->address);
        continue;
      }
      // 常规刷新：实例发现缓存 TTL 重置（实例级维护，与订阅 TTL 无关，§7.4/§7.5）
      r->ttl_left = e->ttl;
      r->state = FW_ST_ACTIVE;
      r->expire_at = 0; // 重新 Active：清除降级窗口计时
      r->major_ver = e->major_ver;
      r->minor_ver = e->minor_ver;
      r->ver = f->ver;
      if (r->client_state == FW_CS_EXPIRED || r->client_state == FW_CS_UNKNOWN)
        transition_found(st, r); // Expired→重新 Found（自动重订阅触发）
      continue;
    }
    // Unknown → Found：加入注册表，启动 TTL 倒计时（§7.4）
    if (st->disc.ndisc == st->disc.disc_cap) {
      int nc = st->disc.disc_cap ? st->disc.disc_cap * 2 : 8;
      void *np = realloc(st->disc.disc, (size_t)nc * sizeof(fw_disc_rec_t));
      if (!np) return;
      st->disc.disc = np;
      st->disc.disc_cap = nc;
    }
    fw_disc_rec_t *fresh = &st->disc.disc[st->disc.ndisc++];
    disc_rec_init(fresh, e, meta, f->ver);
    transition_found(st, fresh);
  }
  free(es); // [REVIEW P1-2] 堆分配解码缓冲释放
}

// ============================================================
// Find 处理：匹配本地实例 → 单播响应（§7.2）
// ============================================================

void fw_disc_on_find(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  const uint8_t *pl = f->payload;
  uint32_t len = f->payload_len;
  // [REVIEW P1-2] 响应数组按本地实例数堆分配（原 resp[64] 截断：>64 实例时
  // Find 响应漏报；对齐 JS onFind 无上限语义）
  fw_offer_entry_t *resp = (fw_offer_entry_t *)malloc(
    (size_t)(st->disc.nlocals > 0 ? st->disc.nlocals : 1) * sizeof(fw_offer_entry_t));
  if (!resp) { fw_log(FW_LOG_ERROR, "sd", "Find response out of memory"); return; }
  int nr = 0;
  if (len == 0) {
    // 空 Payload = 查询所有服务（§7.2）
    for (int i = 0; i < st->disc.nlocals; i++) {
      fw_local_t *r = &st->disc.locals[i];
      memset(&resp[nr], 0, sizeof(resp[nr]));
      resp[nr].svc_id = r->svc_id;
      resp[nr].inst_id = r->inst_id;
      resp[nr].major_ver = r->schema->major_ver;
      resp[nr].minor_ver = r->schema->minor_ver;
      resp[nr].ttl = (uint8_t)ttl_seconds(st);
      nr++;
    }
  } else {
    if (len % FW_ENTRY_FIND != 0) {
      fw_log(FW_LOG_WARN, "sd", "Find payload not aligned (%uB), dropped", len);
      free(resp);
      return; // 整帧无法解析 → 静默
    }
    // [REVIEW P1-2] Find 请求按帧实际 Entry 数堆解码（原 qs[64] 截断）
    int cap = (int)(len / FW_ENTRY_FIND);
    fw_find_entry_t *qs = (fw_find_entry_t *)malloc((size_t)cap * sizeof(fw_find_entry_t));
    if (!qs) { fw_log(FW_LOG_ERROR, "sd", "Find decode out of memory"); free(resp); return; }
    int nq = fw_decode_find_entries(pl, len, qs, cap);
    for (int i = 0; i < nq; i++) {
      fw_find_entry_t *q = &qs[i];
      // 带 Entry 时必须指定 SvcID（非零）；无效 Entry 丢弃+日志（§7.2 Entry 级处理）
      if (q->svc_id == 0) {
        fw_log(FW_LOG_ERROR, "sd", "Find entry svc_id=0 invalid, dropped");
        continue;
      }
      for (int k = 0; k < st->disc.nlocals; k++) {
        fw_local_t *r = &st->disc.locals[k];
        if (r->svc_id != q->svc_id) continue;
        if (q->inst_id != 0 && r->inst_id != q->inst_id) continue; // InstID 0x00 通配
        // SvcID 非通配时 MajorVer 参与精确匹配（Entry major_ver=0 时不过滤版本）
        if (q->major_ver != 0 && r->schema->major_ver != q->major_ver) continue;
        memset(&resp[nr], 0, sizeof(resp[nr]));
        resp[nr].svc_id = r->svc_id;
        resp[nr].inst_id = r->inst_id;
        resp[nr].major_ver = r->schema->major_ver;
        resp[nr].minor_ver = r->schema->minor_ver;
        resp[nr].ttl = (uint8_t)ttl_seconds(st);
        nr++;
      }
    }
    free(qs);
  }
  if (nr == 0) { free(resp); return; } // Find 查询不存在：组播不强制回应（§12.2）
  // 响应帧格式与 Offer 相同（Code=0x01），UDP 单播发送，恒走 server socket（裁定 4）
  // [REVIEW P1-2] 发送侧沿用满装拆帧循环（与 fw_disc_build_offers 口径一致）
  uint8_t buf[1536];
  int max_entries = (int)(st->cfg.max_payload_len / FW_ENTRY_OFFER);
  if (max_entries < 1) max_entries = 1;
  for (int i = 0; i < nr; i += max_entries) {
    int cnt = (nr - i) < max_entries ? (nr - i) : max_entries;
    uint32_t plen = fw_encode_offer_entries(buf, sizeof(buf), resp + i, cnt);
    if (!plen) break;
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ctr = 1;
    d.typ = FW_TYP_NON;
    d.code = FW_CODE_SD_OFFER;
    d.ver = st->cfg.ver;
    d.payload = buf;
    d.payload_len = plen;
    fw_udp_send_frame(st, &d, meta->address, meta->port, 1);
  }
  free(resp);
}
// ============================================================
// Subscribe 服务端处理（§8.1 订阅管理）
// ============================================================

// 回订阅确认（ACK 0x10 建立确认 / 0x00 取消确认），缓存供重传重发（§8.1）
static void send_sub_ack(fw_stack_t *st, int code, uint8_t strm, const fw_meta_t *meta) {
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 1;
  d.typ = FW_TYP_ACK;
  d.code = (uint8_t)code;
  d.ver = st->cfg.ver;
  d.strm_id = strm; // 确认帧回显会话 StrmID（§8.1）
  uint8_t raw[32];
  uint32_t rlen = fw_frame_encode(raw, sizeof(raw), &d);
  fw_udp_sendto_raw(st, meta->address, meta->port, 1, raw, rlen);
  // 缓存供同会话重复 CON 重发（不重执行，§5.5）
  char key[224];
  snprintf(key, sizeof(key), "%s:%u|%u", meta->address, meta->port, strm);
  for (int i = 0; i < st->disc.nack; i++) {
    if (strcmp(st->disc.ack[i].key, key) == 0) {
      memcpy(st->disc.ack[i].frame, raw, rlen);
      st->disc.ack[i].flen = rlen;
      st->disc.ack[i].is_cancel = (code == 0x00);
      st->disc.ack[i].expiry = now_ms(st);
      return;
    }
  }
  if (st->disc.nack == st->disc.ackcap) {
    int nc = st->disc.ackcap ? st->disc.ackcap * 2 : 8;
    void *np = realloc(st->disc.ack, (size_t)nc * sizeof(fw_ack_cache_t));
    if (!np) return;
    st->disc.ack = np;
    st->disc.ackcap = nc;
  }
  fw_ack_cache_t *a = &st->disc.ack[st->disc.nack++];
  memset(a, 0, sizeof(*a));
  snprintf(a->key, sizeof(a->key), "%s", key);
  memcpy(a->frame, raw, rlen);
  a->flen = rlen;
  a->is_cancel = (code == 0x00);
  a->expiry = now_ms(st);
}

// 在本地 IDL 库中查接口定义（[REVIEW P2-6] 按发现缓存该实例的 MajorVer 匹配已加载
// 定义——多版本并存时（§7.2 部署异常场景）避免固定取最高版导致解码错配；实例未在
// 缓存时退回最高版本（对齐 JS _lookupInterface 宽容语义））
static fw_iface_t *lookup_interface(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id) {
  fw_idl_entry_t *e = NULL;
  fw_disc_rec_t *r = fw_disc_get_discovered(st, svc_id, inst_id);
  if (r) e = fw_idl_get(st->idl, svc_id, r->major_ver);
  if (!e) e = fw_idl_get_highest(st->idl, svc_id);
  return e ? fw_schema_iface(e->schema, if_id) : NULL;
}

void fw_disc_on_subscribe(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  const uint8_t *pl = f->payload;
  uint32_t len = f->payload_len;
  if (len == 0 || len % FW_ENTRY_SUB != 0) {
    // 整帧 Payload 无法解析 → RST(0x20)（§7.2 Entry 级处理）
    fw_frame_desc_t d;
    fw_make_rst(&d, FW_RST_BAD_REQUEST, 1, 0, 0, 0, f->strm_id);
    fw_udp_send_frame(st, &d, meta->address, meta->port, 1);
    return;
  }
  // [REVIEW P1-2] 合并 Subscribe 按帧实际 Entry 数堆解码（原 es[32] 截断，对齐 JS 无上限）
  int cap = (int)(len / FW_ENTRY_SUB);
  fw_sub_entry_t *es = (fw_sub_entry_t *)malloc((size_t)cap * sizeof(fw_sub_entry_t));
  if (!es) { fw_log(FW_LOG_ERROR, "sd", "Subscribe decode out of memory (%d entries)", cap); return; }
  int n = fw_decode_sub_entries(pl, len, es, cap);
  int is_con = (f->typ == FW_TYP_CON);
  fw_log(FW_LOG_DEBUG, "sd", "Subscribe Rx: peer=%s:%u strm=%u con=%d entries=%d",
         meta->address, meta->port, f->strm_id, is_con, n);

  // 同一会话 StrmID 的重复 CON 到达 = 重传判定 → 重发上次确认，不重新执行（§5.5/§8.1）
  if (is_con && n > 0) {
    int cur_ttl0 = (es[0].ttl == 0);
    char key[224];
    snprintf(key, sizeof(key), "%s:%u|%u", meta->address, meta->port, f->strm_id);
    for (int i = 0; i < st->disc.nack; i++) {
      if (strcmp(st->disc.ack[i].key, key) == 0 && st->disc.ack[i].is_cancel == cur_ttl0) {
        // 同类重复 CON：重发缓存确认（0x10 重发不重推全量，§8.1）
        fw_udp_sendto_raw(st, meta->address, meta->port, 1, st->disc.ack[i].frame, st->disc.ack[i].flen);
        return;
      }
    }
  }

  // 6.19 调和：单 Entry 帧指向本地完全不存在 (svc,inst) 实例 → RST(0x24)
  //（多 Entry 帧逐 Entry 独立处理，§7.2 Entry 级丢弃——对齐 fw-nodejs）
  if (n == 1) {
    fw_sub_entry_t *e = &es[0];
    int combo_ok = (e->if_id != 0 && e->grp_id == 0) || (e->if_id == 0 && e->grp_id != 0);
    if (combo_ok && e->svc_id != 0 && e->inst_id != 0 && !fw_disc_get_local(st, e->svc_id, e->inst_id)) {
      fw_frame_desc_t d;
      fw_make_rst(&d, FW_RST_NOT_FOUND, 1, 0, 0, 0, f->strm_id);
      fw_udp_send_frame(st, &d, meta->address, meta->port, 1);
      return;
    }
  }
  // 6.17：tcp-event 订阅（transport=tcp 的 event 接口）须预建 TCP 连接 → 无连接 RST(0x24)
  for (int i = 0; i < n; i++) {
    fw_iface_t *iface = lookup_interface(st, es[i].svc_id, es[i].inst_id, es[i].if_id);
    if (iface && iface->type == FW_IF_EVENT && iface->transport == FW_TR_TCP) {
      if (!fw_tcp_find_server_by_ip(st, meta->address)) {
        fw_log(FW_LOG_WARN, "sd", "tcp-event subscribe without connection from %s -> RST(0x24)", meta->address);
        fw_frame_desc_t d;
        fw_make_rst(&d, FW_RST_NOT_FOUND, 1, 0, 0, 0, f->strm_id);
        fw_udp_send_frame(st, &d, meta->address, meta->port, 1);
        return;
      }
    }
  }

  int has_new = 0, any_cancel = 0;
  for (int i = 0; i < n; i++) {
    fw_sub_entry_t *e = &es[i];
    // Entry 合法组合（§7.1）：单接口 IfID≠0 且 GrpId=0 / 组订阅 IfID=0 且 GrpId≠0
    int valid = (e->if_id != 0 && e->grp_id == 0) || (e->if_id == 0 && e->grp_id != 0);
    if (!valid || e->svc_id == 0 || e->inst_id == 0) {
      // 无效 Entry：丢弃 + Error 日志，不影响同帧其他 Entry（§7.2）
      fw_log(FW_LOG_ERROR, "sd", "Subscribe entry invalid (svc=%u, if=%u, grp=%u), dropped",
             e->svc_id, e->if_id, e->grp_id);
      continue;
    }
    // 应用一条订阅 Entry（§8.1 表；订阅表主键 = Entry 内容 (peer, svc, if/grp, inst)）
    char kind = e->if_id != 0 ? 'i' : 'g';
    char key[200];
    snprintf(key, sizeof(key), "%s|%u|%u|%u|%c%u",
             meta->address, meta->port, e->svc_id, e->inst_id,
             kind, e->if_id != 0 ? e->if_id : e->grp_id);
    fw_sub_rec_t *ex = NULL;
    for (int k = 0; k < st->disc.nsubs; k++)
      if (strcmp(st->disc.subs[k].key, key) == 0) { ex = &st->disc.subs[k]; break; }
    if (e->ttl == 0) {
      // 取消：置 Expired，延迟到下次 tick 移除（§7.5）
      if (ex) ex->state = FW_ST_EXPIRED;
      any_cancel = 1;
      continue;
    }
    if (ex) {
      // 已存在（重传或保活到达）：刷新 TTL（重置而非累加，§7.5）
      ex->ttl_left = e->ttl;
      ex->state = FW_ST_ACTIVE;
      ex->session_strm = f->strm_id; // 会话跟踪（§7.2：主键仍为 Entry 内容）
      continue;
    }
    // 从无到有：建立订阅（state=Active，§8.1）
    if (st->disc.nsubs == st->disc.subs_cap) {
      int nc = st->disc.subs_cap ? st->disc.subs_cap * 2 : 8;
      void *np = realloc(st->disc.subs, (size_t)nc * sizeof(fw_sub_rec_t));
      if (!np) continue;
      st->disc.subs = np;
      st->disc.subs_cap = nc;
    }
    fw_sub_rec_t *s = &st->disc.subs[st->disc.nsubs++];
    memset(s, 0, sizeof(*s));
    snprintf(s->key, sizeof(s->key), "%s", key);
    s->svc_id = e->svc_id;
    s->inst_id = e->inst_id;
    s->if_id = e->if_id;
    s->grp_id = e->grp_id;
    snprintf(s->peer_ip, sizeof(s->peer_ip), "%s", meta->address);
    s->peer_port = meta->port;
    s->session_strm = f->strm_id;
    s->ttl_left = e->ttl;
    s->state = FW_ST_ACTIVE;
    has_new = 1;
  }

  if (is_con) {
    // 服务端能正常解析帧即按会话回确认（§7.2）：TTL>0 → ACK(0x10)；TTL=0 → ACK(0x00)
    send_sub_ack(st, any_cancel ? 0x00 : FW_CODE_SD_SUBACK, f->strm_id, meta);
  }
  if (has_new) {
    // 订阅记录从无到有 → 全量推送（数据分发，非确认信号；每条订阅仅一次，§8.1）
    fw_disc_on_subscription_added(st, meta, es, n);
  }
  free(es); // [REVIEW P1-2] 堆分配解码缓冲释放
}

// 订阅者查询（events 推送用，§8.2）：单接口精确 + 组订阅展开
// [REVIEW P3-9] 快照改堆分配（原 static[64] 硬上限：订阅者 >64 时推送漏发且
// static 缓冲跨调用复用）；*out 由调用者 free
void fw_disc_subscribers_of(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                            fw_sub_rec_t **out, int *out_n) {
  *out = NULL;
  *out_n = 0;
  int cap = st->disc.nsubs > 0 ? st->disc.nsubs : 1;
  fw_sub_rec_t *snapshot = (fw_sub_rec_t *)malloc((size_t)cap * sizeof(fw_sub_rec_t));
  if (!snapshot) { fw_log(FW_LOG_ERROR, "sd", "subscribers snapshot out of memory"); return; }
  int n = 0;
  for (int i = 0; i < st->disc.nsubs; i++) {
    fw_sub_rec_t *s = &st->disc.subs[i];
    if (s->svc_id != svc_id || s->inst_id != inst_id || s->state != FW_ST_ACTIVE) continue;
    if (s->if_id == if_id) { snapshot[n++] = *s; continue; }
    if (s->if_id == 0 && s->grp_id != 0) {
      // 组订阅：服务端展开为组内所有 event 接口（§7.1）
      uint16_t *members = NULL;
      int mn = 0;
      fw_disc_group_members(st, svc_id, s->grp_id, &members, &mn);
      for (int k = 0; k < mn; k++) {
        if (members[k] == if_id) { snapshot[n++] = *s; break; }
      }
      free(members); // [REVIEW P3-9] 组成员动态缓冲
    }
  }
  *out = snapshot;
  *out_n = n;
}

// 查 IDL 事件组成员（本地库定义，§7.1）
// [REVIEW P3-9] 成员列表堆分配（原调用方固定 out[64] 截断）；*out 由调用者 free
void fw_disc_group_members(fw_stack_t *st, uint16_t svc_id, uint8_t grp_id,
                           uint16_t **out, int *out_n) {
  *out = NULL;
  *out_n = 0;
  fw_idl_entry_t *e = fw_idl_get_highest(st->idl, svc_id);
  if (!e) return;
  int n = 0;
  const uint16_t *m = fw_schema_group_members(e->schema, grp_id, &n);
  if (!m || n <= 0) return;
  uint16_t *buf = (uint16_t *)malloc((size_t)n * sizeof(uint16_t));
  if (!buf) { fw_log(FW_LOG_ERROR, "sd", "group members out of memory"); return; }
  memcpy(buf, m, (size_t)n * sizeof(uint16_t));
  *out = buf;
  *out_n = n;
}

// ============================================================
// GetIDL 服务端处理（§7.2，仅 TCP 单播——传输绑定已由解析层保证）
// ============================================================

void fw_disc_on_getidl(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  fw_getidl_entry_t e;
  if (!fw_decode_getidl_entry(f->payload, f->payload_len, &e) || e.svc_id == 0) {
    // Payload ≠3B 或 SvcID=0 → RST(0x20)（§7.2）
    fw_frame_desc_t d;
    fw_make_rst(&d, FW_RST_BAD_REQUEST, 1, 0, 0, 0, f->strm_id);
    if (meta->conn) fw_tcp_send_frame(st, meta->conn, &d);
    return;
  }
  // 服务端匹配 = 本地 IDL 库已加载定义（与实例是否在线无关，§7.2/5.35）
  fw_idl_entry_t *def = fw_idl_get(st->idl, e.svc_id, e.major_ver);
  if (!def) {
    fw_frame_desc_t d;
    fw_make_rst(&d, FW_RST_NOT_FOUND, 1, 0, 0, 0, f->strm_id);
    if (meta->conn) fw_tcp_send_frame(st, meta->conn, &d);
    fw_log_frame(FW_LOG_WARN, e.svc_id, 0, 0, f->strm_id, "Tx", meta->address,
                 FW_RST_NOT_FOUND, "GetIDL: no such (SvcID, MajorVer) loaded");
    return;
  }
  // 响应：CTR=1, TYP=NON, Code=0x11, 回显请求 StrmID, Payload=IDL JSON 全文（§7.2）
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 1;
  d.typ = FW_TYP_NON;
  d.code = FW_CODE_SD_IDLRESP;
  d.ver = st->cfg.ver;
  d.strm_id = f->strm_id;
  d.payload = (const uint8_t *)def->json_text;
  d.payload_len = (uint32_t)strlen(def->json_text);
  if (meta->conn) fw_tcp_send_frame(st, meta->conn, &d);
}
// ============================================================
// 客户端角色：发现缓存查询
// ============================================================

fw_disc_rec_t *fw_disc_get_discovered(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id) {
  for (int i = 0; i < st->disc.ndisc; i++) {
    fw_disc_rec_t *r = &st->disc.disc[i];
    if (r->svc_id == svc_id && r->inst_id == inst_id &&
        r->state == FW_ST_ACTIVE && r->client_state != FW_CS_EXPIRED)
      return r;
  }
  return NULL;
}

// 该 svc 的任一在线实例版本（注册场景自动 GetIDL 的 MajorVer 取值，§7.2 双角色）
int fw_disc_online_major_ver(fw_stack_t *st, uint16_t svc_id) {
  for (int i = 0; i < st->disc.ndisc; i++) {
    fw_disc_rec_t *r = &st->disc.disc[i];
    if (r->svc_id == svc_id && r->state == FW_ST_ACTIVE) return r->major_ver;
  }
  return -1;
}

// ============================================================
// 主动 Find（§13.2 find_service / call 的缓存未命中路径）
// ============================================================

int fw_disc_find(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                 uint32_t timeout_ms, fw_svc_info_t *out, char *err, int errsz) {
  fw_disc_rec_t *r = fw_disc_get_discovered(st, svc_id, inst_id);
  if (r) {
    if (out) {
      snprintf(out->address, sizeof(out->address), "%s", r->addr);
      out->port = r->port;
      out->major_ver = r->major_ver;
      out->minor_ver = r->minor_ver;
    }
    return FW_OK; // 缓存命中直接返回（§13.2）
  }
  // 发 Find（组播；带 Entry 指定 SvcID，InstID 通配或精确，§7.2）
  fw_find_entry_t q;
  memset(&q, 0, sizeof(q));
  q.svc_id = svc_id;
  q.inst_id = inst_id;
  q.major_ver = 0;
  uint8_t buf[8];
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 1;
  d.typ = FW_TYP_NON;
  d.code = FW_CODE_SD_FIND;
  d.ver = st->cfg.ver;
  d.payload = buf;
  d.payload_len = fw_encode_find_entries(buf, sizeof(buf), &q, 1);
  fw_udp_send_mcast_frame(st, &d, 0);
  // §2 组播不可用降级：对 Expired 记录的最近已知地址补发单播 Find
  for (int i = 0; i < st->disc.ndisc; i++) {
    fw_disc_rec_t *r = &st->disc.disc[i];
    if (r->svc_id != svc_id || r->state != FW_ST_EXPIRED || r->addr[0] == 0) continue;
    fw_udp_send_frame(st, &d, r->addr, r->port, 0);
  }
  // 登记/复用 pend_find（deadline 供 fw_disc_tick_find 清理；[REVIEW P2-3/P2-4] 不再
  // 挂接等待者——同步泵直接轮询发现缓存，Offer 到达即退，且泵期间 pf 数组 realloc
  // 不会使本函数持有悬空指针）
  fw_pend_find_t *p = NULL;
  for (int i = 0; i < st->disc.npf; i++) {
    if (st->disc.pf[i].svc_id == svc_id && st->disc.pf[i].inst_id == inst_id) { p = &st->disc.pf[i]; break; }
  }
  if (!p) {
    if (st->disc.npf == st->disc.pfcap) {
      int nc = st->disc.pfcap ? st->disc.pfcap * 2 : 8;
      void *np = realloc(st->disc.pf, (size_t)nc * sizeof(fw_pend_find_t));
      if (!np) { snprintf(err, (size_t)errsz, "out of memory"); return FW_ERR_MEMORY; }
      st->disc.pf = np;
      st->disc.pfcap = nc;
    }
    p = &st->disc.pf[st->disc.npf++];
    memset(p, 0, sizeof(*p));
    p->svc_id = svc_id;
    p->inst_id = inst_id;
  }
  p->deadline_ms = now_ms(st) + (timeout_ms ? timeout_ms : st->cfg.response_timeout_ms);
  // 同步等待（泵事件循环；调用方保证 dispatch==0）。
  // [REVIEW P2-3] 原实现依赖 FW_W_FIND 等待者置 done 标志，但 fw_waiters_fire 对
  // FW_W_FIND 无分支 → done 永不置位，Offer 到达也不唤醒，find_service 恒等满
  // timeout；改为逐轮轮询发现缓存（对齐 JS pendingFind Promise 即时 resolve）
  int64_t deadline = p->deadline_ms;
  while (st->dispatch == 0) {
    st->dispatch++;
    fw_stack_poll(st, 20);
    st->dispatch--;
    if (fw_disc_get_discovered(st, svc_id, inst_id)) break; // Offer 到达即命中
    if (now_ms(st) >= deadline) break;
  }
  r = fw_disc_get_discovered(st, svc_id, inst_id);
  if (!r) {
    snprintf(err, (size_t)errsz, "find_service(%u,%u) timeout", svc_id, inst_id);
    return FW_ERR_NOT_FOUND;
  }
  if (out) {
    snprintf(out->address, sizeof(out->address), "%s", r->addr);
    out->port = r->port;
    out->major_ver = r->major_ver;
    out->minor_ver = r->minor_ver;
  }
  return FW_OK;
}

// find 等待 deadline 清理（无等待者的过期记录）
void fw_disc_tick_find(fw_stack_t *st, int64_t now) {
  for (int i = 0; i < st->disc.npf; ) {
    if (now > st->disc.pf[i].deadline_ms && !st->disc.pf[i].waiters) {
      st->disc.pf[i] = st->disc.pf[st->disc.npf - 1];
      st->disc.npf--;
    } else i++;
  }
}
// ============================================================
// 订阅会话（客户端，§7.2 会话 StrmID 规则 / §8.1 确认链路）
// ============================================================

// 发送 Subscribe 帧（首次/重传 CON；保活 NON；取消 CON TTL=0，§7.2）
static void send_subscribe(fw_stack_t *st, fw_session_t *s, int is_initial, int cancel) {
  fw_sub_entry_t e;
  memset(&e, 0, sizeof(e));
  e.svc_id = s->svc_id;
  e.if_id = s->if_id;
  e.inst_id = s->inst_id;
  e.grp_id = s->grp_id;
  e.ttl = cancel ? 0 : (uint8_t)ttl_seconds(st);
  uint8_t buf[16];
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 1;
  d.typ = (uint8_t)((is_initial || cancel) ? FW_TYP_CON : FW_TYP_NON);
  d.code = FW_CODE_SD_SUB;
  d.ver = st->cfg.ver;
  d.strm_id = (uint8_t)s->session_strm;
  d.payload = buf;
  d.payload_len = fw_encode_sub_entries(buf, sizeof(buf), &e, 1);
  uint8_t raw[64];
  uint32_t rlen = fw_frame_encode(raw, sizeof(raw), &d);
  fw_udp_sendto_raw(st, s->addr, s->port, 0, raw, rlen);
  if (d.typ == FW_TYP_CON) {
    // 首次/取消 CON 走重传（§5.5 重传范围）；确认到达或耗尽停止
    snprintf(s->retrans_key, sizeof(s->retrans_key), "ctrl-sub|%s|%d", s->peer, s->session_strm);
    fw_retransmit_start(&st->disc.retrans, s->retrans_key, raw, rlen, s->addr, s->port, 0, now_ms(st));
  }
  fw_log(FW_LOG_DEBUG, "sd", "Subscribe Tx: peer=%s strm=%d ttl=%u initial=%d cancel=%d",
         s->peer, s->session_strm, e.ttl, is_initial, cancel);
}

uint32_t fw_disc_subscribe(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                           uint16_t if_id, uint8_t grp_id, fw_event_cb cb, void *ud) {
  if (st->disc.nsess == st->disc.sess_cap) {
    int nc = st->disc.sess_cap ? st->disc.sess_cap * 2 : 8;
    void *np = realloc(st->disc.sessions, (size_t)nc * sizeof(fw_session_t));
    if (!np) return 0;
    st->disc.sessions = np;
    st->disc.sess_cap = nc;
  }
  fw_session_t *s = &st->disc.sessions[st->disc.nsess++];
  memset(s, 0, sizeof(*s));
  s->handle = ++st->disc.handle_seq;
  s->svc_id = svc_id;
  s->inst_id = inst_id;
  s->if_id = if_id;
  s->grp_id = grp_id;
  s->on_event = cb;
  s->ud = ud;
  s->state = FW_SESS_PENDING; // pending → establishing → active
  // 已 Found：立即发起（未 Found 仅登记，Found 后自动发起，§7.4/§13.2）
  fw_disc_rec_t *r = fw_disc_get_discovered(st, svc_id, inst_id);
  if (r) transition_found(st, r); // 复用 pending 触发路径
  return s->handle;
}

// unsubscribe（§13.2）：发 Subscribe(TTL=0)（CON）等待 ACK(0x00)；
// 应用视角立即完成（登记删除），服务端订阅靠 TTL 自愈兜底。
// [REVIEW P1-1] 会话 StrmID 生命周期：原实现把 cancel_deadline 写在即将被 swap
// 覆盖的槽位上 → ACK(0x00) 匹配失效，StrmID 永不释放（130 轮池耗尽）。改为登记
// 到独立取消等待表 cancels（对齐 JS cancelPending），ACK 到达或重传耗尽兜底释放。
int fw_disc_unsubscribe(fw_stack_t *st, uint32_t handle) {
  for (int i = 0; i < st->disc.nsess; i++) {
    fw_session_t *s = &st->disc.sessions[i];
    if (s->handle != handle) continue;
    // 登记清除条件①：显式 unsubscribe（§7.4）
    if (s->retrans_key[0]) { fw_retransmit_cancel(&st->disc.retrans, s->retrans_key); s->retrans_key[0] = 0; }
    if (s->session_strm && s->addr[0]) {
      send_subscribe(st, s, 0, 1); // 取消（TTL=0, CON，同会话 StrmID，§8.1 场景4）
      // [REVIEW P1-1] 取消等待登记：保留会话 StrmID 直至 ACK(0x00)（§6.1/6.5）
      if (st->disc.ncxl == st->disc.cxlcap) {
        int nc = st->disc.cxlcap ? st->disc.cxlcap * 2 : 8;
        void *np = realloc(st->disc.cancels, (size_t)nc * sizeof(fw_cancel_pend_t));
        if (np) { st->disc.cancels = np; st->disc.cxlcap = nc; }
      }
      if (st->disc.ncxl < st->disc.cxlcap) {
        fw_cancel_pend_t *c = &st->disc.cancels[st->disc.ncxl++];
        memset(c, 0, sizeof(*c));
        snprintf(c->peer, sizeof(c->peer), "%s", s->peer);
        c->strm = s->session_strm;
        snprintf(c->retrans_key, sizeof(c->retrans_key), "ctrl-sub|%s|%d", s->peer, s->session_strm);
        // 重传耗尽兜底释放（服务端靠订阅 TTL 过期自愈）
        c->deadline = now_ms(st) +
          (int64_t)st->cfg.retransmit_interval_ms * (1 << (st->cfg.retransmit_max + 1)) + 200;
        fw_log(FW_LOG_DEBUG, "sd", "unsubscribe pending: peer=%s strm=%d", s->peer, s->session_strm);
      } else {
        // 登记失败（OOM）：立即释放防泄漏（无等待兜底，退化为发后即弃）
        fw_log(FW_LOG_ERROR, "sd", "cancel pending table full, release strm immediately");
        fw_strm_release_ctrl(st->strm, s->peer, s->session_strm);
      }
    }
    st->disc.sessions[i] = st->disc.sessions[st->disc.nsess - 1];
    st->disc.nsess--;
    return FW_OK;
  }
  return FW_ERR_NOT_FOUND;
}

// 保活 + 取消兜底（时间驱动）
void fw_disc_session_tick(fw_stack_t *st, int64_t now) {
  // 保活：每 period_ms 对全部 active 会话发 NON Subscribe(TTL>0)（§7.2）
  if (now - st->disc.last_keepalive_ms >= (int64_t)st->cfg.period_ms) {
    st->disc.last_keepalive_ms = now;
    for (int i = 0; i < st->disc.nsess; i++) {
      fw_session_t *s = &st->disc.sessions[i];
      if (s->state == FW_SESS_ACTIVE && s->session_strm && s->addr[0])
        send_subscribe(st, s, 0, 0); // 保活 NON，不回确认（§8.1）
    }
  }
  // [REVIEW P1-1] 取消重传耗尽兜底：释放取消等待（§8.1 场景4；服务端靠 TTL 自愈）
  for (int i = 0; i < st->disc.ncxl; ) {
    fw_cancel_pend_t *c = &st->disc.cancels[i];
    if (c->deadline && now >= c->deadline) {
      if (c->retrans_key[0]) { fw_retransmit_cancel(&st->disc.retrans, c->retrans_key); c->retrans_key[0] = 0; }
      if (c->strm) {
        fw_strm_release_ctrl(st->strm, c->peer, c->strm);
        c->strm = 0;
      }
      st->disc.cancels[i] = st->disc.cancels[st->disc.ncxl - 1];
      st->disc.ncxl--;
      continue;
    }
    i++;
  }
}

// 收到订阅确认 ACK(Code=0x10)（§8.1）：取消重传，Found→Subscribed
void fw_disc_on_subscribe_ack(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  char peer[80];
  snprintf(peer, sizeof(peer), "%s:%u", meta->address, meta->port);
  for (int i = 0; i < st->disc.nsess; i++) {
    fw_session_t *s = &st->disc.sessions[i];
    if (s->state == FW_SESS_ESTABLISHING && s->session_strm == f->strm_id &&
        strcmp(s->peer, peer) == 0) {
      if (s->retrans_key[0]) { fw_retransmit_cancel(&st->disc.retrans, s->retrans_key); s->retrans_key[0] = 0; }
      s->state = FW_SESS_ACTIVE; // Subscribed（§7.4）
      fw_log(FW_LOG_INFO, "sd", "subscribe established: svc=%u inst=%u strm=0x%02X",
             s->svc_id, s->inst_id, s->session_strm);
      return;
    }
  }
  // 非活跃会话 StrmID 的迟到确认 → 丢弃（§3.6）
}

// 收到取消确认 ACK(Code=0x00)（§8.1）：释放会话 StrmID
// [REVIEW P1-1] 按 (peer, StrmID) 匹配取消等待表（原实现匹配 sessions 中
// cancel_deadline 会话——该槽位已被 swap 覆盖，匹配永不成功）
void fw_disc_on_unsubscribe_ack(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  char peer[80];
  snprintf(peer, sizeof(peer), "%s:%u", meta->address, meta->port);
  for (int i = 0; i < st->disc.ncxl; i++) {
    fw_cancel_pend_t *c = &st->disc.cancels[i];
    if (c->strm == f->strm_id && strcmp(c->peer, peer) == 0) {
      if (c->retrans_key[0]) { fw_retransmit_cancel(&st->disc.retrans, c->retrans_key); c->retrans_key[0] = 0; }
      fw_strm_release_ctrl(st->strm, peer, f->strm_id); // 确认到达后释放/冷却（§6.1，6.5）
      c->strm = 0;
      st->disc.cancels[i] = st->disc.cancels[st->disc.ncxl - 1];
      st->disc.ncxl--;
      fw_log(FW_LOG_INFO, "sd", "unsubscribe confirmed: peer=%s strm=0x%02X", peer, f->strm_id);
      return;
    }
  }
}

// 收到控制帧 RST（订阅被拒 / GetIDL 失败）：按回显 StrmID 匹配（§5.4）
void fw_disc_on_ctrl_rst(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  char peer[80];
  snprintf(peer, sizeof(peer), "%s:%u", meta->address, meta->port);
  // 1) 订阅会话被拒（6.19）：停止重传、释放会话 StrmID、停留 Found、报订阅失败
  for (int i = 0; i < st->disc.nsess; i++) {
    fw_session_t *s = &st->disc.sessions[i];
    if (s->state == FW_SESS_ESTABLISHING && s->session_strm == f->strm_id &&
        strcmp(s->peer, peer) == 0) {
      if (s->retrans_key[0]) { fw_retransmit_cancel(&st->disc.retrans, s->retrans_key); s->retrans_key[0] = 0; }
      fw_strm_release_ctrl(st->strm, peer, f->strm_id);
      s->session_strm = 0;
      s->state = FW_SESS_PENDING; // 登记保留（等待重试时机，§7.4）
      fw_log(FW_LOG_WARN, "sd", "subscribe rejected: RST(0x%02X) svc=%u inst=%u",
             f->code, s->svc_id, s->inst_id);
      return;
    }
  }
  // 2) GetIDL 查询失败（0x24/0x20）→ 查询失败上抛（§7.2）
  for (int i = 0; i < st->disc.nq; i++) {
    fw_idl_query_t *q = &st->disc.queries[i];
    if (!q->done && q->strm == f->strm_id && strcmp(q->peer, peer) == 0) {
      q->done = 1;
      q->err = FW_ERR_GETIDL;
      snprintf(q->msg, sizeof(q->msg), "GetIDL failed: RST(0x%02X) %s", f->code, fw_rst_name(f->code));
      fw_strm_release_ctrl(st->strm, peer, f->strm_id);
      q->strm = 0;
      fw_waiters_fire(st, &q->waiters); // 唤醒等待者（拿失败结果）
      return;
    }
  }
}
// ============================================================
// GetIDL 客户端（§7.2：协议栈内部行为，双角色统一）
// ============================================================

// 收到 GetIDL 响应 0x11（回显 StrmID，§7.2）
void fw_disc_on_getidl_resp(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  char peer[80];
  snprintf(peer, sizeof(peer), "%s:%u", meta->address, meta->port);
  for (int i = 0; i < st->disc.nq; i++) {
    fw_idl_query_t *q = &st->disc.queries[i];
    if (q->done || q->strm != f->strm_id || strcmp(q->peer, peer) != 0) continue;
    // 校验 IDL 自含 svc_id/major_ver 与请求一致（§7.2，落盘前校验）
    char jerr[96];
    fw_value_t *idl = fw_json_parse((const char *)f->payload, f->payload_len, jerr, sizeof(jerr));
    if (!idl) {
      q->done = 1;
      q->err = FW_ERR_GETIDL;
      snprintf(q->msg, sizeof(q->msg), "GetIDL response is not valid JSON: %s", jerr);
    } else {
      const fw_value_t *svc = fw_struct_get(idl, "service");
      const fw_value_t *sidv = svc ? fw_struct_get(svc, "svc_id") : NULL;
      const fw_value_t *mvv = svc ? fw_struct_get(svc, "major_ver") : NULL;
      int64_t sid = sidv ? (sidv->type == FW_V_UINT ? (int64_t)sidv->as.u
                         : (sidv->type == FW_V_INT ? sidv->as.i : 0)) : 0;
      int64_t mver = mvv ? (mvv->type == FW_V_UINT ? (int64_t)mvv->as.u
                          : (mvv->type == FW_V_INT ? mvv->as.i : -1)) : -1;
      if (!svc || sid != q->svc_id || mver != q->major_ver) {
        // 不一致按查询失败处理（IDL 库状态不变，§7.2/§11.1）
        q->done = 1;
        q->err = FW_ERR_GETIDL;
        snprintf(q->msg, sizeof(q->msg), "GetIDL response mismatch: got svc=%lld v%lld, want %u v%u",
                 (long long)sid, (long long)mver, q->svc_id, q->major_ver);
      } else {
        // 落盘持久化 → 解析加载（落盘失败降级内存由 fw_idl_save 内处理，§7.2）
        char *text = (char *)malloc((size_t)f->payload_len + 1);
        if (text) {
          memcpy(text, f->payload, f->payload_len);
          text[f->payload_len] = 0;
          if (fw_idl_save(st->idl, q->svc_id, q->major_ver, text) == FW_OK) {
            q->done = 1;
            q->err = FW_OK;
            fw_log(FW_LOG_INFO, "sd", "GetIDL fetched: svc=%u v%u (%uB)", q->svc_id, q->major_ver, f->payload_len);
          } else {
            q->done = 1;
            q->err = FW_ERR_GETIDL;
            snprintf(q->msg, sizeof(q->msg), "GetIDL response invalid for save");
          }
          free(text);
        } else {
          q->done = 1;
          q->err = FW_ERR_MEMORY;
          snprintf(q->msg, sizeof(q->msg), "out of memory");
        }
      }
      fw_value_free(idl);
    }
    // 收到响应后释放/冷却查询 StrmID（§6.1）
    fw_strm_release_ctrl(st->strm, peer, f->strm_id);
    q->strm = 0;
    fw_waiters_fire(st, &q->waiters); // 唤醒等待者（继续原操作）
    return;
  }
  // 非活跃查询 StrmID 的迟到响应 → 静默丢弃（§3.6，配合释放/冷却防误配）
}

// 发起查询状态推进（tick 驱动；连接就绪后发送请求）
static void query_pump(fw_stack_t *st, fw_idl_query_t *q, int64_t now) {
  if (q->done) return;
  if (!q->sent) {
    // 分配查询 StrmID（控制帧按 peer 统一池，§6.3；订阅会话与 GetIDL 同池）
    if (q->strm == 0) {
      int strm = fw_strm_alloc_ctrl(st->strm, q->peer);
      if (strm < 0) {
        q->done = 1;
        q->err = FW_ERR_GETIDL;
        snprintf(q->msg, sizeof(q->msg), "control StrmID pool exhausted");
        fw_waiters_fire(st, &q->waiters);
        return;
      }
      q->strm = strm;
    }
    // TCP 单播（复用 §5.6 连接策略，与 rpc/tcp-event 共用同一条长连接，§7.2）
    char err[128];
    fw_tcpconn_t *c = fw_tcp_get_conn(st, q->addr, q->port, NULL, err, sizeof(err));
    if (!c) {
      q->done = 1;
      q->err = FW_ERR_GETIDL;
      snprintf(q->msg, sizeof(q->msg), "GetIDL tcp connect failed: %s", err);
      fw_strm_release_ctrl(st->strm, q->peer, q->strm);
      q->strm = 0;
      fw_waiters_fire(st, &q->waiters);
      return;
    }
    if (!c->connected) return; // 连接中：等待下轮 tick（连接完成后此处重入）
    // 请求帧：CTR=1, TYP=NON, Code=0x04, StrmID=栈内分配, Payload=3B Entry（§7.2）
    fw_getidl_entry_t e;
    memset(&e, 0, sizeof(e));
    e.svc_id = q->svc_id;
    e.major_ver = q->major_ver;
    uint8_t buf[4];
    fw_frame_desc_t d;
    memset(&d, 0, sizeof(d));
    d.ctr = 1;
    d.typ = FW_TYP_NON;
    d.code = FW_CODE_SD_GETIDL;
    d.ver = st->cfg.ver;
    d.strm_id = (uint8_t)q->strm;
    d.payload = buf;
    d.payload_len = fw_encode_getidl_entry(buf, sizeof(buf), &e);
    fw_tcp_send_frame(st, c, &d);
    q->sent = 1;
    // 查询超时复用 response_timeout_ms（§7.2，GetIDL 为请求-响应交互，附录 A）
    q->deadline_ms = now + (int64_t)st->cfg.response_timeout_ms;
    fw_log(FW_LOG_DEBUG, "sd", "GetIDL Tx: peer=%s strm=%d svc=%u v%u", q->peer, q->strm, q->svc_id, q->major_ver);
  }
}

// 查询推进：tick 驱动（发送请求 / deadline 超时 / 完成清理）
void fw_disc_tick_queries(fw_stack_t *st, int64_t now) {
  for (int i = 0; i < st->disc.nq; ) {
    fw_idl_query_t *q = &st->disc.queries[i];
    if (q->done && !q->waiters) {
      // 完成 + 无等待者 → 释放
      st->disc.queries[i] = st->disc.queries[st->disc.nq - 1];
      st->disc.nq--;
      continue;
    }
    if (!q->done) {
      query_pump(st, q, now);
      if (!q->done && q->sent && q->deadline_ms && now >= q->deadline_ms) {
        // 查询超时：释放/冷却，查询失败上抛当前操作（§7.2 v4.4 定案：由应用决定重试）
        q->done = 1;
        q->err = FW_ERR_GETIDL;
        snprintf(q->msg, sizeof(q->msg), "GetIDL timeout (svc=%u)", q->svc_id);
        if (q->strm) {
          fw_strm_release_ctrl(st->strm, q->peer, q->strm);
          q->strm = 0;
        }
        fw_waiters_fire(st, &q->waiters);
      }
    }
    i++;
  }
}

// 查询入口：创建/合并查询；返回查询指针（调用方泵至完成）
static fw_idl_query_t *query_start(fw_stack_t *st, uint16_t svc_id, uint8_t major_ver, fw_waiter_t *w) {
  // 并发合并：同一 (SvcID, MajorVer) 并发首调合并为单次查询（§7.2 建议项）
  for (int i = 0; i < st->disc.nq; i++) {
    fw_idl_query_t *q = &st->disc.queries[i];
    if (!q->done && q->svc_id == svc_id && q->major_ver == major_ver) {
      if (w) { w->next = q->waiters; q->waiters = w; }
      return q;
    }
  }
  // 触发条件（§7.2）：查 SD 发现缓存：存在该服务在线实例 → 向其发起 GetIDL
  fw_disc_rec_t *target = NULL;
  for (int i = 0; i < st->disc.ndisc; i++) {
    fw_disc_rec_t *r = &st->disc.disc[i];
    if (r->svc_id == svc_id && r->state == FW_ST_ACTIVE) { target = r; break; }
  }
  if (!target) return NULL; // 发现缓存无在线实例 → 不发起查询，当前操作直接失败（§7.2）
  if (st->disc.nq == st->disc.qcap) {
    int nc = st->disc.qcap ? st->disc.qcap * 2 : 4;
    void *np = realloc(st->disc.queries, (size_t)nc * sizeof(fw_idl_query_t));
    if (!np) return NULL;
    st->disc.queries = np;
    st->disc.qcap = nc;
  }
  fw_idl_query_t *q = &st->disc.queries[st->disc.nq++];
  memset(q, 0, sizeof(*q));
  q->svc_id = svc_id;
  q->major_ver = major_ver;
  snprintf(q->addr, sizeof(q->addr), "%s", target->addr);
  q->port = target->port;
  snprintf(q->peer, sizeof(q->peer), "%s:%u", target->addr, target->port);
  if (w) { w->next = q->waiters; q->waiters = w; }
  return q;
}

// GetIDL 同步拉取（§7.2 双角色统一：调用/订阅/注册前本地 IDL 缺失时自动触发）。
// 查询失败（0x24/0x20/超时/断连）一律上抛当前操作（§7.2 v4.4 定案）。
fw_schema_t *fw_disc_fetch_idl(fw_stack_t *st, uint16_t svc_id, uint8_t major_ver,
                               int *err_code, char *err, int errsz) {
  // [REVIEW P2-4] 不再挂等待者（原 w 挂 q->waiters，泵期间 queries realloc 会使
  // 摘除路径的 q 指针悬空）：泵循环内逐轮按 (svc_id, major_ver) 重查条目
  if (!query_start(st, svc_id, major_ver, NULL)) {
    // 发现缓存无在线实例 → 不发起查询，当前操作直接失败（§7.2/5.22）
    if (err_code) *err_code = FW_ERR_NOT_FOUND;
    snprintf(err, (size_t)errsz, "GetIDL aborted: svc=%u has no online instance in discovery cache", svc_id);
    return NULL;
  }
  int64_t abs_deadline = now_ms(st) + (int64_t)st->cfg.response_timeout_ms * 2 + 1000;
  for (;;) {
    // [REVIEW P2-4] 每轮重查查询条目（poll 处理帧期间应用回调可能经 fw_call_async
    // → fw_disc_query_attach 触发 queries realloc，外层指针禁止跨轮持有）
    fw_idl_query_t *cur = NULL;
    for (int i = 0; i < st->disc.nq; i++) {
      fw_idl_query_t *qq = &st->disc.queries[i];
      if (qq->svc_id == svc_id && qq->major_ver == major_ver && !qq->done) { cur = qq; break; }
    }
    if (!cur) {
      // 无未完成查询：或已完成（下方 fw_idl_get 判定），或条目被清（异常）→ 退出泵
      for (int i = 0; i < st->disc.nq; i++) {
        fw_idl_query_t *qq = &st->disc.queries[i];
        if (qq->svc_id == svc_id && qq->major_ver == major_ver) {
          if (qq->done && qq->err != FW_OK) {
            if (err_code) *err_code = qq->err;
            snprintf(err, (size_t)errsz, "%s", qq->msg);
            return NULL;
          }
          break; // done 且 err=FW_OK → 跳出取定义
        }
      }
      break;
    }
    if (cur->done) {
      if (cur->err != FW_OK) {
        if (err_code) *err_code = cur->err;
        snprintf(err, (size_t)errsz, "%s", cur->msg);
        return NULL;
      }
      break;
    }
    if (st->dispatch > 0) break; // 回调内禁止泵（防御）
    st->dispatch++;
    fw_stack_poll(st, 20);
    st->dispatch--;
    if (now_ms(st) >= abs_deadline) break;
  }
  // 条目不再需要摘除 waiter（P2-4 修复点：本函数不挂 waiter）
  if (st->dispatch > 0) {
    if (err_code) *err_code = FW_ERR_GETIDL;
    snprintf(err, (size_t)errsz, "GetIDL aborted (dispatch context)");
    return NULL;
  }
  fw_idl_entry_t *e = fw_idl_get(st->idl, svc_id, major_ver);
  if (!e) {
    if (err_code) *err_code = FW_ERR_GETIDL;
    snprintf(err, (size_t)errsz, "GetIDL succeeded but definition not loaded");
    return NULL;
  }
  return (fw_schema_t *)e->schema;
}

// GetIDL 异步版（事件到达兜底等；完成无回调，结果落 idlstore）
void fw_disc_fetch_idl_async(fw_stack_t *st, uint16_t svc_id, uint8_t major_ver) {
  query_start(st, svc_id, major_ver, NULL); // tick 驱动推进
}

// TCP 连接断开：该对端 pending GetIDL 查询立即失败（§7.2；响应超时兜底冗余）
void fw_disc_on_tcp_closed(fw_stack_t *st, const char *ip) {
  size_t pl = strlen(ip);
  for (int i = 0; i < st->disc.nq; i++) {
    fw_idl_query_t *q = &st->disc.queries[i];
    if (!q->done && strncmp(q->peer, ip, pl) == 0 && q->peer[pl] == ':') {
      q->done = 1;
      q->err = FW_ERR_GETIDL;
      snprintf(q->msg, sizeof(q->msg), "GetIDL aborted: tcp connection closed (peer %s)", ip);
      if (q->strm) {
        fw_strm_release_ctrl(st->strm, q->peer, q->strm);
        q->strm = 0;
      }
      fw_waiters_fire(st, &q->waiters);
    }
  }
}

// ============================================================
// 收到 REN=1（§3.6）：清除该节点所有服务缓存与订阅登记
// ============================================================

void fw_disc_on_ren(fw_stack_t *st, const fw_meta_t *meta) {
  const char *ip = meta->address;
  fw_log(FW_LOG_INFO, "sd", "REN received from %s: clearing caches", ip);
  // 1) 发现缓存：清除该源 IP 的所有实例（§3.6）
  for (int i = 0; i < st->disc.ndisc; ) {
    fw_disc_rec_t *r = &st->disc.disc[i];
    if (strcmp(r->addr, ip) == 0) {
      // 订阅登记清除条件②：对端 REN → 登记同步清除，不自动重订阅（§7.4/6.13）
      for (int k = 0; k < st->disc.nsess; ) {
        fw_session_t *s = &st->disc.sessions[k];
        if (s->svc_id == r->svc_id && s->inst_id == r->inst_id) {
          if (s->retrans_key[0]) fw_retransmit_cancel(&st->disc.retrans, s->retrans_key);
          if (s->session_strm) fw_strm_release_ctrl(st->strm, s->peer, s->session_strm);
          st->disc.sessions[k] = st->disc.sessions[st->disc.nsess - 1];
          st->disc.nsess--;
          continue;
        }
        k++;
      }
      st->disc.disc[i] = st->disc.disc[st->disc.ndisc - 1];
      st->disc.ndisc--;
      continue;
    }
    i++;
  }
  // 2) 服务端：清除该对端订阅登记（§3.6）
  for (int i = 0; i < st->disc.nsubs; ) {
    if (strcmp(st->disc.subs[i].peer_ip, ip) == 0) {
      st->disc.subs[i] = st->disc.subs[st->disc.nsubs - 1];
      st->disc.nsubs--;
    } else i++;
  }
  // 3) [REVIEW P1-1] 清取消等待（对齐 JS onRen 的 cancelPending.clear()；
  //    StrmID 池由后续 fw_strm_reset_peer 统一重置，此处仅摘重传与表项）
  for (int i = 0; i < st->disc.ncxl; ) {
    if (strncmp(st->disc.cancels[i].peer, ip, strlen(ip)) == 0 &&
        st->disc.cancels[i].peer[strlen(ip)] == ':') { // [REVIEW P2-2] ':' 界定防 IP 前缀撞车
      if (st->disc.cancels[i].retrans_key[0])
        fw_retransmit_cancel(&st->disc.retrans, st->disc.cancels[i].retrans_key);
      st->disc.cancels[i] = st->disc.cancels[st->disc.ncxl - 1];
      st->disc.ncxl--;
    } else i++;
  }
  // 4) 确认缓存清理（[REVIEW P2-2] key 格式 "ip:port|strm"：前缀匹配须以 ':' 界定，
  //    防 "1.2.3.4" 误清 "1.2.3.45" 的确认缓存——对齐 JS startsWith(`${ip}:`)）
  for (int i = 0; i < st->disc.nack; ) {
    const char *k = st->disc.ack[i].key;
    if (strncmp(k, ip, strlen(ip)) == 0 && k[strlen(ip)] == ':') {
      st->disc.ack[i] = st->disc.ack[st->disc.nack - 1];
      st->disc.nack--;
    } else i++;
  }
}
// ============================================================
// 异步等待入口（rpc 状态机使用）
// ============================================================

// 异步 Find：已命中返回 FW_OK 并填 out；等待中返回 FW_WAITING（w 挂接 pend_find）；
// 失败返回错误码（对齐 fw_disc_find 的同步语义，供 call 状态机驱动）
int fw_disc_find_start(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                       fw_waiter_t *w, fw_svc_info_t *out, char *err, int errsz) {
  fw_disc_rec_t *r = fw_disc_get_discovered(st, svc_id, inst_id);
  if (r) {
    if (out) {
      snprintf(out->address, sizeof(out->address), "%s", r->addr);
      out->port = r->port;
      out->major_ver = r->major_ver;
      out->minor_ver = r->minor_ver;
    }
    return FW_OK;
  }
  // 发 Find（组播；带 Entry 指定 SvcID，InstID 通配或精确，§7.2）
  fw_find_entry_t q;
  memset(&q, 0, sizeof(q));
  q.svc_id = svc_id;
  q.inst_id = inst_id;
  q.major_ver = 0;
  uint8_t buf[8];
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 1;
  d.typ = FW_TYP_NON;
  d.code = FW_CODE_SD_FIND;
  d.ver = st->cfg.ver;
  d.payload = buf;
  d.payload_len = fw_encode_find_entries(buf, sizeof(buf), &q, 1);
  fw_udp_send_mcast_frame(st, &d, 0);
  // §2 组播不可用降级：对 Expired 记录的最近已知地址补发单播 Find（单播路径不受组播限制）
  for (int i = 0; i < st->disc.ndisc; i++) {
    fw_disc_rec_t *r = &st->disc.disc[i];
    if (r->svc_id != svc_id) continue;
    if (r->inst_id != inst_id && r->inst_id != 0 && inst_id != 0) continue;
    if (r->state != FW_ST_EXPIRED || r->addr[0] == 0) continue;
    fw_udp_send_frame(st, &d, r->addr, r->port, 0);
  }
  // 登记/复用 pend_find + 挂接等待者（Offer 到达时唤醒）
  fw_pend_find_t *p = NULL;
  for (int i = 0; i < st->disc.npf; i++) {
    if (st->disc.pf[i].svc_id == svc_id && st->disc.pf[i].inst_id == inst_id) { p = &st->disc.pf[i]; break; }
  }
  if (!p) {
    if (st->disc.npf == st->disc.pfcap) {
      int nc = st->disc.pfcap ? st->disc.pfcap * 2 : 8;
      void *np = realloc(st->disc.pf, (size_t)nc * sizeof(fw_pend_find_t));
      if (!np) { snprintf(err, (size_t)errsz, "out of memory"); return FW_ERR_MEMORY; }
      st->disc.pf = np;
      st->disc.pfcap = nc;
    }
    p = &st->disc.pf[st->disc.npf++];
    memset(p, 0, sizeof(*p));
    p->svc_id = svc_id;
    p->inst_id = inst_id;
  }
  p->deadline_ms = now_ms(st) + st->cfg.response_timeout_ms;
  if (w) {
    w->kind = FW_W_CALL; // 由等待方自定（call ctx 传 FW_W_CALL）
    w->next = p->waiters;
    p->waiters = w;
  }
  (void)err;
  return FW_WAITING;
}

// GetIDL 查询挂接：创建/合并查询并挂 waiter；无在线实例返回 NULL（err 填原因，§7.2/5.22）
fw_idl_query_t *fw_disc_query_attach(fw_stack_t *st, uint16_t svc_id, uint8_t major_ver,
                                     fw_waiter_t *w, char *err, int errsz) {
  // 触发条件（§7.2）：发现缓存无在线实例 → 不发起查询
  int has_target = 0;
  for (int i = 0; i < st->disc.ndisc; i++) {
    if (st->disc.disc[i].svc_id == svc_id && st->disc.disc[i].state == FW_ST_ACTIVE) { has_target = 1; break; }
  }
  if (!has_target) {
    snprintf(err, (size_t)errsz, "GetIDL aborted: svc=%u has no online instance in discovery cache", svc_id);
    return NULL;
  }
  // 并发合并：同一 (SvcID, MajorVer) 并发首调合并为单次查询（§7.2 建议项）
  for (int i = 0; i < st->disc.nq; i++) {
    fw_idl_query_t *q = &st->disc.queries[i];
    if (!q->done && q->svc_id == svc_id && q->major_ver == major_ver) {
      if (w) { w->next = q->waiters; q->waiters = w; }
      return q;
    }
  }
  if (st->disc.nq == st->disc.qcap) {
    int nc = st->disc.qcap ? st->disc.qcap * 2 : 4;
    void *np = realloc(st->disc.queries, (size_t)nc * sizeof(fw_idl_query_t));
    if (!np) { snprintf(err, (size_t)errsz, "out of memory"); return NULL; }
    st->disc.queries = np;
    st->disc.qcap = nc;
  }
  fw_idl_query_t *q = &st->disc.queries[st->disc.nq++];
  memset(q, 0, sizeof(*q));
  q->svc_id = svc_id;
  q->major_ver = major_ver;
  // 记录目标（发现缓存首个在线实例）
  for (int i = 0; i < st->disc.ndisc; i++) {
    fw_disc_rec_t *r = &st->disc.disc[i];
    if (r->svc_id == svc_id && r->state == FW_ST_ACTIVE) {
      snprintf(q->addr, sizeof(q->addr), "%s", r->addr);
      q->port = r->port;
      break;
    }
  }
  snprintf(q->peer, sizeof(q->peer), "%s:%u", q->addr, q->port);
  if (w) { w->next = q->waiters; q->waiters = w; }
  return q;
}
// 全量推送钩子（订阅记录从无到有，§8.1）——委托 events 模块
void fw_disc_on_subscription_added(fw_stack_t *st, const fw_meta_t *meta,
                                   const fw_sub_entry_t *entries, int n) {
  fw_events_push_cached_for(st, meta, entries, n);
}