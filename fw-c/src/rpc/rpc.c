// ============================================================
// rpc.c —— §5.1 Request-Response / §5.2 Fire-Forget
//
// 客户端：call / call_async / fire_forget
//   - 发送前确保发现缓存与 IDL 就绪（拉取发生在发送前，§5.1/§7.2）
//   - TCP：TYP=NON，无重传（§3.7/§5.6）；UDP：TYP=CON + 重传时间线（§5.5）
//   - 应用层响应超时（§1.3）：收到 Response 取消，并一并取消该 StrmID 的待确认重传
// 服务端：onRequest / onFireForget
//   - 响应缓存去重（§5.5）：重复 CON Request → 重发缓存响应，处理逻辑仅执行 1 次
//   - 未知服务/接口 → RST(0x24)；类型不支持 → RST(0x25)；IDL 级解码失败 → RST(0x20)；
//     处理异常 → RST(0x30)（§5.4/§12.1）
// ============================================================

#include "../fw_int.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int64_t now_ms(fw_stack_t *st) {
  return st->clock_override ? st->clock_override() : fw_now_ms();
}

void fw_rpc_init(fw_stack_t *st) {
  memset(&st->rpc, 0, sizeof(st->rpc));
  fw_retransmit_init(&st->rpc.retrans, st->cfg.retransmit_interval_ms, st->cfg.retransmit_max);
}

void fw_rpc_free(fw_stack_t *st) {
  fw_retransmit_free(&st->rpc.retrans);
  for (fw_call_ctx_t *c = st->rpc.pending; c; ) {
    fw_call_ctx_t *nx = c->next;
    fw_value_free(c->payload);
    fw_value_free(c->resp);
    free(c);
    c = nx;
  }
  for (fw_call_ctx_t *c = st->rpc.ff_pending; c; ) {
    fw_call_ctx_t *nx = c->next;
    fw_value_free(c->payload);
    free(c);
    c = nx;
  }
  for (int i = 0; i < st->rpc.ncache; i++) {
    free(st->rpc.cache[i].ack_raw);
    free(st->rpc.cache[i].resp_raw);
  }
  free(st->rpc.cache);
  memset(&st->rpc, 0, sizeof(st->rpc));
}

void fw_call_ctx_free(fw_stack_t *st, fw_call_ctx_t *ctx) {
  (void)st;
  // [REVIEW P3-12] 从全量活动链摘除（所有释放路径统一经过此处）
  for (fw_call_ctx_t **pp = &st->rpc.active; *pp; pp = &(*pp)->anext) {
    if (*pp == ctx) { *pp = ctx->anext; ctx->anext = NULL; break; }
  }
  fw_value_free(ctx->payload);
  fw_value_free(ctx->resp);
  free(ctx);
}

// ---- 发送 helper ----

static void send_udp_ack(fw_stack_t *st, const fw_frame_t *echo, const fw_meta_t *meta, int which) {
  // 数据帧空确认 ACK：CTR=0, TYP=ACK, Code=0x00，回显四标识（§3.7）
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 0;
  d.typ = FW_TYP_ACK;
  d.code = 0x00;
  d.ver = st->cfg.ver;
  d.svc_id = echo->svc_id;
  d.if_id = echo->if_id;
  d.inst_id = echo->inst_id;
  d.strm_id = echo->strm_id;
  fw_udp_send_frame(st, &d, meta->address, meta->port, which);
}

static void send_rst(fw_stack_t *st, int code, const fw_frame_t *echo, const fw_meta_t *meta) {
  fw_frame_desc_t d;
  fw_make_rst(&d, code, echo->ctr, echo->svc_id, echo->if_id, echo->inst_id, echo->strm_id);
  if (meta->transport == 1) {
    if (meta->conn) fw_tcp_send_frame(st, meta->conn, &d);
  } else {
    fw_udp_send_frame(st, &d, meta->address, meta->port, 1);
  }
  fw_log_frame(FW_LOG_WARN, echo->svc_id, echo->if_id, echo->inst_id, echo->strm_id,
               "Tx", meta->address, code, fw_rst_name(code));
}

// ============================================================
// 客户端（§5.1/§5.2/§13.2）
// ============================================================

fw_call_ctx_t *fw_call_ctx_new(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                               fw_value_t *payload, int is_ff, uint32_t timeout_ms) {
  fw_call_ctx_t *ctx = (fw_call_ctx_t *)calloc(1, sizeof(fw_call_ctx_t));
  if (!ctx) { fw_value_free(payload); return NULL; }
  ctx->svc_id = svc_id;
  ctx->inst_id = inst_id;
  ctx->if_id = if_id;
  ctx->is_ff = is_ff;
  ctx->payload = payload; // 所有权转移
  ctx->stage = FW_STAGE_RESOLVE;
  ctx->timeout_ms = timeout_ms ? timeout_ms : st->cfg.response_timeout_ms;
  ctx->deadline_ms = now_ms(st) + (int64_t)ctx->timeout_ms; // resolve 阶段总超时（§1.3 唯一终态）
  // 内嵌等待者自指（waiters_fire 回调定位 ctx——缺失将导致 advance(st, NULL) UB）
  ctx->w.kind = FW_W_CALL;
  ctx->w.ctx = ctx;
  // [REVIEW P3-12] 登记全量活动链（含 resolve 阶段 async ctx——原实现仅 wait 阶段
  // 在 pending/ff_pending 链，resolve/send 阶段挂起的 async ctx 无处枚举，stop 悬挂）
  ctx->anext = st->rpc.active;
  st->rpc.active = ctx;
  return ctx;
}

// [REVIEW P3-12] stop 前冲刷全部未完成调用：async ctx 以 err 触发完成回调（不悬挂）；
// 同步 ctx（cb 为空，仅同线程泵场景存在）标记终态防泄漏。遍历中 free 会修改链头。
void fw_rpc_flush_all_pending(fw_stack_t *st, int err, const char *msg) {
  fw_call_ctx_t *c = st->rpc.active;
  while (c) {
    fw_call_ctx_t *nx = c->anext; // 预存（notify_done→free 会摘除 c 自身）
    if (!c->done) {
      if (c->key[0]) fw_retransmit_cancel(&st->rpc.retrans, c->key);
      if (c->strm && c->peer[0])
        fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1;
      c->err = err;
      snprintf(c->msg, sizeof(c->msg), "%s", msg);
      fw_call_advance_notify_done(st, c); // 摘挂接点 + async 触发回调 + free
    }
    c = nx;
  }
}

// ctx 完成（结果已置）；从 pending 链移除 + 释放传输资源
static void call_finish(fw_stack_t *st, fw_call_ctx_t *ctx) {
  if (ctx->done) return;
  ctx->done = 1;
  if (ctx->strm && ctx->peer[0]) {
    if (ctx->is_ff) {
      // ff：ACK/耗尽路径已释放；此处兜底
      fw_strm_release_client(st->strm, ctx->peer, ctx->svc_id, ctx->inst_id, ctx->strm);
    } else {
      fw_strm_release_client(st->strm, ctx->peer, ctx->svc_id, ctx->inst_id, ctx->strm); // §6.2 Stream 释放
    }
  }
  if (ctx->key[0]) fw_retransmit_cancel(&st->rpc.retrans, ctx->key); // §5.1：一并取消待确认重传
  fw_call_advance_notify_done(st, ctx); // async 场景触发回调（同步泵轮询 done 标志）
}

// advance：推进调用状态机（resolve → send → wait）
void fw_call_advance(fw_stack_t *st, void *p) {
  fw_call_ctx_t *ctx = (fw_call_ctx_t *)p;
  if (ctx->done) return;
  // §1.3：应用层响应超时是调用的唯一终态——resolve/send 阶段同样受 deadline 约束
  //（IDL 拉取/Find 等待失败的无限重试被 deadline 掐断，防状态机活锁）
  if (ctx->stage != FW_STAGE_WAIT && now_ms(st) >= ctx->deadline_ms) {
    ctx->done = 1;
    ctx->err = FW_ERR_TIMEOUT;
    snprintf(ctx->msg, sizeof(ctx->msg), "call svc=%u if=0x%04X timeout during resolve (%ums)",
             ctx->svc_id, ctx->if_id, ctx->timeout_ms);
    if (ctx->key[0]) fw_retransmit_cancel(&st->rpc.retrans, ctx->key);
    if (ctx->strm && ctx->peer[0])
      fw_strm_release_client(st->strm, ctx->peer, ctx->svc_id, ctx->inst_id, ctx->strm);
    fw_call_advance_notify_done(st, ctx);
    return;
  }

  if (ctx->stage == FW_STAGE_RESOLVE) {
      // ---- 解析调用目标：发现缓存 → 主动 Find → IDL 自动拉取（§5.1/§7.2） ----
    fw_disc_rec_t *rec = fw_disc_get_discovered(st, ctx->svc_id, ctx->inst_id);
    if (!rec) {
      // 缓存未命中 → 发 Find 等待 Offer（§7.2）；等待者 w 挂 pend_find
      fw_svc_info_t info;
      char err[160];
      int r = fw_disc_find_start(st, ctx->svc_id, ctx->inst_id, &ctx->w, &info, err, sizeof(err));
      if (r == FW_OK) {
        // 已命中（同步返回）
      } else if (r == FW_WAITING) {
        return; // 等待 Offer 唤醒（waiter fire → 再次 advance）
      } else {
        ctx->err = r;
        snprintf(ctx->msg, sizeof(ctx->msg), "%s", err);
        call_finish(st, ctx);
        return;
      }
      rec = fw_disc_get_discovered(st, ctx->svc_id, ctx->inst_id);
      if (!rec) {
        ctx->err = FW_ERR_NOT_FOUND;
        snprintf(ctx->msg, sizeof(ctx->msg), "svc=%u inst=%u not discovered", ctx->svc_id, ctx->inst_id);
        call_finish(st, ctx);
        return;
      }
    }
    // IDL：本地库命中不查询；缺失 → 自动 GetIDL 拉取落盘（§7.2/5.21）
    fw_idl_entry_t *e = fw_idl_get(st->idl, ctx->svc_id, rec->major_ver);
    if (!e) {
      // 版本升级自动重新拉取（§7.2）：登记等待者到 GetIDL 查询
      int done_flag = 0;
      (void)done_flag;
      ctx->w.kind = FW_W_CALL;
      ctx->w.ctx = ctx;
      ctx->w.next = NULL;
      fw_idl_query_t *q = fw_disc_query_attach(st, ctx->svc_id, rec->major_ver, &ctx->w,
                                               ctx->msg, sizeof(ctx->msg));
      if (!q) {
        ctx->err = FW_ERR_NOT_FOUND;
        snprintf(ctx->msg, sizeof(ctx->msg), "GetIDL aborted: svc=%u no online instance", ctx->svc_id);
        call_finish(st, ctx);
        return;
      }
      return; // 等待查询完成唤醒
    }
    ctx->schema = (fw_schema_t *)e->schema;
    ctx->stage = FW_STAGE_SEND;
    // fallthrough 到 SEND
  }

  if (ctx->stage == FW_STAGE_SEND) {
    // ---- 接口校验 + 编码 + 发送（拉取发生在发送前，§5.1） ----
    fw_iface_t *iface = fw_schema_iface(ctx->schema, ctx->if_id);
    if (!iface) {
      ctx->err = FW_ERR_NOT_FOUND;
      snprintf(ctx->msg, sizeof(ctx->msg), "if_id 0x%04X not found in svc=%u v%u",
               ctx->if_id, ctx->svc_id, ctx->schema->major_ver);
      call_finish(st, ctx);
      return;
    }
    const char *want = ctx->is_ff ? "ff" : "rpc";
    const char *got = iface->type == FW_IF_RPC ? "rpc" : (iface->type == FW_IF_FF ? "ff" : "event");
    if (strcmp(got, want) != 0) {
      ctx->err = FW_ERR_PARAM;
      snprintf(ctx->msg, sizeof(ctx->msg), "if_id 0x%04X is %s, not %s", ctx->if_id, got, want);
      call_finish(st, ctx);
      return;
    }
    // 编码 payload（接口 input 方向）
    fw_buf_t body;
    fw_buf_init(&body);
    char eerr[128];
    int r = fw_encode_payload(ctx->schema, iface, 0, ctx->payload, &body, eerr, sizeof(eerr));
    if (r != FW_OK) {
      fw_buf_free(&body);
      ctx->err = FW_ERR_ENCODE;
      snprintf(ctx->msg, sizeof(ctx->msg), "encode payload failed: %s", eerr[0] ? eerr : fw_rst_name(-r));
      call_finish(st, ctx);
      return;
    }
    // 记录目标
    fw_disc_rec_t *rec = fw_disc_get_discovered(st, ctx->svc_id, ctx->inst_id);
    if (!rec) {
      fw_buf_free(&body);
      ctx->err = FW_ERR_NOT_FOUND;
      snprintf(ctx->msg, sizeof(ctx->msg), "svc=%u inst=%u not discovered", ctx->svc_id, ctx->inst_id);
      call_finish(st, ctx);
      return;
    }
    snprintf(ctx->addr, sizeof(ctx->addr), "%s", rec->addr);
    ctx->port = rec->port;
    snprintf(ctx->peer, sizeof(ctx->peer), "%s:%u", rec->addr, rec->port);
    // 分配客户端流 StrmID（§6.1）
    ctx->strm = fw_strm_alloc_client(st->strm, ctx->peer, ctx->svc_id, ctx->inst_id);
    if (ctx->strm < 0) {
      fw_buf_free(&body);
      ctx->err = FW_ERR_STATE;
      snprintf(ctx->msg, sizeof(ctx->msg), "client StrmID pool exhausted for %s", ctx->peer);
      call_finish(st, ctx);
      return;
    }
    snprintf(ctx->key, sizeof(ctx->key), "%s|%u|%u|%d", ctx->peer, ctx->svc_id, ctx->inst_id, ctx->strm);
    ctx->is_udp = (iface->transport == FW_TR_UDP);
    ctx->iface = iface;

    if (!ctx->is_udp) {
      // TCP：TYP=NON，协议栈不重传（§5.1/§3.7）
      char err[128];
      fw_tcpconn_t *c = fw_tcp_get_conn(st, ctx->addr, ctx->port, &ctx->w, err, sizeof(err));
      if (!c) {
        fw_buf_free(&body);
        ctx->err = FW_ERR_CONN;
        snprintf(ctx->msg, sizeof(ctx->msg), "tcp connect failed: %s", err);
        call_finish(st, ctx);
        return;
      }
      if (!c->connected) {
        fw_buf_free(&body);
        return; // 等待连接完成唤醒（waiter fire → 再次 advance）
      }
      fw_frame_desc_t d;
      memset(&d, 0, sizeof(d));
      d.ctr = 0;
      d.typ = FW_TYP_NON;
      d.code = ctx->is_ff ? FW_CODE_FF : FW_CODE_REQUEST;
      d.ver = st->cfg.ver;
      d.svc_id = ctx->svc_id;
      d.if_id = ctx->if_id;
      d.inst_id = ctx->inst_id;
      d.strm_id = (uint8_t)ctx->strm;
      d.payload = body.p;
      d.payload_len = (uint32_t)body.len;
      fw_tcp_send_frame(st, c, &d);
      fw_buf_free(&body);
      if (ctx->is_ff) {
        // TCP FF：发完即释放（传输可靠性由 TCP 保证，§5.2/§6.2）
        call_finish(st, ctx);
        return;
      }
    } else {
      // UDP：TYP=CON，首发 t=0 + 重传表（200/600/1400ms，3000ms 静默停止，§5.5）
      fw_frame_desc_t d;
      memset(&d, 0, sizeof(d));
      d.ctr = 0;
      d.typ = FW_TYP_CON;
      d.code = ctx->is_ff ? FW_CODE_FF : FW_CODE_REQUEST;
      d.ver = st->cfg.ver;
      d.svc_id = ctx->svc_id;
      d.if_id = ctx->if_id;
      d.inst_id = ctx->inst_id;
      d.strm_id = (uint8_t)ctx->strm;
      d.payload = body.p;
      d.payload_len = (uint32_t)body.len;
      uint8_t raw[1600];
      uint32_t rlen = fw_frame_encode(raw, sizeof(raw), &d);
      if (!rlen) {
        fw_buf_free(&body);
        ctx->err = FW_ERR_ENCODE;
        snprintf(ctx->msg, sizeof(ctx->msg), "frame encode failed");
        call_finish(st, ctx);
        return;
      }
      fw_udp_sendto_raw(st, ctx->addr, ctx->port, 0, raw, rlen);
      fw_retransmit_start(&st->rpc.retrans, ctx->key, raw, rlen, ctx->addr, ctx->port, 0, now_ms(st));
      fw_buf_free(&body);
      if (ctx->is_ff) {
        // UDP FF：等传输层 ACK；无应用层超时，重传耗尽静默停止（§5.5）
        ctx->stage = FW_STAGE_WAIT;
        ctx->deadline_ms = now_ms(st) +
          (int64_t)st->cfg.retransmit_interval_ms * (1 << (st->cfg.retransmit_max + 1)) + 200; // 兜底释放
        // 挂 ff_pending 链
        ctx->next = st->rpc.ff_pending;
        st->rpc.ff_pending = ctx;
        return;
      }
    }
    // 登记等待响应（§5.1 应用层响应超时）
    ctx->stage = FW_STAGE_WAIT;
    ctx->deadline_ms = now_ms(st) + (int64_t)ctx->timeout_ms; // §5.1 响应超时自首次发送起计
    // wait 阶段 deadline 由调用入口设置（response_timeout）
    ctx->next = st->rpc.pending;
    st->rpc.pending = ctx;
    return;
  }
  // FW_STAGE_WAIT：等待响应（onResponse/onDataRst/tick 驱动），无主动推进
}

// 同步放弃时从全部挂接点摘除 ctx->w（防悬空：ctx 释放后 waiter 被触发 = UB）
void fw_call_detach(fw_stack_t *st, fw_call_ctx_t *ctx) {
  // 1) conn.waiters
  for (int i = 0; i < st->nconn; i++) {
    fw_tcpconn_t *cn = st->conns[i];
    if (!cn || cn->closed) continue;
    for (fw_waiter_t **pp = &cn->waiters; *pp; pp = &(*pp)->next) {
      if (*pp == &ctx->w) { *pp = ctx->w.next; break; }
    }
  }
  // 2) pend_find.waiters
  for (int i = 0; i < st->disc.npf; i++) {
    for (fw_waiter_t **pp = &st->disc.pf[i].waiters; *pp; pp = &(*pp)->next) {
      if (*pp == &ctx->w) { *pp = ctx->w.next; break; }
    }
  }
  // 3) idl query.waiters
  for (int i = 0; i < st->disc.nq; i++) {
    for (fw_waiter_t **pp = &st->disc.queries[i].waiters; *pp; pp = &(*pp)->next) {
      if (*pp == &ctx->w) { *pp = ctx->w.next; break; }
    }
  }
}// ============================================================
// 客户端接收（Response / ACK / RST）
// ============================================================

// 收到 Response（CTR=0, Code=0x10，回显请求 StrmID，§5.1）
static void on_response(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  const char *peer = meta->address;
  char key[224];
  snprintf(key, sizeof(key), "%s:%u|%u|%u|%u", peer, meta->port, f->svc_id, f->inst_id, f->strm_id);
  int is_udp_con = (meta->transport == 0 && f->typ == FW_TYP_CON);
  // 查找 pending（wait 阶段链表）
  fw_call_ctx_t **pp = &st->rpc.pending;
  fw_call_ctx_t *ctx = NULL;
  for (; *pp; pp = &(*pp)->next) {
    if (strcmp((*pp)->key, key) == 0) { ctx = *pp; break; }
  }
  if (!ctx) {
    // 重复/迟到响应（§5.5）：按 StrmID 判定为重复，只交付首个；UDP CON 仍须回 ACK
    if (is_udp_con) send_udp_ack(st, f, meta, 0);
    return;
  }
  // 完成：取消重传/超时，释放流（§6.2 Active→Closed）
  *pp = ctx->next;
  ctx->next = NULL;
  if (ctx->key[0]) fw_retransmit_cancel(&st->rpc.retrans, ctx->key);
  if (ctx->peer[0] && ctx->strm)
    fw_strm_release_client(st->strm, ctx->peer, ctx->svc_id, ctx->inst_id, ctx->strm);
  if (is_udp_con) send_udp_ack(st, f, meta, 0);
  // 解码交付（解码容忍末尾新增字段，§9.4；响应按 IDL output 方向解码 §5.1）
  char eerr[128];
  int r = fw_decode_payload(ctx->schema, ctx->iface, 1, f->payload, f->payload_len, &ctx->resp,
                            eerr, sizeof(eerr));
  ctx->done = 1;
  if (r != FW_OK) {
    ctx->err = FW_ERR_DECODE;
    snprintf(ctx->msg, sizeof(ctx->msg), "response decode failed: %s", eerr[0] ? eerr : fw_rst_name(-r));
    fw_value_free(ctx->resp);
    ctx->resp = NULL;
  } else {
    ctx->err = FW_OK;
    ctx->msg[0] = 0;
  }
  fw_call_advance_notify_done(st, ctx);
}

// 收到数据帧空确认 ACK（CTR=0, Code=0x00，§3.7）：取消待确认重传 / 清响应缓存
static void on_ack(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  char key[224];
  snprintf(key, sizeof(key), "%s:%u|%u|%u|%u", meta->address, meta->port,
           f->svc_id, f->inst_id, f->strm_id);
  fw_retransmit_cancel(&st->rpc.retrans, key);
  // 服务端角色：客户端对 Response(CON) 的确认 → 响应缓存随 Stream 释放清除（§5.5）
  for (int i = 0; i < st->rpc.ncache; i++) {
    if (strcmp(st->rpc.cache[i].key, key) == 0) {
      free(st->rpc.cache[i].ack_raw);
      free(st->rpc.cache[i].resp_raw);
      st->rpc.cache[i] = st->rpc.cache[st->rpc.ncache - 1];
      st->rpc.ncache--;
      return;
    }
  }
  // 客户端角色：fire_forget 的传输确认 → 释放流（§6.2）
  for (fw_call_ctx_t **pp = &st->rpc.ff_pending; *pp; pp = &(*pp)->next) {
    fw_call_ctx_t *c = *pp;
    if (strcmp(c->key, key) == 0) {
      *pp = c->next;
      c->next = NULL;
      if (c->peer[0] && c->strm)
        fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1;
      c->err = FW_OK;
      fw_call_advance_notify_done(st, c);
      return;
    }
  }
}

// 收到数据帧 RST（§5.4：记录错误，释放 Stream）
static void on_data_rst(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  char key[224];
  snprintf(key, sizeof(key), "%s:%u|%u|%u|%u", meta->address, meta->port,
           f->svc_id, f->inst_id, f->strm_id);
  fw_retransmit_cancel(&st->rpc.retrans, key);
  // 响应缓存清除
  for (int i = 0; i < st->rpc.ncache; i++) {
    if (strcmp(st->rpc.cache[i].key, key) == 0) {
      free(st->rpc.cache[i].ack_raw);
      free(st->rpc.cache[i].resp_raw);
      st->rpc.cache[i] = st->rpc.cache[st->rpc.ncache - 1];
      st->rpc.ncache--;
      break;
    }
  }
  // pending 调用：reject
  for (fw_call_ctx_t **pp = &st->rpc.pending; *pp; pp = &(*pp)->next) {
    fw_call_ctx_t *c = *pp;
    if (strcmp(c->key, key) == 0) {
      *pp = c->next;
      c->next = NULL;
      if (c->peer[0] && c->strm)
        fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1;
      c->err = FW_ERR_RST;
      c->rst_code = f->code;
      snprintf(c->msg, sizeof(c->msg), "call rejected: RST(%s)", fw_rst_name(f->code));
      fw_call_advance_notify_done(st, c);
      return;
    }
  }
  // ff 待确认：释放
  for (fw_call_ctx_t **pp = &st->rpc.ff_pending; *pp; pp = &(*pp)->next) {
    fw_call_ctx_t *c = *pp;
    if (strcmp(c->key, key) == 0) {
      *pp = c->next;
      c->next = NULL;
      if (c->peer[0] && c->strm)
        fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1;
      c->err = FW_ERR_RST;
      c->rst_code = f->code;
      snprintf(c->msg, sizeof(c->msg), "fire_forget rejected: RST(%s)", fw_rst_name(f->code));
      fw_call_advance_notify_done(st, c);
      return;
    }
  }
  fw_log_frame(FW_LOG_WARN, f->svc_id, f->if_id, f->inst_id, f->strm_id,
               "Rx", meta->address, f->code, "RST received (rpc stream released)");
}
// ============================================================
// 服务端（§5.1/§5.2/§5.5 去重/§13.3 处理契约）
// ============================================================

// 收到 Request / Fire-Forget（CTR=0, Code=0x01/0x02）
static void handle_client_call(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta, int is_ff) {
  char key[224];
  snprintf(key, sizeof(key), "%s:%u|%u|%u|%u", meta->address, meta->port,
           f->svc_id, f->inst_id, f->strm_id);
  int is_udp = (meta->transport == 0);

  // ---- 响应缓存去重（§5.5 服务端规则：重复 CON 请求重发缓存响应，不重新执行） ----
  for (int i = 0; i < st->rpc.ncache; i++) {
    fw_resp_cache_t *c = &st->rpc.cache[i];
    if (strcmp(c->key, key) == 0) {
      if (c->done && c->resp_raw) {
        fw_udp_sendto_raw(st, meta->address, meta->port, 1, c->resp_raw, c->resp_len); // 重发缓存响应
      } else if (c->ack_raw) {
        fw_udp_sendto_raw(st, meta->address, meta->port, 1, c->ack_raw, c->ack_len); // 处理中：重发传输确认
      }
      return;
    }
  }

  // UDP CON：回空确认 ACK（传输层确认，§3.7）——TCP 不使用 CON/ACK
  uint8_t ack_raw[32];
  uint32_t ack_len = 0;
  if (is_udp && f->typ == FW_TYP_CON) {
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
    ack_len = fw_frame_encode(ack_raw, sizeof(ack_raw), &d);
    fw_udp_sendto_raw(st, meta->address, meta->port, 1, ack_raw, ack_len);
  }

  // ---- 实例 / 接口校验（§5.4：未知服务/接口 → RST(0x24)；Code 不支持 → RST(0x25)） ----
  fw_local_t *rec = fw_disc_get_local(st, f->svc_id, f->inst_id);
  if (!rec) { send_rst(st, FW_RST_NOT_FOUND, f, meta); return; }
  fw_iface_t *iface = fw_schema_iface(rec->schema, f->if_id);
  if (!iface) { send_rst(st, FW_RST_NOT_FOUND, f, meta); return; }
  const char *want = is_ff ? "ff" : "rpc";
  const char *got = iface->type == FW_IF_RPC ? "rpc" : (iface->type == FW_IF_FF ? "ff" : "event");
  if (strcmp(got, want) != 0) { send_rst(st, FW_RST_METHOD, f, meta); return; }

  // ---- 解码（IDL 级契约违约统一归 RST(0x20)，§12.1 两层两码） ----
  fw_value_t *payload = NULL;
  char eerr[128];
  int r = fw_decode_payload(rec->schema, iface, 0, f->payload, f->payload_len, &payload,
                            eerr, sizeof(eerr));
  if (r != FW_OK) {
    fw_log(FW_LOG_ERROR, "rpc", "decode failed svc=%u if=0x%04X r=%d: %s",
           f->svc_id, f->if_id, r, eerr[0] ? eerr : fw_rst_name(-r));
    send_rst(st, FW_RST_BAD_REQUEST, f, meta);
    return;
  }

  // ---- 建立响应缓存（仅 UDP：重传去重；TCP 无重传无需缓存，§5.5） ----
  if (is_udp) {
    if (st->rpc.ncache == st->rpc.cachecap) {
      int nc = st->rpc.cachecap ? st->rpc.cachecap * 2 : 8;
      void *np = realloc(st->rpc.cache, (size_t)nc * sizeof(fw_resp_cache_t));
      if (!np) { fw_value_free(payload); send_rst(st, FW_RST_INTERNAL, f, meta); return; }
      st->rpc.cache = np;
      st->rpc.cachecap = nc;
    }
    fw_resp_cache_t *c = &st->rpc.cache[st->rpc.ncache++];
    memset(c, 0, sizeof(*c));
    snprintf(c->key, sizeof(c->key), "%s", key);
    if (ack_len) {
      c->ack_raw = (uint8_t *)malloc(ack_len);
      if (c->ack_raw) { memcpy(c->ack_raw, ack_raw, ack_len); c->ack_len = ack_len; }
    }
    c->expiry = now_ms(st) +
      (int64_t)st->cfg.retransmit_interval_ms * (1 << (st->cfg.retransmit_max + 1)) +
      st->cfg.response_timeout_ms;
  }

  // ---- 执行处理逻辑（§13.3：on_request 返回响应 / on_fire_forget 无返回） ----
  if (is_ff) {
    // ff：无响应（§5.2）
    if (rec->handlers.on_fire_forget)
      rec->handlers.on_fire_forget(rec->handlers.ud, f->if_id, payload);
    fw_value_free(payload);
    return;
  }
  fw_value_t *resp = NULL;
  int hret = rec->handlers.on_request(rec->handlers.ud, f->if_id, payload, &resp);
  fw_value_free(payload);
  if (hret != FW_OK || !resp) {
    // 处理逻辑执行异常 → RST(0x30)（§12.1）；并清缓存防泄漏
    fw_log(FW_LOG_ERROR, "rpc", "handler error svc=%u if=0x%04X (ret=%d)", f->svc_id, f->if_id, hret);
    for (int i = 0; i < st->rpc.ncache; i++) {
      if (strcmp(st->rpc.cache[i].key, key) == 0) {
        free(st->rpc.cache[i].ack_raw);
        free(st->rpc.cache[i].resp_raw);
        st->rpc.cache[i] = st->rpc.cache[st->rpc.ncache - 1];
        st->rpc.ncache--;
        break;
      }
    }
    if (resp) fw_value_free(resp);
    send_rst(st, FW_RST_INTERNAL, f, meta);
    return;
  }
  // 编码响应（接口 output 方向）
  fw_buf_t body;
  fw_buf_init(&body);
  int er = fw_encode_payload(rec->schema, iface, 1, resp, &body, eerr, sizeof(eerr));
  fw_value_free(resp);
  if (er != FW_OK) {
    fw_buf_free(&body);
    fw_log(FW_LOG_ERROR, "rpc", "response encode failed svc=%u if=0x%04X: %s",
           f->svc_id, f->if_id, eerr[0] ? eerr : fw_rst_name(-er));
    for (int i = 0; i < st->rpc.ncache; i++) {
      if (strcmp(st->rpc.cache[i].key, key) == 0) {
        free(st->rpc.cache[i].ack_raw);
        free(st->rpc.cache[i].resp_raw);
        st->rpc.cache[i] = st->rpc.cache[st->rpc.ncache - 1];
        st->rpc.ncache--;
        break;
      }
    }
    send_rst(st, FW_RST_INTERNAL, f, meta);
    return;
  }
  // Response 帧形态：CTR=0, TYP=NON/CON（按请求的传输）, Code=0x10（OK），回显 StrmID（§5.1）
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 0;
  d.typ = (uint8_t)(is_udp ? FW_TYP_CON : FW_TYP_NON);
  d.code = FW_CODE_OK;
  d.ver = st->cfg.ver;
  d.svc_id = f->svc_id;
  d.if_id = f->if_id;
  d.inst_id = f->inst_id;
  d.strm_id = f->strm_id;
  d.payload = body.p;
  d.payload_len = (uint32_t)body.len;
  if (is_udp) {
    // UDP Response：TYP=CON（对端回空确认 ACK，§5.1）+ 重传（§5.5）
    uint8_t raw[1700];
    uint32_t rlen = body.len + 24 < sizeof(raw) ? fw_frame_encode(raw, sizeof(raw), &d) : 0;
    if (!rlen) {
      // 超缓冲：堆编码
      uint32_t need = fw_frame_size(&d);
      uint8_t *hb = (uint8_t *)malloc(need);
      if (hb) {
        rlen = fw_frame_encode(hb, need, &d);
        fw_udp_sendto_raw(st, meta->address, meta->port, 1, hb, rlen);
        // 更新响应缓存
        for (int i = 0; i < st->rpc.ncache; i++) {
          if (strcmp(st->rpc.cache[i].key, key) == 0) {
            free(st->rpc.cache[i].resp_raw);
            st->rpc.cache[i].resp_raw = hb;
            st->rpc.cache[i].resp_len = rlen;
            st->rpc.cache[i].done = 1;
            hb = NULL;
            break;
          }
        }
        free(hb);
      }
    } else {
      fw_udp_sendto_raw(st, meta->address, meta->port, 1, raw, rlen);
      for (int i = 0; i < st->rpc.ncache; i++) {
        if (strcmp(st->rpc.cache[i].key, key) == 0) {
          st->rpc.cache[i].resp_raw = (uint8_t *)malloc(rlen);
          if (st->rpc.cache[i].resp_raw) {
            memcpy(st->rpc.cache[i].resp_raw, raw, rlen);
            st->rpc.cache[i].resp_len = rlen;
          }
          st->rpc.cache[i].done = 1;
          break;
        }
      }
      // CON 响应自身走重传（§5.5）
      fw_retransmit_start(&st->rpc.retrans, key, raw, rlen, meta->address, meta->port, 1, now_ms(st));
    }
  } else {
    // TCP Response：TYP=NON（§5.1）
    if (meta->conn) fw_tcp_send_frame(st, meta->conn, &d);
  }
  fw_buf_free(&body);
}
// ============================================================
// 帧入口 / 定时 / REN / 断连
// ============================================================

void fw_rpc_on_frame(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  switch (f->typ) {
    case FW_TYP_NON:
    case FW_TYP_CON:
      if (f->code == FW_CODE_REQUEST) { handle_client_call(st, f, meta, 0); return; }
      if (f->code == FW_CODE_FF)      { handle_client_call(st, f, meta, 1); return; }
      if (f->code == FW_CODE_OK)      { on_response(st, f, meta); return; }
      return; // 其余 Code 已由解析层/校验拒绝
    case FW_TYP_ACK:
      on_ack(st, f, meta); // 数据帧空确认：请求/FF/推送 CON 的传输确认（§3.7）
      return;
    case FW_TYP_RST:
      on_data_rst(st, f, meta); // 数据帧 RST：释放对应 Stream（§5.4）
      return;
  }
}

// tick：响应超时（§1.3 唯一终态）/ ff 兜底释放 / 响应缓存过期
void fw_rpc_tick(fw_stack_t *st, int64_t now) {
  // pending 调用 deadline（§5.1：响应超时触发时若该 StrmID 仍有待确认重传，一并取消）
  for (fw_call_ctx_t **pp = &st->rpc.pending; *pp; ) {
    fw_call_ctx_t *c = *pp;
    if (now >= c->deadline_ms) {
      *pp = c->next;
      c->next = NULL;
      if (c->key[0]) fw_retransmit_cancel(&st->rpc.retrans, c->key);
      if (c->peer[0] && c->strm)
        fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1;
      c->err = FW_ERR_TIMEOUT; // RequestTimeout（调用的唯一终态判定）
      snprintf(c->msg, sizeof(c->msg), "call svc=%u if=0x%04X timeout (%ums)",
               c->svc_id, c->if_id, c->timeout_ms);
      fw_call_advance_notify_done(st, c);
      continue;
    }
    pp = &c->next;
  }
  // ff 待确认兜底释放（重传耗尽后静默，§5.5 重传耗尽语义）
  for (fw_call_ctx_t **pp = &st->rpc.ff_pending; *pp; ) {
    fw_call_ctx_t *c = *pp;
    if (now >= c->deadline_ms) {
      *pp = c->next;
      c->next = NULL;
      if (c->key[0]) fw_retransmit_cancel(&st->rpc.retrans, c->key);
      if (c->peer[0] && c->strm)
        fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1; // 送达保证由 TTL 与保活机制兜底，无应用层错误（§5.2）
      c->err = FW_OK;
      fw_call_advance_notify_done(st, c);
      continue;
    }
    pp = &c->next;
  }
  // 响应缓存过期清理（§5.5：随 Stream 释放/超时清除）
  for (int i = 0; i < st->rpc.ncache; ) {
    if (now > st->rpc.cache[i].expiry) {
      free(st->rpc.cache[i].ack_raw);
      free(st->rpc.cache[i].resp_raw);
      st->rpc.cache[i] = st->rpc.cache[st->rpc.ncache - 1];
      st->rpc.ncache--;
    } else i++;
  }
}

// 收到 REN=1：清该对端重传/等待/响应缓存（§3.6）
void fw_rpc_on_ren(fw_stack_t *st, const char *ip) {
  char prefix[64];
  snprintf(prefix, sizeof(prefix), "%s:", ip);
  fw_retransmit_clear_peer(&st->rpc.retrans, prefix);
  for (fw_call_ctx_t **pp = &st->rpc.pending; *pp; ) {
    fw_call_ctx_t *c = *pp;
    if (strncmp(c->key, prefix, strlen(prefix)) == 0) {
      *pp = c->next;
      c->next = NULL;
      if (c->peer[0] && c->strm)
        fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1;
      c->err = FW_ERR_NOT_FOUND;
      snprintf(c->msg, sizeof(c->msg), "peer %s restarted (REN)", ip);
      fw_call_advance_notify_done(st, c);
      continue;
    }
    pp = &c->next;
  }
  for (fw_call_ctx_t **pp = &st->rpc.ff_pending; *pp; ) {
    fw_call_ctx_t *c = *pp;
    if (strncmp(c->key, prefix, strlen(prefix)) == 0) {
      *pp = c->next;
      c->next = NULL;
      if (c->peer[0] && c->strm)
        fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1;
      c->err = FW_OK;
      fw_call_advance_notify_done(st, c);
      continue;
    }
    pp = &c->next;
  }
  for (int i = 0; i < st->rpc.ncache; ) {
    if (strncmp(st->rpc.cache[i].key, prefix, strlen(prefix)) == 0) {
      free(st->rpc.cache[i].ack_raw);
      free(st->rpc.cache[i].resp_raw);
      st->rpc.cache[i] = st->rpc.cache[st->rpc.ncache - 1];
      st->rpc.ncache--;
    } else i++;
  }
}

// TCP 连接断开：排空该对端 pending 调用等待（§5.6；响应超时兜底冗余）
void fw_rpc_on_tcp_closed(fw_stack_t *st, const char *ip) {
  size_t pl = strlen(ip);
  for (fw_call_ctx_t **pp = &st->rpc.pending; *pp; ) {
    fw_call_ctx_t *c = *pp;
    if (strncmp(c->peer, ip, pl) == 0 && c->peer[pl] == ':') {
      *pp = c->next;
      c->next = NULL;
      if (c->strm) fw_strm_release_client(st->strm, c->peer, c->svc_id, c->inst_id, c->strm);
      c->done = 1;
      c->err = FW_ERR_CONN;
      snprintf(c->msg, sizeof(c->msg), "tcp connection closed (peer %s)", ip);
      fw_call_advance_notify_done(st, c);
      continue;
    }
    pp = &c->next;
  }
}