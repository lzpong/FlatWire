// ============================================================
// stack.c —— §13 协议栈入口（应用 API）+ 事件循环 + 帧分发总线
//
// 组装：transport(UDP/TCP) → idlstore → sd(discovery) → rpc → events
// 帧分发总线：REN → 全模块清理；CTR=1 → SD 四操作/确认/RST；
//             CTR=0 → Request/FF/Notification/Response/ACK/RST
// 生命周期：start（启动即发 Find 预热发现缓存，§2 定案）/
//           stop（REN ×3 组播先发后关，§3.6/4.6）
// ============================================================

#include "fw_int.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

static int64_t (*g_clock_fn)(void) = NULL; // 测试时钟钩子（须在 fw_stack_init 前设置）

static int64_t now_ms(fw_stack_t *st) {
  if (st->clock_override) return st->clock_override();
  return fw_now_ms();
}

// ---- 公共单调时钟（§13 应用/测试用；协议栈内部走 now_ms(st) 以支持时钟注入） ----

int64_t fw_now_ms(void) { return fw_plat_now_ms(); }

// ---- 配置（附录 A：参数默认值） ----

void fw_config_defaults(fw_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->port = 5400;
  cfg->multicast_ipv4 = "224.0.1.187";
  cfg->bind_address = NULL;
  cfg->period_ms = 2000;
  cfg->ttl_ms = 4000;
  cfg->response_timeout_ms = 2000;
  cfg->retransmit_interval_ms = 200;
  cfg->retransmit_max = 3;
  cfg->tcp_frame_timeout_ms = 5000;
  cfg->heartbeat_period_ms = 30000;
  cfg->max_payload_len = 1400;
  cfg->ver = 0;
  cfg->idl_dir = "./idl";
  cfg->tcp_enabled = 1;
  cfg->log_level = FW_LOG_INFO;
}

// 配置校验（附录 A 约束列；5.10 拒绝配置）
int fw_config_validate(const fw_config_t *cfg, char *err, int errsz) {
  if (cfg->port < 1) {
    snprintf(err, (size_t)errsz, "port must be 1~65535");
    return FW_ERR_CONFIG;
  }
  if (cfg->ttl_ms < 2 * cfg->period_ms) {
    snprintf(err, (size_t)errsz, "ttl_ms(%u) must be >= 2 * period_ms(%u)", cfg->ttl_ms, cfg->period_ms);
    return FW_ERR_CONFIG; // 5.10 周期/TTL 约束
  }
  if (cfg->ttl_ms > 255000) {
    snprintf(err, (size_t)errsz, "ttl_ms must be <= 255000 (Entry TTL is uint8 seconds)");
    return FW_ERR_CONFIG;
  }
  if (cfg->response_timeout_ms == 0) {
    snprintf(err, (size_t)errsz, "response_timeout_ms must be > 0");
    return FW_ERR_CONFIG;
  }
  if (cfg->tcp_frame_timeout_ms == 0) {
    snprintf(err, (size_t)errsz, "tcp_frame_timeout_ms must be > 0");
    return FW_ERR_CONFIG;
  }
  if (cfg->max_payload_len == 0) {
    snprintf(err, (size_t)errsz, "max_payload_len must be > 0");
    return FW_ERR_CONFIG;
  }
  if (cfg->retransmit_max < 0 || cfg->retransmit_max > 20) {
    snprintf(err, (size_t)errsz, "retransmit_max must be 0~20");
    return FW_ERR_CONFIG;
  }
  // [REVIEW P3-4] ver 合法性校验：VER 为 2bit 帧字段，>3 时编码 (ver & 0x03) 截断，
  // 本端自发自收解析 VER 不等（RST(0x22)/静默丢弃）且难以排查
  if (cfg->ver > 3) {
    snprintf(err, (size_t)errsz, "ver must be 0~3 (2-bit frame field)");
    return FW_ERR_CONFIG;
  }
  return FW_OK;
}

// ---- 错误记录 ----

void fw_stack_fail(fw_stack_t *st, int code, int rst_code, const char *fmt, ...) {
  st->last_err.code = code;
  st->last_err.rst_code = rst_code;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(st->last_err.msg, sizeof(st->last_err.msg), fmt, ap);
  va_end(ap);
  fw_log(FW_LOG_WARN, "stack", "%s", st->last_err.msg);
}

const fw_result_t *fw_stack_last_error(const fw_stack_t *st) {
  return &st->last_err;
}

// ---- RST 帧构造（§5.4：回显触发帧的 CTR 与标识字段） ----

void fw_make_rst(fw_frame_desc_t *d, int code, int ctr, uint16_t svc, uint16_t if_id,
                 uint8_t inst, uint8_t strm) {
  memset(d, 0, sizeof(*d));
  d->ctr = (uint8_t)(ctr ? 1 : 0);
  d->typ = FW_TYP_RST;
  d->code = (uint8_t)code;
  d->svc_id = svc;
  d->if_id = if_id;
  d->inst_id = inst;
  d->strm_id = strm;
  d->payload = NULL;   // §3.7：RST 帧 PLB 必须为 0
  d->payload_len = 0;
}

// ---- 等待者唤醒 ----

void fw_waiters_fire(fw_stack_t *st, fw_waiter_t **head) {
  fw_waiter_t *w = *head;
  *head = NULL;
  while (w) {
    fw_waiter_t *nx = w->next;
    w->next = NULL;
    if (w->kind == FW_W_CALL) fw_call_advance(st, w->ctx);
    // [REVIEW P3-5] 移除 FW_W_REG 分支（reg_ctx 死代码已删除）
    w = nx;
  }
}

void fw_waiters_fire_fail(fw_stack_t *st, fw_tcpconn_t *c) {
  fw_waiter_t *w = c->waiters;
  c->waiters = NULL;
  while (w) {
    fw_waiter_t *nx = w->next;
    w->next = NULL;
    if (w->kind == FW_W_CALL) {
      fw_call_ctx_t *ctx = (fw_call_ctx_t *)w->ctx;
      if (!ctx->done) {
        ctx->done = 1;
        ctx->err = FW_ERR_CONN;
        snprintf(ctx->msg, sizeof(ctx->msg), "tcp connection closed/failed (peer %s)", c->addrkey);
        fw_call_advance_notify_done(st, ctx);
      }
    }
    w = nx;
  }
}

// ctx 完成通知：异步回调触发 + ctx 释放（resp 所有权随回调移交；同步泵轮询 done 标志）
void fw_call_advance_notify_done(fw_stack_t *st, fw_call_ctx_t *ctx) {
  // 完成即从全部挂接点摘除内嵌 waiter（ctx 即将释放——悬空 waiter 被触发 = UB）
  fw_call_detach(st, ctx);
  if (ctx->cb) {
    fw_call_cb cb = ctx->cb;
    void *ud = ctx->ud;
    fw_value_t *resp = ctx->resp;
    ctx->resp = NULL; // 所有权移交回调
    int err = ctx->err;
    char msg[160];
    snprintf(msg, sizeof(msg), "%s", ctx->msg);
    fw_call_ctx_free(st, ctx);
    cb(ud, resp, err, msg);
  }
  // 同步调用：fw_call 泵轮询 ctx->done，无需额外通知
}

// ============================================================
// 生命周期
// ============================================================

int fw_stack_init(fw_stack_t **out, const fw_config_t *cfg) {
  *out = NULL;
  if (!cfg) return FW_ERR_PARAM;
  char err[128];
  if (fw_config_validate(cfg, err, sizeof(err)) != FW_OK) {
    fw_log(FW_LOG_ERROR, "stack", "config invalid: %s", err);
    return FW_ERR_CONFIG;
  }
  fw_stack_t *st = (fw_stack_t *)calloc(1, sizeof(fw_stack_t));
  if (!st) return FW_ERR_MEMORY;
  st->cfg = *cfg;
  snprintf(st->idl_dir, sizeof(st->idl_dir), "%s", cfg->idl_dir ? cfg->idl_dir : "./idl");
  snprintf(st->mcast, sizeof(st->mcast), "%s", cfg->multicast_ipv4 ? cfg->multicast_ipv4 : "224.0.1.187");
  snprintf(st->bind, sizeof(st->bind), "%s", cfg->bind_address ? cfg->bind_address : "");
  // 自我回环过滤地址集（§2；[REVIEW P3-11] 对齐 JS networkInterfaces 全量收集）：
  //   指定 bind_address → 该地址是本 socket 唯一可能源（不混入枚举集：同机多栈
  //   绑不同网卡地址时，混入会把其他栈的帧误判为自我回环）
  //   未指定 → 平台枚举本机全部 IPv4 地址 + 回环兜底（Windows GetAdaptersAddresses
  //   不含回环接口，须显式追加 127.0.0.1/127.0.0.2 保证回环组播过滤）
  if (st->bind[0]) {
    snprintf(st->local_addrs[st->nlocal++], 48, "%s", st->bind);
  } else {
    char found[16][48];
    int nf = fw_plat_local_addrs(found, 16);
    for (int i = 0; i < nf && st->nlocal < 16; i++) {
      int dup = 0;
      for (int k = 0; k < st->nlocal; k++)
        if (strcmp(st->local_addrs[k], found[i]) == 0) { dup = 1; break; }
      if (!dup) snprintf(st->local_addrs[st->nlocal++], 48, "%.47s", found[i]); // %.47s：源无界推断下保证不截断告警
    }
    // 回环兜底（枚举失败/平台不含回环接口时仍可过滤本机回环组播）
    const char *lo[] = { "127.0.0.1", "127.0.0.2" };
    for (int i = 0; i < 2 && st->nlocal < 16; i++) {
      int dup = 0;
      for (int k = 0; k < st->nlocal; k++)
        if (strcmp(st->local_addrs[k], lo[i]) == 0) { dup = 1; break; }
      if (!dup) snprintf(st->local_addrs[st->nlocal++], 48, "%s", lo[i]);
    }
  }
  st->clock_override = g_clock_fn;
  st->udp_main = FW_FD_INVALID;
  st->udp_client = FW_FD_INVALID;
  st->tcp_listen = FW_FD_INVALID;
  st->strm = fw_strm_new();
  st->idl = fw_idl_new();
  if (!st->strm || !st->idl) { fw_stack_free(st); return FW_ERR_MEMORY; }
  fw_log_set_level(cfg->log_level);
  *out = st;
  return FW_OK;
}

int fw_stack_start(fw_stack_t *st) {
  if (st->started) return FW_OK;
  // 纯动态架构：启动扫描 IDL 库（§11.1）
  fw_idl_load_all(st->idl, st->idl_dir);
  // 平台初始化（Winsock2 WSAStartup）
  static int plat_inited = 0;
  if (!plat_inited) {
    if (fw_plat_init() != FW_OK) { fw_stack_fail(st, FW_ERR_IO, 0, "platform init failed"); return FW_ERR_IO; }
    plat_inited = 1;
  }
  // UDP 双 socket（§2：main bind port / client 临时端口）
  char err[128];
  if (fw_udp_sockets_open(st, err, sizeof(err)) != FW_OK) {
    fw_stack_fail(st, FW_ERR_IO, 0, "%s", err);
    return FW_ERR_IO;
  }
  // TCP 监听（服务端角色）；tcp_enabled=false 时跳过（客户端角色栈仅需出站连接）
  if (st->cfg.tcp_enabled) {
    if (fw_tcp_listen(st, err, sizeof(err)) != FW_OK) {
      fw_stack_fail(st, FW_ERR_IO, 0, "%s", err);
      fw_udp_sockets_close(st);
      return FW_ERR_IO;
    }
  }
  // 模块初始化
  fw_disc_init(st);
  fw_rpc_init(st);
  fw_events_init(st);
  int64_t now = now_ms(st);
  st->last_offer_ms = now;
  st->last_tick_ms = now;
  st->started = 1;
  // 启动立即发 Find（空 Payload）预热发现缓存（§2 定案：单实例，注册拉取失败可重试）
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 1;
  d.typ = FW_TYP_NON;
  d.code = FW_CODE_SD_FIND;
  d.ver = st->cfg.ver;
  fw_udp_send_mcast_frame(st, &d, 0);
  fw_log(FW_LOG_INFO, "stack", "started: port=%u ver=%u idl_dir=%s", st->cfg.port, st->cfg.ver, st->idl_dir);
  return FW_OK;
}

// 停止：REN ×3 组播（间隔 ~100ms）先发后关，再释放资源（§3.6/4.6）
void fw_stack_stop(fw_stack_t *st) {
  if (!st->started) return;
  st->started = 0;
  st->stop_requested = 1;
  fw_frame_desc_t d;
  memset(&d, 0, sizeof(d));
  d.ctr = 1;
  d.ren = 1;          // §3.6：REN=1 固定 TYP=NON、StrmID=0、Code=0x00
  d.typ = FW_TYP_NON;
  d.code = 0x00;
  d.ver = st->cfg.ver;
  for (int i = 0; i < 3; i++) {
    fw_udp_send_mcast_frame(st, &d, 1); // REN 经 UDP 组播从 main socket 发送（§3.6）
    if (i < 2) fw_sleep_ms(100);        // 间隔 ~100ms（协议固定值，隔开发送防交换机缓冲溢出）
  }
  fw_log(FW_LOG_INFO, "stack", "REN x3 sent (graceful shutdown)");
  fw_disc_stop(st);
  // [REVIEW P3-12] stop 时冲刷挂起 async call：以 FW_ERR_STATE 触发完成回调
  //（原实现 fw_rpc_free 直接释放 ctx，应用侧异步等待无终态通知 = 永久悬挂）
  fw_rpc_flush_all_pending(st, FW_ERR_STATE, "stack stopped (call aborted)");
  fw_rpc_free(st);
  fw_events_stop(st);
  fw_tcp_stop(st);
  fw_udp_sockets_close(st);
  fw_log(FW_LOG_INFO, "stack", "stopped");
}

void fw_stack_free(fw_stack_t *st) {
  if (!st) return;
  if (st->started) fw_stack_stop(st);
  fw_disc_free(st);
  fw_rpc_free(st);
  fw_events_free(st);
  fw_strm_free(st->strm);
  fw_idl_free(st->idl);
  free(st->conns);
  free(st);
}

// ---- 事件循环 ----

int fw_stack_poll(fw_stack_t *st, int timeout_ms) {
  if (!st->started) return FW_ERR_STATE;
  // 构造 pollfd 集（每轮重建；连接数少，开销可忽略）
  struct pollfd fds[280];
  int idx[280];
  int n = 0;
  if (st->udp_main != FW_FD_INVALID) {
    fds[n].fd = st->udp_main; fds[n].events = POLLIN; fds[n].revents = 0; idx[n++] = -1;
  }
  if (st->udp_client != FW_FD_INVALID) {
    fds[n].fd = st->udp_client; fds[n].events = POLLIN; fds[n].revents = 0; idx[n++] = -2;
  }
  if (st->tcp_listen != FW_FD_INVALID) {
    fds[n].fd = st->tcp_listen; fds[n].events = POLLIN; fds[n].revents = 0; idx[n++] = -3;
  }
  for (int i = 0; i < st->nconn && n < 279; i++) {
    fw_tcpconn_t *c = st->conns[i];
    if (!c || c->closed) continue;
    short ev = POLLIN;
    if (c->connected && c->slen > c->ssent) ev |= POLLOUT; // 有待发数据
    fds[n].fd = c->fd; fds[n].events = ev; fds[n].revents = 0; idx[n] = i;
    n++;
  }
  fw_plat_poll(fds, n, timeout_ms); // 就绪事件仅作用于下方 POLLOUT flush；错误由收发路径自检
  // 无条件驱动收发与连接管理（Windows WSAPoll 对非阻塞 connect 完成不报告就绪，
  // connecting conn 的完成检查必须每轮执行，不能依赖 poll 就绪事件）
  st->dispatch++;
  fw_udp_poll(st); // 非阻塞清空两个 UDP socket（收包 + 解析 + 分发）
  fw_tcp_poll(st); // accept / connect 完成 / 逐连接非阻塞读
  st->dispatch--;
  // POLLOUT 就绪的发送缓冲 flush（tcp_poll 内未覆盖写就绪场景）
  // [REVIEW P3-3] 原 poll 前记录的 conns 数组下标在 poll 期间连接关闭 swap 后错位
  //（flush 到另一连接）：改按 fd 重查（fd 恒定，句柄复用极端场景 flush 也无害）
  for (int i = 0; i < n; i++) {
    if ((fds[i].revents & POLLOUT) && idx[i] >= 0) {
      fw_tcpconn_t *c = NULL;
      for (int k = 0; k < st->nconn; k++) {
        fw_tcpconn_t *cc = st->conns[k];
        if (cc && !cc->closed && cc->fd == fds[i].fd) { c = cc; break; }
      }
      if (c) fw_tcp_flush(c);
    }
  }  // 时间驱动定时（每轮检查；20ms 粒度足够协议语义）
  int64_t now = now_ms(st);
  fw_disc_tick(st, now);          // Offer 周期 + 1s TTL tick（§7.2/§7.5）
  fw_disc_tick_queries(st, now);  // GetIDL 查询推进/超时（§7.2）
  fw_disc_tick_find(st, now);     // find 等待清理
  fw_disc_session_tick(st, now);  // 订阅保活 + 取消兜底（§7.2）
  fw_retransmit_tick(&st->disc.retrans, st, now);  // Subscribe CON 重传（§5.5）
  fw_retransmit_tick(&st->rpc.retrans, st, now);   // rpc CON 重传（§5.5）
  fw_retransmit_tick(&st->ev.retrans, st, now);    // 推送 CON 重传（§5.5）
  fw_rpc_tick(st, now);           // 响应超时（§1.3）/ff 兜底/缓存过期
  fw_events_tick(st, now);        // 推送兜底/接收记录清理
  fw_tcp_tick(st, now);           // 半帧两阶段 + 心跳（§4.1/§5.7）
  fw_tcp_flush_all(st);           // POLLOUT 就绪的发送缓冲
  return FW_OK;
}

void fw_stack_run(fw_stack_t *st) {
  while (st->started && !st->stop_requested)
    fw_stack_poll(st, 20);
}
// ============================================================
// 帧分发总线（UDP / TCP 双入口统一进入）
// ============================================================

void fw_stack_on_frame(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta) {
  // ---- REN=1（§3.6）：清该对端服务缓存 + 活跃表 + 重传记录（4.4/4.5） ----
  if (f->ren == 1) {
    fw_log_frame(FW_LOG_INFO, 0, 0, 0, 0, "Rx", meta->address, 0, "REN received");
    fw_disc_on_ren(st, meta);
    fw_rpc_on_ren(st, meta->address);
    fw_events_on_ren(st, meta->address);
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "%s:", meta->address);
    fw_strm_reset_peer(st->strm, prefix); // 该对端全部 StrmID 序列重置（§6.3）
    return;
  }

  if (f->ctr == 1) {
    // ---- 控制帧（CTR=1）→ SD 模块 ----
    // Subscribe 的 CON 形态（首次建立/取消/重传，§5.5 重传范围 + §8.1 到达帧行为）
    if (f->typ == FW_TYP_CON) {
      if (f->code == FW_CODE_SD_SUB) fw_disc_on_subscribe(st, f, meta);
      return; // 其余控制帧 CON 组合非法定义（仅 Subscribe 使用 CON），静默丢弃
    }
    switch (f->typ) {
      case FW_TYP_NON:
        switch (f->code) {
          case FW_CODE_SD_OFFER:   fw_disc_on_offer(st, f, meta); return;       // 0x01 Offer / Find 响应
          case FW_CODE_SD_FIND:    fw_disc_on_find(st, f, meta); return;        // 0x02 Find
          case FW_CODE_SD_SUB:     fw_disc_on_subscribe(st, f, meta); return;   // 0x03 Subscribe 保活（NON）
          case FW_CODE_SD_GETIDL:  fw_disc_on_getidl(st, f, meta); return;      // 0x04 GetIDL（仅 TCP，解析层已保证）
          case FW_CODE_SD_IDLRESP: fw_disc_on_getidl_resp(st, f, meta); return; // 0x11 GetIDL 响应（§7.2）
          default: return; // Code=0x00 心跳 Ping：不回任何帧（§5.7）
        }
      case FW_TYP_ACK:
        if (f->code == FW_CODE_SD_SUBACK) fw_disc_on_subscribe_ack(st, f, meta);   // 0x10 订阅建立确认
        else if (f->code == 0x00) fw_disc_on_unsubscribe_ack(st, f, meta);         // 0x00 取消确认（回显会话 StrmID）
        return;
      case FW_TYP_RST:
        fw_disc_on_ctrl_rst(st, f, meta); // 订阅被拒 / GetIDL 失败（§5.4）
        return;
    }
    return;
  }

  // ---- 数据帧（CTR=0）→ RPC / Events ----
  switch (f->typ) {
    case FW_TYP_NON:
    case FW_TYP_CON:
      switch (f->code) {
        case FW_CODE_REQUEST: fw_rpc_on_frame(st, f, meta); return;   // 0x01 Request
        case FW_CODE_FF:      fw_rpc_on_frame(st, f, meta); return;   // 0x02 Fire-Forget
        case FW_CODE_NOTIFY:  fw_events_on_frame(st, f, meta); return; // 0x03 Notification
        case FW_CODE_OK:      fw_rpc_on_frame(st, f, meta); return;   // 0x10 Response
        default: return; // 其余 Code 已由解析层/校验拒绝（0x11~0x1F 保留）
      }
    case FW_TYP_ACK:
      fw_rpc_on_frame(st, f, meta);   // 数据帧空确认（§3.7）
      fw_events_on_frame(st, f, meta);
      return;
    case FW_TYP_RST:
      fw_rpc_on_frame(st, f, meta);   // 数据帧 RST：释放对应 Stream（§5.4）
      fw_events_on_frame(st, f, meta);
      return;
  }
}

// ============================================================
// 应用 API —— 服务端（§13.1）
// ============================================================

// [REVIEW P3-5] 删除 fw_reg_ctx_t/fw_reg_advance 死代码：register 的自动拉取
// 实际走 fw_disc_fetch_idl 同步泵（见 fw_register_service），reg ctx 状态机无调用方

int fw_register_service(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                        const char *idl_json, const fw_handlers_t *handlers) {
  if (!st || !st->started) { fw_stack_fail(st, FW_ERR_STATE, 0, "stack not started"); return FW_ERR_STATE; }
  st->last_err.code = FW_OK;
  fw_schema_t *schema = NULL;

  if (idl_json && idl_json[0]) {
    // 应用提供 IDL：校验自含 svc_id 一致后进库（重复注册同版本直接复用库内定义）
    char jerr[128];
    fw_value_t *idl = fw_json_parse(idl_json, strlen(idl_json), jerr, sizeof(jerr));
    if (!idl) {
      fw_stack_fail(st, FW_ERR_PARAM, 0, "idl is not valid JSON: %s", jerr);
      return FW_ERR_PARAM;
    }
    const fw_value_t *svc = fw_struct_get(idl, "service");
    const fw_value_t *sidv = svc ? fw_struct_get(svc, "svc_id") : NULL;
    const fw_value_t *mvv = svc ? fw_struct_get(svc, "major_ver") : NULL;
    int64_t sid = sidv ? (sidv->type == FW_V_UINT ? (int64_t)sidv->as.u
                       : (sidv->type == FW_V_INT ? sidv->as.i : 0)) : 0;
    int64_t mv = mvv ? (mvv->type == FW_V_UINT ? (int64_t)mvv->as.u
                     : (mvv->type == FW_V_INT ? mvv->as.i : 0)) : 0;
    if (!svc || sid != svc_id) {
      fw_value_free(idl);
      fw_stack_fail(st, FW_ERR_PARAM, 0, "idl svc_id mismatch (idl=%lld arg=%u)", (long long)sid, svc_id);
      return FW_ERR_PARAM;
    }
    if (!fw_idl_has(st->idl, svc_id, (uint8_t)mv)) {
      // 落盘失败降级内存（fw_idl_save 内处理 §7.2）
      fw_idl_save(st->idl, svc_id, (uint8_t)mv, idl_json);
    }
    fw_value_free(idl);
    fw_idl_entry_t *e = fw_idl_get(st->idl, svc_id, (uint8_t)mv);
    schema = e ? (fw_schema_t *)e->schema : NULL;
  } else {
    // 未提供 IDL：库最高版本 → 自动拉取（发现缓存有在线实例时，§7.2/§13.1 双角色统一）
    fw_idl_entry_t *e = fw_idl_get_highest(st->idl, svc_id);
    if (e) {
      schema = (fw_schema_t *)e->schema;
    } else {
      int major = fw_disc_online_major_ver(st, svc_id);
      if (major < 0) {
        // 库无定义且集群无在线实例 → 注册失败上抛（发现缓存更新后重试可成功，§13.1/5.34）
        fw_stack_fail(st, FW_ERR_IDL_UNAVAILABLE, 0,
                      "svc=%u not in local IDL store and no online instance to fetch from", svc_id);
        return FW_ERR_IDL_UNAVAILABLE;
      }
      // 自动 GetIDL（MajorVer 取发现缓存在线版本，§7.2 注册场景；同步泵等待）
      char err[160];
      int ecode = 0;
      schema = fw_disc_fetch_idl(st, svc_id, (uint8_t)major, &ecode, err, sizeof(err));
      if (!schema) {
        fw_stack_fail(st, ecode, 0, "register svc=%u: %s", svc_id, err);
        return ecode;
      }
    }
  }
  if (!schema) {
    fw_stack_fail(st, FW_ERR_IDL_UNAVAILABLE, 0, "svc=%u schema unavailable", svc_id);
    return FW_ERR_IDL_UNAVAILABLE;
  }
  // handler 覆盖检查 + 进入 Offering（重复注册同 (svc,inst) → Err，7.9）
  char err[128];
  int r = fw_disc_register(st, svc_id, inst_id, schema, handlers, err, sizeof(err));
  if (r != FW_OK) {
    fw_stack_fail(st, r, 0, "%s", err);
    return r;
  }
  return FW_OK;
}

int fw_unregister_service(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id) {
  if (!st || !st->started) return FW_ERR_STATE;
  st->last_err.code = FW_OK;
  return fw_disc_unregister(st, svc_id, inst_id); // 注销发 TTL=0 Offer（§7.3；定义不卸载 §7.2）
}

// notify（§13.1）：更新接口缓存并推送给所有订阅者（§8.1/§8.2）
int fw_notify(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id, fw_value_t *payload) {
  if (!st || !st->started) { fw_value_free(payload); return FW_ERR_STATE; }
  st->last_err.code = FW_OK;
  fw_events_notify(st, svc_id, inst_id, if_id, payload); // payload 所有权转移
  return st->last_err.code;
}
// ============================================================
// 应用 API —— 客户端（§13.2）
// ============================================================

// 订阅场景的 IDL 预拉取（协议栈内部行为，应用无感知，§7.2）
// dispatch==0（主线程）同步等待拉取；回调内（dispatch>0）降级异步
static void ensure_idl_for_subscribe(fw_stack_t *st, uint16_t svc_id) {
  if (fw_idl_get_highest(st->idl, svc_id)) return; // 本地命中不查询（5.28/5.29）
  int major = fw_disc_online_major_ver(st, svc_id);
  if (major < 0) return; // 发现缓存无在线实例不发起（§7.2/5.30）
  // 订阅场景的预拉取一律后台化（对齐 fw-nodejs _ensureIdlBackground 语义：失败仅日志，
  // 事件到达时兜底再拉）——单进程双栈等集成场景下同步泵无法驱动对端栈
  fw_disc_fetch_idl_async(st, svc_id, (uint8_t)major);
}

// 启动 call/ff 状态机并驱动到完成（同步；重入保护）
static int call_run_sync(fw_stack_t *st, fw_call_ctx_t *ctx, fw_value_t **out_resp) {
  if (st->dispatch > 0) {
    // 回调内禁止同步泵（单线程事件循环不可重入）；请用 fw_call_async
    fw_call_ctx_free(st, ctx);
    fw_stack_fail(st, FW_ERR_BUSY, 0, "sync call not allowed inside callbacks (use fw_call_async)");
    return FW_ERR_BUSY;
  }
  // 发起（advance 至第一个等待点）
  st->dispatch++;
  fw_call_advance(st, ctx);
  st->dispatch--;
  // 泵循环直到完成（响应超时/错误由 ctx 内部状态与 rpc_tick 驱动）；
  // 总超时兜底：ctx 未挂 pending 链（resolve 阶段）时 rpc_tick 不检查其 deadline
  int64_t abs_deadline = fw_now_ms() + (int64_t)ctx->timeout_ms * 2 + 1000;
  while (!ctx->done) {
    fw_stack_poll(st, 20);
    if (fw_now_ms() >= abs_deadline) {
      // 放弃：摘除全部挂接点（防 ctx 释放后 waiter 悬空）→ 标记终态
      fw_call_detach(st, ctx);
      ctx->done = 1;
      ctx->err = FW_ERR_TIMEOUT;
      snprintf(ctx->msg, sizeof(ctx->msg), "call svc=%u if=0x%04X abandoned (resolve stuck %ums)",
               ctx->svc_id, ctx->if_id, ctx->timeout_ms);
      break;
    }
  }
  int r = ctx->err;
  if (out_resp) {
    *out_resp = ctx->resp; // 所有权移交调用者
    ctx->resp = NULL;
  } else {
    fw_value_free(ctx->resp);
    ctx->resp = NULL;
  }
  if (r != FW_OK) fw_stack_fail(st, r, ctx->rst_code, "%s", ctx->msg);
  fw_call_ctx_free(st, ctx);
  return r;
}

// 同步调用（§13.2 call：阻塞至收到响应或超时；payload 所有权转移）
int fw_call(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
            fw_value_t *payload, uint32_t timeout_ms, fw_value_t **out_resp) {
  if (!st || !st->started) { fw_value_free(payload); if (out_resp) *out_resp = NULL; return FW_ERR_STATE; }
  st->last_err.code = FW_OK;
  if (out_resp) *out_resp = NULL;
  fw_call_ctx_t *ctx = fw_call_ctx_new(st, svc_id, inst_id, if_id, payload, 0, timeout_ms);
  if (!ctx) { if (out_resp) *out_resp = NULL; return FW_ERR_MEMORY; }
  return call_run_sync(st, ctx, out_resp);
}

// 异步调用（§13.2 call_async：立即返回；完成时回调，resp 所有权随回调移交）
int fw_call_async(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                  fw_value_t *payload, uint32_t timeout_ms, fw_call_cb cb, void *ud) {
  if (!st || !st->started) { fw_value_free(payload); return FW_ERR_STATE; }
  st->last_err.code = FW_OK;
  fw_call_ctx_t *ctx = fw_call_ctx_new(st, svc_id, inst_id, if_id, payload, 0, timeout_ms);
  if (!ctx) return FW_ERR_MEMORY;
  ctx->cb = cb;
  ctx->ud = ud;
  fw_call_advance(st, ctx); // 推进至第一个等待点（完成时由 notify_done 触发回调）
  return FW_OK;
}

// 无响应调用（§5.2 FF；payload 所有权转移）
int fw_fire_forget(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                   fw_value_t *payload) {
  if (!st || !st->started) { fw_value_free(payload); return FW_ERR_STATE; }
  st->last_err.code = FW_OK;
  fw_call_ctx_t *ctx = fw_call_ctx_new(st, svc_id, inst_id, if_id, payload, 1, 0);
  if (!ctx) return FW_ERR_MEMORY;
  return call_run_sync(st, ctx, NULL);
}

// 订阅事件（§13.2 subscribe）：返回订阅句柄 handle（0=失败）。
// if_id 与 grp_id 二选一（整组订阅 if_id=0x0000，§7.1 Entry 合法组合）。
uint32_t fw_subscribe(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                      uint16_t if_id, uint8_t grp_id, fw_event_cb cb, void *ud) {
  if (!st || !st->started) return 0;
  // Entry 合法组合（§7.1）：单接口 / 组订阅二选一
  if (!((if_id != 0 && grp_id == 0) || (if_id == 0 && grp_id != 0))) {
    fw_stack_fail(st, FW_ERR_PARAM, 0, "subscribe requires exactly one of if_id / grp_id");
    return 0;
  }
  st->last_err.code = FW_OK;
  ensure_idl_for_subscribe(st, svc_id); // 按需拉取（本地命中不查询，§7.2/5.28）
  return fw_disc_subscribe(st, svc_id, inst_id, if_id, grp_id, cb, ud);
}

// 取消订阅（§13.2）：发 Subscribe(TTL=0)（§8.1 场景4；登记清除条件① §7.4）
int fw_unsubscribe(fw_stack_t *st, uint32_t handle) {
  if (!st || !st->started) return FW_ERR_STATE;
  st->last_err.code = FW_OK;
  return fw_disc_unsubscribe(st, handle);
}

// is_available（§13.2）：注册表存在 + TTL Active + VER 相等（本地缓存判定）
int fw_is_available(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id) {
  if (!st || !st->started) return 0;
  fw_disc_rec_t *r = fw_disc_get_discovered(st, svc_id, inst_id);
  return r && r->ver == st->cfg.ver; // VER 相等才认为可用（§13.2）
}

// find_service（§13.2）：主动发现（触发 SD Find 刷新缓存），返回在线信息（源地址/版本）
int fw_find_service(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                    uint32_t timeout_ms, fw_svc_info_t *out) {
  if (!st || !st->started) return FW_ERR_STATE;
  st->last_err.code = FW_OK;
  if (st->dispatch > 0) {
    fw_stack_fail(st, FW_ERR_BUSY, 0, "sync find not allowed inside callbacks");
    return FW_ERR_BUSY;
  }
  char err[160];
  int r = fw_disc_find(st, svc_id, inst_id, timeout_ms, out, err, sizeof(err));
  if (r != FW_OK) fw_stack_fail(st, r, FW_RST_NOT_FOUND, "%s", err);
  return r;
}

// ---- 测试辅助：时钟注入（全局钩子；须在 fw_stack_init 前设置） ----

void fw_set_clock_override(int64_t (*fn)(void)) { g_clock_fn = fn; }
int64_t (*fw_get_clock_override(void))(void) { return g_clock_fn; }