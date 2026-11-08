// ============================================================
// tcp.c —— §5.6 TCP 长连接管理 + §4.1 半帧两阶段 + §5.7 心跳（Ping）
//
// - 连接建立：客户端按 (IP, Port) 建立唯一长连接并复用（§5.6）
// - 服务端 bind+listen，accept 后纳入帧解析（§5.6）
// - TCP 全帧 TYP=NON，不使用 CON/ACK（§3.7，解析层拒绝）
// - 半帧两阶段（§4.1）：
//     阶段一 帧头不完整（<8B）→ RST(0x26) + 关闭连接
//     阶段二 帧头完整 → RST(0x26) + 丢弃模式（精确丢弃 R=L−已收；退出三条件）
// - 心跳（§5.7）：距上次发送任意帧超过 heartbeat_period_ms 发 Ping；收到 Ping 不回；
//   2×heartbeat_period 未收帧标记连接失效
// ============================================================

#include "../fw_int.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ---- parser 回调（经 conn->stk 定位栈） ----

static void on_sp_frame(void *ud, const fw_frame_t *f) {
  fw_tcpconn_t *c = (fw_tcpconn_t *)ud;
  fw_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  meta.transport = 1;
  snprintf(meta.address, sizeof(meta.address), "%s", c->ip);
  meta.port = c->port;
  meta.conn = c;
  fw_stack_on_frame(c->stk, f, &meta);
}

static void on_sp_rst(void *ud, int code, const fw_head_res_t *echo) {
  fw_tcpconn_t *c = (fw_tcpconn_t *)ud;
  // TCP 上收到解析违规 → 回 RST（§4.4；RST 帧本身仍为合法 NON 帧）
  fw_frame_desc_t d;
  fw_make_rst(&d, code, echo->rst_ctr, echo->rst_svc, echo->rst_if, echo->rst_inst, echo->rst_strm);
  // RST 属小控制帧：直写不入队（数据队列满时仍可发出）；对端不可写则丢弃，不重试
  int rc = fw_tcp_send_frame(c->stk, c, &d);
  if (rc != FW_OK)
    fw_log(FW_LOG_WARN, "tcp", "RST not sent (rc=%d, peer not reading) %s", rc, c->addrkey);
  fw_log_frame(FW_LOG_WARN, echo->rst_svc, echo->rst_if, echo->rst_inst, echo->rst_strm,
               "Tx", c->addrkey, code, fw_rst_name(code));
}

static void on_sp_drop_complete(void *ud) {
  (void)ud; // 丢弃模式结束：兜底计时由 tick 依 drop_mode 判定，无需额外动作
}

// ---- 连接创建/销毁 ----

// 发送背压记账辅助（定义见「发送」段；close 路径在其之前使用，故前置声明）
static size_t conn_pending(const fw_tcpconn_t *c);
static void sendq_release(fw_stack_t *st, size_t n);

static fw_tcpconn_t *conn_new(fw_stack_t *st, fw_fd_t fd, const char *ip, uint16_t port, int role) {
  fw_tcpconn_t *c = (fw_tcpconn_t *)calloc(1, sizeof(fw_tcpconn_t));
  if (!c) return NULL;
  c->fd = fd;
  snprintf(c->ip, sizeof(c->ip), "%s", ip);
  c->port = port;
  snprintf(c->addrkey, sizeof(c->addrkey), "%s:%u", ip, port);
  c->role = role;
  c->connected = 1;
  c->stk = st;
  fw_sp_init(&c->parser);
  c->parser.ver = st->cfg.ver;
  c->parser.ud = c;
  c->parser.on_frame = on_sp_frame;
  c->parser.on_rst = on_sp_rst;
  c->parser.on_drop_complete = on_sp_drop_complete;
  int64_t now = fw_now_ms();
  c->last_send_ms = now;
  c->last_recv_ms = now;
  if (fw_plat_set_nodelay(fd) != FW_OK)
    fw_log(FW_LOG_WARN, "tcp", "TCP_NODELAY failed on %s", c->addrkey);
  return c;
}

static void conn_free(fw_tcpconn_t *c) {
  fw_sp_free(&c->parser);
  free(c->sbuf);
  free(c);
}

// 连接关闭通知：清理该连接关联的上层状态（§5.6）
static void conn_closed_notify(fw_stack_t *st, fw_tcpconn_t *c) {
  if (c->closed) return;
  c->closed = 1;
  fw_log(FW_LOG_INFO, "stack", "tcp conn closed: %s", c->addrkey);
  // §5.6/§7.2：排空该对端 pending rpc 调用与 GetIDL 查询；
  // tcp-event 订阅保留（断连不失效 §8.2）
  fw_rpc_on_tcp_closed(st, c->ip);
  fw_disc_on_tcp_closed(st, c->ip);
}

void fw_tcp_conn_close(fw_stack_t *st, fw_tcpconn_t *c) {
  if (!c) return;
  sendq_release(st, conn_pending(c)); // 丢弃未发字节，归还全栈预算
  conn_closed_notify(st, c);
  // 连接等待者按失败推进（连接失败/EOF 场景）
  fw_waiters_fire_fail(st, c);
  if (c->fd != FW_FD_INVALID) {
    fw_plat_close(c->fd);
    c->fd = FW_FD_INVALID;
  }
  // 从数组移除并释放
  for (int i = 0; i < st->nconn; i++) {
    if (st->conns[i] == c) {
      st->conns[i] = st->conns[st->nconn - 1];
      st->nconn--;
      break;
    }
  }
  conn_free(c);
}

// ---- 监听（服务端角色，§5.6） ----

int fw_tcp_listen(fw_stack_t *st, char *err, int errsz) {
  fw_fd_t fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == FW_FD_INVALID) { snprintf(err, (size_t)errsz, "tcp socket create failed"); return FW_ERR_IO; }
  fw_plat_set_reuse(fd);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(st->cfg.port);
  addr.sin_addr.s_addr = st->bind[0] ? inet_addr(st->bind) : INADDR_ANY;
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    snprintf(err, (size_t)errsz, "tcp bind %u failed (err=%d)", st->cfg.port, fw_plat_err());
    fw_plat_close(fd);
    return FW_ERR_IO;
  }
  if (listen(fd, 16) != 0) {
    snprintf(err, (size_t)errsz, "tcp listen failed (err=%d)", fw_plat_err());
    fw_plat_close(fd);
    return FW_ERR_IO;
  }
  fw_plat_set_nonblock(fd, 1);
  st->tcp_listen = fd;
  return FW_OK;
}

// 测试注入点：非 NULL 时代替 realloc（返回 NULL 可稳定构造连接表扩容失败）。
// 生产环境保持 NULL，零开销；仅单测通过 fw_tcp_test_set_realloc_hook 设置。
static void *(*g_test_realloc_hook)(void *, size_t) = NULL;

void fw_tcp_test_set_realloc_hook(void *(*fn)(void *, size_t)) {
  g_test_realloc_hook = fn;
}

// 连接入表；失败返回 -1：调用方必须关闭 fd 并释放连接，否则会留下"已建立但未注册"的连接。
// 失败原因：①连接数达 cfg.max_conns（R3-8 上限）②连接表扩容 OOM。二者均由调用方统一回收。
static int conns_add(fw_stack_t *st, fw_tcpconn_t *c) {
  if (st->cfg.max_conns && st->nconn >= (int)st->cfg.max_conns) return -1; // R3-8：超限拒绝
  if (st->nconn == st->conncap) {
    int nc = st->conncap ? st->conncap * 2 : 8;
    void *(*ra)(void *, size_t) = g_test_realloc_hook ? g_test_realloc_hook : realloc;
    fw_tcpconn_t **np = (fw_tcpconn_t **)ra(st->conns, (size_t)nc * sizeof(fw_tcpconn_t *));
    if (!np) return -1;
    st->conns = np;
    st->conncap = nc;
  }
  st->conns[st->nconn++] = c;
  return 0;
}

// ---- 发送（背压：实现限制，非协议语义）----
//
// 记账约定：单连接未发字节 = slen - ssent；全栈 st->sendq_bytes 与各连接之和一致。
// 仅数据帧与「大控制帧」（>FW_CTRL_DIRECT_MAX，如 GetIDL 响应 0x11）入队并受上限约束；
// 小控制帧（RST/Ping 等）直写 socket、不进队列——因此数据队列满时 RST/Ping 仍可发出。
// 队列满不丢帧：在写入任何字节之前返回 FW_ERR_WOULDBLOCK，由调用方退避。

#define FW_CTRL_DIRECT_MAX 1024 // 小控制帧直写阈值（帧总字节数）

static size_t conn_pending(const fw_tcpconn_t *c) { return c->slen - c->ssent; }

// 预算释放（下溢保护：任何记账异常都不会让全局计数变负）
static void sendq_release(fw_stack_t *st, size_t n) {
  if (!st || n == 0) return;
  st->sendq_bytes = (n >= st->sendq_bytes) ? 0 : st->sendq_bytes - n;
}

// 更新峰值水位（全栈 + 本连接）
static void sendq_touch_peak(fw_stack_t *st, fw_tcpconn_t *c) {
  size_t pend = conn_pending(c);
  if (pend > st->sendq_peak) st->sendq_peak = pend;
  if (pend > c->q_peak) c->q_peak = (uint32_t)pend;
}

// 单连接上限 + 全栈预算校验（只做判定，不改记账；pending 已包含在 sendq_bytes 中）
static int sendq_has_room(fw_stack_t *st, size_t pending, uint32_t len) {
  if (st->cfg.max_send_queue_bytes && pending + len > st->cfg.max_send_queue_bytes)
    return 0;
  if (st->cfg.send_queue_budget_bytes && st->sendq_bytes + len > st->cfg.send_queue_budget_bytes)
    return 0;
  return 1;
}

// §12.6 记账对账（测试/调试用）：全栈增量计数 sendq_bytes 必须等于各连接未发字节之和。
// 只读不写，不参与生产判定（判定始终是 O(1) 的 st->sendq_bytes 比较）。
int fw_int_sendq_consistent(const fw_stack_t *st) {
  if (!st) return 1;
  size_t sum = 0;
  for (int i = 0; i < st->nconn; i++) sum += conn_pending(st->conns[i]);
  return sum == st->sendq_bytes;
}

// 队列拒绝记账（阈值首次触发时记录起始时刻，供 tick 判定「持续满」）
static int sendq_reject(fw_stack_t *st, fw_tcpconn_t *c, uint32_t len) {
  c->q_rejects++;
  st->sendq_rejects++;
  if (c->q_full_since_ms == 0) c->q_full_since_ms = fw_now_ms();
  fw_log(FW_LOG_WARN, "tcp", "send queue full, reject %ubyte frame (pending=%llu/%u, stack=%llu/%u) %s",
         len, (unsigned long long)conn_pending(c), st->cfg.max_send_queue_bytes,
         (unsigned long long)st->sendq_bytes, st->cfg.send_queue_budget_bytes, c->addrkey);
  return FW_ERR_WOULDBLOCK;
}

// 缓冲容量增长：按 4KB 块对齐（不再按 2 倍扩容——原实现下 scap 最坏可达名义上限的
// 2 倍，导致「配置 256KB、实际峰值 512KB」）。块内余量 < 4KB，名义上限与实际峰值一致。
static int sbuf_reserve(fw_tcpconn_t *c, size_t need) {
  if (need <= c->scap) return FW_OK;
  size_t nc = ((need + 4095) / 4096) * 4096;
  uint8_t *nb = (uint8_t *)realloc(c->sbuf, nc);
  if (!nb) return FW_ERR_MEMORY;
  c->sbuf = nb;
  c->scap = nc;
  return FW_OK;
}

// 小控制帧直写：不排队、不占预算。部分发送视为失败（控制帧不允许半截入队），
// 剩余字节丢弃——RST/Ping 的语义可容忍丢失，调用方记录日志即可，不重试。
static int ctrl_direct_write(fw_tcpconn_t *c, const uint8_t *buf, uint32_t len) {
  int n = (int)send(c->fd, (const char *)buf, (int)len, 0);
  if (n == (int)len) return FW_OK;
  if (n < 0 && !fw_plat_would_block()) return FW_ERR_IO;
  return FW_ERR_WOULDBLOCK; // EWOULDBLOCK 或部分发送
}

void fw_tcp_flush(fw_tcpconn_t *c) {
  if (!c) return;
  size_t before = conn_pending(c);
  while (c->ssent < c->slen) {
    int n = (int)send(c->fd, (const char *)c->sbuf + c->ssent, (int)(c->slen - c->ssent), 0);
    if (n > 0) {
      c->ssent += (size_t)n;
      continue;
    }
    break; // EWOULDBLOCK（POLLOUT 继续）或错误（关闭路径处理）
  }
  sendq_release(c->stk, before - conn_pending(c)); // 已送入内核的字节归还预算
  if (conn_pending(c) == 0) {
    c->slen = 0; // 全部发完：重置缓冲
    c->ssent = 0;
    c->q_full_since_ms = 0; // 队列清空：解除「持续满」计时
    // 大缓冲不常驻：一次性大帧（GetIDL 响应等）发完后释放，避免长连接长期占用峰值内存
    if (c->scap > 65536) {
      free(c->sbuf);
      c->sbuf = NULL;
      c->scap = 0;
    }
  }
}

int fw_tcp_conn_write(fw_stack_t *st, fw_tcpconn_t *c, const uint8_t *buf, uint32_t len) {
  if (!c || c->closed || !c->connected || len == 0) return FW_OK;
  c->last_send_ms = fw_now_ms(); // §5.7：发出任意帧刷新空闲计时
  size_t pending = conn_pending(c);

  // 1) 无积压：先尝试直写（成功则不占预算）。只有部分发送的余量才入队。
  if (pending == 0) {
    int n = (int)send(c->fd, (const char *)buf, (int)len, 0);
    if (n == (int)len) return FW_OK;
    if (n < 0 && !fw_plat_would_block()) return FW_ERR_IO;
    if (n < 0) n = 0;
    // 说明：此处不再做上限判定——已经发出 n 字节，余量必须入队才能保证帧完整，
    // 否则对端会收到半帧。极端情况下单次积压可短暂超过名义上限「最多一帧」，
    // 这是「不丢帧/不产生半帧」优先于名义上限的代价，由全栈预算与 60s 断连兜底。
    uint32_t rest = len - (uint32_t)n;
    if (sbuf_reserve(c, rest) != FW_OK) {
      st->sendq_rejects++;
      return FW_ERR_MEMORY; // 已发部分无法回滚：对端由半帧超时(§4.1)断连
    }
    memcpy(c->sbuf, buf + n, rest);
    c->slen = rest;
    c->ssent = 0;
    st->sendq_bytes += rest;
    sendq_touch_peak(st, c);
    return FW_OK;
  }

  // 2) 有积压：先判上限/预算，再压实追加（拒写发生在写入任何字节之前，不产生半帧）
  if (!sendq_has_room(st, pending, len)) return sendq_reject(st, c, len);
  if (c->ssent > 0) { // 压实已发前缀，回收空间
    memmove(c->sbuf, c->sbuf + c->ssent, c->slen - c->ssent);
    c->slen -= c->ssent;
    c->ssent = 0;
  }
  if (sbuf_reserve(c, c->slen + len) != FW_OK) {
    st->sendq_rejects++;
    return FW_ERR_MEMORY;
  }
  memcpy(c->sbuf + c->slen, buf, len);
  c->slen += len;
  st->sendq_bytes += len;
  sendq_touch_peak(st, c);
  return FW_OK;
}

int fw_tcp_send_frame(fw_stack_t *st, fw_tcpconn_t *c, const fw_frame_desc_t *d) {
  // GetIDL 响应可达数十 KB：动态编码缓冲（TCP 无 max_payload_len 约束，§2）
  uint32_t need = fw_frame_size(d);
  if (need == 0) return FW_ERR_PARAM;
  uint8_t stackbuf[4096];
  uint8_t *buf = stackbuf;
  uint8_t *heap = NULL;
  if (need > sizeof(stackbuf)) {
    heap = (uint8_t *)malloc(need);
    if (!heap) return FW_ERR_MEMORY;
    buf = heap;
  }
  uint32_t n = fw_frame_encode(buf, need, d);
  int rc = FW_OK;
  if (n) {
    if (d->ctr && n <= FW_CTRL_DIRECT_MAX) {
      // 小控制帧（RST/Ping/GetIDL 请求）：直写不入队，数据队列满时仍可发出
      rc = ctrl_direct_write(c, buf, n);
      c->last_send_ms = fw_now_ms();
      if (rc != FW_OK)
        fw_log(FW_LOG_WARN, "tcp", "ctrl frame not sent (rc=%d, %ubytes) %s", rc, n, c->addrkey);
    } else {
      rc = fw_tcp_conn_write(st, c, buf, n);
    }
  } else {
    rc = FW_ERR_PARAM;
  }
  free(heap);
  return rc;
}

// 发送队列水位/拒绝统计（实现限制的可观测项，非协议语义）
void fw_stats_sendq(const fw_stack_t *st, fw_sendq_stats_t *out) {
  if (!out) return;
  memset(out, 0, sizeof(*out));
  if (!st) return;
  out->queued_bytes = st->sendq_bytes;
  out->peak_bytes = st->sendq_peak;
  out->rejects = st->sendq_rejects;
  out->conn_closed_full = st->sendq_closed_full;
}

// ---- 客户端按需建连（§5.6 连接复用；并发建连挂等待者） ----

fw_tcpconn_t *fw_tcp_get_conn(fw_stack_t *st, const char *addr, uint16_t port,
                              fw_waiter_t *w, char *err, int errsz) {
  // 已有连接直接复用（§5.6：按 (IP, Port) 唯一长连接；connecting 中的连接同样复用并挂
  // 等待者——防止状态机重入路径（tick 驱动的 query_pump 等）反复建连）
  for (int i = 0; i < st->nconn; i++) {
    fw_tcpconn_t *c = st->conns[i];
    if (c->role != FW_ROLE_CLIENT || c->closed) continue;
    if (strcmp(c->ip, addr) != 0 || c->port != port) continue;
    if (c->connecting) {
      fw_log(FW_LOG_INFO, "tcp", "reuse connecting conn %s", c->addrkey);
      if (w) { if (!w->kind) w->kind = FW_W_CALL; w->next = c->waiters; c->waiters = w; }
      return c; // 连接进行中：等待者由 conn_finish_connect 唤醒
    }
    if (c->connected) {
      if (w) { w->kind = FW_W_NONE; w->ctx = NULL; w->next = NULL; } // 无需等待
      return c;
    }
  }
  // 非阻塞 connect
  fw_fd_t fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == FW_FD_INVALID) {
    snprintf(err, (size_t)errsz, "tcp socket create failed");
    return NULL;
  }
  fw_plat_set_nonblock(fd, 1);
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = inet_addr(addr);
  int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
  if (r != 0 && !fw_plat_would_block()) {
    snprintf(err, (size_t)errsz, "tcp connect %s:%u failed (err=%d)", addr, port, fw_plat_err());
    fw_plat_close(fd);
    return NULL;
  }
  fw_tcpconn_t *c = conn_new(st, fd, addr, port, FW_ROLE_CLIENT);
  if (!c) { fw_plat_close(fd); snprintf(err, (size_t)errsz, "out of memory"); return NULL; }
  c->connecting = (r != 0);
  c->connected = (r == 0);
  // 入表失败（连接表扩容 OOM）：关闭 fd 并释放连接，绝不留未注册连接（fd/内存泄漏）
  if (conns_add(st, c) != 0) {
    fw_plat_close(fd);
    conn_free(c);
    snprintf(err, (size_t)errsz, "tcp connection limit reached (max_conns=%u) or OOM", st->cfg.max_conns);
    return NULL;
  }
  fw_log(FW_LOG_INFO, "tcp", "new conn %s:%u r=%d connecting=%d connected=%d", addr, port, r, c->connecting, c->connected);
  if (w && c->connecting) {
    w->next = c->waiters; // 挂接：连接完成后由 conn_finish_connect 唤醒
    c->waiters = w;
  } else if (w) {
    w->kind = FW_W_NONE;
  }
  fw_log(FW_LOG_DEBUG, "tcp", "connecting to %s:%u", addr, port);
  return c;
}

fw_tcpconn_t *fw_tcp_find_server_by_ip(fw_stack_t *st, const char *ip) {
  for (int i = 0; i < st->nconn; i++) {
    fw_tcpconn_t *c = st->conns[i];
    if (c->role == FW_ROLE_SERVER && c->connected && !c->closed && strcmp(c->ip, ip) == 0)
      return c;
  }
  return NULL;
}

// ---- poll 就绪处理 ----

static void tcp_accept(fw_stack_t *st) {
  for (;;) {
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    fw_fd_t fd = accept(st->tcp_listen, (struct sockaddr *)&sa, &sl);
    if (fd == FW_FD_INVALID) return;
    char ip[48];
    snprintf(ip, sizeof(ip), "%s", inet_ntoa(sa.sin_addr));
    uint16_t port = ntohs(sa.sin_port);
    fw_plat_set_nonblock(fd, 1);
    fw_tcpconn_t *c = conn_new(st, fd, ip, port, FW_ROLE_SERVER);
    if (!c) { fw_plat_close(fd); continue; }
    // 入表失败：关闭并释放，避免未注册连接泄漏（服务端可无限 accept，风险更高）
    if (conns_add(st, c) != 0) {
      fw_plat_close(fd);
      conn_free(c);
      fw_log(FW_LOG_WARN, "tcp", "drop accepted from %s:%u (limit %u reached or OOM)", ip, port, st->cfg.max_conns);
      continue;
    }
    fw_log(FW_LOG_DEBUG, "tcp", "accepted from %s", c->addrkey);
  }
}

static void conn_finish_connect(fw_stack_t *st, fw_tcpconn_t *c) {
  int err = 0;
  socklen_t elen = sizeof(err);
  getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
  // 降 DEBUG：connect 未完成时每轮 poll 都会打印，属日志风暴源
  fw_log(FW_LOG_DEBUG, "tcp", "finish_connect check: %s err=%d", c->addrkey, err);
  if (err != 0 && fw_plat_would_block()) return; // connect 未完成（勿误判失败）
  if (err != 0) {
    fw_log(FW_LOG_WARN, "tcp", "connect failed to %s (err=%d)", c->addrkey, err);
    fw_tcp_conn_close(st, c); // 等待者由 fw_waiters_fire_fail 标记失败
    return;
  }
  c->connecting = 0;
  c->connected = 1;
  c->last_send_ms = c->last_recv_ms = fw_now_ms();
  fw_log(FW_LOG_DEBUG, "tcp", "connected to %s", c->addrkey);
  fw_waiters_fire(st, &c->waiters); // 唤醒等待者（继续原操作）
}

static void conn_read(fw_stack_t *st, fw_tcpconn_t *c) {
  uint8_t buf[16384];
  for (;;) {
    int n = (int)recv(c->fd, (char *)buf, sizeof(buf), 0);
    if (n > 0) {
      int was_receiving = fw_sp_receiving(&c->parser);
      int was_dropping = c->parser.drop_mode; // feed 前是否处于丢弃模式（§4.1 阶段二）
      c->last_recv_ms = fw_now_ms(); // §5.7：收到任意帧（字节）即刷新存活计时
      // feed 失败（realloc 不足）→ 连接数据流不可靠，关闭连接
      if (fw_sp_feed(&c->parser, buf, (size_t)n) != FW_OK) {
        fw_tcp_conn_close(st, c);
        return;
      }
      // 半帧计时起点：receiving 跳变记录（§4.1 帧开始接收）。
      // 丢弃模式在同一批数据收满 R 字节后可能立即开始新半帧，此时 was_receiving
      // 仍为真（fw_sp_receiving 包含 drop_mode），必须显式用 was_dropping 重置
      // 起点，否则 frame_start_ms 保留旧帧时刻，新半帧会被立即判定超时。
      if (fw_sp_receiving(&c->parser) && !c->parser.drop_mode && (!was_receiving || was_dropping))
        c->frame_start_ms = fw_now_ms();
      // 丢弃模式每收任意字节刷新兜底计时（§4.1 退出条件 3）
      if (c->parser.drop_mode) c->parser.drop_last_ms = fw_now_ms();
      continue;
    }
    if (n == 0) {
      // 对端 EOF：随连接关闭一并处理（§4.1 退出条件 2；§5.6 重连由上层按需触发）
      fw_tcp_conn_close(st, c);
      return;
    }
    if (fw_plat_would_block()) return;
    fw_tcp_conn_close(st, c); // 连接错误
    return;
  }
}

void fw_tcp_poll(fw_stack_t *st) {
  if (st->tcp_listen != FW_FD_INVALID) tcp_accept(st);
  // 倒序遍历（处理中可能关闭连接）
  for (int i = st->nconn - 1; i >= 0; i--) {
    fw_tcpconn_t *c = st->conns[i];
    if (!c || c->closed) continue;
    if (c->connecting) {
      // 降 DEBUG：每轮 poll（20ms）对 connecting 连接打印 INFO 形成
      // 建连期间日志风暴（conn_finish_check 的同类日志一并降级）
      fw_log(FW_LOG_DEBUG, "tcp", "poll connecting conn %s", c->addrkey);
      conn_finish_connect(st, c);
      continue;
    }
    conn_read(st, c);
  }
}

// 发送缓冲 flush（POLLOUT 就绪时由 stack 调用）
void fw_tcp_flush_all(fw_stack_t *st) {
  for (int i = 0; i < st->nconn; i++) {
    fw_tcpconn_t *c = st->conns[i];
    if (c && !c->closed && c->connected && c->slen > c->ssent) fw_tcp_flush(c);
  }
}

// ---- 半帧 RST(0x26)（§4.1） ----

// RST(0x26) 帧形态（实现裁定，对齐 fw-nodejs README 偏差 1）：按 CTR=1 控制帧
// 形态发送（全 0 标识——数据帧 SvcID 必须≠0）；StrmID 仅在 0x01~0x7F 时回显
static void send_frame_timeout_rst(fw_stack_t *st, fw_tcpconn_t *c, int header_complete) {
  uint8_t strm = 0;
  // 必须按有效区间起点 off 取址：粘包消费后 off 前移，buf[7] 会读到已消费帧的 StrmID
  if (header_complete && c->parser.len >= 8) {
    uint8_t s = c->parser.buf[c->parser.off + 7];
    if (s >= 0x01 && s <= 0x7F) strm = s;
  }
  fw_frame_desc_t d;
  fw_make_rst(&d, FW_RST_FRAME_TIMEOUT, 1, 0, 0, 0, strm);
  // 半帧 RST 属小控制帧（直写）：失败时阶段一随后关连接、阶段二保持丢弃模式，无需重试
  int rc = fw_tcp_send_frame(st, c, &d);
  if (rc != FW_OK)
    fw_log(FW_LOG_WARN, "tcp", "half-frame RST not sent (rc=%d) %s", rc, c->addrkey);
  fw_log_frame(FW_LOG_WARN, 0, 0, 0, strm, "Tx", c->addrkey, FW_RST_FRAME_TIMEOUT,
               header_complete ? "Frame Timeout (payload incomplete) -> drop mode"
                               : "Frame Timeout (header incomplete), closing connection");
}

// ---- 半帧两阶段 + 心跳（时间驱动，§4.1/§5.7） ----

void fw_tcp_tick(fw_stack_t *st, int64_t now) {
  for (int i = st->nconn - 1; i >= 0; i--) {
    fw_tcpconn_t *c = st->conns[i];
    if (!c || c->closed || !c->connected || c->connecting) continue;

    // 发送背压（实现限制）：队列持续满超过心跳窗口 → 主动断连。
    // 「持续满」指从首次拒写（q_full_since_ms）起队列一直未清空；期间对端若恢复读取，
    // fw_tcp_flush 清空队列会重置该计时，不会被误断。
    if (conn_pending(c) == 0) {
      c->q_full_since_ms = 0;
    } else if (c->q_full_since_ms &&
               now - c->q_full_since_ms >= (int64_t)(2 * st->cfg.heartbeat_period_ms)) {
      fw_log(FW_LOG_WARN, "tcp", "send queue full for %lldms (>= 2 x heartbeat %ums), closing %s",
             (long long)(now - c->q_full_since_ms), 2 * st->cfg.heartbeat_period_ms, c->addrkey);
      st->sendq_closed_full++;
      fw_tcp_conn_close(st, c);
      continue;
    }

    // 半帧两阶段（§4.1）
    if (c->parser.drop_mode) {
      // 兜底超时 = 2 × tcp_frame_timeout_ms（协议固定倍率，不新增配置项）
      if (now - c->parser.drop_last_ms >= (int64_t)(2 * st->cfg.tcp_frame_timeout_ms)) {
        fw_log(FW_LOG_WARN, "tcp", "drop mode fallback timeout, closing %s", c->addrkey);
        fw_tcp_conn_close(st, c);
        continue;
      }
    } else if (fw_sp_receiving(&c->parser)) {
      // 帧开始接收后超过 tcp_frame_timeout_ms 未收完
      if (now - c->frame_start_ms >= (int64_t)st->cfg.tcp_frame_timeout_ms) {
        if (fw_sp_header_complete(&c->parser)) {
          // 阶段二：帧头完整、Payload 不完整 → RST(0x26) + 丢弃模式（连接不关闭）
          send_frame_timeout_rst(st, c, 1);
          fw_sp_enter_drop_mode(&c->parser, now);
        } else {
          // 阶段一：帧头不完整（<8B）→ RST(0x26) + 关闭连接（帧总长不可知无法重同步）
          send_frame_timeout_rst(st, c, 0);
          fw_tcp_conn_close(st, c);
          continue;
        }
      }
    }

    // 心跳（§5.7，仅 TCP）
    uint32_t hb_to = st->cfg.heartbeat_period_ms * 2; // 存活判定 = 2 × period
    if (now - c->last_recv_ms >= (int64_t)hb_to) {
      fw_log(FW_LOG_WARN, "tcp", "heartbeat timeout (%lldms since last frame), mark dead: %s",
             (long long)(now - c->last_recv_ms), c->addrkey);
      fw_tcp_conn_close(st, c);
      continue;
    }
    if (now - c->last_send_ms >= (int64_t)st->cfg.heartbeat_period_ms) {
      // 空闲判定：距上次发出任意帧超过 heartbeat_period → 发一次 Ping
      // Ping 帧：CTR=1, REN=0, TYP=NON, Code=0x00, 全 0 标识, 空 Payload（§5.7）
      fw_frame_desc_t ping;
      memset(&ping, 0, sizeof(ping));
      ping.ctr = 1;
      ping.typ = FW_TYP_NON;
      ping.code = 0x00;
      ping.ver = st->cfg.ver;
      // Ping 属小控制帧（直写）：对端暂不可写时跳过本次，2×period 后由失效判定兜底
      int rc = fw_tcp_send_frame(st, c, &ping);
      if (rc != FW_OK) fw_log(FW_LOG_DEBUG, "tcp", "ping skipped (rc=%d) %s", rc, c->addrkey);
      c->last_send_ms = now;
    }
  }
}

// 停止：关闭监听与全部连接
void fw_tcp_stop(fw_stack_t *st) {
  if (st->tcp_listen != FW_FD_INVALID) {
    fw_plat_close(st->tcp_listen);
    st->tcp_listen = FW_FD_INVALID;
  }
  for (int i = st->nconn - 1; i >= 0; i--) {
    fw_tcpconn_t *c = st->conns[i];
    if (c) fw_tcp_conn_close(st, c);
  }
  free(st->conns);
  st->conns = NULL;
  st->nconn = st->conncap = 0;
}