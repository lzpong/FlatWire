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
  fw_tcp_send_frame(c->stk, c, &d);
  fw_log_frame(FW_LOG_WARN, echo->rst_svc, echo->rst_if, echo->rst_inst, echo->rst_strm,
               "Tx", c->addrkey, code, fw_rst_name(code));
}

static void on_sp_drop_complete(void *ud) {
  (void)ud; // 丢弃模式结束：兜底计时由 tick 依 drop_mode 判定，无需额外动作
}

// ---- 连接创建/销毁 ----

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

static void conns_add(fw_stack_t *st, fw_tcpconn_t *c) {
  if (st->nconn == st->conncap) {
    int nc = st->conncap ? st->conncap * 2 : 8;
    fw_tcpconn_t **np = (fw_tcpconn_t **)realloc(st->conns, (size_t)nc * sizeof(fw_tcpconn_t *));
    if (!np) return;
    st->conns = np;
    st->conncap = nc;
  }
  st->conns[st->nconn++] = c;
}

// ---- 发送 ----

void fw_tcp_flush(fw_tcpconn_t *c) {
  while (c->ssent < c->slen) {
    int n = (int)send(c->fd, (const char *)c->sbuf + c->ssent, (int)(c->slen - c->ssent), 0);
    if (n > 0) {
      c->ssent += (size_t)n;
      continue;
    }
    return; // EWOULDBLOCK（POLLOUT 继续）或错误（关闭路径处理）
  }
  c->slen = 0;  // 全部发完：重置缓冲
  c->ssent = 0;
}

void fw_tcp_conn_write(fw_tcpconn_t *c, const uint8_t *buf, uint32_t len) {
  if (!c || c->closed || !c->connected || len == 0) return;
  c->last_send_ms = fw_now_ms(); // §5.7：发出任意帧刷新空闲计时
  if (c->slen == 0) {
    // 无积压：直接尝试发送（避免无谓拷贝）
    int n = (int)send(c->fd, (const char *)buf, (int)len, 0);
    if (n == (int)len) return;
    if (n < 0 && !fw_plat_would_block()) return;
    if (n < 0) n = 0;
    // 部分发送：余量入缓冲
    uint32_t rest = len - (uint32_t)n;
    if (rest > c->scap) {
      uint8_t *nb = (uint8_t *)realloc(c->sbuf, rest);
      if (!nb) return;
      c->sbuf = nb;
      c->scap = rest;
    }
    memcpy(c->sbuf, buf + n, rest);
    c->slen = rest;
    c->ssent = 0;
    return;
  }
  // 有积压：压实后追加
  if (c->ssent > 0) {
    memmove(c->sbuf, c->sbuf + c->ssent, c->slen - c->ssent);
    c->slen -= c->ssent;
    c->ssent = 0;
  }
  if (c->slen + len > c->scap) {
    size_t nc = c->scap ? c->scap : 1024;
    while (nc < c->slen + len) nc *= 2;
    uint8_t *nb = (uint8_t *)realloc(c->sbuf, nc);
    if (!nb) return;
    c->sbuf = nb;
    c->scap = nc;
  }
  memcpy(c->sbuf + c->slen, buf, len);
  c->slen += len;
}

int fw_tcp_send_frame(fw_stack_t *st, fw_tcpconn_t *c, const fw_frame_desc_t *d) {
  (void)st;
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
  if (n) fw_tcp_conn_write(c, buf, n);
  else rc = FW_ERR_PARAM;
  free(heap);
  return rc;
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
  conns_add(st, c);
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
    conns_add(st, c);
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
      c->last_recv_ms = fw_now_ms(); // §5.7：收到任意帧（字节）即刷新存活计时
      // feed 失败（realloc 不足）→ 连接数据流不可靠，关闭连接
      if (fw_sp_feed(&c->parser, buf, (size_t)n) != FW_OK) {
        fw_tcp_conn_close(st, c);
        return;
      }
      // 半帧计时起点：receiving 跳变记录（§4.1 帧开始接收）
      if (!was_receiving && fw_sp_receiving(&c->parser) && !c->parser.drop_mode)
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
  if (header_complete && c->parser.len >= 8) {
    uint8_t s = c->parser.buf[7];
    if (s >= 0x01 && s <= 0x7F) strm = s;
  }
  fw_frame_desc_t d;
  fw_make_rst(&d, FW_RST_FRAME_TIMEOUT, 1, 0, 0, 0, strm);
  fw_tcp_send_frame(st, c, &d);
  fw_log_frame(FW_LOG_WARN, 0, 0, 0, strm, "Tx", c->addrkey, FW_RST_FRAME_TIMEOUT,
               header_complete ? "Frame Timeout (payload incomplete) -> drop mode"
                               : "Frame Timeout (header incomplete), closing connection");
}

// ---- 半帧两阶段 + 心跳（时间驱动，§4.1/§5.7） ----

void fw_tcp_tick(fw_stack_t *st, int64_t now) {
  for (int i = st->nconn - 1; i >= 0; i--) {
    fw_tcpconn_t *c = st->conns[i];
    if (!c || c->closed || !c->connected || c->connecting) continue;

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
      fw_tcp_send_frame(st, c, &ping);
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