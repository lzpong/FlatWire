// ============================================================
// fw_int.h —— 协议栈内部契约（模块间共享结构，不对应用暴露）
//
// 模块划分与 fw-nodejs 一一对应：transport / sd / rpc / events /
// idlstore / strm / stack。单线程非阻塞事件循环（poll），时间驱动
// 定时统一在 fw_stack_tick 检查（无独立定时器线程）。
// ============================================================

#ifndef FW_INT_H
#define FW_INT_H

#include "fw/fw.h"
#include "platform/platform.h"

// ---------- 帧元信息（分发 meta，对齐 fw-nodejs meta） ----------
typedef struct {
  int transport;      // 0=udp 1=tcp
  char address[48];
  uint16_t port;
  struct fw_tcpconn *conn; // tcp 时非 NULL
} fw_meta_t;

// ---------- 等待者（手工状态机挂接点） ----------
struct fw_tcpconn;   // 前置声明（定义见下，避免原型内局部 tag 作用域问题）
struct fw_call_ctx;  // 前置声明（定义见下）
enum { FW_W_NONE = 0, FW_W_CALL = 1 }; // 移除死代码 FW_W_REG；移除无动作的 FW_W_FIND
#define FW_WAITING 1 // 异步等待中（正值，与负值错误码区分）
typedef struct fw_waiter {
  int kind;
  void *ctx;
  struct fw_waiter *next;
} fw_waiter_t;

void fw_call_advance(fw_stack_t *st, void *ctx); // call/ff ctx 推进
// 逐个唤醒等待者（链表遍历；回调内可自行摘除）
void fw_waiters_fire(fw_stack_t *st, fw_waiter_t **head);
// 连接失败：等待者标记错误（tcp.c 关闭路径调用）
void fw_waiters_fire_fail(fw_stack_t *st, struct fw_tcpconn *c);
// call ctx 完成通知（async 场景触发回调；stack.c/rpc.c 共用）
void fw_call_advance_notify_done(fw_stack_t *st, struct fw_call_ctx *ctx);

// ---------- TCP 连接（§5.6） ----------
#define FW_ROLE_CLIENT 0
#define FW_ROLE_SERVER 1

typedef struct fw_tcpconn {
  fw_fd_t fd;
  char ip[48];
  uint16_t port;
  char addrkey[80];        // "ip:port"（peer 键口径与 UDP Offer 源一致）
  int role;
  int connecting;          // 非阻塞 connect 进行中
  int connected;
  int closed;
  struct fw_stack *stk;    // 所属栈（parser 回调定位）
  fw_stream_parser_t parser;
  int64_t frame_start_ms;  // receiving 跳变时刻（半帧超时判定 §4.1）
  // 发送缓冲（非阻塞 send 未发完的字节）
  uint8_t *sbuf;
  size_t slen, scap, ssent;
  // 心跳（§5.7）
  int64_t last_send_ms, last_recv_ms;
  // 连接完成等待者（GetIDL/rpc 挂接）
  fw_waiter_t *waiters;
} fw_tcpconn_t;

// ---------- 服务端本地实例（§7.3） ----------
typedef struct {
  uint16_t svc_id;
  uint8_t inst_id;
  fw_schema_t *schema;    // 引用 idlstore 条目（生命周期归 idlstore）
  fw_handlers_t handlers;
} fw_local_t;

// ---------- 服务端订阅者（§8.1） ----------
#define FW_ST_ACTIVE  0
#define FW_ST_EXPIRED 1

typedef struct {
  char key[200];           // "ip|port|svc|inst|i{ifId}|g{grpId}"
  uint16_t svc_id;
  uint8_t inst_id;
  uint16_t if_id;
  uint8_t grp_id;
  char peer_ip[48];
  uint16_t peer_port;
  uint8_t session_strm;
  int ttl_left;            // 秒
  int state;               // FW_ST_*
} fw_sub_rec_t;

// ---------- 客户端发现缓存 + 状态机（§7.4） ----------
enum { FW_CS_UNKNOWN = 0, FW_CS_FOUND, FW_CS_SUBSCRIBED, FW_CS_UNSUBSCRIBED, FW_CS_EXPIRED };

typedef struct {
  uint16_t svc_id;
  uint8_t inst_id;
  uint8_t major_ver, minor_ver;
  char addr[48];
  uint16_t port;
  uint8_t ver;             // Offer 帧版本（is_available 的 VER 判定 §13.2）
  int ttl_left;            // 秒
  int state;               // FW_ST_ACTIVE / FW_ST_EXPIRED
  int client_state;        // FW_CS_*
  int64_t expire_at;       // Expired 时刻（§2 降级窗口起点，0=未记录）
  int64_t last_ufind_ms;   // 上次单播 Find 时刻（组播降级周期，§2）
} fw_disc_rec_t;

// ---------- 客户端订阅会话（§7.2 会话 StrmID 规则） ----------
enum { FW_SESS_PENDING = 0, FW_SESS_ESTABLISHING = 1, FW_SESS_ACTIVE = 2 };

typedef struct {
  uint32_t handle;
  uint16_t svc_id;
  uint8_t inst_id;
  uint16_t if_id;
  uint8_t grp_id;
  fw_event_cb on_event;
  void *ud;
  int state;
  char peer[80];
  char addr[48];
  uint16_t port;
  int session_strm;        // 0=未分配
  char retrans_key[224];
  // 移除 cancel_deadline：unsubscribe 改用独立取消等待表（cancels），
  // 避免会话立即移除导致的槽位覆盖丢失（原实现把 deadline 写在即将被 swap 覆盖的槽位）
} fw_session_t;

// ---------- 订阅取消等待（§8.1 场景4；对齐 fw-nodejs cancelPending） ----------
// unsubscribe 后会话立即从 sessions 移除（应用视角完成），但取消确认 ACK(0x00)
// 到达前会话 StrmID 仍活跃——保留于此表直至确认释放/重传耗尽兜底释放（§6.1/6.5）
typedef struct {
  char peer[80];           // "ip:port"（会话 StrmID 所属控制池键）
  int strm;                // 待释放的会话 StrmID
  char retrans_key[224];   // 取消 CON 的重传键（确认/兜底时取消）
  int64_t deadline;        // 重传耗尽兜底时刻（0=无）
} fw_cancel_pend_t;

// ---------- GetIDL 查询（客户端，§7.2 协议栈内部行为） ----------
typedef struct {
  uint16_t svc_id;
  uint8_t major_ver;
  char addr[48];
  uint16_t port;
  char peer[80];
  int strm;                // 0=未分配
  int sent;                // 请求帧已发出（0=尚未发送，超时判定前置条件）
  int64_t deadline_ms;     // 查询超时复用 response_timeout_ms（附录 A）
  int done;
  int err;
  char msg[160];
  fw_waiter_t *waiters;
} fw_idl_query_t;

// 主动 Find 等待（§7.4 Unknown→Found）
typedef struct {
  uint16_t svc_id;
  uint8_t inst_id;
  int64_t deadline_ms;
  fw_waiter_t *waiters;
} fw_pend_find_t;

// 确认缓存（重复 CON 重发确认，§5.5/§8.1）
typedef struct {
  char key[224];           // "ip:port|strm"
  uint8_t frame[32];
  uint32_t flen;
  int is_cancel;
  int64_t expiry;
} fw_ack_cache_t;

// ---------- 重传表（§5.5：0/200/600/1400ms 时间线，3000ms 静默停止） ----------
typedef struct {
  char key[224];
  uint8_t *buf; uint32_t len;
  int retries;             // 已重传次数
  int64_t next_ms;         // 下次动作时刻（重传或停止清理）
  char addr[48];
  uint16_t port;
  int which;               // 0=client socket 1=main socket
} fw_retrans_t;

typedef struct {
  fw_retrans_t *items; int n, cap;
  uint32_t interval_ms;
  int max_retry;
} fw_retrans_table_t;

// ---------- sd 模块状态 ----------
typedef struct {
  // 服务端角色
  fw_local_t *locals; int nlocals, locals_cap;
  fw_sub_rec_t *subs; int nsubs, subs_cap;
  // 客户端角色
  fw_disc_rec_t *disc; int ndisc, disc_cap;
  fw_session_t *sessions; int nsess, sess_cap;
  uint32_t handle_seq;
  fw_cancel_pend_t *cancels; int ncxl, cxlcap; // 取消等待表（ACK(0x00) 前保留会话 StrmID）
  fw_pend_find_t *pf; int npf, pfcap;
  fw_idl_query_t *queries; int nq, qcap;
  fw_ack_cache_t *ack; int nack, ackcap;
  fw_retrans_table_t retrans; // SD 单播帧重传（Find/Subscribe 等，§5.5）
  int64_t last_keepalive_ms;  // 订阅保活 tick 基准（§8 订阅 TTL 维护）
} fw_disc_t;

// ---------- rpc 模块状态（§5.1/§5.2/§5.5） ----------
enum { FW_STAGE_RESOLVE = 0, FW_STAGE_SEND = 1, FW_STAGE_WAIT = 2 };

// 补 tag fw_call_ctx：与文件头前置声明/next·anext 字段声明的
// struct fw_call_ctx 为同一类型（原匿名 typedef 与前置声明类型分裂）
typedef struct fw_call_ctx {
  uint16_t svc_id;
  uint8_t inst_id;
  uint16_t if_id;
  int is_ff;               // fire_forget 场景
  fw_value_t *payload;
  fw_value_t *resp;
  int done, err;
  char msg[160];
  int sync;                // 同步泵等待（fw_call）
  fw_call_cb cb;
  void *ud;
  int stage;
  fw_waiter_t w;           // 挂接点（find / idl / conn）
  char addr[48];
  uint16_t port;
  char peer[80];
  int strm;                // 0=未分配
  char key[224];           // "peer|svc|inst|strm"
  fw_schema_t *schema;     // 引用 idlstore（不释放）
  fw_iface_t *iface;
  int is_udp;
  int64_t deadline_ms;     // 响应超时（wait 阶段）/ ff 兜底释放
  uint32_t timeout_ms;     // 本次调用响应超时（0=默认 response_timeout_ms，附录 A）
  int rst_code;            // 收到 RST 的具体码（FW_ERR_RST 时 fw_result_t.rst_code）
  struct fw_call_ctx *next;
  struct fw_call_ctx *anext; // 全量活动 ctx 注册链（stop 时 flush 未完成 async 回调）
} fw_call_ctx_t;

// 服务端响应缓存（§5.5 去重：重复 CON 请求重发缓存响应）
typedef struct {
  char key[224];
  int done;
  uint8_t *ack_raw; uint32_t ack_len;
  uint8_t *resp_raw; uint32_t resp_len;
  int64_t expiry;
} fw_resp_cache_t;

typedef struct {
  fw_retrans_table_t retrans;
  fw_call_ctx_t *pending;    // wait 阶段调用链表
  fw_call_ctx_t *ff_pending; // UDP ff 等 ACK 链表
  fw_call_ctx_t *active;     // 全量活动调用注册链（含 resolve 阶段 async ctx）
  fw_resp_cache_t *cache; int ncache, cachecap;
} fw_rpc_t;

// ---------- events 模块状态（§8） ----------
typedef struct {
  char key[96];            // "svc:inst:ifId"
  uint8_t *buf;
  uint32_t len;
} fw_notify_cache_t;

typedef struct {
  char key[224];
  char peer[80];
  uint16_t svc_id;
  uint8_t inst_id;
  int strm;
  char addr[48];
  uint16_t port;
  int64_t deadline;        // CON 推送重传耗尽兜底释放
} fw_push_pending_t;

typedef struct {
  char key[224];
  int64_t expiry;
} fw_recv_rec_t;

typedef struct {
  fw_notify_cache_t *ncache; int nnc, nccap;
  fw_retrans_table_t retrans;
  fw_push_pending_t *push; int npush, pushcap;
  fw_recv_rec_t *recv; int nrecv, recvcap;
} fw_events_t;

// ---------- 协议栈完整结构 ----------
struct fw_stack {
  fw_config_t cfg;
  char idl_dir[260];
  char mcast[48];
  char bind[48];
  fw_strm_mgr_t *strm;
  fw_idlstore_t *idl;
  fw_disc_t disc;
  fw_rpc_t rpc;
  fw_events_t ev;
  // sockets（§2 双 socket：main bind port / client 临时端口）
  fw_fd_t udp_main, udp_client;
  uint16_t client_port;
  fw_fd_t tcp_listen;
  fw_tcpconn_t **conns; int nconn, conncap;
  // 本机地址集（自我回环过滤；平台枚举扩容 8→16）
  char local_addrs[16][48]; int nlocal;
  // 定时
  int64_t last_offer_ms, last_tick_ms;
  int started;
  int dispatch;            // 分发深度（同步 API 重入保护）
  int stop_requested;
  fw_result_t last_err;
  // 时钟注入（测试专用）
  int64_t (*clock_override)(void);
};

// ============================================================
// 模块间函数（stack.c 提供，各模块调用）
// ============================================================

// 记录错误详情（fw_stack_last_error 读取）
void fw_stack_fail(fw_stack_t *st, int code, int rst_code, const char *fmt, ...);

// ---- UDP 发送（transport/udp.c） ----
int fw_udp_sockets_open(fw_stack_t *st, char *err, int errsz); // 双 socket 打开（main+client 临时端口）
void fw_udp_sockets_close(fw_stack_t *st);                     // 双 socket 关闭（stack stop 路径）
void fw_udp_poll(fw_stack_t *st);                              // UDP 双 socket 收包 + 分发
void fw_udp_sendto_raw(fw_stack_t *st, const char *addr, uint16_t port, int which,
                       const uint8_t *buf, uint32_t len);
void fw_udp_send_multicast_raw(fw_stack_t *st, int which, const uint8_t *buf, uint32_t len);
// 编码帧并发送（FW_OK / 错误码）
int fw_udp_send_frame(fw_stack_t *st, const fw_frame_desc_t *d, const char *addr, uint16_t port, int which);
int fw_udp_send_mcast_frame(fw_stack_t *st, const fw_frame_desc_t *d, int which);

// ---- TCP（transport/tcp.c） ----
// 服务端 TCP 监听（fw_stack_start 内部调用；测试可单独使用）
int fw_tcp_listen(fw_stack_t *st, char *err, int errsz);
// 服务端 TCP 停止（关监听与全部连接；测试可单独使用）
void fw_tcp_stop(fw_stack_t *st);
// 获取/建立到 (addr, port) 的出站长连接（§5.6 复用）；w 非 NULL 时挂接连接完成等待者
fw_tcpconn_t *fw_tcp_get_conn(fw_stack_t *st, const char *addr, uint16_t port,
                              fw_waiter_t *w, char *err, int errsz);
// 按远端 IP 查找服务端入站连接（tcp-event 推送按订阅者源 IP 匹配，§8.2）
fw_tcpconn_t *fw_tcp_find_server_by_ip(fw_stack_t *st, const char *ip);
void fw_tcp_conn_write(fw_tcpconn_t *c, const uint8_t *buf, uint32_t len);
int fw_tcp_send_frame(fw_stack_t *st, fw_tcpconn_t *c, const fw_frame_desc_t *d);
void fw_tcp_conn_close(fw_stack_t *st, fw_tcpconn_t *c);
void fw_tcp_tick(fw_stack_t *st, int64_t now);   // 半帧两阶段 + 心跳（§4.1/§5.7）
void fw_tcp_flush(fw_tcpconn_t *c);              // 尝试发送缓冲
void fw_tcp_poll(fw_stack_t *st);                // TCP 连接收发轮询（accept/recv/send）
void fw_tcp_flush_all(fw_stack_t *st);           // 全连接发送缓冲冲刷（poll 末尾统一驱动）

// ---- RST 帧构造（§5.4：回显触发帧标识） ----
void fw_make_rst(fw_frame_desc_t *d, int code, int ctr, uint16_t svc, uint16_t if_id,
                 uint8_t inst, uint8_t strm);

// ---- 帧分发总线（stack.c） ----
void fw_stack_on_frame(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);

// ---- discovery（sd/discovery.c） ----
void fw_disc_init(fw_stack_t *st);
void fw_disc_free(fw_stack_t *st);
void fw_disc_tick(fw_stack_t *st, int64_t now);           // Offer 周期 + 1s TTL tick
void fw_disc_tick_1s(fw_stack_t *st);                     // TTL 推进（§7.5）
void fw_disc_on_ren(fw_stack_t *st, const fw_meta_t *meta);
void fw_disc_on_offer(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_disc_on_find(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_disc_on_subscribe(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_disc_on_getidl(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_disc_on_getidl_resp(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_disc_on_subscribe_ack(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_disc_on_unsubscribe_ack(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_disc_on_ctrl_rst(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_disc_on_tcp_closed(fw_stack_t *st, const char *ip);
void fw_disc_stop(fw_stack_t *st);

// 服务端登记（stack.c register 流程调用）
int fw_disc_register(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                     fw_schema_t *schema, const fw_handlers_t *handlers, char *err, int errsz);
int fw_disc_unregister(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id);
fw_local_t *fw_disc_get_local(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id);

// 客户端查询
fw_disc_rec_t *fw_disc_get_discovered(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id);
int fw_disc_online_major_ver(fw_stack_t *st, uint16_t svc_id); // -1=无在线实例
// 订阅者快照改堆分配（原 static[64] 硬上限静默截断）：*out 由调用者 free
void fw_disc_subscribers_of(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                            fw_sub_rec_t **out, int *out_n);
void fw_disc_on_subscription_added(fw_stack_t *st, const fw_meta_t *meta,
                                   const fw_sub_entry_t *entries, int n);
// 组成员列表改堆分配（原调用方 out[64] 硬上限）：*out 由调用者 free
void fw_disc_group_members(fw_stack_t *st, uint16_t svc_id, uint8_t grp_id,
                           uint16_t **out, int *out_n);

// GetIDL 客户端（§7.2 双角色统一）：失败设置 *err_code 并返回 NULL
fw_schema_t *fw_disc_fetch_idl(fw_stack_t *st, uint16_t svc_id, uint8_t major_ver,
                               int *err_code, char *err, int errsz);
// 异步版（subscribe 预拉取等；完成无回调，结果落 idlstore）
void fw_disc_fetch_idl_async(fw_stack_t *st, uint16_t svc_id, uint8_t major_ver);
// 查询推进（deadline 到期失败等，tick 调用）
void fw_disc_tick_queries(fw_stack_t *st, int64_t now);

// 订阅会话（客户端）
uint32_t fw_disc_subscribe(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                           uint16_t if_id, uint8_t grp_id, fw_event_cb cb, void *ud);
int fw_disc_unsubscribe(fw_stack_t *st, uint32_t handle);
void fw_disc_session_tick(fw_stack_t *st, int64_t now); // 订阅保活 + 取消兜底（§7.2/§8.1）
// 移除死声明 fw_disc_cancel_tick（无实现，取消兜底由 session_tick 承担）

// find（客户端）
int fw_disc_find(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                 uint32_t timeout_ms, fw_svc_info_t *out, char *err, int errsz);
void fw_disc_tick_find(fw_stack_t *st, int64_t now);
// 异步 Find（call 状态机驱动版：已命中 FW_OK / 等待 FW_WAITING / 失败错误码）
int fw_disc_find_start(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                       fw_waiter_t *w, fw_svc_info_t *out, char *err, int errsz);
// GetIDL 查询挂接：创建/合并查询并挂 waiter；无在线实例返回 NULL（§7.2/5.22）
fw_idl_query_t *fw_disc_query_attach(fw_stack_t *st, uint16_t svc_id, uint8_t major_ver,
                                     fw_waiter_t *w, char *err, int errsz);

// ---- rpc（rpc/rpc.c） ----
void fw_rpc_init(fw_stack_t *st);
void fw_rpc_free(fw_stack_t *st);
void fw_rpc_on_frame(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_rpc_tick(fw_stack_t *st, int64_t now);
void fw_rpc_on_ren(fw_stack_t *st, const char *ip);
void fw_rpc_on_tcp_closed(fw_stack_t *st, const char *ip);
// 注册 ctx 作为 GetIDL 等待者的推进入口（fw_call_advance 内部分发）
void fw_rpc_call_ctx_free(fw_stack_t *st, fw_call_ctx_t *ctx);
// call ctx 创建（calloc 归零 + 字段填充；失败释放 payload 并返回 NULL）
fw_call_ctx_t *fw_call_ctx_new(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                               fw_value_t *payload, int is_ff, uint32_t timeout_ms);
// call ctx 资源释放（响应/负载/StrmID/重传登记；rpc.c 内部与 stack.c 共用）
void fw_call_ctx_free(fw_stack_t *st, fw_call_ctx_t *ctx);
// call ctx 从 pending/ff_pending 链表摘除（放弃等待时防悬空，§5 状态机）
void fw_call_detach(fw_stack_t *st, fw_call_ctx_t *ctx);
// stop 前冲刷全部未完成调用：async ctx 以 err 触发回调（不悬挂）
void fw_rpc_flush_all_pending(fw_stack_t *st, int err, const char *msg);

// ---- events（events/events.c） ----
void fw_events_init(fw_stack_t *st);
void fw_events_free(fw_stack_t *st);
void fw_events_on_frame(fw_stack_t *st, const fw_frame_t *f, const fw_meta_t *meta);
void fw_events_notify(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                      fw_value_t *payload);
// 全量推送（订阅建立后按订阅者推送对应接口缓存；纯数据分发，§8.1）
void fw_events_push_cached_for(fw_stack_t *st, const fw_meta_t *meta,
                               const fw_sub_entry_t *entries, int n);
void fw_events_tick(fw_stack_t *st, int64_t now);
void fw_events_on_ren(fw_stack_t *st, const char *ip);
void fw_events_stop(fw_stack_t *st);

// ---- 重传表（rpc/retransmit.c） ----
void fw_retransmit_init(fw_retrans_table_t *t, uint32_t interval_ms, int max_retry);
void fw_retransmit_free(fw_retrans_table_t *t);
void fw_retransmit_start(fw_retrans_table_t *t, const char *key, const uint8_t *buf, uint32_t len,
                         const char *addr, uint16_t port, int which, int64_t now);
void fw_retransmit_cancel(fw_retrans_table_t *t, const char *key);
void fw_retransmit_tick(fw_retrans_table_t *t, fw_stack_t *st, int64_t now);
void fw_retransmit_clear_peer(fw_retrans_table_t *t, const char *peer_prefix);

// Offer 拆帧（§7.2：按 max_payload_len 满装拆分，Entry 粒度 = (SvcID, InstID)）
int fw_disc_build_offers(fw_stack_t *st, const fw_offer_entry_t *entries, int n, int which);

#endif // FW_INT_H
