// ============================================================
// udp.c —— §2 UDP 组播双 socket
//
// - main socket：bind port（服务端角色）——收组播 Find/REN/Offer、收单播请求、
//   收客户端数据帧；发周期 Offer、Find 响应、事件推送、SD 单播应答/确认
//   （裁定 4：SD 单播应答/确认恒走 server socket，源端口=udp_port）
// - client socket：bind 临时端口（客户端角色，§2）——发组播 Find/REN、
//   单播 Request/FF/Subscribe；收单播响应/推送/确认与组播 Offer
// - IP_MULTICAST_LOOP 开启（§2）：本机组播回环
// - 自我回环过滤：源 IP 为本机地址且源端口 == 本 socket 端口 → 丢弃
// ============================================================

#include "../fw_int.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 打开双 socket 并加入组播组（§2 部署约定）
int fw_udp_sockets_open(fw_stack_t *st, char *err, int errsz) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(st->cfg.port);
  addr.sin_addr.s_addr = st->bind[0] ? inet_addr(st->bind) : INADDR_ANY;

  // main socket：bind port（服务端角色）
  st->udp_main = socket(AF_INET, SOCK_DGRAM, 0);
  if (st->udp_main == FW_FD_INVALID) { snprintf(err, (size_t)errsz, "udp main socket create failed"); return FW_ERR_IO; }
  fw_plat_set_reuse(st->udp_main);
  if (bind(st->udp_main, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    snprintf(err, (size_t)errsz, "udp main bind %u failed (err=%d)", st->cfg.port, fw_plat_err());
    return FW_ERR_IO;
  }
  fw_plat_set_nonblock(st->udp_main, 1);
  fw_plat_mcast_loop(st->udp_main, 1); // §2：IP_MULTICAST_LOOP 默认开启
  fw_plat_mcast_if(st->udp_main, st->bind[0] ? st->bind : NULL);
  if (fw_plat_mcast_join(st->udp_main, st->mcast, st->bind[0] ? st->bind : NULL) != FW_OK)
    fw_log(FW_LOG_WARN, "udp", "addMembership failed on main socket (err=%d)", fw_plat_err());

  // client socket：bind 临时端口（§2：客户端 UDP socket 不绑定 5400）
  st->udp_client = socket(AF_INET, SOCK_DGRAM, 0);
  if (st->udp_client == FW_FD_INVALID) { snprintf(err, (size_t)errsz, "udp client socket create failed"); return FW_ERR_IO; }
  struct sockaddr_in caddr;
  memset(&caddr, 0, sizeof(caddr));
  caddr.sin_family = AF_INET;
  caddr.sin_port = 0;
  caddr.sin_addr.s_addr = st->bind[0] ? inet_addr(st->bind) : INADDR_ANY;
  if (bind(st->udp_client, (struct sockaddr *)&caddr, sizeof(caddr)) != 0) {
    snprintf(err, (size_t)errsz, "udp client bind failed (err=%d)", fw_plat_err());
    return FW_ERR_IO;
  }
  fw_plat_set_nonblock(st->udp_client, 1);
  fw_plat_mcast_loop(st->udp_client, 1);
  fw_plat_mcast_if(st->udp_client, st->bind[0] ? st->bind : NULL);
  if (fw_plat_mcast_join(st->udp_client, st->mcast, st->bind[0] ? st->bind : NULL) != FW_OK)
    fw_log(FW_LOG_WARN, "udp", "addMembership failed on client socket (err=%d)", fw_plat_err());

  // 观测 client 临时端口（发现缓存/推送地址观测用）
  struct sockaddr_in ga;
  socklen_t gl = sizeof(ga);
  getsockname(st->udp_client, (struct sockaddr *)&ga, &gl);
  st->client_port = ntohs(ga.sin_port);
  return FW_OK;
}

void fw_udp_sockets_close(fw_stack_t *st) {
  if (st->udp_main != FW_FD_INVALID) { fw_plat_close(st->udp_main); st->udp_main = FW_FD_INVALID; }
  if (st->udp_client != FW_FD_INVALID) { fw_plat_close(st->udp_client); st->udp_client = FW_FD_INVALID; }
}

// ---- 发送 ----

void fw_udp_sendto_raw(fw_stack_t *st, const char *addr, uint16_t port, int which,
                       const uint8_t *buf, uint32_t len) {
  fw_fd_t fd = which ? st->udp_main : st->udp_client;
  if (fd == FW_FD_INVALID) return;
  struct sockaddr_in to;
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_port = htons(port);
  to.sin_addr.s_addr = inet_addr(addr);
  sendto(fd, (const char *)buf, (int)len, 0, (struct sockaddr *)&to, sizeof(to));
}

void fw_udp_send_multicast_raw(fw_stack_t *st, int which, const uint8_t *buf, uint32_t len) {
  fw_udp_sendto_raw(st, st->mcast, st->cfg.port, which, buf, len);
}

// [REVIEW P3-7] 编码缓冲对齐 rpc.c 堆回退模式：栈缓冲 2048B 仅作快速路径，
// 超缓冲改堆编码并正确发送（原实现直接报 FW_ERR_PARAM，与"超 PLB 界"语义混淆，
// 且 IDL 级 max_payload 缺失时合法大帧被误拒）
int fw_udp_send_frame(fw_stack_t *st, const fw_frame_desc_t *d, const char *addr, uint16_t port, int which) {
  uint32_t need = fw_frame_size(d);
  if (need == 0) return FW_ERR_PARAM; // 超 PLB 界（>2^56-1）
  uint8_t stackbuf[2048];
  uint8_t *buf = stackbuf;
  uint8_t *heap = NULL;
  if (need > sizeof(stackbuf)) {
    heap = (uint8_t *)malloc(need);
    if (!heap) return FW_ERR_MEMORY;
    buf = heap;
  }
  uint32_t n = fw_frame_encode(buf, need, d);
  int rc = FW_OK;
  if (n) fw_udp_sendto_raw(st, addr, port, which, buf, n);
  else rc = FW_ERR_ENCODE; // [REVIEW P3-7] 编码失败语义（原误报 FW_ERR_PARAM）
  free(heap);
  return rc;
}

int fw_udp_send_mcast_frame(fw_stack_t *st, const fw_frame_desc_t *d, int which) {
  return fw_udp_send_frame(st, d, st->mcast, st->cfg.port, which);
}

// ---- 接收（非阻塞清空；组播启发式 + 自我回环过滤 + 分发） ----

static int is_local_self(fw_stack_t *st, const char *ip, uint16_t port, fw_fd_t sock) {
  // 源 IP ∈ 本机地址集 且 源端口 == 本 socket 端口 → 本 socket 发出的组播回环帧
  //（对齐 fw-nodejs：仅过滤本 socket 端口；同栈另一 socket 的回环帧不过滤——
  //  双角色同栈共享发现缓存，处理无害）
  if (port != 0) {
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    if (getsockname(sock, (struct sockaddr *)&sa, &sl) == 0 && ntohs(sa.sin_port) == port) {
      for (int i = 0; i < st->nlocal; i++)
        if (strcmp(st->local_addrs[i], ip) == 0) return 1;
    }
  }
  return 0;
}

static void udp_drain(fw_stack_t *st, fw_fd_t fd, int which) {
  uint8_t buf[65535];
  for (;;) {
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    int n = (int)recvfrom(fd, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
    if (n <= 0) return; // EWOULDBLOCK / 错误
    char ip[48];
    uint16_t port = ntohs(from.sin_port);
    // IPv4 点分十进制（inet_ntoa 线程局部，单线程安全）
    snprintf(ip, sizeof(ip), "%s", inet_ntoa(from.sin_addr));
    // 自我回环过滤（§2）
    if (is_local_self(st, ip, port, fd)) continue;

    // 组播操作码启发式：Offer/Find 的解析违规按组播帧静默丢弃
    //（平台限制：socket API 无法直接获知目的地址，对齐 fw-nodejs 偏差 5）
    int multicast_like = n >= 2 && ((buf[1] & 0x3F) == FW_CODE_SD_OFFER || (buf[1] & 0x3F) == FW_CODE_SD_FIND);

    fw_parse_opts_t o;
    memset(&o, 0, sizeof(o));
    o.ver = st->cfg.ver;
    o.max_payload_len = st->cfg.max_payload_len;
    o.is_udp = 1;
    o.multicast_like = multicast_like;

    fw_frame_t f;
    fw_head_res_t rst;
    fw_parse_state_t ps = fw_parse_datagram(buf, (size_t)n, &o, &f, &rst);
    if (ps == FW_PARSE_OK) {
      fw_meta_t meta;
      memset(&meta, 0, sizeof(meta));
      meta.transport = 0;
      snprintf(meta.address, sizeof(meta.address), "%s", ip);
      meta.port = port;
      fw_stack_on_frame(st, &f, &meta);
    } else if (ps == FW_PARSE_INVALID) {
      // 解析失败：需要回 RST 时单播回源地址（§4.4）；否则静默丢弃
      fw_frame_desc_t d;
      fw_make_rst(&d, rst.rst_code, rst.rst_ctr, rst.rst_svc, rst.rst_if, rst.rst_inst, rst.rst_strm);
      uint8_t ob[64];
      uint32_t on = fw_frame_encode(ob, sizeof(ob), &d);
      if (on) {
        fw_udp_sendto_raw(st, ip, port, which, ob, on);
        fw_log_frame(FW_LOG_WARN, rst.rst_svc, rst.rst_if, rst.rst_inst, rst.rst_strm,
                     "Tx", ip, rst.rst_code, fw_rst_name(rst.rst_code));
      }
    }
    // FW_PARSE_SILENT / NEED_MORE：静默丢弃
  }
}

void fw_udp_poll(fw_stack_t *st) {
  if (st->udp_main != FW_FD_INVALID) udp_drain(st, st->udp_main, 1);
  if (st->udp_client != FW_FD_INVALID) udp_drain(st, st->udp_client, 0);
}
