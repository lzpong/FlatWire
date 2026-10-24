// ============================================================
// platform.h —— 平台适配层内部声明（Winsock2 vs POSIX / 时间 / 文件 / 目录）
// ============================================================

#ifndef FW_PLATFORM_H
#define FW_PLATFORM_H

#include "fw/fw.h"

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  typedef SOCKET fw_fd_t;
  #define FW_FD_INVALID INVALID_SOCKET
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <poll.h>
  typedef int fw_fd_t;
  #define FW_FD_INVALID (-1)
#endif

// ---- socket 基础 ----
int  fw_plat_init(void);              // Winsock2: WSAStartup；POSIX: 空操作
void fw_plat_cleanup(void);
int  fw_plat_close(fw_fd_t fd);       // closesocket / close
int  fw_plat_set_nonblock(fw_fd_t fd, int on);
int  fw_plat_set_nodelay(fw_fd_t fd); // TCP_NODELAY
int  fw_plat_set_reuse(fw_fd_t fd);   // SO_REUSEADDR
int  fw_plat_would_block(void);       // 非阻塞 send/recv/connect 的"稍后再试"
int  fw_plat_err(void);               // 最近 socket 错误码
// poll 封装（WSAPoll / poll）；返回就绪 fd 数，超时 0，错误 -1
int  fw_plat_poll(struct pollfd *fds, int nfds, int timeout_ms);

// ---- UDP 组播 ----
int fw_plat_mcast_join(fw_fd_t fd, const char *group, const char *iface); // IP_ADD_MEMBERSHIP
int fw_plat_mcast_loop(fw_fd_t fd, int on);    // IP_MULTICAST_LOOP（§2 默认开启）
int fw_plat_mcast_if(fw_fd_t fd, const char *iface); // IP_MULTICAST_IF（出口接口）

// ---- 单调时间 ----
int64_t fw_plat_now_ms(void);
// 毫秒级休眠（测试辅助；事件循环内禁止调用）
void fw_sleep_ms(int ms);

// ---- 平台随机（§10 MSK key：换用平台 CSPRNG，替换时钟推导） ----
void fw_plat_random_bytes(uint8_t *buf, int n);

// ---- 本机 IPv4 地址枚举（§2 自我回环过滤；对齐 JS networkInterfaces） ----
// 填充 addrs（每项点分十进制），返回写入条数（失败返回 0，调用方回退默认集）
int fw_plat_local_addrs(char addrs[][48], int max);

// ---- 文件系统 ----
int     fw_plat_mkdir_p(const char *path);
int     fw_plat_write_file(const char *path, const char *data, size_t len);
uint8_t *fw_plat_read_file(const char *path, size_t *out_len); // malloc 分配，调用者 free；失败 NULL
// 列目录内 .json 文件（仅文件名）；返回条数，失败 -1。out 由调用者 free(*out) 与各元素
int     fw_plat_list_json(const char *dir, char ***out_files, int *out_count);
// 文件存在判定
int     fw_plat_file_exists(const char *path);

// 可变参数格式化到栈缓冲（logger 用）
void fw_vsnprintf(char *buf, size_t cap, const char *fmt, ...);

// 跨平台字符串复制
#ifdef _WIN32
  #define FW_STRDUP(s) _strdup(s)
  #define FW_STRCASECMP(a, b) _stricmp(a, b)
#else
  #define FW_STRDUP(s) strdup(s)
  #define FW_STRCASECMP(a, b) strcasecmp(a, b)
#endif

#endif // FW_PLATFORM_H
