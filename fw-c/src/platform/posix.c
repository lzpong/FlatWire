// ============================================================
// posix.c —— POSIX 平台适配（Linux / macOS / 交叉编译 ARM）
// ============================================================

#include "platform.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ifaddrs.h> // getifaddrs
#if defined(__linux__)
  #include <sys/random.h> // getrandom
#endif

// ---- socket 基础 ----

int fw_plat_init(void) { return FW_OK; }       // POSIX 无需初始化
void fw_plat_cleanup(void) {}

int fw_plat_close(fw_fd_t fd) { return close(fd) == 0 ? FW_OK : FW_ERR_IO; }

int fw_plat_set_nonblock(fw_fd_t fd, int on) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return FW_ERR_IO;
  if (on) fl |= O_NONBLOCK; else fl &= ~O_NONBLOCK;
  return fcntl(fd, F_SETFL, fl) == 0 ? FW_OK : FW_ERR_IO;
}

int fw_plat_set_nodelay(fw_fd_t fd) {
  int v = 1;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(v)) == 0 ? FW_OK : FW_ERR_IO;
}

int fw_plat_set_reuse(fw_fd_t fd) {
  int v = 1;
  return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) == 0 ? FW_OK : FW_ERR_IO;
}

int fw_plat_would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EALREADY; }

int fw_plat_err(void) { return errno; }

int fw_plat_poll(struct pollfd *fds, int nfds, int timeout_ms) { return poll(fds, nfds, timeout_ms); }

// ---- UDP 组播 ----

int fw_plat_mcast_join(fw_fd_t fd, const char *group, const char *iface) {
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(group);
  mreq.imr_interface.s_addr = iface ? inet_addr(iface) : INADDR_ANY;
  return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0 ? FW_OK : FW_ERR_IO;
}

int fw_plat_mcast_loop(fw_fd_t fd, int on) {
  unsigned char v = on ? 1 : 0; // §2：IP_MULTICAST_LOOP 默认开启
  return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &v, sizeof(v)) == 0 ? FW_OK : FW_ERR_IO;
}

int fw_plat_mcast_if(fw_fd_t fd, const char *iface) {
  if (!iface) return FW_OK;
  struct in_addr addr;
  addr.s_addr = inet_addr(iface);
  return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr)) == 0 ? FW_OK : FW_ERR_IO;
}

// ---- 单调时间（clock_gettime MONOTONIC；回退 timespec_get） ----

int64_t fw_plat_now_ms(void) {
  struct timespec ts;
#if defined(CLOCK_MONOTONIC)
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
  timespec_get(&ts, TIME_UTC);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// 毫秒级休眠（POSIX：nanosleep，测试辅助；被信号打断时补足剩余时长）
void fw_sleep_ms(int ms) {
  if (ms <= 0) return;
  struct timespec req;
  req.tv_sec = ms / 1000;
  req.tv_nsec = (long)(ms % 1000) * 1000000L;
  while (nanosleep(&req, &req) == -1 && errno == EINTR) { /* 重试剩余时长 */ }
}

// ---- 平台随机（§10 MSK key；getrandom() / /dev/urandom 替换时钟推导） ----
void fw_plat_random_bytes(uint8_t *buf, int n) {
#if defined(__linux__) && defined(GRND_NONBLOCK)
  if (getrandom(buf, (size_t)n, 0) == n) return;
#endif
  FILE *f = fopen("/dev/urandom", "rb");
  if (f) {
    size_t r = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (r == (size_t)n) return;
  }
  // 回退：多源熵混合（弱于 CSPRNG，仅极端场景；MSK 用途为线路混淆非加密）
  uint64_t seed = (uint64_t)fw_plat_now_ms() ^ ((uint64_t)(uintptr_t)buf << 17) ^
                  ((uint64_t)getpid() << 3) ^ (uint64_t)clock();
  for (int i = 0; i < n; i++) {
    seed = seed * 6364136223846793005ULL + 1442695040888963407ULL; // LCG 搅拌
    buf[i] = (uint8_t)(seed >> 33);
  }
}

// ---- 本机 IPv4 地址枚举（getifaddrs 对齐 JS networkInterfaces） ----
int fw_plat_local_addrs(char addrs[][48], int max) {
#if defined(__APPLE__) || defined(__linux__) || defined(__unix__)
  struct ifaddrs *ifa = NULL;
  if (getifaddrs(&ifa) != 0) return 0;
  int n = 0;
  for (struct ifaddrs *p = ifa; p && n < max; p = p->ifa_next) {
    if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
    struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
    snprintf(addrs[n], 48, "%s", inet_ntoa(sin->sin_addr));
    n++;
  }
  freeifaddrs(ifa);
  return n;
#else
  (void)addrs; (void)max;
  return 0; // 平台不支持：调用方回退默认集
#endif
}

// ---- 文件系统 ----

int fw_plat_mkdir_p(const char *path) {
  char tmp[512];
  size_t n = strlen(path);
  if (n >= sizeof(tmp)) return FW_ERR_PARAM;
  memcpy(tmp, path, n + 1);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      mkdir(tmp, 0755);
      *p = '/';
    }
  }
  mkdir(tmp, 0755);
  struct stat st;
  return stat(tmp, &st) == 0 && S_ISDIR(st.st_mode) ? FW_OK : FW_ERR_IO;
}

int fw_plat_write_file(const char *path, const char *data, size_t len) {
  FILE *f = fopen(path, "wb");
  if (!f) return FW_ERR_IO;
  size_t w = fwrite(data, 1, len, f);
  fclose(f);
  return w == len ? FW_OK : FW_ERR_IO;
}

uint8_t *fw_plat_read_file(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz < 0) { fclose(f); return NULL; }
  uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1);
  if (!buf) { fclose(f); return NULL; }
  size_t r = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  buf[r] = 0;
  *out_len = r;
  return buf;
}

int fw_plat_list_json(const char *dir, char ***out_files, int *out_count) {
  DIR *d = opendir(dir);
  if (!d) { *out_files = NULL; *out_count = 0; return 0; } // 目录不存在 = 空库
  char **list = NULL;
  int n = 0, cap = 0;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    size_t l = strlen(e->d_name);
    if (l < 5 || strcasecmp(e->d_name + l - 5, ".json") != 0) continue;
    if (n == cap) {
      cap = cap ? cap * 2 : 8;
      char **nl = (char **)realloc(list, (size_t)cap * sizeof(char *));
      if (!nl) { free(list); closedir(d); return -1; }
      list = nl;
    }
    list[n] = strdup(e->d_name);
    if (!list[n]) break;
    n++;
  }
  closedir(d);
  *out_files = list;
  *out_count = n;
  return 0;
}

int fw_plat_file_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

void fw_vsnprintf(char *buf, size_t cap, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, cap, fmt, ap);
  va_end(ap);
}
