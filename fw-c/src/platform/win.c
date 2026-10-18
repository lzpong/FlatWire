// ============================================================
// win.c —— Windows 平台适配（Winsock2 / QueryPerformanceCounter / FindFirstFile）
// ============================================================

#include "platform.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <direct.h>
#include <iphlpapi.h> // [REVIEW P3-11] GetAdaptersAddresses（链接 iphlpapi）

// ---- socket 基础 ----

int fw_plat_init(void) {
  WSADATA wsa;
  // 请求 Winsock 2.2
  return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? FW_OK : FW_ERR_IO;
}

void fw_plat_cleanup(void) { WSACleanup(); }

int fw_plat_close(fw_fd_t fd) { return closesocket(fd) == 0 ? FW_OK : FW_ERR_IO; }

int fw_plat_set_nonblock(fw_fd_t fd, int on) {
  u_long mode = on ? 1 : 0;
  return ioctlsocket(fd, FIONBIO, &mode) == 0 ? FW_OK : FW_ERR_IO;
}

int fw_plat_set_nodelay(fw_fd_t fd) {
  BOOL v = TRUE;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&v, sizeof(v)) == 0 ? FW_OK : FW_ERR_IO;
}

int fw_plat_set_reuse(fw_fd_t fd) {
  BOOL v = TRUE;
  return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&v, sizeof(v)) == 0 ? FW_OK : FW_ERR_IO;
}

int fw_plat_would_block(void) {
  int e = WSAGetLastError();
  return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY;
}

int fw_plat_err(void) { return WSAGetLastError(); }

int fw_plat_poll(struct pollfd *fds, int nfds, int timeout_ms) {
  return WSAPoll(fds, nfds, timeout_ms);
}

// ---- UDP 组播 ----

int fw_plat_mcast_join(fw_fd_t fd, const char *group, const char *iface) {
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(group);
  // iface=NULL → 系统选路（INADDR_ANY）
  mreq.imr_interface.s_addr = iface ? inet_addr(iface) : INADDR_ANY;
  return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq)) == 0
             ? FW_OK : FW_ERR_IO;
}

int fw_plat_mcast_loop(fw_fd_t fd, int on) {
  // §2：IP_MULTICAST_LOOP 默认开启（本机组播回环）
  DWORD v = on ? 1 : 0;
  return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&v, sizeof(v)) == 0
             ? FW_OK : FW_ERR_IO;
}

int fw_plat_mcast_if(fw_fd_t fd, const char *iface) {
  if (!iface) return FW_OK; // 空 = 系统选路
  DWORD addr = inet_addr(iface);
  return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&addr, sizeof(addr)) == 0
             ? FW_OK : FW_ERR_IO;
}

// ---- 单调时间（QueryPerformanceCounter） ----

int64_t fw_plat_now_ms(void) {
  static LARGE_INTEGER freq = {0};
  LARGE_INTEGER now;
  if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&now);
  return (int64_t)(now.QuadPart * 1000 / freq.QuadPart);
}

// 毫秒级休眠（Windows：Sleep，测试辅助）
void fw_sleep_ms(int ms) {
  if (ms > 0) Sleep((DWORD)ms);
}

// ---- 平台随机（§10 MSK key；[REVIEW P3-1] 用 RtlGenRandom 替换时钟推导） ----
// SystemFunction036（RtlGenRandom）来自 advapi32：经 GetProcAddress 动态加载，
// 零额外链接依赖；加载失败回退多源熵混合（QPC 高分辨率计数 + 时钟 + 进程/栈地址 ASLR）
typedef BOOLEAN (WINAPI *fn_rtlgenrandom_t)(void *buf, ULONG len);
void fw_plat_random_bytes(uint8_t *buf, int n) {
  HMODULE h = GetModuleHandleA("advapi32.dll");
  if (!h) h = LoadLibraryA("advapi32.dll");
  if (h) {
    fn_rtlgenrandom_t fn = (fn_rtlgenrandom_t)(void *)GetProcAddress(h, "SystemFunction036");
    if (fn && fn(buf, (ULONG)n)) return;
  }
  // 回退：多源熵混合（弱于 CSPRNG，仅极端加载失败场景；MSK 用途为线路混淆非加密）
  uint64_t seed = (uint64_t)GetTickCount64() ^ (((uint64_t)(uintptr_t)buf) << 32) ^
                  (uint64_t)GetCurrentProcessId() ^ ((uint64_t)GetTickCount() << 17);
  LARGE_INTEGER qpc;
  QueryPerformanceCounter(&qpc);
  seed ^= (uint64_t)qpc.QuadPart;
  for (int i = 0; i < n; i++) {
    seed = seed * 6364136223846793005ULL + 1442695040888963407ULL; // LCG 搅拌
    buf[i] = (uint8_t)(seed >> 33);
  }
}

// ---- 本机 IPv4 地址枚举（[REVIEW P3-11] GetAdaptersAddresses 对齐 JS networkInterfaces） ----
int fw_plat_local_addrs(char addrs[][48], int max) {
  ULONG sz = 15 * 1024;
  IP_ADAPTER_ADDRESSES *aa = NULL;
  int n = 0;
  for (int attempt = 0; attempt < 3 && !aa; attempt++) {
    aa = (IP_ADAPTER_ADDRESSES *)malloc(sz);
    if (!aa) return 0;
    ULONG r = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                   GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
                                   NULL, aa, &sz);
    if (r == ERROR_BUFFER_OVERFLOW) { free(aa); aa = NULL; continue; }
    if (r != NO_ERROR) { free(aa); return 0; }
  }
  if (!aa) return 0;
  for (IP_ADAPTER_ADDRESSES *p = aa; p && n < max; p = p->Next) {
    for (IP_ADAPTER_UNICAST_ADDRESS *u = p->FirstUnicastAddress; u && n < max; u = u->Next) {
      if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
      struct sockaddr_in *sin = (struct sockaddr_in *)u->Address.lpSockaddr;
      // 点分十进制（inet_ntoa 线程局部，栈初始化路径单线程）
      snprintf(addrs[n], 48, "%s", inet_ntoa(sin->sin_addr));
      n++;
    }
  }
  free(aa);
  return n;
}

// ---- 文件系统 ----

int fw_plat_mkdir_p(const char *path) {
  char tmp[512];
  size_t n = strlen(path);
  if (n >= sizeof(tmp)) return FW_ERR_PARAM;
  memcpy(tmp, path, n + 1);
  // 逐级创建（跳过盘符）
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/' || *p == '\\') {
      char c = *p;
      *p = 0;
      _mkdir(tmp);
      *p = c;
    }
  }
  _mkdir(tmp);
  return fw_plat_file_exists(tmp) ? FW_OK : FW_ERR_IO;
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
  buf[r] = 0; // NUL 结尾便于文本处理
  *out_len = r;
  return buf;
}

int fw_plat_list_json(const char *dir, char ***out_files, int *out_count) {
  char pattern[600];
  snprintf(pattern, sizeof(pattern), "%s\\*.json", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    // 目录不存在或无匹配 → 空列表（0 条不算错误，IDL 库允许为空）
    if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND) {
      *out_files = NULL;
      *out_count = 0;
      return 0;
    }
    return -1;
  }
  char **list = NULL;
  int n = 0, cap = 0;
  do {
    if (n == cap) {
      cap = cap ? cap * 2 : 8;
      char **nl = (char **)realloc(list, (size_t)cap * sizeof(char *));
      if (!nl) { free(list); FindClose(h); return -1; }
      list = nl;
    }
    list[n] = _strdup(fd.cFileName);
    if (!list[n]) break;
    n++;
  } while (FindNextFileA(h, &fd));
  FindClose(h);
  *out_files = list;
  *out_count = n;
  return 0;
}

int fw_plat_file_exists(const char *path) {
  DWORD attr = GetFileAttributesA(path);
  return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

void fw_vsnprintf(char *buf, size_t cap, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, cap, fmt, ap);
  va_end(ap);
}
