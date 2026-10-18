// ============================================================
// logger.c —— 日志器
//
// 普通日志格式：[模块名] 描述: 关键参数
// 帧日志遵循 §12.4 格式：
//   [svc_id:04X,if_id:04X,inst_id:02X] Tx|Rx,addr strm_id:02X, Code=0xXX, Msg=...
// 级别为进程级全局（C 单进程多栈共享级别，README 偏差说明）。
// ============================================================

#include "fw/fw.h"
#include <stdio.h>
#include <stdarg.h>

static int g_log_level = FW_LOG_INFO;

void fw_log_set_level(int level) { g_log_level = level; }
int  fw_log_get_level(void) { return g_log_level; }

static const char *level_tag(int lv) {
  switch (lv) {
    case FW_LOG_ERROR: return "error";
    case FW_LOG_WARN:  return "warn";
    case FW_LOG_INFO:  return "info";
    default:           return "debug";
  }
}

void fw_log(int level, const char *module, const char *fmt, ...) {
  if (level > g_log_level) return;
  fprintf(stderr, "[%s][%s] ", level_tag(level), module ? module : "-");
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

void fw_log_frame(int level, uint16_t svc, uint16_t if_id, uint8_t inst, uint8_t strm,
                  const char *dir, const char *addr, int code, const char *msg) {
  if (level > g_log_level) return;
  // §12.4：[svc,if,inst] dir,addr strm, Code=0xXX, Msg=...
  fprintf(stderr, "[%s][%04X,%04X,%02X] %s,%s %02X, Code=0x%02X, Msg=%s\n",
          level_tag(level), svc, if_id, inst,
          dir ? dir : "Tx", addr ? addr : "-", strm,
          code & 0xFF, msg ? msg : "");
}

const char *fw_rst_name(int code) {
  switch (code) {
    case FW_RST_VIOLATION:     return "Protocol Violation";
    case FW_RST_BAD_REQUEST:   return "Bad Request";
    case FW_RST_VERSION:       return "Unsupported Version";
    case FW_RST_TOO_LARGE:     return "Payload Too Large";
    case FW_RST_NOT_FOUND:     return "Not Found";
    case FW_RST_METHOD:        return "Method Not Allowed";
    case FW_RST_FRAME_TIMEOUT: return "Frame Timeout";
    case FW_RST_INTERNAL:      return "Internal Error";
    case FW_RST_NOT_IMPL:      return "Not Implemented";
    case FW_RST_UNAVAILABLE:   return "Service Unavailable";
    default:                   return "Reserved";
  }
}
