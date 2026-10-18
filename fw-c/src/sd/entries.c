// ============================================================
// entries.c —— §7.1 SD Entry 格式编解码
//
//   Offer Entry (6B):     Find Entry (4B):      Subscribe Entry (7B):    GetIDL Entry (3B):
//     uint16  SvcID         uint16  SvcID         uint16  SvcID            uint16  SvcID
//     uint8   InstID        uint8   InstID        uint16  IfID             uint8   MajorVer
//     uint8   MajorVer      uint8   MajorVer      uint8   InstID
//     uint8   MinorVer                            uint8   GrpId
//     uint8   TTL(0=停止)                         uint8   TTL(0=取消,秒)
//
// 多字节整数统一大端（§2）。Offer/Find Entry 无 IfID（实例级事实）；
// Subscribe Entry 保留 IfID（接口级行为）；GetIDL Entry 无 InstID（服务级事实）。
// ============================================================

#include "fw/fw.h"
#include <string.h>

// ---- Offer Entry（6B）：周期广播 / Find 响应（响应帧格式与 Offer 相同，§7.2） ----

uint32_t fw_encode_offer_entries(uint8_t *buf, uint32_t cap, const fw_offer_entry_t *e, int n) {
  uint32_t need = (uint32_t)n * FW_ENTRY_OFFER;
  if (cap < need) return 0;
  for (int i = 0; i < n; i++) {
    uint8_t *p = buf + (uint32_t)i * FW_ENTRY_OFFER;
    p[0] = (uint8_t)(e[i].svc_id >> 8);
    p[1] = (uint8_t)(e[i].svc_id & 0xFF);
    p[2] = e[i].inst_id;
    p[3] = e[i].major_ver;
    p[4] = e[i].minor_ver;
    p[5] = e[i].ttl; // TTL 以秒为单位携带（§7.1）
  }
  return need;
}

int fw_decode_offer_entries(const uint8_t *buf, uint32_t len, fw_offer_entry_t *out, int max) {
  int n = 0;
  for (uint32_t o = 0; o + FW_ENTRY_OFFER <= len && n < max; o += FW_ENTRY_OFFER) {
    out[n].svc_id = (uint16_t)((buf[o] << 8) | buf[o + 1]);
    out[n].inst_id = buf[o + 2];
    out[n].major_ver = buf[o + 3];
    out[n].minor_ver = buf[o + 4];
    out[n].ttl = buf[o + 5];
    n++;
  }
  return n;
}

// ---- Find Entry（4B）：请求查询格式（无 MinorVer：MinorVer 不参与匹配，§7.1） ----

uint32_t fw_encode_find_entries(uint8_t *buf, uint32_t cap, const fw_find_entry_t *e, int n) {
  uint32_t need = (uint32_t)n * FW_ENTRY_FIND;
  if (cap < need) return 0;
  for (int i = 0; i < n; i++) {
    uint8_t *p = buf + (uint32_t)i * FW_ENTRY_FIND;
    p[0] = (uint8_t)(e[i].svc_id >> 8);
    p[1] = (uint8_t)(e[i].svc_id & 0xFF);
    p[2] = e[i].inst_id;   // 0x00 通配
    p[3] = e[i].major_ver; // 0 = 不过滤版本
  }
  return need;
}

int fw_decode_find_entries(const uint8_t *buf, uint32_t len, fw_find_entry_t *out, int max) {
  int n = 0;
  for (uint32_t o = 0; o + FW_ENTRY_FIND <= len && n < max; o += FW_ENTRY_FIND) {
    out[n].svc_id = (uint16_t)((buf[o] << 8) | buf[o + 1]);
    out[n].inst_id = buf[o + 2];
    out[n].major_ver = buf[o + 3];
    n++;
  }
  return n;
}

// ---- Subscribe Entry（7B）：订阅是接口级行为，保留 IfID（§7.1） ----

uint32_t fw_encode_sub_entries(uint8_t *buf, uint32_t cap, const fw_sub_entry_t *e, int n) {
  uint32_t need = (uint32_t)n * FW_ENTRY_SUB;
  if (cap < need) return 0;
  for (int i = 0; i < n; i++) {
    uint8_t *p = buf + (uint32_t)i * FW_ENTRY_SUB;
    p[0] = (uint8_t)(e[i].svc_id >> 8);
    p[1] = (uint8_t)(e[i].svc_id & 0xFF);
    p[2] = (uint8_t)(e[i].if_id >> 8);
    p[3] = (uint8_t)(e[i].if_id & 0xFF);
    p[4] = e[i].inst_id;
    p[5] = e[i].grp_id;
    p[6] = e[i].ttl; // 秒；TTL=0 = 取消订阅
  }
  return need;
}

int fw_decode_sub_entries(const uint8_t *buf, uint32_t len, fw_sub_entry_t *out, int max) {
  int n = 0;
  for (uint32_t o = 0; o + FW_ENTRY_SUB <= len && n < max; o += FW_ENTRY_SUB) {
    out[n].svc_id = (uint16_t)((buf[o] << 8) | buf[o + 1]);
    out[n].if_id = (uint16_t)((buf[o + 2] << 8) | buf[o + 3]);
    out[n].inst_id = buf[o + 4];
    out[n].grp_id = buf[o + 5];
    out[n].ttl = buf[o + 6];
    n++;
  }
  return n;
}

// ---- GetIDL Entry（3B）：无 InstID——IDL 为服务级事实（§7.1） ----

uint32_t fw_encode_getidl_entry(uint8_t *buf, uint32_t cap, const fw_getidl_entry_t *e) {
  if (cap < FW_ENTRY_GETIDL) return 0;
  buf[0] = (uint8_t)(e->svc_id >> 8);
  buf[1] = (uint8_t)(e->svc_id & 0xFF);
  buf[2] = e->major_ver; // 精确匹配
  return FW_ENTRY_GETIDL;
}

// 返回 0 表示 ≠3B（残缺 <3B 或多余 >3B，非 1×Entry → RST(0x20)，§7.2）
int fw_decode_getidl_entry(const uint8_t *buf, uint32_t len, fw_getidl_entry_t *out) {
  if (len != FW_ENTRY_GETIDL) return 0;
  out->svc_id = (uint16_t)((buf[0] << 8) | buf[1]);
  out->major_ver = buf[2];
  return 1;
}
