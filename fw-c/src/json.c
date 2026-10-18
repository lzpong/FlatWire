// ============================================================
// json.c —— 迷你 JSON 解析器（仅够解析 IDL schema）
//
// 支持：对象/数组/字符串（含转义 \" \\ \/ \b \f \n \r \t \uXXXX）/
// 数字（整数→UINT·INT，浮点/指数→FLOAT）/ true / false / null。
// 输出复用 fw_value_t 树（object→STRUCT 携带 name 序）。
// ============================================================

#include "fw/fw.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

typedef struct {
  const char *p;    // 当前位置
  const char *start;// 起始（错误偏移计算）
  const char *end;
  char *err; int errsz;
} jctx_t;

static fw_value_t *j_parse_value(jctx_t *c);

static void j_fail(jctx_t *c, const char *msg) {
  if (c->err && c->errsz > 0 && c->err[0] == 0)
    snprintf(c->err, (size_t)c->errsz, "JSON error at offset %d: %s", (int)(c->p - c->start), msg);
}

// 跳过空白
static void j_skip(jctx_t *c) {
  while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\r' || *c->p == '\n')) c->p++;
}

// 缓冲追加（局部 helper）
static char *j_grow(char *out, size_t *cap, size_t need) {
  if (need <= *cap) return out;
  size_t nc = *cap ? *cap * 2 : 32;
  while (nc < need) nc *= 2;
  char *no = (char *)realloc(out, nc);
  if (!no) { free(out); return NULL; }
  *cap = nc;
  return no;
}

// 解析字符串字面量（c->p 指向开引号后）→ 堆分配 NUL 结尾字节串；失败 NULL
static char *j_parse_string_raw(jctx_t *c) {
  size_t cap = 0, n = 0;
  char *out = NULL;
  while (c->p < c->end) {
    unsigned char ch = (unsigned char)*c->p;
    if (ch == '"') { // 闭合
      c->p++;
      out = j_grow(out, &cap, n + 1);
      if (!out) return NULL;
      out[n] = 0;
      return out;
    }
    if (ch == '\\') {
      c->p++;
      if (c->p >= c->end) break;
      char e = *c->p++;
      char lit;
      switch (e) {
        case '"':  lit = '"';  break;
        case '\\': lit = '\\'; break;
        case '/':  lit = '/';  break;
        case 'b':  lit = '\b'; break;
        case 'f':  lit = '\f'; break;
        case 'n':  lit = '\n'; break;
        case 'r':  lit = '\r'; break;
        case 't':  lit = '\t'; break;
        case 'u': {
          // \uXXXX → UTF-8（含代理对）
          unsigned cp = 0;
          for (int i = 0; i < 4; i++) {
            if (c->p >= c->end) { free(out); return NULL; }
            char h = *c->p++;
            unsigned d = (h >= '0' && h <= '9') ? (unsigned)(h - '0')
                       : (h >= 'a' && h <= 'f') ? (unsigned)(h - 'a' + 10)
                       : (h >= 'A' && h <= 'F') ? (unsigned)(h - 'A' + 10) : 0xFFFFu;
            if (d == 0xFFFFu) { free(out); return NULL; }
            cp = cp * 16 + d;
          }
          // 高代理 → 拼低代理
          if (cp >= 0xD800 && cp <= 0xDBFF && c->end - c->p >= 6 &&
              c->p[0] == '\\' && c->p[1] == 'u') {
            unsigned lo = 0;
            c->p += 2;
            for (int i = 0; i < 4; i++) {
              char h = *c->p++;
              unsigned d = (h >= '0' && h <= '9') ? (unsigned)(h - '0')
                         : (h >= 'a' && h <= 'f') ? (unsigned)(h - 'a' + 10)
                         : (h >= 'A' && h <= 'F') ? (unsigned)(h - 'A' + 10) : 0xFFFFu;
              if (d == 0xFFFFu) { free(out); return NULL; }
              lo = lo * 16 + d;
            }
            if (lo < 0xDC00 || lo > 0xDFFF) { free(out); return NULL; }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            free(out); return NULL; // 孤立代理
          }
          // UTF-8 编码
          uint8_t ub[4]; int un;
          if (cp < 0x80)       { ub[0] = (uint8_t)cp; un = 1; }
          else if (cp < 0x800) { ub[0] = (uint8_t)(0xC0 | (cp >> 6)); ub[1] = (uint8_t)(0x80 | (cp & 0x3F)); un = 2; }
          else if (cp < 0x10000) { ub[0] = (uint8_t)(0xE0 | (cp >> 12)); ub[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F)); ub[2] = (uint8_t)(0x80 | (cp & 0x3F)); un = 3; }
          else { ub[0] = (uint8_t)(0xF0 | (cp >> 18)); ub[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F)); ub[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F)); ub[3] = (uint8_t)(0x80 | (cp & 0x3F)); un = 4; }
          out = j_grow(out, &cap, n + (size_t)un + 1);
          if (!out) return NULL;
          for (int i = 0; i < un; i++) out[n++] = (char)ub[i];
          continue;
        }
        default: free(out); return NULL;
      }
      out = j_grow(out, &cap, n + 2);
      if (!out) return NULL;
      out[n++] = lit;
      continue;
    }
    if (ch < 0x20) break; // 控制字符非法
    out = j_grow(out, &cap, n + 2);
    if (!out) return NULL;
    out[n++] = (char)ch;
    c->p++;
  }
  free(out);
  return NULL;
}

// 解析数字字面量
static fw_value_t *j_parse_number(jctx_t *c) {
  const char *s = c->p;
  int is_float = 0;
  if (c->p < c->end && (*c->p == '-' || *c->p == '+')) c->p++;
  while (c->p < c->end) {
    char ch = *c->p;
    if (ch >= '0' && ch <= '9') { c->p++; continue; }
    if (ch == '.' || ch == 'e' || ch == 'E') { is_float = 1; c->p++; continue; }
    if (ch == '+' || ch == '-') { c->p++; continue; } // 指数符号
    break;
  }
  if (c->p == s) return NULL;
  char tmp[64];
  size_t l = (size_t)(c->p - s);
  if (l >= sizeof(tmp)) return NULL;
  memcpy(tmp, s, l);
  tmp[l] = 0;
  if (is_float) return fw_value_float(atof(tmp));
  // 整数：负 → INT，非负 → UINT
  if (tmp[0] == '-') return fw_value_int(strtoll(tmp, NULL, 10));
  return fw_value_uint(strtoull(tmp, NULL, 10));
}

static fw_value_t *j_parse_value(jctx_t *c) {
  j_skip(c);
  if (c->p >= c->end) { j_fail(c, "unexpected end"); return NULL; }
  char ch = *c->p;
  if (ch == '{') {
    c->p++;
    fw_value_t *obj = fw_value_struct();
    if (!obj) return NULL;
    j_skip(c);
    if (c->p < c->end && *c->p == '}') { c->p++; return obj; }
    for (;;) {
      j_skip(c);
      if (c->p >= c->end || *c->p != '"') { fw_value_free(obj); j_fail(c, "expected key string"); return NULL; }
      c->p++;
      char *key = j_parse_string_raw(c);
      if (!key) { fw_value_free(obj); j_fail(c, "bad key"); return NULL; }
      j_skip(c);
      if (c->p >= c->end || *c->p != ':') { free(key); fw_value_free(obj); j_fail(c, "expected ':'"); return NULL; }
      c->p++;
      fw_value_t *val = j_parse_value(c);
      if (!val) { free(key); fw_value_free(obj); return NULL; }
      if (fw_struct_set(obj, key, val) != FW_OK) { free(key); fw_value_free(val); fw_value_free(obj); return NULL; }
      free(key);
      j_skip(c);
      if (c->p < c->end && *c->p == ',') { c->p++; continue; }
      if (c->p < c->end && *c->p == '}') { c->p++; return obj; }
      fw_value_free(obj);
      j_fail(c, "expected ',' or '}'");
      return NULL;
    }
  }
  if (ch == '[') {
    c->p++;
    fw_value_t *arr = fw_value_array(4);
    if (!arr) return NULL;
    j_skip(c);
    if (c->p < c->end && *c->p == ']') { c->p++; return arr; }
    for (;;) {
      fw_value_t *val = j_parse_value(c);
      if (!val) { fw_value_free(arr); return NULL; }
      if (fw_array_push(arr, val) != FW_OK) { fw_value_free(val); fw_value_free(arr); return NULL; }
      j_skip(c);
      if (c->p < c->end && *c->p == ',') { c->p++; continue; }
      if (c->p < c->end && *c->p == ']') { c->p++; return arr; }
      fw_value_free(arr);
      j_fail(c, "expected ',' or ']'");
      return NULL;
    }
  }
  if (ch == '"') {
    c->p++;
    char *s = j_parse_string_raw(c);
    if (!s) { j_fail(c, "bad string"); return NULL; }
    fw_value_t *v = fw_value_string(s);
    free(s);
    return v;
  }
  if (c->end - c->p >= 4 && memcmp(c->p, "true", 4) == 0)  { c->p += 4; return fw_value_bool(1); }
  if (c->end - c->p >= 5 && memcmp(c->p, "false", 5) == 0) { c->p += 5; return fw_value_bool(0); }
  if (c->end - c->p >= 4 && memcmp(c->p, "null", 4) == 0)  { c->p += 4; return fw_value_null(); }
  if (ch == '-' || (ch >= '0' && ch <= '9')) return j_parse_number(c);
  j_fail(c, "unexpected character");
  return NULL;
}

fw_value_t *fw_json_parse(const char *text, size_t len, char *err, int errsz) {
  jctx_t c;
  c.p = text; c.start = text; c.end = text + len; c.err = err; c.errsz = errsz;
  if (err && errsz > 0) err[0] = 0;
  fw_value_t *v = j_parse_value(&c);
  if (!v) return NULL;
  j_skip(&c);
  if (c.p != c.end) { // 尾随内容 = 非法 JSON
    fw_value_free(v);
    if (err && errsz > 0) snprintf(err, (size_t)errsz, "JSON trailing content at offset %d", (int)(c.p - text));
    return NULL;
  }
  return v;
}
