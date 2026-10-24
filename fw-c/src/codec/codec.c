// ============================================================
// codec.c —— §9 结构化数据字段编解码（v5.0 裸字节编码）
//
// 字段按 IDL schema 顺序裸值连续编码：无字段头、无类型标记、无 null 标记
// （§9.1）。类型/宽度/长度前缀宽度全部由 IDL 静态确定；解码按 schema 顺序
// 读取，schema 字段耗尽后剩余字节忽略（末尾新增字段 MinorVer 兼容 §11.2）。
// 解码错误统一返回负值细分码（映射 RST(0x20)，§12.1）；解码不做部分交付。
// ============================================================

#include "fw/fw.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================
// 动态缓冲
// ============================================================

void fw_buf_init(fw_buf_t *b) { b->p = NULL; b->len = 0; b->cap = 0; }

void fw_buf_free(fw_buf_t *b) { free(b->p); fw_buf_init(b); }

static int buf_grow(fw_buf_t *b, size_t need) {
  if (b->len + need <= b->cap) return FW_OK;
  size_t nc = b->cap ? b->cap : 64;
  while (nc < b->len + need) nc *= 2;
  uint8_t *np = (uint8_t *)realloc(b->p, nc);
  if (!np) return FW_ERR_MEMORY;
  b->p = np;
  b->cap = nc;
  return FW_OK;
}

int fw_buf_put(fw_buf_t *b, const void *data, size_t n) {
  if (buf_grow(b, n) != FW_OK) return FW_ERR_MEMORY;
  if (n) memcpy(b->p + b->len, data, n);
  b->len += n;
  return FW_OK;
}

int fw_buf_put_u8(fw_buf_t *b, uint8_t v) { return fw_buf_put(b, &v, 1); }

int fw_buf_put_u16be(fw_buf_t *b, uint16_t v) {
  uint8_t d[2] = { (uint8_t)(v >> 8), (uint8_t)v };
  return fw_buf_put(b, d, 2);
}

int fw_buf_put_u32be(fw_buf_t *b, uint32_t v) {
  uint8_t d[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
  return fw_buf_put(b, d, 4);
}

// ============================================================
// MSK 掩码（§10：encoded[i] = payload[i] ^ key[i % 4]，编解码对称）
// ============================================================

void fw_mask_xor(uint8_t *data, uint32_t len, const uint8_t key[4]) {
  for (uint32_t i = 0; i < len; i++) data[i] ^= key[i & 3];
}

// ============================================================
// 内部工具
// ============================================================

// 解码递归深度上限（与 schema resolve 32 上限同口径）：损坏/恶意 IDL
// 的循环类型引用（struct→自身）在递归解码时无深度限制会无限递归栈溢出
#define FW_DEC_DEPTH_MAX 32

// 值承载的整数取出（宽容 INT/UINT 互见，对齐 JS Number 语义）
static int value_i64(const fw_value_t *v, int64_t *out) {
  if (v->type == FW_V_INT) { *out = v->as.i; return 1; }
  if (v->type == FW_V_UINT && v->as.u <= (uint64_t)INT64_MAX) { *out = (int64_t)v->as.u; return 1; }
  return 0;
}

static int value_u64(const fw_value_t *v, uint64_t *out) {
  if (v->type == FW_V_UINT) { *out = v->as.u; return 1; }
  if (v->type == FW_V_INT && v->as.i >= 0) { *out = (uint64_t)v->as.i; return 1; }
  return 0;
}

// 整型类型宽度（字节）；非整型返回 0
static int int_width(int kind) {
  switch (kind) {
    case FW_T_U8:  case FW_T_I8:  return 1;
    case FW_T_U16: case FW_T_I16: return 2;
    case FW_T_U32: case FW_T_I32: return 4;
    case FW_T_U64: case FW_T_I64: return 8;
    default: return 0;
  }
}

static int int_is_signed(int kind) {
  return kind == FW_T_I8 || kind == FW_T_I16 || kind == FW_T_I32 || kind == FW_T_I64;
}

// 无符号值域上限（size 1~8）
static uint64_t u_max_for(int size) {
  if (size >= 8) return UINT64_MAX;
  return ((uint64_t)1 << (8 * size)) - 1;
}

// 有符号值域（size 1~8）；返回 0 表示宽度非法
static int i_range_for(int size, int64_t *lo, int64_t *hi) {
  if (size == 8) { *lo = INT64_MIN; *hi = INT64_MAX; return 1; }
  if (size < 1 || size > 7) return 0;
  uint64_t bits = (uint64_t)size * 8;
  *hi = (int64_t)(((uint64_t)1 << (bits - 1)) - 1);
  *lo = -(int64_t)((uint64_t)1 << (bits - 1));
  return 1;
}

// 长度前缀宽度 w(N)（§9.3）：N≤255→1B，N≤65535→2B，否则 4B
static int prefix_width(int max_len) {
  if (max_len <= 255) return 1;
  if (max_len <= 65535) return 2;
  return 4;
}

// 读取 n 字节大端无符号整数（校验剩余长度）
static int read_uint_be(const uint8_t *buf, size_t len, size_t *pos, int n, uint64_t *out) {
  if (*pos > len || len - *pos < (size_t)n) return FW_DEC_UNDERRUN;
  uint64_t v = 0;
  for (int i = 0; i < n; i++) v = (v << 8) | buf[(*pos)++];
  *out = v;
  return FW_OK;
}

// 写入 n 字节大端无符号整数
static int write_uint_be(fw_buf_t *b, uint64_t v, int n) {
  if (buf_grow(b, (size_t)n) != FW_OK) return FW_ERR_MEMORY;
  for (int i = n - 1; i >= 0; i--) b->p[b->len++] = (uint8_t)(v >> (8 * i));
  return FW_OK;
}

// 有符号解码：大端补码 → int64（符号位展开）
static int64_t sign_extend(uint64_t uv, int size) {
  if (size == 8) return (int64_t)uv;
  uint64_t sign = (uint64_t)1 << (8 * size - 1);
  if (uv & sign) return (int64_t)(uv | (~(uint64_t)0 << (8 * size)));
  return (int64_t)uv;
}

// 前向声明
static int encode_value(const fw_tdesc_t *t, const fw_value_t *v, fw_buf_t *out, int depth);
static int decode_value(const fw_tdesc_t *t, const uint8_t *buf, size_t len, size_t *pos,
                        fw_value_t **out, int depth);
static int encode_int_kind(int kind, const fw_value_t *v, fw_buf_t *out);

// ============================================================
// 编码（§9.1/§9.2/§9.3/§9.4）
// ============================================================

// 整型编解码（含 enum 基类型复用）：按 kind 的固定宽度裸值大端
static int encode_int_kind(int kind, const fw_value_t *v, fw_buf_t *out) {
  int size = int_width(kind);
  if (size < 1) return FW_ERR_UNSUPPORTED;
  if (int_is_signed(kind)) {
    int64_t sv;
    if (!value_i64(v, &sv)) return FW_DEC_RANGE;
    int64_t lo, hi;
    if (!i_range_for(size, &lo, &hi)) return FW_ERR_UNSUPPORTED;
    if (sv < lo || sv > hi) return FW_DEC_RANGE;
    return write_uint_be(out, (uint64_t)sv, size); // 补码位型与大端一致
  }
  uint64_t uv;
  if (!value_u64(v, &uv)) return FW_DEC_RANGE;
  if (uv > u_max_for(size)) return FW_DEC_RANGE;
  return write_uint_be(out, uv, size);
}

int fw_encode_field(const fw_tdesc_t *t, const fw_value_t *v, fw_buf_t *out) {
  return encode_value(t, v, out, 0);
}

static int encode_value(const fw_tdesc_t *t, const fw_value_t *v, fw_buf_t *out, int depth) {
  if (!t || !out) return FW_ERR_PARAM;
  if (depth > FW_DEC_DEPTH_MAX) return FW_DEC_MAXLEN; // 深度超限（循环引用防护）
  // §9.1：v5.0 无 null/optional 编码——值为 null 即违约
  if (!v || v->type == FW_V_NULL) return FW_DEC_UNEXPECTED_NULL;

  switch (t->kind) {
    case FW_T_U8: case FW_T_U16: case FW_T_U32: case FW_T_U64:
    case FW_T_I8: case FW_T_I16: case FW_T_I32: case FW_T_I64:
      return encode_int_kind(t->kind, v, out);

    case FW_T_BOOL: {
      // §9.2：仅 0x00 / 0x01
      if (v->type != FW_V_BOOL) return FW_DEC_RANGE;
      return fw_buf_put_u8(out, (uint8_t)(v->as.b ? 1 : 0));
    }

    case FW_T_F32: {
      double d;
      if (v->type == FW_V_FLOAT) d = v->as.f;
      else if (v->type == FW_V_INT) d = (double)v->as.i;
      else if (v->type == FW_V_UINT) d = (double)v->as.u;
      else return FW_DEC_RANGE;
      float f = (float)d;
      uint32_t bits;
      memcpy(&bits, &f, 4);
      return write_uint_be(out, (uint64_t)bits, 4); // IEEE754 大端
    }

    case FW_T_F64: {
      double d;
      if (v->type == FW_V_FLOAT) d = v->as.f;
      else if (v->type == FW_V_INT) d = (double)v->as.i;
      else if (v->type == FW_V_UINT) d = (double)v->as.u;
      else return FW_DEC_RANGE;
      uint64_t bits;
      memcpy(&bits, &d, 8);
      return write_uint_be(out, bits, 8); // IEEE754 大端
    }

    case FW_T_F80:
      // x87 80bit 可选扩展：本实现不支持（schema 加载期已拒绝声明，防御性返回）
      return FW_ERR_UNSUPPORTED;

    case FW_T_TIMESTAMP: {
      // §9.2：48bit 无符号大端（2000 基准毫秒）
      uint64_t tv;
      if (!value_u64(v, &tv)) return FW_DEC_RANGE;
      if (tv >= ((uint64_t)1 << 48)) return FW_DEC_RANGE;
      return write_uint_be(out, tv, 6);
    }

    case FW_T_ENUM: {
      // §9.2：enum 线格式 = base 基类型裸值；支持名称→值映射与未知值透传
      if (v->type == FW_V_STRING) {
        for (int i = 0; i < t->enum_n; i++) {
          if (strcmp(t->enum_vals[i].name, v->as.s.ptr) == 0) {
            fw_value_t tv;
            memset(&tv, 0, sizeof(tv));
            if (t->enum_base) { tv.type = FW_V_INT; tv.as.i = t->enum_vals[i].val; }
            else { tv.type = FW_V_UINT; tv.as.u = (uint64_t)t->enum_vals[i].val; }
            int kind = t->enum_base ? (t->size == 8 ? FW_T_I64 : t->size == 4 ? FW_T_I32
                                  : t->size == 2 ? FW_T_I16 : FW_T_I8)
                                    : (t->size == 8 ? FW_T_U64 : t->size == 4 ? FW_T_U32
                                  : t->size == 2 ? FW_T_U16 : FW_T_U8);
            return encode_int_kind(kind, &tv, out);
          }
        }
        return FW_DEC_RANGE; // 未声明的枚举名
      }
      int kind = t->enum_base ? (t->size == 8 ? FW_T_I64 : t->size == 4 ? FW_T_I32
                            : t->size == 2 ? FW_T_I16 : FW_T_I8)
                              : (t->size == 8 ? FW_T_U64 : t->size == 4 ? FW_T_U32
                            : t->size == 2 ? FW_T_U16 : FW_T_U8);
      return encode_int_kind(kind, v, out);
    }

    case FW_T_STRING: {
      // §9.3：fixed_len=裸 N 字节（无前缀）；max_len=w(N) 前缀 + 内容
      if (v->type != FW_V_STRING) return FW_DEC_RANGE;
      uint32_t n = v->as.s.len;
      if (t->fixed_len >= 0) {
        if ((int64_t)n != (int64_t)t->fixed_len) return FW_DEC_FIXEDLEN;
        return fw_buf_put(out, v->as.s.ptr, n);
      }
      if (t->max_len < 0) return FW_DEC_MAXLEN; // schema 已强制声明（防御）
      if ((int64_t)n > (int64_t)t->max_len) return FW_DEC_MAXLEN;
      int w = prefix_width(t->max_len);
      if (write_uint_be(out, (uint64_t)n, w) != FW_OK) return FW_ERR_MEMORY;
      return fw_buf_put(out, v->as.s.ptr, n);
    }

    case FW_T_BYTES: {
      if (v->type != FW_V_BYTES) return FW_DEC_RANGE;
      uint32_t n = v->as.by.len;
      if (t->fixed_len >= 0) {
        if ((int64_t)n != (int64_t)t->fixed_len) return FW_DEC_FIXEDLEN;
        return fw_buf_put(out, v->as.by.ptr, n);
      }
      if (t->max_len < 0) return FW_DEC_MAXLEN;
      if ((int64_t)n > (int64_t)t->max_len) return FW_DEC_MAXLEN;
      int w = prefix_width(t->max_len);
      if (write_uint_be(out, (uint64_t)n, w) != FW_OK) return FW_ERR_MEMORY;
      return fw_buf_put(out, v->as.by.ptr, n);
    }

    case FW_T_ARRAY: {
      // §9.4：fixed_len=裸 N 元素（无前缀）；max_len=w(N) 元素个数前缀 + 裸元素
      if (v->type != FW_V_ARRAY) return FW_DEC_RANGE;
      if (!t->element) return FW_ERR_UNSUPPORTED;
      uint32_t n = v->as.arr.len;
      if (t->fixed_len >= 0) {
        if ((int64_t)n != (int64_t)t->fixed_len) return FW_DEC_FIXEDLEN;
      } else {
        if (t->max_len < 0) return FW_DEC_MAXLEN;
        if ((int64_t)n > (int64_t)t->max_len) return FW_DEC_MAXLEN;
        int w = prefix_width(t->max_len);
        if (write_uint_be(out, (uint64_t)n, w) != FW_OK) return FW_ERR_MEMORY;
      }
      for (uint32_t i = 0; i < n; i++) {
        int r = encode_value(t->element, v->as.arr.items[i], out, depth + 1);
        if (r != FW_OK) return r;
      }
      return FW_OK;
    }

    case FW_T_STRUCT: {
      // §9.4：N 个字段按 schema 顺序裸排，无边界标记；全部必填
      if (v->type != FW_V_STRUCT) return FW_DEC_RANGE;
      for (int i = 0; i < t->field_n; i++) {
        const fw_tfield_t *f = &t->fields[i];
        const fw_value_t *fv = fw_struct_get(v, f->name);
        if (!fv || fv->type == FW_V_NULL) return FW_DEC_UNEXPECTED_NULL;
        int r = encode_value(f->type, fv, out, depth + 1);
        if (r != FW_OK) return r;
      }
      return FW_OK;
    }
  }
  return FW_ERR_UNSUPPORTED; // 非法 kind（schema 构建期已拦截）
}

// ============================================================
// 解码（§9.1~§9.4）
// ============================================================

int fw_decode_field(const fw_tdesc_t *t, const uint8_t *buf, size_t len, size_t *pos,
                    fw_value_t **out) {
  return decode_value(t, buf, len, pos, out, 0);
}

static int decode_value(const fw_tdesc_t *t, const uint8_t *buf, size_t len, size_t *pos,
                        fw_value_t **out, int depth) {
  if (!t || !buf || !pos || !out) return FW_ERR_PARAM;
  *out = NULL;
  if (depth > FW_DEC_DEPTH_MAX) return FW_DEC_MAXLEN; // 深度超限（循环引用防护）
  if (*pos > len) return FW_DEC_UNDERRUN;

  switch (t->kind) {
    case FW_T_U8: case FW_T_U16: case FW_T_U32: case FW_T_U64: {
      int size = int_width(t->kind);
      uint64_t uv;
      int r = read_uint_be(buf, len, pos, size, &uv);
      if (r != FW_OK) return r;
      *out = fw_value_uint(uv);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }

    case FW_T_I8: case FW_T_I16: case FW_T_I32: case FW_T_I64: {
      int size = int_width(t->kind);
      uint64_t uv;
      int r = read_uint_be(buf, len, pos, size, &uv);
      if (r != FW_OK) return r;
      *out = fw_value_int(sign_extend(uv, size));
      return *out ? FW_OK : FW_ERR_MEMORY;
    }

    case FW_T_BOOL: {
      // §9.2：仅 0x00/0x01 合法，其他 → InvalidBoolEncoding
      if (len - *pos < 1) return FW_DEC_UNDERRUN;
      uint8_t b = buf[(*pos)++];
      if (b > 1) return FW_DEC_INVALID_BOOL;
      *out = fw_value_bool(b == 1);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }

    case FW_T_F32: {
      uint64_t bits;
      int r = read_uint_be(buf, len, pos, 4, &bits);
      if (r != FW_OK) return r;
      uint32_t b32 = (uint32_t)bits;
      float f;
      memcpy(&f, &b32, 4);
      *out = fw_value_float((double)f);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }

    case FW_T_F64: {
      uint64_t bits;
      int r = read_uint_be(buf, len, pos, 8, &bits);
      if (r != FW_OK) return r;
      double d;
      memcpy(&d, &bits, 8);
      *out = fw_value_float(d);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }

    case FW_T_F80:
      return FW_ERR_UNSUPPORTED; // 可选扩展未支持

    case FW_T_TIMESTAMP: {
      uint64_t tv;
      int r = read_uint_be(buf, len, pos, 6, &tv);
      if (r != FW_OK) return r;
      *out = fw_value_uint(tv);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }

    case FW_T_ENUM: {
      // §11.2：未知值按 base 整型透传（MinorVer 兼容）
      int size = t->size;
      if (size < 1 || size > 8) return FW_ERR_UNSUPPORTED;
      uint64_t uv;
      int r = read_uint_be(buf, len, pos, size, &uv);
      if (r != FW_OK) return r;
      *out = t->enum_base ? fw_value_int(sign_extend(uv, size)) : fw_value_uint(uv);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }

    case FW_T_STRING: {
      uint64_t n;
      if (t->fixed_len >= 0) {
        n = (uint64_t)t->fixed_len; // §9.3：定长无前缀，读取恰 N 字节
      } else {
        if (t->max_len < 0) return FW_DEC_MAXLEN;
        int w = prefix_width(t->max_len);
        int r = read_uint_be(buf, len, pos, w, &n);
        if (r != FW_OK) return r;
        if (n > (uint64_t)t->max_len) return FW_DEC_MAXLEN;
      }
      if ((uint64_t)(len - *pos) < n) return FW_DEC_UNDERRUN;
      *out = fw_value_string_n((const char *)buf + *pos, (uint32_t)n);
      if (!*out) return FW_ERR_MEMORY;
      *pos += (size_t)n;
      return FW_OK;
    }

    case FW_T_BYTES: {
      uint64_t n;
      if (t->fixed_len >= 0) {
        n = (uint64_t)t->fixed_len;
      } else {
        if (t->max_len < 0) return FW_DEC_MAXLEN;
        int w = prefix_width(t->max_len);
        int r = read_uint_be(buf, len, pos, w, &n);
        if (r != FW_OK) return r;
        if (n > (uint64_t)t->max_len) return FW_DEC_MAXLEN;
      }
      if ((uint64_t)(len - *pos) < n) return FW_DEC_UNDERRUN;
      *out = fw_value_bytes(buf + *pos, (uint32_t)n);
      if (!*out) return FW_ERR_MEMORY;
      *pos += (size_t)n;
      return FW_OK;
    }

    case FW_T_ARRAY: {
      if (!t->element) return FW_ERR_UNSUPPORTED;
      uint64_t n;
      if (t->fixed_len >= 0) {
        n = (uint64_t)t->fixed_len; // 定长无前缀
      } else {
        if (t->max_len < 0) return FW_DEC_MAXLEN;
        int w = prefix_width(t->max_len);
        int r = read_uint_be(buf, len, pos, w, &n);
        if (r != FW_OK) return r;
        if (n > (uint64_t)t->max_len) return FW_DEC_MAXLEN; // §9.3 解码上限校验
      }
      fw_value_t *arr = fw_value_array(n ? (uint32_t)n : 1);
      if (!arr) return FW_ERR_MEMORY;
      for (uint64_t i = 0; i < n; i++) {
        fw_value_t *el = NULL;
        int r = decode_value(t->element, buf, len, pos, &el, depth + 1);
        if (r != FW_OK) { fw_value_free(el); fw_value_free(arr); return r; }
        if (fw_array_push(arr, el) != FW_OK) { fw_value_free(el); fw_value_free(arr); return FW_ERR_MEMORY; }
      }
      *out = arr;
      return FW_OK;
    }

    case FW_T_STRUCT: {
      // §9.4：按 schema 顺序裸排解码，无边界标记
      fw_value_t *s = fw_value_struct();
      if (!s) return FW_ERR_MEMORY;
      for (int i = 0; i < t->field_n; i++) {
        const fw_tfield_t *f = &t->fields[i];
        fw_value_t *fv = NULL;
        int r = decode_value(f->type, buf, len, pos, &fv, depth + 1);
        if (r != FW_OK) { fw_value_free(fv); fw_value_free(s); return r; }
        if (fw_struct_set(s, f->name, fv) != FW_OK) { fw_value_free(fv); fw_value_free(s); return FW_ERR_MEMORY; }
      }
      // schema 字段耗尽后剩余字节 = 对端新增末尾字段 → 忽略（§9.1/§11.2）
      *out = s;
      return FW_OK;
    }
  }
  return FW_ERR_UNSUPPORTED;
}

// ============================================================
// 接口级 payload 编解码（§13 payload 语义 + §2 max_payload + §9.6 CRC）
// ============================================================

// 解析接口方向类型名列表 → 规范化类型数组；失败返回 -1
static int iface_types(fw_schema_t *s, const fw_iface_t *iface, int direction,
                       const fw_tdesc_t **types, int max, char *err, int errsz) {
  int n = 0;
  if (direction == 0) {
    for (int i = 0; i < iface->input_n && n < max; i++) {
      types[n] = fw_schema_resolve(s, iface->input_names[i]);
      if (!types[n]) {
        if (err && errsz > 0) snprintf(err, (size_t)errsz, "type \"%s\" not defined in IDL", iface->input_names[i]);
        return -1;
      }
      n++;
    }
  } else {
    if (iface->output_name && n < max) {
      types[0] = fw_schema_resolve(s, iface->output_name);
      if (!types[0]) {
        if (err && errsz > 0) snprintf(err, (size_t)errsz, "type \"%s\" not defined in IDL", iface->output_name);
        return -1;
      }
      n = 1;
    }
  }
  return n;
}

int fw_encode_payload(const fw_schema_t *s, const fw_iface_t *iface, int direction,
                      const fw_value_t *payload, fw_buf_t *out, char *err, int errsz) {
  const fw_tdesc_t *types[16];
  int n = iface_types((fw_schema_t *)s, iface, direction, types, 16, err, errsz);
  if (n < 0) return FW_ERR_PARAM;

  int r = FW_OK;
  if (n == 0) {
    // 无类型：空 Data Fields（§9.1）
  } else if (n == 1) {
    r = encode_value(types[0], payload, out, 0);
  } else {
    // 多参数：payload 必须为 ARRAY 且逐位置对应
    if (!payload || payload->type != FW_V_ARRAY || payload->as.arr.len != (uint32_t)n)
      return FW_ERR_PARAM;
    for (int i = 0; i < n && r == FW_OK; i++)
      r = encode_value(types[i], payload->as.arr.items[i], out, 0);
  }
  if (r != FW_OK) return r;

  // §9.6：接口声明 "crc": true 才在字段序列末尾附加 2B CRC-16/CCITT-FALSE（大端）
  // max_payload 校验移到 CRC 附加之后：上限对象是"含 CRC 的最终 Payload"
  if (iface->crc) {
    uint16_t crc = fw_crc16(out->p, out->len);
    if (fw_buf_put_u8(out, (uint8_t)(crc >> 8)) != FW_OK) return FW_ERR_MEMORY;
    if (fw_buf_put_u8(out, (uint8_t)(crc & 0xFF)) != FW_OK) return FW_ERR_MEMORY;
  }
  // 接口级 max_payload 校验（§2：TCP/UDP 均适用；IDL 级超限归 0x20）
  if (iface->max_payload >= 0 && out->len > (uint32_t)iface->max_payload) return FW_DEC_MAXLEN;
  return FW_OK;
}

int fw_decode_payload(const fw_schema_t *s, const fw_iface_t *iface, int direction,
                      const uint8_t *buf, uint32_t len, fw_value_t **out, char *err, int errsz) {
  const fw_tdesc_t *types[16];
  int n = iface_types((fw_schema_t *)s, (fw_iface_t *)iface, direction, types, 16, err, errsz);
  if (n < 0) return FW_ERR_PARAM;
  *out = NULL;

  // §9.6 接收顺序：CRC 校验（先于字段解码）→ 剥离 → 契约字段解码
  if (iface->crc) {
    if (len < 2) return FW_DEC_CRC;
    uint16_t expect = (uint16_t)(((uint16_t)buf[len - 2] << 8) | buf[len - 1]);
    if (fw_crc16(buf, len - 2) != expect) return FW_DEC_CRC;
    len -= 2; // 剥离 CRC：解码器看到的 Data 不含 CRC
  }

  size_t pos = 0;
  if (n == 0) return FW_OK; // 无类型：*out = NULL
  if (n == 1) {
    // schema 字段耗尽后剩余字节忽略（§9.1 末尾新增字段兼容）
    return decode_value(types[0], buf, len, &pos, out, 0);
  }

  // 多参数：逐类型解码为值数组
  fw_value_t *arr = fw_value_array((uint32_t)n);
  if (!arr) return FW_ERR_MEMORY;
  for (int i = 0; i < n; i++) {
    fw_value_t *v = NULL;
    int r = decode_value(types[i], buf, len, &pos, &v, 0);
    if (r != FW_OK) { fw_value_free(v); fw_value_free(arr); return r; }
    if (fw_array_push(arr, v) != FW_OK) { fw_value_free(v); fw_value_free(arr); return FW_ERR_MEMORY; }
  }
  *out = arr;
  return FW_OK;
}
