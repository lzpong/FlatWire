// ============================================================
// codec.c —— §9 结构化数据字段编解码（类型系统 / 恒定宽度 / null 语义 / MSK）
//
// 字段头（1 字节）：高 4bit=类型（0~8），低 4bit 用途因类型而异（§9.1）。
// 解码错误统一返回负值细分码（映射 RST(0x20)，§12.1 两层两码）；
// 解码不做部分交付（§9.4 末尾）。
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

// 长度块字节数：len 需要多少字节表示（string/bytes 长度块占 low4+1 字节，1~16，§9.2）
static int len_block_width(uint64_t len) {
  int w = 1;
  while (w < 16 && len >= ((uint64_t)1 << (8 * w))) w++;
  return w;
}

// fixed_len / max_len 校验（§9.2 编码侧 / §9.4 check_len 解码侧）
static int check_len(int64_t len, const fw_tdesc_t *t) {
  if (t->fixed_len >= 0 && len != t->fixed_len) return FW_DEC_FIXEDLEN; // 实际长度 == N
  if (t->max_len >= 0 && len > t->max_len) return FW_DEC_MAXLEN;        // 实际长度 ≤ N
  return FW_OK;
}

// 读取 n 字节大端无符号整数（校验剩余长度）
static int read_uint_be(const uint8_t *buf, size_t len, size_t *pos, int n, uint64_t *out) {
  if (len - *pos < (size_t)n) return FW_DEC_UNDERRUN;
  uint64_t v = 0;
  for (int i = 0; i < n; i++) v = (v << 8) | buf[(*pos)++];
  *out = v;
  return FW_OK;
}

static int write_uint_be(fw_buf_t *b, uint64_t v, int n) {
  if (buf_grow(b, (size_t)n) != FW_OK) return FW_ERR_MEMORY;
  for (int i = n - 1; i >= 0; i--) b->p[b->len++] = (uint8_t)(v >> (8 * i));
  return FW_OK;
}

// 整型宽度上限（int64/uint64 承载；size>8 不支持，README 偏差清单）
#define FW_INT_SIZE_MAX 8

// 前向声明
static int f_encode_float(fw_buf_t *out, int width, double d);
static int decode_field_opt(const fw_tdesc_t *t, int optional, const uint8_t *buf, size_t len,
                            size_t *pos, fw_value_t **out, int depth);

// [REVIEW P3-6] 解码递归深度上限（与 schema resolve 32 上限同口径）：损坏/恶意 IDL
// 的循环类型引用（struct→自身）在 decode_field_opt 无深度限制时会无限递归栈溢出
#define FW_DEC_DEPTH_MAX 32

// ============================================================
// 编码（§9.1/§9.2/§9.3）
// ============================================================

int fw_encode_field(const fw_tdesc_t *t, const fw_value_t *v, fw_buf_t *out) {
  if (!t || !out) return FW_ERR_PARAM;

  // §9.2：null 仅 optional 字段可编码（1B 空头 0x00）——optional 判定在父层
  // struct 分支完成；此处 null 输入一律视为违约
  if (!v || v->type == FW_V_NULL) return FW_DEC_UNEXPECTED_NULL;

  switch (t->kind) {
    case FW_T_BOOL: {
      if (v->type != FW_V_BOOL) return FW_DEC_RANGE;
      // §9.1：0=false, 1=true（编码仅产出合法值）
      return fw_buf_put_u8(out, (uint8_t)((1 << 4) | (v->as.b ? 1 : 0)));
    }

    case FW_T_SIGNED: {
      // §9.2：线上宽度恒等于 IDL size，low4 恒等于 size（校验位）
      int size = t->size;
      if (size < 1 || size > FW_INT_SIZE_MAX) return FW_ERR_UNSUPPORTED;
      int64_t sv;
      if (!value_i64(v, &sv)) return FW_DEC_RANGE;
      int64_t lo = size == 8 ? INT64_MIN : -(int64_t)(((uint64_t)1) << (8 * size - 1));
      int64_t hi = size == 8 ? INT64_MAX : ((int64_t)1 << (8 * size - 1)) - 1;
      if (sv < lo || sv > hi) return FW_DEC_RANGE;
      if (fw_buf_put_u8(out, (uint8_t)((2 << 4) | size)) != FW_OK) return FW_ERR_MEMORY;
      return write_uint_be(out, (uint64_t)sv, size); // 二进制补码位型一致
    }

    case FW_T_UNSIGNED: {
      int size = t->size;
      if (size < 1 || size > FW_INT_SIZE_MAX) return FW_ERR_UNSUPPORTED;
      uint64_t uv;
      if (!value_u64(v, &uv)) return FW_DEC_RANGE;
      uint64_t hi = size == 8 ? UINT64_MAX : (((uint64_t)1) << (8 * size)) - 1;
      if (uv > hi) return FW_DEC_RANGE;
      if (fw_buf_put_u8(out, (uint8_t)((3 << 4) | size)) != FW_OK) return FW_ERR_MEMORY;
      return write_uint_be(out, uv, size);
    }

    case FW_T_ENUM: {
      // §11.1：enum 线格式 = 底层整型（按 signed/unsigned 恒定宽度规则编码）
      fw_tdesc_t base;
      memset(&base, 0, sizeof(base));
      base.kind = t->enum_base;
      base.size = t->size;
      if (v->type == FW_V_STRING) {
        // 名称 → 整数值（查 IDL values 映射）
        for (int i = 0; i < t->enum_n; i++) {
          if (strcmp(t->enum_vals[i].name, v->as.s.ptr) == 0) {
            fw_value_t tv;
            memset(&tv, 0, sizeof(tv));
            tv.type = FW_V_INT;
            tv.as.i = t->enum_vals[i].val;
            return fw_encode_field(&base, &tv, out);
          }
        }
        return FW_DEC_RANGE;
      }
      return fw_encode_field(&base, v, out);
    }

    case FW_T_FLOAT:
      // §9.1：1=32bit, 2=64bit；80bit 为可选扩展，本实现不支持（与 JS 版一致）
      if (v->type == FW_V_FLOAT) return f_encode_float(out, t->width, v->as.f);
      if (v->type == FW_V_INT)   return f_encode_float(out, t->width, (double)v->as.i);
      if (v->type == FW_V_UINT)  return f_encode_float(out, t->width, (double)v->as.u);
      return FW_DEC_RANGE;

    case FW_T_TIMESTAMP: {
      // §9.1：字段头 0x50|t[43:40]，payload 5B = t[39:0]，共 44bit
      uint64_t tv;
      if (!value_u64(v, &tv)) return FW_DEC_RANGE;
      if (tv >= ((uint64_t)1 << 44)) return FW_DEC_RANGE;
      if (fw_buf_put_u8(out, (uint8_t)((5 << 4) | (tv >> 40))) != FW_OK) return FW_ERR_MEMORY;
      return write_uint_be(out, tv & (((uint64_t)1 << 40) - 1), 5);
    }

    case FW_T_STRING: {
      if (v->type != FW_V_STRING) return FW_DEC_RANGE;
      uint32_t n = v->as.s.len;
      int cr = check_len((int64_t)n, t);
      if (cr != FW_OK) return cr;
      int w = len_block_width(n); // 长度块占 low4+1 字节（1~16）
      if (fw_buf_put_u8(out, (uint8_t)((6 << 4) | (w - 1))) != FW_OK) return FW_ERR_MEMORY;
      if (write_uint_be(out, n, w) != FW_OK) return FW_ERR_MEMORY;
      return fw_buf_put(out, v->as.s.ptr, n);
    }

    case FW_T_BYTES: {
      if (v->type != FW_V_BYTES) return FW_DEC_RANGE;
      uint32_t n = v->as.by.len;
      int cr = check_len((int64_t)n, t);
      if (cr != FW_OK) return cr;
      int w = len_block_width(n);
      if (fw_buf_put_u8(out, (uint8_t)((7 << 4) | (w - 1))) != FW_OK) return FW_ERR_MEMORY;
      if (write_uint_be(out, n, w) != FW_OK) return FW_ERR_MEMORY;
      return fw_buf_put(out, v->as.by.ptr, n);
    }

    case FW_T_ARRAY: {
      // §9.3：0x8X，X=0~14 内联元素个数；X=15 后跟 2 字节长度（0~65535）
      if (v->type != FW_V_ARRAY) return FW_DEC_RANGE;
      uint32_t n = v->as.arr.len;
      if (n > 65535) return FW_DEC_MAXLEN;
      int cr = check_len((int64_t)n, t);
      if (cr != FW_OK) return cr;
      if (n <= 14) {
        if (fw_buf_put_u8(out, (uint8_t)((8 << 4) | n)) != FW_OK) return FW_ERR_MEMORY;
      } else {
        if (fw_buf_put_u8(out, (uint8_t)((8 << 4) | 15)) != FW_OK) return FW_ERR_MEMORY;
        if (fw_buf_put_u16be(out, (uint16_t)n) != FW_OK) return FW_ERR_MEMORY;
      }
      for (uint32_t i = 0; i < n; i++) {
        int r = fw_encode_field(t->element, v->as.arr.items[i], out);
        if (r != FW_OK) return r;
      }
      return FW_OK;
    }

    case FW_T_STRUCT: {
      // §9.3：N 个字段按顺序连续编码，无边界标记；值为 STRUCT（按名取字段）
      if (v->type != FW_V_STRUCT) return FW_DEC_RANGE;
      for (int i = 0; i < t->field_n; i++) {
        const fw_tfield_t *f = &t->fields[i];
        const fw_value_t *fv = fw_struct_get(v, f->name);
        if (!fv || fv->type == FW_V_NULL) {
          if (f->optional) {
            // optional 字段缺省/空 → 编码为 null（§9.2：1B 空头）
            if (fw_buf_put_u8(out, 0x00) != FW_OK) return FW_ERR_MEMORY;
            continue;
          }
          return FW_DEC_UNEXPECTED_NULL; // 非 optional 缺失/null 违约
        }
        int r = fw_encode_field(f->type, fv, out);
        if (r != FW_OK) return r;
      }
      return FW_OK;
    }
  }
  return FW_DEC_UNKNOWN_FIELD;
}

// float 编码辅助
static int f_encode_float(fw_buf_t *out, int width, double d) {
  if (width == 32) {
    if (fw_buf_put_u8(out, (uint8_t)((4 << 4) | 1)) != FW_OK) return FW_ERR_MEMORY;
    float f = (float)d;
    uint32_t bits;
    memcpy(&bits, &f, 4);
    return fw_buf_put_u32be(out, bits);
  }
  if (width == 64) {
    if (fw_buf_put_u8(out, (uint8_t)((4 << 4) | 2)) != FW_OK) return FW_ERR_MEMORY;
    uint64_t bits;
    memcpy(&bits, &d, 8);
    for (int i = 7; i >= 0; i--)
      if (fw_buf_put_u8(out, (uint8_t)(bits >> (8 * i))) != FW_OK) return FW_ERR_MEMORY;
    return FW_OK;
  }
  return FW_DEC_UNSUPPORTED_FLOAT; // 80bit 扩展不支持
}

// ============================================================
// 解码（§9.4 decode_field / decode_fields）
// ============================================================

int fw_decode_field(const fw_tdesc_t *t, const uint8_t *buf, size_t len, size_t *pos,
                    fw_value_t **out) {
  return decode_field_opt(t, 0, buf, len, pos, out, 0);
}

// optional 标志由字段引用层传入（optional 字段遇 null → 缺省值，§9.4）
// [REVIEW P3-6] depth：递归深度（struct/array 嵌套），超 FW_DEC_DEPTH_MAX 拒绝
static int decode_field_opt(const fw_tdesc_t *t, int optional, const uint8_t *buf, size_t len,
                            size_t *pos, fw_value_t **out, int depth) {
  if (!t || !buf || !pos || !out) return FW_ERR_PARAM;
  *out = NULL;
  if (depth > FW_DEC_DEPTH_MAX) return FW_DEC_MAXLEN; // 深度超限（循环引用防护）

  // §9.3：struct 无外层字段头——按字段列表顺序消费字段序列
  //（顶层 struct 与嵌套/数组元素场景统一经此入口）
  if (t->kind == FW_T_STRUCT) {
    // optional 结构体引用遇 null（1B 空头 0x00）：先窥探首字节确认 null 再消费
    //（否则 0x00 会被误当作首个成员的字段头；对齐 fw-nodejs 行为）
    if (optional && len - *pos >= 1 && buf[*pos] == 0x00) {
      (*pos)++;
      *out = fw_value_null();
      return *out ? FW_OK : FW_ERR_MEMORY;
    }
    fw_value_t *s = fw_value_struct();
    if (!s) return FW_ERR_MEMORY;
    for (int i = 0; i < t->field_n; i++) {
      const fw_tfield_t *f = &t->fields[i];
      fw_value_t *fv = NULL;
      int r = decode_field_opt(f->type, f->optional, buf, len, pos, &fv, depth + 1);
      if (r != FW_OK) { fw_value_free(fv); fw_value_free(s); return r; }
      if (fw_struct_set(s, f->name, fv) != FW_OK) { fw_value_free(fv); fw_value_free(s); return FW_ERR_MEMORY; }
    }
    // schema 字段耗尽后 buf 的剩余字节 = 对端新增的末尾字段 → 忽略（§9.4，Minor 向后兼容）
    *out = s;
    return FW_OK;
  }

  if (len - *pos < 1) return FW_DEC_UNDERRUN;
  uint8_t type_byte = buf[(*pos)++];
  int type_id = type_byte >> 4;   // §9.4：高 4bit
  int low4 = type_byte & 0x0F;    // 低 4bit
  int r;

  switch (type_id) {
    case 0x0: {
      // §9.4：仅 optional 字段遇 null 合法 → 缺省值；否则 UnexpectedNull
      if (!optional) return FW_DEC_UNEXPECTED_NULL;
      *out = fw_value_null();
      return *out ? FW_OK : FW_ERR_MEMORY;
    }
    case 0x1: {
      // §9.4：low4 > 1 → InvalidBoolEncoding
      if (low4 > 1) return FW_DEC_INVALID_BOOL;
      *out = fw_value_bool(low4 == 1);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }
    case 0x2: {
      // §9.4：low4=0 → InvalidSignedLength；byte_len != size → SizeMismatch（§9.2 恒定宽度）
      if (low4 == 0) return FW_DEC_INVALID_SIGNED_LEN;
      if (t->size <= 0) return FW_DEC_SIZE_MISMATCH;
      if (low4 != t->size) return FW_DEC_SIZE_MISMATCH;
      if (low4 > FW_INT_SIZE_MAX) return FW_DEC_RANGE; // size>8 承载限制（README 偏差）
      uint64_t uv;
      r = read_uint_be(buf, len, pos, low4, &uv);
      if (r != FW_OK) return r;
      // 符号位展开（大端补码）
      int64_t sv;
      if (low4 == 8) {
        sv = (uv & 0x8000000000000000ULL)
                 ? (int64_t)(uv - 0x8000000000000000ULL) - INT64_MAX - 1
                 : (int64_t)uv;
      } else {
        int64_t sign_bit = (int64_t)1 << (8 * low4 - 1);
        sv = ((int64_t)uv >= sign_bit) ? (int64_t)uv - ((int64_t)1 << (8 * low4)) : (int64_t)uv;
      }
      *out = fw_value_int(sv);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }
    case 0x3: {
      if (low4 == 0) return FW_DEC_INVALID_UNSIGNED_LEN;
      if (t->size <= 0) return FW_DEC_SIZE_MISMATCH;
      if (low4 != t->size) return FW_DEC_SIZE_MISMATCH;
      if (low4 > FW_INT_SIZE_MAX) return FW_DEC_RANGE;
      uint64_t uv;
      r = read_uint_be(buf, len, pos, low4, &uv);
      if (r != FW_OK) return r;
      *out = fw_value_uint(uv);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }
    case 0x4: {
      // §9.4：low4=1→f32, 2→f64, 3→80bit（可选扩展，不支持），否则非法
      if (low4 == 1) {
        if (len - *pos < 4) return FW_DEC_UNDERRUN;
        uint32_t bits = 0;
        for (int i = 0; i < 4; i++) bits = (bits << 8) | buf[(*pos)++];
        float f;
        memcpy(&f, &bits, 4);
        *out = fw_value_float((double)f);
        return *out ? FW_OK : FW_ERR_MEMORY;
      }
      if (low4 == 2) {
        if (len - *pos < 8) return FW_DEC_UNDERRUN;
        uint64_t bits = 0;
        for (int i = 0; i < 8; i++) bits = (bits << 8) | buf[(*pos)++];
        double d;
        memcpy(&d, &bits, 8);
        *out = fw_value_float(d);
        return *out ? FW_OK : FW_ERR_MEMORY;
      }
      return FW_DEC_UNSUPPORTED_FLOAT;
    }
    case 0x5: {
      // §9.1：t = (low4 << 40) | read_uint_be(5)，44bit
      uint64_t body;
      r = read_uint_be(buf, len, pos, 5, &body);
      if (r != FW_OK) return r;
      *out = fw_value_uint(((uint64_t)low4 << 40) | body);
      return *out ? FW_OK : FW_ERR_MEMORY;
    }
    case 0x6: {
      // §9.4：len = read_uint_be(low4 + 1)，长度块 1~16 字节
      if (low4 + 1 > 8) { // 长度块超 8 字节：读取后按超限处理（uint64 承载限制）
        if (len - *pos < (size_t)(low4 + 1)) return FW_DEC_UNDERRUN;
        *pos += (size_t)(low4 + 1);
        return FW_DEC_MAXLEN;
      }
      uint64_t l;
      r = read_uint_be(buf, len, pos, low4 + 1, &l);
      if (r != FW_OK) return r;
      r = check_len((int64_t)l, t);
      if (r != FW_OK) return r;
      if (len - *pos < l) return FW_DEC_UNDERRUN;
      *out = fw_value_string_n((const char *)buf + *pos, (uint32_t)l);
      if (!*out) return FW_ERR_MEMORY;
      *pos += (size_t)l;
      return FW_OK;
    }
    case 0x7: {
      if (low4 + 1 > 8) {
        if (len - *pos < (size_t)(low4 + 1)) return FW_DEC_UNDERRUN;
        *pos += (size_t)(low4 + 1);
        return FW_DEC_MAXLEN;
      }
      uint64_t l;
      r = read_uint_be(buf, len, pos, low4 + 1, &l);
      if (r != FW_OK) return r;
      r = check_len((int64_t)l, t);
      if (r != FW_OK) return r;
      if (len - *pos < l) return FW_DEC_UNDERRUN;
      *out = fw_value_bytes(buf + *pos, (uint32_t)l);
      if (!*out) return FW_ERR_MEMORY;
      *pos += (size_t)l;
      return FW_OK;
    }
    case 0x8: {
      // §9.4：array_len = low4 <= 14 ? low4 : read_u16_be()
      uint64_t n;
      if (low4 <= 14) {
        n = (uint64_t)low4;
      } else {
        r = read_uint_be(buf, len, pos, 2, &n);
        if (r != FW_OK) return r;
      }
      r = check_len((int64_t)n, t);
      if (r != FW_OK) return r;
      fw_value_t *arr = fw_value_array(n ? (uint32_t)n : 1);
      if (!arr) return FW_ERR_MEMORY;
      for (uint64_t i = 0; i < n; i++) {
        fw_value_t *el = NULL;
        r = decode_field_opt(t->element, 0, buf, len, pos, &el, depth + 1); // [REVIEW P3-6] 深度递增
        if (r != FW_OK) { fw_value_free(el); fw_value_free(arr); return r; }
        if (fw_array_push(arr, el) != FW_OK) { fw_value_free(el); fw_value_free(arr); return FW_ERR_MEMORY; }
      }
      *out = arr;
      return FW_OK;
    }
    default:
      // §9.4：type_id = 0x9~0xF → UnknownFieldType（新增类型 = Major 不兼容变更）
      return FW_DEC_UNKNOWN_FIELD;
  }
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
    // 无类型：空 Data Fields（§9.3 顶层无字段）
  } else if (n == 1) {
    r = fw_encode_field(types[0], payload, out);
  } else {
    // 多参数：payload 必须为 ARRAY 且逐位置对应
    if (!payload || payload->type != FW_V_ARRAY || payload->as.arr.len != (uint32_t)n)
      return FW_ERR_PARAM;
    for (int i = 0; i < n && r == FW_OK; i++)
      r = fw_encode_field(types[i], payload->as.arr.items[i], out);
  }
  if (r != FW_OK) return r;

  // §9.6：接口契约级 CRC——2 字节结果大端附加于 Data Fields 末尾，计入 Payload Length
  // [REVIEW P2-1] max_payload 校验移到 CRC 附加之后：§2/§11.1 的上限对象是
  // "含 CRC 的最终 Payload"（§3.1 Payload Length = Data Fields + CRC16 之和），
  // 原实现先校验再附加 2B CRC，恰边界帧最终 Payload 超限 2B
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
  if (n == 1) return decode_field_opt(types[0], 0, buf, len, &pos, out, 0); // [REVIEW P3-6]

  // 多参数：逐类型解码为值数组
  fw_value_t *arr = fw_value_array((uint32_t)n);
  if (!arr) return FW_ERR_MEMORY;
  for (int i = 0; i < n; i++) {
    fw_value_t *v = NULL;
    int r = decode_field_opt(types[i], 0, buf, len, &pos, &v, 0); // [REVIEW P3-6]
    if (r != FW_OK) { fw_value_free(v); fw_value_free(arr); return r; }
    if (fw_array_push(arr, v) != FW_OK) { fw_value_free(v); fw_value_free(arr); return FW_ERR_MEMORY; }
  }
  *out = arr;
  return FW_OK;
}
