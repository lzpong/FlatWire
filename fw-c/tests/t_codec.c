// ============================================================
// t_codec.c —— 测试基准 1.5~1.35：§9 全类型编解码（恒定宽度/null/MSK）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

// 手工构造类型描述 helper
static fw_tdesc_t tdesc(int kind, int size, int width, int fixed_len, int max_len) {
  fw_tdesc_t t;
  memset(&t, 0, sizeof(t));
  t.kind = kind;
  t.size = size;
  t.width = width;
  t.fixed_len = fixed_len;
  t.max_len = max_len;
  return t;
}

// 编码到新 buf 并返回
static fw_buf_t enc(const fw_tdesc_t *t, const fw_value_t *v) {
  fw_buf_t b;
  fw_buf_init(&b);
  fw_encode_field(t, v, &b);
  return b;
}

int suite_codec(void) {
  fw_buf_t b;
  size_t pos = 0;
  fw_value_t *out = NULL;

  TEST_BEGIN("1.7/1.8 signed/unsigned 边界（恒定宽度大端）");
  fw_tdesc_t s1 = tdesc(FW_T_SIGNED, 1, 0, -1, -1);
  b = enc(&s1, fw_value_int(-128));  // §9.5：signed(1) -128 → 21 80
  CHECK_EQ_INT(b.len, 2); CHECK_EQ_MEM(b.p, (uint8_t[]){0x21, 0x80}, 2); fw_buf_free(&b);
  b = enc(&s1, fw_value_int(0));     CHECK_EQ_MEM(b.p, (uint8_t[]){0x21, 0x00}, 2); fw_buf_free(&b);
  b = enc(&s1, fw_value_int(127));   CHECK_EQ_MEM(b.p, (uint8_t[]){0x21, 0x7F}, 2); fw_buf_free(&b);
  fw_tdesc_t u1 = tdesc(FW_T_UNSIGNED, 1, 0, -1, -1);
  b = enc(&u1, fw_value_uint(255));  // §9.5：unsigned(1) 255 → 31 FF
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x31, 0xFF}, 2); fw_buf_free(&b);
  // 8B 字段值 10 占 8 字节（§9.2 恒定宽度：byte_len 恒等于 IDL size）
  fw_tdesc_t u8 = tdesc(FW_T_UNSIGNED, 8, 0, -1, -1);
  b = enc(&u8, fw_value_uint(10));
  CHECK_EQ_INT(b.len, 9); CHECK_EQ_INT(b.p[0], 0x38); CHECK_EQ_INT(b.p[8], 10); fw_buf_free(&b);
  // 值域越界
  CHECK_EQ_INT(fw_encode_field(&s1, fw_value_int(128), &b), FW_DEC_RANGE);
  CHECK_EQ_INT(fw_encode_field(&u1, fw_value_int(-1), &b), FW_DEC_RANGE);
  TEST_END();

  TEST_BEGIN("1.9/1.10/1.32 low4=0 非法 + SizeMismatch");
  pos = 0;
  uint8_t raw1[] = {0x20, 0x01}; // signed low4=0
  CHECK_EQ_INT(fw_decode_field(&s1, raw1, 2, &pos, &out), FW_DEC_INVALID_SIGNED_LEN);
  pos = 0;
  uint8_t raw2[] = {0x30, 0x01}; // unsigned low4=0
  CHECK_EQ_INT(fw_decode_field(&u1, raw2, 2, &pos, &out), FW_DEC_INVALID_UNSIGNED_LEN);
  pos = 0;
  uint8_t raw4[] = {0x31, 0x0A}; // unsigned(8) 收到 byte_len=1 → SizeMismatch
  CHECK_EQ_INT(fw_decode_field(&u8, raw4, 2, &pos, &out), FW_DEC_SIZE_MISMATCH);
  TEST_END();

  TEST_BEGIN("1.6 bool 严格解码（11/10；low4>1 抛错）");
  fw_tdesc_t tb = tdesc(FW_T_BOOL, 0, 0, -1, -1);
  b = enc(&tb, fw_value_bool(1)); CHECK_EQ_MEM(b.p, (uint8_t[]){0x11}, 1); fw_buf_free(&b);
  b = enc(&tb, fw_value_bool(0)); CHECK_EQ_MEM(b.p, (uint8_t[]){0x10}, 1); fw_buf_free(&b);
  pos = 0;
  uint8_t bad[] = {0x12};
  CHECK_EQ_INT(fw_decode_field(&tb, bad, 1, &pos, &out), FW_DEC_INVALID_BOOL); // 测试 1.6
  TEST_END();

  TEST_BEGIN("1.11/1.12 float32/64 + 子类型非法");
  fw_tdesc_t f32 = tdesc(FW_T_FLOAT, 0, 32, -1, -1);
  b = enc(&f32, fw_value_float(3.14159)); // §9.5：41 40 49 0F D0
  CHECK_EQ_INT(b.len, 5); CHECK_EQ_INT(b.p[0], 0x41);
  pos = 0; out = NULL;
  CHECK_EQ_INT(fw_decode_field(&f32, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_F(out->as.f, 3.14159); fw_value_free(out); out = NULL; fw_buf_free(&b);
  fw_tdesc_t f64 = tdesc(FW_T_FLOAT, 0, 64, -1, -1);
  b = enc(&f64, fw_value_float(0.618));
  CHECK_EQ_INT(b.len, 9); CHECK_EQ_INT(b.p[0], 0x42);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&f64, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_F(out->as.f, 0.618); fw_value_free(out); out = NULL; fw_buf_free(&b);
  // low4=0 / low4>=4 → UnsupportedFloatType（测试 1.12）
  pos = 0;
  uint8_t fbad[] = {0x40, 0, 0, 0, 0};
  CHECK_EQ_INT(fw_decode_field(&f32, fbad, 5, &pos, &out), FW_DEC_UNSUPPORTED_FLOAT);
  pos = 0;
  uint8_t fbad2[] = {0x44, 0, 0, 0, 0};
  CHECK_EQ_INT(fw_decode_field(&f32, fbad2, 5, &pos, &out), FW_DEC_UNSUPPORTED_FLOAT);
  // 80bit 扩展不支持（编码与解码一致抛错）
  fw_tdesc_t f80 = tdesc(FW_T_FLOAT, 0, 80, -1, -1);
  CHECK_EQ_INT(fw_encode_field(&f80, fw_value_float(1.0), &b), FW_DEC_UNSUPPORTED_FLOAT);
  TEST_END();

  TEST_BEGIN("1.13 timestamp 边界（44bit 拆分）");
  fw_tdesc_t ts = tdesc(FW_T_TIMESTAMP, 0, 0, -1, -1);
  b = enc(&ts, fw_value_uint(1)); // §9.5：50 00 00 00 00 01
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x50, 0, 0, 0, 0, 1}, 6); fw_buf_free(&b);
  uint64_t max44 = ((uint64_t)1 << 44) - 1;
  b = enc(&ts, fw_value_uint(max44));
  CHECK_EQ_INT(b.len, 6); CHECK_EQ_INT(b.p[0], 0x5F);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&ts, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_U64(out->as.u, max44); fw_value_free(out); out = NULL; fw_buf_free(&b);
  // 超出 44bit → 拒绝
  CHECK_EQ_INT(fw_encode_field(&ts, fw_value_uint(max44 + 1), &b), FW_DEC_RANGE);
  TEST_END();

  TEST_BEGIN("1.14/1.15 string/bytes 长度前缀");
  fw_tdesc_t str = tdesc(FW_T_STRING, 0, 0, -1, -1);
  b = enc(&str, fw_value_string("hi")); // §9.5：60 02 68 69
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x60, 2, 'h', 'i'}, 4); fw_buf_free(&b);
  b = enc(&str, fw_value_string(""));
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x60, 0}, 2); fw_buf_free(&b);
  fw_tdesc_t byt = tdesc(FW_T_BYTES, 0, 0, -1, -1);
  b = enc(&byt, fw_value_bytes((const uint8_t[]){0x00, 0xFF}, 2)); // §9.5：70 02 00 FF
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x70, 2, 0x00, 0xFF}, 4); fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.18/1.19/1.21/1.35 定长 string/array（空位 0x00）");
  fw_tdesc_t fs4 = tdesc(FW_T_STRING, 0, 0, 4, -1);
  b = enc(&fs4, fw_value_string("abcd")); // 长度恒为 4，内容恰 4 字节
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x60, 4, 'a', 'b', 'c', 'd'}, 6); fw_buf_free(&b);
  CHECK_EQ_INT(fw_encode_field(&fs4, fw_value_string("ab"), &b), FW_DEC_FIXEDLEN); // 长度不符报错
  fw_tdesc_t uelem = tdesc(FW_T_UNSIGNED, 1, 0, -1, -1);
  fw_tdesc_t fa10 = tdesc(FW_T_ARRAY, 0, 0, 10, -1);
  fa10.element = &uelem;
  fw_value_t *arrv = fw_value_array(10);
  for (int i = 0; i < 10; i++) fw_array_push(arrv, fw_value_uint(i < 2 ? 1 : 0)); // 空位填 0
  b = enc(&fa10, arrv); // 8A [31 XX] ×10（长度恒为 10，占位不压缩；每元素 2B）
  CHECK_EQ_INT(b.len, 21); CHECK_EQ_INT(b.p[0], 0x8A);
  fw_value_free(arrv); fw_buf_free(&b);
  // 19 个元素（fixed_len=20 少 1）→ 编码错误（测试 1.21 语义）
  fw_tdesc_t fa20 = tdesc(FW_T_ARRAY, 0, 0, 20, -1);
  fa20.element = &uelem;
  fw_value_t *arr19 = fw_value_array(19);
  for (int i = 0; i < 19; i++) fw_array_push(arr19, fw_value_uint(0));
  CHECK_EQ_INT(fw_encode_field(&fa20, arr19, &b), FW_DEC_FIXEDLEN);
  fw_value_free(arr19);
  TEST_END();

  TEST_BEGIN("1.22 max_len 超限");
  fw_tdesc_t m64 = tdesc(FW_T_STRING, 0, 0, -1, 64);
  CHECK_EQ_INT(fw_encode_field(&m64, fw_value_string_n("", 0), &b), FW_OK);
  fw_buf_free(&b);
  char big[65]; memset(big, 'x', 65);
  CHECK_EQ_INT(fw_encode_field(&m64, fw_value_string_n(big, 65), &b), FW_DEC_MAXLEN);
  TEST_END();

  TEST_BEGIN("1.16/1.17 array 内联/扩展长度");
  fw_tdesc_t a2 = tdesc(FW_T_ARRAY, 0, 0, -1, -1);
  a2.element = &uelem;
  fw_value_t *a2v = fw_value_array(2);
  fw_array_push(a2v, fw_value_uint(1));
  fw_array_push(a2v, fw_value_uint(2));
  b = enc(&a2, a2v); // §9.5：82 31 01 31 02
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x82, 0x31, 0x01, 0x31, 0x02}, 5);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&a2, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.arr.len, 2);
  fw_value_free(out); out = NULL; fw_value_free(a2v); fw_buf_free(&b);
  // 15 个元素 → 0x8F + 2B 长度
  fw_value_t *a15 = fw_value_array(15);
  for (int i = 0; i < 15; i++) fw_array_push(a15, fw_value_uint(7));
  b = enc(&a2, a15);
  CHECK_EQ_INT(b.len, 33); CHECK_EQ_INT(b.p[0], 0x8F); CHECK_EQ_INT((b.p[1] << 8) | b.p[2], 15); // 1+2+15×2
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&a2, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.arr.len, 15);
  fw_value_free(out); out = NULL; fw_value_free(a15); fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.5/1.33 null 仅 optional（非 optional 遇 null 抛错）");
  pos = 0;
  uint8_t nullb[] = {0x00};
  CHECK_EQ_INT(fw_decode_field(&s1, nullb, 1, &pos, &out), FW_DEC_UNEXPECTED_NULL);
  // optional 语义在 struct 字段层（见 t_schema 套件 1.34）
  TEST_END();

  TEST_BEGIN("1.27 UnknownFieldType（0x9~0xF）");
  for (int h = 0x9; h <= 0xF; h++) {
    pos = 0;
    uint8_t unk[] = {(uint8_t)(h << 4), 0xAA};
    CHECK_EQ_INT(fw_decode_field(&s1, unk, 2, &pos, &out), FW_DEC_UNKNOWN_FIELD);
  }
  TEST_END();

  TEST_BEGIN("1.28 MSK XOR（4B 对齐/不对齐）");
  uint8_t d1[9] = {1,2,3,4,5,6,7,8,9};
  uint8_t k[4] = {0x11, 0x22, 0x33, 0x44};
  uint8_t tmp[9];
  memcpy(tmp, d1, 9);
  fw_mask_xor(tmp, 9, k);
  CHECK(memcmp(tmp, d1, 9) != 0);
  fw_mask_xor(tmp, 9, k); // 两次 XOR 还原
  CHECK_EQ_MEM(tmp, d1, 9);
  TEST_END();

  return 0;
}