// ============================================================
// t_codec.c —— 测试基准 §1（1.6~1.29、1.31、1.33、1.38）：
//              v5.0 裸字节编解码（无字段头/无 null/大端定宽）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"
#include <math.h>

// 类型宽度（与 schema 的 scalar_size 同口径，测试手工构造 tdesc 用）
static int width_of(int kind) {
  switch (kind) {
    case FW_T_U8: case FW_T_I8: case FW_T_BOOL: return 1;
    case FW_T_U16: case FW_T_I16: return 2;
    case FW_T_U32: case FW_T_I32: case FW_T_F32: return 4;
    case FW_T_U64: case FW_T_I64: case FW_T_F64: return 8;
    case FW_T_TIMESTAMP: return 6;
    default: return 0;
  }
}

// 手工构造类型描述（fixed_len/max_len = -1 表示未声明）
static fw_tdesc_t tdesc(int kind, int fixed_len, int max_len) {
  fw_tdesc_t t;
  memset(&t, 0, sizeof(t));
  t.kind = kind;
  t.size = width_of(kind);
  t.fixed_len = fixed_len;
  t.max_len = max_len;
  return t;
}

// 编码到新 buf 并返回（忽略错误码，错误用例直接调 fw_encode_field）
static fw_buf_t enc(const fw_tdesc_t *t, const fw_value_t *v) {
  fw_buf_t b;
  fw_buf_init(&b);
  fw_encode_field(t, v, &b);
  return b;
}

// struct 字段赋值助手
static void set_field(fw_tfield_t *f, const char *name, fw_tdesc_t *t) {
  snprintf(f->name, sizeof(f->name), "%s", name);
  f->type = t;
}

int suite_codec(void) {
  size_t pos = 0;
  fw_value_t *out = NULL;
  fw_buf_t b;

  TEST_BEGIN("1.7/1.10/1.38 signed 边界（裸字节补码定宽）");
  fw_tdesc_t i8t = tdesc(FW_T_I8, -1, -1);
  b = enc(&i8t, fw_value_int(-128)); // §9.5：i8 -128 → 80
  CHECK_EQ_INT(b.len, 1); CHECK_EQ_MEM(b.p, (uint8_t[]){0x80}, 1); fw_buf_free(&b);
  b = enc(&i8t, fw_value_int(0));     CHECK_EQ_MEM(b.p, (uint8_t[]){0x00}, 1); fw_buf_free(&b);
  b = enc(&i8t, fw_value_int(127));   CHECK_EQ_MEM(b.p, (uint8_t[]){0x7F}, 1); fw_buf_free(&b);
  // 值域越界（测试 1.10）
  fw_buf_init(&b);
  CHECK_EQ_INT(fw_encode_field(&i8t, fw_value_int(128), &b), FW_DEC_RANGE);
  fw_buf_free(&b);
  // i16 -1 / -2（1.7 / 1.38 大端补码）
  fw_tdesc_t i16t = tdesc(FW_T_I16, -1, -1);
  b = enc(&i16t, fw_value_int(-1));
  CHECK_EQ_MEM(b.p, (uint8_t[]){0xFF, 0xFF}, 2); fw_buf_free(&b);
  b = enc(&i16t, fw_value_int(-2));
  CHECK_EQ_MEM(b.p, (uint8_t[]){0xFF, 0xFE}, 2); fw_buf_free(&b);
  // i64 值 10 仍占满 8B（恒定宽度，不压缩）
  fw_tdesc_t i64t = tdesc(FW_T_I64, -1, -1);
  b = enc(&i64t, fw_value_int(10));
  CHECK_EQ_INT(b.len, 8);
  CHECK_EQ_MEM(b.p, (uint8_t[]){0,0,0,0,0,0,0,10}, 8);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&i64t, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.i, 10); fw_value_free(out); out = NULL; fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.8 unsigned 边界（裸字节大端定宽）");
  fw_tdesc_t u8t = tdesc(FW_T_U8, -1, -1);
  b = enc(&u8t, fw_value_uint(0));   CHECK_EQ_MEM(b.p, (uint8_t[]){0x00}, 1); fw_buf_free(&b);
  b = enc(&u8t, fw_value_uint(255)); CHECK_EQ_MEM(b.p, (uint8_t[]){0xFF}, 1); fw_buf_free(&b);
  // 值域越界（测试 1.10）
  fw_buf_init(&b);
  CHECK_EQ_INT(fw_encode_field(&u8t, fw_value_uint(300), &b), FW_DEC_RANGE);
  fw_buf_free(&b);
  // u64 值 10 仍占满 8B
  fw_tdesc_t u64t = tdesc(FW_T_U64, -1, -1);
  b = enc(&u64t, fw_value_uint(10));
  CHECK_EQ_INT(b.len, 8); CHECK_EQ_MEM(b.p, (uint8_t[]){0,0,0,0,0,0,0,10}, 8); fw_buf_free(&b);
  // u16 0x1234 → 12 34（1.38 大端统一）
  fw_tdesc_t u16t = tdesc(FW_T_U16, -1, -1);
  b = enc(&u16t, fw_value_uint(0x1234));
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x12, 0x34}, 2); fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.9 字段字节不足（u32 仅剩 3B）→ UNDERRUN");
  fw_tdesc_t u32t = tdesc(FW_T_U32, -1, -1);
  uint8_t short3[] = {0x01, 0x02, 0x03};
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&u32t, short3, 3, &pos, &out), FW_DEC_UNDERRUN);
  CHECK(out == NULL);
  TEST_END();

  TEST_BEGIN("1.6 bool 严格解码（0x00/0x01，0x02 非法）");
  fw_tdesc_t bt = tdesc(FW_T_BOOL, -1, -1);
  b = enc(&bt, fw_value_bool(1)); CHECK_EQ_MEM(b.p, (uint8_t[]){0x01}, 1); fw_buf_free(&b);
  b = enc(&bt, fw_value_bool(0)); CHECK_EQ_MEM(b.p, (uint8_t[]){0x00}, 1); fw_buf_free(&b);
  uint8_t b1[] = {0x01}, b0[] = {0x00}, b2[] = {0x02};
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&bt, b1, 1, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.b, 1); fw_value_free(out); out = NULL;
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&bt, b0, 1, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.b, 0); fw_value_free(out); out = NULL;
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&bt, b2, 1, &pos, &out), FW_DEC_INVALID_BOOL); // InvalidBoolEncoding
  CHECK(out == NULL);
  TEST_END();

  TEST_BEGIN("1.11 float32/64（IEEE754 大端；NaN/±Inf 往返）");
  fw_tdesc_t f32t = tdesc(FW_T_F32, -1, -1);
  b = enc(&f32t, fw_value_float(3.14159)); // §9.5：40 49 0F D0
  CHECK_EQ_INT(b.len, 4); CHECK_EQ_MEM(b.p, (uint8_t[]){0x40, 0x49, 0x0F, 0xD0}, 4);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&f32t, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_F(out->as.f, 3.14159); fw_value_free(out); out = NULL; fw_buf_free(&b);

  fw_tdesc_t f64t = tdesc(FW_T_F64, -1, -1);
  b = enc(&f64t, fw_value_float(0.618));
  CHECK_EQ_INT(b.len, 8);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&f64t, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_F(out->as.f, 0.618); fw_value_free(out); out = NULL; fw_buf_free(&b);

  // NaN / +Inf / -Inf（位模式往返，不做数值比较）
  fw_value_t *vals[3] = { fw_value_float(NAN), fw_value_float(INFINITY), fw_value_float(-INFINITY) };
  for (int i = 0; i < 3; i++) {
    fw_buf_t fb;
    fw_buf_init(&fb);
    CHECK_EQ_INT(fw_encode_field(&f64t, vals[i], &fb), FW_OK);
    pos = 0;
    CHECK_EQ_INT(fw_decode_field(&f64t, fb.p, fb.len, &pos, &out), FW_OK);
    if (i == 0) CHECK(out->as.f != out->as.f);            // NaN
    else if (i == 1) CHECK(out->as.f == INFINITY);
    else CHECK(out->as.f == -INFINITY);
    fw_value_free(out); out = NULL;
    fw_buf_free(&fb);
    fw_value_free(vals[i]);
  }
  TEST_END();

  TEST_BEGIN("1.13 timestamp 48bit（6B 大端，2000 基准）");
  fw_tdesc_t ts = tdesc(FW_T_TIMESTAMP, -1, -1);
  b = enc(&ts, fw_value_uint(1)); // §9.5：00 00 00 00 00 01
  CHECK_EQ_MEM(b.p, (uint8_t[]){0,0,0,0,0,1}, 6); fw_buf_free(&b);
  uint64_t max48 = ((uint64_t)1 << 48) - 1;
  b = enc(&ts, fw_value_uint(max48));
  CHECK_EQ_INT(b.len, 6);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&ts, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_U64(out->as.u, max48); fw_value_free(out); out = NULL; fw_buf_free(&b);
  // 超出 48bit → 编码报错
  fw_buf_init(&b);
  CHECK_EQ_INT(fw_encode_field(&ts, fw_value_uint(max48 + 1), &b), FW_DEC_RANGE);
  fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.14/1.15 string/bytes 变长（max_len 前缀）");
  fw_tdesc_t str = tdesc(FW_T_STRING, -1, 64);
  b = enc(&str, fw_value_string("hi")); // §9.5：02 68 69（1B 前缀）
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x02, 'h', 'i'}, 3); fw_buf_free(&b);
  b = enc(&str, fw_value_string(""));
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x00}, 1); fw_buf_free(&b);
  b = enc(&str, fw_value_string("中文")); // UTF-8 6 字节
  CHECK_EQ_INT(b.len, 7); CHECK_EQ_INT(b.p[0], 6);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&str, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.s.len, 6); fw_value_free(out); out = NULL; fw_buf_free(&b);

  fw_tdesc_t byt = tdesc(FW_T_BYTES, -1, 64);
  b = enc(&byt, fw_value_bytes((const uint8_t[]){0x00, 0xFF}, 2)); // §9.5：02 00 FF
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x02, 0x00, 0xFF}, 3); fw_buf_free(&b);
  b = enc(&byt, fw_value_bytes(NULL, 0));
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x00}, 1); fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.16 长度前缀宽度推导（255/256/65535/65536）");
  // N=255 → 1B
  fw_tdesc_t m255 = tdesc(FW_T_STRING, -1, 255);
  b = enc(&m255, fw_value_string("a"));
  CHECK_EQ_INT(b.len, 2); CHECK_EQ_INT(b.p[0], 1); fw_buf_free(&b);
  // N=256 → 2B
  fw_tdesc_t m256 = tdesc(FW_T_STRING, -1, 256);
  b = enc(&m256, fw_value_string("a"));
  CHECK_EQ_INT(b.len, 3); CHECK_EQ_INT(b.p[0], 0); CHECK_EQ_INT(b.p[1], 1); fw_buf_free(&b);
  // N=65535 → 2B
  fw_tdesc_t m65535 = tdesc(FW_T_STRING, -1, 65535);
  b = enc(&m65535, fw_value_string("a"));
  CHECK_EQ_INT(b.len, 3); CHECK_EQ_INT(b.p[0], 0); CHECK_EQ_INT(b.p[1], 1); fw_buf_free(&b);
  // N=65536 → 4B
  fw_tdesc_t m65536 = tdesc(FW_T_STRING, -1, 65536);
  b = enc(&m65536, fw_value_string("a"));
  CHECK_EQ_INT(b.len, 5); CHECK_EQ_INT(b.p[3], 1); fw_buf_free(&b);
  // 解码回读（4B 前缀）
  b = enc(&m65536, fw_value_string("hello"));
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&m65536, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.s.len, 5); fw_value_free(out); out = NULL; fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.17 array 变长（max_len=100：0/2/100 元素，元素无类型头）");
  fw_tdesc_t uelem = tdesc(FW_T_U8, -1, -1);
  fw_tdesc_t arr100 = tdesc(FW_T_ARRAY, -1, 100);
  arr100.element = &uelem;
  // 0 个元素
  fw_value_t *a0 = fw_value_array(1);
  b = enc(&arr100, a0);
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x00}, 1); fw_value_free(a0); fw_buf_free(&b);
  // 2 个元素 → 02 01 02（§9.5）
  fw_value_t *a2 = fw_value_array(2);
  fw_array_push(a2, fw_value_uint(1));
  fw_array_push(a2, fw_value_uint(2));
  b = enc(&arr100, a2);
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x02, 0x01, 0x02}, 3); fw_buf_free(&b);
  // 100 个元素
  fw_value_t *a100 = fw_value_array(100);
  for (int i = 0; i < 100; i++) fw_array_push(a100, fw_value_uint((uint64_t)(i & 0xFF)));
  b = enc(&arr100, a100);
  CHECK_EQ_INT(b.len, 101); CHECK_EQ_INT(b.p[0], 100);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&arr100, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.arr.len, 100); fw_value_free(out); out = NULL;
  fw_value_free(a2); fw_value_free(a100); fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.18/1.19 定长 string（fixed_len=4 无前缀；长度不符报错）");
  fw_tdesc_t fs4 = tdesc(FW_T_STRING, 4, -1);
  b = enc(&fs4, fw_value_string("abcd"));
  CHECK_EQ_MEM(b.p, (uint8_t[]){'a', 'b', 'c', 'd'}, 4); fw_buf_free(&b);
  fw_value_t *v3 = fw_value_string_n("abc", 3);
  fw_buf_init(&b);
  CHECK_EQ_INT(fw_encode_field(&fs4, v3, &b), FW_DEC_FIXEDLEN);
  fw_value_free(v3); fw_buf_free(&b);
  fw_value_t *v5 = fw_value_string_n("abcde", 5);
  fw_buf_init(&b);
  CHECK_EQ_INT(fw_encode_field(&fs4, v5, &b), FW_DEC_FIXEDLEN);
  fw_value_free(v5); fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.20/1.21 定长 array（fixed_len=20 无前缀；空位默认 0）");
  fw_tdesc_t fa20 = tdesc(FW_T_ARRAY, 20, -1);
  fa20.element = &uelem;
  fw_value_t *p20 = fw_value_array(20);
  for (int i = 0; i < 20; i++) fw_array_push(p20, fw_value_uint(i < 12 ? 7 : 0)); // 12 业务值 + 8 空位
  b = enc(&fa20, p20);
  CHECK_EQ_INT(b.len, 20);            // 裸 20 元素，无长度字段
  CHECK_EQ_INT(b.p[0], 7); CHECK_EQ_INT(b.p[11], 7); CHECK_EQ_INT(b.p[19], 0);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&fa20, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.arr.len, 20);
  CHECK_EQ_INT(out->as.arr.items[0]->as.u, 7);
  CHECK_EQ_INT(out->as.arr.items[19]->as.u, 0);
  fw_value_free(out); out = NULL; fw_value_free(p20); fw_buf_free(&b);
  // 19 个元素（fixed_len=20 少 1）→ 编码报错（测试 1.21）
  fw_value_t *p19 = fw_value_array(19);
  for (int i = 0; i < 19; i++) fw_array_push(p19, fw_value_uint(0));
  fw_buf_init(&b);
  CHECK_EQ_INT(fw_encode_field(&fa20, p19, &b), FW_DEC_FIXEDLEN);
  fw_value_free(p19); fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.22 max_len 超限（编码报错 / 解码 MAXLEN）");
  fw_tdesc_t m64 = tdesc(FW_T_STRING, -1, 64);
  char big[65]; memset(big, 'x', 65);
  fw_value_t *bigv = fw_value_string_n(big, 65);
  fw_buf_init(&b);
  CHECK_EQ_INT(fw_encode_field(&m64, bigv, &b), FW_DEC_MAXLEN);
  fw_value_free(bigv); fw_buf_free(&b);
  // 解码：前缀声明 65 字节 > max_len=64 → MAXLEN（其余内容存在也应先校验上限）
  uint8_t over[67];
  over[0] = 65;
  memset(over + 1, 'x', 65);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&m64, over, sizeof(over), &pos, &out), FW_DEC_MAXLEN);
  CHECK(out == NULL);
  TEST_END();

  TEST_BEGIN("1.23~1.26 嵌套：struct/array 裸排（无边界标记）");
  // 1.23 struct 含 struct
  fw_tfield_t inner_f[2];
  fw_tdesc_t in_u8 = tdesc(FW_T_U8, -1, -1);
  fw_tdesc_t in_i8 = tdesc(FW_T_I8, -1, -1);
  set_field(&inner_f[0], "n", &in_u8);
  set_field(&inner_f[1], "d", &in_i8);
  fw_tdesc_t inner = tdesc(FW_T_STRUCT, -1, -1);
  inner.fields = inner_f; inner.field_n = 2;
  fw_tfield_t outer_f[2];
  set_field(&outer_f[0], "tag", &in_u8);
  set_field(&outer_f[1], "in", &inner);
  fw_tdesc_t outer = tdesc(FW_T_STRUCT, -1, -1);
  outer.fields = outer_f; outer.field_n = 2;
  fw_value_t *in_v = fw_value_struct();
  fw_struct_set(in_v, "n", fw_value_uint(2));
  fw_struct_set(in_v, "d", fw_value_int(-1));
  fw_value_t *out_v = fw_value_struct();
  fw_struct_set(out_v, "tag", fw_value_uint(1));
  fw_struct_set(out_v, "in", in_v);
  b = enc(&outer, out_v);
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x01, 0x02, 0xFF}, 3);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&outer, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(fw_struct_get(out, "tag")->as.u, 1);
  CHECK_EQ_INT(fw_struct_get(fw_struct_get(out, "in"), "d")->as.i, -1);
  fw_value_free(out); out = NULL; fw_value_free(out_v); fw_buf_free(&b);

  // 1.24 struct 含 array（max_len=4）
  fw_tdesc_t inner_arr = tdesc(FW_T_ARRAY, -1, 4);
  inner_arr.element = &in_u8;
  fw_tfield_t sf[2];
  set_field(&sf[0], "id", &in_u8);
  set_field(&sf[1], "xs", &inner_arr);
  fw_tdesc_t st = tdesc(FW_T_STRUCT, -1, -1);
  st.fields = sf; st.field_n = 2;
  fw_value_t *xs = fw_value_array(2);
  fw_array_push(xs, fw_value_uint(2));
  fw_array_push(xs, fw_value_uint(3));
  fw_value_t *sv = fw_value_struct();
  fw_struct_set(sv, "id", fw_value_uint(1));
  fw_struct_set(sv, "xs", xs);
  b = enc(&st, sv);
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x01, 0x02, 0x02, 0x03}, 4);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&st, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(fw_struct_get(out, "xs")->as.arr.len, 2);
  fw_value_free(out); out = NULL; fw_value_free(sv); fw_buf_free(&b);

  // 1.25 array 元素为 struct（max_len=2）
  fw_tfield_t elem_struct_f[1];
  set_field(&elem_struct_f[0], "v", &in_u8);
  fw_tdesc_t elem_struct = tdesc(FW_T_STRUCT, -1, -1);
  elem_struct.fields = elem_struct_f; elem_struct.field_n = 1;
  fw_tdesc_t arr_struct = tdesc(FW_T_ARRAY, -1, 2);
  arr_struct.element = &elem_struct;
  fw_value_t *sv1 = fw_value_struct();
  fw_struct_set(sv1, "v", fw_value_uint(1));
  fw_value_t *sv2 = fw_value_struct();
  fw_struct_set(sv2, "v", fw_value_uint(2));
  fw_value_t *arrv = fw_value_array(2);
  fw_array_push(arrv, sv1);
  fw_array_push(arrv, sv2);
  b = enc(&arr_struct, arrv);
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x02, 0x01, 0x02}, 3);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&arr_struct, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.arr.len, 2);
  CHECK_EQ_INT(fw_struct_get(out->as.arr.items[1], "v")->as.u, 2);
  fw_value_free(out); out = NULL; fw_value_free(arrv); fw_buf_free(&b);

  // 1.26 多维数组：外层 fixed_len=3、内层 fixed_len=4 → 12B 裸排
  fw_tdesc_t row4 = tdesc(FW_T_ARRAY, 4, -1);
  row4.element = &in_u8;
  fw_tdesc_t md_fixed = tdesc(FW_T_ARRAY, 3, -1);
  md_fixed.element = &row4;
  fw_value_t *mdf = fw_value_array(3);
  for (int r = 0; r < 3; r++) {
    fw_value_t *row = fw_value_array(4);
    for (int c = 0; c < 4; c++) fw_array_push(row, fw_value_uint((uint64_t)(r * 4 + c + 1)));
    fw_array_push(mdf, row);
  }
  b = enc(&md_fixed, mdf);
  CHECK_EQ_INT(b.len, 12); CHECK_EQ_INT(b.p[0], 1); CHECK_EQ_INT(b.p[11], 12);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&md_fixed, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.arr.len, 3);
  CHECK_EQ_INT(out->as.arr.items[2]->as.arr.len, 4);
  CHECK_EQ_INT(out->as.arr.items[2]->as.arr.items[3]->as.u, 12);
  fw_value_free(out); out = NULL; fw_value_free(mdf); fw_buf_free(&b);
  // 外层变长 + 内层变长：各层自带前缀（[03][03 01 02 03][03 ...]...）
  fw_tdesc_t row4m = tdesc(FW_T_ARRAY, -1, 4);
  row4m.element = &in_u8;
  fw_tdesc_t md_max = tdesc(FW_T_ARRAY, -1, 3);
  md_max.element = &row4m;
  fw_value_t *mdm = fw_value_array(2);
  for (int r = 0; r < 2; r++) {
    fw_value_t *row = fw_value_array(2);
    fw_array_push(row, fw_value_uint(1));
    fw_array_push(row, fw_value_uint(2));
    fw_array_push(mdm, row);
  }
  b = enc(&md_max, mdm);
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02}, 7);
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&md_max, b.p, b.len, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.arr.len, 2);
  CHECK_EQ_INT(out->as.arr.items[0]->as.arr.len, 2);
  fw_value_free(out); out = NULL; fw_value_free(mdm); fw_buf_free(&b);
  TEST_END();

  TEST_BEGIN("1.27/1.28/1.29 enum（i8 负值 / 未知值透传 / 值域）");
  struct { char name[32]; int64_t val; } evals[3] = {
    { "Zero", 0 }, { "NegOne", -1 }, { "Neg128", -128 }
  };
  fw_tdesc_t en = tdesc(FW_T_ENUM, -1, -1);
  en.size = 1; en.enum_base = 1; // 有符号基（i8）
  en.enum_vals = (void *)evals; en.enum_n = 3;
  b = enc(&en, fw_value_int(-1)); // §1.27：FF
  CHECK_EQ_MEM(b.p, (uint8_t[]){0xFF}, 1); fw_buf_free(&b);
  b = enc(&en, fw_value_int(-128)); // 80
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x80}, 1); fw_buf_free(&b);
  pos = 0;
  uint8_t b_ff[] = {0xFF};
  CHECK_EQ_INT(fw_decode_field(&en, b_ff, 1, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.i, -1);
  fw_value_free(out); out = NULL; fw_buf_free(&b);
  // 名称 → 值
  b = enc(&en, fw_value_string("Neg128"));
  CHECK_EQ_MEM(b.p, (uint8_t[]){0x80}, 1); fw_buf_free(&b);
  // 值域校验：base u8 编码 300 报错（1.29）
  fw_tdesc_t en_u8 = tdesc(FW_T_ENUM, -1, -1);
  en_u8.size = 1; en_u8.enum_base = 0;
  fw_buf_init(&b);
  CHECK_EQ_INT(fw_encode_field(&en_u8, fw_value_uint(300), &b), FW_DEC_RANGE);
  fw_buf_free(&b);
  // 未知值透传（1.28）：收到 IDL 未声明的 200 → 不报错，保留 200
  uint8_t b200[] = {200};
  pos = 0;
  CHECK_EQ_INT(fw_decode_field(&en_u8, b200, 1, &pos, &out), FW_OK);
  CHECK_EQ_INT(out->as.u, 200); fw_value_free(out); out = NULL;
  TEST_END();

  TEST_BEGIN("1.31/1.33 CRC + MSK 顺序（先 CRC 后 XOR）");
  CHECK_EQ_INT(fw_crc16_selfcheck(), 1);
  CHECK_EQ_INT(fw_crc16((const uint8_t *)"123456789", 9), 0x29B1);
  uint8_t data[5] = {1, 2, 3, 4, 5};
  uint16_t crc = fw_crc16(data, 5);
  uint8_t with_crc[7] = {1, 2, 3, 4, 5, (uint8_t)(crc >> 8), (uint8_t)(crc & 0xFF)};
  uint8_t key[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  fw_mask_xor(with_crc, 7, key);              // 整体（Data + CRC）XOR
  fw_mask_xor(with_crc, 7, key);              // 接收侧先还原
  CHECK_EQ_INT((with_crc[5] << 8) | with_crc[6], fw_crc16(with_crc, 5));
  CHECK_EQ_MEM(with_crc, data, 5);
  TEST_END();

  return 0;
}
