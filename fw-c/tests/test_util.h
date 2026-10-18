// ============================================================
// test_util.h —— 轻量测试框架（assert 宏 + 用例注册 + 计数）
// ============================================================

#ifndef FW_TEST_UTIL_H
#define FW_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__)
  #define FW_TU __attribute__((unused)) // 抑制未用 static 告警（部分套件不触发全部宏）
#else
  #define FW_TU
#endif

static FW_TU int g_t_pass = 0, g_t_fail = 0;
static FW_TU const char *g_t_cur = NULL;

#define TEST_BEGIN(name) do { g_t_cur = (name); g_t_pass = g_t_fail = 0; printf("TEST %s ...\n", name); fflush(stdout); } while (0)

#define CHECK(cond) do { \
  if (cond) { g_t_pass++; } \
  else { g_t_fail++; printf("  [FAIL] %s:%d: %s\n", g_t_cur, __LINE__, #cond); } \
} while (0)

#define CHECK_EQ_INT(a, b) do { \
  long long va_ = (long long)(a), vb_ = (long long)(b); \
  if (va_ == vb_) { g_t_pass++; } \
  else { g_t_fail++; printf("  [FAIL] %s:%d: %s == %s (%lld != %lld)\n", g_t_cur, __LINE__, #a, #b, va_, vb_); } \
} while (0)

#define CHECK_EQ_U64(a, b) do { \
  unsigned long long va_ = (unsigned long long)(a), vb_ = (unsigned long long)(b); \
  if (va_ == vb_) { g_t_pass++; } \
  else { g_t_fail++; printf("  [FAIL] %s:%d: %s == %s (%llu != %llu)\n", g_t_cur, __LINE__, #a, #b, va_, vb_); } \
} while (0)

#define CHECK_EQ_F(a, b) do { \
  double va_ = (double)(a), vb_ = (double)(b); \
  double d_ = va_ > vb_ ? va_ - vb_ : vb_ - va_; \
  if (d_ < 1e-6) { g_t_pass++; } /* float32 编码精度约 1e-7 */ \
  else { g_t_fail++; printf("  [FAIL] %s:%d: %s == %s (%f != %f)\n", g_t_cur, __LINE__, #a, #b, va_, vb_); } \
} while (0)

#define CHECK_EQ_STR(a, b) do { \
  const char *sa_ = (a), *sb_ = (b); \
  if (sa_ && sb_ && strcmp(sa_, sb_) == 0) { g_t_pass++; } \
  else { g_t_fail++; printf("  [FAIL] %s:%d: %s == %s (\"%s\" != \"%s\")\n", g_t_cur, __LINE__, #a, #b, sa_ ? sa_ : "(null)", sb_ ? sb_ : "(null)"); } \
} while (0)

// 内存比较经真实函数接收（复合字面量参数不被宏分裂）
static FW_TU int t_mem_eq(const void *a, const void *b, size_t n) {
  return a && b && memcmp(a, b, n) == 0;
}
#define CHECK_EQ_MEM(...) CHECK(t_mem_eq(__VA_ARGS__))

#define TEST_END() do { \
  if (g_t_fail) { printf("[SUITE-FAIL] %s: %d passed, %d failed\n", g_t_cur, g_t_pass, g_t_fail); return 1; } \
} while (0)

#endif // FW_TEST_UTIL_H