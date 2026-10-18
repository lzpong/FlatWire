// ============================================================
// test_all.c —— 测试入口（CTest 汇总；用例编号对齐《Test Cases.v4.md》）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

// 各套件入口（返回失败数）
int suite_crc(void);
int suite_value_json(void);
int suite_codec(void);
int suite_frame(void);
int suite_stream(void);
int suite_strm(void);
int suite_entries(void);
int suite_schema(void);
int suite_retrans(void);
int suite_tcp(void);
int suite_integration(void);
int suite_regress(void);

int main(int argc, char **argv) {
  int fails = 0;
  int only = argc > 1 ? atoi(argv[1]) : 0; // 可选：单跑某套件（1~12）
  printf("== FlatWire Protocol v4.4 C 实现 —— 单元测试 ==\n"); fflush(stdout);
  if (only == 0 || only == 1) fails += suite_crc();
  if (only == 0 || only == 2) fails += suite_value_json();
  if (only == 0 || only == 3) fails += suite_codec();
  if (only == 0 || only == 4) fails += suite_frame();
  if (only == 0 || only == 5) fails += suite_stream();
  if (only == 0 || only == 6) fails += suite_strm();
  if (only == 0 || only == 7) fails += suite_entries();
  if (only == 0 || only == 8) fails += suite_schema();
  if (only == 0 || only == 9) fails += suite_retrans();
  if (only == 0 || only == 10) fails += suite_tcp();
  if (only == 0 || only == 11) fails += suite_integration();
  if (only == 0 || only == 12) fails += suite_regress();
  printf("\n== 汇总：%s（失败套件数 %d）==\n", fails == 0 ? "全部通过" : "存在失败", fails);
  return fails ? 1 : 0;
}