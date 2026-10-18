// ============================================================
// t_value_json.c —— fw_value 生命周期 + 迷你 JSON 解析器
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

int suite_value_json(void) {
  TEST_BEGIN("fw_value 构造/释放/克隆");
  fw_value_t *st = fw_value_struct();
  CHECK(fw_struct_set(st, "a", fw_value_uint(42)) == FW_OK);
  CHECK(fw_struct_set(st, "b", fw_value_string("hi")) == FW_OK);
  fw_value_t *arr = fw_value_array(2);
  fw_array_push(arr, fw_value_int(-1));
  fw_array_push(arr, fw_value_float(0.5));
  CHECK(fw_struct_set(st, "c", arr) == FW_OK);
  fw_value_t *cl = fw_value_clone(st);
  CHECK(cl != NULL && cl != st);
  CHECK(fw_struct_get(cl, "a") && fw_struct_get(cl, "a")->as.u == 42);
  CHECK(fw_struct_get(cl, "b") && strcmp(fw_struct_get(cl, "b")->as.s.ptr, "hi") == 0);
  fw_value_free(st);
  fw_value_free(cl);
  // 重名覆盖
  fw_value_t *s2 = fw_value_struct();
  fw_struct_set(s2, "x", fw_value_uint(1));
  fw_struct_set(s2, "x", fw_value_uint(2));
  CHECK(fw_struct_get(s2, "x")->as.u == 2);
  fw_value_free(s2);
  TEST_END();

  TEST_BEGIN("JSON 解析：对象/数组/字符串转义/数字/bool/null");
  char err[128];
  fw_value_t *v = fw_json_parse(
    "{\"a\": 1, \"b\": -2, \"c\": 3.5, \"d\": \"x\\u4e2dy\\n\", \"e\": [true, false, null], \"f\": {}}",
    strlen("{\"a\": 1, \"b\": -2, \"c\": 3.5, \"d\": \"x\\u4e2dy\\n\", \"e\": [true, false, null], \"f\": {}}"), err, sizeof(err));
  CHECK(v != NULL);
  if (v) {
    CHECK(fw_struct_get(v, "a")->type == FW_V_UINT && fw_struct_get(v, "a")->as.u == 1);
    CHECK(fw_struct_get(v, "b")->type == FW_V_INT && fw_struct_get(v, "b")->as.i == -2);
    CHECK(fw_struct_get(v, "c")->type == FW_V_FLOAT);
    const fw_value_t *d = fw_struct_get(v, "d");
    CHECK(d && d->type == FW_V_STRING && strstr(d->as.s.ptr, "中") != NULL); // \u4e2d = 中
    const fw_value_t *e = fw_struct_get(v, "e");
    CHECK(e && e->type == FW_V_ARRAY && e->as.arr.len == 3);
    CHECK(e->as.arr.items[0]->type == FW_V_BOOL && e->as.arr.items[0]->as.b == 1);
    CHECK(e->as.arr.items[2]->type == FW_V_NULL);
    CHECK(fw_struct_get(v, "f")->type == FW_V_STRUCT);
    fw_value_free(v);
  }
  TEST_END();

  TEST_BEGIN("JSON 非法输入");
  CHECK(fw_json_parse("{bad}", 5, err, sizeof(err)) == NULL);
  CHECK(fw_json_parse("{\"a\":1} tail", 12, err, sizeof(err)) == NULL); // 尾随内容
  CHECK(fw_json_parse("\"unterminated", 13, err, sizeof(err)) == NULL);
  TEST_END();

  return 0;
}