// ============================================================
// t_schema.c —— §11.1 IDL 解析 + 类型解析 + 接口级编解码往返
//               （1.23~1.26 嵌套 / 1.34 optional / 9.1 末尾新增字段容忍）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

// 规范 §11.1 VehicleState IDL（测试自含副本）
static const char *IDL =
"{"
"\"version\":\"1.0\","
"\"service\":{\"name\":\"VehicleStateService\",\"svc_id\":4096,\"major_ver\":1,\"minor_ver\":0,"
"\"interfaces\":["
"{\"name\":\"GetState\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\",\"input\":[],\"output\":\"VehicleState\"},"
"{\"name\":\"UpdateState\",\"if_id\":2,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"VehicleState\"]},"
"{\"name\":\"StateChanged\",\"if_id\":32769,\"type\":\"event\",\"transport\":\"udp\",\"output\":\"VehicleState\",\"reliable\":false}"
"],"
"\"event_groups\":[{\"name\":\"G\",\"grp_id\":1,\"members\":[32769]}]},"
"\"type_def\":{"
"\"structs\":{"
"\"VehicleState\":["
"{\"name\":\"veh_md\",\"type\":\"unsigned\",\"size\":1},"
"{\"name\":\"usg_md\",\"type\":\"unsigned\",\"size\":1},"
"{\"name\":\"sys_pwr_md\",\"type\":\"signed\",\"size\":1},"
"{\"name\":\"timestamp\",\"type\":\"timestamp\"},"
"{\"name\":\"timestr\",\"type\":\"string\",\"fixed_len\":20},"
"{\"name\":\"status_msg\",\"type\":\"string\",\"max_len\":64},"
"{\"name\":\"diag_note\",\"type\":\"string\",\"max_len\":32,\"optional\":true},"
"{\"name\":\"ratio\",\"type\":\"float\",\"width\":64}"
"],"
"\"Blob\":["
"{\"name\":\"vin\",\"type\":\"bytes\",\"fixed_len\":17},"
"{\"name\":\"payload\",\"type\":\"bytes\",\"max_len\":64000}"
"]},"
"\"enums\":{\"PowerMode\":{\"type\":\"unsigned\",\"size\":1,\"values\":{\"Off\":0,\"Run\":2}}},"
"\"arrays\":{"
"\"VehicleStateArray\":{\"type\":\"array\",\"fixed_len\":10,\"element_type\":\"VehicleState\"},"
"\"VehicleStateArray2\":{\"type\":\"array\",\"max_len\":100,\"element_type\":\"VehicleState\"}"
"}}}";

int suite_schema(void) {
  fw_schema_t *s = NULL; // 跨块复用
  TEST_BEGIN("IDL 解析与类型解析");
  char err[128];
  fw_value_t *idl = fw_json_parse(IDL, strlen(IDL), err, sizeof(err));
  CHECK(idl != NULL);
  s = idl ? fw_schema_build(idl, err, sizeof(err)) : NULL;
  CHECK(s != NULL);
  if (s) {
    CHECK_EQ_INT(s->svc_id, 4096);
    CHECK_EQ_INT(s->major_ver, 1);
    CHECK_EQ_INT(s->iface_n, 3);
    fw_iface_t *get_state = fw_schema_iface(s, 1);
    CHECK(get_state != NULL);
    CHECK_EQ_STR(get_state->name, "GetState");
    CHECK_EQ_INT(get_state->type, FW_IF_RPC);
    CHECK_EQ_INT(get_state->transport, FW_TR_TCP);
    CHECK_EQ_INT(get_state->input_n, 0);
    CHECK(get_state->output_name && strcmp(get_state->output_name, "VehicleState") == 0);
    fw_iface_t *ev = fw_schema_iface(s, 32769);
    CHECK(ev != NULL && ev->type == FW_IF_EVENT && ev->transport == FW_TR_UDP);
    // 类型解析
    fw_tdesc_t *vs = fw_schema_resolve(s, "VehicleState");
    CHECK(vs != NULL && vs->kind == FW_T_STRUCT && vs->field_n == 8);
    fw_tdesc_t *pm = fw_schema_resolve(s, "PowerMode");
    CHECK(pm != NULL && pm->kind == FW_T_ENUM && pm->size == 1);
    fw_tdesc_t *arr = fw_schema_resolve(s, "VehicleStateArray");
    CHECK(arr != NULL && arr->kind == FW_T_ARRAY && arr->fixed_len == 10);
    CHECK(arr->element && arr->element->kind == FW_T_STRUCT);
    // 事件组
    int mn = 0;
    fw_schema_group_members(s, 1, &mn);
    CHECK_EQ_INT(mn, 1);
    fw_schema_free(s);
  }
  fw_value_free(idl);
  TEST_END();

  // ---- 接口级编解码往返（重新构建 schema）----
  fw_value_t *idl2 = fw_json_parse(IDL, strlen(IDL), err, sizeof(err));
  fw_schema_t *s2 = idl2 ? fw_schema_build(idl2, err, sizeof(err)) : NULL;
  s = s2;
  fw_iface_t *get_state = s ? fw_schema_iface(s, 1) : NULL;

  TEST_BEGIN("1.34 optional 往返（空 → 00；有值正常编码）");
  if (get_state) {
    fw_value_t *v = fw_value_struct();
    fw_struct_set(v, "veh_md", fw_value_uint(1));
    fw_struct_set(v, "usg_md", fw_value_uint(2));
    fw_struct_set(v, "sys_pwr_md", fw_value_int(2));
    fw_struct_set(v, "timestamp", fw_value_uint(123456));
    fw_struct_set(v, "timestr", fw_value_string("2026-10-13T12:00:00Z")); // 恰 20 字节
    fw_struct_set(v, "status_msg", fw_value_string("ok"));
    // diag_note 缺省 → null（1B 空头 §9.2）
    fw_struct_set(v, "ratio", fw_value_float(0.618));
    fw_buf_t b;
    fw_buf_init(&b);
    int r = fw_encode_payload(s, get_state, 1, v, &b, err, sizeof(err));
    CHECK_EQ_INT(r, FW_OK);
    // 线上必含 00（diag_note 位置）——解码回读
    fw_value_t *back = NULL;
    r = fw_decode_payload(s, get_state, 1, b.p, (uint32_t)b.len, &back, err, sizeof(err));
    CHECK_EQ_INT(r, FW_OK);
    CHECK(back != NULL);
    const fw_value_t *dn = fw_struct_get(back, "diag_note");
    CHECK(dn != NULL && dn->type == FW_V_NULL); // 解码为缺省 None
    CHECK(fw_struct_get(back, "veh_md")->as.u == 1);
    CHECK(fw_struct_get(back, "sys_pwr_md")->as.i == 2);
    fw_value_free(back);
    fw_buf_free(&b);
    fw_value_free(v);
  }
  TEST_END();

  TEST_BEGIN("1.33 非 optional 缺失 → 编码报错（UnexpectedNull）");
  if (get_state) {
    fw_value_t *v = fw_value_struct();
    fw_struct_set(v, "veh_md", fw_value_uint(1));
    // 缺 usg_md 等非 optional 字段
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s, get_state, 1, v, &b, err, sizeof(err)), FW_DEC_UNEXPECTED_NULL);
    fw_buf_free(&b);
    fw_value_free(v);
  }
  TEST_END();

  TEST_BEGIN("1.35 定长 string 长度不符 → 编码报错");
  if (get_state) {
    fw_value_t *v = fw_value_struct();
    fw_struct_set(v, "veh_md", fw_value_uint(1));
    fw_struct_set(v, "usg_md", fw_value_uint(2));
    fw_struct_set(v, "sys_pwr_md", fw_value_int(0));
    fw_struct_set(v, "timestamp", fw_value_uint(0));
    fw_struct_set(v, "timestr", fw_value_string("short")); // fixed_len=20 但 5 字节
    fw_struct_set(v, "status_msg", fw_value_string("ok"));
    fw_struct_set(v, "ratio", fw_value_float(0));
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s, get_state, 1, v, &b, err, sizeof(err)), FW_DEC_FIXEDLEN);
    fw_buf_free(&b);
    fw_value_free(v);
  }
  TEST_END();

  TEST_BEGIN("enum 编解码（线格式 = 底层整型，§11.1）");
  if (s) {
    fw_tdesc_t *pm = fw_schema_resolve(s, "PowerMode");
    fw_buf_t b;
    fw_buf_init(&b);
    // 名称 → 整数编码
    CHECK_EQ_INT(fw_encode_field(pm, fw_value_string("Run"), &b), FW_OK);
    CHECK_EQ_MEM(b.p, (uint8_t[]){0x31, 0x02}, 2); // unsigned(1) 值 2
    // 整数直接编码
    fw_buf_free(&b);
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_field(pm, fw_value_uint(0), &b), FW_OK);
    CHECK_EQ_MEM(b.p, (uint8_t[]){0x31, 0x00}, 2);
    fw_buf_free(&b);
  }
  TEST_END();

  TEST_BEGIN("9.1 末尾新增字段容忍（解码忽略剩余字节）");
  if (get_state) {
    // 编码标准结构
    fw_value_t *v = fw_value_struct();
    fw_struct_set(v, "veh_md", fw_value_uint(3));
    fw_struct_set(v, "usg_md", fw_value_uint(4));
    fw_struct_set(v, "sys_pwr_md", fw_value_int(1));
    fw_struct_set(v, "timestamp", fw_value_uint(99));
    fw_struct_set(v, "timestr", fw_value_string("2026-10-13T12:00:00Z"));
    fw_struct_set(v, "status_msg", fw_value_string("x"));
    fw_struct_set(v, "diag_note", fw_value_string("note"));
    fw_struct_set(v, "ratio", fw_value_float(1.5));
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s, get_state, 1, v, &b, err, sizeof(err)), FW_OK);
    // 附加"对端新增末尾字段"（unsigned(1) 0x31 05）→ 解码忽略不报错
    fw_buf_put_u8(&b, 0x31);
    fw_buf_put_u8(&b, 0x05);
    fw_value_t *back = NULL;
    CHECK_EQ_INT(fw_decode_payload(s, get_state, 1, b.p, (uint32_t)b.len, &back, err, sizeof(err)), FW_OK);
    CHECK(back && fw_struct_get(back, "veh_md")->as.u == 3);
    CHECK(fw_struct_get(back, "diag_note") && fw_struct_get(back, "diag_note")->type == FW_V_STRING);
    fw_value_free(back);
    fw_buf_free(&b);
    fw_value_free(v);
  }
  TEST_END();

  TEST_BEGIN("1.23/1.25 嵌套：结构体数组（VehicleStateArray 元素为结构体）");
  if (s) {
    fw_tdesc_t *arr = fw_schema_resolve(s, "VehicleStateArray");
    CHECK(arr != NULL);
    // 构造 2 个有效元素 + 8 个默认占位（fixed_len=10）
    fw_value_t *v = fw_value_array(10);
    for (int i = 0; i < 10; i++) {
      fw_value_t *el = fw_value_struct();
      fw_struct_set(el, "veh_md", fw_value_uint(i < 2 ? 1 : 0)); // 空位默认 0
      fw_struct_set(el, "usg_md", fw_value_uint(0));
      fw_struct_set(el, "sys_pwr_md", fw_value_int(0));
      fw_struct_set(el, "timestamp", fw_value_uint(0));
      fw_struct_set(el, "timestr", fw_value_string("                    ")); // 20 空格
      fw_struct_set(el, "status_msg", fw_value_string(""));
      fw_struct_set(el, "ratio", fw_value_float(0));
      fw_array_push(v, el);
    }
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_field(arr, v, &b), FW_OK);
    CHECK_EQ_INT(b.p[0], 0x8A); // 长度恒为 10
    fw_value_t *back = NULL;
    size_t pos = 0;
    CHECK_EQ_INT(fw_decode_field(arr, b.p, b.len, &pos, &back), FW_OK);
    CHECK(back && back->as.arr.len == 10);
    CHECK(fw_struct_get(back->as.arr.items[0], "veh_md")->as.u == 1);
    CHECK(fw_struct_get(back->as.arr.items[2], "veh_md")->as.u == 0); // 空位
    fw_value_free(back);
    fw_buf_free(&b);
    fw_value_free(v);
  }
  TEST_END();

  if (s2) fw_schema_free(s2);
  if (idl2) fw_value_free(idl2);
  return 0;
}