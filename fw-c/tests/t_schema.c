// ============================================================
// t_schema.c —— §11.1 v5.0 IDL 解析 + 类型解析 + 接口级编解码往返
//               （1.5 / 1.12 / 1.23~1.26 / 1.29 / 1.33~1.36）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

// 规范 §11.1 v5.0 VehicleState IDL（测试自含副本）
static const char *IDL =
"{"
"\"version\":\"1.0\","
"\"service\":{\"name\":\"VehicleStateService\",\"svc_id\":4096,\"major_ver\":1,\"minor_ver\":0,"
"\"interfaces\":["
"{\"name\":\"GetState\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\",\"input\":[],\"output\":\"VehicleState\"},"
"{\"name\":\"UpdateState\",\"if_id\":2,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"VehicleState\"]},"
"{\"name\":\"UploadBlob\",\"if_id\":3,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"Blob\"],\"max_payload\":1048576},"
"{\"name\":\"StateChanged\",\"if_id\":32769,\"type\":\"event\",\"transport\":\"udp\",\"output\":\"VehicleState\",\"reliable\":false},"
"{\"name\":\"PowerModeChanged\",\"if_id\":32770,\"type\":\"event\",\"transport\":\"udp\",\"output\":\"PowerMode\",\"reliable\":false}"
"],"
"\"event_groups\":[{\"name\":\"VehicleStateGroup\",\"grp_id\":1,\"members\":[32769,32770]}]},"
"\"type_def\":{"
"\"structs\":{"
"\"VehicleState\":["
"{\"name\":\"veh_md\",\"type\":\"u8\"},"
"{\"name\":\"usg_md\",\"type\":\"u8\"},"
"{\"name\":\"sys_pwr_md\",\"type\":\"i8\"},"
"{\"name\":\"timestamp\",\"type\":\"timestamp\"},"
"{\"name\":\"timestr\",\"type\":\"string\",\"fixed_len\":20},"
"{\"name\":\"status_msg\",\"type\":\"string\",\"max_len\":64},"
"{\"name\":\"ratio\",\"type\":\"f64\"}"
"],"
"\"Blob\":["
"{\"name\":\"vin\",\"type\":\"bytes\",\"fixed_len\":17},"
"{\"name\":\"payload\",\"type\":\"bytes\",\"max_len\":64000}"
"]},"
"\"enums\":{"
"\"PowerMode\":{\"base\":\"u8\",\"values\":{\"Off\":0,\"Accessory\":1,\"Run\":2,\"CrankRequest\":3}},"
"\"SignedMode\":{\"base\":\"i8\",\"values\":{\"MinusOne\":-1,\"Minus128\":-128}}"
"},"
"\"arrays\":{"
"\"VehicleStateArray\":{\"fixed_len\":10,\"element_type\":\"VehicleState\"},"
"\"VehicleStateArray2\":{\"max_len\":100,\"element_type\":\"VehicleState\"}"
"}}}";

// 最小 IDL 模板（service + 单 struct T），fields 由测试用例替换
static const char *IDL_MIN_PREFIX =
"{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,"
"\"interfaces\":[{\"name\":\"Get\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\","
"\"input\":[],\"output\":\"T\"}]},"
"\"type_def\":{\"structs\":{\"T\":[";
static const char *IDL_MIN_SUFFIX = "]}}}";

static fw_schema_t *build_text(const char *json, char *err, int errsz) {
  fw_value_t *idl = fw_json_parse(json, strlen(json), err, errsz);
  if (!idl) return NULL;
  fw_schema_t *s = fw_schema_build(idl, err, errsz);
  fw_value_free(idl);
  return s;
}

// 用字段片段构造最小 IDL 并尝试构建
static fw_schema_t *build_fields(const char *fields, char *err, int errsz) {
  char buf[1024];
  snprintf(buf, sizeof(buf), "%s%s%s", IDL_MIN_PREFIX, fields, IDL_MIN_SUFFIX);
  return build_text(buf, err, errsz);
}

// 构造 VehicleState 值（timestr 恰 20 字节）
static fw_value_t *make_state(unsigned veh, unsigned usg, int pwr, uint64_t ts,
                             const char *timestr, const char *status, double ratio) {
  fw_value_t *v = fw_value_struct();
  fw_struct_set(v, "veh_md", fw_value_uint(veh));
  fw_struct_set(v, "usg_md", fw_value_uint(usg));
  fw_struct_set(v, "sys_pwr_md", fw_value_int(pwr));
  fw_struct_set(v, "timestamp", fw_value_uint(ts));
  fw_struct_set(v, "timestr", fw_value_string(timestr));
  fw_struct_set(v, "status_msg", fw_value_string(status));
  fw_struct_set(v, "ratio", fw_value_float(ratio));
  return v;
}

int suite_schema(void) {
  char err[192];

  TEST_BEGIN("IDL 解析与类型解析（v5.0 白名单/base/数组）");
  fw_schema_t *s = build_text(IDL, err, sizeof(err));
  CHECK(s != NULL);
  if (s) {
    CHECK_EQ_INT(s->svc_id, 4096);
    CHECK_EQ_INT(s->major_ver, 1);
    CHECK_EQ_INT(s->iface_n, 5);
    fw_iface_t *get_state = fw_schema_iface(s, 1);
    CHECK(get_state != NULL);
    CHECK_EQ_INT(get_state->type, FW_IF_RPC);
    CHECK_EQ_INT(get_state->transport, FW_TR_TCP);
    CHECK_EQ_INT(get_state->input_n, 0);
    CHECK(get_state->output_name && strcmp(get_state->output_name, "VehicleState") == 0);
    CHECK_EQ_INT(get_state->crc, 0); // CRC 缺省关闭（§9.6/1.34）
    fw_iface_t *ev = fw_schema_iface(s, 32769);
    CHECK(ev != NULL && ev->type == FW_IF_EVENT && ev->transport == FW_TR_UDP);
    // 类型解析
    fw_tdesc_t *vs = fw_schema_resolve(s, "VehicleState");
    CHECK(vs != NULL && vs->kind == FW_T_STRUCT && vs->field_n == 7);
    if (vs) {
      CHECK_EQ_INT(vs->fields[0].type->kind, FW_T_U8);
      CHECK_EQ_INT(vs->fields[0].type->size, 1);
      CHECK_EQ_INT(vs->fields[2].type->kind, FW_T_I8);
      CHECK_EQ_INT(vs->fields[3].type->kind, FW_T_TIMESTAMP);
      CHECK_EQ_INT(vs->fields[3].type->size, 6);
      CHECK_EQ_INT(vs->fields[4].type->fixed_len, 20);
      CHECK_EQ_INT(vs->fields[5].type->max_len, 64);
      CHECK_EQ_INT(vs->fields[6].type->kind, FW_T_F64);
    }
    fw_tdesc_t *pm = fw_schema_resolve(s, "PowerMode");
    CHECK(pm != NULL && pm->kind == FW_T_ENUM && pm->size == 1 && pm->enum_base == 0);
    fw_tdesc_t *sm = fw_schema_resolve(s, "SignedMode");
    CHECK(sm != NULL && sm->kind == FW_T_ENUM && sm->size == 1 && sm->enum_base == 1); // i8 基
    fw_tdesc_t *arr = fw_schema_resolve(s, "VehicleStateArray");
    CHECK(arr != NULL && arr->kind == FW_T_ARRAY && arr->fixed_len == 10);
    CHECK(arr && arr->element && arr->element->kind == FW_T_STRUCT);
    fw_tdesc_t *arr2 = fw_schema_resolve(s, "VehicleStateArray2");
    CHECK(arr2 != NULL && arr2->max_len == 100);
    // 事件组
    int mn = 0;
    fw_schema_group_members(s, 1, &mn);
    CHECK_EQ_INT(mn, 2);
    fw_schema_free(s);
  }
  TEST_END();

  TEST_BEGIN("1.5 string/bytes/array 长度声明强制（缺 → IDL 加载失败）");
  const char *bad_fields[] = {
    "{\"name\":\"x\",\"type\":\"string\"}",
    "{\"name\":\"x\",\"type\":\"bytes\"}",
    "{\"name\":\"x\",\"type\":\"array\",\"element_type\":\"u8\"}",
    "{\"name\":\"x\",\"type\":\"string\",\"fixed_len\":4,\"max_len\":8}" // 同时声明亦非法
  };
  for (unsigned i = 0; i < sizeof(bad_fields) / sizeof(bad_fields[0]); i++) {
    fw_schema_t *bs = build_fields(bad_fields[i], err, sizeof(err));
    CHECK(bs == NULL);
    CHECK(strstr(err, "fixed_len") != NULL || strstr(err, "max_len") != NULL);
  }
  // arrays 条目缺长度声明 → 加载失败
  {
    const char *json =
      "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[]},"
      "\"type_def\":{\"arrays\":{\"A\":{\"element_type\":\"u8\"}}}}";
    fw_schema_t *bs = build_text(json, err, sizeof(err));
    CHECK(bs == NULL);
    CHECK(strstr(err, "fixed_len") != NULL);
  }
  // 合法的定长/变长声明可正常加载
  {
    fw_schema_t *ok = build_fields(
      "{\"name\":\"a\",\"type\":\"string\",\"fixed_len\":4},"
      "{\"name\":\"b\",\"type\":\"bytes\",\"max_len\":8},"
      "{\"name\":\"c\",\"type\":\"array\",\"element_type\":\"u16\",\"fixed_len\":3}", err, sizeof(err));
    CHECK(ok != NULL);
    if (ok) {
      fw_tdesc_t *t = fw_schema_resolve(ok, "T");
      CHECK(t != NULL && t->field_n == 3);
      CHECK(t && t->fields[2].type->kind == FW_T_ARRAY && t->fields[2].type->element->kind == FW_T_U16);
      fw_schema_free(ok);
    }
  }
  TEST_END();

  TEST_BEGIN("v5.0 拒绝 optional / size / width（§11.1）");
  const char *legacy_fields[] = {
    "{\"name\":\"x\",\"type\":\"string\",\"max_len\":8,\"optional\":true}",
    "{\"name\":\"x\",\"type\":\"u16\",\"size\":2}",
    "{\"name\":\"x\",\"type\":\"f64\",\"width\":64}"
  };
  for (unsigned i = 0; i < sizeof(legacy_fields) / sizeof(legacy_fields[0]); i++) {
    fw_schema_t *bs = build_fields(legacy_fields[i], err, sizeof(err));
    CHECK(bs == NULL);
    if (bs) fw_schema_free(bs);
  }
  // enum 不再使用 type/size 声明基类型
  {
    const char *json =
      "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[]},"
      "\"type_def\":{\"enums\":{\"E\":{\"type\":\"unsigned\",\"size\":1,\"values\":{\"A\":0}}}}}";
    fw_schema_t *bs = build_text(json, err, sizeof(err));
    CHECK(bs == NULL);
  }
  TEST_END();

  TEST_BEGIN("1.12 f80 可选扩展：本端不支持 → IDL 加载失败");
  {
    fw_schema_t *bs = build_fields("{\"name\":\"x\",\"type\":\"f80\"}", err, sizeof(err));
    CHECK(bs == NULL);
    CHECK(strstr(err, "f80") != NULL);
  }
  TEST_END();

  TEST_BEGIN("1.29 enum 值域/重复值校验（IDL 加载失败）");
  // 重复值
  {
    const char *json =
      "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[]},"
      "\"type_def\":{\"enums\":{\"E\":{\"base\":\"u8\",\"values\":{\"A\":1,\"B\":1}}}}}";
    fw_schema_t *bs = build_text(json, err, sizeof(err));
    CHECK(bs == NULL);
    CHECK(strstr(err, "duplicate") != NULL);
  }
  // 超出 base 值域
  {
    const char *json =
      "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[]},"
      "\"type_def\":{\"enums\":{\"E\":{\"base\":\"u8\",\"values\":{\"A\":300}}}}}";
    fw_schema_t *bs = build_text(json, err, sizeof(err));
    CHECK(bs == NULL);
    CHECK(strstr(err, "range") != NULL);
  }
  // 有符号基接受负值
  {
    const char *json =
      "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[]},"
      "\"type_def\":{\"enums\":{\"E\":{\"base\":\"i8\",\"values\":{\"A\":-1,\"B\":-128}}}}}";
    fw_schema_t *bs = build_text(json, err, sizeof(err));
    CHECK(bs != NULL);
    if (bs) {
      fw_tdesc_t *e = fw_schema_resolve(bs, "E");
      CHECK(e != NULL && e->enum_base == 1 && e->enum_n == 2);
      fw_schema_free(bs);
    }
  }
  TEST_END();

  // ---- 接口级编解码往返（重新构建 schema）----
  fw_schema_t *s2 = build_text(IDL, err, sizeof(err));
  fw_iface_t *get_state = s2 ? fw_schema_iface(s2, 1) : NULL;

  TEST_BEGIN("接口级 payload 往返（GetState output = VehicleState）");
  if (s2 && get_state) {
    fw_value_t *v = make_state(1, 2, -2, 123456, "2026-10-13T12:00:00Z", "ok", 0.618);
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s2, get_state, 1, v, &b, err, sizeof(err)), FW_OK);
    // 裸字节长度：1+1+1+6+20+(1+2)+8 = 40（无字段头、无 CRC）
    CHECK_EQ_INT(b.len, 40);
    CHECK_EQ_INT(b.p[0], 1);   // veh_md
    CHECK_EQ_INT(b.p[2], 0xFE); // sys_pwr_md = -2 补码
    CHECK_EQ_INT(b.p[29], 2);   // status_msg 长度前缀（20+6+2+1 = 29 索引）
    fw_value_t *back = NULL;
    CHECK_EQ_INT(fw_decode_payload(s2, get_state, 1, b.p, (uint32_t)b.len, &back,
                                   err, sizeof(err)), FW_OK);
    CHECK(back != NULL);
    if (back) {
      CHECK_EQ_INT(fw_struct_get(back, "veh_md")->as.u, 1);
      CHECK_EQ_INT(fw_struct_get(back, "usg_md")->as.u, 2);
      CHECK_EQ_INT(fw_struct_get(back, "sys_pwr_md")->as.i, -2);
      CHECK_EQ_U64(fw_struct_get(back, "timestamp")->as.u, 123456);
      CHECK_EQ_STR(fw_struct_get(back, "timestr")->as.s.ptr, "2026-10-13T12:00:00Z");
      CHECK_EQ_STR(fw_struct_get(back, "status_msg")->as.s.ptr, "ok");
      CHECK_EQ_F(fw_struct_get(back, "ratio")->as.f, 0.618);
      fw_value_free(back);
    }
    fw_value_free(v);
    fw_buf_free(&b);
  }
  TEST_END();

  TEST_BEGIN("1.33 字段缺失/null → 编码报错（全部必填）");
  if (s2 && get_state) {
    fw_value_t *v = fw_value_struct();
    fw_struct_set(v, "veh_md", fw_value_uint(1)); // 缺其余字段
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s2, get_state, 1, v, &b, err, sizeof(err)),
                 FW_DEC_UNEXPECTED_NULL);
    fw_buf_free(&b);
    fw_value_free(v);
    // 显式 null 值同样违约
    fw_value_t *v2 = make_state(1, 2, 0, 0, "2026-10-13T12:00:00Z", "ok", 0.0);
    fw_struct_set(v2, "ratio", fw_value_null());
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s2, get_state, 1, v2, &b, err, sizeof(err)),
                 FW_DEC_UNEXPECTED_NULL);
    fw_buf_free(&b);
    fw_value_free(v2);
  }
  TEST_END();

  TEST_BEGIN("1.18/1.19 定长 string 长度不符 → 编码报错");
  if (s2 && get_state) {
    fw_value_t *v = make_state(1, 2, 0, 0, "short", "ok", 0);
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s2, get_state, 1, v, &b, err, sizeof(err)), FW_DEC_FIXEDLEN);
    fw_buf_free(&b);
    fw_value_free(v);
  }
  TEST_END();

  TEST_BEGIN("1.34 CRC 缺省关闭（未声明 \"crc\": true）");
  if (s2 && get_state) {
    CHECK_EQ_INT(get_state->crc, 0);
    fw_value_t *v = make_state(0, 0, 0, 0, "2026-10-13T12:00:00Z", "", 0);
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s2, get_state, 1, v, &b, err, sizeof(err)), FW_OK);
    // 3 + 6 + 20 + 1 + 0 + 8 = 38，末尾无 2B CRC
    CHECK_EQ_INT(b.len, 38);
    fw_value_free(v);
    fw_buf_free(&b);
  }
  TEST_END();

  TEST_BEGIN("1.35 CRC 开启与校验（末尾 2B 大端；篡改 1 字节 → CRC 失败）");
  {
    // 同构 IDL，GetState 声明 "crc": true
    const char *json =
    "{\"service\":{\"name\":\"C\",\"svc_id\":4097,\"major_ver\":1,\"minor_ver\":0,"
    "\"interfaces\":[{\"name\":\"Get\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\","
    "\"input\":[],\"output\":\"T\",\"crc\":true}]},"
    "\"type_def\":{\"structs\":{\"T\":[{\"name\":\"a\",\"type\":\"u16\"},"
    "{\"name\":\"s\",\"type\":\"string\",\"max_len\":8}]}}}";
    fw_schema_t *sc = build_text(json, err, sizeof(err));
    CHECK(sc != NULL);
    fw_iface_t *ifc = sc ? fw_schema_iface(sc, 1) : NULL;
    CHECK(ifc != NULL && ifc->crc == 1);
    if (sc && ifc) {
      fw_value_t *v = fw_value_struct();
      fw_struct_set(v, "a", fw_value_uint(0x1234));
      fw_struct_set(v, "s", fw_value_string("hi"));
      fw_buf_t b;
      fw_buf_init(&b);
      CHECK_EQ_INT(fw_encode_payload(sc, ifc, 1, v, &b, err, sizeof(err)), FW_OK);
      CHECK_EQ_INT(b.len, 5 + 2); // 2 + (1+2) + 2B CRC
      uint16_t crc = (uint16_t)(((uint16_t)b.p[5] << 8) | b.p[6]);
      CHECK_EQ_INT(crc, fw_crc16(b.p, 5));
      // 正常校验通过
      fw_value_t *back = NULL;
      CHECK_EQ_INT(fw_decode_payload(sc, ifc, 1, b.p, (uint32_t)b.len, &back,
                                     err, sizeof(err)), FW_OK);
      CHECK(back != NULL && fw_struct_get(back, "a")->as.u == 0x1234);
      fw_value_free(back);
      // 篡改 1 字节 → CRC 失败（该帧应回 RST(0x20)）
      b.p[1] ^= 0xFF;
      CHECK_EQ_INT(fw_decode_payload(sc, ifc, 1, b.p, (uint32_t)b.len, &back,
                                     err, sizeof(err)), FW_DEC_CRC);
      fw_value_free(v);
      fw_buf_free(&b);
    }
    if (sc) fw_schema_free(sc);
  }
  TEST_END();

  TEST_BEGIN("1.36 末尾新增字段忽略（旧解码器跳过剩余字节）");
  if (s2 && get_state) {
    fw_value_t *v = make_state(3, 4, 1, 99, "2026-10-13T12:00:00Z", "x", 1.5);
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_payload(s2, get_state, 1, v, &b, err, sizeof(err)), FW_OK);
    size_t base = b.len;
    // 模拟对端新增末尾字段：u8 + i16（旧端无此字段定义）
    CHECK_EQ_INT(fw_buf_put_u8(&b, 0x05), FW_OK);
    CHECK_EQ_INT(fw_buf_put_u8(&b, 0x00), FW_OK);
    CHECK_EQ_INT(fw_buf_put_u8(&b, 0x2A), FW_OK);
    fw_value_t *back = NULL;
    CHECK_EQ_INT(fw_decode_payload(s2, get_state, 1, b.p, (uint32_t)b.len, &back,
                                   err, sizeof(err)), FW_OK);
    CHECK(back != NULL);
    if (back) {
      CHECK_EQ_INT(fw_struct_get(back, "veh_md")->as.u, 3);
      CHECK(fw_struct_get(back, "new_field") == NULL); // 未解析新增字段
      fw_value_free(back);
    }
    CHECK_EQ_INT(b.len, (long long)base + 3); // 新增字节已附加，解码时被忽略
    fw_value_free(v);
    fw_buf_free(&b);
  }
  TEST_END();

  TEST_BEGIN("1.23/1.25 数组元素为结构体（定长 10，无长度前缀）");
  if (s2) {
    fw_tdesc_t *arr = fw_schema_resolve(s2, "VehicleStateArray");
    CHECK(arr != NULL);
    fw_value_t *v = fw_value_array(10);
    for (int i = 0; i < 10; i++) {
      // 空位取默认值（数值 0 / 空串），构造方保证恰 10 个元素（§9.3）
      fw_value_t *el = make_state(i < 2 ? 1u : 0u, 0, 0, 0, "2026-10-13T12:00:00Z", "", 0.0);
      fw_array_push(v, el);
    }
    fw_buf_t b;
    fw_buf_init(&b);
    CHECK_EQ_INT(fw_encode_field(arr, v, &b), FW_OK);
    // 每个元素 3+6+20+1+0+8 = 38 字节，无数组长度前缀
    CHECK_EQ_INT(b.len, 38 * 10);
    fw_value_t *back = NULL;
    size_t pos = 0;
    CHECK_EQ_INT(fw_decode_field(arr, b.p, b.len, &pos, &back), FW_OK);
    CHECK(back && back->as.arr.len == 10);
    if (back) {
      CHECK_EQ_INT(fw_struct_get(back->as.arr.items[0], "veh_md")->as.u, 1);
      CHECK_EQ_INT(fw_struct_get(back->as.arr.items[2], "veh_md")->as.u, 0);
      fw_value_free(back);
    }
    fw_value_free(v);
    fw_buf_free(&b);
  }
  TEST_END();

  if (s2) fw_schema_free(s2);
  return 0;
}
