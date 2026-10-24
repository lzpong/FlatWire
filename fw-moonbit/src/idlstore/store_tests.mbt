// idlstore 测试：JSON 解析（§11.1 v5.0 类型白名单/强制长度声明/enum base）+ 类型展开 + 库组织
//
// 注：load_all/put 依赖文件系统 FFI，仅在 node 运行时可用；moon test 的 node 进程
// 实际可执行同步 FFI，但依赖外部目录状态，文件系统路径行为放集成冒烟验证。

/// 规范 §11.1 v5.0 VehicleState 示例 IDL（类型白名单：u8/i8/timestamp/fixed_len string/
/// max_len string/f64/bytes/enum base u8/定长与变长数组；无 optional、无 size/width）
const VEHICLE_IDL : String = "{\"version\":\"1.0\",\"service\":{\"name\":\"VehicleStateService\",\"svc_id\":4096,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"GetState\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\",\"input\":[],\"output\":\"VehicleState\"},{\"name\":\"UpdateState\",\"if_id\":2,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"VehicleState\"]},{\"name\":\"UploadBlob\",\"if_id\":3,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"Blob\"],\"max_payload\":1048576},{\"name\":\"StateChanged\",\"if_id\":32769,\"type\":\"event\",\"transport\":\"udp\",\"output\":\"VehicleState\",\"reliable\":false}],\"event_groups\":[{\"name\":\"VehicleStateGroup\",\"grp_id\":1,\"members\":[32769,32770]}]},\"type_def\":{\"structs\":{\"VehicleState\":[{\"name\":\"veh_md\",\"type\":\"u8\"},{\"name\":\"usg_md\",\"type\":\"u8\"},{\"name\":\"sys_pwr_md\",\"type\":\"i8\"},{\"name\":\"timestamp\",\"type\":\"timestamp\"},{\"name\":\"timestr\",\"type\":\"string\",\"fixed_len\":20},{\"name\":\"status_msg\",\"type\":\"string\",\"max_len\":64},{\"name\":\"ratio\",\"type\":\"f64\"}],\"Blob\":[{\"name\":\"vin\",\"type\":\"bytes\",\"fixed_len\":17},{\"name\":\"payload\",\"type\":\"bytes\",\"max_len\":64000}]},\"enums\":{\"PowerMode\":{\"base\":\"u8\",\"values\":{\"Off\":0,\"Accessory\":1,\"Run\":2,\"CrankRequest\":3}}},\"arrays\":{\"VehicleStateArray\":{\"fixed_len\":10,\"element_type\":\"VehicleState\"},\"VehicleStateArray2\":{\"max_len\":100,\"element_type\":\"VehicleState\"}}}}"

/// 解析成功性断言（失败信息带异常文本）
fn parse_ok(text : String) -> IdlDef raise IdlError {
  parse_idl(text)
}

/// 解析应失败：返回 true=按预期失败
fn parse_fails(text : String) -> Bool {
  let r : Result[IdlDef, IdlError] = try {
    Ok(parse_idl(text))
  } catch {
    e => Err(e)
  }
  match r {
    Ok(_) => false
    Err(_) => true
  }
}

/// 完整解析：服务字段 + 接口路由 + 事件组
test "parse vehicle idl" {
  let def = parse_ok(VEHICLE_IDL)
  assert_eq(def.svc_id, 4096)
  assert_eq(def.major_ver, 1)
  assert_eq(def.minor_ver, 0)
  assert_eq(def.name, "VehicleStateService")
  assert_eq(def.interfaces.length(), 4)
  assert_eq(def.groups.length(), 1)
  assert_eq(def.groups[0].grp_id, 1)
  assert_eq(def.groups[0].members[0], 32769)
}

/// transport 默认路由（§11.1：rpc/ff=tcp、event=udp；声明覆盖默认）+ CRC 缺省关闭
test "interface transport defaults & crc default" {
  let def = parse_ok(VEHICLE_IDL)
  // GetState 声明 tcp（CType/IfKind 已补 Debug derive）
  assert_eq(def.interfaces[0].tcp, true)
  assert_eq(def.interfaces[0].kind, IfRpc)
  assert_eq(def.interfaces[0].if_id, 1)
  assert_eq(def.interfaces[0].output is Some(_), true)
  // §9.6 CRC 缺省关闭
  assert_eq(def.interfaces[0].crc, false)
  // UploadBlob：max_payload=1048576
  assert_eq(def.interfaces[2].max_payload, 1048576)
  // StateChanged：event + udp + if_id 32769
  assert_eq(def.interfaces[3].tcp, false)
  assert_eq(def.interfaces[3].kind, IfEvent)
  assert_eq(def.interfaces[3].if_id, 32769)
}

/// struct 引用内联展开（§9.4 嵌套）：UpdateState.input = CStruct(VehicleState 7 字段)
test "struct reference inlined" {
  let def = parse_ok(VEHICLE_IDL)
  match def.interfaces[1].input[0] {
    @codec.CStruct(fields) => {
      assert_eq(fields.length(), 7)
      // 首字段 veh_md: u8
      assert_eq(fields[0].name, "veh_md")
      assert_eq(fields[0].ctype, @codec.CUInt(1))
      // sys_pwr_md: i8（有符号补码）
      assert_eq(fields[2].ctype, @codec.CInt(1))
      // ratio: f64
      assert_eq(fields[6].ctype, @codec.CFloat(64))
    }
    _ => fail("expect CStruct")
  }
}

/// 数组元素为 struct 的内联展开 + enum base → 底层整型（§9.2/§9.4）
test "array of struct inlined & enum base" {
  let def = parse_ok(VEHICLE_IDL)
  // GetState.output = VehicleState struct
  match def.interfaces[0].output {
    Some(@codec.CStruct(fields)) => assert_eq(fields.length(), 7)
    _ => fail("expect struct output")
  }
  // 具名数组引用：VehicleStateArray fixed_len=10，元素为 struct
  let idl2 = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"Dump\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"VehicleStateArray\"],\"output\":\"PowerMode\"}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"u8\"}]},\"enums\":{\"PowerMode\":{\"base\":\"u8\",\"values\":{\"Off\":0}}},\"arrays\":{\"VehicleStateArray\":{\"fixed_len\":10,\"element_type\":\"V\"}}}}"
  let d2 = parse_ok(idl2)
  match d2.interfaces[0].input[0] {
    @codec.CArray(elem, Some(10), None) =>
      match elem {
        @codec.CStruct(fields) => assert_eq(fields.length(), 1)
        _ => fail("expect struct element")
      }
    _ => fail("expect CArray(fixed=10)")
  }
  // output = enum base u8 → CUInt(1)
  match d2.interfaces[0].output {
    Some(t) => assert_eq(t, @codec.CUInt(1))
    None => fail("expect output")
  }
}

/// 测试 1.5：string/bytes/array 既无 fixed_len 也无 max_len → IDL 加载失败
test "1.5 missing length declaration rejected" {
  // string 缺长度声明
  let base = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"V\"]}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"string\"}]}}}"
  assert_eq(parse_fails(base), true)
  // bytes 缺长度声明
  let bytes_idl = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"V\"]}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"bytes\"}]}}}"
  assert_eq(parse_fails(bytes_idl), true)
  // array 定义缺长度声明
  let arr_idl = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"A\"]}]},\"type_def\":{\"arrays\":{\"A\":{\"element_type\":\"u8\"}}}}"
  assert_eq(parse_fails(arr_idl), true)
  // 同时声明 fixed_len 与 max_len → 同样拒绝
  let both = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"V\"]}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"string\",\"fixed_len\":4,\"max_len\":8}]}}}"
  assert_eq(parse_fails(both), true)
}

/// 测试 1.12：f80 可选扩展——本实现不支持 → IDL 加载失败
test "1.12 f80 unsupported at load" {
  let idl = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"V\"]}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"f80\"}]}}}"
  assert_eq(parse_fails(idl), true)
}

/// 测试 1.27：enum base="i8" → 解析为 CInt(1)，负值合法
test "1.27 enum signed base" {
  let idl = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"output\":\"E\"}]},\"type_def\":{\"enums\":{\"E\":{\"base\":\"i8\",\"values\":{\"NegOne\":-1,\"Min\":-128}}}}}"
  let def = parse_ok(idl)
  match def.interfaces[0].output {
    Some(t) => assert_eq(t, @codec.CInt(1))
    None => fail("expect output")
  }
}

/// 测试 1.29：enum values 重复 / 超出 base 值域 → IDL 加载失败
test "1.29 enum values validation" {
  // 重复值
  let dup = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"output\":\"E\"}]},\"type_def\":{\"enums\":{\"E\":{\"base\":\"u8\",\"values\":{\"A\":1,\"B\":1}}}}}"
  assert_eq(parse_fails(dup), true)
  // 超出 u8 值域（300）
  let out = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"output\":\"E\"}]},\"type_def\":{\"enums\":{\"E\":{\"base\":\"u8\",\"values\":{\"A\":300}}}}}"
  assert_eq(parse_fails(out), true)
  // 负值在无符号 base 下非法
  let neg = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"output\":\"E\"}]},\"type_def\":{\"enums\":{\"E\":{\"base\":\"u8\",\"values\":{\"A\":-1}}}}}"
  assert_eq(parse_fails(neg), true)
}

/// §11.1 v5.0：optional / size / width / 旧类型名 → schema 错误
test "v5 legacy attrs rejected" {
  // optional
  let opt = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"V\"]}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"u8\",\"optional\":true}]}}}"
  assert_eq(parse_fails(opt), true)
  // size 属性
  let size = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"V\"]}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"u8\",\"size\":1}]}}}"
  assert_eq(parse_fails(size), true)
  // width 属性
  let width = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"V\"]}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"f32\",\"width\":32}]}}}"
  assert_eq(parse_fails(width), true)
  // 旧类型名 unsigned/signed/float
  let legacy = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"V\"]}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"unsigned\"}]}}}"
  assert_eq(parse_fails(legacy), true)
  // enum 旧 type 属性（应使用 base）
  let enum_type = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"output\":\"E\"}]},\"type_def\":{\"enums\":{\"E\":{\"type\":\"unsigned\",\"size\":1,\"values\":{\"A\":0}}}}}"
  assert_eq(parse_fails(enum_type), true)
}

/// 测试 1.34/1.35：接口 "crc": true 才启用（缺省关闭）
test "1.34/1.35 interface crc flag" {
  let idl = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"R\",\"if_id\":1,\"type\":\"rpc\",\"crc\":true},{\"name\":\"R2\",\"if_id\":2,\"type\":\"rpc\"}]}}"
  let def = parse_ok(idl)
  assert_eq(def.interfaces[0].crc, true)
  assert_eq(def.interfaces[1].crc, false)
}

/// 残缺 IDL 解析报错（跳过文件场景的数据基础）
test "broken idl raises" {
  let r : Result[IdlDef, IdlError] = try Ok(parse_idl("{\"service\":{\"svc_id\":1}}")) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expect parse error")
    Err(_) => ()
  }
}

/// IdlStore 内存组织：多版本并存不覆盖 + get_any 取最高版本
test "idl store versioning" {
  let store = IdlStore::new("unused_dir")
  let d1 = parse_idl("{\"service\":{\"name\":\"A\",\"svc_id\":100,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[]},\"type_def\":{}}")
  let d2 = parse_idl("{\"service\":{\"name\":\"A\",\"svc_id\":100,\"major_ver\":2,\"minor_ver\":0,\"interfaces\":[]},\"type_def\":{}}")
  // put 会尝试落盘到 unused_dir——失败降级内存（恰好验证降级路径）
  let _ = store.put(d1)
  let _ = store.put(d2)
  assert_eq(store.has(100, 1), true)
  assert_eq(store.has(100, 2), true)
  assert_eq(store.has(100, 3), false)
  match store.get_any(100) {
    Some(def) => assert_eq(def.major_ver, 2)
    None => fail("expect any version")
  }
  // raw 原文回取（GetIDL 响应体）
  match store.raw(100, 1) {
    Some(text) => assert_eq(text, d1.raw)
    None => fail("expect raw")
  }
}
