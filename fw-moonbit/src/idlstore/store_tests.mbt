// idlstore 测试：JSON 解析（§11.1 全类型特性）+ 类型展开 + 库组织（FFI 文件操作由冒烟验证）
//
// 注：load_all/put 依赖文件系统 FFI，仅在 node 运行时可用；moon test 的 node 进程
// 实际可执行同步 FFI，但依赖外部目录状态，文件系统路径行为放集成冒烟验证。

/// 规范 §11.1 VehicleState 示例 IDL（全部类型特性：signed/unsigned/timestamp/
/// fixed_len string/max_len string/optional/float64/bytes/fixed_len bytes/enum/
/// fixed_len array/max_len array）
const VEHICLE_IDL : String = "{\"version\":\"1.0\",\"service\":{\"name\":\"VehicleStateService\",\"svc_id\":4096,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"GetState\",\"if_id\":1,\"type\":\"rpc\",\"transport\":\"tcp\",\"input\":[],\"output\":\"VehicleState\"},{\"name\":\"UpdateState\",\"if_id\":2,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"VehicleState\"]},{\"name\":\"UploadBlob\",\"if_id\":3,\"type\":\"ff\",\"transport\":\"tcp\",\"input\":[\"Blob\"],\"max_payload\":1048576},{\"name\":\"StateChanged\",\"if_id\":32769,\"type\":\"event\",\"transport\":\"udp\",\"output\":\"VehicleState\",\"reliable\":false}],\"event_groups\":[{\"name\":\"VehicleStateGroup\",\"grp_id\":1,\"members\":[32769,32770]}]},\"type_def\":{\"structs\":{\"VehicleState\":[{\"name\":\"veh_md\",\"type\":\"unsigned\",\"size\":1},{\"name\":\"sys_pwr_md\",\"type\":\"signed\",\"size\":1},{\"name\":\"timestamp\",\"type\":\"timestamp\"},{\"name\":\"timestr\",\"type\":\"string\",\"fixed_len\":20},{\"name\":\"status_msg\",\"type\":\"string\",\"max_len\":64},{\"name\":\"diag_note\",\"type\":\"string\",\"max_len\":32,\"optional\":true},{\"name\":\"ratio\",\"type\":\"float\",\"width\":64}],\"Blob\":[{\"name\":\"vin\",\"type\":\"bytes\",\"fixed_len\":17},{\"name\":\"payload\",\"type\":\"bytes\",\"max_len\":64000}]},\"enums\":{\"PowerMode\":{\"type\":\"unsigned\",\"size\":1,\"values\":{\"Off\":0}}},\"arrays\":{\"VehicleStateArray\":{\"type\":\"array\",\"fixed_len\":10,\"element_type\":\"VehicleState\"}}}}"

/// 完整解析：服务字段 + 接口路由 + 事件组
test "parse vehicle idl" {
  let def = parse_idl(VEHICLE_IDL)
  assert_eq(def.svc_id, 4096)
  assert_eq(def.major_ver, 1)
  assert_eq(def.minor_ver, 0)
  assert_eq(def.name, "VehicleStateService")
  assert_eq(def.interfaces.length(), 4)
  assert_eq(def.groups.length(), 1)
  assert_eq(def.groups[0].grp_id, 1)
  assert_eq(def.groups[0].members[0], 32769)
}

/// transport 默认路由（§11.1：rpc/ff=tcp、event=udp；声明覆盖默认）
test "interface transport defaults" {
  let def = parse_idl(VEHICLE_IDL)
  // GetState 声明 tcp（CType/IfKind 已补 Debug derive）
  assert_eq(def.interfaces[0].tcp, true)
  assert_eq(def.interfaces[0].kind, IfRpc)
  assert_eq(def.interfaces[0].if_id, 1)
  assert_eq(def.interfaces[0].output is Some(_), true)
  // UploadBlob：max_payload=1048576
  assert_eq(def.interfaces[2].max_payload, 1048576)
  // StateChanged：event + udp + if_id 32769
  assert_eq(def.interfaces[3].tcp, false)
  assert_eq(def.interfaces[3].kind, IfEvent)
  assert_eq(def.interfaces[3].if_id, 32769)
}

/// struct 引用内联展开（§9.3 嵌套）：UpdateState.input = CStruct(VehicleState 字段组)
test "struct reference inlined" {
  let def = parse_idl(VEHICLE_IDL)
  match def.interfaces[1].input[0] {
    @codec.CStruct(fields) => {
      assert_eq(fields.length(), 7)
      // 首字段 veh_md: unsigned(1)
      assert_eq(fields[0].name, "veh_md")
      assert_eq(fields[0].ctype, @codec.CUnsigned(1))
      // diag_note: optional
      assert_eq(fields[5].optional, true)
      // ratio: float(64)
      assert_eq(fields[6].ctype, @codec.CFloat(64))
    }
    _ => fail("expect CStruct")
  }
}

/// 数组元素为 struct 的内联展开（§9.3 任意嵌套）
test "array of struct inlined" {
  let def = parse_idl(VEHICLE_IDL)
  let it = def.interfaces[1]
  let _ = it
  // 通过 GetState.output 间接验证不了 array——直接解析一个含数组引用的接口
  let idl2 = "{\"service\":{\"name\":\"S\",\"svc_id\":1,\"major_ver\":1,\"minor_ver\":0,\"interfaces\":[{\"name\":\"Dump\",\"if_id\":1,\"type\":\"rpc\",\"input\":[\"VehicleStateArray\"],\"output\":\"PowerMode\"}]},\"type_def\":{\"structs\":{\"V\":[{\"name\":\"a\",\"type\":\"unsigned\",\"size\":1}]},\"enums\":{\"PowerMode\":{\"type\":\"unsigned\",\"size\":1,\"values\":{\"Off\":0}}},\"arrays\":{\"VehicleStateArray\":{\"type\":\"array\",\"fixed_len\":10,\"element_type\":\"V\"}}}}"
  let d2 = parse_idl(idl2)
  match d2.interfaces[0].input[0] {
    @codec.CArray(elem, Some(10), None) =>
      match elem {
        @codec.CStruct(fields) => assert_eq(fields.length(), 1)
        _ => fail("expect struct element")
      }
    _ => fail("expect CArray(fixed=10)")
  }
  // output = enum → 底层 unsigned(1)（§11.1 enum 线格式 = 底层整型）
  match d2.interfaces[0].output {
    Some(t) => assert_eq(t, @codec.CUnsigned(1))
    None => fail("expect output")
  }
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
