// §11.1 / §7.2 IDL 库：本地文件夹加载 / 按 (SvcID, MajorVer) 组织 / 拉取落盘持久化
//
// - 启动加载：解析失败的文件跳过并记 Error 日志，不阻塞其他服务加载（启动健壮性）
// - 多版本并存：同 SvcID 跨 MajorVer 定义并存不覆盖（版本升级重新拉取场景，§7.2）
// - 拉取落盘：put 先内存后落盘；落盘失败降级为仅内存加载并记 Error 日志（可用性优先）
// - GetIDL 响应体：raw 原始 JSON 文本直传（§7.2 无前缀、UTF-8）

/// IDL 库（dir = 本地文件夹路径，实现约定：文件命名 "\{svc_id}_v\{major_ver}.json"）
pub struct IdlStore {
  dir : String
  priv defs : Map[Int, Map[Int, IdlDef]] // svc_id → (major_ver → 定义)
}

/// 创建 IDL 库（不加载；load_all 启动时调用）
pub fn IdlStore::new(dir : String) -> IdlStore {
  { dir, defs: Map([], capacity=8) }
}

/// 启动加载：readdir → 逐文件读取解析；失败跳过记 Error（§11.1 启动健壮性）
pub fn IdlStore::load_all(self : IdlStore) -> Int {
  let listing = ffi_fs_readdir(self.dir)
  let names : Array[String] = []
  // 目录清单为 JSON 数组文本；解析失败视为空目录（目录不存在的 FFI 路径已回 "[]"）
  try {
    match @json.parse(listing) {
      Array(items) =>
        for it in items {
          match it {
            String(s) => names.push(s)
            _ => ()
          }
        }
      _ => ()
    }
  } catch {
    _ => ()
  }
  let mut loaded = 0
  for name in names {
    // 同步读取：on_ok/on_err 在 FFI 内同步回调，借 box 取回结果
    let box : Array[String] = []
    ffi_fs_read_file(self.dir, name, fn(s) { box.push(s) }, fn(msg) {
      ffi_log_error("[idlstore] 读取文件失败: file=\{name} err=\{msg}")
    })
    if box.length() != 1 {
      continue
    }
    // 解析失败：跳过该文件不阻塞其他服务加载（§11.1）；本地文件视为已校验内容
    let r : Result[IdlDef, IdlError] = try { Ok(parse_idl(box[0])) } catch { e => Err(e) }
    match r {
      Ok(def) => {
        self.insert(def)
        loaded = loaded + 1
      }
      Err(err) =>
        ffi_log_error("[idlstore] IDL 解析失败，跳过文件: file=\{name} err=\{Repr(err)}")
    }
  }
  loaded
}

/// 查询指定 (SvcID, MajorVer) 的已加载定义（§7.2 GetIDL 服务端匹配 = 库中已加载定义，与实例在线无关）
pub fn IdlStore::get(self : IdlStore, svc_id : Int, major_ver : Int) -> IdlDef? {
  match self.defs.get(svc_id) {
    Some(by_major) => by_major.get(major_ver)
    None => None
  }
}

/// 查询某 SvcID 任一已加载版本（建议最高版本；§7.2 注册拉取部署异常场景取任一）
pub fn IdlStore::get_any(self : IdlStore, svc_id : Int) -> IdlDef? {
  match self.defs.get(svc_id) {
    Some(by_major) => {
      let mut best : IdlDef? = None
      for _major, def in by_major {
        match best {
          Some(b) => if def.major_ver > b.major_ver {
            best = Some(def)
          }
          None => best = Some(def)
        }
      }
      best
    }
    None => None
  }
}

/// 判定 (SvcID, MajorVer) 定义是否在库（§7.2 触发条件判定）
pub fn IdlStore::has(self : IdlStore, svc_id : Int, major_ver : Int) -> Bool {
  self.get(svc_id, major_ver) is Some(_)
}

/// 取 GetIDL 响应体（§7.2：Payload = 完整 IDL JSON 全文）
pub fn IdlStore::raw(self : IdlStore, svc_id : Int, major_ver : Int) -> String? {
  match self.get(svc_id, major_ver) {
    Some(def) => Some(def.raw)
    None => None
  }
}

/// 写入定义：内存插入 + 落盘持久化（§7.2 协议要求）
/// 返回 true=内存就绪（落盘失败也返回 true——降级为仅内存，§7.2 落盘失败降级）
pub fn IdlStore::put(self : IdlStore, def : IdlDef) -> Bool {
  self.insert(def)
  let name = "\{def.svc_id}_v\{def.major_ver}.json"
  let ok = ffi_fs_write_file(self.dir, name, def.raw)
  if !ok {
    // §7.2：落盘失败降级为仅内存加载使用并记 Error 日志（重启后需重新拉取）
    ffi_log_error("[idlstore] IDL 落盘失败，降级内存加载: svc=\{def.svc_id} major=\{def.major_ver}")
  }
  true
}

/// 仅内存插入（多版本并存不覆盖，§7.2）
fn IdlStore::insert(self : IdlStore, def : IdlDef) -> Unit {
  match self.defs.get(def.svc_id) {
    Some(by_major) => by_major[def.major_ver] = def
    None => {
      let by_major : Map[Int, IdlDef] = Map([], capacity=4)
      by_major[def.major_ver] = def
      self.defs[def.svc_id] = by_major
    }
  }
}
