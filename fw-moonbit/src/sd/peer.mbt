// 发现缓存条目的应用侧视图（§13.2）
//
// DiscEntry 为 sd 包内部结构（priv），应用层（stack / 示例服务）需要读取
// 实例在线信息（源地址/端口/版本）时经本文件 pub 投影输出

/// 在线实例信息（find_service / call 定位结果）
pub(all) struct PeerInst {
  svc_id : Int
  inst_id : Int
  peer : String // 源 IP（Offer 源地址）
  port : Int // 源端口（= 对端 server socket 端口，单播目标）
  major_ver : Int
  minor_ver : Int
}

/// 纯缓存定位实例（call / fire_forget / subscribe 的服务端地址来源；inst_id=0 通配任一）
/// 不触发 Find——主动发现走 find_service（stack 层 send_find_all + 本方法，§13.2）
pub fn Sd::locate_instance(self : Sd, svc_id : Int, inst_id : Int) -> PeerInst? {
  match self.pick_instance(svc_id, inst_id) {
    Some(d) =>
      Some({
        svc_id: d.svc_id,
        inst_id: d.inst_id,
        peer: d.peer,
        port: d.port,
        major_ver: d.major_ver,
        minor_ver: d.minor_ver,
      })
    None => None
  }
}
