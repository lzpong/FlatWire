/// §12 错误处理与恢复 —— 错误码总表（§12.1）与应用层错误类型
///
/// 两层两码原则（v4.2 定案）：
/// - 帧级超限（max_payload_len，仅 UDP）→ 0x23
/// - IDL 级契约违约（max_payload/max_len/fixed_len/SizeMismatch/UnexpectedNull）→ 0x20
/// - 服务不存在 → 0x24；处理异常 → 0x30

// §12.1 错误码常量
pub const RST_OK : Int = 0x00 // 协议违规（TYP=RST 时 Code=0x00）
pub const RST_BAD_REQUEST : Int = 0x20 // IDL 级契约违约 / 格式错误
pub const RST_UNSUPPORTED_VERSION : Int = 0x22 // VER 不一致
pub const RST_PAYLOAD_TOO_LARGE : Int = 0x23 // 帧级超限（仅 UDP）
pub const RST_NOT_FOUND : Int = 0x24 // 服务/接口/IDL 定义不存在
pub const RST_METHOD_NOT_ALLOWED : Int = 0x25 // 不支持的操作码
pub const RST_FRAME_TIMEOUT : Int = 0x26 // TCP 半帧超时（§4.1 两阶段）
pub const RST_INTERNAL_ERROR : Int = 0x30 // 处理逻辑执行异常
pub const RST_NOT_IMPLEMENTED : Int = 0x31
pub const RST_SERVICE_UNAVAILABLE : Int = 0x33

/// RST Code 合法范围校验（§4.3 步骤 2）：Code ∈ {0x00} ∪ 0x20~0x3F
pub fn is_valid_rst_code(code : Int) -> Bool {
  code == 0x00 || (code >= 0x20 && code <= 0x3F)
}

/// 应用层可见的协议栈错误（本地产生；对端错误以 Remote(code) 传递）
pub(all) enum FwError {
  /// §5.1 应用层响应超时（唯一终态判定）
  RequestTimeout
  /// 对端回 RST，携带 §12.1 错误码
  Remote(Int)
  /// 服务不可用（发现缓存无在线实例 / 实例过期）
  NotAvailable
  /// 本地编解码失败（IDL 级契约校验）
  Codec(String)
  /// 本地无 IDL 定义且无法自动拉取（§7.2）
  IdlMissing(String)
  /// 其他本地状态错误
  Local(String)
} derive(Eq, Debug)

// v0.10 惯用法：derive 生成的方法须显式 extend 提升为常规方法（moonc 警告 0079）；
// Show 已废弃（v0.9.2 core 迁移），日志/调试输出统一走 Debug（插值中用 Repr 包装）
pub extend FwError with Eq::{not_equal, equal}
pub extend FwError with @moonbitlang/core/debug.Debug::{to_repr}

/// FwError 转人读描述（§12.4 日志 Msg 取错误码名称）
pub fn FwError::message(self : FwError) -> String {
  match self {
    RequestTimeout => "Request Timeout"
    Remote(code) =>
      match code {
        0x00 => "Protocol Violation"
        0x20 => "Bad Request"
        0x22 => "Unsupported Version"
        0x23 => "Payload Too Large"
        0x24 => "Not Found"
        0x25 => "Method Not Allowed"
        0x26 => "Frame Timeout"
        0x30 => "Internal Error"
        0x31 => "Not Implemented"
        0x33 => "Service Unavailable"
        _ => "Remote Error 0x\{code}"
      }
    NotAvailable => "Service Not Available"
    Codec(msg) => "Codec Error: \{msg}"
    IdlMissing(msg) => "IDL Missing: \{msg}"
    Local(msg) => "Local Error: \{msg}"
  }
}
