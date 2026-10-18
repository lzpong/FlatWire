// ============================================================
// errors.js —— §12 错误码（两层两码）+ 内部错误类型
//
// 两层两码（§12.1）：
//  - 帧级：max_payload_len 超限（仅 UDP）→ RST(0x23)
//  - IDL 级：max_payload / max_len / fixed_len / SizeMismatch 等契约违约 → RST(0x20)
// ============================================================

// ---- RST 错误码总表（§12.1 / §12.2） ----
export const RST_CODE = Object.freeze({
  PROTOCOL_VIOLATION: 0x00,   // 协议违规（帧头一致性校验失败）
  BAD_REQUEST: 0x20,          // Bad Request（Payload 与契约不符 / IDL 级校验失败 / CRC 失败 / 控制帧格式错误）
  UNSUPPORTED_VERSION: 0x22,  // VER 与本端不一致
  PAYLOAD_TOO_LARGE: 0x23,    // Payload 超过 max_payload_len（仅 UDP，帧级）
  NOT_FOUND: 0x24,            // SvcID/IfID 无对应处理者 / SD Not Found
  METHOD_NOT_ALLOWED: 0x25,   // Code 不支持
  FRAME_TIMEOUT: 0x26,        // TCP 半帧超时（当前帧作废，请机械发完剩余字节）
  INTERNAL_ERROR: 0x30,       // 处理逻辑执行异常
  NOT_IMPLEMENTED: 0x31,      // 请求的接口功能未实现
  SERVICE_UNAVAILABLE: 0x33,  // 服务临时不可用
});

// 错误码名称表（§12.4 日志 Msg 字段取此名称）
export const RST_NAME = Object.freeze({
  0x00: 'Protocol Violation',
  0x20: 'Bad Request',
  0x21: 'Reserved',
  0x22: 'Unsupported Version',
  0x23: 'Payload Too Large',
  0x24: 'Not Found',
  0x25: 'Method Not Allowed',
  0x26: 'Frame Timeout',
  0x30: 'Internal Error',
  0x31: 'Not Implemented',
  0x33: 'Service Unavailable',
});

// ---- 解码错误（§9.4，IDL 级契约违约统一归 RST(0x20)） ----
export class DecodeError extends Error {
  constructor(msg) { super(msg); this.name = this.constructor.name; }
}
// bool 字段头 low4 ∉ {0,1}（§9.1）
export class InvalidBoolEncoding extends DecodeError { }
// signed 字段头 low4=0（恒定宽度下不可达，§9.1）
export class InvalidSignedLength extends DecodeError { }
// unsigned 字段头 low4=0（同上）
export class InvalidUnsignedLength extends DecodeError { }
// signed/unsigned 线上宽度 ≠ IDL size（§9.2 恒定宽度校验位）
export class SizeMismatch extends DecodeError { }
// 非 optional 字段编码为 null（§9.1/§9.2）
export class UnexpectedNull extends DecodeError { }
// 字段类型 0x9~0xF（未定义类型，§9.4；新增类型 = Major 不兼容变更）
export class UnknownFieldType extends DecodeError { }
// float 子类型非法或 80bit 扩展不支持（§9.1）
export class UnsupportedFloatType extends DecodeError { }
// 编码缓冲不足（数据被截断）
export class BufferUnderrun extends DecodeError { }
// 字段级 max_len / 接口级 max_payload 超限（IDL 级，归 0x20）
export class MaxLenExceeded extends DecodeError { }
// fixed_len 定长不符（IDL 级，归 0x20）
export class FixedLenMismatch extends DecodeError { }
// CRC-16 校验失败（§9.6，归 0x20）
export class CrcMismatch extends DecodeError { }
// 编码值超出字段位宽范围
export class ValueRangeExceeded extends DecodeError { }

// ---- 应用/协议栈错误（上抛应用层） ----
export class FwError extends Error {
  /** @param rstCode 对应的 RST 错误码（0 表示非 RST 场景） */
  constructor(msg, rstCode = 0) {
    super(msg);
    this.name = this.constructor.name;
    this.rstCode = rstCode;
  }
}
// 应用层响应超时（§1.3：调用的唯一终态判定）
export class RequestTimeout extends FwError { }
// 服务/实例未发现或不可用（对应 0x24）
export class ServiceNotFound extends FwError {
  constructor(msg = 'service not found or offline') { super(msg, RST_CODE.NOT_FOUND); }
}
// 服务已注册 / 参数错误
export class InvalidArgument extends FwError { }
// IDL 未就绪（本地库缺失且无法自动拉取）
export class IdlUnavailable extends FwError { }
// GetIDL 查询失败（0x24/0x20/超时/连接断开）
export class GetIdlError extends FwError { }
