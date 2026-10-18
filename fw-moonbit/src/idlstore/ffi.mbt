// §11.1 IDL 库文件系统 FFI（Node.js fs，仅 js target）
//
// - 同步 fs 调用（readFileSync/writeFileSync）：IDL 库操作为低频路径（启动加载 / 拉取落盘），
//   同步语义换取解析流程的直线性
// - readdir 返回 JSON 数组文本（extern "js" 边界仅传基础类型，数组经 JSON 序列化）
// - 调用约定注解（函数级属性行，参数名引用）：同步消费的 String → #borrow；
//   JS 异步持有的回调闭包 → #owned

/// 列出 IDL 库文件夹内的 .json 文件名（JSON 数组文本；目录不存在/读取失败 → "[]"）
#borrow(dir)
extern "js" fn ffi_fs_readdir(dir : String) -> String =
  "(dir) => { try { return JSON.stringify(require('node:fs').readdirSync(dir).filter(n => n.endsWith('.json'))); } catch (e) { return '[]'; } }"

/// 读取文本文件（同步执行；成功 on_ok(内容)，失败 on_err(消息)；回调长期持有 → owned）
#borrow(dir, name)
#owned(on_ok, on_err)
extern "js" fn ffi_fs_read_file(
  dir : String,
  name : String,
  on_ok : (String) -> Unit,
  on_err : (String) -> Unit
) -> Unit =
  "(dir, name, on_ok, on_err) => { try { on_ok(require('node:fs').readFileSync(dir + '/' + name, 'utf8')); } catch (e) { on_err(String(e && e.message ? e.message : e)); } }"

/// 写文本文件（同步；必要时递归建目录；成功 true / 失败 false——§7.2 落盘失败降级内存的判定依据）
#borrow(dir, name, content)
extern "js" fn ffi_fs_write_file(dir : String, name : String, content : String) -> Bool =
  "(dir, name, content) => { try { const fs = require('node:fs'); fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(dir + '/' + name, content, 'utf8'); return true; } catch (e) { return false; } }"

/// Error 级日志输出（§11.1 加载失败/落盘失败降级等错误场景；msg 同步消费 → borrow）
#borrow(msg)
extern "js" fn ffi_log_error(msg : String) -> Unit =
  "(msg) => { console.error(msg); }"
