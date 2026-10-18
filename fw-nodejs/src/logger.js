// ============================================================
// logger.js —— 日志器
// 帧日志遵循 §12.4 格式：
//   [{Timestamp}][{level}][{svc_id:04X},{if_id:04X},{inst_id:02X}] {Tx|Rx},{addr} {strm_id:02X}, Code=0x{code:02X}, Msg={msg}
// 其余日志采用 `[模块名] 描述: 关键参数` 形式。
// ============================================================

const LEVEL_ORDER = { error: 0, warn: 1, info: 2, debug: 3 };

function pad(n, w) {
  return n.toString(16).toUpperCase().padStart(w, '0');
}

// 创建日志器；options: { level: 'error'|'warn'|'info'|'debug', out: console 类对象 }
export function createLogger(options = {}) {
  const maxLevel = LEVEL_ORDER[options.level ?? 'info'] ?? LEVEL_ORDER.info;
  const out = options.out ?? console;

  const enabled = (lv) => (LEVEL_ORDER[lv] ?? LEVEL_ORDER.info) <= maxLevel;

  const write = (lv, line) => {
    if (!enabled(lv)) return;
    const fn = lv === 'error' ? 'error' : lv === 'warn' ? 'warn' : 'log';
    out[fn](`[${new Date().toISOString()}][${lv}] ${line}`);
  };

  return {
    /** 普通模块日志：[模块名] 描述: 关键参数 */
    log(lv, module, msg) {
      write(lv, `[${module}] ${msg}`);
    },
    /** 帧日志（§12.4 格式） */
    frame(lv, f) {
      if (!enabled(lv)) return;
      const svc = f.svc_id ?? 0;
      const ifid = f.if_id ?? 0;
      const inst = f.inst_id ?? 0;
      const strm = f.strm_id ?? 0;
      const code = f.code ?? 0;
      const line =
        `[${pad(svc, 4)},${pad(ifid, 4)},${pad(inst, 2)}] ` +
        `${f.dir ?? 'Tx'},${f.addr ?? '-'} ${pad(strm, 2)}, ` +
        `Code=0x${pad(code, 2)}, Msg=${f.msg ?? ''}`;
      write(lv, line);
    },
    error(module, msg) { this.log('error', module, msg); },
    warn(module, msg) { this.log('warn', module, msg); },
    info(module, msg) { this.log('info', module, msg); },
    debug(module, msg) { this.log('debug', module, msg); },
  };
}
