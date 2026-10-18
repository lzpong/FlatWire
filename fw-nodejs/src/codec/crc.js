// ============================================================
// crc.js —— CRC-16/CCITT-FALSE（§9.6 唯一变体）
//
// 参数（§9.6 表）：
//   poly=0x1021, init=0xFFFF, refin=false, refout=false, xorout=0x0000
//   标准校验值：CRC-16/CCITT-FALSE("123456789") = 0x29B1（实现自检用，测试 1.31）
//
// 附加规则（§9.6）：
//   - 2 字节结果大端附加于 Data Fields 末尾，计入 Payload Length
//   - 仅数据帧（CTR=0）可附加 CRC；控制帧固定不附加 CRC（§3.4）
//   - 先计算并附加 CRC，再对整体（Data + CRC）应用 MSK XOR（§10）
// ============================================================

/**
 * 计算 CRC-16/CCITT-FALSE。
 * @param {Buffer|Uint8Array} buf 输入字节
 * @returns {number} 16 位 CRC 值
 */
export function crc16(buf) {
  let crc = 0xffff; // init=0xFFFF
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i] << 8; // refin=false：高位对齐
    for (let b = 0; b < 8; b++) {
      if (crc & 0x8000) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff; // poly=0x1021
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  }
  return crc & 0xffff; // refout=false, xorout=0x0000
}

/** 自检：规范要求的 "123456789" → 0x29B1（§9.6） */
export function crc16SelfCheck() {
  return crc16(Buffer.from('123456789', 'ascii')) === 0x29b1;
}
