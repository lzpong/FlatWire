// ============================================================
// crc.c —— CRC-16/CCITT-FALSE（§9.6 唯一变体）
//
// 参数（§9.6 表）：poly=0x1021, init=0xFFFF, refin=false, refout=false, xorout=0x0000
// 标准校验值：CRC-16/CCITT-FALSE("123456789") = 0x29B1（测试 1.31）
//
// 附加规则（§9.6）：
//   - 2 字节结果大端附加于 Data Fields 末尾，计入 Payload Length
//   - 仅数据帧（CTR=0）可附加 CRC；控制帧固定不附加（§3.4 跨实现硬性约定）
//   - 先算 CRC 附加，再整体 MSK XOR（§10）；接收侧顺序相反
// ============================================================

#include "fw/fw.h"

uint16_t fw_crc16(const uint8_t *buf, size_t len) {
  uint16_t crc = 0xFFFF; // init=0xFFFF
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)((uint16_t)buf[i] << 8); // refin=false：高位对齐
    for (int b = 0; b < 8; b++) {
      if (crc & 0x8000)
        crc = (uint16_t)((crc << 1) ^ 0x1021); // poly=0x1021
      else
        crc = (uint16_t)(crc << 1);
    }
  }
  return crc; // refout=false, xorout=0x0000
}

int fw_crc16_selfcheck(void) {
  return fw_crc16((const uint8_t *)"123456789", 9) == 0x29B1;
}
