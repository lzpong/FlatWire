// ============================================================
// t_crc.c —— 测试基准 1.31 CRC 自检值 + 1.29 CRC/MSK 顺序（§9.6/§10）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

int suite_crc(void) {
  TEST_BEGIN("1.31 CRC-16/CCITT-FALSE 自检值");
  // §9.6：poly=0x1021, init=0xFFFF, refin/refout=false, xorout=0
  // 标准校验值 CRC("123456789") = 0x29B1
  CHECK_EQ_INT(fw_crc16((const uint8_t *)"123456789", 9), 0x29B1);
  CHECK_EQ_INT(fw_crc16_selfcheck(), 1);
  // 边界：空串 = init
  CHECK_EQ_INT(fw_crc16((const uint8_t *)"", 0), 0xFFFF);
  // 单字节 'A' = 0xB915（CRC-16/CCITT-FALSE 公开校验值）
  CHECK_EQ_INT(fw_crc16((const uint8_t *)"A", 1), 0xB915);
  TEST_END();

  TEST_BEGIN("1.29 CRC 附加与 MSK 顺序（先 CRC 后 XOR，解码相反）");
  // 构造数据：先算 CRC 附加（大端 2B），再整体 XOR
  uint8_t data[5] = {1, 2, 3, 4, 5};
  uint16_t crc = fw_crc16(data, 5);
  uint8_t with_crc[7] = {1, 2, 3, 4, 5, (uint8_t)(crc >> 8), (uint8_t)(crc & 0xFF)};
  uint8_t key[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  fw_mask_xor(with_crc, 7, key); // §10：整体（Data + CRC）应用 MSK XOR
  // 接收侧顺序相反：XOR 还原 → CRC 校验 → 剥离
  fw_mask_xor(with_crc, 7, key);
  CHECK_EQ_INT((with_crc[5] << 8) | with_crc[6], fw_crc16(with_crc, 5));
  CHECK_EQ_MEM(with_crc, data, 5);
  TEST_END();

  return 0;
}