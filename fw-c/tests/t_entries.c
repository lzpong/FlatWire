// ============================================================
// t_entries.c —— 测试基准 5.5/5.6：SD Entry 编解码（§7.1）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

int suite_entries(void) {
  uint8_t buf[128];

  TEST_BEGIN("5.5 Offer Entry 6B / Find Entry 4B（无 IfID/MinorVer）");
  fw_offer_entry_t oe = {0x1000, 2, 1, 7, 4};
  CHECK_EQ_INT(fw_encode_offer_entries(buf, sizeof(buf), &oe, 1), 6);
  CHECK_EQ_INT(buf[0], 0x10); CHECK_EQ_INT(buf[1], 0x00); // SvcID 大端
  CHECK_EQ_INT(buf[2], 2); CHECK_EQ_INT(buf[3], 1); CHECK_EQ_INT(buf[4], 7); CHECK_EQ_INT(buf[5], 4); // TTL 秒
  fw_offer_entry_t od[2];
  CHECK_EQ_INT(fw_decode_offer_entries(buf, 6, od, 2), 1);
  CHECK_EQ_INT(od[0].svc_id, 0x1000);
  CHECK_EQ_INT(od[0].inst_id, 2);
  CHECK_EQ_INT(od[0].major_ver, 1);
  CHECK_EQ_INT(od[0].minor_ver, 7);
  CHECK_EQ_INT(od[0].ttl, 4);
  // Find Entry 4B（无 MinorVer：MinorVer 不参与匹配 §7.1）
  fw_find_entry_t fe = {0x1000, 0, 1};
  CHECK_EQ_INT(fw_encode_find_entries(buf, sizeof(buf), &fe, 1), 4);
  fw_find_entry_t fd[2];
  CHECK_EQ_INT(fw_decode_find_entries(buf, 4, fd, 2), 1);
  CHECK_EQ_INT(fd[0].svc_id, 0x1000);
  CHECK_EQ_INT(fd[0].inst_id, 0); // 0x00 通配
  TEST_END();

  TEST_BEGIN("5.6 Subscribe Entry 7B（含 IfID/GrpId）");
  fw_sub_entry_t se = {0x1000, 32769, 1, 0, 4};
  CHECK_EQ_INT(fw_encode_sub_entries(buf, sizeof(buf), &se, 1), 7);
  fw_sub_entry_t sd[2];
  CHECK_EQ_INT(fw_decode_sub_entries(buf, 7, sd, 2), 1);
  CHECK_EQ_INT(sd[0].svc_id, 0x1000);
  CHECK_EQ_INT(sd[0].if_id, 32769);
  CHECK_EQ_INT(sd[0].inst_id, 1);
  CHECK_EQ_INT(sd[0].grp_id, 0);
  CHECK_EQ_INT(sd[0].ttl, 4);
  TEST_END();

  TEST_BEGIN("GetIDL Entry 3B（无 InstID；≠3B 拒绝）");
  fw_getidl_entry_t ge = {0x1000, 1};
  CHECK_EQ_INT(fw_encode_getidl_entry(buf, sizeof(buf), &ge), 3);
  fw_getidl_entry_t gd;
  CHECK_EQ_INT(fw_decode_getidl_entry(buf, 3, &gd), 1);
  CHECK_EQ_INT(gd.svc_id, 0x1000);
  CHECK_EQ_INT(gd.major_ver, 1);
  CHECK_EQ_INT(fw_decode_getidl_entry(buf, 2, &gd), 0); // <3B → RST(0x20) 场景
  CHECK_EQ_INT(fw_decode_getidl_entry(buf, 4, &gd), 0); // >3B
  TEST_END();

  TEST_BEGIN("5.11 Offer 拆帧容量（max_payload_len=1400 → 233 Entry/帧）");
  CHECK_EQ_INT(1400 / FW_ENTRY_OFFER, 233);
  TEST_END();

  return 0;
}