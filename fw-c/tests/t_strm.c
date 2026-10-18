// ============================================================
// t_strm.c —— 测试基准 4.1/4.2：StrmID 循环/隔离（§6）
// ============================================================

#include "test_util.h"
#include "fw/fw.h"

int suite_strm(void) {
  TEST_BEGIN("4.1 StrmID 循环：单对端分配 128 次回绕 0x01");
  fw_strm_mgr_t *m = fw_strm_new();
  // 分配 127 个（0x01~0x7F 全部活跃）
  for (int i = 0; i < 127; i++) {
    int id = fw_strm_alloc_client(m, "1.1.1.1:5400", 100, 1);
    CHECK(id >= 0x01 && id <= 0x7F);
  }
  CHECK_EQ_INT(fw_strm_alloc_client(m, "1.1.1.1:5400", 100, 1), -1); // 池耗尽
  // 释放 → 冷却 → 重新分配回绕
  fw_strm_release_client(m, "1.1.1.1:5400", 100, 1, 0x01);
  CHECK_EQ_INT(fw_strm_alloc_client(m, "1.1.1.1:5400", 100, 1), 0x01);
  TEST_END();

  TEST_BEGIN("4.2 StrmID 隔离：两个对端独立分配");
  int a = fw_strm_alloc_client(m, "2.2.2.2:5400", 100, 1);
  int b = fw_strm_alloc_client(m, "3.3.3.3:5400", 100, 1);
  CHECK_EQ_INT(a, 0x01); // 各自池首
  CHECK_EQ_INT(b, 0x01);
  TEST_END();

  TEST_BEGIN("服务端流 0x80~0xFE 独立 + 控制帧同池（§6.1/§6.3）");
  int s = fw_strm_alloc_server(m, "2.2.2.2:5400", 100, 1);
  CHECK(s >= 0x80 && s <= 0xFE); // 服务端流独立编号空间
  int c1 = fw_strm_alloc_ctrl(m, "2.2.2.2:5400");
  int c2 = fw_strm_alloc_ctrl(m, "2.2.2.2:5400");
  CHECK(c1 >= 0x01 && c1 <= 0x7F);
  CHECK(c2 >= 0x01 && c2 <= 0x7F);
  CHECK(c1 != c2); // 同键内活跃唯一（§3.5）
  TEST_END();

  TEST_BEGIN("冷却语义：释放后 ≥2 次其它分配（§6.3）");
  fw_strm_mgr_t *m2 = fw_strm_new();
  // 冷却语义（§6.3）：释放后经过 ≥2 次其它分配的 StrmID 优先于未冷却的 fallback 复用
  //（fallback 恒取第一个非活跃编号，冷却优先只能在"高 id 已冷却、低 id 未冷却"时观察）
  int a1 = fw_strm_alloc_ctrl(m2, "p");
  int a2 = fw_strm_alloc_ctrl(m2, "p");
  int a3 = fw_strm_alloc_ctrl(m2, "p");
  CHECK_EQ_INT(a1, 0x01); CHECK_EQ_INT(a2, 0x02); CHECK_EQ_INT(a3, 0x03);
  fw_strm_release_ctrl(m2, "p", a2); // 0x02 进入冷却（记录释放序号）
  fw_strm_release_ctrl(m2, "p", a3); // 0x03 进入冷却（同一序号）
  int a4 = fw_strm_alloc_ctrl(m2, "p");
  CHECK_EQ_INT(a4, 0x02); // 二者均未冷却 → fallback 取第一非活跃 0x02
  fw_strm_release_ctrl(m2, "p", a4);
  int a5 = fw_strm_alloc_ctrl(m2, "p");
  CHECK_EQ_INT(a5, 0x02); // 0x02 未冷却（距释放 1 次分配）→ fallback
  fw_strm_release_ctrl(m2, "p", a5);
  int a6 = fw_strm_alloc_ctrl(m2, "p");
  CHECK_EQ_INT(a6, 0x03); // 0x03 冷却命中优先于 fallback 0x02
  fw_strm_release_ctrl(m2, "p", a6);
  // 0x02 未冷却（距释放 1 次分配，fallback 候选）；0x03 已冷却（距释放 ≥2 次分配）
  // → 冷却优先命中 0x03；再次分配时 0x03 活跃 → fallback 回 0x02
  int a7 = fw_strm_alloc_ctrl(m2, "p");
  CHECK_EQ_INT(a7, 0x02);
  fw_strm_free(m2);
  TEST_END();

  TEST_BEGIN("REN 清对端全部序列（§3.6）");
  fw_strm_reset_peer(m, "2.2.2.2:");
  int c3 = fw_strm_alloc_ctrl(m, "2.2.2.2:5400");
  CHECK_EQ_INT(c3, 0x01); // 重置后从池首重新分配
  fw_strm_free(m);
  TEST_END();

  return 0;
}