// strm 包测试：§6 StrmID 分配 / 回绕 / 跳过活跃 / 冷却 / REN 清除 / 控制帧统一池

/// 测试辅助：必须分配成功
fn must_alloc_client(pool : DataStrmPool, peer : String, svc : Int, inst : Int) -> Int raise {
  match pool.alloc_client(peer, svc, inst) {
    Some(v) => v
    None => fail("client alloc failed")
  }
}

/// 客户端流顺序分配 + 回绕 + 空间耗尽（§6.1：0x01~0x7F 共 127 个）
test "client stream alloc wraps and exhausts" {
  let pool = DataStrmPool::new()
  let peer = "192.168.1.10"
  // 顺序分配 0x01~0x7F
  for i in 0..<127 {
    assert_eq(must_alloc_client(pool, peer, 1, 1), i + 1)
  }
  // 全活跃 → 耗尽返回 None（§6.1 空间 127 个）
  assert_eq(pool.alloc_client(peer, 1, 1), None)
  // 释放 0x05 后再分配：唯一空闲位 = 0x05（其余仍活跃，§6.3"目标仍活跃时跳过"）
  pool.release(peer, 1, 1, 5)
  assert_eq(must_alloc_client(pool, peer, 1, 1), 5)
}

/// 目标 StrmID 活跃时跳过（§6.3）
test "alloc skips active strm" {
  let pool = DataStrmPool::new()
  let peer = "n1"
  let s1 = must_alloc_client(pool, peer, 1, 1)
  let s2 = must_alloc_client(pool, peer, 1, 1)
  // 两个分配不重复
  assert_false(s1 == s2)
}

/// 冷却语义（§6.3：距上次释放 ≥2 次其它分配才优先复用；游标顺序下新号优先）
test "cooldown before reuse" {
  let pool = DataStrmPool::new()
  let peer = "n1"
  // 分配 1 并释放 → 立即分配：1 未冷却（0 次间隔）→ 得 2
  let s1 = must_alloc_client(pool, peer, 1, 1)
  assert_eq(s1, 1)
  pool.release(peer, 1, 1, s1)
  assert_eq(must_alloc_client(pool, peer, 1, 1), 2)
  pool.release(peer, 1, 1, 2)
  // 1 已隔 1 次分配仍未冷却 → 得 3
  assert_eq(must_alloc_client(pool, peer, 1, 1), 3)
  pool.release(peer, 1, 1, 3)
  // 1 已隔 2 次达到冷却阈值；但游标处新号 4 从未释放同样视为冷却 → 游标优先得 4
  assert_eq(must_alloc_client(pool, peer, 1, 1), 4)
  pool.release(peer, 1, 1, 4)
  // 耗尽新号 5..127（游标回绕至 0）；1/2/3/4 早已冷却 → pass1 依次复用
  for _i in 0..<123 {
    let _ = must_alloc_client(pool, peer, 1, 1)
  }
  assert_eq(must_alloc_client(pool, peer, 1, 1), 1)
  assert_eq(must_alloc_client(pool, peer, 1, 1), 2)
  assert_eq(must_alloc_client(pool, peer, 1, 1), 3)
  assert_eq(must_alloc_client(pool, peer, 1, 1), 4)
}

/// 服务端流独立空间（0x80~0xFE，§6.1）
test "server stream independent space" {
  let pool = DataStrmPool::new()
  let peer = "n1"
  // client 分配不影响 server 空间
  let _ = pool.alloc_client(peer, 1, 1)
  match pool.alloc_server(peer, 1, 1) {
    Some(v) => assert_eq(v, 0x80)
    None => fail("server alloc failed")
  }
  // server 连续分配递增
  match pool.alloc_server(peer, 1, 1) {
    Some(v) => assert_eq(v, 0x81)
    None => fail("server alloc 2 failed")
  }
  // server 释放后冷却复用逻辑同 client（立即重分配走第二遍扫描）
  pool.release(peer, 1, 1, 0x80)
  match pool.alloc_server(peer, 1, 1) {
    Some(v) => assert_eq(v, 0x82) // 0x80 未冷却，跳过
    None => fail("server alloc 3 failed")
  }
}

/// 释放幂等：未活跃 StrmID 释放无副作用
test "release idempotent" {
  let pool = DataStrmPool::new()
  pool.release("n1", 1, 1, 0x01) // 组不存在
  let _ = pool.alloc_client("n1", 1, 1)
  pool.release("n1", 1, 1, 0x02) // 未活跃
  pool.release("n1", 1, 1, 0x01) // 正常释放
  pool.release("n1", 1, 1, 0x01) // 重复释放
}

/// REN 清除该对端全部序列并重置游标（§3.6/§6.3）
test "clear_peer on ren (6.3)" {
  let pool = DataStrmPool::new()
  let a = "10.0.0.1"
  let b = "10.0.0.2"
  let _ = pool.alloc_client(a, 1, 1)
  let _ = pool.alloc_client(a, 1, 2)
  let _ = pool.alloc_server(a, 1, 1)
  let _ = pool.alloc_client(b, 1, 1)
  let cleared = pool.clear_peer(a)
  // 仅清除对端 a：3 条（client×2 + server×1）
  assert_eq(cleared.length(), 3)
  // a 的空间已清空：重新分配从头开始
  match pool.alloc_client(a, 1, 1) {
    Some(v) => assert_eq(v, 0x01)
    None => fail("realloc after ren failed")
  }
  // 对端 b 不受影响（其活跃流仍占用）
  match pool.alloc_client(b, 1, 1) {
    Some(v) => assert_eq(v, 0x02)
    None => fail("peer b should keep its sequence")
  }
}

/// 控制帧统一池：分配 / 回绕 / 耗尽（§6.1/§6.3：订阅会话 + GetIDL 查询共用 0x01~0x7F）
test "ctrl pool alloc and exhaust" {
  let pool = CtrlStrmPool::new()
  let peer = "n1"
  for i in 0..<127 {
    match pool.alloc(peer) {
      Some(v) => assert_eq(v, i + 1)
      None => fail("ctrl alloc failed at \{i}")
    }
  }
  assert_eq(pool.alloc(peer), None)
  // 释放后可复用
  pool.release(peer, 10)
  match pool.alloc(peer) {
    Some(v) => assert_eq(v, 10)
    None => fail("ctrl realloc failed")
  }
}

/// 控制帧池冷却：释放后立即分配不复用刚释放的号（防迟到 0x11 误配，§6.1/§6.3）
test "ctrl pool cooldown" {
  let pool = CtrlStrmPool::new()
  let peer = "n1"
  let s1 = match pool.alloc(peer) {
    Some(v) => v
    None => fail("ctrl alloc s1 failed")
  }
  assert_eq(s1, 1)
  pool.release(peer, s1)
  // 立即分配：s1 未冷却 → 得 s2
  match pool.alloc(peer) {
    Some(v) => assert_eq(v, 2)
    None => fail("ctrl alloc s2 failed")
  }
}

/// 控制帧池按 peer 隔离 + REN/断连清除（§6.3）
test "ctrl pool peer isolation and clear" {
  let pool = CtrlStrmPool::new()
  let _ = pool.alloc("n1")
  let _ = pool.alloc("n2")
  // n1 的 1 号已占用 → n1 下一个是 2；n2 下一个也是 2（各 peer 独立池）
  match pool.alloc("n1") {
    Some(v) => assert_eq(v, 2)
    None => fail("n1 alloc failed")
  }
  match pool.alloc("n2") {
    Some(v) => assert_eq(v, 2)
    None => fail("n2 alloc failed")
  }
  // 清除 n1 后重新分配从头开始
  pool.clear_peer("n1")
  match pool.alloc("n1") {
    Some(v) => assert_eq(v, 1)
    None => fail("n1 realloc after clear failed")
  }
}

/// 数据帧池与控制帧池相互独立（§3.5/§6.3：键空间天然不相交，编号可复用）
test "data and ctrl pools independent" {
  let dp = DataStrmPool::new()
  let cp = CtrlStrmPool::new()
  let peer = "n1"
  let _ = dp.alloc_client(peer, 1, 1)
  // 控制帧池不受数据帧池影响：同样从 0x01 开始
  match cp.alloc(peer) {
    Some(v) => assert_eq(v, 1)
    None => fail("ctrl alloc failed")
  }
  // 数据帧池不受控制帧池释放影响
  cp.release(peer, 1)
  match dp.alloc_client(peer, 1, 1) {
    Some(v) => assert_eq(v, 2)
    None => fail("data alloc failed")
  }
}
