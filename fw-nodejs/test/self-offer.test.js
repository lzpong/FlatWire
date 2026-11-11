// ============================================================
// self-offer.test.js —— Test Cases §5.38 / Design §7.2
//
// 自身 Offer 必须跳过（MUST）。这里用**真实 start + register_service 形态**
// 覆盖"Find 单播应答 → client socket"这条链路，而不是只观测传输层：
//   client 发启动 Find（源 = bind:clientPort，目的 = 组播:port）
//   → main 收到并匹配本地实例 → 单播 Offer 回 bind:clientPort（源端口 = port）
//   → client 收到（源端口 ≠ clientPort，传输层过滤不命中）
//   → SD 入口按 (源地址, 源端口) == (bind_address, port) 整帧剔除
// 传输层那条"源地址 ∈ 本 socket 地址集 且 源端口 == 本 socket 端口"只拦
// main 的组播自回环，对单播应答天然不命中，两层各管一条路径。
// ============================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { FwStack } from '../src/stack.js';
import { CODE } from '../src/frame/frame.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** 轮询等待条件成立（超时抛错） */
async function waitFor(fn, timeout = 5000, step = 60) {
  const t0 = Date.now();
  for (;;) {
    if (fn()) return;
    if (Date.now() - t0 > timeout) throw new Error(`waitFor timeout (${timeout}ms)`);
    await sleep(step);
  }
}

const SVC_ID = 4096;

const TEST_IDL = {
  type_def: {
    structs: {
      ReqIn: [{ name: 'a', type: 'u16' }],
      SumOut: [{ name: 'sum', type: 'u32' }],
    },
  },
  service: {
    svc_id: SVC_ID, major_ver: 1, minor_ver: 0, name: 'SelfOfferSvc',
    interfaces: [{ if_id: 1, type: 'rpc', transport: 'udp', input: ['ReqIn'], output: 'SumOut' }],
  },
};

const HANDLERS = { on_request: () => ({ sum: 0 }), on_fire_forget: () => {} };

/**
 * 观测单栈：client socket 收到的 Offer（源端口 == 本栈 port 即自身单播应答）。
 * 返回 { selfOffers, findSends }：selfOffers 为真实到达 client 的自身 Offer，
 * findSends 为 client 侧发出的 Find 帧计数（用于识别周期性自问自答）。
 */
function instrument(stack) {
  const port = stack.cfg.port;
  const selfOffers = [];
  stack.udp.on('frame', (frame, meta) => {
    // 只关心 client socket 收到的控制帧 Offer（启动 Find 的单播应答落点）
    if (meta.socket === 'client' && frame.ctr === 1 && frame.code === CODE.SD_OFFER && meta.port === port) {
      selfOffers.push({ address: meta.address, port: meta.port });
    }
  });
  const orig = stack.udp.sendMulticast.bind(stack.udp);
  let findSends = 0;
  stack.udp.sendMulticast = (buf, which = 'main') => {
    if (which === 'client' && (buf[1] & 0x3f) === CODE.SD_FIND) findSends++;
    return orig(buf, which);
  };
  return { selfOffers, getFindSends: () => findSends };
}

// ============================================================
// §5.38 单栈：启动 Find 的单播应答不得把本栈自己录成远端实例
// ============================================================
test('5.38(Node) 单栈 start+register：单播应答被 SD 入口剔除，发现缓存无自身', async () => {
  const PORT = 45470;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-self-'));
  const stack = new FwStack({
    port: PORT,
    bind_address: '127.0.0.1',
    multicast_interface: '127.0.0.1',
    period_ms: 200,
    ttl_ms: 1000, // ttl >= 2*period；且 TTL 字段按秒取整，必须 >=1000 才不会退化成 TTL=0
    log_level: 'error',
    idl_dir: dir,
  });
  const probe = instrument(stack); // 必须在 start 前插桩（启动 Find 也要计数）

  try {
    await stack.start();
    await stack.register_service(SVC_ID, 1, TEST_IDL, HANDLERS);

    // 先跑若干周期 Offer（组播到 main，由传输层过滤），缓存应保持为空
    await sleep(400);
    assert.equal(stack.discovery.discovered.size, 0, 'periodic Offer must not create self entry');

    // 发起发现（等价客户端 Find）：main 匹配本地实例后单播应答回 client 临时端口。
    // 修复前这里会立即命中自身条目直接返回；修复后应答被 SD 入口剔除 → 超时。
    for (let i = 0; i < 3; i++) {
      await assert.rejects(
        stack.find_service(SVC_ID, 1, 150),
        /timeout/,
        `round ${i}: find_service(self) must time out (no remote provider)`,
      );
      assert.equal(stack.discovery.discovered.size, 0, `round ${i}: discovered still empty`);
    }

    // ① 链路确实被触发：client socket 收到了源端口 == 本栈 port 的 Offer（自身单播应答）
    assert.ok(probe.selfOffers.length >= 1,
      `expected self unicast Offer on client socket, got ${probe.selfOffers.length}`);
    // ② SD 入口整帧剔除：发现缓存为空、对自己不可用（修复前这里会是 1 和 true）
    assert.equal(stack.discovery.discovered.size, 0, 'discovered must not contain self instance');
    assert.equal(stack.is_available(SVC_ID, 1), false, 'is_available(self) must be false');
    // ③ 没有额外的内部周期 Find：client 侧 Find 仅 = 启动预热 1 次 + 显式 3 次
    assert.equal(probe.getFindSends(), 4, `client Find sends = 1(start) + 3(explicit), got ${probe.getFindSends()}`);
  } finally {
    await stack.stop().catch(() => {});
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================
// §5.38 双栈：远端 Offer 不被误杀（判据只针对本栈 (bind, port)）
// ============================================================
test('5.38(Node) 双栈：远端 Offer 照常入库，仅剔除自身来源', async () => {
  const PORT = 45471;
  const dirA = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-self-a-'));
  const dirB = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-self-b-'));
  const base = { port: PORT, period_ms: 200, ttl_ms: 1000, log_level: 'error' };
  const a = new FwStack({ ...base, bind_address: '127.0.0.1', multicast_interface: '127.0.0.1', idl_dir: dirA });
  const b = new FwStack({ ...base, bind_address: '127.0.0.2', multicast_interface: '127.0.0.2', idl_dir: dirB, tcp_enabled: false });

  try {
    await a.start();
    await a.register_service(SVC_ID, 1, TEST_IDL, HANDLERS);
    await b.start();

    // B 通过 A 的组播 Offer / Find 单播应答发现 A（远端来源，判据不命中）
    await waitFor(() => b.is_available(SVC_ID, 1), 6000);
    assert.equal(b.is_available(SVC_ID, 1), true);

    // B 的发现缓存中不得出现自身来源 (127.0.0.2, PORT)
    const selfEntries = [...b.discovery.discovered.values()]
      .filter((r) => r.addr.address === '127.0.0.2' && r.addr.port === PORT);
    assert.equal(selfEntries.length, 0, 'B must not cache its own Offer source');
    // A 发现的记录是 B 的地址/端口（远端单播应答来源），证明剔除没有误伤远端
    const rec = b.discovery.discovered.get(`${SVC_ID}:1`);
    assert.ok(rec, 'A instance must be discovered by B');
    assert.equal(rec.addr.address, '127.0.0.1');
    assert.equal(rec.addr.port, PORT);
  } finally {
    await b.stop().catch(() => {});
    await a.stop().catch(() => {});
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  }
});
