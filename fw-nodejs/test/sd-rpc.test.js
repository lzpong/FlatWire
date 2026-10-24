// ============================================================
// sd-rpc.test.js —— 测试基准 §3.10~3.13 重传时间线 + §3.15/3.16 响应缓存去重
//                   + SD 发现 / 订阅确认链路 / GetIDL 拉取落盘 / 事件推送 / REN 清理
// 双栈测试使用真实回环网络（同端口组播 + B 栈 tcp_enabled=false 避免 TCP 冲突）。
// ============================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import dgram from 'node:dgram';
import { RetransmitTable } from '../src/rpc/retransmit.js';
import { FwStack } from '../src/stack.js';
import { TYP, CODE, encodeFrame, parseDatagram } from '../src/frame/frame.js';

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

// ============================================================
// §3.10~3.13 UDP CON 重传时间线（短间隔配置加速）
// ============================================================

test('3.10/3.12 重传时间线：200/600/1400 退避 + 耗尽静默停止（等比缩短）', async () => {
  const sent = []; // 每次重传的时间戳
  const t0 = Date.now();
  const rt = new RetransmitTable({ intervalMs: 50, maxRetry: 3 }); // 时间线 50/150/350，末次后 +400 清理
  rt.start('k1', Buffer.from([1]), () => sent.push(Date.now() - t0));
  await sleep(820); // 覆盖全部重传 + 静默清理窗口（350 + 50×2^3 = 750ms）
  // 首发不计入（start 约定首发已完成）；重传 3 次后静默停止（§5.5 不报错）
  assert.equal(sent.length, 3);
  assert.ok(sent[0] >= 40 && sent[0] <= 90, `retransmit#1 at ${sent[0]}ms`);
  assert.ok(sent[1] >= 140 && sent[1] <= 200, `retransmit#2 at ${sent[1]}ms`);
  assert.ok(sent[2] >= 340 && sent[2] <= 400, `retransmit#3 at ${sent[2]}ms`);
  assert.equal(rt.has('k1'), false); // 耗尽后清理，无悬挂定时器
});

test('3.11 收到 ACK/响应取消重传', async () => {
  const sent = [];
  const rt = new RetransmitTable({ intervalMs: 50, maxRetry: 3 });
  rt.start('k', Buffer.from([1]), () => sent.push(1));
  await sleep(80); // 首次重传已发生
  assert.ok(rt.cancel('k'));
  await sleep(150);
  assert.equal(sent.length, 1); // 取消后不再重传
  assert.equal(rt.has('k'), false);
});

test('3.13 REN 清空该对端重传记录（前缀过滤）', () => {
  const rt = new RetransmitTable({ intervalMs: 50, maxRetry: 3 });
  const noop = () => {};
  rt.start('10.0.0.1:100|1|1|5', Buffer.alloc(1), noop);
  rt.start('10.0.0.1:100|1|1|6', Buffer.alloc(1), noop);
  rt.start('10.0.0.2:200|1|1|7', Buffer.alloc(1), noop);
  rt.clearPeer('10.0.0.1:');
  assert.equal(rt.has('10.0.0.1:100|1|1|5'), false);
  assert.equal(rt.has('10.0.0.1:100|1|1|6'), false);
  assert.equal(rt.has('10.0.0.2:200|1|1|7'), true); // 其它对端不受影响
  rt.clearPeer('');
  assert.equal(rt.size, 0);
});

// ============================================================
// 双栈集成（真实回环）：A 注册服务（rpc/ff/event），B 空 IDL 库起步
// ============================================================

// 测试服务 IDL（v5 §11.1 语法：interfaces.input/output 引用 type_def 类型名；
// 类型独立化为 u16/i16；string 必须声明 fixed_len 或 max_len）
const SVC_ID = 4096;
const TEST_IDL = {
  // type_def 与 service 平级（§11.1 顶层语法）
  type_def: {
    structs: {
      ReqIn:  [{ name: 'a', type: 'u16' }, { name: 'b', type: 'u16' }],
      SumOut: [{ name: 'sum', type: 'u32' }],
      FfIn:   [{ name: 'note', type: 'string', max_len: 64 }],
      EvIn:   [{ name: 'temp', type: 'i16' }],
    },
  },
  service: {
    svc_id: SVC_ID, major_ver: 1, minor_ver: 0, name: 'TestSvc',
    interfaces: [
      { if_id: 1, type: 'rpc',   transport: 'udp', input: ['ReqIn'], output: 'SumOut' },
      { if_id: 2, type: 'ff',    transport: 'udp', input: ['FfIn'], output: null },
      { if_id: 3, type: 'event', transport: 'udp', reliable: false, output: 'EvIn' }, // 事件 payload 定义在 output（§11.1）
    ],
  },
};

const PORT = 45410; // 双栈共用 UDP/组播端口（组播投递到固定端口；TCP 仅 A 监听）；45400 留给 transport.test.js 并行运行
// 同机双栈模拟两台主机：各自绑定不同 loopback IP（127/8 全回环），避免 Windows
// 对同端口 UDP 单播的投递竞争（A/B main 同 bind 45400 时单播会被对端抢收）
const CFG = { port: PORT, period_ms: 500, ttl_ms: 2000, log_level: 'error' };
const CFG_A = { ...CFG, bind_address: '127.0.0.1', multicast_interface: '127.0.0.1' };
const CFG_B = { ...CFG, bind_address: '127.0.0.2', multicast_interface: '127.0.0.2' };

let stackA, stackB, dirA, dirB;
const counts = { rpc: 0, ff: 0 };

test('setup：双栈启动 + A 注册服务', async (t) => {
  dirA = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-a-'));
  dirB = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-b-'));
  stackA = new FwStack({ ...CFG_A, idl_dir: dirA });
  await stackA.start();
  await stackA.register_service(SVC_ID, 1, TEST_IDL, {
    on_request: (ifId, payload) => { counts.rpc++; return { sum: payload.a + payload.b }; },
    on_fire_forget: (ifId, payload) => { counts.ff++; },
  });
  // B：空 IDL 库 + 无 TCP 监听（客户端角色：GetIDL 走出站连接）
  stackB = new FwStack({ ...CFG_B, idl_dir: dirB, tcp_enabled: false });
  await stackB.start();
  // 发现链路：B 通过组播 Offer / Find 预热得知 A 的实例（§7.2/§7.3）
  await waitFor(() => stackB.is_available(SVC_ID, 1));
  assert.equal(stackB.is_available(SVC_ID, 1), true);
  const info = await stackB.find_service(SVC_ID, 1);
  assert.equal(info.address, '127.0.0.1');
  assert.equal(info.port, PORT);
  assert.equal(info.major_ver, 1);
  // t.cleanup 同时清理临时目录（栈在下方专门测试中停止）
  t.after(() => {
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  });
});

test('3.15/5.21 B 空 IDL 库：call 触发 GetIDL 拉取落盘 + 调用往返', async () => {
  assert.ok(!stackB.idlStore.getHighest(SVC_ID)); // 前置：B 库为空（5.28 本地命中不查询）
  const ret = await stackB.call(SVC_ID, 1, 1, { a: 2, b: 3 }); // 内部自动 GetIDL（§7.2）
  assert.deepEqual(ret, { sum: 5 });
  // 落盘持久化（§7.2）：库内有定义 + IDL 目录出现文件
  assert.ok(stackB.idlStore.has(SVC_ID, 1));
  assert.ok(fs.readdirSync(dirB).length >= 1, 'IDL json persisted to disk');
  assert.equal(counts.rpc, 1);
});

test('3.16 响应缓存去重：重复 CON 请求只执行一次处理逻辑', async () => {
  // 用独立原始 socket 模拟客户端重传：同一 CON 帧发两次，服务端仅执行 1 次 handler
  const schema = stackB.idlStore.getHighest(SVC_ID).schema;
  const iface = schema.getInterface(1);
  const body = schema.encodePayload(iface, 'input', { a: 9, b: 1 });
  const req = encodeFrame({
    ctr: 0, typ: TYP.CON, code: CODE.REQUEST,
    svc_id: SVC_ID, if_id: 1, inst_id: 1, strm_id: 0x55, payload: body,
  });
  const sock = dgram.createSocket('udp4');
  await new Promise((r) => sock.bind(0, r));
  const rx = [];
  sock.on('message', (buf) => {
    const r = parseDatagram(buf, { ver: 0, isUdp: true });
    if (r.ok) rx.push(r.frame);
  });
  try {
    sock.send(req, PORT, '127.0.0.1'); // 首发CON
    await sleep(320);                  // 收 ACK + Response（Response 200ms 重传也计入）
    const before = rx.length;
    sock.send(req, PORT, '127.0.0.1'); // 重复 CON（模拟 ACK 丢失后的重传，§5.5）
    await sleep(250);
    const acks = rx.filter((f) => f.typ === TYP.ACK && f.code === 0x00);
    const resps = rx.filter((f) => f.typ === TYP.CON && f.code === CODE.OK);
    assert.ok(acks.length >= 1, 'server replied transport ACK');
    assert.ok(resps.length >= Math.min(2, before + 1), `got ${resps.length} responses (dup CON re-served cached response)`);
    // 去重核心断言：重复 CON 到达后处理逻辑仍只执行过 1 次（setup 中 1 次 + 本测试首发 1 次）
    assert.equal(counts.rpc, 2);
  } finally {
    sock.close();
  }
});

test('fire_forget：UDP CON 传输确认，处理逻辑到达', async () => {
  await stackB.fire_forget(SVC_ID, 1, 2, { note: 'ping' });
  await waitFor(() => counts.ff === 1);
  assert.equal(counts.ff, 1);
});

test('订阅确认链路（ACK 0x10）+ 事件推送 + 全量推送', async () => {
  // A 先 notify 一次形成接口缓存 → B 订阅建立后应收到全量推送（§8.1）
  stackA.notify(SVC_ID, 1, 3, { temp: 20 });
  const got = [];
  const handle = stackB.subscribe(SVC_ID, 1, { if_id: 3 }, (payload) => got.push(payload));
  // 订阅确认链路：Subscribe(CON) → 服务端 ACK(0x10) → 会话 active（§8.1）
  const session = stackB.discovery.sessions.get(handle);
  await waitFor(() => session.state === 'active');
  assert.equal(session.state, 'active');
  // 全量推送（订阅建立即推缓存）或后续 notify 推送，二者至少交付一次
  await waitFor(() => got.length >= 1);
  assert.deepEqual(got[0], { temp: 20 });
  // 实时推送：A 再 notify → B 交付
  stackA.notify(SVC_ID, 1, 3, { temp: -7 });
  await waitFor(() => got.length >= 2);
  assert.deepEqual(got[got.length - 1], { temp: -7 });
  // 取消订阅：Subscribe(TTL=0) → 取消确认 ACK(0x00)，会话 StrmID 释放（§8.1 场景4）
  await stackB.unsubscribe(handle);
  assert.equal(session.state, 'pending');
});

test('REN：A 重启（stop 发 REN×3）后 B 清空该源发现缓存（§3.6）', async () => {
  await stackA.stop();
  await sleep(450); // REN×3（间隔 100ms）+ 组播传播余量
  assert.equal(stackB.is_available(SVC_ID, 1), false); // 缓存已清，等待新 Offer 重建
});

test('teardown：停止 B 栈', async () => {
  await stackB.stop();
});
