// ============================================================
// node-b.js —— 示例客户端：发现 → 调用 → 订阅（实现计划 §5 场景）
//
// 验证点（输出带 [VERIFY] 标记，冒烟脚本检查）：
//   1. 服务发现：is_available(4096,1) → true（组播 Offer 建立发现缓存）
//   2. GetIDL 自动拉取落盘：本地 IDL 库为空 → 调用触发协议栈内部 GetIDL（§7.2/5.21）
//      → 库内出现 4096_v1.json（重启后本地命中不重复拉取，5.28）
//   3. rpc call 往返：GetState 返回 VehicleState 结构
//   4. fire_forget：UpdateState / UploadBlob 到达（TCP 全 NON 无确认）
//   5. 订阅确认链路 + 事件推送：Subscribe(CON) → ACK(0x10) → 交付推送
//   6. REN 感知：服务端优雅退出（REN×3）→ is_available=false；重启 → 重新发现 true（§3.6/4.6）
//
// 运行：node examples/node-b.js [--run-for 55000]
// 环境变量：FW_PORT(默认 5400) / FW_BIND(默认 127.0.0.2) / FW_IDL_DIR(默认 examples/.idl-b)
//   FW_BIND 默认 127.0.0.2：同机演示时与 NodeA（127.0.0.1）区分，避免同端口 UDP 单播
//   投递竞争（127/8 全回环）；跨机部署任选地址或省略（= 全接口）。
// ============================================================

import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import { FwStack } from '../src/stack.js';

// ---- 参数解析（最小化） ----
const argOf = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : null;
};
const runForMs = argOf('run-for') ? Number(argOf('run-for')) : 55000;

const PORT = Number(process.env.FW_PORT ?? 5400);
const BIND = process.env.FW_BIND ?? '127.0.0.2';
const IDL_DIR = process.env.FW_IDL_DIR ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '.idl-b');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeout, label) {
  const t0 = Date.now();
  while (!fn()) {
    if (Date.now() - t0 > timeout) throw new Error(`timeout waiting: ${label}`);
    await sleep(100);
  }
}

// ---- 协议栈启动：空 IDL 库起步（纯动态架构 §11.1 客户端按需拉取） ----
fs.mkdirSync(IDL_DIR, { recursive: true });
const stack = new FwStack({
  port: PORT,
  bind_address: BIND,
  multicast_interface: BIND,
  idl_dir: IDL_DIR,
  tcp_enabled: false, // 客户端角色不监听 TCP（GetIDL/rpc 走出站连接）；跨机部署可开启
  log_level: process.env.FW_LOG ?? 'info',
});
await stack.start();
console.log(`[NodeB] stack started: port=${PORT} bind=${BIND} idl_dir=${IDL_DIR}`);

// 1. 服务发现（§7.4 客户端状态机：启动即发 Find 预热 + 组播 Offer 周期刷新）
await waitFor(() => stack.is_available(4096, 1), 10000, 'service 4096/1 available');
console.log('[VERIFY-1] discovery: svc 4096/1 available = true');
const info = await stack.find_service(4096, 1);
console.log(`[NodeB] found: ${info.address}:${info.port} major_ver=${info.major_ver}`);

// 2+3. rpc call：本地无 IDL → 协议栈自动 GetIDL（TCP 单播）→ 落盘 → 按已加载 IDL 编解码（§7.2）
console.log('[NodeB] local IDL store empty:', !stack.idlStore.getHighest(4096));
const ret = await stack.call(4096, 1, 1); // GetState：无输入（input=[]）
console.log('[VERIFY-2] GetIDL persisted:', fs.existsSync(path.join(IDL_DIR, '4096_v1.json')));
console.log('[VERIFY-3] rpc GetState →', JSON.stringify(ret));

// 4. fire_forget（TCP 全 NON，无传输确认，§5.2）
await stack.fire_forget(4096, 1, 2, {
  veh_md: 1, usg_md: 2, sys_pwr_md: 3, timestamp: Date.now(),
  timestr: '2026-10-13T12:30:00Z', status_msg: 'updated by NodeB', diag_note: 'demo', ratio: 0.717,
});
await stack.fire_forget(4096, 1, 3, {
  vin: Buffer.from('LFV3A23C8K3123456', 'utf8'), // 17B 定长 bytes
  payload: Buffer.from([1, 2, 3, 4, 5]),
});
console.log('[VERIFY-4] fire_forget UpdateState/UploadBlob sent (tcp)');

// 5. 订阅：Subscribe(CON) → ACK(0x10) 确认 → 事件推送交付（§8.1）
let pushes = 0;
const handle = stack.subscribe(4096, 1, { if_id: 32769 }, (payload) => {
  pushes++;
  console.log(`[VERIFY-5] event push #${pushes}:`, JSON.stringify(payload));
});
await waitFor(() => pushes >= 1, 10000, 'first event push');
console.log('[NodeB] subscribed (handle=%d), %d push(es) received', handle, pushes);

// 6. REN 感知观察：周期打印可用性（服务端优雅退出 → REN×3 → 缓存清空；重启 → 重新发现）
let last = true;
const watchTimer = setInterval(() => {
  const cur = stack.is_available(4096, 1);
  if (cur !== last) {
    console.log(`[VERIFY-6] availability changed: ${last} → ${cur} (${cur ? 'rediscovered' : 'REN cleared'})`);
    last = cur;
  }
}, 500);
watchTimer.unref?.();

// ---- 自动退出（--run-for 默认 55s）：unsubscribe → stop（§8.1 场景4） ----
setTimeout(async () => {
  clearInterval(watchTimer);
  stack.unsubscribe(handle);
  console.log(`[NodeB] done: ${pushes} push(es) received, unsubscribed, stopping ...`);
  await stack.stop();
  process.exit(0);
}, runForMs).unref?.();

process.on('SIGINT', async () => {
  clearInterval(watchTimer);
  await stack.stop();
  process.exit(0);
});
