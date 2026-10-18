// ============================================================
// node-a.js —— 示例服务端：注册 VehicleState 服务实例（实现计划 §5）
//
// 场景：
//   - 注册 svc_id=4096（规范 §11.1 VehicleState IDL）实例 inst_id=1
//   - 提供 rpc GetState / ff UpdateState + UploadBlob 的 handler
//   - 周期 notify StateChanged(32769) / PowerModeChanged(32770)
//   - 优雅退出（stop 发 REN×3 组播，§3.6）：SIGINT 或 --run-for <ms> 到期
//
// 运行：node examples/node-a.js [--run-for 25000]
// 环境变量：FW_PORT(默认 5400) / FW_BIND(默认 127.0.0.1) / FW_IDL_DIR(默认 examples/.idl-a)
// ============================================================

import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { FwStack } from '../src/stack.js';

// ---- 参数解析（最小化：仅示例编排需要） ----
const argOf = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : null;
};
const runForMs = argOf('run-for') ? Number(argOf('run-for')) : null;

const PORT = Number(process.env.FW_PORT ?? 5400);
const BIND = process.env.FW_BIND ?? '127.0.0.1'; // 同机演示绑定回环地址（跨机部署可省略 = 全接口）
const IDL_DIR = process.env.FW_IDL_DIR ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '.idl-a');

// ---- 规范 §11.1 VehicleState IDL（本目录自含副本，纯动态架构：运行时进库，§11.1） ----
const idlText = readFileSync(new URL('./vehicle-state.idl.json', import.meta.url), 'utf8');

// ---- 业务状态：演示用内存态 ----
const state = {
  veh_md: 1,              // 车辆模式
  usg_md: 2,              // 使用模式
  sys_pwr_md: 2,          // 电源模式（signed）
  timestamp: Date.now(),  // 毫秒时间戳（§9.1 timestamp）
  timestr: '2026-10-13T12:00:00Z', // fixed_len=20，恰 20 字节
  status_msg: 'all systems nominal',
  diag_note: null,        // optional 字段：null 编码为 1B 空头（§9.2）
  ratio: 0.618,           // float64
};

// ---- 协议栈启动 + 注册（§13.1） ----
const stack = new FwStack({
  port: PORT,
  bind_address: BIND,
  multicast_interface: BIND, // 组播出口接口与绑定地址一致（多网卡/回环演示场景）
  idl_dir: IDL_DIR,
  log_level: process.env.FW_LOG ?? 'info',
});

await stack.start();
console.log(`[NodeA] stack started: port=${PORT} bind=${BIND} idl_dir=${IDL_DIR}`);

await stack.register_service(4096, 1, idlText, {
  // rpc：请求-响应（GetState if_id=1：无输入，返回 VehicleState 结构）
  on_request: (ifId, payload) => {
    if (ifId === 1) {
      state.timestamp = Date.now();
      console.log(`[NodeA] rpc GetState ← replying current state`);
      return { ...state };
    }
    throw new Error(`unexpected rpc if_id=${ifId}`);
  },
  // ff：无响应调用（UpdateState if_id=2 / UploadBlob if_id=3）
  on_fire_forget: (ifId, payload) => {
    if (ifId === 2) {
      Object.assign(state, payload); // 更新本地状态
      console.log(`[NodeA] ff UpdateState: sys_pwr_md=${payload.sys_pwr_md} status="${payload.status_msg}"`);
      stack.notify(4096, 1, 32769, { ...state }); // 状态变更即推送（§8.2）
    } else if (ifId === 3) {
      console.log(`[NodeA] ff UploadBlob: vin=${Buffer.from(payload.vin).toString('hex')} payload=${payload.payload.length}B`);
    }
  },
});
console.log('[NodeA] service 4096/1 registered (VehicleStateService) → Offering');

// ---- 周期事件推送：StateChanged（32769, VehicleState）+ PowerModeChanged（32770, enum=2 Run） ----
let seq = 0;
const pushTimer = setInterval(() => {
  state.timestamp = Date.now();
  state.ratio = Math.round((seq % 10) * 0.1 * 1000) / 1000;
  stack.notify(4096, 1, 32769, { ...state });   // event output=VehicleState（§8.2）
  stack.notify(4096, 1, 32770, 2);              // event output=PowerMode（enum 线格式=底层整型，§11.1）
  seq++;
}, 3000);
pushTimer.unref?.();

// ---- 优雅退出：stop 发 REN×3 组播后释放资源（§3.6） ----
async function shutdown(reason) {
  clearInterval(pushTimer);
  console.log(`[NodeA] stopping (${reason}) → sending REN x3 ...`);
  await stack.stop();
  console.log('[NodeA] stopped');
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
if (runForMs !== null) setTimeout(() => shutdown(`--run-for ${runForMs}ms elapsed`), runForMs);
