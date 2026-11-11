#!/usr/bin/env node
// ============================================================
// 跨栈互通冒烟编排（FlatWire v5，示例场景 §5）
//
// 三栈（C / Node / MoonBit-JS）两两组合，共 6 组：
//   A（服务端，注册 svc 4096/1）+ B（客户端：发现 → GetIDL → rpc → ff → 订阅推送）
//
// 判定标准（三栈 B 端示例已内置）：
//   - B 退出码 0
//   - B 标准输出出现 [VERIFY-1] ~ [VERIFY-5]
//   - A 由 --run-for 自然退出（超时才强杀，并记为失败证据）
//
// 端口/地址约定：
//   - 每组独立端口（BASE_PORT + 2i），避免 TIME_WAIT 与组播串流
//   - A 绑定 127.0.0.1、B 绑定 127.0.0.2：同机同端口下两个进程不能绑同一个回环地址
//     （否则第二个进程 bind EADDRINUSE），三栈示例本身即按此约定区分"两台主机"
//
// 用法（在仓库根）：
//   node scripts/interop.mjs
//   INTEROP_BASE_PORT=5450 INTEROP_B_RUN_MS=8000 INTEROP_VERBOSE=1 node scripts/interop.mjs
// ============================================================

import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WIN = process.platform === 'win32';
const BASE_PORT = Number(process.env.INTEROP_BASE_PORT || 5450);
const B_RUN_MS = Number(process.env.INTEROP_B_RUN_MS || 8000); // B 运行时长（覆盖订阅 + 至少 2 次推送）
const A_EXTRA_MS = 3000;                                       // A 比 B 多跑的时间，保证 B 先退
const READY_TIMEOUT_MS = 25000;                                // A 就绪（stack started）超时
const B_TIMEOUT_MS = 45000;                                    // B 整体超时（C 的 B 自驱最多 35s）
const TMP = path.join(ROOT, 'tmp', 'interop');
const VERBOSE = process.env.INTEROP_VERBOSE === '1';

const winPath = (p) => (WIN ? p.replace(/\//g, '\\') : p);
const exePath = (name) => winPath(path.join(ROOT, 'fw-c', 'build', WIN ? `${name}.exe` : name));
const mbtJs = (name) =>
  winPath(path.join(ROOT, 'fw-moonbit', '_build', 'js', 'debug', 'build', 'examples', name, `${name}.js`));

// 栈描述：端口/绑定通过环境变量下发；C 示例例外，走位置参数 [port] [bind]
const STACKS = {
  c: {
    name: 'C',
    cwd: () => winPath(path.join(ROOT, 'fw-c')),
    a: (port) => ({
      cmd: exePath('fw_node_a'),
      args: [String(port), '127.0.0.1', '--run-for', String(B_RUN_MS + A_EXTRA_MS)],
    }),
    b: (port) => ({ cmd: exePath('fw_node_b'), args: [String(port), '127.0.0.2'] }),
  },
  node: {
    name: 'Node',
    cwd: () => winPath(path.join(ROOT, 'fw-nodejs')),
    a: () => ({ cmd: process.execPath, args: ['examples/node-a.js', '--run-for', String(B_RUN_MS + A_EXTRA_MS)] }),
    b: () => ({ cmd: process.execPath, args: ['examples/node-b.js', '--run-for', String(B_RUN_MS)] }),
  },
  moonbit: {
    name: 'MoonBit',
    cwd: () => winPath(path.join(ROOT, 'fw-moonbit')),
    a: () => ({ cmd: process.execPath, args: [mbtJs('node_a'), '--run-for', String(B_RUN_MS + A_EXTRA_MS)] }),
    b: () => ({ cmd: process.execPath, args: [mbtJs('node_b'), '--run-for', String(B_RUN_MS)] }),
  },
};
const ORDER = ['c', 'node', 'moonbit'];

/// 前置产物检查：缺失时给出可直接执行的构建命令（不自动构建，避免脚本隐式改变仓库状态）
function preflight() {
  const missing = [];
  if (!fs.existsSync(exePath('fw_node_a')) || !fs.existsSync(exePath('fw_node_b'))) {
    missing.push('C 示例：cmake --build fw-c/build --config Release');
  }
  if (!fs.existsSync(mbtJs('node_a')) || !fs.existsSync(mbtJs('node_b'))) {
    missing.push('MoonBit 示例：cd fw-moonbit && moon build --target js');
  }
  if (missing.length) {
    console.error('[interop] 缺少构建产物，请先执行：');
    for (const m of missing) console.error(`  - ${m}`);
    process.exit(2);
  }
}

/// 启动子进程并收集输出（不实时打印，失败时统一 dump；VERBOSE=1 时实时透传）
function spawnProc(label, spec, env) {
  const child = spawn(spec.cmd, spec.args, {
    cwd: spec.cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    detached: !WIN, // POSIX 下便于整组回收；Windows 用 taskkill /T
  });
  const rec = { label, child, out: '', err: '', exited: false, code: null, signal: null, killed: false };
  child.stdout.on('data', (b) => {
    const s = b.toString('utf8');
    rec.out += s;
    if (VERBOSE) process.stdout.write(s);
  });
  child.stderr.on('data', (b) => {
    const s = b.toString('utf8');
    rec.err += s;
    if (VERBOSE) process.stderr.write(s);
  });
  const done = new Promise((resolve) => {
    child.once('exit', (code, signal) => {
      rec.exited = true;
      rec.code = code;
      rec.signal = signal;
      resolve(rec);
    });
    child.once('error', (e) => {
      rec.err += `\n[spawn error] ${e.message}\n`;
      rec.exited = true;
      rec.code = -1;
      resolve(rec);
    });
  });
  return { rec, done };
}

/// 轮询等待输出匹配（A 就绪信号）
function waitForOutput(rec, re, timeout) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = () => {
      if (re.test(rec.out)) return resolve();
      if (rec.exited) return reject(new Error(`${rec.label} 提前退出（code=${rec.code}）\n${tail(rec)}`));
      if (Date.now() - t0 > timeout) return reject(new Error(`${rec.label} 就绪超时 ${timeout}ms\n${tail(rec)}`));
      setTimeout(tick, 100);
    };
    tick();
  });
}

/// 等待进程退出（带超时）
function waitExit(rec, done, timeout) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${rec.label} 退出超时 ${timeout}ms`)), timeout);
    done.then(() => {
      clearTimeout(t);
      resolve();
    });
  });
}

/// 强制回收进程树（Windows 用 taskkill /T /F；POSIX 杀进程组）
function killTree(rec) {
  if (rec.exited) return;
  rec.killed = true;
  if (WIN) {
    spawnSync('taskkill', ['/pid', String(rec.child.pid), '/T', '/F'], { stdio: 'ignore' });
  } else {
    try {
      process.kill(-rec.child.pid, 'SIGKILL');
    } catch {
      /* 已退出 */
    }
  }
}

/// 输出尾部（失败诊断用，限长避免刷屏）
function tail(rec, n = 2500) {
  const s = `--- ${rec.label} stdout ---\n${rec.out}\n--- ${rec.label} stderr ---\n${rec.err}`;
  return s.length > n ? s.slice(-n) : s;
}

/// 跑一组：A 起服务 → 等就绪 → B 跑验证 → 等 A 退出 → 断言
async function runGroup(aKey, bKey, port) {
  const gid = `${aKey}__as_a__${bKey}__as_b`;
  const dir = path.join(TMP, gid);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  // C 的 IDL 库路径硬编码在 cwd 下（.idl-a / .idl-b）：清空以保证 B 真正走 GetIDL 自动拉取
  fs.rmSync(path.join(ROOT, 'fw-c', '.idl-a'), { recursive: true, force: true });
  fs.rmSync(path.join(ROOT, 'fw-c', '.idl-b'), { recursive: true, force: true });
  const idlA = path.join(dir, 'idl-a');
  const idlB = path.join(dir, 'idl-b');
  fs.mkdirSync(idlA, { recursive: true });
  fs.mkdirSync(idlB, { recursive: true });

  const baseEnv = { ...process.env, FW_PORT: String(port), FW_LOG: 'info' };
  const aSpec = { ...STACKS[aKey].a(port), cwd: STACKS[aKey].cwd() };
  const bSpec = { ...STACKS[bKey].b(port), cwd: STACKS[bKey].cwd() };

  // A：服务端。MoonBit 的 A 必须用自带 IDL 库（examples/node_a/idl），不覆盖 FW_IDL_DIR
  const aEnv = { ...baseEnv, FW_BIND: '127.0.0.1' };
  if (aKey !== 'moonbit') aEnv.FW_IDL_DIR = idlA;

  const A = spawnProc(`${STACKS[aKey].name} A`, aSpec, aEnv);
  try {
    await waitForOutput(A.rec, /stack started/, READY_TIMEOUT_MS);

    // B：客户端（127.0.0.2 与 A 区分回环地址；空 IDL 库触发 GetIDL）
    const bEnv = { ...baseEnv, FW_BIND: '127.0.0.2', FW_IDL_DIR: idlB };
    const B = spawnProc(`${STACKS[bKey].name} B`, bSpec, bEnv);
    try {
      await waitExit(B.rec, B.done, B_TIMEOUT_MS);
    } finally {
      if (!B.rec.exited) killTree(B.rec);
    }

    // A 交给 --run-for 自然退出；超时兜底强杀（强杀本身记为异常证据）
    try {
      await waitExit(A.rec, A.done, B_RUN_MS + A_EXTRA_MS + 5000);
    } catch {
      killTree(A.rec);
    }

    const problems = [];
    if (B.rec.code !== 0) problems.push(`B 退出码 ${B.rec.code}（期望 0）`);
    for (const n of [1, 2, 3, 4, 5]) {
      if (!new RegExp(`\\[VERIFY-${n}\\]`).test(B.rec.out)) problems.push(`B 缺少 [VERIFY-${n}]`);
    }
    if (A.rec.killed) problems.push('A 未按 --run-for 自然退出（被强杀）');

    return { gid, port, problems, aText: tail(A.rec), bText: tail(B.rec) };
  } catch (e) {
    return { gid, port, problems: [e.message], aText: tail(A.rec), bText: '' };
  } finally {
    if (!A.rec.exited) killTree(A.rec);
  }
}

async function main() {
  preflight();
  fs.mkdirSync(TMP, { recursive: true });

  const groups = [];
  for (const a of ORDER) for (const b of ORDER) if (a !== b) groups.push([a, b]);

  console.log(`[interop] 共 ${groups.length} 组；B 时长 ${B_RUN_MS}ms；日志 ${TMP}`);
  let failed = 0;
  let idx = 0;
  for (const [a, b] of groups) {
    const port = BASE_PORT + idx * 2;
    idx++;
    const label = `${STACKS[a].name} -> ${STACKS[b].name} (port ${port})`;
    process.stdout.write(`[interop] ${label} ... `);
    const r = await runGroup(a, b, port);
    if (r.problems.length === 0) {
      console.log('PASS');
    } else {
      failed++;
      console.log('FAIL');
      for (const p of r.problems) console.log(`    - ${p}`);
      console.log(r.aText);
      console.log(r.bText);
    }
  }

  console.log(`[interop] ${groups.length - failed}/${groups.length} 组通过`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(`[interop] 编排异常：${e.stack || e}`);
  process.exit(1);
});
