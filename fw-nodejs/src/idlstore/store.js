// ============================================================
// store.js —— §11.1 IDL 库：加载 / 落盘 / 纯动态架构
//
// - 协议栈不内置任何 IDL：全部服务定义运行时从本地 IDL 库（文件夹）加载
// - 库内按 (SvcID, MajorVer) 组织；文件命名约定：`{svc_id}_v{major_ver}.json`
// - 解析失败的文件跳过并记 Error 日志，不阻塞其他服务加载（启动健壮性）
// - GetIDL 拉取成功后持久化写入（§7.2）；落盘失败降级为仅内存加载并记 Error 日志
// - 新旧版本定义并存，不覆盖（§7.2 版本演进）
// ============================================================

import fs from 'node:fs';
import path from 'node:path';
import { Schema } from '../codec/schema.js';

export class IdlStore {
  /**
   * @param {string} dir IDL 库文件夹路径
   * @param {object} logger 日志器
   */
  constructor(dir, logger) {
    this.dir = dir;
    this.log = logger;
    // key = `${svcId}:${majorVer}` → { idl, schema, jsonText, fileName, persisted }
    this._store = new Map();
  }

  /** 启动扫描加载：读取目录内全部 .json，损坏文件跳过（§11.1） */
  async loadAll() {
    let files = [];
    try {
      await fs.promises.mkdir(this.dir, { recursive: true });
      files = (await fs.promises.readdir(this.dir)).filter((f) => f.toLowerCase().endsWith('.json'));
    } catch (e) {
      this.log.error('idlstore', `IDL 库目录不可读: ${this.dir}, ${e.message}`);
      return;
    }
    for (const f of files) {
      const full = path.join(this.dir, f);
      try {
        const text = await fs.promises.readFile(full, 'utf8');
        this._loadText(text, f, true);
      } catch (e) {
        // 解析失败的文件跳过并记 Error 日志，不阻塞其他服务加载（§11.1）
        this.log.error('idlstore', `IDL 文件损坏/跳过: ${f}, ${e.message}`);
      }
    }
    this.log.info('idlstore', `IDL 库加载完成: ${this._store.size} 个定义 (${this.dir})`);
  }

  /** 解析并载入一段 IDL JSON 文本；失败抛错（调用方决定跳过或降级） */
  _loadText(text, fileName, persisted) {
    const idl = JSON.parse(text);
    const schema = new Schema(idl); // 校验 svc_id 等必要字段
    const key = `${schema.svcId}:${schema.majorVer}`;
    // 新旧版本并存不覆盖（§7.2）；同 key 重复加载以内存为准（后到覆盖同版本属重复文件，无语义差异）
    this._store.set(key, { idl, schema, jsonText: text, fileName, persisted });
    return key;
  }

  /** 是否已有该 (SvcID, MajorVer) 的已加载定义（§7.2 服务端匹配依据） */
  has(svcId, majorVer) {
    return this._store.has(`${svcId}:${majorVer}`);
  }

  /** 取已加载定义；不存在返回 undefined */
  get(svcId, majorVer) {
    return this._store.get(`${svcId}:${majorVer}`);
  }

  /** 该 SvcID 的所有已加载版本 key（`${svcId}:${majorVer}` 形式），建议取最高版本（§7.2） */
  listVersions(svcId) {
    const keys = [];
    for (const key of this._store.keys()) {
      if (key.startsWith(`${svcId}:`)) keys.push(key);
    }
    return keys;
  }

  /** 取该 SvcID 的最高已加载版本定义；无则 undefined */
  getHighest(svcId) {
    let best = null;
    for (const key of this.listVersions(svcId)) {
      const major = Number(key.split(':')[1]);
      if (best === null || major > best.major) best = { major, entry: this._store.get(key) };
    }
    return best?.entry;
  }

  /**
   * GetIDL 拉取成功后落盘持久化（§7.2 协议要求）。
   * 写入前由调用方校验 svc_id/major_ver 与请求一致（见 sd 模块）。
   * 落盘失败 → 抛错（调用方降级为仅内存加载并记 Error 日志，§7.2）。
   * @returns {Promise<string>} 存储 key
   */
  async save(svcId, majorVer, jsonText) {
    let key;
    try {
      key = this._loadText(jsonText, `${svcId}_v${majorVer}.json`, true); // 先解析校验
    } catch (e) {
      throw new Error(`fetched IDL invalid: ${e.message}`);
    }
    const fileName = `${svcId}_v${majorVer}.json`;
    try {
      await fs.promises.mkdir(this.dir, { recursive: true });
      await fs.promises.writeFile(path.join(this.dir, fileName), jsonText, 'utf8');
      this._store.get(key).persisted = true;
      this.log.info('idlstore', `IDL 落盘成功: ${fileName}`);
    } catch (e) {
      // 落盘失败（磁盘满/只读等）：降级为仅内存加载使用，可用性优先（§7.2）
      this.log.error('idlstore', `IDL 落盘失败(降级内存): ${fileName}, ${e.message}`);
      this._store.get(key).persisted = false;
    }
    return key;
  }

  /** 全部已加载定义的迭代（接口查询/事件组查询用，§7.2 库级匹配） */
  allEntries() {
    return [...this._store.values()];
  }

  /** 全部已加载定义数量 */
  get size() { return this._store.size; }
}
