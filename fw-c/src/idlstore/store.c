// ============================================================
// store.c —— §11.1 IDL 库：加载 / 落盘 / 纯动态架构
//
// - 协议栈不内置任何 IDL：全部服务定义运行时从本地 IDL 库（文件夹）加载
// - 库内按 (SvcID, MajorVer) 组织；文件命名约定：`{svc_id}_v{major_ver}.json`
// - 解析失败的文件跳过并记 Error 日志，不阻塞其他服务加载（启动健壮性）
// - GetIDL 拉取成功后持久化写入（§7.2）；落盘失败降级为仅内存加载并记 Error 日志
// - 新旧版本定义并存，不覆盖（§7.2 版本演进）
// - GetIDL 响应直接回 IDL 库文件原文字节（jsonText，不做序列化往返）
// ============================================================

#include "fw/fw.h"
#include "platform/platform.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  fw_schema_t *schema;
  char *json_text;      // 原文（GetIDL 响应直接回发，§7.2）
  char file_name[64];
  int persisted;
} idl_entry_t;

struct fw_idlstore {
  char dir[260];
  idl_entry_t *entries;
  int n, cap;
};

fw_idlstore_t *fw_idl_new(void) {
  return (fw_idlstore_t *)calloc(1, sizeof(fw_idlstore_t));
}

static void entry_free(idl_entry_t *e) {
  if (e->schema) fw_schema_free(e->schema);
  free(e->json_text);
}

void fw_idl_free(fw_idlstore_t *s) {
  if (!s) return;
  for (int i = 0; i < s->n; i++) entry_free(&s->entries[i]);
  free(s->entries);
  free(s);
}

// 解析并载入一段 IDL JSON 文本；失败返回 NULL（调用方决定跳过或降级）
static idl_entry_t *load_text(fw_idlstore_t *s, const char *text, size_t len,
                              const char *file_name, int persisted) {
  char err[128];
  fw_value_t *idl = fw_json_parse(text, len, err, sizeof(err));
  if (!idl) {
    fw_log(FW_LOG_ERROR, "idlstore", "IDL JSON 解析失败: %s, %s", file_name, err);
    return NULL;
  }
  fw_schema_t *schema = fw_schema_build(idl, err, sizeof(err));
  fw_value_free(idl);
  if (!schema) {
    fw_log(FW_LOG_ERROR, "idlstore", "IDL schema 构建失败: %s, %s", file_name, err);
    return NULL;
  }
  // [REVIEW P3-10] 同 (svc,major) 已存在 → 拒绝重载并保留旧定义（原实现 free 旧
  // schema：若 local/handler 持有旧 schema 指针则悬空）。当前调用点均先 fw_idl_has
  // 防覆盖，此处为防御加固；§7.2"并存不覆盖"语义下旧定义优先
  for (int i = 0; i < s->n; i++) {
    if (s->entries[i].schema->svc_id == schema->svc_id &&
        s->entries[i].schema->major_ver == schema->major_ver) {
      fw_log(FW_LOG_WARN, "idlstore",
             "IDL (svc=%u, major=%u) already loaded (%s), keep existing definition",
             schema->svc_id, schema->major_ver, s->entries[i].file_name);
      fw_schema_free(schema);
      return &s->entries[i]; // 返回既有条目（幂等）
    }
  }
  if (s->n == s->cap) {
    int nc = s->cap ? s->cap * 2 : 8;
    idl_entry_t *ne = (idl_entry_t *)realloc(s->entries, (size_t)nc * sizeof(idl_entry_t));
    if (!ne) { fw_schema_free(schema); return NULL; }
    s->entries = ne;
    s->cap = nc;
  }
  idl_entry_t *e = &s->entries[s->n++];
  memset(e, 0, sizeof(*e));
  e->schema = schema;
  char *jt = (char *)malloc(len + 1);
  if (!jt) { s->n--; fw_schema_free(schema); return NULL; }
  memcpy(jt, text, len);
  jt[len] = 0;
  e->json_text = jt;
  snprintf(e->file_name, sizeof(e->file_name), "%s", file_name);
  e->persisted = persisted;
  return e;
}

// 启动扫描加载：读取目录内全部 .json，损坏文件跳过（§11.1 启动健壮性）
int fw_idl_load_all(fw_idlstore_t *s, const char *dir) {
  snprintf(s->dir, sizeof(s->dir), "%s", dir);
  fw_plat_mkdir_p(dir);
  char **files = NULL;
  int nf = 0;
  if (fw_plat_list_json(dir, &files, &nf) != 0) {
    fw_log(FW_LOG_ERROR, "idlstore", "IDL 库目录不可读: %s", dir);
    return FW_ERR_IO;
  }
  for (int i = 0; i < nf; i++) {
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
    size_t len = 0;
    uint8_t *data = fw_plat_read_file(path, &len);
    if (!data) {
      fw_log(FW_LOG_ERROR, "idlstore", "IDL 文件读取失败/跳过: %s", files[i]);
      continue;
    }
    // 解析失败的文件跳过并记 Error 日志，不阻塞其他服务加载（§11.1）
    load_text(s, (const char *)data, len, files[i], 1);
    free(data);
  }
  for (int i = 0; i < nf; i++) free(files[i]);
  free(files);
  fw_log(FW_LOG_INFO, "idlstore", "IDL 库加载完成: %d 个定义 (%s)", s->n, dir);
  return FW_OK;
}

// 是否已有该 (SvcID, MajorVer) 的已加载定义（§7.2 服务端匹配依据）
int fw_idl_has(fw_idlstore_t *s, uint16_t svc, uint8_t major) {
  for (int i = 0; i < s->n; i++)
    if (s->entries[i].schema->svc_id == svc && s->entries[i].schema->major_ver == major) return 1;
  return 0;
}

fw_idl_entry_t *fw_idl_get(fw_idlstore_t *s, uint16_t svc, uint8_t major) {
  for (int i = 0; i < s->n; i++)
    if (s->entries[i].schema->svc_id == svc && s->entries[i].schema->major_ver == major)
      return (fw_idl_entry_t *)&s->entries[i];
  return NULL;
}

// 取该 SvcID 的最高已加载版本定义；无则 NULL（§7.2 建议最高版本）
fw_idl_entry_t *fw_idl_get_highest(fw_idlstore_t *s, uint16_t svc) {
  idl_entry_t *best = NULL;
  for (int i = 0; i < s->n; i++) {
    if (s->entries[i].schema->svc_id != svc) continue;
    if (!best || s->entries[i].schema->major_ver > best->schema->major_ver)
      best = &s->entries[i];
  }
  return (fw_idl_entry_t *)best;
}

// GetIDL 拉取成功后落盘持久化（§7.2 协议要求）。
// 写入前由调用方校验 svc_id/major_ver 与请求一致。
// 落盘失败 → 降级为仅内存加载使用并记 Error 日志（可用性优先，§7.2）。
int fw_idl_save(fw_idlstore_t *s, uint16_t svc, uint8_t major, const char *json) {
  // 先解析校验（失败不落盘不加载，IDL 库状态不变）
  char file_name[64];
  snprintf(file_name, sizeof(file_name), "%u_v%u.json", svc, major);
  idl_entry_t *e = load_text(s, json, strlen(json), file_name, 1);
  if (!e) return FW_ERR_DECODE;
  // 落盘
  char path[600];
  snprintf(path, sizeof(path), "%s/%s", s->dir, file_name);
  fw_plat_mkdir_p(s->dir);
  if (fw_plat_write_file(path, json, strlen(json)) == FW_OK) {
    e->persisted = 1;
    fw_log(FW_LOG_INFO, "idlstore", "IDL 落盘成功: %s", file_name);
  } else {
    // 落盘失败（磁盘满/只读等）：降级为仅内存加载使用（§7.2）
    e->persisted = 0;
    fw_log(FW_LOG_ERROR, "idlstore", "IDL 落盘失败(降级内存): %s", file_name);
  }
  return FW_OK;
}
