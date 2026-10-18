// ============================================================
// schema.c —— IDL 解析（§11.1）与类型解析（resolve 递归展开）
//
// 内存模型：
//   - 命名类型（structs/enums/arrays）→ schema->cache 统一持有（owned=0）
//   - 字段级基础/内联数组 tdesc → owned=1，随引用它的 struct tdesc 释放
//   - array tdesc 的 element 指向共享 tdesc，不随本体释放
// ============================================================

#include "fw/fw.h"
#include "platform/platform.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 基础字段类型名（IDL 字段 type 直接使用，§9.1）；返回 0 = 类型名引用
static int basic_type_kind(const char *t) {
  if (!t) return 0;
  if (strcmp(t, "bool") == 0)      return FW_T_BOOL;
  if (strcmp(t, "signed") == 0)    return FW_T_SIGNED;
  if (strcmp(t, "unsigned") == 0)  return FW_T_UNSIGNED;
  if (strcmp(t, "float") == 0)     return FW_T_FLOAT;
  if (strcmp(t, "timestamp") == 0) return FW_T_TIMESTAMP;
  if (strcmp(t, "string") == 0)    return FW_T_STRING;
  if (strcmp(t, "bytes") == 0)     return FW_T_BYTES;
  return 0;
}

// ---- JSON 取值助手 ----
static const char *jstr(const fw_value_t *o, const char *key, const char *dflt) {
  const fw_value_t *v = fw_struct_get(o, key);
  if (v && v->type == FW_V_STRING) return v->as.s.ptr;
  return dflt;
}
static int64_t jint(const fw_value_t *o, const char *key, int64_t dflt) {
  const fw_value_t *v = fw_struct_get(o, key);
  if (v && v->type == FW_V_INT) return v->as.i;
  if (v && v->type == FW_V_UINT) return (int64_t)v->as.u;
  return dflt;
}
static int jbool(const fw_value_t *o, const char *key, int dflt) {
  const fw_value_t *v = fw_struct_get(o, key);
  if (v && v->type == FW_V_BOOL) return v->as.b;
  return dflt;
}

// ---- tdesc 分配 ----
static fw_tdesc_t *tdesc_new(int kind, const char *name, int owned) {
  fw_tdesc_t *t = (fw_tdesc_t *)calloc(1, sizeof(fw_tdesc_t));
  if (!t) return NULL;
  t->kind = kind;
  t->owned = owned;
  t->fixed_len = -1;
  t->max_len = -1;
  if (name) snprintf(t->name, sizeof(t->name), "%s", name);
  return t;
}

// cache 登记（命名类型统一持有；重名以首次为准）
static int cache_add(fw_schema_t *s, const char *name, fw_tdesc_t *t) {
  if (s->cache_n == s->cache_cap) {
    int nc = s->cache_cap ? s->cache_cap * 2 : 16;
    void *np = realloc(s->cache, (size_t)nc * sizeof(*s->cache));
    if (!np) return 0;
    s->cache = np;
    s->cache_cap = nc;
  }
  snprintf(s->cache[s->cache_n].name, sizeof(s->cache[s->cache_n].name), "%s", name);
  s->cache[s->cache_n].t = t;
  s->cache_n++;
  return 1;
}

// 递归解析（depth 限制防循环引用栈溢出；IDL 实践不出现循环）
static fw_tdesc_t *resolve_depth(fw_schema_t *s, const char *name, int depth);

fw_tdesc_t *fw_schema_resolve(fw_schema_t *s, const char *name) {
  return resolve_depth(s, name, 0);
}

static fw_tdesc_t *resolve_depth(fw_schema_t *s, const char *name, int depth) {
  if (!s || !name || !name[0] || depth > 32) return NULL;
  // 缓存命中
  for (int i = 0; i < s->cache_n; i++)
    if (strcmp(s->cache[i].name, name) == 0) return s->cache[i].t;
  // 查原始定义表
  fw_typedef_t *def = NULL;
  for (int i = 0; i < s->def_n; i++) {
    if (strcmp(s->defs[i].name, name) == 0) { def = &s->defs[i]; break; }
  }
  if (!def) return NULL;

  if (def->kind == 0) {
    // 结构体：N 个字段的有序组合（§9.3）
    fw_tdesc_t *t = tdesc_new(FW_T_STRUCT, name, 0);
    if (!t) return NULL;
    t->field_n = def->field_n;
    t->fields = (fw_tfield_t *)calloc((size_t)(def->field_n ? def->field_n : 1), sizeof(fw_tfield_t));
    if (!t->fields) { free(t); return NULL; }
    if (!cache_add(s, name, t)) { free(t->fields); free(t); return NULL; }
    for (int i = 0; i < def->field_n; i++) {
      fw_tfield_t *f = &t->fields[i];
      snprintf(f->name, sizeof(f->name), "%s", def->fields[i].name);
      f->optional = def->fields[i].optional;
      const char *ft = def->fields[i].type;
      if (strcmp(ft, "array") == 0) {
        // 内联数组字段定义（element_type 引用其他类型，§11.1/§9.3）
        fw_tdesc_t *el = tdesc_new(FW_T_ARRAY, "", 1);
        if (!el) return NULL;
        el->fixed_len = def->fields[i].fixed_len;
        el->max_len = def->fields[i].max_len;
        el->element = resolve_depth(s, def->fields[i].element_type, depth + 1);
        if (!el->element) { free(el); return NULL; }
        f->type = el;
      } else {
        int bk = basic_type_kind(ft);
        if (bk != 0) {
          // 基础类型字段（直接展开，§9.1）
          fw_tdesc_t *bt = tdesc_new(bk, ft, 1);
          if (!bt) return NULL;
          bt->size = def->fields[i].size;
          bt->width = def->fields[i].width;
          bt->fixed_len = def->fields[i].fixed_len;
          bt->max_len = def->fields[i].max_len;
          f->type = bt;
        } else {
          // 类型名引用（struct/enum/array 定义名）——展开并保留字段名与 optional（§11.1）
          f->type = resolve_depth(s, ft, depth + 1);
          if (!f->type) return NULL;
        }
      }
    }
    return t;
  }
  if (def->kind == 1) {
    // 枚举：线格式 = 底层整型（§11.1）
    fw_tdesc_t *t = tdesc_new(FW_T_ENUM, name, 0);
    if (!t) return NULL;
    t->enum_base = (strcmp(def->base, "signed") == 0) ? FW_T_SIGNED : FW_T_UNSIGNED;
    t->size = def->size;
    t->enum_n = def->val_n;
    // [REVIEW P3-6] enum_vals 改为拷贝：消除 tdesc 布局与 fw_typedef_t.vals
    // 必须逐字节一致的脆弱耦合（原实现直接指向 typedef.vals）
    t->enum_vals = NULL;
    if (def->val_n > 0) {
      t->enum_vals = (void *)malloc((size_t)def->val_n * sizeof(*t->enum_vals));
      if (!t->enum_vals) { free(t); return NULL; }
      memcpy(t->enum_vals, def->vals, (size_t)def->val_n * sizeof(*t->enum_vals));
    }
    if (!cache_add(s, name, t)) { free(t->enum_vals); free(t); return NULL; }
    return t;
  }
  if (def->kind == 2) {
    // 数组类型：element_type 可为 struct/array/enum（任意嵌套，§9.3/§11.1）
    fw_tdesc_t *t = tdesc_new(FW_T_ARRAY, name, 0);
    if (!t) return NULL;
    t->fixed_len = def->fixed_len;
    t->max_len = def->max_len;
    if (!cache_add(s, name, t)) { free(t); return NULL; }
    t->element = resolve_depth(s, def->element_type, depth + 1);
    if (!t->element) return NULL;
    return t;
  }
  return NULL;
}

fw_iface_t *fw_schema_iface(const fw_schema_t *s, uint16_t if_id) {
  for (int i = 0; i < s->iface_n; i++)
    if (s->ifaces[i].if_id == if_id) return (fw_iface_t *)&s->ifaces[i];
  return NULL;
}

// 查 IDL 事件组成员（§7.1；成员列表借用 schema 生命周期）
const uint16_t *fw_schema_group_members(const fw_schema_t *s, int grp_id, int *out_n) {
  for (int i = 0; i < s->group_n; i++) {
    if (s->groups[i].grp_id == grp_id) {
      *out_n = s->groups[i].members_n;
      return s->groups[i].members;
    }
  }
  *out_n = 0;
  return NULL;
}

// ---- 原始定义表构建 ----

static int def_add(fw_schema_t *s, const char *name, int kind) {
  if (s->def_n == s->def_cap) {
    int nc = s->def_cap ? s->def_cap * 2 : 8;
    void *np = realloc(s->defs, (size_t)nc * sizeof(fw_typedef_t));
    if (!np) return 0;
    s->defs = np;
    s->def_cap = nc;
  }
  fw_typedef_t *d = &s->defs[s->def_n++];
  memset(d, 0, sizeof(*d));
  d->kind = kind;
  d->fixed_len = -1;
  d->max_len = -1;
  snprintf(d->name, sizeof(d->name), "%s", name);
  return 1;
}

// struct 字段原始定义录入
static int build_field_def(fw_typedef_t *d, const fw_value_t *jf) {
  if (jf->type != FW_V_STRUCT) return 0;
  const char *tname = jstr(jf, "type", NULL);
  if (!tname) return 0;
  if (d->field_n == d->field_cap) {
    int nc = d->field_cap ? d->field_cap * 2 : 8;
    void *np = realloc(d->fields, (size_t)nc * sizeof(*d->fields));
    if (!np) return 0;
    d->fields = np;
    d->field_cap = nc;
  }
  typedef struct { char name[64]; char type[64]; char element_type[64];
                   int optional, size, width, fixed_len, max_len; } field_t;
  field_t *f = &((field_t *)d->fields)[d->field_n];
  memset(f, 0, sizeof(*f));
  snprintf(f->name, sizeof(f->name), "%s", jstr(jf, "name", "?"));
  snprintf(f->type, sizeof(f->type), "%s", tname);
  // 内联数组字段的元素类型（type=="array" 时使用，§11.1）
  if (strcmp(tname, "array") == 0)
    snprintf(f->element_type, sizeof(f->element_type), "%s", jstr(jf, "element_type", ""));
  f->optional = jbool(jf, "optional", 0);
  f->size = (int)jint(jf, "size", 0);
  f->width = (int)jint(jf, "width", 0);
  f->fixed_len = (int)jint(jf, "fixed_len", -1);
  f->max_len = (int)jint(jf, "max_len", -1);
  d->field_n++;
  return 1;
}

fw_schema_t *fw_schema_build(const fw_value_t *idl, char *err, int errsz) {
  fw_schema_t *s = NULL; // 先声明（FAIL 宏引用）
#define FAIL(msg) do { if (err && errsz > 0) snprintf(err, (size_t)errsz, "%s", (msg)); fw_schema_free(s); return NULL; } while (0)
  if (!idl || idl->type != FW_V_STRUCT) { FAIL("IDL must be an object"); }
  s = (fw_schema_t *)calloc(1, sizeof(fw_schema_t));
  if (!s) { FAIL("out of memory"); }

  const fw_value_t *svc = fw_struct_get(idl, "service");
  if (!svc || svc->type != FW_V_STRUCT) FAIL("IDL missing service");
  int64_t svc_id = jint(svc, "svc_id", 0);
  if (svc_id <= 0 || svc_id > 0xFFFF) FAIL("IDL missing/invalid service.svc_id");
  s->svc_id = (uint16_t)svc_id;
  s->major_ver = (uint8_t)jint(svc, "major_ver", 0);
  s->minor_ver = (uint8_t)jint(svc, "minor_ver", 0);
  snprintf(s->name, sizeof(s->name), "%s", jstr(svc, "name", ""));

  // ---- interfaces（transport 省略按类型默认：rpc/ff=tcp，event=udp，§11.1） ----
  const fw_value_t *ifaces = fw_struct_get(svc, "interfaces");
  if (ifaces && ifaces->type == FW_V_ARRAY) {
    int n = (int)ifaces->as.arr.len;
    s->ifaces = (fw_iface_t *)calloc((size_t)(n ? n : 1), sizeof(fw_iface_t));
    if (!s->ifaces) FAIL("out of memory");
    s->iface_n = n;
    for (int i = 0; i < n; i++) {
      const fw_value_t *ji = ifaces->as.arr.items[i];
      fw_iface_t *d = &s->ifaces[i];
      snprintf(d->name, sizeof(d->name), "%s", jstr(ji, "name", "?"));
      d->if_id = (uint16_t)jint(ji, "if_id", 0);
      const char *ty = jstr(ji, "type", "rpc");
      d->type = strcmp(ty, "event") == 0 ? FW_IF_EVENT : (strcmp(ty, "ff") == 0 ? FW_IF_FF : FW_IF_RPC);
      const char *tr = jstr(ji, "transport", NULL);
      if (tr) d->transport = (strcmp(tr, "udp") == 0) ? FW_TR_UDP : FW_TR_TCP;
      else d->transport = (d->type == FW_IF_EVENT) ? FW_TR_UDP : FW_TR_TCP; // §11.1 默认绑定
      d->reliable = jbool(ji, "reliable", 0);
      d->max_payload = (int32_t)jint(ji, "max_payload", -1);
      d->crc = jbool(ji, "crc", 0); // 实现约定扩展：接口契约级 CRC（§9.6）
      // input：类型名数组
      const fw_value_t *in = fw_struct_get(ji, "input");
      if (in && in->type == FW_V_ARRAY && in->as.arr.len > 0) {
        d->input_n = (int)in->as.arr.len;
        d->input_names = (char **)calloc((size_t)d->input_n, sizeof(char *));
        if (!d->input_names) FAIL("out of memory");
        for (int k = 0; k < d->input_n; k++) {
          const fw_value_t *e = in->as.arr.items[k];
          d->input_names[k] = FW_STRDUP(e && e->type == FW_V_STRING ? e->as.s.ptr : "");
          if (!d->input_names[k]) FAIL("out of memory");
        }
      }
      const fw_value_t *outv = fw_struct_get(ji, "output");
      if (outv && outv->type == FW_V_STRING) {
        d->output_name = FW_STRDUP(outv->as.s.ptr);
        if (!d->output_name) FAIL("out of memory");
      }
    }
  }

  // ---- event_groups（§7.1/§11.1） ----
  const fw_value_t *groups = fw_struct_get(svc, "event_groups");
  if (groups && groups->type == FW_V_ARRAY) {
    int n = (int)groups->as.arr.len;
    s->groups = (fw_group_t *)calloc((size_t)(n ? n : 1), sizeof(fw_group_t));
    if (!s->groups) FAIL("out of memory");
    s->group_n = n;
    for (int i = 0; i < n; i++) {
      const fw_value_t *jg = groups->as.arr.items[i];
      fw_group_t *d = &s->groups[i];
      snprintf(d->name, sizeof(d->name), "%s", jstr(jg, "name", "?"));
      d->grp_id = (int)jint(jg, "grp_id", 0);
      const fw_value_t *mem = fw_struct_get(jg, "members");
      if (mem && mem->type == FW_V_ARRAY && mem->as.arr.len > 0) {
        d->members_n = (int)mem->as.arr.len;
        d->members = (uint16_t *)calloc((size_t)d->members_n, sizeof(uint16_t));
        if (!d->members) FAIL("out of memory");
        for (int k = 0; k < d->members_n; k++) {
          const fw_value_t *e = mem->as.arr.items[k];
          d->members[k] = (uint16_t)(e && e->type == FW_V_UINT ? (uint16_t)e->as.u
                                   : (e && e->type == FW_V_INT ? (uint16_t)e->as.i : 0));
        }
      }
    }
  }

  // ---- type_def：structs / enums / arrays（§11.1） ----
  const fw_value_t *td = fw_struct_get(idl, "type_def");
  if (td && td->type == FW_V_STRUCT) {
    const fw_value_t *structs = fw_struct_get(td, "structs");
    if (structs && structs->type == FW_V_STRUCT) {
      for (uint32_t i = 0; i < structs->as.st.len; i++) {
        const fw_value_t *fl = structs->as.st.vals[i];
        if (fl->type != FW_V_ARRAY) FAIL("structs[name] must be an array of fields");
        if (!def_add(s, structs->as.st.names[i], 0)) FAIL("out of memory");
        fw_typedef_t *d = &s->defs[s->def_n - 1];
        for (uint32_t k = 0; k < fl->as.arr.len; k++) {
          if (!build_field_def(d, fl->as.arr.items[k])) FAIL("invalid struct field definition");
        }
      }
    }
    const fw_value_t *enums = fw_struct_get(td, "enums");
    if (enums && enums->type == FW_V_STRUCT) {
      for (uint32_t i = 0; i < enums->as.st.len; i++) {
        const fw_value_t *je = enums->as.st.vals[i];
        if (je->type != FW_V_STRUCT) FAIL("enums[name] must be an object");
        if (!def_add(s, enums->as.st.names[i], 1)) FAIL("out of memory");
        fw_typedef_t *d = &s->defs[s->def_n - 1];
        snprintf(d->base, sizeof(d->base), "%s", jstr(je, "type", "unsigned"));
        d->size = (int)jint(je, "size", 1);
        const fw_value_t *vals = fw_struct_get(je, "values");
        if (vals && vals->type == FW_V_STRUCT) {
          int vn = (int)vals->as.st.len;
          d->vals = calloc((size_t)(vn ? vn : 1), sizeof(*d->vals));
          if (!d->vals) FAIL("out of memory");
          d->val_n = vn;
          for (int k = 0; k < vn; k++) {
            snprintf(d->vals[k].name, sizeof(d->vals[k].name), "%s", vals->as.st.names[k]);
            const fw_value_t *e = vals->as.st.vals[k];
            d->vals[k].val = (e && e->type == FW_V_UINT) ? (int64_t)e->as.u
                           : (e && e->type == FW_V_INT ? e->as.i : 0);
          }
        }
      }
    }
    const fw_value_t *arrays = fw_struct_get(td, "arrays");
    if (arrays && arrays->type == FW_V_STRUCT) {
      for (uint32_t i = 0; i < arrays->as.st.len; i++) {
        const fw_value_t *ja = arrays->as.st.vals[i];
        if (ja->type != FW_V_STRUCT) FAIL("arrays[name] must be an object");
        if (!def_add(s, arrays->as.st.names[i], 2)) FAIL("out of memory");
        fw_typedef_t *d = &s->defs[s->def_n - 1];
        snprintf(d->element_type, sizeof(d->element_type), "%s", jstr(ja, "element_type", ""));
        d->fixed_len = (int)jint(ja, "fixed_len", -1);
        d->max_len = (int)jint(ja, "max_len", -1);
      }
    }
  }
  return s;
#undef FAIL
}

// 释放字段级 owned tdesc（递归处理内联数组；共享 cache tdesc 直接返回）
static void free_owned_tdesc(fw_tdesc_t *t) {
  if (!t || !t->owned) return;
  if (t->kind == FW_T_ARRAY) free_owned_tdesc(t->element);
  free(t);
}

void fw_schema_free(fw_schema_t *s) {
  if (!s) return;
  for (int i = 0; i < s->iface_n; i++) {
    for (int k = 0; k < s->ifaces[i].input_n; k++) free(s->ifaces[i].input_names[k]);
    free(s->ifaces[i].input_names);
    free(s->ifaces[i].output_name);
  }
  free(s->ifaces);
  for (int i = 0; i < s->group_n; i++) free(s->groups[i].members);
  free(s->groups);
  // cache 持有的命名 tdesc：struct 递归释放字段级 owned tdesc + fields 数组
  for (int i = 0; i < s->cache_n; i++) {
    fw_tdesc_t *t = s->cache[i].t;
    if (t->kind == FW_T_STRUCT) {
      for (int k = 0; k < t->field_n; k++) free_owned_tdesc(t->fields[k].type);
      free(t->fields);
    } else if (t->kind == FW_T_ENUM) {
      free(t->enum_vals); // [REVIEW P3-6] enum_vals 为独立拷贝，随 cache 释放
    }
    free(t);
  }
  free(s->cache);
  for (int i = 0; i < s->def_n; i++) {
    free(s->defs[i].fields);
    free(s->defs[i].vals);
  }
  free(s->defs);
  free(s);
}
