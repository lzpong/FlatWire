// ============================================================
// schema.c —— IDL 解析（§11.1 v5.0）与类型解析（resolve 递归展开）
//
// v5.0 类型白名单（§9.2）：u8/u16/u32/u64、i8/i16/i32/i64、f32/f64/f80、
// bool、timestamp、enum（base 整型，默认 u8）、string/bytes/array（必须声明
// fixed_len 或 max_len 之一）、struct。不存在 optional / size / width。
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

// 标量类型名 → 类型种类（§9.2 白名单）；返回 0 = 非标量（类型名引用或非法）
static int scalar_type_kind(const char *t) {
  if (!t) return 0;
  if (strcmp(t, "u8") == 0)  return FW_T_U8;
  if (strcmp(t, "u16") == 0) return FW_T_U16;
  if (strcmp(t, "u32") == 0) return FW_T_U32;
  if (strcmp(t, "u64") == 0) return FW_T_U64;
  if (strcmp(t, "i8") == 0)  return FW_T_I8;
  if (strcmp(t, "i16") == 0) return FW_T_I16;
  if (strcmp(t, "i32") == 0) return FW_T_I32;
  if (strcmp(t, "i64") == 0) return FW_T_I64;
  if (strcmp(t, "f32") == 0) return FW_T_F32;
  if (strcmp(t, "f64") == 0) return FW_T_F64;
  if (strcmp(t, "f80") == 0) return FW_T_F80;
  if (strcmp(t, "bool") == 0)      return FW_T_BOOL;
  if (strcmp(t, "timestamp") == 0) return FW_T_TIMESTAMP;
  if (strcmp(t, "string") == 0)    return FW_T_STRING;
  if (strcmp(t, "bytes") == 0)     return FW_T_BYTES;
  return 0;
}

// 标量线上宽度（字节，§9.2）；string/bytes 返回 0（由 fixed_len/max_len 定界）
static int scalar_size(int kind) {
  switch (kind) {
    case FW_T_U8: case FW_T_I8: case FW_T_BOOL: return 1;
    case FW_T_U16: case FW_T_I16: return 2;
    case FW_T_U32: case FW_T_I32: case FW_T_F32: return 4;
    case FW_T_U64: case FW_T_I64: case FW_T_F64: return 8;
    case FW_T_TIMESTAMP: return 6;
    case FW_T_F80: return 10;
    default: return 0;
  }
}

// enum base 类型名 → 整型种类（§9.2：u8/u16/u32/u64/i8/i16/i32/i64）
static int enum_base_kind(const char *t) {
  int k = scalar_type_kind(t);
  switch (k) {
    case FW_T_U8: case FW_T_U16: case FW_T_U32: case FW_T_U64:
    case FW_T_I8: case FW_T_I16: case FW_T_I32: case FW_T_I64:
      return k;
    default:
      return 0;
  }
}

static int enum_base_signed(int kind) {
  return kind == FW_T_I8 || kind == FW_T_I16 || kind == FW_T_I32 || kind == FW_T_I64;
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
// 键是否存在于对象（用于拒绝 v5 已删除的属性）
static int jhas(const fw_value_t *o, const char *key) {
  return o && o->type == FW_V_STRUCT && fw_struct_get(o, key) != NULL;
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
    // 结构体：N 个字段按 schema 顺序裸排（§9.4）
    fw_tdesc_t *t = tdesc_new(FW_T_STRUCT, name, 0);
    if (!t) return NULL;
    t->field_n = def->field_n;
    t->fields = (fw_tfield_t *)calloc((size_t)(def->field_n ? def->field_n : 1), sizeof(fw_tfield_t));
    if (!t->fields) { free(t); return NULL; }
    if (!cache_add(s, name, t)) { free(t->fields); free(t); return NULL; }
    for (int i = 0; i < def->field_n; i++) {
      fw_tfield_t *f = &t->fields[i];
      snprintf(f->name, sizeof(f->name), "%s", def->fields[i].name);
      const char *ft = def->fields[i].type;
      if (strcmp(ft, "array") == 0) {
        // 内联数组字段（element_type 可为标量或类型名，§11.1/§9.4）
        fw_tdesc_t *el = tdesc_new(FW_T_ARRAY, "", 1);
        if (!el) return NULL;
        el->fixed_len = def->fields[i].fixed_len;
        el->max_len = def->fields[i].max_len;
        int ebk = scalar_type_kind(def->fields[i].element_type);
        if (ebk != 0) {
          fw_tdesc_t *ee = tdesc_new(ebk, def->fields[i].element_type, 1);
          if (!ee) { free(el); return NULL; }
          ee->size = scalar_size(ebk);
          el->element = ee;
        } else {
          el->element = resolve_depth(s, def->fields[i].element_type, depth + 1);
          if (!el->element) { free(el); return NULL; }
        }
        f->type = el;
      } else {
        int bk = scalar_type_kind(ft);
        if (bk != 0) {
          // 标量字段（宽度由类型静态确定，§9.2）
          fw_tdesc_t *bt = tdesc_new(bk, ft, 1);
          if (!bt) return NULL;
          bt->size = scalar_size(bk);
          bt->fixed_len = def->fields[i].fixed_len;
          bt->max_len = def->fields[i].max_len;
          f->type = bt;
        } else {
          // 类型名引用（struct/enum/array 定义名）
          f->type = resolve_depth(s, ft, depth + 1);
          if (!f->type) return NULL;
        }
      }
    }
    return t;
  }
  if (def->kind == 1) {
    // 枚举：线格式 = base 整型裸值（§9.2）
    fw_tdesc_t *t = tdesc_new(FW_T_ENUM, name, 0);
    if (!t) return NULL;
    t->enum_base = enum_base_signed(enum_base_kind(def->base));
    t->size = def->size;
    t->enum_n = def->val_n;
    // enum_vals 为独立拷贝：随 cache 释放
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
    // 数组类型：element_type 可为标量/struct/array/enum（任意嵌套 §9.4）
    fw_tdesc_t *t = tdesc_new(FW_T_ARRAY, name, 0);
    if (!t) return NULL;
    t->fixed_len = def->fixed_len;
    t->max_len = def->max_len;
    if (!cache_add(s, name, t)) { free(t); return NULL; }
    int bk = scalar_type_kind(def->element_type);
    if (bk != 0) {
      fw_tdesc_t *el = tdesc_new(bk, def->element_type, 1);
      if (!el) return NULL;
      el->size = scalar_size(bk);
      t->element = el;
    } else {
      t->element = resolve_depth(s, def->element_type, depth + 1);
    }
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

// 长度声明校验（§9.3）：string/bytes/array 必须且只能声明 fixed_len 或 max_len 之一
static int check_len_decl(const fw_value_t *jf, int *fixed_len, int *max_len,
                          const char *fname, const char *tname, char *err, int errsz) {
  int has_fixed = jhas(jf, "fixed_len");
  int has_max = jhas(jf, "max_len");
  if (has_fixed && has_max) {
    snprintf(err, (size_t)errsz, "field \"%s\": %s must not declare both fixed_len and max_len",
             fname, tname);
    return 0;
  }
  if (!has_fixed && !has_max) {
    snprintf(err, (size_t)errsz, "field \"%s\": %s requires fixed_len or max_len",
             fname, tname);
    return 0;
  }
  int64_t fl = has_fixed ? jint(jf, "fixed_len", -1) : -1;
  int64_t ml = has_max ? jint(jf, "max_len", -1) : -1;
  if (has_fixed && fl < 0) {
    snprintf(err, (size_t)errsz, "field \"%s\": fixed_len must be >= 0", fname);
    return 0;
  }
  if (has_max && ml < 0) {
    snprintf(err, (size_t)errsz, "field \"%s\": max_len must be >= 0", fname);
    return 0;
  }
  if (fl > INT32_MAX || ml > INT32_MAX) {
    snprintf(err, (size_t)errsz, "field \"%s\": length declaration too large", fname);
    return 0;
  }
  *fixed_len = (int)fl;
  *max_len = (int)ml;
  return 1;
}

// struct 字段原始定义录入（v5.0：拒绝 optional/size/width；强制长度声明）
static int build_field_def(fw_typedef_t *d, const fw_value_t *jf, char *err, int errsz) {
  if (jf->type != FW_V_STRUCT) {
    snprintf(err, (size_t)errsz, "struct field must be an object");
    return 0;
  }
  const char *fname = jstr(jf, "name", "?");
  const char *tname = jstr(jf, "type", NULL);
  if (!tname) {
    snprintf(err, (size_t)errsz, "field \"%s\": missing type", fname);
    return 0;
  }
  // v5.0 类型独立化：不存在 optional / size / width（§11.1）
  if (jhas(jf, "optional")) {
    snprintf(err, (size_t)errsz, "field \"%s\": optional is not supported in v5", fname);
    return 0;
  }
  if (jhas(jf, "size") || jhas(jf, "width")) {
    snprintf(err, (size_t)errsz, "field \"%s\": size/width is not supported in v5 (use type names)",
             fname);
    return 0;
  }

  int bk = scalar_type_kind(tname);
  int is_array = (strcmp(tname, "array") == 0);
  int needs_len = is_array || bk == FW_T_STRING || bk == FW_T_BYTES;

  int fixed_len = -1, max_len = -1;
  if (bk == FW_T_F80) {
    // 可选扩展：本端不支持 → IDL 加载失败（§9.2/测试 1.12）
    snprintf(err, (size_t)errsz, "field \"%s\": f80 is not supported by this implementation", fname);
    return 0;
  }
  if (needs_len) {
    if (!check_len_decl(jf, &fixed_len, &max_len, fname, tname, err, errsz)) return 0;
  } else if (jhas(jf, "fixed_len") || jhas(jf, "max_len")) {
    // 长度声明仅对 string/bytes/array 有意义（§9.3）
    snprintf(err, (size_t)errsz, "field \"%s\": fixed_len/max_len only valid for string/bytes/array",
             fname);
    return 0;
  }
  char element_type[64] = "";
  if (is_array) {
    const char *et = jstr(jf, "element_type", NULL);
    if (!et || !et[0]) {
      snprintf(err, (size_t)errsz, "field \"%s\": array requires element_type", fname);
      return 0;
    }
    if (strcmp(et, "array") == 0) {
      snprintf(err, (size_t)errsz,
               "field \"%s\": nested array must reference a named array type", fname);
      return 0;
    }
    snprintf(element_type, sizeof(element_type), "%s", et);
  }

  if (d->field_n == d->field_cap) {
    int nc = d->field_cap ? d->field_cap * 2 : 8;
    void *np = realloc(d->fields, (size_t)nc * sizeof(*d->fields));
    if (!np) {
      snprintf(err, (size_t)errsz, "out of memory");
      return 0;
    }
    d->fields = np;
    d->field_cap = nc;
  }
  // fw_typedef_t.fields 的匿名结构体成员：使用同布局占位类型访问
  typedef struct { char name[64]; char type[64]; char element_type[64];
                   int fixed_len, max_len; } field_t;
  field_t *f = &((field_t *)d->fields)[d->field_n];
  memset(f, 0, sizeof(*f));
  snprintf(f->name, sizeof(f->name), "%s", fname);
  snprintf(f->type, sizeof(f->type), "%s", tname);
  snprintf(f->element_type, sizeof(f->element_type), "%s", element_type);
  f->fixed_len = fixed_len;
  f->max_len = max_len;
  d->field_n++;
  return 1;
}

// enum 定义录入（base 白名单 + 值域/重复校验，§9.2/§11.1）
static int build_enum_def(fw_typedef_t *d, const fw_value_t *je, const char *ename,
                          char *err, int errsz) {
  // v5.0：enum 使用 base 声明基类型，无 type/size
  if (jhas(je, "type")) {
    snprintf(err, (size_t)errsz, "enum \"%s\": use base instead of type", ename);
    return 0;
  }
  if (jhas(je, "size")) {
    snprintf(err, (size_t)errsz, "enum \"%s\": size is not supported in v5 (use base)", ename);
    return 0;
  }
  const char *base = jstr(je, "base", "u8");
  int bk = enum_base_kind(base);
  if (!bk) {
    snprintf(err, (size_t)errsz, "enum \"%s\": invalid base \"%s\"", ename, base);
    return 0;
  }
  snprintf(d->base, sizeof(d->base), "%s", base);
  d->size = scalar_size(bk);

  const fw_value_t *vals = fw_struct_get(je, "values");
  if (!vals || vals->type != FW_V_STRUCT) {
    snprintf(err, (size_t)errsz, "enum \"%s\": values must be an object", ename);
    return 0;
  }
  int vn = (int)vals->as.st.len;
  d->vals = calloc((size_t)(vn ? vn : 1), sizeof(*d->vals));
  if (!d->vals) {
    snprintf(err, (size_t)errsz, "out of memory");
    return 0;
  }
  d->val_n = vn;
  for (int k = 0; k < vn; k++) {
    snprintf(d->vals[k].name, sizeof(d->vals[k].name), "%s", vals->as.st.names[k]);
    const fw_value_t *e = vals->as.st.vals[k];
    if (!e || (e->type != FW_V_INT && e->type != FW_V_UINT)) {
      snprintf(err, (size_t)errsz, "enum \"%s\": value \"%s\" must be an integer",
               ename, vals->as.st.names[k]);
      return 0;
    }
    int64_t v = (e->type == FW_V_INT) ? e->as.i : (int64_t)e->as.u;
    // 值域校验（按 base 宽度/符号）
    if (enum_base_signed(bk)) {
      int64_t lo, hi;
      if (d->size == 8) { lo = INT64_MIN; hi = INT64_MAX; }
      else {
        uint64_t bits = (uint64_t)d->size * 8;
        hi = (int64_t)(((uint64_t)1 << (bits - 1)) - 1);
        lo = -(int64_t)((uint64_t)1 << (bits - 1));
      }
      if (v < lo || v > hi) {
        snprintf(err, (size_t)errsz, "enum \"%s\": value \"%s\" out of base range",
                 ename, vals->as.st.names[k]);
        return 0;
      }
    } else {
      if (d->size < 8 && (uint64_t)v > (((uint64_t)1 << (8 * d->size)) - 1)) {
        snprintf(err, (size_t)errsz, "enum \"%s\": value \"%s\" out of base range",
                 ename, vals->as.st.names[k]);
        return 0;
      }
      if (v < 0) {
        snprintf(err, (size_t)errsz, "enum \"%s\": negative value with unsigned base",
                 ename);
        return 0;
      }
    }
    // 重复值校验
    for (int j = 0; j < k; j++) {
      if (d->vals[j].val == v) {
        snprintf(err, (size_t)errsz, "enum \"%s\": duplicate value %lld",
                 ename, (long long)v);
        return 0;
      }
    }
    d->vals[k].val = v;
  }
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
      d->crc = jbool(ji, "crc", 0); // 缺省关闭：仅 "crc": true 时附加 2B CRC（§9.6）
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
  char ferr[128];
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
          if (!build_field_def(d, fl->as.arr.items[k], ferr, sizeof(ferr))) FAIL(ferr);
        }
      }
    }
    const fw_value_t *enums = fw_struct_get(td, "enums");
    if (enums && enums->type == FW_V_STRUCT) {
      for (uint32_t i = 0; i < enums->as.st.len; i++) {
        const fw_value_t *je = enums->as.st.vals[i];
        const char *ename = enums->as.st.names[i];
        if (je->type != FW_V_STRUCT) FAIL("enums[name] must be an object");
        if (!def_add(s, ename, 1)) FAIL("out of memory");
        fw_typedef_t *d = &s->defs[s->def_n - 1];
        if (!build_enum_def(d, je, ename, ferr, sizeof(ferr))) FAIL(ferr);
      }
    }
    const fw_value_t *arrays = fw_struct_get(td, "arrays");
    if (arrays && arrays->type == FW_V_STRUCT) {
      for (uint32_t i = 0; i < arrays->as.st.len; i++) {
        const fw_value_t *ja = arrays->as.st.vals[i];
        const char *aname = arrays->as.st.names[i];
        if (ja->type != FW_V_STRUCT) FAIL("arrays[name] must be an object");
        // v5.0：arrays 条目不再声明 "type":"array"
        if (jhas(ja, "type")) {
          snprintf(ferr, sizeof(ferr), "array \"%s\": type field is not supported in v5", aname);
          FAIL(ferr);
        }
        const char *et = jstr(ja, "element_type", NULL);
        if (!et || !et[0]) {
          snprintf(ferr, sizeof(ferr), "array \"%s\": missing element_type", aname);
          FAIL(ferr);
        }
        int fixed_len = -1, max_len = -1;
        char lerr[128];
        if (!check_len_decl(ja, &fixed_len, &max_len, aname, "array", lerr, sizeof(lerr))) {
          FAIL(lerr);
        }
        if (!def_add(s, aname, 2)) FAIL("out of memory");
        fw_typedef_t *d = &s->defs[s->def_n - 1];
        snprintf(d->element_type, sizeof(d->element_type), "%s", et);
        d->fixed_len = fixed_len;
        d->max_len = max_len;
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
      free(t->enum_vals); // enum_vals 为独立拷贝，随 cache 释放
    } else if (t->kind == FW_T_ARRAY) {
      // 数组类型的标量元素为字段级独立分配（resolve 内创建，owned=1）
      free_owned_tdesc(t->element);
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
