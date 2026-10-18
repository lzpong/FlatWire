// ============================================================
// value.c —— fw_value_t 动态值模型（payload / JSON 树共用）
//
// 内存约定：所有构造函数返回堆分配对象；fw_value_free 深度释放；
// API 间传递所有权（应用 → 协议栈 → 回调/调用者）。
// ============================================================

#include "fw/fw.h"
#include "platform/platform.h"
#include <stdlib.h>

// ---- 构造 ----

fw_value_t *fw_value_null(void) {
  fw_value_t *v = (fw_value_t *)calloc(1, sizeof(fw_value_t));
  if (v) v->type = FW_V_NULL;
  return v;
}

fw_value_t *fw_value_bool(int b) {
  fw_value_t *v = fw_value_null();
  if (v) { v->type = FW_V_BOOL; v->as.b = b ? 1 : 0; }
  return v;
}

fw_value_t *fw_value_int(int64_t i) {
  fw_value_t *v = fw_value_null();
  if (v) { v->type = FW_V_INT; v->as.i = i; }
  return v;
}

fw_value_t *fw_value_uint(uint64_t u) {
  fw_value_t *v = fw_value_null();
  if (v) { v->type = FW_V_UINT; v->as.u = u; }
  return v;
}

fw_value_t *fw_value_float(double f) {
  fw_value_t *v = fw_value_null();
  if (v) { v->type = FW_V_FLOAT; v->as.f = f; }
  return v;
}

fw_value_t *fw_value_string_n(const char *s, uint32_t n) {
  fw_value_t *v = fw_value_null();
  if (!v) return NULL;
  char *p = (char *)malloc((size_t)n + 1);
  if (!p) { free(v); return NULL; }
  if (n) memcpy(p, s, n);
  p[n] = 0;
  v->type = FW_V_STRING;
  v->as.s.ptr = p;
  v->as.s.len = n;
  return v;
}

fw_value_t *fw_value_string(const char *s) {
  return fw_value_string_n(s, (uint32_t)strlen(s));
}

fw_value_t *fw_value_bytes(const uint8_t *p, uint32_t n) {
  fw_value_t *v = fw_value_null();
  if (!v) return NULL;
  uint8_t *b = (uint8_t *)malloc(n ? n : 1);
  if (!b) { free(v); return NULL; }
  if (n) memcpy(b, p, n);
  v->type = FW_V_BYTES;
  v->as.by.ptr = b;
  v->as.by.len = n;
  return v;
}

fw_value_t *fw_value_array(uint32_t reserve) {
  fw_value_t *v = fw_value_null();
  if (!v) return NULL;
  v->type = FW_V_ARRAY;
  if (reserve > 0) {
    v->as.arr.items = (fw_value_t **)calloc(reserve, sizeof(fw_value_t *));
    if (!v->as.arr.items) { free(v); return NULL; }
    v->as.arr.cap = reserve;
  }
  return v;
}

fw_value_t *fw_value_struct(void) {
  fw_value_t *v = fw_value_null();
  if (!v) return NULL;
  v->type = FW_V_STRUCT;
  return v;
}

int fw_array_push(fw_value_t *arr, fw_value_t *item) {
  if (!arr || arr->type != FW_V_ARRAY || !item) { fw_value_free(item); return FW_ERR_PARAM; }
  if (arr->as.arr.len == arr->as.arr.cap) {
    uint32_t nc = arr->as.arr.cap ? arr->as.arr.cap * 2 : 4;
    fw_value_t **ni = (fw_value_t **)realloc(arr->as.arr.items, (size_t)nc * sizeof(fw_value_t *));
    if (!ni) { fw_value_free(item); return FW_ERR_MEMORY; }
    arr->as.arr.items = ni;
    arr->as.arr.cap = nc;
  }
  arr->as.arr.items[arr->as.arr.len++] = item;
  return FW_OK;
}

int fw_struct_set(fw_value_t *st, const char *name, fw_value_t *v) {
  if (!st || st->type != FW_V_STRUCT || !name || !v) { fw_value_free(v); return FW_ERR_PARAM; }
  // 重名覆盖（保持位置）
  for (uint32_t i = 0; i < st->as.st.len; i++) {
    if (strcmp(st->as.st.names[i], name) == 0) {
      fw_value_free(st->as.st.vals[i]);
      st->as.st.vals[i] = v;
      return FW_OK;
    }
  }
  if (st->as.st.len == st->as.st.cap) {
    uint32_t nc = st->as.st.cap ? st->as.st.cap * 2 : 8;
    char **nn = (char **)realloc(st->as.st.names, (size_t)nc * sizeof(char *));
    if (!nn) { fw_value_free(v); return FW_ERR_MEMORY; }
    st->as.st.names = nn;
    fw_value_t **nv = (fw_value_t **)realloc(st->as.st.vals, (size_t)nc * sizeof(fw_value_t *));
    if (!nv) { fw_value_free(v); return FW_ERR_MEMORY; }
    st->as.st.vals = nv;
    st->as.st.cap = nc;
  }
  char *cp = FW_STRDUP(name);
  if (!cp) { fw_value_free(v); return FW_ERR_MEMORY; }
  st->as.st.names[st->as.st.len] = cp;
  st->as.st.vals[st->as.st.len] = v;
  st->as.st.len++;
  return FW_OK;
}

fw_value_t *fw_struct_get(const fw_value_t *st, const char *name) {
  if (!st || st->type != FW_V_STRUCT || !name) return NULL;
  for (uint32_t i = 0; i < st->as.st.len; i++)
    if (strcmp(st->as.st.names[i], name) == 0) return st->as.st.vals[i];
  return NULL;
}

void fw_value_free(fw_value_t *v) {
  if (!v) return;
  switch (v->type) {
    case FW_V_STRING: free(v->as.s.ptr); break;
    case FW_V_BYTES:  free(v->as.by.ptr); break;
    case FW_V_ARRAY:
      for (uint32_t i = 0; i < v->as.arr.len; i++) fw_value_free(v->as.arr.items[i]);
      free(v->as.arr.items);
      break;
    case FW_V_STRUCT:
      for (uint32_t i = 0; i < v->as.st.len; i++) {
        free(v->as.st.names[i]);
        fw_value_free(v->as.st.vals[i]);
      }
      free(v->as.st.names);
      free(v->as.st.vals);
      break;
    default: break;
  }
  free(v);
}

fw_value_t *fw_value_clone(const fw_value_t *v) {
  if (!v) return NULL;
  switch (v->type) {
    case FW_V_NULL:   return fw_value_null();
    case FW_V_BOOL:   return fw_value_bool(v->as.b);
    case FW_V_INT:    return fw_value_int(v->as.i);
    case FW_V_UINT:   return fw_value_uint(v->as.u);
    case FW_V_FLOAT:  return fw_value_float(v->as.f);
    case FW_V_STRING: return fw_value_string_n(v->as.s.ptr, v->as.s.len);
    case FW_V_BYTES:  return fw_value_bytes(v->as.by.ptr, v->as.by.len);
    case FW_V_ARRAY: {
      fw_value_t *a = fw_value_array(v->as.arr.len);
      if (!a) return NULL;
      for (uint32_t i = 0; i < v->as.arr.len; i++) {
        fw_value_t *c = fw_value_clone(v->as.arr.items[i]);
        if (!c || fw_array_push(a, c) != FW_OK) { fw_value_free(a); return NULL; }
      }
      return a;
    }
    case FW_V_STRUCT: {
      fw_value_t *s = fw_value_struct();
      if (!s) return NULL;
      for (uint32_t i = 0; i < v->as.st.len; i++) {
        fw_value_t *c = fw_value_clone(v->as.st.vals[i]);
        if (!c || fw_struct_set(s, v->as.st.names[i], c) != FW_OK) { fw_value_free(s); return NULL; }
      }
      return s;
    }
  }
  return NULL;
}
