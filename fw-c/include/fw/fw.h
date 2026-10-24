// ============================================================
// fw.h —— FlatWire Protocol v5.0 C 实现公共头（唯一公共契约）
//
// 应用视角 API（§13）+ 内部模块契约（codec/frame/strm/entries 等，
// 供单元测试与模块间共享）。规范唯一事实来源：
//   《FlatWire Protocol (FW) Design.v5.md》
// 行为基准：implementations/fw-nodejs（同名模块逻辑交叉对照）
// ============================================================

#ifndef FW_H
#define FW_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// 错误码（§12）
// ============================================================

// ---- RST 错误码总表（§12.1 / §12.2） ----
#define FW_RST_VIOLATION       0x00  // 协议违规（帧头一致性校验失败）
#define FW_RST_BAD_REQUEST     0x20  // Bad Request（契约违约/CRC 失败/控制帧格式错误）
#define FW_RST_VERSION         0x22  // VER 与本端不一致
#define FW_RST_TOO_LARGE       0x23  // Payload 超 max_payload_len（仅 UDP，帧级）
#define FW_RST_NOT_FOUND       0x24  // SvcID/IfID 无处理者 / SD Not Found
#define FW_RST_METHOD          0x25  // Code 不支持
#define FW_RST_FRAME_TIMEOUT   0x26  // TCP 半帧超时（当前帧作废）
#define FW_RST_INTERNAL        0x30  // 处理逻辑执行异常
#define FW_RST_NOT_IMPL        0x31  // 功能未实现
#define FW_RST_UNAVAILABLE     0x33  // 服务临时不可用

// ---- 应用层返回码（fw_* API） ----
#define FW_OK                   0
#define FW_ERR_PARAM           -1   // 参数非法
#define FW_ERR_CONFIG          -2   // 配置校验失败（附录 A 约束，5.10）
#define FW_ERR_MEMORY          -3   // 内存分配失败
#define FW_ERR_BUSY            -4   // 实例已注册（7.9）/ 同步调用重入
#define FW_ERR_TIMEOUT         -5   // RequestTimeout（§1.3 调用唯一终态）
#define FW_ERR_NOT_FOUND       -6   // 服务/实例未发现或不可用（对应 0x24）
#define FW_ERR_IDL_UNAVAILABLE -7   // IDL 库缺失且无法自动拉取
#define FW_ERR_GETIDL          -8   // GetIDL 查询失败（0x24/0x20/超时/断连）
#define FW_ERR_ENCODE          -9   // 编码失败（IDL 级契约违约）
#define FW_ERR_DECODE          -10  // 解码失败
#define FW_ERR_RST             -11  // 对端 RST（fw_result_t.rst_code 为具体码）
#define FW_ERR_CONN            -12  // 连接建立失败/断开
#define FW_ERR_IO              -13  // 文件/socket IO 错误
#define FW_ERR_UNSUPPORTED     -14  // 不支持（float80/整型 size>8）
#define FW_ERR_STATE           -15  // 状态机不允许的操作

// ---- 解码错误细分（codec 层负值，统一映射 RST(0x20)，§9.1/§9.3/§12.1） ----
#define FW_DEC_UNEXPECTED_NULL      -101  // 值为 null（v5 无 null 编码，字段必填）
#define FW_DEC_INVALID_BOOL         -102  // bool 非 0x00/0x01（§9.2）
#define FW_DEC_UNSUPPORTED_FLOAT    -103  // f80 可选扩展本端不支持
#define FW_DEC_UNDERRUN             -108  // 字段字节不足（数据截断）
#define FW_DEC_MAXLEN               -109  // max_len 超限（IDL 级 → 0x20）
#define FW_DEC_FIXEDLEN             -110  // fixed_len 不符
#define FW_DEC_RANGE                -111  // 编码值超出类型值域
#define FW_DEC_CRC                  -112  // CRC-16 校验失败（§9.6）

// RST 错误码名称表（§12.4 日志 Msg 字段）
const char *fw_rst_name(int code);

// ============================================================
// 日志（§12.4 格式；级别全局共享——C 单进程多栈共用级别，README 偏差说明）
// ============================================================
enum { FW_LOG_ERROR = 0, FW_LOG_WARN = 1, FW_LOG_INFO = 2, FW_LOG_DEBUG = 3 };

void fw_log_set_level(int level);
int  fw_log_get_level(void);
// 普通模块日志：[模块名] 描述: 关键参数
void fw_log(int level, const char *module, const char *fmt, ...);
// 帧日志（§12.4）：[svc,if,inst] dir,addr strm, Code=0xXX, Msg=...
void fw_log_frame(int level, uint16_t svc, uint16_t if_id, uint8_t inst, uint8_t strm,
                  const char *dir, const char *addr, int code, const char *msg);

// ============================================================
// 动态缓冲与时间
// ============================================================
typedef struct { uint8_t *p; size_t len, cap; } fw_buf_t;
void fw_buf_init(fw_buf_t *b);
void fw_buf_free(fw_buf_t *b);
int  fw_buf_put(fw_buf_t *b, const void *data, size_t n);
int  fw_buf_put_u8(fw_buf_t *b, uint8_t v);
int  fw_buf_put_u16be(fw_buf_t *b, uint16_t v);
int  fw_buf_put_u32be(fw_buf_t *b, uint32_t v);

// 单调毫秒时钟（平台层：QueryPerformanceCounter / clock_gettime）
int64_t fw_now_ms(void);

// ============================================================
// 值模型 fw_value_t（payload / JSON 树共用）
//
// payload 语义（§13）：应用传入/接收的结构化字段值集合，编解码由
// 协议栈按本地 IDL 动态执行。struct 值 = 有序 name→value 集合。
// ============================================================
typedef enum {
  FW_V_NULL = 0, FW_V_BOOL, FW_V_INT, FW_V_UINT, FW_V_FLOAT,
  FW_V_STRING, FW_V_BYTES, FW_V_ARRAY, FW_V_STRUCT
} fw_vtype_t;

typedef struct fw_value fw_value_t;
struct fw_value {
  fw_vtype_t type;
  union {
    int      b;                                       // FW_V_BOOL
    int64_t  i;                                       // FW_V_INT
    uint64_t u;                                       // FW_V_UINT（含 timestamp/enum 整数值）
    double   f;                                       // FW_V_FLOAT
    struct { char *ptr; uint32_t len; } s;            // FW_V_STRING（len=字节数）
    struct { uint8_t *ptr; uint32_t len; } by;        // FW_V_BYTES
    struct { fw_value_t **items; uint32_t len, cap; } arr;   // FW_V_ARRAY
    struct { char **names; fw_value_t **vals; uint32_t len, cap; } st; // FW_V_STRUCT
  } as;
};

// 构造助手（全部返回堆分配值，失败返回 NULL；所有权按 API 约定转移）
fw_value_t *fw_value_null(void);
fw_value_t *fw_value_bool(int v);
fw_value_t *fw_value_int(int64_t v);
fw_value_t *fw_value_uint(uint64_t v);
fw_value_t *fw_value_float(double v);
fw_value_t *fw_value_string(const char *s);               // NUL 结尾 UTF-8
fw_value_t *fw_value_string_n(const char *s, uint32_t n);
fw_value_t *fw_value_bytes(const uint8_t *p, uint32_t n);  // 拷贝
fw_value_t *fw_value_array(uint32_t reserve);              // 空 array
fw_value_t *fw_value_struct(void);                         // 空 struct
int  fw_array_push(fw_value_t *arr, fw_value_t *item);     // 转移所有权
int  fw_struct_set(fw_value_t *st, const char *name, fw_value_t *v); // 转移所有权（重名覆盖）
fw_value_t *fw_struct_get(const fw_value_t *st, const char *name);   // 借用（不移交）
void fw_value_free(fw_value_t *v);                          // 深度释放
fw_value_t *fw_value_clone(const fw_value_t *v);            // 深拷贝

// ============================================================
// 迷你 JSON（仅够解析 IDL schema：对象/数组/字符串/数字/bool/null）
// ============================================================
// 解析 JSON 文本 → fw_value 树（object→STRUCT / array→ARRAY / 整数→UINT·INT /
// 浮点→FLOAT）。失败返回 NULL 并填 err。树用 fw_value_free 释放。
fw_value_t *fw_json_parse(const char *text, size_t len, char *err, int errsz);

// ============================================================
// 配置（附录 A：参数默认值，时间一律 ms）
// ============================================================
typedef struct {
  uint16_t     port;                  // 5400
  const char  *multicast_ipv4;        // "224.0.1.187"
  const char  *bind_address;          // NULL=全接口；同机演示绑回环（127.0.0.x）
  uint32_t     period_ms;             // 2000（Offer/Subscribe 保活周期）
  uint32_t     ttl_ms;                // 4000（>= 2*period_ms，<= 255000）
  uint32_t     response_timeout_ms;   // 2000（调用/GetIDL 查询唯一终态）
  uint32_t     retransmit_interval_ms;// 200
  int          retransmit_max;        // 3（不含首次）
  uint32_t     tcp_frame_timeout_ms;  // 5000（半帧超时；丢弃模式兜底 = 2×）
  uint32_t     heartbeat_period_ms;   // 30000（仅 TCP）
  uint32_t     max_payload_len;       // 1400（仅 UDP，帧级）
  uint8_t      ver;                   // 0（协议版本 VER）
  const char  *idl_dir;               // "./idl"（IDL 库文件夹，§11.1）
  int          tcp_enabled;           // 1=TCP 监听（客户端角色栈可关，同机双栈演示）
  int          log_level;             // FW_LOG_*
} fw_config_t;

void fw_config_defaults(fw_config_t *cfg);
// 配置校验（附录 A 约束列）；失败返回非 0 并填 err（5.10）
int  fw_config_validate(const fw_config_t *cfg, char *err, int errsz);

// ============================================================
// 帧格式（§3）
// ============================================================
// TYP 传输类型（§3.7）
#define FW_TYP_NON 0
#define FW_TYP_CON 1
#define FW_TYP_ACK 2
#define FW_TYP_RST 3

// Code（§3.4；CTR 区分数据帧/控制帧两个码空间）
#define FW_CODE_REQUEST    0x01  // 数据帧 Request
#define FW_CODE_FF         0x02  // 数据帧 Fire-Forget
#define FW_CODE_NOTIFY     0x03  // 数据帧 Notification
#define FW_CODE_OK         0x10  // 数据帧 Response 唯一成功码
#define FW_CODE_SD_OFFER   0x01  // 控制帧 Offer（TTL=0=停止提供）
#define FW_CODE_SD_FIND    0x02  // 控制帧 Find
#define FW_CODE_SD_SUB     0x03  // 控制帧 Subscribe
#define FW_CODE_SD_GETIDL  0x04  // 控制帧 GetIDL（仅 TCP 单播）
#define FW_CODE_SD_SUBACK  0x10  // 控制帧 Subscribe 确认
#define FW_CODE_SD_IDLRESP 0x11  // 控制帧 GetIDL 响应（回显 StrmID）

// REN=1 帧固定形态（§3.6）
typedef struct {
  uint8_t  ctr, ren, ver, msk, typ, code;
  uint16_t svc_id, if_id;
  uint8_t  inst_id, strm_id;
  const uint8_t *payload;   // 已按 MSK 还原的数据
  uint32_t payload_len;
} fw_frame_t;

// 帧编码描述（encodeFrame 输入）
typedef struct {
  uint8_t  ctr, ren, ver, msk, typ, code;
  uint16_t svc_id, if_id;
  uint8_t  inst_id, strm_id;
  const uint8_t *payload;
  uint32_t payload_len;
  const uint8_t *mask_key;  // msk=1 时：NULL=运行时随机生成（§10 每帧随机 4B）
} fw_frame_desc_t;

// 计算帧总字节数（8 + PLB + MSK4 + payload）
uint32_t fw_frame_size(const fw_frame_desc_t *d);
// 编码帧到 buf（cap 不足返回 0）；返回写入字节数
uint32_t fw_frame_encode(uint8_t *buf, uint32_t cap, const fw_frame_desc_t *d);
// 计算 PLB（§3.2：len=0 → 0；否则最小可表示字节数 1~7）
int fw_calc_plb(uint64_t len);

// ---- 解析（§4.3 十步 / §4.2 UDP 报文） ----
typedef enum {
  FW_PARSE_NEED_MORE = 0,  // 字节不足（TCP 等待）
  FW_PARSE_SILENT,         // 组播帧静默丢弃
  FW_PARSE_INVALID,        // 校验失败 → 需回 RST
  FW_PARSE_OK              // 帧头解析成功
} fw_parse_state_t;

typedef struct {
  uint8_t ver;             // 本端协议版本
  uint32_t max_payload_len;// UDP 帧级上限
  int is_udp;              // 传输绑定相关校验（TCP 禁 CON/ACK、UDP 禁 GetIDL）
  int multicast_like;      // 组播启发式（Offer/Find 操作码违规 → 静默丢弃）
} fw_parse_opts_t;

// 帧头解析结果（fw_parse_header / fw_parse_datagram 输出）
typedef struct {
  fw_parse_state_t state;
  // OK 时有效（完整帧头 + 声明信息）：
  uint8_t  ver, ctr, ren, msk, plb, typ, code;
  uint16_t svc_id, if_id;
  uint8_t  inst_id, strm_id;
  uint32_t header_len;      // 8 + plb + (msk?4:0)
  uint32_t payload_len;
  uint32_t expected_total;  // header_len + payload_len
  const uint8_t *mask_key;  // msk=1 时指向 buf 内 4B
  // INVALID 时有效：待回 RST 的回显字段（§5.4）
  uint8_t  rst_ctr;
  uint16_t rst_svc, rst_if;
  uint8_t  rst_inst, rst_strm;
  int      rst_code;
} fw_head_res_t;

// §4.3 步骤 1~6：解析帧头（buf[offset..] 至 Masking Key）
fw_parse_state_t fw_parse_header(const uint8_t *buf, size_t avail, size_t offset,
                                 const fw_parse_opts_t *o, fw_head_res_t *out);

// §4.2 + §4.3：UDP 单报文解析。返回 FW_PARSE_OK 时 frame 填充（payload 就地 XOR
// 还原，仅本次处理内有效）；INVALID 时 rst 填充；其余静默丢弃。
fw_parse_state_t fw_parse_datagram(uint8_t *buf, size_t len, const fw_parse_opts_t *o,
                                   fw_frame_t *frame, fw_head_res_t *rst);

// 从（可能不完整的）帧头字节尽力提取回显字段（§5.4 RST 回显）
void fw_head_echo_partial(const uint8_t *buf, size_t avail, int ctr,
                          uint16_t *svc, uint16_t *if_id, uint8_t *inst, uint8_t *strm);

// ---- TCP 流式解析器（§4.1：分包保存/粘包逐帧/半帧两阶段/丢弃模式） ----
typedef struct fw_stream_parser fw_stream_parser_t;
typedef void (*fw_sp_frame_cb)(void *ud, const fw_frame_t *f);
typedef void (*fw_sp_rst_cb)(void *ud, int code, const fw_head_res_t *echo);
typedef void (*fw_sp_drop_cb)(void *ud);

struct fw_stream_parser {
  uint8_t *buf;              // 待解析缓冲（分包不丢弃已读字节，§4.1）
  size_t   len, cap;
  uint8_t  ver;              // 本端协议版本（§4.3 步骤 1 校验）
  int      receiving;        // 有帧正在接收（帧首字节已到达且未交付）
  int      header_done;      // 当前帧帧头已收齐（≥8B 含 Length/Mask）
  fw_head_res_t head;        // 当前帧头信息（header_done 时有效）
  uint32_t received;         // 当前帧已收总字节
  int      drop_mode;        // 丢弃模式（§4.1 阶段二）
  uint32_t drop_remaining;   // 剩余待丢弃字节 R = L − 已收
  int64_t  drop_last_ms;     // 丢弃模式每收字节刷新计时（兜底超时判定）
  uint8_t *scratch;          // 交付暂存（粘包下 on_frame 回调前解析缓冲会被
  size_t   scratch_cap;      //   memmove 挪动，payload 须拷贝解耦后再消费）
  // 回调（feed 过程中触发）
  void *ud;
  fw_sp_frame_cb on_frame;
  fw_sp_rst_cb   on_rst;
  fw_sp_drop_cb  on_drop_complete;
};

void fw_sp_init(fw_stream_parser_t *p);
void fw_sp_free(fw_stream_parser_t *p);
// 返回 FW_OK / FW_ERR_MEMORY（realloc 失败显式上报，原 void 静默丢 chunk）
int  fw_sp_feed(fw_stream_parser_t *p, const uint8_t *chunk, size_t n);
int  fw_sp_receiving(const fw_stream_parser_t *p);   // receiving || drop_mode
int  fw_sp_header_complete(const fw_stream_parser_t *p);
void fw_sp_frame_info(const fw_stream_parser_t *p, uint32_t *total, uint32_t *recv);
// 进入丢弃模式（帧头完整、Payload 不完整；§4.1 阶段二），返回剩余丢弃字节数
uint32_t fw_sp_enter_drop_mode(fw_stream_parser_t *p, int64_t now_ms);

// ============================================================
// CRC-16/CCITT-FALSE（§9.6 唯一变体）
// poly=0x1021 / init=0xFFFF / refin=false / refout=false / xorout=0
// 自检：CRC("123456789") = 0x29B1
// ============================================================
uint16_t fw_crc16(const uint8_t *buf, size_t len);
int      fw_crc16_selfcheck(void);

// ============================================================
// §9 结构化数据字段编解码（schema 驱动）
// ============================================================
// 规范化类型种类（fw_tdesc_t.kind；v5.0 裸字节编码类型白名单 §9.2）
#define FW_T_U8        1
#define FW_T_U16       2
#define FW_T_U32       3
#define FW_T_U64       4
#define FW_T_I8        5
#define FW_T_I16       6
#define FW_T_I32       7
#define FW_T_I64       8
#define FW_T_F32       9
#define FW_T_F64      10
#define FW_T_F80      11   // x87 80bit 可选扩展（本实现不支持 → IDL 加载失败）
#define FW_T_BOOL     12
#define FW_T_TIMESTAMP 13
#define FW_T_ENUM     14
#define FW_T_STRING   15
#define FW_T_BYTES    16
#define FW_T_ARRAY    17
#define FW_T_STRUCT   18

typedef struct fw_tdesc fw_tdesc_t;
typedef struct fw_tfield fw_tfield_t;

struct fw_tdesc {
  int  kind;              // FW_T_*（§9.2 白名单）
  char name[64];
  int  size;              // 线上宽度（字节）：整型 1/2/4/8、float 4/8/10、bool 1、timestamp 6、enum=base 宽度
  int  fixed_len;         // string/bytes/array：N=定长裸排（无长度前缀）；-1=未声明
  int  max_len;           // string/bytes/array：N=变长（w(N) 字节长度前缀）；-1=未声明
  int  enum_base;         // enum 基类型符号：0=无符号 / 1=有符号（§9.2）
  struct { char name[32]; int64_t val; } *enum_vals; int enum_n; // 名称→整数映射
  fw_tdesc_t *element;    // array 元素类型（指向共享 tdesc，不随本体释放）
  fw_tfield_t *fields;    // struct 字段列表（按 schema 顺序裸排 §9.4）
  int field_n;
  int owned;              // 内存归属：1=字段级独立分配（随引用者释放）；0=cache 共享
};

// 结构体字段（v5.0：全部必填，无 optional、无 null 编码 §9.1）
struct fw_tfield {
  char name[64];
  fw_tdesc_t *type;       // 规范化类型（schema 持有）
};

// 接口类型（IDL interface.type）
#define FW_IF_RPC   0
#define FW_IF_FF    1
#define FW_IF_EVENT 2
// 传输绑定（IDL interface.transport；省略按类型默认 rpc/ff=tcp event=udp）
#define FW_TR_TCP 0
#define FW_TR_UDP 1

typedef struct {
  char     name[64];
  uint16_t if_id;
  int      type;          // FW_IF_*
  int      transport;     // FW_TR_*
  int      reliable;      // event：UDP 上 CON 重传（§11.1）
  int32_t  max_payload;   // 接口级单帧 Payload 上限（-1=未声明，TCP/UDP 均适用 §2）
  int      crc;           // 接口契约级 CRC（§9.6 "CRC 作为服务契约约定"的实现落点）
  char   **input_names;   // input 类型名数组（可为 0 个）
  int      input_n;
  char    *output_name;   // output 单类型名（NULL=无）
} fw_iface_t;

typedef struct {
  char     name[64];
  int      grp_id;        // 1~255
  uint16_t *members;      // 组内 event if_id 列表
  int      members_n;
} fw_group_t;

// 原始类型定义表条目（structs/enums/arrays 统一存放，resolve 递归展开）
typedef struct {
  char name[64];
  int  kind;            // 0=struct 1=enum 2=array
  // struct 字段原始定义（v5.0：无 optional/size/width）
  struct {
    char name[64]; char type[64]; char element_type[64];
    int fixed_len, max_len;
  } *fields; int field_n, field_cap;
  // enum（base 为整型基类型名，默认 u8，§9.2）
  char base[16]; int size;
  struct { char name[32]; int64_t val; } *vals; int val_n;
  // array
  char element_type[64];
  int  fixed_len, max_len;
} fw_typedef_t;

// IDL Schema（§11.1 语法解析产物）
typedef struct fw_schema {
  uint16_t svc_id;
  uint8_t  major_ver, minor_ver;
  char     name[64];
  fw_iface_t *ifaces; int iface_n;
  fw_group_t *groups; int group_n;
  fw_typedef_t *defs; int def_n, def_cap;
  // resolve 缓存（name → tdesc）
  struct { char name[64]; fw_tdesc_t *t; } *cache; int cache_n, cache_cap;
} fw_schema_t;

// 从 IDL JSON 树构建 schema（失败返回 NULL 并填 err）；idl 所有权不移交
fw_schema_t *fw_schema_build(const fw_value_t *idl, char *err, int errsz);
void fw_schema_free(fw_schema_t *s);
// 按名称取规范化类型（struct/array/enum 递归展开）；失败 NULL
fw_tdesc_t *fw_schema_resolve(fw_schema_t *s, const char *name);
fw_iface_t *fw_schema_iface(const fw_schema_t *s, uint16_t if_id);
const uint16_t *fw_schema_group_members(const fw_schema_t *s, int grp_id, int *out_n);

// ---- 接口级 payload 编解码（§13 payload 语义） ----
// direction：0=input / 1=output（事件推送按 output 编解码，§11.1）
// 编码：成功返回 FW_OK 并填充 buf（追加）；IDL 级违约返回 FW_DEC_* / FW_ERR_*
int fw_encode_payload(const fw_schema_t *s, const fw_iface_t *iface, int direction,
                      const fw_value_t *payload, fw_buf_t *out, char *err, int errsz);
// 解码：成功返回 FW_OK（*out 所有权归调用者）；容忍末尾新增字段（§9.4）
int fw_decode_payload(const fw_schema_t *s, const fw_iface_t *iface, int direction,
                      const uint8_t *buf, uint32_t len, fw_value_t **out, char *err, int errsz);

// 单字段编解码（单测/嵌套复用）
int fw_encode_field(const fw_tdesc_t *t, const fw_value_t *v, fw_buf_t *out);
int fw_decode_field(const fw_tdesc_t *t, const uint8_t *buf, size_t len, size_t *pos,
                    fw_value_t **out);

// MSK 掩码（§10：encoded[i]=payload[i]^key[i%4]，编解码对称）
void fw_mask_xor(uint8_t *data, uint32_t len, const uint8_t key[4]);

// ============================================================
// StrmID 管理（§6：分配/冷却/回绕）
// ============================================================
typedef struct fw_strm_mgr fw_strm_mgr_t;
fw_strm_mgr_t *fw_strm_new(void);
void fw_strm_free(fw_strm_mgr_t *m);
// 返回 StrmID（1~254），失败 -1（池耗尽）
int  fw_strm_alloc_client(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst);
int  fw_strm_alloc_server(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst);
int  fw_strm_alloc_ctrl(fw_strm_mgr_t *m, const char *peer);  // 订阅会话+GetIDL 同池（§6.3）
void fw_strm_release_client(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst, int strm);
void fw_strm_release_server(fw_strm_mgr_t *m, const char *peer, uint16_t svc, uint8_t inst, int strm);
void fw_strm_release_ctrl(fw_strm_mgr_t *m, const char *peer, int strm);
// 收到 REN=1：清除该对端（peer 前缀，如 "1.2.3.4:"）全部序列（§3.6/§6.3）
void fw_strm_reset_peer(fw_strm_mgr_t *m, const char *peer_prefix);

// ============================================================
// SD Entry 编解码（§7.1；多字节整数大端）
// ============================================================
typedef struct { uint16_t svc_id; uint8_t inst_id, major_ver, minor_ver, ttl; } fw_offer_entry_t;
typedef struct { uint16_t svc_id; uint8_t inst_id, major_ver; } fw_find_entry_t;
typedef struct { uint16_t svc_id, if_id; uint8_t inst_id, grp_id, ttl; } fw_sub_entry_t;
typedef struct { uint16_t svc_id; uint8_t major_ver; } fw_getidl_entry_t;

#define FW_ENTRY_OFFER 6
#define FW_ENTRY_FIND  4
#define FW_ENTRY_SUB   7
#define FW_ENTRY_GETIDL 3

uint32_t fw_encode_offer_entries(uint8_t *buf, uint32_t cap, const fw_offer_entry_t *e, int n);
int      fw_decode_offer_entries(const uint8_t *buf, uint32_t len, fw_offer_entry_t *out, int max);
uint32_t fw_encode_find_entries(uint8_t *buf, uint32_t cap, const fw_find_entry_t *e, int n);
int      fw_decode_find_entries(const uint8_t *buf, uint32_t len, fw_find_entry_t *out, int max);
uint32_t fw_encode_sub_entries(uint8_t *buf, uint32_t cap, const fw_sub_entry_t *e, int n);
int      fw_decode_sub_entries(const uint8_t *buf, uint32_t len, fw_sub_entry_t *out, int max);
uint32_t fw_encode_getidl_entry(uint8_t *buf, uint32_t cap, const fw_getidl_entry_t *e);
// 返回 0 表示 ≠3B（→ RST(0x20) §7.2）
int      fw_decode_getidl_entry(const uint8_t *buf, uint32_t len, fw_getidl_entry_t *out);

// ============================================================
// IDL 库（§11.1：加载/落盘/版本并存；GetIDL 响应直接回原文 jsonText）
// ============================================================
typedef struct fw_idlstore fw_idlstore_t;

typedef struct {
  const fw_schema_t *schema;
  const char *json_text;   // IDL JSON 原文（GetIDL 响应直接回发，§7.2）
  const char *file_name;
  int persisted;           // 落盘成功标记（失败降级内存，§7.2）
} fw_idl_entry_t;

fw_idlstore_t  *fw_idl_new(void);
void            fw_idl_free(fw_idlstore_t *s);
int             fw_idl_load_all(fw_idlstore_t *s, const char *dir); // 启动扫描（§11.1）
int             fw_idl_has(fw_idlstore_t *s, uint16_t svc, uint8_t major);
fw_idl_entry_t *fw_idl_get(fw_idlstore_t *s, uint16_t svc, uint8_t major);
fw_idl_entry_t *fw_idl_get_highest(fw_idlstore_t *s, uint16_t svc);
int             fw_idl_save(fw_idlstore_t *s, uint16_t svc, uint8_t major, const char *json);

// ============================================================
// 协议栈（§13 应用 API；句柄式不透明指针）
// ============================================================
typedef struct fw_stack fw_stack_t;

// 结果描述（fw_stack_last_error 返回最近一次错误的详情）
typedef struct {
  int  code;      // FW_* 返回码
  int  rst_code;  // 对端 RST 码（无则 0）
  char msg[192];
} fw_result_t;

// ---- 回调 ----
// 服务端 rpc 处理（§13.3）：返回 FW_OK 且 *out 置响应值（所有权转移协议栈）；
// 返回非 0 → RST(0x30) Internal Error
typedef int  (*fw_request_cb)(void *ud, uint16_t if_id, const fw_value_t *payload, fw_value_t **out);
// 服务端 ff 处理（无返回值）
typedef void (*fw_ff_cb)(void *ud, uint16_t if_id, const fw_value_t *payload);
// 客户端事件回调（payload 所有权转移给回调，用完 fw_value_free）
// 客户端事件回调（payload 所有权转移给回调，用完 fw_value_free）
typedef void (*fw_event_cb)(void *ud, uint16_t svc_id, uint16_t if_id, fw_value_t *payload);
// 异步调用回调（resp 成功时非 NULL 所有权转移；失败 NULL + err/msg）
typedef void (*fw_call_cb)(void *ud, fw_value_t *resp, int err, const char *msg);

typedef struct {
  fw_request_cb on_request;
  fw_ff_cb      on_fire_forget;
  void         *ud;
} fw_handlers_t;

// 在线信息（find_service 返回，§13.2：不返回接口列表）
typedef struct {
  char     address[48];
  uint16_t port;
  uint8_t  major_ver, minor_ver;
} fw_svc_info_t;

// ---- 生命周期 ----
int  fw_stack_init(fw_stack_t **out, const fw_config_t *cfg);   // 校验配置并分配（不占端口）
int  fw_stack_start(fw_stack_t *st);   // 加载 IDL 库 → 开 UDP/TCP → Find 预热（§2）
int  fw_stack_poll(fw_stack_t *st, int timeout_ms);  // 单轮事件循环（非阻塞 poll + 定时处理）
void fw_stack_run(fw_stack_t *st);     // 循环 poll 直到 fw_stack_stop
void fw_stack_stop(fw_stack_t *st);    // REN×3 组播（~100ms 间隔，先发后关 §3.6）→ 释放资源
void fw_stack_free(fw_stack_t *st);
const fw_result_t *fw_stack_last_error(const fw_stack_t *st);
// 注入虚假时钟（测试专用；NULL 恢复真实时钟）
void fw_set_clock_override(int64_t (*fn)(void));

// ---- 服务端（§13.1） ----
// idl_json：应用提供 IDL 定义（JSON 文本，NULL=本地库/自动拉取，§7.2 双角色）。
// 本地无定义且发现缓存有在线实例 → 自动 GetIDL（同步等待，失败上抛）。
int  fw_register_service(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                         const char *idl_json, const fw_handlers_t *handlers);
int  fw_unregister_service(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id);
// 更新接口缓存并推送给所有订阅者（§8.1/§8.2；payload 所有权转移）
int  fw_notify(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id, fw_value_t *payload);

// ---- 客户端（§13.2） ----
// 同步调用（阻塞至响应/超时；payload 所有权转移；*out_resp 所有权归调用者）
int  fw_call(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
             fw_value_t *payload, uint32_t timeout_ms, fw_value_t **out_resp);
// 异步调用（payload 所有权转移；完成时回调）
int  fw_call_async(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                   fw_value_t *payload, uint32_t timeout_ms, fw_call_cb cb, void *ud);
// 无响应调用（§5.2）
int  fw_fire_forget(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id, uint16_t if_id,
                    fw_value_t *payload);
// 订阅（if_id/grp_id 二选一；返回 handle，0=失败）。实例未 Found 时登记意图，
// Found 后自动发起（§7.4）；订阅触发 IDL 按需拉取（§7.2/5.21）
uint32_t fw_subscribe(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                      uint16_t if_id, uint8_t grp_id, fw_event_cb cb, void *ud);
// 取消订阅（发 Subscribe(TTL=0)，§8.1 场景4）
int  fw_unsubscribe(fw_stack_t *st, uint32_t handle);
// 本地缓存判定：注册表存在 + TTL Active + VER 相等（§13.2）
int  fw_is_available(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id);
// 主动发现（触发 SD Find 刷新缓存；返回在线信息）
int  fw_find_service(fw_stack_t *st, uint16_t svc_id, uint8_t inst_id,
                     uint32_t timeout_ms, fw_svc_info_t *out);

#ifdef __cplusplus
}
#endif

#endif // FW_H
