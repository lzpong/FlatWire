# ============================================================
# FlatWire Protocol v5.0 —— C 实现构建脚本
#
# 要求：CMake >= 3.15，C11 编译器（MSVC VS2019+ / GCC / Clang），零第三方依赖
# 本机验证：cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
#           cmake --build build
#           ctest --test-dir build
# ============================================================
cmake_minimum_required(VERSION 3.15)
project(flatwire_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# 警告策略：全部告警（验收要求 0 warning）
if(MSVC)
  add_compile_options(/W4 /utf-8 /permissive-)
  # MSVC 平台头文件固有告警豁免（计入 README 偏差清单）
  add_compile_options(/wd4204 /wd4221)
else()
  add_compile_options(-Wall -Wextra)
endif()

# ---- 协议栈静态库 ----
set(FW_SOURCES
  src/value.c
  src/json.c
  src/logger.c
  src/codec/crc.c
  src/codec/codec.c
  src/codec/schema.c
  src/frame/frame.c
  src/strm.c
  src/sd/entries.c
  src/idlstore/store.c
  src/rpc/retransmit.c
  src/transport/udp.c
  src/transport/tcp.c
  src/sd/discovery.c
  src/rpc/rpc.c
  src/events/events.c
  src/stack.c
)

if(WIN32)
  list(APPEND FW_SOURCES src/platform/win.c)
else()
  list(APPEND FW_SOURCES src/platform/posix.c)
endif()

add_library(fw STATIC ${FW_SOURCES})
target_include_directories(fw PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(fw PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(WIN32)
  target_link_libraries(fw PUBLIC ws2_32 iphlpapi) # iphlpapi：本机地址枚举
  target_compile_definitions(fw PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

# ---- 单元测试（CTest） ----
enable_testing()
add_executable(fw_tests
  tests/test_all.c
  tests/t_crc.c
  tests/t_value_json.c
  tests/t_codec.c
  tests/t_frame.c
  tests/t_stream.c
  tests/t_strm.c
  tests/t_entries.c
  tests/t_schema.c
  tests/t_retrans.c
  tests/t_tcp.c
  tests/t_integration.c
  tests/t_regress.c
)
target_link_libraries(fw_tests PRIVATE fw)
target_include_directories(fw_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_test(NAME fw_tests COMMAND fw_tests)

# ---- 示例（§11.1 VehicleState 双节点场景） ----
add_executable(fw_node_a examples/node_a.c)
target_link_libraries(fw_node_a PRIVATE fw)

add_executable(fw_node_b examples/node_b.c)
target_link_libraries(fw_node_b PRIVATE fw)
