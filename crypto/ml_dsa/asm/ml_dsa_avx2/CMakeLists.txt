cmake_minimum_required(VERSION 3.20)
project(mldsa_avx2 C)

set(CMAKE_C_STANDARD 17)

enable_language(ASM)

# 编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mpopcnt -mbmi2 -march=native -mtune=native -O3")

# 源文件和头文件
set(SOURCES sign.c packing.c polyvec.c poly.c rejsample.c rounding.c hybrid.c pspm.c)
set(HEADERS config.h params.h api.h sign.h packing.h polyvec.h poly.h shuffle.inc rejsample.h rounding.h keccak4x/symmetric.h randombytes.h hybrid.h pspm.h)
set(KECCAK_SOURCES ${SOURCES} keccak4x/fips202.c  keccak4x/KeccakP-1600-times4-SIMD256.c keccak4x/fips202x4.c)
set(KECCAK_HEADERS ${HEADERS} keccak4x/fips202.h keccak4x/fips202x4.h)
set(NTT_SOURCES ${SOURCES} ntt/ntt_avx2.c ntt/intt_avx2.c ntt/consts.c ntt/pointwise.S)
set(NTT_HEADERS ${HEADERS} ntt/ntt.h ntt/consts.h ntt/cdecl.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} keccak4x test ntt)

# 生成动态库
add_library(pqcrystals_dilithium2_avx2 SHARED ${SOURCES} )
target_compile_definitions(pqcrystals_dilithium2_avx2 PRIVATE DILITHIUM_MODE=2)

add_library(pqcrystals_dilithium3_avx2 SHARED ${SOURCES} )
target_compile_definitions(pqcrystals_dilithium3_avx2 PRIVATE DILITHIUM_MODE=3)

add_library(pqcrystals_dilithium5_avx2 SHARED ${SOURCES} )
target_compile_definitions(pqcrystals_dilithium5_avx2 PRIVATE DILITHIUM_MODE=5)

add_library(pqcrystals_fips202_ref SHARED keccak4x/fips202.c)
add_library(pqcrystals_fips202x4_avx2 SHARED keccak4x/KeccakP-1600-times4-SIMD256.c)

# 测试可执行文件
add_executable(test_dilithium2 test/test_dilithium.c randombytes.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(test_dilithium2 PRIVATE DILITHIUM_MODE=2)

add_executable(test_dilithium3 test/test_dilithium.c randombytes.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(test_dilithium3 PRIVATE DILITHIUM_MODE=3)

add_executable(test_dilithium5 test/test_dilithium.c randombytes.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(test_dilithium5 PRIVATE DILITHIUM_MODE=5)

add_executable(test_speed2 test/test_speed.c test/speed_print.c test/cpucycles.c randombytes.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(test_speed2 PRIVATE DILITHIUM_MODE=2)

add_executable(test_speed3 test/test_speed.c test/speed_print.c test/cpucycles.c randombytes.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(test_speed3 PRIVATE DILITHIUM_MODE=3)

add_executable(test_speed5 test/test_speed.c test/speed_print.c test/cpucycles.c randombytes.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(test_speed5 PRIVATE DILITHIUM_MODE=5)

add_executable(PQCgenKAT_sign2 PQCgenKAT_sign.c rng.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(PQCgenKAT_sign2 PRIVATE DILITHIUM_MODE=2)
target_link_libraries(PQCgenKAT_sign2 crypto)

add_executable(PQCgenKAT_sign3 PQCgenKAT_sign.c rng.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(PQCgenKAT_sign3 PRIVATE DILITHIUM_MODE=3)
target_link_libraries(PQCgenKAT_sign3 crypto)

add_executable(PQCgenKAT_sign5 PQCgenKAT_sign.c rng.c ${KECCAK_SOURCES} ${NTT_SOURCES})
target_compile_definitions(PQCgenKAT_sign5 PRIVATE DILITHIUM_MODE=5)
target_link_libraries(PQCgenKAT_sign5 crypto)