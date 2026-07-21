#ifndef DILITHIUM_AVX2_CONSTS_H
#define DILITHIUM_AVX2_CONSTS_H
#include <immintrin.h>
#include <stdint.h>

#define _8XQINV      0
#define _8XQ         8


extern const int32_t qdata[16];

extern const int32_t inte_qdata[512];

extern const int32_t inv_qdata[512];

extern const int64_t inte_data2[32];


#endif