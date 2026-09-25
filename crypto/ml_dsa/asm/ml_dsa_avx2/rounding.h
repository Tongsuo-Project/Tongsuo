#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "params.h"

void power2round_avx(int32_t a1[N], int32_t a0[N], const int32_t a[N]);
void decompose_avx(int32_t a1[N], int32_t a0[N], const int32_t a[N]);
unsigned int make_hint_avx(int32_t h[N], const int32_t a0[N], const int32_t a1[N]);
void use_hint_avx(int32_t b[N], const int32_t a[N], const int32_t hint[N]);

#endif
