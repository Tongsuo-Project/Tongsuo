#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "params.h"

void power2round_avx(int32_t *restrict a1, int32_t *restrict a0,
                     const int32_t *restrict a);
void decompose_avx(int32_t *restrict a1, int32_t *restrict a0,
                   const int32_t *restrict a);
unsigned int make_hint_avx(int32_t *restrict h, const int32_t *restrict a0,
                           const int32_t *restrict a1);
void use_hint_avx(int32_t *restrict b, const int32_t *restrict a,
                  const int32_t *restrict hint);

#endif
