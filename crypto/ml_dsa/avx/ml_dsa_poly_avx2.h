#ifndef OSSL_CRYPTO_ML_DSA_POLY_AVX2_H
# define OSSL_CRYPTO_ML_DSA_POLY_AVX2_H

#include <stdint.h>
#include "ml_dsa_ntt_avx2.h"

void power2_round_avx(const uint32_t * restrict a, uint32_t * restrict a1, uint32_t * restrict a0);
void decompose_avx(const int32_t * restrict a, uint32_t gamma2, int32_t * restrict a1, int32_t * restrict a0);
void high_bits_avx(const int32_t * restrict a, uint32_t gamma2, int32_t * restrict a1);
void low_bits_avx(const int32_t * restrict a, uint32_t gamma2, int32_t * restrict a0);
void make_hint_avx(const uint32_t * restrict r_high, 
                const uint32_t * restrict r_plus_z_high, 
                uint32_t * restrict h);
void use_hint_avx(const int32_t * restrict hint, const int32_t * restrict a, uint32_t gamma2, int32_t * restrict b);

#endif /* OSSL_CRYPTO_ML_DSA_POLY_AVX2_H */