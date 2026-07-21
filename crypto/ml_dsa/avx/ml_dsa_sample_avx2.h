#ifndef OSSL_CRYPTO_ML_DSA_SAMPLE_AVX2_H
#define OSSL_CRYPTO_ML_DSA_SAMPLE_AVX2_H

#include <stdint.h>
#include <stdio.h>

#include "keccak4x/align.h"
#include "ml_dsa_ntt_avx2.h"

#include "../ml_dsa_local.h"
#include "../ml_dsa_matrix.h"
#include "../ml_dsa_vector.h"
#include "../ml_dsa_poly.h"

void ExpandA_44(MATRIX *mat, const uint8_t *rho);
void ExpandA_65(MATRIX *mat, const uint8_t *rho);
void ExpandA_87(MATRIX *mat, const uint8_t *rho);

void ExpandS_44(VECTOR *s1, VECTOR *s2, const uint64_t seed[8]);
void ExpandS_65(VECTOR *s1, VECTOR *s2, const uint64_t seed[8]);
void ExpandS_87(VECTOR *s1, VECTOR *s2, const uint64_t seed[8]);

void expand_mask_avx2(VECTOR *out, const uint8_t *rho_prime, uint32_t kappa, uint32_t gamma1);


#endif /* OSSL_CRYPTO_ML_DSA_SAMPLE_AVX2_H */