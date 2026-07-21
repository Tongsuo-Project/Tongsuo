#ifndef OSSL_CRYPTO_ML_DSA_NTT_AVX2_H
#define OSSL_CRYPTO_ML_DSA_NTT_AVX2_H

#include <stdint.h>
#include <x86intrin.h>


void XRQ_ntt_avx2_bo(int32_t c[256]);
void XRQ_intt_avx2_bo(int32_t c[256]);
void pointwise_avx(int32_t *c, const int32_t *a, const int32_t *b);


static ossl_inline void poly_normalize_avx2(int32_t *c)
{
    __m256i v_zero = _mm256_setzero_si256();
    __m256i v_q    = _mm256_set1_epi32(ML_DSA_Q);
    
    for (int i = 0; i < 32; i++) {
        __m256i val = _mm256_loadu_si256((__m256i *)(c + i * 8));
        __m256i mask_neg = _mm256_srai_epi32(val, 31); 
        __m256i add_q = _mm256_and_si256(mask_neg, v_q);
        val = _mm256_add_epi32(val, add_q);
        
        __m256i sub_q_val = _mm256_sub_epi32(val, v_q);
        __m256i mask_lt = _mm256_srai_epi32(sub_q_val, 31);
        __m256i mask_ge = _mm256_andnot_si256(mask_lt, _mm256_set1_epi32(-1));
        __m256i sub_final = _mm256_and_si256(mask_ge, v_q);
        val = _mm256_sub_epi32(val, sub_final);
        
        _mm256_storeu_si256((__m256i *)(c + i * 8), val);
    }
}

#endif /* OSSL_CRYPTO_ML_DSA_NTT_AVX2_H */