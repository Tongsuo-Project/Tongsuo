#include <stdint.h>
#include <immintrin.h>

#include "../ml_dsa_local.h"

#include "ml_dsa_avx2_target.h"
#include "ml_dsa_poly_avx2.h"
#include "ml_dsa_consts_avx2.h"

#define _mm256_blendv_epi32(a,b,mask) \
  _mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), \
                                       _mm256_castsi256_ps(b), \
                                       _mm256_castsi256_ps(mask)))

void power2_round_avx(const uint32_t * restrict a, uint32_t * restrict a1, uint32_t * restrict a0)
{
  unsigned int i;
  __m256i f, f0, f1;
  __m256i is_negative, q_correction;

  const __m256i mask = _mm256_set1_epi32(-(1U << ML_DSA_D_BITS));
  const __m256i half = _mm256_set1_epi32((1U << (ML_DSA_D_BITS - 1)) - 1);
  const __m256i zero = _mm256_setzero_si256();
  const __m256i v_q  = _mm256_set1_epi32(ML_DSA_Q);

  for(i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS / 8; ++i) {
    f = _mm256_loadu_si256((__m256i *)&a[8*i]);
    
    f1 = _mm256_add_epi32(f, half);
    f0 = _mm256_and_si256(f1, mask);
    f1 = _mm256_srli_epi32(f1, ML_DSA_D_BITS);
    f0 = _mm256_sub_epi32(f, f0);

    is_negative = _mm256_cmpgt_epi32(zero, f0); 
    q_correction = _mm256_and_si256(is_negative, v_q);
    f0 = _mm256_add_epi32(f0, q_correction);

    _mm256_storeu_si256((__m256i *)&a1[8*i], f1);
    _mm256_storeu_si256((__m256i *)&a0[8*i], f0);
  }

}

/* decompose function */
void decompose_avx(const int32_t * restrict a, uint32_t gamma2, int32_t * restrict a1, int32_t * restrict a0)
{
  if (gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32){
    unsigned int i;
    __m256i f,f0,f1;
    const __m256i q = _mm256_loadu_si256((__m256i *)&qdata[_8XQ]);
    const __m256i hq = _mm256_srli_epi32(q,1);
    const __m256i v = _mm256_set1_epi32(1025);
    const __m256i alpha = _mm256_set1_epi32(2*gamma2);
    const __m256i off = _mm256_set1_epi32(127);
    const __m256i shift = _mm256_set1_epi32(512);
    const __m256i mask = _mm256_set1_epi32(15);

    for(i=0;i<ML_DSA_NUM_POLY_COEFFICIENTS/8;i++) {
      f = _mm256_loadu_si256((__m256i *)&a[8*i]);
      f1 = _mm256_add_epi32(f,off);
      f1 = _mm256_srli_epi32(f1,7);
      f1 = _mm256_mulhi_epu16(f1,v);
      f1 = _mm256_mulhrs_epi16(f1,shift);
      f1 = _mm256_and_si256(f1,mask);
      f0 = _mm256_mullo_epi32(f1,alpha);
      f0 = _mm256_sub_epi32(f,f0);
      f = _mm256_cmpgt_epi32(f0,hq);
      f = _mm256_and_si256(f,q);
      f0 = _mm256_sub_epi32(f0,f);
      _mm256_storeu_si256((__m256i *)&a1[8*i],f1);
      _mm256_storeu_si256((__m256i *)&a0[8*i],f0);
    }
  }
  else{
    unsigned int i;
    __m256i f,f0,f1,t;
    const __m256i q = _mm256_loadu_si256((__m256i *)&qdata[_8XQ]);
    const __m256i hq = _mm256_srli_epi32(q,1);
    const __m256i v = _mm256_set1_epi32(11275);
    const __m256i alpha = _mm256_set1_epi32(2*gamma2);
    const __m256i off = _mm256_set1_epi32(127);
    const __m256i shift = _mm256_set1_epi32(128);
    const __m256i max = _mm256_set1_epi32(43);
    const __m256i zero = _mm256_setzero_si256();

    for(i=0;i<ML_DSA_NUM_POLY_COEFFICIENTS/8;i++) {
      f = _mm256_loadu_si256((__m256i *)&a[8*i]);
      f1 = _mm256_add_epi32(f,off);
      f1 = _mm256_srli_epi32(f1,7);
      f1 = _mm256_mulhi_epu16(f1,v);
      f1 = _mm256_mulhrs_epi16(f1,shift);
      t = _mm256_cmpgt_epi32(f1,max);
      f1 = _mm256_blendv_epi8(f1,zero,t);
      f0 = _mm256_mullo_epi32(f1,alpha);
      f0 = _mm256_sub_epi32(f,f0);
      f = _mm256_cmpgt_epi32(f0,hq);
      f = _mm256_and_si256(f,q);
      f0 = _mm256_sub_epi32(f0,f);
      _mm256_storeu_si256((__m256i *)&a1[8*i],f1);
      _mm256_storeu_si256((__m256i *)&a0[8*i],f0);
    }
  }
}

void high_bits_avx(const int32_t * restrict a, uint32_t gamma2, int32_t * restrict a1)
{
  uint32_t a0[ML_DSA_NUM_POLY_COEFFICIENTS];
  decompose_avx(a, gamma2, a1, a0);
}

void low_bits_avx(const int32_t * restrict a, uint32_t gamma2, int32_t * restrict a0)
{
  uint32_t a1[ML_DSA_NUM_POLY_COEFFICIENTS];
  decompose_avx(a, gamma2, a1, a0);
}

void make_hint_avx(const uint32_t * restrict r_high, 
                  const uint32_t * restrict r_plus_z_high, 
                  uint32_t * restrict h)
{
    unsigned int i;
    __m256i v_r_high, v_rpz_high, v_eq, v_hint;
    const __m256i one = _mm256_set1_epi32(1);

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS / 8; ++i) {
        v_r_high   = _mm256_loadu_si256((const __m256i *)&r_high[8 * i]);
        v_rpz_high = _mm256_loadu_si256((const __m256i *)&r_plus_z_high[8 * i]);
        
        v_eq = _mm256_cmpeq_epi32(v_r_high, v_rpz_high);
        v_hint = _mm256_andnot_si256(v_eq, one);
        
        _mm256_storeu_si256((__m256i *)&h[8 * i], v_hint);
    }

    // printf("make hint avx has been called!!!\n");
}

void use_hint_avx(const int32_t * restrict hint, const int32_t * restrict a, uint32_t gamma2, int32_t * restrict b) 
{
  unsigned int i;
  int32_t a0[ML_DSA_NUM_POLY_COEFFICIENTS];
  __m256i f, g, h, t;
  const __m256i zero = _mm256_setzero_si256();

  decompose_avx(a, gamma2, b, a0);

  if (gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32) {
    const __m256i mask = _mm256_set1_epi32(15);

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS / 8; i++) {
      f = _mm256_loadu_si256((__m256i *)&a0[8 * i]);
      g = _mm256_loadu_si256((__m256i *)&b[8 * i]);
      h = _mm256_loadu_si256((__m256i *)&hint[8 * i]);
      
      t = _mm256_blendv_epi32(zero, h, f);
      t = _mm256_slli_epi32(t, 1);
      h = _mm256_sub_epi32(h, t);
      g = _mm256_add_epi32(g, h);

      g = _mm256_and_si256(g, mask);

      _mm256_storeu_si256((__m256i *)&b[8 * i], g);
    }
  } 
  else { 
    const __m256i max = _mm256_set1_epi32(43);

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS / 8; i++) {
      f = _mm256_loadu_si256((__m256i *)&a0[8 * i]);
      g = _mm256_loadu_si256((__m256i *)&b[8 * i]);
      h = _mm256_loadu_si256((__m256i *)&hint[8 * i]);
      
      t = _mm256_blendv_epi32(zero, h, f);
      t = _mm256_slli_epi32(t, 1);
      h = _mm256_sub_epi32(h, t);
      g = _mm256_add_epi32(g, h);

      g = _mm256_blendv_epi32(g, max, g);
      f = _mm256_cmpgt_epi32(g, max);
      g = _mm256_blendv_epi32(g, zero, f);

      _mm256_storeu_si256((__m256i *)&b[8 * i], g);
    }
  }

  // printf("use hint avx has been called!!!\n");
}