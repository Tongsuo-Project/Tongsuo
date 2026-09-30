#include "ml_dsa_avx2_target.h"
#include <stdint.h>
#include <immintrin.h>
#include "params.h"
#include "rounding.h"
#include "ntt/consts.h"

#define _mm256_blendv_epi32(a,b,mask) \
  _mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), \
                                       _mm256_castsi256_ps(b), \
                                       _mm256_castsi256_ps(mask)))

/*************************************************
* Name:        power2round
*
* Description: For finite field elements a, compute a0, a1 such that
*              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - int32_t *a1: output array of length N with high bits
*              - int32_t *a0: output array of length N with low bits a0
*              - const int32_t *a: input array of length N
*
**************************************************/
void power2round_avx(int32_t * restrict a1, int32_t * restrict a0, const int32_t * restrict a)
{
  unsigned int i;
  __m256i f,f0,f1;
  const __m256i mask = _mm256_set1_epi32(-(1U << D));
  const __m256i half = _mm256_set1_epi32((1U << (D-1)) - 1);

  for(i = 0; i < N/8; ++i) {
    f = _mm256_load_si256((__m256i *)&a[8*i]);
    f1 = _mm256_add_epi32(f,half);
    f0 = _mm256_and_si256(f1,mask);
    f1 = _mm256_srli_epi32(f1,D);
    f0 = _mm256_sub_epi32(f,f0);
    _mm256_store_si256((__m256i *)&a1[8*i], f1);
    _mm256_store_si256((__m256i *)&a0[8*i], f0);
  }
}

/*************************************************
* Name:        decompose
*
* Description: For finite field element a, compute high and low parts a0, a1 such
*              that a mod Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
*              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
*              -ALPHA/2 <= a0 = a mod Q - Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - int32_t *a1: output array of length N with high parts
*              - int32_t *a0: output array of length N with low parts a0
*              - const int32_t *a: input array of length N
*
**************************************************/
#if GAMMA2 == (Q-1)/32
void decompose_avx(int32_t * restrict a1, int32_t * restrict a0, const int32_t * restrict a)
{
  unsigned int i;
  __m256i f,f0,f1;
  const __m256i q = _mm256_load_si256((__m256i *)&qdata[_8XQ]);
  const __m256i hq = _mm256_srli_epi32(q,1);
  const __m256i v = _mm256_set1_epi32(1025);
  const __m256i alpha = _mm256_set1_epi32(2*GAMMA2);
  const __m256i off = _mm256_set1_epi32(127);
  const __m256i shift = _mm256_set1_epi32(512);
  const __m256i mask = _mm256_set1_epi32(15);

  for(i=0;i<N/8;i++) {
    f = _mm256_load_si256((__m256i *)&a[8*i]);
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
    _mm256_store_si256((__m256i *)&a1[8*i],f1);
    _mm256_store_si256((__m256i *)&a0[8*i],f0);
  }
}

#elif GAMMA2 == (Q-1)/88
void decompose_avx(int32_t * restrict a1, int32_t * restrict a0, const int32_t * restrict a)
{
  unsigned int i;
  __m256i f,f0,f1,t;
  const __m256i q = _mm256_load_si256((__m256i *)&qdata[_8XQ]);
  const __m256i hq = _mm256_srli_epi32(q,1);
  const __m256i v = _mm256_set1_epi32(11275);
  const __m256i alpha = _mm256_set1_epi32(2*GAMMA2);
  const __m256i off = _mm256_set1_epi32(127);
  const __m256i shift = _mm256_set1_epi32(128);
  const __m256i max = _mm256_set1_epi32(43);
  const __m256i zero = _mm256_setzero_si256();

  for(i=0;i<N/8;i++) {
    f = _mm256_load_si256((__m256i *)&a[8*i]);
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
    _mm256_store_si256((__m256i *)&a1[8*i],f1);
    _mm256_store_si256((__m256i *)&a0[8*i],f0);
  }
}
#endif

/*************************************************
* Name:        make_hint
*
* Description: Compute hint bits indicating whether the low bits of the
*              input element overflow into the high bits. Inputs assumed to be
*              standard representatives.
*
* Arguments:   - int32_t *a0: low bits of input elements
*              - int32_t *a1: high bits of input elements
*
* Returns number of overflowing low bits
**************************************************/
unsigned int make_hint_avx(int32_t * restrict h, const int32_t * restrict a0, const int32_t * restrict a1)
{
  unsigned int i, r = 0;
  __m256i f0, f1, g0, g1;
  const __m256i blo = _mm256_set1_epi32(GAMMA2 + 1);
  const __m256i bhi = _mm256_set1_epi32(Q - GAMMA2);
  const __m256i zero = _mm256_setzero_si256();
  const __m256i one = _mm256_set1_epi32(1);

  for(i = 0; i < N/8; ++i) {
    f0 = _mm256_load_si256((__m256i *)&a0[8*i]);
    f1 = _mm256_load_si256((__m256i *)&a1[8*i]);

    g0 = _mm256_cmpgt_epi32(blo,f0);
    g1 = _mm256_cmpgt_epi32(f0,bhi);
    g0 = _mm256_or_si256(g0,g1);
    g1 = _mm256_cmpeq_epi32(f0,bhi);
    f1 = _mm256_cmpeq_epi32(f1,zero);
    g1 = _mm256_and_si256(g1,f1);
    g0 = _mm256_or_si256(g0,g1);

    r += _mm_popcnt_u32(_mm256_movemask_ps((__m256)g0));
    g0 = _mm256_add_epi32(g0,one);
    _mm256_store_si256((__m256i *)&h[8*i], g0);
  }

  return N - r;
}

/*************************************************
* Name:        use_hint
*
* Description: Correct high parts according to hint.
*
* Arguments:   - int32_t *b: output array of length N with corrected high parts
*              - int32_t *a: input array of length N
*              - const int32_t *a: input array of length N with hint bits
*
**************************************************/
void use_hint_avx(int32_t * restrict b, const int32_t * restrict a, const int32_t * restrict hint) {
  unsigned int i;
  __attribute__((aligned(32)))
  int32_t a0[N];
  __m256i f,g,h,t;
  const __m256i zero = _mm256_setzero_si256();
#if GAMMA2 == (Q-1)/32
  const __m256i mask = _mm256_set1_epi32(15);
#elif GAMMA2 == (Q-1)/88
  const __m256i max = _mm256_set1_epi32(43);
#endif

  decompose_avx(b, a0, a);
  for(i=0;i<N/8;i++) {
    f = _mm256_load_si256((__m256i *)&a0[8*i]);
    g = _mm256_load_si256((__m256i *)&b[8*i]);
    h = _mm256_load_si256((__m256i *)&hint[8*i]);
    t = _mm256_blendv_epi32(zero,h,f);
    t = _mm256_slli_epi32(t,1);
    h = _mm256_sub_epi32(h,t);
    g = _mm256_add_epi32(g,h);
#if GAMMA2 == (Q-1)/32
    g = _mm256_and_si256(g,mask);
#elif GAMMA2 == (Q-1)/88
    g = _mm256_blendv_epi32(g,max,g);
    f = _mm256_cmpgt_epi32(g,max);
    g = _mm256_blendv_epi32(g,zero,f);
#endif
    _mm256_store_si256((__m256i *)&b[8*i],g);
  }
}
