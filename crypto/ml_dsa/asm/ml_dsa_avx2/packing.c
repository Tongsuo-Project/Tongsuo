#include "params.h"
#include "packing.h"

#include <string.h>

#include "polyvec.h"
#include "poly.h"

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[SEEDBYTES],
             const polyveck *t1)
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += SEEDBYTES;

  for(i = 0; i < K; ++i)
    polyt1_pack(pk + i*POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void unpack_pk(uint8_t rho[SEEDBYTES],
               polyveck *t1,
               const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += SEEDBYTES;

  for(i = 0; i < K; ++i)
    polyt1_unpack(&t1->vec[i], pk + i*POLYT1_PACKEDBYTES);
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
static void gen_slist(sword slist[N * 3], const uint8_t *a) {
#if ETA == 2
  __m256i f0,f1,f2,f3;
  __m256i t;
  const __m256i mask0 = _mm256_set1_epi32(0x7);
  const __m256i idx0 = _mm256_setr_epi32(0,3,6,9,12,15,18,21);
  const __m256i inx = _mm256_setr_epi8(0,4,8,12,0,0,0,0,0,0,0,0,0,0,0,0,0,4,8,12,0,0,0,0,0,0,0,0,0,0,0,0);
  const __m256i inx1 = _mm256_setr_epi32(0,4,0,0,0,0,0,0);
  const __m256i zero = _mm256_setzero_si256();
  const __m256i eta = _mm256_set1_epi8(ETA);

  for (int i = 0; i < N/32; ++i) {
    t = _mm256_loadu_si256((__m256i *) (a + 12 * i));

    f0 = _mm256_permutevar8x32_epi32(t,zero);
    f0 = _mm256_srlv_epi32(f0,idx0);
    f0 = f0 & mask0;
    f0 = _mm256_shuffle_epi8(f0, inx);
    f0 = _mm256_permutevar8x32_epi32(f0,inx1);

    f1 = _mm256_srli_si256(t,3);
    f1 = _mm256_permutevar8x32_epi32(f1,zero);
    f1 = _mm256_srlv_epi32(f1,idx0);
    f1 = f1 & mask0;
    f1 = _mm256_shuffle_epi8(f1, inx);
    f1 = _mm256_permutevar8x32_epi32(f1,inx1);

    f2 = _mm256_srli_si256(t,6);
    f2 = _mm256_permutevar8x32_epi32(f2,zero);
    f2 = _mm256_srlv_epi32(f2,idx0);
    f2 = f2 & mask0;
    f2 = _mm256_shuffle_epi8(f2, inx);
    f2 = _mm256_permutevar8x32_epi32(f2,inx1);

    f3 = _mm256_srli_si256(t,9);
    f3 = _mm256_permutevar8x32_epi32(f3,zero);
    f3 = _mm256_srlv_epi32(f3,idx0);
    f3 = f3 & mask0;
    f3 = _mm256_shuffle_epi8(f3, inx);
    f3 = _mm256_permutevar8x32_epi32(f3,inx1);

    f1 = _mm256_unpacklo_epi64(f0,f1);
    f3 = _mm256_unpacklo_epi64(f2,f3);
    f1 = _mm256_permute2x128_si256(f1,f3,0x20);
    f2 = _mm256_sub_epi8(f1, eta); //-a
    f3 = _mm256_sub_epi8(eta, f1); // a

    _mm256_store_si256(slist + i * 32, f2);
    _mm256_store_si256(slist + N + i * 32 , f3);
    _mm256_store_si256(slist + 2 * N + i * 32, f2);
  }

#else
  __m256i f0, f1, f2, f3;
  __m256i g0, g1, g2, g3;
  __m256i h0, h1, h2, h3;
  const __m256i mask = _mm256_set1_epi8(0xf);
  const __m256i eta = _mm256_set1_epi8(ETA);
  for(int i = 0; i < N / 64; ++i) {
    f0 = _mm256_loadu_si256(a + i * 32);
    f1 = _mm256_srli_epi16(f0, 4);
    f0 = _mm256_and_si256(f0, mask);
    f1 = _mm256_and_si256(f1, mask);

    f2 = _mm256_unpacklo_epi8(f0,f1);
    f3 = _mm256_unpackhi_epi8(f0, f1);

    f0 = _mm256_sub_epi8(eta, f2); //a
    f1 = _mm256_sub_epi8(eta, f3);
    f2 = _mm256_sub_epi8(f2,eta); //-a
    f3 = _mm256_sub_epi8(f3, eta);

    g0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f0));
    g1 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f1));
    g2 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f0,1));
    g3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f1,1));

    h0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f2));
    h1 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f3));
    h2 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f2,1));
    h3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f3,1));

    _mm256_store_si256(slist + 64 * i, h0);
    _mm256_store_si256(slist + 64 * i + 16, h1);
    _mm256_store_si256(slist + 64 * i + 32, h2);
    _mm256_store_si256(slist + 64 * i + 48, h3);

    _mm256_store_si256(slist + N + 64 * i, g0);
    _mm256_store_si256(slist + N + 64 * i + 16, g1);
    _mm256_store_si256(slist + N + 64 * i + 32, g2);
    _mm256_store_si256(slist + N + 64 * i + 48, g3);

    _mm256_store_si256(slist + 2 * N + 64 * i, h0);
    _mm256_store_si256(slist + 2 * N + 64 * i + 16, h1);
    _mm256_store_si256(slist + 2 * N + 64 * i + 32, h2);
    _mm256_store_si256(slist + 2 * N + 64 * i + 48, h3);

  }
#endif
}

void unpack_sk(uint8_t rho[SEEDBYTES],
               uint8_t tr[CRHBYTES],
               uint8_t key[SEEDBYTES],
               polyveck *t0,
               sword s1list[L][N * 3],
               sword s2list[K][N * 3],
               const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += SEEDBYTES;

  for(i = 0; i < SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += SEEDBYTES;

  for(i = 0; i < CRHBYTES; ++i)
    tr[i] = sk[i];
  sk += CRHBYTES;

  for(i=0; i < L; ++i)
    gen_slist(s1list[i], sk + i*POLYETA_PACKEDBYTES);
  sk += L*POLYETA_PACKEDBYTES;

  for(i=0; i < K; ++i)
    gen_slist(s2list[i], sk + i*POLYETA_PACKEDBYTES);
  sk += K*POLYETA_PACKEDBYTES;

  for(i=0; i < K; ++i)
    polyt0_unpack(&t0->vec[i], sk + i*POLYT0_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/
void pack_sig(uint8_t sig[CRYPTO_BYTES],
              const uint8_t c[SEEDBYTES],
              const polyvecl *z,
              const polyveck *h)
{
  unsigned int i, j, k;

  for(i=0; i < SEEDBYTES; ++i)
    sig[i] = c[i];
  sig += SEEDBYTES;

  for(i = 0; i < L; ++i)
    polyz_pack(sig + i*POLYZ_PACKEDBYTES, &z->vec[i]);
  sig += L*POLYZ_PACKEDBYTES;

  /* Encode h */
  for(i = 0; i < OMEGA + K; ++i)
    sig[i] = 0;

  k = 0;
  for(i = 0; i < K; ++i) {
    for(j = 0; j < N; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;

    sig[OMEGA + i] = k;
  }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int unpack_sig(uint8_t c[SEEDBYTES],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[CRYPTO_BYTES])
{
  unsigned int i, j, k;

  for(i = 0; i < SEEDBYTES; ++i)
    c[i] = sig[i];
  sig += SEEDBYTES;

  for(i = 0; i < L; ++i)
    polyz_unpack(&z->vec[i], sig + i*POLYZ_PACKEDBYTES);
  sig += L*POLYZ_PACKEDBYTES;

  /* Decode h */
  k = 0;
  for(i = 0; i < K; ++i) {
    for(j = 0; j < N; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA)
      return 1;

    for(j = k; j < sig[OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = k; j < OMEGA; ++j)
    if(sig[j])
      return 1;

  return 0;
}


/*************************************************
* Name:        polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYT1_PACKED_BYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyt1_pack(uint8_t *r, const poly *a) {
  __m256i f0;
  __m256i t0;
  __m128i g0, g1;
  const __m256i mask0 = _mm256_set1_epi64x(0x00000000ffffffffUL);

  for (int i = 0; i < 30; ++i) {
    //concatenate32(r,10)
    f0 = _mm256_load_si256(&a->vec[i]);
    t0 = _mm256_srli_epi64(f0, 22);
    f0 = t0 ^ f0;
    f0 = _mm256_and_si256(mask0, f0);

    //concatenate64(r, 20)
    t0 = _mm256_srli_si256(f0, 4);
    t0 = _mm256_andnot_si256(mask0,t0);
    t0 = _mm256_srli_epi64(t0, 12);
    f0 = f0 ^ t0;

    g0 = _mm256_castsi256_si128(f0);
    g1 = _mm256_extractf128_si256(f0, 1);
    _mm_storeu_si128((__m128i_u *) (r + i * 10), g0);
    _mm_storeu_si128((__m128i_u *) (r + i * 10 + 5), g1);
  }
  uint64_t v0, v1;
  for (int i = 30; i < 32; ++i) {
    //concatenate32(r,10)
    f0 = _mm256_load_si256(&a->vec[i]);
    t0 = _mm256_srli_epi64(f0, 22);
    f0 = t0 ^ f0;
    f0 = _mm256_and_si256(mask0, f0);

    //concatenate64(r, 20)
    t0 = _mm256_srli_si256(f0, 4);
    t0 = _mm256_andnot_si256(mask0,t0);
    t0 = _mm256_srli_epi64(t0, 12);
    f0 = f0 ^ t0;

    g0 = _mm256_castsi256_si128(f0);
    g1 = _mm256_extractf128_si256(f0, 1);
    v0 = (uint64_t)_mm_cvtsi128_si64(g0);
    v1 = (uint64_t)_mm_cvtsi128_si64(g1);
    memcpy(r + i * 10, &v0, 5);
    memcpy(r + i * 10 + 5, &v1, 5);
  }
}

/*************************************************
* Name:        polyt1_unpack
*
* Description: Unpack polynomial t1 with 10-bit coefficients.
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyt1_unpack(poly *r, const uint8_t *a) {
  __m256i b, b0;
  __m256i mask0 = _mm256_set_epi32(4, 4, 3, 2, 3, 2, 1, 0);
  __m256i mask1 = _mm256_set_epi8(11, 10, 10, 9, 9, 8, 8, 7, 6, 5, 5, 4, 4, 3, 3, 2, 9, 8, 8, 7, 7, 6, 6, 5, 4, 3, 3, 2,
                                  2, 1, 1, 0);
  __m256i mask2 = _mm256_set1_epi32(0x3ff);
  __m256i index = _mm256_set_epi32(6, 4, 2, 0, 6, 4, 2, 0);

  for (int i = 0; i < 16; ++i) {
    b = _mm256_loadu_si256((__m256i *) (a + 20 * i));
    b = _mm256_permutevar8x32_epi32(b, mask0);
    b = _mm256_shuffle_epi8(b, mask1);
    b0 = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(b));
    b = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(b, 1));
    b0 = _mm256_srlv_epi32(b0, index);
    b = _mm256_srlv_epi32(b, index);
    b0 = b0 & mask2;
    b = b & mask2;
    _mm256_store_si256(&r->vec[i * 2], b0);
    _mm256_store_si256(&r->vec[i * 2 + 1], b);
  }
}

/*************************************************
* Name:        polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYT0_PACKED_BYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyt0_pack(uint8_t *r, const poly *a) {
  __m256i f0;
  __m256i t0;
  __m128i g0;
  const __m256i d = _mm256_set1_epi32(1 << (D - 1));
  const __m256i mask0 = _mm256_set1_epi64x(0xffffffff00000000UL);
  const __m256i idx0 = _mm256_setr_epi64x(0, 12, 0, 12);

  for (int i = 0; i < 32; ++i) {
    //concatenate32(r,13)
    f0 = _mm256_load_si256(&a->vec[i]);
    f0 = _mm256_sub_epi32(d, f0);
    t0 = _mm256_srli_epi64(f0, 19);
    f0 = t0 ^ f0;
    f0 = _mm256_andnot_si256(mask0, f0);

    //concatenate64(r, 26)
    t0 = _mm256_srli_si256(f0, 4);
    f0 = f0 ^ t0;
    t0 = f0 & mask0;
    t0 = _mm256_srli_epi64(t0, 6);
    f0 = _mm256_andnot_si256(mask0, f0);
    f0 = f0 ^ t0;
    f0 = _mm256_permute4x64_epi64(f0, 0xd8);

    //concatenate64(r,52)
    t0 = _mm256_srli_si256(f0, 4);
    t0 = t0 & mask0;
    t0 = _mm256_slli_epi32(t0, 20);
    f0 = f0 ^ t0;
    f0 = _mm256_srlv_epi64(f0, idx0);

    g0 = _mm256_castsi256_si128(f0);
    _mm_storeu_si128((__m128i_u *) (r + i * 13), g0);
  }
}

/*************************************************
* Name:        polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyt0_unpack(poly *r, const uint8_t *a) {
  __m256i f0, f1;

  const __m256i mask0 = _mm256_set1_epi32(0x1fff);
  const __m256i idx0 = _mm256_setr_epi8(0, 1, 2, 3, 0, 1, 2, 3, 2, 3, 4, 5, 4, 5, 6, 7, 6, 7, 8, 9, 8, 9, 8, 9, 8, 9,
                                        10, 11, 10, 11, 12, 13);
  const __m256i idx1 = _mm256_setr_epi32(0, 13, 10, 7, 4, 1, 14, 11);
  const __m256i d = _mm256_set1_epi32(1 << (D - 1));

  for (int i = 0; i < N / 8; ++i) {
    f0 = _mm256_loadu_si256((__m256i *) (a + 13 * i));

    f1 = _mm256_permute4x64_epi64(f0, 0x44);
    f1 = _mm256_shuffle_epi8(f1, idx0);
    f1 = _mm256_srlv_epi32(f1, idx1);
    f1 = f1 & mask0;
    f1 = _mm256_sub_epi32(d, f1);

    _mm256_store_si256(&r->vec[i], f1);
  }
}

/*************************************************
* Name:        polyz_pack
*               reuqire reduancy bytes at end
* Description: Bit-pack polynomial with coefficients
*              in [-(GAMMA1 - 1), GAMMA1].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYZ_PACKED_BYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
#if GAMMA1 == (1 << 17)
void polyz_pack(uint8_t *r, const poly *a) {
  __m256i f0, f1, f2, f3;
  __m256i t0, t1, t2, t3;
  __m128i g0, g1;
  const __m256i gamma1 = _mm256_set1_epi32(GAMMA1);
  const __m256i mask0 = _mm256_set1_epi64x(0xffffffff00000000ULL);
  const __m256i idx0 = _mm256_setr_epi64x(0, 28, 0, 28);

  for (int i = 0; i < 8; ++i) {
    //concatenate32(r,18)
    f0 = _mm256_load_si256(&a->vec[i * 4 + 0]);
    f1 = _mm256_load_si256(&a->vec[i * 4 + 1]);
    f2 = _mm256_load_si256(&a->vec[i * 4 + 2]);
    f3 = _mm256_load_si256(&a->vec[i * 4 + 3]);
    f0 = _mm256_sub_epi32(gamma1, f0);
    f1 = _mm256_sub_epi32(gamma1, f1);
    f2 = _mm256_sub_epi32(gamma1, f2);
    f3 = _mm256_sub_epi32(gamma1, f3);
    t0 = _mm256_srli_epi64(f0 & mask0, 14);
    t1 = _mm256_srli_epi64(f1 & mask0, 14);
    t2 = _mm256_srli_epi64(f2 & mask0, 14);
    t3 = _mm256_srli_epi64(f3 & mask0, 14);
    f0 = _mm256_andnot_si256(mask0, f0) ^ t0;
    f1 = _mm256_andnot_si256(mask0, f1) ^ t1;
    f2 = _mm256_andnot_si256(mask0, f2) ^ t2;
    f3 = _mm256_andnot_si256(mask0, f3) ^ t3;

    //concatenate64(r,36)
    t0 = _mm256_srli_si256(f0, 4);
    t1 = _mm256_srli_si256(f1, 4);
    t2 = _mm256_srli_si256(f2, 4);
    t3 = _mm256_srli_si256(f3, 4);
    t0 = t0 & mask0;
    t1 = t1 & mask0;
    t2 = t2 & mask0;
    t3 = t3 & mask0;
    t0 = _mm256_slli_epi32(t0, 4);
    t1 = _mm256_slli_epi32(t1, 4);
    t2 = _mm256_slli_epi32(t2, 4);
    t3 = _mm256_slli_epi32(t3, 4);
    f0 = f0 ^ t0;
    f1 = f1 ^ t1;
    f2 = f2 ^ t2;
    f3 = f3 ^ t3;
    f0 = _mm256_srlv_epi64(f0, idx0);
    f1 = _mm256_srlv_epi64(f1, idx0);
    f2 = _mm256_srlv_epi64(f2, idx0);
    f3 = _mm256_srlv_epi64(f3, idx0);

    g0 = _mm256_castsi256_si128(f0);
    g1 = _mm256_extractf128_si256(f0, 1);
    _mm_storeu_si128((__m128i_u *) (r + i * 72 + 0), g0);
    _mm_storeu_si128((__m128i_u *) (r + i * 72 + 9), g1);

    g0 = _mm256_castsi256_si128(f1);
    g1 = _mm256_extractf128_si256(f1, 1);
    _mm_storeu_si128((__m128i_u *) (r + i * 72 + 18), g0);
    _mm_storeu_si128((__m128i_u *) (r + i * 72 + 27), g1);

    g0 = _mm256_castsi256_si128(f2);
    g1 = _mm256_extractf128_si256(f2, 1);
    _mm_storeu_si128((__m128i_u *) (r + i * 72 + 36), g0);
    _mm_storeu_si128((__m128i_u *) (r + i * 72 + 45), g1);

    g0 = _mm256_castsi256_si128(f3);
    g1 = _mm256_extractf128_si256(f3, 1);
    _mm_storeu_si128((__m128i_u *) (r + i * 72 + 54), g0);
    _mm_storeu_si128((__m128i_u *) (r + i * 72 + 63), g1);
  }
}
#elif GAMMA1 == (1 << 19)
void polyz_pack(uint8_t *r, const poly *a) {
  __m256i f0, f1, f2, f3;
  __m256i p0, p1, p2, p3;

  const __m256i mask0 = _mm256_set1_epi64x(0xffffffff);
  const __m256i gamma = _mm256_set1_epi32(GAMMA1);
  const __m256i index = _mm256_setr_epi8(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 8, 9,
                                         10, 11, 12, -1, -1, -1, -1, -1, -1);


  for (int i = 0; i < N / 8; ++i) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f0 = _mm256_sub_epi32(gamma, f0);
    p0 = _mm256_andnot_si256(mask0, f0);
    f0 = (f0 & mask0) | _mm256_srli_epi64(p0, 12);
    f0 = _mm256_shuffle_epi8(f0, index);

    _mm_storeu_si128(r + 20 * i, _mm256_castsi256_si128(f0));
    _mm_storeu_si128(r + 20 * i + 10, _mm256_extracti128_si256(f0, 1));
  }
}
#endif

/*************************************************
* Name:        polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(GAMMA1 - 1), GAMMA1].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
#if GAMMA1 == (1 << 19)

void polyz_unpack(poly *restrict r, const uint8_t *a) {
  unsigned int i;
  __m256i f;
  const __m256i shufbidx = _mm256_set_epi8(-1, 11, 10, 9, -1, 9, 8, 7, -1, 6, 5, 4, -1, 4, 3, 2, -1, 9, 8, 7, -1, 7, 6,
                                           5, -1, 4, 3, 2, -1, 2, 1, 0);
  const __m256i srlvdidx = _mm256_set1_epi64x((uint64_t) 4 << 32);
  const __m256i mask = _mm256_set1_epi32(0xFFFFF);
  const __m256i gamma1 = _mm256_set1_epi32(GAMMA1);

  for (i = 0; i < N / 8; i++) {
    f = _mm256_loadu_si256(a + 20 * i);
    f = _mm256_permute4x64_epi64(f, 0x94);
    f = _mm256_shuffle_epi8(f, shufbidx);
    f = _mm256_srlv_epi32(f, srlvdidx);
    f = _mm256_and_si256(f, mask);
    f = _mm256_sub_epi32(gamma1, f);
    _mm256_store_si256(&r->vec[i], f);
  }
}

#else

void polyz_unpack(poly *r, const uint8_t *a) {
  __m256i f0, f1, f2;
  const __m256i shufbidx = _mm256_set_epi8(-1, 9, 8, 7, -1, 7, 6, 5, -1, 5, 4, 3, -1, 3, 2, 1, -1, 8, 7, 6, -1, 6, 5, 4,
                                           -1, 4, 3, 2, -1, 2, 1, 0);
  const __m256i srlvdidx = _mm256_set_epi32(6, 4, 2, 0, 6, 4, 2, 0);
  const __m256i mask = _mm256_set1_epi32(0x3FFFF);
  const __m256i gamma1 = _mm256_set1_epi32(GAMMA1);

  for (int i = 0; i < 30; i += 3) {
    f0 = _mm256_loadu_si256((__m256i *) &a[18 * i]);
    f1 = _mm256_loadu_si256((__m256i *) &a[18 * i + 18]);
    f2 = _mm256_loadu_si256((__m256i *) &a[18 * i + 36]);

    f0 = _mm256_permute4x64_epi64(f0, 0x94);
    f1 = _mm256_permute4x64_epi64(f1, 0x94);
    f2 = _mm256_permute4x64_epi64(f2, 0x94);

    f0 = _mm256_shuffle_epi8(f0, shufbidx);
    f1 = _mm256_shuffle_epi8(f1, shufbidx);
    f2 = _mm256_shuffle_epi8(f2, shufbidx);

    f0 = _mm256_srlv_epi32(f0, srlvdidx);
    f1 = _mm256_srlv_epi32(f1, srlvdidx);
    f2 = _mm256_srlv_epi32(f2, srlvdidx);

    f0 = _mm256_and_si256(f0, mask);
    f1 = _mm256_and_si256(f1, mask);
    f2 = _mm256_and_si256(f2, mask);

    f0 = _mm256_sub_epi32(gamma1, f0);
    f1 = _mm256_sub_epi32(gamma1, f1);
    f2 = _mm256_sub_epi32(gamma1, f2);

    _mm256_store_si256(&r->vec[i], f0);
    _mm256_store_si256(&r->vec[i + 1], f1);
    _mm256_store_si256(&r->vec[i + 2], f2);
  }

  f0 = _mm256_loadu_si256((__m256i *) &a[18 * 30]);
  f1 = _mm256_loadu_si256((__m256i *) &a[18 * 31]);

  f0 = _mm256_permute4x64_epi64(f0, 0x94);
  f1 = _mm256_permute4x64_epi64(f1, 0x94);

  f0 = _mm256_shuffle_epi8(f0, shufbidx);
  f1 = _mm256_shuffle_epi8(f1, shufbidx);

  f0 = _mm256_srlv_epi32(f0, srlvdidx);
  f1 = _mm256_srlv_epi32(f1, srlvdidx);

  f0 = _mm256_and_si256(f0, mask);
  f1 = _mm256_and_si256(f1, mask);

  f0 = _mm256_sub_epi32(gamma1, f0);
  f1 = _mm256_sub_epi32(gamma1, f1);

  _mm256_store_si256(&r->vec[30], f0);
  _mm256_store_si256(&r->vec[31], f1);
}
#endif

/*************************************************
* Name:        polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYW1_PACKED_BYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
#if GAMMA2 == (Q-1)/88
void polyw1_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i shift1 = _mm256_set1_epi16((64 << 8) + 1);
  const __m256i shift2 = _mm256_set1_epi32((4096 << 16) + 1);
  const __m256i shufdidx1 = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);
  const __m256i shufdidx2 = _mm256_set_epi32(-1, -1, 6, 5, 4, 2, 1, 0);
  const __m256i shufbidx = _mm256_set_epi8(-1, -1, -1, -1, 14, 13, 12, 10, 9, 8, 6, 5, 4, 2, 1, 0,
                                           -1, -1, -1, -1, 14, 13, 12, 10, 9, 8, 6, 5, 4, 2, 1, 0);

  for (i = 0; i < N / 32; i++) {
    f0 = _mm256_load_si256(&a->vec[4 * i + 0]);
    f1 = _mm256_load_si256(&a->vec[4 * i + 1]);
    f2 = _mm256_load_si256(&a->vec[4 * i + 2]);
    f3 = _mm256_load_si256(&a->vec[4 * i + 3]);
    f0 = _mm256_packus_epi32(f0, f1);
    f1 = _mm256_packus_epi32(f2, f3);
    f0 = _mm256_packus_epi16(f0, f1);
    f0 = _mm256_maddubs_epi16(f0, shift1);
    f0 = _mm256_madd_epi16(f0, shift2);
    f0 = _mm256_permutevar8x32_epi32(f0, shufdidx1);
    f0 = _mm256_shuffle_epi8(f0, shufbidx);
    f0 = _mm256_permutevar8x32_epi32(f0, shufdidx2);
    _mm256_storeu_si256((__m256i *) &r[24 * i], f0);
  }
}

#elif GAMMA2 == (Q-1)/32
void polyw1_pack(uint8_t *restrict r, const poly *restrict a) {
  unsigned int i;
  __m256i f0, f1, f2, f3, f4, f5, f6, f7;
  const __m256i mask = _mm256_set1_epi64x(0xFF00FF00FF00FF00);
  const __m256i idx = _mm256_set_epi8(15, 13, 14, 12, 11, 9, 10, 8, 7, 5, 6, 4, 3, 1, 2, 0, 15, 13, 14, 12, 11, 9, 10,
                                      8, 7, 5, 6, 4, 3, 1, 2, 0);


  for (i = 0; i < N / 64; ++i) {
    f0 = _mm256_load_si256((__m256i *) &a->coeffs[64 * i + 0]);
    f1 = _mm256_load_si256((__m256i *) &a->coeffs[64 * i + 8]);
    f2 = _mm256_load_si256((__m256i *) &a->coeffs[64 * i + 16]);
    f3 = _mm256_load_si256((__m256i *) &a->coeffs[64 * i + 24]);

    f0 = _mm256_and_si256(f0, _mm256_set1_epi32(15));
    f1 = _mm256_and_si256(f1, _mm256_set1_epi32(15));
    f2 = _mm256_and_si256(f2, _mm256_set1_epi32(15));
    f3 = _mm256_and_si256(f3, _mm256_set1_epi32(15));

    f0 = _mm256_packus_epi32(f0, f1);
    f4 = _mm256_load_si256((__m256i *) &a->coeffs[64 * i + 32]);
    f5 = _mm256_load_si256((__m256i *) &a->coeffs[64 * i + 40]);

    f1 = _mm256_packus_epi32(f2, f3);
    f6 = _mm256_load_si256((__m256i *) &a->coeffs[64 * i + 48]);
    f7 = _mm256_load_si256((__m256i *) &a->coeffs[64 * i + 56]);

    f4 = _mm256_and_si256(f4, _mm256_set1_epi32(15));
    f5 = _mm256_and_si256(f5, _mm256_set1_epi32(15));
    f6 = _mm256_and_si256(f6, _mm256_set1_epi32(15));
    f7 = _mm256_and_si256(f7, _mm256_set1_epi32(15));

    f2 = _mm256_packus_epi32(f4, f5);
    f3 = _mm256_packus_epi32(f6, f7);
    f0 = _mm256_packus_epi16(f0, f1);
    f1 = _mm256_packus_epi16(f2, f3);
    f2 = _mm256_permute2x128_si256(f0, f1, 0x20); /* ABCD */
    f3 = _mm256_permute2x128_si256(f0, f1, 0x31); /* EFGH */

    f4 = _mm256_srli_epi16(f2, 8); /* B0D0 */
    f5 = _mm256_slli_epi16(f3, 8); /* 0E0G */
    f0 = _mm256_blendv_epi8(f2, f5, mask); /* AECG */
    f1 = _mm256_blendv_epi8(f4, f3, mask); /* BFDH */

    f1 = _mm256_slli_epi16(f1, 4);
    f0 = _mm256_add_epi16(f0, f1);

    f0 = _mm256_shuffle_epi8(f0, idx);
    _mm256_storeu_si256((__m256i *) &r[32 * i], f0);
  }
}
#endif
