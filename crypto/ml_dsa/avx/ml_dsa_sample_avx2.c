#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>

#include "ml_dsa_avx2_target.h"
#include "ml_dsa_consts_avx2.h"
#include "../ml_dsa_local.h"

// #include "../ml_dsa_poly.h"
// #include "../ml_dsa_matrix.h"

#include "ml_dsa_sample_avx2.h"

#include "keccak4x/symmetric.h"
#include "keccak4x/fips202x4.h"

const uint8_t idxlut[256][8] = {
    {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}, {1, 0, 0, 0, 0, 0, 0, 0}, {0, 1, 0, 0, 0, 0, 0, 0},
    {2, 0, 0, 0, 0, 0, 0, 0}, {0, 2, 0, 0, 0, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 0}, {0, 1, 2, 0, 0, 0, 0, 0},
    {3, 0, 0, 0, 0, 0, 0, 0}, {0, 3, 0, 0, 0, 0, 0, 0}, {1, 3, 0, 0, 0, 0, 0, 0}, {0, 1, 3, 0, 0, 0, 0, 0},
    {2, 3, 0, 0, 0, 0, 0, 0}, {0, 2, 3, 0, 0, 0, 0, 0}, {1, 2, 3, 0, 0, 0, 0, 0}, {0, 1, 2, 3, 0, 0, 0, 0},
    {4, 0, 0, 0, 0, 0, 0, 0}, {0, 4, 0, 0, 0, 0, 0, 0}, {1, 4, 0, 0, 0, 0, 0, 0}, {0, 1, 4, 0, 0, 0, 0, 0},
    {2, 4, 0, 0, 0, 0, 0, 0}, {0, 2, 4, 0, 0, 0, 0, 0}, {1, 2, 4, 0, 0, 0, 0, 0}, {0, 1, 2, 4, 0, 0, 0, 0},
    {3, 4, 0, 0, 0, 0, 0, 0}, {0, 3, 4, 0, 0, 0, 0, 0}, {1, 3, 4, 0, 0, 0, 0, 0}, {0, 1, 3, 4, 0, 0, 0, 0},
    {2, 3, 4, 0, 0, 0, 0, 0}, {0, 2, 3, 4, 0, 0, 0, 0}, {1, 2, 3, 4, 0, 0, 0, 0}, {0, 1, 2, 3, 4, 0, 0, 0},
    {5, 0, 0, 0, 0, 0, 0, 0}, {0, 5, 0, 0, 0, 0, 0, 0}, {1, 5, 0, 0, 0, 0, 0, 0}, {0, 1, 5, 0, 0, 0, 0, 0},
    {2, 5, 0, 0, 0, 0, 0, 0}, {0, 2, 5, 0, 0, 0, 0, 0}, {1, 2, 5, 0, 0, 0, 0, 0}, {0, 1, 2, 5, 0, 0, 0, 0},
    {3, 5, 0, 0, 0, 0, 0, 0}, {0, 3, 5, 0, 0, 0, 0, 0}, {1, 3, 5, 0, 0, 0, 0, 0}, {0, 1, 3, 5, 0, 0, 0, 0},
    {2, 3, 5, 0, 0, 0, 0, 0}, {0, 2, 3, 5, 0, 0, 0, 0}, {1, 2, 3, 5, 0, 0, 0, 0}, {0, 1, 2, 3, 5, 0, 0, 0},
    {4, 5, 0, 0, 0, 0, 0, 0}, {0, 4, 5, 0, 0, 0, 0, 0}, {1, 4, 5, 0, 0, 0, 0, 0}, {0, 1, 4, 5, 0, 0, 0, 0},
    {2, 4, 5, 0, 0, 0, 0, 0}, {0, 2, 4, 5, 0, 0, 0, 0}, {1, 2, 4, 5, 0, 0, 0, 0}, {0, 1, 2, 4, 5, 0, 0, 0},
    {3, 4, 5, 0, 0, 0, 0, 0}, {0, 3, 4, 5, 0, 0, 0, 0}, {1, 3, 4, 5, 0, 0, 0, 0}, {0, 1, 3, 4, 5, 0, 0, 0},
    {2, 3, 4, 5, 0, 0, 0, 0}, {0, 2, 3, 4, 5, 0, 0, 0}, {1, 2, 3, 4, 5, 0, 0, 0}, {0, 1, 2, 3, 4, 5, 0, 0},
    {6, 0, 0, 0, 0, 0, 0, 0}, {0, 6, 0, 0, 0, 0, 0, 0}, {1, 6, 0, 0, 0, 0, 0, 0}, {0, 1, 6, 0, 0, 0, 0, 0},
    {2, 6, 0, 0, 0, 0, 0, 0}, {0, 2, 6, 0, 0, 0, 0, 0}, {1, 2, 6, 0, 0, 0, 0, 0}, {0, 1, 2, 6, 0, 0, 0, 0},
    {3, 6, 0, 0, 0, 0, 0, 0}, {0, 3, 6, 0, 0, 0, 0, 0}, {1, 3, 6, 0, 0, 0, 0, 0}, {0, 1, 3, 6, 0, 0, 0, 0},
    {2, 3, 6, 0, 0, 0, 0, 0}, {0, 2, 3, 6, 0, 0, 0, 0}, {1, 2, 3, 6, 0, 0, 0, 0}, {0, 1, 2, 3, 6, 0, 0, 0},
    {4, 6, 0, 0, 0, 0, 0, 0}, {0, 4, 6, 0, 0, 0, 0, 0}, {1, 4, 6, 0, 0, 0, 0, 0}, {0, 1, 4, 6, 0, 0, 0, 0},
    {2, 4, 6, 0, 0, 0, 0, 0}, {0, 2, 4, 6, 0, 0, 0, 0}, {1, 2, 4, 6, 0, 0, 0, 0}, {0, 1, 2, 4, 6, 0, 0, 0},
    {3, 4, 6, 0, 0, 0, 0, 0}, {0, 3, 4, 6, 0, 0, 0, 0}, {1, 3, 4, 6, 0, 0, 0, 0}, {0, 1, 3, 4, 6, 0, 0, 0},
    {2, 3, 4, 6, 0, 0, 0, 0}, {0, 2, 3, 4, 6, 0, 0, 0}, {1, 2, 3, 4, 6, 0, 0, 0}, {0, 1, 2, 3, 4, 6, 0, 0},
    {5, 6, 0, 0, 0, 0, 0, 0}, {0, 5, 6, 0, 0, 0, 0, 0}, {1, 5, 6, 0, 0, 0, 0, 0}, {0, 1, 5, 6, 0, 0, 0, 0},
    {2, 5, 6, 0, 0, 0, 0, 0}, {0, 2, 5, 6, 0, 0, 0, 0}, {1, 2, 5, 6, 0, 0, 0, 0}, {0, 1, 2, 5, 6, 0, 0, 0},
    {3, 5, 6, 0, 0, 0, 0, 0}, {0, 3, 5, 6, 0, 0, 0, 0}, {1, 3, 5, 6, 0, 0, 0, 0}, {0, 1, 3, 5, 6, 0, 0, 0},
    {2, 3, 5, 6, 0, 0, 0, 0}, {0, 2, 3, 5, 6, 0, 0, 0}, {1, 2, 3, 5, 6, 0, 0, 0}, {0, 1, 2, 3, 5, 6, 0, 0},
    {4, 5, 6, 0, 0, 0, 0, 0}, {0, 4, 5, 6, 0, 0, 0, 0}, {1, 4, 5, 6, 0, 0, 0, 0}, {0, 1, 4, 5, 6, 0, 0, 0},
    {2, 4, 5, 6, 0, 0, 0, 0}, {0, 2, 4, 5, 6, 0, 0, 0}, {1, 2, 4, 5, 6, 0, 0, 0}, {0, 1, 2, 4, 5, 6, 0, 0},
    {3, 4, 5, 6, 0, 0, 0, 0}, {0, 3, 4, 5, 6, 0, 0, 0}, {1, 3, 4, 5, 6, 0, 0, 0}, {0, 1, 3, 4, 5, 6, 0, 0},
    {2, 3, 4, 5, 6, 0, 0, 0}, {0, 2, 3, 4, 5, 6, 0, 0}, {1, 2, 3, 4, 5, 6, 0, 0}, {0, 1, 2, 3, 4, 5, 6, 0},
    {7, 0, 0, 0, 0, 0, 0, 0}, {0, 7, 0, 0, 0, 0, 0, 0}, {1, 7, 0, 0, 0, 0, 0, 0}, {0, 1, 7, 0, 0, 0, 0, 0},
    {2, 7, 0, 0, 0, 0, 0, 0}, {0, 2, 7, 0, 0, 0, 0, 0}, {1, 2, 7, 0, 0, 0, 0, 0}, {0, 1, 2, 7, 0, 0, 0, 0},
    {3, 7, 0, 0, 0, 0, 0, 0}, {0, 3, 7, 0, 0, 0, 0, 0}, {1, 3, 7, 0, 0, 0, 0, 0}, {0, 1, 3, 7, 0, 0, 0, 0},
    {2, 3, 7, 0, 0, 0, 0, 0}, {0, 2, 3, 7, 0, 0, 0, 0}, {1, 2, 3, 7, 0, 0, 0, 0}, {0, 1, 2, 3, 7, 0, 0, 0},
    {4, 7, 0, 0, 0, 0, 0, 0}, {0, 4, 7, 0, 0, 0, 0, 0}, {1, 4, 7, 0, 0, 0, 0, 0}, {0, 1, 4, 7, 0, 0, 0, 0},
    {2, 4, 7, 0, 0, 0, 0, 0}, {0, 2, 4, 7, 0, 0, 0, 0}, {1, 2, 4, 7, 0, 0, 0, 0}, {0, 1, 2, 4, 7, 0, 0, 0},
    {3, 4, 7, 0, 0, 0, 0, 0}, {0, 3, 4, 7, 0, 0, 0, 0}, {1, 3, 4, 7, 0, 0, 0, 0}, {0, 1, 3, 4, 7, 0, 0, 0},
    {2, 3, 4, 7, 0, 0, 0, 0}, {0, 2, 3, 4, 7, 0, 0, 0}, {1, 2, 3, 4, 7, 0, 0, 0}, {0, 1, 2, 3, 4, 7, 0, 0},
    {5, 7, 0, 0, 0, 0, 0, 0}, {0, 5, 7, 0, 0, 0, 0, 0}, {1, 5, 7, 0, 0, 0, 0, 0}, {0, 1, 5, 7, 0, 0, 0, 0},
    {2, 5, 7, 0, 0, 0, 0, 0}, {0, 2, 5, 7, 0, 0, 0, 0}, {1, 2, 5, 7, 0, 0, 0, 0}, {0, 1, 2, 5, 7, 0, 0, 0},
    {3, 5, 7, 0, 0, 0, 0, 0}, {0, 3, 5, 7, 0, 0, 0, 0}, {1, 3, 5, 7, 0, 0, 0, 0}, {0, 1, 3, 5, 7, 0, 0, 0},
    {2, 3, 5, 7, 0, 0, 0, 0}, {0, 2, 3, 5, 7, 0, 0, 0}, {1, 2, 3, 5, 7, 0, 0, 0}, {0, 1, 2, 3, 5, 7, 0, 0},
    {4, 5, 7, 0, 0, 0, 0, 0}, {0, 4, 5, 7, 0, 0, 0, 0}, {1, 4, 5, 7, 0, 0, 0, 0}, {0, 1, 4, 5, 7, 0, 0, 0},
    {2, 4, 5, 7, 0, 0, 0, 0}, {0, 2, 4, 5, 7, 0, 0, 0}, {1, 2, 4, 5, 7, 0, 0, 0}, {0, 1, 2, 4, 5, 7, 0, 0},
    {3, 4, 5, 7, 0, 0, 0, 0}, {0, 3, 4, 5, 7, 0, 0, 0}, {1, 3, 4, 5, 7, 0, 0, 0}, {0, 1, 3, 4, 5, 7, 0, 0},
    {2, 3, 4, 5, 7, 0, 0, 0}, {0, 2, 3, 4, 5, 7, 0, 0}, {1, 2, 3, 4, 5, 7, 0, 0}, {0, 1, 2, 3, 4, 5, 7, 0},
    {6, 7, 0, 0, 0, 0, 0, 0}, {0, 6, 7, 0, 0, 0, 0, 0}, {1, 6, 7, 0, 0, 0, 0, 0}, {0, 1, 6, 7, 0, 0, 0, 0},
    {2, 6, 7, 0, 0, 0, 0, 0}, {0, 2, 6, 7, 0, 0, 0, 0}, {1, 2, 6, 7, 0, 0, 0, 0}, {0, 1, 2, 6, 7, 0, 0, 0},
    {3, 6, 7, 0, 0, 0, 0, 0}, {0, 3, 6, 7, 0, 0, 0, 0}, {1, 3, 6, 7, 0, 0, 0, 0}, {0, 1, 3, 6, 7, 0, 0, 0},
    {2, 3, 6, 7, 0, 0, 0, 0}, {0, 2, 3, 6, 7, 0, 0, 0}, {1, 2, 3, 6, 7, 0, 0, 0}, {0, 1, 2, 3, 6, 7, 0, 0},
    {4, 6, 7, 0, 0, 0, 0, 0}, {0, 4, 6, 7, 0, 0, 0, 0}, {1, 4, 6, 7, 0, 0, 0, 0}, {0, 1, 4, 6, 7, 0, 0, 0},
    {2, 4, 6, 7, 0, 0, 0, 0}, {0, 2, 4, 6, 7, 0, 0, 0}, {1, 2, 4, 6, 7, 0, 0, 0}, {0, 1, 2, 4, 6, 7, 0, 0},
    {3, 4, 6, 7, 0, 0, 0, 0}, {0, 3, 4, 6, 7, 0, 0, 0}, {1, 3, 4, 6, 7, 0, 0, 0}, {0, 1, 3, 4, 6, 7, 0, 0},
    {2, 3, 4, 6, 7, 0, 0, 0}, {0, 2, 3, 4, 6, 7, 0, 0}, {1, 2, 3, 4, 6, 7, 0, 0}, {0, 1, 2, 3, 4, 6, 7, 0},
    {5, 6, 7, 0, 0, 0, 0, 0}, {0, 5, 6, 7, 0, 0, 0, 0}, {1, 5, 6, 7, 0, 0, 0, 0}, {0, 1, 5, 6, 7, 0, 0, 0},
    {2, 5, 6, 7, 0, 0, 0, 0}, {0, 2, 5, 6, 7, 0, 0, 0}, {1, 2, 5, 6, 7, 0, 0, 0}, {0, 1, 2, 5, 6, 7, 0, 0},
    {3, 5, 6, 7, 0, 0, 0, 0}, {0, 3, 5, 6, 7, 0, 0, 0}, {1, 3, 5, 6, 7, 0, 0, 0}, {0, 1, 3, 5, 6, 7, 0, 0},
    {2, 3, 5, 6, 7, 0, 0, 0}, {0, 2, 3, 5, 6, 7, 0, 0}, {1, 2, 3, 5, 6, 7, 0, 0}, {0, 1, 2, 3, 5, 6, 7, 0},
    {4, 5, 6, 7, 0, 0, 0, 0}, {0, 4, 5, 6, 7, 0, 0, 0}, {1, 4, 5, 6, 7, 0, 0, 0}, {0, 1, 4, 5, 6, 7, 0, 0},
    {2, 4, 5, 6, 7, 0, 0, 0}, {0, 2, 4, 5, 6, 7, 0, 0}, {1, 2, 4, 5, 6, 7, 0, 0}, {0, 1, 2, 4, 5, 6, 7, 0},
    {3, 4, 5, 6, 7, 0, 0, 0}, {0, 3, 4, 5, 6, 7, 0, 0}, {1, 3, 4, 5, 6, 7, 0, 0}, {0, 1, 3, 4, 5, 6, 7, 0},
    {2, 3, 4, 5, 6, 7, 0, 0}, {0, 2, 3, 4, 5, 6, 7, 0}, {1, 2, 3, 4, 5, 6, 7, 0}, {0, 1, 2, 3, 4, 5, 6, 7}
};

/* begin expand A 44 */
unsigned int XURQ_AVX2_rej_uniform_avx_s1s3(int32_t *restrict r, const uint8_t *buf, unsigned int num) {
    unsigned int ctr, pos;
    uint32_t good;
    __m256i d, tmp;
    const __m256i bound = _mm256_set1_epi32(ML_DSA_Q);
    const __m256i mask = _mm256_set1_epi32(0x7FFFFF);
    const __m256i idx8 = _mm256_set_epi8(-1, 15, 14, 13, -1, 12, 11, 10,
                                         -1, 9, 8, 7, -1, 6, 5, 4,
                                         -1, 11, 10, 9, -1, 8, 7, 6,
                                         -1, 5, 4, 3, -1, 2, 1, 0);

    ctr = num;
    pos = 0;
    for (int i = 0; i < 7; ++i) {
        d = _mm256_loadu_si256((__m256i *) &buf[pos]);
        d = _mm256_permute4x64_epi64(d, 0x94);
        d = _mm256_shuffle_epi8(d, idx8);
        d = _mm256_and_si256(d, mask);
        pos += 24;

        tmp = _mm256_sub_epi32(d, bound);
        good = _mm256_movemask_ps((__m256) tmp);
        if (good == 0xff) {
            _mm256_storeu_si256((__m256i *) &r[ctr], d);
            ctr += 8;
        } else {
            tmp = _mm256_cvtepu8_epi32(_mm_loadl_epi64((__m128i *) &idxlut[good]));
            d = _mm256_permutevar8x32_epi32(d, tmp);
            _mm256_storeu_si256((__m256i *) &r[ctr], d);
            ctr += _mm_popcnt_u32(good);
        }
    }

    return ctr;
}

unsigned int XURQ_AVX2_rej_uniform_avx_s1s3_final(int32_t *restrict r, const uint8_t *buf, unsigned int num) {
    unsigned int ctr, pos;
    uint32_t good;
    __m256i d, tmp;
    const __m256i bound = _mm256_set1_epi32(ML_DSA_Q);
    const __m256i mask = _mm256_set1_epi32(0x7FFFFF);
    const __m256i idx8 = _mm256_set_epi8(-1, 15, 14, 13, -1, 12, 11, 10,
                                         -1, 9, 8, 7, -1, 6, 5, 4,
                                         -1, 11, 10, 9, -1, 8, 7, 6,
                                         -1, 5, 4, 3, -1, 2, 1, 0);

    ctr = num;

    pos = 0;

    for (int i = 0; i < 3; ++i) {
        d = _mm256_loadu_si256((__m256i *) &buf[pos]);
        d = _mm256_permute4x64_epi64(d, 0x94);
        d = _mm256_shuffle_epi8(d, idx8);
        d = _mm256_and_si256(d, mask);
        pos += 24;

        tmp = _mm256_sub_epi32(d, bound);
        good = _mm256_movemask_ps((__m256) tmp);
        if (good == 0xff) {
            _mm256_storeu_si256((__m256i *) &r[ctr], d);
            ctr += 8;
        } else {
            tmp = _mm256_cvtepu8_epi32(_mm_loadl_epi64((__m128i *) &idxlut[good]));
            d = _mm256_permutevar8x32_epi32(d, tmp);
            _mm256_storeu_si256((__m256i *) &r[ctr], d);
            ctr += _mm_popcnt_u32(good);
        }
    }

    while (ctr < 248 && pos <= 144) {
        d = _mm256_loadu_si256((__m256i *) &buf[pos]);
        d = _mm256_permute4x64_epi64(d, 0x94);
        d = _mm256_shuffle_epi8(d, idx8);
        d = _mm256_and_si256(d, mask);
        pos += 24;

        tmp = _mm256_sub_epi32(d, bound);
        good = _mm256_movemask_ps((__m256) tmp);
        if (good == 0xff) {
            _mm256_storeu_si256((__m256i *) &r[ctr], d);
            ctr += 8;
        } else {
            tmp = _mm256_cvtepu8_epi32(_mm_loadl_epi64((__m128i *) &idxlut[good]));
            d = _mm256_permutevar8x32_epi32(d, tmp);
            _mm256_storeu_si256((__m256i *) &r[ctr], d);
            ctr += _mm_popcnt_u32(good);
        }
    }

    uint32_t t;
    while (ctr < ML_DSA_NUM_POLY_COEFFICIENTS && pos <= 168) {
        t = buf[pos++];
        t |= (uint32_t) buf[pos++] << 8;
        t |= (uint32_t) buf[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < ML_DSA_Q) {
            r[ctr++] = t;
        }
    }

    return ctr;
}

static unsigned int rej_uniform(int32_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint32_t t;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        t = buf[pos++];
        t |= (uint32_t) buf[pos++] << 8;
        t |= (uint32_t) buf[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < ML_DSA_Q) {
            a[ctr++] = t;
        }
    }

    return ctr;
}

void poly_uniform_4x_op13(POLY *a0,
                          POLY *a1,
                          POLY *a2,
                          POLY *a3,
                          const uint8_t seed[32],
                          uint16_t nonce0,
                          uint16_t nonce1,
                          uint16_t nonce2,
                          uint16_t nonce3) {
    unsigned int ctr[4] = {0};
    uint8_t buf[4][192];
    keccakx4_state state;
    uint64_t *seed64 = (uint64_t *) seed;

    state.s[0] = _mm256_set1_epi64x(seed64[0]);
    state.s[1] = _mm256_set1_epi64x(seed64[1]);
    state.s[2] = _mm256_set1_epi64x(seed64[2]);
    state.s[3] = _mm256_set1_epi64x(seed64[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ nonce3, (0x1f << 16) ^ nonce2,
                                   (0x1f << 16) ^ nonce1, (0x1f << 16) ^ nonce0);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[20] = _mm256_set1_epi64x(0x1ULL << 63);

    for (int i = 0; i < 4; ++i) {
        XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeff, buf[0], ctr[0]);
        ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeff, buf[1], ctr[1]);
        ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3(a2->coeff, buf[2], ctr[2]);
        ctr[3] = XURQ_AVX2_rej_uniform_avx_s1s3(a3->coeff, buf[3], ctr[3]);
    }

    XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a0->coeff, buf[0], ctr[0]);
    ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a1->coeff, buf[1], ctr[1]);
    ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a2->coeff, buf[2], ctr[2]);
    ctr[3] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a3->coeff, buf[3], ctr[3]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) {
        XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] += rej_uniform(a0->coeff + ctr[0], ML_DSA_NUM_POLY_COEFFICIENTS - ctr[0], buf[0], SHAKE128_RATE);
        ctr[1] += rej_uniform(a1->coeff + ctr[1], ML_DSA_NUM_POLY_COEFFICIENTS - ctr[1], buf[1], SHAKE128_RATE);
        ctr[2] += rej_uniform(a2->coeff + ctr[2], ML_DSA_NUM_POLY_COEFFICIENTS - ctr[2], buf[2], SHAKE128_RATE);
        ctr[3] += rej_uniform(a3->coeff + ctr[3], ML_DSA_NUM_POLY_COEFFICIENTS - ctr[3], buf[3], SHAKE128_RATE);
    }
}

void ExpandA_44(MATRIX *mat, const uint8_t *rho) {
    POLY *poly = mat->m_poly;
    poly_uniform_4x_op13(poly+0, poly+1, poly+2, poly+3, rho, 0, 1, 2, 3);
    poly_uniform_4x_op13(poly+4, poly+5, poly+6, poly+7, rho, 256, 257,
                         258, 259);
    poly_uniform_4x_op13(poly+8, poly+9, poly+10, poly+11, rho, 512, 513,
                         514, 515);
    poly_uniform_4x_op13(poly+12, poly+13, poly+14, poly+15, rho, 768, 769,
                         770, 771);
}
/* end expand A 44 */

/* begin expand A 65 */
void XURQ_AVX2_polyvec_matrix_expand_row0_65(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+0, rowa+1, rowa+2, rowa+3, rho, 0, 1, 2, 3);
    poly_uniform_4x_op13(rowa+4, rowb+0, rowb+1, rowb+2, rho, 4, 256, 257, 258);
}

void XURQ_AVX2_polyvec_matrix_expand_row1_65(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+3, rowa+4, rowb+0, rowb+1, rho, 259, 260, 512, 513);

}

void XURQ_AVX2_polyvec_matrix_expand_row2_65(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+2, rowa+3, rowa+4, rowb+0, rho, 514, 515, 516, 768);

}

void XURQ_AVX2_polyvec_matrix_expand_row3_65(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+1, rowa+2, rowa+3, rowa+4, rho, 769, 770, 771, 772);

}

void XURQ_AVX2_polyvec_matrix_expand_row4_65(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+0, rowa+1, rowa+2, rowa+3, rho, 1024, 1025, 1026, 1027);
    poly_uniform_4x_op13(rowa+4, rowb+0, rowb+1, rowb+2, rho, 1028, 1280, 1281, 1282);

}

void XURQ_AVX2_polyvec_matrix_expand_row5_65(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+3, rowa+4, rowb+0, rowb+1, rho, 1283, 1284, 1536, 1537);

}

void ExpandA_65(MATRIX *mat, const uint8_t *rho) {
    POLY *poly = mat->m_poly;
    POLY *tmp = (POLY *)calloc(2, sizeof(POLY));
    XURQ_AVX2_polyvec_matrix_expand_row0_65(poly+0, poly+5, rho);
    XURQ_AVX2_polyvec_matrix_expand_row1_65(poly+5, poly+10, rho);
    XURQ_AVX2_polyvec_matrix_expand_row2_65(poly+10, poly+15, rho);
    XURQ_AVX2_polyvec_matrix_expand_row3_65(poly+15, NULL, rho);
    XURQ_AVX2_polyvec_matrix_expand_row4_65(poly+20, poly+25, rho);
    XURQ_AVX2_polyvec_matrix_expand_row5_65(poly+25, tmp, rho);
}
/* end expand A 65 */

/* begin expand A 87 */
static void XURQ_AVX2_polyvec_matrix_expand_row0_87(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+0, rowa+1, rowa+2, rowa+3, rho, 0, 1, 2, 3);
    poly_uniform_4x_op13(rowa+4, rowa+5, rowa+6, rowb+0, rho, 4, 5, 6, 256);
}

static void XURQ_AVX2_polyvec_matrix_expand_row1_87(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+1, rowa+2, rowa+3, rowa+4, rho, 257, 258, 259, 260);
    poly_uniform_4x_op13(rowa+5, rowa+6, rowb+0, rowb+1, rho, 261, 262, 512, 513);
}

static void XURQ_AVX2_polyvec_matrix_expand_row2_87(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+2, rowa+3, rowa+4, rowa+5, rho, 514, 515, 516, 517);
    poly_uniform_4x_op13(rowa+6, rowb+0, rowb+1, rowb+2, rho, 518, 768, 769, 770);
}

static void XURQ_AVX2_polyvec_matrix_expand_row3_87(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+3, rowa+4, rowa+5, rowa+6, rho, 771, 772, 773, 774);
}

static void XURQ_AVX2_polyvec_matrix_expand_row4_87(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+0, rowa+1, rowa+2, rowa+3, rho, 1024, 1025, 1026, 1027);
    poly_uniform_4x_op13(rowa+4, rowa+5, rowa+6, rowb+0, rho, 1028, 1029, 1030, 1280);
}

static void XURQ_AVX2_polyvec_matrix_expand_row5_87(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+1, rowa+2, rowa+3, rowa+4, rho, 1281, 1282, 1283, 1284);
    poly_uniform_4x_op13(rowa+5, rowa+6, rowb+0, rowb+1, rho, 1285, 1286, 1536, 1537);
}

static void XURQ_AVX2_polyvec_matrix_expand_row6_87(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+2, rowa+3, rowa+4, rowa+5, rho, 1538, 1539, 1540, 1541);
    poly_uniform_4x_op13(rowa+6, rowb+0, rowb+1, rowb+2, rho, 1542, 1792, 1793, 1794);
}

static void XURQ_AVX2_polyvec_matrix_expand_row7_87(POLY *rowa, POLY *rowb, const uint8_t *rho) {
    poly_uniform_4x_op13(rowa+3, rowa+4, rowa+5, rowa+6, rho, 1795, 1796, 1797, 1798);
}

void ExpandA_87(MATRIX *mat, const uint8_t *rho) {
    POLY *poly = mat->m_poly;
    XURQ_AVX2_polyvec_matrix_expand_row0_87(poly+0, poly+7, rho);
    XURQ_AVX2_polyvec_matrix_expand_row1_87(poly+7, poly+14, rho);
    XURQ_AVX2_polyvec_matrix_expand_row2_87(poly+14, poly+21, rho);
    XURQ_AVX2_polyvec_matrix_expand_row3_87(poly+21, NULL, rho);
    XURQ_AVX2_polyvec_matrix_expand_row4_87(poly+28, poly+35, rho);
    XURQ_AVX2_polyvec_matrix_expand_row5_87(poly+35, poly+42, rho);
    XURQ_AVX2_polyvec_matrix_expand_row6_87(poly+42, poly+49, rho);
    XURQ_AVX2_polyvec_matrix_expand_row7_87(poly+49, NULL, rho);
}
/* end expand A 87 */

static void expand_s_state_init(keccakx4_state *state,
                                const uint64_t seed[8],
                                uint16_t nonce0, uint16_t nonce1,
                                uint16_t nonce2, uint16_t nonce3)
{
    int i;

    for (i = 0; i < 8; ++i)
        state->s[i] = _mm256_set1_epi64x(seed[i]);
    state->s[8] = _mm256_set_epi64x((0x1f << 16) ^ nonce3,
                                    (0x1f << 16) ^ nonce2,
                                    (0x1f << 16) ^ nonce1,
                                    (0x1f << 16) ^ nonce0);
    for (i = 9; i < 25; ++i)
        state->s[i] = _mm256_setzero_si256();
    state->s[16] = _mm256_set1_epi64x(0x1ULL << 63);
}

/* begin expand S 44 */
#define REJ(n) \
g0 = _mm256_castsi256_si128(f##n);\
g1 = _mm_bsrli_si128(g0, 8);\
g2 = _mm256_extracti128_si256(f##n, 1);\
g3 = _mm_bsrli_si128(g2, 8);\
\
d0 = _mm_loadl_epi64((__m128i *) &idxlut[good##n & 0xFF]);\
d1 = _mm_loadl_epi64((__m128i *) &idxlut[(good##n >> 8) & 0xFF]);\
d2 = _mm_loadl_epi64((__m128i *) &idxlut[(good##n >> 16) & 0xFF]);\
d3 = _mm_loadl_epi64((__m128i *) &idxlut[(good##n >> 24) & 0xFF]);\
\
d0 = _mm_shuffle_epi8(g0,d0);\
d1 = _mm_shuffle_epi8(g1,d1);\
d2 = _mm_shuffle_epi8(g2,d2);\
d3 = _mm_shuffle_epi8(g3,d3);\
\
f4 = _mm256_cvtepi8_epi32(d0);\
f5 = _mm256_cvtepi8_epi32(d1);\
f6 = _mm256_cvtepi8_epi32(d2);\
f7 = _mm256_cvtepi8_epi32(d3);\
\
_mm256_storeu_si256((__m256i *) &r[ctr], f4);                                     \
ctr += _mm_popcnt_u32(good##n & 0xFF);\
_mm256_storeu_si256((__m256i *) &r[ctr], f5);                                     \
ctr += _mm_popcnt_u32((good##n >> 8) & 0xFF);\
_mm256_storeu_si256((__m256i *) &r[ctr], f6);                                     \
ctr += _mm_popcnt_u32((good##n >> 16) & 0xFF);\
_mm256_storeu_si256((__m256i *) &r[ctr], f7);                                     \
ctr += _mm_popcnt_u32((good##n >> 24) & 0xFF);\
\

static uint32_t rej_eta_final2(int32_t *restrict r, uint32_t ctr, const uint8_t *buf) {
    __m256i f0, f1;
    __m128i g0, g1;
    __m128i d0, d1;
    uint32_t good0;

    const __m128i mask = _mm_set1_epi8(0x0f);
    const __m128i mask2 = _mm_set1_epi8(0x03);
    const __m128i eta = _mm_set1_epi8(2);
    const __m128i bound = mask;
    const __m128i num13 = _mm_set1_epi16(13);
    const __m128i num5 = _mm_set1_epi16(5);

    g0 = _mm_loadl_epi64((__m128i*)buf);
    g0 = _mm_cvtepu8_epi16(g0);
    g1 = _mm_slli_epi16(g0,4);
    g0 = (g0 | g1) & mask;

    good0 = _mm_movemask_epi8(_mm_sub_epi8(g0,bound));

    g1 = _mm_mullo_epi16(g0, num13);
    g1 = _mm_srli_epi16(g1,6);
    g1 = g1 & mask2;
    g1 = _mm_mullo_epi16(g1, num5);

    g0 = _mm_sub_epi8(g0, g1);
    g0 = _mm_sub_epi8(eta, g0);

    //ctr <= 240
    if (ctr <= (ML_DSA_NUM_POLY_COEFFICIENTS - 16)) {
        g1 = _mm_bsrli_si128(g0, 8);

        d0 = _mm_loadl_epi64((__m128i *) &idxlut[good0 & 0xFF]);
        d1 = _mm_loadl_epi64((__m128i *) &idxlut[(good0 >> 8) & 0xFF]);
        g0 = _mm_shuffle_epi8(g0,d0);
        g1 = _mm_shuffle_epi8(g1,d1);
        f0 = _mm256_cvtepi8_epi32(g0);
        f1 = _mm256_cvtepi8_epi32(g1);

        _mm256_storeu_si256((__m256i *) &r[ctr], f0);
        ctr += _mm_popcnt_u32(good0 & 0xFF);
        _mm256_storeu_si256((__m256i *) &r[ctr], f1);
        ctr += _mm_popcnt_u32((good0 >> 8) & 0xFF);

        return ctr;
    }

    // 248 >= ctr > 240
    if (ctr <= (ML_DSA_NUM_POLY_COEFFICIENTS - 8)) {
        g1 = _mm_bsrli_si128(g0, 8);

        d0 = _mm_loadl_epi64((__m128i *) &idxlut[good0 & 0xFF]);
        d1 = _mm_loadl_epi64((__m128i *) &idxlut[(good0 >> 8) & 0xFF]);
        g0 = _mm_shuffle_epi8(g0,d0);
        g1 = _mm_shuffle_epi8(g1,d1);
        f0 = _mm256_cvtepi8_epi32(g0);
        f1 = _mm256_cvtepi8_epi32(g1);

        _mm256_storeu_si256((__m256i *) &r[ctr], f0);
        ctr += _mm_popcnt_u32(good0 & 0xFF);

        ALIGN(32) int32_t t[8];
        _mm256_storeu_si256((__m256i *) t, f1);
        int count = _mm_popcnt_u32((good0 >> 8) & 0xFF);
        int i = 0;
        while(count != 0 && ctr < ML_DSA_NUM_POLY_COEFFICIENTS) {
            r[ctr] = t[i];
            i++;
            count--;
            ctr++;
        }

        return ctr;
    }

    //ctr > 248
    ALIGN(32) int32_t t[8];

    d0 = _mm_loadl_epi64((__m128i *) &idxlut[good0 & 0xFF]);
    d0 = _mm_shuffle_epi8(g0,d0);
    f0 = _mm256_cvtepi8_epi32(d0);

    _mm256_storeu_si256((__m256i *) t, f0);

    int count = _mm_popcnt_u32((good0 >> 8) & 0xFF);
    int i = 0;
    while(count > 0 && ctr < ML_DSA_NUM_POLY_COEFFICIENTS) {
        r[ctr] = t[i];
        i++;
        count--;
        ctr++;
    }

    return ctr;
}

unsigned int XURQ_AVX2_rej_eta_avx_2(int32_t *restrict r, const uint8_t *buf) {
    unsigned int ctr, pos;
    uint32_t good0, good1, good2, good3;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;
    __m128i g0, g1, g2, g3;
    __m128i d0, d1, d2, d3;
    const __m256i mask = _mm256_set1_epi8(0x0f);
    const __m256i mask2 = _mm256_set1_epi8(0x03);
    const __m256i eta = _mm256_set1_epi8(2);
    const __m256i bound = mask;//15
    const __m256i num5 = _mm256_set1_epi16(5);
    const __m256i num13 = _mm256_set1_epi16(13);
    const __m128i etas = _mm_set1_epi8(2);

    ctr = 0;

    f1 = _mm256_loadu_si256((__m256i *) (buf));
    f3 = _mm256_loadu_si256((__m256i *) (buf + 32));

    f0 = _mm256_cvtepu8_epi16(_mm256_castsi256_si128(f1));
    f1 = _mm256_cvtepu8_epi16(_mm256_extracti128_si256(f1, 1));
    f2 = _mm256_cvtepu8_epi16(_mm256_castsi256_si128(f3));
    f3 = _mm256_cvtepu8_epi16(_mm256_extracti128_si256(f3, 1));

    f4 = _mm256_slli_epi16(f0, 4);
    f5 = _mm256_slli_epi16(f1, 4);
    f6 = _mm256_slli_epi16(f2, 4);
    f7 = _mm256_slli_epi16(f3, 4);

    f0 = _mm256_or_si256(f0, f4);
    f1 = _mm256_or_si256(f1, f5);
    f2 = _mm256_or_si256(f2, f6);
    f3 = _mm256_or_si256(f3, f7);

    f0 = f0 & mask;
    f1 = f1 & mask;
    f2 = f2 & mask;
    f3 = f3 & mask;

    good0 = _mm256_movemask_epi8(_mm256_sub_epi8(f0,bound));
    good1 = _mm256_movemask_epi8(_mm256_sub_epi8(f1,bound));
    good2 = _mm256_movemask_epi8(_mm256_sub_epi8(f2,bound));
    good3 = _mm256_movemask_epi8(_mm256_sub_epi8(f3,bound));

    f4 =_mm256_mullo_epi16(f0,num13);
    f5 =_mm256_mullo_epi16(f1,num13);
    f6 =_mm256_mullo_epi16(f2,num13);
    f7 =_mm256_mullo_epi16(f3,num13);

    f4 = _mm256_srli_epi32(f4, 6);
    f5 = _mm256_srli_epi32(f5, 6);
    f6 = _mm256_srli_epi32(f6, 6);
    f7 = _mm256_srli_epi32(f7, 6);

    f4 = f4 & mask2;
    f5 = f5 & mask2;
    f6 = f6 & mask2;
    f7 = f7 & mask2;

    f4 = _mm256_mullo_epi16(f4,num5);
    f5 = _mm256_mullo_epi16(f5,num5);
    f6 = _mm256_mullo_epi16(f6,num5);
    f7 = _mm256_mullo_epi16(f7,num5);

    f0 = _mm256_sub_epi8(f0, f4);
    f1 = _mm256_sub_epi8(f1, f5);
    f2 = _mm256_sub_epi8(f2, f6);
    f3 = _mm256_sub_epi8(f3, f7);

    f0 = _mm256_sub_epi8(eta, f0);
    f1 = _mm256_sub_epi8(eta, f1);
    f2 = _mm256_sub_epi8(eta, f2);
    f3 = _mm256_sub_epi8(eta, f3);

    REJ(0)
    REJ(1)
    REJ(2)
    REJ(3)

    f1 = _mm256_loadu_si256((__m256i *) (buf + 64));
    f3 = _mm256_loadu_si256((__m256i *) (buf + 96));

    f0 = _mm256_cvtepu8_epi16(_mm256_castsi256_si128(f1));
    f1 = _mm256_cvtepu8_epi16(_mm256_extracti128_si256(f1, 1));
    f2 = _mm256_cvtepu8_epi16(_mm256_castsi256_si128(f3));
    f3 = _mm256_cvtepu8_epi16(_mm256_extracti128_si256(f3, 1));

    f4 = _mm256_slli_epi16(f0, 4);
    f5 = _mm256_slli_epi16(f1, 4);
    f6 = _mm256_slli_epi16(f2, 4);
    f7 = _mm256_slli_epi16(f3, 4);

    f0 = _mm256_or_si256(f0, f4);
    f1 = _mm256_or_si256(f1, f5);
    f2 = _mm256_or_si256(f2, f6);
    f3 = _mm256_or_si256(f3, f7);

    f0 = f0 & mask;
    f1 = f1 & mask;
    f2 = f2 & mask;
    f3 = f3 & mask;

    good0 = _mm256_movemask_epi8(_mm256_sub_epi8(f0,bound));
    good1 = _mm256_movemask_epi8(_mm256_sub_epi8(f1,bound));
    good2 = _mm256_movemask_epi8(_mm256_sub_epi8(f2,bound));
    good3 = _mm256_movemask_epi8(_mm256_sub_epi8(f3,bound));

    f4 =_mm256_mullo_epi16(f0,num13);
    f5 =_mm256_mullo_epi16(f1,num13);
    f6 =_mm256_mullo_epi16(f2,num13);
    f7 =_mm256_mullo_epi16(f3,num13);

    f4 = _mm256_srli_epi32(f4, 6);
    f5 = _mm256_srli_epi32(f5, 6);
    f6 = _mm256_srli_epi32(f6, 6);
    f7 = _mm256_srli_epi32(f7, 6);

    f4 = f4 & mask2;
    f5 = f5 & mask2;
    f6 = f6 & mask2;
    f7 = f7 & mask2;

    f4 = _mm256_mullo_epi16(f4,num5);
    f5 = _mm256_mullo_epi16(f5,num5);
    f6 = _mm256_mullo_epi16(f6,num5);
    f7 = _mm256_mullo_epi16(f7,num5);

    f0 = _mm256_sub_epi8(f0, f4);
    f1 = _mm256_sub_epi8(f1, f5);
    f2 = _mm256_sub_epi8(f2, f6);
    f3 = _mm256_sub_epi8(f3, f7);

    f0 = _mm256_sub_epi8(eta, f0);
    f1 = _mm256_sub_epi8(eta, f1);
    f2 = _mm256_sub_epi8(eta, f2);
    f3 = _mm256_sub_epi8(eta, f3);

    REJ(0)
    REJ(1)
    REJ(2)
    REJ(3)


    if (ctr < ML_DSA_NUM_POLY_COEFFICIENTS)
        ctr = rej_eta_final2(r, ctr,&buf[128]);

    return ctr;
}

static uint32_t rej_eta_2(int32_t *a, uint32_t ctr, const uint8_t *buf) 
{
    int32_t t0, t1;
    int pos = 0;
    while (ctr < ML_DSA_NUM_POLY_COEFFICIENTS && pos < 136) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;

        if (t0 < 15) {
            t0 = t0 - ((13 * t0) >> 6) * 5;
            a[ctr++] = 2 - t0;
        }
        if (t1 < 15 && ctr < ML_DSA_NUM_POLY_COEFFICIENTS) {
            t1 = t1 - ((13 * t1) >> 6) * 5;
            a[ctr++] = 2 - t1;
        }
    }

    return ctr;
}

void ExpandS_44(VECTOR *s1, VECTOR *s2, const uint64_t seed[8]) 
{
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][136];

    POLY *poly1 = s1->poly;
    POLY *poly2 = s2->poly;

    keccakx4_state state;

    // sample and pack s1

    expand_s_state_init(&state, seed, 0, 1, 2, 3);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_2(poly1+0, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_2(poly1+1, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_2(poly1+2, buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_2(poly1+3, buf[3]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) 
    {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = rej_eta_2(poly1+0,ctr[0], buf[0]);
        ctr[1] = rej_eta_2(poly1+1,ctr[1], buf[1]);
        ctr[2] = rej_eta_2(poly1+2,ctr[2], buf[2]);
        ctr[3] = rej_eta_2(poly1+3,ctr[3], buf[3]);
    }

    // sample and pack s2

    expand_s_state_init(&state, seed, 4, 5, 6, 7);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_2(poly2+0, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_2(poly2+1, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_2(poly2+2, buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_2(poly2+3, buf[3]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) 
    {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] += rej_eta_2(poly2+0, ctr[0],buf[0]);
        ctr[1] += rej_eta_2(poly2+1, ctr[1],buf[1]);
        ctr[2] += rej_eta_2(poly2+2, ctr[2],buf[2]);
        ctr[3] += rej_eta_2(poly2+3, ctr[3],buf[3]);
    }

    for(int i = 0; i < s1->num_poly; i++) poly_normalize_avx2(poly1+i);
    for(int i = 0; i < s2->num_poly; i++) poly_normalize_avx2(poly2+i);

}
/* end expand S 44 */


/* begin expand S 65 */
unsigned int XURQ_AVX2_rej_eta_avx_4(int32_t *restrict r, const uint8_t *buf) {
    unsigned int ctr, pos;
    uint32_t good;
    __m256i f0, f1;
    __m128i g0, g1;
    const __m256i mask = _mm256_set1_epi8(15);
    const __m256i eta = _mm256_set1_epi8(4);
    const __m128i etas = _mm_set1_epi8(4);
    const __m256i bound = _mm256_set1_epi8(9);

    ctr = pos = 0;
    while (ctr <= ML_DSA_NUM_POLY_COEFFICIENTS - 8 && pos <= 136 - 16) {
        f0 = _mm256_cvtepu8_epi16(_mm_loadu_si128((__m128i *)&buf[pos]));
        f1 = _mm256_slli_epi16(f0, 4);
        f0 = _mm256_or_si256(f0, f1);
        f0 = _mm256_and_si256(f0, mask);

        f1 = _mm256_sub_epi8(f0, bound);
        f0 = _mm256_sub_epi8(eta, f0);
        good = _mm256_movemask_epi8(f1);

        g0 = _mm256_castsi256_si128(f0);
        g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);

        _mm256_storeu_si256((__m256i *)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > ML_DSA_NUM_POLY_COEFFICIENTS - 8) {
            break;
        }
        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i *)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > ML_DSA_NUM_POLY_COEFFICIENTS - 8) {
            break;
        }
        g0 = _mm256_extracti128_si256(f0, 1);
        g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i *)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > ML_DSA_NUM_POLY_COEFFICIENTS - 8) {
            break;
        }
        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i *)&idxlut[good]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i *)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good);
        pos += 4;
    }

    uint32_t t0, t1;
    while (ctr < ML_DSA_NUM_POLY_COEFFICIENTS && pos < 136) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;

        if (t0 < 9) {
            r[ctr] = 4 - t0;
            ctr++;
        }
        if (t1 < 9 && ctr < ML_DSA_NUM_POLY_COEFFICIENTS) {
            r[ctr] = 4 - t1;
            ctr++;
        }
    }

    return ctr;
}

static uint32_t rej_eta_4(int32_t *a, uint32_t ctr, const uint8_t *buf) 
{
    int32_t t0, t1;
    int pos = 0;
    while (ctr < ML_DSA_NUM_POLY_COEFFICIENTS && pos < SHAKE256_RATE) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;

        if (t0 < 9) {
            a[ctr] = 4 - t0;
            ctr++;
        }
        if (t1 < 9 && ctr < ML_DSA_NUM_POLY_COEFFICIENTS) {
            a[ctr] = 4 - t1;
            ctr++;
        }
    }

    return ctr;
}

void ExpandS_65(VECTOR *s1, VECTOR *s2, const uint64_t seed[8]) 
{
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][136];

    POLY *poly1 = s1->poly;
    POLY *poly2 = s2->poly;

    keccakx4_state state;

    // sample and pack s1[0] s1[1] s1[2] s1[3]

    expand_s_state_init(&state, seed, 0, 1, 2, 3);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 2, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_4(poly1+0, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_4(poly1+1, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_4(poly1+2, buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_4(poly1+3, buf[3]);


    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = rej_eta_4(poly1+0, ctr[0], buf[0]);
        ctr[1] = rej_eta_4(poly1+1, ctr[1], buf[1]);
        ctr[2] = rej_eta_4(poly1+2, ctr[2], buf[2]);
        ctr[3] = rej_eta_4(poly1+3, ctr[3], buf[3]);

    }

    // sample and pack  s1[4] s2[0] s2[1] s2[2]

    expand_s_state_init(&state, seed, 4, 5, 6, 7);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],  2, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_4(poly1+4, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_4(poly2+0, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_4(poly2+1, buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_4(poly2+2, buf[3]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],  1, &state);

        ctr[0] = rej_eta_4(poly1+4, ctr[0],buf[0]);
        ctr[1] = rej_eta_4(poly2+0, ctr[1],buf[1]);
        ctr[2] = rej_eta_4(poly2+1, ctr[2],buf[2]);
        ctr[3] = rej_eta_4(poly2+2, ctr[3],buf[3]);
    }

    // sample and pack   s2[3] s2[4] s2[5]

    expand_s_state_init(&state, seed, 8, 9, 10, 11);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],  2, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_4(poly2+3, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_4(poly2+4, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_4(poly2+5, buf[2]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS ) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],  1, &state);

        ctr[0] = rej_eta_4(poly2+3, ctr[0],buf[0]);
        ctr[1] = rej_eta_4(poly2+4, ctr[1],buf[1]);
        ctr[2] = rej_eta_4(poly2+5, ctr[2],buf[2]);
    }

    for(int i = 0; i < s1->num_poly; i++) poly_normalize_avx2(poly1+i);
    for(int i = 0; i < s2->num_poly; i++) poly_normalize_avx2(poly2+i);
}
/* end expand S 65 */

/* begin expand S 87 */

void ExpandS_87(VECTOR *s1, VECTOR *s2, const uint64_t seed[8])
{
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][136];

    POLY *poly1 = s1->poly;
    POLY *poly2 = s2->poly;

    keccakx4_state state;

    // sample and pack s1

    expand_s_state_init(&state, seed, 0, 1, 2, 3);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_2(poly1+0, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_2(poly1+1, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_2(poly1+2, buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_2(poly1+3, buf[3]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = rej_eta_2(poly1+0,ctr[0], buf[0]);
        ctr[1] = rej_eta_2(poly1+1,ctr[1], buf[1]);
        ctr[2] = rej_eta_2(poly1+2,ctr[2], buf[2]);
        ctr[3] = rej_eta_2(poly1+3,ctr[3], buf[3]);
    }

    expand_s_state_init(&state, seed, 4, 5, 6, 7);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_2(poly1+4, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_2(poly1+5, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_2(poly1+6, buf[2]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = rej_eta_2(poly1+4,ctr[0], buf[0]);
        ctr[1] = rej_eta_2(poly1+5,ctr[1], buf[1]);
        ctr[2] = rej_eta_2(poly1+6,ctr[2], buf[2]);
    }

    // sample and pack s2

    expand_s_state_init(&state, seed, 7, 8, 9, 10);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_2(poly2+0, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_2(poly2+1, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_2(poly2+2, buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_2(poly2+3, buf[3]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] += rej_eta_2(poly2+0, ctr[0], buf[0]);
        ctr[1] += rej_eta_2(poly2+1, ctr[1], buf[1]);
        ctr[2] += rej_eta_2(poly2+2, ctr[2], buf[2]);
        ctr[3] += rej_eta_2(poly2+3, ctr[3], buf[3]);
    }

    expand_s_state_init(&state, seed, 11, 12, 13, 14);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_2(poly2+4, buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_2(poly2+5, buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_2(poly2+6, buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_2(poly2+7, buf[3]);

    while (ctr[0] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[1] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[2] < ML_DSA_NUM_POLY_COEFFICIENTS || ctr[3] < ML_DSA_NUM_POLY_COEFFICIENTS) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],1, &state);

        ctr[0] += rej_eta_2(poly2+4, ctr[0], buf[0]);
        ctr[1] += rej_eta_2(poly2+5, ctr[1], buf[1]);
        ctr[2] += rej_eta_2(poly2+6, ctr[2], buf[2]);
        ctr[3] += rej_eta_2(poly2+7, ctr[3], buf[3]);
    }

    for(int i = 0; i < s1->num_poly; i++) poly_normalize_avx2(poly1+i);
    for(int i = 0; i < s2->num_poly; i++) poly_normalize_avx2(poly2+i);
}

/* end expand S 87 */

/* begin sample gamma1 */
void polyz_unpack_19(uint32_t *restrict r, const uint8_t *a) {
  unsigned int i;
  __m256i f;
  const __m256i shufbidx = _mm256_set_epi8(-1, 11, 10, 9, -1, 9, 8, 7, -1, 6, 5, 4, -1, 4, 3, 2, -1, 9, 8, 7, -1, 7, 6,
                                           5, -1, 4, 3, 2, -1, 2, 1, 0);
  const __m256i srlvdidx = _mm256_set1_epi64x((uint64_t) 4 << 32);
  const __m256i mask = _mm256_set1_epi32(0xFFFFF);
  const __m256i gamma1 = _mm256_set1_epi32(1u<<19);

  for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS / 8; i++) {
    f = _mm256_loadu_si256(a + 20 * i);
    f = _mm256_permute4x64_epi64(f, 0x94);
    f = _mm256_shuffle_epi8(f, shufbidx);
    f = _mm256_srlv_epi32(f, srlvdidx);
    f = _mm256_and_si256(f, mask);
    f = _mm256_sub_epi32(gamma1, f);
    _mm256_storeu_si256((__m256i *)(r + i * 8), f);
  }
}

void polyz_unpack_17(uint32_t *r, const uint8_t *a) {
  __m256i f0, f1, f2;
  const __m256i shufbidx = _mm256_set_epi8(-1, 9, 8, 7, -1, 7, 6, 5, -1, 5, 4, 3, -1, 3, 2, 1, -1, 8, 7, 6, -1, 6, 5, 4,
                                           -1, 4, 3, 2, -1, 2, 1, 0);
  const __m256i srlvdidx = _mm256_set_epi32(6, 4, 2, 0, 6, 4, 2, 0);
  const __m256i mask = _mm256_set1_epi32(0x3FFFF);
  const __m256i gamma1 = _mm256_set1_epi32(1u<<17);

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

    _mm256_storeu_si256((__m256i *)(r + i * 8), f0);
    _mm256_storeu_si256((__m256i *)(r + (i + 1) * 8), f1);
    _mm256_storeu_si256((__m256i *)(r + (i + 2) * 8), f2);
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

  _mm256_storeu_si256((__m256i *)(r + 30 * 8), f0);
  _mm256_storeu_si256((__m256i *)(r + 31 * 8), f1);
}

void poly_generate_random_gamma1_4x(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, 
                        uint32_t gamma1, const uint8_t seed[64], 
                        uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3) 
{
    keccakx4_state state;
    uint64_t *seed64 = (uint64_t *) seed;
    uint8_t y_buff0[680], y_buff1[680], y_buff2[680], y_buff3[680];

    state.s[0] = _mm256_set1_epi64x(seed64[0]);
    state.s[1] = _mm256_set1_epi64x(seed64[1]);
    state.s[2] = _mm256_set1_epi64x(seed64[2]);
    state.s[3] = _mm256_set1_epi64x(seed64[3]);
    state.s[4] = _mm256_set1_epi64x(seed64[4]);
    state.s[5] = _mm256_set1_epi64x(seed64[5]);
    state.s[6] = _mm256_set1_epi64x(seed64[6]);
    state.s[7] = _mm256_set1_epi64x(seed64[7]);
    state.s[8] = _mm256_set_epi64x((0x1f << 16) ^ nonce3, (0x1f << 16) ^ nonce2, (0x1f << 16) ^ nonce1,
                                   (0x1f << 16) ^ nonce0);

    for (int j = 9; j < 25; ++j) state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(y_buff0, y_buff1, y_buff2, y_buff3, 5, &state);

    if(gamma1 == 1u << 17){
        polyz_unpack_17(r0, y_buff0);
        polyz_unpack_17(r1, y_buff1);
        polyz_unpack_17(r2, y_buff2);
        polyz_unpack_17(r3, y_buff3);
    }
    else{
        polyz_unpack_19(r0, y_buff0);
        polyz_unpack_19(r1, y_buff1);
        polyz_unpack_19(r2, y_buff2);
        polyz_unpack_19(r3, y_buff3);
    }
}

void expand_mask_avx2(VECTOR *out, const uint8_t *rho_prime, uint32_t kappa, uint32_t gamma1)
{
    POLY *poly = out->poly;
    POLY tmp1, tmp2, tmp3;

    if(out->num_poly == 4){
        poly_generate_random_gamma1_4x(poly+0, poly+1, poly+2, poly+3, gamma1, rho_prime, kappa+0, kappa+1, kappa+2, kappa+3);
    }
    else if(out->num_poly == 5){
        poly_generate_random_gamma1_4x(poly+0, poly+1, poly+2, poly+3, gamma1, rho_prime, kappa+0, kappa+1, kappa+2, kappa+3);
        poly_generate_random_gamma1_4x(poly+4, &tmp1, &tmp2, &tmp3, gamma1, rho_prime, kappa+4, kappa+5, kappa+6, kappa+7);
    }
    else {
        poly_generate_random_gamma1_4x(poly+0, poly+1, poly+2, poly+3, gamma1, rho_prime, kappa+0, kappa+1, kappa+2, kappa+3);
        poly_generate_random_gamma1_4x(poly+4, poly+5, poly+6, &tmp1, gamma1, rho_prime, kappa+4, kappa+5, kappa+6, kappa+7);
    }

    for(int i = 0; i < out->num_poly; i++) poly_normalize_avx2(poly+i);
}

/* end sample gamma1 */