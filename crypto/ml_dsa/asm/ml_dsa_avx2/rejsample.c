#include <stdint.h>
#include <immintrin.h>
#include "params.h"
#include "rejsample.h"

#include "align.h"
#include "polyvec.h"
#include "keccak4x/symmetric.h"
#include "keccak4x/fips202x4.h"
#include "ntt/consts.h"
#include "ntt/ntt.h"



ALIGN(32)
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


unsigned int XURQ_AVX2_rej_uniform_avx_s1s3(int32_t *restrict r, const uint8_t *buf, unsigned int num) {
    unsigned int ctr, pos;
    uint32_t good;
    __m256i d, tmp;
    const __m256i bound = _mm256_set1_epi32(Q);
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
    const __m256i bound = _mm256_set1_epi32(Q);
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
    while (ctr < N && pos <= 168) {
        t = buf[pos++];
        t |= (uint32_t) buf[pos++] << 8;
        t |= (uint32_t) buf[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < Q) {
            r[ctr++] = t;
        }
    }

    return ctr;
}

unsigned int rej_uniform_avx(int32_t *restrict r, const uint8_t *buf, unsigned int num) {
    unsigned int ctr, pos;
    uint32_t good;
    __m256i d, tmp;
    const __m256i bound = _mm256_set1_epi32(Q);
    const __m256i mask = _mm256_set1_epi32(0x7FFFFF);
    const __m256i idx8 = _mm256_set_epi8(-1, 15, 14, 13, -1, 12, 11, 10,
                                         -1, 9, 8, 7, -1, 6, 5, 4,
                                         -1, 11, 10, 9, -1, 8, 7, 6,
                                         -1, 5, 4, 3, -1, 2, 1, 0);

    ctr = num;

    pos = 0;

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
    while (ctr < N && pos <= 168) {
        t = buf[pos++];
        t |= (uint32_t) buf[pos++] << 8;
        t |= (uint32_t) buf[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < Q) {
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

        if (t < Q) {
            a[ctr++] = t;
        }
    }

    return ctr;
}


static void state_trans4x4(__m256i * s, __m256i f0, __m256i f1, __m256i f2, __m256i f3) {
    __m256i t0, t1, t2, t3;
    t0 = _mm256_unpacklo_epi64(f0, f1);
    t1 = _mm256_unpackhi_epi64(f0, f1);
    t2 = _mm256_unpacklo_epi64(f2, f3);
    t3 = _mm256_unpackhi_epi64(f2, f3);

    s[0] = _mm256_permute2x128_si256(t0, t2, 0x20);
    s[1] = _mm256_permute2x128_si256(t1, t3, 0x20);
    s[2] = _mm256_permute2x128_si256(t0, t2, 0x31);
    s[3] = _mm256_permute2x128_si256(t1, t3, 0x31);
}

void poly_uniform_4x_op13_state_trans(poly *a0,
                          poly *a1,
                          poly *a2,
                          poly *a3,
                          const uint8_t seed[32],
                          uint16_t nonce0,
                          uint16_t nonce1,
                          uint16_t nonce2,
                          uint16_t nonce3) {
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][192];
    keccakx4_state state;
    uint64_t *seed64 = (uint64_t *) seed;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;;

    f0 = _mm256_loadu_si256((__m256i *)seed);
    f1 = f0;
    f2 = f0;
    f3 = f0;
    state_trans4x4(state.s, f0,f1,f2,f3);

    // state.s[0] = _mm256_set1_epi64x(seed64[0]);
    // state.s[1] = _mm256_set1_epi64x(seed64[1]);
    // state.s[2] = _mm256_set1_epi64x(seed64[2]);
    // state.s[3] = _mm256_set1_epi64x(seed64[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ nonce3, (0x1f << 16) ^ nonce2,
                                   (0x1f << 16) ^ nonce1, (0x1f << 16) ^ nonce0);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[20] = _mm256_set1_epi64x(0x1ULL << 63);

    for (int i = 0; i < 4; ++i) {
        XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0], ctr[0]);
        ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1], ctr[1]);
        ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3(a2->coeffs, buf[2], ctr[2]);
        ctr[3] = XURQ_AVX2_rej_uniform_avx_s1s3(a3->coeffs, buf[3], ctr[3]);
    }

    XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a0->coeffs, buf[0], ctr[0]);
    ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a1->coeffs, buf[1], ctr[1]);
    ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a2->coeffs, buf[2], ctr[2]);
    ctr[3] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a3->coeffs, buf[3], ctr[3]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] += rej_uniform(a0->coeffs + ctr[0], N - ctr[0], buf[0], SHAKE128_RATE);
        ctr[1] += rej_uniform(a1->coeffs + ctr[1], N - ctr[1], buf[1], SHAKE128_RATE);
        ctr[2] += rej_uniform(a2->coeffs + ctr[2], N - ctr[2], buf[2], SHAKE128_RATE);
        ctr[3] += rej_uniform(a3->coeffs + ctr[3], N - ctr[3], buf[3], SHAKE128_RATE);
    }
}

void poly_uniform_4x_op13(poly *a0,
                          poly *a1,
                          poly *a2,
                          poly *a3,
                          const uint8_t seed[32],
                          uint16_t nonce0,
                          uint16_t nonce1,
                          uint16_t nonce2,
                          uint16_t nonce3) {
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][192];
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

        ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0], ctr[0]);
        ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1], ctr[1]);
        ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3(a2->coeffs, buf[2], ctr[2]);
        ctr[3] = XURQ_AVX2_rej_uniform_avx_s1s3(a3->coeffs, buf[3], ctr[3]);
    }

    XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a0->coeffs, buf[0], ctr[0]);
    ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a1->coeffs, buf[1], ctr[1]);
    ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a2->coeffs, buf[2], ctr[2]);
    ctr[3] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a3->coeffs, buf[3], ctr[3]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] += rej_uniform(a0->coeffs + ctr[0], N - ctr[0], buf[0], SHAKE128_RATE);
        ctr[1] += rej_uniform(a1->coeffs + ctr[1], N - ctr[1], buf[1], SHAKE128_RATE);
        ctr[2] += rej_uniform(a2->coeffs + ctr[2], N - ctr[2], buf[2], SHAKE128_RATE);
        ctr[3] += rej_uniform(a3->coeffs + ctr[3], N - ctr[3], buf[3], SHAKE128_RATE);
    }
}

#if K == 4

void ExpandA_shuffled(polyvecl mat[4], const uint8_t *rho) {
    poly_uniform_4x_op13(&mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], &mat[0].vec[3], rho, 0, 1, 2, 3);
    shuffle(mat[0].vec[0].coeffs);
    shuffle(mat[0].vec[1].coeffs);
    shuffle(mat[0].vec[2].coeffs);
    shuffle(mat[0].vec[3].coeffs);
    poly_uniform_4x_op13(&mat[1].vec[0], &mat[1].vec[1], &mat[1].vec[2], &mat[1].vec[3], rho, 256, 257,
                         258, 259);
    shuffle(mat[1].vec[0].coeffs);
    shuffle(mat[1].vec[1].coeffs);
    shuffle(mat[1].vec[2].coeffs);
    shuffle(mat[1].vec[3].coeffs);
    poly_uniform_4x_op13(&mat[2].vec[0], &mat[2].vec[1], &mat[2].vec[2], &mat[2].vec[3], rho, 512, 513,
                         514, 515);
    shuffle(mat[2].vec[0].coeffs);
    shuffle(mat[2].vec[1].coeffs);
    shuffle(mat[2].vec[2].coeffs);
    shuffle(mat[2].vec[3].coeffs);
    poly_uniform_4x_op13(&mat[3].vec[0], &mat[3].vec[1], &mat[3].vec[2], &mat[3].vec[3], rho, 768, 769,
                         770, 771);
    shuffle(mat[3].vec[0].coeffs);
    shuffle(mat[3].vec[1].coeffs);
    shuffle(mat[3].vec[2].coeffs);
    shuffle(mat[3].vec[3].coeffs);
}

void ExpandA_row(polyvecl **row, polyvecl buf[2], const uint8_t rho[32], unsigned int i) {
    switch (i) {
        case 0:
            poly_uniform_4x_op13(&buf[0].vec[0], &buf[0].vec[1], &buf[0].vec[2], &buf[0].vec[3], rho, 0,
                                 1, 2, 3);
            *row = buf;
            break;
        case 1:
            poly_uniform_4x_op13(&buf[1].vec[0], &buf[1].vec[1], &buf[1].vec[2], &buf[1].vec[3], rho,
                                 256, 257,
                                 258, 259);
            *row = buf + 1;
            break;
        case 2:
            poly_uniform_4x_op13(&buf[0].vec[0], &buf[0].vec[1], &buf[0].vec[2], &buf[0].vec[3], rho,
                                 512, 513,
                                 514, 515);
            *row = buf;
            break;
        case 3:
            poly_uniform_4x_op13(&buf[1].vec[0], &buf[1].vec[1], &buf[1].vec[2], &buf[1].vec[3], rho,
                                 768, 769,
                                 770, 771);
            *row = buf + 1;
            break;
    }
}

#elif K == 6

void XURQ_AVX2_polyvec_matrix_expand_row0(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 0, 1, 2, 3);
    poly_uniform_4x_op13(&rowa->vec[4], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 4, 256, 257, 258);
}

void XURQ_AVX2_polyvec_matrix_expand_row1(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[3], &rowa->vec[4], &rowb->vec[0], &rowb->vec[1], rho, 259, 260, 512, 513);

}

void XURQ_AVX2_polyvec_matrix_expand_row2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowb->vec[0], rho, 514, 515, 516, 768);

}

void XURQ_AVX2_polyvec_matrix_expand_row3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 769, 770, 771, 772);

}

void XURQ_AVX2_polyvec_matrix_expand_row4(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 1024, 1025, 1026, 1027);
    poly_uniform_4x_op13(&rowa->vec[4], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 1028, 1280, 1281, 1282);

}

void XURQ_AVX2_polyvec_matrix_expand_row5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[3], &rowa->vec[4], &rowb->vec[0], &rowb->vec[1], rho, 1283, 1284, 1536, 1537);

}

static void XURQ_AVX2_polyvec_matrix_expand_row0_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 0, 1, 2, 3);
    poly_uniform_4x_op13(&rowa->vec[4], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 4, 256, 257, 258);
    shuffle(rowa->vec[0].coeffs);
    shuffle(rowa->vec[1].coeffs);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowb->vec[0].coeffs);
    shuffle(rowb->vec[1].coeffs);
    shuffle(rowb->vec[2].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row1_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[3], &rowa->vec[4], &rowb->vec[0], &rowb->vec[1], rho, 259, 260, 512, 513);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowb->vec[0].coeffs);
    shuffle(rowb->vec[1].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row2_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowb->vec[0], rho, 514, 515, 516, 768);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowb->vec[0].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row3_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 769, 770, 771, 772);
    shuffle(rowa->vec[1].coeffs);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row4_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 1024, 1025, 1026, 1027);
    poly_uniform_4x_op13(&rowa->vec[4], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 1028, 1280, 1281, 1282);
    shuffle(rowa->vec[0].coeffs);
    shuffle(rowa->vec[1].coeffs);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowb->vec[0].coeffs);
    shuffle(rowb->vec[1].coeffs);
    shuffle(rowb->vec[2].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row5_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[3], &rowa->vec[4], &rowb->vec[0], &rowb->vec[1], rho, 1283, 1284, 1536, 1537);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
}

void ExpandA_shuffled(polyvecl mat[6], const uint8_t rho[32]) {
    polyvecl tmp;
    XURQ_AVX2_polyvec_matrix_expand_row0_shuffled(&mat[0], &mat[1], rho);
    XURQ_AVX2_polyvec_matrix_expand_row1_shuffled(&mat[1], &mat[2], rho);
    XURQ_AVX2_polyvec_matrix_expand_row2_shuffled(&mat[2], &mat[3], rho);
    XURQ_AVX2_polyvec_matrix_expand_row3_shuffled(&mat[3], NULL, rho);
    XURQ_AVX2_polyvec_matrix_expand_row4_shuffled(&mat[4], &mat[5], rho);
    XURQ_AVX2_polyvec_matrix_expand_row5_shuffled(&mat[5], &tmp, rho);
}

void ExpandA_row(polyvecl **row, polyvecl buf[2], const uint8_t rho[32], unsigned int i) {
    switch (i) {
        case 0:
            XURQ_AVX2_polyvec_matrix_expand_row0(buf, buf + 1, rho);
            *row = buf;
            break;
        case 1:
            XURQ_AVX2_polyvec_matrix_expand_row1(buf + 1, buf, rho);
            *row = buf + 1;
            break;
        case 2:
            XURQ_AVX2_polyvec_matrix_expand_row2(buf, buf + 1, rho);
            *row = buf;
            break;
        case 3:
            XURQ_AVX2_polyvec_matrix_expand_row3(buf + 1, buf, rho);
            *row = buf + 1;
            break;
        case 4:
            XURQ_AVX2_polyvec_matrix_expand_row4(buf, buf + 1, rho);
            *row = buf;
            break;
        case 5:
            XURQ_AVX2_polyvec_matrix_expand_row5(buf + 1, buf, rho);
            *row = buf + 1;
            break;
    }
}

#elif K == 8



static void XURQ_AVX2_polyvec_matrix_expand_row0_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 0, 1, 2, 3);
    poly_uniform_4x_op13(&rowa->vec[4], &rowa->vec[5], &rowa->vec[6], &rowb->vec[0], rho, 4, 5, 6, 256);
    shuffle(rowa->vec[0].coeffs);
    shuffle(rowa->vec[1].coeffs);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowa->vec[5].coeffs);
    shuffle(rowa->vec[6].coeffs);
    shuffle(rowb->vec[0].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row1_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 257, 258, 259, 260);
    poly_uniform_4x_op13(&rowa->vec[5], &rowa->vec[6], &rowb->vec[0], &rowb->vec[1], rho, 261, 262, 512, 513);
    shuffle(rowa->vec[1].coeffs);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowa->vec[5].coeffs);
    shuffle(rowa->vec[6].coeffs);
    shuffle(rowb->vec[0].coeffs);
    shuffle(rowb->vec[1].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row2_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowa->vec[5], rho, 514, 515, 516, 517);
    poly_uniform_4x_op13(&rowa->vec[6], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 518, 768, 769, 770);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowa->vec[5].coeffs);
    shuffle(rowa->vec[6].coeffs);
    shuffle(rowb->vec[0].coeffs);
    shuffle(rowb->vec[1].coeffs);
    shuffle(rowb->vec[2].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row3_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[3], &rowa->vec[4], &rowa->vec[5], &rowa->vec[6], rho, 771, 772, 773, 774);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowa->vec[5].coeffs);
    shuffle(rowa->vec[6].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row4_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 1024, 1025, 1026, 1027);
    poly_uniform_4x_op13(&rowa->vec[4], &rowa->vec[5], &rowa->vec[6], &rowb->vec[0], rho, 1028, 1029, 1030, 1280);
    shuffle(rowa->vec[0].coeffs);
    shuffle(rowa->vec[1].coeffs);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowa->vec[5].coeffs);
    shuffle(rowa->vec[6].coeffs);
    shuffle(rowb->vec[0].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row5_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 1281, 1282, 1283, 1284);
    poly_uniform_4x_op13(&rowa->vec[5], &rowa->vec[6], &rowb->vec[0], &rowb->vec[1], rho, 1285, 1286, 1536, 1537);
    shuffle(rowa->vec[1].coeffs);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowa->vec[5].coeffs);
    shuffle(rowa->vec[6].coeffs);
    shuffle(rowb->vec[0].coeffs);
    shuffle(rowb->vec[1].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row6_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowa->vec[5], rho, 1538, 1539, 1540, 1541);
    poly_uniform_4x_op13(&rowa->vec[6], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 1542, 1792, 1793, 1794);
    shuffle(rowa->vec[2].coeffs);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowa->vec[5].coeffs);
    shuffle(rowa->vec[6].coeffs);
    shuffle(rowb->vec[0].coeffs);
    shuffle(rowb->vec[1].coeffs);
    shuffle(rowb->vec[2].coeffs);
}

static void XURQ_AVX2_polyvec_matrix_expand_row7_shuffled(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[3], &rowa->vec[4], &rowa->vec[5], &rowa->vec[6], rho, 1795, 1796, 1797, 1798);
    shuffle(rowa->vec[3].coeffs);
    shuffle(rowa->vec[4].coeffs);
    shuffle(rowa->vec[5].coeffs);
    shuffle(rowa->vec[6].coeffs);
}


static void XURQ_AVX2_polyvec_matrix_expand_row0(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 0, 1, 2, 3);
    poly_uniform_4x_op13(&rowa->vec[4], &rowa->vec[5], &rowa->vec[6], &rowb->vec[0], rho, 4, 5, 6, 256);
}

static void XURQ_AVX2_polyvec_matrix_expand_row1(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 257, 258, 259, 260);
    poly_uniform_4x_op13(&rowa->vec[5], &rowa->vec[6], &rowb->vec[0], &rowb->vec[1], rho, 261, 262, 512, 513);
}

static void XURQ_AVX2_polyvec_matrix_expand_row2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowa->vec[5], rho, 514, 515, 516, 517);
    poly_uniform_4x_op13(&rowa->vec[6], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 518, 768, 769, 770);
}

static void XURQ_AVX2_polyvec_matrix_expand_row3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[3], &rowa->vec[4], &rowa->vec[5], &rowa->vec[6], rho, 771, 772, 773, 774);
}

static void XURQ_AVX2_polyvec_matrix_expand_row4(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 1024, 1025, 1026, 1027);
    poly_uniform_4x_op13(&rowa->vec[4], &rowa->vec[5], &rowa->vec[6], &rowb->vec[0], rho, 1028, 1029, 1030, 1280);
}

static void XURQ_AVX2_polyvec_matrix_expand_row5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 1281, 1282, 1283, 1284);
    poly_uniform_4x_op13(&rowa->vec[5], &rowa->vec[6], &rowb->vec[0], &rowb->vec[1], rho, 1285, 1286, 1536, 1537);
}

static void XURQ_AVX2_polyvec_matrix_expand_row6(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowa->vec[5], rho, 1538, 1539, 1540, 1541);
    poly_uniform_4x_op13(&rowa->vec[6], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 1542, 1792, 1793, 1794);
}

static void XURQ_AVX2_polyvec_matrix_expand_row7(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    poly_uniform_4x_op13(&rowa->vec[3], &rowa->vec[4], &rowa->vec[5], &rowa->vec[6], rho, 1795, 1796, 1797, 1798);
}

void ExpandA_shuffled(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
    XURQ_AVX2_polyvec_matrix_expand_row0_shuffled(&mat[0], &mat[1], rho);
    XURQ_AVX2_polyvec_matrix_expand_row1_shuffled(&mat[1], &mat[2], rho);
    XURQ_AVX2_polyvec_matrix_expand_row2_shuffled(&mat[2], &mat[3], rho);
    XURQ_AVX2_polyvec_matrix_expand_row3_shuffled(&mat[3], NULL, rho);
    XURQ_AVX2_polyvec_matrix_expand_row4_shuffled(&mat[4], &mat[5], rho);
    XURQ_AVX2_polyvec_matrix_expand_row5_shuffled(&mat[5], &mat[6], rho);
    XURQ_AVX2_polyvec_matrix_expand_row6_shuffled(&mat[6], &mat[7], rho);
    XURQ_AVX2_polyvec_matrix_expand_row7_shuffled(&mat[7], NULL, rho);
}


void ExpandA_row(polyvecl **row, polyvecl buf[2], const uint8_t rho[SEEDBYTES], unsigned int i) {
    switch (i) {
        case 0:
            XURQ_AVX2_polyvec_matrix_expand_row0(buf, buf + 1, rho);
            *row = buf;
            break;
        case 1:
            XURQ_AVX2_polyvec_matrix_expand_row1(buf + 1, buf, rho);
            *row = buf + 1;
            break;
        case 2:
            XURQ_AVX2_polyvec_matrix_expand_row2(buf, buf + 1, rho);
            *row = buf;
            break;
        case 3:
            XURQ_AVX2_polyvec_matrix_expand_row3(buf + 1, buf, rho);
            *row = buf + 1;
            break;
        case 4:
            XURQ_AVX2_polyvec_matrix_expand_row4(buf, buf + 1, rho);
            *row = buf;
            break;
        case 5:
            XURQ_AVX2_polyvec_matrix_expand_row5(buf + 1, buf, rho);
            *row = buf + 1;
            break;
        case 6:
            XURQ_AVX2_polyvec_matrix_expand_row6(buf, buf + 1, rho);
            *row = buf;
            break;
        case 7:
            XURQ_AVX2_polyvec_matrix_expand_row7(buf + 1, buf, rho);
            *row = buf + 1;
            break;
    }
}
#endif



#if K == 4

void ExpandA(polyvecl mat[K], const uint8_t *rho) {
    poly_uniform_4x_op13(&mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], &mat[0].vec[3], rho, 0, 1, 2, 3);
    poly_uniform_4x_op13(&mat[1].vec[0], &mat[1].vec[1], &mat[1].vec[2], &mat[1].vec[3], rho, 256, 257,
                         258, 259);
    poly_uniform_4x_op13(&mat[2].vec[0], &mat[2].vec[1], &mat[2].vec[2], &mat[2].vec[3], rho, 512, 513,
                         514, 515);
    poly_uniform_4x_op13(&mat[3].vec[0], &mat[3].vec[1], &mat[3].vec[2], &mat[3].vec[3], rho, 768, 769,
                         770, 771);
}

#elif K == 6

void ExpandA(polyvecl mat[K], const uint8_t rho[32]) {
    polyvecl tmp;
    XURQ_AVX2_polyvec_matrix_expand_row0(&mat[0], &mat[1], rho);
    XURQ_AVX2_polyvec_matrix_expand_row1(&mat[1], &mat[2], rho);
    XURQ_AVX2_polyvec_matrix_expand_row2(&mat[2], &mat[3], rho);
    XURQ_AVX2_polyvec_matrix_expand_row3(&mat[3], NULL, rho);
    XURQ_AVX2_polyvec_matrix_expand_row4(&mat[4], &mat[5], rho);
    XURQ_AVX2_polyvec_matrix_expand_row5(&mat[5], &tmp, rho);
}

#elif K == 8

void ExpandA(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
    XURQ_AVX2_polyvec_matrix_expand_row0(&mat[0], &mat[1], rho);
    XURQ_AVX2_polyvec_matrix_expand_row1(&mat[1], &mat[2], rho);
    XURQ_AVX2_polyvec_matrix_expand_row2(&mat[2], &mat[3], rho);
    XURQ_AVX2_polyvec_matrix_expand_row3(&mat[3], NULL, rho);
    XURQ_AVX2_polyvec_matrix_expand_row4(&mat[4], &mat[5], rho);
    XURQ_AVX2_polyvec_matrix_expand_row5(&mat[5], &mat[6], rho);
    XURQ_AVX2_polyvec_matrix_expand_row6(&mat[6], &mat[7], rho);
    XURQ_AVX2_polyvec_matrix_expand_row7(&mat[7], NULL, rho);
}

#endif

#if ETA == 2

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
_mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(etas, d0));\
ctr += _mm_popcnt_u32(good##n & 0xFF);\
_mm256_storeu_si256((__m256i *) &r[ctr], f5);                                     \
_mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(etas, d1));\
ctr += _mm_popcnt_u32((good##n >> 8) & 0xFF);\
_mm256_storeu_si256((__m256i *) &r[ctr], f6);                                     \
_mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(etas, d2));\
ctr += _mm_popcnt_u32((good##n >> 16) & 0xFF);\
_mm256_storeu_si256((__m256i *) &r[ctr], f7);                                     \
_mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(etas, d3));\
ctr += _mm_popcnt_u32((good##n >> 24) & 0xFF);\
\



#define REJ2(n) \
g0 = _mm256_castsi256_si128(f##n);\
g1 = _mm_bsrli_si128(g0, 8);\
g2 = _mm256_extracti128_si256(f##n, 1);\
g3 = _mm_bsrli_si128(g2, 8);\
\
t4 = _mm256_cvtepu8_epi32(g0);\
t5 = _mm256_cvtepu8_epi32(g1);\
t6 = _mm256_cvtepu8_epi32(g2);\
t7 = _mm256_cvtepu8_epi32(g3);\
\
_mm256_storeu_si256((__m256i *) &r[ctr], t4);\
ctr += 8;\
_mm256_storeu_si256((__m256i *) &r[ctr], t5);\
ctr += 8;\
_mm256_storeu_si256((__m256i *) &r[ctr], t6);\
ctr += 8;\
_mm256_storeu_si256((__m256i *) &r[ctr], t7);\
ctr += 8;\
\


static uint32_t rej_eta_final2(int32_t *restrict r, uint8_t *pipe, uint32_t ctr, const uint8_t *buf) {
    __m256i f0, f1;
    __m128i g0, g1;
    __m128i d0, d1;
    uint32_t good0;

    const __m128i mask = _mm_set1_epi8(0x0f);
    const __m128i mask2 = _mm_set1_epi8(0x03);
    const __m128i eta = _mm_set1_epi8(ETA);
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
    if (ctr <= (N - 16)) {
        g1 = _mm_bsrli_si128(g0, 8);

        d0 = _mm_loadl_epi64((__m128i *) &idxlut[good0 & 0xFF]);
        d1 = _mm_loadl_epi64((__m128i *) &idxlut[(good0 >> 8) & 0xFF]);
        g0 = _mm_shuffle_epi8(g0,d0);
        g1 = _mm_shuffle_epi8(g1,d1);
        f0 = _mm256_cvtepi8_epi32(g0);
        f1 = _mm256_cvtepi8_epi32(g1);

        _mm256_storeu_si256((__m256i *) &r[ctr], f0);
        _mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(eta, g0));
        ctr += _mm_popcnt_u32(good0 & 0xFF);
        _mm256_storeu_si256((__m256i *) &r[ctr], f1);
        _mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(eta, g1));
        ctr += _mm_popcnt_u32((good0 >> 8) & 0xFF);

        return ctr;
    }

    // 248 >= ctr > 240
    if (ctr <= (N - 8)) {
        g1 = _mm_bsrli_si128(g0, 8);

        d0 = _mm_loadl_epi64((__m128i *) &idxlut[good0 & 0xFF]);
        d1 = _mm_loadl_epi64((__m128i *) &idxlut[(good0 >> 8) & 0xFF]);
        g0 = _mm_shuffle_epi8(g0,d0);
        g1 = _mm_shuffle_epi8(g1,d1);
        f0 = _mm256_cvtepi8_epi32(g0);
        f1 = _mm256_cvtepi8_epi32(g1);

        _mm256_storeu_si256((__m256i *) &r[ctr], f0);
        _mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(eta, g0));
        ctr += _mm_popcnt_u32(good0 & 0xFF);

        ALIGN(32) int32_t t[8];
        _mm256_storeu_si256((__m256i *) t, f1);
        int count = _mm_popcnt_u32((good0 >> 8) & 0xFF);
        int i = 0;
        while(count != 0 && ctr < N) {
            r[ctr] = t[i];
            pipe[ctr] = ETA - t[i];
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
    while(count > 0 && ctr < N) {
        r[ctr] = t[i];
        pipe[ctr] = ETA - t[i];
        i++;
        count--;
        ctr++;
    }

    return ctr;
}

unsigned int XURQ_AVX2_rej_eta_avx_with_pack(int32_t *restrict r, uint8_t *pipe, const uint8_t buf[REJ_UNIFORM_ETA_BUFLEN]) {
    unsigned int ctr, pos;
    uint32_t good0, good1, good2, good3;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;
    __m128i g0, g1, g2, g3;
    __m128i d0, d1, d2, d3;
    const __m256i mask = _mm256_set1_epi8(0x0f);
    const __m256i mask2 = _mm256_set1_epi8(0x03);
    const __m256i eta = _mm256_set1_epi8(ETA);
    const __m256i bound = mask;//15
    const __m256i num5 = _mm256_set1_epi16(5);
    const __m256i num13 = _mm256_set1_epi16(13);
    const __m128i etas = _mm_set1_epi8(ETA);

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


    if (ctr < N)
        ctr = rej_eta_final2(r, pipe, ctr,&buf[128]);

    return ctr;
}


static void pack_eta_avx2(uint8_t *r, const uint8_t *pipe) {
    __m256i b0, b1, b2, b3, b4, b5, b6, b7;
    int ptr = 0;

    const __m256i mask0 = _mm256_set1_epi16(0xff);
    const __m256i mask1 = _mm256_set1_epi32(0xffff);
    const __m256i mask2 = _mm256_set1_epi64x(0xffffffff);
    const __m256i mask3 = _mm256_set_epi64x(0, 0xffffffffffffffffULL,0,0xffffffffffffffffULL);

    b0  = _mm256_load_si256((__m256i *) &pipe[0]);
    b1  = _mm256_load_si256((__m256i *) &pipe[32]);
    b2  = _mm256_load_si256((__m256i *) &pipe[64]);
    b3  = _mm256_load_si256((__m256i *) &pipe[96]);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi16(b0, 5));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi16(b1, 5));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi16(b2, 5));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi16(b3, 5));

    b0 = _mm256_and_si256(b0, mask0);
    b1 = _mm256_and_si256(b1, mask0);
    b2 = _mm256_and_si256(b2, mask0);
    b3 = _mm256_and_si256(b3, mask0);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi32(b0, 10));
    b1  = _mm256_xor_si256(b1, _mm256_srli_epi32(b1, 10));
    b2  = _mm256_xor_si256(b2, _mm256_srli_epi32(b2, 10));
    b3  = _mm256_xor_si256(b3, _mm256_srli_epi32(b3, 10));

    b0 = _mm256_and_si256(b0, mask1);
    b1 = _mm256_and_si256(b1, mask1);
    b2 = _mm256_and_si256(b2, mask1);
    b3 = _mm256_and_si256(b3, mask1);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi64(b0, 20));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi64(b1, 20));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi64(b2, 20));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi64(b3, 20));

    b0 = _mm256_and_si256(b0, mask2);
    b1 = _mm256_and_si256(b1, mask2);
    b2 = _mm256_and_si256(b2, mask2);
    b3 = _mm256_and_si256(b3, mask2);

    b0 = _mm256_xor_si256(b0, _mm256_bsrli_epi128(b0, 5));
    b1 = _mm256_xor_si256(b1, _mm256_bsrli_epi128(b1, 5));
    b2 = _mm256_xor_si256(b2, _mm256_bsrli_epi128(b2, 5));
    b3 = _mm256_xor_si256(b3, _mm256_bsrli_epi128(b3, 5));

    b0 = _mm256_and_si256(b0, mask3);
    b1 = _mm256_and_si256(b1, mask3);
    b2 = _mm256_and_si256(b2, mask3);
    b3 = _mm256_and_si256(b3, mask3);

    b0 = _mm256_xor_si256(b0, _mm256_bsrli_epi128(_mm256_permute4x64_epi64(b0,0x59), 2));
    b1 = _mm256_xor_si256(b1, _mm256_bsrli_epi128(_mm256_permute4x64_epi64(b1,0x59), 2));
    b2 = _mm256_xor_si256(b2, _mm256_bsrli_epi128(_mm256_permute4x64_epi64(b2,0x59), 2));
    b3 = _mm256_xor_si256(b3, _mm256_bsrli_epi128(_mm256_permute4x64_epi64(b3,0x59), 2));

    _mm256_storeu_si256((__m256i *)&r[ptr],b0);
    ptr += 12;
    _mm256_storeu_si256((__m256i *)&r[ptr],b1);
    ptr += 12;
    _mm256_storeu_si256((__m256i *)&r[ptr],b2);
    ptr += 12;
    _mm256_storeu_si256((__m256i *)&r[ptr],b3);
    ptr += 12;


    b0  = _mm256_load_si256((__m256i *) &pipe[128]);
    b1  = _mm256_load_si256((__m256i *) &pipe[160]);
    b2  = _mm256_load_si256((__m256i *) &pipe[192]);
    b3  = _mm256_load_si256((__m256i *) &pipe[224]);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi16(b0, 5));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi16(b1, 5));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi16(b2, 5));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi16(b3, 5));

    b0 = _mm256_and_si256(b0, mask0);
    b1 = _mm256_and_si256(b1, mask0);
    b2 = _mm256_and_si256(b2, mask0);
    b3 = _mm256_and_si256(b3, mask0);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi32(b0, 10));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi32(b1, 10));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi32(b2, 10));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi32(b3, 10));

    b0 = _mm256_and_si256(b0, mask1);
    b1 = _mm256_and_si256(b1, mask1);
    b2 = _mm256_and_si256(b2, mask1);
    b3 = _mm256_and_si256(b3, mask1);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi64(b0, 20));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi64(b1, 20));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi64(b2, 20));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi64(b3, 20));

    b0 = _mm256_and_si256(b0, mask2);
    b1 = _mm256_and_si256(b1, mask2);
    b2 = _mm256_and_si256(b2, mask2);
    b3 = _mm256_and_si256(b3, mask2);

    b0 = _mm256_xor_si256(b0, _mm256_bsrli_epi128(b0, 5));
    b1 = _mm256_xor_si256(b1, _mm256_bsrli_epi128(b1, 5));
    b2 = _mm256_xor_si256(b2, _mm256_bsrli_epi128(b2, 5));
    b3 = _mm256_xor_si256(b3, _mm256_bsrli_epi128(b3, 5));

    b0 = _mm256_and_si256(b0, mask3);
    b1 = _mm256_and_si256(b1, mask3);
    b2 = _mm256_and_si256(b2, mask3);
    b3 = _mm256_and_si256(b3, mask3);

    b0 = _mm256_xor_si256(b0, _mm256_bsrli_epi128(_mm256_permute4x64_epi64(b0,0x59), 2));
    b1 = _mm256_xor_si256(b1, _mm256_bsrli_epi128(_mm256_permute4x64_epi64(b1,0x59), 2));
    b2 = _mm256_xor_si256(b2, _mm256_bsrli_epi128(_mm256_permute4x64_epi64(b2,0x59), 2));
    b3 = _mm256_xor_si256(b3, _mm256_bsrli_epi128(_mm256_permute4x64_epi64(b3,0x59), 2));

    _mm256_storeu_si256((__m256i *)&r[ptr],b0);
    ptr += 12;
    _mm256_storeu_si256((__m256i *)&r[ptr],b1);
    ptr += 12;
    _mm256_storeu_si256((__m256i *)&r[ptr],b2);
    ptr += 12;
    _mm256_storeu_si256((__m256i *)&r[ptr],b3);
    //最后这里会溢出 但sk保留了足够的空间

}


static uint32_t rej_eta_with_pipe(int32_t *a,
                                  uint32_t ctr,
                                  uint8_t *pipe,
                                  const uint8_t *buf) {
    int32_t t0, t1;
    int pos = 0;
    while (ctr < N && pos < REJ_UNIFORM_ETA_BUFLEN) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;

        if (t0 < 15) {
            t0 = t0 - ((13 * t0) >> 6) * 5;
            pipe[ctr] = t0;
            a[ctr++] = ETA - t0;
        }
        if (t1 < 15 && ctr < N) {
            t1 = t1 - ((13 * t1) >> 6) * 5;
            pipe[ctr] = t1;
            a[ctr++] = ETA - t1;
        }
    }

    return ctr;
}

#endif


#if DILITHIUM_MODE == 2



void ExpandS_with_pack(polyvecl *s1,
                       polyveck *s2,
                       uint8_t *r,
                       const uint64_t seed[4]) {
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][REJ_UNIFORM_ETA_BUFLEN];
    ALIGN(32) uint8_t pipe[4][288];  //20 bytes redundancy

    keccakx4_state state;

    // sample and pack s1

    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 3, (0x1f << 16) ^ 2,
                                   (0x1f << 16) ^ 1, (0x1f << 16) ^ 0);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[0].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[1].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[2].coeffs, pipe[2],buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[3].coeffs, pipe[3],buf[3]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = rej_eta_with_pipe(s1->vec[0].coeffs,ctr[0], pipe[0],buf[0]);
        ctr[1] = rej_eta_with_pipe(s1->vec[1].coeffs,ctr[1], pipe[1],buf[1]);
        ctr[2] = rej_eta_with_pipe(s1->vec[2].coeffs,ctr[2], pipe[2],buf[2]);
        ctr[3] = rej_eta_with_pipe(s1->vec[3].coeffs,ctr[3], pipe[3],buf[3]);
    }

    for ( int i = 0; i < L; i++) {
        pack_eta_avx2(r + i * POLYETA_PACKEDBYTES, pipe[i]);
    }

    // sample and pack s2

    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 7, (0x1f << 16) ^ 6,
                                   (0x1f << 16) ^ 5, (0x1f << 16) ^ 4);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[0].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[1].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[2].coeffs, pipe[2],buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[3].coeffs, pipe[3],buf[3]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] += rej_eta_with_pipe(s2->vec[0].coeffs, ctr[0],pipe[0],buf[0]);
        ctr[1] += rej_eta_with_pipe(s2->vec[1].coeffs, ctr[1],pipe[1],buf[1]);
        ctr[2] += rej_eta_with_pipe(s2->vec[2].coeffs, ctr[2],pipe[2],buf[2]);
        ctr[3] += rej_eta_with_pipe(s2->vec[3].coeffs, ctr[3],pipe[3],buf[3]);
    }


    for (int i = 0; i < K; i++) {
        pack_eta_avx2(r + (L + i) * POLYETA_PACKEDBYTES, pipe[i]);
    }
}

#elif DILITHIUM_MODE == 3

unsigned int XURQ_AVX2_rej_eta_avx_with_pack(int32_t *restrict r, uint8_t *pipe, const uint8_t buf[REJ_UNIFORM_ETA_BUFLEN]) {
    unsigned int ctr, pos;
    uint32_t good;
    __m256i f0, f1;
    __m128i g0, g1;
    const __m256i mask = _mm256_set1_epi8(15);
    const __m256i eta = _mm256_set1_epi8(4);
    const __m128i etas = _mm_set1_epi8(ETA);
    const __m256i bound = _mm256_set1_epi8(9);

    ctr = pos = 0;
    while (ctr <= N - 8 && pos <= REJ_UNIFORM_ETA_BUFLEN - 16) {
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
        _mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(etas, g1));
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > N - 8) {
            break;
        }
        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i *)&r[ctr], f1);
        _mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(etas, g1));
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > N - 8) {
            break;
        }
        g0 = _mm256_extracti128_si256(f0, 1);
        g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i *)&r[ctr], f1);
        _mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(etas, g1));
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > N - 8) {
            break;
        }
        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i *)&idxlut[good]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i *)&r[ctr], f1);
        _mm_storeu_si128((__m128i *)&pipe[ctr], _mm_sub_epi8(etas, g1));
        ctr += _mm_popcnt_u32(good);
        pos += 4;
    }

    uint32_t t0, t1;
    while (ctr < N && pos < REJ_UNIFORM_ETA_BUFLEN) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;

        if (t0 < 9) {
            r[ctr] = 4 - t0;
            pipe[ctr] = t0;
            ctr++;
        }
        if (t1 < 9 && ctr < N) {
            r[ctr] = 4 - t1;
            pipe[ctr] = t1;
            ctr++;
        }
    }

    return ctr;
}

void pack_eta(uint8_t *r, const uint8_t *pipe) {
    __m256i b0, b1, b2, b3;
    int ptr = 0;

    const __m256i mask0 = _mm256_set1_epi16(0xff);
    const __m256i mask1 = _mm256_set1_epi32(0xffff);
    const __m256i mask2 = _mm256_set1_epi64x(0xffffffff);
    const __m256i mask3 = _mm256_set_epi64x(0, 0xffffffffffffffffULL,0,0xffffffffffffffffULL);

    b0  = _mm256_load_si256((__m256i *) &pipe[0]);
    b1  = _mm256_load_si256((__m256i *) &pipe[32]);
    b2  = _mm256_load_si256((__m256i *) &pipe[64]);
    b3  = _mm256_load_si256((__m256i *) &pipe[96]);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi16(b0, 4));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi16(b1, 4));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi16(b2, 4));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi16(b3, 4));

    b0 = _mm256_and_si256(b0, mask0);
    b1 = _mm256_and_si256(b1, mask0);
    b2 = _mm256_and_si256(b2, mask0);
    b3 = _mm256_and_si256(b3, mask0);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi32(b0, 8));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi32(b1, 8));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi32(b2, 8));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi32(b3, 8));

    b0 = _mm256_and_si256(b0, mask1);
    b1 = _mm256_and_si256(b1, mask1);
    b2 = _mm256_and_si256(b2, mask1);
    b3 = _mm256_and_si256(b3, mask1);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi64(b0, 16));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi64(b1, 16));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi64(b2, 16));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi64(b3, 16));

    b0 = _mm256_and_si256(b0, mask2);
    b1 = _mm256_and_si256(b1, mask2);
    b2 = _mm256_and_si256(b2, mask2);
    b3 = _mm256_and_si256(b3, mask2);

    b0 = _mm256_xor_si256(b0, _mm256_srli_si256(b0, 4));
    b1 = _mm256_xor_si256(b1, _mm256_srli_si256(b1, 4));
    b2 = _mm256_xor_si256(b2, _mm256_srli_si256(b2, 4));
    b3 = _mm256_xor_si256(b3, _mm256_srli_si256(b3, 4));

    b0 = _mm256_and_si256(b0, mask3);
    b1 = _mm256_and_si256(b1, mask3);
    b2 = _mm256_and_si256(b2, mask3);
    b3 = _mm256_and_si256(b3, mask3);

    b0 = _mm256_permute4x64_epi64(b0,0x08);
    b1 = _mm256_permute4x64_epi64(b1,0x08);
    b2 = _mm256_permute4x64_epi64(b2,0x08);
    b3 = _mm256_permute4x64_epi64(b3,0x08);

    _mm256_storeu_si256((__m256i *)&r[ptr],b0);
    ptr += 16;
    _mm256_storeu_si256((__m256i *)&r[ptr],b1);
    ptr += 16;
    _mm256_storeu_si256((__m256i *)&r[ptr],b2);
    ptr += 16;
    _mm256_storeu_si256((__m256i *)&r[ptr],b3);
    ptr += 16;

    b0  = _mm256_load_si256((__m256i *) &pipe[128]);
    b1  = _mm256_load_si256((__m256i *) &pipe[160]);
    b2  = _mm256_load_si256((__m256i *) &pipe[192]);
    b3  = _mm256_load_si256((__m256i *) &pipe[224]);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi16(b0, 4));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi16(b1, 4));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi16(b2, 4));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi16(b3, 4));

    b0 = _mm256_and_si256(b0, mask0);
    b1 = _mm256_and_si256(b1, mask0);
    b2 = _mm256_and_si256(b2, mask0);
    b3 = _mm256_and_si256(b3, mask0);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi32(b0, 8));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi32(b1, 8));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi32(b2, 8));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi32(b3, 8));

    b0 = _mm256_and_si256(b0, mask1);
    b1 = _mm256_and_si256(b1, mask1);
    b2 = _mm256_and_si256(b2, mask1);
    b3 = _mm256_and_si256(b3, mask1);

    b0 = _mm256_xor_si256(b0, _mm256_srli_epi64(b0, 16));
    b1 = _mm256_xor_si256(b1, _mm256_srli_epi64(b1, 16));
    b2 = _mm256_xor_si256(b2, _mm256_srli_epi64(b2, 16));
    b3 = _mm256_xor_si256(b3, _mm256_srli_epi64(b3, 16));

    b0 = _mm256_and_si256(b0, mask2);
    b1 = _mm256_and_si256(b1, mask2);
    b2 = _mm256_and_si256(b2, mask2);
    b3 = _mm256_and_si256(b3, mask2);

    b0 = _mm256_xor_si256(b0, _mm256_srli_si256(b0, 4));
    b1 = _mm256_xor_si256(b1, _mm256_srli_si256(b1, 4));
    b2 = _mm256_xor_si256(b2, _mm256_srli_si256(b2, 4));
    b3 = _mm256_xor_si256(b3, _mm256_srli_si256(b3, 4));

    b0 = _mm256_and_si256(b0, mask3);
    b1 = _mm256_and_si256(b1, mask3);
    b2 = _mm256_and_si256(b2, mask3);
    b3 = _mm256_and_si256(b3, mask3);

    b0 = _mm256_permute4x64_epi64(b0,0x08);
    b1 = _mm256_permute4x64_epi64(b1,0x08);
    b2 = _mm256_permute4x64_epi64(b2,0x08);
    b3 = _mm256_permute4x64_epi64(b3,0x08);

    _mm256_storeu_si256((__m256i *)&r[ptr],b0);
    ptr += 16;
    _mm256_storeu_si256((__m256i *)&r[ptr],b1);
    ptr += 16;
    _mm256_storeu_si256((__m256i *)&r[ptr],b2);
    ptr += 16;
    // _mm256_storeu_si256((__m256i *)&r[ptr],b3);
    _mm_storeu_si128((__m128i *)&r[ptr], _mm256_extracti128_si256(b3,0));

}

static uint32_t rej_eta_with_pipe(int32_t *a,
                                  uint32_t ctr,
                                  uint8_t *pipe,
                                  const uint8_t *buf) {
    int32_t t0, t1;
    int pos = 0;
    while (ctr < N && pos < SHAKE256_RATE) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;

        if (t0 < 9) {
            a[ctr] = 4 - t0;
            pipe[ctr] = t0;
            ctr++;
        }
        if (t1 < 9 && ctr < N) {
            a[ctr] = 4 - t1;
            pipe[ctr] = t1;
            ctr++;
        }
    }

    return ctr;
}



void ExpandS_with_pack(polyvecl *s1,
                       polyveck *s2,
                       uint8_t *r,
                       const uint64_t seed[4]) {
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][REJ_UNIFORM_ETA_BUFLEN];
    ALIGN(32) uint8_t pipe[4][288];  //32 bytes redundancy

    keccakx4_state state;

    // sample and pack s1[0] s1[1] s1[2] s1[3]

    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 3, (0x1f << 16) ^ 2,
                                   (0x1f << 16) ^ 1, (0x1f << 16) ^ 0);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], REJ_UNIFORM_ETA_NBLOCKS, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[0].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[1].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[2].coeffs, pipe[2],buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[3].coeffs, pipe[3],buf[3]);


    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = rej_eta_with_pipe(s1->vec[0].coeffs, ctr[0], pipe[0],buf[0]);
        ctr[1] = rej_eta_with_pipe(s1->vec[1].coeffs, ctr[1], pipe[1],buf[1]);
        ctr[2] = rej_eta_with_pipe(s1->vec[2].coeffs, ctr[2], pipe[2],buf[2]);
        ctr[3] = rej_eta_with_pipe(s1->vec[3].coeffs, ctr[3], pipe[3],buf[3]);

    }


    for ( int i = 0; i < 4; i++) {
        pack_eta(r , pipe[i]);
        r += POLYETA_PACKEDBYTES;
    }

    // sample and pack  s1[4] s2[0] s2[1] s2[2]

    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 7, (0x1f << 16) ^ 6,
                                   (0x1f << 16) ^ 5, (0x1f << 16) ^ 4);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],  REJ_UNIFORM_ETA_NBLOCKS, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[4].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[0].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[1].coeffs, pipe[2],buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[2].coeffs, pipe[3],buf[3]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],  1, &state);

        ctr[0] = rej_eta_with_pipe(s1->vec[4].coeffs, ctr[0],pipe[0],buf[0]);
        ctr[1] = rej_eta_with_pipe(s2->vec[0].coeffs, ctr[1],pipe[1],buf[1]);
        ctr[2] = rej_eta_with_pipe(s2->vec[1].coeffs, ctr[2],pipe[2],buf[2]);
        ctr[3] = rej_eta_with_pipe(s2->vec[2].coeffs, ctr[3],pipe[3],buf[3]);
    }

    for ( int i = 0; i < 4; i++) {
        pack_eta(r , pipe[i]);
        r += POLYETA_PACKEDBYTES;
    }


    // sample and pack   s2[3] s2[4] s2[5]

    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 11, (0x1f << 16) ^ 10,
                                   (0x1f << 16) ^ 9, (0x1f << 16) ^ 8);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],  REJ_UNIFORM_ETA_NBLOCKS, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[3].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[4].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[5].coeffs, pipe[2],buf[2]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N ) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],  1, &state);

        ctr[0] = rej_eta_with_pipe(s1->vec[3].coeffs, ctr[0],pipe[0],buf[0]);
        ctr[1] = rej_eta_with_pipe(s2->vec[4].coeffs, ctr[1],pipe[1],buf[1]);
        ctr[2] = rej_eta_with_pipe(s2->vec[5].coeffs, ctr[2],pipe[2],buf[2]);
    }

    for ( int i = 0; i < 3; i++) {
        pack_eta(r , pipe[i]);
        r += POLYETA_PACKEDBYTES;
    }
}

#elif DILITHIUM_MODE == 5

void ExpandS_with_pack(polyvecl *s1,
                       polyveck *s2,
                       uint8_t *r,
                       const uint64_t seed[4]){
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][REJ_UNIFORM_ETA_BUFLEN];
    ALIGN(32) uint8_t pipe[4][288];  //32 bytes redundancy

    keccakx4_state state;

    // sample and pack s1

    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 3, (0x1f << 16) ^ 2,
                                   (0x1f << 16) ^ 1, (0x1f << 16) ^ 0);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[0].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[1].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[2].coeffs, pipe[2],buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[3].coeffs, pipe[3],buf[3]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = rej_eta_with_pipe(s1->vec[0].coeffs,ctr[0], pipe[0],buf[0]);
        ctr[1] = rej_eta_with_pipe(s1->vec[1].coeffs,ctr[1], pipe[1],buf[1]);
        ctr[2] = rej_eta_with_pipe(s1->vec[2].coeffs,ctr[2], pipe[2],buf[2]);
        ctr[3] = rej_eta_with_pipe(s1->vec[3].coeffs,ctr[3], pipe[3],buf[3]);
    }

    for ( int i = 0; i < 4; i++) {
        pack_eta_avx2(r + i * POLYETA_PACKEDBYTES, pipe[i]);
    }

    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 7, (0x1f << 16) ^ 6,
                                   (0x1f << 16) ^ 5, (0x1f << 16) ^ 4);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[4].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[5].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[6].coeffs, pipe[2],buf[2]);
//    ctr[3] = XURQ_AVX2_rej_eta_avx_with_pack(s1->vec[3].coeffs, pipe[3].coeffs,buf[3].coeffs);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] = rej_eta_with_pipe(s1->vec[4].coeffs,ctr[0], pipe[0],buf[0]);
        ctr[1] = rej_eta_with_pipe(s1->vec[5].coeffs,ctr[1], pipe[1],buf[1]);
        ctr[2] = rej_eta_with_pipe(s1->vec[6].coeffs,ctr[2], pipe[2],buf[2]);
//        ctr[3] = rej_eta_with_pipe(s1->vec[3].coeffs,ctr[3], pipe[3].coeffs,buf[3].coeffs);
    }

    for ( int i = 4; i < L; i++) {
        pack_eta_avx2(r + i * POLYETA_PACKEDBYTES, pipe[i-4]);
    }

    // sample and pack s2

    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 10, (0x1f << 16) ^ 9,
                                   (0x1f << 16) ^ 8, (0x1f << 16) ^ 7);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[0].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[1].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[2].coeffs, pipe[2],buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[3].coeffs, pipe[3],buf[3]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

        ctr[0] += rej_eta_with_pipe(s2->vec[0].coeffs, ctr[0],pipe[0],buf[0]);
        ctr[1] += rej_eta_with_pipe(s2->vec[1].coeffs, ctr[1],pipe[1],buf[1]);
        ctr[2] += rej_eta_with_pipe(s2->vec[2].coeffs, ctr[2],pipe[2],buf[2]);
        ctr[3] += rej_eta_with_pipe(s2->vec[3].coeffs, ctr[3],pipe[3],buf[3]);
    }


    for (int i = 0; i < 4; i++) {
        pack_eta_avx2(r + (L + i) * POLYETA_PACKEDBYTES, pipe[i]);
    }


    state.s[0] = _mm256_set1_epi64x(seed[0]);
    state.s[1] = _mm256_set1_epi64x(seed[1]);
    state.s[2] = _mm256_set1_epi64x(seed[2]);
    state.s[3] = _mm256_set1_epi64x(seed[3]);
    state.s[4] = _mm256_set_epi64x((0x1f << 16) ^ 14, (0x1f << 16) ^ 13,
                                   (0x1f << 16) ^ 12, (0x1f << 16) ^ 11);

    for (int j = 5; j < 25; ++j)
        state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[4].coeffs, pipe[0],buf[0]);
    ctr[1] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[5].coeffs, pipe[1],buf[1]);
    ctr[2] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[6].coeffs, pipe[2],buf[2]);
    ctr[3] = XURQ_AVX2_rej_eta_avx_with_pack(s2->vec[7].coeffs, pipe[3],buf[3]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N || ctr[3] < N) {
        XURQ_AVX2_shake256x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3],1, &state);

        ctr[0] += rej_eta_with_pipe(s2->vec[4].coeffs, ctr[0],pipe[0],buf[0]);
        ctr[1] += rej_eta_with_pipe(s2->vec[5].coeffs, ctr[1],pipe[1],buf[1]);
        ctr[2] += rej_eta_with_pipe(s2->vec[6].coeffs, ctr[2],pipe[2],buf[2]);
        ctr[3] += rej_eta_with_pipe(s2->vec[7].coeffs, ctr[3],pipe[3],buf[3]);
    }


    for (int i = 4; i < K; i++) {
        pack_eta_avx2(r + (L + i) * POLYETA_PACKEDBYTES, pipe[i-4]);
    }

}



#endif
