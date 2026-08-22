/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * SHAKE x4 multi-buffer implementation for AVX2
 *
 * Thin wrappers around SHA3_shake*_x4_*_avx2 (keccak1600x4-avx2.s).
 * Callers should check SHA3_avx2_capable() before calling.
 */

#include "internal/sha3.h"
#include <openssl/crypto.h>
#include <string.h>

#if defined(KECCAK1600_ASM)                                                               \
    && (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    && !defined(OPENSSL_NO_ASM)

void ossl_sha3_shake128_x4_inc_init_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->rate = SHA3_BLOCKSIZE(128);
    ctx->finalized = 0;
}

void ossl_sha3_shake128_x4_inc_absorb_avx2(KECCAK1600_X4_AVX2_CTX *ctx,
                                           const void *in0, const void *in1,
                                           const void *in2, const void *in3,
                                           size_t inlen)
{
    if (ctx->finalized)
        return;

    SHA3_shake128_x4_inc_absorb_avx2(ctx->A, in0, in1, in2, in3, inlen);
}

void ossl_sha3_shake128_x4_inc_cleanup_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
    OPENSSL_cleanse(ctx, sizeof(*ctx));
}

static void sha3_shake128_x4_inc_finalize_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
    if (ctx->finalized)
        return;

    SHA3_shake128_x4_inc_finalize_avx2(ctx->A);
    ctx->finalized = 1;
}

void ossl_sha3_shake128_x4_inc_squeeze_avx2(void *out0, void *out1,
                                            void *out2, void *out3,
                                            size_t outlen,
                                            KECCAK1600_X4_AVX2_CTX *ctx)
{
    if (!ctx->finalized)
        sha3_shake128_x4_inc_finalize_avx2(ctx);

    SHA3_shake128_x4_inc_squeeze_avx2(out0, out1, out2, out3, outlen, ctx->A);
}

void ossl_sha3_shake256_x4_inc_init_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->rate = SHA3_BLOCKSIZE(256);
    ctx->finalized = 0;
}

void ossl_sha3_shake256_x4_inc_absorb_avx2(KECCAK1600_X4_AVX2_CTX *ctx,
                                           const void *in0, const void *in1,
                                           const void *in2, const void *in3,
                                           size_t inlen)
{
    if (ctx->finalized)
        return;

    SHA3_shake256_x4_inc_absorb_avx2(ctx->A, in0, in1, in2, in3, inlen);
}

void ossl_sha3_shake256_x4_inc_cleanup_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
    OPENSSL_cleanse(ctx, sizeof(*ctx));
}

static void sha3_shake256_x4_inc_finalize_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
    if (ctx->finalized)
        return;

    SHA3_shake256_x4_inc_finalize_avx2(ctx->A);
    ctx->finalized = 1;
}

void ossl_sha3_shake256_x4_inc_squeeze_avx2(void *out0, void *out1,
                                            void *out2, void *out3,
                                            size_t outlen,
                                            KECCAK1600_X4_AVX2_CTX *ctx)
{
    if (!ctx->finalized)
        sha3_shake256_x4_inc_finalize_avx2(ctx);

    SHA3_shake256_x4_inc_squeeze_avx2(out0, out1, out2, out3, outlen, ctx->A);
}

void ossl_sha3_shake128_x4_avx2(void *out0, void *out1, void *out2, void *out3,
                                size_t outlen,
                                const void *in0, const void *in1,
                                const void *in2, const void *in3,
                                size_t inlen)
{
    SHA3_shake128_x4_avx2(out0, out1, out2, out3, outlen,
                          in0, in1, in2, in3, inlen);
}

void ossl_sha3_shake256_x4_avx2(void *out0, void *out1, void *out2, void *out3,
                                size_t outlen,
                                const void *in0, const void *in1,
                                const void *in2, const void *in3,
                                size_t inlen)
{
    SHA3_shake256_x4_avx2(out0, out1, out2, out3, outlen,
                          in0, in1, in2, in3, inlen);
}

#endif /* KECCAK1600_ASM && x86_64 && !OPENSSL_NO_ASM */
