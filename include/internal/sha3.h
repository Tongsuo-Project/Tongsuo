/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This header can move into provider when legacy support is removed */
#ifndef OSSL_INTERNAL_SHA3_H
# define OSSL_INTERNAL_SHA3_H
# pragma once

# include <openssl/e_os2.h>
# include <stddef.h>

# define KECCAK1600_WIDTH 1600
# define SHA3_MDSIZE(bitlen)    (bitlen / 8)
# define KMAC_MDSIZE(bitlen)    2 * (bitlen / 8)
# define SHA3_BLOCKSIZE(bitlen) (KECCAK1600_WIDTH - bitlen * 2) / 8

typedef struct keccak_st KECCAK1600_CTX;

typedef size_t (sha3_absorb_fn)(void *vctx, const void *in, size_t inlen);
typedef int (sha3_final_fn)(void *vctx, unsigned char *out, size_t outlen);
typedef int (sha3_squeeze_fn)(void *vctx, unsigned char *out, size_t outlen);

typedef struct prov_sha3_meth_st {
    sha3_absorb_fn *absorb;
    sha3_final_fn *final;
    sha3_squeeze_fn *squeeze;
} PROV_SHA3_METHOD;

#define XOF_STATE_INIT    0
#define XOF_STATE_ABSORB  1
#define XOF_STATE_FINAL   2
#define XOF_STATE_SQUEEZE 3

struct keccak_st {
    uint64_t A[5][5];
    unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
    size_t block_size;          /* cached ctx->digest->block_size */
    size_t md_size;             /* output length, variable in XOF */
    size_t bufsz;               /* used bytes in below buffer */
    unsigned char pad;
    PROV_SHA3_METHOD meth;
    int xof_state;
};

void ossl_sha3_reset(KECCAK1600_CTX *ctx);
int ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen);
int ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned char pad,
                     size_t typelen, size_t mdlen);
int ossl_sha3_update(KECCAK1600_CTX *ctx, const void *_inp, size_t len);
int ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);
int ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);

size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
                   size_t r);

/* Multi-buffer (x4) Keccak-f[1600] context and API (AVX2) */
#if defined(KECCAK1600_ASM)                                                               \
    && (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    && !defined(OPENSSL_NO_ASM)

int SHA3_avx2_capable(void);

void SHA3_shake128_x4_inc_absorb_avx2(
    uint64_t *state,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);
void SHA3_shake256_x4_inc_absorb_avx2(
    uint64_t *state,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);
void SHA3_shake128_x4_inc_finalize_avx2(uint64_t *state);
void SHA3_shake256_x4_inc_finalize_avx2(uint64_t *state);
void SHA3_shake128_x4_inc_squeeze_avx2(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    uint64_t *state);
void SHA3_shake256_x4_inc_squeeze_avx2(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    uint64_t *state);
void SHA3_shake128_x4_avx2(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);
void SHA3_shake256_x4_avx2(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);

typedef struct {
    uint64_t A[(25 * 4) + 1];
    size_t rate;
    unsigned finalized;
} KECCAK1600_X4_AVX2_CTX
# if defined(__GNUC__) || defined(__clang__)
    __attribute__((aligned(32)))
# endif
    ;

void ossl_sha3_shake128_x4_inc_init_avx2(KECCAK1600_X4_AVX2_CTX *ctx);
void ossl_sha3_shake128_x4_inc_absorb_avx2(
    KECCAK1600_X4_AVX2_CTX *ctx,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);
void ossl_sha3_shake128_x4_inc_cleanup_avx2(KECCAK1600_X4_AVX2_CTX *ctx);
void ossl_sha3_shake128_x4_inc_squeeze_avx2(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    KECCAK1600_X4_AVX2_CTX *ctx);

void ossl_sha3_shake256_x4_inc_init_avx2(KECCAK1600_X4_AVX2_CTX *ctx);
void ossl_sha3_shake256_x4_inc_absorb_avx2(
    KECCAK1600_X4_AVX2_CTX *ctx,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);
void ossl_sha3_shake256_x4_inc_cleanup_avx2(KECCAK1600_X4_AVX2_CTX *ctx);
void ossl_sha3_shake256_x4_inc_squeeze_avx2(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    KECCAK1600_X4_AVX2_CTX *ctx);

void ossl_sha3_shake128_x4_avx2(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);
void ossl_sha3_shake256_x4_avx2(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);

#endif /* KECCAK1600_ASM && x86_64 && !OPENSSL_NO_ASM */

#endif /* OSSL_INTERNAL_SHA3_H */
