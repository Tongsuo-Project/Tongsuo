/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include "testutil.h"
#include "internal/nelem.h"
#include "threadstest.h"

#ifndef OPENSSL_NO_SM4TH
# include "crypto/sm4th.h"
# include "../crypto/sm4th/blockcipher.h"
# include "../crypto/sm4th/fields.h"
# include "../crypto/sm4th/sign.h"

static int test_sm4th_core_roundtrip(int variant)
{
    SM4TH_KEY *key = NULL;
    unsigned char msg[16] = { 0 };
    unsigned char rho[SM4TH_SEED_BYTES] = { 0 };
    unsigned char *sig = NULL;
    size_t siglen, maxsig;
    int ok = 0;

    if (!TEST_ptr(key = tons_sm4th_key_new(NULL, NULL, variant))
            || !TEST_true(tons_sm4th_generate_key(key)))
        goto end;

    maxsig = tons_sm4th_key_get_sig_len(key);
    if (!TEST_size_t_gt(maxsig, 0)
            || !TEST_ptr(sig = OPENSSL_malloc(maxsig)))
        goto end;

    siglen = maxsig;
    if (!TEST_true(tons_sm4th_sign(key, msg, sizeof(msg),
                                   rho, sizeof(rho), sig, &siglen))
            || !TEST_size_t_le(siglen, maxsig)
            || !TEST_true(tons_sm4th_verify(key, msg, sizeof(msg),
                                            sig, siglen)))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(sig);
    tons_sm4th_key_free(key);
    return ok;
}

static int test_sm4th_core_f(void)
{
    return test_sm4th_core_roundtrip(SM4TH_VARIANT_F);
}

static int test_sm4th_core_s(void)
{
    return test_sm4th_core_roundtrip(SM4TH_VARIANT_S);
}

static int test_sm4th_evp_roundtrip(const char *alg)
{
    EVP_PKEY_CTX *gctx = NULL, *sctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    unsigned char msg[] = "sm4th-evp";
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ok = 0;

    if (!TEST_ptr(gctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL))
            || !TEST_int_gt(EVP_PKEY_keygen_init(gctx), 0)
            || !TEST_int_gt(EVP_PKEY_keygen(gctx, &pkey), 0))
        goto end;

    if (!TEST_ptr(mctx = EVP_MD_CTX_new())
            || !TEST_int_gt(EVP_DigestSignInit_ex(mctx, &sctx, NULL, NULL,
                                                  NULL, pkey, NULL), 0)
            || !TEST_int_gt(EVP_DigestSign(mctx, NULL, &siglen, msg,
                                           sizeof(msg) - 1), 0)
            || !TEST_ptr(sig = OPENSSL_malloc(siglen))
            || !TEST_int_gt(EVP_DigestSign(mctx, sig, &siglen, msg,
                                           sizeof(msg) - 1), 0))
        goto end;

    EVP_MD_CTX_free(mctx);
    mctx = NULL;
    sctx = NULL;

    if (!TEST_ptr(mctx = EVP_MD_CTX_new())
            || !TEST_int_gt(EVP_DigestVerifyInit_ex(mctx, &sctx, NULL, NULL,
                                                    NULL, pkey, NULL), 0)
            || !TEST_int_gt(EVP_DigestVerify(mctx, sig, siglen, msg,
                                             sizeof(msg) - 1), 0))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gctx);
    return ok;
}

static int test_sm4th_evp_f(void)
{
    return test_sm4th_evp_roundtrip("SM4TH-F");
}

static int test_sm4th_evp_s(void)
{
    return test_sm4th_evp_roundtrip("SM4TH-S");
}
/* Fixed vectors were independently generated from sm4th_sf_spec.tex. */
static const unsigned char kat_key[16] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};

static int test_sm4th_kat(int variant)
{
    static const char *hashes[] = {
        "ef472a19dce3543179e2931fa281628c752f29da1998f22f450f6b87ba89b0e8",
        "26bd27281b2bca8c86dc1cd4e0f68fa4f628d2f6143dbd55b60a50e302c450c8"
    };
    const unsigned char msg[] = "independent spec transcript";
    unsigned char sk[32], rho[32], digest[32], sig[6725];
    unsigned char *expected = NULL;
    unsigned int digestlen;
    long expectedlen;
    size_t siglen = sizeof(sig);
    SM4TH_KEY *key = NULL;
    int ok = 0, i;

    memcpy(sk, kat_key, 16);
    memcpy(sk + 16, kat_key, 16);
    for (i = 0; i < 32; i++)
        rho[i] = (unsigned char)i;
    if (!TEST_ptr(key = tons_sm4th_key_new(NULL, NULL, variant))
        || !TEST_true(tons_sm4th_key_set_sk(key, sk, sizeof(sk)))
        || !TEST_true(tons_sm4th_sign(key, msg, sizeof(msg) - 1,
                                     rho, sizeof(rho), sig, &siglen))
        || !TEST_size_t_eq(siglen, variant == SM4TH_VARIANT_F ? 6724 : 5056)
        || !TEST_ptr(expected = OPENSSL_hexstr2buf(hashes[variant], &expectedlen))
        || !TEST_true(EVP_Digest(sig, siglen, digest, &digestlen,
                                EVP_sha256(), NULL))
        || !TEST_mem_eq(digest, digestlen, expected, expectedlen)
        || !TEST_true(tons_sm4th_verify(key, msg, sizeof(msg) - 1, sig, siglen))
        || !TEST_false(tons_sm4th_verify(key, (const unsigned char *)"different", 9,
                                         sig, siglen))
        || !TEST_false(tons_sm4th_verify(key, msg, sizeof(msg) - 1, sig, siglen - 1))
        || !TEST_false(tons_sm4th_verify(key, msg, sizeof(msg) - 1, sig, siglen + 1)))
        goto end;
    /* Exercise every serialized field, including the grinding bits. */
    {
        size_t base = (variant == SM4TH_VARIANT_F ? 15 : 10) * 276;
        size_t offsets[9];

        offsets[0] = 0;
        offsets[1] = base;
        offsets[2] = base + 18;
        offsets[3] = base + 244;
        offsets[4] = base + 260;
        offsets[5] = base + 276;
        offsets[6] = siglen - 21;
        offsets[7] = siglen - 20;
        offsets[8] = siglen - 1;
        for (i = 0; i < (int)OSSL_NELEM(offsets); i++) {
            sig[offsets[i]] ^= 0x80;
            if (!TEST_false(tons_sm4th_verify(key, msg, sizeof(msg) - 1,
                                              sig, siglen)))
                goto end;
            sig[offsets[i]] ^= 0x80;
        }
    }
    ok = 1;
end:
    OPENSSL_free(expected);
    tons_sm4th_key_free(key);
    return ok;
}

/* Same raw key/message/rho must not reuse ivpre across profiles. Changing
 * only the verification domain (not tree shape or length) must also reject. */
static int test_sm4th_domain_separation(void)
{
    static const unsigned char msg[] = "independent spec transcript";
    unsigned char sk[32], pk[32], rho[32], sig[6724], repeat[6724];
    unsigned char ivpre[2][16];
    const sm4th_params_t *p;
    sm4th_params_t other;
    EVP_MD *md = NULL;
    unsigned i;
    int variant, ok = 0;

    memcpy(sk, kat_key, 16);
    memcpy(sk + 16, kat_key, 16);
    memcpy(pk, kat_key, 16);
    sm4_enc(kat_key, kat_key, pk + 16);
    for (i = 0; i < sizeof(rho); i++)
        rho[i] = (unsigned char)i;
    if (!TEST_ptr(md = EVP_MD_fetch(NULL, "SHAKE-128", NULL)))
        goto end;
    for (variant = 0; variant < SM4TH_NUM_SETS; variant++) {
        if (!TEST_ptr(p = sm4th_params_get(variant)))
            goto end;
        if (!TEST_int_eq(sm4th_core_sign(p, md, msg, sizeof(msg) - 1,
                                         sk, rho, sig), 0)
            || !TEST_int_eq(sm4th_core_verify(p, md, msg, sizeof(msg) - 1,
                                               pk, sizeof(pk), sig, p->sig_len), 1)
            || !TEST_int_eq(sm4th_core_sign(p, md, msg, sizeof(msg) - 1,
                                             sk, rho, repeat), 0)
            || !TEST_mem_eq(sig, p->sig_len, repeat, p->sig_len))
            goto end;
        memcpy(ivpre[variant], sig + p->sig_len - 20, 16);
        other = *p;
        memcpy(other.domain, sm4th_params_get(1 - variant)->domain,
               sizeof(other.domain));
        if (!TEST_int_eq(sm4th_core_verify(&other, md, msg, sizeof(msg) - 1,
                                           pk, sizeof(pk), sig, p->sig_len), 0))
            goto end;
        other = *p;
        other.domain[7] = 0x32; /* ASCII '2': only the version changes */
        if (!TEST_int_eq(sm4th_core_verify(&other, md, msg, sizeof(msg) - 1,
                                           pk, sizeof(pk), sig, p->sig_len), 0))
            goto end;
        /* Empty messages still absorb D_p and pk, and remain deterministic. */
        if (!TEST_int_eq(sm4th_core_sign(p, md, NULL, 0, sk, rho, sig), 0)
            || !TEST_int_eq(sm4th_core_verify(p, md, NULL, 0, pk, sizeof(pk),
                                               sig, p->sig_len), 1)
            || !TEST_int_eq(sm4th_core_sign(p, md, msg, 0, sk, rho, repeat), 0)
            || !TEST_mem_eq(sig, p->sig_len, repeat, p->sig_len))
            goto end;
    }
    ok = TEST_mem_ne(ivpre[0], sizeof(ivpre[0]), ivpre[1], sizeof(ivpre[1]));
end:
    EVP_MD_free(md);
    return ok;
}

static int test_sm4th_invalid_key(int variant)
{
    SM4TH_KEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    unsigned char sk[32] = {0}, before[32], after[32];
    unsigned int i;
    int ok = 0;

    /* The provider must reject the same invalid raw private key at import. */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                 sk, sizeof(sk));
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(NULL,
                           variant == SM4TH_VARIANT_F ? "SM4TH-F" : "SM4TH-S", NULL))
        || !TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_le(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params), 0)
        || !TEST_ptr_null(pkey))
        goto end;
    ERR_clear_error();
    if (!TEST_ptr(key = tons_sm4th_key_new(NULL, NULL, variant))
        || !TEST_false(tons_sm4th_key_set_sk(key, sk, sizeof(sk)))
        || !TEST_false(tons_sm4th_key_has_private(key)))
        goto end;
    memcpy(sk, kat_key, 16);
    memcpy(sk + 16, kat_key, 16);
    if (!TEST_true(tons_sm4th_key_set_sk(key, sk, sizeof(sk))))
        goto end;
    for (i = 0; i < 256; i++) {
        int valid = ((i ^ 0xa3) & 3) != 3;
        if (!TEST_true(tons_sm4th_key_get_sk(key, before, sizeof(before))))
            goto end;
        sk[16] = (unsigned char)i;
        if (!TEST_int_eq(tons_sm4th_key_set_sk(key, sk, sizeof(sk)), valid)
            || !TEST_true(tons_sm4th_key_get_sk(key, after, sizeof(after)))
            || !TEST_mem_eq(after, sizeof(after), valid ? sk : before, sizeof(sk)))
            goto end;
    }
    ok = 1;
end:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    tons_sm4th_key_free(key);
    return ok;
}

static int test_sm4th_prg_bounds(void)
{
    static const unsigned char ciphertext[16] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };
    const size_t lengths[] = {0, 1, 15, 16, 17, 31, 32, 275, 276};
    unsigned char iv[16] = {0}, expected[288], guarded[320];
    size_t i, j, n;
    sm4_enc(kat_key, kat_key, expected);
    if (!TEST_mem_eq(expected, 16, ciphertext, sizeof(ciphertext)))
        return 0;
    sm4th_prg(kat_key, iv, 0x80000000, expected, sizeof(expected));
    for (i = 0; i < OSSL_NELEM(lengths); i++) {
        n = lengths[i];
        memset(guarded, 0xa5, sizeof(guarded));
        sm4th_prg(kat_key, iv, 0x80000000, guarded + 16, n);
        if (!TEST_mem_eq(guarded + 16, n, expected, n))
            return 0;
        for (j = 0; j < sizeof(guarded); j++)
            if ((j < 16 || j >= 16 + n) && !TEST_int_eq(guarded[j], 0xa5))
                return 0;
    }
    return 1;
}

/* Check all S-box entries against the algebraic definition, then compare
 * the witness round-state implementation with the Tongsuo block backend.
 */
static unsigned char reference_affine(unsigned char x)
{
    static const unsigned char rows[8] = {
        0xa7, 0x4f, 0x9e, 0x3d, 0x7a, 0xf4, 0xe9, 0xd3
    };
    unsigned char result = 0xd3;
    unsigned r, bit;

    for (r = 0; r < 8; r++) {
        unsigned parity = 0;
        for (bit = 0; bit < 8; bit++)
            parity ^= (x & rows[r]) >> bit & 1;
        result ^= (unsigned char)(parity << r);
    }
    return result;
}

static int test_sm4th_sbox(void)
{
    unsigned value, j;
    unsigned char key[16] = {0}, expected[16], got[16];
    uint32_t rk[36];

    for (value = 0; value < 256; value++) {
        unsigned char sbox = reference_affine(gf8_inv(reference_affine(value)));
        if (!TEST_int_eq(sm4_sbox((unsigned char)value), sbox))
            return 0;
        for (j = 0; j < 4; j++)
            key[4 + j] = (unsigned char)(value + 37 * j);
        sm4_key_expansion(key, rk);
        sm4_encrypt_block(rk, kat_key, expected);
        sm4_enc(key, kat_key, got);
        if (!TEST_mem_eq(expected, sizeof(expected), got, sizeof(got)))
            return 0;
    }
    return 1;
}

/* Deliberately simple polynomial reference, used only on public test data. */
static unsigned char reference_gf8(unsigned a, unsigned b)
{
    unsigned p = 0;
    int i;
    for (i = 0; i < 8; i++)
        if ((a >> i) & 1)
            p ^= b << i;
    for (i = 14; i >= 8; i--)
        if ((p >> i) & 1)
            p ^= 0x1f5u << (i - 8);
    return (unsigned char)p;
}

static int test_sm4th_fields(void)
{
    unsigned a, b;
    int bits, i, j;
    for (a = 0; a < 256; a++) {
        unsigned char inverse = gf8_inv((unsigned char)a);
        if (!TEST_int_eq(reference_gf8(a, inverse), a != 0))
            return 0;
        for (b = 0; b < 256; b++)
            if (!TEST_int_eq(gf8_mul((unsigned char)a, (unsigned char)b),
                             reference_gf8(a, b)))
                return 0;
    }
    /* Multiplying by each basis vector checks all carry/reduction positions. */
    for (bits = 64; bits <= 160; bits += bits == 64 ? 64 : 32) {
        fe_t x, basis, got, expected, alias;
        fe_zero(&x);
        for (i = 0; i < bits / 8; i++)
            x.b[i] = (unsigned char)(0xf3u + 17u * i);
        expected = x;
        for (i = 0; i < bits; i++) {
            unsigned carry = (expected.b[bits / 8 - 1] >> 7) & 1;
            fe_zero(&basis);
            basis.b[i / 8] = (unsigned char)(1u << (i % 8));
            gf_mul(&got, &x, &basis, bits);
            alias = x;
            gf_mul(&alias, &alias, &basis, bits);
            if (!TEST_mem_eq(got.b, sizeof(got.b), expected.b, sizeof(expected.b))
                || !TEST_mem_eq(alias.b, sizeof(alias.b), got.b, sizeof(got.b)))
                return 0;
            for (j = bits / 8 - 1; j > 0; j--)
                expected.b[j] = (unsigned char)((expected.b[j] << 1)
                                               | (expected.b[j - 1] >> 7));
            expected.b[0] = (unsigned char)((expected.b[0] << 1)
                                           ^ (carry ? gf_low_terms(bits) : 0));
        }
    }
    return 1;
}

static int parallel_result[2];
static void parallel_f(void) { parallel_result[0] = test_sm4th_core_roundtrip(0); }
static void parallel_s(void) { parallel_result[1] = test_sm4th_core_roundtrip(1); }
static int test_sm4th_parallel_first_use(void)
{
    int i;
    thread_t threads[2] = {0};
    int started = 0, ok = 0;
    if (!TEST_true(run_thread(&threads[0], parallel_f)))
        goto end;
    started++;
    if (!TEST_true(run_thread(&threads[1], parallel_s)))
        goto end;
    started++;
    ok = 1;
end:
    for (i = 0; i < started; i++)
        if (!TEST_true(wait_for_thread(threads[i])))
            ok = 0;
    return ok && TEST_true(parallel_result[0]) && TEST_true(parallel_result[1]);
}

#endif /* OPENSSL_NO_SM4TH */

int setup_tests(void)
{
#ifndef OPENSSL_NO_SM4TH
    ADD_TEST(test_sm4th_parallel_first_use);
    ADD_TEST(test_sm4th_prg_bounds);
    ADD_TEST(test_sm4th_fields);
    ADD_TEST(test_sm4th_sbox);
    ADD_ALL_TESTS(test_sm4th_invalid_key, 2);
    ADD_ALL_TESTS(test_sm4th_kat, 2);
    ADD_TEST(test_sm4th_domain_separation);
    ADD_TEST(test_sm4th_core_f);
    ADD_TEST(test_sm4th_core_s);
    ADD_TEST(test_sm4th_evp_f);
    ADD_TEST(test_sm4th_evp_s);
#endif
    return 1;
}
