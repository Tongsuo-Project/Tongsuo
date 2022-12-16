/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Performance test for SM2,3,4 on xxx times 1MB random data, in average
 * Detailed performance indices:
 * SM2: encrypt(Mbps), decrypt(Mbps), sign(TPS), verify(TPS), keygen(TPS)
 * SM3: hash(Mbps)
 * SM4: ECB encrypt, CBC Encrypt, ECB decrypt, CBC decrypt(All in Mbps)
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

static long long get_time();

/* iteration number, could be adjusted as required */
#define ITR_NUM 100
#define RND_DATA_SIZE 1024 * 1024

/* time difference on each index */
struct perf_index {
    int sm2_enc;
    int sm2_dec;
    int sm2_sign;
    int sm2_verify;
    int sm2_keygen;
    int sm3_hash;
    int sm4_ecb_enc;
    int sm4_cbc_enc;
    int sm4_ecb_dec;
    int sm4_cbc_dec;
};

/* final result in either Mbps or TPS */
struct perf_result {
    int sm2_enc_avg;
    int sm2_dec_avg;
    int sm2_sign_avg;
    int sm2_verify_avg;
    int sm2_keygen_avg;
    int sm3_hash_avg;
    int sm4_ecb_enc_avg;
    int sm4_cbc_enc_avg;
    int sm4_ecb_dec_avg;
    int sm4_cbc_dec_avg;
};

static long long get_time()
{
    /* just using gettimeofday() is adequate for our case */
    struct timeval tp;

    if (gettimeofday(&tp, NULL) != 0)
        return 0;
    else
        return (long long)(tp.tv_sec * 1000 * 1000 + tp.tv_usec);
}

int main(void)
{
    struct perf_index *indices = NULL;
    struct perf_result result;
    int i = 0;
    unsigned char *rnd_data = NULL;
    long long start = 0, end = 0;
    EVP_PKEY *sm2_key = NULL;
    EVP_PKEY_CTX *sm2_ctx = NULL;
    unsigned char *out = NULL, *out2 = NULL;
    size_t outlen = 0, out2len = 0, tmplen = 0, inlen = RND_DATA_SIZE;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned char *sig = NULL;
    size_t mdlen = 0, siglen = 0;
    EVP_CIPHER_CTX *sm4_ctx = NULL;
    unsigned char key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    EVP_RAND *rand;
    EVP_RAND_CTX *rctx;
    OSSL_PARAM params[2], *p = NULL;
    unsigned int strength = 128;

    memset(&result, 0, sizeof(result));
    indices = malloc(sizeof(struct perf_index) * ITR_NUM);
    if (indices == NULL) {
        fprintf(stderr, "malloc error - indices\n");
        return -1;
    }
    memset(indices, 0, sizeof(struct perf_index) * ITR_NUM);

    rnd_data = malloc(RND_DATA_SIZE);
    if (rnd_data == NULL) {
        fprintf(stderr, "malloc error - rnd data\n");
        free(indices);
        return -1;
    }

    /* initialize the library by create a dummy key */
    sm2_key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    if (sm2_key == NULL) {
        goto err;
    }
    EVP_PKEY_free(sm2_key);

    for (; i < ITR_NUM; i++) {
        fprintf(stdout, "Iteration %d: ", i);

        /* create a pair of SM2 pub and priv keys, this is new in 8.4.0 */
        start = get_time();
        sm2_key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
        if (sm2_key == NULL) {
            goto err;
        }
        end = get_time();
        /* We simply calculate "1sec / one-key's-usec" as the result */
        indices[i].sm2_keygen = 1000 * 1000 / (end - start);

        /* fill-in the random data, as per GM/T 0105 */
        rand = EVP_RAND_fetch(NULL, "HASH-DRBG", NULL);
        if (rand == NULL) {
            goto err;
        }
        rctx = EVP_RAND_CTX_new(rand, NULL);
        if (rctx == NULL) {
            goto err;
        }
        EVP_RAND_free(rand);
        p = params;
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, SN_sm3, 0);
        *p = OSSL_PARAM_construct_end();
        if (!EVP_RAND_instantiate(rctx, strength, 0, NULL, 0, params)) {
            goto err;
        }
        if (!EVP_RAND_generate(rctx, rnd_data, RND_DATA_SIZE, strength, 0, NULL, 0)) {
            goto err;
        }
        EVP_RAND_CTX_free(rctx);

        sm2_ctx = EVP_PKEY_CTX_new(sm2_key, NULL);
        if (sm2_ctx == NULL) {
            goto err;
        }
        if (EVP_PKEY_encrypt_init(sm2_ctx) <= 0) {
            goto err;
        }
        if (EVP_PKEY_encrypt(sm2_ctx, NULL, &outlen, rnd_data, inlen) <= 0) {
            goto err;
        }
        out = OPENSSL_malloc(outlen);
        if (out == NULL) {
            goto err;
        }
        /* SM2 encrypt */
        start = get_time();
        if (EVP_PKEY_encrypt(sm2_ctx, out, &outlen, rnd_data, inlen) <= 0) {
            goto err;
        }
        end = get_time();
        indices[i].sm2_enc = 1000 * 1000 * 8 / (end - start);

        EVP_PKEY_CTX_free(sm2_ctx);
        sm2_ctx = EVP_PKEY_CTX_new(sm2_key, NULL);
        if (sm2_ctx == NULL) {
            goto err;
        }
        if (EVP_PKEY_decrypt_init(sm2_ctx) <= 0) {
            goto err;
        }
        out2 = OPENSSL_malloc(inlen);
        if (out2 == NULL) {
            goto err;
        }
        out2len = inlen;
        /* SM2 decrypt */
        start = get_time();
        if (EVP_PKEY_decrypt(sm2_ctx, out2, &out2len, out, outlen) <= 0) {
            goto err;
        }
        end = get_time();
        indices[i].sm2_dec = 1000 * 1000 * 8 / (end - start);

        /* SM3 hash */
        start = get_time();
        if (!EVP_Q_digest(NULL, "SM3", NULL, rnd_data, inlen, md, &mdlen)) {
            goto err;
        }
        end = get_time();
        indices[i].sm3_hash = 1000 * 1000 * 8 / (end - start);

        EVP_PKEY_CTX_free(sm2_ctx);
        sm2_ctx = EVP_PKEY_CTX_new(sm2_key, NULL);
        if (sm2_ctx == NULL) {
            goto err;
        }
        if (EVP_PKEY_sign_init(sm2_ctx) <= 0) {
            goto err;
        }
        if (EVP_PKEY_sign(sm2_ctx, NULL, &siglen, md, mdlen) <= 0) {
            goto err;
        }
        sig = OPENSSL_malloc(siglen);
        if (sig == NULL) {
            goto err;
        }
        /* SM2 sign */
        start = get_time();
        if (EVP_PKEY_sign(sm2_ctx, sig, &siglen, md, mdlen) <= 0) {
            goto err;
        }
        end = get_time();
        indices[i].sm2_sign = 1000 * 1000 / (end - start);

        EVP_PKEY_CTX_free(sm2_ctx);
        sm2_ctx = EVP_PKEY_CTX_new(sm2_key, NULL);
        if (sm2_ctx == NULL) {
            goto err;
        }
        if (EVP_PKEY_verify_init(sm2_ctx) <= 0) {
            goto err;
        }
        /* SM2 verify */
        start = get_time();
        if (EVP_PKEY_verify(sm2_ctx, sig, siglen, md, mdlen) != 1) {
            goto err;
        }
        end = get_time();
        indices[i].sm2_verify = 1000 * 1000 / (end - start);

        OPENSSL_free(out);
        OPENSSL_free(out2);
        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(sm2_ctx);
        EVP_PKEY_free(sm2_key);
        out = NULL;
        out2 = NULL;
        sig = NULL;
        sm2_ctx = NULL;
        sm2_key = NULL;

        out = OPENSSL_malloc(inlen * 2);
        if (out == NULL) {
            goto err;
        }
        sm4_ctx = EVP_CIPHER_CTX_new();
        if (sm4_ctx == NULL) {
            goto err;
        }
        if (!EVP_EncryptInit_ex2(sm4_ctx, EVP_sm4_ecb(), key, iv, NULL)) {
            goto err;
        }
        /* SM4 ECB encrypt */
        start = get_time();
        if (!EVP_EncryptUpdate(sm4_ctx, out, (int *)&outlen, rnd_data, inlen)) {
            goto err;
        }
        if (!EVP_EncryptFinal_ex(sm4_ctx, out + outlen, (int *)&tmplen)) {
            goto err;
        }
        end = get_time();
        indices[i].sm4_ecb_enc = 1000 * 1000 * 8 / (end - start);
 
        outlen += tmplen;

        EVP_CIPHER_CTX_free(sm4_ctx);
        sm4_ctx = NULL;

        out2 = OPENSSL_malloc(inlen * 2);
        if (out2 == NULL) {
            goto err;
        }
        sm4_ctx = EVP_CIPHER_CTX_new();
        if (sm4_ctx == NULL) {
            goto err;
        }
        if (!EVP_DecryptInit_ex2(sm4_ctx, EVP_sm4_ecb(), key, iv, NULL)) {
            goto err;
        }
        /* SM4 ECB decrypt */
        start = get_time();
        if (!EVP_DecryptUpdate(sm4_ctx, out2, (int *)&out2len, out, outlen)) {
            goto err;
        }
        if (!EVP_DecryptFinal_ex(sm4_ctx, out2 + out2len, (int *)&tmplen)) {
            goto err;
        }
        end = get_time();
        indices[i].sm4_ecb_dec = 1000 * 1000 * 8 / (end - start);
        EVP_CIPHER_CTX_free(sm4_ctx);

        sm4_ctx = EVP_CIPHER_CTX_new();
        if (sm4_ctx == NULL) {
            goto err;
        }
        if (!EVP_EncryptInit_ex2(sm4_ctx, EVP_sm4_cbc(), key, iv, NULL)) {
            goto err;
        }
        /* SM4 CBC encrypt */
        start = get_time();
        if (!EVP_EncryptUpdate(sm4_ctx, out, (int *)&outlen, rnd_data, inlen)) {
            goto err;
        }
        if (!EVP_EncryptFinal_ex(sm4_ctx, out + outlen, (int *)&tmplen)) {
            goto err;
        }
        end = get_time();
        indices[i].sm4_cbc_enc = 1000 * 1000 * 8 / (end - start);
 
        outlen += tmplen;
        EVP_CIPHER_CTX_free(sm4_ctx);

        sm4_ctx = EVP_CIPHER_CTX_new();
        if (sm4_ctx == NULL) {
            goto err;
        }
        if (!EVP_DecryptInit_ex2(sm4_ctx, EVP_sm4_cbc(), key, iv, NULL)) {
            goto err;
        }
        /* SM4 CBC decrypt */
        start = get_time();
        if (!EVP_DecryptUpdate(sm4_ctx, out2, (int *)&out2len, out, outlen)) {
            goto err;
        }
        if (!EVP_DecryptFinal_ex(sm4_ctx, out2 + out2len, (int *)&tmplen)) {
            goto err;
        }
        end = get_time();
        indices[i].sm4_cbc_dec = 1000 * 1000 * 8 / (end - start);
        EVP_CIPHER_CTX_free(sm4_ctx);
        sm4_ctx = NULL;

        OPENSSL_free(out);
        OPENSSL_free(out2);
        out = NULL;
        out2 = NULL;

#if 1
        fprintf(stdout, "sm2-enc: %d, "
                        "sm2-dec: %d, "
                        "sm2-sign: %d, "
                        "sm2-verify: %d, "
                        "sm2-keygen: %d, "
                        "sm3-hash: %d, "
                        "sm4-ecb-enc: %d, "
                        "sm4-cbc-enc: %d, "
                        "sm4-ecb-dec: %d, "
                        "sm4-cbc-dec: %d\n",
                        indices[i].sm2_enc, indices[i].sm2_dec,
                        indices[i].sm2_sign, indices[i].sm2_verify,
                        indices[i].sm2_keygen, indices[i].sm3_hash,
                        indices[i].sm4_ecb_enc, indices[i].sm4_cbc_enc,
                        indices[i].sm4_ecb_dec, indices[i].sm4_cbc_dec);
#endif
    }

    /* calculate the final average result */
    for (i = 0; i < ITR_NUM; i++) {
        result.sm2_enc_avg += indices[i].sm2_enc;
        result.sm2_dec_avg += indices[i].sm2_dec;
        result.sm2_sign_avg += indices[i].sm2_sign;
        result.sm2_verify_avg += indices[i].sm2_verify;
        result.sm2_keygen_avg += indices[i].sm2_keygen;
        result.sm3_hash_avg += indices[i].sm3_hash;
        result.sm4_ecb_enc_avg += indices[i].sm4_ecb_enc;
        result.sm4_cbc_enc_avg += indices[i].sm4_cbc_enc;
        result.sm4_ecb_dec_avg += indices[i].sm4_ecb_dec;
        result.sm4_cbc_dec_avg += indices[i].sm4_cbc_dec;
    }

    result.sm2_enc_avg /= ITR_NUM;
    result.sm2_dec_avg /= ITR_NUM;
    result.sm2_sign_avg /= ITR_NUM;
    result.sm2_verify_avg /= ITR_NUM;
    result.sm2_keygen_avg /= ITR_NUM;
    result.sm3_hash_avg /= ITR_NUM;
    result.sm4_ecb_enc_avg /= ITR_NUM;
    result.sm4_cbc_enc_avg /= ITR_NUM;
    result.sm4_ecb_dec_avg /= ITR_NUM;
    result.sm4_cbc_dec_avg /= ITR_NUM;
 
    fprintf(stdout, "Final result:\n"
            "sm2-enc: %d Mbps\n"
            "sm2-dec: %d Mbps\n"
            "sm2-sign: %d/s\n"
            "sm2-verify: %d/s\n"
            "sm2-keygen: %d/s\n"
            "sm3-hash: %d Mbps\n"
            "sm4-ecb-enc: %d Mbps\n"
            "sm4-cbc-enc: %d Mbps\n"
            "sm4-ecb-dec: %d Mbps\n"
            "sm4-cbc-dec: %d Mbps\n",
            result.sm2_enc_avg, result.sm2_dec_avg,
            result.sm2_sign_avg, result.sm2_verify_avg,
            result.sm2_keygen_avg, result.sm3_hash_avg,
            result.sm4_ecb_enc_avg, result.sm4_cbc_enc_avg,
            result.sm4_ecb_dec_avg, result.sm4_cbc_dec_avg);

    free(rnd_data);
    return 0;
err:
    fprintf(stderr, "Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_CTX_free(sm2_ctx);
    EVP_PKEY_free(sm2_key);
    OPENSSL_free(out);
    OPENSSL_free(out2);
    OPENSSL_free(sig);
    free(rnd_data);
    EVP_CIPHER_CTX_free(sm4_ctx);
    return -1;
}
