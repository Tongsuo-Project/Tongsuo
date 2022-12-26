/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <openssl/ec.h>
#include "internal/nelem.h"
#include "rand/rand_local.h"
#include "crypto/rand.h"

#if defined(OPENSSL_NO_EC) || defined(OPENSSL_NO_SM2)
    || defined(OPENSSL_NO_SM3) || defined(OPENSSL_NO_SM4)
# error "SM2, SM3 and SM4 must be enabled"
#endif

#define SALT_LEN 64

typedef struct test_ctx_st {
    const unsigned char *entropy;
    size_t entropylen;
    int entropycnt;
    const unsigned char *nonce;
    size_t noncelen;
    int noncecnt;
} TEST_DRBG_CTX;

static size_t self_test_get_entropy(RAND_DRBG *drbg, unsigned char **pout,
                                    int entropy, size_t min_len, size_t max_len,
                                    int prediction_resistance);
static size_t self_test_get_nonce(RAND_DRBG *drbg, unsigned char **pout,
                                  int entropy, size_t min_len, size_t max_len);

static int self_test_drbg_data_index;

#ifdef GM_DEBUG
static void hexdump(FILE *fp, const char *name, const unsigned char *buf,
                    size_t len)
{
    size_t i;

    fprintf(fp, "%s=", name);

    for (i = 0; i < len; i++)
        fprintf(fp, "%02X", buf[i]);

    fprintf(fp, "\n");
}
#endif

static int entropy_source_startup_health_test(void)
{
    unsigned char *entropy = NULL;
    RAND_DRBG *drbg = RAND_DRBG_get0_master();
    size_t entropylen = 0;
    int total = 1000000 / 8;
    unsigned int last = -1, cur;
    unsigned int cnt = 1, max = 27;
    int ret = 0;
    size_t i, j;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { startup health test for entropy source }\n");
#endif
    if (drbg == NULL)
        goto end;

    while (total > 0) {
        entropylen =
            drbg->get_entropy(drbg, &entropy, drbg->strength,
                              drbg->min_entropylen, drbg->max_entropylen, 0);

        if (entropylen < drbg->min_entropylen
            || entropylen > drbg->max_entropylen)
            goto end;

        for (i = 0; i < entropylen; i++) {
            for (j = 0; j < 8; j++) {
                cur = (entropy[i] >> j) & 0x01;

                if (last == cur) {
                    cnt++;

                    if (cnt >= max)
                        goto end;
                } else {
                    last = cur;
                    cnt = 1;
                }
            }
        }

        total -= entropylen;

        if (drbg->cleanup_entropy != NULL) {
            drbg->cleanup_entropy(drbg, entropy, entropylen);
            entropy = NULL;
            entropylen = 0;
        }
    }
#ifdef GM_DEBUG
    fprintf(stderr, "END { startup health test for entropy source }\n");
#endif
    ret = 1;
end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);

    return ret;
}

int Tongsuo_self_test_sm3_drbg(void)
{
    RAND_DRBG *drbg = NULL;
    TEST_DRBG_CTX t;
    int ret = 0;
    size_t request_len = 256 / 8;
    unsigned char buff[1024];
    unsigned char pers[] = {0xc9, 0x80, 0xde, 0xdf, 0x98, 0x82, 0xed, 0x44,
                            0x64, 0xa6, 0x74, 0x96, 0x78, 0x68, 0xf1, 0x43};
    unsigned char entropy[] = {
        0xE1, 0x0B, 0xC2, 0x8A, 0x0B, 0xFD, 0xDF, 0xE9, 0x3E, 0x7F, 0x51,
        0x86, 0xE0, 0xCA, 0x0B, 0x3B, 0x89, 0x0e, 0xb0, 0x67, 0xac, 0xf7,
        0x38, 0x2e, 0xff, 0x80, 0xb0, 0xc7, 0x3b, 0xc8, 0x72, 0xc6,
    };
    unsigned char nonce[] = {
        0x9F, 0xF4, 0x77, 0xC1, 0x86, 0x73, 0x84, 0x0D,
        0xaa, 0xd4, 0x71, 0xef, 0x3e, 0xf1, 0xd2, 0x03,
    };
    unsigned char adinreseed[] = {0x38, 0xBF, 0xEC, 0x9A, 0x10, 0xE6,
                                  0xE4, 0x0C, 0x10, 0x68, 0x41, 0xDA,
                                  0xE4, 0x8D, 0xC3, 0xB8};
    unsigned char adin2[] = {0x7E, 0xAA, 0x1B, 0xBE, 0xC7, 0x93, 0x93, 0xA7,
                             0xF4, 0xA8, 0x22, 0x7B, 0x69, 0x1E, 0xCB, 0x68};
    unsigned char expected[] = {0xFA, 0xAB, 0x8A, 0x9B, 0xA0, 0x16, 0x16, 0xB4,
                                0x0F, 0xD1, 0xD7, 0x3A, 0x9F, 0x58, 0xA5, 0xEA,
                                0xC0, 0xF3, 0x74, 0x54, 0x5D, 0x74, 0x53, 0x09,
                                0xA8, 0x73, 0x30, 0x92, 0xB4, 0x5F, 0xC1, 0xA9};
    int i;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test SM3-DRBG }\n");
#endif
    if ((drbg = RAND_DRBG_new(NID_sm3, 0, NULL)) == NULL)
        return 0;

    if (!RAND_DRBG_set_callbacks(drbg, self_test_get_entropy, NULL,
                                 self_test_get_nonce, NULL)) {
        goto err;
    }
    memset(&t, 0, sizeof(t));
    t.entropy = entropy;
    t.entropylen = sizeof(entropy);
    t.nonce = nonce;
    t.noncelen = sizeof(nonce);

    RAND_DRBG_set_ex_data(drbg, self_test_drbg_data_index, &t);
#ifdef GM_DEBUG
    hexdump(stderr, "entropy", entropy, sizeof(entropy));
    hexdump(stderr, "nonce", nonce, sizeof(nonce));
    hexdump(stderr, "personalization_str", pers, sizeof(pers));
    hexdump(stderr, "reseed additional_input", adinreseed, sizeof(adinreseed));
    hexdump(stderr, "generate additional_input", adin2, sizeof(adin2));
    fprintf(stderr, "requested_number_of_bits=%lu\n", request_len * 8);
    hexdump(stderr, "returned_bits", buff, request_len);
#endif
    for (i = 0; i < 1000; i++) {
        if (!RAND_DRBG_instantiate(drbg, pers, sizeof(pers))
            || !RAND_DRBG_reseed(drbg, adinreseed, sizeof(adinreseed), 0)
            || !RAND_DRBG_generate(drbg, buff, request_len, 0, adin2,
                                   sizeof(adin2))
            || memcmp(expected, buff, request_len) != 0)
            goto err;

        RAND_DRBG_uninstantiate(drbg);
    }
#ifdef GM_DEBUG
    fprintf(stderr, "END { self test SM3-DRBG }\n");
#endif
    ret = 1;
err:
    if (drbg != NULL)
        RAND_DRBG_uninstantiate(drbg);

    RAND_DRBG_free(drbg);
    return ret;
}

int Tongsuo_do_passwd(const char *passphrase, int passphrase_len, const char *salt,
                  int salt_len, char *result, int *res_len)
{
    int ret = 0;
    unsigned char new_salt[SALT_LEN] = {
        0x17, 0xce, 0x14, 0x4c, 0x26, 0x64, 0xc3, 0x90, 0x44, 0x6b, 0x51,
        0x1c, 0x39, 0xa5, 0x27, 0x1f, 0xc7, 0x01, 0x67, 0x12, 0x7b, 0x54,
        0xc9, 0x39, 0xbe, 0x66, 0xda, 0x88, 0x2d, 0xd0, 0xf4, 0x58, 0x7e,
        0x7e, 0x0f, 0x42, 0x9a, 0x41, 0xdb, 0xb9, 0xd5, 0xea, 0x2a, 0x35,
        0xc5, 0xa8, 0xac, 0x25, 0x6f, 0x78, 0xc0, 0xe4, 0xb7, 0xf6, 0xd7,
        0xfd, 0xb9, 0x0e, 0xf6, 0xbc, 0xa0, 0x3e, 0xfd, 0x31};

    EVP_MD_CTX *mctx = NULL;
    unsigned char buf[EVP_MAX_MD_SIZE];

    if (salt == NULL) {
        salt = (const char *)new_salt;
        salt_len = sizeof(new_salt);
    }

    if ((mctx = EVP_MD_CTX_new()) == NULL
        || !EVP_DigestInit_ex(mctx, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(mctx, salt, salt_len)
        || !EVP_DigestUpdate(mctx, passphrase, passphrase_len)
        || !EVP_DigestFinal_ex(mctx, buf, NULL))
        goto end;

    if (*res_len <= EVP_MD_size(EVP_sm3()))
        goto end;

    memcpy(result, buf, EVP_MD_size(EVP_sm3()));
    *res_len = EVP_MD_size(EVP_sm3());

    ret = 1;
end:
    EVP_MD_CTX_free(mctx);
    return ret;
}

int Tongsuo_setup_password(void)
{
    int ret = 0;
    int templen;
    BIO *out = NULL;
    char passwd[512];
    char salt_pass[1024];

    if (EVP_read_pw_string(passwd, sizeof(passwd), "Setup password: ", 1) != 0)
        goto end;

    templen = sizeof(salt_pass);

    if (!Tongsuo_do_passwd(passwd, strlen(passwd), NULL, 0, salt_pass, &templen))
        goto end;

    out = BIO_new_file(Tongsuo_get_default_passwd_file(), "w");
    if (out == NULL)
        goto end;

    BIO_hex_string(out, 0, 999999, (unsigned char *)salt_pass, templen);

    ret = 1;
end:
    BIO_free_all(out);
    return ret;
}

int Tongsuo_verify_password(void)
{
    int ret = 0;
    BIO *in = NULL;
    char *buf = NULL;
    long buf_len;
    int templen;
    char passwd[512];
    char calc_pass[1024];
    char read_pass[1024];

    in = BIO_new_file(Tongsuo_get_default_passwd_file(), "r");
    if (in == NULL)
        goto end;

    BIO_gets(in, read_pass, sizeof(read_pass));

    buf = (char *)OPENSSL_hexstr2buf(read_pass, &buf_len);
    if (buf == NULL)
        goto end;

    if (buf_len != EVP_MD_size(EVP_sm3()))
        goto end;

    if (EVP_read_pw_string(passwd, sizeof(passwd), "Enter password: ", 0) != 0)
        goto end;

    templen = sizeof(calc_pass);

    if (!Tongsuo_do_passwd(passwd, strlen(passwd), NULL, 0, calc_pass, &templen))
        goto end;

    if (templen != EVP_MD_size(EVP_sm3()))
        goto end;

    if (memcmp(buf, calc_pass, EVP_MD_size(EVP_sm3())))
        goto end;

    ret = 1;
end:
    BIO_free(in);
    OPENSSL_free(buf);
    return ret;
}

int Tongsuo_init_mod(void)
{
    RAND_DRBG_set_defaults(NID_sm3, 0);

    if (getenv("TONGSUO_NO_SELF_TEST_RAND_PERIOD"))
        RAND_DRBG_set_self_test_period_time_default(0);

    if (!getenv("TONGSUO_NO_ENTROPY_SOURCE_STARTUP_TEST")) {
        if (entropy_source_startup_health_test())
#ifdef GM_DEBUG
        fprintf(stderr, "Init: init random module success\n");
#else
        ;
#endif
    else
        return 0;
    }

#ifdef GM_DEBUG
    fprintf(stderr, "Init: crypto module init success\n");
    fprintf(stderr, "------------------------------------------------------\n");
#endif
    return 1;
}

int Tongsuo_self_test_integrity(void)
{
    const char *exe = Tongsuo_get_default_bin();
    int ret = 0;
    const char *pubkey;
    const char *def_pubkey = "-----BEGIN PUBLIC KEY-----\n"
          "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE4DyCERSfDFCtzDYEzXwFGnPy7PBS\n"
          "46vljnpWQKcgCkR3x+ZmzuXsabCZMfKPBNbAnSKlDwO9btRUzE19aRChLg==\n"
          "-----END PUBLIC KEY-----";
    char *buf = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIO *keybio = NULL;
    BIO *sigbio = NULL;
    size_t siglen;
    unsigned char *sigbuf = NULL;
    BIO *in = NULL;
    BIO *bmd = NULL;
    BIO *inp = NULL;
    int bufsize = 1024 * 8;
    char *sighex = NULL;
    int len;

    pubkey = getenv("TONGSUO_SIGN_PUBKEY");
    if (pubkey == NULL)
        pubkey = def_pubkey;

#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test integrity }\n");
    fprintf(stderr, "Pubkey=%s\n", pubkey);
#endif
    buf = OPENSSL_malloc(bufsize);
    if (buf == NULL)
        goto end;

    keybio = BIO_new_mem_buf(pubkey, -1);
    if (keybio == NULL)
        goto end;

    pkey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
    if (pkey == NULL)
        goto end;

    in = BIO_new(BIO_s_file());
    if (in == NULL)
        goto end;

    bmd = BIO_new(BIO_f_md());
    if (bmd == NULL)
        goto end;

    if (!BIO_get_md_ctx(bmd, &mctx))
        goto end;

    if (!EVP_DigestVerifyInit(mctx, &pctx, EVP_sm3(), NULL, pkey))
        goto end;

    sigbio = BIO_new_file(Tongsuo_get_default_signature_file(), "rb");
    if (sigbio == NULL)
        goto end;

    siglen = EVP_PKEY_size(pkey);
    sigbuf = OPENSSL_malloc(siglen);
    if (sigbuf == NULL)
        goto end;

    siglen = BIO_read(sigbio, sigbuf, siglen);
    if (siglen <= 0) {
        goto end;
    }

    BIO_free(sigbio);
    sigbio = NULL;

    sighex = OPENSSL_buf2hexstr(sigbuf, siglen);
    if (sighex == NULL)
        goto end;

#ifdef GM_DEBUG
    fprintf(stderr, "Input=%s\n", sighex);
#endif
    inp = BIO_push(bmd, in);

    if (BIO_read_filename(in, exe) <= 0)
        goto end;

    while (BIO_pending(inp) || !BIO_eof(inp)) {
        len = BIO_read(inp, (char *)buf, bufsize);
        if (len < 0) {
#ifdef GM_DEBUG
            fprintf(stderr, "Read Error in %s\n", exe);
            ERR_print_errors_fp(stderr);
#endif
            goto end;
        }
        if (len == 0)
            break;
    }

    if (!EVP_DigestVerifyFinal(mctx, sigbuf, (unsigned int)siglen))
        goto end;

    ret = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "END { self test integrity }\n");
#endif
end:
    OPENSSL_free(buf);
    OPENSSL_free(sigbuf);
    OPENSSL_free(sighex);
    BIO_free(in);
    BIO_free(bmd);
    BIO_free(sigbio);
    BIO_free(keybio);
    EVP_PKEY_free(pkey);

    return ret;
}

int Tongsuo_self_test_sm2_encrypt(void)
{
    int ret = 0;
    unsigned char pubkey[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEOToq2eJ+Q6yqq4WhnTuFWR4UQGFX\n"
        "F1rd03v3f/DK+e03/POotPVcA4UjJh/KZjav5qevoqFIKmBvXLOhiy4qHg==\n"
        "-----END PUBLIC KEY-----";
    unsigned char privkey[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7\n"
        "2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX\n"
        "Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe\n"
        "-----END PRIVATE KEY-----";
    const char *plain =
        "54686520666c6f6f66792062756e6e69657320686f70206174206d69646e69676874";
    EVP_PKEY *pub = NULL;
    EVP_PKEY *priv = NULL;
    unsigned char *plainbin = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *buf1 = NULL;
    unsigned char *buf2 = NULL;
    size_t outlen, ctextlen;
    BIO *bio = NULL;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test SM2 encrypt }\n");
    fprintf(stderr, "Pubkey=%s\n", pubkey);
    fprintf(stderr, "Input=%s\n", plain);
#endif

    bio = BIO_new_mem_buf(pubkey, -1);
    if (bio == NULL)
        goto end;

    pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pub == NULL)
        goto end;

    plainbin = OPENSSL_hexstr2buf(plain, NULL);
    if (plainbin == NULL)
        goto end;

    if ((pctx = EVP_PKEY_CTX_new(pub, NULL)) == NULL)
        goto end;

    if (EVP_PKEY_encrypt_init(pctx) <= 0)
        goto end;

    if (EVP_PKEY_encrypt(pctx, NULL, &outlen, plainbin, strlen(plain) / 2) <= 0)
        goto end;

    buf1 = OPENSSL_malloc(outlen);
    if (buf1 == NULL)
        goto end;

    if (EVP_PKEY_encrypt(pctx, buf1, &outlen, plainbin, strlen(plain) / 2) <= 0)
        goto end;

    ctextlen = outlen;
#ifdef GM_DEBUG
    fprintf(stderr, "Output=%s\n", OPENSSL_buf2hexstr(buf1, outlen));
#endif
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    BIO_free(bio);
    bio = NULL;

    bio = BIO_new_mem_buf(privkey, -1);
    if (bio == NULL)
        goto end;

    priv = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (priv == NULL)
        goto end;

    if ((pctx = EVP_PKEY_CTX_new(priv, NULL)) == NULL)
        goto end;

    if (EVP_PKEY_decrypt_init(pctx) <= 0)
        goto end;

    if (EVP_PKEY_decrypt(pctx, NULL, &outlen, buf1, ctextlen) <= 0)
        goto end;

    if (outlen != strlen(plain) / 2)
        goto end;

    buf2 = OPENSSL_malloc(outlen);
    if (buf2 == NULL)
        goto end;

    if (EVP_PKEY_decrypt(pctx, buf2, &outlen, buf1, ctextlen) <= 0)
        goto end;

    if (memcmp(buf2, plainbin, strlen(plain) / 2) != 0)
        goto end;

    ret = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "END { self test SM2 encrypt }\n");
#endif
end:
    OPENSSL_free(plainbin);
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    EVP_PKEY_CTX_free(pctx);
    BIO_free(bio);
    return ret;
}

int Tongsuo_self_test_sm2_decrypt(void)
{
    int ret = 0;
    unsigned char privkey[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7\n"
        "2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX\n"
        "Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe\n"
        "-----END PRIVATE KEY-----";
    const char *plain =
        "54686520666c6f6f66792062756e6e69657320686f70206174206d69646e69676874";
    const char *ctext =
        "30818A0220466BE2EF5C11782EC77864A0055417F407A5AFC11D653C6BCE69E417BB1D"
        "05B6022062B572E21FF0DDF5C726BD3F9FF2EAE56E6294713A607E9B9525628965F62C"
        "C804203C1B5713B5DB2728EB7BF775E44F4689FC32668BDC564F52EA45B09E8DF2A5F4"
        "0422084A9D0CC2997092B7D3C404FCE95956EB604D732B2307A8E5B8900ED6608CA5B1"
        "97";
    EVP_PKEY *pkey = NULL;
    unsigned char *plainbin = NULL;
    unsigned char *ctextbin = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *buf = NULL;
    size_t outlen;
    BIO *bio = NULL;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test SM2 decrypt }\n");
    fprintf(stderr, "Privatekey=%s\n", privkey);
    fprintf(stderr, "Input=%s\n", ctext);
    fprintf(stderr, "Output=%s\n", plain);
#endif
    bio = BIO_new_mem_buf(privkey, -1);
    if (bio == NULL)
        goto end;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL)
        goto end;

    plainbin = OPENSSL_hexstr2buf(plain, NULL);
    if (plainbin == NULL)
        goto end;

    ctextbin = OPENSSL_hexstr2buf(ctext, NULL);
    if (ctextbin == NULL)
        goto end;

    if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL)
        goto end;

    if (EVP_PKEY_decrypt_init(pctx) <= 0)
        goto end;

    if (EVP_PKEY_decrypt(pctx, NULL, &outlen, ctextbin, strlen(ctext) / 2) <= 0)
        goto end;

    if (outlen != strlen(plain) / 2)
        goto end;

    buf = OPENSSL_malloc(outlen);
    if (buf == NULL)
        goto end;

    if (EVP_PKEY_decrypt(pctx, buf, &outlen, ctextbin, strlen(ctext) / 2) <= 0)
        goto end;

    if (memcmp(buf, plainbin, strlen(plain) / 2) != 0)
        goto end;

    ret = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "END { self test SM2 decrypt }\n");
#endif
end:
    OPENSSL_free(plainbin);
    OPENSSL_free(ctextbin);
    OPENSSL_free(buf);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    BIO_free(bio);
    return ret;
}

int Tongsuo_self_test_sm2_verify(void)
{
    int ret = 0;
    unsigned char pubkey[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAECfnfMR5UIaFQ3X0WHkvFxnIXn60Y\n"
        "M/wHa7CP81bzUCDM6kkM4md1pS3G6nGMwapgCu0F+/NeCEpmMvYHLamtEw==\n"
        "-----END PUBLIC KEY-----";
    const char *tbs = "6D65737361676520646967657374";
    const char *sig =
        "3046022100f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee7"
        "20b3022100b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bb"
        "c1aa";
    EVP_PKEY *pkey = NULL;
    unsigned char *tbsbin = NULL;
    unsigned char *sigbin = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIO *bio = NULL;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test SM2 verify }\n");
    fprintf(stderr, "Pubkey=%s\n", pubkey);
    fprintf(stderr, "Input=%s\n", sig);
    fprintf(stderr, "Output=%s\n", tbs);
#endif
    bio = BIO_new_mem_buf(pubkey, -1);
    if (bio == NULL)
        goto end;

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pkey == NULL)
        goto end;

    tbsbin = OPENSSL_hexstr2buf(tbs, NULL);
    if (tbsbin == NULL)
        goto end;

    sigbin = OPENSSL_hexstr2buf(sig, NULL);
    if (sigbin == NULL)
        goto end;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL)
        goto end;

    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

    if (EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey) <= 0
        || EVP_DigestVerify(mctx, sigbin, strlen(sig) / 2, tbsbin,
                            strlen(tbs) / 2) <= 0) {
#ifdef GM_DEBUG
        fprintf(stderr, "Self test: SM2 verify failed\n");
#endif
        goto end;
    }

    ret = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "END { self test SM2 verify }\n");
#endif
end:
    OPENSSL_free(tbsbin);
    OPENSSL_free(sigbin);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    BIO_free(bio);
    return ret;
}

int Tongsuo_self_test_sm2_sign(void)
{
    int ret = 0;
    unsigned char privkey[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgOUUgj3shRLE/NuOK\n"
        "xtOflYiTk2koYLUaQvuB7033xbihRANCAAQJ+d8xHlQhoVDdfRYeS8XGchefrRgz\n"
        "/AdrsI/zVvNQIMzqSQziZ3WlLcbqcYzBqmAK7QX7814ISmYy9gctqa0T\n"
        "-----END PRIVATE KEY-----\n";
    const char *tbs = "6D65737361676520646967657374";
    EVP_PKEY *pkey = NULL;
    unsigned char *tbsbin = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIO *bio = NULL;
    unsigned char *buf = NULL;
    char *sig = NULL;
    size_t tmplen;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test SM2 sign }\n");
    fprintf(stderr, "PrivKey=%s\n", privkey);
    fprintf(stderr, "Input=%s\n", tbs);
#endif
    bio = BIO_new_mem_buf(privkey, -1);
    if (bio == NULL)
        goto end;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL)
        goto end;

    tbsbin = OPENSSL_hexstr2buf(tbs, NULL);
    if (tbsbin == NULL)
        goto end;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL)
        goto end;

    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

    tmplen = ECDSA_size(EVP_PKEY_get0_EC_KEY(pkey));

    buf = OPENSSL_malloc(tmplen);
    if (buf == NULL)
        goto end;

    if (EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey) <= 0
        || EVP_DigestSign(mctx, buf, &tmplen, tbsbin, strlen(tbs) / 2) <= 0)
        goto end;

    if (EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey) <= 0
        || EVP_DigestVerify(mctx, buf, tmplen, tbsbin, strlen(tbs) / 2) <= 0)
        goto end;

    sig = OPENSSL_buf2hexstr(buf, tmplen);
    if (sig == NULL)
        goto end;

    ret = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "Output=%s\n", sig);
    fprintf(stderr, "END { self test SM2 sign }\n");
#endif
end:
    OPENSSL_free(sig);
    OPENSSL_free(buf);
    OPENSSL_free(tbsbin);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    BIO_free(bio);
    return ret;
}

int Tongsuo_self_test_sm4_decrypt(void)
{
    int ret = 0;
    unsigned char buf[1024];
    EVP_CIPHER_CTX *ctx = NULL;
    const char *key = "0123456789ABCDEFFEDCBA9876543210";
    const char *iv = "0123456789ABCDEFFEDCBA9876543210";
    const char *input =
        "2677f46b09c122cc975533105bd4a22af6125f7275ce552c3a2bbcf533de8a3bfff5a4"
        "f208092c0901ba02d5772977369915e3fa2356c9f4eb6460ecc457e7f8";
    const char *output =
        "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210012345"
        "6789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210";
    unsigned char *keybin = NULL;
    unsigned char *outputbin = NULL;
    unsigned char *inputbin = NULL;
    unsigned char *ivbin = NULL;
    int tmplen;
    int outlen;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test SM4 decrypt }\n");
    fprintf(stderr, "Key=%s\n", key);
    fprintf(stderr, "IV=%s\n", iv);
    fprintf(stderr, "Input=%s\n", input);
    fprintf(stderr, "Output=%s\n", output);
#endif
    keybin = OPENSSL_hexstr2buf(key, NULL);
    if (keybin == NULL)
        goto end;

    ivbin = OPENSSL_hexstr2buf(iv, NULL);
    if (ivbin == NULL)
        goto end;

    inputbin = OPENSSL_hexstr2buf(input, NULL);
    if (inputbin == NULL)
        goto end;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL
        || !EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, keybin, ivbin)
        || !EVP_CIPHER_CTX_set_padding(ctx, 0)
        || !EVP_DecryptUpdate(ctx, buf, &outlen, inputbin, strlen(input) / 2)
        || !EVP_DecryptFinal_ex(ctx, buf + outlen, &tmplen))
        goto end;

    outlen += tmplen;

    outputbin = OPENSSL_hexstr2buf(output, NULL);
    if (outputbin == NULL)
        goto end;

    if (outlen != (int)strlen(output) / 2
        || memcmp(buf, outputbin, outlen) != 0)
        goto end;

    ret = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "END { self test SM4 decrypt }\n");
#endif
end:
    OPENSSL_free(keybin);
    OPENSSL_free(ivbin);
    OPENSSL_free(inputbin);
    OPENSSL_free(outputbin);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int Tongsuo_self_test_sm4_encrypt(void)
{
    int ret = 0;
    unsigned char buf[1024];
    EVP_CIPHER_CTX *ctx = NULL;
    const char *key = "0123456789ABCDEFFEDCBA9876543210";
    const char *iv = "0123456789ABCDEFFEDCBA9876543210";
    const char *input =
        "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210012345"
        "6789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210";
    const char *output =
        "2677f46b09c122cc975533105bd4a22af6125f7275ce552c3a2bbcf533de8a3bfff5a4"
        "f208092c0901ba02d5772977369915e3fa2356c9f4eb6460ecc457e7f8";
    unsigned char *keybin = NULL;
    unsigned char *outputbin = NULL;
    unsigned char *inputbin = NULL;
    unsigned char *ivbin = NULL;
    int tmplen;
    int outlen;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test SM4 encrypt }\n");
    fprintf(stderr, "Key=%s\n", key);
    fprintf(stderr, "IV=%s\n", iv);
    fprintf(stderr, "Input=%s\n", input);
    fprintf(stderr, "Output=%s\n", output);
#endif
    keybin = OPENSSL_hexstr2buf(key, NULL);
    if (keybin == NULL)
        goto end;

    ivbin = OPENSSL_hexstr2buf(iv, NULL);
    if (ivbin == NULL)
        goto end;

    inputbin = OPENSSL_hexstr2buf(input, NULL);
    if (inputbin == NULL)
        goto end;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL
        || !EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, keybin, ivbin)
        || !EVP_CIPHER_CTX_set_padding(ctx, 0)
        || !EVP_EncryptUpdate(ctx, buf, &outlen, inputbin, strlen(input) / 2)
        || !EVP_EncryptFinal_ex(ctx, buf + outlen, &tmplen))
        goto end;

    outlen += tmplen;

    outputbin = OPENSSL_hexstr2buf(output, NULL);
    if (outputbin == NULL)
        goto end;

    if (outlen != (int)strlen(output) / 2
        || memcmp(buf, outputbin, outlen) != 0)
        goto end;

    ret = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "END { self test SM4 encrypt }\n");
#endif
end:

    OPENSSL_free(keybin);
    OPENSSL_free(ivbin);
    OPENSSL_free(inputbin);
    OPENSSL_free(outputbin);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int Tongsuo_self_test_sm3(void)
{
    int ret = 0;
    EVP_MD_CTX *mctx = NULL;
    const char *input =
        "217b5ebc849b8637cfd06121c9e0035ac887ab33d4736ffa6539e22b4daf839088d3c8"
        "84001e97bf3351f11df69e1b9a4f2fa5929427f470e844de08b6434ffa";
    const char *output =
        "d82f2d501852941255ee2e11b2902982191717a365c48262d9239b30d85c58e9";
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned char *inputbin = NULL;
    unsigned char *outputbin = NULL;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test SM3 }\n");
    fprintf(stderr, "Input=%s\n", input);
    fprintf(stderr, "Output=%s\n", output);
#endif
    inputbin = OPENSSL_hexstr2buf(input, NULL);
    if (inputbin == NULL)
        goto end;

    if ((mctx = EVP_MD_CTX_new()) == NULL
        || !EVP_DigestInit_ex(mctx, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(mctx, inputbin, strlen(input) / 2)
        || !EVP_DigestFinal_ex(mctx, buf, NULL))
        goto end;

    outputbin = OPENSSL_hexstr2buf(output, NULL);
    if (outputbin == NULL)
        goto end;

    if (memcmp(buf, outputbin, strlen(output) / 2) != 0)
        goto end;

    EVP_MD_CTX_free(mctx);
    mctx = NULL;
    OPENSSL_free(inputbin);
    inputbin = NULL;
    OPENSSL_free(outputbin);
    outputbin = NULL;
#ifdef GM_DEBUG
    fprintf(stderr, "END { self test SM3 }\n");
#endif
    ret = 1;
end:
    OPENSSL_free(outputbin);
    EVP_MD_CTX_free(mctx);
    OPENSSL_free(inputbin);

    return ret;
}

static size_t self_test_get_entropy(RAND_DRBG *drbg, unsigned char **pout,
                                    int entropy, size_t min_len, size_t max_len,
                                    int prediction_resistance)
{
    TEST_DRBG_CTX *t =
        (TEST_DRBG_CTX *)RAND_DRBG_get_ex_data(drbg, self_test_drbg_data_index);

    t->entropycnt++;
    *pout = (unsigned char *)t->entropy;
    return t->entropylen;
}

static size_t self_test_get_nonce(RAND_DRBG *drbg, unsigned char **pout,
                                  int entropy, size_t min_len, size_t max_len)
{
    TEST_DRBG_CTX *t =
        (TEST_DRBG_CTX *)RAND_DRBG_get_ex_data(drbg, self_test_drbg_data_index);

    t->noncecnt++;
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

int Tongsuo_self_test_rand_delivery(void)
{
    int nbit = 1000000;
    unsigned char buf[1000000 / 8];
    int fail[15] = {0};
    size_t i = 0, j, k;
    int retry = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test random delivery }\n");
#endif

    while (i++ < 50) {
        if (RAND_bytes(buf, nbit / 8) != 1)
            return 0;

        j = 0;
        fail[j++] += rand_self_test_frequency(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_block_frequency(buf, nbit, 10000, NULL) ^ 1;
        fail[j++] += rand_self_test_poker(buf, nbit, 8, NULL) ^ 1;
        fail[j++] += rand_self_test_serial(buf, nbit, 5, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_runs(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_runs_distribution(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_longest_run_of_ones(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_derivation(buf, nbit, 7, NULL) ^ 1;
        fail[j++] += rand_self_test_self_correlation(buf, nbit, 16, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_matrix_rank(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_cumulative_sums(buf, nbit, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_approximate_entropy(buf, nbit, 5, NULL) ^ 1;
        fail[j++] += rand_self_test_linear_complexity(buf, nbit, 1000, NULL) ^ 1;
        fail[j++] += rand_self_test_maurer_universal_statistical(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_discrete_fourier_transform(buf, nbit, NULL) ^ 1;

        for (k = 0; k < OSSL_NELEM(fail); k++) {
            if (fail[k] >= 3) {
                if (--retry < 0)
                    return 0;

                i = 0;
                memset(fail, 0, sizeof(fail));
                break;
            }
        }
    }
#ifdef GM_DEBUG
    fprintf(stderr, "PASSED\t\t单比特频数检测\n");
    fprintf(stderr, "PASSED\t\t块内频数检测\n");
    fprintf(stderr, "PASSED\t\t扑克检测\n");
    fprintf(stderr, "PASSED\t\t重叠子序列检测\n");
    fprintf(stderr, "PASSED\t\t游程总数检测\n");
    fprintf(stderr, "PASSED\t\t游程分布检测\n");
    fprintf(stderr, "PASSED\t\t块内最大1游程检测\n");
    fprintf(stderr, "PASSED\t\t二元推导检测\n");
    fprintf(stderr, "PASSED\t\t自相关检测\n");
    fprintf(stderr, "PASSED\t\t矩阵秩检测\n");
    fprintf(stderr, "PASSED\t\t累加和检测\n");
    fprintf(stderr, "PASSED\t\t近似熵检测\n");
    fprintf(stderr, "PASSED\t\t线性复杂度检测\n");
    fprintf(stderr, "PASSED\t\t通用统计检测\n");
    fprintf(stderr, "PASSED\t\t离散傅里叶检测\n");

    fprintf(stderr, "END { self test random delivery }\n");
#endif
    return 1;
}

int Tongsuo_self_test_rand_poweron(void)
{
    int nbit = 1000000;
    unsigned char buf[1000000 / 8];
    int fail[15];
    size_t i = 0, j, k;
    int retry = 1;
#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test random poweron }\n");
#endif
    while(i++ < 20) {
        if (RAND_bytes(buf, nbit / 8) != 1)
            return 0;

        j = 0;
        fail[j++] += rand_self_test_frequency(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_block_frequency(buf, nbit, 10000, NULL) ^ 1;
        fail[j++] += rand_self_test_poker(buf, nbit, 8, NULL) ^ 1;
        fail[j++] += rand_self_test_serial(buf, nbit, 5, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_runs(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_runs_distribution(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_longest_run_of_ones(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_derivation(buf, nbit, 7, NULL) ^ 1;
        fail[j++] += rand_self_test_self_correlation(buf, nbit, 16, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_matrix_rank(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_cumulative_sums(buf, nbit, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_approximate_entropy(buf, nbit, 5, NULL) ^ 1;
        fail[j++] += rand_self_test_linear_complexity(buf, nbit, 1000, NULL) ^ 1;
        fail[j++] += rand_self_test_maurer_universal_statistical(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_discrete_fourier_transform(buf, nbit, NULL) ^ 1;

        for (k = 0; k < OSSL_NELEM(fail); k++) {
            if (fail[k] >= 2) {
                if (--retry < 0)
                    return 0;

                i = 0;
                memset(fail, 0, sizeof(fail));
                break;
            }
        }
    }

#ifdef GM_DEBUG
    fprintf(stderr, "PASSED\t\t单比特频数检测\n");
    fprintf(stderr, "PASSED\t\t块内频数检测\n");
    fprintf(stderr, "PASSED\t\t扑克检测\n");
    fprintf(stderr, "PASSED\t\t重叠子序列检测\n");
    fprintf(stderr, "PASSED\t\t游程总数检测\n");
    fprintf(stderr, "PASSED\t\t游程分布检测\n");
    fprintf(stderr, "PASSED\t\t块内最大1游程检测\n");
    fprintf(stderr, "PASSED\t\t二元推导检测\n");
    fprintf(stderr, "PASSED\t\t自相关检测\n");
    fprintf(stderr, "PASSED\t\t矩阵秩检测\n");
    fprintf(stderr, "PASSED\t\t累加和检测\n");
    fprintf(stderr, "PASSED\t\t近似熵检测\n");
    fprintf(stderr, "PASSED\t\t线性复杂度检测\n");
    fprintf(stderr, "PASSED\t\t通用统计检测\n");
    fprintf(stderr, "PASSED\t\t离散傅里叶检测\n");

    fprintf(stderr, "END { self test random poweron }\n");
#endif
    return 1;
}

int Tongsuo_self_test_rand_period(void)
{
    int nbit = 20000;
    unsigned char buf[20000 / 8];
    int fail[12] = {0};
    size_t i = 0, j, k;
    int retry = 1;

#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test random period }\n");
#endif
    while(i++ < 20) {
        if (RAND_bytes(buf, nbit / 8) != 1)
            return 0;

        j = 0;
        fail[j++] += rand_self_test_frequency(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_block_frequency(buf, nbit, 1000, NULL) ^ 1;
        fail[j++] += rand_self_test_poker(buf, nbit, 8, NULL) ^ 1;
        fail[j++] += rand_self_test_serial(buf, nbit, 5, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_runs(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_runs_distribution(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_longest_run_of_ones(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_derivation(buf, nbit, 7, NULL) ^ 1;
        fail[j++] += rand_self_test_self_correlation(buf, nbit, 16, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_matrix_rank(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_cumulative_sums(buf, nbit, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_approximate_entropy(buf, nbit, 5, NULL) ^ 1;

        for (k = 0; k < OSSL_NELEM(fail); k++) {
            if (fail[k] >= 2) {
                if (--retry < 0)
                    return 0;

                i = 0;
                memset(fail, 0, sizeof(fail));
                break;
            }
        }
    }
#ifdef GM_DEBUG
    fprintf(stderr, "PASSED\t\t单比特频数检测\n");
    fprintf(stderr, "PASSED\t\t块内频数检测\n");
    fprintf(stderr, "PASSED\t\t扑克检测\n");
    fprintf(stderr, "PASSED\t\t重叠子序列检测\n");
    fprintf(stderr, "PASSED\t\t游程总数检测\n");
    fprintf(stderr, "PASSED\t\t游程分布检测\n");
    fprintf(stderr, "PASSED\t\t块内最大1游程检测\n");
    fprintf(stderr, "PASSED\t\t二元推导检测\n");
    fprintf(stderr, "PASSED\t\t自相关检测\n");
    fprintf(stderr, "PASSED\t\t矩阵秩检测\n");
    fprintf(stderr, "PASSED\t\t累加和检测\n");
    fprintf(stderr, "PASSED\t\t近似熵检测\n");

    fprintf(stderr, "END { self test random period }\n");
#endif
    return 1;
}

int Tongsuo_self_test_rand_single(void)
{
    int nbit = 256;
    unsigned char buf[256 / 8];
    int retry = 1;

#ifdef GM_DEBUG
    fprintf(stderr, "BEGIN { self test random single }\n");
#endif

    do {
        if (RAND_bytes(buf, nbit / 8) != 1)
            return 0;

        if (rand_self_test_poker(buf, nbit, 2, NULL) == 1)
            break;
        else
            retry--;
    } while (retry >= 0);

#ifdef GM_DEBUG
    fprintf(stderr, "PASSED\t\t扑克检测\n");
    fprintf(stderr, "END { self test random single }\n");
#endif
    return 1;
}
