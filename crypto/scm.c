
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
#include "crypto/rand.h"
#include "rand/rand_local.h"
#include "internal/cryptlib.h"

#define SALT_LEN    64

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

    fprintf(stdout, "BEGIN { startup health test for entropy source }\n");

    if (drbg == NULL)
        goto end;

    while (total > 0) {
        entropylen = drbg->get_entropy(drbg, &entropy, drbg->strength,
                                       drbg->min_entropylen,
                                       drbg->max_entropylen, 0);

        if (entropylen < drbg->min_entropylen ||
                entropylen > drbg->max_entropylen)
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

    fprintf(stdout, "END { startup health test for entropy source }\n");

    ret = 1;
end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);

    return ret;
}

int scm_init(void)
{
    fprintf(stderr, "Init: SM2 module init success\n");
    fprintf(stderr, "Init: SM3 module init success\n");
    fprintf(stderr, "Init: SM4 module init success\n");

    RAND_DRBG_set_defaults(NID_sm3, 0);

    if (entropy_source_startup_health_test())
        fprintf(stderr, "Init: Random module init success\n");
    else
        return 0;

    fprintf(stderr, "------------------------------------------------------\n");

    return 1;
}

int scm_self_test_integrity(const char *exe)
{
    int ret = 0;
    const char *pubkey = "-----BEGIN PUBLIC KEY-----\n"
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
    int i;

    buf = app_malloc(bufsize, "I/O buffer");

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

    sigbio = BIO_new_file(OPENSSL_get_default_signature_file(), "rb");
    if (sigbio == NULL)
        goto end;

    siglen = EVP_PKEY_size(pkey);
    sigbuf = app_malloc(siglen, "signature buffer");
    siglen = BIO_read(sigbio, sigbuf, siglen);
    if (siglen <= 0) {
        goto end;
    }

    BIO_free(sigbio);
    sigbio = NULL;

    inp = BIO_push(bmd, in);

    if (BIO_read_filename(in, exe) <= 0)
        goto end;

    while (BIO_pending(inp) || !BIO_eof(inp)) {
        i = BIO_read(inp, (char *)buf, bufsize);
        if (i < 0) {
            BIO_printf(bio_err, "Read Error in %s\n", exe);
            ERR_print_errors(bio_err);
            goto end;
        }
        if (i == 0)
            break;
    }

    if (!EVP_DigestVerifyFinal(mctx, sigbuf, (unsigned int)siglen))
        goto end;

    sighex = OPENSSL_buf2hexstr(sigbuf, siglen);
    if (sighex == NULL)
        goto end;

    ret = 1;

    fprintf(stderr, "BEGIN { Self-test integrity test }\n");
    fprintf(stderr, "Self-test: integrity test\n");
    fprintf(stderr, "Pubkey=%s\n", pubkey);
    fprintf(stderr, "Input=%s\n", sighex);
//    fprintf(stderr, "Output=%s\n", tbs);
    fprintf(stderr, "END { Self-test integrity test }\n");
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

int scm_self_test_sm2_verify(void)
{
    int ret = 0;
    unsigned char pubkey[] = "-----BEGIN PUBLIC KEY-----\n"
                             "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEOToq2eJ+Q6yqq4WhnTuFWR4UQGFX\n"
                             "F1rd03v3f/DK+e03/POotPVcA4UjJh/KZjav5qevoqFIKmBvXLOhiy4qHg==\n"
                             "-----END PUBLIC KEY-----";
    const char *sig = "D7AD397F6FFA5D4F7F11E7217F241607DC30618C236D2C09C1B9EA8FDADEE2E8";
    const char *tbs = "3046022100AB1DB64DE7C40EDBDE6651C9B8EBDB804673DB836E5D5C7FE15DCF9ED2725037022100EBA714451FF69B0BB930B379E192E7CD5FA6E3C41C7FBD8303B799AB54A54621";
    EVP_PKEY *pkey = NULL;
    unsigned char *tbsbin = NULL;
    unsigned char *sigbin = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIO *bio = NULL;

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

    if (!EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey)
        || !EVP_DigestVerify(mctx, sigbin, strlen(sig)/2,
                             tbsbin, strlen(tbs)/2)) {
        fprintf(stderr, "Self test: SM2 sign failed\n");
        goto end;
    }

    ret = 1;

    fprintf(stderr, "BEGIN { Self-test SM2 verify test }\n");
    fprintf(stderr, "Pubkey=%s\n", pubkey);
    fprintf(stderr, "Input=%s\n", sig);
    fprintf(stderr, "Output=%s\n", tbs);
    fprintf(stderr, "END { Self-test SM2 verify test }\n");
end:
    OPENSSL_free(tbsbin);
    OPENSSL_free(sigbin);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    BIO_free(bio);
    return ret;
}


int scm_self_test_sm2_sign(void)
{
    int ret = 0;
    unsigned char privkey[] = "-----BEGIN PRIVATE KEY-----\n"
                              "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7\n"
                              "2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX\n"
                              "Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe\n"
                              "-----END PRIVATE KEY-----";
    const char *tbs = "3046022100AB1DB64DE7C40EDBDE6651C9B8EBDB804673DB836E5D5C7FE15DCF9ED2725037022100EBA714451FF69B0BB930B379E192E7CD5FA6E3C41C7FBD8303B799AB54A54621";
    EVP_PKEY *pkey = NULL;
    unsigned char *tbsbin = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIO *bio = NULL;
    unsigned char *buf = NULL;
    char *sig = NULL;
    size_t tmplen;

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

    if (!EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey)
        || !EVP_DigestSign(mctx, buf, &tmplen,
                           tbsbin, strlen(tbs)/2)) {
        fprintf(stderr, "Self test: SM2 sign failed\n");
        goto end;
    }

    if (!EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey)
        || !EVP_DigestVerify(mctx, buf, tmplen, tbsbin, strlen(tbs)/2))
        goto end;

    sig = OPENSSL_buf2hexstr(buf, tmplen);
    if (sig == NULL)
        goto end;

    ret = 1;

    fprintf(stderr, "BEGIN { Self-test SM2 sign test }\n");
    fprintf(stderr, "PrivKey=%s\n", privkey);
    fprintf(stderr, "Input=%s\n", tbs);
    fprintf(stderr, "Output=%s\n", sig);
    fprintf(stderr, "END { Self-test SM2 sign test }\n");
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

int scm_self_test_sm4_decrypt(void)
{
    int ret = 0;
    unsigned char buf[1024];
    EVP_CIPHER_CTX *ctx = NULL;
    const char *key = "95F28D1231BB9EE5F01DDF2E3148CF41";
    const char *iv = "01020304050607080901020304050607";
    const char *input = "0A1D209300FD1D410E5C538F18D91299F6DE0ADD8A4212D88D7FC44A992EC795";
    const char *output = "A7009665F44878D3AE472FC8B9A3E0AD6DA9B0DC44331EA9D6CF95A3081D4117";
    unsigned char *keybin = NULL;
    unsigned char *outputbin = NULL;
    unsigned char *inputbin = NULL;
    unsigned char *ivbin = NULL;
    int tmplen;
    int outlen;

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
        || !EVP_DecryptUpdate(ctx, buf, &outlen,
                              inputbin, strlen(input)/2)
        || !EVP_DecryptFinal_ex(ctx, buf + outlen, &tmplen))
        goto end;

    outlen += tmplen;

    outputbin = OPENSSL_hexstr2buf(output, NULL);
    if (outputbin == NULL)
        goto end;

    if (outlen != (int)strlen(output)/2 ||
        memcmp(buf, outputbin, outlen) != 0)
        goto end;

    ret = 1;

    fprintf(stdout, "BEGIN { Self-test SM4 decrypt test }\n");
    fprintf(stderr, "Key=%s\n", key);
    fprintf(stderr, "IV=%s\n", iv);
    fprintf(stderr, "Input=%s\n", input);
    fprintf(stderr, "Output=%s\n", output);
    fprintf(stdout, "END { Self-test SM4 decrypt test }\n");

end:
    OPENSSL_free(keybin);
    OPENSSL_free(ivbin);
    OPENSSL_free(inputbin);
    OPENSSL_free(outputbin);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int scm_self_test_sm4_encrypt(void)
{
    int ret = 0;
    unsigned char buf[1024];
    EVP_CIPHER_CTX *ctx = NULL;
    const char *key = "95F28D1231BB9EE5F01DDF2E3148CF41";
    const char *iv = "01020304050607080901020304050607";
    const char *input = "A7009665F44878D3AE472FC8B9A3E0AD6DA9B0DC44331EA9D6CF95A3081D4117";
    const char *output = "0A1D209300FD1D410E5C538F18D91299F6DE0ADD8A4212D88D7FC44A992EC795";
    unsigned char *keybin = NULL;
    unsigned char *outputbin = NULL;
    unsigned char *inputbin = NULL;
    unsigned char *ivbin = NULL;
    int tmplen;
    int outlen;

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
        || !EVP_EncryptUpdate(ctx, buf, &outlen,
                              inputbin, strlen(input)/2)
        || !EVP_EncryptFinal_ex(ctx, buf + outlen, &tmplen))
        goto end;

    outlen += tmplen;

    outputbin = OPENSSL_hexstr2buf(output, NULL);
    if (outputbin == NULL)
        goto end;

    if (outlen != (int)strlen(output)/2 ||
        memcmp(buf, outputbin, outlen) != 0)
        goto end;

    ret = 1;

    fprintf(stdout, "BEGIN { Self-test SM4 encrypt test }\n");
    fprintf(stderr, "Key=%s\n", key);
    fprintf(stderr, "IV=%s\n", iv);
    fprintf(stderr, "Input=%s\n", input);
    fprintf(stderr, "Output=%s\n", output);
    fprintf(stdout, "END { Self-test SM4 encrypt test }\n");

end:

    OPENSSL_free(keybin);
    OPENSSL_free(ivbin);
    OPENSSL_free(inputbin);
    OPENSSL_free(outputbin);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int scm_self_test_sm3(void)
{
    int ret = 0;
    EVP_MD_CTX *mctx = NULL;
    const char *input1[] = {
        "c684788d8e3cb4eac0c680500c175e54",
        "259909fe49ada2b1455b81a4e0a0f79912636ebaed96cb9d60c85cc2926e247e",
        "217b5ebc849b8637cfd06121c9e0035ac887ab33d4736ffa6539e22b4daf839088d3c884001e97bf3351f11df69e1b9a4f2fa5929427f470e844de08b6434ffa",
        "f66f79cb4f41fa491d0d6c7a78590545cb5a3850dc08f50b246bc365243ed5181c33f5d1f1f241a3cf1d38ae4077afebcc002a9302b01d4c3713ab855869ee7026d5fe3c2954bad913583526e0806f6272ae4a88e9d3fffb62ecac769419b23d81dec7b2de2ef6a7903e52ed6f5ed6aae804d0070896128633bf55c38e400a51",
        "3c45817cfc093f18b4f8fb3ae9941e28e079b4d443e7e53cedc8aafe131b5ebfa3897fd61f49fed14e84006be0525347e570ec741a5a10a9bc28df9d13bc187530bd821dd74005e9a4226da97c8e7a409f8d1cf042ba4ba04ff1583e1d37c225ab6772f78e825c02f61799987cb2ce234262312d98e258f649e2a47fbc2777d91823a56b9354f85516d250c08b731cb87d905521de3ade205403bc5e237d83580a8612fd2af8858b4874fb434f90dafe0b1efa5de8e981f18e08a9fa38851fd63cd8b80e68275d425a45dc8bb3956d8aef77bf99e01ed3d467a03233a8739e90db50a03330cbc2ac28b64f73321996f9a089cfe17788c2a3544a93ac3be70af8",
    };
    const char *output1[] = {
        "f00f5012914600a3ec71c8e99526dc41e3b51bb82def800fbd7cb7992e54c322",
        "804752ea387065b95cd46d108fa3d52d3657cfc0a9abb2d6f0bb8fbaf00b7c54",
        "d82f2d501852941255ee2e11b2902982191717a365c48262d9239b30d85c58e9",
        "ace600eb40c3d1506c10af1b3df6c51c9cf0389f61d98b29b24c89bd6256884f",
        "26cd58cf6961a1cdfcc12f1bbb1ec4b97ca332151a640b7582b1c73ccac94b88",
    };
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned char *inputbin = NULL;
    unsigned char *outputbin = NULL;
    size_t i;

    fprintf(stdout, "BEGIN { Self-test SM3 test }\n");

    for (i = 0; i < OSSL_NELEM(input1); i++) {
        inputbin = OPENSSL_hexstr2buf(input1[i], NULL);
        if (inputbin == NULL)
            goto end;

        if ((mctx = EVP_MD_CTX_new()) == NULL
            || !EVP_DigestInit_ex(mctx, EVP_sm3(), NULL)
            || !EVP_DigestUpdate(mctx, inputbin, strlen(input1[i]) / 2)
            || !EVP_DigestFinal_ex(mctx, buf, NULL))
            goto end;

        outputbin = OPENSSL_hexstr2buf(output1[i], NULL);
        if (outputbin == NULL)
            goto end;

        if (memcmp(buf, outputbin, strlen(output1[i]) / 2) != 0)
            goto end;

        EVP_MD_CTX_free(mctx);
        mctx = NULL;
        OPENSSL_free(inputbin);
        inputbin = NULL;
        OPENSSL_free(outputbin);
        outputbin = NULL;

        fprintf(stderr, "Self-test: SM3 test item %ld\n", i + 1);
        fprintf(stderr, "Input=%s\n", input1[i]);
        fprintf(stderr, "Output=%s\n", output1[i]);
    }

    fprintf(stdout, "END { Self-test SM3 test }\n");

    ret = 1;
end:
    OPENSSL_free(outputbin);
    EVP_MD_CTX_free(mctx);
    OPENSSL_free(inputbin);

    return ret;
}

static void hexdump(FILE *fp, const char *name,
               const unsigned char *buf, size_t len)
{
    size_t i;

    fprintf(fp, "%s=", name);

    for (i = 0; i < len; i++)
        fprintf(fp, "%02X", buf[i]);

    fprintf(fp, "\n");
}

static int self_test_drbg_data_index;

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
                                    int prediction_resistance)
{
    TEST_DRBG_CTX *t = (TEST_DRBG_CTX *)RAND_DRBG_get_ex_data(
                            drbg, self_test_drbg_data_index);

    t->entropycnt++;
    *pout = (unsigned char *)t->entropy;
    return t->entropylen;
}

static size_t self_test_get_nonce(RAND_DRBG *drbg, unsigned char **pout,
                                  int entropy, size_t min_len, size_t max_len)
{
    TEST_DRBG_CTX *t = (TEST_DRBG_CTX *)RAND_DRBG_get_ex_data(
                        drbg, self_test_drbg_data_index);

    t->noncecnt++;
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

int scm_self_test_sm3_drbg(void)
{
    RAND_DRBG *drbg = NULL;
    TEST_DRBG_CTX t;
    int ret = 0;
    size_t request_len = 256 / 8;
    unsigned char buff[1024];
    unsigned char pers[] = {
        0xc9, 0x80, 0xde, 0xdf, 0x98, 0x82, 0xed, 0x44, 0x64, 0xa6, 0x74, 0x96,
        0x78, 0x68, 0xf1, 0x43
    };
    unsigned char entropy[] = {
        0xE1, 0x0B, 0xC2, 0x8A, 0x0B, 0xFD, 0xDF, 0xE9, 0x3E, 0x7F, 0x51, 0x86,
        0xE0, 0xCA, 0x0B, 0x3B, 0x89, 0x0e, 0xb0, 0x67, 0xac, 0xf7, 0x38, 0x2e,
        0xff, 0x80, 0xb0, 0xc7, 0x3b, 0xc8, 0x72, 0xc6,
    };
    unsigned char nonce[] = {
        0x9F, 0xF4, 0x77, 0xC1, 0x86, 0x73, 0x84, 0x0D, 0xaa, 0xd4, 0x71, 0xef,
        0x3e, 0xf1, 0xd2, 0x03,
    };
    unsigned char adinreseed[] = {
        0x38, 0xBF, 0xEC, 0x9A, 0x10, 0xE6, 0xE4, 0x0C, 0x10, 0x68, 0x41, 0xDA,
        0xE4, 0x8D, 0xC3, 0xB8
    };
    unsigned char adin2[] = {
        0x7E, 0xAA, 0x1B, 0xBE, 0xC7, 0x93, 0x93, 0xA7, 0xF4, 0xA8, 0x22, 0x7B,
        0x69, 0x1E, 0xCB, 0x68
    };
    unsigned char expected[] = {
        0xFA, 0xAB, 0x8A, 0x9B, 0xA0, 0x16, 0x16, 0xB4, 0x0F, 0xD1, 0xD7, 0x3A,
        0x9F, 0x58, 0xA5, 0xEA, 0xC0, 0xF3, 0x74, 0x54, 0x5D, 0x74, 0x53, 0x09,
        0xA8, 0x73, 0x30, 0x92, 0xB4, 0x5F, 0xC1, 0xA9
    };
    int i;

    fprintf(stdout, "BEGIN { Self-test SM3-DRBG test }\n");

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

    hexdump(stdout, "entropy", entropy, sizeof(entropy));
    hexdump(stdout, "nonce", nonce, sizeof(nonce));
    hexdump(stdout, "personalization_str", pers, sizeof(pers));
    hexdump(stdout, "reseed additional_input", adinreseed, sizeof(adinreseed));
    hexdump(stdout, "generate additional_input", adin2, sizeof(adin2));
    fprintf(stdout, "requested_number_of_bits=%lu\n", request_len * 8);
    hexdump(stdout, "returned_bits", buff, request_len);

    for (i = 0; i < 1000; i++) {
        if (!RAND_DRBG_instantiate(drbg, pers, sizeof(pers))
            || !RAND_DRBG_reseed(drbg, adinreseed, sizeof(adinreseed), 0)
            || !RAND_DRBG_generate(drbg, buff, request_len, 0,
                                   adin2, sizeof(adin2))
            || memcmp(expected, buff, request_len) != 0)
            goto err;

        RAND_DRBG_uninstantiate(drbg);
        fprintf(stdout, ".");
    }

    fprintf(stdout, "\n");

    fprintf(stdout, "END { Self-test SM3-DRBG test }\n");

    ret = 1;
err:
    if (drbg != NULL)
        RAND_DRBG_uninstantiate(drbg);

    RAND_DRBG_free(drbg);
    return ret;
}

int scm_do_passwd(const char *passphrase, int passphrase_len,
                     const char *salt, int salt_len,
                     char *result, int *res_len)
{
    int ret = 0;
    unsigned char new_salt[SALT_LEN] = {
        0x17, 0xce, 0x14, 0x4c, 0x26, 0x64, 0xc3, 0x90, 0x44, 0x6b, 0x51, 0x1c,
        0x39, 0xa5, 0x27, 0x1f, 0xc7, 0x01, 0x67, 0x12, 0x7b, 0x54, 0xc9, 0x39,
        0xbe, 0x66, 0xda, 0x88, 0x2d, 0xd0, 0xf4, 0x58, 0x7e, 0x7e, 0x0f, 0x42,
        0x9a, 0x41, 0xdb, 0xb9, 0xd5, 0xea, 0x2a, 0x35, 0xc5, 0xa8, 0xac, 0x25,
        0x6f, 0x78, 0xc0, 0xe4, 0xb7, 0xf6, 0xd7, 0xfd, 0xb9, 0x0e, 0xf6, 0xbc,
        0xa0, 0x3e, 0xfd, 0x31};

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

int scm_setup_password(void)
{
    int ret = 0;
    int templen;
    BIO *out = NULL;
    char passwd[512];
    char salt_pass[1024];

    fprintf(stdout, "Setup admin password\n");

    if (EVP_read_pw_string(passwd, sizeof(passwd), "Password: ", 1) != 0)
        goto end;

    templen = sizeof(salt_pass);

    if (!scm_do_passwd(passwd, strlen(passwd), NULL, 0, salt_pass, &templen))
        goto end;

    out = bio_open_default(OPENSSL_get_default_passwd_file(), 'w', FORMAT_TEXT);
    if (out == NULL)
        goto end;

    BIO_hex_string(out, 0, 999999, (unsigned char *)salt_pass, templen);

    ret = 1;
end:
    BIO_free_all(out);
    return ret;
}

int scm_verify_password(void)
{
    int ret = 0;
    BIO *in = NULL;
    char *buf = NULL;
    long buf_len;
    int templen;
    char passwd[512];
    char calc_pass[1024];
    char read_pass[1024];

    in = BIO_new_file(OPENSSL_get_default_passwd_file(), "r");
    if (in == NULL)
        goto end;

    BIO_gets(in, read_pass, sizeof(read_pass));

    buf = (char *)OPENSSL_hexstr2buf(read_pass, &buf_len);
    if (buf == NULL)
        goto end;

    if (buf_len != EVP_MD_size(EVP_sm3()))
        goto end;

    if (EVP_read_pw_string(passwd, sizeof(passwd), "Password: ", 0) != 0)
        goto end;

    templen = sizeof(calc_pass);

    if (!scm_do_passwd(passwd, strlen(passwd), NULL, 0, calc_pass, &templen))
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
