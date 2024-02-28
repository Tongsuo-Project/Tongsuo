/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/tsapi.h>
#include <openssl/evp.h>
#include <openssl/sdf.h>
#include <openssl/pem.h>
#include <openssl/sgd.h>
#include "testutil.h"
#include "../crypto/sdf/sdf_local.h"
#ifdef SDF_LIB
# include "sdfe_api.h"
#endif

static int test_TSAPI_Version(void)
{
    char *version = TSAPI_Version();

    if (!TEST_ptr(version))
        return 0;
    
    OPENSSL_free(version);
    return 1;
}

static int test_TSAPI_RandBytes(void)
{
    int ret = 0;
    size_t len = 32;
    unsigned char *buf1 = NULL;
    unsigned char *buf2 = NULL;

    buf1 = TSAPI_RandBytes(len);
    if (!TEST_ptr(buf1))
        goto end;

    buf2 = TSAPI_RandBytes(len);
    if (!TEST_ptr(buf2))
        goto end;

    if (!TEST_mem_ne(buf1, len, buf2, len))
        goto end;

    ret = 1;
end:
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    return ret;
}

#ifndef OPENSSL_NO_SM2
static int test_TSAPI_SM2Keygen(void)
{
    int ok = 0;
    EVP_PKEY *key = NULL, *pubkey = NULL;
    unsigned char *sig = NULL;
    const char *input = "test";
    size_t siglen;
    BIO *tmpbio = NULL;

    key = TSAPI_SM2Keygen();
    if (!TEST_ptr(key))
        return 0;

    tmpbio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(tmpbio))
        goto end;

    if (!TEST_true(PEM_write_bio_PUBKEY(tmpbio, key)))
        goto end;

    pubkey = PEM_read_bio_PUBKEY(tmpbio, NULL, NULL, NULL);
    if (!TEST_ptr(pubkey))
        goto end;

    sig = TSAPI_SM2Sign(key, (const unsigned char *)input, strlen(input),
                        &siglen);
    if (!TEST_ptr(sig))
        goto end;

    if (!TEST_true(TSAPI_SM2Verify(pubkey, (const unsigned char *)input,
                                   strlen(input), sig, siglen)))
        goto end;

    ok = 1;
end:
    BIO_free(tmpbio);
    OPENSSL_free(sig);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(key);
    return ok;
}

static int test_TSAPI_SM2Sign(void)
{
    int ok = 0;
    EVP_PKEY *key = NULL;
    const char *input = "test";
    unsigned char *sig = NULL;
    size_t siglen;

    key = TSAPI_SM2Keygen();
    if (!TEST_ptr(key))
        return 0;

    sig = TSAPI_SM2Sign(key, (const unsigned char *)input, strlen(input),
                        &siglen);
    if (!TEST_ptr(sig) || !TEST_true(siglen > 0))
        goto end;

    ok = 1;
end:
    OPENSSL_free(sig);
    EVP_PKEY_free(key);
    return ok;
}

static int test_TSAPI_SM2Verify(void)
{
    int ok = 0;
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    const char *pem = "-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEOToq2eJ+Q6yqq4WhnTuFWR4UQGFX\n"
"F1rd03v3f/DK+e03/POotPVcA4UjJh/KZjav5qevoqFIKmBvXLOhiy4qHg==\n"
"-----END PUBLIC KEY-----";
    const char *input = "hello world";
    unsigned char sig[] = {
        0x30, 0x45, 0x02, 0x20, 0x6b, 0xa1, 0x2c, 0x29, 0xaf, 0x6a, 0x4d, 0xe7,
        0x6d, 0xb0, 0x85, 0xa1, 0xd3, 0x5f, 0xfa, 0x1d, 0x00, 0x77, 0xfc, 0x6a,
        0x13, 0xe4, 0xac, 0x1b, 0x64, 0xe6, 0x82, 0x9e, 0x34, 0x89, 0x71, 0xfb,
        0x02, 0x21, 0x00, 0xcb, 0xfe, 0xab, 0xc6, 0xcb, 0x61, 0x2d, 0x25, 0xe9,
        0x0a, 0xdc, 0x71, 0xde, 0xe3, 0x9a, 0xdb, 0xfa, 0xcf, 0x62, 0x4e, 0x5a,
        0xa9, 0x4b, 0x8d, 0xac, 0x7c, 0x7b, 0xa8, 0x4b, 0x7b, 0x77, 0x9c,};
    size_t siglen = sizeof(sig);

    bio = BIO_new_mem_buf(pem, -1);
    if (!TEST_ptr(bio))
        return 0;

    key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!TEST_ptr(key))
        goto end;

    if (!TEST_true(TSAPI_SM2Verify(key, (const unsigned char *)input,
                                   strlen(input), sig, siglen)))
        goto end;

    ok = 1;
end:
    BIO_free(bio);
    EVP_PKEY_free(key);
    return ok;
}

static int test_TSAPI_SM2Encrypt(void)
{
    int ok = 0;
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    const char *pem = "-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEOToq2eJ+Q6yqq4WhnTuFWR4UQGFX\n"
"F1rd03v3f/DK+e03/POotPVcA4UjJh/KZjav5qevoqFIKmBvXLOhiy4qHg==\n"
"-----END PUBLIC KEY-----";
    const char *input = "test";
    unsigned char *out = NULL;
    size_t outlen;

    bio = BIO_new_mem_buf(pem, -1);
    if (!TEST_ptr(bio))
        return 0;

    key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!TEST_ptr(key))
        goto end;

    out = TSAPI_SM2Encrypt(key, (const unsigned char *)input, strlen(input),
                           &outlen);
    if (!TEST_ptr(out)
        || !TEST_true(outlen > 0))
        goto end;

    ok = 1;
end:
    BIO_free(bio);
    EVP_PKEY_free(key);
    OPENSSL_free(out);
    return ok;
}

# ifdef SDF_LIB
static int bitmap_is_inuse(uint64_t *pu64, int32_t index)
{

	int32_t pos, offset;
	uint64_t mask;

	mask = 0x1ull;

	pos = index >> 6;
	offset = (63 - (index & 0x3f));
	mask <<= offset;

	return (pu64[pos] & mask) ? 1 : 0;
}
# endif

static int test_TSAPI_SM2Decrypt(void)
{
    int ok = 0;
# ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    OSSL_ECCrefPrivateKey *privkey = NULL;
    OSSL_ECCrefPublicKey *pubkey = NULL;
    sdfe_bitmap_t bitmap;
    sdfe_asym_key_ecc_t asym;
    OSSL_ECCCipher *pECCCipher = NULL;
    uint32_t cnt, i;
    int index = -1;
    unsigned char out[256];
    unsigned int outlen = sizeof(out);
# else
    unsigned char *out = NULL;
    size_t outlen;
# endif
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    const char *pem = "-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7\n"
"2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX\n"
"Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe\n"
"-----END PRIVATE KEY-----";
    unsigned char in[] = {
        0x30, 0x81, 0x8A, 0x02, 0x20, 0x46, 0x6B, 0xE2, 0xEF, 0x5C, 0x11, 0x78,
        0x2E, 0xC7, 0x78, 0x64, 0xA0, 0x05, 0x54, 0x17, 0xF4, 0x07, 0xA5, 0xAF,
        0xC1, 0x1D, 0x65, 0x3C, 0x6B, 0xCE, 0x69, 0xE4, 0x17, 0xBB, 0x1D, 0x05,
        0xB6, 0x02, 0x20, 0x62, 0xB5, 0x72, 0xE2, 0x1F, 0xF0, 0xDD, 0xF5, 0xC7,
        0x26, 0xBD, 0x3F, 0x9F, 0xF2, 0xEA, 0xE5, 0x6E, 0x62, 0x94, 0x71, 0x3A,
        0x60, 0x7E, 0x9B, 0x95, 0x25, 0x62, 0x89, 0x65, 0xF6, 0x2C, 0xC8, 0x04,
        0x20, 0x3C, 0x1B, 0x57, 0x13, 0xB5, 0xDB, 0x27, 0x28, 0xEB, 0x7B, 0xF7,
        0x75, 0xE4, 0x4F, 0x46, 0x89, 0xFC, 0x32, 0x66, 0x8B, 0xDC, 0x56, 0x4F,
        0x52, 0xEA, 0x45, 0xB0, 0x9E, 0x8D, 0xF2, 0xA5, 0xF4, 0x04, 0x22, 0x08,
        0x4A, 0x9D, 0x0C, 0xC2, 0x99, 0x70, 0x92, 0xB7, 0xD3, 0xC4, 0x04, 0xFC,
        0xE9, 0x59, 0x56, 0xEB, 0x60, 0x4D, 0x73, 0x2B, 0x23, 0x07, 0xA8, 0xE5,
        0xB8, 0x90, 0x0E, 0xD6, 0x60, 0x8C, 0xA5, 0xB1, 0x97,};
    const char *expected = "The floofy bunnies hop at midnight";

    bio = BIO_new_mem_buf(pem, -1);
    if (!TEST_ptr(bio))
        return 0;

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!TEST_ptr(key))
        goto end;

# ifdef SDF_LIB
    memset(&login_arg, 0, sizeof(login_arg));

    strcpy((char *)login_arg.name, "admin");
    login_arg.passwd = (uint8_t *)"123123";
    login_arg.passwd_len = 6;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK)
        goto end;

    bitmap.start = 0;
    bitmap.cnt = SDFE_BITMAP_U64_MAX_CNT;
    if (SDFE_BitmapAsymKey(hSessionHandle, SDFE_ASYM_KEY_AREA_ENC,
                           SDFE_ASYM_KEY_TYPE_SM2, &bitmap) != OSSL_SDR_OK)
        goto end;

    cnt = bitmap.cnt << 6;
    for(i = 0; i < cnt; i++){
        if(!bitmap_is_inuse(bitmap.bitmap, i)) {
            index = i;
            break;
        }
    }

    if (index < 0)
        goto end;

    asym.area = SDFE_ASYM_KEY_AREA_ENC;
    asym.index = index;
    asym.type = SDFE_ASYM_KEY_TYPE_SM2;
    asym.privkey_bits = 256;
    asym.privkey_len = asym.privkey_bits >> 3;
    asym.pubkey_bits = 256;
    asym.pubkey_len = (asym.pubkey_bits >> 3) << 1;

    pubkey = TSAPI_EVP_PKEY_get_ECCrefPublicKey(key);
    if (!TEST_ptr(pubkey))
        goto end;

    privkey = TSAPI_EVP_PKEY_get_ECCrefPrivateKey(key);
    if (!TEST_ptr(privkey))
        goto end;

    memcpy(asym.pubkey, pubkey, sizeof(*pubkey));
    memcpy(asym.privkey, privkey, sizeof(*privkey));

    if (SDFE_ImportECCKey(hSessionHandle, &asym, NULL) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_GetPrivateKeyAccessRight(hSessionHandle, index, NULL, 0)
            != OSSL_SDR_OK)
        goto end;

    pECCCipher = TSAPI_SM2Ciphertext_to_ECCCipher(in, sizeof(in));

    if (TSAPI_SDF_InternalDecrypt_ECC(hSessionHandle, index, pECCCipher,
                                      out, &outlen) != OSSL_SDR_OK)
        goto end;
# else
    out = TSAPI_SM2Decrypt(key, in, sizeof(in), &outlen);
    if (!TEST_ptr(out))
        goto end;
# endif

    if (!TEST_true(outlen == strlen(expected))
        || !TEST_mem_eq(out, outlen, expected, strlen(expected)))
        goto end;

    ok = 1;
end:
    BIO_free(bio);
    EVP_PKEY_free(key);
# ifdef SDF_LIB
    OPENSSL_free(pubkey);
    OPENSSL_free(privkey);
    OPENSSL_free(pECCCipher);
    (void)SDFE_DelECCKey(hSessionHandle, asym.area, index);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
# else
    OPENSSL_free(out);
# endif
    return ok;
}
#endif

#ifndef OPENSSL_NO_SM4
static int test_TSAPI_SM4Encrypt(void)
{
    unsigned char key[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char iv[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char in[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char expected[] = {
        0x26, 0x77, 0xF4, 0x6B, 0x09, 0xC1, 0x22, 0xCC, 0x97, 0x55, 0x33, 0x10,
        0x5B, 0xD4, 0xA2, 0x2A, 0xF6, 0x12, 0x5F, 0x72, 0x75, 0xCE, 0x55, 0x2C,
        0x3A, 0x2B, 0xBC, 0xF5, 0x33, 0xDE, 0x8A, 0x3B,
    };
    unsigned char *out = NULL;
    size_t outlen;

    out = TSAPI_SM4Encrypt(OSSL_SGD_MODE_CBC, key, sizeof(key), -1, iv, in,
                           sizeof(in), &outlen);
    if (!TEST_ptr(out))
        return 0;

    if (!TEST_mem_eq(out, outlen, expected, sizeof(expected))) {
        OPENSSL_free(out);
        return 0;
    }

    OPENSSL_free(out);
    return 1;
}

static int test_TSAPI_SM4Decrypt(void)
{
    unsigned char key[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char iv[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char in[] = {
        0x26, 0x77, 0xF4, 0x6B, 0x09, 0xC1, 0x22, 0xCC, 0x97, 0x55, 0x33, 0x10,
        0x5B, 0xD4, 0xA2, 0x2A, 0xF6, 0x12, 0x5F, 0x72, 0x75, 0xCE, 0x55, 0x2C,
        0x3A, 0x2B, 0xBC, 0xF5, 0x33, 0xDE, 0x8A, 0x3B,
    };
    unsigned char expected[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char *out = NULL;
    size_t outlen;

    out = TSAPI_SM4Decrypt(OSSL_SGD_MODE_CBC, key, sizeof(key), -1, iv, in,
                           sizeof(in), &outlen);
    if (!TEST_ptr(out))
        return 0;

    if (!TEST_mem_eq(out, outlen, expected, sizeof(expected))) {
        OPENSSL_free(out);
        return 0;
    }

    OPENSSL_free(out);
    return 1;
}
#endif

#ifndef OPENSSL_NO_SM3
static int test_TSAPI_SM3(void)
{
    unsigned char in[] = {
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64,
    };
    unsigned char expected[] = {
        0xDE, 0xBE, 0x9F, 0xF9, 0x22, 0x75, 0xB8, 0xA1, 0x38, 0x60, 0x48, 0x89,
        0xC1, 0x8E, 0x5A, 0x4D, 0x6F, 0xDB, 0x70, 0xE5, 0x38, 0x7E, 0x57, 0x65,
        0x29, 0x3d, 0xCb, 0xA3, 0x9C, 0x0C, 0x57, 0x32,
    };
    size_t outlen;
    unsigned char *out = TSAPI_SM3(in, sizeof(in), &outlen);

    if (!TEST_ptr(out))
        return 0;

    if (!TEST_mem_eq(out, outlen, expected, sizeof(expected))) {
        OPENSSL_free(out);
        return 0;
    }

    OPENSSL_free(out);
    return 1;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_TSAPI_Version);
    ADD_TEST(test_TSAPI_RandBytes);
#ifndef OPENSSL_NO_SM2
    ADD_TEST(test_TSAPI_SM2Keygen);
    ADD_TEST(test_TSAPI_SM2Sign);
    ADD_TEST(test_TSAPI_SM2Verify);
    ADD_TEST(test_TSAPI_SM2Encrypt);
    ADD_TEST(test_TSAPI_SM2Decrypt);
#endif
#ifndef OPENSSL_NO_SM4
    ADD_TEST(test_TSAPI_SM4Encrypt);
    ADD_TEST(test_TSAPI_SM4Decrypt);
#endif
#ifndef OPENSSL_NO_SM3
    ADD_TEST(test_TSAPI_SM3);
#endif

    return 1;
}
