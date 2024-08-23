/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"
#include <string.h>
#include <openssl/tsapi.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sdf.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sgd.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include "internal/e_os.h"
#include "crypto/rand.h"
#include "crypto/sm2.h"
#include "../sdf/sdf_local.h"
#ifdef SDF_LIB
# include "sdfe_api.h"
#endif

unsigned char *TSAPI_GetEntropy(int entropy, size_t *outlen)
{
    unsigned char *out = NULL;
    size_t len;

    len = ossl_rand_get_entropy(NULL, &out, entropy, entropy, entropy * 4);
    if (len == 0) {
        *outlen = 0;
        return NULL;
    }

    *outlen = len;
    return out;
}

void TSAPI_FreeEntropy(unsigned char *ent, size_t len)
{
    ossl_rand_cleanup_entropy(NULL, ent, len);
}

unsigned char *TSAPI_RandBytes(size_t len)
{
    unsigned char *buf = OPENSSL_malloc(len);

    if (buf == NULL)
        return NULL;

    if (RAND_bytes(buf, (int)len) <= 0) {
        OPENSSL_free(buf);
        return NULL;
    }

    return buf;
}

char *TSAPI_Version(void)
{
    int ret;
    int buflen = 1 + strlen(OpenSSL_version(TONGSUO_VERSION)) + 1
#ifdef SMTC_MODULE
                 + strlen(OpenSSL_version(TONGSUO_SMTC_INFO)) + 1
#endif
                 ;
    char *buf = OPENSSL_malloc(buflen);

    ret = BIO_snprintf((char *)buf, buflen, "%s\n",
                            OpenSSL_version(TONGSUO_VERSION));
    if (ret < 0) {
        OPENSSL_free(buf);
        return NULL;
    }

#ifdef SMTC_MODULE
    ret = BIO_snprintf(buf + ret, buflen - ret, "%s\n",
                       OpenSSL_version(TONGSUO_SMTC_INFO));
    if (ret < 0) {
        OPENSSL_free(buf);
        return NULL;
    }
#endif

    return buf;
}

#ifndef OPENSSL_NO_SM2
int TSAPI_DelSm2KeyWithIndex(int index, int sign, const char *user,
                             const char *password)
{
    int ok = 0;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;

    if (sign) {
        area = SDFE_ASYM_KEY_AREA_SIGN;
    } else {
        area = SDFE_ASYM_KEY_AREA_ENC;
    }

    memset(&login_arg, 0, sizeof(login_arg));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name))
            return 0;

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK)
        goto end;

    if (SDFE_DelECCKey(hSessionHandle, area, index)
            != OSSL_SDR_OK)
        goto end;

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

int TSAPI_GenerateSM2KeyWithIndex(int index, int sign, const char *user,
                                  const char *password)
{
    int ok = 0;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name))
            return 0;

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK)
        goto end;

    if (SDFE_GenECCKey(hSessionHandle, area, index, 0, NULL) != OSSL_SDR_OK)
        goto end;

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

EVP_PKEY *TSAPI_EVP_PKEY_new_from_ECCrefKey(const OSSL_ECCrefPublicKey *pubkey,
                                            const OSSL_ECCrefPrivateKey *privkey)
{
    int ok = 0;
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int bytes;

    if (pubkey == NULL)
        return NULL;

    eckey = EC_KEY_new();
    if (eckey == NULL)
        return NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)
        goto end;

    if (!EC_KEY_set_group(eckey, group))
        goto end;

    bytes = (pubkey->bits + 7) / 8;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto end;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);

    if (BN_bin2bn(pubkey->x + sizeof(pubkey->x) - bytes, bytes, x) == NULL)
        goto end;

    if (BN_bin2bn(pubkey->y + sizeof(pubkey->y) - bytes, bytes, y) == NULL)
        goto end;

    if (!EC_KEY_set_public_key_affine_coordinates(eckey, x, y))
        goto end;

    if (privkey) {
        bytes = (privkey->bits + 7) / 8;
        if (BN_bin2bn(privkey->K + sizeof(privkey->K) - bytes, bytes, x) == NULL)
            goto end;

        if (!EC_KEY_set_private_key(eckey, x))
            goto end;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto end;

    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
        goto end;

    eckey = NULL;

    ok = 1;
end:
    if (!ok) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    EC_KEY_free(eckey);
    return pkey;
}

OSSL_ECCrefPublicKey *TSAPI_EVP_PKEY_get_ECCrefPublicKey(const EVP_PKEY *pkey)
{
    int ok = 0;
    const EC_KEY *eckey = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BN_CTX *ctx = NULL;
    OSSL_ECCrefPublicKey *outkey = NULL;

    if (pkey == NULL)
        return NULL;

    eckey = EVP_PKEY_get0_EC_KEY(pkey);
    if (eckey == NULL)
        return NULL;

    group = EC_KEY_get0_group(eckey);
    point = EC_KEY_get0_public_key(eckey);
    if (group == NULL || point == NULL)
        return NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        return NULL;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto end;

    if (!EC_POINT_get_affine_coordinates(group, point, x, y, ctx))
        goto end;

    outkey = OPENSSL_zalloc(sizeof(*outkey));
    if (outkey == NULL)
        goto end;

    outkey->bits = EVP_PKEY_get_bits(pkey);

    if (BN_bn2bin(x, outkey->x + sizeof(outkey->x) - BN_num_bytes(x)) < 0)
        goto end;
    if (BN_bn2bin(y, outkey->y + sizeof(outkey->y) - BN_num_bytes(y)) < 0)
        goto end;

    ok = 1;
end:
    if (!ok) {
        OPENSSL_free(outkey);
        outkey = NULL;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return outkey;
}

OSSL_ECCrefPrivateKey *TSAPI_EVP_PKEY_get_ECCrefPrivateKey(const EVP_PKEY *pkey)
{
    int ok = 0;
    const EC_KEY *eckey = NULL;
    const BIGNUM *priv = NULL;
    OSSL_ECCrefPrivateKey *outkey = NULL;

    if (pkey == NULL)
        return NULL;

    eckey = EVP_PKEY_get0_EC_KEY(pkey);
    if (eckey == NULL)
        return NULL;

    priv = EC_KEY_get0_private_key(eckey);
    if (priv == NULL)
        return NULL;

    outkey = OPENSSL_zalloc(sizeof(*outkey));
    if (outkey == NULL)
        goto end;

    outkey->bits = EVP_PKEY_get_bits(pkey);

    if (BN_bn2bin(priv, outkey->K + sizeof(outkey->K) - BN_num_bytes(priv)) < 0)
        goto end;

    ok = 1;
end:
    if (!ok) {
        OPENSSL_free(outkey);
        outkey = NULL;
    }
    return outkey;
}

int TSAPI_ImportSM2Key(int index, int sign, const char *user,
                       const char *password, const EVP_PKEY *sm2_pkey)
{
    int ok = 0;
#ifdef SDF_LIB
    int area;
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCrefPrivateKey *privkey = NULL;
    OSSL_ECCrefPublicKey *pubkey = NULL;
    sdfe_asym_key_ecc_t sm2_key;
    sdfe_login_arg_t login_arg;

    memset(&login_arg, 0, sizeof(login_arg));
    memset(&sm2_key, 0, sizeof(sm2_key));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name))
            return 0;

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK)
        goto end;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    privkey = TSAPI_EVP_PKEY_get_ECCrefPrivateKey(sm2_pkey);
    if (privkey == NULL)
        goto end;

    pubkey = TSAPI_EVP_PKEY_get_ECCrefPublicKey(sm2_pkey);
    if (pubkey == NULL)
        goto end;

    sm2_key.area = area;
    sm2_key.index = index;
    sm2_key.type = SDFE_ASYM_KEY_TYPE_SM2;
    sm2_key.privkey_bits = 256;
    sm2_key.privkey_len = sm2_key.privkey_bits >> 3;
    sm2_key.pubkey_bits = 256;
    sm2_key.pubkey_len = (sm2_key.pubkey_bits >> 3) << 1;

    memcpy(sm2_key.pubkey, pubkey, sizeof(*pubkey));
    memcpy(sm2_key.privkey, privkey, sizeof(*privkey));

    if (SDFE_ImportECCKey(hSessionHandle, &sm2_key, NULL)
            != OSSL_SDR_OK)
        goto end;

    ok = 1;
end:
    OPENSSL_free(privkey);
    OPENSSL_free(pubkey);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

int TSAPI_ImportSM2KeyWithEvlp(int index, int sign, const char *user,
                               const char *password, unsigned char *key,
                               size_t keylen, unsigned char *dek, size_t deklen)
{
    int ok = 0;
#ifdef SDF_LIB
    int area;
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_asym_key_ecc_t sm2_key;
    sdfe_sym_key_evlp_t sym_key_evlp;
    sdfe_login_arg_t login_arg;

    memset(&login_arg, 0, sizeof(login_arg));
    memset(&sm2_key, 0, sizeof(sm2_key));
    memset(&sym_key_evlp, 0, sizeof(sym_key_evlp));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name))
            return 0;

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK)
        goto end;

    sym_key_evlp.flags = SDFE_SYM_KEY_EVLP_F_IMPORT_KEY_INDEX_VALID;
    sym_key_evlp.asym_key_type = SDFE_ASYM_KEY_TYPE_SM2;
    sym_key_evlp.sym_key_type = SDFE_SYM_KEY_TYPE_SM4;
    sym_key_evlp.sym_key_len = 16;
    sym_key_evlp.asym_key_index = 0;

    if (deklen > sizeof(sym_key_evlp.data))
        goto end;
    sym_key_evlp.data_len = deklen;
    memcpy(sym_key_evlp.data, dek, deklen);

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    sm2_key.area = area;
    sm2_key.index = index;
    sm2_key.type = SDFE_ASYM_KEY_TYPE_SM2;
    sm2_key.privkey_bits = 256;
    sm2_key.privkey_len = sm2_key.privkey_bits >> 3;
    sm2_key.pubkey_bits = 256;
    sm2_key.pubkey_len = (sm2_key.pubkey_bits >> 3) << 1;

    if (keylen != sizeof(sm2_key.privkey) + sizeof(sm2_key.pubkey))
        goto end;
    
    memcpy(sm2_key.pubkey, key, sizeof(sm2_key.pubkey));
    memcpy(sm2_key.privkey, key + sizeof(sm2_key.pubkey),
                sizeof(sm2_key.privkey));

    if (SDFE_ImportECCKeyWithEvlp(hSessionHandle, &sm2_key, &sym_key_evlp, NULL)
            != OSSL_SDR_OK)
        goto end;

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

int TSAPI_ExportSM2KeyWithEvlp(int index, int sign, const char *user,
                               const char *password, EVP_PKEY *sm2_pkey,
                               unsigned char **priv, size_t *privlen,
                               unsigned char **pub, size_t *publen,
                               unsigned char **outevlp, size_t *outevlplen)

{
    int ok = 0;
#ifdef SDF_LIB
    int area;
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCrefPublicKey *pubkey = NULL;
    sdfe_asym_key_ecc_t sm2_key;
    sdfe_sym_key_evlp_t sym_key_evlp;
    sdfe_login_arg_t login_arg;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));
    memset(&sm2_key, 0, sizeof(sm2_key));
    memset(&sym_key_evlp, 0, sizeof(sym_key_evlp));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name))
            return 0;

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK)
        goto end;

    sm2_key.area = area;
    sm2_key.index = index;
    sm2_key.type = SDFE_ASYM_KEY_TYPE_SM2;

    sym_key_evlp.asym_key_type = SDFE_ASYM_KEY_TYPE_SM2;
    sym_key_evlp.sym_key_type = SDFE_SYM_KEY_TYPE_SM4;
    sym_key_evlp.sym_key_len = 16;

    pubkey = TSAPI_EVP_PKEY_get_ECCrefPublicKey(sm2_pkey);
    if (pubkey == NULL)
        goto end;

    if (SDFE_ExportECCKeyWithEvlp(hSessionHandle, &sm2_key, &sym_key_evlp,
                                  (void *)pubkey) != OSSL_SDR_OK)
        goto end;

    *outevlp = OPENSSL_malloc(sym_key_evlp.data_len);
    if (*outevlp == NULL)
        goto end;

    memcpy(*outevlp, sym_key_evlp.data, sym_key_evlp.data_len);
    *outevlplen = sym_key_evlp.data_len;

    *priv = OPENSSL_malloc(sizeof(sm2_key.privkey));
    if (*priv == NULL)
        goto end;
    
    memcpy(*priv, sm2_key.privkey, sizeof(sm2_key.privkey));
    *privlen = sizeof(sm2_key.privkey);

    *pub = OPENSSL_malloc(sizeof(sm2_key.pubkey));
    if (*pub == NULL)
        goto end;

    memcpy(*pub, sm2_key.pubkey, sizeof(sm2_key.pubkey));
    *publen = sizeof(sm2_key.pubkey);

    ok = 1;
end:
    if (!ok) {
        OPENSSL_free(*priv);
        OPENSSL_free(*pub);
        OPENSSL_free(*outevlp);
        *priv = NULL;
        *pub = NULL;
        *outevlp = NULL;
        *privlen = 0;
        *publen = 0;
        *outevlplen = 0;
    }

    OPENSSL_free(pubkey);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

EVP_PKEY *TSAPI_ExportSM2KeyWithIndex(int index, int sign, const char *user,
                                      const char *password)
{
    EVP_PKEY *pkey = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;
    OSSL_ECCrefPrivateKey privkey;
    OSSL_ECCrefPublicKey pubkey;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name))
            return 0;

        strcpy((char *)login_arg.name, user);
    }

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK)
        goto end;

    if (SDFE_ExportECCPrivKey(hSessionHandle, area, index, 0, NULL,
            (ECCrefPrivateKey *)&privkey) != OSSL_SDR_OK)
        goto end;

    if (sign && TSAPI_SDF_ExportSignPublicKey_ECC(hSessionHandle, index,
            &pubkey) != OSSL_SDR_OK)
        goto end;
    
    if (!sign && TSAPI_SDF_ExportEncPublicKey_ECC(hSessionHandle, index,
            &pubkey) != OSSL_SDR_OK)
        goto end;

    pkey = TSAPI_EVP_PKEY_new_from_ECCrefKey(&pubkey, &privkey);
    if (pkey == NULL)
        goto end;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return pkey;
}

EVP_PKEY *TSAPI_ExportSM2PubKeyWithIndex(int index, int sign)
{
    EVP_PKEY *pkey = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCrefPublicKey pubkey;
    EC_GROUP *group = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int nbytes;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (sign) {
        if (TSAPI_SDF_ExportSignPublicKey_ECC(hSessionHandle, index, &pubkey)
                != OSSL_SDR_OK)
            goto end;
    } else {
        if (TSAPI_SDF_ExportEncPublicKey_ECC(hSessionHandle, index, &pubkey)
                != OSSL_SDR_OK)
            goto end;
    }

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)
        goto end;

    eckey = EC_KEY_new();
    if (eckey == NULL)
        goto end;

    EC_KEY_set_group(eckey, group);

    nbytes = (pubkey.bits + 7) / 8;

    x = BN_bin2bn(pubkey.x + sizeof(pubkey.x) - nbytes, nbytes, NULL);
    if (x == NULL)
        goto end;

    y = BN_bin2bn(pubkey.y + sizeof(pubkey.y) - nbytes, nbytes, NULL);
    if (y == NULL)
        goto end;

    if (!EC_KEY_set_public_key_affine_coordinates(eckey, x, y))
        goto end;

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto end;

    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
        EVP_PKEY_free(pkey);
        goto end;
    }
    eckey = NULL;

end:
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    BN_free(x);
    BN_free(y);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return pkey;
}

int TSAPI_UpdateSm2KeyWithIndex(int index, int sign, const char *user, const char *password)
{
    int ok = 0;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name))
            return 0;

        strcpy((char *)login_arg.name, user);
    }

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK)
        goto end;

    if (SDFE_DelECCKey(hSessionHandle, area, index)
            != OSSL_SDR_OK)
        goto end;

    if (SDFE_GenECCKey(hSessionHandle, area, index, 0, NULL)
            != OSSL_SDR_OK)
        goto end;

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

EVP_PKEY *TSAPI_SM2Keygen(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
}

# ifndef OPENSSL_NO_SM3
int TSAPI_SM2Verify(EVP_PKEY *key, const unsigned char *tbs, size_t tbslen,
                    const unsigned char *sig, size_t siglen)
{
    int ok = 0;
    EVP_MD_CTX *ctx = NULL;

    if (key == NULL || tbs == NULL || sig == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;

    if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, key)
        || EVP_DigestVerify(ctx, sig, siglen, tbs, tbslen) <= 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        goto end;
    }

    ok = 1;
end:
    EVP_MD_CTX_free(ctx);
    return ok;
}

unsigned char *TSAPI_SM2Sign(EVP_PKEY *key, const unsigned char *tbs,
                             size_t tbslen, size_t *siglen)
{
    unsigned char *sig = NULL;
    size_t len;
    EVP_MD_CTX *ctx = NULL;

    if (key == NULL || tbs == NULL || siglen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return NULL;

    if (!EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, key)
        || !EVP_DigestSign(ctx, NULL, &len, tbs, tbslen)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        goto end;
    }

    sig = OPENSSL_malloc(len);
    if (sig == NULL)
        goto end;

    if (!EVP_DigestSign(ctx, sig, &len, tbs, tbslen)) {
        OPENSSL_free(sig);
        *siglen = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        goto end;
    }

    *siglen = len;
end:
    EVP_MD_CTX_free(ctx);
    return sig;
}
# endif

static unsigned char *do_SM2Crypt(int enc, EVP_PKEY *key,
                                  const unsigned char *in, size_t inlen,
                                  size_t *outlen)
{
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = 0;
    unsigned char *out = NULL;

    if (key == NULL || in == NULL || outlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (enc) {
        ctx = EVP_PKEY_CTX_new_from_pkey_provided(NULL, key, NULL);
    } else {
        ctx = EVP_PKEY_CTX_new(key, NULL);
    }

    if (ctx == NULL)
        return NULL;

    if (enc) {
        if (EVP_PKEY_encrypt_init(ctx) <= 0
            || EVP_PKEY_encrypt(ctx, NULL, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            goto end;
        }
    } else {
        if (EVP_PKEY_decrypt_init(ctx) <= 0
            || EVP_PKEY_decrypt(ctx, NULL, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            goto end;
        }
    }

    out = OPENSSL_malloc(len);
    if (out == NULL)
        goto end;

    if (enc) {
        if (EVP_PKEY_encrypt(ctx, out, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            OPENSSL_free(out);
            out = NULL;
            len = 0;
        }
    } else {
        if (EVP_PKEY_decrypt(ctx, out, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            OPENSSL_free(out);
            out = NULL;
            len = 0;
        }
    }

    *outlen = len;
end:
    EVP_PKEY_CTX_free(ctx);
    return out;
}

unsigned char *TSAPI_SM2DecryptWithISK(int isk, const unsigned char *in,
                                       size_t inlen, size_t *outlen)
{
    unsigned char *out = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCCipher *ecc = NULL;
    unsigned int len;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        return NULL;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    if (TSAPI_SDF_GetPrivateKeyAccessRight(hSessionHandle, isk, NULL, 0)
            != OSSL_SDR_OK)
        goto end;

    ecc = TSAPI_SM2Ciphertext_to_ECCCipher(in, inlen);
    if (ecc == NULL)
        goto end;

    len = ecc->L;
    out = OPENSSL_malloc(len);
    if (out == NULL)
        goto end;

    if (TSAPI_SDF_InternalDecrypt_ECC(hSessionHandle, isk, ecc, out, &len)
            != OSSL_SDR_OK) {
        OPENSSL_free(out);
        out = NULL;
        *outlen = 0;
        goto end;
    }

    *outlen = len;
end:
    OPENSSL_free(ecc);
    TSAPI_SDF_ReleasePrivateKeyAccessRight(hSessionHandle, isk);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return out;
}

unsigned char *TSAPI_SM2EncryptWithISK(int isk, const unsigned char *in,
                                       size_t inlen, size_t *outlen)
{
    unsigned char *out = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCCipher *ecc = NULL;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
        return NULL;

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
        goto end;

    ecc = OPENSSL_zalloc(sizeof(OSSL_ECCCipher) + inlen);
    if (ecc == NULL)
        goto end;

    if (TSAPI_SDF_InternalEncrypt_ECC(hSessionHandle, isk, (unsigned char *)in,
                                      inlen, ecc)
            != OSSL_SDR_OK)
        goto end;

    out = TSAPI_ECCCipher_to_SM2Ciphertext(ecc, outlen);

end:
    OPENSSL_free(ecc);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return out;
}

unsigned char *TSAPI_SM2Encrypt(EVP_PKEY *key, const unsigned char *in,
                                size_t inlen, size_t *outlen)
{
    return do_SM2Crypt(1, key, in, inlen, outlen);
}

unsigned char *TSAPI_SM2Decrypt(EVP_PKEY *key, const unsigned char *in,
                                size_t inlen, size_t *outlen)
{
    return do_SM2Crypt(0, key, in, inlen, outlen);
}

unsigned char *TSAPI_ECCCipher_to_SM2Ciphertext(const OSSL_ECCCipher *ecc,
                                                size_t *ciphertext_len)
{
    BIGNUM *x = NULL, *y = NULL;
    unsigned char *out = NULL;

    if (ecc == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if ((x = BN_bin2bn(ecc->x, sizeof(ecc->x), NULL)) == NULL
        || (y = BN_bin2bn(ecc->y, sizeof(ecc->y), NULL)) == NULL)
        goto end;

    out = ossl_sm2_ciphertext_encode(x, y, ecc->C, ecc->L, ecc->M,
                                     sizeof(ecc->M), ciphertext_len);
end:
    BN_free(x);
    BN_free(y);
    return out;

}

OSSL_ECCCipher *TSAPI_SM2Ciphertext_to_ECCCipher(const unsigned char *ciphertext,
                                                 size_t ciphertext_len)
{
    int ok = 0;
    EC_POINT *C1 = NULL;
    uint8_t *C2_data = NULL, *C3_data = NULL;
    size_t C2_len, C3_len;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *Cx = NULL, *Cy = NULL;
    OSSL_ECCCipher *ecc = NULL;

    if (ciphertext == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!ossl_sm2_ciphertext_decode(ciphertext, ciphertext_len, &C1, &C2_data,
                                    &C2_len, &C3_data, &C3_len))
        goto end;

    ecc = OPENSSL_zalloc(sizeof(OSSL_ECCCipher) + C2_len);
    if (ecc == NULL)
        goto end;

    if (C3_len != sizeof(ecc->M))
        goto end;

    memcpy(ecc->M, C3_data, C3_len);
    ecc->L = C2_len;
    memcpy(ecc->C, C2_data, C2_len);

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)
        goto end;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto end;

    BN_CTX_start(ctx);
    Cx = BN_CTX_get(ctx);
    Cy = BN_CTX_get(ctx);
    if (Cy == NULL)
        goto end;

    if (!EC_POINT_get_affine_coordinates(group, C1, Cx, Cy, NULL))
        goto end;

    if (BN_bn2bin(Cx, ecc->x + sizeof(ecc->x) - BN_num_bytes(Cx))
            != BN_num_bytes(Cx)
        || BN_bn2bin(Cy, ecc->y + sizeof(ecc->y) - BN_num_bytes(Cy))
            != BN_num_bytes(Cy))
        goto end;

    ok = 1;
end:
    if (!ok) {
        OPENSSL_free(ecc);
        ecc = NULL;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(C1);
    OPENSSL_free(C2_data);
    OPENSSL_free(C3_data);
    return ecc;

}
#endif

#ifndef OPENSSL_NO_SM4
static unsigned char *do_SM4Crypt(int mode, int enc,
                                  const unsigned char *key,
                                  size_t keylen, int isk,
                                  const unsigned char *iv,
                                  const unsigned char *in, size_t inlen,
                                  size_t *outlen)
{
# ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    void *hkeyHandle = NULL;
    OSSL_ECCCipher *ecc = NULL;
# endif
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *outbuf = NULL;
    unsigned int len = 0;
    int lenf = 0;
    size_t max_out_len;

    if (isk < 0) {
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL)
            return 0;

        if (mode == OSSL_SGD_MODE_ECB)
            cipher = EVP_sm4_ecb();
        else if (mode == OSSL_SGD_MODE_CBC)
            cipher = EVP_sm4_cbc();
        else if (mode == OSSL_SGD_MODE_CFB)
            cipher = EVP_sm4_cfb();
        else if (mode == OSSL_SGD_MODE_OFB)
            cipher = EVP_sm4_ofb();
        else if (mode == OSSL_SGD_MODE_CTR)
            cipher = EVP_sm4_ctr();
        else
            goto end;

        if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc)
            || !EVP_CIPHER_CTX_set_padding(ctx, 0))
            goto end;

        max_out_len = inlen + EVP_CIPHER_CTX_get_block_size(ctx);

        outbuf = OPENSSL_malloc(max_out_len);
        if (outbuf == NULL)
            goto end;

        if (!EVP_CipherUpdate(ctx, outbuf, (int *)&len, in, inlen)) {
            OPENSSL_free(outbuf);
            outbuf = NULL;
            len = 0;
            goto end;
        }

        if (!EVP_CipherFinal_ex(ctx, outbuf + len, &lenf)) {
            OPENSSL_free(outbuf);
            outbuf = NULL;
            len = 0;
            goto end;
        }

        len += lenf;
    }
# ifdef SDF_LIB
    else {

        if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK)
            goto end;

        if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK)
            goto end;

        if (TSAPI_SDF_GetPrivateKeyAccessRight(hSessionHandle, isk, NULL, 0)
                != OSSL_SDR_OK)
            goto end;

        ecc = TSAPI_SM2Ciphertext_to_ECCCipher(key, keylen);
        if (ecc == NULL)
            goto end;

        if (TSAPI_SDF_ImportKeyWithISK_ECC(hSessionHandle, isk, ecc, &hkeyHandle)
                != OSSL_SDR_OK)
            goto end;

        outbuf = (unsigned char *)OPENSSL_malloc(inlen + 128);
        if (outbuf == NULL)
            goto end;

        if (enc) {
            if (TSAPI_SDF_Encrypt(hSessionHandle, hkeyHandle,
                                  OSSL_SGD_SM4 | mode,
                                  (unsigned char *)iv, (unsigned char *)in,
                                  inlen, outbuf, &len) != OSSL_SDR_OK) {
                OPENSSL_free(outbuf);
                outbuf = NULL;
                goto end;
            }
        } else {
            if (TSAPI_SDF_Decrypt(hSessionHandle, hkeyHandle,
                                  OSSL_SGD_SM4 | mode,
                                  (unsigned char *)iv, (unsigned char *)in,
                                  inlen, outbuf, &len) != OSSL_SDR_OK) {
                OPENSSL_free(outbuf);
                outbuf = NULL;
                goto end;
            }
        }
    }
# endif
    *outlen = len;
end:
    EVP_CIPHER_CTX_free(ctx);
# ifdef SDF_LIB
    if (isk >= 0) {
        TSAPI_SDF_DestroyKey(hSessionHandle, hkeyHandle);
        TSAPI_SDF_ReleasePrivateKeyAccessRight(hSessionHandle, isk);
        OPENSSL_free(ecc);
        TSAPI_SDF_CloseSession(hSessionHandle);
        TSAPI_SDF_CloseDevice(hDeviceHandle);
    }
# endif
    return outbuf;
}

unsigned char *TSAPI_SM4Decrypt(int mode, const unsigned char *key,
                                size_t keylen, int isk,
                                const unsigned char *iv,
                                const unsigned char *in, size_t inlen,
                                size_t *outlen)
{
    return do_SM4Crypt(mode, 0, key, keylen, isk, iv, in, inlen, outlen);
}

unsigned char *TSAPI_SM4Encrypt(int mode, const unsigned char *key,
                                size_t keylen, int isk,
                                const unsigned char *iv,
                                const unsigned char *in, size_t inlen,
                                size_t *outlen)
{
    return do_SM4Crypt(mode, 1, key, keylen, isk, iv, in, inlen, outlen);
}
#endif

#ifndef OPENSSL_NO_SM3
unsigned char *TSAPI_SM3(const void *data, size_t datalen, size_t *outlen)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char *out = NULL;
    unsigned int len = 0;

    if (data == NULL || outlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return NULL;

    if (!EVP_DigestInit_ex(ctx, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(ctx, data, datalen)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        goto end;
    }

    out = OPENSSL_malloc(EVP_MD_CTX_get_size(ctx));
    if (out == NULL)
        goto end;

    if (!EVP_DigestFinal_ex(ctx, out, &len)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        OPENSSL_free(out);
        out = NULL;
        len = 0;
    }

    *outlen = len;
end:
    EVP_MD_CTX_free(ctx);
    return out;
}
#endif
