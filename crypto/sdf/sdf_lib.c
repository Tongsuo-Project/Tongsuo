/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */


// OK
#include <openssl/crypto.h>
#include <openssl/types.h>
#include <openssl/sdf.h>
#include "internal/thread_once.h"
#include "internal/dso.h"
#include "internal/sdf.h"
#include "sdf_local.h"
#include <string.h>
// #define DEBUG
// #ifdef DEBUG
//     #define debug_printf(...) printf(__VA_ARGS__)
// #else
//     #define debug_printf(...)
// #endif


#ifdef SDF_LIB
# ifdef SDF_LIB_SHARED
static DSO *sdf_dso = NULL;
# else
    # include "sdf_sym_weak.h"
# endif

static CRYPTO_ONCE sdf_lib_once = CRYPTO_ONCE_STATIC_INIT;
static SDF_METHOD sdfm;
static int tag = 0;

DEFINE_RUN_ONCE_STATIC(ossl_sdf_lib_init)
{
# ifdef SDF_LIB_SHARED
#  ifndef LIBSDF
// #   define LIBSDF "sdf"
#  define LIBSDF "swsds"
#  endif

    sdf_dso = DSO_load(NULL, LIBSDF, NULL, 0);
    if (sdf_dso != NULL) {
        #include "sdf_bind.h"
        sdf_bind_init(&sdfm, sdf_dso);
        printf("Debug1: This is a debug message.\n");
    }
# else
    printf("Debug: This is a debug message.\n");
# endif
    return 1;
}
#endif

void ossl_sdf_lib_cleanup(void)
{
#ifdef SDF_LIB_SHARED
    DSO_free(sdf_dso);
    sdf_dso = NULL;
#endif
}

static const SDF_METHOD *sdf_get_method(void)
{
    const SDF_METHOD *meth = &ts_sdf_meth;

#ifdef SDF_LIB
    if (tag == 0)
    {
        sdf_dso = DSO_load(NULL, LIBSDF, NULL, 0);
        if (sdf_dso != NULL) {
            #include "sdf_bind.h"
            sdf_bind_init(&sdfm, sdf_dso);

            printf("Debug1: This is a debug message.\n");
        }
        tag = 1;
    }

    // if (RUN_ONCE(&sdf_lib_once, ossl_sdf_lib_init))
    // {
    //     meth = &sdfm;
    //      printf("==========DEBUG2========\n");

    // }
    meth = &sdfm;

#endif
    return meth;
}

/*
 * 数据结构转换函数
 */
static void sdf_to_ossl_eccref_publickey(const ECCrefPublicKey *sdf_pub,
                                         OSSL_ECCrefPublicKey *ossl_pub)
{
    if (sdf_pub == NULL || ossl_pub == NULL)return;
    ossl_pub->bits = sdf_pub->bits;
    memcpy(ossl_pub->x, sdf_pub->x, ECCref_MAX_LEN);
    memcpy(ossl_pub->y, sdf_pub->y, ECCref_MAX_LEN);
}

static void sdf_to_ossl_ecc_signature(const ECCSignature *sdf_sig,
                                      OSSL_ECCSignature *ossl_sig)
{
    if (sdf_sig == NULL || ossl_sig == NULL)return;
    memcpy(ossl_sig->r, sdf_sig->r, ECCref_MAX_LEN);
    memcpy(ossl_sig->s, sdf_sig->s, ECCref_MAX_LEN);
}

static void sdf_to_ossl_ecc_cipher(const ECCCipher *sdf_c, OSSL_ECCCipher *ossl_c)
{
if (sdf_c == NULL || ossl_c == NULL) {
        return -1;
    }

    memcpy(ossl_c->x, sdf_c->x, ECCref_MAX_LEN);
    memcpy(ossl_c->y, sdf_c->y, ECCref_MAX_LEN);
    memcpy(ossl_c->M, sdf_c->M, sizeof(sdf_c->M));
    
    ossl_c->L = sdf_c->L;
    
    if (ossl_c->L > sizeof(ossl_c->C)) {
        fprintf(stderr, "ossl_c->C space is insufficient, need %d, have %zu\n", 
                ossl_c->L, sizeof(ossl_c->C));
        return -1;
    }
    
    memcpy(ossl_c->C, sdf_c->C, sdf_c->L);
    
    return 0;
}


static void sdf_to_ossl_rsa_pub(const RSArefPublicKey *sdf_rsa,
                                OSSL_RSArefPublicKey *ossl_rsa)
{
    if (sdf_rsa == NULL || ossl_rsa == NULL)return;
    ossl_rsa->bits = sdf_rsa->bits;
    memcpy(ossl_rsa->m, sdf_rsa->m, RSAref_MAX_LEN);
    memcpy(ossl_rsa->e, sdf_rsa->e, RSAref_MAX_LEN);
}



/* =============================================================
 * 设备管理类 (8)
 * ============================================================= */
int TSAPI_SDF_OpenDevice(void **phDeviceHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->OpenDevice == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->OpenDevice(phDeviceHandle);
}

int TSAPI_SDF_CloseDevice(void *hDeviceHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (hDeviceHandle == NULL)
        return OSSL_SDR_OK;
    if (meth == NULL || meth->CloseDevice == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->CloseDevice(hDeviceHandle);
}

int TSAPI_SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->OpenSession == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->OpenSession(hDeviceHandle, phSessionHandle);
}

int TSAPI_SDF_CloseSession(void *hSessionHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (hSessionHandle == NULL)
        return OSSL_SDR_OK;
    if (meth == NULL || meth->CloseSession == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->CloseSession(hSessionHandle);
}

int TSAPI_SDF_GetDeviceInfo(void *hDeviceHandle, DEVICEINFO *pstDeviceInfo)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->GetDeviceInfo == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->GetDeviceInfo(hDeviceHandle, pstDeviceInfo);
}

int TSAPI_SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
                             unsigned char *pucRandom)
{
#define MAX_RANDOM_LEN 2048
    unsigned int len;
    int ret;
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->GenerateRandom == NULL)
        return OSSL_SDR_NOTSUPPORT;
    while (uiLength > 0) {
        len = uiLength > MAX_RANDOM_LEN ? MAX_RANDOM_LEN : uiLength;
        ret = meth->GenerateRandom(hSessionHandle, len, pucRandom);
        if (ret != OSSL_SDR_OK)
            return ret;
        uiLength -= len;
        pucRandom += len;
    }
    return OSSL_SDR_OK;
}

int TSAPI_SDF_GetPrivateKeyAccessRight(void *hSessionHandle,
                                       unsigned int uiKeyIndex,
                                       unsigned char *pucPassword,
                                       unsigned int uiPwdLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->GetPrivateKeyAccessRight == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex,
                                          (char *)pucPassword, uiPwdLength);
}

int TSAPI_SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,
                                           unsigned int uiKeyIndex)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ReleasePrivateKeyAccessRight == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ReleasePrivateKeyAccessRight(hSessionHandle, uiKeyIndex);
}

/* =============================================================
 * 密钥管理类 (16)
 * ============================================================= */
int TSAPI_SDF_ExportSignPublicKey_RSA(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_RSArefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();
    RSArefPublicKey raw;
    if (meth == NULL || meth->ExportSignPublicKey_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->ExportSignPublicKey_RSA(hSessionHandle, uiKeyIndex, &raw);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_rsa_pub(&raw, pucPublicKey);
    return ret;
}

int TSAPI_SDF_ExportEncPublicKey_RSA(void *hSessionHandle,
                                     unsigned int uiKeyIndex,
                                     OSSL_RSArefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();
    RSArefPublicKey raw;
    if (meth == NULL || meth->ExportEncPublicKey_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->ExportEncPublicKey_RSA(hSessionHandle, uiKeyIndex, &raw);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_rsa_pub(&raw, pucPublicKey);
    return ret;
}
int TSAPI_SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits,
                                  OSSL_RSArefPublicKey *pucPublicKey,
                                  OSSL_RSArefPrivateKey *pucPrivateKey)
{
    const SDF_METHOD *meth = sdf_get_method();
    RSArefPublicKey raw_pub; RSArefPrivateKey raw_pri;
    if (meth == NULL || meth->GenerateKeyPair_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->GenerateKeyPair_RSA(uiKeyBits, &raw_pub, &raw_pri);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_rsa_pub(&raw_pub, pucPublicKey);
        memcpy(pucPrivateKey, &raw_pri, sizeof(RSArefPrivateKey)); /* 简单复制 */
    }
    return ret;
}
int TSAPI_SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      unsigned int uiKeyBits,
                                      unsigned char *pucKey,
                                      unsigned int *puiKeyLength,
                                      void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->GenerateKeyWithIPK_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->GenerateKeyWithIPK_RSA(hSessionHandle, uiKeyIndex, uiKeyBits,
                                        pucKey, puiKeyLength, phKeyHandle);
}

int TSAPI_SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle,
                                      unsigned int uiKeyBits,
                                      OSSL_RSArefPublicKey *pucPublicKey,
                                      unsigned char *pubKcy,
                                      unsigned int *puiKeyLength,
                                      void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    RSArefPublicKey raw;
    if (meth == NULL || meth->GenerateKeyWithEPK_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;

    int ret = meth->GenerateKeyWithEPK_RSA(hSessionHandle, uiKeyBits,
                                           (RSArefPublicKey *)pucPublicKey,
                                           pubKcy, puiKeyLength, phKeyHandle);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_rsa_pub(&raw, pucPublicKey);
    }
    return ret;
}

int TSAPI_SDF_ImportKeyWithISK_RSA(void *hSessionHandle,
                                   unsigned int uiISKIndex,
                                   unsigned char *pucKey,
                                   unsigned int PuiKeyLength,
                                   void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ImportKeyWithISK_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ImportKeyWithISK_RSA(hSessionHandle, uiISKIndex, pucKey,
                                      PuiKeyLength, phKeyHandle);
}

int TSAPI_SDF_ExportSignPublicKey_ECC(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_ECCrefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw;
    if (meth == NULL || meth->ExportSignPublicKey_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, &raw);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_eccref_publickey(&raw, pucPublicKey);
    return ret;
}

int TSAPI_SDF_ExportEncPublicKey_ECC(void *hSessionHandle,
                                     unsigned int uiKeyIndex,
                                     OSSL_ECCrefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw;
    if (meth == NULL || meth->ExportEncPublicKey_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->ExportEncPublicKey_ECC(hSessionHandle, uiKeyIndex, &raw);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_eccref_publickey(&raw, pucPublicKey);
    return ret;
}
int TSAPI_SDF_GenerateKeyPair_ECC(unsigned int uiAlgID,
                                  unsigned int uiKeyBits,
                                  OSSL_ECCrefPublicKey *pucPublicKey,
                                  OSSL_ECCrefPrivateKey *pucPrivateKey)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_pub; ECCrefPrivateKey raw_pri;
    if (meth == NULL || meth->GenerateKeyPair_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->GenerateKeyPair_ECC(uiAlgID, uiKeyBits, &raw_pub, &raw_pri);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_eccref_publickey(&raw_pub, pucPublicKey);
        memcpy(pucPrivateKey, &raw_pri, sizeof(ECCrefPrivateKey));
    }
    return ret;
}
int TSAPI_SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle,
                                      unsigned int uiIPKIndex,
                                      unsigned int uiKeyBits,
                                      OSSL_ECCCipher *pucKey,
                                      void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCCipher raw;
    if (meth == NULL || meth->GenerateKeyWithIPK_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->GenerateKeyWithIPK_ECC(hSessionHandle, uiIPKIndex,
                                           uiKeyBits, &raw, phKeyHandle);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_ecc_cipher(&raw, pucKey);
    return ret;
}

int TSAPI_SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle,
                                      unsigned int uiKeyBits,
                                      unsigned int uiAlgID,
                                      OSSL_ECCrefPublicKey *pucPublicKey,
                                      OSSL_ECCCipher *pucKey,
                                      void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_pub;
    ECCCipher raw_key;
    if (meth == NULL || meth->GenerateKeyWithEPK_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    /* 传入公钥 (可写) 与输出密钥 */
    int ret = meth->GenerateKeyWithEPK_ECC(hSessionHandle, uiKeyBits, uiAlgID,
                                           (ECCrefPublicKey *)pucPublicKey,
                                           &raw_key, phKeyHandle);
    if (ret == OSSL_SDR_OK) {
        memcpy(&raw_pub, pucPublicKey, sizeof(ECCrefPublicKey));
        sdf_to_ossl_eccref_publickey(&raw_pub, pucPublicKey);
        sdf_to_ossl_ecc_cipher(&raw_key, pucKey);
    }
    return ret;
}

int TSAPI_SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
                                   unsigned int uiISKIndex,
                                   OSSL_ECCCipher *pucKey,
                                   void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCCipher raw;
    if (meth == NULL || meth->ImportKeyWithISK_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->ImportKeyWithISK_ECC(hSessionHandle, uiISKIndex, &raw,
                                         phKeyHandle);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_ecc_cipher(&raw, pucKey);
    return ret;
}

int TSAPI_SDF_GenerateAgreementDataWithECC(void *hSessionHandle,
                                           unsigned int uiISKIndex,
                                           unsigned int uiKeyBits,
                                           unsigned char *pucSponsorID,
                                           unsigned int uiSponsorIDLength,
                                           OSSL_ECCrefPublicKey *pucSponsorPublicKey,
                                           OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
                                           void **phAgreementHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_pub, raw_tmp;
    if (meth == NULL || meth->GenerateAgreementDataWithECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->GenerateAgreementDataWithECC(hSessionHandle, uiISKIndex,
                                                 uiKeyBits, pucSponsorID,
                                                 uiSponsorIDLength, &raw_pub,
                                                 &raw_tmp, phAgreementHandle);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_eccref_publickey(&raw_pub, pucSponsorPublicKey);
        sdf_to_ossl_eccref_publickey(&raw_tmp, pucSponsorTmpPublicKey);
    }
    return ret;
}

int TSAPI_SDF_GenerateKeyWithECC(void *hSessionHandle,
                                 unsigned char *pucResponseID,
                                 unsigned int uiResponseIDLength,
                                 OSSL_ECCrefPublicKey *pucResponsePublicKey,
                                 OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
                                 void *hAgreementHandle,
                                 void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_pub, raw_tmp;
    if (meth == NULL || meth->GenerateKeyWithECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->GenerateKeyWithECC(hSessionHandle, pucResponseID,
                                       uiResponseIDLength, &raw_pub, &raw_tmp,
                                       hAgreementHandle, phKeyHandle);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_eccref_publickey(&raw_pub, pucResponsePublicKey);
        sdf_to_ossl_eccref_publickey(&raw_tmp, pucResponseTmpPublicKey);
    }
    return ret;
}

int TSAPI_SDF_GenerateAgreementDataAndKeyWithECC(
    void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_S_pub, raw_S_tmp, raw_R_pub, raw_R_tmp;
    if (meth == NULL || meth->GenerateAgreementDataAndKeyWithECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->GenerateAgreementDataAndKeyWithECC(
        hSessionHandle, uiISKIndex, uiKeyBits, pucResponseID,
        uiResponseIDLength, pucSponsorID, uiSponsorIDLength, &raw_S_pub,
        &raw_S_tmp, &raw_R_pub, &raw_R_tmp, phKeyHandle);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_eccref_publickey(&raw_S_pub, pucSponsorPublicKey);
        sdf_to_ossl_eccref_publickey(&raw_S_tmp, pucSponsorTmpPublicKey);
        sdf_to_ossl_eccref_publickey(&raw_R_pub, pucResponsePublicKey);
        sdf_to_ossl_eccref_publickey(&raw_R_tmp, pucResponseTmpPublicKey);
    }
    return ret;
}

int TSAPI_SDF_GenerateKeyWithKEK(void *hSessionHandle,
                                  unsigned int uiKeyBits,
                                  unsigned int uiAlgID,
                                  unsigned int uiKEKIndex,
                                  unsigned char *pucKey,
                                  unsigned int *puiKeyLength,
                                  void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->GenerateKeyWithKEK == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->GenerateKeyWithKEK(hSessionHandle, uiKeyBits, uiAlgID,
                                    uiKEKIndex, pucKey, puiKeyLength,
                                    phKeyHandle);
}

int TSAPI_SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
                               unsigned int uiKEKIndex, unsigned char *pucKey,
                               unsigned int uiKeyLength, void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ImportKeyWithKEK == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ImportKeyWithKEK(hSessionHandle, uiAlgID, uiKEKIndex, pucKey,
                                  uiKeyLength, phKeyHandle);
}

int TSAPI_SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->DestroyKey == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->DestroyKey(hSessionHandle, hKeyHandle);
}

/* =============================================================
 * 数字信封交换（旧标准保留, 2023 标准删除）
 * ============================================================= */
int TSAPI_SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle,
                                             unsigned int uiKeyIndex,
                                             OSSL_RSArefPublicKey *pucPublicKey,
                                             unsigned char *pucDEInput,
                                             unsigned int uiDELength,
                                             unsigned char *pucDEOutput,
                                             unsigned int *puiDELength)
{
    const SDF_METHOD *meth = sdf_get_method();
    RSArefPublicKey raw_pub;
    if (meth == NULL || meth->ExchangeDigitEnvelopeBaseOnRSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw_pub, pucPublicKey, sizeof(RSArefPublicKey));
    int ret = meth->ExchangeDigitEnvelopeBaseOnRSA(hSessionHandle, uiKeyIndex,
                                                   &raw_pub, pucDEInput,
                                                   uiDELength, pucDEOutput,
                                                   puiDELength);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_rsa_pub(&raw_pub, pucPublicKey);
    return ret;
}

int TSAPI_SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle,
                                             unsigned int uiKeyIndex,
                                             unsigned int uiAlgID,
                                             OSSL_ECCrefPublicKey *pucPublicKey,
                                             OSSL_ECCCipher *pucEncDataIn,
                                             OSSL_ECCCipher *pucEncDataOut)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_pub; ECCCipher raw_in; ECCCipher raw_out;
    if (meth == NULL || meth->ExchangeDigitEnvelopeBaseOnECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw_pub, pucPublicKey, sizeof(ECCrefPublicKey));
    if (pucEncDataIn)
        memcpy(&raw_in, pucEncDataIn, sizeof(ECCCipher));
    int ret = meth->ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, uiKeyIndex,
                                                   uiAlgID, &raw_pub,
                                                   pucEncDataIn ? &raw_in : NULL,
                                                   &raw_out);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_eccref_publickey(&raw_pub, pucPublicKey);
        if (pucEncDataOut)
            sdf_to_ossl_ecc_cipher(&raw_out, pucEncDataOut);
    }
    return ret;
}

/* =============================================================
 * 非对称运算类 (7)
 * ============================================================= */
int TSAPI_SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle,
                                             OSSL_RSArefPublicKey *pucPublicKey,
                                             unsigned char *pucDataInput,
                                             unsigned int uiInputLength,
                                             unsigned char *pucDataOutput,
                                             unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    RSArefPublicKey raw;
    if (meth == NULL || meth->ExternalPublicKeyOperation_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw, pucPublicKey, sizeof(RSArefPublicKey));
    int ret = meth->ExternalPublicKeyOperation_RSA(hSessionHandle, &raw,
                                                   pucDataInput, uiInputLength,
                                                   pucDataOutput,
                                                   puiOutputLength);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_rsa_pub(&raw, pucPublicKey);
    return ret;
}
int TSAPI_SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle,
                                             unsigned int uiKeyIndex,
                                             unsigned char *pucDataInput,
                                             unsigned int uiInputLength,
                                             unsigned char *pucDataOutput,
                                             unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->InternalPublicKeyOperation_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->InternalPublicKeyOperation_RSA(hSessionHandle, uiKeyIndex,
                                                pucDataInput, uiInputLength,
                                                pucDataOutput,
                                                puiOutputLength);
}

int TSAPI_SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle,
                                              unsigned int uiKeyIndex,
                                              unsigned char *pucDataInput,
                                              unsigned int uiInputLength,
                                              unsigned char *pucDataOutput,
                                              unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->InternalPrivateKeyOperation_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->InternalPrivateKeyOperation_RSA(hSessionHandle, uiKeyIndex,
                                                 pucDataInput, uiInputLength,
                                                 pucDataOutput,
                                                 puiOutputLength);
}

int TSAPI_SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID,
                                 OSSL_ECCrefPublicKey *pucPublicKey,
                                 unsigned char *pucDataInput,
                                 unsigned int uiInputLength,
                                 OSSL_ECCSignature *pucSignature)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_pub; ECCSignature raw_sig;
    if (meth == NULL || meth->ExternalVerify_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw_pub, pucPublicKey, sizeof(ECCrefPublicKey));
    int ret = meth->ExternalVerify_ECC(hSessionHandle, uiAlgID, &raw_pub,
                                       pucDataInput, uiInputLength, &raw_sig);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_eccref_publickey(&raw_pub, pucPublicKey);
        sdf_to_ossl_ecc_signature(&raw_sig, pucSignature);
    }
    return ret;
}

int TSAPI_SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                               unsigned char *pucData,
                               unsigned int uiDataLength,
                               OSSL_ECCSignature *pucSignature)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCSignature raw_sig;
    if (meth == NULL || meth->InternalSign_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->InternalSign_ECC(hSessionHandle, uiISKIndex, pucData,
                                     uiDataLength, &raw_sig);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_ecc_signature(&raw_sig, pucSignature);
    return ret;
}

int TSAPI_SDF_InternalVerify_ECC(void *hSessionHandle,
                                 unsigned int uiISKIndex,
                                 unsigned char *pucData,
                                 unsigned int uiDataLength,
                                 OSSL_ECCSignature *pucSignature)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCSignature raw_sig;
    if (meth == NULL || meth->InternalVerify_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw_sig, pucSignature, sizeof(ECCSignature));
    return meth->InternalVerify_ECC(hSessionHandle, uiISKIndex, pucData,
                                    uiDataLength, &raw_sig);
}

int TSAPI_SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID,
                                  OSSL_ECCrefPublicKey *pucPublicKey,
                                  unsigned char *pucData,
                                  unsigned int uiDataLength,
                                  OSSL_ECCCipher *pucEncData)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_pub; ECCCipher raw_cipher;
    if (meth == NULL || meth->ExternalEncrypt_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw_pub, pucPublicKey, sizeof(ECCrefPublicKey));
    int ret = meth->ExternalEncrypt_ECC(hSessionHandle, uiAlgID, &raw_pub,
                                        pucData, uiDataLength, &raw_cipher);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_eccref_publickey(&raw_pub, pucPublicKey);
        sdf_to_ossl_ecc_cipher(&raw_cipher, pucEncData);
    }
    return ret;
}

/* =============================================================
 * 对称算法运算类 (20)
 * ============================================================= */
int TSAPI_SDF_Encrypt(void *hSessionHandle, void *hKeyHandle,
                      unsigned int uiAlgID, unsigned char *pucIV,
                      unsigned char *pucData, unsigned int uiDataLength,
                      unsigned char *pucEncData,
                      unsigned int *puiEncDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->Encrypt == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->Encrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData,
                         uiDataLength, pucEncData, puiEncDataLength);
}

int TSAPI_SDF_Decrypt(void *hSessionHandle, void *hKeyHandle,
                      unsigned int uiAlgID, unsigned char *pucIV,
                      unsigned char *pucEncData, unsigned int uiEncDataLength,
                      unsigned char *pucData, unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->Decrypt == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->Decrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                         pucEncData, uiEncDataLength, pucData, puiDataLength);
}

int TSAPI_SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
                           unsigned int uiAlgID, unsigned char *pucIV,
                           unsigned char *pucData, unsigned int uiDataLength,
                           unsigned char *pucMac, unsigned int *puiMacLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->CalculateMAC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->CalculateMAC(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                              pucData, uiDataLength, pucMac, puiMacLength);
}

#if defined(SDF_VERSION_2023)
int TSAPI_SDF_AuthEnc(void *hSessionHandle, void *hKeyHandle,
                      unsigned int uiAlgID, unsigned char *pucStartVar,
                      unsigned int uiStartVarLength, unsigned char *pucAad,
                      unsigned int uiAadLength, unsigned char *pucData,
                      unsigned int uiDataLength, unsigned char *pucEncData,
                      unsigned int *puiEncDataLength,
                      unsigned char *pucAuthData,
                      unsigned int *puiAuthDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->AuthEnc == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->AuthEnc(hSessionHandle, hKeyHandle, uiAlgID, pucStartVar,
                         uiStartVarLength, pucAad, uiAadLength, pucData,
                         uiDataLength, pucEncData, puiEncDataLength,
                         pucAuthData, puiAuthDataLength);
}

int TSAPI_SDF_AuthDec(void *hSessionHandle, void *hKeyHandle,
                      unsigned int uiAlgID, unsigned char *pucStartVar,
                      unsigned int uiStartVarLength, unsigned char *pucAad,
                      unsigned int uiAadLength, unsigned char *pucAuthData,
                      unsigned int *puiAuthDataLength,
                      unsigned char *pucEncData, unsigned int uiEncDataLength,
                      unsigned char *pucData, unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->AuthDec == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->AuthDec(hSessionHandle, hKeyHandle, uiAlgID, pucStartVar,
                         uiStartVarLength, pucAad, uiAadLength, pucAuthData,
                         puiAuthDataLength, pucEncData, uiEncDataLength,
                         pucData, puiDataLength);
}

int TSAPI_SDF_EncryptInit(void *hSessionHandle, void *hKeyHandle,
                          unsigned int uiAlgID, unsigned char *pucIV,
                          unsigned int uiIVLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->EncryptInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->EncryptInit(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                             uiIVLength);
}

int TSAPI_SDF_EncryptUpdate(void *hSessionHandle, unsigned char *pucData,
                            unsigned int uiDataLength,
                            unsigned char *pucEncData,
                            unsigned int *puiEncDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->EncryptUpdate == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->EncryptUpdate(hSessionHandle, (char *)pucData, uiDataLength,
                               pucEncData, puiEncDataLength);
}

int TSAPI_SDF_EncryptFinal(void *hSessionHandle,
                           unsigned char *pucLastEncData,
                           unsigned int *puiLastEncDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->EncryptFinal == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->EncryptFinal(hSessionHandle, pucLastEncData,
                              puiLastEncDataLength);
}

int TSAPI_SDF_DecryptInit(void *hSessionHandle, void *hKeyHandle,
                          unsigned int uiAlgID, unsigned char *pucIV,
                          unsigned int uiIVLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->DecryptInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->DecryptInit(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                             uiIVLength);
}

int TSAPI_SDF_DecryptUpdate(void *hSessionHandle, unsigned char *pucEncData,
                            unsigned int uiEncDataLength,
                            unsigned char *pucData,
                            unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->DecryptUpdate == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->DecryptUpdate(hSessionHandle, (char *)pucEncData,
                               uiEncDataLength, pucData, puiDataLength);
}

int TSAPI_SDF_DecryptFinal(void *hSessionHandle, unsigned char *pucLastData,
                           unsigned int *puiLastDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->DecryptFinal == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->DecryptFinal(hSessionHandle, pucLastData, puiLastDataLength);
}

int TSAPI_SDF_CalculateMACInit(void *hSessionHandle, void *hKeyHandle,
                               unsigned int uiAlgID, unsigned char *pucIV,
                               unsigned int uiIVLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->CalculateMACInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->CalculateMACInit(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                                  uiIVLength);
}

int TSAPI_SDF_CalculateMACUpdate(void *hSessionHandle,
                                 unsigned char *pucData,
                                 unsigned int uiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->CalculateMACUpdate == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->CalculateMACUpdate(hSessionHandle, pucData, uiDataLength);
}

int TSAPI_SDF_CalculateMACFinal(void *hSessionHandle, unsigned char *pucMac,
                                unsigned int *puiMacLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->CalculateMACFinal == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->CalculateMACFinal(hSessionHandle, pucMac, puiMacLength);
}

int TSAPI_SDF_AuthEncInit(void *hSessionHandle, void *hKeyHandle,
                          unsigned int uiAlgID, unsigned char *pucStartVar,
                          unsigned int uiStartVarLength,
                          unsigned char *pucAad, unsigned int uiAadLength,
                          unsigned int uiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->AuthEncInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->AuthEncInit(hSessionHandle, hKeyHandle, uiAlgID, pucStartVar,
                             uiStartVarLength, pucAad, uiAadLength,
                             uiDataLength);
}

int TSAPI_SDF_AuthEncUpdate(void *hSessionHandle, unsigned char *pucData,
                            unsigned int uiDataLength,
                            unsigned char *pucEncData,
                            unsigned int *puiEncDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->AuthEncUpdate == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->AuthEncUpdate(hSessionHandle, pucData, uiDataLength,
                               pucEncData, puiEncDataLength);
}

int TSAPI_SDF_AuthEncFinal(void *hSessionHandle, unsigned char *pucLastEncData,
                           unsigned int *puiLastEncDataLength,
                           unsigned char *pucAuthData,
                           unsigned int *puiAuthDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->AuthEncFinal == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->AuthEncFinal(hSessionHandle, pucLastEncData,
                              puiLastEncDataLength, pucAuthData,
                              puiAuthDataLength);
}

int TSAPI_SDF_AuthDecInit(void *hSessionHandle, void *hKeyHandle,
                          unsigned int uiAlgID, unsigned char *pucStartVar,
                          unsigned int uiStartVarLength,
                          unsigned char *pucAad, unsigned int uiAadLength,
                          unsigned char *pucAuthData,
                          unsigned int uiAuthDataLength,
                          unsigned int uiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->AuthDecInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->AuthDecInit(hSessionHandle, hKeyHandle, uiAlgID, pucStartVar,
                             uiStartVarLength, pucAad, uiAadLength,
                             pucAuthData, uiAuthDataLength, uiDataLength);
}

int TSAPI_SDF_AuthDecUpdate(void *hSessionHandle, unsigned char *pucEncData,
                            unsigned int uiEncDataLength,
                            unsigned char *pucData,
                            unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->AuthDecUpdate == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->AuthDecUpdate(hSessionHandle, pucEncData, uiEncDataLength,
                               pucData, puiDataLength);
}

int TSAPI_SDF_AuthDecFinal(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puiLastDataLength) {
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->AuthDecFinal == NULL) {
        return OSSL_SDR_NOTSUPPORT;
    }
    return meth->AuthDecFinal(hSessionHandle, pucLastData, puiLastDataLength);
}

#endif
/* =============================================================
 * 杂凑运算类 (6)
 * ============================================================= */
#if defined(SDF_VERSION_2023)

int TSAPI_SDF_HMACInit(void *hSessionHandle, void *hKeyHandle,
                       unsigned int uiAlgID)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->HMACInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->HMACInit(hSessionHandle, hKeyHandle, uiAlgID);
}

int TSAPI_SDF_HMACUpdate(void *hSessionHandle, unsigned char *pucData,
                         unsigned int uiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->HMACUpdate == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->HMACUpdate(hSessionHandle, (char *)pucData, uiDataLength);
}

int TSAPI_SDF_HMACFinal(void *hSessionHandle, unsigned char *pucHMac,
                        unsigned int *puiMacLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->HMACFinal == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->HMACFinal(hSessionHandle, (char *)pucHMac, puiMacLength);
}

#endif 

int TSAPI_SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID,
                       OSSL_ECCrefPublicKey *pucPublicKey, unsigned char *pucID,
                       unsigned int uiIDLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw;
    if (meth == NULL || meth->HashInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    if (pucPublicKey != NULL) {
        memcpy(&raw, pucPublicKey, sizeof(ECCrefPublicKey));
        return meth->HashInit(hSessionHandle, uiAlgID, &raw, (char *)pucID,
                              uiIDLength);
    }
    return meth->HashInit(hSessionHandle, uiAlgID, NULL, (char *)pucID,
                          uiIDLength);
}

int TSAPI_SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData,
                         unsigned int uiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->HashUpdate == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->HashUpdate(hSessionHandle, (char *)pucData, uiDataLength);
}

int TSAPI_SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash,
                        unsigned int *puiHashLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->HashFinal == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->HashFinal(hSessionHandle, (char *)pucHash, puiHashLength);
}

/* =============================================================
 * 用户文件操作类 (4)
 * ============================================================= */
int TSAPI_SDF_CreateFile(void *hSessionHandle, unsigned char *pucFileName,
                         unsigned int uiNameLen, unsigned int uiFileSize)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->CreateFile == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->CreateFile(hSessionHandle, (char *)pucFileName, uiNameLen,
                            uiFileSize);
}

int TSAPI_SDF_ReadFile(void *hSessionHandle, unsigned char *pucFileName,
                       unsigned int uiNameLen, unsigned int uiOffset,
                       unsigned int *puiFileLength,
                       unsigned char *pucBuffer)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ReadFile == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ReadFile(hSessionHandle, (char *)pucFileName, uiNameLen,
                          uiOffset, puiFileLength, pucBuffer);
}

int TSAPI_SDF_WriteFile(void *hSessionHandle, unsigned char *pucFileName,
                        unsigned int uiNameLen, unsigned int uiOffset,
                        unsigned int uiFileLength, unsigned char *pucBuffer)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->WriteFile == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->WriteFile(hSessionHandle, (char *)pucFileName, uiNameLen,
                           uiOffset, uiFileLength, (char *)pucBuffer);
}

int TSAPI_SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName,
                         unsigned int uiNameLen)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->DeleteFile == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->DeleteFile(hSessionHandle, (char *)pucFileName, uiNameLen);
}

/* =============================================================
 * 验证调试类 (12)
 * ============================================================= */
#if defined(SDF_VERSION_2023)
int TSAPI_SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits,
                                  OSSL_RSArefPublicKey *pucPublicKey,
                                  OSSL_RSArefPrivateKey *pucPrivateKey)
{
    const SDF_METHOD *meth = sdf_get_method();
    RSArefPublicKey raw_pub; RSArefPrivateKey raw_pri;
    if (meth == NULL || meth->GenerateKeyPair_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->GenerateKeyPair_RSA(uiKeyBits, &raw_pub, &raw_pri);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_rsa_pub(&raw_pub, pucPublicKey);
        memcpy(pucPrivateKey, &raw_pri, sizeof(RSArefPrivateKey)); /* 简单复制 */
    }
    return ret;
}

int TSAPI_SDF_GenerateKeyPair_ECC(unsigned int uiAlgID,
                                  unsigned int uiKeyBits,
                                  OSSL_ECCrefPublicKey *pucPublicKey,
                                  OSSL_ECCrefPrivateKey *pucPrivateKey)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPublicKey raw_pub; ECCrefPrivateKey raw_pri;
    if (meth == NULL || meth->GenerateKeyPair_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->GenerateKeyPair_ECC(uiAlgID, uiKeyBits, &raw_pub, &raw_pri);
    if (ret == OSSL_SDR_OK) {
        sdf_to_ossl_eccref_publickey(&raw_pub, pucPublicKey);
        memcpy(pucPrivateKey, &raw_pri, sizeof(ECCrefPrivateKey));
    }
    return ret;
}

int TSAPI_SDF_ExternalPrivateKeyOperation_RSA(
    OSSL_RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ExternalPrivateKeyOperation_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ExternalPrivateKeyOperation_RSA(
        (RSArefPrivateKey *)pucPrivateKey, pucDataInput, uiInputLength,
        pucDataOutput, puiOutputLength);
}

int TSAPI_SDF_ExternalSign_ECC(unsigned int uiAlgID,
                               OSSL_ECCrefPrivateKey *pucPrivateKey,
                               unsigned char *pucDataInput,
                               unsigned int uiInputLength,
                               OSSL_ECCSignature *pucSignature)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCSignature raw_sig; ECCrefPrivateKey raw_pri;
    if (meth == NULL || meth->ExternalSign_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw_pri, pucPrivateKey, sizeof(ECCrefPrivateKey));
    int ret = meth->ExternalSign_ECC(uiAlgID, &raw_pri, pucDataInput,
                                     uiInputLength, &raw_sig);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_ecc_signature(&raw_sig, pucSignature);
    return ret;
}

int TSAPI_SDF_ExternalDecrypt_ECC(unsigned int uiAlgID,
                                  OSSL_ECCrefPrivateKey *pucPrivateKey,
                                  OSSL_ECCCipher *pucEncData,
                                  unsigned char *pucData,
                                  unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCrefPrivateKey raw_pri; ECCCipher raw_cipher;
    if (meth == NULL || meth->ExternalDecrypt_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw_pri, pucPrivateKey, sizeof(ECCrefPrivateKey));
    memcpy(&raw_cipher, pucEncData, sizeof(ECCCipher));
    return meth->ExternalDecrypt_ECC(uiAlgID, &raw_pri, &raw_cipher, pucData,
                                     puiDataLength);
}

/* SM9 / 外部 Key 接口也仅 2023 标准可用，已在上面整体条件编译包裹。
 * 若需要在此处分离，可再添加宏，但当前实现保持最小改动。 */
// - **SDF_ExternalSign_SM9**
//   外部私钥SM9签名
// - **SDF_ExternalDecrypt_SM9**
//   外部私钥SM9解密
//

int TSAPI_SDF_ExternalKeyEncrypt(unsigned int uiAlgID, unsigned char *pucKey,
                                 unsigned int uiKeyLength,
                                 unsigned char *pucIV,
                                 unsigned int uiIVLength,
                                 unsigned char *pucData,
                                 unsigned int uiDataLength,
                                 unsigned char *pucEncData,
                                 unsigned int *puiEncDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ExternalKeyEncrypt == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ExternalKeyEncrypt(uiAlgID, pucKey, uiKeyLength, pucIV,
                                    uiIVLength, pucData, uiDataLength,
                                    pucEncData, puiEncDataLength);
}

int TSAPI_SDF_ExternalKeyDecrypt(unsigned int uiAlgID, unsigned char *pucKey,
                                 unsigned int uiKeyLength,
                                 unsigned char *pucIV,
                                 unsigned int uiIVLength,
                                 unsigned char *pucEncData,
                                 unsigned int uiEncDataLength,
                                 unsigned char *pucData,
                                 unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ExternalKeyDecrypt == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ExternalKeyDecrypt(uiAlgID, pucKey, uiKeyLength, pucIV,
                                    uiIVLength, pucEncData, uiEncDataLength,
                                    pucData, puiDataLength);
}

int TSAPI_SDF_ExternalKeyEncryptInit(void *hSessionHandle,
                                     unsigned int uiAlgID,
                                     unsigned char *pucKey,
                                     unsigned int uiKeyLength,
                                     unsigned char *pucIV,
                                     unsigned int uiIVLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ExternalKeyEncryptInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ExternalKeyEncryptInit(hSessionHandle, uiAlgID, pucKey,
                                        uiKeyLength, pucIV, uiIVLength);
}

int TSAPI_SDF_ExternalKeyDecryptInit(void *hSessionHandle,
                                     unsigned int uiAlgID,
                                     unsigned char *pucKey,
                                     unsigned int uiKeyLength,
                                     unsigned char *pucIV,
                                     unsigned int uiIVLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ExternalKeyDecryptInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ExternalKeyDecryptInit(hSessionHandle, uiAlgID, pucKey,
                                        uiKeyLength, pucIV, uiIVLength);
}

int TSAPI_SDF_ExternalKeyHMACInit(void *hSessionHandle, unsigned int uiAlgID,
                                  unsigned char *pucKey,
                                  unsigned int uiKeyLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->ExternalKeyHMACInit == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->ExternalKeyHMACInit(hSessionHandle, uiAlgID, pucKey,
                                     uiKeyLength);
}
#endif








/* =============================================================
 * 扩展 API
 * ============================================================= */
int TSAPI_SDF_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek,
                          uint32_t len, void **pkey_handle)
{
    const SDF_METHOD *meth = sdf_get_method();
    if (meth == NULL || meth->GenerateKey == NULL)
        return OSSL_SDR_NOTSUPPORT;
    return meth->GenerateKey(hSessionHandle, type, no_kek, len, pkey_handle);
}

int TSAPI_SDF_InternalEncrypt_ECC(void *hSessionHandle,
                                  unsigned int uiISKIndex,
                                  unsigned char *pucData,
                                  unsigned int uiDataLength,
                                  OSSL_ECCCipher *pucEncData)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCCipher raw;
    if (meth == NULL || meth->InternalEncrypt_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    int ret = meth->InternalEncrypt_ECC(hSessionHandle, uiISKIndex, pucData,
                                        uiDataLength, &raw);
    if (ret == OSSL_SDR_OK)
        sdf_to_ossl_ecc_cipher(&raw, pucEncData);
    return ret;
}

int TSAPI_SDF_InternalDecrypt_ECC(void *hSessionHandle,
                                  unsigned int uiISKIndex,
                                  OSSL_ECCCipher *pucEncData,
                                  unsigned char *pucData,
                                  unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();
    ECCCipher raw;
    if (meth == NULL || meth->InternalDecrypt_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;
    memcpy(&raw, pucEncData, sizeof(ECCCipher));
    return meth->InternalDecrypt_ECC(hSessionHandle, uiISKIndex, &raw, pucData,
                                     puiDataLength);
}



