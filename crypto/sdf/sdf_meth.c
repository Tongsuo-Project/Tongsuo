/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/types.h>
#include <openssl/sdf.h>
#include "sdf_local.h"

static int x_OpenDevice(void **phDeviceHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_CloseDevice(void *hDeviceHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_OpenSession(void *hDeviceHandle, void **phSessionHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_CloseSession(void *hSessionHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
                            unsigned char *pucRandom)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GetPrivateKeyAccessRight(void *hSessionHandle,
                                        unsigned int uiKeyIndex,
                                        unsigned char *pucPassword,
                                        unsigned int uiPwdLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ReleasePrivateKeyAccessRight(void *hSessionHandlek,
                                            unsigned int uiKeyIndex)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ImportKeyWithISK_ECC(void *hSessionHandle,
                                    unsigned int uiISKIndex,
                                    OSSL_ECCCipher *pucKey,
                                    void **phKeyHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}


static int x_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
                                unsigned int uiKEKIndex, unsigned char *pucKey,
                                unsigned int puiKeyLength, void **phKeyHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ExportSignPublicKey_ECC(void *hSessionHandle,
                                     unsigned int uiKeyIndex,
                                     OSSL_ECCrefPublicKey *pucPublicKey)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ExportEncPublicKey_ECC(void *hSessionHandle,
                                     unsigned int uiKeyIndex,
                                     OSSL_ECCrefPublicKey *pucPublicKey)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_DestroyKey(void *hSessionHandle, void *hKeyHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalEncrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  unsigned char *pucData,
                                  unsigned int uiDataLength,
                                  OSSL_ECCCipher *pucEncData)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  OSSL_ECCCipher *pucEncData,
                                  unsigned char *pucData,
                                  unsigned int *puiDataLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                              unsigned char * pucData,
                              unsigned int uiDataLength,
                              OSSL_ECCSignature *pucSignature)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_Encrypt(void *hSessionHandle, void *hKeyHandle,
                       unsigned int uiAlgID, unsigned char *pucIV,
                       unsigned char *pucData,
                       unsigned int uiDataLength,
                       unsigned char *pucEncData,
                       unsigned int *puiEncDataLength)
{
    return OSSL_SDR_NOTSUPPORT;
}
    
static int x_Decrypt(void *hSessionHandle, void *hKeyHandle,
                       unsigned int uiAlgID, unsigned char *pucIV,
                       unsigned char *pucEncData, unsigned int uiEncDataLength,
                       unsigned char *pucData,
                       unsigned int *puiDataLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
                            unsigned int uiAlgID, unsigned char *pucIV,
                            unsigned char *pucData, unsigned int uiDataLength,
                            unsigned char *pucMac, unsigned int *puiMACLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek,
                            uint32_t len, void **pkey_handle)
{
    return OSSL_SDR_NOTSUPPORT;
}

SDF_METHOD ts_sdf_meth = {
    x_OpenDevice,
    x_CloseDevice,
    x_OpenSession,
    x_CloseSession,
    x_GenerateRandom,
    x_GetPrivateKeyAccessRight,
    x_ReleasePrivateKeyAccessRight,
    x_ImportKeyWithISK_ECC,
    x_ImportKeyWithKEK,
    x_ExportSignPublicKey_ECC,
    x_ExportEncPublicKey_ECC,
    x_DestroyKey,
    x_InternalEncrypt_ECC,
    x_InternalDecrypt_ECC,
    x_InternalSign_ECC,
    x_Encrypt,
    x_Decrypt,
    x_CalculateMAC,

    /* SDF Ext API */
    x_GenerateKey,
};
