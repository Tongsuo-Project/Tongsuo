/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_SDF_LOCAL_H
# define OSSL_CRYPTO_SDF_LOCAL_H

# include <openssl/types.h>
# include <openssl/sdf.h>

# define OSSL_ECCref_MAX_BITS            512
# define OSSL_ECCref_MAX_LEN             ((OSSL_ECCref_MAX_BITS + 7) / 8)

# pragma pack(1)
struct OSSL_ECCrefPrivateKey_st {
    unsigned int bits;
    unsigned char K[OSSL_ECCref_MAX_LEN];
};

struct OSSL_ECCrefPublicKey_st{
    unsigned int bits;
    unsigned char x[OSSL_ECCref_MAX_LEN];
    unsigned char y[OSSL_ECCref_MAX_LEN];
};

struct OSSL_ECCCipher_st {
    unsigned char x[OSSL_ECCref_MAX_LEN];
    unsigned char y[OSSL_ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
    unsigned char C[1];
};

struct OSSL_ECCSignature_st {
    unsigned char r[OSSL_ECCref_MAX_LEN];
    unsigned char s[OSSL_ECCref_MAX_LEN];
};
# pragma pack()

typedef int (*SDF_OpenDevice_fn)(void **phDeviceHandle);
typedef int (*SDF_CloseDevice_fn)(void *hDeviceHandle);
typedef int (*SDF_OpenSession_fn)(void *hDeviceHandle, void **phSessionHandle);
typedef int (*SDF_CloseSession_fn)(void *hSessionHandle);
typedef int (*SDF_GenerateRandom_fn)(void *hSessionHandle,
    unsigned int uiLength, unsigned char *pucRandom);

typedef int (*SDF_GetPrivateKeyAccessRight_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucPassword,
    unsigned int uiPwdLength);

typedef int (*SDF_ReleasePrivateKeyAccessRight_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex);

typedef int (*SDF_ImportKeyWithISK_ECC_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, OSSL_ECCCipher *pucKey, void **phKeyHandle);

typedef int (*SDF_ImportKeyWithKEK_fn)(void *hSessionHandle,
    unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
    unsigned int puiKeyLength, void **phKeyHandle);

typedef int (*SDF_DestroyKey_fn)(void *hSessionHandle, void *hKeyHandle);

typedef int (*SDF_Encrypt_fn)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucEncData,
    unsigned int *puiEncDataLength);

typedef int (*SDF_Decrypt_fn)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
    unsigned int uiEncDataLength, unsigned char *pucData,
    unsigned int *puiDataLength);

typedef int (*SDF_CalculateMAC_fn)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucMac,
    unsigned int *puiMACLength);

typedef int (*SDF_GenerateKey_fn)(void *hSessionHandle, uint8_t type,
    uint8_t no_kek, uint32_t len, void **pkey_handle);

typedef int (*SDF_ExportSignPublicKey_ECC_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey);

typedef int (*SDF_ExportEncPublicKey_ECC_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey);

typedef int (*SDF_InternalEncrypt_ECC_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength,
    OSSL_ECCCipher *pucEncData);
typedef int (*SDF_InternalDecrypt_ECC_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, OSSL_ECCCipher *pucEncData, unsigned char *pucData,
    unsigned int *puiDataLength);

typedef int (*SDF_InternalSign_ECC_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength,
    OSSL_ECCSignature *pucSignature);
/*
 * Returns 0 for success, others for error code
 */
struct sdf_method_st {
    SDF_OpenDevice_fn OpenDevice;
    SDF_CloseDevice_fn CloseDevice;
    SDF_OpenSession_fn OpenSession;
    SDF_CloseSession_fn CloseSession;
    SDF_GenerateRandom_fn GenerateRandom;
    SDF_GetPrivateKeyAccessRight_fn GetPrivateKeyAccessRight;
    SDF_ReleasePrivateKeyAccessRight_fn ReleasePrivateKeyAccessRight;
    SDF_ImportKeyWithISK_ECC_fn ImportKeyWithISK_ECC;
    SDF_ImportKeyWithKEK_fn ImportKeyWithKEK;
    SDF_ExportSignPublicKey_ECC_fn ExportSignPublicKey_ECC;
    SDF_ExportEncPublicKey_ECC_fn ExportEncPublicKey_ECC;
    SDF_DestroyKey_fn DestroyKey;
    SDF_InternalEncrypt_ECC_fn InternalEncrypt_ECC;
    SDF_InternalDecrypt_ECC_fn InternalDecrypt_ECC;
    SDF_InternalSign_ECC_fn InternalSign_ECC;
    SDF_Encrypt_fn Encrypt;
    SDF_Decrypt_fn Decrypt;
    SDF_CalculateMAC_fn CalculateMAC;

    /* SDF Ext API */
    SDF_GenerateKey_fn GenerateKey;
};

extern SDF_METHOD ts_sdf_meth;
#endif
