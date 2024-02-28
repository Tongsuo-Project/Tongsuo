/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OPENSSL_SDF_H
# define OPENSSL_SDF_H
# pragma once

# include <stdint.h>
# include <openssl/evp.h>

# ifdef __cplusplus
extern "C" {
# endif

/* SDF error codes from GM/T 0018-2012 Appendix A */
# define OSSL_SDR_OK                         0
# define OSSL_SDR_BASE                       0x01000000
# define OSSL_SDR_UNKNOWNERR                 (OSSL_SDR_BASE + 1)
# define OSSL_SDR_NOTSUPPORT                 (OSSL_SDR_BASE + 2)
# define OSSL_SDR_COMMFAIL                   (OSSL_SDR_BASE + 3)
# define OSSL_SDR_HARDFAIL                   (OSSL_SDR_BASE + 4)
# define OSSL_SDR_OPENDEVICE                 (OSSL_SDR_BASE + 5)
# define OSSL_SDR_OPENSESSION                (OSSL_SDR_BASE + 6)
# define OSSL_SDR_PARDENY                    (OSSL_SDR_BASE + 7)
# define OSSL_SDR_KEYNOTEXIST                (OSSL_SDR_BASE + 8)
# define OSSL_SDR_ALGNOTSUPPORT              (OSSL_SDR_BASE + 9)
# define OSSL_SDR_ALGMODNOTSUPPORT           (OSSL_SDR_BASE + 10)
# define OSSL_SDR_PKOPERR                    (OSSL_SDR_BASE + 11)
# define OSSL_SDR_SKOPERR                    (OSSL_SDR_BASE + 12)
# define OSSL_SDR_SIGNERR                    (OSSL_SDR_BASE + 13)
# define OSSL_SDR_VERIFYERR                  (OSSL_SDR_BASE + 14)
# define OSSL_SDR_SYMOPERR                   (OSSL_SDR_BASE + 15)
# define OSSL_SDR_STEPERR                    (OSSL_SDR_BASE + 16)
# define OSSL_SDR_FILESIZEERR                (OSSL_SDR_BASE + 17)
# define OSSL_SDR_FILENOTEXIST               (OSSL_SDR_BASE + 18)
# define OSSL_SDR_FILEOFSERR                 (OSSL_SDR_BASE + 19)
# define OSSL_SDR_KEYTYPEERR                 (OSSL_SDR_BASE + 20)
# define OSSL_SDR_KEYERR                     (OSSL_SDR_BASE + 21)
# define OSSL_SDR_ENCDATAERR                 (OSSL_SDR_BASE + 22)
# define OSSL_SDR_RANDERR                    (OSSL_SDR_BASE + 23)
# define OSSL_SDR_PRKRERR                    (OSSL_SDR_BASE + 24)
# define OSSL_SDR_MACERR                     (OSSL_SDR_BASE + 25)
# define OSSL_SDR_FILEEXISTS                 (OSSL_SDR_BASE + 26)
# define OSSL_SDR_FILEWERR                   (OSSL_SDR_BASE + 27)
# define OSSL_SDR_NOBUFFER                   (OSSL_SDR_BASE + 28)
# define OSSL_SDR_INARGERR                   (OSSL_SDR_BASE + 29)
# define OSSL_SDR_OUTARGERR                  (OSSL_SDR_BASE + 30)

#define OSSL_SDFE_ASYM_KEY_TYPE_SM2         (0xa0)
#define OSSL_SDFE_SYM_KEY_TYPE_SM4          (0xb0)

typedef struct OSSL_ECCCipher_st OSSL_ECCCipher;
typedef struct OSSL_ECCSignature_st OSSL_ECCSignature;
typedef struct OSSL_ECCrefPrivateKey_st OSSL_ECCrefPrivateKey;
typedef struct OSSL_ECCrefPublicKey_st OSSL_ECCrefPublicKey;
int TSAPI_SDF_OpenDevice(void **phDeviceHandle);
int TSAPI_SDF_CloseDevice(void *hDeviceHandle);
int TSAPI_SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
int TSAPI_SDF_CloseSession(void *hSessionHandle);
int TSAPI_SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
                             unsigned char *pucRandom);
int TSAPI_SDF_GetPrivateKeyAccessRight(void *hSessionHandle,
                                       unsigned int uiKeyIndex,
                                       unsigned char *pucPassword,
                                       unsigned int uiPwdLength);
int TSAPI_SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,
                                           unsigned int uiKeyIndex);               
int TSAPI_SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
                                   unsigned int uiISKIndex,
                                   OSSL_ECCCipher *pucKey,
                                   void **phKeyHandle);
int TSAPI_SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
    unsigned int uiKEKIndex, unsigned char *pucKey, unsigned int puiKeyLength,
    void **phKeyHandle);
int TSAPI_SDF_ExportSignPublicKey_ECC(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_ECCrefPublicKey *pucPublicKey);
int TSAPI_SDF_ExportEncPublicKey_ECC(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_ECCrefPublicKey *pucPublicKey);
int TSAPI_SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle);
int TSAPI_SDF_InternalEncrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  unsigned char *pucData,
                                  unsigned int uiDataLength,
                                  OSSL_ECCCipher *pucEncData);
int TSAPI_SDF_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  OSSL_ECCCipher *pucEncData,
                                  unsigned char *pucData,
                                  unsigned int *puiDataLength);
int TSAPI_SDF_Encrypt(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucEncData,
    unsigned int *puiEncDataLength);
int TSAPI_SDF_Decrypt(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
    unsigned int uiEncDataLength, unsigned char *pucData,
    unsigned int *puiDataLength);
int TSAPI_SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucMac,
    unsigned int *puiMACLength);
int TSAPI_SDF_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek,
    uint32_t len, void **pkey_handle);
int TSAPI_SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                               unsigned char *pucData,
                               unsigned int uiDataLength,
                               OSSL_ECCSignature *pucSignature);

# ifdef __cplusplus
}
# endif
#endif /* OPENSSL_SDF_H */
