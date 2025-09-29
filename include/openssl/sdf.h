/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OPENSSL_TSAPI_SDF_H
# define OPENSSL_TSAPI_SDF_H
# pragma once

# include <stdint.h>
# include <openssl/evp.h>

# ifdef __cplusplus
 "C" {
# endif

/* TSAPI_SDF error codes from GM/T 0018-2012 Appendix A */
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

#define OSSL_TSAPI_SDFE_ASYM_KEY_TYPE_SM2         (0xa0)
#define OSSL_TSAPI_SDFE_SYM_KEY_TYPE_SM4          (0xb0)


#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7) / 8)

#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)

struct OSSL_RSArefPublicKey_st{
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} ;
struct OSSL_RSArefPrivateKey_st{
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} ;

struct OSSL_ECCrefPublicKey_st{
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ;
 struct OSSL_ECCrefPrivateKey_st
{
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
} ;
 struct OSSL_ECCCipher_st{
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
	unsigned char C[1];
	// Extend sizeof(C) to SM2_MAX_PLAINTEXT_SIZE
	// unsigned char C_[254];
    // unsigned char *C_; 
};
 struct OSSL_ECCSignature_st{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ;

typedef struct OSSL_ECCCipher_st OSSL_ECCCipher;
typedef struct OSSL_ECCSignature_st OSSL_ECCSignature;
typedef struct OSSL_ECCrefPrivateKey_st OSSL_ECCrefPrivateKey;
typedef struct OSSL_ECCrefPublicKey_st OSSL_ECCrefPublicKey;
typedef struct OSSL_RSArefPublicKey_st OSSL_RSArefPublicKey;
typedef struct OSSL_RSArefPrivateKey_st OSSL_RSArefPrivateKey;
// include/openssl/sdf.h
#ifndef DEVICEINFO_DEFINED
#define DEVICEINFO_DEFINED
typedef struct DeviceInfo_st {
    unsigned char IssuerName[40];
    unsigned char SerialNumber[16];
    unsigned char FirmwareVersion[16];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[2];
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DEVICEINFO;
#endif // DEVICEINFO_DEFINED
 int TSAPI_SDF_OpenDevice(void **phDeviceHandle) ;
 int TSAPI_SDF_CloseDevice(void *hDeviceHandle) ;
 int TSAPI_SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) ;
 int TSAPI_SDF_CloseSession(void *hSessionHandle) ;
 int TSAPI_SDF_GetDeviceInfo(void *hDeviceHandle, DEVICEINFO *pstDeviceInfo) ;
 int TSAPI_SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,unsigned char *pucRandom) ;
 int TSAPI_SDF_GetPrivateKeyAccessRight(void *hSessionHandle,unsigned int uiKeyIndex, unsigned char *pucPassword,unsigned int uiPwdLength) ;
 int TSAPI_SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,unsigned int uiKeyIndex) ;
 int TSAPI_SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pubPublicKey) ;
 int TSAPI_SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pubPublicKey) ;
 int TSAPI_SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits, OSSL_RSArefPublicKey *pucPublicKey,OSSL_RSArefPrivateKey *pucPrivateKey) ;
 int TSAPI_SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiKeyBits, unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) ;
 int TSAPI_SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, unsigned int uiKeyBits, OSSL_RSArefPublicKey *pucPublicKey, unsigned char *pubKcy, unsigned int *puiKeyLength, void **phKeyHandle) ;
 int TSAPI_SDF_ImportKeyWithISK_RSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey, unsigned int PuiKeyLength, void **phKeyHandle) ;
 int TSAPI_SDF_ExchangeDigitEnvelopeBaseOnRSA_fn(void *hSessionHandle, unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pucPublicKey, unsigned char *pucDEInput, unsigned int uiDELength, unsigned char *pucDEOutput, unsigned int *puiDELength);
 int TSAPI_SDF_ExportSignPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey);
 int TSAPI_SDF_ExportEncPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey);
 int TSAPI_SDF_GenerateKeyPair_ECC(unsigned int uiAlgID, unsigned int uiKeyBits, OSSL_ECCrefPublicKey *pucPublicKey, OSSL_ECCrefPrivateKey *pucPrivateKey) ;
 int TSAPI_SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle,unsigned int uiIPKIndex, unsigned int uiKeyBits, OSSL_ECCCipher *pucKey,void **phKeyHandle) ;
 int TSAPI_SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle,unsigned int uiKeyBits, unsigned int uiAlgID, OSSL_ECCrefPublicKey *pucPublicKey,OSSL_ECCCipher *pucKey, void **phKeyHandle) ;
 int TSAPI_SDF_ImportKeyWithISK_ECC(void *hSessionHandle,unsigned int uiISKIndex, OSSL_ECCCipher *pucKey,void **phKeyHandle) ;
 int TSAPI_SDF_GenerateAgreementDataWithECC(void *hSessionHandle,unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID,unsigned int uiSponsorIDLength, OSSL_ECCrefPublicKey *pucSponsorPublicKey,OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle) ;
 int TSAPI_SDF_GenerateKeyWithECC(void *hSessionHandle,unsigned char *pucResponseID, unsigned int uiResponseIDLength,OSSL_ECCrefPublicKey *pucResponsePublicKey, OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,void *hAgreementHandle, void **phKeyHandle) ;
 int TSAPI_SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle,unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID,unsigned int uiResponseIDLength, unsigned char *pucSponsorID,unsigned int uiSponsorIDLength, OSSL_ECCrefPublicKey *pucSponsorPublicKey,OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey, OSSL_ECCrefPublicKey *pucResponsePublicKey,OSSL_ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle) ;
 int TSAPI_SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle,unsigned int uiKeyIndex, unsigned int uiAlgID, OSSL_ECCrefPublicKey *pucPublicKey,OSSL_ECCCipher *pucEncDataIn, OSSL_ECCCipher *pucEncDataOut) ;
 int TSAPI_SDF_GenerateKeyWithKEK(void *hSessionHandle,unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,unsigned char *pucKey, unsigned int *puiKeyLength,void **phKeyHandle) ;
 int TSAPI_SDF_ImportKeyWithKEK(void *hSessionHandle,unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,unsigned int puiKeyLength, void **phKeyHandle) ;
 int TSAPI_SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle);

 int TSAPI_SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle,OSSL_RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,unsigned int uiInputLength, unsigned char *pucDataOutput,unsigned int *puiOutputLength) ;
 int TSAPI_SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength) ;
 int TSAPI_SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle,unsigned int uiKeyIndex, unsigned char *pucDataInput,unsigned int uiInputLength, unsigned char *pucDataOutput,unsigned int *puiOutputLength) ;
 int TSAPI_SDF_ExternalVerify_ECC(void *hSessionHandle,unsigned int uiAlgID, OSSL_ECCrefPublicKey *pucPublicKey,unsigned char *pucDataInput, unsigned int uiInputLength,OSSL_ECCSignature *pucSignature) ;
 int TSAPI_SDF_InternalSign_ECC(void *hSessionHandle,unsigned int uiISKIndex, unsigned char *pucData,unsigned int uiDataLength, OSSL_ECCSignature *pucSignature) ;
 int TSAPI_SDF_InternalVerify_ECC(void *hSessionHandle,unsigned int uiISKIndex, unsigned char *pucData,unsigned int uiDataLength, OSSL_ECCSignature *pucSignature) ;
 int TSAPI_SDF_ExternalEncrypt_ECC(void *hSessionHandle,unsigned int uiAlgID, OSSL_ECCrefPublicKey *pucPublicKey,unsigned char *pucData, unsigned int uiDataLength,OSSL_ECCCipher *pucEncData) ;
 int TSAPI_SDF_Encrypt(void *hSessionHandle, void *hKeyHandle,unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,unsigned int uiDataLength, unsigned char *pucEncData,unsigned int *puiEncDataLength) ;
 int TSAPI_SDF_Decrypt(void *hSessionHandle, void *hKeyHandle,unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,unsigned int uiEncDataLength, unsigned char *pucData,unsigned int *puiDataLength) ;
 int TSAPI_SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle,unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,unsigned int uiDataLength, unsigned char *pucMac,unsigned int *puiMACLength) ;

#ifdef TSAPI_SDF_VERSION_2023
 int TSAPI_SDF_AuthEnc(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength) ;
 int TSAPI_SDF_AuthDec(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) ;
 int TSAPI_SDF_EncryptInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength) ;
 int TSAPI_SDF_EncryptUpdate(void *hSessionHandle, char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) ;
 int TSAPI_SDF_EncryptFinal(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength) ;
 int TSAPI_SDF_DecryptInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength) ;
 int TSAPI_SDF_DecryptUpdate(void *hSessionHandle, char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) ;
 int TSAPI_SDF_DecryptFinal(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puiLastDataLength) ;
 int TSAPI_SDF_CalculateMACInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength) ;
 int TSAPI_SDF_CalculateMACUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength) ;
 int TSAPI_SDF_CalculateMACFinal(void *hSessionHandle, unsigned char *pucMac, unsigned int *puiMacLength) ;
 int TSAPI_SDF_AuthEncInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned int uiDataLength) ;
 int TSAPI_SDF_AuthEncUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) ;
 int TSAPI_SDF_AuthEncFinal(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength) ;
 int TSAPI_SDF_AuthDecInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData, unsigned int uiAuthDataLength, unsigned int uiDataLength) ;
 int TSAPI_SDF_AuthDecUpdate(void *hSessionHandle, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) ;
 int TSAPI_SDF_AuthDecFinal(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puLastDataLength) ;
 int TSAPI_SDF_HMACInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID) ;
 int TSAPI_SDF_HMACUpdate(void *hSessionHandle, char *pucData, unsigned int uiDataLength) ;
 int TSAPI_SDF_HMACFinal(void *hSessionHandle, char *pucHMac, unsigned int *puiMacLength) ;
#endif
 int TSAPI_SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID, OSSL_ECCrefPublicKey *pucPublicKey, unsigned char *pucID, unsigned int uiIDLength) ;
 int TSAPI_SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength) ;
 int TSAPI_SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength) ;
 int TSAPI_SDF_CreateFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize) ;
 int TSAPI_SDF_ReadFile(void *hSessionHandle, unsigned char *pucfileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer) ;
 int TSAPI_SDF_WriteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNamelen, unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer) ;
 int TSAPI_SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen) ;

#ifdef TSAPI_SDF_VERSION_2023
 int TSAPI_SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits, OSSL_RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) ;
 int TSAPI_SDF_GenerateKeyPair_ECC(unsigned int uiAlgID, unsigned int uiKeyBits, OSSL_ECCrefPublicKey *pucPublicKey, OSSL_ECCrefPrivateKey *pucPrivateKey) ;
 int TSAPI_SDF_ExternalPrivateKeyOperation_RSA(RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength) ;
 int TSAPI_SDF_ExternalSign_ECC(unsigned int uiAlgID, OSSL_ECCrefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, OSSL_ECCSignature *pucSignature) ;
 int TSAPI_SDF_ExternalDecrypt_ECC(unsigned int uiAlgID, OSSL_ECCrefPrivateKey *pucPrivateKey, OSSL_ECCCipher *pucEncData, unsigned char *pucData, unsigned int *uiDataLength) ;
 int TSAPI_SDF_ExternalSign_SM9(SM9SignMasterPublicKey *pSignMasterPublicKey, SM9SignUserPrivateKey *pSignUserPrivateKey, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pSignature) ;
 int TSAPI_SDF_ExternalDecrypt_SM9(SM9EncUserPrivateKey *pEncUserPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pEncData) ;
 int TSAPI_SDF_ExternalKeyEncrypt(unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) ;
 int TSAPI_SDF_ExternalKeyDecrypt(unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) ;
 int TSAPI_SDF_ExternalKeyEncryptInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength) ;
 int TSAPI_SDF_ExternalKeyDecryptInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength) ;
 int TSAPI_SDF_ExternalKeyHMACInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength) ;
#endif


# ifdef __cplusplus
}
# endif
#endif /* OPENSSL_TSAPI_SDF_H */