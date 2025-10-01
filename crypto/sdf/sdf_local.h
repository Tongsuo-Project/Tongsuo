/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */


// OK

#ifndef OSSL_CRYPTO_SDF_LOCAL_H
# define OSSL_CRYPTO_SDF_LOCAL_H


# include <openssl/types.h>
# include <openssl/sdf.h>


# pragma pack(1)
#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7) / 8)

#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)

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
typedef struct RSArefPublicKey_st{
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;
typedef struct RSArefPrivateKey_st{
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

typedef struct ECCrefPublicKey_st{
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;
typedef struct ECCrefPrivateKey_st
{
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;
typedef struct ECCCipher_st{
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
	unsigned char C[1];
	// Extend sizeof(C) to SM2_MAX_PLAINTEXT_SIZE
	// unsigned char C_[254]; 
    // unsigned char *C_;
} ECCCipher;
typedef struct ECCSignature_st{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;
#if defined(SDF_VERSION_2023)

// 2023标准中删除了数字信封相关接口。但是原数据结构仍保留。
typedef struct EnvelopedECCKey_st{
    unsigned int Version;
    unsigned int uiSymmAlgID;
    unsigned int ulBits;
    unsigned char cbEncryptedPriKey[ECCref_MAX_LEN];
    ECCrefPublicKey PubKey;
    ECCCipher ECCCipherBlob;
} EnvelopedECCKey;
#else
typedef struct SDF_ENVELOPEDKEYBLOB{
    unsigned long ulAsymmAlgID;
    unsigned long ulSymmAlgID;
    // ECCCIPHERBLOB ECCCipherBlob;
    // ECCPUBLICKEYBLOB PubKey;
    ECCCipher ECCCipherBlob;
    ECCrefPublicKey PubKey;
    unsigned char cbEncryptedPriKey[64];
} SDF_ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

#endif
#if defined(SDF_VERSION_2023)
#define SM9ref_MAX_BITS 256
#define SM9ref_MAX_LEN ((SM9ref_MAX_BITS + 7) / 8)
typedef struct SM9refMasterPrivateKey_st
{
    unsigned int bits;
    unsigned char s[SM9ref_MAX_LEN];
} SM9MasterPrivateKey;

typedef struct SM9refSignMasterPublicKey_st{
    unsigned int bits;
    unsigned char xa[SM9ref_MAX_LEN];
    unsigned char xb[SM9ref_MAX_LEN];
    unsigned char ya[SM9ref_MAX_LEN];
    unsigned char yb[SM9ref_MAX_LEN];
} SM9SignMasterPublicKey;

typedef struct SM9refEncMasterPublicKey_st{
    unsigned int bits;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9EncMasterPublicKey;

typedef struct  SM9refSignUserPrivateKey_st
{
    unsigned int bits;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
}SM9SignUserPrivateKey;

typedef struct  SM9refEncUserPrivateKey_st
{
    unsigned int bits;
    unsigned char xa[SM9ref_MAX_LEN];
    unsigned char xb[SM9ref_MAX_LEN];
    unsigned char ya[SM9ref_MAX_LEN];
    unsigned char yb[SM9ref_MAX_LEN];
}SM9EncUserPrivateKey;

typedef struct SM9refCipher_st
{
    unsigned int EncType;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
    char h[32];
    unsigned int L;
    unsigned char C[];
}SM9Cipher;
typedef struct SM9refSignature_st{
    unsigned char h[SM9ref_MAX_LEN];
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9Signature;

typedef struct SM9refKeyPackage_st{
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9KeyPackage;
typedef struct SM9refEncEnvelopedKey_st{
    unsigned int version;
    unsigned int ulSymmAlgID;
    unsigned int bits;
    unsigned char encryptedPriKey[SM9ref_MAX_LEN * 4];
    SM9EncMasterPublicKey encMastPubKey;
    SM9EncMasterPublicKey tempMastPubKey;
    unsigned int userIDLen;
    unsigned char userID[256];
    unsigned int keyLen;
    SM9KeyPackage keyPackage;
} SM9EncEnvelopedKey;
#endif

# pragma pack()


    // 设备管理类(8)
    typedef int (*SDF_OpenDevice_fn)(void**);
    typedef int (*SDF_CloseDevice_fn)(void**);
    typedef int (*SDF_OpenSession_fn)(void *hDeviceHandle, void **phSessionHandle);
    typedef int (*SDF_CloseSession_fn)(void *hSessionHandle);
    typedef int (*SDF_GetDeviceInfo_fn)(void *hDeviceHandle, DEVICEINFO *pstDeviceInfo);
    typedef int (*SDF_GenerateRandom_fn)(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom);
    typedef int (*SDF_GetPrivateKeyAccessRight_fn)(void *hSessionHandle, unsigned int uiKeyIndex, char *pucPassword, unsigned int uiPwdLength);
    typedef int (*SDF_ReleasePrivateKeyAccessRight_fn)(void *hSessionHandle, unsigned int uiKeyIndex);


    // 密钥管理类(20)=>(16)
    typedef int (*SDF_ExportSignPublicKey_RSA_fn)(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pubPublicKey);
    typedef int (*SDF_ExportEncPublicKey_RSA_fn)(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pubPublicKey);
    typedef int (*SDF_GenerateKeyPair_RSA_fn)(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey); // Moved in 2023
    typedef int (*SDF_GenerateKeyWithIPK_RSA_fn)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiKeyBits, unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
    typedef int (*SDF_GenerateKeyWithEPK_RSA_fn)(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, unsigned char *pubKcy, unsigned int *puiKeyLength, void **phKeyHandle);
    typedef int (*SDF_ImportKeyWithISK_RSA_fn)(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey, unsigned int PuiKeyLength, void **phKeyHandle);
    typedef int (*SDF_ExchangeDigitEnvelopeBaseOnRSA_fn)(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey, unsigned char *pucDEInput, unsigned int uiDELength, unsigned char *pucDEOutput, unsigned int *puiDELength); // Del in 2023
    typedef int (*SDF_ExportSignPublicKey_ECC_fn)(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
    typedef int (*SDF_ExportEncPublicKey_ECC_fn)(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
    typedef int (*SDF_GenerateKeyPair_ECC_fn)(unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
    typedef int (*SDF_GenerateKeyWithIPK_ECC_fn)(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits, ECCCipher *pucKey, void **phKeyHandle); // Moved in 2023
    typedef int (*SDF_GenerateKeyWithEPK_ECC_fn)(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle);
    typedef int (*SDF_ImportKeyWithISK_ECC_fn)(void *hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle);
    typedef int (*SDF_GenerateAgreementDataWithECC_fn)(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID,unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, void ** phAgreementHandle);
    typedef int (*SDF_GenerateKeyWithECC_fn)(void *hSessionHandle, unsigned char *pucResponseID, unsigned int uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void *hAgreementHandle, void **phKeyHandle);
    typedef int (*SDF_GenerateAgreementDataAndKeyWithECC_fn)(
        void *hSessionHandle, 
        unsigned int uiISKIndex, 
        unsigned int uiKeyBits, 
        unsigned char *pucResponseID, 
        unsigned int uiResponseIDLength, 
        unsigned char *pucSponsorID,
        unsigned int uiSponsorIDLength,
        ECCrefPublicKey *pucSponsorPublicKey, 
        ECCrefPublicKey *pucSponsorTmpPublicKey, 
        ECCrefPublicKey *pucResponsePublicKey, 
        ECCrefPublicKey *pucResponseTmpPublicKey, 
        void **phKeyHandle);
    typedef int (*SDF_ExchangeDigitEnvelopeBaseOnECC_fn)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut); // Del in 2023
    typedef int (*SDF_GenerateKeyWithKEK_fn)(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
    typedef int (*SDF_ImportKeyWithKEK_fn)(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);
    typedef int (*SDF_DestroyKey_fn)(void *hSessionHandle, void *hKeyHandle);


    // 非对称运算类(7)
    typedef int (*SDF_ExternalPublicKeyOperation_RSA_fn)(void *hSessionHandle, RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    typedef int (*SDF_InternalPublicKeyOperation_RSA_fn)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    typedef int (*SDF_InternalPrivateKeyOperation_RSA_fn)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    typedef int (*SDF_ExternalVerify_ECC_fn)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
    typedef int (*SDF_InternalSign_ECC_fn)(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
    typedef int (*SDF_InternalVerify_ECC_fn)(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
    typedef int (*SDF_ExternalEncrypt_ECC_fn)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char* pucData, unsigned int uiDataLength, ECCCipher *pucEncData);


    // 对称算法运算类(20)
    typedef int (*SDF_Encrypt_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char*pucData,unsigned int uiDataLength,unsigned char *pucEncData, unsigned int *puiEncDataLength);
    typedef int (*SDF_Decrypt_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
    typedef int (*SDF_CalculateMAC_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucMAC, unsigned int *puiMACLength);
    #if defined(SDF_VERSION_2023)
    typedef int (*SDF_AuthEnc_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength);
    typedef int (*SDF_AuthDec_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
    typedef int (*SDF_EncryptInit_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_EncryptUpdate_fn)(void *hSessionHandle, char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
    typedef int (*SDF_EncryptFinal_fn)(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength);
    typedef int (*SDF_DecryptInit_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_DecryptUpdate_fn)(void *hSessionHandle, char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
    typedef int (*SDF_DecryptFinal_fn)(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puiLastDataLength);
    typedef int (*SDF_CalculateMACInit_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_CalculateMACUpdate_fn)(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);
    typedef int (*SDF_CalculateMACFinal_fn)(void *hSessionHandle, unsigned char *pucMac, unsigned int *puiMacLength);
    typedef int (*SDF_AuthEncInit_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned int uiDataLength);
    typedef int (*SDF_AuthEncUpdate_fn)(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
    typedef int (*SDF_AuthEncFinal_fn)(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength);
    typedef int (*SDF_AuthDecInit_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData, unsigned int uiAuthDataLength, unsigned int uiDataLength);
    typedef int (*SDF_AuthDecUpdate_fn)(void *hSessionHandle, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
    typedef int (*SDF_AuthDecFinal_fn)(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puLastDataLength);
    #endif

    // 杂凑运算类(3) => (6)
    #if defined(SDF_VERSION_2023)
    typedef int (*SDF_HMACInit_fn)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID);
    typedef int (*SDF_HMACUpdate_fn)(void *hSessionHandle, char *pucData, unsigned int uiDataLength);
    typedef int (*SDF_HMACFinal_fn)(void *hSessionHandle, char *pucHMac, unsigned int *puiMacLength);
    #endif
    typedef int (*SDF_HashInit_fn)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, char *pucID, unsigned int uiIDLength);
    typedef int (*SDF_HashUpdate_fn)(void *hSessionHandle, char *pucData, unsigned int uiDataLength);
    typedef int (*SDF_HashFinal_fn)(void *hSessionHandle, char *pucHash, unsigned int *puiHashLength);

    // 用户文件操作类(4)
    typedef int (*SDF_CreateFile_fn)(void *hSessionHandle, char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize);
    typedef int (*SDF_ReadFile_fn)(void *hSessionHandle, char *pucfileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int *puiFileLength,unsigned char *pucBuffer);
    typedef int (*SDF_WriteFile_fn)(void *hSessionHandle, char *pucFileName, unsigned int uiNamelen, unsigned int uiOffset, unsigned int uiFileLength, char *pucBuffer);
    typedef int (*SDF_DeleteFile_fn)(void *hSessionHandle, char *pucFileName, unsigned int uiNameLen);

    // 验证调试类(12)
    #if defined(SDF_VERSION_2023)
    // typedef int (*SDF_GenerateKeyPair_RSA_fn)(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
    // typedef int (*SDF_GenerateKeyPair_ECC_fn)(unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
    typedef int (*SDF_ExternalPrivateKeyOperation_RSA_fn)(RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    typedef int (*SDF_ExternalSign_ECC_fn)(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
    typedef int (*SDF_ExternalDecrypt_ECC_fn)(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, unsigned char *pucData, unsigned int *uiDataLength);
    
    typedef int (*SDF_ExternalSign_SM_fn9)(SM9SignMasterPublicKey *pSignMasterPublicKey, SM9SignUserPrivateKey *pSignUserPrivateKey, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pSignature);
    typedef int (*SDF_ExternalDecrypt_SM_fn9)(SM9EncUserPrivateKey *pEncUserPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pEncData);
    
    typedef int (*SDF_ExternalKeyEncrypt_fn)(unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
    typedef int (*SDF_ExternalKeyDecrypt_fn)(
        unsigned int uiAlgID, 
        unsigned char *pucKey, 
        unsigned int uiKeyLength, 
        unsigned char *pucIV,
        unsigned int uiIVLength,
        unsigned char *pucEncData, 
        unsigned int uiEncDataLength,
        unsigned char *pucData, 
        unsigned int *puiDataLength);
    typedef int (*SDF_ExternalKeyEncryptInit_fn)(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_ExternalKeyDecryptInit_fn)(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_ExternalKeyHMACInit_fn)(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength);
    
    
    
    #endif
    // 标准之外的函数
    typedef int (*SDF_InternalEncrypt_ECC_fn)(void *hSessionHandle,
        unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength,
        ECCCipher *pucEncData);
    typedef int (*SDF_InternalDecrypt_ECC_fn)(void *hSessionHandle,
        unsigned int uiISKIndex, ECCCipher *pucEncData, unsigned char *pucData,
        unsigned int *puiDataLength); 
typedef int (*SDF_GenerateKey_fn)(void *hSessionHandle, uint8_t type,
    uint8_t no_kek, uint32_t len, void **pkey_handle);
    /*
     * Returns 0 for success, others for error code
     */

    struct sdf_method_st {
        SDF_OpenDevice_fn OpenDevice;
        SDF_CloseDevice_fn CloseDevice;
        SDF_OpenSession_fn OpenSession;
        SDF_CloseSession_fn CloseSession;
        SDF_GetDeviceInfo_fn GetDeviceInfo;
        SDF_GenerateRandom_fn GenerateRandom;
        SDF_GetPrivateKeyAccessRight_fn GetPrivateKeyAccessRight;
        SDF_ReleasePrivateKeyAccessRight_fn ReleasePrivateKeyAccessRight;


        SDF_ExportSignPublicKey_RSA_fn ExportSignPublicKey_RSA;
        SDF_ExportEncPublicKey_RSA_fn ExportEncPublicKey_RSA;
        SDF_GenerateKeyPair_RSA_fn GenerateKeyPair_RSA;         // Moved in 2023

        SDF_GenerateKeyWithIPK_RSA_fn GenerateKeyWithIPK_RSA;
        SDF_GenerateKeyWithEPK_RSA_fn GenerateKeyWithEPK_RSA;
        SDF_ImportKeyWithISK_RSA_fn ImportKeyWithISK_RSA;
        SDF_ExchangeDigitEnvelopeBaseOnRSA_fn ExchangeDigitEnvelopeBaseOnRSA; // Del in 2023

        SDF_ExportSignPublicKey_ECC_fn ExportSignPublicKey_ECC;
        SDF_ExportEncPublicKey_ECC_fn ExportEncPublicKey_ECC;
        SDF_GenerateKeyPair_ECC_fn GenerateKeyPair_ECC;         // Moved in 2023
        SDF_GenerateKeyWithIPK_ECC_fn GenerateKeyWithIPK_ECC;
        SDF_GenerateKeyWithEPK_ECC_fn GenerateKeyWithEPK_ECC;
        SDF_ImportKeyWithISK_ECC_fn ImportKeyWithISK_ECC;
        SDF_GenerateAgreementDataWithECC_fn GenerateAgreementDataWithECC;
        SDF_GenerateKeyWithECC_fn GenerateKeyWithECC;
        SDF_GenerateAgreementDataAndKeyWithECC_fn GenerateAgreementDataAndKeyWithECC;
        SDF_ExchangeDigitEnvelopeBaseOnECC_fn ExchangeDigitEnvelopeBaseOnECC; //Del in 2023

        SDF_GenerateKeyWithKEK_fn GenerateKeyWithKEK;
        SDF_ImportKeyWithKEK_fn ImportKeyWithKEK;
        SDF_DestroyKey_fn DestroyKey;

        SDF_ExternalPublicKeyOperation_RSA_fn ExternalPublicKeyOperation_RSA;
        SDF_InternalPublicKeyOperation_RSA_fn InternalPublicKeyOperation_RSA;
        SDF_InternalPrivateKeyOperation_RSA_fn InternalPrivateKeyOperation_RSA;
        SDF_ExternalVerify_ECC_fn ExternalVerify_ECC;
        SDF_InternalSign_ECC_fn InternalSign_ECC;
        SDF_InternalVerify_ECC_fn InternalVerify_ECC;
        SDF_ExternalEncrypt_ECC_fn ExternalEncrypt_ECC;
        SDF_Encrypt_fn Encrypt;
        SDF_Decrypt_fn Decrypt;
        SDF_CalculateMAC_fn CalculateMAC;
        #if defined(SDF_VERSION_2023)
        SDF_AuthEnc_fn AuthEnc;
        SDF_AuthDec_fn AuthDec;
        SDF_EncryptInit_fn EncryptInit;
        SDF_EncryptUpdate_fn EncryptUpdate;
        SDF_EncryptFinal_fn EncryptFinal;
        SDF_DecryptInit_fn DecryptInit;
        SDF_DecryptUpdate_fn DecryptUpdate;
        SDF_DecryptFinal_fn DecryptFinal;
        SDF_CalculateMACInit_fn CalculateMACInit;
        SDF_CalculateMACUpdate_fn CalculateMACUpdate;
        SDF_CalculateMACFinal_fn CalculateMACFinal;
        SDF_AuthEncInit_fn AuthEncInit;
        SDF_AuthEncUpdate_fn AuthEncUpdate;
        SDF_AuthEncFinal_fn AuthEncFinal;
        SDF_AuthDecInit_fn AuthDecInit;
        SDF_AuthDecUpdate_fn AuthDecUpdate;
        SDF_AuthDecFinal_fn AuthDecFinal;

        SDF_HMACInit_fn HMACInit;
        SDF_HMACUpdate_fn HMACUpdate;
        SDF_HMACFinal_fn HMACFinal;
        #endif

        SDF_HashInit_fn HashInit;
        SDF_HashUpdate_fn HashUpdate;
        SDF_HashFinal_fn HashFinal;

        SDF_CreateFile_fn CreateFile;
        SDF_ReadFile_fn ReadFile;
        SDF_WriteFile_fn WriteFile;
        SDF_DeleteFile_fn DeleteFile;

        // 验证调试类函数(12)
        #if defined(SDF_VERSION_2023)
        SDF_GenerateKeyPair_RSA_fn GenerateKeyPair_RSA;
        SDF_GenerateKeyPair_ECC_fn GenerateKeyPair_ECC;
        SDF_ExternalPrivateKeyOperation_RSA_fn ExternalPrivateKeyOperation_RSA;
        SDF_ExternalSign_ECC_fn ExternalSign_ECC;
        SDF_ExternalDecrypt_ECC_fn ExternalDecrypt_ECC;
  
        SDF_ExternalSign_SM_fn9 ExternalSign_SM9;
        SDF_ExternalDecrypt_SM_fn9 ExternalDecrypt_SM9;
        SDF_ExternalKeyEncrypt_fn ExternalKeyEncrypt;
        SDF_ExternalKeyDecrypt_fn ExternalKeyDecrypt;
        SDF_ExternalKeyEncryptInit_fn ExternalKeyEncryptInit;
        SDF_ExternalKeyDecryptInit_fn ExternalKeyDecryptInit;
        SDF_ExternalKeyHMACInit_fn ExternalKeyHMACInit;
        #endif


        /*SDF Ext API*/
        SDF_GenerateKey_fn GenerateKey;

        
        SDF_InternalEncrypt_ECC_fn InternalEncrypt_ECC;
        SDF_InternalDecrypt_ECC_fn InternalDecrypt_ECC;


        
    };

extern SDF_METHOD ts_sdf_meth;
#endif
