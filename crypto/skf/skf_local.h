/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_SKF_DRIVER_H
# define OSSL_CRYPTO_SKF_DRIVER_H

# ifdef __cplusplus
extern "C" {
# endif  /* __cplusplus */

// #include "skf_ext.h"


#define SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT   10
#define SKF_DEFAULT_USER_PIN_RETRY_COUNT    10
#define SKF_DEFAULT_FILE_RIGHTS             0

#define MAX_RSA_MODULUS_LEN 256
#define MAX_RSA_EXPONENT_LEN 4

#define ECC_MAX_XCOORDINATE_BITS_LEN 512
#define ECC_MAX_YCOORDINATE_BITS_LEN 512
#define MAX_IV_LEN 32
typedef struct Struct_Version{
    unsigned char major;
    unsigned char minor;
}VERSION;

typedef struct Struct_DEVINFO{
    VERSION Version;
    unsigned char Manufacturer[64];
    unsigned char Issuer[64];
    unsigned char Label[32];
    unsigned char SerialNumber[32];
    VERSION HWVersion;
    VERSION FirmwareVersion;
    unsigned int AlgSymCap;
    unsigned int AlgAsymCap;
    unsigned int DevAuthAlgId;
    unsigned int TotalSpace;
    unsigned int FreeSpace;
    unsigned char Reserved[64];
}DEVINFO,*PDEVINFO;


typedef struct Struct_RSAPUBLICKEYBLOB{
    unsigned int AlgID;
    unsigned int BitLen;
    unsigned char Modulus[MAX_RSA_MODULUS_LEN];
    unsigned char PublicExponent[MAX_RSA_EXPONENT_LEN];
}RSAPUBLICKEYBLOB,*PRSAPUBLICKEYBLOB;

typedef struct  Struct_RSAPRIVATEKEYBLOB{
    unsigned int AlgID;
    unsigned int BitLen;
    unsigned char Modulus[MAX_RSA_MODULUS_LEN];
    unsigned char PublicExponent[MAX_RSA_EXPONENT_LEN];
    unsigned char PrivateExponent[MAX_RSA_MODULUS_LEN];
    unsigned char Prime1[MAX_RSA_MODULUS_LEN/2];
    unsigned char Prime2[MAX_RSA_MODULUS_LEN/2];
    unsigned char Prime1Exponent[MAX_RSA_MODULUS_LEN/2];
    unsigned char Prime2Exponent[MAX_RSA_MODULUS_LEN/2];
    unsigned char Coefficient[MAX_RSA_MODULUS_LEN/2];
}RSAPRIVATEKEYBLOB,*PRSAPRIVATEKEYBLOB;


typedef struct Struct_ECCPUBLICKEYBLOB{
    unsigned int BitLen;
    unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCPUBLICKEYBLOB,*PECCPUBLICKEYBLOB;

typedef struct Struct_ECCCIPHERBLOB{
    unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
    unsigned char HASH[32];
    unsigned int CipherLen;
    unsigned char Cipher[1];
}ECCCIPHERBLOB,*PECCCIPHERBLOB;
typedef struct Struct_ECCSIGNATUREBLOB{
    unsigned char r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char s[ECC_MAX_XCOORDINATE_BITS_LEN/8];
}ECCSIGNATUREBLOB,*PECCSIGNATUREBLOB;

typedef struct Struct_BLOCKCIPHERPARAM{
    unsigned char IV[MAX_IV_LEN];
    unsigned int IVLen;
    unsigned int PaddingType;
    unsigned int FeedBitLen;
}BLOCKCIPHERPARAM,*PBLOCKCIPHERPARAM;

typedef struct SKF_ENVELOPEDKEYBLOB
{
    unsigned int Version;
    unsigned int ulSymmAlgID;
    unsigned int ulBits;
    unsigned char cbEncryptedPriKey[64];
    ECCPUBLICKEYBLOB PubKey;
    ECCCIPHERBLOB ECCCipherBlob;
};


typedef struct Struct_FILEATTRIBUTE{
    unsigned char FileName[32];
    unsigned int FileSize;
    unsigned int ReadRights;
    unsigned int WriteRights;
}FILEATTRIBUTE,*PFILEATTRIBUTE;


/* SKF Standard API */
typedef unsigned int  (*SKF_WaitForDevEvent_fn)(char * szDevName, unsigned int  *pulDevNameLen, unsigned int  *pulEvent);
typedef unsigned int  (*SKF_CancelWaitForDevEvent_fn)(void);
typedef unsigned int  (*SKF_EnumDev_fn)(int bPresent, char * szNameList, unsigned int  *pulSize);
typedef unsigned int  (*SKF_ConnectDev_fn)(char * szName, void  * *phDev);
typedef unsigned int  (*SKF_DisConnectDev_fn)(void  * hDev);
typedef unsigned int  (*SKF_GetDevState_fn)(char * szDevName, unsigned int  *pulDevState);
typedef unsigned int  (*SKF_SetLabel_fn)(void  * hDev, char * szLabel);
typedef unsigned int  (*SKF_GetDevInfo_fn)(void  * hDev, DEVINFO *pDevInfo);
typedef unsigned int  (*SKF_LockDev_fn)(void  * hDev, unsigned int  ulTimeOut);
typedef unsigned int  (*SKF_UnlockDev_fn)(void  * hDev);
typedef unsigned int  (*SKF_Transmit_fn)(void  * hDev, unsigned char  *pbCommand, unsigned int  ulCommandLen, unsigned char  *pbData, unsigned int  *pulDataLen);
typedef unsigned int  (*SKF_ChangeDevAuthKey_fn)(void  * hDev, unsigned char  *pbKeyValue, unsigned int  ulKeyLen);
typedef unsigned int  (*SKF_DevAuth_fn)(void  * hDev, unsigned char  *pbAuthData, unsigned int  ulLen);
typedef unsigned int  (*SKF_ChangePIN_fn)(void * hApplication, unsigned int  ulPINType, char * szOldPin, char * szNewPin, unsigned int  *pulRetryCount);
typedef unsigned int  (*SKF_GetPINInfo_fn)(void * hApplication, unsigned int  ulPINType, unsigned int  *pulMaxRetryCount, unsigned int  *pulRemainRetryCount, int *pbDefaultPin);
typedef unsigned int  (*SKF_VerifyPIN_fn)(void * hApplication, unsigned int  ulPINType, char * szPIN, unsigned int  *pulRetryCount);
typedef unsigned int  (*SKF_UnblockPIN_fn)(void * hApplication, char * szAdminPIN, char * szNewUserPIN, unsigned int  *pulRetryCount);
typedef unsigned int  (*SKF_ClearSecureState_fn)(void * hApplication);
typedef unsigned int  (*SKF_CreateApplication_fn)(void  * hDev, char * szAppName, char * szAdminPin, unsigned int dwAdminPinRetryCount, char * szUserPin, unsigned int dwUserPinRetryCount, unsigned int dwCreateFileRights, void * *phApplication);
typedef unsigned int  (*SKF_EnumApplication_fn)(void  * hDev, char * szAppName, unsigned int  *pulSize);
typedef unsigned int  (*SKF_DeleteApplication_fn)(void  * hDev, char * szAppName);
typedef unsigned int  (*SKF_OpenApplication_fn)(void  * hDev, char * szAppName, void * *phApplication);
typedef unsigned int  (*SKF_CloseApplication_fn)(void * hApplication);
typedef unsigned int  (*SKF_CreateFile_fn)(void * hApplication, char * szFileName, unsigned int  ulFileSize, unsigned int  ulReadRights, unsigned int  ulWriteRights);
typedef unsigned int  (*SKF_DeleteFile_fn)(void * hApplication, char * szFileName);
typedef unsigned int  (*SKF_EnumFiles_fn)(void * hApplication, char * szFileList, unsigned int  *pulSize);
typedef unsigned int  (*SKF_GetFileInfo_fn)(void * hApplication, char * szFileName, FILEATTRIBUTE *pFileInfo);
typedef unsigned int  (*SKF_ReadFile_fn)(void * hApplication, char * szFileName, unsigned int  ulOffset, unsigned int  ulSize, unsigned char  *pbOutData, unsigned int  *pulOutLen);
typedef unsigned int  (*SKF_WriteFile_fn)(void * hApplication, char * szFileName, unsigned int  ulOffset, unsigned char  *pbData, unsigned int  ulSize);
typedef unsigned int  (*SKF_CreateContainer_fn)(void * hApplication, char * szContainerName, void * *phContainer);
typedef unsigned int  (*SKF_DeleteContainer_fn)(void * hApplication, char * szContainerName);
typedef unsigned int  (*SKF_OpenContainer_fn)(void * hApplication, char * szContainerName, void * *phContainer);
typedef unsigned int  (*SKF_CloseContainer_fn)(void * hContainer);
typedef unsigned int  (*SKF_EnumContainer_fn)(void * hApplication, char * szContainerName, unsigned int  *pulSize);
typedef unsigned int  (*SKF_GetContainerType_fn)(void * hContainer, unsigned int  *pulContainerType);
typedef unsigned int  (*SKF_ImportCertificate_fn)(void * hContainer, int bExportSignKey, unsigned char  *pbCert, unsigned int  ulCertLen);
typedef unsigned int  (*SKF_ExportCertificate_fn)(void * hContainer, int bSignFlag, unsigned char  *pbCert, unsigned int  *pulCertLen);
typedef unsigned int  (*SKF_GenRandom_fn)(void  * hDev, unsigned char  *pbRandom, unsigned int  ulRandomLen);
typedef unsigned int  (*SKF_GenExtRSAKey_fn)(void  * hDev, unsigned int  ulBitsLen, RSAPRIVATEKEYBLOB *pBlob);
typedef unsigned int  (*SKF_GenRSAKeyPair_fn)(void * hContainer, unsigned int  ulBitsLen, RSAPUBLICKEYBLOB *pBlob);
typedef unsigned int  (*SKF_ImportRSAKeyPair_fn)(void * hContainer, unsigned int  ulSymAlgId, unsigned char  *pbWrappedKey, unsigned int  ulWrappedKeyLen, unsigned char  *pbEncryptedData, unsigned int  ulEncryptedDataLen);
typedef unsigned int  (*SKF_RSASignData_fn)(void * hContainer, unsigned char  *pbData, unsigned int  ulDataLen, unsigned char  *pbSignature, unsigned int  *pulSignLen);
typedef unsigned int  (*SKF_RSAVerify_fn)(void  * hDev, RSAPUBLICKEYBLOB *pRSAPubKeyBlob, unsigned char  *pbData, unsigned int  ulDataLen, unsigned char  *pbSignature, unsigned int  ulSignLen);
typedef unsigned int  (*SKF_RSAExportSessionKey_fn)(void * hContainer, unsigned int  ulAlgId, RSAPUBLICKEYBLOB *pPubKey, unsigned char  *pbData, unsigned int  *pulDataLen, void * *phSessionKey);
typedef unsigned int  (*SKF_ExtRSAPubKeyOperation_fn)(void  * hDev, RSAPUBLICKEYBLOB *pRSAPubKeyBlob, unsigned char  *pbInput, unsigned int  ulInputLen, unsigned char  *pbOutput, unsigned int  *pulOutputLen);
typedef unsigned int  (*SKF_ExtRSAPriKeyOperation_fn)(void  * hDev, RSAPRIVATEKEYBLOB *pRSAPriKeyBlob, unsigned char  *pbInput, unsigned int  ulInputLen, unsigned char  *pbOutput, unsigned int  *pulOutputLen);
typedef unsigned int  (*SKF_GenECCKeyPair_fn)(void * hContainer, unsigned int  ulAlgId, ECCPUBLICKEYBLOB *pBlob);
typedef unsigned int  (*SKF_ImportECCKeyPair_fn)(void * hContainer, ENVELOPEDKEYBLOB *pEnvelopedKeyBlob);
typedef unsigned int  (*SKF_ECCSignData_fn)(void * hContainer, unsigned char  *pbDigest, unsigned int  ulDigestLen, ECCSIGNATUREBLOB *pSignature);
typedef unsigned int  (*SKF_ECCVerify_fn)(void  * hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, unsigned char  *pbData, unsigned int  ulDataLen, ECCSIGNATUREBLOB *pSignature);
typedef unsigned int  (*SKF_ECCExportSessionKey_fn)(void * hContainer, unsigned int  ulAlgId, ECCPUBLICKEYBLOB *pPubKey, ECCCIPHERBLOB *pData, void * *phSessionKey);
typedef unsigned int  (*SKF_ExtECCEncrypt_fn)(void  * hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, unsigned char  *pbPlainText, unsigned int  ulPlainTextLen, ECCCIPHERBLOB *pCipherText);
typedef unsigned int  (*SKF_ExtECCDecrypt_fn)(void  * hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob, ECCCIPHERBLOB *pCipherText, unsigned char  *pbPlainText, unsigned int  *pulPlainTextLen);
typedef unsigned int  (*SKF_ExtECCSign_fn)(void  * hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob, unsigned char  *pbData, unsigned int  ulDataLen, ECCSIGNATUREBLOB *pSignature);
typedef unsigned int  (*SKF_ExtECCVerify_fn)(void  * hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, unsigned char  *pbData, unsigned int  ulDataLen, ECCSIGNATUREBLOB *pSignature);
typedef unsigned int  (*SKF_GenerateAgreementDataWithECC_fn)(void * hContainer, unsigned int  ulAlgId, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, unsigned char  *pbID, unsigned int  ulIDLen, void * *phAgreementvoid *);
typedef unsigned int  (*SKF_GenerateAgreementDataAndKeyWithECC_fn)(void * hContainer, unsigned int  ulAlgId, ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, unsigned char  *pbID, unsigned int  ulIDLen, unsigned char  *pbSponsorID, unsigned int  ulSponsorIDLen, void * *phKeyvoid *);
typedef unsigned int  (*SKF_GenerateKeyWithECC_fn)(void * hAgreementvoid *, ECCPUBLICKEYBLOB *pECCPubKeyBlob, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, unsigned char  *pbID, unsigned int  ulIDLen, void * *phKeyvoid *);
typedef unsigned int  (*SKF_ExportPublicKey_fn)(void * hContainer, int bSignFlag, unsigned char  *pbBlob, unsigned int  *pulBlobLen);
typedef unsigned int  (*SKF_ImportSessionKey_fn)(void * hContainer, unsigned int  ulAlgId, unsigned char  *pbWrapedData, unsigned int  ulWrapedLen, void * *phKey);
typedef unsigned int  (*SKF_SetSymmKey_fn)(void  * hDev, unsigned char  *pbKey, unsigned int  ulAlgID, void * *phKey);
typedef unsigned int  (*SKF_EncryptInit_fn)(void * hKey, BLOCKCIPHERPARAM EncryptParam);
typedef unsigned int  (*SKF_Encrypt_fn)(void * hKey, unsigned char  *pbData, unsigned int  ulDataLen, unsigned char  *pbEncryptedData, unsigned int  *pulEncryptedLen);
typedef unsigned int  (*SKF_EncryptUpdate_fn)(void * hKey, unsigned char  *pbData, unsigned int  ulDataLen, unsigned char  *pbEncryptedData, unsigned int  *pulEncryptedLen);
typedef unsigned int  (*SKF_EncryptFinal_fn)(void * hKey, unsigned char  *pbEncryptedData, unsigned int  *pulEncryptedDataLen);
typedef unsigned int  (*SKF_DecryptInit_fn)(void * hKey, BLOCKCIPHERPARAM DecryptParam);
typedef unsigned int  (*SKF_Decrypt_fn)(void * hKey, unsigned char  *pbEncryptedData, unsigned int  ulEncryptedLen, unsigned char  *pbData, unsigned int  *pulDataLen);
typedef unsigned int  (*SKF_DecryptUpdate_fn)(void * hKey, unsigned char  *pbEncryptedData, unsigned int  ulEncryptedLen, unsigned char  *pbData, unsigned int  *pulDataLen);
typedef unsigned int  (*SKF_DecryptFinal_fn)(void * hKey, unsigned char  *pbDecryptedData, unsigned int  *pulDecryptedDataLen);
typedef unsigned int  (*SKF_DigestInit_fn)(void  * hDev, unsigned int  ulAlgID, ECCPUBLICKEYBLOB *pPubKey, unsigned char  *pbID, unsigned int  ulIDLen, void * *phHash);
typedef unsigned int  (*SKF_Digest_fn)(void * hHash, unsigned char  *pbData, unsigned int  ulDataLen, unsigned char  *pbHashData, unsigned int  *pulHashLen);
typedef unsigned int  (*SKF_DigestUpdate_fn)(void * hHash, unsigned char  *pbData, unsigned int  ulDataLen);
typedef unsigned int  (*SKF_DigestFinal_fn)(void * hHash, unsigned char  *pHashData, unsigned int  *pulHashLen);
typedef unsigned int  (*SKF_MacInit_fn)(void * hKey, BLOCKCIPHERPARAM *pMacParam, void * *phMac);
typedef unsigned int  (*SKF_Mac_fn)(void * hMac, unsigned char  *pbData, unsigned int  ulDataLen, unsigned char  *pbMacData, unsigned int  *pulMacLen);
typedef unsigned int  (*SKF_MacUpdate_fn)(void * hMac, unsigned char  *pbData, unsigned int  ulDataLen);
typedef unsigned int  (*SKF_MacFinal_fn)(void * hMac, unsigned char  *pbMacData, unsigned int  *pulMacDataLen);
typedef unsigned int  (*SKF_CloseHandle_fn)(void * hvoid *);

/* SKF Extention API */
typedef unsigned int  (*SKF_AuthDev_fn)(void  * hDev);
typedef unsigned int  (*SKF_ECCDecrypt_fn)(void * hContainer, int bSignFlag, ECCCIPHERBLOB *pCipherBlob, unsigned char  *pbPlainText, unsigned int  *pulPlainTextLen);
typedef unsigned int  (*SKF_RSADecrypt_fn)(void * hContainer, unsigned char  *pbCipherText, unsigned int  ulCipherTextLen, unsigned char  *pbPlainText, unsigned int  *pulPlainTextLen);

/**
 * @brief SKF method structure
 *
 */
struct skf_method_st {
    /* Device Management Functions */
    SKF_WaitForDevEvent_fn WaitForDevEvent;
    SKF_CancelWaitForDevEvent_fn CancelWaitForDevEvent;
    SKF_EnumDev_fn EnumDev;
    SKF_ConnectDev_fn ConnectDev;
    SKF_DisConnectDev_fn DisConnectDev;
    SKF_GetDevState_fn GetDevState;
    SKF_SetLabel_fn SetLabel;
    SKF_GetDevInfo_fn GetDevInfo;
    SKF_LockDev_fn LockDev;
    SKF_UnlockDev_fn UnlockDev;
    SKF_Transmit_fn Transmit;

    // Access Control
    SKF_ChangeDevAuthKey_fn ChangeDevAuthKey;
    SKF_DevAuth_fn DevAuth;
    SKF_ChangePIN_fn ChangePIN;
    SKF_GetPINInfo_fn GetPINInfo;
    SKF_VerifyPIN_fn VerifyPIN;
    SKF_UnblockPIN_fn UnblockPIN;
    SKF_ClearSecureState_fn ClearSecureState;

    /* Application Management Functions */
    SKF_CreateApplication_fn CreateApplication;
    SKF_EnumApplication_fn EnumApplication;
    SKF_DeleteApplication_fn DeleteApplication;
    SKF_OpenApplication_fn OpenApplication;
    SKF_CloseApplication_fn CloseApplication;

    /* File Management Functions */
    SKF_CreateFile_fn CreateFile;
    SKF_DeleteFile_fn DeleteFile;
    SKF_EnumFiles_fn EnumFiles;
    SKF_GetFileInfo_fn GetFileInfo;
    SKF_ReadFile_fn ReadFile;
    SKF_WriteFile_fn WriteFile;

    /* Container Management Functions */
    SKF_CreateContainer_fn CreateContainer;
    SKF_DeleteContainer_fn DeleteContainer;
    SKF_EnumContainer_fn EnumContainer;
    SKF_OpenContainer_fn OpenContainer;
    SKF_CloseContainer_fn CloseContainer;
    SKF_GetContainerType_fn GetContainerType;
    SKF_ImportCertificate_fn ImportCertificate;
    SKF_ExportCertificate_fn ExportCertificate;

    /* Crypto Service */
    SKF_GenRandom_fn GenRandom;

    /* RSA Functions */
    SKF_GenExtRSAKey_fn GenExtRSAKey;
    SKF_GenRSAKeyPair_fn GenRSAKeyPair;
    SKF_ImportRSAKeyPair_fn ImportRSAKeyPair;
    SKF_RSASignData_fn RSASignData;
    SKF_RSAVerify_fn RSAVerify;
    SKF_RSAExportSessionKey_fn RSAExportSessionKey;
    SKF_ExtRSAPubKeyOperation_fn ExtRSAPubKeyOperation;
    SKF_ExtRSAPriKeyOperation_fn ExtRSAPriKeyOperation;

    /* ECC Functions */
    SKF_GenECCKeyPair_fn GenECCKeyPair;
    SKF_ImportECCKeyPair_fn ImportECCKeyPair;
    SKF_ECCSignData_fn ECCSignData;
    SKF_ECCVerify_fn ECCVerify;
    SKF_ECCExportSessionKey_fn ECCExportSessionKey;
    SKF_ExtECCEncrypt_fn ExtECCEncrypt;
    SKF_ExtECCDecrypt_fn ExtECCDecrypt;
    SKF_ExtECCSign_fn ExtECCSign;
    SKF_ExtECCVerify_fn ExtECCVerify;
    SKF_GenerateAgreementDataWithECC_fn GenerateAgreementDataWithECC;
    SKF_GenerateAgreementDataAndKeyWithECC_fn GenerateAgreementDataAndKeyWithECC;
    SKF_GenerateKeyWithECC_fn GenerateKeyWithECC;

    /* Key Management Functions */
    SKF_ExportPublicKey_fn ExportPublicKey;
    SKF_ImportSessionKey_fn ImportSessionKey;
    SKF_SetSymmKey_fn SetSymmKey;

    /* Cryptographic Operations */
    SKF_EncryptInit_fn EncryptInit;
    SKF_Encrypt_fn Encrypt;
    SKF_EncryptUpdate_fn EncryptUpdate;
    SKF_EncryptFinal_fn EncryptFinal;
    SKF_DecryptInit_fn DecryptInit;
    SKF_Decrypt_fn Decrypt;
    SKF_DecryptUpdate_fn DecryptUpdate;
    SKF_DecryptFinal_fn DecryptFinal;

    /* Hash Functions */
    SKF_DigestInit_fn DigestInit;
    SKF_Digest_fn Digest;
    SKF_DigestUpdate_fn DigestUpdate;
    SKF_DigestFinal_fn DigestFinal;

    /* MAC Functions */
    SKF_MacInit_fn MacInit;
    SKF_Mac_fn Mac;
    SKF_MacUpdate_fn MacUpdate;
    SKF_MacFinal_fn MacFinal;

    /* Handle Management */
    SKF_CloseHandle_fn CloseHandle;

    /* Extension Functions */
    // SKF_AuthDev_fn AuthDev;
    // SKF_ECCDecrypt_fn ECCDecrypt;
    // SKF_RSADecrypt_fn RSADecrypt;
};
extern SKF_METHOD ts_skf_meth;

# ifdef __cplusplus
}
# endif  /* __cplusplus */
#endif  /* OSSL_CRYPTO_SKF_DRIVER_H */