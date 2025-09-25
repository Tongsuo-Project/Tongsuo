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

/**
 * @brief Default Config
 *
 */
#define SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT   10
#define SKF_DEFAULT_USER_PIN_RETRY_COUNT    10
#define SKF_DEFAULT_FILE_RIGHTS             0

/* SKF Standard API */
typedef ULONG (*SKF_WaitForDevEvent_fn)(char * szDevName, ULONG *pulDevNameLen, ULONG *pulEvent);
typedef ULONG (*SKF_CancelWaitForDevEvent_fn)(void);
typedef ULONG (*SKF_EnumDev_fn)(BOOL bPresent, char * szNameList, ULONG *pulSize);
typedef ULONG (*SKF_ConnectDev_fn)(char * szName, DEVHANDLE *phDev);
typedef ULONG (*SKF_DisConnectDev_fn)(DEVHANDLE hDev);
typedef ULONG (*SKF_GetDevState_fn)(char * szDevName, ULONG *pulDevState);
typedef ULONG (*SKF_SetLabel_fn)(DEVHANDLE hDev, char * szLabel);
typedef ULONG (*SKF_GetDevInfo_fn)(DEVHANDLE hDev, DEVINFO *pDevInfo);
typedef ULONG (*SKF_LockDev_fn)(DEVHANDLE hDev, ULONG ulTimeOut);
typedef ULONG (*SKF_UnlockDev_fn)(DEVHANDLE hDev);
typedef ULONG (*SKF_Transmit_fn)(DEVHANDLE hDev, BYTE *pbCommand, ULONG ulCommandLen, BYTE *pbData, ULONG *pulDataLen);
typedef ULONG (*SKF_ChangeDevAuthKey_fn)(DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);
typedef ULONG (*SKF_DevAuth_fn)(DEVHANDLE hDev, BYTE *pbAuthData, ULONG ulLen);
typedef ULONG (*SKF_ChangePIN_fn)(HAPPLICATION hApplication, ULONG ulPINType, char * szOldPin, char * szNewPin, ULONG *pulRetryCount);
typedef ULONG (*SKF_GetPINInfo_fn)(HAPPLICATION hApplication, ULONG ulPINType, ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount, BOOL *pbDefaultPin);
typedef ULONG (*SKF_VerifyPIN_fn)(HAPPLICATION hApplication, ULONG ulPINType, char * szPIN, ULONG *pulRetryCount);
typedef ULONG (*SKF_UnblockPIN_fn)(HAPPLICATION hApplication, char * szAdminPIN, char * szNewUserPIN, ULONG *pulRetryCount);
typedef ULONG (*SKF_ClearSecureState_fn)(HAPPLICATION hApplication);
typedef ULONG (*SKF_CreateApplication_fn)(DEVHANDLE hDev, char * szAppName, char * szAdminPin, DWORD dwAdminPinRetryCount, char * szUserPin, DWORD dwUserPinRetryCount, DWORD dwCreateFileRights, HAPPLICATION *phApplication);
typedef ULONG (*SKF_EnumApplication_fn)(DEVHANDLE hDev, char * szAppName, ULONG *pulSize);
typedef ULONG (*SKF_DeleteApplication_fn)(DEVHANDLE hDev, char * szAppName);
typedef ULONG (*SKF_OpenApplication_fn)(DEVHANDLE hDev, char * szAppName, HAPPLICATION *phApplication);
typedef ULONG (*SKF_CloseApplication_fn)(HAPPLICATION hApplication);
typedef ULONG (*SKF_CreateFile_fn)(HAPPLICATION hApplication, char * szFileName, ULONG ulFileSize, ULONG ulReadRights, ULONG ulWriteRights);
typedef ULONG (*SKF_DeleteFile_fn)(HAPPLICATION hApplication, char * szFileName);
typedef ULONG (*SKF_EnumFiles_fn)(HAPPLICATION hApplication, char * szFileList, ULONG *pulSize);
typedef ULONG (*SKF_GetFileInfo_fn)(HAPPLICATION hApplication, char * szFileName, FILEATTRIBUTE *pFileInfo);
typedef ULONG (*SKF_ReadFile_fn)(HAPPLICATION hApplication, char * szFileName, ULONG ulOffset, ULONG ulSize, BYTE *pbOutData, ULONG *pulOutLen);
typedef ULONG (*SKF_WriteFile_fn)(HAPPLICATION hApplication, char * szFileName, ULONG ulOffset, BYTE *pbData, ULONG ulSize);
typedef ULONG (*SKF_CreateContainer_fn)(HAPPLICATION hApplication, char * szContainerName, HCONTAINER *phContainer);
typedef ULONG (*SKF_DeleteContainer_fn)(HAPPLICATION hApplication, char * szContainerName);
typedef ULONG (*SKF_OpenContainer_fn)(HAPPLICATION hApplication, char * szContainerName, HCONTAINER *phContainer);
typedef ULONG (*SKF_CloseContainer_fn)(HCONTAINER hContainer);
typedef ULONG (*SKF_EnumContainer_fn)(HAPPLICATION hApplication, char * szContainerName, ULONG *pulSize);
typedef ULONG (*SKF_GetContainerType_fn)(HCONTAINER hContainer, ULONG *pulContainerType);
typedef ULONG (*SKF_ImportCertificate_fn)(HCONTAINER hContainer, BOOL bExportSignKey, BYTE *pbCert, ULONG ulCertLen);
typedef ULONG (*SKF_ExportCertificate_fn)(HCONTAINER hContainer, BOOL bSignFlag, BYTE *pbCert, ULONG *pulCertLen);
typedef ULONG (*SKF_GenRandom_fn)(DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen);
typedef ULONG (*SKF_GenExtRSAKey_fn)(DEVHANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob);
typedef ULONG (*SKF_GenRSAKeyPair_fn)(HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB *pBlob);
typedef ULONG (*SKF_ImportRSAKeyPair_fn)(HCONTAINER hContainer, ULONG ulSymAlgId, BYTE *pbWrappedKey, ULONG ulWrappedKeyLen, BYTE *pbEncryptedData, ULONG ulEncryptedDataLen);
typedef ULONG (*SKF_RSASignData_fn)(HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature, ULONG *pulSignLen);
typedef ULONG (*SKF_RSAVerify_fn)(DEVHANDLE hDev, RSAPUBLICKEYBLOB *pRSAPubKeyBlob, BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature, ULONG ulSignLen);
typedef ULONG (*SKF_RSAExportSessionKey_fn)(HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey, BYTE *pbData, ULONG *pulDataLen, HANDLE *phSessionKey);
typedef ULONG (*SKF_ExtRSAPubKeyOperation_fn)(DEVHANDLE hDev, RSAPUBLICKEYBLOB *pRSAPubKeyBlob, BYTE *pbInput, ULONG ulInputLen, BYTE *pbOutput, ULONG *pulOutputLen);
typedef ULONG (*SKF_ExtRSAPriKeyOperation_fn)(DEVHANDLE hDev, RSAPRIVATEKEYBLOB *pRSAPriKeyBlob, BYTE *pbInput, ULONG ulInputLen, BYTE *pbOutput, ULONG *pulOutputLen);
typedef ULONG (*SKF_GenECCKeyPair_fn)(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pBlob);
typedef ULONG (*SKF_ImportECCKeyPair_fn)(HCONTAINER hContainer, ENVELOPEDKEYBLOB *pEnvelopedKeyBlob);
typedef ULONG (*SKF_ECCSignData_fn)(HCONTAINER hContainer, BYTE *pbDigest, ULONG ulDigestLen, ECCSIGNATUREBLOB *pSignature);
typedef ULONG (*SKF_ECCVerify_fn)(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, BYTE *pbData, ULONG ulDataLen, ECCSIGNATUREBLOB *pSignature);
typedef ULONG (*SKF_ECCExportSessionKey_fn)(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pPubKey, ECCCIPHERBLOB *pData, HANDLE *phSessionKey);
typedef ULONG (*SKF_ExtECCEncrypt_fn)(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, BYTE *pbPlainText, ULONG ulPlainTextLen, ECCCIPHERBLOB *pCipherText);
typedef ULONG (*SKF_ExtECCDecrypt_fn)(DEVHANDLE hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob, ECCCIPHERBLOB *pCipherText, BYTE *pbPlainText, ULONG *pulPlainTextLen);
typedef ULONG (*SKF_ExtECCSign_fn)(DEVHANDLE hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob, BYTE *pbData, ULONG ulDataLen, ECCSIGNATUREBLOB *pSignature);
typedef ULONG (*SKF_ExtECCVerify_fn)(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, BYTE *pbData, ULONG ulDataLen, ECCSIGNATUREBLOB *pSignature);
typedef ULONG (*SKF_GenerateAgreementDataWithECC_fn)(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, BYTE *pbID, ULONG ulIDLen, HANDLE *phAgreementHandle);
typedef ULONG (*SKF_GenerateAgreementDataAndKeyWithECC_fn)(HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, BYTE *pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen, HANDLE *phKeyHandle);
typedef ULONG (*SKF_GenerateKeyWithECC_fn)(HANDLE hAgreementHandle, ECCPUBLICKEYBLOB *pECCPubKeyBlob, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, BYTE *pbID, ULONG ulIDLen, HANDLE *phKeyHandle);
typedef ULONG (*SKF_ExportPublicKey_fn)(HCONTAINER hContainer, BOOL bSignFlag, BYTE *pbBlob, ULONG *pulBlobLen);
typedef ULONG (*SKF_ImportSessionKey_fn)(HCONTAINER hContainer, ULONG ulAlgId, BYTE *pbWrapedData, ULONG ulWrapedLen, HANDLE *phKey);
typedef ULONG (*SKF_SetSymmKey_fn)(DEVHANDLE hDev, BYTE *pbKey, ULONG ulAlgID, HANDLE *phKey);
typedef ULONG (*SKF_EncryptInit_fn)(HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);
typedef ULONG (*SKF_Encrypt_fn)(HANDLE hKey, BYTE *pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
typedef ULONG (*SKF_EncryptUpdate_fn)(HANDLE hKey, BYTE *pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
typedef ULONG (*SKF_EncryptFinal_fn)(HANDLE hKey, BYTE *pbEncryptedData, ULONG *pulEncryptedDataLen);
typedef ULONG (*SKF_DecryptInit_fn)(HANDLE hKey, BLOCKCIPHERPARAM DecryptParam);
typedef ULONG (*SKF_Decrypt_fn)(HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen, BYTE *pbData, ULONG *pulDataLen);
typedef ULONG (*SKF_DecryptUpdate_fn)(HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen, BYTE *pbData, ULONG *pulDataLen);
typedef ULONG (*SKF_DecryptFinal_fn)(HANDLE hKey, BYTE *pbDecryptedData, ULONG *pulDecryptedDataLen);
typedef ULONG (*SKF_DigestInit_fn)(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB *pPubKey, BYTE *pbID, ULONG ulIDLen, HANDLE *phHash);
typedef ULONG (*SKF_Digest_fn)(HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);
typedef ULONG (*SKF_DigestUpdate_fn)(HANDLE hHash, BYTE *pbData, ULONG ulDataLen);
typedef ULONG (*SKF_DigestFinal_fn)(HANDLE hHash, BYTE *pHashData, ULONG *pulHashLen);
typedef ULONG (*SKF_MacInit_fn)(HANDLE hKey, BLOCKCIPHERPARAM *pMacParam, HANDLE *phMac);
typedef ULONG (*SKF_Mac_fn)(HANDLE hMac, BYTE *pbData, ULONG ulDataLen, BYTE *pbMacData, ULONG *pulMacLen);
typedef ULONG (*SKF_MacUpdate_fn)(HANDLE hMac, BYTE *pbData, ULONG ulDataLen);
typedef ULONG (*SKF_MacFinal_fn)(HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen);
typedef ULONG (*SKF_CloseHandle_fn)(HANDLE hHandle);

/* SKF Extention API */
typedef ULONG (*SKF_AuthDev_fn)(DEVHANDLE hDev);
typedef ULONG (*SKF_ECCDecrypt_fn)(HCONTAINER hContainer, BOOL bSignFlag, ECCCIPHERBLOB *pCipherBlob, BYTE *pbPlainText, ULONG *pulPlainTextLen);
typedef ULONG (*SKF_RSADecrypt_fn)(HCONTAINER hContainer, BYTE *pbCipherText, ULONG ulCipherTextLen, BYTE *pbPlainText, ULONG *pulPlainTextLen);

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
    SKF_ChangeDevAuthKey_fn ChangeDevAuthKey;
    SKF_DevAuth_fn DevAuth;

    /* Application Management Functions */
    SKF_ChangePIN_fn ChangePIN;
    SKF_GetPINInfo_fn GetPINInfo;
    SKF_VerifyPIN_fn VerifyPIN;
    SKF_UnblockPIN_fn UnblockPIN;
    SKF_ClearSecureState_fn ClearSecureState;
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
    SKF_OpenContainer_fn OpenContainer;
    SKF_CloseContainer_fn CloseContainer;
    SKF_EnumContainer_fn EnumContainer;
    SKF_GetContainerType_fn GetContainerType;
    SKF_ImportCertificate_fn ImportCertificate;
    SKF_ExportCertificate_fn ExportCertificate;

    /* Random Number Generation */
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
    SKF_AuthDev_fn AuthDev;
    SKF_ECCDecrypt_fn ECCDecrypt;
    SKF_RSADecrypt_fn RSADecrypt;
};

# ifdef __cplusplus
}
# endif  /* __cplusplus */
#endif  /* OSSL_CRYPTO_SKF_DRIVER_H */