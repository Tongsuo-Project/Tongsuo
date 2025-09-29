
/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include <openssl/crypto.h>
#include <openssl/types.h>
#include <openssl/skf.h>
#include "internal/thread_once.h"
#include "internal/dso.h"
// #include "internal/skf.h"
#include "skf_local.h"
#include <string.h>

#ifdef SKF_LIB
# ifdef SKF_LIB_SHARED
static DSO *sdf_dso = NULL;
# else
    # include "skf_sym_weak.h"
# endif
#endif
// static CRYPTO_ONCE sdf_lib_once = CRYPTO_ONCE_STATIC_INIT;
static SKF_METHOD skfm;
static int tag = 0;
void ossl_skf_lib_cleanup(void)
{
#ifdef SKF_LIB_SHARED
    DSO_free(skf_dso);
    skf_dso = NULL;
#endif
}

static const SKF_METHOD *skf_get_method(void)
{
    const SKF_METHOD *meth = &ts_skf_meth;

#ifdef SKF_LIB
    if (tag == 0)
    {
#ifdef SKF_LIB_SHARED
        skf_dso = DSO_load(NULL, LIBSKF, NULL, 0);
        if (skf_dso != NULL) {
            skf_bind_init(&skfm, skf_dso);
        }
#endif
        tag = 1;
    }

    meth = &skfm;
#endif
    return meth;
}

/* =============================================================
 * 设备管理类函数
 * ============================================================= */
unsigned int TSAPI_SKF_WaitForDevEvent(char *szDevName, unsigned int *pulDevNameLen, 
                                      unsigned int *pulEvent)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->WaitForDevEvent == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->WaitForDevEvent(szDevName, pulDevNameLen, pulEvent);
}

unsigned int TSAPI_SKF_CancelWaitForDevEvent(void)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->CancelWaitForDevEvent == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->CancelWaitForDevEvent();
}

unsigned int TSAPI_SKF_EnumDev(int bPresent, char *szNameList, unsigned int *pulSize)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->EnumDev == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->EnumDev(bPresent, szNameList, pulSize);
}

unsigned int TSAPI_SKF_ConnectDev(char *szName, void **phDev)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ConnectDev == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ConnectDev(szName, phDev);
}

unsigned int TSAPI_SKF_DisConnectDev(void *hDev)
{
    const SKF_METHOD *meth = skf_get_method();
    if (hDev == NULL)
        return SAR_OK;
    if (meth == NULL || meth->DisConnectDev == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DisConnectDev(hDev);
}

unsigned int TSAPI_SKF_GetDevState(char *szDevName, unsigned int *pulDevState)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GetDevState == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GetDevState(szDevName, pulDevState);
}

unsigned int TSAPI_SKF_SetLabel(void *hDev, char *szLabel)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->SetLabel == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->SetLabel(hDev, szLabel);
}

unsigned int TSAPI_SKF_GetDevInfo(void *hDev, DEVINFO *pDevInfo)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GetDevInfo == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GetDevInfo(hDev, pDevInfo);
}

unsigned int TSAPI_SKF_LockDev(void *hDev, unsigned int ulTimeOut)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->LockDev == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->LockDev(hDev, ulTimeOut);
}

unsigned int TSAPI_SKF_UnlockDev(void *hDev)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->UnlockDev == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->UnlockDev(hDev);
}

unsigned int TSAPI_SKF_Transmit(void *hDev, unsigned char *pbCommand, 
                               unsigned int ulCommandLen, unsigned char *pbData, 
                               unsigned int *pulDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->Transmit == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->Transmit(hDev, pbCommand, ulCommandLen, pbData, pulDataLen);
}

/* =============================================================
 * 访问控制类函数
 * ============================================================= */
unsigned int TSAPI_SKF_ChangeDevAuthKey(void *hDev, unsigned char *pbKeyValue, 
                                       unsigned int ulKeyLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ChangeDevAuthKey == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ChangeDevAuthKey(hDev, pbKeyValue, ulKeyLen);
}

unsigned int TSAPI_SKF_DevAuth(void *hDev, unsigned char *pbAuthData, 
                              unsigned int ulLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DevAuth == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DevAuth(hDev, pbAuthData, ulLen);
}

unsigned int TSAPI_SKF_ChangePIN(void *hApplication, unsigned int ulPINType, 
                                char *szOldPin, char *szNewPin, 
                                unsigned int *pulRetryCount)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ChangePIN == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ChangePIN(hApplication, ulPINType, szOldPin, szNewPin, pulRetryCount);
}

unsigned int TSAPI_SKF_GetPINInfo(void *hApplication, unsigned int ulPINType, 
                                 unsigned int *pulMaxRetryCount, 
                                 unsigned int *pulRemainRetryCount, 
                                 int *pbDefaultPin)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GetPINInfo == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GetPINInfo(hApplication, ulPINType, pulMaxRetryCount, 
                           pulRemainRetryCount, pbDefaultPin);
}

unsigned int TSAPI_SKF_VerifyPIN(void *hApplication, unsigned int ulPINType, 
                                char *szPIN, unsigned int *pulRetryCount)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->VerifyPIN == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->VerifyPIN(hApplication, ulPINType, szPIN, pulRetryCount);
}

unsigned int TSAPI_SKF_UnblockPIN(void *hApplication, char *szAdminPIN, 
                                 char *szNewUserPIN, unsigned int *pulRetryCount)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->UnblockPIN == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->UnblockPIN(hApplication, szAdminPIN, szNewUserPIN, pulRetryCount);
}

unsigned int TSAPI_SKF_ClearSecureState(void *hApplication)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ClearSecureState == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ClearSecureState(hApplication);
}

/* =============================================================
 * 应用管理类函数
 * ============================================================= */
unsigned int TSAPI_SKF_CreateApplication(void *hDev, char *szAppName, 
                                        char *szAdminPin, unsigned int dwAdminPinRetryCount, 
                                        char *szUserPin, unsigned int dwUserPinRetryCount, 
                                        unsigned int dwCreateFileRights, void **phApplication)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->CreateApplication == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->CreateApplication(hDev, szAppName, szAdminPin, dwAdminPinRetryCount, 
                                  szUserPin, dwUserPinRetryCount, dwCreateFileRights, 
                                  phApplication);
}

unsigned int TSAPI_SKF_EnumApplication(void *hDev, char *szAppName, unsigned int *pulSize)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->EnumApplication == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->EnumApplication(hDev, szAppName, pulSize);
}

unsigned int TSAPI_SKF_DeleteApplication(void *hDev, char *szAppName)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DeleteApplication == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DeleteApplication(hDev, szAppName);
}

unsigned int TSAPI_SKF_OpenApplication(void *hDev, char *szAppName, void **phApplication)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->OpenApplication == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->OpenApplication(hDev, szAppName, phApplication);
}

unsigned int TSAPI_SKF_CloseApplication(void *hApplication)
{
    const SKF_METHOD *meth = skf_get_method();
    if (hApplication == NULL)
        return SAR_OK;
    if (meth == NULL || meth->CloseApplication == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->CloseApplication(hApplication);
}

/* =============================================================
 * 文件管理类函数
 * ============================================================= */
unsigned int TSAPI_SKF_CreateFile(void *hApplication, char *szFileName, 
                                 unsigned int ulFileSize, unsigned int ulReadRights, 
                                 unsigned int ulWriteRights)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->CreateFile == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->CreateFile(hApplication, szFileName, ulFileSize, ulReadRights, ulWriteRights);
}

unsigned int TSAPI_SKF_DeleteFile(void *hApplication, char *szFileName)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DeleteFile == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DeleteFile(hApplication, szFileName);
}

unsigned int TSAPI_SKF_EnumFiles(void *hApplication, char *szFileList, unsigned int *pulSize)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->EnumFiles == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->EnumFiles(hApplication, szFileList, pulSize);
}

unsigned int TSAPI_SKF_GetFileInfo(void *hApplication, char *szFileName, FILEATTRIBUTE *pFileInfo)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GetFileInfo == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GetFileInfo(hApplication, szFileName, pFileInfo);
}

unsigned int TSAPI_SKF_ReadFile(void *hApplication, char *szFileName, 
                               unsigned int ulOffset, unsigned int ulSize, 
                               unsigned char *pbOutData, unsigned int *pulOutLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ReadFile == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ReadFile(hApplication, szFileName, ulOffset, ulSize, pbOutData, pulOutLen);
}

unsigned int TSAPI_SKF_WriteFile(void *hApplication, char *szFileName, 
                                unsigned int ulOffset, unsigned char *pbData, 
                                unsigned int ulSize)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->WriteFile == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->WriteFile(hApplication, szFileName, ulOffset, pbData, ulSize);
}

/* =============================================================
 * 容器管理类函数
 * ============================================================= */
unsigned int TSAPI_SKF_CreateContainer(void *hApplication, char *szContainerName, 
                                      void **phContainer)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->CreateContainer == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->CreateContainer(hApplication, szContainerName, phContainer);
}

unsigned int TSAPI_SKF_DeleteContainer(void *hApplication, char *szContainerName)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DeleteContainer == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DeleteContainer(hApplication, szContainerName);
}

unsigned int TSAPI_SKF_EnumContainer(void *hApplication, char *szContainerName, 
                                    unsigned int *pulSize)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->EnumContainer == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->EnumContainer(hApplication, szContainerName, pulSize);
}

unsigned int TSAPI_SKF_OpenContainer(void *hApplication, char *szContainerName, 
                                    void **phContainer)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->OpenContainer == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->OpenContainer(hApplication, szContainerName, phContainer);
}

unsigned int TSAPI_SKF_CloseContainer(void *hContainer)
{
    const SKF_METHOD *meth = skf_get_method();
    if (hContainer == NULL)
        return SAR_OK;
    if (meth == NULL || meth->CloseContainer == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->CloseContainer(hContainer);
}

unsigned int TSAPI_SKF_GetContainerType(void *hContainer, unsigned int *pulContainerType)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GetContainerType == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GetContainerType(hContainer, pulContainerType);
}

unsigned int TSAPI_SKF_ImportCertificate(void *hContainer, int bExportSignKey, 
                                        unsigned char *pbCert, unsigned int ulCertLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ImportCertificate == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ImportCertificate(hContainer, bExportSignKey, pbCert, ulCertLen);
}

unsigned int TSAPI_SKF_ExportCertificate(void *hContainer, int bSignFlag, 
                                        unsigned char *pbCert, unsigned int *pulCertLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ExportCertificate == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ExportCertificate(hContainer, bSignFlag, pbCert, pulCertLen);
}

/* =============================================================
 * 密码服务类函数
 * ============================================================= */
unsigned int TSAPI_SKF_GenRandom(void *hDev, unsigned char *pbRandom, 
                                unsigned int ulRandomLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GenRandom == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GenRandom(hDev, pbRandom, ulRandomLen);
}

/* =============================================================
 * RSA 相关函数
 * ============================================================= */
unsigned int TSAPI_SKF_GenExtRSAKey(void *hDev, unsigned int ulBitsLen, 
                                   RSAPRIVATEKEYBLOB *pBlob)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GenExtRSAKey == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GenExtRSAKey(hDev, ulBitsLen, pBlob);
}

unsigned int TSAPI_SKF_GenRSAKeyPair(void *hContainer, unsigned int ulBitsLen, 
                                    RSAPUBLICKEYBLOB *pBlob)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GenRSAKeyPair == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GenRSAKeyPair(hContainer, ulBitsLen, pBlob);
}

unsigned int TSAPI_SKF_ImportRSAKeyPair(void *hContainer, unsigned int ulSymAlgId, 
                                       unsigned char *pbWrappedKey, 
                                       unsigned int ulWrappedKeyLen, 
                                       unsigned char *pbEncryptedData, 
                                       unsigned int ulEncryptedDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ImportRSAKeyPair == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ImportRSAKeyPair(hContainer, ulSymAlgId, pbWrappedKey, 
                                 ulWrappedKeyLen, pbEncryptedData, ulEncryptedDataLen);
}

unsigned int TSAPI_SKF_RSASignData(void *hContainer, unsigned char *pbData, 
                                  unsigned int ulDataLen, unsigned char *pbSignature, 
                                  unsigned int *pulSignLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->RSASignData == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->RSASignData(hContainer, pbData, ulDataLen, pbSignature, pulSignLen);
}

unsigned int TSAPI_SKF_RSAVerify(void *hDev, RSAPUBLICKEYBLOB *pRSAPubKeyBlob, 
                                unsigned char *pbData, unsigned int ulDataLen, 
                                unsigned char *pbSignature, unsigned int ulSignLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->RSAVerify == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->RSAVerify(hDev, pRSAPubKeyBlob, pbData, ulDataLen, pbSignature, ulSignLen);
}

unsigned int TSAPI_SKF_RSAExportSessionKey(void *hContainer, unsigned int ulAlgId, 
                                          RSAPUBLICKEYBLOB *pPubKey, 
                                          unsigned char *pbData, unsigned int *pulDataLen, 
                                          void **phSessionKey)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->RSAExportSessionKey == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->RSAExportSessionKey(hContainer, ulAlgId, pPubKey, pbData, 
                                    pulDataLen, phSessionKey);
}

unsigned int TSAPI_SKF_ExtRSAPubKeyOperation(void *hDev, RSAPUBLICKEYBLOB *pRSAPubKeyBlob, 
                                            unsigned char *pbInput, unsigned int ulInputLen, 
                                            unsigned char *pbOutput, unsigned int *pulOutputLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ExtRSAPubKeyOperation == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ExtRSAPubKeyOperation(hDev, pRSAPubKeyBlob, pbInput, ulInputLen, 
                                      pbOutput, pulOutputLen);
}

unsigned int TSAPI_SKF_ExtRSAPriKeyOperation(void *hDev, RSAPRIVATEKEYBLOB *pRSAPriKeyBlob, 
                                            unsigned char *pbInput, unsigned int ulInputLen, 
                                            unsigned char *pbOutput, unsigned int *pulOutputLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ExtRSAPriKeyOperation == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ExtRSAPriKeyOperation(hDev, pRSAPriKeyBlob, pbInput, ulInputLen, 
                                      pbOutput, pulOutputLen);
}

/* =============================================================
 * ECC 相关函数
 * ============================================================= */
unsigned int TSAPI_SKF_GenECCKeyPair(void *hContainer, unsigned int ulAlgId, 
                                    ECCPUBLICKEYBLOB *pBlob)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GenECCKeyPair == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GenECCKeyPair(hContainer, ulAlgId, pBlob);
}

unsigned int TSAPI_SKF_ImportECCKeyPair(void *hContainer, ENVELOPEDKEYBLOB *pEnvelopedKeyBlob)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ImportECCKeyPair == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ImportECCKeyPair(hContainer, pEnvelopedKeyBlob);
}

unsigned int TSAPI_SKF_ECCSignData(void *hContainer, unsigned char *pbDigest, 
                                  unsigned int ulDigestLen, ECCSIGNATUREBLOB *pSignature)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ECCSignData == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ECCSignData(hContainer, pbDigest, ulDigestLen, pSignature);
}

unsigned int TSAPI_SKF_ECCVerify(void *hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, 
                                unsigned char *pbData, unsigned int ulDataLen, 
                                ECCSIGNATUREBLOB *pSignature)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ECCVerify == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ECCVerify(hDev, pECCPubKeyBlob, pbData, ulDataLen, pSignature);
}

unsigned int TSAPI_SKF_ECCExportSessionKey(void *hContainer, unsigned int ulAlgId, 
                                          ECCPUBLICKEYBLOB *pPubKey, 
                                          ECCCIPHERBLOB *pData, void **phSessionKey)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ECCExportSessionKey == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ECCExportSessionKey(hContainer, ulAlgId, pPubKey, pData, phSessionKey);
}

unsigned int TSAPI_SKF_ExtECCEncrypt(void *hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, 
                                    unsigned char *pbPlainText, unsigned int ulPlainTextLen, 
                                    ECCCIPHERBLOB *pCipherText)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ExtECCEncrypt == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ExtECCEncrypt(hDev, pECCPubKeyBlob, pbPlainText, ulPlainTextLen, pCipherText);
}

unsigned int TSAPI_SKF_ExtECCDecrypt(void *hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob, 
                                    ECCCIPHERBLOB *pCipherText, unsigned char *pbPlainText, 
                                    unsigned int *pulPlainTextLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ExtECCDecrypt == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ExtECCDecrypt(hDev, pECCPriKeyBlob, pCipherText, pbPlainText, pulPlainTextLen);
}

unsigned int TSAPI_SKF_ExtECCSign(void *hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob, 
                                 unsigned char *pbData, unsigned int ulDataLen, 
                                 ECCSIGNATUREBLOB *pSignature)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ExtECCSign == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ExtECCSign(hDev, pECCPriKeyBlob, pbData, ulDataLen, pSignature);
}

unsigned int TSAPI_SKF_ExtECCVerify(void *hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, 
                                   unsigned char *pbData, unsigned int ulDataLen, 
                                   ECCSIGNATUREBLOB *pSignature)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ExtECCVerify == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ExtECCVerify(hDev, pECCPubKeyBlob, pbData, ulDataLen, pSignature);
}

unsigned int TSAPI_SKF_GenerateAgreementDataWithECC(void *hContainer, 
                                                   unsigned int ulAlgId, 
                                                   ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, 
                                                   unsigned char *pbID, 
                                                   unsigned int ulIDLen, 
                                                   void **phAgreementHandle)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GenerateAgreementDataWithECC == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GenerateAgreementDataWithECC(hContainer, ulAlgId, pTempECCPubKeyBlob, 
                                             pbID, ulIDLen, phAgreementHandle);
}

unsigned int TSAPI_SKF_GenerateAgreementDataAndKeyWithECC(void *hContainer, 
                                                         unsigned int ulAlgId, 
                                                         ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob, 
                                                         ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob, 
                                                         ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, 
                                                         unsigned char *pbID, 
                                                         unsigned int ulIDLen, 
                                                         unsigned char *pbSponsorID, 
                                                         unsigned int ulSponsorIDLen, 
                                                         void **phKeyHandle)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GenerateAgreementDataAndKeyWithECC == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GenerateAgreementDataAndKeyWithECC(hContainer, ulAlgId, 
                                                   pSponsorECCPubKeyBlob, 
                                                   pSponsorTempECCPubKeyBlob, 
                                                   pTempECCPubKeyBlob, 
                                                   pbID, ulIDLen, 
                                                   pbSponsorID, ulSponsorIDLen, 
                                                   phKeyHandle);
}

unsigned int TSAPI_SKF_GenerateKeyWithECC(void *hAgreementHandle, 
                                         ECCPUBLICKEYBLOB *pECCPubKeyBlob, 
                                         ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, 
                                         unsigned char *pbID, unsigned int ulIDLen, 
                                         void **phKeyHandle)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->GenerateKeyWithECC == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->GenerateKeyWithECC(hAgreementHandle, pECCPubKeyBlob, 
                                   pTempECCPubKeyBlob, pbID, ulIDLen, phKeyHandle);
}

/* =============================================================
 * 密钥管理类函数
 * ============================================================= */
unsigned int TSAPI_SKF_ExportPublicKey(void *hContainer, int bSignFlag, 
                                      unsigned char *pbBlob, unsigned int *pulBlobLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ExportPublicKey == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ExportPublicKey(hContainer, bSignFlag, pbBlob, pulBlobLen);
}

unsigned int TSAPI_SKF_ImportSessionKey(void *hContainer, unsigned int ulAlgId, 
                                       unsigned char *pbWrapedData, 
                                       unsigned int ulWrapedLen, void **phKey)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ImportSessionKey == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ImportSessionKey(hContainer, ulAlgId, pbWrapedData, ulWrapedLen, phKey);
}

unsigned int TSAPI_SKF_SetSymmKey(void *hDev, unsigned char *pbKey, 
                                 unsigned int ulAlgID, void **phKey)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->SetSymmKey == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->SetSymmKey(hDev,phKey,ulAlgID,phKey);
}


unsigned int TSAPI_SKF_EncryptInit(void *hKey, BLOCKCIPHERPARAM EncryptParam)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->EncryptInit == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->EncryptInit(hKey, EncryptParam);
}

unsigned int TSAPI_SKF_Encrypt(void *hKey, unsigned char *pbData, 
                               unsigned int ulDataLen, unsigned char *pbEncryptedData, 
                               unsigned int *pulEncryptedLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->Encrypt == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->Encrypt(hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen);
}

unsigned int TSAPI_SKF_EncryptUpdate(void *hKey, unsigned char *pbData, 
                                     unsigned int ulDataLen, unsigned char *pbEncryptedData, 
                                     unsigned int *pulEncryptedLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->EncryptUpdate == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->EncryptUpdate(hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen);
}

unsigned int TSAPI_SKF_EncryptFinal(void *hKey, unsigned char *pbEncryptedData, 
                                    unsigned int *pulEncryptedDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->EncryptFinal == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->EncryptFinal(hKey, pbEncryptedData, pulEncryptedDataLen);
}

unsigned int TSAPI_SKF_DecryptInit(void *hKey, BLOCKCIPHERPARAM DecryptParam)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DecryptInit == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DecryptInit(hKey, DecryptParam);
}

unsigned int TSAPI_SKF_Decrypt(void *hKey, unsigned char *pbEncryptedData, 
                               unsigned int ulEncryptedLen, unsigned char *pbData, 
                               unsigned int *pulDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->Decrypt == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->Decrypt(hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen);
}

unsigned int TSAPI_SKF_DecryptUpdate(void *hKey, unsigned char *pbEncryptedData, 
                                     unsigned int ulEncryptedLen, unsigned char *pbData, 
                                     unsigned int *pulDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DecryptUpdate == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DecryptUpdate(hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen);
}

unsigned int TSAPI_SKF_DecryptFinal(void *hKey, unsigned char *pbDecryptedData, 
                                    unsigned int *pulDecryptedDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DecryptFinal == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DecryptFinal(hKey, pbDecryptedData, pulDecryptedDataLen);
}

unsigned int TSAPI_SKF_DigestInit(void *hDev, unsigned int ulAlgID, 
                                  ECCPUBLICKEYBLOB *pPubKey, unsigned char *pbID, 
                                  unsigned int ulIDLen, void **phHash)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DigestInit == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DigestInit(hDev, ulAlgID, pPubKey, pbID, ulIDLen, phHash);
}

unsigned int TSAPI_SKF_Digest(void *hHash, unsigned char *pbData, 
                              unsigned int ulDataLen, unsigned char *pbHashData, 
                              unsigned int *pulHashLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->Digest == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->Digest(hHash, pbData, ulDataLen, pbHashData, pulHashLen);
}

unsigned int TSAPI_SKF_DigestUpdate(void *hHash, unsigned char *pbData, 
                                    unsigned int ulDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DigestUpdate == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DigestUpdate(hHash, pbData, ulDataLen);
}

unsigned int TSAPI_SKF_DigestFinal(void *hHash, unsigned char *pHashData, 
                                   unsigned int *pulHashLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->DigestFinal == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->DigestFinal(hHash, pHashData, pulHashLen);
}

unsigned int TSAPI_SKF_MacInit(void *hKey, BLOCKCIPHERPARAM *pMacParam, void **phMac)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->MacInit == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->MacInit(hKey, pMacParam, phMac);
}

unsigned int TSAPI_SKF_Mac(void *hMac, unsigned char *pbData, 
                           unsigned int ulDataLen, unsigned char *pbMacData, 
                           unsigned int *pulMacLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->Mac == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->Mac(hMac, pbData, ulDataLen, pbMacData, pulMacLen);
}

unsigned int TSAPI_SKF_MacUpdate(void *hMac, unsigned char *pbData, 
                                 unsigned int ulDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->MacUpdate == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->MacUpdate(hMac, pbData, ulDataLen);
}

unsigned int TSAPI_SKF_MacFinal(void *hMac, unsigned char *pbMacData, 
                                unsigned int *pulMacDataLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->MacFinal == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->MacFinal(hMac, pbMacData, pulMacDataLen);
}

unsigned int TSAPI_SKF_CloseHandle(void *hvoid *)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->CloseHandle == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->CloseHandle(hvoid *);
}

/* SKF Extention API */
unsigned int TSAPI_SKF_AuthDev(void *hDev)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->AuthDev == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->AuthDev(hDev);
}

unsigned int TSAPI_SKF_ECCDecrypt(void *hContainer, int bSignFlag, 
                                  ECCCIPHERBLOB *pCipherBlob, unsigned char *pbPlainText, 
                                  unsigned int *pulPlainTextLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->ECCDecrypt == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->ECCDecrypt(hContainer, bSignFlag, pCipherBlob, pbPlainText, pulPlainTextLen);
}

unsigned int TSAPI_SKF_RSADecrypt(void *hContainer, unsigned char *pbCipherText, 
                                  unsigned int ulCipherTextLen, unsigned char *pbPlainText, 
                                  unsigned int *pulPlainTextLen)
{
    const SKF_METHOD *meth = skf_get_method();
    if (meth == NULL || meth->RSADecrypt == NULL)
        return SAR_NOTSUPPORTYETERR;
    return meth->RSADecrypt(hContainer, pbCipherText, ulCipherTextLen, pbPlainText, pulPlainTextLen);
}