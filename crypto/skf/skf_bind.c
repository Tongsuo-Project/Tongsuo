#include <stdio.h>
#include "sdf_bind.h"
#include "internal/dso.h"
#include <openssl/types.h>
#include "skf_local.h"

// OK

SKF_WaitForDevEvent_fn WaitForDevEvent=NULL;
SKF_CancelWaitForDevEvent_fn CancelWaitForDevEvent=NULL;
SKF_EnumDev_fn EnumDev=NULL;
SKF_ConnectDev_fn ConnectDev=NULL;
SKF_DisConnectDev_fn DisConnectDev=NULL;
SKF_GetDevState_fn GetDevState=NULL;
SKF_SetLabel_fn SetLabel=NULL;
SKF_GetDevInfo_fn GetDevInfo=NULL;
SKF_LockDev_fn LockDev=NULL;
SKF_UnlockDev_fn UnlockDev=NULL;
SKF_Transmit_fn Transmit=NULL;

// Access Control
SKF_ChangeDevAuthKey_fn ChangeDevAuthKey=NULL;
SKF_DevAuth_fn DevAuth=NULL;
SKF_ChangePIN_fn ChangePIN=NULL;
SKF_GetPINInfo_fn GetPINInfo=NULL;
SKF_VerifyPIN_fn VerifyPIN=NULL;
SKF_UnblockPIN_fn UnblockPIN=NULL;
SKF_ClearSecureState_fn ClearSecureState=NULL;

/* Application Management Functions */
SKF_CreateApplication_fn CreateApplication=NULL;
SKF_EnumApplication_fn EnumApplication=NULL;
SKF_DeleteApplication_fn DeleteApplication=NULL;
SKF_OpenApplication_fn OpenApplication=NULL;
SKF_CloseApplication_fn CloseApplication=NULL;

/* File Management Functions */
SKF_CreateFile_fn CreateFile=NULL;
SKF_DeleteFile_fn DeleteFile=NULL;
SKF_EnumFiles_fn EnumFiles=NULL;
SKF_GetFileInfo_fn GetFileInfo=NULL;
SKF_ReadFile_fn ReadFile=NULL;
SKF_WriteFile_fn WriteFile=NULL;

/* Container Management Functions */
SKF_CreateContainer_fn CreateContainer=NULL;
SKF_DeleteContainer_fn DeleteContainer=NULL;
SKF_EnumContainer_fn EnumContainer=NULL;
SKF_OpenContainer_fn OpenContainer=NULL;
SKF_CloseContainer_fn CloseContainer=NULL;
SKF_GetContainerType_fn GetContainerType=NULL;
SKF_ImportCertificate_fn ImportCertificate=NULL;
SKF_ExportCertificate_fn ExportCertificate=NULL;

/* Crypto Service */
SKF_GenRandom_fn GenRandom=NULL;

/* RSA Functions */
SKF_GenExtRSAKey_fn GenExtRSAKey=NULL;
SKF_GenRSAKeyPair_fn GenRSAKeyPair=NULL;
SKF_ImportRSAKeyPair_fn ImportRSAKeyPair=NULL;
SKF_RSASignData_fn RSASignData=NULL;
SKF_RSAVerify_fn RSAVerify=NULL;
SKF_RSAExportSessionKey_fn RSAExportSessionKey=NULL;
SKF_ExtRSAPubKeyOperation_fn ExtRSAPubKeyOperation=NULL;
SKF_ExtRSAPriKeyOperation_fn ExtRSAPriKeyOperation=NULL;

/* ECC Functions */
SKF_GenECCKeyPair_fn GenECCKeyPair=NULL;
SKF_ImportECCKeyPair_fn ImportECCKeyPair=NULL;
SKF_ECCSignData_fn ECCSignData=NULL;
SKF_ECCVerify_fn ECCVerify=NULL;
SKF_ECCExportSessionKey_fn ECCExportSessionKey=NULL;
SKF_ExtECCEncrypt_fn ExtECCEncrypt=NULL;
SKF_ExtECCDecrypt_fn ExtECCDecrypt=NULL;
SKF_ExtECCSign_fn ExtECCSign=NULL;
SKF_ExtECCVerify_fn ExtECCVerify=NULL;
SKF_GenerateAgreementDataWithECC_fn GenerateAgreementDataWithECC=NULL;
SKF_GenerateAgreementDataAndKeyWithECC_fn GenerateAgreementDataAndKeyWithECC=NULL;
SKF_GenerateKeyWithECC_fn GenerateKeyWithECC=NULL;

/* Key Management Functions */
SKF_ExportPublicKey_fn ExportPublicKey=NULL;
SKF_ImportSessionKey_fn ImportSessionKey=NULL;
SKF_SetSymmKey_fn SetSymmKey=NULL;

/* Cryptographic Operations */
SKF_EncryptInit_fn EncryptInit=NULL;
SKF_Encrypt_fn Encrypt=NULL;
SKF_EncryptUpdate_fn EncryptUpdate=NULL;
SKF_EncryptFinal_fn EncryptFinal=NULL;
SKF_DecryptInit_fn DecryptInit=NULL;
SKF_Decrypt_fn Decrypt=NULL;
SKF_DecryptUpdate_fn DecryptUpdate=NULL;
SKF_DecryptFinal_fn DecryptFinal=NULL;

/* Hash Functions */
SKF_DigestInit_fn DigestInit=NULL;
SKF_Digest_fn Digest=NULL;
SKF_DigestUpdate_fn DigestUpdate=NULL;
SKF_DigestFinal_fn DigestFinal=NULL;

/* MAC Functions */
SKF_MacInit_fn MacInit=NULL;
SKF_Mac_fn Mac=NULL;
SKF_MacUpdate_fn MacUpdate=NULL;
SKF_MacFinal_fn MacFinal=NULL;

/* Handle Management */
SKF_CloseHandle_fn CloseHandle=NULL;

/* Extension Functions */
// SKF_AuthDev_fn AuthDev=NULL;
// SKF_ECCDecrypt_fn ECCDecrypt=NULL;
// SKF_RSADecrypt_fn RSADecrypt=NULL;

int skf_bind_init(SDF_METHOD *skfm,DSO *dso) {
    if (skfm == NULL) {
        fprintf(stderr, "SDF_METHOD pointer is NULL\n");
        return -1;
    }
    if (dso == NULL) {
        fprintf(stderr, "DSO object is NULL\n");
        return -1;
    }
    skfm->WaitForDevEvent = (SKF_WaitForDevEvent_fn)DSO_bind_func(dso, "SKF_WaitForDevEvent");
    skfm->CancelWaitForDevEvent = (SKF_CancelWaitForDevEvent_fn)DSO_bind_func(dso, "SKF_CancelWaitForDevEvent");
    skfm->EnumDev = (SKF_EnumDev_fn)DSO_bind_func(dso, "SKF_EnumDev");
    skfm->ConnectDev = (SKF_ConnectDev_fn)DSO_bind_func(dso, "SKF_ConnectDev");
    skfm->DisConnectDev = (SKF_DisConnectDev_fn)DSO_bind_func(dso, "SKF_DisConnectDev");
    skfm->GetDevState = (SKF_GetDevState_fn)DSO_bind_func(dso, "SKF_GetDevState");
    skfm->SetLabel = (SKF_SetLabel_fn)DSO_bind_func(dso, "SKF_SetLabel");
    skfm->GetDevInfo = (SKF_GetDevInfo_fn)DSO_bind_func(dso, "SKF_GetDevInfo");
    skfm->LockDev = (SKF_LockDev_fn)DSO_bind_func(dso, "SKF_LockDev");
    skfm->UnlockDev = (SKF_UnlockDev_fn)DSO_bind_func(dso, "SKF_UnlockDev");
    skfm->Transmit = (SKF_Transmit_fn)DSO_bind_func(dso, "SKF_Transmit");

    // Access Control
    skfm->ChangeDevAuthKey = (SKF_ChangeDevAuthKey_fn)DSO_bind_func(dso, "SKF_ChangeDevAuthKey");
    skfm->DevAuth = (SKF_DevAuth_fn)DSO_bind_func(dso, "SKF_DevAuth");
    skfm->ChangePIN = (SKF_ChangePIN_fn)DSO_bind_func(dso, "SKF_ChangePIN");
    skfm->GetPINInfo = (SKF_GetPINInfo_fn)DSO_bind_func(dso, "SKF_GetPINInfo");
    skfm->VerifyPIN = (SKF_VerifyPIN_fn)DSO_bind_func(dso, "SKF_VerifyPIN");
    skfm->UnblockPIN = (SKF_UnblockPIN_fn)DSO_bind_func(dso, "SKF_UnblockPIN");
    skfm->ClearSecureState = (SKF_ClearSecureState_fn)DSO_bind_func(dso, "SKF_ClearSecureState");

    /* Application Management Functions */
    skfm->CreateApplication = (SKF_CreateApplication_fn)DSO_bind_func(dso, "SKF_CreateApplication");
    skfm->EnumApplication = (SKF_EnumApplication_fn)DSO_bind_func(dso, "SKF_EnumApplication");
    skfm->DeleteApplication = (SKF_DeleteApplication_fn)DSO_bind_func(dso, "SKF_DeleteApplication");
    skfm->OpenApplication = (SKF_OpenApplication_fn)DSO_bind_func(dso, "SKF_OpenApplication");
    skfm->CloseApplication = (SKF_CloseApplication_fn)DSO_bind_func(dso, "SKF_CloseApplication");

    /* File Management Functions */
    skfm->CreateFile = (SKF_CreateFile_fn)DSO_bind_func(dso, "SKF_CreateFile");
    skfm->DeleteFile = (SKF_DeleteFile_fn)DSO_bind_func(dso, "SKF_DeleteFile");
    skfm->EnumFiles = (SKF_EnumFiles_fn)DSO_bind_func(dso, "SKF_EnumFiles");
    skfm->GetFileInfo = (SKF_GetFileInfo_fn)DSO_bind_func(dso, "SKF_GetFileInfo");
    skfm->ReadFile = (SKF_ReadFile_fn)DSO_bind_func(dso, "SKF_ReadFile");
    skfm->WriteFile = (SKF_WriteFile_fn)DSO_bind_func(dso, "SKF_WriteFile");

    /* Container Management Functions */
    skfm->CreateContainer = (SKF_CreateContainer_fn)DSO_bind_func(dso, "SKF_CreateContainer");
    skfm->DeleteContainer = (SKF_DeleteContainer_fn)DSO_bind_func(dso, "SKF_DeleteContainer");
    skfm->EnumContainer = (SKF_EnumContainer_fn)DSO_bind_func(dso, "SKF_EnumContainer");
    skfm->OpenContainer = (SKF_OpenContainer_fn)DSO_bind_func(dso, "SKF_OpenContainer");
    skfm->CloseContainer = (SKF_CloseContainer_fn)DSO_bind_func(dso, "SKF_CloseContainer");
    skfm->GetContainerType = (SKF_GetContainerType_fn)DSO_bind_func(dso, "SKF_GetContainerType");
    skfm->ImportCertificate = (SKF_ImportCertificate_fn)DSO_bind_func(dso, "SKF_ImportCertificate");
    skfm->ExportCertificate = (SKF_ExportCertificate_fn)DSO_bind_func(dso, "SKF_ExportCertificate");

    /* Crypto Service */
    skfm->GenRandom = (SKF_GenRandom_fn)DSO_bind_func(dso, "SKF_GenRandom");

    /* RSA Functions */
    skfm->GenExtRSAKey = (SKF_GenExtRSAKey_fn)DSO_bind_func(dso, "SKF_GenExtRSAKey");
    skfm->GenRSAKeyPair = (SKF_GenRSAKeyPair_fn)DSO_bind_func(dso, "SKF_GenRSAKeyPair");
    skfm->ImportRSAKeyPair = (SKF_ImportRSAKeyPair_fn)DSO_bind_func(dso, "SKF_ImportRSAKeyPair");
    skfm->RSASignData = (SKF_RSASignData_fn)DSO_bind_func(dso, "SKF_RSASignData");
    skfm->RSAVerify = (SKF_RSAVerify_fn)DSO_bind_func(dso, "SKF_RSAVerify");
    skfm->RSAExportSessionKey = (SKF_RSAExportSessionKey_fn)DSO_bind_func(dso, "SKF_RSAExportSessionKey");
    skfm->ExtRSAPubKeyOperation = (SKF_ExtRSAPubKeyOperation_fn)DSO_bind_func(dso, "SKF_ExtRSAPubKeyOperation");
    skfm->ExtRSAPriKeyOperation = (SKF_ExtRSAPriKeyOperation_fn)DSO_bind_func(dso, "SKF_ExtRSAPriKeyOperation");

    /* ECC Functions */
    skfm->GenECCKeyPair = (SKF_GenECCKeyPair_fn)DSO_bind_func(dso, "SKF_GenECCKeyPair");
    skfm->ImportECCKeyPair = (SKF_ImportECCKeyPair_fn)DSO_bind_func(dso, "SKF_ImportECCKeyPair");
    skfm->ECCSignData = (SKF_ECCSignData_fn)DSO_bind_func(dso, "SKF_ECCSignData");
    skfm->ECCVerify = (SKF_ECCVerify_fn)DSO_bind_func(dso, "SKF_ECCVerify");
    skfm->ECCExportSessionKey = (SKF_ECCExportSessionKey_fn)DSO_bind_func(dso, "SKF_ECCExportSessionKey");
    skfm->ExtECCEncrypt = (SKF_ExtECCEncrypt_fn)DSO_bind_func(dso, "SKF_ExtECCEncrypt");
    skfm->ExtECCDecrypt = (SKF_ExtECCDecrypt_fn)DSO_bind_func(dso, "SKF_ExtECCDecrypt");
    skfm->ExtECCSign = (SKF_ExtECCSign_fn)DSO_bind_func(dso, "SKF_ExtECCSign");
    skfm->ExtECCVerify = (SKF_ExtECCVerify_fn)DSO_bind_func(dso, "SKF_ExtECCVerify");
    skfm->GenerateAgreementDataWithECC = (SKF_GenerateAgreementDataWithECC_fn)DSO_bind_func(dso, "SKF_GenerateAgreementDataWithECC");
    skfm->GenerateAgreementDataAndKeyWithECC = (SKF_GenerateAgreementDataAndKeyWithECC_fn)DSO_bind_func(dso, "SKF_GenerateAgreementDataAndKeyWithECC");
    skfm->GenerateKeyWithECC = (SKF_GenerateKeyWithECC_fn)DSO_bind_func(dso, "SKF_GenerateKeyWithECC");

    /* Key Management Functions */
    skfm->ExportPublicKey = (SKF_ExportPublicKey_fn)DSO_bind_func(dso, "SKF_ExportPublicKey");
    skfm->ImportSessionKey = (SKF_ImportSessionKey_fn)DSO_bind_func(dso, "SKF_ImportSessionKey");
    skfm->SetSymmKey = (SKF_SetSymmKey_fn)DSO_bind_func(dso, "SKF_SetSymmKey");

    /* Cryptographic Operations */
    skfm->EncryptInit = (SKF_EncryptInit_fn)DSO_bind_func(dso, "SKF_EncryptInit");
    skfm->Encrypt = (SKF_Encrypt_fn)DSO_bind_func(dso, "SKF_Encrypt");
    skfm->EncryptUpdate = (SKF_EncryptUpdate_fn)DSO_bind_func(dso, "SKF_EncryptUpdate");
    skfm->EncryptFinal = (SKF_EncryptFinal_fn)DSO_bind_func(dso, "SKF_EncryptFinal");
    skfm->DecryptInit = (SKF_DecryptInit_fn)DSO_bind_func(dso, "SKF_DecryptInit");
    skfm->Decrypt = (SKF_Decrypt_fn)DSO_bind_func(dso, "SKF_Decrypt");
    skfm->DecryptUpdate = (SKF_DecryptUpdate_fn)DSO_bind_func(dso, "SKF_DecryptUpdate");
    skfm->DecryptFinal = (SKF_DecryptFinal_fn)DSO_bind_func(dso, "SKF_DecryptFinal");
    /* Hash Functions */
    skfm->DigestInit = (SKF_DigestInit_fn)DSO_bind_func(dso, "SKF_DigestInit");
    skfm->Digest = (SKF_Digest_fn)DSO_bind_func(dso, "SKF_Digest");
    skfm->DigestUpdate = (SKF_DigestUpdate_fn)DSO_bind_func(dso, "SKF_DigestUpdate");
    skfm->DigestFinal = (SKF_DigestFinal_fn)DSO_bind_func(dso, "SKF_DigestFinal");
    /* MAC Functions */
    skfm->MacInit = (SKF_MacInit_fn)DSO_bind_func(dso, "SKF_MacInit");
    skfm->Mac = (SKF_Mac_fn)DSO_bind_func(dso, "SKF_Mac");
    skfm->MacUpdate = (SKF_MacUpdate_fn)DSO_bind_func(dso, "SKF_MacUpdate");
    skfm->MacFinal = (SKF_MacFinal_fn)DSO_bind_func(dso, "SKF_MacFinal");
    /* Handle Management */
    skfm->CloseHandle = (SKF_CloseHandle_fn)DSO_bind_func(dso, "SKF_CloseHandle");
    return 0;
}