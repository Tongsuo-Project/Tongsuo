#include <stdio.h>
#include "sdf_bind.h"
#include "internal/dso.h"
#include <openssl/types.h>
#include "sdf_local.h"

// OK


SDF_OpenDevice_fn  OpenDevice = NULL;
SDF_CloseDevice_fn  CloseDevice = NULL;
SDF_OpenSession_fn  OpenSession = NULL;
SDF_CloseSession_fn  CloseSession = NULL;
SDF_GetDeviceInfo_fn  GetDeviceInfo = NULL;
SDF_GenerateRandom_fn  GenerateRandom = NULL;
SDF_GetPrivateKeyAccessRight_fn  GetPrivateKeyAccessRight = NULL;
SDF_ReleasePrivateKeyAccessRight_fn  ReleasePrivateKeyAccessRight = NULL;
SDF_ExportSignPublicKey_RSA_fn  ExportSignPublicKey_RSA = NULL;
SDF_ExportEncPublicKey_RSA_fn  ExportEncPublicKey_RSA = NULL;
SDF_GenerateKeyPair_RSA_fn GenerateKeyPair_RSA = NULL; //

SDF_GenerateKeyWithIPK_RSA_fn  GenerateKeyWithIPK_RSA = NULL;
SDF_GenerateKeyWithEPK_RSA_fn  GenerateKeyWithEPK_RSA = NULL;
SDF_ImportKeyWithISK_RSA_fn  ImportKeyWithISK_RSA= NULL;
SDF_ExchangeDigitEnvelopeBaseOnRSA_fn ExchangeDigitEnvelopeBaseOnRSA = NULL; //
SDF_ExportSignPublicKey_ECC_fn  ExportSignPublicKey_ECC = NULL;
SDF_ExportEncPublicKey_ECC_fn  ExportEncPublicKey_ECC = NULL;
SDF_GenerateKeyPair_ECC_fn SDF_GenerateKeyPair_ECC = NULL; //

SDF_GenerateKeyWithIPK_ECC_fn  GenerateKeyWithIPK_ECC = NULL;
SDF_GenerateKeyWithEPK_ECC_fn  GenerateKeyWithEPK_ECC = NULL;
SDF_ImportKeyWithISK_ECC_fn  ImportKeyWithISK_ECC = NULL;
SDF_GenerateAgreementDataWithECC_fn  GenerateAgreementDataWithECC = NULL;
SDF_GenerateKeyWithECC_fn  GenerateKeyWithECC = NULL;
SDF_GenerateAgreementDataAndKeyWithECC_fn  GenerateAgreementDataAndKeyWithECC = NULL;
SDF_ExchangeDigitEnvelopeBaseOnECC_fn SDF_ExchangeDigitEnvelopeBaseOnECC = NULL; //

SDF_GenerateKeyWithKEK_fn  GenerateKeyWithKEK = NULL;
SDF_ImportKeyWithKEK_fn  ImportKeyWithKEK = NULL;
SDF_DestroyKey_fn  DestroyKey = NULL;
SDF_ExternalPublicKeyOperation_RSA_fn  ExternalPublicKeyOperation_RSA = NULL;
SDF_InternalPublicKeyOperation_RSA_fn  InternalPublicKeyOperation_RSA = NULL;
SDF_InternalPrivateKeyOperation_RSA_fn  InternalPrivateKeyOperation_RSA = NULL;
SDF_ExternalVerify_ECC_fn  ExternalVerify_ECC = NULL;
SDF_InternalSign_ECC_fn  InternalSign_ECC = NULL;
SDF_InternalVerify_ECC_fn  InternalVerify_ECC = NULL;
SDF_ExternalEncrypt_ECC_fn  ExternalEncrypt_ECC = NULL;
SDF_Encrypt_fn  Encrypt = NULL;
SDF_Decrypt_fn  Decrypt = NULL;
SDF_CalculateMAC_fn  CalculateMAC = NULL;
#ifdef SDF_VERSION_2023 

SDF_AuthEnc_fn  AuthEnc = NULL;
SDF_AuthDec_fn  AuthDec = NULL;
SDF_EncryptInit_fn  EncryptInit = NULL;
SDF_EncryptUpdate_fn  EncryptUpdate = NULL;
SDF_EncryptFinal_fn  EncryptFinal = NULL;
SDF_DecryptInit_fn  DecryptInit = NULL;
SDF_DecryptUpdate_fn  DecryptUpdate = NULL;
SDF_DecryptFinal_fn  DecryptFinal = NULL;
SDF_CalculateMACInit_fn  CalculateMACInit = NULL;
SDF_CalculateMACUpdate_fn  CalculateMACUpdate = NULL;
SDF_CalculateMACFinal_fn  CalculateMACFinal = NULL;
SDF_AuthEncInit_fn  AuthEncInit = NULL;
SDF_AuthEncUpdate_fn  AuthEncUpdate = NULL;
SDF_AuthEncFinal_fn  AuthEncFinal = NULL;
SDF_AuthDecInit_fn  AuthDecInit = NULL;
SDF_AuthDecUpdate_fn  AuthDecUpdate = NULL;
SDF_AuthDecFinal_fn  AuthDecFinal = NULL;
SDF_HMACInit_fn  HMACInit = NULL;
SDF_HMACUpdate_fn  HMACUpdate = NULL;
SDF_HMACFinal_fn  HMACFinal = NULL;
SDF_HashInit_fn  HashInit = NULL;
SDF_HashUpdate_fn  HashUpdate = NULL;
SDF_HashFinal_fn  HashFinal = NULL;
SDF_CreateFile_fn  CreateFile = NULL;
SDF_ReadFile_fn  ReadFile = NULL;
SDF_WriteFile_fn  WriteFile = NULL;
SDF_DeleteFile_fn  DeleteFile = NULL;
#endif

#ifdef SDF_VERSION_2023 
SDF_GenerateKeyPair_RSA_fn  GenerateKeyPair_RSA = NULL;
SDF_GenerateKeyPair_ECC_fn  GenerateKeyPair_ECC = NULL;
SDF_ExternalPrivateKeyOperation_RSA_fn  ExternalPrivateKeyOperation_RSA = NULL;
SDF_ExternalSign_ECC_fn  ExternalSign_ECC = NULL;
SDF_ExternalDecrypt_ECC_fn  ExternalDecrypt_ECC = NULL;
SDF_ExternalSign_SM9_fn  ExternalSign_SM9 = NULL;
SDF_ExternalDecrypt_SM9_fn  ExternalDecrypt_SM9 = NULL;
SDF_ExternalKeyEncrypt_fn  ExternalKeyEncrypt = NULL;
SDF_ExternalKeyDecrypt_fn  ExternalKeyDecrypt = NULL;
SDF_ExternalKeyEncryptInit_fn  ExternalKeyEncryptInit = NULL;
SDF_ExternalKeyDecryptInit_fn  ExternalKeyDecryptInit = NULL;
SDF_ExternalKeyHMACInit_fn  ExternalKeyHMACInit = NULL;
#endif

int sdf_bind_init(SDF_METHOD *sdfm,DSO *dso) {
    if (sdfm == NULL) {
        fprintf(stderr, "SDF_METHOD pointer is NULL\n");
        return -1;
    }
    if (dso == NULL) {
        fprintf(stderr, "DSO object is NULL\n");
        return -1;
    }
    sdfm->OpenDevice = (SDF_OpenDevice_fn)DSO_bind_func(dso, "SDF_OpenDevice");
    sdfm->CloseDevice = (SDF_CloseDevice_fn)DSO_bind_func(dso, "SDF_CloseDevice");
    sdfm->OpenSession = (SDF_OpenSession_fn)DSO_bind_func(dso, "SDF_OpenSession");
    sdfm->CloseSession = (SDF_CloseSession_fn)DSO_bind_func(dso, "SDF_CloseSession");
    sdfm->GetDeviceInfo = (SDF_GetDeviceInfo_fn)DSO_bind_func(dso, "SDF_GetDeviceInfo");
    sdfm->GenerateRandom = (SDF_GenerateRandom_fn)DSO_bind_func(dso, "SDF_GenerateRandom");
    sdfm->GetPrivateKeyAccessRight = (SDF_GetPrivateKeyAccessRight_fn)DSO_bind_func(dso, "SDF_GetPrivateKeyAccessRight");
    sdfm->ReleasePrivateKeyAccessRight = (SDF_ReleasePrivateKeyAccessRight_fn)DSO_bind_func(dso, "SDF_ReleasePrivateKeyAccessRight");
    sdfm->ExportSignPublicKey_RSA = (SDF_ExportSignPublicKey_RSA_fn)DSO_bind_func(dso, "SDF_ExportSignPublicKey_RSA");
    sdfm->ExportEncPublicKey_RSA = (SDF_ExportEncPublicKey_RSA_fn)DSO_bind_func(dso, "SDF_ExportEncPublicKey_RSA");
    sdfm->GenerateKeyPair_RSA = (SDF_GenerateKeyPair_RSA_fn)DSO_bind_func(dso, "SDF_GenerateKeyPair_RSA"); //
    sdfm->GenerateKeyWithIPK_RSA = (SDF_GenerateKeyWithIPK_RSA_fn)DSO_bind_func(dso, "SDF_GenerateKeyWithIPK_RSA");
    sdfm->GenerateKeyWithEPK_RSA = (SDF_GenerateKeyWithEPK_RSA_fn)DSO_bind_func(dso, "SDF_GenerateKeyWithEPK_RSA");
    sdfm->ImportKeyWithISK_RSA = (SDF_ImportKeyWithISK_RSA_fn)DSO_bind_func(dso, "SDF_ImportKeyWithISK_RSA");
    sdfm->ExchangeDigitEnvelopeBaseOnRSA = (SDF_ExchangeDigitEnvelopeBaseOnRSA_fn)DSO_bind_func(dso, "SDF_ExchangeDigitEnvelopeBaseOnRSA"); //
    sdfm->ExportSignPublicKey_ECC = (SDF_ExportSignPublicKey_ECC_fn)DSO_bind_func(dso, "SDF_ExportSignPublicKey_ECC");
    sdfm->ExportEncPublicKey_ECC = (SDF_ExportEncPublicKey_ECC_fn)DSO_bind_func(dso, "SDF_ExportEncPublicKey_ECC");
    sdfm->GenerateKeyPair_ECC = (SDF_GenerateKeyPair_ECC_fn)DSO_bind_func(dso, "SDF_GenerateKeyPair_ECC"); //
    sdfm->GenerateKeyWithIPK_ECC = (SDF_GenerateKeyWithIPK_ECC_fn)DSO_bind_func(dso, "SDF_GenerateKeyWithIPK_ECC");
    sdfm->GenerateKeyWithEPK_ECC = (SDF_GenerateKeyWithEPK_ECC_fn)DSO_bind_func(dso, "SDF_GenerateKeyWithEPK_ECC");
    sdfm->ImportKeyWithISK_ECC = (SDF_ImportKeyWithISK_ECC_fn)DSO_bind_func(dso, "SDF_ImportKeyWithISK_ECC");
    sdfm->GenerateAgreementDataWithECC = (SDF_GenerateAgreementDataWithECC_fn)DSO_bind_func(dso, "SDF_GenerateAgreementDataWithECC");
    sdfm->GenerateKeyWithECC = (SDF_GenerateKeyWithECC_fn)DSO_bind_func(dso, "SDF_GenerateKeyWithECC");
    sdfm->GenerateAgreementDataAndKeyWithECC = (SDF_GenerateAgreementDataAndKeyWithECC_fn)DSO_bind_func(dso, "SDF_GenerateAgreementDataAndKeyWithECC");
    sdfm->ExchangeDigitEnvelopeBaseOnECC =  (SDF_ExchangeDigitEnvelopeBaseOnECC_fn)DSO_bind_func(dso, "SDF_ExchangeDigitEnvelopeBaseOnECC");  //    
    sdfm->GenerateKeyWithKEK = (SDF_GenerateKeyWithKEK_fn)DSO_bind_func(dso, "SDF_GenerateKeyWithKEK");
    sdfm->ImportKeyWithKEK = (SDF_ImportKeyWithKEK_fn)DSO_bind_func(dso, "SDF_ImportKeyWithKEK");
    sdfm->DestroyKey = (SDF_DestroyKey_fn)DSO_bind_func(dso, "SDF_DestroyKey");
    sdfm->ExternalPublicKeyOperation_RSA = (SDF_ExternalPublicKeyOperation_RSA_fn)DSO_bind_func(dso, "SDF_ExternalPublicKeyOperation_RSA");
    sdfm->InternalPublicKeyOperation_RSA = (SDF_InternalPublicKeyOperation_RSA_fn)DSO_bind_func(dso, "SDF_InternalPublicKeyOperation_RSA");
    sdfm->InternalPrivateKeyOperation_RSA = (SDF_InternalPrivateKeyOperation_RSA_fn)DSO_bind_func(dso, "SDF_InternalPrivateKeyOperation_RSA");
    sdfm->ExternalVerify_ECC = (SDF_ExternalVerify_ECC_fn)DSO_bind_func(dso, "SDF_ExternalVerify_ECC");
    sdfm->InternalSign_ECC = (SDF_InternalSign_ECC_fn)DSO_bind_func(dso, "SDF_InternalSign_ECC");
    sdfm->InternalVerify_ECC = (SDF_InternalVerify_ECC_fn)DSO_bind_func(dso, "SDF_InternalVerify_ECC");
    sdfm->ExternalEncrypt_ECC = (SDF_ExternalEncrypt_ECC_fn)DSO_bind_func(dso, "SDF_ExternalEncrypt_ECC");
    sdfm->Encrypt = (SDF_Encrypt_fn)DSO_bind_func(dso, "SDF_Encrypt");
    sdfm->Decrypt = (SDF_Decrypt_fn)DSO_bind_func(dso, "SDF_Decrypt");
    sdfm->CalculateMAC = (SDF_CalculateMAC_fn)DSO_bind_func(dso, "SDF_CalculateMAC");
    #ifdef SDF_VERSION_2023 
    sdfm->AuthEnc = (SDF_AuthEnc_fn)DSO_bind_func(dso, "SDF_AuthEnc");
    sdfm->AuthDec = (SDF_AuthDec_fn)DSO_bind_func(dso, "SDF_AuthDec");
    sdfm->EncryptInit = (SDF_EncryptInit_fn)DSO_bind_func(dso, "SDF_EncryptInit");
    sdfm->EncryptUpdate = (SDF_EncryptUpdate_fn)DSO_bind_func(dso, "SDF_EncryptUpdate");
    sdfm->EncryptFinal = (SDF_EncryptFinal_fn)DSO_bind_func(dso, "SDF_EncryptFinal");
    sdfm->DecryptInit = (SDF_DecryptInit_fn)DSO_bind_func(dso, "SDF_DecryptInit");
    sdfm->DecryptUpdate = (SDF_DecryptUpdate_fn)DSO_bind_func(dso, "SDF_DecryptUpdate");
    sdfm->DecryptFinal = (SDF_DecryptFinal_fn)DSO_bind_func(dso, "SDF_DecryptFinal");
    sdfm->CalculateMACInit = (SDF_CalculateMACInit_fn)DSO_bind_func(dso, "SDF_CalculateMACInit");
    sdfm->CalculateMACUpdate = (SDF_CalculateMACUpdate_fn)DSO_bind_func(dso, "SDF_CalculateMACUpdate");
    sdfm->CalculateMACFinal = (SDF_CalculateMACFinal_fn)DSO_bind_func(dso, "SDF_CalculateMACFinal");
    sdfm->AuthEncInit = (SDF_AuthEncInit_fn)DSO_bind_func(dso, "SDF_AuthEncInit");
    sdfm->AuthEncUpdate = (SDF_AuthEncUpdate_fn)DSO_bind_func(dso, "SDF_AuthEncUpdate");
    sdfm->AuthEncFinal = (SDF_AuthEncFinal_fn)DSO_bind_func(dso, "SDF_AuthEncFinal");
    sdfm->AuthDecInit = (SDF_AuthDecInit_fn)DSO_bind_func(dso, "SDF_AuthDecInit");
    sdfm->AuthDecUpdate = (SDF_AuthDecUpdate_fn)DSO_bind_func(dso, "SDF_AuthDecUpdate");
    sdfm->AuthDecFinal = (SDF_AuthDecFinal_fn)DSO_bind_func(dso, "SDF_AuthDecFinal");
    sdfm->HMACInit = (SDF_HMACInit_fn)DSO_bind_func(dso, "SDF_HMACInit");
    sdfm->HMACUpdate = (SDF_HMACUpdate_fn)DSO_bind_func(dso, "SDF_HMACUpdate");
    sdfm->HMACFinal = (SDF_HMACFinal_fn)DSO_bind_func(dso, "SDF_HMACFinal");
    #endif
    sdfm->HashInit = (SDF_HashInit_fn)DSO_bind_func(dso, "SDF_HashInit");
    sdfm->HashUpdate = (SDF_HashUpdate_fn)DSO_bind_func(dso, "SDF_HashUpdate");
    sdfm->HashFinal = (SDF_HashFinal_fn)DSO_bind_func(dso, "SDF_HashFinal");
    sdfm->CreateFile = (SDF_CreateFile_fn)DSO_bind_func(dso, "SDF_CreateFile");
    sdfm->ReadFile = (SDF_ReadFile_fn)DSO_bind_func(dso, "SDF_ReadFile");
    sdfm->WriteFile = (SDF_WriteFile_fn)DSO_bind_func(dso, "SDF_WriteFile");
    sdfm->DeleteFile = (SDF_DeleteFile_fn)DSO_bind_func(dso, "SDF_DeleteFile");
    #ifdef SDF_VERSION_2023
    // sdfm->GenerateKeyPair_RSA = (SDF_GenerateKeyPair_RSA_fn)DSO_bind_func(dso, "SDF_GenerateKeyPair_RSA");
    // sdfm->GenerateKeyPair_ECC = (SDF_GenerateKeyPair_ECC_fn)DSO_bind_func(dso, "SDF_GenerateKeyPair_ECC");
    sdfm->ExternalPrivateKeyOperation_RSA = (SDF_ExternalPrivateKeyOperation_RSA_fn)DSO_bind_func(dso, "SDF_ExternalPrivateKeyOperation_RSA");
    sdfm->ExternalSign_ECC = (SDF_ExternalSign_ECC_fn)DSO_bind_func(dso, "SDF_ExternalSign_ECC");
    sdfm->ExternalDecrypt_ECC = (SDF_ExternalDecrypt_ECC_fn)DSO_bind_func(dso, "SDF_ExternalDecrypt_ECC");
    sdfm->ExternalSign_SM9 = (SDF_ExternalSign_SM9_fn)DSO_bind_func(dso, "SDF_ExternalSign_SM9");
    sdfm->ExternalDecrypt_SM9 = (SDF_ExternalDecrypt_SM9_fn)DSO_bind_func(dso, "SDF_ExternalDecrypt_SM9");
    sdfm->ExternalKeyEncrypt = (SDF_ExternalKeyEncrypt_fn)DSO_bind_func(dso, "SDF_ExternalKeyEncrypt");
    sdfm->ExternalKeyDecrypt = (SDF_ExternalKeyDecrypt_fn)DSO_bind_func(dso, "SDF_ExternalKeyDecrypt");
    sdfm->ExternalKeyEncryptInit = (SDF_ExternalKeyEncryptInit_fn)DSO_bind_func(dso, "SDF_ExternalKeyEncryptInit");
    sdfm->ExternalKeyDecryptInit = (SDF_ExternalKeyDecryptInit_fn)DSO_bind_func(dso, "SDF_ExternalKeyDecryptInit");
    sdfm->ExternalKeyHMACInit = (SDF_ExternalKeyHMACInit_fn)DSO_bind_func(dso, "SDF_ExternalKeyHMACInit");
    #endif
    return 0;
}