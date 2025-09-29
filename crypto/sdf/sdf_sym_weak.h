/* Weak declarations for direct-linked SDF symbols.*/

// OK

#ifndef OSSL_CRYPTO_SDF_SYM_WEAK_H
#define OSSL_CRYPTO_SDF_SYM_WEAK_H

#include <stdint.h>
#include <openssl/sdf.h>
#include "sdf_local.h"
extern int SDF_OpenDevice(void **phDeviceHandle) __attribute__((weak));
extern int SDF_CloseDevice(void *hDeviceHandle) __attribute__((weak));
extern int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) __attribute__((weak));
extern int SDF_CloseSession(void *hSessionHandle) __attribute__((weak));
extern int SDF_GetDeviceInfo(void *hDeviceHandle, DEVICEINFO *pstDeviceInfo) __attribute__((weak));
extern int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,unsigned char *pucRandom) __attribute__((weak));
extern int SDF_GetPrivateKeyAccessRight(void *hSessionHandle,unsigned int uiKeyIndex, unsigned char *pucPassword,unsigned int uiPwdLength) __attribute__((weak));
extern int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,unsigned int uiKeyIndex) __attribute__((weak));
extern int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pubPublicKey) __attribute__((weak));
extern int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pubPublicKey) __attribute__((weak));
extern int SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) __attribute__((weak));
extern int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiKeyBits, unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) __attribute__((weak));
extern int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, unsigned char *pubKcy, unsigned int *puiKeyLength, void **phKeyHandle) __attribute__((weak));
extern int SDF_ImportKeyWithISK_RSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey, unsigned int PuiKeyLength, void **phKeyHandle) __attribute__((weak));
extern int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey, unsigned char *pucDEInput, unsigned int uiDELength, unsigned char *pucDEOutput, unsigned int *puiDELength)__attribute__((weak));
extern int SDF_ExportSignPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey)__attribute__((weak));
extern int SDF_ExportEncPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey)__attribute__((weak));
extern int SDF_GenerateKeyPair_ECC(unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey) __attribute__((weak));
extern int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle,
    unsigned int uiIPKIndex, unsigned int uiKeyBits, ECCCipher *pucKey,
    void **phKeyHandle) __attribute__((weak));

extern int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle,
    unsigned int uiKeyBits, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKey, void **phKeyHandle) __attribute__((weak));

extern int SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
    unsigned int uiISKIndex, ECCCipher *pucKey,
    void **phKeyHandle) __attribute__((weak));

extern int SDF_GenerateAgreementDataWithECC(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID,
    unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle) __attribute__((weak));

extern int SDF_GenerateKeyWithECC(void *hSessionHandle,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey,
    void *hAgreementHandle, void **phKeyHandle) __attribute__((weak));

extern int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID,
    unsigned int uiResponseIDLength, unsigned char *pucSponsorID,
    unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle) __attribute__((weak));

extern int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut) __attribute__((weak));
extern int SDF_GenerateKeyWithKEK(void *hSessionHandle,
    unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
    unsigned char *pucKey, unsigned int *puiKeyLength,
    void **phKeyHandle) __attribute__((weak));
extern int SDF_ImportKeyWithKEK(void *hSessionHandle,
    unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
    unsigned int puiKeyLength, void **phKeyHandle) __attribute__((weak));


extern int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
    __attribute__((weak));



extern int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle,RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,unsigned int uiInputLength, unsigned char *pucDataOutput,unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle,unsigned int uiKeyIndex, unsigned char *pucDataInput,unsigned int uiInputLength, unsigned char *pucDataOutput,unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_ExternalVerify_ECC(void *hSessionHandle,unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,unsigned char *pucDataInput, unsigned int uiInputLength,ECCSignature *pucSignature) __attribute__((weak));
extern int SDF_InternalSign_ECC(void *hSessionHandle,unsigned int uiISKIndex, unsigned char *pucData,unsigned int uiDataLength, ECCSignature *pucSignature) __attribute__((weak));
extern int SDF_InternalVerify_ECC(void *hSessionHandle,unsigned int uiISKIndex, unsigned char *pucData,unsigned int uiDataLength, ECCSignature *pucSignature) __attribute__((weak));
extern int SDF_ExternalEncrypt_ECC(void *hSessionHandle,unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,unsigned char *pucData, unsigned int uiDataLength,ECCCipher *pucEncData) __attribute__((weak));
extern int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucEncData,
    unsigned int *puiEncDataLength) __attribute__((weak));

extern int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
    unsigned int uiEncDataLength, unsigned char *pucData,
    unsigned int *puiDataLength) __attribute__((weak));

extern int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucMac,
    unsigned int *puiMACLength) __attribute__((weak));

#ifdef SDF_VERSION_2023
extern int SDF_AuthEnc(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength) __attribute__((weak));
extern int SDF_AuthDec(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) __attribute__((weak));
extern int SDF_EncryptInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength) __attribute__((weak));
extern int SDF_EncryptUpdate(void *hSessionHandle, char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) __attribute__((weak));
extern int SDF_EncryptFinal(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength) __attribute__((weak));
extern int SDF_DecryptInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength) __attribute__((weak));
extern int SDF_DecryptUpdate(void *hSessionHandle, char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) __attribute__((weak));
extern int SDF_DecryptFinal(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puiLastDataLength) __attribute__((weak));
extern int SDF_CalculateMACInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength) __attribute__((weak));
extern int SDF_CalculateMACUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength) __attribute__((weak));
extern int SDF_CalculateMACFinal(void *hSessionHandle, unsigned char *pucMac, unsigned int *puiMacLength) __attribute__((weak));
extern int SDF_AuthEncInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned int uiDataLength) __attribute__((weak));
extern int SDF_AuthEncUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) __attribute__((weak));
extern int SDF_AuthEncFinal(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength) __attribute__((weak));
extern int SDF_AuthDecInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData, unsigned int uiAuthDataLength, unsigned int uiDataLength) __attribute__((weak));
extern int SDF_AuthDecUpdate(void *hSessionHandle, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) __attribute__((weak));
extern int SDF_AuthDecFinal(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puLastDataLength) __attribute__((weak));
extern int SDF_HMACInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID) __attribute__((weak));
extern int SDF_HMACUpdate(void *hSessionHandle, char *pucData, unsigned int uiDataLength) __attribute__((weak));
extern int SDF_HMACFinal(void *hSessionHandle, char *pucHMac, unsigned int *puiMacLength) __attribute__((weak));
#endif
extern int SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, char *pucID, unsigned int uiIDLength) __attribute__((weak));
extern int SDF_HashUpdate(void *hSessionHandle, char *pucData, unsigned int uiDataLength) __attribute__((weak));
extern int SDF_HashFinal(void *hSessionHandle, char *pucHash, unsigned int *puiHashLength) __attribute__((weak));
extern int SDF_CreateFile(void *hSessionHandle, char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize) __attribute__((weak));
extern int SDF_ReadFile(void *hSessionHandle, char *pucfileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer) __attribute__((weak));
extern int SDF_WriteFile(void *hSessionHandle, char *pucFileName, unsigned int uiNamelen, unsigned int uiOffset, unsigned int uiFileLength, char *pucBuffer) __attribute__((weak));
extern int SDF_DeleteFile(void *hSessionHandle, char *pucFileName, unsigned int uiNameLen) __attribute__((weak));

#ifdef SDF_VERSION_2023
// extern int SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey) __attribute__((weak));
// extern int SDF_GenerateKeyPair_ECC(unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey) __attribute__((weak));
extern int SDF_ExternalPrivateKeyOperation_RSA(RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_ExternalSign_ECC(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature) __attribute__((weak));
extern int SDF_ExternalDecrypt_ECC(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, unsigned char *pucData, unsigned int *uiDataLength) __attribute__((weak));
extern int SDF_ExternalSign_SM9(SM9SignMasterPublicKey *pSignMasterPublicKey, SM9SignUserPrivateKey *pSignUserPrivateKey, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pSignature) __attribute__((weak));
extern int SDF_ExternalDecrypt_SM9(SM9EncUserPrivateKey *pEncUserPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pEncData) __attribute__((weak));
extern int SDF_ExternalKeyEncrypt(unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) __attribute__((weak));
extern int SDF_ExternalKeyDecrypt(unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) __attribute__((weak));
extern int SDF_ExternalKeyEncryptInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength) __attribute__((weak));
extern int SDF_ExternalKeyDecryptInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength) __attribute__((weak));
extern int SDF_ExternalKeyHMACInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength) __attribute__((weak));
extern int SDF_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek, uint32_t len, void **pkey_handle) __attribute__((weak));
#endif
#endif /* OSSL_CRYPTO_SDF_SYM_WEAK_H */
