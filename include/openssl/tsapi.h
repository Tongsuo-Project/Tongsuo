/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef TONGSUO_API_H
# define TONGSUO_API_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_TSAPI_H
# endif

# include <stddef.h>
# include <openssl/opensslconf.h>
# include <openssl/evp.h>
# include <openssl/sdf.h>


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

# ifdef  __cplusplus
extern "C" {
# endif

    int TSAPI_Device();
    int TSAPI_Session();
    int TSAPI_GetDeviceInfo();
    int TSAPI_GenerateRandom(unsigned int uiLength);
    int TSAPI_PrivateKeyAccessRight();
    int TSAPI_ExportEncPublicKey_ECC(unsigned int KeyIndex);
    int TSAPI_ExportSignPublicKey_ECC(unsigned int KeyIndex);
    int TSAPI_ExportEncPublic_RSA(unsigned int KeyIndex);
    int TSAPI_ExportSignPublicKey_RSA(unsigned int KeyIndex);
    int TSAPI_GenerateKeyWithKEK(unsigned int KeyIndex);
    int TSAPI_GenerateKeyWithIPK_RSA(unsigned int KeyIndex);
    int TSAPI_GenerateKeyWithEPK_RSA(unsigned int KeyIndex);
    int TSAPI_GenerateKeyWithIPK_ECC(unsigned int KeyIndex);
    int TSAPI_GenerateKeyWithEPK_ECC(unsigned int KeyIndex);
    int TSAPI_ImportKeyWithKEK(unsigned int KeyIndex);
    int TSAPI_ImportKeyWithISK_RSA(unsigned int KeyIndex);
    int TSAPI_ImportKeyWithISK_ECC(unsigned int KeyIndex);
    void ExtRSAOptTest();
    void IntRSAOptTest();
    void ExtECCSignTest();   // 2023
    void ExtECCOptTest(); // 2023
    void SymmEncDecTest();
    int TSAPI_Encrypt();
    int TSAPI_Decrypt();
    int TSAPI_CalculateMAC();


    // int TSAPI_AuthEnc();
    // int TSAPI_AuthDec();


    // int TSAPI_EncryptInit();
    // int TSAPI_EncryptUpdate();
    // int TSAPI_EncryptFinal();
    // int TSAPI_DecryptInit();
    // int TSAPI_DecryptUpdate();
    // int TSAPI_DecryptFinal();
    // int TSAPI_CalculateMACInit();
    // int TSAPI_CalculateMACUpdate();
    // int TSAPI_CalculateMACFinal();
    // int TSAPI_AuthEncInit();
    // int TSAPI_AuthEncUpdate();
    // int TSAPI_AuthEncFinal();
    // int TSAPI_AuthDecInit();
    // int TSAPI_AuthDecUpdate();
    // int TSAPI_AuthDecFinal();
    // int TSAPI_HMACInit();
    // int TSAPI_HMACUpdate();
    // int TSAPI_HMACFinal();
    // int TSAPI_HashInit();
    // int TSAPI_HashUpdate();
    // int TSAPI_HashFinal();
    // int TSAPI_CreateFile();
    // int TSAPI_ReadFile();
    // int TSAPI_WriteFile();
    // int TSAPI_DeleteFile();
    // int TSAPI_GenerateKeyPair_RSA();
    // int TSAPI_GenerateKeyPair_ECC();
    // int TSAPI_ExternalPrivateKeyOperation_RSA();
    // int TSAPI_ExternalSign_ECC();
    // int TSAPI_ExternalDecrypt_ECC();
    // int TSAPI_ExternalSign_SM9();
    // int TSAPI_ExternalDecrypt_SM9();
    // int TSAPI_ExternalKeyEncrypt();
    // int TSAPI_ExternalKeyDecrypt();
    // int TSAPI_ExternalKeyEncryptInit();
    // int TSAPI_ExternalKeyDecryptInit();
    // int TSAPI_ExternalKeyHMACInit();



    // void ExtRSAOptTest();
    // void IntRSAOptTest();
    // void IntECCSignTest();
    // void ExtECCOptTest();
    // void ExtECCSignTest();
    // // void IntECCOptTest();

    // void SymmEncDecTest();


    void parse_device_alg_ability(const unsigned int asym_alg_ability[2], 
                             unsigned int sym_alg_ability, 
                             unsigned int hash_alg_ability);
    void analyze_asym_ability(const unsigned int asym_alg_ability[2]);
# ifdef  __cplusplus
}
# endif

#endif
