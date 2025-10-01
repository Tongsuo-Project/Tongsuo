

/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#ifndef __SKF_TYPE_DEF_H__
#define __SKF_TYPE_DEF_H__

# pragma once

# include <stdint.h>
# include <openssl/evp.h>

# ifdef __cplusplus
 "C" {
# endif

#include "base_type.h"

#if defined(_WIN32) || defined(_WIN64)
#ifndef _WINDOWS
#define _WINDOWS
#endif
#endif


#define MAX_RSA_MODULUS_LEN 256
#define MAX_RSA_EXPONENT_LEN 4
#define ECC_MAX_XCOORDINATE_BITS_LEN 512
#define ECC_MAX_YCOORDINATE_BITS_LEN ECC_MAX_XCOORDINATE_BITS_LEN
#define ECC_MAX_MODULUS_BITS_LEN ECC_MAX_XCOORDINATE_BITS_LEN
#define MAX_IV_LEN 32




// #define V_FPF_FEARURE 0x00
// #define V_FPF_IMAGE 0x01
// #define V_FPF_RECOVER 0x100
// #define V_FPF_BEGIN 0x200
// typedef struct __fp_id_name
// {
//     u32 uId;
//     char szName[32];
//     u32 uAttr;
// } FP_ID_NAME;

// typedef struct __fp_info
// {
//     u32 uType;
//     u32 uRegCount;
//     u32 uMaxFP;
//     FP_ID_NAME *pIdName;
//     u32 uCount;
// } FP_INFO;

// Flags for CIPHER_PARAM
// #define CIPHER_NO_PADDING 0x0000
// #define CIPHER_PKCS5_PADDING 0x0001
// #define CIPHER_ENCRYPT 0x0000
// #define CIPHER_DECRYPT 0x0010
// #define CIPHER_FEED_BITS_MASK 0xFF00
// typedef struct __cipher_param
// {
//     u32 uAlgo;
//     u32 uFlags;
//     int cbIV;
//     u8 pbIV[32];
//     int cbKey;
//     u8 pbKey[128];
// } PACKED_ST(CIPHER_PARAM);

// typedef struct blockcipherdata_st
// {
//     u32 num;
//     u8 **buf;
//     u32 *bufLen;
// } BLOCKCIPHERDATA, *PBLOCKCIPHERDATA;

// typedef struct init_param_st
// {
//     char *token;    /* the length MUST BE less than 32 bytes */
//     u8 *k_external; /* the length MUST BE 16 bytes, CAN be NULL */

//     char *app_name;  /* app name */
//     char *k_sopin;   /* the length MUST BE less than 16 bytes */
//     char *k_userpin; /* the length MUST BE less than 16 bytes */
//     int so_retry;    /* value 1-15 */
//     int user_retry;  /* value 1-15 */
// } INIT_PARAM;

// #define V_SGD_SIGN (0x100)
// #define V_SGD_KEYX (0x400)

// 以下宏用于V_GenerateKey函数ulAlgId参数
#define GENERATE_KEY_USAGE_SIGN 0x00001000
#define GENERATE_KEY_USAGE_ENCRYPT 0x00002000
#define GENERATE_KEY_USAGE_MASK 0x00003000
#define GENERATE_KEY_SRAM 0x00010000
#define GENERATE_KEY_EFLASH 0x00020000
#define GENERATE_KEY_SAVE_MASK 0x00030000
#define GENERATE_KEY_ALGO_RSA 0x00000100
#define GENERATE_KEY_ALGO_SM2 0x00000200
#define GENERATE_KEY_ALGO_SM9 0x00000300
#define GENERATE_KEY_ASYM_ALGO_MASK 0x00000300
#define GENERATE_KEY_SYM_MODE_ECB 0x00000001
#define GENERATE_KEY_SYM_MODE_CBC 0x00000002
#define GENERATE_KEY_SYM_MODE_CFB 0x00000003
#define GENERATE_KEY_SYM_MODE_OFB 0x00000004
#define GENERATE_KEY_SYM_MODE_MAC 0x00000005
#define GENERATE_KEY_SYM_MODE_MASK 0x00000007
#define GENERATE_KEY_ALGO_DES 0x00000010
#define GENERATE_KEY_ALGO_AES 0x00000020
#define GENERATE_KEY_ALGO_SM1 0x00000030
#define GENERATE_KEY_ALGO_SM4 0x00000040
#define GENERATE_KEY_ALGO_SM6 0x00000050
#define GENERATE_KEY_ALGO_SSF33 0x00000060
#define GENERATE_KEY_SYM_ALGO_MASK 0x00000070
#define GENERATE_KEY_BIT_64 0x00400000
#define GENERATE_KEY_BIT_128 0x00800000
#define GENERATE_KEY_BIT_256 0x01000000
#define GENERATE_KEY_BIT_512 0x02000000
#define GENERATE_KEY_BIT_1024 0x04000000
#define GENERATE_KEY_BIT_2048 0x08000000
#define GENERATE_KEY_BIT_MASK 0x0FF00000



#define MAX_CONTAINER_NAME_LEN 64
#define MAX_APPLICATION_NAME_LEN 16

/* algorithm */
#define SGD_SM1_ECB 0x00000101   // SM1 算法 ECB 加密模式
#define SGD_SM1_CBC 0x00000102   // SM1 算法 CBC 加密模式
#define SGD_SM1_CFB 0x00000104   // SM1 算法 CFB 加密模式
#define SGD_SM1_OFB 0x00000108   // SM1 算法 OFB 加密模式
#define SGD_SM1_MAC 0x00000110   // SM1 算法 MAC 运算
#define SGD_SSF33_ECB 0x00000201 // SSF33 算法 ECB 加密模式
#define SGD_SSF33_CBC 0x00000202 // SSF33 算法 CBC 加密模式
#define SGD_SSF33_CFB 0x00000204 // SSF33 算法 CFB 加密模式
#define SGD_SSF33_OFB 0x00000208 // SSF33 算法 OFB 加密模式
#define SGD_SSF33_MAC 0x00000210 // SSF33 算法 MAC 运算
#define SGD_SMS4_ECB 0x00000401  // SMS4 算法 ECB 加密模式
#define SGD_SMS4_CBC 0x00000402  // SMS4 算法 CBC 加密模式
#define SGD_SMS4_CFB 0x00000404  // SMS4 算法 CFB 加密模式
#define SGD_SMS4_OFB 0x00000408  // SMS4 算法 OFB 加密模式
#define SGD_SMS4_MAC 0x00000410  // SMS4 算法 MAC 运算

#define SGD_RSA 0x00010000   // RSA 算法
#define SGD_SM2 0x00020000   // SM2 算法
#define SGD_SM2_1 0x00020100 // 椭圆曲线签名算法
#define SGD_SM2_2 0x00020200 // 椭圆曲线密钥交换协议
#define SGD_SM2_3 0x00020400 // 椭圆曲线加密算法

#define SGD_SM3 0x00000001    // SM3 杂凑算法
#define SGD_SHA1 0x00000002   // SHA1 杂凑算法
#define SGD_SHA256 0x00000004 // SHA256 杂凑算法

////////////////////////////VENDOR DEFINED/////////////////////////////////////
#define SGD_DES_ECB 0x80000101 // DES 算法 ECB 加密模式
#define SGD_DES_CBC 0x80000102 // DES 算法 CBC 加密模式
#define SGD_DES_CFB 0x80000104 // DES 算法 CFB 加密模式
#define SGD_DES_OFB 0x80000108 // DES 算法 OFB 加密模式
#define SGD_DES_MAC 0x80000110 // DES 算法 MAC 运算

#define SGD_AES_ECB 0x80000201 // AES-128 算法 ECB 加密模式
#define SGD_AES_CBC 0x80000202 // AES-128 算法 CBC 加密模式
#define SGD_AES_CFB 0x80000204 // AES-128 算法 CFB 加密模式
#define SGD_AES_OFB 0x80000208 // AES-128 算法 OFB 加密模式
#define SGD_AES_MAC 0x80000210 // AES-128 算法 MAC 运算

#define SGD_SM6_ECB 0x80000301 // SM6 算法 ECB 加密模式
#define SGD_SM6_CBC 0x80000302 // SM6 算法 CBC 加密模式
#define SGD_SM6_CFB 0x80000304 // SM6 算法 CFB 加密模式
#define SGD_SM6_OFB 0x80000308 // SM6 算法 OFB 加密模式
#define SGD_SM6_MAC 0x80000310 // SM6 算法 MAC 运算
////////////////////////////VENDOR DEFINED/////////////////////////////////////

#ifndef TRUE
#define TRUE 1 // 布尔值为真
#endif
#ifndef FALSE
#define FALSE 0 // 布尔值为假
#endif

#ifndef NULL
#define NULL 0
#endif

#define ADMIN_TYPE 0 // 管理员 PIN 类型
#define USER_TYPE 1  // 用户 PIN 类型

/* account */
#define SECURE_NEVER_ACCOUNT 0x00  // 不允许
#define SECURE_ADM_ACCOUNT 0x01    // 管理员权限
#define SECURE_USER_ACCOUNT 0x10   // 用户权限
#define SECURE_ANYONE_ACCOUNT 0xFF // 任何人

#ifndef MIN_PIN_LEN
#define MIN_PIN_LEN 0x06
#endif
#ifndef MAX_PIN_LEN
#ifdef MAX_PIN_LEN
#undef MAX_PIN_LEN
#endif
#define MAX_PIN_LEN 0x10
#endif

#define DEV_ABSENT_STATE 0x00000000  // 设备不存在
#define DEV_PRESENT_STATE 0x00000001 // 设备存在
#define DEV_UNKNOW_STATE 0x00000002  // 设备状态未知

#ifndef PKCS5_PADDING
#define PKCS5_PADDING 1
#endif

#ifndef NO_PADDING
#define NO_PADDING 0
#endif

#define CTNF_NOSET 0
#define CTNF_RSA 1
#define CTNF_ECC 2

#define HLF_DEV 0x1
#define HLF_APP 0x2
#define HLF_CTN 0x4
#define HLF_KEY 0x8
#define HLF_HASH 0x10
#define HLF_ECCWRAP_KEY 0x20

/* return value */
#define SAR_OK 0x00000000
#define SAR_FAIL 0x0A000001
#define SAR_UNKOWNERR 0x0A000002
#define SAR_NOTSUPPORTYETERR 0x0A000003
#define SAR_FILEERR 0x0A000004
#define SAR_INVALIDHANDLEERR 0x0A000005
#define SAR_INVALIDPARAMERR 0x0A000006
#define SAR_READFILEERR 0x0A000007
#define SAR_WRITEFILEERR 0x0A000008
#define SAR_NAMELENERR 0x0A000009
#define SAR_KEYUSAGEERR 0x0A00000A
#define SAR_MODULUSLENERR 0x0A00000B
#define SAR_NOTINITIALIZEERR 0x0A00000C
#define SAR_OBJERR 0x0A00000D
#define SAR_MEMORYERR 0x0A00000E
#define SAR_TIMEOUTERR 0x0A00000F
#define SAR_INDATALENERR 0x0A000010
#define SAR_INDATAERR 0x0A000011
#define SAR_GENRANDERR 0x0A000012
#define SAR_HASHOBJERR 0x0A000013
#define SAR_HASHERR 0x0A000014
#define SAR_GENRSAKEYERR 0x0A000015
#define SAR_RSAMODULUSLENERR 0x0A000016
#define SAR_CSPIMPRTPUBKEYERR 0x0A000017
#define SAR_RSAENCERR 0x0A000018
#define SAR_RSADECERR 0x0A000019
#define SAR_HASHNOTEQUALERR 0x0A00001A
#define SAR_KEYNOTFOUNTERR 0x0A00001B
#define SAR_CERTNOTFOUNTERR 0x0A00001C
#define SAR_NOTEXPORTERR 0x0A00001D
#define SAR_DECRYPTPADERR 0x0A00001E
#define SAR_MACLENERR 0x0A00001F
#define SAR_BUFFER_TOO_SMALL 0x0A000020
#define SAR_KEYINFOTYPEERR 0x0A000021
#define SAR_NOT_EVENTERR 0x0A000022
#define SAR_DEVICE_REMOVED 0x0A000023
#define SAR_PIN_INCORRECT 0x0A000024
#define SAR_PIN_LOCKED 0x0A000025
#define SAR_PIN_INVALID 0x0A000026
#define SAR_PIN_LEN_RANGE 0x0A000027
#define SAR_USER_ALREADY_LOGGED_IN 0x0A000028
#define SAR_USER_PIN_NOT_INITIALIZED 0x0A000029
#define SAR_USER_TYPE_INVALID 0x0A00002A
#define SAR_APPLICATION_NAME_INVALID 0x0A00002B
#define SAR_APPLICATION_EXISTS 0x0A00002C
#define SAR_USER_NOT_LOGGED_IN 0x0A00002D
#define SAR_APPLICATION_NOT_EXISTS 0x0A00002E
#define SAR_FILE_ALREADY_EXIST 0x0A00002F
#define SAR_NO_ROOM 0x0A000030
#define SAR_FILE_NOT_EXIST 0x0A000031
#define SAR_REACH_MAX_CONTAINER_COUNT 0x0A000032

#define VR_FP_ID_INVALIED 0x0B000001
#define VR_FP_IMAGE_ERROR 0x0B000002
#define VR_FP_MATCH_ERROR 0x0B000003
#define VR_FP_NOT_LEAVE 0x0B000004
#define VR_FP_NOT_TOUCH 0x0B000005
#define VR_OP_NOT_FOUND 0x0B000006

///</ 以下为龙脉 SKF定义的对称密钥算法标识

#define LM_SGD_FINGER_STATUS 0x80080000
#define LM_SGD_VENDOR_DEFINED 0x80000000

#define LM_SGD_DES_ECB ((LM_SGD_VENDOR_DEFINED) + 0x00000211)
#define LM_SGD_DES_CBC ((LM_SGD_VENDOR_DEFINED) + 0x00000212)

#define LM_SGD_3DES168_ECB ((LM_SGD_VENDOR_DEFINED) + 0x00000241)
#define LM_SGD_3DES168_CBC ((LM_SGD_VENDOR_DEFINED) + 0x00000242)

#define LM_SGD_3DES112_ECB ((LM_SGD_VENDOR_DEFINED) + 0x00000221)
#define LM_SGD_3DES112_CBC ((LM_SGD_VENDOR_DEFINED) + 0x00000222)

#define LM_SGD_AES128_ECB ((LM_SGD_VENDOR_DEFINED) + 0x00000111)
#define LM_SGD_AES128_CBC ((LM_SGD_VENDOR_DEFINED) + 0x00000112)

#define LM_SGD_AES192_ECB ((LM_SGD_VENDOR_DEFINED) + 0x00000121)
#define LM_SGD_AES192_CBC ((LM_SGD_VENDOR_DEFINED) + 0x00000122)

#define LM_SGD_AES256_ECB ((LM_SGD_VENDOR_DEFINED) + 0x00000141)
#define LM_SGD_AES256_CBC ((LM_SGD_VENDOR_DEFINED) + 0x00000142)





# ifdef __cplusplus
}
#endif /*__SKF_TYPE_DEF_H__*/