/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#ifndef HEADER_NTLS_H
#define HEADER_NTLS_H

/* NTLS version */
# define NTLS1_1_VERSION	0x0101
# define NTLS1_1_VERSION_MAJOR	0x01
# define NTLS1_1_VERSION_MINOR	0x01
# define NTLS_VERSION		NTLS1_1_VERSION
# define NTLS_VERSION_MAJOR	NTLS1_1_VERSION_MAJOR
# define NTLS_VERSOIN_MINOR	NTLS1_1_VERSION_MINOR
/*
 * This tag is used to replace SSLv3 when use NTLS.
 * SSLv3 is not used default, so it always be the min protocal version in test,
 * but when add NTLS, the NTLS becomes the min version, and NTLS is commonly use,
 * then will cause some problems, so add this tag
 */
# define MIN_VERSION_WITH_NTLS 0x0100

/* GM/T 0024-2014 cipher suites */
/*
 * XXX:
 *
 * We currently ignore all SM1 and SM9 related ciphers, the reasons are:
 *
 * 1. SM1 is not public usable, the specification is credential;
 * 2. OpenSSL currently doesn't support SM9 yet.
 *
 * Fortunately, major NTLS implementations mostly support 0xe011 and 0xe013
 * only.
 */
/*
# define NTLS_CK_SM2DHE_WITH_SM1_SM3     0x0300E001
# define NTLS_CK_SM2_WITH_SM1_SM3        0x0300E003
# define NTLS_CK_SM9DHE_WITH_SM1_SM3     0x0300E005
# define NTLS_CK_SM9_WITH_SM1_SM3        0x0300E007
# define NTLS_CK_RSA_WITH_SM1_SM3        0x0300E009
# define NTLS_CK_RSA_WITH_SM1_SHA1       0x0300E00A
# define NTLS_CK_SM9DHE_WITH_SM4_SM3     0x0300E015
# define NTLS_CK_SM9_WITH_SM4_SM3        0x0300E017
*/
# define NTLS_CK_SM2DHE_WITH_SM4_SM3     0x0300E011
# define NTLS_CK_SM2_WITH_SM4_SM3        0x0300E013
# define NTLS_CK_RSA_WITH_SM4_SM3        0x0300E019
# define NTLS_CK_RSA_WITH_SM4_SHA1       0x0300E01A

/* GM/T 0024-2014 Cipher Suites Text */
/*
# define NTLS_TXT_SM2DHE_WITH_SM1_SM3          "SM2DHE-WITH-SM1-SM3"
# define NTLS_TXT_SM2_WITH_SM1_SM3             "SM2-WITH-SM1-SM3"
# define NTLS_TXT_SM9DHE_WITH_SM1_SM3          "SM9DHE-WITH-SM1-SM3"
# define NTLS_TXT_SM9_WITH_SM1_SM3             "SM9-WITH-SM1-SM3"
# define NTLS_TXT_RSA_WITH_SM1_SM3             "RSA-WITH-SM1-SM3"
# define NTLS_TXT_RSA_WITH_SM1_SHA1            "RSA-WITH-SM1-SHA1"
# define NTLS_TXT_SM9DHE_WITH_SMS4_SM3         "SM9DHE-WITH-SMS4-SM3"
# define NTLS_TXT_SM9_WITH_SMS4_SM3            "SM9-WITH-SMS4-SM3"
*/
# define NTLS_TXT_SM2DHE_WITH_SM4_SM3          "ECDHE-SM2-WITH-SM4-SM3"
# define NTLS_TXT_SM2_WITH_SM4_SM3             "ECC-SM2-WITH-SM4-SM3"
# define NTLS_TXT_RSA_WITH_SM4_SM3             "RSA-WITH-SM4-SM3"
# define NTLS_TXT_RSA_WITH_SM4_SHA1            "RSA-WITH-SM4-SHA1"

/* GM/T 0024-2014 */
#define NTLS_AD_UNSUPPORTED_SITE2SITE   200
#define NTLS_AD_NO_AREA                 201
#define NTLS_AD_UNSUPPORTED_AREATYPE    202
#define NTLS_AD_BAD_IBCPARAM            203
#define NTLS_AD_UNSUPPORTED_IBCPARAM    204
#define NTLS_AD_IDENTITY_NEED           205

#endif
