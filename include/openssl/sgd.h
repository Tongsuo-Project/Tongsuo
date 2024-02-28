/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OPENSSL_SGD_H
# define OPENSSL_SGD_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_SGD_H
# endif

# ifdef  __cplusplus
extern "C" {
# endif

/* Defined in GM/T 0006-2012 */
# define OSSL_SGD_MODE_ECB          0x00000001
# define OSSL_SGD_MODE_CBC          0x00000002
# define OSSL_SGD_MODE_CFB          0x00000004
# define OSSL_SGD_MODE_OFB          0x00000008
# define OSSL_SGD_MODE_MAC          0x00000010
# define OSSL_SGD_MODE_CTR          0x00000020
# define OSSL_SGD_MODE_XTS          0x00000040

# define OSSL_SGD_SM4               0x00000400
# define OSSL_SGD_SM4_ECB           (OSSL_SGD_SM4 | OSSL_SGD_MODE_ECB)
# define OSSL_SGD_SM4_CBC           (OSSL_SGD_SM4 | OSSL_SGD_MODE_CBC)
# define OSSL_SGD_SM4_CFB           (OSSL_SGD_SM4 | OSSL_SGD_MODE_CFB)
# define OSSL_SGD_SM4_OFB           (OSSL_SGD_SM4 | OSSL_SGD_MODE_OFB)
# define OSSL_SGD_SM4_MAC           (OSSL_SGD_SM4 | OSSL_SGD_MODE_MAC)

# define OSSL_SGD_RSA                               0x00010000
# define OSSL_SGD_SM2                               0x00020100
# define OSSL_SGD_SM2_1                             0x00020200
# define OSSL_SGD_SM2_2                             0x00020400
# define OSSL_SGD_SM2_3                             0x00020800

# define OSSL_SGD_SM3                               0x00000001

# define OSSL_SGD_SM3_SM2                           0x00020201

# ifdef  __cplusplus
}
# endif

#endif
