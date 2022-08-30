/*
 * Copyright 2017-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Certificate table information. NB: table entries must match SSL_PKEY indices
 */
static const SSL_CERT_LOOKUP ssl_cert_info [] = {
    {EVP_PKEY_RSA, SSL_aRSA}, /* SSL_PKEY_RSA */
    {EVP_PKEY_RSA_PSS, SSL_aRSA}, /* SSL_PKEY_RSA_PSS_SIGN */
    {EVP_PKEY_DSA, SSL_aDSS}, /* SSL_PKEY_DSA_SIGN */
#ifndef OPENSSL_NO_SM2
    {EVP_PKEY_EC, SSL_aECDSA | SSL_aSM2}, /* SSL_PKEY_ECC */
#else
    {EVP_PKEY_EC, SSL_aECDSA}, /* SSL_PKEY_ECC */
#endif
    {EVP_PKEY_ED25519, SSL_aECDSA}, /* SSL_PKEY_ED25519 */
    {EVP_PKEY_ED448, SSL_aECDSA}, /* SSL_PKEY_ED448 */
    {EVP_PKEY_SM2, SSL_aSM2}, /* SSL_PKEY_ECC SM2 */
#ifndef OPENSSL_NO_NTLS
    {EVP_PKEY_SM2, SSL_aSM2}, /* SSL_PKEY_SM2_SIGN */
    {EVP_PKEY_SM2, SSL_aSM2}, /* SSL_PKEY_SM2_ENC */
    {EVP_PKEY_RSA, SSL_aRSA}, /* SSL_PKEY_RSA_SIGN */
    {EVP_PKEY_RSA, SSL_aRSA}, /* SSL_PKEY_RSA_ENC */
#endif
};
