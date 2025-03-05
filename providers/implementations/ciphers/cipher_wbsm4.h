/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "prov/ciphercommon.h"
#include "crypto/wbsm4.h"

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
typedef struct {
    PROV_CIPHER_CTX base; /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        wbsm4_xiaolai_key ks;
    } ks;
} PROV_WBSM4_XIAOLAI_CTX;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_xiaolai_cbc(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_xiaolai_ecb(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_xiaolai_ctr(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_xiaolai_ofb128(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_xiaolai_cfb128(size_t keybits);
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
typedef struct {
    PROV_CIPHER_CTX base; /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        wbsm4_baiwu_key ks;
    } ks;
} PROV_WBSM4_BAIWU_CTX;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_baiwu_cbc(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_baiwu_ecb(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_baiwu_ctr(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_baiwu_ofb128(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_baiwu_cfb128(size_t keybits);
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
typedef struct {
    PROV_CIPHER_CTX base; /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        wbsm4_wsise_key ks;
    } ks;
} PROV_WBSM4_WSISE_CTX;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_wsise_cbc(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_wsise_ecb(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_wsise_ctr(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_wsise_ofb128(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_wsise_cfb128(size_t keybits);
#endif /* OPENSSL_NO_WBSM4_WSISE */
