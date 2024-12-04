/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <crypto/wbsm4.h>
#include "prov/ciphercommon.h"
#include "prov/ciphercommon_gcm.h"

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
typedef struct prov_wbsm4_xiaolai_gcm_ctx_st {
    PROV_GCM_CTX base; /* must be first entry in struct */
    union {
        OSSL_UNION_ALIGN;
        wbsm4_xiaolai_key ks;
    } ks; /* WBSM4 key schedule to use */
} PROV_WBSM4_XIAOLAI_GCM_CTX;

const PROV_GCM_HW *ossl_prov_wbsm4_xiaolai_hw_gcm(size_t keybits);
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
typedef struct prov_wbsm4_baiwu_gcm_ctx_st {
    PROV_GCM_CTX base; /* must be first entry in struct */
    union {
        OSSL_UNION_ALIGN;
        wbsm4_baiwu_key ks;
    } ks; /* WBSM4 key schedule to use */
} PROV_WBSM4_BAIWU_GCM_CTX;

const PROV_GCM_HW *ossl_prov_wbsm4_baiwu_hw_gcm(size_t keybits);
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
typedef struct prov_wbsm4_wsise_gcm_ctx_st {
    PROV_GCM_CTX base; /* must be first entry in struct */
    union {
        OSSL_UNION_ALIGN;
        wbsm4_wsise_key ks;
    } ks; /* WBSM4 key schedule to use */
} PROV_WBSM4_WSISE_GCM_CTX;

const PROV_GCM_HW *ossl_prov_wbsm4_wsise_hw_gcm(size_t keybits);
#endif /* OPENSSL_NO_WBSM4_WSISE */
