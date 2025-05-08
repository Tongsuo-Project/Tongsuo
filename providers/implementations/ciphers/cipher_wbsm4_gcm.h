/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <crypto/wbsm4.h>
#include "prov/ciphercommon.h"
#include "prov/ciphercommon_gcm.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
typedef struct prov_wbsm4_xiao_dykey_gcm_ctx_st {
    PROV_GCM_CTX base;          /* must be first entry in struct */
    union {
        OSSL_UNION_ALIGN;
        wbsm4_xiao_dykey_context ks;
    } ks;                       /* SM4 key schedule to use */
} PROV_WBSM4_XIAO_DYKEY_GCM_CTX;

const PROV_GCM_HW *ossl_prov_wbsm4_xiao_dykey_hw_gcm(size_t keybits);
#endif
