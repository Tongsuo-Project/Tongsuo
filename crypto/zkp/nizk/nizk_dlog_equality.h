/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_NIZK_DLOG_EQUALITY_LOCAL_H
# define HEADER_NIZK_DLOG_EQUALITY_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <crypto/zkp/common/zkp_transcript.h>
# include "internal/refcount.h"
# include "nizk.h"

struct nizk_dlog_equality_ctx_st {
    ZKP_TRANSCRIPT *transcript;
    NIZK_PUB_PARAM *pp;
    NIZK_WITNESS *witness;
    EC_POINT *G;
    EC_POINT *H;
};

struct nizk_dlog_equality_proof_st {
    EC_POINT *A1;
    EC_POINT *A2;
    BIGNUM *z;
};

# ifdef  __cplusplus
}
# endif

#endif


