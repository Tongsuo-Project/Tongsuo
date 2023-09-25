/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_NIZK_LOCAL_H
# define HEADER_NIZK_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/nizk.h>
# include "internal/refcount.h"

struct nizk_pub_param_st {
    EC_GROUP *group;
    EC_POINT *G;
    EC_POINT *H;
    CRYPTO_RWLOCK *lock;
    CRYPTO_REF_COUNT references;
};

struct nizk_witness_st {
    BIGNUM *order;
    BIGNUM *r;
    BIGNUM *v;
    CRYPTO_RWLOCK *lock;
    CRYPTO_REF_COUNT references;
};

# ifdef  __cplusplus
}
# endif

#endif
