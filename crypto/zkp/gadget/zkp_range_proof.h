/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_ZKP_RANGE_PROOF_LOCAL_H
# define HEADER_ZKP_RANGE_PROOF_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/nizk.h>
# include <openssl/bulletproofs.h>
# include <openssl/zkp_gadget.h>
# include "internal/refcount.h"

struct zkp_range_pub_param_st {
    BP_PUB_PARAM *bp_pp;
    CRYPTO_RWLOCK *lock;
    CRYPTO_REF_COUNT references;
};

struct zkp_range_witness_st {
    BIGNUM *order;
    BIGNUM *r;
    BIGNUM *v;
    CRYPTO_RWLOCK *lock;
    CRYPTO_REF_COUNT references;
};

struct zkp_range_ctx_st {
    ZKP_TRANSCRIPT *transcript;
    ZKP_RANGE_PUB_PARAM *pp;
    ZKP_RANGE_WITNESS *witness;
    EC_POINT *PK;
    EC_ELGAMAL_CTX *enc_ctx;
    EC_ELGAMAL_CIPHERTEXT *enc_ct;
};

struct zkp_range_proof_st {
    NIZK_PLAINTEXT_KNOWLEDGE_PROOF *ptke_proof;
    BP_RANGE_PROOF *bp_proof;
};

# ifdef  __cplusplus
}
# endif

#endif
