/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_EC_ELGAMAL_H
# define HEADER_EC_ELGAMAL_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_EC_ELGAMAL
# ifdef  __cplusplus
extern "C" {
# endif

# include <stdlib.h>
# include <openssl/ec.h>
# include <openssl/bn.h>
# include <openssl/lhash.h>
# include <crypto/lhash.h>
# include <crypto/ec.h>
# include <crypto/ec/ec_local.h>

struct ec_elgamal_ciphertext_st {
    EC_POINT *C1;
    EC_POINT *C2;
};

typedef struct ec_elgamal_decrypt_table_entry_st {
    int32_t value;
    uint32_t key_len;
    unsigned char *key;
} EC_ELGAMAL_dec_tbl_entry;

DEFINE_LHASH_OF(EC_ELGAMAL_dec_tbl_entry);

struct ec_elgamal_decrypt_table_st {
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
    int32_t flag;
    int32_t size;
    uint32_t baby_step_bits;
    uint32_t giant_step_bits;
    EC_POINT *mG_inv;
    LHASH_OF(EC_ELGAMAL_dec_tbl_entry) *positive_entries;
    LHASH_OF(EC_ELGAMAL_dec_tbl_entry) *negative_entries;
};

struct ec_elgamal_ctx_st {
    EC_KEY *key;
    EC_ELGAMAL_DECRYPT_TABLE *decrypt_table;
    int32_t flag;
# ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    EC_POINT *h;
    BIGNUM *sk_inv;
# endif
};

int EC_ELGAMAL_dlog_brute(EC_ELGAMAL_CTX *ctx, int32_t *r, EC_POINT *M);
int EC_ELGAMAL_dlog_bsgs(EC_ELGAMAL_CTX *ctx, int32_t *r, EC_POINT *M);

# ifdef  __cplusplus
}
# endif
# endif

#endif
