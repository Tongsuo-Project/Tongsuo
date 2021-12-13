/*
 * Copyright 2021 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
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

typedef struct ec_elgamal_bsgs_entry_st {
    int key_len;
    unsigned char *key;
    uint32_t value;
} EC_ELGAMAL_BSGS_ENTRY;

DEFINE_LHASH_OF(EC_ELGAMAL_BSGS_ENTRY);

typedef struct ec_elgamal_bsgs_hash_table_st {
    uint32_t size;
    EC_POINT *mG_neg;
    LHASH_OF(EC_ELGAMAL_BSGS_ENTRY) *bsgs_entries;
} EC_ELGAMAL_BSGS_HASH_TABLE;

struct ec_elgamal_ctx_st {
    EC_KEY *key;
    EC_ELGAMAL_BSGS_HASH_TABLE *bsgs_hash_table;
};

# ifdef  __cplusplus
}
# endif
# endif

#endif
