/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SM3_H
# define OSSL_CRYPTO_SM3_H

# include <openssl/opensslconf.h>
# include <openssl/sm3.h>

# ifdef OPENSSL_NO_SM3
#  error SM3 is disabled.
# endif

# ifdef  __cplusplus
extern "C" {
# endif

int sm3_init(SM3_CTX *c);
int sm3_update(SM3_CTX *c, const void *data, size_t len);
int sm3_final(unsigned char *md, SM3_CTX *c);

void sm3_block_data_order(SM3_CTX *c, const void *p, size_t num);

# ifdef  __cplusplus
}
# endif
#endif
