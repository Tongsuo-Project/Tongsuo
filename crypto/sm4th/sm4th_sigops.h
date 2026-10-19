/*
 * Copyright 2023-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Parameterized keygen/sign/verify entry points for the SM4th key layer.
 * Return values: 0 success, -1 invalid input, 2 key mismatch (validate).
 */
#ifndef SM4TH_SIGOPS_H
# define SM4TH_SIGOPS_H

# include "params.h"
# include "crypto/sm4th.h"

# include <openssl/evp.h>
# include <stddef.h>
# include <stdint.h>

/* pk = OWF input || output; sk = OWF input || key. */
int sm4th_keygen(const params_t *params, uint8_t *pk, uint8_t *sk,
                 const uint8_t *sk_key, const uint8_t *sk_input);
int sm4th_validate(const params_t *params, const uint8_t *pk,
                   const uint8_t *sk);
int sm4th_sign(const params_t *params, const EVP_MD *shake128_md,
               const uint8_t *sk,
               const uint8_t *msg, size_t msglen,
               const uint8_t *seed, size_t seedlen,
               uint8_t *sig, size_t *siglen);
int sm4th_verify(const params_t *params, const EVP_MD *shake128_md,
                 const uint8_t *pk, size_t pklen,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *sig, size_t siglen);

#endif
