/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_ML_KEM_AVX2_H
# define OSSL_CRYPTO_ML_KEM_AVX2_H
# pragma once

# include <stddef.h>
# include <stdint.h>
# include "crypto/ml_kem.h"

int ossl_ml_kem_avx2_keypair_derand(const ML_KEM_VINFO *vinfo,
                                    uint8_t *pk, size_t pklen,
                                    uint8_t *sk, size_t sklen,
                                    const uint8_t *seed, size_t seedlen);

int ossl_ml_kem_avx2_encap_derand(const ML_KEM_VINFO *vinfo,
                                  uint8_t *ct, size_t ctlen,
                                  uint8_t *ss, size_t sslen,
                                  const uint8_t *pk, size_t pklen,
                                  const uint8_t *entropy, size_t entropylen);

int ossl_ml_kem_avx2_decap(const ML_KEM_VINFO *vinfo,
                           uint8_t *ss, size_t sslen,
                           const uint8_t *ct, size_t ctlen,
                           const uint8_t *sk, size_t sklen);

#endif
