/*
 * Copyright 2023-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_SM4TH_PARAMS_ALIAS_H
# define OSSL_CRYPTO_SM4TH_PARAMS_ALIAS_H

# include "sm4th_params.h"

typedef sm4th_params_t params_t;

const params_t *sm4th_params_d3_f(void);
const params_t *sm4th_params_d3_s(void);

#endif
