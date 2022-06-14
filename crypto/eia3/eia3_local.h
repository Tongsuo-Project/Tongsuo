/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OPENSSL_NO_ZUC

# include <stdlib.h>
# include <string.h>
# include <openssl/crypto.h>

# include "crypto/zuc.h"

struct eia3_context {
    ZUC_KEY zk;
    size_t num;
    size_t length;  /* The bits of the input message */
    uint32_t T;
};

#endif
