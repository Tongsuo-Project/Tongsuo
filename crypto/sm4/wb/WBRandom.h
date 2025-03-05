/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2024 Nexus-TYF. All Rights Reserved.
 * Ported from Nexus-TYF/WBMatrix.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef _WBRANDOM_H_
#define _WBRANDOM_H_

#include "openssl/e_os2.h"
#include "openssl/rand.h"

static ossl_inline unsigned int cus_random()
{
    unsigned int ret;
    RAND_bytes((unsigned char *)&ret, sizeof(ret));
    return ret;
}

#endif /* _WBRANDOM_H_ */
