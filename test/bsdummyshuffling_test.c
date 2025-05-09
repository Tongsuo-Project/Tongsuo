/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "testutil.h"
#include "crypto/bsdummyshuffling.h"

#ifndef OPENSSL_NO_SM4
#include "crypto/sm4.h"
static int test_bsdummyshuffling_random_input(void){
    
    return 1;
}
#endif


int setup_tests(void)
{
#ifndef OPENSSL_NO_SM4
    ADD_TEST(test_bsdummyshuffling_random_input);
#endif
    return 1;
}
