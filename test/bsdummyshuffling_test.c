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
    uint8_t input[SM4_BLOCK_SIZE];

    /* 密钥需要在上层电路确定 */
    uint8_t k[SM4_BLOCK_SIZE]={0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x6b, 0x65, 0x79, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    uint8_t block_sm4[SM4_BLOCK_SIZE];
    uint8_t block_wbsm4_dsdummyshuffling[SM4_BLOCK_SIZE];
    SM4_KEY key;

    if(!TEST_int_eq(RAND_bytes(input,SM4_BLOCK_SIZE), 1)){
        return 0;
    }
    memcpy(block_sm4, input, SM4_BLOCK_SIZE);
    memcpy(block_wbsm4_dsdummyshuffling, input, SM4_BLOCK_SIZE);

    ossl_sm4_set_key(k, &key);
    
    /* 加密 */
    ossl_sm4_encrypt(block_sm4, block_sm4, &key);
    WBSM4_bsdummyshuffling_enc(block_wbsm4_dsdummyshuffling, block_wbsm4_dsdummyshuffling);
    if (!TEST_mem_eq(block_sm4, SM4_BLOCK_SIZE, block_wbsm4_dsdummyshuffling, SM4_BLOCK_SIZE)){
        return 0;
    }

    /* 解密 */
    ossl_sm4_decrypt(block_sm4, block_sm4, &key);
    WBSM4_bsdummyshuffling_dec(block_wbsm4_dsdummyshuffling, block_wbsm4_dsdummyshuffling);
    if (!TEST_mem_eq(block_sm4, SM4_BLOCK_SIZE, block_wbsm4_dsdummyshuffling, SM4_BLOCK_SIZE)){
        return 0;
    }
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
