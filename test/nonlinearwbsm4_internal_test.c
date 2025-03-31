/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/symbol_prefix.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "testutil.h"
#include "crypto/nonlinearwbsm4.h" 
#ifndef OPENSSL_NO_NONLINEARWBSM4
static int test_nonlinearwbsm4(void)
{
    /* 测试密钥 */
    static const uint8_t k[16] = {
        0x78, 0x3b, 0xd7, 0x63, 0x47, 0xaa, 0x6b, 0xfe,
        0x47, 0x05, 0xeb, 0xc0, 0x60, 0x4a, 0x7b, 0x0f
    };

    /* 测试明文 */
    static const uint8_t input[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    /* 预期加密结果 */
    static const uint8_t expected[16] = {
        0x32, 0x1a, 0xfa, 0xbb, 0x83, 0x47, 0xb5, 0xff,
        0x94, 0x07, 0x78, 0xb4, 0xf6, 0xdf, 0x1b, 0x37
    };

    WB_SM4_Tables *tables = NULL;
    uint8_t encrypted[16];
    uint8_t decrypted[16];
    int ret = 0;

    /* 分配白盒表内存 */
    tables = OPENSSL_zalloc(sizeof(WB_SM4_Tables)); 
    if (!TEST_ptr(tables))
        goto err;

    /* 生成白盒查找表 */
    Nonlinearwbsm4_generate_tables(k, tables);

    /* 执行白盒加密 */
    Nonlinearwbsm4_encrypt(input, encrypted, tables);
    if (!TEST_mem_eq(encrypted, sizeof(encrypted), expected, sizeof(expected)))
        goto err;

    /* 执行白盒解密 */
    Nonlinearwbsm4_decrypt(encrypted, decrypted, tables);
    if (!TEST_mem_eq(decrypted, sizeof(decrypted), input, sizeof(input)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(tables);
    return ret;
}
static int test_nonlinearwbsm4_random_gen_tables(void)
{
    uint8_t key[16];
    WB_SM4_Tables *tables1 = NULL;
    WB_SM4_Tables *tables2 = NULL;
    int ret = 0;

    /* 生成随机密钥 */
    if (!TEST_true(RAND_bytes(key, sizeof(key))))
        goto err;

    tables1 = OPENSSL_zalloc(sizeof(WB_SM4_Tables));
    tables2 = OPENSSL_zalloc(sizeof(WB_SM4_Tables));
    if (!TEST_ptr(tables1) || !TEST_ptr(tables2))
        goto err;

    /* 生成两次白盒表 */
    Nonlinearwbsm4_generate_tables(key, tables1);
    Nonlinearwbsm4_generate_tables(key, tables2);

    /* 比较两个表结构体内容是否不同 */
    if (!TEST_mem_ne(tables1, sizeof(WB_SM4_Tables), tables2, sizeof(WB_SM4_Tables)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(tables1);
    OPENSSL_free(tables2);
    return ret;
}

#ifndef OPENSSL_NO_SM4
#include "crypto/sm4.h"
static int test_nonlinearwbsm4_random_key_and_input(void)
{
    uint8_t key[SM4_BLOCK_SIZE];
    uint8_t input[SM4_BLOCK_SIZE];
    uint8_t encrypted_std[SM4_BLOCK_SIZE], encrypted_wb[SM4_BLOCK_SIZE];
    uint8_t decrypted_std[SM4_BLOCK_SIZE], decrypted_wb[SM4_BLOCK_SIZE];
    WB_SM4_Tables *tables = NULL;
    SM4_KEY sm4_key;
    int ret = 0;

    /* 生成随机密钥和明文 */
    if (!TEST_true(RAND_bytes(key, sizeof(key))))
        goto err;
    if (!TEST_true(RAND_bytes(input, sizeof(input))))
        goto err;

    /* 初始化白盒表 */
    tables = OPENSSL_zalloc(sizeof(WB_SM4_Tables));
    if (!TEST_ptr(tables))
        goto err;
    Nonlinearwbsm4_generate_tables(key, tables);

    /* 初始化标准SM4密钥 */
    ossl_sm4_set_key(key, &sm4_key);

    /* 标准SM4加密 */
    ossl_sm4_encrypt(input, encrypted_std, &sm4_key);
    /* 白盒加密 */
    Nonlinearwbsm4_encrypt(input, encrypted_wb, tables);
    if (!TEST_mem_eq(encrypted_std, sizeof(encrypted_std), encrypted_wb, sizeof(encrypted_wb)))
        goto err;

    /* 标准SM4解密 */
    ossl_sm4_decrypt(encrypted_std, decrypted_std, &sm4_key);
    if (!TEST_mem_eq(decrypted_std, sizeof(decrypted_std), input, sizeof(input)))
        goto err;

    /* 白盒解密 */
    Nonlinearwbsm4_decrypt(encrypted_wb, decrypted_wb, tables);
    if (!TEST_mem_eq(decrypted_wb, sizeof(decrypted_wb), input, sizeof(input)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(tables);
    return ret;
}
#endif
#endif
int setup_tests(void)
{
#ifndef OPENSSL_NO_NONLINEARWBSM4
    ADD_TEST(test_nonlinearwbsm4);
    ADD_TEST(test_nonlinearwbsm4_random_gen_tables);
    #ifndef OPENSSL_NO_SM4
    ADD_TEST(test_nonlinearwbsm4_random_key_and_input);
#endif
#endif

    return 1;
}
