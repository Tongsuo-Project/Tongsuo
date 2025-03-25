/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include <stdint.h> 
#include <openssl/opensslconf.h>
#ifndef NONLINEARWBSM4_NONLINEARWBSM4_H
#define NONLINEARWBSM4_NONLINEARWBSM4_H
# ifdef OPENSSL_NO_NONLINEARWBSM4
#  error NONLINEARWBSM4 is disabled.
# endif
#include "NonlinearWBMatrix.h"

/* 定义查找表数据结构 */
typedef struct {
    /* Part1 Tables  */
    uint8_t part1_table1[32][4][256];
    uint8_t part1_table2[32][4][256];
    uint8_t part1_table3[32][4][256];

    /* Part2 Tables */
    uint32_t part2_table[32][4][256];
    uint8_t part2_table_temp[32][4][256];

    /* Part3 Tables*/
    uint8_t part3_table1[32][4][256];
    uint8_t part3_table1_dec[32][4][256];
    uint8_t part3_table2[32][4][256];

    /* Part4 Tables */
    uint8_t part4_1_table[32][4][65536];
    uint8_t part4_2_table[32][4][65536];
    uint8_t part4_3_table[32][4][65536];
    uint8_t part4_3_table_dec[32][4][65536];

    /* P */
    Nonlinear32 P[36];
    Nonlinear32 P_inv[36];
} WB_SM4_Tables;

/*白盒查找表生成 */
void Nonlinearwbsm4_generate_tables(const uint8_t key[16], WB_SM4_Tables* tables);
/* 白盒加密核心接口 */
void Nonlinearwbsm4_encrypt(const unsigned char IN[16], unsigned char OUT[16], const WB_SM4_Tables* tables);
/* 白盒加密核心接口*/
void Nonlinearwbsm4_decrypt(const unsigned char IN[16], unsigned char OUT[16], const WB_SM4_Tables* tables);
#endif 
