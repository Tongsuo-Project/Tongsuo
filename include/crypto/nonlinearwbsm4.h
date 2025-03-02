//
// Created by fuyu on 2025-03-01.
//
#include "NonlinearWBMatrix.h"
#ifndef NONLINEARWBSM4_NONLINEARWBSM4_H
#define NONLINEARWBSM4_NONLINEARWBSM4_H

#endif //NONLINEARWBSM4_NONLINEARWBSM4_H
// 定义查找表数据结构
typedef struct {
    // Part1 Tables
    uint8_t(*part1_table1)[4][256];
    uint8_t(*part1_table2)[4][256];
    uint8_t(*part1_table3)[4][256];

    // Part2 Tables
    uint32_t(*part2_table)[4][256];
    uint8_t(*part2_table_temp)[4][256];

    // Part3 Tables
    uint8_t(*part3_table1)[4][256];
    uint8_t(*part3_table1_dec)[4][256];
    uint8_t(*part3_table2)[4][256];

    // Part4 Tables
    uint8_t(*part4_1_table)[4][65536];
    uint8_t(*part4_2_table)[4][65536];
    uint8_t(*part4_3_table)[4][65536];
    uint8_t(*part4_3_table_dec)[4][65536];

    // P盒
    Nonlinear32* P;
    Nonlinear32* P_inv;
} WB_SM4_Tables;

//白盒查找表生成
void Nonlinearwbsm4_generate_tables(const uint8_t key[16], WB_SM4_Tables* tables);
// 白盒加密核心接口
void Nonlinearwbsm4_encrypt(const unsigned char IN[16], unsigned char OUT[16], const WB_SM4_Tables* tables);
// 白盒加密核心接口
void Nonlinearwbsm4_decrypt(const unsigned char IN[16], unsigned char OUT[16], const WB_SM4_Tables* tables);
//释放内存
void Nonlinearwbsm4_free_tables(WB_SM4_Tables* tables); //