/*
 * Copyright 2022-2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Tests for the gm rand self test
 */

#include <string.h>
#include "testutil.h"
#include "providers/smtc/self_test_rand.h"
#include "smtc_rand_self_test.h"


static unsigned char *bits2buf(const char *bits)
{
    size_t i;
    size_t nbit = strlen(bits);
    size_t len = (nbit + 7) / 8;
    unsigned char *buf = OPENSSL_malloc(len);
    if (buf == NULL)
        return NULL;

    memset(buf, 0, len);

    for (i = 0; i < nbit; i++)
        buf[i / 8] |= (bits[i] - '0') << (7 - i % 8);

    return buf;
}

/*
 * Test vectors from GM/T 0005-2021, Appendix C
 */
static int test_smtc_rand_self_test(void)
{
    int ret = 0;
    const unsigned char *bits128 = bits2buf("11001100000101010110110001001100111000000000001001001101010100010001001111010110100000001101011111001100111001101101100010110010");
    const unsigned char *bits100 = bits2buf("1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000");
    double actual_P = 0.0;
    double actual_P1 = 0.0;
    double actual_P2 = 0.0;

    if (!TEST_ptr(bits128) || !TEST_ptr(bits100))
        goto end;

    TEST_true(sizeof(million_bits_of_e) == 1000000 / 8);
    if (!TEST_true(rand_self_test_frequency(bits128, 128, &actual_P))
        || !TEST_double_eq(0.215925, actual_P)
        || !TEST_true(rand_self_test_block_frequency(bits100, 100, 10, &actual_P))
        || !TEST_double_eq(0.706438, actual_P)
        || !TEST_true(rand_self_test_poker(bits128, 128, 4, &actual_P))
        || !TEST_double_eq(0.213734, actual_P)
        || !TEST_true(
            rand_self_test_serial(bits128, 128, 2, &actual_P1, &actual_P2))
        || !TEST_double_eq(0.436868, actual_P1)
        || !TEST_double_eq(0.723674, actual_P2)
        || !TEST_true(rand_self_test_runs(bits128, 128, &actual_P))
        || !TEST_double_eq(0.620729, actual_P)
        || !TEST_true(
            rand_self_test_runs_distribution(bits128, 128, &actual_P))
        || !TEST_double_eq(0.970152, actual_P)
        || !TEST_true(
            rand_self_test_longest_run_of_ones(bits128, 128, &actual_P))
        || !TEST_double_eq(0.180598, actual_P)
        || !TEST_true(
            rand_self_test_binary_derivation(bits128, 128, 3, &actual_P))
        || !TEST_double_eq(0.039669, actual_P)
        || !TEST_true(
            rand_self_test_self_correlation(bits128, 128, 1, &actual_P))
        || !TEST_double_eq(0.790080, actual_P)
        || !TEST_true(rand_self_test_binary_matrix_rank(million_bits_of_e,
                                                        1000000,
                                                        &actual_P))
        || !TEST_double_eq(0.307543, actual_P)
        || !TEST_true(rand_self_test_cumulative_sums(bits100, 100, &actual_P1,
                                                     &actual_P2))
        || !TEST_double_eq(0.219194, actual_P1)
        || !TEST_double_eq(0.114866, actual_P2)
        || !TEST_true(rand_self_test_approximate_entropy(bits100, 100, 2,
                                                         &actual_P))
        || !TEST_double_eq(0.235301, actual_P)
        || !TEST_true(rand_self_test_linear_complexity(million_bits_of_e,
                                                       1000000, 1000,
                                                       &actual_P))
        || !TEST_double_eq(0.844721, actual_P)
        || !TEST_true(rand_self_test_maurer_universal_statistical(
                            million_bits_of_e, 1000000, &actual_P))
        || !TEST_double_eq(0.282568, actual_P)
        || !TEST_true(rand_self_test_discrete_fourier_transform(bits100, 100, &actual_P))
        || !TEST_double_eq(0.654721, actual_P))
        goto end;

    ret = 1;
end:
    OPENSSL_free((void *)bits128);
    OPENSSL_free((void *)bits100);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_smtc_rand_self_test);

    return 1;
}
