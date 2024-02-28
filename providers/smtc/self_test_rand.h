/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/types.h>

int rand_self_test_frequency(const unsigned char *buf, size_t nbit, double *P_value);
int rand_self_test_block_frequency(const unsigned char *buf,
                                   size_t len,
                                   size_t m,
                                   double *P_value);
int rand_self_test_poker(const unsigned char *buf, size_t nbit, size_t m,
                         double *P_value);
int rand_self_test_serial(const unsigned char *buf,
                          size_t nbit,
                          size_t m,
                          double *P1,
                          double *P2);
int rand_self_test_runs(const unsigned char *buf, size_t nbit, double *P);
int rand_self_test_runs_distribution(const unsigned char *buf, size_t nbit, double *P);
int rand_self_test_longest_run_of_ones(const unsigned char *buf, size_t nbit, double *P);
int rand_self_test_binary_derivation(const unsigned char *buf, size_t nbit,
                                     size_t k, double *P);
int rand_self_test_self_correlation(const unsigned char *buf, size_t nbit,
                                    size_t d, double *P);
int rand_self_test_binary_matrix_rank(const unsigned char *buf, size_t nbit,
                                      double *P);
int rand_self_test_cumulative_sums(const unsigned char *buf,
                                   size_t nbit,
                                   double *P1,
                                   double *P2);
int rand_self_test_approximate_entropy(const unsigned char *buf,
                                       size_t nbit,
                                       size_t m,
                                       double *P);
int rand_self_test_linear_complexity(const unsigned char *buf, size_t nbit,
                                     size_t M, double *P);
int rand_self_test_maurer_universal_statistical(const unsigned char *buf,
                                                size_t nbit, double *P);
int rand_self_test_discrete_fourier_transform(const unsigned char *buf,
                                              size_t nbit, double *P);

int smtc_rand_delivery_test(OSSL_SELF_TEST *st, int sdf);
int smtc_rand_poweron_test(OSSL_SELF_TEST *st, int sdf);
int smtc_rand_cyclical_test(OSSL_SELF_TEST *st, int sdf);
int smtc_rand_single_test(OSSL_SELF_TEST *st, int sdf);
