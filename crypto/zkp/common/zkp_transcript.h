/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_ZKP_TRANSCRIPT_LOCAL_H
# define HEADER_ZKP_TRANSCRIPT_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/zkp_transcript.h>

struct zkp_transcript_method_st {
    int (*init)(ZKP_TRANSCRIPT *transcript);
    int (*reset)(ZKP_TRANSCRIPT *transcript);
    int (*cleanup)(ZKP_TRANSCRIPT *transcript);
    int (*append_int64)(ZKP_TRANSCRIPT *transcript, const char *label, int64_t i64);
    int (*append_str)(ZKP_TRANSCRIPT *transcript, const char *label,
                      const char *str, int len);
    int (*append_point)(ZKP_TRANSCRIPT *transcript, const char *label,
                        const EC_POINT *point, const EC_GROUP *group);
    int (*append_bn)(ZKP_TRANSCRIPT *transcript, const char *label, const BIGNUM *bn);
    int (*challange)(ZKP_TRANSCRIPT *transcript, const char *label, BIGNUM *out);
};

struct zkp_transcript_st {
    char *label;
    void *data;
    const ZKP_TRANSCRIPT_METHOD *method;
};

# ifdef  __cplusplus
}
# endif

#endif

