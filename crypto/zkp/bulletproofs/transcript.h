/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BP_TRANSCRIPT_LOCAL_H
# define HEADER_BP_TRANSCRIPT_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include "internal/refcount.h"

typedef struct bp_transcript_method_st BP_TRANSCRIPT_METHOD;
typedef struct bp_transcript_st BP_TRANSCRIPT;

struct bp_transcript_method_st {
    int (*init)(BP_TRANSCRIPT *transcript);
    int (*reset)(BP_TRANSCRIPT *transcript);
    int (*cleanup)(BP_TRANSCRIPT *transcript);
    int (*append_int64)(BP_TRANSCRIPT *transcript, const char *label, int64_t i64);
    int (*append_str)(BP_TRANSCRIPT *transcript, const char *label,
                      const char *str, int len);
    int (*append_point)(BP_TRANSCRIPT *transcript, const char *label,
                        const EC_POINT *point, const EC_GROUP *group);
    int (*append_bn)(BP_TRANSCRIPT *transcript, const char *label, const BIGNUM *bn);
    int (*challange)(BP_TRANSCRIPT *transcript, const char *label, BIGNUM *out);
};

struct bp_transcript_st {
    char *label;
    void *data;
    const BP_TRANSCRIPT_METHOD *method;
};

BP_TRANSCRIPT *BP_TRANSCRIPT_new(const BP_TRANSCRIPT_METHOD *method,
                                 const char *label);
BP_TRANSCRIPT *BP_TRANSCRIPT_dup(const BP_TRANSCRIPT *src);
void BP_TRANSCRIPT_free(BP_TRANSCRIPT *transcript);
int BP_TRANSCRIPT_reset(BP_TRANSCRIPT *transcript);

int BP_TRANSCRIPT_append_int64(BP_TRANSCRIPT *transcript, const char *label,
                               int64_t i64);
int BP_TRANSCRIPT_append_str(BP_TRANSCRIPT *transcript, const char *label,
                             const char *str, int len);
int BP_TRANSCRIPT_append_point(BP_TRANSCRIPT *transcript, const char *label,
                                const EC_POINT *point, const EC_GROUP *group);
int BP_TRANSCRIPT_append_bn(BP_TRANSCRIPT *transcript, const char *label, const BIGNUM *bn);
int BP_TRANSCRIPT_challange(BP_TRANSCRIPT *transcript, const char *label, BIGNUM *out);

# ifdef  __cplusplus
}
# endif

#endif

