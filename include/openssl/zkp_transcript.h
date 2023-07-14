/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_ZKP_TRANSCRIPT_H
# define HEADER_ZKP_TRANSCRIPT_H

# include <stdlib.h>
# include <openssl/macros.h>
# include <openssl/opensslconf.h>
# include <openssl/types.h>
# include <openssl/ec.h>

# ifndef OPENSSL_NO_ZKP_TRANSCRIPT
#  ifdef  __cplusplus
extern "C" {
#  endif

typedef struct zkp_transcript_method_st ZKP_TRANSCRIPT_METHOD;
typedef struct zkp_transcript_st ZKP_TRANSCRIPT;

ZKP_TRANSCRIPT *ZKP_TRANSCRIPT_new(const ZKP_TRANSCRIPT_METHOD *method,
                                   const char *label);
ZKP_TRANSCRIPT *ZKP_TRANSCRIPT_dup(const ZKP_TRANSCRIPT *src);
void ZKP_TRANSCRIPT_free(ZKP_TRANSCRIPT *transcript);
int ZKP_TRANSCRIPT_reset(ZKP_TRANSCRIPT *transcript);

int ZKP_TRANSCRIPT_append_int64(ZKP_TRANSCRIPT *transcript, const char *label,
                                int64_t i64);
int ZKP_TRANSCRIPT_append_str(ZKP_TRANSCRIPT *transcript, const char *label,
                              const char *str, int len);
int ZKP_TRANSCRIPT_append_point(ZKP_TRANSCRIPT *transcript, const char *label,
                                const EC_POINT *point, const EC_GROUP *group);
int ZKP_TRANSCRIPT_append_bn(ZKP_TRANSCRIPT *transcript, const char *label,
                             const BIGNUM *bn);
int ZKP_TRANSCRIPT_challange(ZKP_TRANSCRIPT *transcript, const char *label,
                             BIGNUM *out);

const ZKP_TRANSCRIPT_METHOD *ZKP_TRANSCRIPT_METHOD_sha256(void);

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
