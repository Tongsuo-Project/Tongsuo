/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/zkperr.h>
#include "zkp_transcript.h"

ZKP_TRANSCRIPT *ZKP_TRANSCRIPT_new(const ZKP_TRANSCRIPT_METHOD *method,
                                   const char *label)
{
    ZKP_TRANSCRIPT *transcript = NULL;

    if (method == NULL || label == NULL) {
        return NULL;
    }

    transcript = OPENSSL_zalloc(sizeof(*transcript));
    if (transcript == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    transcript->method = method;
    transcript->label = OPENSSL_strdup(label);
    if (transcript->label == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!transcript->method->init(transcript)) {
        ERR_raise(ERR_LIB_ZKP, ZKP_R_TRANSCRIPT_INIT_FAILED);
        goto err;
    }

    return transcript;
err:
    ZKP_TRANSCRIPT_free(transcript);
    return NULL;
}

ZKP_TRANSCRIPT *ZKP_TRANSCRIPT_dup(const ZKP_TRANSCRIPT *src)
{
    return ZKP_TRANSCRIPT_new(src->method, src->label);
}

void ZKP_TRANSCRIPT_free(ZKP_TRANSCRIPT *transcript)
{
    if (transcript == NULL)
        return;

    if (transcript->method)
        transcript->method->cleanup(transcript);

    OPENSSL_free(transcript->label);
    OPENSSL_free(transcript);
}

int ZKP_TRANSCRIPT_append_int64(ZKP_TRANSCRIPT *transcript, const char *label,
                                int64_t i64)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->append_int64(transcript, label, i64);
}

int ZKP_TRANSCRIPT_append_str(ZKP_TRANSCRIPT *transcript, const char *label,
                              const char *str, int len)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->append_str(transcript, label, str, len);
}

int ZKP_TRANSCRIPT_append_point(ZKP_TRANSCRIPT *transcript, const char *label,
                                const EC_POINT *point, const EC_GROUP *group)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->append_point(transcript, label, point, group);
}

int ZKP_TRANSCRIPT_append_bn(ZKP_TRANSCRIPT *transcript, const char *label,
                             const BIGNUM *bn)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->append_bn(transcript, label, bn);
}

int ZKP_TRANSCRIPT_challange(ZKP_TRANSCRIPT *transcript, const char *label,
                             BIGNUM *out)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->challange(transcript, label, out);
}

int ZKP_TRANSCRIPT_reset(ZKP_TRANSCRIPT *transcript)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->reset(transcript);
}
