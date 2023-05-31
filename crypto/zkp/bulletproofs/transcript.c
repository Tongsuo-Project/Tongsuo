/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/zkpbperr.h>
#include "transcript.h"

BP_TRANSCRIPT *BP_TRANSCRIPT_new(const BP_TRANSCRIPT_METHOD *method,
                                 const char *label)
{
    BP_TRANSCRIPT *transcript = NULL;

    if (method == NULL || label == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    transcript = OPENSSL_zalloc(sizeof(*transcript));
    if (transcript == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    transcript->method = method;
    transcript->label = OPENSSL_strdup(label);
    if (transcript->label == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!transcript->method->init(transcript)) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_TRANSCRIPT_INIT_FAILED);
        goto err;
    }

    return transcript;
err:
    BP_TRANSCRIPT_free(transcript);
    return NULL;
}

BP_TRANSCRIPT *BP_TRANSCRIPT_dup(const BP_TRANSCRIPT *src)
{
    return BP_TRANSCRIPT_new(src->method, src->label);
}

void BP_TRANSCRIPT_free(BP_TRANSCRIPT *transcript)
{
    if (transcript == NULL)
        return;

    if (transcript->method)
        transcript->method->cleanup(transcript);

    OPENSSL_free(transcript->label);
    OPENSSL_free(transcript);
}

int BP_TRANSCRIPT_append_int64(BP_TRANSCRIPT *transcript, const char *label,
                               int64_t i64)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->append_int64(transcript, label, i64);
}

int BP_TRANSCRIPT_append_str(BP_TRANSCRIPT *transcript, const char *label,
                             const char *str, int len)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->append_str(transcript, label, str, len);
}

int BP_TRANSCRIPT_append_point(BP_TRANSCRIPT *transcript, const char *label,
                                const EC_POINT *point, const EC_GROUP *group)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->append_point(transcript, label, point, group);
}

int BP_TRANSCRIPT_append_bn(BP_TRANSCRIPT *transcript, const char *label, const BIGNUM *bn)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->append_bn(transcript, label, bn);
}

int BP_TRANSCRIPT_challange(BP_TRANSCRIPT *transcript, const char *label, BIGNUM *out)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->challange(transcript, label, out);
}

int BP_TRANSCRIPT_reset(BP_TRANSCRIPT *transcript)
{
    if (transcript == NULL || transcript->method == NULL)
        return 0;

    return transcript->method->reset(transcript);
}
