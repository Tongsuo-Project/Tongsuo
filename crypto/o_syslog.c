/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdarg.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include "internal/nelem.h"

static int logging = 0;

void OSSL_enable_syslog(void)
{
    logging = 1;
}

void OSSL_disable_syslog(void)
{
    logging = 0;
}

void OSSL_syslog(int priority, const char *message, ...)
{
    va_list args;
    unsigned char buf[4096];
    BIO *bio = NULL;
    size_t i;
    int written = 0, ret;
    const struct {
        int log_level;
        const char *str;
    } mapping[] = {
        { LOG_EMERG, "EMERG" },
        { LOG_ALERT, "ALERT" },
        { LOG_CRIT, "CRIT" },
        { LOG_ERR, "ERROR" },
        { LOG_WARNING, "WARNING" },
        { LOG_NOTICE, "NOTICE" },
        { LOG_INFO, "INFO" },
        { LOG_DEBUG, "DEBUG" },
    };

    if (logging == 0)
        return;

    bio = BIO_new(BIO_s_log());
    if (bio == NULL)
        return;
    
    for (i = 0; i < OSSL_NELEM(mapping); i++) {
        if (mapping[i].log_level == priority) {
            ret = BIO_snprintf((char *)buf, sizeof(buf), "%s ", mapping[i].str);
            if (ret < 0)
                goto end;
            
            written += ret;
            break;
        }
    }

    va_start(args, message);
    ret = BIO_vsnprintf((char *)buf, sizeof(buf) - written, message, args);
    va_end(args);

    if (ret < 0)
        goto end;

    written += ret;

    if (BIO_write(bio, buf, written) != written)
        goto end;

end:
    BIO_free(bio);
}
