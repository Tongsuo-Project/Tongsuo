/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined (__TANDEM) && defined (_SPT_MODEL_)
/*
 * These definitions have to come first in SPT due to scoping of the
 * declarations in c99 associated with SPT use of stat.
 */
# include <sys/types.h>
# include <sys/stat.h>
#endif

#include "internal/cryptlib.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>

#include <sys/types.h>
#ifndef OPENSSL_NO_POSIX_IO
# include <sys/stat.h>
# include <fcntl.h>
# if defined(_WIN32) && !defined(_WIN32_WCE)
#  include <windows.h>
#  include <io.h>
#  define stat    _stat
#  define chmod   _chmod
#  define open    _open
#  define fdopen  _fdopen
#  define fstat   _fstat
#  define fileno  _fileno
# endif
#endif

/*
 * Following should not be needed, and we could have been stricter
 * and demand S_IS*. But some systems just don't comply... Formally
 * below macros are "anatomically incorrect", because normally they
 * would look like ((m) & MASK == TYPE), but since MASK availability
 * is as questionable, we settle for this poor-man fallback...
 */
# if !defined(S_ISREG)
#   define S_ISREG(m) ((m) & S_IFREG)
# endif

#define RAND_BUF_SIZE 1024
#define RFILE ".rnd"

/*
 * Note that these functions are intended for seed files only. Entropy
 * devices and EGD sockets are handled in rand_unix.c  If |bytes| is
 * -1 read the complete file; otherwise read the specified amount.
 */
int RAND_load_file(const char *file, long bytes)
{
    /*
     * The load buffer size exceeds the chunk size by the comfortable amount
     * of 'RAND_DRBG_STRENGTH' bytes (not bits!). This is done on purpose
     * to avoid calling RAND_add() with a small final chunk. Instead, such
     * a small final chunk will be added together with the previous chunk
     * (unless it's the only one).
     */
#define RAND_LOAD_BUF_SIZE (RAND_BUF_SIZE + RAND_DRBG_STRENGTH)
    unsigned char buf[RAND_LOAD_BUF_SIZE];

#ifndef OPENSSL_NO_POSIX_IO
    struct stat sb;
#endif
    int i, n, ret = 0;
    FILE *in;

    if (bytes == 0)
        return 0;

    if ((in = openssl_fopen(file, "rb")) == NULL) {
        ERR_raise_data(ERR_LIB_RAND, RAND_R_CANNOT_OPEN_FILE,
                       "Filename=%s", file);
        return -1;
    }

#ifndef OPENSSL_NO_POSIX_IO
    if (fstat(fileno(in), &sb) < 0) {
        ERR_raise_data(ERR_LIB_RAND, RAND_R_INTERNAL_ERROR,
                       "Filename=%s", file);
        fclose(in);
        return -1;
    }

    if (bytes < 0) {
        if (S_ISREG(sb.st_mode))
            bytes = sb.st_size;
        else
            bytes = RAND_DRBG_STRENGTH;
    }
#endif
    /*
     * Don't buffer, because even if |file| is regular file, we have
     * no control over the buffer, so why would we want a copy of its
     * contents lying around?
     */
    setbuf(in, NULL);

    for ( ; ; ) {
        if (bytes > 0)
            n = (bytes <= RAND_LOAD_BUF_SIZE) ? (int)bytes : RAND_BUF_SIZE;
        else
            n = RAND_LOAD_BUF_SIZE;
        i = fread(buf, 1, n, in);
#ifdef EINTR
        if (ferror(in) && errno == EINTR){
            clearerr(in);
            if (i == 0)
                continue;
        }
#endif
        if (i == 0)
            break;

        RAND_add(buf, i, (double)i);
        ret += i;

        /* If given a bytecount, and we did it, break. */
        if (bytes > 0 && (bytes -= i) <= 0)
            break;
    }

    OPENSSL_cleanse(buf, sizeof(buf));
    fclose(in);
    if (!RAND_status()) {
        ERR_raise_data(ERR_LIB_RAND, RAND_R_RESEED_ERROR, "Filename=%s", file);
        return -1;
    }

    return ret;
}

int RAND_write_file(const char *file)
{
    unsigned char buf[RAND_BUF_SIZE];
    int ret = -1;
    FILE *out = NULL;
#ifndef OPENSSL_NO_POSIX_IO
    struct stat sb;

    if (stat(file, &sb) >= 0 && !S_ISREG(sb.st_mode)) {
        ERR_raise_data(ERR_LIB_RAND, RAND_R_NOT_A_REGULAR_FILE,
                       "Filename=%s", file);
        return -1;
    }
#endif

    /* Collect enough random data. */
    if (RAND_priv_bytes(buf, (int)sizeof(buf)) != 1)
        return  -1;

#if defined(O_CREAT) && !defined(OPENSSL_NO_POSIX_IO) && \
    !defined(OPENSSL_SYS_WINDOWS)
    {
# ifndef O_BINARY
#  define O_BINARY 0
# endif
        /*
         * chmod(..., 0600) is too late to protect the file, permissions
         * should be restrictive from the start
         */
        int fd = open(file, O_WRONLY | O_CREAT | O_BINARY, 0600);
        if (fd != -1)
            out = fdopen(fd, "wb");
    }
#endif

    if (out == NULL)
        out = openssl_fopen(file, "wb");
    if (out == NULL) {
        ERR_raise_data(ERR_LIB_RAND, RAND_R_CANNOT_OPEN_FILE,
                       "Filename=%s", file);
        return -1;
    }

#if !defined(NO_CHMOD) && !defined(OPENSSL_NO_POSIX_IO)
    /*
     * Yes it's late to do this (see above comment), but better than nothing.
     */
    chmod(file, 0600);
#endif

    ret = fwrite(buf, 1, RAND_BUF_SIZE, out);
    fclose(out);
    OPENSSL_cleanse(buf, RAND_BUF_SIZE);
    return ret;
}

const char *RAND_file_name(char *buf, size_t size)
{
    char *s = NULL;
    size_t len;
    int use_randfile = 1;

#if defined(_WIN32) && defined(CP_UTF8) && !defined(_WIN32_WCE)
    DWORD envlen;
    WCHAR *var;

    /* Look up various environment variables. */
    if ((envlen = GetEnvironmentVariableW(var = L"RANDFILE", NULL, 0)) == 0) {
        use_randfile = 0;
        if ((envlen = GetEnvironmentVariableW(var = L"HOME", NULL, 0)) == 0
                && (envlen = GetEnvironmentVariableW(var = L"USERPROFILE",
                                                  NULL, 0)) == 0)
            envlen = GetEnvironmentVariableW(var = L"SYSTEMROOT", NULL, 0);
    }

    /* If we got a value, allocate space to hold it and then get it. */
    if (envlen != 0) {
        int sz;
        WCHAR *val = _alloca(envlen * sizeof(WCHAR));

        if (GetEnvironmentVariableW(var, val, envlen) < envlen
                && (sz = WideCharToMultiByte(CP_UTF8, 0, val, -1, NULL, 0,
                                             NULL, NULL)) != 0) {
            s = _alloca(sz);
            if (WideCharToMultiByte(CP_UTF8, 0, val, -1, s, sz,
                                    NULL, NULL) == 0)
                s = NULL;
        }
    }
#else
    if ((s = ossl_safe_getenv("RANDFILE")) == NULL || *s == '\0') {
        use_randfile = 0;
        s = ossl_safe_getenv("HOME");
    }
#endif

#ifdef DEFAULT_HOME
    if (!use_randfile && s == NULL)
        s = DEFAULT_HOME;
#endif
    if (s == NULL || *s == '\0')
        return NULL;

    len = strlen(s);
    if (use_randfile) {
        if (len + 1 >= size)
            return NULL;
        strcpy(buf, s);
    } else {
        if (len + 1 + strlen(RFILE) + 1 >= size)
            return NULL;
        strcpy(buf, s);
        strcat(buf, "/");
        strcat(buf, RFILE);
    }

    return buf;
}
