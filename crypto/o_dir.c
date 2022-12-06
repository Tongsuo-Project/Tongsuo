/*
 * Copyright 2004-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file is dual-licensed and is also available under the following
 * terms:
 *
 * Copyright (c) 2004, 2018, Richard Levitte <richard@levitte.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "internal/e_os.h"
#include <errno.h>
#include "internal/o_dir.h"

#if defined OPENSSL_SYS_UNIX
/* Original LPdir_unix.c */
# include <stddef.h>
# include <stdlib.h>
# include <limits.h>
# include <string.h>
# include <sys/types.h>
# include <dirent.h>
# include <errno.h>

/*
 * The POSIX macro for the maximum number of characters in a file path is
 * NAME_MAX.  However, some operating systems use PATH_MAX instead.
 * Therefore, it seems natural to first check for PATH_MAX and use that, and
 * if it doesn't exist, use NAME_MAX.
 */
# if defined(PATH_MAX)
#  define LP_ENTRY_SIZE PATH_MAX
# elif defined(NAME_MAX)
#  define LP_ENTRY_SIZE NAME_MAX
# endif

/*
 * Of course, there's the possibility that neither PATH_MAX nor NAME_MAX
 * exist.  It's also possible that NAME_MAX exists but is define to a very
 * small value (HP-UX offers 14), so we need to check if we got a result, and
 * if it meets a minimum standard, and create or change it if not.
 */
# if !defined(LP_ENTRY_SIZE) || LP_ENTRY_SIZE<255
#  undef LP_ENTRY_SIZE
#  define LP_ENTRY_SIZE 255
# endif

struct OPENSSL_dir_context_st {
    DIR *dir;
    char entry_name[LP_ENTRY_SIZE + 1];
};

const char *OPENSSL_DIR_read(OPENSSL_DIR_CTX **ctx, const char *directory)
{
    struct dirent *direntry = NULL;

    if (ctx == NULL || directory == NULL) {
        errno = EINVAL;
        return 0;
    }

    errno = 0;
    if (*ctx == NULL) {
        *ctx = malloc(sizeof(**ctx));
        if (*ctx == NULL) {
            errno = ENOMEM;
            return 0;
        }
        memset(*ctx, 0, sizeof(**ctx));

        (*ctx)->dir = opendir(directory);
        if ((*ctx)->dir == NULL) {
            int save_errno = errno; /* Probably not needed, but I'm paranoid */
            free(*ctx);
            *ctx = NULL;
            errno = save_errno;
            return 0;
        }
    }

    direntry = readdir((*ctx)->dir);
    if (direntry == NULL) {
        return 0;
    }

    OPENSSL_strlcpy((*ctx)->entry_name, direntry->d_name,
                    sizeof((*ctx)->entry_name));
    return (*ctx)->entry_name;
}

int OPENSSL_DIR_end(OPENSSL_DIR_CTX **ctx)
{
    if (ctx != NULL && *ctx != NULL) {
        int ret = closedir((*ctx)->dir);

        free(*ctx);
        switch (ret) {
        case 0:
            return 1;
        case -1:
            return 0;
        default:
            break;
        }
    }
    errno = EINVAL;
    return 0;
}
#elif defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
/* Original LPdir_win/win32/wince.c */
# if defined OPENSSL_SYS_WIN32
#  define LP_SYS_WIN32
#  define LP_MULTIBYTE_AVAILABLE
# elif defined OPENSSL_SYS_WINCE
#  define LP_SYS_WINCE
# endif
# include <windows.h>
# include <tchar.h>
# include "internal/numbers.h"

/*
 * We're most likely overcautious here, but let's reserve for broken WinCE
 * headers and explicitly opt for UNICODE call. Keep in mind that our WinCE
 * builds are compiled with -DUNICODE [as well as -D_UNICODE].
 */
# if defined(LP_SYS_WINCE) && !defined(FindFirstFile)
#  define FindFirstFile FindFirstFileW
# endif
# if defined(LP_SYS_WINCE) && !defined(FindNextFile)
#  define FindNextFile FindNextFileW
# endif

# ifndef NAME_MAX
#  define NAME_MAX 255
# endif

# ifdef CP_UTF8
#  define CP_DEFAULT CP_UTF8
# else
#  define CP_DEFAULT CP_ACP
# endif

struct OPENSSL_dir_context_st {
    WIN32_FIND_DATA ctx;
    HANDLE handle;
    char entry_name[NAME_MAX + 1];
};

const char *OPENSSL_DIR_read(OPENSSL_DIR_CTX **ctx, const char *directory)
{
    if (ctx == NULL || directory == NULL) {
        errno = EINVAL;
        return 0;
    }

    errno = 0;
    if (*ctx == NULL) {
        size_t dirlen = strlen(directory);

        if (dirlen == 0 || dirlen > INT_MAX - 3) {
            errno = ENOENT;
            return 0;
        }

        *ctx = malloc(sizeof(**ctx));
        if (*ctx == NULL) {
            errno = ENOMEM;
            return 0;
        }
        memset(*ctx, 0, sizeof(**ctx));

        if (sizeof(TCHAR) != sizeof(char)) {
            TCHAR *wdir = NULL;
            /* len_0 denotes string length *with* trailing 0 */
            size_t index = 0, len_0 = dirlen + 1;
# ifdef LP_MULTIBYTE_AVAILABLE
            int sz = 0;
            UINT cp;

            do {
#  ifdef CP_UTF8
                if ((sz = MultiByteToWideChar((cp = CP_UTF8), 0,
                                              directory, len_0,
                                              NULL, 0)) > 0 ||
                    GetLastError() != ERROR_NO_UNICODE_TRANSLATION)
                    break;
#  endif
                sz = MultiByteToWideChar((cp = CP_ACP), 0,
                                         directory, len_0,
                                         NULL, 0);
            } while (0);

            if (sz > 0) {
                /*
                 * allocate two additional characters in case we need to
                 * concatenate asterisk, |sz| covers trailing '\0'!
                 */
                wdir = _alloca((sz + 2) * sizeof(TCHAR));
                if (!MultiByteToWideChar(cp, 0, directory, len_0,
                                         (WCHAR *)wdir, sz)) {
                    free(*ctx);
                    *ctx = NULL;
                    errno = EINVAL;
                    return 0;
                }
            } else
# endif
            {
                sz = len_0;
                /*
                 * allocate two additional characters in case we need to
                 * concatenate asterisk, |sz| covers trailing '\0'!
                 */
                wdir = _alloca((sz + 2) * sizeof(TCHAR));
                for (index = 0; index < len_0; index++)
                    wdir[index] = (TCHAR)directory[index];
            }

            sz--; /* wdir[sz] is trailing '\0' now */
            if (wdir[sz - 1] != TEXT('*')) {
                if (wdir[sz - 1] != TEXT('/') && wdir[sz - 1] != TEXT('\\'))
                    _tcscpy(wdir + sz, TEXT("/*"));
                else
                    _tcscpy(wdir + sz, TEXT("*"));
            }

            (*ctx)->handle = FindFirstFile(wdir, &(*ctx)->ctx);
        } else {
            if (directory[dirlen - 1] != '*') {
                char *buf = _alloca(dirlen + 3);

                strcpy(buf, directory);
                if (buf[dirlen - 1] != '/' && buf[dirlen - 1] != '\\')
                    strcpy(buf + dirlen, "/*");
                else
                    strcpy(buf + dirlen, "*");

                directory = buf;
            }

            (*ctx)->handle = FindFirstFile((TCHAR *)directory, &(*ctx)->ctx);
        }

        if ((*ctx)->handle == INVALID_HANDLE_VALUE) {
            free(*ctx);
            *ctx = NULL;
            errno = EINVAL;
            return 0;
        }
    } else {
        if (FindNextFile((*ctx)->handle, &(*ctx)->ctx) == FALSE) {
            return 0;
        }
    }
    if (sizeof(TCHAR) != sizeof(char)) {
        TCHAR *wdir = (*ctx)->ctx.cFileName;
        size_t index, len_0 = 0;

        while (wdir[len_0] && len_0 < (sizeof((*ctx)->entry_name) - 1))
            len_0++;
        len_0++;

# ifdef LP_MULTIBYTE_AVAILABLE
        if (!WideCharToMultiByte(CP_DEFAULT, 0, (WCHAR *)wdir, len_0,
                                 (*ctx)->entry_name,
                                 sizeof((*ctx)->entry_name), NULL, 0))
# endif
            for (index = 0; index < len_0; index++)
                (*ctx)->entry_name[index] = (char)wdir[index];
    } else
        strncpy((*ctx)->entry_name, (const char *)(*ctx)->ctx.cFileName,
                sizeof((*ctx)->entry_name) - 1);

    (*ctx)->entry_name[sizeof((*ctx)->entry_name) - 1] = '\0';

    return (*ctx)->entry_name;
}

int OPENSSL_DIR_end(OPENSSL_DIR_CTX **ctx)
{
    if (ctx != NULL && *ctx != NULL) {
        FindClose((*ctx)->handle);
        free(*ctx);
        *ctx = NULL;
        return 1;
    }
    errno = EINVAL;
    return 0;
}
#else
/* Original LPdir_nyi.c */
struct OPENSSL_dir_context_st {
    void *dummy;
};

const char *OPENSSL_DIR_read(OPENSSL_DIR_CTX **ctx, const char *directory)
{
    errno = EINVAL;
    return 0;
}

int OPENSSL_DIR_end(OPENSSL_DIR_CTX **ctx)
{
    errno = EINVAL;
    return 0;
}
#endif
