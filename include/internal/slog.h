/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_INTERNAL_SLOG_H
# define OSSL_INTERNAL_SLOG_H

# ifndef NO_SYSLOG
#  if defined(OPENSSL_SYS_WIN32)
#   define LOG_EMERG       0
#   define LOG_ALERT       1
#   define LOG_CRIT        2
#   define LOG_ERR         3
#   define LOG_WARNING     4
#   define LOG_NOTICE      5
#   define LOG_INFO        6
#   define LOG_DEBUG       7
#   define LOG_DAEMON      (3<<3)
#  elif (!defined(MSDOS) || defined(WATT32)) && !defined(OPENSSL_SYS_VXWORKS) && !defined(OPENSSL_SYS_WINCE)
#   include <syslog.h>
#  endif
# endif

void ossl_syslog(int priority, const char *message, ...);

#endif
