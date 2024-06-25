/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_INTERNAL_SMTC_NAMES_H
# define OSSL_INTERNAL_SMTC_NAMES_H
# pragma once

# include <openssl/e_os2.h>

# define OSSL_PROV_SMTC_PARAM_MODULE_PATH          "module-path"
# define OSSL_PROV_SMTC_PARAM_MODULE_MAC           "module-mac"
# define OSSL_PROV_SMTC_PARAM_ADMIN_PASS           "admin-pass"
# define OSSL_PROV_SMTC_PARAM_ADMIN_SALT           "admin-salt"
# define OSSL_PROV_SMTC_PARAM_SHOW_SELFTEST        "show-selftest"
# define OSSL_PROV_SMTC_PARAM_RNG_POWERON_TEST     "rng-poweron-test"
# define OSSL_PROV_SMTC_PARAM_RNG_CONTINUOUS_TEST  "rng-continuous-test"
# define OSSL_PROV_SMTC_PARAM_RANDOMNESS_POWERON_TEST "randomness-poweron-test"

# ifndef OPENSSL_NO_SMTC_DEBUG
#  define OSSL_PROV_SMTC_PARAM_MODULE_VERIFY_MAC   "verify-mac"
#  define OSSL_PROV_SMTC_PARAM_MODULE_VERIFY_PASS  "verify-pass"
# endif

#endif /* OSSL_INTERNAL_SMTC_NAMES_H */
