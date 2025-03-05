#! /usr/bin/env perl
# Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
# Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
# Copyright 2017 [Ribose Inc.](https://www.ribose.com). All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_internal_wbsm4");

if (!disabled("wbsm4-xiaolai")) {
    simple_test("test_internal_wbsm4", "wbsm4_internal_test", "wbsm4-xiaolai");
} elsif (!disabled("wbsm4-baiwu")) {
    simple_test("test_internal_wbsm4", "wbsm4_internal_test", "wbsm4-baiwu");
} elsif (!disabled("wbsm4-wsise")) {
    simple_test("test_internal_wbsm4", "wbsm4_internal_test", "wbsm4-wsise");
} else {
    simple_test("test_internal_wbsm4", "wbsm4_internal_test", "wbsm4-xiaolai",
                "wbsm4-baiwu", "wbsm4-wsise");
}
