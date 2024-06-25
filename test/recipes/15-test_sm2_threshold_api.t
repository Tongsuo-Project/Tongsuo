#! /usr/bin/env perl
# Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use OpenSSL::Test;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_threshold_sm2_api");

plan skip_all => "This test is unsupported in a no-sm2_threshold build"
    if disabled("sm2_threshold");

simple_test("test_threshold_sm2_api", "sm2_threshold_test", "sm2");
