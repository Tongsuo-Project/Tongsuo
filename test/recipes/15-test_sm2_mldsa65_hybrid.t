#! /usr/bin/env perl
# Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_sm2_mldsa65_hybrid");

simple_test("test_sm2_mldsa65_hybrid", "sm2_mldsa65_hybrid_test", "sm2-mldsa65-hybrid");
