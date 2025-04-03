#! /usr/bin/env perl
# Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use warnings;
use OpenSSL::Test;              
use OpenSSL::Test::Simple;      
use OpenSSL::Test::Utils;      

setup("test_internal_nonlinearwbsm4");

simple_test("test_internal_nonlinearwbsm4", "nonlinearwbsm4_internal_test", "nonlinearwbsm4");