#! /usr/bin/env perl
# Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
#
# Licensed under the BabaSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE

use strict;
use OpenSSL::Test qw/:DEFAULT bldtop_dir/;
use OpenSSL::Test::Utils;

my $test_name = "test_ecpmeth";
setup($test_name);

plan skip_all => "$test_name not supported for this build"
    if disabled("ec") || disabled("engine") || disabled("dynamic-engine");

plan tests => 1;

$ENV{OPENSSL_ENGINES} = bldtop_dir("engines");

ok(run(test(["ecpmeth_test"])), "running ecpmeth_test");
