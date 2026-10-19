#! /usr/bin/env perl
# Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
# Licensed under the Apache License 2.0 (the "License").
# You may obtain a copy at https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test qw(:DEFAULT);
use OpenSSL::Test::Utils;

setup("test_sm4th");
plan skip_all => 'SM4th is not supported in this build' if disabled('sm4th');
plan tests => 2;

ok(run(test(["sm4th_test"])), "SM4th s/f regression tests");
ok(run(test(["sm4th_fault_test"])), "SM4th failure propagation and cleanup");
