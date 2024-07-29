#! /usr/bin/env perl
# Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_tsapi");

my $no_smtc = disabled('smtc') || disabled('smtc-debug');

if (!$no_smtc) {
    my $smtcconf = srctop_file("test", "smtc.cnf");
    $ENV{OPENSSL_CONF} = $smtcconf;
}

simple_test("test_tsapi", "tsapi_test");
