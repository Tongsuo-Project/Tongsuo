#! /usr/bin/env perl
# Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_mod_sm2");

my $no_smtc = disabled('smtc') || disabled('smtc-debug');

if (!$no_smtc) {
    $ENV{OPENSSL_CONF} = srctop_file("test", "smtc.cnf");
}

simple_test("test_mod_sm2", "sm2_mod_test", "sm2");
