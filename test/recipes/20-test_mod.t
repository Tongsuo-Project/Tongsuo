#! /usr/bin/env perl
# Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use warnings;

use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use Cwd qw(abs_path);

setup("test_mod");

plan skip_all => "Test only supported in a smtc build" if disabled("smtc");
plan tests => 1;

$ENV{OPENSSL_CONF} = abs_path(srctop_file("test", "smtc-and-base.cnf"));

ok(run(app(['openssl', 'mod', '-test'])), "mod self test");
