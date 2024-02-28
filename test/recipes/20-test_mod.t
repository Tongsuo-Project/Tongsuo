#! /usr/bin/env perl
# Copyright 2023-2024 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

setup("test_mod");

plan skip_all => "Test only supported in a smtc build" if disabled("smtc");
plan tests => 2;

$ENV{OPENSSL_CONF} = srctop_file("test", "smtc.cnf");

ok(run(app(['openssl', 'mod', '-test'])), "mod self test");
ok(run(app(['openssl', 'mod', '-status'])), "mod show status");
