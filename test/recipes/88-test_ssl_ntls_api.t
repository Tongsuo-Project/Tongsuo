#! /usr/bin/env perl
# Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use OpenSSL::Test;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_ssl_ntls_api");

plan tests => 1;

SKIP: {
    skip "Skipping NTLS test because ntls is disabled in this build", 1
        if disabled("ntls");

    ok(run(test([ "ssl_ntls_api_test",
        srctop_file("test", "certs", "sm2", "server_sign.crt"),
        srctop_file("test", "certs", "sm2", "server_sign.key"),
        srctop_file("test", "certs", "sm2", "server_enc.crt"),
        srctop_file("test", "certs", "sm2", "server_enc.key"),
        srctop_file("test", "certs", "server-rsa-sign.crt"),
        srctop_file("test", "certs", "server-rsa-sign.key"),
        srctop_file("test", "certs", "server-rsa-enc.crt"),
        srctop_file("test", "certs", "server-rsa-enc.key")])));
}
