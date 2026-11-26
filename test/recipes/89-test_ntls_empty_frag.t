#! /usr/bin/env perl
# Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_ntls_empty_frag");

plan tests => 1;

SKIP: {
    skip "NTLS or the compared TLS versions are disabled in this build", 1
        if disabled("ntls") || disabled("sm2") || disabled("sm3")
           || disabled("sm4") || disabled("tls1") || disabled("tls1_2");

    ok(run(test(["ntls_empty_frag_test",
                 srctop_file("test", "certs", "sm2", "server_sign.crt"),
                 srctop_file("test", "certs", "sm2", "server_sign.key"),
                 srctop_file("test", "certs", "sm2", "server_enc.crt"),
                 srctop_file("test", "certs", "sm2", "server_enc.key"),
                 srctop_file("test", "certs", "servercert.pem"),
                 srctop_file("test", "certs", "serverkey.pem")])));
}
