#! /usr/bin/env perl

use strict;
use OpenSSL::Test;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir/;
use File::Temp qw(tempfile);

setup("test_ssl_ntls_api");

use File::Spec::Functions qw/catfile/;

plan tests => 1;

ok(run(test(["ssl_ntls_api_test",
    catfile(".", "test_sign_sm2", "server_sign.crt"),
    catfile(".", "test_sign_sm2", "server_sign.key"),
    catfile(".", "test_sign_sm2", "server_enc.crt"),
    catfile(".", "test_sign_sm2", "server_enc.key")])));
