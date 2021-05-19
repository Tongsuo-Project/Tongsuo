#! /usr/bin/env perl

use strict;
use OpenSSL::Test;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir/;
use File::Temp qw(tempfile);

setup("test_ssl_ntls_api");

plan tests => 1;

ok(run(test(["ssl_ntls_api_test",
             srctop_file("test", "certs", "SS.cert.pem"),
             srctop_file("test", "certs", "SS.key.pem"),
             srctop_file("test", "certs", "SE.cert.pem"),
             srctop_file("test", "certs", "SE.key.pem")])));
