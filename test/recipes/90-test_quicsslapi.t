#! /usr/bin/env perl

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir/;
use File::Temp qw(tempfile);

setup("test_quicapi");

plan skip_all => "No TLS_1.3 or QUIC protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ eq "tls1_3" } available_protocols("tls")) or disabled("quic");

plan tests => 1;

ok(run(test(["quicapitest", srctop_dir("test", "certs")])),
             "running quicapitest");
