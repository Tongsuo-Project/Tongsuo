#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_x509");

plan tests => 10;

require_ok(srctop_file('test','recipes','tconversion.pl'));

my $pem = srctop_file("test/certs", "cyrillic.pem");
my $out = "cyrillic.out";
my $msb = srctop_file("test/certs", "cyrillic.msb");
my $utf = srctop_file("test/certs", "cyrillic.utf8");

ok(run(app(["openssl", "x509", "-text", "-in", $pem, "-out", $out,
            "-nameopt", "esc_msb"])));
is(cmp_text($out, srctop_file("test/certs", "cyrillic.msb")),
   0, 'Comparing esc_msb output');
ok(run(app(["openssl", "x509", "-text", "-in", $pem, "-out", $out,
            "-nameopt", "utf8"])));
is(cmp_text($out, srctop_file("test/certs", "cyrillic.utf8")),
   0, 'Comparing utf8 output');
unlink $out;

subtest 'x509 -- x.509 v1 certificate' => sub {
    tconversion("x509", srctop_file("test","testx509.pem"));
};
subtest 'x509 -- first x.509 v3 certificate' => sub {
    tconversion("x509", srctop_file("test","v3-cert1.pem"));
};
subtest 'x509 -- second x.509 v3 certificate' => sub {
    tconversion("x509", srctop_file("test","v3-cert2.pem"));
};

subtest 'x509 -- pathlen' => sub {
    ok(run(test(["v3ext", srctop_file("test/certs", "pathlen.pem")])));
};

subtest 'x509 -- sign sm2 cert' => sub {
    plan tests => 2;

    SKIP: {
        skip "SM2 is not supported by this OpenSSL build", 2
            if disabled("sm2");

        # test x509 sign sm2 cert, should include X509v3 extensions
        my $csr = srctop_file("test", "certs", "sm2-root.csr");
        my $key = srctop_file("test", "certs", "sm2-root.key");
        my $cert = "sm2-root.tmp";
        ok(run(app([ "openssl", "x509", "-req", "-in", $csr, "-extfile",
            srctop_file("apps", "openssl.cnf"), "-extensions", "v3_ca", "-sm3",
            "-signkey", $key, "-out", $cert ])));

        my @output = run(app([ "openssl", "x509", "-in", $cert, "-text",
            "-noout" ], stderr => undef), capture => 1);

        unlink $cert;

        my $count = grep /X509v3 Basic Constraints:/, @output;
        ok($count == 1);
    }
};
