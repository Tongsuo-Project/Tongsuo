#! /usr/bin/env perl
# Copyright 2015-2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_x509");

plan tests => 36;

# Prevent MSys2 filename munging for arguments that look like file paths but
# aren't
$ENV{MSYS2_ARG_CONV_EXCL} = "/CN=";

require_ok(srctop_file("test", "recipes", "tconversion.pl"));

my @certs = qw(test certs);
my $pem = srctop_file(@certs, "cyrillic.pem");
my $out_msb = "out-cyrillic.msb";
my $out_utf8 = "out-cyrillic.utf8";
my $der = "cyrillic.der";
my $der2 = "cyrillic.der";
my $msb = srctop_file(@certs, "cyrillic.msb");
my $utf = srctop_file(@certs, "cyrillic.utf8");

ok(run(app(["openssl", "x509", "-text", "-in", $pem, "-out", $out_msb,
            "-nameopt", "esc_msb"])));
is(cmp_text($out_msb, $msb),
   0, 'Comparing esc_msb output with cyrillic.msb');
ok(run(app(["openssl", "x509", "-text", "-in", $pem, "-out", $out_utf8,
            "-nameopt", "utf8"])));
is(cmp_text($out_utf8, $utf),
   0, 'Comparing utf8 output with cyrillic.utf8');

SKIP: {
    skip "DES disabled", 1 if disabled("des");
    skip "Platform doesn't support command line UTF-8", 1 if $^O =~ /^msys$/;

    my $p12 = srctop_file("test", "shibboleth.pfx");
    my $p12pass = "σύνθημα γνώρισμα";
    my $out_pem = "out.pem";
    ok(run(app(["openssl", "x509", "-text", "-in", $p12, "-out", $out_pem,
                "-passin", "pass:$p12pass"])));
    # not unlinking $out_pem
}

ok(!run(app(["openssl", "x509", "-in", $pem, "-inform", "DER",
             "-out", $der, "-outform", "DER"])),
   "Checking failure of mismatching -inform DER");
ok(run(app(["openssl", "x509", "-in", $pem, "-inform", "PEM",
            "-out", $der, "-outform", "DER"])),
   "Conversion to DER");
ok(!run(app(["openssl", "x509", "-in", $der, "-inform", "PEM",
             "-out", $der2, "-outform", "DER"])),
   "Checking failure of mismatching -inform PEM");

# producing and checking self-issued (but not self-signed) cert
my $subj = "/CN=CA"; # using same DN as in issuer of ee-cert.pem
my $extfile = srctop_file("test", "v3_ca_exts.cnf");
my $pkey = srctop_file(@certs, "ca-key.pem"); # issuer private key
my $pubkey = "ca-pubkey.pem"; # the corresponding issuer public key
# use any (different) key for signing our self-issued cert:
my $signkey = srctop_file(@certs, "serverkey.pem");
my $selfout = "self-issued.out";
my $testcert = srctop_file(@certs, "ee-cert.pem");
ok(run(app(["openssl", "pkey", "-in", $pkey, "-pubout", "-out", $pubkey]))
&& run(app(["openssl", "x509", "-new", "-force_pubkey", $pubkey,
            "-subj", $subj, "-extfile", $extfile,
            "-signkey", $signkey, "-out", $selfout]))
&& run(app(["openssl", "verify", "-no_check_time",
            "-trusted", $selfout, "-partial_chain", $testcert])));
# not unlinking $pubkey
# not unlinking $selfout

SKIP: {
    skip "SM2 is not supported by this OpenSSL build", 2 if disabled("sm2");
    ok(run(app(["openssl", "x509",
                "-req",
                "-in", srctop_file(@certs, "sm2-csr.pem"),
                "-signkey", srctop_file(@certs, "sm2.key"),
                "-out", "sm2.crt",
                "-sm3",
                "-vfyopt", "distid:1234567812345678",
                "-sigopt", "distid:1234567812345678"])),
                "Generating self-signed SM2 certificate");

    ok(run(app(["openssl", "x509",
                "-req",
                "-in", srctop_file(@certs, "sm2-csr.pem"),
                "-signkey", srctop_file(@certs, "sm2.key"),
                "-out", "sm2-compat.crt",
                "-sm3",
                "-sm2-id", "1234567812345678",
                "-sigopt", "sm2_id:1234567812345678"])),
                "Generating self-signed SM2 certificate (compat)");
}


subtest 'x509 -- x.509 v1 certificate' => sub {
    tconversion( -type => 'x509', -prefix => 'x509v1',
                 -in => srctop_file("test", "testx509.pem") );
};
subtest 'x509 -- first x.509 v3 certificate' => sub {
    tconversion( -type => 'x509', -prefix => 'x509v3-1',
                 -in => srctop_file("test", "v3-cert1.pem") );
};
subtest 'x509 -- second x.509 v3 certificate' => sub {
    tconversion( -type => 'x509', -prefix => 'x509v3-2',
                 -in => srctop_file("test", "v3-cert2.pem") );
};

subtest 'x509 -- pathlen' => sub {
    ok(run(test(["v3ext", srctop_file(@certs, "pathlen.pem")])));
};

cert_contains(srctop_file(@certs, "fake-gp.pem"),
              "2.16.528.1.1003.1.3.5.5.2-1-0000006666-Z-12345678-01.015-12345678",
              1, 'x500 -- subjectAltName');

my $sda_cert = srctop_file(@certs, "ext-subjectDirectoryAttributes.pem");
cert_contains($sda_cert,
              "Steve Brule",
              1, 'X.509 Subject Directory Attributes');
cert_contains($sda_cert,
              "CN=Hi mom",
              1, 'X.509 Subject Directory Attributes');
cert_contains($sda_cert,
              "<No Values>",
              1, 'X.509 Subject Directory Attributes');
cert_contains($sda_cert,
              "Funkytown",
              1, 'X.509 Subject Directory Attributes');
cert_contains($sda_cert,
              "commonName",
              1, 'X.509 Subject Directory Attributes');
cert_contains($sda_cert,
              "owner",
              1, 'X.509 Subject Directory Attributes');
cert_contains($sda_cert,
              "givenName",
              1, 'X.509 Subject Directory Attributes');
cert_contains($sda_cert,
              "localityName",
              1, 'X.509 Subject Directory Attributes');

my $ass_info_cert = srctop_file(@certs, "ext-associatedInformation.pem");
cert_contains($ass_info_cert,
              "Steve Brule",
              1, 'X509v3 Associated Information');
cert_contains($ass_info_cert,
              "CN=Hi mom",
              1, 'X509v3 Associated Information');
cert_contains($ass_info_cert,
              "<No Values>",
              1, 'X509v3 Associated Information');
cert_contains($ass_info_cert,
              "Funkytown",
              1, 'X509v3 Associated Information');
cert_contains($ass_info_cert,
              "commonName",
              1, 'X509v3 Associated Information');
cert_contains($ass_info_cert,
              "owner",
              1, 'X509v3 Associated Information');
cert_contains($sda_cert,
              "givenName",
              1, 'X509v3 Associated Information');
cert_contains($ass_info_cert,
              "localityName",
              1, 'X509v3 Associated Information');

sub test_errors { # actually tests diagnostics of OSSL_STORE
    my ($expected, $cert, @opts) = @_;
    my $infile = srctop_file(@certs, $cert);
    my @args = qw(openssl x509 -in);
    push(@args, $infile, @opts);
    my $tmpfile = 'out.txt';
    my $res =  grep(/-text/, @opts) ? run(app([@args], stdout => $tmpfile))
                                    : !run(app([@args], stderr => $tmpfile));
    my $found = 0;
    open(my $in, '<', $tmpfile) or die "Could not open file $tmpfile";
    while(<$in>) {
        print; # this may help debugging
        $res &&= !m/asn1 encoding/; # output must not include ASN.1 parse errors
        $found = 1 if m/$expected/; # output must include $expected
    }
    close $in;
    # $tmpfile is kept to help with investigation in case of failure
    return $res && $found;
}

# 3 tests for non-existence of spurious OSSL_STORE ASN.1 parse error output.
# This requires provoking a failure exit of the app after reading input files.
ok(test_errors("Bad output format", "root-cert.pem", '-outform', 'http'),
   "load root-cert errors");
SKIP: {
    skip "sm2 not disabled", 1 if !disabled("sm2");

    ok(test_errors("Unable to load Public Key", "sm2-cert.pem", '-text'),
       "error loading unsupported sm2 cert");
}

subtest 'x509 -- sign sm2 cert' => sub {
    plan tests => 2;

    SKIP: {
        skip "SM2 is not supported by this OpenSSL build", 2
            if disabled("sm2");

        # test x509 sign sm2 cert, should include X509v3 extensions
        my $csr = srctop_file(@certs, "sm2-csr.pem");
        my $key = srctop_file(@certs, "sm2-root.key");
        my $cert = "sm2-root.tmp";
        ok(run(app([ "openssl", "x509", "-req", "-in", $csr, "-extfile",
            srctop_file("apps", "openssl.cnf"), "-extensions", "v3_ca", "-sm3",
            "-vfyopt", "distid:1234567812345678",
            "-signkey", $key, "-out", $cert ])));

        my @output = run(app([ "openssl", "x509", "-in", $cert, "-text",
            "-noout" ], stderr => undef), capture => 1);

        unlink $cert;

        my $count = grep /X509v3 Basic Constraints:/, @output;
        ok($count == 1);
    }
};
