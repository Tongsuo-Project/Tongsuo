#! /usr/bin/env perl
# Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_dir bldtop_file srctop_file/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

BEGIN {
    setup("test_cli_smtc");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "Test only supported in a smtc build"
    if disabled("smtc") || disabled("smtc-debug");
plan tests => 9;

my $defaultconf = srctop_file("test", "default.cnf");
my $smtcconf = srctop_file("test", "smtc-and-base.cnf");
my $tbs_data = abs_path(bldtop_file('apps', 'openssl' . platform->binext()));
my $bogus_data = $smtcconf;

$ENV{OPENSSL_CONF} = $smtcconf;

ok(run(app(['openssl', 'list', '-public-key-methods', '-verbose'])),
   "provider listing of public key methods");
ok(run(app(['openssl', 'list', '-public-key-algorithms', '-verbose'])),
   "provider listing of public key algorithms");
ok(run(app(['openssl', 'list', '-key-managers', '-verbose'])),
   "provider listing of keymanagers");
ok(run(app(['openssl', 'list', '-key-exchange-algorithms', '-verbose'])),
   "provider listing of key exchange algorithms");
ok(run(app(['openssl', 'list', '-kem-algorithms', '-verbose'])),
   "provider listing of key encapsulation algorithms");
ok(run(app(['openssl', 'list', '-signature-algorithms', '-verbose'])),
   "provider listing of signature algorithms");
ok(run(app(['openssl', 'list', '-asymcipher-algorithms', '-verbose'])),
   "provider listing of encryption algorithms");
ok(run(app(['openssl', 'list', '-key-managers', '-verbose', '-select', 'SM2' ])),
   "provider listing of one item in the keymanager");

sub pubfrompriv {
    my $prefix = shift;
    my $key = shift;
    my $pub_key = shift;
    my $type = shift;

    ok(run(app(['openssl', 'pkey',
                '-in', $key,
                '-pubout',
                '-out', $pub_key])),
        $prefix.': '."Create the public key with $type parameters");

}

my $tsignverify_count = 8;
sub tsignverify {
    my $prefix = shift;
    my $smtc_key = shift;
    my $smtc_pub_key = shift;
    my $nonsmtc_key = shift;
    my $nonsmtc_pub_key = shift;
    my $md = shift;
    my $smtc_sigfile = $prefix.'.smtc.sig';
    my $nonsmtc_sigfile = $prefix.'.nonsmtc.sig';
    my $sigfile = '';
    my $testtext = '';

    $ENV{OPENSSL_CONF} = $smtcconf;

    $sigfile = $smtc_sigfile;
    $testtext = $prefix.': '.
        'Sign something with a SMTC key';
    ok(run(app(['openssl', 'dgst', $md,
                '-sign', $smtc_key,
                '-out', $sigfile,
                $tbs_data])),
       $testtext);

    $testtext = $prefix.': '.
        'Verify something with a SMTC key';
    ok(run(app(['openssl', 'dgst', $md,
                '-verify', $smtc_pub_key,
                '-signature', $sigfile,
                $tbs_data])),
       $testtext);

    $testtext = $prefix.': '.
        'Verify a valid signature against the wrong data with a SMTC key'.
        ' (should fail)';
    ok(!run(app(['openssl', 'dgst', $md,
                 '-verify', $smtc_pub_key,
                 '-signature', $sigfile,
                 $bogus_data])),
       $testtext);

    $ENV{OPENSSL_CONF} = $defaultconf;

    $sigfile = $nonsmtc_sigfile;
    $testtext = $prefix.': '.
        'Sign something with a non-SMTC key'.
        ' with the default provider';
    ok(run(app(['openssl', 'dgst', $md,
                '-sign', $nonsmtc_key,
                '-out', $sigfile,
                $tbs_data])),
       $testtext);

    $testtext = $prefix.': '.
        'Verify something with a non-SMTC key'.
        ' with the default provider';
    ok(run(app(['openssl', 'dgst', $md,
                '-verify', $nonsmtc_pub_key,
                '-signature', $sigfile,
                $tbs_data])),
       $testtext);

    $ENV{OPENSSL_CONF} = $smtcconf;

    $testtext = $prefix.': '.
        'Sign something with a non-SMTC key'.
        ' (should fail)';
    ok(!run(app(['openssl', 'dgst', $md,
                 '-sign', $nonsmtc_key,
                 '-out', $prefix.'.nonsmtc.fail.sig',
                 $tbs_data])),
       $testtext);

    $testtext = $prefix.': '.
        'Verify something with a non-SMTC key'.
        ' (should fail)';
    ok(!run(app(['openssl', 'dgst', $md,
                 '-verify', $nonsmtc_pub_key,
                 '-signature', $sigfile,
                 $tbs_data])),
       $testtext);

    $testtext = $prefix.': '.
        'Verify a valid signature against the wrong data with a non-SMTC key'.
        ' (should fail)';
    ok(!run(app(['openssl', 'dgst', $md,
                 '-verify', $nonsmtc_pub_key,
                 '-signature', $sigfile,
                 $bogus_data])),
       $testtext);
}

SKIP : {
    skip "SMTC SM2 tests because of no sm2 or sm3 in this build", 1
        if disabled("sm2") || disabled("sm3");

    subtest SM2 => sub {
        my $testtext_prefix = 'SM2';
        my $smtc_key = $testtext_prefix.'.smtc.priv.pem';
        my $smtc_pub_key = $testtext_prefix.'.smtc.pub.pem';
        my $a_nonsmtc_curve = 'brainpoolP256r1';
        my $nonsmtc_key = $testtext_prefix.'.nonsmtc.priv.pem';
        my $nonsmtc_pub_key = $testtext_prefix.'.nonsmtc.pub.pem';
        my $testtext = '';
        my $curvename = '';

        plan tests => 5 + $tsignverify_count;

        $ENV{OPENSSL_CONF} = $defaultconf;
        $curvename = $a_nonsmtc_curve;
        $testtext = $testtext_prefix.': '.
            'Generate a key with a non-SMTC algorithm with the default provider';
        ok(run(app(['openssl', 'genpkey', '-algorithm', 'EC',
                    '-pkeyopt', 'ec_paramgen_curve:'.$curvename,
                    '-out', $nonsmtc_key])),
           $testtext);

        pubfrompriv($testtext_prefix, $nonsmtc_key, $nonsmtc_pub_key, "non-SMTC");

        $ENV{OPENSSL_CONF} = $smtcconf;

        $testtext = $testtext_prefix.': '.
            'Generate a key with a SMTC algorithm';
        ok(run(app(['openssl', 'genpkey', '-algorithm', 'SM2',
                    '-out', $smtc_key])),
           $testtext);

        pubfrompriv($testtext_prefix, $smtc_key, $smtc_pub_key, "SMTC");

        $curvename = $a_nonsmtc_curve;
        $testtext = $testtext_prefix.': '.
            'Generate a key with a non-SMTC algorithm'.
            ' (should fail)';
        ok(!run(app(['openssl', 'genpkey', '-algorithm', 'EC',
                     '-pkeyopt', 'ec_paramgen_curve:'.$curvename,
                     '-out', $testtext_prefix.'.'.$curvename.'.priv.pem'])),
           $testtext);

        tsignverify($testtext_prefix, $smtc_key, $smtc_pub_key, $nonsmtc_key,
                    $nonsmtc_pub_key, '-sm3');
    };
}
