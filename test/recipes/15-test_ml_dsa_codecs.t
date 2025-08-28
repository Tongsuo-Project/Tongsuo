#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use File::Copy;
use File::Compare qw/compare_text compare/;
use IO::File;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT data_file srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;

setup("test_ml_dsa_codecs");

my @algs = qw(65);
my @formats = qw(seed-priv priv-only seed-only oqskeypair bare-seed bare-priv);

plan skip_all => "ML-DSA isn't supported in this build"
    if disabled("ml_dsa");

plan tests => @algs * (2 + 7 * @formats);
my $seed = join ("", map {sprintf "%02x", $_} (0..31));
my $weed = join ("", map {sprintf "%02x", $_} (1..32));
my $ikme = join ("", map {sprintf "%02x", $_} (0..31));
my %alg = ("44" => [4, 4, 2560], "65" => [6, 5, 4032], "87" => [8, 7, 4896]);

foreach my $alg (@algs) {
    my $pub = sprintf("pub-%s.pem", $alg);
    my %formats = map { ($_, sprintf("prv-%s-%s.pem", $alg, $_)) } @formats;
    my ($k, $l, $sk_len) = @{$alg{$alg}};
    # The number of low-bits |d| in t_0 is 13 across all the variants
    my $t0_len = $k * 13 * 32;

    # (1 + 6 * @formats) tests
    my $i = 0;
    my $in0 = data_file($pub);
    my $der0 = sprintf("pub-%s.%d.der", $alg, $i++);
    ok(run(app(['openssl', 'pkey', '-pubin', '-in', $in0,
                '-outform', 'DER', '-out', $der0])));
    foreach my $f (keys %formats) {
        my $kf = $formats{$f};
        my %pruned = %formats;
        delete $pruned{$f};
        my $rest = join(", ", keys %pruned);
        my $in = data_file($kf);
        my $der = sprintf("pub-%s.%d.der", $alg, $i);
        #
        # Compare expected DER public key with DER public key of private
        ok(run(app(['openssl', 'pkey', '-in', $in, '-pubout',
                    '-outform', 'DER', '-out', $der])));
        ok(!compare($der0, $der),
            sprintf("pubkey DER match: %s, %s", $alg, $f));
        #
        # Compare expected PEM private key with regenerated key
        my $pem = sprintf("prv-%s-%s.%d.pem", $alg, $f, $i++);
        ok(run(app(['openssl', 'genpkey',
                    '-algorithm', "ml-dsa-$alg", '-pkeyopt', "hexseed:$seed",
                    '-pkeyopt', "sk-format:$f", '-out', $pem])));
        ok(!compare_text($in, $pem),
            sprintf("prvkey PEM match: %s, %s", $alg, $f));

        ok(run(app(['openssl', 'pkey', '-in', $in, '-noout'])));
    }

    # (1 + 2 * @formats) tests
    # Perform sign/verify PCT
    $i = 0;
    my $refsig = data_file(sprintf("sig-%s.dat", $alg));
    my $sig = sprintf("sig-%s.%d.dat", $alg, $i);
    ok(run(app([qw(openssl pkeyutl -verify -rawin -pubin -inkey),
                $in0, '-in', $der0, '-sigfile', $refsig],
               sprintf("Signature verify with pubkey: %s", $alg))));
    while (my ($f, $kf) = each %formats) {
        my $sk = data_file($kf);
        my $s = sprintf("sig-%s.%d.dat", $alg, $i++);
        ok(run(app([qw(openssl pkeyutl -sign -rawin -inkey), $sk, '-in', $der0,
                    qw(-pkeyopt deterministic:1 -out), $s])));
        ok(!compare($s, $refsig),
            sprintf("Signature blob match %s with %s", $alg, $f));
    }

}
