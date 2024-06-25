#! /usr/bin/env perl
# Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use OpenSSL::Test;
use OpenSSL::Test::Utils;
use File::Compare;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_threshold_sm2_app");

plan skip_all => "This test is unsupported in a no-sm2_threshold build"
    if disabled("sm2_threshold");

plan tests => 4;

sub hex_to_binary {
    my ($infile, $outfile) = @_;

    open(my $in, '<', $infile) or return 0;
    my $hex = <$in>;
    close($in);

    $hex =~ s/://g;

    my $bytes = pack "H*", $hex;

    open(my $fh, '>', $outfile) or return 0;
    print $fh $bytes;
    close($fh);

    return 1;
}

subtest "Derive SM2 threshold keys" => sub {
    plan tests => 7;

    ok(run(app(['openssl', 'genpkey', '-algorithm', 'ec', '-pkeyopt',
                'ec_paramgen_curve:sm2', '-out', 'A-sm2.key'])));
    ok(run(app(['openssl', 'genpkey', '-algorithm', 'ec', '-pkeyopt',
                'ec_paramgen_curve:sm2', '-out', 'B-sm2.key'])));

    ok(run(app(['openssl', 'sm2_threshold', '-derive', '-inkey', 'A-sm2.key',
                '-pubout', 'A-pub.key'])));
    ok(run(app(['openssl', 'sm2_threshold', '-derive', '-inkey', 'B-sm2.key',
                '-pubout', 'B-pub.key'])));

    ok(run(app(['openssl', 'sm2_threshold', '-derive', '-inkey', 'A-sm2.key',
                '-peerkey', 'B-pub.key', '-pubout', 'ABpub.key'])));
    ok(run(app(['openssl', 'sm2_threshold', '-derive', '-inkey', 'B-sm2.key',
                '-peerkey', 'A-pub.key', '-pubout', 'BApub.key'])));

    is(compare("ABpub.key", "BApub.key"), 0);
};

subtest "SM2 two-party threshold signature" => sub {
    plan tests => 5;

    ok(run(app(['openssl', 'genpkey', '-algorithm', 'ec', '-pkeyopt',
                'ec_paramgen_curve:sm2', '-out', 'temp-sm2.key'])));
    ok(run(app(['openssl', 'pkey', '-in', 'temp-sm2.key', '-pubout',
                '-out', 'temp-sm2pub.key'])));

    my @dgst = run(app(['openssl', 'sm2_threshold', '-sign1', '-pubin',
                        '-inkey', 'ABpub.key', '-in',
                        srctop_file('test', 'data.bin')]), capture => 1);
    chomp(@dgst);

    @dgst[0] =~ m|^SM2_threshold_sign1, digest=([0-9a-fA-F]+)$|;
    my $dgst = $1;

    ok(run(app(['openssl', 'sm2_threshold', '-sign2', '-inkey', 'B-sm2.key',
                '-digest', $dgst, '-temppeerkey', 'temp-sm2pub.key',
                '-out', 'partial_sig.bin'])));

    ok(run(app(['openssl', 'sm2_threshold', '-sign3', '-inkey', 'A-sm2.key',
                '-sigfile', 'partial_sig.bin', '-tempkey', 'temp-sm2.key',
                '-out', 'signature.bin'])));

    ok(run(app(['openssl', 'dgst', '-sm3', '-verify', 'ABpub.key',
                '-signature', 'signature.bin',
                srctop_file('test', 'data.bin')])));
};

subtest "SM2 two-party threshold signature, newkey + hex format sigfile" => sub {
    plan tests => 4;

    my @dgst = run(app(['openssl', 'sm2_threshold', '-sign1', '-newkey',
                        'temp-sm2.key', '-pubout', 'temp-sm2pub.key', '-pubin',
                        '-inkey', 'ABpub.key', '-in',
                        srctop_file('test', 'data.bin')]), capture => 1);
    chomp(@dgst);

    @dgst[0] =~ m|^SM2_threshold_sign1, digest=([0-9a-fA-F]+)$|;
    my $dgst = $1;

    ok(run(app(['openssl', 'sm2_threshold', '-sign2', '-inkey', 'B-sm2.key',
                '-digest', $dgst, '-temppeerkey', 'temp-sm2pub.key',
                '-hex', '-out', 'partial_sig.txt'])));

    ok(run(app(['openssl', 'sm2_threshold', '-sign3', '-inkey', 'A-sm2.key',
                '-sigform', 'hex', '-sigfile', 'partial_sig.txt', '-tempkey',
                'temp-sm2.key', '-hex', '-out', 'signature.txt'])));

    ok(hex_to_binary("signature.txt", "signature.bin"));

    ok(run(app(['openssl', 'dgst', '-sm3', '-verify', 'ABpub.key',
                '-signature', 'signature.bin',
                srctop_file('test', 'data.bin')])));
};

subtest "SM2 two-party threshold decryption" => sub {
    plan tests => 5;

    ok(run(app(['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey',
                'ABpub.key', '-in', srctop_file('test', 'data.bin'), '-out',
                'data.bin.enc'])));

    ok(run(app(['openssl', 'sm2_threshold', '-decrypt1', '-in', 'data.bin.enc',
                '-newrand', 'w.bin', '-newpoint', 'T1.bin'])));

    ok(run(app(['openssl', 'sm2_threshold', '-decrypt2', '-inkey', 'B-sm2.key',
                '-pointin', 'T1.bin', '-pointout', 'T2.bin'])));

    ok(run(app(['openssl', 'sm2_threshold', '-decrypt3', '-inkey', 'A-sm2.key',
                '-randin', 'w.bin', '-pointin', 'T2.bin', '-in', 'data.bin.enc',
                '-out', 'data.bin'])));

    is(compare("data.bin", srctop_file('test', 'data.bin')), 0);
};
