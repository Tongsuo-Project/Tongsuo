#! /usr/bin/env perl
# Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use warnings;

use File::Path 2.00 qw/rmtree/;
use OpenSSL::Test qw/:DEFAULT data_file result_dir/;
use OpenSSL::Test::Utils;
use File::Spec::Functions qw/catfile catdir/;
use Cwd qw/getcwd/;

my $BULLETPROOFS_TEST_D = getcwd();
my $BULLETPROOFS_TEST_OUT_D = catdir($BULLETPROOFS_TEST_D, "bulletproofs_test_outs");

my $ppgen_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "pp.pem");
my $pp_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "pp-out.txt");
my $proof_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "proof-out.txt");
my $prove_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "proof.pem");
my $verify_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "verify-out.txt");

my $pp_path = $ppgen_out_path;
my $proof_path = $prove_out_path;

rmtree(${BULLETPROOFS_TEST_OUT_D}, { safe => 0 });

mkdir($BULLETPROOFS_TEST_OUT_D);

sub file_content
{
    my($file) = @_;
    my $content;
    my $opened = open(IN, $file);
    if (!$opened) {
      $content = "Error.";
    } else {
      my @lines = <IN>;
      foreach my $line (@lines) {
        $content .= $line;
      }
      close(IN);
    }
    return $content;
}

sub bulletproofs_ppgen
{
    my ($curve_name, $bits, $agg_max, $text) = @_;
    my @app_args = ("openssl", "bulletproofs", "-ppgen", "-out", $ppgen_out_path);
    if ($curve_name) {
        push @app_args, "-curve_name";
        push @app_args, $curve_name;
    }
    if ($bits) {
        push @app_args, "-bits";
        push @app_args, $bits;
    }
    if ($agg_max) {
        push @app_args, "-agg_max";
        push @app_args, $agg_max;
    }
    if ($text) {
        push @app_args, "-text";
    }
    if (run(app([@app_args]))) {
        return file_content($ppgen_out_path);
    }
    return 'Error';
}

sub bulletproofs_pp
{
    my ($pp, $text) = @_;
    my @app_args = ("openssl", "bulletproofs", "-pp", "-in", $pp, "-out", $pp_out_path);
    if ($text) {
        push @app_args, "-text";
    }
    if (run(app([@app_args]))) {
        return file_content($pp_out_path);
    }
    return 'Error';
}

sub bulletproofs_proof
{
    my ($proof, $text) = @_;
    my @app_args = ("openssl", "bulletproofs", "-proof", "-in", $proof, "-out", $proof_out_path);
    if ($text) {
        push @app_args, "-text";
    }
    if (run(app([@app_args]))) {
        return file_content($proof_out_path);
    }
    return 'Error';
}

sub bulletproofs_prove
{
    my ($pp, @secrets, $text) = @_;
    my @app_args = ("openssl", "bulletproofs", "-prove", "-pp_in", $pp, "-out", $prove_out_path);
    if ($text) {
        push @app_args, "-text";
    }
    push @app_args, @secrets;
    if (run(app([@app_args]))) {
        return file_content($prove_out_path);
    }
    return "Error";
}

sub bulletproofs_verify
{
    my ($pp, $proof) = @_;
    my @app_args = ("openssl", "bulletproofs", "-verify", "-pp_in", $pp,, "-in", $proof, "-out", $verify_out_path);
    ok(run(app([@app_args])), "test bulletproofs -verify");
    if (run(app([@app_args]))) {
        return file_content($verify_out_path);
    }
    return 'Error';
}

setup("test_app_bulletproofs");

plan skip_all => "app_bulletproofs is not supported by this OpenSSL build"
    if disabled("bulletproofs");

plan tests => 21;

my $res = bulletproofs_ppgen();
ok($res =~ m/BULLETPROOFS PUBLIC PARAM/, "check bulletproofs public parameter generate with default arguments");
$res = bulletproofs_pp($pp_path, 1);
ok($res =~ m/curve_id: \d+ \([\d\-A-Za-z_]+\)\nbits: \d+\nmax aggregation number: \d+/, "check bulletproofs public parameter generate with default arguments");

$res = bulletproofs_ppgen("SM2", 16, 2, 1);
ok($res =~ m/curve_id: 1172 \(SM2\)\nbits: 16\nmax aggregation number: 2/, "check bulletproofs public parameter generate with (SM2, 16, 2)");

# test prove secrets: 1
$res = bulletproofs_prove($pp_path, (1));
ok($res =~ m/BEGIN BULLETPROOFS PROOF/, "check bulletproofs prove secrets: 1");
$res = bulletproofs_verify($pp_path, $proof_path);
ok($res =~ m/The proof is valid/, "check bulletproofs verify proof(secrets: 1)");
$res = bulletproofs_proof($proof_path);
ok($res =~ m/BEGIN BULLETPROOFS PROOF/ && $res !~ m/n: 1/, "check bulletproofs proof output");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/n: 1/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "check bulletproofs proof text output");

# test prove secrets: 1 100
$res = bulletproofs_prove($pp_path, (1, 100));
ok($res =~ m/BEGIN BULLETPROOFS PROOF/, "check bulletproofs prove secrets: 1 100");
$res = bulletproofs_verify($pp_path, $proof_path);
ok($res =~ m/The proof is valid/, "check bulletproofs verify proof(secrets: 1 100)");
$res = bulletproofs_proof($proof_path);
ok($res =~ m/BEGIN BULLETPROOFS PROOF/ && $res !~ m/n: 2/, "check bulletproofs proof output");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/n: 2/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "check bulletproofs proof text output");

# test prove secrets: 1 100000
$res = bulletproofs_prove($pp_path, (1, 100000));
ok($res =~ m/BEGIN BULLETPROOFS PROOF/, "check bulletproofs prove secrets: 1 100000");
$res = bulletproofs_verify($pp_path, $proof_path);
ok($res =~ m/The proof is invalid/, "check bulletproofs verify proof(secrets: 1 100000), 100000 is not in [0, 2^16)");
$res = bulletproofs_proof($proof_path);
ok($res =~ m/BEGIN BULLETPROOFS PROOF/ && $res !~ m/n: 2/, "check bulletproofs proof output");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/n: 2/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "check bulletproofs proof text output");

# test prove secrets: 1 100 1000
$res = bulletproofs_prove($pp_path, (1, 100, 1000));
ok($res =~ m/Error/, "check bulletproofs prove secrets: 1 100 1000, the max agg is exceeded");

bulletproofs_ppgen();
$res = bulletproofs_verify($pp_path, $proof_path);
ok($res =~ m/The proof is invalid/, "check bulletproofs verify proof by other public parameter");

rmtree(${BULLETPROOFS_TEST_OUT_D}, { safe => 0 });
