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
my $witness_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "witness-out.txt");
my $proof_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "proof-out.txt");
my $prove_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "proof.pem");
my $verify_out_path = catfile($BULLETPROOFS_TEST_OUT_D, "verify-out.txt");

my $pp_path = $ppgen_out_path;
my $witness_path = $witness_out_path;
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
    my ($curve_name, $gens_capacity, $party_capacity, $text) = @_;
    my @app_args = ("openssl", "bulletproofs", "-ppgen", "-out", $ppgen_out_path);
    if ($curve_name) {
        push @app_args, "-curve_name";
        push @app_args, $curve_name;
    }
    if ($gens_capacity) {
        push @app_args, "-gens_capacity";
        push @app_args, $gens_capacity;
    }
    if ($party_capacity) {
        push @app_args, "-party_capacity";
        push @app_args, $party_capacity;
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
    my ($pp_path, $text) = @_;
    my @app_args = ("openssl", "bulletproofs", "-pp", "-in", $pp_path, "-out", $pp_out_path);
    if ($text) {
        push @app_args, "-text";
    }
    if (run(app([@app_args]))) {
        return file_content($pp_out_path);
    }
    return 'Error';
}

sub bulletproofs_witness_commit
{
    my ($pp_path, $r1cs, $text, @witnesses) = @_;
    my @app_args = ("openssl", "bulletproofs", "-witness", "-pp_in", $pp_path, "-out", $witness_out_path);
    if ($r1cs) {
        push @app_args, "-r1cs";
    }
    if ($text) {
        push @app_args, "-text";
    }
    push @app_args, @witnesses;
    if (run(app([@app_args]))) {
        return file_content($witness_out_path);
    }
    return 'Error';
}

sub bulletproofs_witness_print
{
    my ($text) = @_;
    my @app_args = ("openssl", "bulletproofs", "-witness", "-in", $witness_path);
    if ($text) {
        push @app_args, "-text";
    }
    if (run(app([@app_args]))) {
        return file_content($witness_out_path);
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
    my ($pp, $witness, $r1cs_constraint, $text) = @_;
    my @app_args = ("openssl", "bulletproofs", "-prove", "-pp_in", $pp, "-witness_in", $witness, "-out", $prove_out_path);
    if ($r1cs_constraint) {
        push @app_args, "-r1cs_constraint";
        push @app_args, "$r1cs_constraint";
    }
    if ($text) {
        push @app_args, "-text";
    }
    if (run(app([@app_args]))) {
        return file_content($prove_out_path);
    }
    return "Error";
}

sub bulletproofs_verify
{
    my ($pp, $proof, $r1cs_constraint) = @_;
    my @app_args = ("openssl", "bulletproofs", "-verify", "-pp_in", $pp,, "-in", $proof, "-out", $verify_out_path);
    if ($r1cs_constraint) {
        push @app_args, "-r1cs_constraint";
        push @app_args, "$r1cs_constraint";
    }
    if (run(app([@app_args]))) {
        return file_content($verify_out_path);
    }
    return 'Error';
}

setup("test_app_bulletproofs");

plan skip_all => "app_bulletproofs is not supported by this OpenSSL build"
    if disabled("bulletproofs");

plan tests => 66;

my $res = bulletproofs_ppgen();
ok($res =~ m/BULLETPROOFS PUBLIC PARAM/, "Check bulletproofs public parameter generate with default arguments");
$res = bulletproofs_pp($pp_path, 1);
ok($res =~ m/curve: [\d\-A-Za-z_]+ \(\d+\)\ngens_capacity: \d+\nparty_capacity: \d+/, "Check bulletproofs public parameter generate with default arguments");

$res = bulletproofs_ppgen("SM2", 16, 4, 1);
ok($res =~ m/curve: SM2 \(1172\)\ngens_capacity: 16\nparty_capacity: 4/, "Check bulletproofs public parameter generate with (SM2, 16, 4)");

# test witness: 1
$res = bulletproofs_witness_commit($pp_path, 0, 1, (1));
ok($res =~ m/BEGIN BULLETPROOFS WITNESS/, "Check bulletproofs witness output format");
ok($res =~ m/v\[n\]:\s+\[0\]: 1 \(0x1\)/, "Check the value of V in the bulletproofs witness, generated with wintesses: 1");

# test prove secrets: 1
$res = bulletproofs_prove($pp_path, $witness_path, 0, 1);
ok($res =~ m/BEGIN BULLETPROOFS RANGE PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs range proof result with witness: 1");
$res = bulletproofs_verify($pp_path, $proof_path, 0);
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs range proof with the witness: 1");
$res = bulletproofs_proof($proof_path);
ok($res =~ m/BEGIN BULLETPROOFS RANGE PROOF/, "Check bulletproofs range proof output");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/A: (\w\w:?)+\s+S: (\w\w:?)+\s+T1: (\w\w:?)+\s+T2: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: (\w\w:?)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs range proof text output");

# test witness: 1,100
$res = bulletproofs_witness_commit($pp_path, 0, 1, (1, 100));
ok($res =~ m/v\[n\]:\s+\[0\]: 1 \(0x1\)\s+\[1\]: 100 \(0x64\)/, "Check the value of v in the bulletproofs witness, generated with wintesses: 1,100");

# test prove secrets: 1,100
$res = bulletproofs_prove($pp_path, $witness_path, 0, 1);
ok($res =~ m/BEGIN BULLETPROOFS RANGE PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs range proof result with witness: 1,100");
$res = bulletproofs_verify($pp_path, $proof_path, 0);
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs range proof with the witness: 1,100");
$res = bulletproofs_proof($proof_path);
ok($res =~ m/BEGIN BULLETPROOFS RANGE PROOF/, "Check bulletproofs range proof output");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/A: (\w\w:?)+\s+S: (\w\w:?)+\s+T1: (\w\w:?)+\s+T2: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: (\w\w:?)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs range proof text output");

bulletproofs_ppgen("SM2", 16, 4, 1);
$res = bulletproofs_verify($pp_path, $proof_path, 0);
ok($res =~ m/The proof is invalid/, "Check the verification of the bulletproofs range proof using the other public parameters.");

# test witness: 1,2,100000
$res = bulletproofs_witness_commit($pp_path, 0, 1, (1, 2, 100000));
ok($res =~ m/v\[n\]:\s+\[0\]: 1 \(0x1\)\s+\[1\]: 2 \(0x2\)\s+\[2\]: 100000 \(0x186a0\)/, "Check the value of v in the bulletproofs witness, generated with wintesses: 1,2,100000");

# test prove secrets: 1,2,100000
$res = bulletproofs_prove($pp_path, $witness_path, 0, 1);
ok($res =~ m/BEGIN BULLETPROOFS RANGE PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs range proof result with witness: 1,2,100000");
$res = bulletproofs_verify($pp_path, $proof_path, 0);
ok($res =~ m/The proof is invalid/, "Check the verification of the bulletproofs range proof with the witness: 1,2,100000. 100000 is out of range [0, 1<<16), it should fail.");
$res = bulletproofs_proof($proof_path);
ok($res =~ m/BEGIN BULLETPROOFS RANGE PROOF/, "Check bulletproofs range proof output");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/A: (\w\w:?)+\s+S: (\w\w:?)+\s+T1: (\w\w:?)+\s+T2: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: (\w\w:?)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs range proof text output");

# test witness: 1,2,100000,3,4
$res = bulletproofs_witness_commit($pp_path, 0, 1, (1, 2, 100000, 3, 4));
ok($res =~ m/v\[n\]:\s+\[0\]: 1 \(0x1\)\s+\[1\]: 2 \(0x2\)\s+\[2\]: 100000 \(0x186a0\)\s+\[3\]: 3 \(0x3\)\s+\[4\]: 4 \(0x4\)/, "Check the value of v in the bulletproofs witness, generated with wintesses: 1,2,100000,3,4");

# test prove secrets: 1,2,100000,3,4
$res = bulletproofs_prove($pp_path, $witness_path, 0, 1);
ok($res =~ m/Error/, "Check the format of the bulletproofs range proof result with witness: 1,2,100000. The party capacity is exceeded");

$res = bulletproofs_witness_commit($pp_path, 0, 1, ("a=1"));
ok($res =~ m/V\[n\]:\s+\[a\]: \w+/, "Check the value of V in the bulletproofs witness, generated with wintesses: a=1");
ok($res =~ m/v\[n\]:\s+\[a\]: 1 \(0x1\)/, "Check the value of v in the bulletproofs witness, generated with wintesses: a=1");
$res = bulletproofs_witness_commit($pp_path, 0, 1, ("a=1", "b=-2"));
ok($res =~ m/V\[n\]:\s+\[a\]: (\w\w:?)+\s+\[b\]: \w+/, "Check the value of V in the bulletproofs witness, generated with wintesses: a=1,b=-2");
ok($res =~ m/v\[n\]:\s+\[a\]: 1 \(0x1\)\s+\[b\]: -2 \(-0x2\)/, "Check the value of v in the bulletproofs witness, generated with wintesses: a=1,b=-2");
$res = bulletproofs_witness_commit($pp_path, 0, 1, ("a1=1", "b1=-2", "c1=3"));
ok($res =~ m/V\[n\]:\s+\[a1\]: (\w\w:?)+\s+\[b1\]: (\w\w:?)+\s+\[c1\]: (\w\w:?)+/, "Check the value of V in the bulletproofs witness, generated with wintesses: a1=1,b1=-2,c1=3");
ok($res =~ m/v\[n\]:\s+\[a1\]: 1 \(0x1\)\s+\[b1\]: -2 \(-0x2\)\s+\[c1\]: 3 \(0x3\)/, "Check the value of v in the bulletproofs witness, generated with wintesses: a1=1,b1=-2,c1=3");
$res = bulletproofs_witness_print(1);
ok($res =~ m/V\[n\]:\s+\[a1\]: (\w\w:?)+\s+\[b1\]: (\w\w:?)+\s+\[c1\]: (\w\w:?)+/, "Check the value of V in the bulletproofs witness pem file, generated with wintesses: a1=1,b1=-2,c1=3");
ok($res =~ m/v\[n\]:\s+\[a1\]: 1 \(0x1\)\s+\[b1\]: -2 \(-0x2\)\s+\[c1\]: 3 \(0x3\)/, "Check the value of v in the bulletproofs witness pem file, generated with wintesses: a1=1,b1=-2,c1=3");
$res = bulletproofs_witness_commit($pp_path, 0, 1, ("aa=1", "bb=2", "cc=33333", "dddd=4"));
ok($res =~ m/V\[n\]:\s+\[aa\]: (\w\w:?)+\s+\[bb\]: (\w\w:?)+\s+\[cc\]: (\w\w:?)+\s+\[dddd\]: (\w\w:?)+/, "Check the value of V in the bulletproofs witness, generated with wintesses: aa=1,bb=2,cc=3333,dddd=4");
ok($res =~ m/v\[n\]:\s+\[aa\]: 1 \(0x1\)\s+\[bb\]: 2 \(0x2\)\s+\[cc\]: 33333 \(0x8235\)\s+\[dddd\]: 4 \(0x4\)/, "Check the value of v in the bulletproofs witness, generated with wintesses: aa=1,bb=2,cc=3333,dddd=4");

# test r1cs
$res = bulletproofs_witness_commit($pp_path, 1, 1, ("aa=1", "bb=2", "cc=-3", "dd=4"));
ok($res =~ m/V\[n\]:\s+\[aa\]: (\w\w:?)+\s+\[bb\]: (\w\w:?)+\s+\[cc\]: (\w\w:?)+\s+\[dd\]: (\w\w:?)+/, "Check the value of V in the bulletproofs witness, generated with wintesses: aa=1,bb=2,cc=-3,dd=4");
ok($res =~ m/v\[n\]:\s+\[aa\]: 1 \(0x1\)\s+\[bb\]: 2 \(0x2\)\s+\[cc\]: -3 \(-0x3\)\s+\[dd\]: 4 \(0x4\)/, "Check the value of v in the bulletproofs witness, generated with wintesses: aa=1,bb=2,cc=-3,dd=4");

# test prove constraint expression: aa+bb+cc=0
$res = bulletproofs_prove($pp_path, $witness_path, "aa+bb+cc", 1);
ok($res =~ m/BEGIN BULLETPROOFS R1CS PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs r1cs proof result with constraint expression: aa+bb+cc=0");
$res = bulletproofs_proof($proof_path);
ok($res =~ m/BEGIN BULLETPROOFS R1CS PROOF/, "Check bulletproofs r1cs proof output");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/AI1: (\w\w:?)+\s+AO1: (\w\w:?)+\s+S1: (\w\w:?)+\s+AI2: (\w\w:?)+\s+AO2: (\w\w:?)+\s+S2: (\w\w:?)+\s+T1: (\w\w:?)+\s+T3: (\w\w:?)+\s+T4: (\w\w:?)+\s+T5: (\w\w:?)+\s+T6: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: ((\w\w:?)|0)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs r1cs proof text output");
$res = bulletproofs_verify($pp_path, $proof_path, "aa+bb+cc");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa+bb+cc=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "aa+bb+cc+0");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa+bb+cc+0=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "aa+bb+cc+1");
ok($res =~ m/The proof is invalid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa+bb+cc+1=0, it should failed");

# test prove constraint expression: aa*bb+cc+1=0
$res = bulletproofs_prove($pp_path, $witness_path, "aa*bb+cc+1", 1);
ok($res =~ m/BEGIN BULLETPROOFS R1CS PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs r1cs proof result with constraint expression: aa*bb+cc+1=0");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/AI1: (\w\w:?)+\s+AO1: (\w\w:?)+\s+S1: (\w\w:?)+\s+AI2: (\w\w:?)+\s+AO2: (\w\w:?)+\s+S2: (\w\w:?)+\s+T1: (\w\w:?)+\s+T3: (\w\w:?)+\s+T4: (\w\w:?)+\s+T5: (\w\w:?)+\s+T6: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: ((\w\w:?)|0)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs r1cs proof text output");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*bb+cc+1");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*bb+cc+1=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*bb+cc+1+0");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*bb+cc+1+0=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*bb+cc+2");
ok($res =~ m/The proof is invalid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*bb+cc+2=0, it should failed");

# test prove constraint expression: aa*bb*cc+6=0
$res = bulletproofs_prove($pp_path, $witness_path, "aa*bb*cc+6", 1);
ok($res =~ m/BEGIN BULLETPROOFS R1CS PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs r1cs proof result with constraint expression: aa*bb*cc+6=0");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/AI1: (\w\w:?)+\s+AO1: (\w\w:?)+\s+S1: (\w\w:?)+\s+AI2: (\w\w:?)+\s+AO2: (\w\w:?)+\s+S2: (\w\w:?)+\s+T1: (\w\w:?)+\s+T3: (\w\w:?)+\s+T4: (\w\w:?)+\s+T5: (\w\w:?)+\s+T6: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: ((\w\w:?)|0)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs r1cs proof text output");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*bb*cc+6");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*bb*cc+6=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*bb*cc+6-0");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*bb*cc+6-0=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*bb*cc+6-1");
ok($res =~ m/The proof is invalid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*bb*cc+6-1=0, it should failed");

# test prove constraint expression: aa*aa+bb*bb+cc*cc-14=0
$res = bulletproofs_prove($pp_path, $witness_path, "aa*aa+bb*bb+cc*cc-14", 1);
ok($res =~ m/BEGIN BULLETPROOFS R1CS PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs r1cs proof result with constraint expression: aa*aa+bb*bb+cc*cc-14=0");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/AI1: (\w\w:?)+\s+AO1: (\w\w:?)+\s+S1: (\w\w:?)+\s+AI2: (\w\w:?)+\s+AO2: (\w\w:?)+\s+S2: (\w\w:?)+\s+T1: (\w\w:?)+\s+T3: (\w\w:?)+\s+T4: (\w\w:?)+\s+T5: (\w\w:?)+\s+T6: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: ((\w\w:?)|0)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs r1cs proof text output");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*aa+bb*bb+cc*cc-14");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*aa+bb*bb+cc*cc-14=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*aa+bb*bb+cc*cc-14-0");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*aa+bb*bb+cc*cc-14-0=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "aa*aa+bb*bb+cc*cc-14-1");
ok($res =~ m/The proof is invalid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: aa*aa+bb*bb+cc*cc-14-1=0, it should failed");

# test prove constraint expression: (2*aa+bb)*cc+dd*3=0
$res = bulletproofs_prove($pp_path, $witness_path, "(2*aa+bb)*cc+dd*3", 1);
ok($res =~ m/BEGIN BULLETPROOFS R1CS PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs r1cs proof result with constraint expression: (2*aa+bb)*cc+dd*3=0");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/AI1: (\w\w:?)+\s+AO1: (\w\w:?)+\s+S1: (\w\w:?)+\s+AI2: (\w\w:?)+\s+AO2: (\w\w:?)+\s+S2: (\w\w:?)+\s+T1: (\w\w:?)+\s+T3: (\w\w:?)+\s+T4: (\w\w:?)+\s+T5: (\w\w:?)+\s+T6: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: ((\w\w:?)|0)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs r1cs proof text output");
$res = bulletproofs_verify($pp_path, $proof_path, "(2*aa+bb)*cc+dd*3");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: (2*aa+bb)*cc+dd*3=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "(2*aa+bb)*cc+dd*3-0");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: (2*aa+bb)*cc+dd*3-0=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "(2*aa+bb)*cc+dd*3-1");
ok($res =~ m/The proof is invalid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: (2*aa+bb)*cc+dd*3-1=0, it should failed");

# test prove constraint expression: ((aa+bb)*cc+23)-(dd+10)=0
$res = bulletproofs_prove($pp_path, $witness_path, "((aa+bb)*cc+23)-(dd+10)", 1);
ok($res =~ m/BEGIN BULLETPROOFS R1CS PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs r1cs proof result with constraint expression: ((aa+bb)*cc+23)-(dd+10)=0");
$res = bulletproofs_proof($proof_path, 1);
ok($res =~ m/AI1: (\w\w:?)+\s+AO1: (\w\w:?)+\s+S1: (\w\w:?)+\s+AI2: (\w\w:?)+\s+AO2: (\w\w:?)+\s+S2: (\w\w:?)+\s+T1: (\w\w:?)+\s+T3: (\w\w:?)+\s+T4: (\w\w:?)+\s+T5: (\w\w:?)+\s+T6: (\w\w:?)+\s+taux: (\w\w:?)+\s+mu: (\w\w:?)+\s+tx: ((\w\w:?)|0)+\s+inner proof:/ && $res =~ m/V\[n\]:/ && $res =~ m/    R\[n\]:/, "Check bulletproofs r1cs proof text output");
$res = bulletproofs_verify($pp_path, $proof_path, "((aa+bb)*cc+23)-(dd+10)");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: ((aa+bb)*cc+23)-(dd+10)=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "((aa+bb)*cc+23)-(dd+10)-0");
ok($res =~ m/The proof is valid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: ((aa+bb)*cc+23)-(dd+10)-0=0, it should ok");
$res = bulletproofs_verify($pp_path, $proof_path, "((aa+bb)*cc+23)-(dd+10)-1");
ok($res =~ m/The proof is invalid/, "Check the verification of the bulletproofs r1cs proof with constraint expression: ((aa+bb)*cc+23)-(dd+10)-1=0, it should failed");

# test prove constraint expression: aaa+bb+cc=0
$res = bulletproofs_prove($pp_path, $witness_path, "aaa+bb+cc", 1);
ok($res =~ m/Error/ && $res !~ m/BEGIN BULLETPROOFS R1CS PROOF[\s\S]+BEGIN BULLETPROOFS WITNESS/, "Check the format of the bulletproofs r1cs proof result with constraint expression: aaa+bb+cc=0. aaa not found, it should failed");

rmtree(${BULLETPROOFS_TEST_OUT_D}, { safe => 0 });
