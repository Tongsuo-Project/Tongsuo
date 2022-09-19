#! /usr/bin/env perl
# Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
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

my $PAILLIER_TEST_D = getcwd();
my $PAILLIER_TEST_KEY_D = catdir($PAILLIER_TEST_D, "paillier_test_keys");
my $PAILLIER_TEST_OUT_D = catdir($PAILLIER_TEST_D, "paillier_test_outs");

rmtree(${PAILLIER_TEST_KEY_D}, { safe => 0 });
rmtree(${PAILLIER_TEST_OUT_D}, { safe => 0 });

mkdir($PAILLIER_TEST_KEY_D);
mkdir($PAILLIER_TEST_OUT_D);

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

sub paillier_encrypt
{
    my ($key, $plain) = @_;
    if ($plain < 0) {
        $plain *= -1;
        $plain = "_$plain";
    }
    my $out_path = catfile($PAILLIER_TEST_OUT_D, "encrypt-$plain.txt");
    ok(run(app(["openssl", "paillier",
        "-encrypt", "-key_in", $key, "-out", $out_path, $plain])), "test paillier -encrypt");
    my $content = file_content($out_path);
    if ($content =~ /ciphertext: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

sub paillier_decrypt
{
    my ($key, $ciphertext) = @_;
    my $c16 = substr($ciphertext, 0, 16);
    my $out_path = catfile($PAILLIER_TEST_OUT_D, "decrypt-$c16.txt");
    ok(run(app(["openssl", "paillier",
        "-decrypt", "-key_in", $key, "-out", $out_path, $ciphertext])), "test paillier -decrypt");
    my $content = file_content($out_path);
    if ($content =~ /plaintext: (-?\d+)/) {
        return $1;
    }
    return 'Error';
}

sub paillier_add
{
    my ($key, $c1, $c2) = @_;
    my $c16 = substr($c1, 0, 8);
    $c16 .= substr($c2, 0, 8);
    my $out_path = catfile($PAILLIER_TEST_OUT_D, "add-$c16.txt");
    ok(run(app(["openssl", "paillier",
        "-add", "-key_in", $key, "-out", $out_path, $c1, $c2])), "test paillier -add");
    my $content = file_content($out_path);
    if ($content =~ /result: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

sub paillier_add_plain
{
    my ($key, $c1, $plain) = @_;
    if ($plain < 0) {
        $plain *= -1;
        $plain = "_$plain";
    }
    my $c16 = substr($c1, 0, 16);
    $c16 .= "-$plain";
    my $out_path = catfile($PAILLIER_TEST_OUT_D, "add_plain-$c16.txt");
    ok(run(app(["openssl", "paillier",
        "-add_plain", "-key_in", $key, "-out", $out_path, $c1, $plain])), "test paillier -add_plain");
    my $content = file_content($out_path);
    if ($content =~ /result: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

sub paillier_sub
{
    my ($key, $c1, $c2) = @_;
    my $c16 = substr($c1, 0, 8);
    $c16 .= substr($c2, 0, 8);
    my $out_path = catfile($PAILLIER_TEST_OUT_D, "sub-$c16.txt");
    ok(run(app(["openssl", "paillier",
        "-sub", "-key_in", $key, "-out", $out_path, $c1, $c2])), "test paillier -sub");
    my $content = file_content($out_path);
    if ($content =~ /result: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

sub paillier_mul
{
    my ($key, $c1, $plain) = @_;
    if ($plain < 0) {
        $plain *= -1;
        $plain = "_$plain";
    }
    my $c16 = substr($c1, 0, 16);
    $c16 .= "-$plain";
    my $out_path = catfile($PAILLIER_TEST_OUT_D, "mul-$c16.txt");
    ok(run(app(["openssl", "paillier",
        "-mul", "-key_in", $key, "-out", $out_path, $c1, $plain])), "test paillier -mul");
    my $content = file_content($out_path);
    if ($content =~ /result: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

setup("test_app_paillier");

plan skip_all => "app_paillier is not supported by this OpenSSL build"
    if disabled("paillier");

plan tests => 190;

my $pail_key_path = catfile($PAILLIER_TEST_KEY_D, "pail-key.pem");
my $pail_pub_path = catfile($PAILLIER_TEST_KEY_D, "pail-pub.pem");
my $key_out_path = catfile($PAILLIER_TEST_OUT_D, "key-out.txt");
my $key_text_out_path = catfile($PAILLIER_TEST_OUT_D, "key-text-out.txt");
my $pub_out_path = catfile($PAILLIER_TEST_OUT_D, "pub-out.txt");
my $pub_text_out_path = catfile($PAILLIER_TEST_OUT_D, "pub-text-out.txt");

# test paillier key generate
ok(run(app(["openssl", "paillier",
    "-keygen", "-out", $pail_key_path])), "test paillier -keygen -out");
ok(run(app(["openssl", "paillier",
    "-pubgen", "-key_in", $pail_key_path, "-out", $pail_pub_path])), "test paillier -pubgen -out");

# test paillier -key/pub action
ok(run(app(["openssl", "paillier",
    "-key", "-in", $pail_key_path])), "test paillier -key");
ok(run(app(["openssl", "paillier",
    "-key", "-in", $pail_key_path, "-out", $key_out_path])), "test paillier -key -out");
ok(run(app(["openssl", "paillier",
    "-key", "-in", $pail_key_path, "-text", "-out", $key_text_out_path])), "test paillier -key -text -out");
ok(run(app(["openssl", "paillier",
    "-pub", "-in", $pail_pub_path])), "test paillier -pub");
ok(run(app(["openssl", "paillier",
    "-pub", "-in", $pail_pub_path, "-out", $pub_out_path])), "test paillier -pub -out");
ok(run(app(["openssl", "paillier",
    "-pub", "-in", $pail_pub_path, "-text", "-out", $pub_text_out_path])), "test paillier -pub -text -out");

my $key_value = file_content($pail_key_path);
my $key_out_value = file_content($key_out_path);
my $key_text_out_value = file_content($key_text_out_path);
my $pub_value = file_content($pail_pub_path);
my $pub_out_value = file_content($pub_out_path);
my $pub_text_out_value = file_content($pub_text_out_path);

ok("$key_value" eq "$key_out_value", "check paillier priavte key file");
ok($key_text_out_value =~ m/n:/, "check paillier private key n");
ok($key_text_out_value =~ m/p:/, "check paillier private key p");
ok($key_text_out_value =~ m/q:/, "check paillier private key q");
ok($key_text_out_value =~ m/lambda:/, "check paillier private key lambda");
ok($key_text_out_value =~ m/u:/, "check paillier private key u");

ok("$pub_value" eq "$pub_out_value", "check paillier public key file");
ok($pub_text_out_value =~ m/n:/, "check paillier public key n");
ok($pub_text_out_value =~ m/g:/, "check paillier public key g");

# test paillier -encrypt/decrypt action
my $e_111 = paillier_encrypt($pail_pub_path, 111);
my $d_111 = paillier_decrypt($pail_key_path, $e_111);
ok($e_111 !~ m/Error/, "test paillier -encrypt");
ok($d_111 !~ m/Error/, "test paillier -decrypt");
ok($d_111 == 111, "test if paillier decryption result is equal to 111");

my @test_data = (
    [1111, 9999],
    [1111, -9999],
    [-1111, 9999],
    [-1111, -9999],
    [1111, 0],
    [-1111, 0],
    [0, 9999],
    [0, -9999],
    [9999, 1111],
    [9999, -1111],
    [-9999, 1111],
    [-9999, -1111],
);

for(my $i = 0; $i < scalar(@test_data); $i++) {
    my $x = $test_data[$i][0];
    my $y = $test_data[$i][1];
    my $e_x = paillier_encrypt($pail_pub_path, $x);
    my $e_y = paillier_encrypt($pail_pub_path, $y);
    my $e_add = paillier_add($pail_pub_path, $e_x, $e_y);
    my $e_add_plain = paillier_add_plain($pail_pub_path, $e_x, $y);
    my $e_sub = paillier_sub($pail_pub_path, $e_x, $e_y);
    my $e_mul = paillier_mul($pail_pub_path, $e_x, $y);
    my $d_add = paillier_decrypt($pail_key_path, $e_add);
    my $d_add_plain = paillier_decrypt($pail_key_path, $e_add_plain);
    my $d_sub = paillier_decrypt($pail_key_path, $e_sub);
    my $d_mul = paillier_decrypt($pail_key_path, $e_mul);
    ok($d_add == $x + $y, "test paillier add ($x + ($y))");
    ok($d_add_plain == $x + $y, "test paillier add_plain ($x + ($y))");
    ok($d_sub == $x - $y, "test paillier sub ($x - ($y))");
    ok($d_mul == $x * $y, "test paillier mul ($x * ($y))");
}

rmtree(${PAILLIER_TEST_KEY_D}, { safe => 0 });
rmtree(${PAILLIER_TEST_OUT_D}, { safe => 0 });
