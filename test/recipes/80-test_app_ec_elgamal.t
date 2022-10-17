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

my $EC_ELGAMAL_TEST_D = getcwd();
my $EC_ELGAMAL_TEST_KEY_D = catdir($EC_ELGAMAL_TEST_D, "ec_elgamal_test_keys");
my $EC_ELGAMAL_TEST_OUT_D = catdir($EC_ELGAMAL_TEST_D, "ec_elgamal_test_outs");

rmtree(${EC_ELGAMAL_TEST_KEY_D}, { safe => 0 });
rmtree(${EC_ELGAMAL_TEST_OUT_D}, { safe => 0 });

mkdir($EC_ELGAMAL_TEST_KEY_D);
mkdir($EC_ELGAMAL_TEST_OUT_D);

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

sub ec_elgamal_encrypt
{
    my ($key, $plain) = @_;
    if ($plain < 0) {
        $plain *= -1;
        $plain = "_$plain";
    }
    my $out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "encrypt-$plain.txt");
    ok(run(app(["openssl", "ec_elgamal",
        "-encrypt", "-key_in", $key, "-out", $out_path, $plain])), "test ec_elgamal -encrypt");
    my $content = file_content($out_path);
    if ($content =~ /ciphertext: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

sub ec_elgamal_decrypt
{
    my ($key, $ciphertext) = @_;
    my $c16 = substr($ciphertext, 0, 16);
    my $out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "decrypt-$c16.txt");
    ok(run(app(["openssl", "ec_elgamal",
        "-decrypt", "-key_in", $key, "-out", $out_path, $ciphertext])), "test ec_elgamal -decrypt");
    my $content = file_content($out_path);
    if ($content =~ /plaintext: (-?\d+)/) {
        return $1;
    }
    return 'Error';
}

sub ec_elgamal_add
{
    my ($key, $c1, $c2) = @_;
    my $c16 = substr($c1, 0, 8);
    $c16 .= substr($c2, 0, 8);
    my $out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "add-$c16.txt");
    ok(run(app(["openssl", "ec_elgamal",
        "-add", "-key_in", $key, "-out", $out_path, $c1, $c2])), "test ec_elgamal -add");
    my $content = file_content($out_path);
    if ($content =~ /result: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

sub ec_elgamal_sub
{
    my ($key, $c1, $c2) = @_;
    my $c16 = substr($c1, 0, 8);
    $c16 .= substr($c2, 0, 8);
    my $out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "sub-$c16.txt");
    ok(run(app(["openssl", "ec_elgamal",
        "-sub", "-key_in", $key, "-out", $out_path, $c1, $c2])), "test ec_elgamal -sub");
    my $content = file_content($out_path);
    if ($content =~ /result: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

sub ec_elgamal_mul
{
    my ($key, $c1, $plain) = @_;
    if ($plain < 0) {
        $plain *= -1;
        $plain = "_$plain";
    }
    my $c16 = substr($c1, 0, 16);
    $c16 .= "-$plain";
    my $out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "mul-$c16.txt");
    ok(run(app(["openssl", "ec_elgamal",
        "-mul", "-key_in", $key, "-out", $out_path, $c1, $plain])), "test ec_elgamal -mul");
    my $content = file_content($out_path);
    if ($content =~ /result: ([\dA-F]+)/) {
        return $1;
    }
    return 'Error';
}

setup("test_app_ec_elgamal");

plan skip_all => "app_ec_elgamal is not supported by this OpenSSL build"
    if disabled("ec_elgamal");

plan tests => 139;

my $ec_key_path = catfile($EC_ELGAMAL_TEST_KEY_D, "ec-key.pem");
my $ec_pub_path = catfile($EC_ELGAMAL_TEST_KEY_D, "ec-pub.pem");
my $key_out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "key-out.txt");
my $key_text_out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "key-text-out.txt");
my $pub_out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "pub-out.txt");
my $pub_text_out_path = catfile($EC_ELGAMAL_TEST_OUT_D, "pub-text-out.txt");

# generate ec key
ok(run(app(["openssl", "ecparam",
    "-genkey", "-name", "prime256v1", "-out", $ec_key_path])), "generate ec private key");
ok(run(app(["openssl", "ec",
    "-in", $ec_key_path, "-pubout", "-out", $ec_pub_path])), "generate ec pub key");

# test ec_elgamal -encrypt/decrypt action
my $e_111 = ec_elgamal_encrypt($ec_pub_path, 111);
my $d_111 = ec_elgamal_decrypt($ec_key_path, $e_111);
ok($e_111 !~ m/Error/, "test ec_elgamal -encrypt");
ok($d_111 !~ m/Error/, "test ec_elgamal -decrypt");
ok($d_111 == 111, "test if ec_elgamal decryption result is equal to 111");

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
    my $e_x = ec_elgamal_encrypt($ec_pub_path, $x);
    my $e_y = ec_elgamal_encrypt($ec_pub_path, $y);
    my $e_add = ec_elgamal_add($ec_pub_path, $e_x, $e_y);
    my $e_sub = ec_elgamal_sub($ec_pub_path, $e_x, $e_y);
    my $e_mul = ec_elgamal_mul($ec_pub_path, $e_x, $y);
    my $d_add = ec_elgamal_decrypt($ec_key_path, $e_add);
    my $d_sub = ec_elgamal_decrypt($ec_key_path, $e_sub);
    my $d_mul = ec_elgamal_decrypt($ec_key_path, $e_mul);
    ok($d_add == $x + $y, "test ec_elgamal add ($x + ($y))");
    ok($d_sub == $x - $y, "test ec_elgamal sub ($x - ($y))");
    ok($d_mul == $x * $y, "test ec_elgamal mul ($x * ($y))");
}

rmtree(${EC_ELGAMAL_TEST_KEY_D}, { safe => 0 });
rmtree(${EC_ELGAMAL_TEST_OUT_D}, { safe => 0 });
