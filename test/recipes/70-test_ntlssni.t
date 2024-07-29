#! /usr/bin/env perl
# Copyright 2023-2024 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file srctop_dir bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use TLSProxy::Proxy;

my $test_name = "test_ntlssni";
setup($test_name);

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs NTLS enabled"
    if disabled("ntls");

plan skip_all => "$test_name needs SM2, SM3 and SM4 enabled"
    if disabled("sm2") || disabled("sm3") || disabled("sm4");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';

my $no_smtc = disabled('smtc') || disabled('smtc-debug');
if (!$no_smtc) {
    $ENV{OPENSSL_CONF} = srctop_file("test", "smtc.cnf");
}

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

#Test 1: Check we get all the right messages for a default handshake
$proxy->ciphers("ECC-SM2-SM4-CBC-SM3");
$proxy->serverconnects(2);
$proxy->clientflags("-servername test" .
                    " -enable_ntls -ntls");
$proxy->serverflags("-servername localhost" .
                    " -servername_fatal" .
                    " -enable_ntls" .
                    " -sign_cert " . srctop_file("test", "certs", "sm2",
                                                 "server_sign.crt") .
                    " -sign_key " . srctop_file("test", "certs", "sm2",
                                                "server_sign.key") .
                    " -enc_cert " . srctop_file("test", "certs", "sm2",
                                                "server_enc.crt") .
                    " -enc_key " . srctop_file("test", "certs", "sm2",
                                               "server_enc.key") .
                    " -sign_cert2 " . srctop_file("test", "certs", "sm2",
                                                  "server_sign2.crt") .
                    " -sign_key2 " . srctop_file("test", "certs", "sm2",
                                                 "server_sign2.key") .
                    " -enc_cert2 " . srctop_file("test", "certs", "sm2",
                                                 "server_enc2.crt") .
                    " -enc_key2 " . srctop_file("test", "certs", "sm2",
                                                "server_enc2.key"));
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 3;
ok(TLSProxy::Message->fail(), "Servername mismatch send fatal alert");

$proxy->clearClient();
$proxy->clientflags("-servername localhost" .
                    " -enable_ntls -ntls");
$proxy->clientstart();
my $record = pop @{$proxy->record_list};
ok(TLSProxy::Message->success()
   && $record->version() == TLSProxy::Record::VERS_TLCP_1_1,
   "servername handshake test switch server ctx2");

# Check the server cert is server_sign2.crt, not server_sign.crt
foreach my $message (@{$proxy->message_list}) {
    if ($message->mt == TLSProxy::Message::MT_CERTIFICATE) {
        ok ($message->first_certificate =~ m/localhost.localdomain/,
            "server cert is sign_cert2");
    }
}
