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

setup("test_dc_sign");

plan skip_all => "dc_sign is not supported by this OpenSSL build"
    if disabled("delegated-credential");

plan tests => 22;

my $CERTS_D = getcwd();
my $DC_D = catdir($CERTS_D, "dc");
my $CA_D = catdir($CERTS_D, "ca");
my $SUBCA_D = catdir($CERTS_D, "subca");

rmtree(${DC_D}, { safe => 0 });
rmtree(${CA_D}, { safe => 0 });
rmtree(${SUBCA_D}, { safe => 0 });

sub setup_ca {
    my $CATOP = shift;

    mkdir($CATOP);
    mkdir(catdir($CATOP, "newcerts"));
    mkdir(catdir($CATOP, "db"));
    mkdir(catdir($CATOP, "private"));
    mkdir(catdir($CATOP, "crl"));

    open OUT, ">", catfile($CATOP, "db", "index.txt");
    close OUT;
    open OUT, ">", catfile($CATOP, "db", "serial");
    print OUT "00\n";
    close OUT;
}

mkdir($DC_D);
setup_ca(${CA_D});
setup_ca(${SUBCA_D});

# ca
ok(run(app(["openssl", "genpkey",
    "-algorithm", "rsa",
     "-pkeyopt", "rsa_keygen_bits:2048",
     "-out", catfile($DC_D, "dc-root.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("ca.cnf"),
    "-new", "-key", catfile($DC_D, "dc-root.key"),
    "-out", catfile($DC_D, "dc-root.csr"),
    "-sha256", "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=root ca",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-selfsign", "-config", data_file("ca.cnf"),
    "-keyfile", catfile($DC_D, "dc-root.key"),
    "-in", catfile($DC_D, "dc-root.csr"),
    "-extensions", "v3_ca",
    "-days", "3650",
    "-out", catfile($DC_D, "dc-root.crt"),
    "-md", "sha256",
    "-batch"])));

# sub ca
ok(run(app(["openssl", "genpkey",
    "-algorithm", "rsa",
     "-pkeyopt", "rsa_keygen_bits:2048",
     "-out", catfile($DC_D, "dc-subca.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("ca.cnf"),
    "-new", "-key", catfile($DC_D, "dc-subca.key"),
    "-out", catfile($DC_D, "dc-subca.csr"),
    "-sha256", "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=sub ca",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("ca.cnf"),
    "-cert", catfile($DC_D, "dc-root.crt"),
    "-keyfile", catfile($DC_D, "dc-root.key"),
    "-in", catfile($DC_D, "dc-subca.csr"),
    "-extensions", "v3_intermediate_ca",
    "-days", "3650",
    "-out", catfile($DC_D, "dc-subca.crt"),
    "-md", "sha256",
    "-batch"])));

my $dc_root_path = catfile($DC_D, "dc-root.crt");
my $dc_subca_path = catfile($DC_D, "dc-subca.crt");
my $dc_chain_ca_path = catfile($DC_D, "dc-chain-ca.crt");

open my $dc_chain_ca, '>', $dc_chain_ca_path
    or die "Trying to write to $dc_chain_ca_path: $!\n";
open my $dc_root, "<", $dc_root_path
    or die "Could not open $dc_root_path: $!\n";
open my $dc_subca, "<", $dc_subca_path
    or die "Could not open $dc_subca_path: $!\n";

while (my $line = <$dc_root>) {
    print $dc_chain_ca $line;
}

while (my $line = <$dc_subca>) {
    print $dc_chain_ca $line;
}

close $dc_root;
close $dc_subca;
close $dc_chain_ca;

# server
ok(run(app(["openssl", "genpkey",
    "-algorithm", "rsa",
     "-pkeyopt", "rsa_keygen_bits:2048",
     "-out", catfile($DC_D, "dc-leaf-server.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-new", "-key", catfile($DC_D, "dc-leaf-server.key"),
    "-out", catfile($DC_D, "dc-leaf-server.csr"),
    "-sha256", "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=server",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-cert", catfile($DC_D, "dc-subca.crt"),
    "-keyfile", catfile($DC_D, "dc-subca.key"),
    "-in", catfile($DC_D, "dc-leaf-server.csr"),
    "-extensions", "server_cert",
    "-days", "3650",
    "-out", catfile($DC_D, "dc-leaf-server.crt"),
    "-md", "sha256",
    "-batch"])));

# client
ok(run(app(["openssl", "genpkey",
    "-algorithm", "rsa",
     "-pkeyopt", "rsa_keygen_bits:2048",
     "-out", catfile($DC_D, "dc-leaf-client.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-new", "-key", catfile($DC_D, "dc-leaf-client.key"),
    "-out", catfile($DC_D, "dc-leaf-client.csr"),
    "-sha256", "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=client",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-cert", catfile($DC_D, "dc-subca.crt"),
    "-keyfile", catfile($DC_D, "dc-subca.key"),
    "-in", catfile($DC_D, "dc-leaf-client.csr"),
    "-extensions", "usr_cert",
    "-days", "3650",
    "-out", catfile($DC_D, "dc-leaf-client.crt"),
    "-md", "sha256",
    "-batch"])));

# server dc
ok(run(app(["openssl", "genpkey",
    "-algorithm", "RSA-PSS",
     "-pkeyopt", "rsa_keygen_bits:2048",
     "-out", catfile($DC_D, "dc-server.key")])));

ok(run(app(["openssl", "delecred",
    "-new", "-server",
    "-sec", "604800",
    "-dc_key", catfile($DC_D, "dc-server.key"),
    "-out", catfile($DC_D, "dc-server.dc"),
    "-parent_cert", catfile($DC_D, "dc-leaf-server.crt"),
    "-parent_key", catfile($DC_D, "dc-leaf-server.key"),
    "-expect_verify_md", "sha256",
    "-sha256"])));

ok(run(app(["openssl", "delecred",
    "-in", catfile($DC_D, "dc-server.dc"),
    "-text", "-noout"])));

# client dc
ok(run(app(["openssl", "genpkey",
    "-algorithm", "RSA-PSS",
     "-pkeyopt", "rsa_keygen_bits:2048",
     "-out", catfile($DC_D, "dc-client.key")])));

ok(run(app(["openssl", "delecred",
    "-new", "-client",
    "-sec", "604800",
    "-dc_key", catfile($DC_D, "dc-client.key"),
    "-out", catfile($DC_D, "dc-client.dc"),
    "-parent_cert", catfile($DC_D, "dc-leaf-client.crt"),
    "-parent_key", catfile($DC_D, "dc-leaf-client.key"),
    "-expect_verify_md", "sha256",
    "-sha256"])));

ok(run(app(["openssl", "delecred",
    "-in", catfile($DC_D, "dc-client.dc"),
    "-text", "-noout"])));

# server expire dc
ok(run(app(["openssl", "genpkey",
    "-algorithm", "RSA-PSS",
     "-pkeyopt", "rsa_keygen_bits:2048",
     "-out", catfile($DC_D, "dc-server-expire.key")])));

ok(run(app(["openssl", "delecred",
    "-new", "-server",
    "-sec", "1",
    "-dc_key", catfile($DC_D, "dc-server-expire.key"),
    "-out", catfile($DC_D, "dc-server-expire.dc"),
    "-parent_cert", catfile($DC_D, "dc-leaf-server.crt"),
    "-parent_key", catfile($DC_D, "dc-leaf-server.key"),
    "-expect_verify_md", "sha256",
    "-sha256"])));

# client expire dc
ok(run(app(["openssl", "genpkey",
    "-algorithm", "RSA-PSS",
     "-pkeyopt", "rsa_keygen_bits:2048",
     "-out", catfile($DC_D, "dc-client-expire.key")])));

ok(run(app(["openssl", "delecred",
    "-new", "-client",
    "-sec", "1",
    "-dc_key", catfile($DC_D, "dc-client-expire.key"),
    "-out", catfile($DC_D, "dc-client-expire.dc"),
    "-parent_cert", catfile($DC_D, "dc-leaf-client.crt"),
    "-parent_key", catfile($DC_D, "dc-leaf-client.key"),
    "-expect_verify_md", "sha256",
    "-sha256"])));
