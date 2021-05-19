use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/splitdir curdir catfile/;
use File::Compare;
use OpenSSL::Test qw/:DEFAULT data_file data_dir cmdstr srctop_file/;
use OpenSSL::Test::Utils;

setup("test_dc_sign");

$ENV{DATADIR} = data_dir();

plan skip_all => "dc_sign is not supported by this OpenSSL build"
    if disabled("delegated-credential");

plan tests => 10;

ok(run(cmd(["sh", data_file("sign_dc.sh")])));

# sign client dc
ok(run(app(["openssl", "delecred", "-new", "-client", "-sec", "604800",
    "-dc_key", data_file("dc-ecc-client-longterm.key"),
    "-out", data_file("dc-ecc-client-longterm.dc"),
    "-parent_cert", data_file("dc-ecc-leaf.crt"),
    "-parent_key", data_file("dc-ecc-leaf.key"),
    "-expect_verify_md", "sha256", "-sha256"])));

ok(run(app(["openssl", "delecred",
    "-in", data_file("dc-ecc-client-longterm.dc"),
    "-text", "-noout"])));

# sign server dc
ok(run(app(["openssl", "delecred", "-new", "-server", "-sec", "604800",
    "-dc_key", data_file("dc-ecc-server-longterm.key"),
    "-out", data_file("dc-server.dc.tmp"),
    "-parent_cert", data_file("dc-ecc-leaf.crt"),
    "-parent_key", data_file("dc-ecc-leaf.key"),
    "-expect_verify_md", "sha256", "-sha256"])));

ok(run(app(["openssl", "delecred",
    "-in", data_file("dc-server.dc.tmp"),
    "-text", "-noout"])));

# valid time too large
ok(!run(app(["openssl", "delecred", "-new", "-server", "-sec", "604801",
    "-dc_key", data_file("dc-ecc-server-longterm.key"),
    "-out", data_file("dc-server.dc.tmp"),
    "-parent_cert", data_file("dc-ecc-leaf.crt"),
    "-parent_key", data_file("dc-ecc-leaf.key"),
    "-expect_verify_md", "sha256", "-sha256"])));
# default md
ok(run(app(["openssl", "delecred", "-new", "-client", "-sec", "604800",
    "-dc_key", data_file("dc-ecc-client-longterm.key"),
    "-out", data_file("dc-ecc-client-longterm.dc"),
    "-parent_cert", data_file("dc-ecc-leaf.crt"),
    "-parent_key", data_file("dc-ecc-leaf.key"),
    "-expect_verify_md", "sha256"])));

ok(run(app(["openssl", "delecred",
    "-in", data_file("dc-ecc-client-longterm.dc"),
    "-text", "-noout"])));

# default expect verify md
ok(run(app(["openssl", "delecred", "-new", "-server", "-sec", "604800",
    "-dc_key", data_file("dc-ecc-server-longterm.key"),
    "-out", data_file("dc-ecc-server-longterm.key"),
    "-parent_cert", data_file("dc-ecc-leaf.crt"),
    "-parent_key", data_file("dc-ecc-leaf.key")])));

ok(run(app(["openssl", "delecred", "-in", data_file("dc-ecc-server-longterm.key"),
    "-text", "-noout"])));