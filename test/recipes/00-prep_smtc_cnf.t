#! /usr/bin/env perl
# Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_dir bldtop_file srctop_file data_file/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

BEGIN {
    setup("prep_smtc_cnf");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "SMTC module config file only supported in a smtc build"
    if disabled("smtc") || disabled("smtc-debug");

my $bin = abs_path(bldtop_file('apps', 'openssl' . platform->binext()));
my $smtcconf = bldtop_file('test', 'smtcmodule.cnf');

plan tests => 1;

$ENV{OPENSSL_CONF} = "";

# Create the smtc conf file
ok(run(app(['openssl', 'mod', '-install', '-no_verify', '-no_auth',
    '-no_rand_poweron_test', '-module', $bin, '-out', $smtcconf])),
    "smtc install");
