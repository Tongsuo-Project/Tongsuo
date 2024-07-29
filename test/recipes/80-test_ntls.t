#! /usr/bin/env perl
# Copyright 2015-2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Basename;
use File::Compare qw/compare_text/;
use File::Spec::Functions qw/devnull catdir/;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file bldtop_dir result_dir/;
use OpenSSL::Test::Utils qw/disabled alldisabled available_protocols/;

BEGIN {
setup("test_ntls");
}

plan skip_all => "NTLS is not supported by this OpenSSL build"
    if disabled("ntls");

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

my $no_smtc = disabled('smtc') || disabled('smtc-debug');
if (!$no_smtc) {
    $ENV{OPENSSL_CONF} = srctop_file("test", "smtc.cnf");
}

$ENV{TEST_CERTS_DIR} = srctop_dir("test", "certs");

my @conf_srcs =  glob(srctop_file("test", "ntls-tests", "*.cnf.in"));
my @conf_files = map { basename($_, ".in") } @conf_srcs;

# We hard-code the number of tests to double-check that the globbing above
# finds all files as expected.
plan tests => 5;


# Add your test here if the test conf.in generates test cases and/or
# expectations dynamically based on the OpenSSL compile-time config.
my %conf_dependent_tests = (
  "31-ntls.cnf" => disabled("ntls"),
  "32-ntls-force-ntls.cnf" => disabled("ntls"),
  "39-ntls-sni-ticket.cnf" => disabled("ntls"),
  "40-ntls_client_auth.cnf" => disabled("ntls"),
  "41-ntls-alpn.cnf" => disabled("ntls"),
);

# Add your test here if it should be skipped for some compile-time
# configurations. Default is $no_tls but some tests have different skip
# conditions.
my %skip = (
  "31-ntls.cnf" => disabled("ntls") || disabled("sm2") || disabled("sm3")
                    || disabled("sm4"),
  "32-ntls-force-ntls.cnf" => disabled("ntls") || disabled("sm2")
                                || disabled("sm3") || disabled("sm4")
                                || !disabled("smtc"),
  "39-ntls-sni-ticket.cnf" => disabled("ntls") || disabled("sm2")
                                || disabled("sm3") || disabled("sm4"),
  "40-ntls_client_auth.cnf" => disabled("ntls") || disabled("sm2")
                                || disabled("sm3") || disabled("sm4"),
  "41-ntls-alpn.cnf" => disabled("ntls") || disabled("sm2") || disabled("sm3")
                        || disabled("sm4"),
);

foreach my $conf (@conf_files) {
    subtest "Test configuration $conf" => sub {
        plan tests => $no_smtc ? 6 : 3;
        test_conf($conf,
                  $conf_dependent_tests{$conf} ? 0 : 1, $skip{$conf}, "none")
                  unless !$no_smtc;
        test_conf($conf, 0, $skip{$conf}, "default") unless !$no_smtc;
        test_conf($conf, 0, $skip{$conf}, "smtc") unless $no_smtc;
    };
}

sub test_conf {
    my ($conf, $check_source, $skip, $provider) = @_;

    my $conf_file = srctop_file("test", "ntls-tests", $conf);
    my $input_file = $conf_file . ".in";
    my $output_file = $conf . "." . $provider;
    my $run_test = 1;

  SKIP: {
      # "Test" 1. Generate the source.
      skip 'failure', 2 unless
        ok(run(perltest(["generate_ssl_tests.pl", $input_file, $provider],
                        interpreter_args => [ "-I", srctop_dir("util", "perl")],
                        stdout => $output_file)),
           "Getting output from generate_ssl_tests.pl.");

    SKIP: {
        # Test 2. Compare against existing output in test/ntls-tests/
        skip "Skipping generated source test for $conf", 1
          if !$check_source;

        $run_test = is(cmp_text($output_file, $conf_file), 0,
                       "Comparing generated $output_file with $conf_file.");
      }

      # Test 3. Run the test.
      skip "No tests available; skipping tests", 1 if $skip;
      skip "Stale sources; skipping tests", 1 if !$run_test;

    if ($provider eq "smtc") {
          ok(run(test(["ssl_test", $output_file, $provider,
                       srctop_file("test", "smtc.cnf")])),
             "running ssl_test $conf");
      } else {
          ok(run(test(["ssl_test", $output_file, $provider])),
             "running ssl_test $conf");
      }
    }
}

sub cmp_text {
    return compare_text(@_, sub {
        $_[0] =~ s/\R//g;
        $_[1] =~ s/\R//g;
        return $_[0] ne $_[1];
    });
}
