#! /usr/bin/env perl
# Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
#
# Licensed under the BabaSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE

use lib ".";
use configdata;
use File::Spec::Functions;
use File::Basename;
use FindBin;
use lib "$FindBin::Bin/perl";
use OpenSSL::Glob;
use OpenSSL::Symbol;

(my $SO_VARIANT = qq{\U$target{"shlib_variant"}}) =~ s/\W/_/g;

my $debug=0;
my $trace=0;
my $verbose=0;

my $do_all = 1;
my $do_crypto = 0;
my $do_ssl = 0;
my $do_internal = 0;
my $do_variable = 0;

my $prefix = $config{symbol_prefix};

my $zlib;

foreach (@ARGV, split(/ /, $config{options})) {
    $debug=1 if $_ eq "debug";
    $trace=1 if $_ eq "trace";
    $verbose=1 if $_ eq "verbose";
    if ($_ eq "zlib" || $_ eq "enable-zlib" || $_ eq "zlib-dynamic"
             || $_ eq "enable-zlib-dynamic") {
        $zlib = 1;
    }

    $do_crypto=1 if $_ eq "libcrypto" || $_ eq "crypto";
    $do_ssl=1 if $_ eq "libssl" || $_ eq "ssl";
    $do_internal=1 if $_ eq "internal";
    $do_variable=1 if $_ eq "variable";
}

if ("$prefix" eq "") {
    print "";
    exit(0);
}

$do_all = (!$do_ssl && !$do_crypto && !$do_internal && !$do_variable);

my %skipthese;
$skipthese{'include/openssl/ebcdic.h'} = 1;
$skipthese{'include/openssl/opensslconf.h'} = 1;
$skipthese{'include/openssl/symbol_prefix.h'} = 1;

my $symhacks="include/openssl/symhacks.h";

my %all_symbols;
my %ignore_symbols = (
    "HASH_INIT" => 1,
    "HASH_UPDATE" => 1,
    "HASH_TRANSFORM" => 1,
    "HASH_FINAL" => 1,
    "HASH_BLOCK_DATA_ORDER" => 1,
    "declare_dh_bn" => 1,
);
my @custom_symbols = (
    "curve448_point_eq",
    "do_engine_lock_init_ossl_ret_",
    "err_clear_last_constant_time",
    "_openssl_os_toascii",
    "_openssl_os_toebcdic",
    "_openssl_ebcdic2ascii",
    "_openssl_ascii2ebcdic",
    "md5_block_asm_data_order",
);

if ($do_all || $do_ssl) {
    my $ssl = "include/openssl/ssl.h";
    $ssl .= " include/openssl/sslerr.h";
    $ssl .= " include/openssl/tls1.h";
    $ssl .= " include/openssl/srtp.h";

    get_function_symbols("LIBSSL", $ssl, $symhacks, $debug, $trace, $verbose);
}

if ($do_all || $do_crypto) {
    my $crypto = "include/internal/dso.h";
    $crypto .= " include/internal/o_dir.h";
    $crypto .= " include/internal/o_str.h";
    $crypto .= " include/internal/err.h";
    $crypto .= " include/internal/sslconf.h";
    foreach my $f ( glob(catfile($config{sourcedir},'include/openssl/*.h')) ) {
        my $fn = "include/openssl/" . basename($f);
        $crypto .= " $fn" if !defined $skipthese{$fn};
    }

    get_function_symbols("LIBCRYPTO", $crypto, $symhacks, $debug, $trace, $verbose);
}

if ($do_all || $do_internal) {
    my $internal = "";
    $internal .= " include/internal/cryptlib.h";
    $internal .= " include/internal/bio.h";
    $internal .= " include/internal/comp.h";
    $internal .= " include/internal/conf.h";
    foreach my $f ( glob(catfile($config{sourcedir},'include/crypto/*.h')),
                    glob(catfile($config{sourcedir},'ssl/*.h')),
                    glob(catfile($config{sourcedir},'ssl/*/*.h')),
                    glob(catfile($config{sourcedir},'crypto/*.h')),
                    glob(catfile($config{sourcedir},'crypto/*/*.h')),
                    glob(catfile($config{sourcedir},'crypto/*/*/*.h')) ) {
        $internal .= " $f";
    }

    $internal .= " crypto/poly1305/poly1305.c";
    $internal .= " crypto/sha/sha512.c";
    $internal .= " crypto/sha/sha256.c";
    $internal .= " crypto/ec/ecp_nistz256.c";
    $internal .= " ssl/statem/statem_srvr.c";

    get_function_symbols("INTERNAL", $internal, $symhacks, $debug, $trace, $verbose);
}


if ($do_all || $do_variable) {
    my $variable_header_file = "crypto/ec/ecp_nistz256.c";
    foreach my $f ( glob(catfile($config{sourcedir},'include/*.h')),
                    glob(catfile($config{sourcedir},'include/internal/*.h')),
                    glob(catfile($config{sourcedir},'include/openssl/*.h')),
                    glob(catfile($config{sourcedir},'include/crypto/*.h')),
                    glob(catfile($config{sourcedir},'ssl/*.h')),
                    glob(catfile($config{sourcedir},'ssl/*/*.h')),
                    glob(catfile($config{sourcedir},'crypto/*.h')),
                    glob(catfile($config{sourcedir},'crypto/*/*.h')),
                    glob(catfile($config{sourcedir},'crypto/*/*/*.h')) ) {
        $variable_header_file .= " $f";
    }

    get_extern_variable_symbols($variable_header_file, $debug, $trace, $verbose);
}

print "#ifndef HEADER_SYMBOL_PREFIX_H\n";
print "# define HEADER_SYMBOL_PREFIX_H\n\n";
print "# define SYMBOL_PREFIX \"$prefix\"\n\n";

while(($symbol, $symbol_defs) = each(%all_symbols)) {
    print "# define $symbol $prefix$symbol\n" if !defined $ignore_symbols{$symbol};
}

foreach my $symbol (@custom_symbols) {
    print "# define $symbol $prefix$symbol\n";
}
print "\n#endif /* HEADER_SYMBOL_PREFIX_H */\n";

sub get_function_symbols {
    my($name, $files, $symhacksfile, $debug, $trace, $verbose) = @_;
    my @symbols = do_defs($name, $files, $symhacksfile, $debug, $trace, $verbose);

    foreach my $symbol (@symbols) {
        if ($symbol =~ /\{1\}/) {
            next;
        }
        $symbol =~ /(\S+)\\.*FUNCTION:(\S*)/;
        $all_symbols{$1} = $symbol;
    }
}

sub get_extern_variable_symbols {
    my($files, $debug, $trace, $verbose) = @_;

    foreach $file (split(/\s+/, $files)) {
        my $fn = catfile($config{sourcedir},$file);
        print STDERR "DEBUG: starting on $fn:\n" if $debug;
        print STDERR "TRACE: start reading $fn\n" if $trace;
        open(IN,"<$fn") || die "Can't open $fn, $!,";
        my $line = "", my $def= "";
        print STDERR "DEBUG: parsing ----------\n" if $debug;
        while(<IN>) {
            print STDERR "DEBUG: \$def=\"$def\"\n" if $debug && $def ne "";
            print STDERR "DEBUG: \$_=\"$_\"\n" if $debug;
            my @matched = $_ =~ /^extern\s+(\w+\s)+(\**\w+(?:\[\d*\])*\s*,\s*)?(\**\w+(?:\[\d*\])*\s*,\s*)?(\**\w+(?:\[\d*\])*\s*,\s*)?(\**\w+(?:\[\d*\])*\s*,\s*)?(\**\w+(?:\[\d*\])*\s*,\s*)?(\**\w+(?:\[\d*\])*)\s*;/;
            foreach my $m (@matched) {
                if ($m eq $1 || $m eq "") {
                    next;
                }
                $m =~ s/\*//g;
                $m =~ s/,//g;
                $m =~ s/\[\d*\]//g;
                $all_symbols{$m} = $m;
            }
            if (/^declare_dh_bn\((\d+)_(\d+)\)/) {
                $p = "_bignum_dh$1_$2_p";
                $g = "_bignum_dh$1_$2_g";
                $q = "_bignum_dh$1_$2_q";
                $all_symbols{$p} = $p;
                $all_symbols{$g} = $g;
                $all_symbols{$q} = $q;
            }
        }
        close(IN);

        print STDERR "DEBUG: postprocessing ----------\n" if $debug;
    }
}
