#! /usr/bin/env perl
# Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use warnings;

use Getopt::Long;
use FindBin;
use lib "$FindBin::Bin/perl";

use OpenSSL::ParseC;

use File::Spec::Functions;
use lib '.';
use configdata;

my $symhacks_file = "include/openssl/symhacks.h";
my $version = undef;            # the version to use for added symbols
my $checkexist = 0;             # (unsure yet)
my $warnings = 0;
my $verbose = 0;
my $debug = 0;
my $prefix = $config{symbol_prefix};

my %all_symbols;
my %ignore_symbols = (
    "HASH_INIT" => 1,
    "HASH_UPDATE" => 1,
    "HASH_TRANSFORM" => 1,
    "HASH_FINAL" => 1,
    "HASH_BLOCK_DATA_ORDER" => 1,
    "gethostbyname" => 1,
    "gethostbyaddr" => 1,
    "getservbyname" => 1,
);

foreach my $f (catfile($config{sourcedir}, "util/engines.num"),
               catfile($config{sourcedir}, "util/providers.num")) {
    open IN, $f or die "Couldn't open $f: $!\n";
    while(<IN>) {
        print STDERR "DEBUG: \$_=\"$_\"\n" if $debug;
        $_ =~ qr/([\w_\d]+)\s+(?:\d+)\s+(?:\S+)/x;
        $ignore_symbols{$1} = 1;
    }
    close IN;
}

my @custom_symbols = ();

GetOptions('symhacks=s' => \$symhacks_file,
           'version=s'  => \$version,
           'exist'      => \$checkexist,
           'warnings!'  => \$warnings,
           'verbose'    => \$verbose,
           'debug'      => \$debug)
    or die "Error in command line arguments\n";

if ("$prefix" eq "") {
    output_symbols();
    exit(0);
}

@custom_symbols = (
    "ossl_md5_block_asm_data_order",
    "sha256_block_data_order",
    "sha512_block_data_order",
);

my @files = ();

foreach my $f ( glob(catfile($config{sourcedir}, 'include/*.h')),
                glob(catfile($config{sourcedir}, 'include/*/*.h')),
                glob(catfile($config{sourcedir}, 'ssl/*.h')),
                glob(catfile($config{sourcedir}, 'ssl/*/*.h')),
                glob(catfile($config{sourcedir}, 'crypto/*.h')),
                glob(catfile($config{sourcedir}, 'crypto/*/*.h')),
                glob(catfile($config{sourcedir}, 'crypto/*/*/*.h')),
                glob(catfile($config{sourcedir}, 'engines/*.h')),
                glob(catfile($config{sourcedir}, 'providers/*.h')),
                glob(catfile($config{sourcedir}, 'providers/*/*.h')),
                glob(catfile($config{sourcedir}, 'providers/*/*/*.h')),
                glob(catfile($config{sourcedir}, 'providers/*/*/*/*.h')) ) {
    push @files, $f;
}

foreach my $f (($symhacks_file // (), @files)) {
    print STDERR $f," ","-" x (69 - length($f)),"\n" if $verbose;
    open IN, $f or die "Couldn't open $f: $!\n";
    foreach (parse(<IN>, { filename => $f,
                           warnings => $warnings,
                           verbose => $verbose,
                           debug => $debug })) {
        $_->{value} = $_->{value}||"";
        next if grep { $_ eq 'CONST_STRICT' } @{$_->{conds}};
        printf STDERR "%s> %s%s : %s\n",
            $_->{type},
            $_->{name},
            ($_->{type} eq 'M' && defined $symhacks_file && $f eq $symhacks_file
             ? ' = ' . $_->{value}
             : ''),
            join(', ', @{$_->{conds}})
            if $verbose;
        if ($_->{type} eq 'M'
                && defined $symhacks_file
                && $f eq $symhacks_file
                && $_->{value} =~ /^\w(?:\w|\d)*/) {
            $all_symbols{$_->{name}} = join(',', @{$_->{conds}});
        } else {
            next if $_->{returntype} =~ /\b(?:ossl_)inline/;
            my $type = {
                F => 'FUNCTION',
                V => 'VARIABLE',
                e => 'EXTERN',
            } -> {$_->{type}};
            if ($type) {
                $all_symbols{$_->{name}} = join(',', @{$_->{conds}});
            }
        }
    }
    close IN;
}

output_symbols();

sub output_symbols {
    print "#ifndef HEADER_SYMBOL_PREFIX_H\n";
    print "# define HEADER_SYMBOL_PREFIX_H\n\n";
    print "# define SYMBOL_PREFIX \"$prefix\"\n\n";

    print "/***************PARSED SYMBOLS***************/\n";
    while((my $symbol, my $conds) = each(%all_symbols)) {
        print "# define $symbol $prefix$symbol\n" if !defined $ignore_symbols{$symbol};
    }

    print "\n\n/***************CUSTOM SYMBOLS***************/\n";
    foreach my $symbol (@custom_symbols) {
        print "# define $symbol $prefix$symbol\n";
    }
    print "\n#endif /* HEADER_SYMBOL_PREFIX_H */\n";
}
