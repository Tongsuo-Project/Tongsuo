package OpenSSL::Symbol;
# Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
#
# Licensed under the BabaSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE

use Exporter;
use vars qw($VERSION @ISA @EXPORT);

use configdata;
use File::Spec::Functions;

our @known_platforms = ( "__FreeBSD__", "PERL5", "EXPORT_VAR_AS_FUNCTION",
                        "ZLIB", "_WIN32");
our @known_ossl_platforms = ( "UNIX", "VMS", "WIN32", "WINNT", "OS2" );
our @known_algorithms = ( # These are algorithms we know are guarded in relevant
             # header files, but aren't actually disablable.
             # Without these, this script will warn a lot.
             "RSA", "MD5",
             # @disablables comes from configdata.pm
             map { (my $x = uc $_) =~ s|-|_|g; $x; } @disablables,
             # Deprecated functions.  Not really algorithmss, but
             # treated as such here for the sake of simplicity
             "DEPRECATEDIN_0_9_8",
             "DEPRECATEDIN_1_0_0",
             "DEPRECATEDIN_1_1_0",
             "DEPRECATEDIN_1_2_0");

$VERSION = '0.1';
@ISA = qw(Exporter);
@EXPORT = qw(do_defs info_string count_parens do_deprecated reduce_platforms @known_platforms);

sub do_defs
{
    my($name, $files, $symhacksfile, $debug, $trace, $verbose) = @_;
    my $file;
    my @ret;
    my %syms;
    my %platform;        # For anything undefined, we assume ""
    my %kind;            # For anything undefined, we assume "FUNCTION"
    my %algorithm;       # For anything undefined, we assume ""
    my %variant;
    my %variant_cnt;     # To be able to allocate "name{n}" if "name"
                         # is the same name as the original.
    my $cpp;
    my %unknown_algorithms = ();
    my $parens = 0;

    foreach $file (split(/\s+/,$symhacksfile." ".$files)) {
        my $fn = catfile($config{sourcedir},$file);
        print STDERR "DEBUG: starting on $fn:\n" if $debug;
        print STDERR "TRACE: start reading $fn\n" if $trace;
        open(IN,"<$fn") || die "Can't open $fn, $!,";
        my $line = "", my $def= "";
        my %tag = (
            (map { $_ => 0 } @known_platforms),
            (map { "OPENSSL_SYS_".$_ => 0 } @known_ossl_platforms),
            (map { "OPENSSL_NO_".$_ => 0 } @known_algorithms),
            (map { "OPENSSL_USE_".$_ => 0 } @known_algorithms),
            (grep /^DEPRECATED_/, @known_algorithms),
            NOPROTO        => 0,
            PERL5          => 0,
            _WINDLL        => 0,
            CONST_STRICT   => 0,
            TRUE           => 1,
        );
        my $symhacking = $file eq $symhacksfile;
        my @current_platforms = ();
        my @current_algorithms = ();

        # params: symbol, alias, platforms, kind
        # The reason to put this subroutine in a variable is that
        # it will otherwise create its own, unshared, version of
        # %tag and %variant...
        my $make_variant = sub
        {
            my ($s, $a, $p, $k) = @_;
            my ($a1, $a2);

            print STDERR "DEBUG: make_variant: Entered with ",$s,", ",$a,", ",(defined($p)?$p:""),", ",(defined($k)?$k:""),"\n" if $debug;
            if (defined($p)) {
                $a1 = join(",",$p,
                       grep(!/^$/,
                        map { $tag{$_} == 1 ? $_ : "" }
                        @known_platforms));
            } else {
                $a1 = join(",",
                       grep(!/^$/,
                        map { $tag{$_} == 1 ? $_ : "" }
                        @known_platforms));
            }
            $a2 = join(",", grep(!/^$/,
                                 map { $tag{"OPENSSL_SYS_".$_} == 1 ? $_ : "" }
                                 @known_ossl_platforms));
            print STDERR "DEBUG: make_variant: a1 = $a1; a2 = $a2\n" if $debug;
            if ($a1 eq "") { $a1 = $a2; }
            elsif ($a1 ne "" && $a2 ne "") { $a1 .= ",".$a2; }
            if ($a eq $s) {
                if (!defined($variant_cnt{$s})) {
                    $variant_cnt{$s} = 0;
                }
                $variant_cnt{$s}++;
                $a .= "{$variant_cnt{$s}}";
            }
            my $toadd = $a.":".$a1.(defined($k)?":".$k:"");
            my $togrep = $s.'(\{[0-9]+\})?:'.$a1.(defined($k)?":".$k:"");
            if (!grep(/^$togrep$/, split(/;/, defined($variant{$s})?$variant{$s}:""))) {
                if (defined($variant{$s})) { $variant{$s} .= ";"; }
                $variant{$s} .= $toadd;
            }
            print STDERR "DEBUG: make_variant: Exit with variant of ",$s," = ",$variant{$s},"\n" if $debug;
        };

        print STDERR "DEBUG: parsing ----------\n" if $debug;
        while(<IN>) {
            s|\R$||; # Better chomp
            if($parens > 0) {
                #Inside a DEPRECATEDIN
                $stored_multiline .= $_;
                print STDERR "DEBUG: Continuing multiline DEPRECATEDIN: $stored_multiline\n" if $debug;
                $parens = count_parens($stored_multiline);
                if ($parens == 0) {
                    $def .= do_deprecated($stored_multiline,
                            \@current_platforms,
                            \@current_algorithms);
                }
                next;
            }
            if (/\/\* Error codes for the \w+ functions\. \*\//) {
                undef @tag;
                last;
            }
            if ($line ne '') {
                $_ = $line . $_;
                $line = '';
            }

            if (/\\$/) {
                $line = $`; # keep what was before the backslash
                next;
            }

            if(/\/\*/) {
                if (not /\*\//) {    # multi-line comment...
                    $line = $_;    # ... just accumulate
                    next;
                } else {
                    s/\/\*.*?\*\///gs;# wipe it
                }
            }

            if ($cpp) {
                $cpp++ if /^\s*#\s*if/;
                $cpp-- if /^\s*#\s*endif/;
                next;
            }
            if (/^\s*#.*ifdef.*cplusplus/ or /^\s*#.*if\s+define.*cplusplus/) {
                $cpp = 1;
                next;
            }

            s/{[^{}]*}//gs;                      # ignore {} blocks
            print STDERR "DEBUG: \$def=\"$def\"\n" if $debug && $def ne "";
            print STDERR "DEBUG: \$_=\"$_\"\n" if $debug;
            if (/^\s*\#\s*if\s+OPENSSL_API_COMPAT\s*(\S)\s*(0x[0-9a-fA-F]{8})L\s*$/) {
                my $op = $1;
                my $v = hex($2);
                if ($op ne '<' && $op ne '>=') {
                    die "$file unacceptable operator $op: $_\n";
                }
                my ($one, $major, $minor) =
                   ( ($v >> 28) & 0xf,
                     ($v >> 20) & 0xff,
                     ($v >> 12) & 0xff );
                my $t = "DEPRECATEDIN_${one}_${major}_${minor}";
                push(@tag,"-");
                push(@tag,$t);
                $tag{$t}=($op eq '<' ? 1 : -1);
                print STDERR "DEBUG: $file: found tag $t = $tag{$t}\n" if $debug;
            } elsif (/^\s*\#\s*ifndef\s+(.*)/) {
                push(@tag,"-");
                push(@tag,$1);
                $tag{$1}=-1;
                print STDERR "DEBUG: $file: found tag $1 = -1\n" if $debug;
            } elsif (/^\s*\#\s*if\s+!defined\s*\(([^\)]+)\)/) {
                push(@tag,"-");
                if (/^\#\s*if\s+(!defined\s*\(([^\)]+)\)(\s+\&\&\s+!defined\s*\(([^\)]+)\))*)$/) {
                    my $tmp_1 = $1;
                    my $tmp_;
                    foreach $tmp_ (split '\&\&',$tmp_1) {
                        $tmp_ =~ /!defined\s*\(([^\)]+)\)/;
                        print STDERR "DEBUG: $file: found tag $1 = -1\n" if $debug;
                        push(@tag,$1);
                        $tag{$1}=-1;
                    }
                } else {
                    print STDERR "Warning: $file: taking only '!defined($1)' of complicated expression: $_" if $verbose; # because it is O...
                    print STDERR "DEBUG: $file: found tag $1 = -1\n" if $debug;
                    push(@tag,$1);
                    $tag{$1}=-1;
                }
            } elsif (/^\s*\#\s*ifdef\s+(\S*)/) {
                push(@tag,"-");
                push(@tag,$1);
                $tag{$1}=1;
                print STDERR "DEBUG: $file: found tag $1 = 1\n" if $debug;
            } elsif (/^\s*\#\s*if\s+defined\s*\(([^\)]+)\)/) {
                push(@tag,"-");
                if (/^\#\s*if\s+(defined\s*\(([^\)]+)\)(\s+\|\|\s+defined\s*\(([^\)]+)\))*)$/) {
                    my $tmp_1 = $1;
                    my $tmp_;
                    foreach $tmp_ (split '\|\|',$tmp_1) {
                        $tmp_ =~ /defined\s*\(([^\)]+)\)/;
                        print STDERR "DEBUG: $file: found tag $1 = 1\n" if $debug;
                        push(@tag,$1);
                        $tag{$1}=1;
                    }
                } else {
                    print STDERR "Warning: $file: taking only 'defined($1)' of complicated expression: $_\n" if $verbose; # because it is O...
                    print STDERR "DEBUG: $file: found tag $1 = 1\n" if $debug;
                    push(@tag,$1);
                    $tag{$1}=1;
                }
            } elsif (/^\s*\#\s*error\s+(\w+) is disabled\./) {
                my $tag_i = $#tag;
                while($tag[$tag_i] ne "-") {
                    if ($tag[$tag_i] eq "OPENSSL_NO_".$1) {
                        $tag{$tag[$tag_i]}=2;
                        print STDERR "DEBUG: $file: changed tag $1 = 2\n" if $debug;
                    }
                    $tag_i--;
                }
            } elsif (/^\s*\#\s*endif/) {
                my $tag_i = $#tag;
                while($tag_i > 0 && $tag[$tag_i] ne "-") {
                    my $t=$tag[$tag_i];
                    print STDERR "DEBUG: \$t=\"$t\"\n" if $debug;
                    if ($tag{$t}==2) {
                        $tag{$t}=-1;
                    } else {
                        $tag{$t}=0;
                    }
                    print STDERR "DEBUG: $file: changed tag ",$t," = ",$tag{$t},"\n" if $debug;
                    pop(@tag);
                    if ($t =~ /^OPENSSL_NO_([A-Z0-9_]+)$/) {
                        $t=$1;
                    } elsif ($t =~ /^OPENSSL_USE_([A-Z0-9_]+)$/) {
                        $t=$1;
                    } else {
                        $t="";
                    }
                    if ($t ne "" && !grep(/^$t$/, @known_algorithms)) {
                        $unknown_algorithms{$t} = 1;
                        #print STDERR "DEBUG: Added as unknown algorithm: $t\n" if $debug;
                    }
                    $tag_i--;
                }
                pop(@tag);
            } elsif (/^\s*\#\s*else/) {
                my $tag_i = $#tag;
                die "$file unmatched else\n" if $tag_i < 0;
                while($tag[$tag_i] ne "-") {
                    my $t=$tag[$tag_i];
                    $tag{$t}= -$tag{$t};
                    print STDERR "DEBUG: $file: changed tag ",$t," = ",$tag{$t},"\n" if $debug;
                    $tag_i--;
                }
            } elsif (/^\s*\#\s*if\s+1/) {
                push(@tag,"-");
                # Dummy tag
                push(@tag,"TRUE");
                $tag{"TRUE"}=1;
                print STDERR "DEBUG: $file: found 1\n" if $debug;
            } elsif (/^\s*\#\s*if\s+0/) {
                push(@tag,"-");
                # Dummy tag
                push(@tag,"TRUE");
                $tag{"TRUE"}=-1;
                print STDERR "DEBUG: $file: found 0\n" if $debug;
            } elsif (/^\s*\#\s*if\s+/) {
                #Some other unrecognized "if" style
                push(@tag,"-");
                print STDERR "Warning: $file: ignoring unrecognized expression: $_\n" if $verbose; # because it is O...
            } elsif (/^\s*\#\s*define\s+(\w+)\s+(\w+)/) {
                if ($1 eq "HASH_INIT") {
                    $def .= "void $2(SHA_CTX *c);";
                } elsif ($1 eq "HASH_UPDATE") {
                    $def .= "int $2(HASH_CTX *c, const void *data_, size_t len);";
                } elsif ($1 eq "HASH_TRANSFORM") {
                    $def .= "void $2(HASH_CTX *c, const unsigned char *data);";
                } elsif ($1 eq "HASH_FINAL") {
                    $def .= "int $2(unsigned char *md, HASH_CTX *c);";
                } elsif ($1 eq "HASH_BLOCK_DATA_ORDER") {
                    $def .= "void $2(void *ctx, const void *inp, size_t len);";
                }
                if ($symhacking && $tag{'TRUE'} != -1) {
                    # This is for aliasing.  When we find an alias,
                    # we have to invert
                    &$make_variant($1,$2);
                    print STDERR "DEBUG: $file: defined $1 = $2\n" if $debug;
                }
            }
            if (/^\s*\#/) {
                @current_platforms =
                    grep(!/^$/,
                     map { $tag{$_} == 1 ? $_ :
                           $tag{$_} == -1 ? "!".$_  : "" }
                     @known_platforms);
                push @current_platforms
                    , grep(!/^$/,
                       map { $tag{"OPENSSL_SYS_".$_} == 1 ? $_ :
                             $tag{"OPENSSL_SYS_".$_} == -1 ? "!".$_  : "" }
                       @known_ossl_platforms);
                @current_algorithms = ();
                @current_algorithms =
                    grep(!/^$/,
                     map { $tag{"OPENSSL_NO_".$_} == -1 ? $_ : "" }
                     @known_algorithms);
                push @current_algorithms
                    , grep(!/^$/,
                     map { $tag{"OPENSSL_USE_".$_} == 1 ? $_ : "" }
                     @known_algorithms);
                push @current_algorithms,
                    grep { /^DEPRECATEDIN_/ && $tag{$_} == 1 }
                    @known_algorithms;
                $def .=
                    "#INFO:"
                    .join(',',@current_platforms).":"
                        .join(',',@current_algorithms).";";
                next;
            }
            if ($tag{'TRUE'} != -1) {
                if (/^\s*DEFINE_STACK_OF\s*\(\s*(\w*)\s*\)/ || /^\s*DEFINE_STACK_OF_CONST\s*\(\s*(\w*)\s*\)/) {
                    next;
                } elsif (/^\s*DECLARE_ASN1_ENCODE_FUNCTIONS\s*\(\s*(\w*)\s*,\s*(\w*)\s*,\s*(\w*)\s*\)/) {
                    $def .= "int d2i_$3(void);";
                    $def .= "int i2d_$3(void);";
                    # Variant for platforms that do not
                    # have to access global variables
                    # in shared libraries through functions
                    $def .=
                        "#INFO:"
                        .join(',',"!EXPORT_VAR_AS_FUNCTION",@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    $def .= "OPENSSL_EXTERN int $2_it;";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Variant for platforms that have to
                    # access global variables in shared
                    # libraries through functions
                    &$make_variant("$2_it","$2_it",
                              "EXPORT_VAR_AS_FUNCTION",
                              "FUNCTION");
                    next;
                } elsif (/^\s*DECLARE_ASN1_FUNCTIONS_fname\s*\(\s*(\w*)\s*,\s*(\w*)\s*,\s*(\w*)\s*\)/) {
                    $def .= "int d2i_$3(void);";
                    $def .= "int i2d_$3(void);";
                    $def .= "int $3_free(void);";
                    $def .= "int $3_new(void);";
                    # Variant for platforms that do not
                    # have to access global variables
                    # in shared libraries through functions
                    $def .=
                        "#INFO:"
                        .join(',',"!EXPORT_VAR_AS_FUNCTION",@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    $def .= "OPENSSL_EXTERN int $2_it;";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Variant for platforms that have to
                    # access global variables in shared
                    # libraries through functions
                    &$make_variant("$2_it","$2_it",
                              "EXPORT_VAR_AS_FUNCTION",
                              "FUNCTION");
                    next;
                } elsif (/^\s*DECLARE_ASN1_FUNCTIONS\s*\(\s*(\w*)\s*\)/ || /^\s*DECLARE_ASN1_FUNCTIONS_const\s*\(\s*(\w*)\s*\)/) {
                    $def .= "int d2i_$1(void);";
                    $def .= "int i2d_$1(void);";
                    $def .= "int $1_free(void);";
                    $def .= "int $1_new(void);";
                    # Variant for platforms that do not
                    # have to access global variables
                    # in shared libraries through functions
                    $def .=
                        "#INFO:"
                        .join(',',"!EXPORT_VAR_AS_FUNCTION",@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    $def .= "OPENSSL_EXTERN int $1_it;";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Variant for platforms that have to
                    # access global variables in shared
                    # libraries through functions
                    &$make_variant("$1_it","$1_it",
                              "EXPORT_VAR_AS_FUNCTION",
                              "FUNCTION");
                    next;
                } elsif (/^\s*DECLARE_ASN1_ENCODE_FUNCTIONS_const\s*\(\s*(\w*)\s*,\s*(\w*)\s*\)/) {
                    $def .= "int d2i_$2(void);";
                    $def .= "int i2d_$2(void);";
                    # Variant for platforms that do not
                    # have to access global variables
                    # in shared libraries through functions
                    $def .=
                        "#INFO:"
                        .join(',',"!EXPORT_VAR_AS_FUNCTION",@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    $def .= "OPENSSL_EXTERN int $2_it;";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Variant for platforms that have to
                    # access global variables in shared
                    # libraries through functions
                    &$make_variant("$2_it","$2_it",
                              "EXPORT_VAR_AS_FUNCTION",
                              "FUNCTION");
                    next;
                } elsif (/^\s*DECLARE_ASN1_ALLOC_FUNCTIONS\s*\(\s*(\w*)\s*\)/) {
                    $def .= "int $1_free(void);";
                    $def .= "int $1_new(void);";
                    next;
                } elsif (/^\s*DECLARE_ASN1_FUNCTIONS_name\s*\(\s*(\w*)\s*,\s*(\w*)\s*\)/) {
                    $def .= "int d2i_$2(void);";
                    $def .= "int i2d_$2(void);";
                    $def .= "int $2_free(void);";
                    $def .= "int $2_new(void);";
                    # Variant for platforms that do not
                    # have to access global variables
                    # in shared libraries through functions
                    $def .=
                        "#INFO:"
                        .join(',',"!EXPORT_VAR_AS_FUNCTION",@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    $def .= "OPENSSL_EXTERN int $2_it;";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Variant for platforms that have to
                    # access global variables in shared
                    # libraries through functions
                    &$make_variant("$2_it","$2_it",
                              "EXPORT_VAR_AS_FUNCTION",
                              "FUNCTION");
                    next;
                } elsif (/^\s*DECLARE_ASN1_ITEM\s*\(\s*(\w*)\s*\)/) {
                    # Variant for platforms that do not
                    # have to access global variables
                    # in shared libraries through functions
                    $def .=
                        "#INFO:"
                        .join(',',"!EXPORT_VAR_AS_FUNCTION",@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    $def .= "OPENSSL_EXTERN int $1_it;";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Variant for platforms that have to
                    # access global variables in shared
                    # libraries through functions
                    &$make_variant("$1_it","$1_it",
                              "EXPORT_VAR_AS_FUNCTION",
                              "FUNCTION");
                    next;
                } elsif (/^\s*DECLARE_ASN1_NDEF_FUNCTION\s*\(\s*(\w*)\s*\)/) {
                    $def .= "int i2d_$1_NDEF(void);";
                } elsif (/^\s*DECLARE_ASN1_SET_OF\s*\(\s*(\w*)\s*\)/) {
                    next;
                } elsif (/^\s*DECLARE_ASN1_PRINT_FUNCTION\s*\(\s*(\w*)\s*\)/) {
                    $def .= "int $1_print_ctx(void);";
                    next;
                } elsif (/^\s*DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN\s*\(\s*(\w*)\s*,\s*(\w*)\s*,\s*(\w*)\s*\)/) {
                    $def .= "$2 OBJ_bsearch_$3($2 *key, $2 const *base, int num);";
                    next;
                } elsif (/^\s*DECLARE_RUN_ONCE\s*\(\s*(\w*)\s*\)/) {
                    $def .= "int $1_ossl_(void);";
                    next;
                } elsif (/^\s*DECLARE_ASN1_PRINT_FUNCTION_name\s*\(\s*(\w*)\s*,\s*(\w*)\s*\)/) {
                    $def .= "int $2_print_ctx(void);";
                    next;
                } elsif (/^\s*DECLARE_PKCS12_STACK_OF\s*\(\s*(\w*)\s*\)/) {
                    next;
                } elsif (/^DECLARE_PEM_rw\s*\(\s*(\w*)\s*,/ ||
                     /^DECLARE_PEM_rw_cb\s*\(\s*(\w*)\s*,/ ||
                     /^DECLARE_PEM_rw_const\s*\(\s*(\w*)\s*,/ ) {
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',"STDIO",@current_algorithms).";";
                    $def .= "int PEM_read_$1(void);";
                    $def .= "int PEM_write_$1(void);";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Things that are everywhere
                    $def .= "int PEM_read_bio_$1(void);";
                    $def .= "int PEM_write_bio_$1(void);";
                    next;
                } elsif (/^DECLARE_PEM_write\s*\(\s*(\w*)\s*,/ ||
                    /^DECLARE_PEM_write_const\s*\(\s*(\w*)\s*,/ ||
                     /^DECLARE_PEM_write_cb\s*\(\s*(\w*)\s*,/ ) {
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',"STDIO",@current_algorithms).";";
                    $def .= "int PEM_write_$1(void);";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Things that are everywhere
                    $def .= "int PEM_write_bio_$1(void);";
                    next;
                } elsif (/^DECLARE_PEM_read\s*\(\s*(\w*)\s*,/ ||
                     /^DECLARE_PEM_read_cb\s*\(\s*(\w*)\s*,/ ) {
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',"STDIO",@current_algorithms).";";
                    $def .= "int PEM_read_$1(void);";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',"STDIO",@current_algorithms).";";
                    # Things that are everywhere
                    $def .= "int PEM_read_bio_$1(void);";
                    next;
                } elsif (/^OPENSSL_DECLARE_GLOBAL\s*\(\s*(\w*)\s*,\s*(\w*)\s*\)/) {
                    # Variant for platforms that do not
                    # have to access global variables
                    # in shared libraries through functions
                    $def .=
                        "#INFO:"
                        .join(',',"!EXPORT_VAR_AS_FUNCTION",@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    $def .= "OPENSSL_EXTERN int _shadow_$2;";
                    $def .=
                        "#INFO:"
                        .join(',',@current_platforms).":"
                            .join(',',@current_algorithms).";";
                    # Variant for platforms that have to
                    # access global variables in shared
                    # libraries through functions
                    &$make_variant("_shadow_$2","_shadow_$2",
                              "EXPORT_VAR_AS_FUNCTION",
                              "FUNCTION");
                } elsif (/^\s*DEPRECATEDIN/) {
                    $parens = count_parens($_);
                    if ($parens == 0) {
                        $def .= do_deprecated($_,
                            \@current_platforms,
                            \@current_algorithms);
                    } else {
                        $stored_multiline = $_;
                        print STDERR "DEBUG: Found multiline DEPRECATEDIN starting with: $stored_multiline\n" if $debug;
                        next;
                    }
                } elsif ($tag{'CONST_STRICT'} != 1) {
                    if (/\{|\/\*|\([^\)]*$/) {
                        $line = $_;
                    } else {
                        $def .= $_;
                    }
                }
            }
        }
        close(IN);
        die "$file: Unmatched tags\n" if $#tag >= 0;

        my $algs;
        my $plays;

        print STDERR "DEBUG: postprocessing ----------\n" if $debug;
        foreach (split /;/, $def) {
            my $s; my $k = "FUNCTION"; my $p; my $a;
            s/^[\n\s]*//g;
            s/[\n\s]*$//g;
            next if(/\#undef/);
            next if(/typedef\W/);
            next if(/\#define/);
            next if(/static /);

            print STDERR "TRACE: processing $_\n" if $trace && !/^\#INFO:/;
            # Reduce argument lists to empty ()
            # fold round brackets recursively: (t(*v)(t),t) -> (t{}{},t) -> {}
            my $nsubst = 1; # prevent infinite loop, e.g., on  int fn()
            while($nsubst && /\(.*\)/s) {
                $nsubst = s/\([^\(\)]+\)/\{\}/gs;
                $nsubst+= s/\(\s*\*\s*(\w+)\s*\{\}\s*\)/$1/gs;    #(*f{}) -> f
            }
            # pretend as we didn't use curly braces: {} -> ()
            s/\{\}/\(\)/gs;

            s/STACK_OF\(\)/void/gs;
            s/LHASH_OF\(\)/void/gs;

            print STDERR "DEBUG: \$_ = \"$_\"\n" if $debug;
            if (/^\#INFO:([^:]*):(.*)$/) {
                $plats = $1;
                $algs = $2;
                print STDERR "DEBUG: found info on platforms ($plats) and algorithms ($algs)\n" if $debug;
                next;
            } elsif (/^\s*OPENSSL_EXTERN\s.*?(\w+(\{[0-9]+\})?)(\[[0-9]*\])*\s*$/) {
                $s = $1;
                $k = "VARIABLE";
                print STDERR "DEBUG: found external variable $s\n" if $debug;
            } elsif (/TYPEDEF_\w+_OF/s) {
                next;
            } elsif (/(\w+)\s*\(\).*/s) {    # first token prior [first] () is
                $s = $1;        # a function name!
                print STDERR "DEBUG: found function $s\n" if $debug;
            } elsif (/\(/ and not (/=/)) {
                print STDERR "File $file: cannot parse: $_;\n";
                next;
            } else {
                next;
            }

            $syms{$s} = 1;
            $kind{$s} = $k;

            $p = $plats;
            $a = $algs;

            $platform{$s} =
                &reduce_platforms((defined($platform{$s})?$platform{$s}.',':"").$p);
            $algorithm{$s} .= ','.$a;

            if (defined($variant{$s})) {
                foreach $v (split /;/,$variant{$s}) {
                    (my $r, my $p, my $k) = split(/:/,$v);
                    my $ip = join ',',map({ /^!(.*)$/ ? $1 : "!".$_ } split /,/, $p);
                    $syms{$r} = 1;
                    if (!defined($k)) { $k = $kind{$s}; }
                    $kind{$r} = $k."(".$s.")";
                    $algorithm{$r} = $algorithm{$s};
                    $platform{$r} = &reduce_platforms($platform{$s}.",".$p.",".$p);
                    $platform{$s} = &reduce_platforms($platform{$s}.','.$ip.','.$ip);
                    print STDERR "DEBUG: \$variant{\"$s\"} = ",$v,"; \$r = $r; \$p = ",$platform{$r},"; \$a = ",$algorithm{$r},"; \$kind = ",$kind{$r},"\n" if $debug;
                }
            }
            print STDERR "DEBUG: \$s = $s; \$p = ",$platform{$s},"; \$a = ",$algorithm{$s},"; \$kind = ",$kind{$s},"\n" if $debug;
        }
    }

    # Info we know about

    push @ret, map { $_."\\".&info_string($_,"EXIST",
                          $platform{$_},
                          $kind{$_},
                          $algorithm{$_}) } keys %syms;

    if (keys %unknown_algorithms) {
        print STDERR "WARNING: mkdef.pl doesn't know the following algorithms:\n";
        print STDERR "\t",join("\n\t",keys %unknown_algorithms),"\n";
    }
    return(@ret);
}

sub info_string
{
    (my $symbol, my $exist, my $platforms, my $kind, my $algorithms) = @_;

    my %a = defined($algorithms) ?  map { $_ => 1 } split /,/, $algorithms : ();
    my $k = defined($kind) ? $kind : "FUNCTION";
    my $ret;
    my $p = &reduce_platforms($platforms);

    delete $a{""};

    $ret = $exist;
    $ret .= ":".$p;
    $ret .= ":".$k;
    $ret .= ":".join(',',sort keys %a);
    return $ret;
}

sub count_parens
{
    my $line = shift(@_);

    my $open = $line =~ tr/\(//;
    my $close = $line =~ tr/\)//;

    return $open - $close;
}

sub do_deprecated()
{
    my ($decl, $plats, $algs) = @_;
    $decl =~ /^\s*(DEPRECATEDIN_\d+_\d+_\d+)\s*\((.*)\)\s*$/
            or die "Bad DEPRECATEDIN: $decl\n";
    my $info1 .= "#INFO:";
    $info1 .= join(',', @{$plats}) . ":";
    my $info2 = $info1;
    $info1 .= join(',',@{$algs}, $1) . ";";
    $info2 .= join(',',@{$algs}) . ";";
    return $info1 . $2 . ";" . $info2;
}

# Param: string of comma-separated platform-specs.
sub reduce_platforms
{
    my ($platforms) = @_;
    my $pl = defined($platforms) ? $platforms : "";
    my %p = map { $_ => 0 } split /,/, $pl;
    my $ret;

    print STDERR "DEBUG: Entered reduce_platforms with \"$platforms\"\n"
        if $debug;
    # We do this, because if there's code like the following, it really
    # means the function exists in all cases and should therefore be
    # everywhere.  By increasing and decreasing, we may attain 0:
    #
    # ifndef WIN16
    #    int foo();
    # else
    #    int _fat foo();
    # endif
    foreach $platform (split /,/, $pl) {
        if ($platform =~ /^!(.*)$/) {
            $p{$1}--;
        } else {
            $p{$platform}++;
        }
    }
    foreach $platform (keys %p) {
        if ($p{$platform} == 0) { delete $p{$platform}; }
    }

    delete $p{""};

    $ret = join(',',sort(map { $p{$_} < 0 ? "!".$_ : $_ } keys %p));
    print STDERR "DEBUG: Exiting reduce_platforms with \"$ret\"\n"
        if $debug;
    return $ret;
}

1;
__END__
