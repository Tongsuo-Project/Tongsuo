#! /usr/bin/env perl
#
# Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
# Copyright (c) 2026 Intel Corporation. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

###############################################################################
# ML-DSA AVX2 NTT-domain matrix-row × vector accumulate (pointwise)
#
# Implemented:
#   ml_dsa_pointwise_acc_avx_l4
#   ml_dsa_pointwise_acc_avx_l5
#   ml_dsa_pointwise_acc_avx_l7
###############################################################################

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64 = 0;
$win64 = 1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$avx2 = 0;

$0 =~ m/(.*[\/\\])[^\/\\]+$/;
$dir = $1;
($xlate = "${dir}x86_64-xlate.pl" and -f $xlate)
  or ($xlate = "${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate)
  or die "can't locate x86_64-xlate.pl";

my $cc = $ENV{CC};
$cc = "gcc" if !defined($cc) || $cc eq "";

if (`$cc -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1` =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
  $avx2 = ($1 >= 2.22);
}

if (!$avx2
  && $win64
  && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/)
  && `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)(?:\.([0-9]+))?/)
{
  $avx2 = ($1 >= 2.10);
}

if (!$avx2 && `$cc -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
    $avx2 = ($2>=3.3);
}

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
  or die "can't call $xlate: $!";
*STDOUT = *OUT;

my $poly_bytes = 256 * 4;
my $ML_DSA_Q = 8380417;
my $ML_DSA_Q_INV = 58728449;   # q^{-1} mod 2^32 (Dilithium montgomery)

sub emit_pointwise {
    my ($off) = @_;
    return <<___;
    vmovdqu         $off(\%rsi), \%ymm6
    vmovdqu         $off+32(\%rsi), \%ymm8
    vmovdqu         $off(\%rdx), \%ymm10
    vmovdqu         $off+32(\%rdx), \%ymm12
    vpsrlq          \$32, \%ymm6, \%ymm7
    vpsrlq          \$32, \%ymm8, \%ymm9
    vpsrlq          \$32, \%ymm10, \%ymm11
    vpsrlq          \$32, \%ymm12, \%ymm13
    vpmuldq         \%ymm6, \%ymm10, \%ymm6
    vpmuldq         \%ymm7, \%ymm11, \%ymm7
    vpmuldq         \%ymm8, \%ymm12, \%ymm8
    vpmuldq         \%ymm9, \%ymm13, \%ymm9
___
}

sub emit_acc {
    return <<___;
    vpaddq          \%ymm6, \%ymm2, \%ymm2
    vpaddq          \%ymm7, \%ymm3, \%ymm3
    vpaddq          \%ymm8, \%ymm4, \%ymm4
    vpaddq          \%ymm9, \%ymm5, \%ymm5
___
}

sub emit_reduce_store {
    return <<___;
    vpmuldq         \%ymm0, \%ymm2, \%ymm6
    vpmuldq         \%ymm0, \%ymm3, \%ymm7
    vpmuldq         \%ymm0, \%ymm4, \%ymm8
    vpmuldq         \%ymm0, \%ymm5, \%ymm9
    vpmuldq         \%ymm1, \%ymm6, \%ymm6
    vpmuldq         \%ymm1, \%ymm7, \%ymm7
    vpmuldq         \%ymm1, \%ymm8, \%ymm8
    vpmuldq         \%ymm1, \%ymm9, \%ymm9
    vpsubq          \%ymm6, \%ymm2, \%ymm2
    vpsubq          \%ymm7, \%ymm3, \%ymm3
    vpsubq          \%ymm8, \%ymm4, \%ymm4
    vpsubq          \%ymm9, \%ymm5, \%ymm5
    vpsrlq          \$32, \%ymm2, \%ymm2
    vpsrlq          \$32, \%ymm4, \%ymm4
    vpblendd        \$0xAA, \%ymm3, \%ymm2, \%ymm2
    vpblendd        \$0xAA, \%ymm5, \%ymm4, \%ymm4
    vmovdqu         \%ymm2, (\%rdi)
    vmovdqu         \%ymm4, 32(\%rdi)
___
}

sub emit_normalize {
    my ($sym) = @_;
    return <<___;
    sub             \$1024, \%rdi
    vpbroadcastd    ml_dsa_pw_q(\%rip), \%ymm0
    xor             \%eax, \%eax
.L${sym}_norm:
    vmovdqu         (\%rdi,\%rax), \%ymm1
    vpsrad          \$31, \%ymm1, \%ymm2
    vpand           \%ymm0, \%ymm2, \%ymm2
    vpaddd          \%ymm2, \%ymm1, \%ymm1
    vpsubd          \%ymm0, \%ymm1, \%ymm2
    vpsrad          \$31, \%ymm2, \%ymm3
    vpandn          \%ymm0, \%ymm3, \%ymm3
    vpsubd          \%ymm3, \%ymm1, \%ymm1
    vmovdqu         \%ymm1, (\%rdi,\%rax)
    add             \$32, \%eax
    cmp             \$1024, \%eax
    jb              .L${sym}_norm
___
}

sub emit_pointwise_acc {
    my ($L, $suffix) = @_;
    my $sym = "ml_dsa_pointwise_acc_avx_l$suffix";
    my $body = '';

    $body .= emit_pointwise(0);
    $body .= <<___;
    vmovdqa         \%ymm6, \%ymm2
    vmovdqa         \%ymm7, \%ymm3
    vmovdqa         \%ymm8, \%ymm4
    vmovdqa         \%ymm9, \%ymm5
___

    for (my $j = 1; $j < $L; $j++) {
        my $off = $j * $poly_bytes;
        $body .= emit_pointwise($off);
        $body .= emit_acc();
    }

    $body .= emit_reduce_store();

    my $norm = emit_normalize($sym);

    return <<___;
.globl  $sym
.type   $sym,\@function,3
.align  32
$sym:
.cfi_startproc
    vpbroadcastd    ml_dsa_pw_qinv(\%rip), \%ymm0
    vpbroadcastd    ml_dsa_pw_q(\%rip), \%ymm1
    xor             \%eax, \%eax
.L${sym}_loop:
$body
    add             \$64, \%rsi
    add             \$64, \%rdx
    add             \$64, \%rdi
    add             \$1, \%eax
    cmp             \$16, \%eax
    jb              .L${sym}_loop
$norm
    vzeroupper
    ret
.cfi_endproc
.size   $sym, .-$sym
___
}

my $code = "";

if ($avx2>0) {{{
$code .= <<___;
.text

___
$code .= emit_pointwise_acc(4, 4);
$code .= emit_pointwise_acc(5, 5);
$code .= emit_pointwise_acc(7, 7);
$code .= <<___;
.section .rodata
.align 4
ml_dsa_pw_qinv:
    .long $ML_DSA_Q_INV
.align 4
ml_dsa_pw_q:
    .long $ML_DSA_Q
___

}}} else {{{
$code .= <<___;
.text
.globl  ml_dsa_pointwise_acc_avx_l4
.globl  ml_dsa_pointwise_acc_avx_l5
.globl  ml_dsa_pointwise_acc_avx_l7
.type   ml_dsa_pointwise_acc_avx_l4,\@abi-omnipotent
ml_dsa_pointwise_acc_avx_l4:
ml_dsa_pointwise_acc_avx_l5:
ml_dsa_pointwise_acc_avx_l7:
    .byte   0x0f,0x0b
    ret
.size   ml_dsa_pointwise_acc_avx_l4, .-ml_dsa_pointwise_acc_avx_l4
___
}}}

print $code;
close STDOUT or die "error closing STDOUT: $!";
