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
# ML-DSA AVX2 polynomial add / sub / max
#
# Implemented:
#   ossl_ml_dsa_poly_add_avx2
#   ossl_ml_dsa_poly_sub_avx2
#   ossl_ml_dsa_poly_max_avx2
#   ossl_ml_dsa_poly_max_signed_avx2
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

my $ML_DSA_Q = 8380417;
my $ML_DSA_Q_HALF = ($ML_DSA_Q - 1) / 2;
my $poly_bytes = 256 * 4;

# reduce_once: if acc >= q then acc -= q (acc assumed < 2*q)
sub reduce_once_ymm {
    my ($acc, $q, $tmp) = @_;
    return <<___;
    vpcmpgtd $acc, $q, $tmp
    vpandn  $q, $tmp, $tmp
    vpsubd  $tmp, $acc, $acc
___
}

# dst = reduce_once(q + a - b); clobbers tmp0
sub mod_sub_ymm {
    my ($a, $b, $dst, $q, $tmp0) = @_;
    my $body = <<___;
    vpsubd  $b, $a, $dst
    vpaddd  $dst, $q, $dst
___
    return $body . reduce_once_ymm($dst, $q, $tmp0);
}

sub emit_poly_add {
    my $red = reduce_once_ymm("%ymm0", "%ymm15", "%ymm2");
    my $head = <<___;
.globl  ossl_ml_dsa_poly_add_avx2
.type   ossl_ml_dsa_poly_add_avx2,\@function,3
.align 32
ossl_ml_dsa_poly_add_avx2:
.cfi_startproc
    vpbroadcastd    ml_dsa_arith_q(\%rip), %ymm15
    xor             \%r10d, \%r10d
.Lpoly_add_loop:
    vmovdqu         (\%rdi,\%r10), %ymm0
    vmovdqu         (\%rsi,\%r10), %ymm1
    vpaddd          %ymm1, %ymm0, %ymm0
___
    my $tail = <<___;
    vmovdqu         %ymm0, (\%rdx,\%r10)
    add             \$32, \%r10d
    cmp             \$$poly_bytes, \%r10d
    jb              .Lpoly_add_loop
    vzeroupper
    ret
.cfi_endproc
.size   ossl_ml_dsa_poly_add_avx2, .-ossl_ml_dsa_poly_add_avx2
___
    return $head . $red . $tail;
}

sub emit_poly_sub {
    my $ms = mod_sub_ymm("%ymm0", "%ymm1", "%ymm0", "%ymm15", "%ymm2");
    my $head = <<___;
.globl  ossl_ml_dsa_poly_sub_avx2
.type   ossl_ml_dsa_poly_sub_avx2,\@function,3
.align 32
ossl_ml_dsa_poly_sub_avx2:
.cfi_startproc
    vpbroadcastd    ml_dsa_arith_q(\%rip), %ymm15
    xor             \%r10d, \%r10d
.Lpoly_sub_loop:
    vmovdqu         (\%rdi,\%r10), %ymm0
    vmovdqu         (\%rsi,\%r10), %ymm1
___
    my $tail = <<___;
    vmovdqu         %ymm0, (\%rdx,\%r10)
    add             \$32, \%r10d
    cmp             \$$poly_bytes, \%r10d
    jb              .Lpoly_sub_loop
    vzeroupper
    ret
.cfi_endproc
.size   ossl_ml_dsa_poly_sub_avx2, .-ossl_ml_dsa_poly_sub_avx2
___
    return $head . $ms . $tail;
}

# Horizontal unsigned max of 8 lanes vs *mx (rsi); %rsp must be 32-byte aligned.
sub emit_horiz_max_epu32 {
    return <<___;
    vmovdqa         %ymm7, (\%rsp)
    mov             (\%rsi), \%ecx
    mov             (\%rsp), \%eax
    cmp             \%eax, \%ecx
    cmovb           \%eax, \%ecx
    mov             4(\%rsp), \%eax
    cmp             \%eax, \%ecx
    cmovb           \%eax, \%ecx
    mov             8(\%rsp), \%eax
    cmp             \%eax, \%ecx
    cmovb           \%eax, \%ecx
    mov             12(\%rsp), \%eax
    cmp             \%eax, \%ecx
    cmovb           \%eax, \%ecx
    mov             16(\%rsp), \%eax
    cmp             \%eax, \%ecx
    cmovb           \%eax, \%ecx
    mov             20(\%rsp), \%eax
    cmp             \%eax, \%ecx
    cmovb           \%eax, \%ecx
    mov             24(\%rsp), \%eax
    cmp             \%eax, \%ecx
    cmovb           \%eax, \%ecx
    mov             28(\%rsp), \%eax
    cmp             \%eax, \%ecx
    cmovb           \%eax, \%ecx
    mov             \%ecx, (\%rsi)
___
}

sub emit_poly_max_prologue {
    return <<___;
    push            \%rbp
    .cfi_offset     \%rbp,-16
    mov             \%rsp, \%rbp
    .cfi_def_cfa_register \%rbp
    sub             \$64, \%rsp
    and             \$-32, \%rsp
___
}

sub emit_poly_max_epilogue {
    return <<___;
    mov             \%rbp, \%rsp
    pop             \%rbp
    .cfi_def_cfa_register \%rsp
    vzeroupper
    ret
___
}

sub emit_poly_max {
    my $tail = emit_horiz_max_epu32();
    my $head = <<___;
.globl  ossl_ml_dsa_poly_max_avx2
.type   ossl_ml_dsa_poly_max_avx2,\@function,2
.align 32
ossl_ml_dsa_poly_max_avx2:
.cfi_startproc
___
    $head .= emit_poly_max_prologue();
    $head .= <<___;
    vpbroadcastd    ml_dsa_arith_q(\%rip), %ymm15
    vpbroadcastd    ml_dsa_arith_half(\%rip), %ymm14
    vpxor           %ymm7, %ymm7, %ymm7
    xor             \%r10d, \%r10d
.Lpoly_max_loop:
    vmovdqu         (\%rdi,\%r10), %ymm0
    vpcmpgtd        %ymm14, %ymm0, %ymm1
    vpsubd          %ymm0, %ymm15, %ymm2
    vpand           %ymm1, %ymm2, %ymm3
    vpandn          %ymm0, %ymm1, %ymm4
    vpor            %ymm3, %ymm4, %ymm0
    vpmaxud         %ymm0, %ymm7, %ymm7
    add             \$32, \%r10d
    cmp             \$$poly_bytes, \%r10d
    jb              .Lpoly_max_loop
___
    my $foot = emit_poly_max_epilogue() . <<___;
.cfi_endproc
.size   ossl_ml_dsa_poly_max_avx2, .-ossl_ml_dsa_poly_max_avx2
___
    return $head . $tail . $foot;
}

sub emit_poly_max_signed {
    my $tail = emit_horiz_max_epu32();
    my $head = <<___;
.globl  ossl_ml_dsa_poly_max_signed_avx2
.type   ossl_ml_dsa_poly_max_signed_avx2,\@function,2
.align 32
ossl_ml_dsa_poly_max_signed_avx2:
.cfi_startproc
___
    $head .= emit_poly_max_prologue();
    $head .= <<___;
    vpxor           %ymm8, %ymm8, %ymm8
    vpxor           %ymm7, %ymm7, %ymm7
    xor             \%r10d, \%r10d
.Lpoly_max_s_loop:
    vmovdqu         (\%rdi,\%r10), %ymm0
    vpsrad          \$31, %ymm0, %ymm1
    vpsubd          %ymm0, %ymm8, %ymm2
    vpand           %ymm1, %ymm2, %ymm3
    vpandn          %ymm0, %ymm1, %ymm4
    vpor            %ymm3, %ymm4, %ymm0
    vpmaxud         %ymm0, %ymm7, %ymm7
    add             \$32, \%r10d
    cmp             \$$poly_bytes, \%r10d
    jb              .Lpoly_max_s_loop
___
    my $foot = emit_poly_max_epilogue() . <<___;
.cfi_endproc
.size   ossl_ml_dsa_poly_max_signed_avx2, .-ossl_ml_dsa_poly_max_signed_avx2
___
    return $head . $tail . $foot;
}

my $code = "";

if ($avx2>0) {{{
$code .= <<___;
.text

___
$code .= emit_poly_add();
$code .= emit_poly_sub();
$code .= emit_poly_max();
$code .= emit_poly_max_signed();
$code .= <<___;
.section .rodata
.align 4
ml_dsa_arith_q:
    .long $ML_DSA_Q
.align 4
ml_dsa_arith_half:
    .long $ML_DSA_Q_HALF
___

}}} else {{{
$code .= <<___;
.text
.globl  ossl_ml_dsa_poly_add_avx2
.globl  ossl_ml_dsa_poly_sub_avx2
.globl  ossl_ml_dsa_poly_max_avx2
.globl  ossl_ml_dsa_poly_max_signed_avx2
.type   ossl_ml_dsa_poly_add_avx2,\@abi-omnipotent
ossl_ml_dsa_poly_add_avx2:
ossl_ml_dsa_poly_sub_avx2:
ossl_ml_dsa_poly_max_avx2:
ossl_ml_dsa_poly_max_signed_avx2:
    .byte   0x0f,0x0b
    ret
.size   ossl_ml_dsa_poly_add_avx2, .-ossl_ml_dsa_poly_add_avx2
___
}}}

print $code;
close STDOUT or die "error closing STDOUT: $!";
