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
# ML-DSA AVX2 SO-domain NTT / INTT and coefficient shuffle
#
# Implemented:
#   ml_dsa_avx_ntt_forward_so_impl
#   ml_dsa_avx_ntt_inverse_so_impl
#   ossl_ml_dsa_avx_poly_shuffle
###############################################################################

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64 = 0;
$win64 = 1 if (defined($flavour) && $flavour =~ /[nm]asm|mingw64/)
          || (defined($output) && $output =~ /\.asm$/);

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
  && (defined($flavour) && $flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/)
  && `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)(?:\.([0-9]+))?/)
{
  $avx2 = ($1 >= 2.10);
}

if (!$avx2 && `$cc -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
    $avx2 = ($2>=3.3);
}

die "output path required\n" unless defined $output;

if ($avx2>0) {{{
    open my $out, '>', $output or die "can't write $output: $!";
    while (<DATA>) {
        print $out $_;
    }
    close $out or die "can't close $output: $!";
}}} else {{{
    my $code = <<___;
.text

.globl  ml_dsa_avx_ntt_forward_so_impl
.globl  ml_dsa_avx_ntt_inverse_so_impl
.globl  ossl_ml_dsa_avx_poly_shuffle
.type   ml_dsa_avx_ntt_forward_so_impl,\@abi-omnipotent
.align 32
ml_dsa_avx_ntt_forward_so_impl:
ml_dsa_avx_ntt_inverse_so_impl:
ossl_ml_dsa_avx_poly_shuffle:
    .byte   0x0f,0x0b       # ud2
    ret
.size   ml_dsa_avx_ntt_forward_so_impl, .-ml_dsa_avx_ntt_forward_so_impl
___

    open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
      or die "can't call $xlate: $!";
    print OUT $code;
    close OUT or die "error closing STDOUT: $!";
}}}

__DATA__
	.file	"ml_dsa_ntt_so-x86_64.s"
	.text
.text
	.p2align 4
	.globl	ml_dsa_avx_ntt_forward_so_impl
	.type	ml_dsa_avx_ntt_forward_so_impl, @function
ml_dsa_avx_ntt_forward_so_impl:
.LFB5824:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	leaq	1024(%rdi), %rdx
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	andq	$-32, %rsp
	subq	$936, %rsp
	vmovdqa	.LC0(%rip), %ymm1
	vmovdqu	512(%rdi), %ymm0
	vmovdqa	.LC1(%rip), %ymm2
	vmovdqu	544(%rdi), %ymm7
	vpmuldq	%ymm0, %ymm1, %ymm3
	vpsrlq	$32, %ymm0, %ymm9
	vmovdqu	576(%rdi), %ymm5
	vmovdqu	608(%rdi), %ymm4
	vpmuldq	%ymm9, %ymm1, %ymm6
	vpmuldq	%ymm0, %ymm2, %ymm8
	vmovdqa	.LC2(%rip), %ymm0
	vpmuldq	%ymm9, %ymm2, %ymm9
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm8, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm6, %ymm6
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm6, %ymm3, %ymm3
	vmovdqu	(%rdi), %ymm6
	vpaddd	(%rdi), %ymm3, %ymm8
	vpsubd	%ymm3, %ymm6, %ymm11
	vmovdqa	%ymm8, -120(%rsp)
	vpmuldq	%ymm7, %ymm1, %ymm3
	vmovdqa	%ymm11, 488(%rsp)
	vpsrlq	$32, %ymm7, %ymm8
	vpmuldq	%ymm7, %ymm2, %ymm7
	vpmuldq	%ymm8, %ymm1, %ymm6
	vpmuldq	%ymm8, %ymm2, %ymm8
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm7, %ymm3, %ymm3
	vmovdqu	32(%rdi), %ymm7
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm8, %ymm6, %ymm6
	vpsrlq	$32, %ymm5, %ymm8
	vpblendd	$170, %ymm6, %ymm3, %ymm3
	vpmuldq	%ymm8, %ymm1, %ymm6
	vpaddd	32(%rdi), %ymm3, %ymm12
	vpsubd	%ymm3, %ymm7, %ymm7
	vpmuldq	%ymm5, %ymm1, %ymm3
	vmovdqa	%ymm7, 520(%rsp)
	vpmuldq	%ymm5, %ymm2, %ymm7
	vpmuldq	%ymm8, %ymm2, %ymm8
	vmovdqa	%ymm12, -88(%rsp)
	vpmuldq	%ymm0, %ymm6, %ymm5
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm8, %ymm5, %ymm5
	vpsubd	%ymm7, %ymm3, %ymm3
	vpmuldq	%ymm4, %ymm2, %ymm7
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm5, %ymm3, %ymm3
	vmovdqu	64(%rdi), %ymm5
	vpaddd	64(%rdi), %ymm3, %ymm6
	vpsubd	%ymm3, %ymm5, %ymm9
	vmovdqa	%ymm6, -56(%rsp)
	vpmuldq	%ymm4, %ymm1, %ymm3
	vmovdqa	%ymm9, 552(%rsp)
	vpsrlq	$32, %ymm4, %ymm6
	vmovdqu	736(%rdi), %ymm9
	vpmuldq	%ymm6, %ymm1, %ymm5
	vpmuldq	%ymm6, %ymm2, %ymm6
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm5, %ymm4
	vpsubd	%ymm7, %ymm3, %ymm3
	vmovdqu	640(%rdi), %ymm7
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm6, %ymm4, %ymm4
	vpsrlq	$32, %ymm7, %ymm8
	vmovdqu	672(%rdi), %ymm6
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vmovdqu	96(%rdi), %ymm4
	vpaddd	96(%rdi), %ymm3, %ymm5
	vpsubd	%ymm3, %ymm4, %ymm4
	vpmuldq	%ymm7, %ymm1, %ymm3
	vmovdqa	%ymm5, -24(%rsp)
	vmovdqu	704(%rdi), %ymm5
	vmovdqa	%ymm4, 584(%rsp)
	vpmuldq	%ymm8, %ymm1, %ymm4
	vpmuldq	%ymm7, %ymm2, %ymm7
	vpmuldq	%ymm8, %ymm2, %ymm8
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm7, %ymm3, %ymm3
	vpsrlq	$32, %ymm6, %ymm7
	vpsubd	%ymm8, %ymm4, %ymm4
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vpaddd	128(%rdi), %ymm3, %ymm15
	vpmuldq	%ymm6, %ymm1, %ymm4
	vpmuldq	%ymm6, %ymm2, %ymm6
	vmovdqa	%ymm15, 8(%rsp)
	vmovdqu	128(%rdi), %ymm14
	vmovdqu	160(%rdi), %ymm13
	vmovdqu	256(%rdi), %ymm15
	vmovdqu	832(%rdi), %ymm8
	vpsubd	%ymm3, %ymm14, %ymm3
	vmovdqa	%ymm3, 616(%rsp)
	vpmuldq	%ymm7, %ymm1, %ymm3
	vpmuldq	%ymm7, %ymm2, %ymm7
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm6, %ymm4, %ymm4
	vpsrlq	$32, %ymm5, %ymm6
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm7, %ymm3, %ymm3
	vmovdqu	192(%rdi), %ymm7
	vpblendd	$170, %ymm3, %ymm4, %ymm3
	vpaddd	160(%rdi), %ymm3, %ymm14
	vpsubd	%ymm3, %ymm13, %ymm10
	vpmuldq	%ymm5, %ymm1, %ymm3
	vpmuldq	%ymm6, %ymm1, %ymm4
	vpmuldq	%ymm5, %ymm2, %ymm5
	vmovdqa	%ymm10, 648(%rsp)
	vpmuldq	%ymm6, %ymm2, %ymm6
	vmovdqa	%ymm14, 40(%rsp)
	vmovdqu	864(%rdi), %ymm14
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm9, %ymm5
	vpsubd	%ymm6, %ymm4, %ymm4
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vpaddd	192(%rdi), %ymm3, %ymm13
	vpmuldq	%ymm5, %ymm1, %ymm4
	vpmuldq	%ymm9, %ymm2, %ymm6
	vpsubd	%ymm3, %ymm7, %ymm7
	vpmuldq	%ymm9, %ymm1, %ymm3
	vpmuldq	%ymm5, %ymm2, %ymm5
	vmovdqa	%ymm7, 680(%rsp)
	vmovdqa	%ymm13, 72(%rsp)
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm5, %ymm4, %ymm4
	vmovdqu	800(%rdi), %ymm5
	vpsubd	%ymm6, %ymm3, %ymm3
	vmovdqu	224(%rdi), %ymm6
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vpaddd	224(%rdi), %ymm3, %ymm4
	vpsubd	%ymm3, %ymm6, %ymm6
	vmovdqa	%ymm6, 712(%rsp)
	vmovdqu	768(%rdi), %ymm6
	vmovdqa	%ymm4, 104(%rsp)
	vpsrlq	$32, %ymm6, %ymm7
	vpmuldq	%ymm6, %ymm1, %ymm4
	vpmuldq	%ymm7, %ymm1, %ymm3
	vpmuldq	%ymm6, %ymm2, %ymm6
	vpmuldq	%ymm7, %ymm2, %ymm7
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm6, %ymm4, %ymm4
	vpsrlq	$32, %ymm5, %ymm6
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm7, %ymm3, %ymm3
	vpblendd	$170, %ymm3, %ymm4, %ymm3
	vpmuldq	%ymm5, %ymm1, %ymm4
	vpaddd	256(%rdi), %ymm3, %ymm13
	vpsubd	%ymm3, %ymm15, %ymm11
	vpmuldq	%ymm6, %ymm1, %ymm3
	vpmuldq	%ymm5, %ymm2, %ymm5
	vpmuldq	%ymm6, %ymm2, %ymm6
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm5, %ymm4, %ymm4
	vmovdqu	288(%rdi), %ymm5
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm3, %ymm3
	vpblendd	$170, %ymm3, %ymm4, %ymm3
	vpmuldq	%ymm8, %ymm1, %ymm4
	vpaddd	288(%rdi), %ymm3, %ymm12
	vpsubd	%ymm3, %ymm5, %ymm10
	vpsrlq	$32, %ymm8, %ymm5
	vpmuldq	%ymm5, %ymm1, %ymm3
	vpmuldq	%ymm8, %ymm2, %ymm6
	vpmuldq	%ymm5, %ymm2, %ymm5
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm6, %ymm4, %ymm4
	vpmuldq	%ymm14, %ymm2, %ymm6
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm5, %ymm3, %ymm3
	vmovdqu	320(%rdi), %ymm5
	vpblendd	$170, %ymm3, %ymm4, %ymm3
	vpmuldq	%ymm14, %ymm1, %ymm4
	vpaddd	320(%rdi), %ymm3, %ymm15
	vpsubd	%ymm3, %ymm5, %ymm9
	vpsrlq	$32, %ymm14, %ymm5
	vmovdqu	928(%rdi), %ymm14
	vmovdqa	%ymm15, 744(%rsp)
	vpmuldq	%ymm5, %ymm1, %ymm3
	vpmuldq	%ymm5, %ymm2, %ymm5
	vmovdqu	960(%rdi), %ymm15
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm6, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm5, %ymm3, %ymm3
	vmovdqu	352(%rdi), %ymm5
	vpblendd	$170, %ymm3, %ymm4, %ymm3
	vpaddd	352(%rdi), %ymm3, %ymm7
	vpsubd	%ymm3, %ymm5, %ymm8
	vmovdqu	896(%rdi), %ymm5
	vmovdqa	%ymm7, 776(%rsp)
	vpmuldq	%ymm5, %ymm1, %ymm4
	vpsrlq	$32, %ymm5, %ymm6
	vpmuldq	%ymm6, %ymm1, %ymm3
	vpmuldq	%ymm5, %ymm2, %ymm5
	vpmuldq	%ymm6, %ymm2, %ymm6
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm5, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm3, %ymm3
	vpblendd	$170, %ymm3, %ymm4, %ymm3
	vpaddd	384(%rdi), %ymm3, %ymm6
	vpmuldq	%ymm14, %ymm1, %ymm4
	vmovdqa	%ymm6, 808(%rsp)
	vpmuldq	%ymm14, %ymm2, %ymm6
	vmovdqu	384(%rdi), %ymm5
	vpsubd	%ymm3, %ymm5, %ymm7
	vpsrlq	$32, %ymm14, %ymm5
	vpmuldq	%ymm5, %ymm1, %ymm3
	vpmuldq	%ymm5, %ymm2, %ymm5
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm15, %ymm2, %ymm14
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm6, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm5, %ymm3, %ymm3
	vpblendd	$170, %ymm3, %ymm4, %ymm3
	vpaddd	416(%rdi), %ymm3, %ymm5
	vmovdqa	%ymm5, 840(%rsp)
	vmovdqu	416(%rdi), %ymm5
	vpsubd	%ymm3, %ymm5, %ymm6
	vpmuldq	%ymm15, %ymm1, %ymm3
	vpsrlq	$32, %ymm15, %ymm5
	vpsrlq	$32, %ymm11, %ymm15
	vpmuldq	%ymm5, %ymm1, %ymm4
	vpmuldq	%ymm5, %ymm2, %ymm5
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm14, %ymm3, %ymm3
	vpmuldq	992(%rdi), %ymm2, %ymm14
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm5, %ymm4, %ymm4
	vmovdqu	448(%rdi), %ymm5
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vpaddd	448(%rdi), %ymm3, %ymm4
	vpsubd	%ymm3, %ymm5, %ymm5
	vpmuldq	992(%rdi), %ymm1, %ymm3
	vpmuldq	%ymm0, %ymm3, %ymm3
	vmovdqa	%ymm4, 872(%rsp)
	vmovdqu	992(%rdi), %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpmuldq	%ymm4, %ymm1, %ymm1
	vpmuldq	%ymm4, %ymm2, %ymm4
	vpsubd	%ymm14, %ymm3, %ymm3
	vpsrlq	$32, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm3, %ymm3
	vmovdqu	480(%rdi), %ymm1
	vpaddd	480(%rdi), %ymm3, %ymm2
	vmovdqa	%ymm2, 904(%rsp)
	vpsubd	%ymm3, %ymm1, %ymm4
	vmovdqa	.LC3(%rip), %ymm1
	vmovdqa	.LC4(%rip), %ymm2
	vpmuldq	%ymm11, %ymm1, %ymm3
	vpmuldq	%ymm15, %ymm1, %ymm14
	vpmuldq	%ymm11, %ymm2, %ymm11
	vpmuldq	%ymm15, %ymm2, %ymm15
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm14, %ymm14
	vpsubd	%ymm11, %ymm3, %ymm3
	vpsubd	%ymm15, %ymm14, %ymm14
	vmovdqa	488(%rsp), %ymm11
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm14, %ymm3, %ymm3
	vpaddd	%ymm11, %ymm3, %ymm14
	vpsubd	%ymm3, %ymm11, %ymm3
	vmovdqa	%ymm14, 136(%rsp)
	vpsrlq	$32, %ymm10, %ymm14
	vmovdqa	%ymm3, 168(%rsp)
	vpmuldq	%ymm10, %ymm1, %ymm3
	vpmuldq	%ymm14, %ymm1, %ymm11
	vpmuldq	%ymm10, %ymm2, %ymm10
	vpmuldq	%ymm14, %ymm2, %ymm14
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm11, %ymm11
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsubd	%ymm14, %ymm11, %ymm11
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm11, %ymm3, %ymm3
	vmovdqa	520(%rsp), %ymm11
	vpaddd	%ymm11, %ymm3, %ymm10
	vpsubd	%ymm3, %ymm11, %ymm11
	vpmuldq	%ymm9, %ymm1, %ymm3
	vmovdqa	%ymm11, 232(%rsp)
	vpsrlq	$32, %ymm9, %ymm11
	vpmuldq	%ymm9, %ymm2, %ymm9
	vmovdqa	%ymm10, 200(%rsp)
	vpmuldq	%ymm11, %ymm1, %ymm10
	vpmuldq	%ymm11, %ymm2, %ymm11
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm9, %ymm3, %ymm3
	vmovdqa	552(%rsp), %ymm9
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm11, %ymm10, %ymm10
	vpblendd	$170, %ymm10, %ymm3, %ymm3
	vpsrlq	$32, %ymm8, %ymm10
	vpaddd	%ymm9, %ymm3, %ymm11
	vmovdqa	%ymm11, 264(%rsp)
	vpsubd	%ymm3, %ymm9, %ymm11
	vpmuldq	%ymm8, %ymm1, %ymm3
	vpmuldq	%ymm10, %ymm1, %ymm9
	vpmuldq	%ymm8, %ymm2, %ymm8
	vpmuldq	%ymm10, %ymm2, %ymm10
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpsubd	%ymm8, %ymm3, %ymm3
	vpsubd	%ymm10, %ymm9, %ymm9
	vpsrlq	$32, %ymm3, %ymm3
	vmovdqa	648(%rsp), %ymm10
	vpblendd	$170, %ymm9, %ymm3, %ymm3
	vmovdqa	584(%rsp), %ymm9
	vpaddd	%ymm9, %ymm3, %ymm8
	vpsubd	%ymm3, %ymm9, %ymm3
	vpsrlq	$32, %ymm7, %ymm9
	vmovdqa	%ymm3, 328(%rsp)
	vpmuldq	%ymm7, %ymm1, %ymm3
	vpmuldq	%ymm7, %ymm2, %ymm7
	vmovdqa	%ymm8, 296(%rsp)
	vpmuldq	%ymm9, %ymm1, %ymm8
	vpmuldq	%ymm9, %ymm2, %ymm9
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsubd	%ymm7, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm8, %ymm8
	vpsrlq	$32, %ymm3, %ymm3
	vmovdqa	616(%rsp), %ymm9
	vpblendd	$170, %ymm8, %ymm3, %ymm3
	vpsubd	%ymm3, %ymm9, %ymm7
	vpaddd	%ymm9, %ymm3, %ymm8
	vpmuldq	%ymm6, %ymm1, %ymm3
	vmovdqa	%ymm8, 360(%rsp)
	vpsrlq	$32, %ymm6, %ymm9
	vpmuldq	%ymm6, %ymm2, %ymm6
	vpmuldq	%ymm9, %ymm1, %ymm8
	vpmuldq	%ymm9, %ymm2, %ymm9
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm8, %ymm8
	vpblendd	$170, %ymm8, %ymm3, %ymm3
	vpaddd	%ymm10, %ymm3, %ymm9
	vpsubd	%ymm3, %ymm10, %ymm6
	vpmuldq	%ymm5, %ymm1, %ymm3
	vmovdqa	%ymm9, 392(%rsp)
	vpsrlq	$32, %ymm5, %ymm9
	vpmuldq	%ymm5, %ymm2, %ymm5
	vpmuldq	%ymm9, %ymm1, %ymm8
	vpmuldq	%ymm9, %ymm2, %ymm9
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsubd	%ymm5, %ymm3, %ymm3
	vpmuldq	%ymm4, %ymm1, %ymm5
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm8, %ymm8
	vmovdqa	680(%rsp), %ymm9
	vpblendd	$170, %ymm8, %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm8
	vpmuldq	%ymm8, %ymm1, %ymm1
	vpmuldq	%ymm4, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm3, %ymm10
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm8, %ymm2, %ymm8
	vpsubd	%ymm3, %ymm9, %ymm3
	vmovdqa	%ymm10, 424(%rsp)
	vmovdqa	712(%rsp), %ymm9
	vmovdqa	744(%rsp), %ymm15
	vmovdqa	808(%rsp), %ymm14
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm5, %ymm5
	vmovdqa	.LC6(%rip), %ymm4
	vpsrlq	$32, %ymm5, %ymm5
	vpmuldq	%ymm15, %ymm4, %ymm10
	vpsubd	%ymm8, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm5, %ymm2
	vpaddd	%ymm9, %ymm2, %ymm1
	vpsubd	%ymm2, %ymm9, %ymm2
	vpsrlq	$32, %ymm13, %ymm9
	vmovdqa	%ymm1, 456(%rsp)
	vmovdqa	.LC5(%rip), %ymm1
	vpmuldq	%ymm13, %ymm1, %ymm5
	vpmuldq	%ymm9, %ymm1, %ymm8
	vpmuldq	%ymm13, %ymm4, %ymm13
	vpmuldq	%ymm9, %ymm4, %ymm9
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsubd	%ymm13, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm8, %ymm8
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vmovdqa	-120(%rsp), %ymm8
	vpaddd	%ymm8, %ymm5, %ymm9
	vpsubd	%ymm5, %ymm8, %ymm5
	vmovdqa	%ymm9, 488(%rsp)
	vpsrlq	$32, %ymm12, %ymm9
	vmovdqa	%ymm5, 520(%rsp)
	vpmuldq	%ymm12, %ymm1, %ymm5
	vpmuldq	%ymm9, %ymm1, %ymm8
	vpmuldq	%ymm12, %ymm4, %ymm12
	vpmuldq	%ymm9, %ymm4, %ymm9
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm8, %ymm8
	vmovdqa	-88(%rsp), %ymm12
	vpsrlq	$32, %ymm15, %ymm9
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vpaddd	%ymm12, %ymm5, %ymm8
	vpsubd	%ymm5, %ymm12, %ymm5
	vmovdqa	-56(%rsp), %ymm12
	vmovdqa	%ymm5, 584(%rsp)
	vpmuldq	%ymm15, %ymm1, %ymm5
	vmovdqa	776(%rsp), %ymm15
	vmovdqa	%ymm8, 552(%rsp)
	vpmuldq	%ymm9, %ymm1, %ymm8
	vpmuldq	%ymm9, %ymm4, %ymm9
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsubd	%ymm10, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm8, %ymm8
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vpsrlq	$32, %ymm15, %ymm9
	vpaddd	%ymm12, %ymm5, %ymm10
	vpsubd	%ymm5, %ymm12, %ymm5
	vpmuldq	%ymm9, %ymm1, %ymm8
	vmovdqa	-24(%rsp), %ymm12
	vmovdqa	%ymm5, 648(%rsp)
	vpmuldq	%ymm15, %ymm1, %ymm5
	vpmuldq	%ymm9, %ymm4, %ymm9
	vmovdqa	%ymm10, 616(%rsp)
	vpmuldq	%ymm15, %ymm4, %ymm10
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm8, %ymm8
	vpsrlq	$32, %ymm14, %ymm9
	vpsubd	%ymm10, %ymm5, %ymm5
	vpmuldq	%ymm14, %ymm4, %ymm10
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vpmuldq	%ymm9, %ymm1, %ymm8
	vpaddd	%ymm12, %ymm5, %ymm15
	vpsubd	%ymm5, %ymm12, %ymm12
	vpmuldq	%ymm14, %ymm1, %ymm5
	vmovdqa	872(%rsp), %ymm14
	vmovdqa	%ymm15, 680(%rsp)
	vpmuldq	%ymm9, %ymm4, %ymm9
	vmovdqa	840(%rsp), %ymm15
	vmovdqa	%ymm12, 712(%rsp)
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm8, %ymm8
	vpsrlq	$32, %ymm15, %ymm9
	vpsubd	%ymm10, %ymm5, %ymm5
	vpmuldq	%ymm15, %ymm4, %ymm10
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vmovdqa	8(%rsp), %ymm8
	vpaddd	%ymm8, %ymm5, %ymm12
	vpsubd	%ymm5, %ymm8, %ymm5
	vpmuldq	%ymm9, %ymm1, %ymm8
	vmovdqa	%ymm5, 776(%rsp)
	vpmuldq	%ymm15, %ymm1, %ymm5
	vpmuldq	%ymm9, %ymm4, %ymm9
	vmovdqa	%ymm12, 744(%rsp)
	vmovdqa	40(%rsp), %ymm12
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm8, %ymm8
	vpsrlq	$32, %ymm14, %ymm9
	vpsubd	%ymm10, %ymm5, %ymm5
	vpmuldq	%ymm14, %ymm4, %ymm10
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vpmuldq	%ymm9, %ymm1, %ymm8
	vpaddd	%ymm12, %ymm5, %ymm15
	vpsubd	%ymm5, %ymm12, %ymm5
	vpmuldq	%ymm9, %ymm4, %ymm9
	vmovdqa	72(%rsp), %ymm12
	vmovdqa	%ymm5, 840(%rsp)
	vpmuldq	%ymm14, %ymm1, %ymm5
	vmovdqa	904(%rsp), %ymm14
	vmovdqa	%ymm15, 808(%rsp)
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm4, %ymm9
	vpsubd	%ymm10, %ymm5, %ymm5
	vpsrlq	$32, %ymm6, %ymm10
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vpsrlq	$32, %ymm14, %ymm8
	vpaddd	%ymm12, %ymm5, %ymm15
	vpsubd	%ymm5, %ymm12, %ymm12
	vpmuldq	%ymm14, %ymm1, %ymm5
	vmovdqa	%ymm12, 872(%rsp)
	vpmuldq	%ymm8, %ymm1, %ymm1
	vpmuldq	%ymm8, %ymm4, %ymm8
	vmovdqa	104(%rsp), %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm9, %ymm5, %ymm5
	vpsrlq	$32, %ymm7, %ymm9
	vpsubd	%ymm8, %ymm1, %ymm1
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm1, %ymm5, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm14
	vpsubd	%ymm5, %ymm4, %ymm4
	vmovdqa	%ymm4, 904(%rsp)
	vmovdqa	.LC7(%rip), %ymm1
	leaq	inte_qdata(%rip), %rax
	vmovdqa	.LC8(%rip), %ymm8
	vmovdqa	232(%rsp), %ymm12
	vpmuldq	%ymm7, %ymm1, %ymm5
	vpmuldq	%ymm9, %ymm1, %ymm4
	vpmuldq	%ymm7, %ymm8, %ymm7
	vpmuldq	%ymm9, %ymm8, %ymm9
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm7, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm4, %ymm4
	vpmuldq	%ymm10, %ymm1, %ymm7
	vmovdqa	168(%rsp), %ymm9
	vpsrlq	$32, %ymm5, %ymm5
	vpmuldq	%ymm10, %ymm8, %ymm10
	vpblendd	$170, %ymm4, %ymm5, %ymm4
	vpaddd	%ymm9, %ymm4, %ymm5
	vpsubd	%ymm4, %ymm9, %ymm4
	vpmuldq	%ymm6, %ymm1, %ymm9
	vpmuldq	%ymm6, %ymm8, %ymm6
	vpmuldq	%ymm0, %ymm7, %ymm7
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm7, %ymm7
	vpmuldq	%ymm3, %ymm1, %ymm10
	vpsubd	%ymm6, %ymm9, %ymm9
	vpsrlq	$32, %ymm9, %ymm9
	vpblendd	$170, %ymm7, %ymm9, %ymm7
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpaddd	%ymm12, %ymm7, %ymm6
	vpsubd	%ymm7, %ymm12, %ymm7
	vpsrlq	$32, %ymm3, %ymm12
	vpmuldq	%ymm12, %ymm1, %ymm9
	vpmuldq	%ymm3, %ymm8, %ymm3
	vpmuldq	%ymm12, %ymm8, %ymm12
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpsubd	%ymm3, %ymm10, %ymm10
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm12, %ymm9, %ymm9
	vpblendd	$170, %ymm9, %ymm10, %ymm3
	vpmuldq	%ymm2, %ymm1, %ymm10
	vpaddd	%ymm11, %ymm3, %ymm9
	vpsubd	%ymm3, %ymm11, %ymm3
	vpsrlq	$32, %ymm2, %ymm11
	vpmuldq	%ymm11, %ymm1, %ymm1
	vpmuldq	%ymm2, %ymm8, %ymm2
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpsrlq	$32, %ymm3, %ymm13
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm2, %ymm10, %ymm10
	vmovdqa	328(%rsp), %ymm2
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm1, %ymm1
	vmovdqa	.LC10(%rip), %ymm11
	vpblendd	$170, %ymm1, %ymm10, %ymm1
	vpaddd	%ymm2, %ymm1, %ymm8
	vpsubd	%ymm1, %ymm2, %ymm1
	vmovdqa	.LC9(%rip), %ymm2
	vpmuldq	%ymm3, %ymm2, %ymm12
	vpmuldq	%ymm13, %ymm2, %ymm10
	vpmuldq	%ymm3, %ymm11, %ymm3
	vpmuldq	%ymm13, %ymm11, %ymm13
	vpmuldq	%ymm0, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm3, %ymm12, %ymm12
	vpsubd	%ymm13, %ymm10, %ymm10
	vpsrlq	$32, %ymm9, %ymm13
	vpsrlq	$32, %ymm12, %ymm12
	vpblendd	$170, %ymm10, %ymm12, %ymm3
	vpsrlq	$32, %ymm1, %ymm12
	vpaddd	%ymm4, %ymm3, %ymm10
	vpsubd	%ymm3, %ymm4, %ymm4
	vpmuldq	%ymm1, %ymm2, %ymm3
	vpmuldq	%ymm12, %ymm2, %ymm2
	vpmuldq	%ymm1, %ymm11, %ymm1
	vpmuldq	%ymm12, %ymm11, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm1, %ymm3, %ymm3
	vmovdqa	.LC11(%rip), %ymm1
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm12, %ymm2, %ymm2
	vmovdqa	.LC12(%rip), %ymm12
	vpblendd	$170, %ymm2, %ymm3, %ymm2
	vpmuldq	%ymm13, %ymm1, %ymm3
	vpaddd	%ymm7, %ymm2, %ymm11
	vpsubd	%ymm2, %ymm7, %ymm2
	vpmuldq	%ymm9, %ymm1, %ymm7
	vpmuldq	%ymm9, %ymm12, %ymm9
	vpmuldq	%ymm13, %ymm12, %ymm13
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm7, %ymm7
	vpsubd	%ymm13, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm7, %ymm7
	vpsrlq	$32, %ymm8, %ymm9
	vpsrlq	$32, %ymm7, %ymm7
	vpblendd	$170, %ymm3, %ymm7, %ymm3
	vpaddd	%ymm5, %ymm3, %ymm7
	vpsubd	%ymm3, %ymm5, %ymm5
	vpmuldq	%ymm8, %ymm1, %ymm3
	vpmuldq	%ymm9, %ymm1, %ymm1
	vpmuldq	%ymm8, %ymm12, %ymm8
	vpmuldq	%ymm9, %ymm12, %ymm9
	vpsrlq	$32, %ymm2, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm8, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm3
	vmovdqa	.LC14(%rip), %ymm9
	vpblendd	$170, %ymm1, %ymm3, %ymm8
	vmovdqa	.LC13(%rip), %ymm3
	vpaddd	%ymm6, %ymm8, %ymm1
	vpsubd	%ymm8, %ymm6, %ymm8
	vpmuldq	%ymm2, %ymm3, %ymm6
	vpmuldq	%ymm12, %ymm3, %ymm3
	vpmuldq	%ymm2, %ymm9, %ymm2
	vpmuldq	%ymm12, %ymm9, %ymm9
	vpsrlq	$32, %ymm11, %ymm12
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm2, %ymm6, %ymm6
	vpsubd	%ymm9, %ymm3, %ymm3
	vmovdqa	.LC15(%rip), %ymm2
	vmovdqa	.LC16(%rip), %ymm9
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm3, %ymm6, %ymm3
	vpaddd	%ymm4, %ymm3, %ymm6
	vpsubd	%ymm3, %ymm4, %ymm4
	vpmuldq	%ymm11, %ymm2, %ymm3
	vpmuldq	%ymm12, %ymm2, %ymm2
	vpmuldq	%ymm11, %ymm9, %ymm11
	vpmuldq	%ymm12, %ymm9, %ymm9
	vpsrlq	$32, %ymm8, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm11, %ymm3, %ymm3
	vmovdqa	.LC18(%rip), %ymm11
	vpsubd	%ymm9, %ymm2, %ymm2
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm2, %ymm3, %ymm3
	vmovdqa	.LC17(%rip), %ymm2
	vpaddd	%ymm10, %ymm3, %ymm9
	vpsubd	%ymm3, %ymm10, %ymm3
	vpmuldq	%ymm8, %ymm2, %ymm10
	vpmuldq	%ymm12, %ymm2, %ymm2
	vpmuldq	%ymm8, %ymm11, %ymm8
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsrlq	$32, %ymm1, %ymm12
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm8, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm2, %ymm2
	vmovdqa	.LC20(%rip), %ymm11
	vpsrlq	$32, %ymm10, %ymm10
	vpblendd	$170, %ymm2, %ymm10, %ymm2
	vpaddd	%ymm5, %ymm2, %ymm8
	vpsubd	%ymm2, %ymm5, %ymm2
	vmovdqa	.LC19(%rip), %ymm5
	vpmuldq	%ymm1, %ymm5, %ymm10
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm1, %ymm11, %ymm1
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm5, %ymm5
	vmovdqu	(%rax), %ymm11
	vpsrlq	$32, %ymm10, %ymm10
	vpblendd	$170, %ymm5, %ymm10, %ymm1
	vpsrlq	$32, %ymm11, %ymm5
	vpaddd	%ymm7, %ymm1, %ymm10
	vpsubd	%ymm1, %ymm7, %ymm1
	vperm2i128	$32, %ymm6, %ymm4, %ymm7
	vperm2i128	$49, %ymm6, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm12
	vpmuldq	%ymm4, %ymm5, %ymm6
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm4, %ymm11, %ymm4
	vpmuldq	%ymm12, %ymm11, %ymm12
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm6, %ymm6
	vpsubd	%ymm12, %ymm5, %ymm5
	vmovdqu	32(%rax), %ymm12
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm5, %ymm6, %ymm5
	vperm2i128	$32, %ymm9, %ymm3, %ymm6
	vperm2i128	$49, %ymm9, %ymm3, %ymm3
	vpsrlq	$32, %ymm12, %ymm4
	vpsrlq	$32, %ymm3, %ymm9
	vpaddd	%ymm7, %ymm5, %ymm11
	vpsubd	%ymm5, %ymm7, %ymm7
	vpmuldq	%ymm3, %ymm4, %ymm5
	vpmuldq	%ymm9, %ymm4, %ymm4
	vpmuldq	%ymm3, %ymm12, %ymm3
	vpmuldq	%ymm9, %ymm12, %ymm9
	vmovdqu	64(%rax), %ymm12
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm3, %ymm5, %ymm5
	vpsrlq	$32, %ymm12, %ymm3
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm4, %ymm4
	vpblendd	$170, %ymm4, %ymm5, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm9
	vpsubd	%ymm4, %ymm6, %ymm6
	vperm2i128	$32, %ymm8, %ymm2, %ymm4
	vperm2i128	$49, %ymm8, %ymm2, %ymm2
	vpmuldq	%ymm2, %ymm3, %ymm5
	vpsrlq	$32, %ymm2, %ymm8
	vpmuldq	%ymm8, %ymm3, %ymm3
	vpmuldq	%ymm2, %ymm12, %ymm2
	vpmuldq	%ymm8, %ymm12, %ymm8
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm2, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm8, %ymm3, %ymm3
	vmovdqu	96(%rax), %ymm8
	vpblendd	$170, %ymm3, %ymm5, %ymm3
	vperm2i128	$32, %ymm10, %ymm1, %ymm5
	vperm2i128	$49, %ymm10, %ymm1, %ymm1
	vpsrlq	$32, %ymm8, %ymm2
	vpsrlq	$32, %ymm1, %ymm10
	vpaddd	%ymm4, %ymm3, %ymm12
	vpsubd	%ymm3, %ymm4, %ymm4
	vpmuldq	%ymm1, %ymm2, %ymm3
	vpmuldq	%ymm10, %ymm2, %ymm2
	vpmuldq	%ymm1, %ymm8, %ymm1
	vpmuldq	%ymm10, %ymm8, %ymm10
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsubd	%ymm10, %ymm2, %ymm2
	vmovdqu	512(%rax), %ymm10
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm2, %ymm3, %ymm2
	vpunpcklqdq	%ymm11, %ymm7, %ymm3
	vpunpckhqdq	%ymm11, %ymm7, %ymm7
	vpsrlq	$32, %ymm10, %ymm1
	vpsrlq	$32, %ymm7, %ymm11
	vpaddd	%ymm5, %ymm2, %ymm8
	vpsubd	%ymm2, %ymm5, %ymm5
	vpmuldq	%ymm7, %ymm1, %ymm2
	vpmuldq	%ymm11, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm10, %ymm7
	vpmuldq	%ymm11, %ymm10, %ymm11
	vmovdqu	544(%rax), %ymm10
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm7, %ymm2, %ymm2
	vpsrlq	$32, %ymm2, %ymm2
	vpsubd	%ymm11, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm2, %ymm1
	vpunpcklqdq	%ymm9, %ymm6, %ymm2
	vpunpckhqdq	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm3, %ymm1, %ymm7
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm10, %ymm1
	vpmuldq	%ymm6, %ymm1, %ymm9
	vpsrlq	$32, %ymm6, %ymm11
	vpmuldq	%ymm11, %ymm1, %ymm1
	vpmuldq	%ymm6, %ymm10, %ymm6
	vpmuldq	%ymm11, %ymm10, %ymm11
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm6, %ymm9, %ymm9
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm11, %ymm1, %ymm1
	vmovdqu	576(%rax), %ymm11
	vpblendd	$170, %ymm1, %ymm9, %ymm1
	vpaddd	%ymm2, %ymm1, %ymm9
	vpsrlq	$32, %ymm11, %ymm6
	vpsubd	%ymm1, %ymm2, %ymm2
	vpunpcklqdq	%ymm12, %ymm4, %ymm1
	vpunpckhqdq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm4, %ymm6, %ymm10
	vpsrlq	$32, %ymm4, %ymm12
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm4, %ymm11, %ymm4
	vpmuldq	%ymm12, %ymm11, %ymm12
	vmovdqu	608(%rax), %ymm11
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm4, %ymm10, %ymm10
	vpsubd	%ymm12, %ymm6, %ymm6
	vpsrlq	$32, %ymm10, %ymm10
	vpblendd	$170, %ymm6, %ymm10, %ymm4
	vpsrlq	$32, %ymm11, %ymm10
	vpaddd	%ymm1, %ymm4, %ymm6
	vpsubd	%ymm4, %ymm1, %ymm1
	vpunpcklqdq	%ymm8, %ymm5, %ymm4
	vpunpckhqdq	%ymm8, %ymm5, %ymm5
	vpmuldq	%ymm5, %ymm10, %ymm8
	vpsrlq	$32, %ymm5, %ymm12
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm5, %ymm11, %ymm5
	vpmuldq	%ymm12, %ymm11, %ymm12
	vmovdqu	1024(%rax), %ymm11
	vpsrlq	$32, %ymm11, %ymm11
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm5, %ymm8, %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm10, %ymm10
	vpblendd	$170, %ymm10, %ymm8, %ymm10
	vpsllq	$32, %ymm7, %ymm8
	vpaddd	%ymm4, %ymm10, %ymm5
	vpblendd	$170, %ymm8, %ymm3, %ymm8
	vpsubd	%ymm10, %ymm4, %ymm4
	vmovdqu	1536(%rax), %ymm10
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm7, %ymm7
	vpsrlq	$32, %ymm10, %ymm10
	vpmuldq	1536(%rax), %ymm3, %ymm3
	vpsrlq	$32, %ymm7, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	1024(%rax), %ymm7, %ymm7
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsubd	%ymm7, %ymm3, %ymm3
	vpsllq	$32, %ymm9, %ymm7
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm7, %ymm2, %ymm7
	vpsrlq	$32, %ymm2, %ymm2
	vpblendd	$85, %ymm2, %ymm9, %ymm9
	vpmuldq	1568(%rax), %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsrlq	$32, %ymm9, %ymm12
	vpsubd	%ymm11, %ymm10, %ymm10
	vpblendd	$170, %ymm10, %ymm3, %ymm3
	vmovdqu	1568(%rax), %ymm10
	vpmuldq	1056(%rax), %ymm9, %ymm9
	vmovdqu	1056(%rax), %ymm11
	vmovdqa	392(%rsp), %ymm13
	vpsubd	%ymm9, %ymm2, %ymm2
	vpsllq	$32, %ymm6, %ymm9
	vpsrlq	$32, %ymm10, %ymm10
	vpsrlq	$32, %ymm11, %ymm11
	vpblendd	$170, %ymm9, %ymm1, %ymm9
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsrlq	$32, %ymm2, %ymm2
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$85, %ymm1, %ymm6, %ymm6
	vpmuldq	1600(%rax), %ymm1, %ymm1
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsrlq	$32, %ymm6, %ymm12
	vpmuldq	1088(%rax), %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm6, %ymm1, %ymm1
	vpsllq	$32, %ymm5, %ymm6
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm6, %ymm4, %ymm6
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm11, %ymm10, %ymm10
	vmovdqu	1088(%rax), %ymm11
	vpblendd	$170, %ymm10, %ymm2, %ymm2
	vmovdqu	1600(%rax), %ymm10
	vpsrlq	$32, %ymm11, %ymm11
	vpsrlq	$32, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm10, %ymm10
	vpblendd	$85, %ymm4, %ymm5, %ymm11
	vpmuldq	1632(%rax), %ymm4, %ymm4
	vpsrlq	$32, %ymm11, %ymm12
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendd	$170, %ymm10, %ymm1, %ymm1
	vmovdqu	1632(%rax), %ymm10
	vpmuldq	1120(%rax), %ymm11, %ymm11
	vpsrlq	$32, %ymm10, %ymm5
	vmovdqu	1120(%rax), %ymm10
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpsrlq	$32, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm4, %ymm4
	vmovdqa	.LC24(%rip), %ymm12
	vpsrlq	$32, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm4, %ymm5
	vpsubd	%ymm3, %ymm8, %ymm4
	vpaddd	%ymm3, %ymm8, %ymm8
	vpsubd	%ymm2, %ymm7, %ymm3
	vpaddd	%ymm2, %ymm7, %ymm7
	vmovdqu	%ymm4, (%rdi)
	vpsubd	%ymm1, %ymm9, %ymm2
	vpaddd	%ymm1, %ymm9, %ymm9
	vmovdqu	%ymm7, 96(%rdi)
	vmovdqa	360(%rsp), %ymm7
	vpsubd	%ymm5, %ymm6, %ymm1
	vmovdqu	%ymm3, 64(%rdi)
	vpaddd	%ymm5, %ymm6, %ymm6
	vmovdqa	.LC22(%rip), %ymm5
	vmovdqu	%ymm1, 192(%rdi)
	vmovdqa	.LC21(%rip), %ymm1
	vpsrlq	$32, %ymm7, %ymm4
	vmovdqu	%ymm2, 128(%rdi)
	vpmuldq	%ymm7, %ymm1, %ymm3
	vpmuldq	%ymm4, %ymm1, %ymm2
	vmovdqu	%ymm6, 224(%rdi)
	vpmuldq	%ymm7, %ymm5, %ymm6
	vpmuldq	%ymm4, %ymm5, %ymm4
	vmovdqu	%ymm8, 32(%rdi)
	vpmuldq	%ymm13, %ymm5, %ymm8
	vmovdqu	%ymm9, 160(%rdi)
	vmovdqa	200(%rsp), %ymm9
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsubd	%ymm4, %ymm2, %ymm2
	vpsrlq	$32, %ymm13, %ymm6
	vpsrlq	$32, %ymm3, %ymm3
	vpmuldq	%ymm13, %ymm1, %ymm4
	vmovdqa	424(%rsp), %ymm13
	vpblendd	$170, %ymm2, %ymm3, %ymm3
	vmovdqa	136(%rsp), %ymm2
	vpmuldq	%ymm13, %ymm5, %ymm10
	vpaddd	%ymm2, %ymm3, %ymm7
	vpsubd	%ymm3, %ymm2, %ymm3
	vpmuldq	%ymm6, %ymm1, %ymm2
	vpmuldq	%ymm6, %ymm5, %ymm6
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm8, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm2, %ymm2
	vpmuldq	%ymm13, %ymm1, %ymm6
	vpblendd	$170, %ymm2, %ymm4, %ymm2
	vpaddd	%ymm9, %ymm2, %ymm8
	vpsubd	%ymm2, %ymm9, %ymm2
	vpsrlq	$32, %ymm13, %ymm9
	vmovdqa	456(%rsp), %ymm13
	vpmuldq	%ymm9, %ymm1, %ymm4
	vpmuldq	%ymm9, %ymm5, %ymm9
	vpmuldq	%ymm13, %ymm5, %ymm11
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm10, %ymm6, %ymm6
	vmovdqa	264(%rsp), %ymm10
	vpsrlq	$32, %ymm6, %ymm6
	vpsubd	%ymm9, %ymm4, %ymm4
	vpblendd	$170, %ymm4, %ymm6, %ymm4
	vpmuldq	%ymm13, %ymm1, %ymm6
	vpaddd	%ymm10, %ymm4, %ymm9
	vpsubd	%ymm4, %ymm10, %ymm4
	vpsrlq	$32, %ymm13, %ymm10
	vpmuldq	%ymm10, %ymm1, %ymm1
	vpmuldq	%ymm10, %ymm5, %ymm10
	vmovdqa	.LC23(%rip), %ymm5
	vpsrlq	$32, %ymm4, %ymm13
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm11, %ymm6, %ymm6
	vpmuldq	%ymm4, %ymm5, %ymm11
	vpsrlq	$32, %ymm6, %ymm6
	vpmuldq	%ymm4, %ymm12, %ymm4
	vpsubd	%ymm10, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm6, %ymm1
	vmovdqa	296(%rsp), %ymm6
	vpaddd	%ymm6, %ymm1, %ymm10
	vpsubd	%ymm1, %ymm6, %ymm1
	vpmuldq	%ymm13, %ymm5, %ymm6
	vpmuldq	%ymm0, %ymm11, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm13
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm4, %ymm11, %ymm11
	vpmuldq	%ymm1, %ymm5, %ymm4
	vpsrlq	$32, %ymm11, %ymm11
	vpsubd	%ymm13, %ymm6, %ymm6
	vpsrlq	$32, %ymm9, %ymm13
	vpblendd	$170, %ymm6, %ymm11, %ymm6
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpaddd	%ymm3, %ymm6, %ymm11
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm6
	vpmuldq	%ymm6, %ymm5, %ymm5
	vpmuldq	%ymm1, %ymm12, %ymm1
	vpmuldq	%ymm6, %ymm12, %ymm6
	vmovdqa	.LC26(%rip), %ymm12
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm4, %ymm4
	vmovdqa	.LC25(%rip), %ymm1
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm4, %ymm5
	vpmuldq	%ymm13, %ymm1, %ymm4
	vpaddd	%ymm2, %ymm5, %ymm6
	vpsubd	%ymm5, %ymm2, %ymm2
	vpmuldq	%ymm9, %ymm1, %ymm5
	vpmuldq	%ymm9, %ymm12, %ymm9
	vpmuldq	%ymm13, %ymm12, %ymm13
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm13, %ymm4, %ymm4
	vpsubd	%ymm9, %ymm5, %ymm5
	vpsrlq	$32, %ymm10, %ymm9
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm4, %ymm5, %ymm4
	vpaddd	%ymm7, %ymm4, %ymm5
	vpsubd	%ymm4, %ymm7, %ymm7
	vpmuldq	%ymm10, %ymm1, %ymm4
	vpmuldq	%ymm9, %ymm1, %ymm1
	vpmuldq	%ymm10, %ymm12, %ymm10
	vpmuldq	%ymm9, %ymm12, %ymm9
	vpsrlq	$32, %ymm2, %ymm12
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm10, %ymm4, %ymm4
	vpsubd	%ymm9, %ymm1, %ymm1
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$170, %ymm1, %ymm4, %ymm4
	vpaddd	%ymm8, %ymm4, %ymm1
	vpsubd	%ymm4, %ymm8, %ymm8
	vmovdqa	.LC27(%rip), %ymm4
	vmovdqa	.LC28(%rip), %ymm10
	vmovdqu	1152(%rax), %ymm13
	vpmuldq	%ymm2, %ymm4, %ymm9
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm2, %ymm10, %ymm2
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsrlq	$32, %ymm6, %ymm12
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm2, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm4, %ymm4
	vmovdqa	.LC29(%rip), %ymm2
	vmovdqa	.LC30(%rip), %ymm10
	vpsrlq	$32, %ymm9, %ymm9
	vpblendd	$170, %ymm4, %ymm9, %ymm4
	vpaddd	%ymm3, %ymm4, %ymm9
	vpsubd	%ymm4, %ymm3, %ymm4
	vpmuldq	%ymm6, %ymm2, %ymm3
	vpmuldq	%ymm12, %ymm2, %ymm2
	vpmuldq	%ymm6, %ymm10, %ymm6
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsrlq	$32, %ymm8, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsubd	%ymm10, %ymm2, %ymm2
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm2, %ymm3, %ymm3
	vmovdqa	.LC31(%rip), %ymm2
	vpaddd	%ymm11, %ymm3, %ymm10
	vpsubd	%ymm3, %ymm11, %ymm3
	vmovdqa	.LC32(%rip), %ymm11
	vpmuldq	%ymm8, %ymm2, %ymm6
	vpmuldq	%ymm12, %ymm2, %ymm2
	vpmuldq	%ymm8, %ymm11, %ymm8
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsrlq	$32, %ymm1, %ymm12
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm8, %ymm6, %ymm6
	vpsubd	%ymm11, %ymm2, %ymm2
	vmovdqa	.LC34(%rip), %ymm11
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm2, %ymm6, %ymm2
	vmovdqa	.LC33(%rip), %ymm6
	vpaddd	%ymm7, %ymm2, %ymm8
	vpsubd	%ymm2, %ymm7, %ymm2
	vpmuldq	%ymm1, %ymm6, %ymm7
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm1, %ymm11, %ymm1
	vpmuldq	%ymm12, %ymm11, %ymm11
	vmovdqu	128(%rax), %ymm12
	vpmuldq	%ymm0, %ymm7, %ymm7
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm1, %ymm7, %ymm7
	vpsubd	%ymm11, %ymm6, %ymm6
	vpsrlq	$32, %ymm7, %ymm7
	vpblendd	$170, %ymm6, %ymm7, %ymm1
	vperm2i128	$32, %ymm9, %ymm4, %ymm7
	vperm2i128	$49, %ymm9, %ymm4, %ymm4
	vpaddd	%ymm5, %ymm1, %ymm11
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsrlq	$32, %ymm12, %ymm5
	vpmuldq	%ymm4, %ymm5, %ymm6
	vpsrlq	$32, %ymm4, %ymm9
	vpmuldq	%ymm9, %ymm5, %ymm5
	vpmuldq	%ymm4, %ymm12, %ymm4
	vpmuldq	%ymm9, %ymm12, %ymm9
	vmovdqu	160(%rax), %ymm12
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm4
	vpsrlq	$32, %ymm6, %ymm6
	vpsubd	%ymm9, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm6, %ymm5
	vperm2i128	$32, %ymm10, %ymm3, %ymm6
	vperm2i128	$49, %ymm10, %ymm3, %ymm3
	vpaddd	%ymm7, %ymm5, %ymm9
	vpsrlq	$32, %ymm3, %ymm10
	vpsubd	%ymm5, %ymm7, %ymm7
	vpmuldq	%ymm3, %ymm4, %ymm5
	vpmuldq	%ymm10, %ymm4, %ymm4
	vpmuldq	%ymm3, %ymm12, %ymm3
	vpmuldq	%ymm10, %ymm12, %ymm10
	vmovdqu	192(%rax), %ymm12
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm3, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm4, %ymm4
	vpsrlq	$32, %ymm12, %ymm3
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm4, %ymm5, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm10
	vpsubd	%ymm4, %ymm6, %ymm6
	vperm2i128	$32, %ymm8, %ymm2, %ymm4
	vperm2i128	$49, %ymm8, %ymm2, %ymm2
	vpmuldq	%ymm2, %ymm3, %ymm5
	vpsrlq	$32, %ymm2, %ymm8
	vpmuldq	%ymm8, %ymm3, %ymm3
	vpmuldq	%ymm2, %ymm12, %ymm2
	vpmuldq	%ymm8, %ymm12, %ymm8
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm2, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm8, %ymm3, %ymm3
	vmovdqu	224(%rax), %ymm8
	vpblendd	$170, %ymm3, %ymm5, %ymm3
	vperm2i128	$32, %ymm11, %ymm1, %ymm5
	vperm2i128	$49, %ymm11, %ymm1, %ymm1
	vpsrlq	$32, %ymm8, %ymm2
	vpsrlq	$32, %ymm1, %ymm11
	vpaddd	%ymm4, %ymm3, %ymm12
	vpsubd	%ymm3, %ymm4, %ymm4
	vpmuldq	%ymm1, %ymm2, %ymm3
	vpmuldq	%ymm11, %ymm2, %ymm2
	vpmuldq	%ymm1, %ymm8, %ymm1
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsubd	%ymm11, %ymm2, %ymm2
	vmovdqu	640(%rax), %ymm11
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm2, %ymm3, %ymm2
	vpunpcklqdq	%ymm9, %ymm7, %ymm3
	vpunpckhqdq	%ymm9, %ymm7, %ymm7
	vpsrlq	$32, %ymm11, %ymm1
	vpsrlq	$32, %ymm7, %ymm9
	vpaddd	%ymm5, %ymm2, %ymm8
	vpsubd	%ymm2, %ymm5, %ymm5
	vpmuldq	%ymm7, %ymm1, %ymm2
	vpmuldq	%ymm9, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm11, %ymm7
	vpmuldq	%ymm9, %ymm11, %ymm9
	vmovdqu	672(%rax), %ymm11
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm7, %ymm2, %ymm2
	vpsrlq	$32, %ymm2, %ymm2
	vpsubd	%ymm9, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm2, %ymm1
	vpunpcklqdq	%ymm10, %ymm6, %ymm2
	vpunpckhqdq	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm3, %ymm1, %ymm7
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm11, %ymm1
	vpmuldq	%ymm6, %ymm1, %ymm9
	vpsrlq	$32, %ymm6, %ymm10
	vpmuldq	%ymm10, %ymm1, %ymm1
	vpmuldq	%ymm6, %ymm11, %ymm6
	vpmuldq	%ymm10, %ymm11, %ymm10
	vmovdqu	704(%rax), %ymm11
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm6, %ymm9, %ymm9
	vpsrlq	$32, %ymm11, %ymm6
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm9, %ymm1
	vpaddd	%ymm2, %ymm1, %ymm9
	vpsubd	%ymm1, %ymm2, %ymm2
	vpunpcklqdq	%ymm12, %ymm4, %ymm1
	vpunpckhqdq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm4, %ymm6, %ymm10
	vpsrlq	$32, %ymm4, %ymm12
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm4, %ymm11, %ymm4
	vpmuldq	%ymm12, %ymm11, %ymm12
	vmovdqu	736(%rax), %ymm11
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm4, %ymm10, %ymm10
	vpsubd	%ymm12, %ymm6, %ymm6
	vpsrlq	$32, %ymm10, %ymm10
	vpblendd	$170, %ymm6, %ymm10, %ymm4
	vpsrlq	$32, %ymm11, %ymm10
	vpaddd	%ymm1, %ymm4, %ymm6
	vpsubd	%ymm4, %ymm1, %ymm1
	vpunpcklqdq	%ymm8, %ymm5, %ymm4
	vpunpckhqdq	%ymm8, %ymm5, %ymm5
	vpmuldq	%ymm5, %ymm10, %ymm8
	vpsrlq	$32, %ymm5, %ymm12
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm5, %ymm11, %ymm5
	vpmuldq	%ymm12, %ymm11, %ymm12
	vpsrlq	$32, %ymm13, %ymm11
	vmovdqu	1184(%rax), %ymm13
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm5, %ymm8, %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm10, %ymm10
	vpblendd	$170, %ymm10, %ymm8, %ymm10
	vpsllq	$32, %ymm7, %ymm8
	vpaddd	%ymm4, %ymm10, %ymm5
	vpblendd	$170, %ymm8, %ymm3, %ymm8
	vpsubd	%ymm10, %ymm4, %ymm4
	vmovdqu	1664(%rax), %ymm10
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm7, %ymm7
	vpsrlq	$32, %ymm10, %ymm10
	vpmuldq	1664(%rax), %ymm3, %ymm3
	vpsrlq	$32, %ymm7, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	1152(%rax), %ymm7, %ymm7
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsubd	%ymm7, %ymm3, %ymm3
	vpsllq	$32, %ymm9, %ymm7
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm7, %ymm2, %ymm7
	vpsrlq	$32, %ymm2, %ymm2
	vpblendd	$85, %ymm2, %ymm9, %ymm9
	vpmuldq	1696(%rax), %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsrlq	$32, %ymm9, %ymm12
	vpmuldq	1184(%rax), %ymm9, %ymm9
	vpsubd	%ymm11, %ymm10, %ymm10
	vpsrlq	$32, %ymm13, %ymm11
	vmovdqu	1216(%rax), %ymm13
	vpblendd	$170, %ymm10, %ymm3, %ymm3
	vmovdqu	1696(%rax), %ymm10
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsubd	%ymm9, %ymm2, %ymm2
	vpsllq	$32, %ymm6, %ymm9
	vpsrlq	$32, %ymm10, %ymm10
	vpsrlq	$32, %ymm2, %ymm2
	vpblendd	$170, %ymm9, %ymm1, %ymm9
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$85, %ymm1, %ymm6, %ymm6
	vpmuldq	1728(%rax), %ymm1, %ymm1
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsrlq	$32, %ymm6, %ymm12
	vpmuldq	1216(%rax), %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm6, %ymm1, %ymm1
	vpsllq	$32, %ymm5, %ymm6
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm6, %ymm4, %ymm6
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm11, %ymm10, %ymm10
	vpsrlq	$32, %ymm13, %ymm11
	vpblendd	$170, %ymm10, %ymm2, %ymm2
	vmovdqu	1728(%rax), %ymm10
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsrlq	$32, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm10, %ymm10
	vpblendd	$85, %ymm4, %ymm5, %ymm11
	vpmuldq	1760(%rax), %ymm4, %ymm4
	vpsrlq	$32, %ymm11, %ymm12
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendd	$170, %ymm10, %ymm1, %ymm1
	vmovdqu	1760(%rax), %ymm10
	vpmuldq	1248(%rax), %ymm11, %ymm11
	vpsrlq	$32, %ymm10, %ymm5
	vmovdqu	1248(%rax), %ymm10
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpsrlq	$32, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm4, %ymm5
	vpsubd	%ymm3, %ymm8, %ymm4
	vpaddd	%ymm3, %ymm8, %ymm8
	vpsubd	%ymm2, %ymm7, %ymm3
	vpaddd	%ymm2, %ymm7, %ymm7
	vmovdqu	%ymm4, 256(%rdi)
	vmovdqa	840(%rsp), %ymm11
	vpsubd	%ymm1, %ymm9, %ymm2
	vpaddd	%ymm1, %ymm9, %ymm9
	vmovdqu	%ymm3, 320(%rdi)
	vmovdqa	.LC38(%rip), %ymm12
	vpsubd	%ymm5, %ymm6, %ymm1
	vpaddd	%ymm5, %ymm6, %ymm6
	vmovdqu	%ymm2, 384(%rdi)
	vmovdqa	.LC36(%rip), %ymm5
	vmovdqu	%ymm1, 448(%rdi)
	vmovdqa	.LC35(%rip), %ymm1
	vmovdqu	%ymm6, 480(%rdi)
	vmovdqa	776(%rsp), %ymm6
	vmovdqu	%ymm7, 352(%rdi)
	vpmuldq	%ymm6, %ymm1, %ymm3
	vpsrlq	$32, %ymm6, %ymm4
	vmovdqu	%ymm8, 288(%rdi)
	vpmuldq	%ymm4, %ymm1, %ymm2
	vpmuldq	%ymm6, %ymm5, %ymm6
	vmovdqu	%ymm9, 416(%rdi)
	vpmuldq	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm11, %ymm5, %ymm8
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm6, %ymm3, %ymm3
	vmovdqa	520(%rsp), %ymm6
	vpsubd	%ymm4, %ymm2, %ymm2
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm2, %ymm3, %ymm3
	vpmuldq	%ymm11, %ymm1, %ymm4
	vpaddd	%ymm6, %ymm3, %ymm7
	vpsubd	%ymm3, %ymm6, %ymm3
	vpsrlq	$32, %ymm11, %ymm6
	vmovdqa	872(%rsp), %ymm11
	vpmuldq	%ymm6, %ymm1, %ymm2
	vpmuldq	%ymm6, %ymm5, %ymm6
	vpsrlq	$32, %ymm11, %ymm9
	vpmuldq	%ymm11, %ymm5, %ymm10
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm8, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm2, %ymm2
	vmovdqa	584(%rsp), %ymm6
	vpblendd	$170, %ymm2, %ymm4, %ymm2
	vpmuldq	%ymm9, %ymm1, %ymm4
	vpaddd	%ymm6, %ymm2, %ymm8
	vpsubd	%ymm2, %ymm6, %ymm2
	vpmuldq	%ymm11, %ymm1, %ymm6
	vmovdqa	904(%rsp), %ymm11
	vpmuldq	%ymm9, %ymm5, %ymm9
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm9, %ymm4, %ymm4
	vpsubd	%ymm10, %ymm6, %ymm6
	vpsrlq	$32, %ymm11, %ymm10
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm4, %ymm6, %ymm4
	vmovdqa	648(%rsp), %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9
	vpsubd	%ymm4, %ymm6, %ymm4
	vpmuldq	%ymm11, %ymm1, %ymm6
	vpmuldq	%ymm10, %ymm1, %ymm1
	vpmuldq	%ymm11, %ymm5, %ymm11
	vpmuldq	%ymm10, %ymm5, %ymm10
	vmovdqa	.LC37(%rip), %ymm5
	vpsrlq	$32, %ymm4, %ymm13
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm11, %ymm6, %ymm6
	vpmuldq	%ymm4, %ymm5, %ymm11
	vpsrlq	$32, %ymm6, %ymm6
	vpmuldq	%ymm4, %ymm12, %ymm4
	vpsubd	%ymm10, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm6, %ymm1
	vmovdqa	712(%rsp), %ymm6
	vpaddd	%ymm6, %ymm1, %ymm10
	vpsubd	%ymm1, %ymm6, %ymm1
	vpmuldq	%ymm13, %ymm5, %ymm6
	vpmuldq	%ymm0, %ymm11, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm13
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm4, %ymm11, %ymm11
	vpmuldq	%ymm1, %ymm5, %ymm4
	vpsrlq	$32, %ymm11, %ymm11
	vpsubd	%ymm13, %ymm6, %ymm6
	vpsrlq	$32, %ymm9, %ymm13
	vpblendd	$170, %ymm6, %ymm11, %ymm6
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpaddd	%ymm3, %ymm6, %ymm11
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm6
	vpmuldq	%ymm6, %ymm5, %ymm5
	vpmuldq	%ymm1, %ymm12, %ymm1
	vpmuldq	%ymm6, %ymm12, %ymm6
	vmovdqa	.LC40(%rip), %ymm12
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm4, %ymm4
	vmovdqa	.LC39(%rip), %ymm1
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm4, %ymm5
	vpmuldq	%ymm13, %ymm1, %ymm4
	vpaddd	%ymm5, %ymm2, %ymm6
	vpsubd	%ymm5, %ymm2, %ymm2
	vpmuldq	%ymm9, %ymm1, %ymm5
	vpmuldq	%ymm9, %ymm12, %ymm9
	vpmuldq	%ymm13, %ymm12, %ymm13
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm13, %ymm4, %ymm4
	vpsubd	%ymm9, %ymm5, %ymm5
	vpsrlq	$32, %ymm10, %ymm9
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm4, %ymm5, %ymm4
	vpaddd	%ymm7, %ymm4, %ymm5
	vpsubd	%ymm4, %ymm7, %ymm7
	vpmuldq	%ymm10, %ymm1, %ymm4
	vpmuldq	%ymm9, %ymm1, %ymm1
	vpmuldq	%ymm10, %ymm12, %ymm10
	vpmuldq	%ymm9, %ymm12, %ymm9
	vpsrlq	$32, %ymm2, %ymm12
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm10, %ymm4, %ymm4
	vmovdqa	.LC42(%rip), %ymm10
	vpsubd	%ymm9, %ymm1, %ymm1
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$170, %ymm1, %ymm4, %ymm4
	vpaddd	%ymm8, %ymm4, %ymm1
	vpsubd	%ymm4, %ymm8, %ymm8
	vmovdqa	.LC41(%rip), %ymm4
	vpmuldq	%ymm2, %ymm4, %ymm9
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm2, %ymm10, %ymm2
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsrlq	$32, %ymm6, %ymm12
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm2, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm4, %ymm4
	vmovdqa	.LC43(%rip), %ymm2
	vmovdqa	.LC44(%rip), %ymm10
	vpsrlq	$32, %ymm9, %ymm9
	vpblendd	$170, %ymm4, %ymm9, %ymm4
	vpaddd	%ymm4, %ymm3, %ymm9
	vpsubd	%ymm4, %ymm3, %ymm4
	vpmuldq	%ymm6, %ymm2, %ymm3
	vpmuldq	%ymm12, %ymm2, %ymm2
	vpmuldq	%ymm6, %ymm10, %ymm6
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsrlq	$32, %ymm8, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsubd	%ymm10, %ymm2, %ymm2
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm2, %ymm3, %ymm3
	vmovdqa	.LC45(%rip), %ymm2
	vpaddd	%ymm3, %ymm11, %ymm10
	vpsubd	%ymm3, %ymm11, %ymm3
	vmovdqa	.LC46(%rip), %ymm11
	vpmuldq	%ymm8, %ymm2, %ymm6
	vpmuldq	%ymm12, %ymm2, %ymm2
	vpmuldq	%ymm8, %ymm11, %ymm8
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsrlq	$32, %ymm1, %ymm12
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm8, %ymm6, %ymm6
	vpsubd	%ymm11, %ymm2, %ymm2
	vmovdqa	.LC48(%rip), %ymm11
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm2, %ymm6, %ymm2
	vmovdqa	.LC47(%rip), %ymm6
	vpaddd	%ymm2, %ymm7, %ymm8
	vpsubd	%ymm2, %ymm7, %ymm2
	vpmuldq	%ymm1, %ymm6, %ymm7
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm1, %ymm11, %ymm1
	vpmuldq	%ymm12, %ymm11, %ymm11
	vmovdqu	256(%rax), %ymm12
	vpmuldq	%ymm0, %ymm7, %ymm7
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm1, %ymm7, %ymm7
	vpsubd	%ymm11, %ymm6, %ymm6
	vpsrlq	$32, %ymm7, %ymm7
	vpblendd	$170, %ymm6, %ymm7, %ymm1
	vperm2i128	$32, %ymm9, %ymm4, %ymm7
	vperm2i128	$49, %ymm9, %ymm4, %ymm4
	vpaddd	%ymm1, %ymm5, %ymm11
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsrlq	$32, %ymm12, %ymm5
	vpmuldq	%ymm4, %ymm5, %ymm6
	vpsrlq	$32, %ymm4, %ymm9
	vpmuldq	%ymm9, %ymm5, %ymm5
	vpmuldq	%ymm4, %ymm12, %ymm4
	vpmuldq	%ymm9, %ymm12, %ymm9
	vmovdqu	288(%rax), %ymm12
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm4
	vpsrlq	$32, %ymm6, %ymm6
	vpsubd	%ymm9, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm6, %ymm5
	vperm2i128	$32, %ymm10, %ymm3, %ymm6
	vperm2i128	$49, %ymm10, %ymm3, %ymm3
	vpaddd	%ymm7, %ymm5, %ymm9
	vpsrlq	$32, %ymm3, %ymm10
	vpsubd	%ymm5, %ymm7, %ymm7
	vpmuldq	%ymm3, %ymm4, %ymm5
	vpmuldq	%ymm10, %ymm4, %ymm4
	vpmuldq	%ymm3, %ymm12, %ymm3
	vpmuldq	%ymm10, %ymm12, %ymm10
	vmovdqu	320(%rax), %ymm12
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm3, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm4, %ymm4
	vpsrlq	$32, %ymm12, %ymm3
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm4, %ymm5, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm10
	vpsubd	%ymm4, %ymm6, %ymm6
	vperm2i128	$32, %ymm8, %ymm2, %ymm4
	vperm2i128	$49, %ymm8, %ymm2, %ymm2
	vpmuldq	%ymm2, %ymm3, %ymm5
	vpsrlq	$32, %ymm2, %ymm8
	vpmuldq	%ymm8, %ymm3, %ymm3
	vpmuldq	%ymm2, %ymm12, %ymm2
	vpmuldq	%ymm8, %ymm12, %ymm8
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm2, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm8, %ymm3, %ymm3
	vmovdqu	352(%rax), %ymm8
	vpblendd	$170, %ymm3, %ymm5, %ymm3
	vperm2i128	$32, %ymm11, %ymm1, %ymm5
	vperm2i128	$49, %ymm11, %ymm1, %ymm1
	vpsrlq	$32, %ymm8, %ymm2
	vpsrlq	$32, %ymm1, %ymm11
	vpaddd	%ymm4, %ymm3, %ymm12
	vpsubd	%ymm3, %ymm4, %ymm4
	vpmuldq	%ymm1, %ymm2, %ymm3
	vpmuldq	%ymm11, %ymm2, %ymm2
	vpmuldq	%ymm1, %ymm8, %ymm1
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsubd	%ymm11, %ymm2, %ymm2
	vmovdqu	768(%rax), %ymm11
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm2, %ymm3, %ymm2
	vpunpcklqdq	%ymm9, %ymm7, %ymm3
	vpunpckhqdq	%ymm9, %ymm7, %ymm7
	vpsrlq	$32, %ymm11, %ymm1
	vpsrlq	$32, %ymm7, %ymm9
	vpaddd	%ymm5, %ymm2, %ymm8
	vpsubd	%ymm2, %ymm5, %ymm5
	vpmuldq	%ymm7, %ymm1, %ymm2
	vpmuldq	%ymm9, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm11, %ymm7
	vpmuldq	%ymm9, %ymm11, %ymm9
	vmovdqu	800(%rax), %ymm11
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm7, %ymm2, %ymm2
	vpsrlq	$32, %ymm2, %ymm2
	vpsubd	%ymm9, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm2, %ymm1
	vpunpcklqdq	%ymm10, %ymm6, %ymm2
	vpunpckhqdq	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm3, %ymm1, %ymm7
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm11, %ymm1
	vpmuldq	%ymm6, %ymm1, %ymm9
	vpsrlq	$32, %ymm6, %ymm10
	vpmuldq	%ymm10, %ymm1, %ymm1
	vpmuldq	%ymm6, %ymm11, %ymm6
	vpmuldq	%ymm10, %ymm11, %ymm10
	vmovdqu	832(%rax), %ymm11
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm6, %ymm9, %ymm9
	vpsrlq	$32, %ymm11, %ymm6
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm9, %ymm1
	vpaddd	%ymm2, %ymm1, %ymm9
	vpsubd	%ymm1, %ymm2, %ymm2
	vpunpcklqdq	%ymm12, %ymm4, %ymm1
	vpunpckhqdq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm4, %ymm6, %ymm10
	vpsrlq	$32, %ymm4, %ymm12
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm4, %ymm11, %ymm4
	vpmuldq	%ymm12, %ymm11, %ymm12
	vmovdqu	864(%rax), %ymm11
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm4, %ymm10, %ymm10
	vpsubd	%ymm12, %ymm6, %ymm6
	vpsrlq	$32, %ymm10, %ymm10
	vpblendd	$170, %ymm6, %ymm10, %ymm4
	vpsrlq	$32, %ymm11, %ymm10
	vpaddd	%ymm1, %ymm4, %ymm6
	vpsubd	%ymm4, %ymm1, %ymm1
	vpunpcklqdq	%ymm8, %ymm5, %ymm4
	vpunpckhqdq	%ymm8, %ymm5, %ymm5
	vpmuldq	%ymm5, %ymm10, %ymm8
	vpsrlq	$32, %ymm5, %ymm12
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm5, %ymm11, %ymm5
	vpmuldq	%ymm12, %ymm11, %ymm12
	vmovdqu	1792(%rax), %ymm11
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm5, %ymm8, %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm10, %ymm10
	vpblendd	$170, %ymm10, %ymm8, %ymm10
	vpsllq	$32, %ymm7, %ymm8
	vpblendd	$170, %ymm8, %ymm3, %ymm8
	vpsrlq	$32, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm10, %ymm5
	vpblendd	$85, %ymm3, %ymm7, %ymm7
	vpsubd	%ymm10, %ymm4, %ymm4
	vpmuldq	1792(%rax), %ymm3, %ymm3
	vpsrlq	$32, %ymm7, %ymm12
	vpsrlq	$32, %ymm11, %ymm10
	vmovdqu	1280(%rax), %ymm11
	vpmuldq	1280(%rax), %ymm7, %ymm7
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsrlq	$32, %ymm11, %ymm11
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm7, %ymm3, %ymm3
	vpsllq	$32, %ymm9, %ymm7
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm7, %ymm2, %ymm7
	vpsrlq	$32, %ymm2, %ymm2
	vpblendd	$85, %ymm2, %ymm9, %ymm9
	vpmuldq	1824(%rax), %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpsrlq	$32, %ymm9, %ymm12
	vpmuldq	1312(%rax), %ymm9, %ymm9
	vpsubd	%ymm11, %ymm10, %ymm10
	vmovdqu	1824(%rax), %ymm11
	vpblendd	$170, %ymm10, %ymm3, %ymm3
	vpsrlq	$32, %ymm11, %ymm10
	vmovdqu	1312(%rax), %ymm11
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsubd	%ymm9, %ymm2, %ymm2
	vpsrlq	$32, %ymm11, %ymm11
	vpsllq	$32, %ymm6, %ymm9
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsrlq	$32, %ymm2, %ymm2
	vpblendd	$170, %ymm9, %ymm1, %ymm9
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$85, %ymm1, %ymm6, %ymm6
	vpmuldq	1856(%rax), %ymm1, %ymm1
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsrlq	$32, %ymm6, %ymm12
	vpmuldq	1344(%rax), %ymm6, %ymm6
	vpsubd	%ymm6, %ymm1, %ymm1
	vmovdqu	1888(%rax), %ymm6
	vpsubd	%ymm11, %ymm10, %ymm10
	vmovdqu	1856(%rax), %ymm11
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm10, %ymm2, %ymm2
	vpsrlq	$32, %ymm11, %ymm10
	vmovdqu	1344(%rax), %ymm11
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpsrlq	$32, %ymm11, %ymm11
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpmuldq	%ymm0, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm10, %ymm10
	vpblendd	$170, %ymm10, %ymm1, %ymm1
	vpsllq	$32, %ymm5, %ymm10
	vpblendd	$170, %ymm10, %ymm4, %ymm10
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$85, %ymm4, %ymm5, %ymm11
	vpsrlq	$32, %ymm6, %ymm5
	vmovdqu	1376(%rax), %ymm6
	vpmuldq	1888(%rax), %ymm4, %ymm4
	vpsrlq	$32, %ymm11, %ymm12
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	1376(%rax), %ymm11, %ymm11
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpsrlq	$32, %ymm6, %ymm6
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpsubd	%ymm11, %ymm4, %ymm4
	vpsrlq	$32, %ymm14, %ymm11
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm4, %ymm5
	vpsubd	%ymm3, %ymm8, %ymm4
	vpaddd	%ymm8, %ymm3, %ymm3
	vmovdqu	%ymm3, 544(%rdi)
	vpsubd	%ymm2, %ymm7, %ymm3
	vpaddd	%ymm7, %ymm2, %ymm2
	vmovdqa	744(%rsp), %ymm7
	vmovdqu	%ymm2, 608(%rdi)
	vpsubd	%ymm1, %ymm9, %ymm2
	vpaddd	%ymm9, %ymm1, %ymm1
	vpsrlq	$32, %ymm15, %ymm9
	vmovdqu	%ymm1, 672(%rdi)
	vpsubd	%ymm5, %ymm10, %ymm1
	vpaddd	%ymm10, %ymm5, %ymm5
	vmovdqu	%ymm1, 704(%rdi)
	vmovdqa	.LC49(%rip), %ymm1
	vmovdqu	%ymm4, 512(%rdi)
	vmovdqu	%ymm5, 736(%rdi)
	vpmuldq	%ymm7, %ymm1, %ymm4
	vpsrlq	$32, %ymm7, %ymm5
	vmovdqu	%ymm3, 576(%rdi)
	vpmuldq	%ymm5, %ymm1, %ymm3
	vmovdqu	%ymm2, 640(%rdi)
	vmovdqa	.LC50(%rip), %ymm2
	vpmuldq	%ymm7, %ymm2, %ymm6
	vpmuldq	%ymm5, %ymm2, %ymm5
	vmovdqa	488(%rsp), %ymm7
	vmovdqa	808(%rsp), %ymm13
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm15, %ymm2, %ymm10
	vmovdqa	.LC52(%rip), %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm13, %ymm2, %ymm8
	vpsubd	%ymm6, %ymm4, %ymm4
	vpsubd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$170, %ymm3, %ymm4, %ymm4
	vpmuldq	%ymm13, %ymm1, %ymm3
	vpaddd	%ymm7, %ymm4, %ymm5
	vpsubd	%ymm4, %ymm7, %ymm4
	vpsrlq	$32, %ymm13, %ymm7
	vpmuldq	%ymm7, %ymm1, %ymm6
	vpmuldq	%ymm7, %ymm2, %ymm7
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm8, %ymm3, %ymm3
	vpmuldq	%ymm15, %ymm1, %ymm8
	vmovdqa	616(%rsp), %ymm15
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm7, %ymm6, %ymm6
	vmovdqa	552(%rsp), %ymm7
	vpblendd	$170, %ymm6, %ymm3, %ymm3
	vpaddd	%ymm7, %ymm3, %ymm6
	vpsubd	%ymm3, %ymm7, %ymm3
	vpmuldq	%ymm9, %ymm1, %ymm7
	vpmuldq	%ymm9, %ymm2, %ymm9
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm7, %ymm7
	vpsubd	%ymm10, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm2, %ymm10
	vpmuldq	%ymm11, %ymm2, %ymm2
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm9, %ymm7, %ymm7
	vpmuldq	%ymm14, %ymm1, %ymm9
	vpmuldq	%ymm11, %ymm1, %ymm1
	vpblendd	$170, %ymm7, %ymm8, %ymm8
	vpaddd	%ymm15, %ymm8, %ymm7
	vpsubd	%ymm8, %ymm15, %ymm8
	vmovdqu	1408(%rax), %ymm15
	vpsrlq	$32, %ymm8, %ymm11
	vpmuldq	%ymm8, %ymm12, %ymm14
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpsubd	%ymm10, %ymm9, %ymm9
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm2, %ymm1, %ymm1
	vmovdqa	680(%rsp), %ymm2
	vpblendd	$170, %ymm1, %ymm9, %ymm1
	vmovdqa	.LC51(%rip), %ymm9
	vpaddd	%ymm2, %ymm1, %ymm10
	vpsubd	%ymm1, %ymm2, %ymm1
	vpmuldq	%ymm8, %ymm9, %ymm2
	vpmuldq	%ymm11, %ymm9, %ymm13
	vpmuldq	%ymm11, %ymm12, %ymm11
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm13, %ymm8
	vmovdqa	.LC54(%rip), %ymm13
	vpsubd	%ymm14, %ymm2, %ymm2
	vpsubd	%ymm11, %ymm8, %ymm8
	vmovdqu	1952(%rax), %ymm14
	vpsrlq	$32, %ymm2, %ymm2
	vpblendd	$170, %ymm8, %ymm2, %ymm2
	vpsrlq	$32, %ymm1, %ymm8
	vpaddd	%ymm2, %ymm4, %ymm11
	vpsubd	%ymm2, %ymm4, %ymm2
	vpmuldq	%ymm1, %ymm9, %ymm4
	vpmuldq	%ymm8, %ymm9, %ymm9
	vpmuldq	%ymm1, %ymm12, %ymm1
	vpmuldq	%ymm8, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpsubd	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm12, %ymm9, %ymm1
	vmovdqa	.LC53(%rip), %ymm12
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$170, %ymm1, %ymm4, %ymm4
	vpsrlq	$32, %ymm7, %ymm9
	vpmuldq	%ymm7, %ymm12, %ymm1
	vpmuldq	%ymm7, %ymm13, %ymm7
	vpaddd	%ymm4, %ymm3, %ymm8
	vpsubd	%ymm4, %ymm3, %ymm4
	vpmuldq	%ymm9, %ymm12, %ymm3
	vpmuldq	%ymm9, %ymm13, %ymm9
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpsubd	%ymm7, %ymm1, %ymm1
	vpsrlq	$32, %ymm10, %ymm7
	vpsubd	%ymm9, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm3, %ymm1, %ymm1
	vpmuldq	%ymm10, %ymm12, %ymm3
	vpaddd	%ymm1, %ymm5, %ymm9
	vpsubd	%ymm1, %ymm5, %ymm1
	vpmuldq	%ymm7, %ymm12, %ymm5
	vpmuldq	%ymm10, %ymm13, %ymm10
	vpmuldq	%ymm7, %ymm13, %ymm13
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm3, %ymm3
	vmovdqa	.LC56(%rip), %ymm10
	vpsubd	%ymm13, %ymm5, %ymm5
	vpsrlq	$32, %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm13
	vpmuldq	%ymm4, %ymm10, %ymm7
	vpblendd	$170, %ymm5, %ymm3, %ymm3
	vpaddd	%ymm3, %ymm6, %ymm12
	vpsubd	%ymm3, %ymm6, %ymm3
	vmovdqa	.LC55(%rip), %ymm6
	vpmuldq	%ymm13, %ymm10, %ymm10
	vpmuldq	%ymm4, %ymm6, %ymm5
	vpmuldq	%ymm13, %ymm6, %ymm6
	vpsrlq	$32, %ymm3, %ymm13
	vpmuldq	%ymm0, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm6, %ymm5
	vmovdqa	.LC58(%rip), %ymm6
	vpsubd	%ymm7, %ymm4, %ymm4
	vpsubd	%ymm10, %ymm5, %ymm5
	vpsrlq	$32, %ymm8, %ymm7
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$170, %ymm5, %ymm4, %ymm4
	vmovdqa	.LC57(%rip), %ymm5
	vpaddd	%ymm4, %ymm2, %ymm10
	vpsubd	%ymm4, %ymm2, %ymm2
	vpmuldq	%ymm8, %ymm5, %ymm4
	vpmuldq	%ymm7, %ymm5, %ymm5
	vpmuldq	%ymm8, %ymm6, %ymm8
	vpmuldq	%ymm7, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpsubd	%ymm8, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm5, %ymm5
	vmovdqa	.LC59(%rip), %ymm6
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$170, %ymm5, %ymm4, %ymm4
	vpaddd	%ymm4, %ymm11, %ymm8
	vpsubd	%ymm4, %ymm11, %ymm5
	vpmuldq	%ymm3, %ymm6, %ymm4
	vmovdqa	.LC60(%rip), %ymm11
	vpmuldq	%ymm13, %ymm6, %ymm6
	vpmuldq	%ymm3, %ymm11, %ymm7
	vpmuldq	%ymm13, %ymm11, %ymm11
	vpmuldq	%ymm0, %ymm4, %ymm3
	vpmuldq	%ymm0, %ymm6, %ymm4
	vmovdqa	.LC62(%rip), %ymm6
	vpsubd	%ymm7, %ymm3, %ymm3
	vpsubd	%ymm11, %ymm4, %ymm4
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vmovdqa	.LC61(%rip), %ymm4
	vpsrlq	$32, %ymm12, %ymm11
	vpaddd	%ymm3, %ymm1, %ymm7
	vpsubd	%ymm3, %ymm1, %ymm1
	vpmuldq	%ymm12, %ymm4, %ymm3
	vpmuldq	%ymm11, %ymm4, %ymm4
	vpmuldq	%ymm12, %ymm6, %ymm12
	vpmuldq	%ymm11, %ymm6, %ymm6
	vperm2i128	$32, %ymm10, %ymm2, %ymm11
	vperm2i128	$49, %ymm10, %ymm2, %ymm2
	vpsrlq	$32, %ymm2, %ymm13
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm12, %ymm3, %ymm3
	vpsubd	%ymm6, %ymm4, %ymm4
	vmovdqu	384(%rax), %ymm12
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vpmuldq	%ymm2, %ymm12, %ymm10
	vpaddd	%ymm3, %ymm9, %ymm6
	vpsubd	%ymm3, %ymm9, %ymm4
	vpsrlq	$32, %ymm12, %ymm9
	vpmuldq	%ymm2, %ymm9, %ymm3
	vpmuldq	%ymm13, %ymm9, %ymm9
	vpmuldq	%ymm13, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm9, %ymm2
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsubd	%ymm12, %ymm2, %ymm2
	vmovdqu	416(%rax), %ymm12
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm2, %ymm3, %ymm3
	vpsrlq	$32, %ymm12, %ymm10
	vpaddd	%ymm11, %ymm3, %ymm9
	vpsubd	%ymm3, %ymm11, %ymm2
	vperm2i128	$49, %ymm8, %ymm5, %ymm11
	vpsrlq	$32, %ymm11, %ymm13
	vperm2i128	$32, %ymm8, %ymm5, %ymm3
	vpmuldq	%ymm11, %ymm10, %ymm5
	vpmuldq	%ymm13, %ymm10, %ymm8
	vperm2i128	$32, %ymm7, %ymm1, %ymm10
	vpmuldq	%ymm11, %ymm12, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm12
	vperm2i128	$49, %ymm7, %ymm1, %ymm1
	vpsrlq	$32, %ymm1, %ymm13
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsubd	%ymm12, %ymm8, %ymm8
	vmovdqu	448(%rax), %ymm12
	vpsrlq	$32, %ymm5, %ymm5
	vpsrlq	$32, %ymm12, %ymm11
	vpmuldq	%ymm1, %ymm12, %ymm7
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vpaddd	%ymm3, %ymm5, %ymm8
	vpsubd	%ymm5, %ymm3, %ymm3
	vpmuldq	%ymm1, %ymm11, %ymm5
	vpmuldq	%ymm13, %ymm11, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm5, %ymm5
	vpmuldq	%ymm0, %ymm11, %ymm1
	vperm2i128	$49, %ymm6, %ymm4, %ymm11
	vpsrlq	$32, %ymm11, %ymm13
	vpsubd	%ymm7, %ymm5, %ymm5
	vpsubd	%ymm12, %ymm1, %ymm1
	vpsrlq	$32, %ymm5, %ymm5
	vmovdqu	480(%rax), %ymm12
	vpblendd	$170, %ymm1, %ymm5, %ymm5
	vpaddd	%ymm10, %ymm5, %ymm7
	vpsubd	%ymm5, %ymm10, %ymm1
	vpsrlq	$32, %ymm12, %ymm10
	vperm2i128	$32, %ymm6, %ymm4, %ymm5
	vpmuldq	%ymm11, %ymm10, %ymm4
	vpmuldq	%ymm13, %ymm10, %ymm6
	vpmuldq	%ymm11, %ymm12, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm11, %ymm4, %ymm4
	vpunpckhqdq	%ymm9, %ymm2, %ymm11
	vpsrlq	$32, %ymm4, %ymm4
	vpsrlq	$32, %ymm11, %ymm13
	vpsubd	%ymm12, %ymm6, %ymm6
	vmovdqu	896(%rax), %ymm12
	vpblendd	$170, %ymm6, %ymm4, %ymm4
	vpsrlq	$32, %ymm12, %ymm10
	vpaddd	%ymm5, %ymm4, %ymm6
	vpsubd	%ymm4, %ymm5, %ymm5
	vpunpcklqdq	%ymm9, %ymm2, %ymm4
	vpmuldq	%ymm11, %ymm10, %ymm2
	vpmuldq	%ymm13, %ymm10, %ymm9
	vpmuldq	%ymm11, %ymm12, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpsubd	%ymm11, %ymm2, %ymm2
	vpunpckhqdq	%ymm8, %ymm3, %ymm11
	vpsrlq	$32, %ymm2, %ymm2
	vpsrlq	$32, %ymm11, %ymm13
	vpsubd	%ymm12, %ymm9, %ymm9
	vmovdqu	928(%rax), %ymm12
	vpblendd	$170, %ymm9, %ymm2, %ymm2
	vpsrlq	$32, %ymm12, %ymm9
	vpaddd	%ymm4, %ymm2, %ymm10
	vpsubd	%ymm2, %ymm4, %ymm4
	vpunpcklqdq	%ymm8, %ymm3, %ymm2
	vpmuldq	%ymm11, %ymm9, %ymm3
	vpmuldq	%ymm13, %ymm9, %ymm8
	vpmuldq	%ymm11, %ymm12, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsubd	%ymm11, %ymm3, %ymm3
	vpunpckhqdq	%ymm7, %ymm1, %ymm11
	vpsrlq	$32, %ymm3, %ymm3
	vpsrlq	$32, %ymm11, %ymm13
	vpsubd	%ymm12, %ymm8, %ymm8
	vmovdqu	960(%rax), %ymm12
	vpblendd	$170, %ymm8, %ymm3, %ymm3
	vpsrlq	$32, %ymm12, %ymm8
	vpaddd	%ymm2, %ymm3, %ymm9
	vpsubd	%ymm3, %ymm2, %ymm2
	vpunpcklqdq	%ymm7, %ymm1, %ymm3
	vpmuldq	%ymm11, %ymm8, %ymm1
	vpmuldq	%ymm13, %ymm8, %ymm7
	vpmuldq	%ymm11, %ymm12, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpmuldq	%ymm0, %ymm7, %ymm7
	vpsubd	%ymm11, %ymm1, %ymm1
	vpsubd	%ymm12, %ymm7, %ymm7
	vpsrlq	$32, %ymm1, %ymm1
	vmovdqu	992(%rax), %ymm12
	vpblendd	$170, %ymm7, %ymm1, %ymm1
	vpaddd	%ymm3, %ymm1, %ymm8
	vpsrlq	$32, %ymm12, %ymm7
	vpsubd	%ymm1, %ymm3, %ymm3
	vpunpcklqdq	%ymm6, %ymm5, %ymm1
	vpunpckhqdq	%ymm6, %ymm5, %ymm5
	vpmuldq	%ymm5, %ymm7, %ymm6
	vpsrlq	$32, %ymm5, %ymm13
	vpmuldq	%ymm13, %ymm7, %ymm7
	vpmuldq	%ymm5, %ymm12, %ymm11
	vpmuldq	%ymm13, %ymm12, %ymm12
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm7, %ymm5
	vpsllq	$32, %ymm10, %ymm7
	vpblendd	$170, %ymm7, %ymm4, %ymm7
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$85, %ymm4, %ymm10, %ymm10
	vpmuldq	1920(%rax), %ymm4, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpsubd	%ymm11, %ymm6, %ymm6
	vpsrlq	$32, %ymm15, %ymm11
	vpsubd	%ymm12, %ymm5, %ymm5
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm5, %ymm6, %ymm6
	vpsrlq	$32, %ymm10, %ymm12
	vpmuldq	1408(%rax), %ymm10, %ymm10
	vpaddd	%ymm1, %ymm6, %ymm5
	vpsubd	%ymm6, %ymm1, %ymm1
	vmovdqu	1920(%rax), %ymm6
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsubd	%ymm10, %ymm4, %ymm4
	vpsrlq	$32, %ymm6, %ymm6
	vpsrlq	$32, %ymm4, %ymm4
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm0, %ymm6, %ymm6
	vpsubd	%ymm11, %ymm6, %ymm6
	vpblendd	$170, %ymm6, %ymm4, %ymm4
	vpsllq	$32, %ymm9, %ymm6
	vpblendd	$170, %ymm6, %ymm2, %ymm6
	vpsrlq	$32, %ymm2, %ymm2
	vpblendd	$85, %ymm2, %ymm9, %ymm10
	vpsrlq	$32, %ymm14, %ymm9
	vpmuldq	1952(%rax), %ymm2, %ymm2
	vpsrlq	$32, %ymm10, %ymm12
	vpmuldq	%ymm0, %ymm2, %ymm2
	vpmuldq	1440(%rax), %ymm10, %ymm10
	vmovdqu	1440(%rax), %ymm15
	vpmuldq	%ymm12, %ymm9, %ymm9
	vmovdqu	1984(%rax), %ymm14
	vpsrlq	$32, %ymm15, %ymm11
	vmovdqu	1472(%rax), %ymm15
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsubd	%ymm10, %ymm2, %ymm2
	vpmuldq	%ymm0, %ymm9, %ymm9
	vpsrlq	$32, %ymm2, %ymm2
	vpsubd	%ymm11, %ymm9, %ymm9
	vpsrlq	$32, %ymm15, %ymm11
	vpblendd	$170, %ymm9, %ymm2, %ymm2
	vpsllq	$32, %ymm8, %ymm9
	vpblendd	$170, %ymm9, %ymm3, %ymm9
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm8, %ymm10
	vpsrlq	$32, %ymm14, %ymm8
	vpmuldq	1984(%rax), %ymm3, %ymm3
	vpsrlq	$32, %ymm10, %ymm12
	vpmuldq	%ymm0, %ymm3, %ymm3
	vpmuldq	1472(%rax), %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsllq	$32, %ymm5, %ymm10
	vpmuldq	%ymm0, %ymm8, %ymm8
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm10, %ymm1, %ymm10
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$85, %ymm1, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm12
	vpsubd	%ymm11, %ymm8, %ymm8
	vmovdqu	2016(%rax), %ymm11
	vpblendd	$170, %ymm8, %ymm3, %ymm3
	vmovdqu	1504(%rax), %ymm8
	movq	%rdi, %rax
	vpmuldq	%ymm1, %ymm11, %ymm1
	vpsrlq	$32, %ymm11, %ymm11
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpmuldq	%ymm5, %ymm8, %ymm5
	vpsrlq	$32, %ymm8, %ymm8
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpmuldq	%ymm0, %ymm11, %ymm11
	vpsubd	%ymm5, %ymm1, %ymm0
	vpsrlq	$32, %ymm0, %ymm0
	vpsubd	%ymm8, %ymm11, %ymm1
	vpblendd	$170, %ymm1, %ymm0, %ymm0
	vpsubd	%ymm4, %ymm7, %ymm1
	vpaddd	%ymm7, %ymm4, %ymm4
	vmovdqu	%ymm1, 768(%rdi)
	vpsubd	%ymm2, %ymm6, %ymm1
	vpaddd	%ymm6, %ymm2, %ymm2
	vmovdqu	%ymm1, 832(%rdi)
	vpsubd	%ymm3, %ymm9, %ymm1
	vpaddd	%ymm9, %ymm3, %ymm3
	vmovdqu	%ymm2, 864(%rdi)
	vmovdqa	.LC63(%rip), %ymm2
	vmovdqu	%ymm1, 896(%rdi)
	vpsubd	%ymm0, %ymm10, %ymm1
	vpaddd	%ymm10, %ymm0, %ymm0
	vmovdqu	%ymm4, 800(%rdi)
	vmovdqu	%ymm3, 928(%rdi)
	vmovdqu	%ymm1, 960(%rdi)
	vmovdqu	%ymm0, 992(%rdi)
	.p2align 4,,10
	.p2align 3
.L2:
	vpaddd	(%rax), %ymm2, %ymm1
	vmovdqu	(%rax), %ymm7
	addq	$32, %rax
	vpsrad	$23, %ymm1, %ymm1
	vpslld	$10, %ymm1, %ymm0
	vpsubd	%ymm1, %ymm0, %ymm0
	vpslld	$13, %ymm0, %ymm0
	vpaddd	%ymm1, %ymm0, %ymm0
	vpsubd	%ymm0, %ymm7, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %rdx
	jne	.L2
	vmovdqa	.LC64(%rip), %ymm2
	vmovdqa	.LC65(%rip), %ymm3
	.p2align 4,,10
	.p2align 3
.L3:
	vmovdqu	(%rdi), %ymm7
	addq	$32, %rdi
	vpsrad	$31, %ymm7, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm7, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rdi)
	cmpq	%rdi, %rdx
	jne	.L3
	vzeroupper
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5824:
	.size	ml_dsa_avx_ntt_forward_so_impl, .-ml_dsa_avx_ntt_forward_so_impl
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC0:
	.long	1830765815
	.long	1830765815
	.long	1830765815
	.long	1830765815
	.long	1830765815
	.long	1830765815
	.long	1830765815
	.long	1830765815
	.align 32
.LC1:
	.long	25847
	.long	25847
	.long	25847
	.long	25847
	.long	25847
	.long	25847
	.long	25847
	.long	25847
	.align 32
.LC2:
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.align 32
.LC3:
	.long	-1929875198
	.long	-1929875198
	.long	-1929875198
	.long	-1929875198
	.long	-1929875198
	.long	-1929875198
	.long	-1929875198
	.long	-1929875198
	.align 32
.LC4:
	.long	-2608894
	.long	-2608894
	.long	-2608894
	.long	-2608894
	.long	-2608894
	.long	-2608894
	.long	-2608894
	.long	-2608894
	.align 32
.LC5:
	.long	-1927777021
	.long	-1927777021
	.long	-1927777021
	.long	-1927777021
	.long	-1927777021
	.long	-1927777021
	.long	-1927777021
	.long	-1927777021
	.align 32
.LC6:
	.long	-518909
	.long	-518909
	.long	-518909
	.long	-518909
	.long	-518909
	.long	-518909
	.long	-518909
	.long	-518909
	.align 32
.LC7:
	.long	1640767044
	.long	1640767044
	.long	1640767044
	.long	1640767044
	.long	1640767044
	.long	1640767044
	.long	1640767044
	.long	1640767044
	.align 32
.LC8:
	.long	237124
	.long	237124
	.long	237124
	.long	237124
	.long	237124
	.long	237124
	.long	237124
	.long	237124
	.align 32
.LC9:
	.long	308362795
	.long	308362795
	.long	308362795
	.long	308362795
	.long	308362795
	.long	308362795
	.long	308362795
	.long	308362795
	.align 32
.LC10:
	.long	1826347
	.long	1826347
	.long	1826347
	.long	1826347
	.long	1826347
	.long	1826347
	.long	1826347
	.long	1826347
	.align 32
.LC11:
	.long	-1815525077
	.long	-1815525077
	.long	-1815525077
	.long	-1815525077
	.long	-1815525077
	.long	-1815525077
	.long	-1815525077
	.long	-1815525077
	.align 32
.LC12:
	.long	2353451
	.long	2353451
	.long	2353451
	.long	2353451
	.long	2353451
	.long	2353451
	.long	2353451
	.long	2353451
	.align 32
.LC13:
	.long	1727305304
	.long	1727305304
	.long	1727305304
	.long	1727305304
	.long	1727305304
	.long	1727305304
	.long	1727305304
	.long	1727305304
	.align 32
.LC14:
	.long	2725464
	.long	2725464
	.long	2725464
	.long	2725464
	.long	2725464
	.long	2725464
	.long	2725464
	.long	2725464
	.align 32
.LC15:
	.long	2082316400
	.long	2082316400
	.long	2082316400
	.long	2082316400
	.long	2082316400
	.long	2082316400
	.long	2082316400
	.long	2082316400
	.align 32
.LC16:
	.long	1024112
	.long	1024112
	.long	1024112
	.long	1024112
	.long	1024112
	.long	1024112
	.long	1024112
	.long	1024112
	.align 32
.LC17:
	.long	-1364982364
	.long	-1364982364
	.long	-1364982364
	.long	-1364982364
	.long	-1364982364
	.long	-1364982364
	.long	-1364982364
	.long	-1364982364
	.align 32
.LC18:
	.long	-1079900
	.long	-1079900
	.long	-1079900
	.long	-1079900
	.long	-1079900
	.long	-1079900
	.long	-1079900
	.long	-1079900
	.align 32
.LC19:
	.long	858240904
	.long	858240904
	.long	858240904
	.long	858240904
	.long	858240904
	.long	858240904
	.long	858240904
	.long	858240904
	.align 32
.LC20:
	.long	3585928
	.long	3585928
	.long	3585928
	.long	3585928
	.long	3585928
	.long	3585928
	.long	3585928
	.long	3585928
	.align 32
.LC21:
	.long	1477910808
	.long	1477910808
	.long	1477910808
	.long	1477910808
	.long	1477910808
	.long	1477910808
	.long	1477910808
	.long	1477910808
	.align 32
.LC22:
	.long	-777960
	.long	-777960
	.long	-777960
	.long	-777960
	.long	-777960
	.long	-777960
	.long	-777960
	.long	-777960
	.align 32
.LC23:
	.long	-1374673747
	.long	-1374673747
	.long	-1374673747
	.long	-1374673747
	.long	-1374673747
	.long	-1374673747
	.long	-1374673747
	.long	-1374673747
	.align 32
.LC24:
	.long	-359251
	.long	-359251
	.long	-359251
	.long	-359251
	.long	-359251
	.long	-359251
	.long	-359251
	.long	-359251
	.align 32
.LC25:
	.long	-1091570561
	.long	-1091570561
	.long	-1091570561
	.long	-1091570561
	.long	-1091570561
	.long	-1091570561
	.long	-1091570561
	.long	-1091570561
	.align 32
.LC26:
	.long	-2091905
	.long	-2091905
	.long	-2091905
	.long	-2091905
	.long	-2091905
	.long	-2091905
	.long	-2091905
	.long	-2091905
	.align 32
.LC27:
	.long	1806278032
	.long	1806278032
	.long	1806278032
	.long	1806278032
	.long	1806278032
	.long	1806278032
	.long	1806278032
	.long	1806278032
	.align 32
.LC28:
	.long	-549488
	.long	-549488
	.long	-549488
	.long	-549488
	.long	-549488
	.long	-549488
	.long	-549488
	.long	-549488
	.align 32
.LC29:
	.long	222489248
	.long	222489248
	.long	222489248
	.long	222489248
	.long	222489248
	.long	222489248
	.long	222489248
	.long	222489248
	.align 32
.LC30:
	.long	-1119584
	.long	-1119584
	.long	-1119584
	.long	-1119584
	.long	-1119584
	.long	-1119584
	.long	-1119584
	.long	-1119584
	.align 32
.LC31:
	.long	-346752664
	.long	-346752664
	.long	-346752664
	.long	-346752664
	.long	-346752664
	.long	-346752664
	.long	-346752664
	.long	-346752664
	.align 32
.LC32:
	.long	2619752
	.long	2619752
	.long	2619752
	.long	2619752
	.long	2619752
	.long	2619752
	.long	2619752
	.long	2619752
	.align 32
.LC33:
	.long	684667771
	.long	684667771
	.long	684667771
	.long	684667771
	.long	684667771
	.long	684667771
	.long	684667771
	.long	684667771
	.align 32
.LC34:
	.long	-2108549
	.long	-2108549
	.long	-2108549
	.long	-2108549
	.long	-2108549
	.long	-2108549
	.long	-2108549
	.long	-2108549
	.align 32
.LC35:
	.long	1612161320
	.long	1612161320
	.long	1612161320
	.long	1612161320
	.long	1612161320
	.long	1612161320
	.long	1612161320
	.long	1612161320
	.align 32
.LC36:
	.long	-876248
	.long	-876248
	.long	-876248
	.long	-876248
	.long	-876248
	.long	-876248
	.long	-876248
	.long	-876248
	.align 32
.LC37:
	.long	-1929495947
	.long	-1929495947
	.long	-1929495947
	.long	-1929495947
	.long	-1929495947
	.long	-1929495947
	.long	-1929495947
	.long	-1929495947
	.align 32
.LC38:
	.long	3119733
	.long	3119733
	.long	3119733
	.long	3119733
	.long	3119733
	.long	3119733
	.long	3119733
	.long	3119733
	.align 32
.LC39:
	.long	515185417
	.long	515185417
	.long	515185417
	.long	515185417
	.long	515185417
	.long	515185417
	.long	515185417
	.long	515185417
	.align 32
.LC40:
	.long	-2884855
	.long	-2884855
	.long	-2884855
	.long	-2884855
	.long	-2884855
	.long	-2884855
	.long	-2884855
	.long	-2884855
	.align 32
.LC41:
	.long	1654287830
	.long	1654287830
	.long	1654287830
	.long	1654287830
	.long	1654287830
	.long	1654287830
	.long	1654287830
	.long	1654287830
	.align 32
.LC42:
	.long	-2118186
	.long	-2118186
	.long	-2118186
	.long	-2118186
	.long	-2118186
	.long	-2118186
	.long	-2118186
	.long	-2118186
	.align 32
.LC43:
	.long	-878576921
	.long	-878576921
	.long	-878576921
	.long	-878576921
	.long	-878576921
	.long	-878576921
	.long	-878576921
	.long	-878576921
	.align 32
.LC44:
	.long	-3859737
	.long	-3859737
	.long	-3859737
	.long	-3859737
	.long	-3859737
	.long	-3859737
	.long	-3859737
	.long	-3859737
	.align 32
.LC45:
	.long	-1257667337
	.long	-1257667337
	.long	-1257667337
	.long	-1257667337
	.long	-1257667337
	.long	-1257667337
	.long	-1257667337
	.long	-1257667337
	.align 32
.LC46:
	.long	-1399561
	.long	-1399561
	.long	-1399561
	.long	-1399561
	.long	-1399561
	.long	-1399561
	.long	-1399561
	.long	-1399561
	.align 32
.LC47:
	.long	-748618600
	.long	-748618600
	.long	-748618600
	.long	-748618600
	.long	-748618600
	.long	-748618600
	.long	-748618600
	.long	-748618600
	.align 32
.LC48:
	.long	-3277672
	.long	-3277672
	.long	-3277672
	.long	-3277672
	.long	-3277672
	.long	-3277672
	.long	-3277672
	.long	-3277672
	.align 32
.LC49:
	.long	1640734244
	.long	1640734244
	.long	1640734244
	.long	1640734244
	.long	1640734244
	.long	1640734244
	.long	1640734244
	.long	1640734244
	.align 32
.LC50:
	.long	466468
	.long	466468
	.long	466468
	.long	466468
	.long	466468
	.long	466468
	.long	466468
	.long	466468
	.align 32
.LC51:
	.long	-285697463
	.long	-285697463
	.long	-285697463
	.long	-285697463
	.long	-285697463
	.long	-285697463
	.long	-285697463
	.long	-285697463
	.align 32
.LC52:
	.long	3111497
	.long	3111497
	.long	3111497
	.long	3111497
	.long	3111497
	.long	3111497
	.long	3111497
	.long	3111497
	.align 32
.LC53:
	.long	625853735
	.long	625853735
	.long	625853735
	.long	625853735
	.long	625853735
	.long	625853735
	.long	625853735
	.long	625853735
	.align 32
.LC54:
	.long	2680103
	.long	2680103
	.long	2680103
	.long	2680103
	.long	2680103
	.long	2680103
	.long	2680103
	.long	2680103
	.align 32
.LC55:
	.long	329347125
	.long	329347125
	.long	329347125
	.long	329347125
	.long	329347125
	.long	329347125
	.long	329347125
	.long	329347125
	.align 32
.LC56:
	.long	1757237
	.long	1757237
	.long	1757237
	.long	1757237
	.long	1757237
	.long	1757237
	.long	1757237
	.long	1757237
	.align 32
.LC57:
	.long	1837364258
	.long	1837364258
	.long	1837364258
	.long	1837364258
	.long	1837364258
	.long	1837364258
	.long	1837364258
	.long	1837364258
	.align 32
.LC58:
	.long	-19422
	.long	-19422
	.long	-19422
	.long	-19422
	.long	-19422
	.long	-19422
	.long	-19422
	.long	-19422
	.align 32
.LC59:
	.long	-1443016191
	.long	-1443016191
	.long	-1443016191
	.long	-1443016191
	.long	-1443016191
	.long	-1443016191
	.long	-1443016191
	.long	-1443016191
	.align 32
.LC60:
	.long	4010497
	.long	4010497
	.long	4010497
	.long	4010497
	.long	4010497
	.long	4010497
	.long	4010497
	.long	4010497
	.align 32
.LC61:
	.long	-1170414139
	.long	-1170414139
	.long	-1170414139
	.long	-1170414139
	.long	-1170414139
	.long	-1170414139
	.long	-1170414139
	.long	-1170414139
	.align 32
.LC62:
	.long	280005
	.long	280005
	.long	280005
	.long	280005
	.long	280005
	.long	280005
	.long	280005
	.long	280005
	.align 32
.LC63:
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.set	.LC64,.LC2
	.align 32
.LC65:
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417

.text
	.p2align 4
	.globl	ml_dsa_avx_ntt_inverse_so_impl
	.type	ml_dsa_avx_ntt_inverse_so_impl, @function
ml_dsa_avx_ntt_inverse_so_impl:
.iLFB5823:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	andq	$-32, %rsp
	subq	$744, %rsp
	leaq	inv_qdata(%rip), %rax
	vmovdqu	(%rdi), %ymm2
	vpsubd	32(%rdi), %ymm2, %ymm0
	vmovdqu	32(%rdi), %ymm2
	vmovdqu	512(%rax), %ymm4
	vpaddd	(%rdi), %ymm2, %ymm3
	vpmuldq	512(%rax), %ymm0, %ymm5
	vmovdqu	(%rax), %ymm6
	vpsrlq	$32, %ymm0, %ymm2
	vpsrlq	$32, %ymm4, %ymm1
	vpmuldq	(%rax), %ymm0, %ymm4
	vpmuldq	%ymm1, %ymm2, %ymm1
	vpsrlq	$32, %ymm6, %ymm0
	vmovdqu	32(%rax), %ymm6
	vpmuldq	%ymm0, %ymm2, %ymm2
	vmovdqa	.iLC0(%rip), %ymm0
	vpsrlq	$32, %ymm6, %ymm6
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpmuldq	%ymm1, %ymm0, %ymm1
	vpsubd	%ymm5, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm1, %ymm2, %ymm2
	vpsrlq	$32, %ymm3, %ymm1
	vpblendd	$170, %ymm2, %ymm4, %ymm4
	vmovdqu	64(%rdi), %ymm2
	vpsllq	$32, %ymm4, %ymm7
	vpblendd	$85, %ymm1, %ymm4, %ymm4
	vpsubd	96(%rdi), %ymm2, %ymm1
	vmovdqu	96(%rdi), %ymm2
	vpaddd	64(%rdi), %ymm2, %ymm5
	vpblendd	$170, %ymm7, %ymm3, %ymm7
	vmovdqu	544(%rax), %ymm2
	vpmuldq	544(%rax), %ymm1, %ymm8
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	32(%rax), %ymm1, %ymm1
	vpsrlq	$32, %ymm2, %ymm2
	vpmuldq	%ymm2, %ymm3, %ymm2
	vpmuldq	%ymm6, %ymm3, %ymm3
	vpmuldq	%ymm8, %ymm0, %ymm6
	vpmuldq	%ymm2, %ymm0, %ymm2
	vpsubd	%ymm6, %ymm1, %ymm1
	vpsrlq	$32, %ymm1, %ymm1
	vpsubd	%ymm2, %ymm3, %ymm3
	vmovdqu	128(%rdi), %ymm2
	vpsubd	160(%rdi), %ymm2, %ymm2
	vpmuldq	576(%rax), %ymm2, %ymm10
	vpblendd	$170, %ymm3, %ymm1, %ymm1
	vmovdqu	160(%rdi), %ymm3
	vpaddd	128(%rdi), %ymm3, %ymm8
	vpsllq	$32, %ymm1, %ymm6
	vmovdqu	576(%rax), %ymm3
	vpsrlq	$32, %ymm2, %ymm9
	vpblendd	$170, %ymm6, %ymm5, %ymm6
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm5
	vpmuldq	64(%rax), %ymm2, %ymm3
	vmovdqu	64(%rax), %ymm2
	vpmuldq	%ymm5, %ymm9, %ymm5
	vpsrlq	$32, %ymm2, %ymm2
	vpmuldq	%ymm2, %ymm9, %ymm9
	vpmuldq	%ymm5, %ymm0, %ymm2
	vpmuldq	%ymm10, %ymm0, %ymm5
	vpsubd	%ymm5, %ymm3, %ymm3
	vpsubd	%ymm2, %ymm9, %ymm9
	vmovdqu	192(%rdi), %ymm2
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	224(%rdi), %ymm2, %ymm2
	vmovdqu	224(%rdi), %ymm5
	vpmuldq	608(%rax), %ymm2, %ymm11
	vpblendd	$170, %ymm9, %ymm3, %ymm3
	vmovdqu	96(%rax), %ymm15
	vpaddd	192(%rdi), %ymm5, %ymm10
	vpsllq	$32, %ymm3, %ymm9
	vmovdqu	608(%rax), %ymm5
	vpmuldq	%ymm11, %ymm0, %ymm11
	leaq	inte_data2(%rip), %rdx
	vpblendd	$170, %ymm9, %ymm8, %ymm9
	vpsrlq	$32, %ymm8, %ymm8
	vpsrlq	$32, %ymm5, %ymm5
	vpsrlq	$32, %ymm15, %ymm12
	vpblendd	$85, %ymm8, %ymm3, %ymm3
	vpsrlq	$32, %ymm2, %ymm8
	vpmuldq	96(%rax), %ymm2, %ymm2
	vpmuldq	%ymm5, %ymm8, %ymm5
	vpmuldq	%ymm12, %ymm8, %ymm8
	vmovdqu	1024(%rax), %ymm12
	vpsubd	%ymm11, %ymm2, %ymm2
	vpsrlq	$32, %ymm2, %ymm2
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm5, %ymm8, %ymm8
	vpsubd	%ymm4, %ymm7, %ymm5
	vpblendd	$170, %ymm8, %ymm2, %ymm2
	vpaddd	%ymm4, %ymm7, %ymm4
	vpsllq	$32, %ymm2, %ymm8
	vpsrlq	$32, %ymm5, %ymm7
	vpblendd	$170, %ymm8, %ymm10, %ymm8
	vpsrlq	$32, %ymm10, %ymm10
	vpblendd	$85, %ymm10, %ymm2, %ymm2
	vpsrlq	$32, %ymm12, %ymm10
	vpmuldq	%ymm5, %ymm10, %ymm11
	vpmuldq	%ymm10, %ymm7, %ymm10
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm12, %ymm7, %ymm7
	vmovdqu	1056(%rax), %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm7, %ymm7
	vpsrlq	$32, %ymm12, %ymm10
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm7, %ymm5, %ymm5
	vpunpcklqdq	%ymm5, %ymm4, %ymm7
	vpunpckhqdq	%ymm5, %ymm4, %ymm4
	vpsubd	%ymm1, %ymm6, %ymm5
	vpmuldq	%ymm5, %ymm10, %ymm11
	vpaddd	%ymm1, %ymm6, %ymm1
	vpsrlq	$32, %ymm5, %ymm6
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm10, %ymm6, %ymm10
	vpmuldq	%ymm12, %ymm6, %ymm6
	vmovdqu	1088(%rax), %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm6, %ymm5, %ymm5
	vpunpcklqdq	%ymm5, %ymm1, %ymm6
	vpunpckhqdq	%ymm5, %ymm1, %ymm1
	vpsubd	%ymm3, %ymm9, %ymm5
	vpmuldq	%ymm5, %ymm10, %ymm11
	vpaddd	%ymm3, %ymm9, %ymm3
	vpsrlq	$32, %ymm5, %ymm9
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm10, %ymm9, %ymm10
	vpmuldq	%ymm12, %ymm9, %ymm9
	vmovdqu	1120(%rax), %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm9, %ymm9
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm9, %ymm5, %ymm5
	vpunpcklqdq	%ymm5, %ymm3, %ymm9
	vpunpckhqdq	%ymm5, %ymm3, %ymm3
	vpsubd	%ymm2, %ymm8, %ymm5
	vpmuldq	%ymm5, %ymm10, %ymm11
	vpaddd	%ymm2, %ymm8, %ymm2
	vpsrlq	$32, %ymm5, %ymm8
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm10, %ymm8, %ymm10
	vpmuldq	%ymm12, %ymm8, %ymm8
	vmovdqu	1536(%rax), %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm8, %ymm8
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm8, %ymm5, %ymm5
	vpunpcklqdq	%ymm5, %ymm2, %ymm8
	vpunpckhqdq	%ymm5, %ymm2, %ymm2
	vpsubd	%ymm4, %ymm7, %ymm5
	vpmuldq	%ymm5, %ymm10, %ymm11
	vpaddd	%ymm7, %ymm4, %ymm4
	vpsrlq	$32, %ymm5, %ymm7
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm10, %ymm7, %ymm10
	vpmuldq	%ymm12, %ymm7, %ymm7
	vmovdqu	1568(%rax), %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm7, %ymm7
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm7, %ymm5, %ymm5
	vperm2i128	$32, %ymm5, %ymm4, %ymm7
	vperm2i128	$49, %ymm5, %ymm4, %ymm4
	vpsubd	%ymm1, %ymm6, %ymm5
	vpmuldq	%ymm5, %ymm10, %ymm11
	vpaddd	%ymm6, %ymm1, %ymm1
	vpsrlq	$32, %ymm5, %ymm6
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm10, %ymm6, %ymm10
	vpmuldq	%ymm12, %ymm6, %ymm6
	vmovdqu	1600(%rax), %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsrlq	$32, %ymm12, %ymm11
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm6, %ymm6
	vpblendd	$170, %ymm6, %ymm5, %ymm5
	vperm2i128	$32, %ymm5, %ymm1, %ymm6
	vperm2i128	$49, %ymm5, %ymm1, %ymm1
	vpsubd	%ymm3, %ymm9, %ymm5
	vpsrlq	$32, %ymm5, %ymm10
	vpaddd	%ymm9, %ymm3, %ymm9
	vpmuldq	%ymm5, %ymm11, %ymm3
	vpmuldq	%ymm11, %ymm10, %ymm11
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm12, %ymm10, %ymm10
	vmovdqu	1632(%rax), %ymm12
	vpmuldq	%ymm3, %ymm0, %ymm3
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm3, %ymm5, %ymm5
	vpsubd	%ymm11, %ymm10, %ymm10
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm10, %ymm5, %ymm5
	vpsrlq	$32, %ymm12, %ymm10
	vperm2i128	$32, %ymm5, %ymm9, %ymm11
	vperm2i128	$49, %ymm5, %ymm9, %ymm9
	vpsubd	%ymm2, %ymm8, %ymm5
	vpsrlq	$32, %ymm5, %ymm3
	vpaddd	%ymm8, %ymm2, %ymm2
	vpmuldq	%ymm5, %ymm10, %ymm8
	vpmuldq	%ymm10, %ymm3, %ymm10
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm12, %ymm3, %ymm3
	vpbroadcastq	(%rdx), %ymm12
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm8, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm3, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm7, %ymm3
	vpaddd	%ymm7, %ymm4, %ymm7
	vperm2i128	$32, %ymm5, %ymm2, %ymm8
	vpsrlq	$32, %ymm3, %ymm4
	vperm2i128	$49, %ymm5, %ymm2, %ymm2
	vpsrlq	$32, %ymm12, %ymm5
	vpmuldq	%ymm3, %ymm5, %ymm10
	vpmuldq	%ymm5, %ymm4, %ymm5
	vpmuldq	%ymm12, %ymm3, %ymm3
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpbroadcastq	8(%rdx), %ymm12
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsubd	%ymm5, %ymm4, %ymm4
	vpsrlq	$32, %ymm12, %ymm5
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vpsubd	%ymm1, %ymm6, %ymm4
	vpaddd	%ymm6, %ymm1, %ymm1
	vpmuldq	%ymm4, %ymm5, %ymm10
	vpsrlq	$32, %ymm4, %ymm6
	vpmuldq	%ymm5, %ymm6, %ymm13
	vpmuldq	%ymm12, %ymm4, %ymm5
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpbroadcastq	16(%rdx), %ymm12
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm13, %ymm0, %ymm4
	vpsubd	%ymm10, %ymm5, %ymm5
	vpsrlq	$32, %ymm12, %ymm10
	vpsubd	%ymm4, %ymm6, %ymm6
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm11, %ymm4
	vpblendd	$170, %ymm6, %ymm5, %ymm5
	vpsrlq	$32, %ymm4, %ymm6
	vpaddd	%ymm11, %ymm9, %ymm9
	vpmuldq	%ymm4, %ymm10, %ymm11
	vpmuldq	%ymm10, %ymm6, %ymm10
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpbroadcastq	24(%rdx), %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm11, %ymm4, %ymm4
	vpsubd	%ymm10, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm10
	vpsrlq	$32, %ymm4, %ymm4
	vpblendd	$170, %ymm6, %ymm4, %ymm11
	vpsubd	%ymm2, %ymm8, %ymm6
	vpaddd	%ymm8, %ymm2, %ymm2
	vpsrlq	$32, %ymm6, %ymm4
	vpmuldq	%ymm6, %ymm10, %ymm8
	vpmuldq	%ymm10, %ymm4, %ymm10
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpbroadcastq	32(%rdx), %ymm12
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm8, %ymm6, %ymm6
	vpsubd	%ymm1, %ymm7, %ymm8
	vpsubd	%ymm10, %ymm4, %ymm4
	vpsrlq	$32, %ymm6, %ymm6
	vpaddd	%ymm7, %ymm1, %ymm10
	vpblendd	$170, %ymm4, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm4
	vpmuldq	%ymm8, %ymm4, %ymm7
	vpsrlq	$32, %ymm8, %ymm1
	vpmuldq	%ymm4, %ymm1, %ymm13
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm12, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpsubd	%ymm7, %ymm8, %ymm8
	vpsubd	%ymm13, %ymm1, %ymm1
	vpsrlq	$32, %ymm8, %ymm8
	vpblendd	$170, %ymm1, %ymm8, %ymm8
	vpsubd	%ymm5, %ymm3, %ymm1
	vpaddd	%ymm5, %ymm3, %ymm3
	vpmuldq	%ymm1, %ymm4, %ymm13
	vpsrlq	$32, %ymm1, %ymm5
	vpmuldq	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm12, %ymm1, %ymm7
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpbroadcastq	40(%rdx), %ymm12
	vpsrlq	$32, %ymm12, %ymm1
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm13, %ymm7, %ymm7
	vpsubd	%ymm2, %ymm9, %ymm13
	vpsubd	%ymm4, %ymm5, %ymm5
	vpsrlq	$32, %ymm7, %ymm7
	vpaddd	%ymm9, %ymm2, %ymm2
	vpsrlq	$32, %ymm13, %ymm4
	vpmuldq	%ymm12, %ymm13, %ymm9
	vpblendd	$170, %ymm5, %ymm7, %ymm7
	vpmuldq	%ymm13, %ymm1, %ymm5
	vpmuldq	%ymm1, %ymm4, %ymm14
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpmuldq	%ymm14, %ymm0, %ymm13
	vpsubd	%ymm5, %ymm9, %ymm9
	vpsubd	%ymm13, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm11, %ymm5
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm2, %ymm10, %ymm13
	vpblendd	$170, %ymm4, %ymm9, %ymm9
	vpaddd	%ymm6, %ymm11, %ymm4
	vpaddd	%ymm10, %ymm2, %ymm2
	vpmuldq	%ymm5, %ymm1, %ymm11
	vpsrlq	$32, %ymm5, %ymm6
	vpmuldq	%ymm1, %ymm6, %ymm1
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm1, %ymm0, %ymm1
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsrlq	$32, %ymm13, %ymm11
	vpsubd	%ymm1, %ymm6, %ymm6
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm6, %ymm5, %ymm5
	vpbroadcastq	48(%rdx), %ymm6
	vpsrlq	$32, %ymm6, %ymm1
	vpmuldq	%ymm6, %ymm13, %ymm10
	vpmuldq	%ymm13, %ymm1, %ymm12
	vpmuldq	%ymm1, %ymm11, %ymm14
	vpmuldq	%ymm6, %ymm11, %ymm11
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm13
	vpsubd	%ymm12, %ymm10, %ymm10
	vpsubd	%ymm13, %ymm11, %ymm11
	vpsrlq	$32, %ymm10, %ymm10
	vpaddd	%ymm3, %ymm4, %ymm13
	vpblendd	$170, %ymm11, %ymm10, %ymm15
	vpsubd	%ymm4, %ymm3, %ymm11
	vpmuldq	%ymm11, %ymm1, %ymm10
	vpsrlq	$32, %ymm11, %ymm4
	vmovdqa	%ymm15, 392(%rsp)
	vpmuldq	%ymm1, %ymm4, %ymm12
	vpmuldq	%ymm6, %ymm11, %ymm3
	vpmuldq	%ymm6, %ymm4, %ymm4
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm12, %ymm0, %ymm11
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm11, %ymm4, %ymm4
	vpblendd	$170, %ymm4, %ymm3, %ymm4
	vpsubd	%ymm9, %ymm8, %ymm3
	vpaddd	%ymm9, %ymm8, %ymm9
	vmovdqa	%ymm4, 360(%rsp)
	vpmuldq	%ymm3, %ymm1, %ymm8
	vpsrlq	$32, %ymm3, %ymm4
	vmovdqa	%ymm9, 424(%rsp)
	vpmuldq	%ymm1, %ymm4, %ymm9
	vpmuldq	%ymm6, %ymm3, %ymm3
	vpmuldq	%ymm6, %ymm4, %ymm4
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpsubd	%ymm8, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm4, %ymm4
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm4, %ymm3, %ymm3
	vmovdqa	%ymm3, 328(%rsp)
	vpsubd	%ymm5, %ymm7, %ymm3
	vpaddd	%ymm5, %ymm7, %ymm7
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm3, %ymm1, %ymm5
	vmovdqa	%ymm7, 456(%rsp)
	vpmuldq	%ymm1, %ymm4, %ymm1
	vpmuldq	%ymm6, %ymm3, %ymm3
	vpmuldq	%ymm6, %ymm4, %ymm4
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpmuldq	%ymm1, %ymm0, %ymm1
	vpsubd	%ymm5, %ymm3, %ymm3
	vmovdqu	256(%rdi), %ymm5
	vpsubd	288(%rdi), %ymm5, %ymm5
	vpsubd	%ymm1, %ymm4, %ymm4
	vpsrlq	$32, %ymm3, %ymm3
	vmovdqu	288(%rdi), %ymm1
	vpblendd	$170, %ymm4, %ymm3, %ymm6
	vpaddd	256(%rdi), %ymm1, %ymm3
	vmovdqa	%ymm6, 296(%rsp)
	vpsrlq	$32, %ymm5, %ymm7
	vpmuldq	640(%rax), %ymm5, %ymm6
	vmovdqu	640(%rax), %ymm1
	vmovdqu	128(%rax), %ymm11
	vpmuldq	%ymm6, %ymm0, %ymm6
	vpmuldq	128(%rax), %ymm5, %ymm5
	vmovdqu	704(%rax), %ymm14
	vpsrlq	$32, %ymm1, %ymm1
	vpmuldq	%ymm1, %ymm7, %ymm1
	vpsrlq	$32, %ymm11, %ymm4
	vmovdqu	352(%rdi), %ymm11
	vpmuldq	%ymm4, %ymm7, %ymm4
	vpsubd	%ymm6, %ymm5, %ymm5
	vpaddd	320(%rdi), %ymm11, %ymm6
	vmovdqu	672(%rax), %ymm11
	vpsrlq	$32, %ymm5, %ymm5
	vpmuldq	%ymm1, %ymm0, %ymm1
	vpsubd	%ymm1, %ymm4, %ymm4
	vmovdqu	320(%rdi), %ymm1
	vpsubd	352(%rdi), %ymm1, %ymm1
	vpmuldq	672(%rax), %ymm1, %ymm7
	vpblendd	$170, %ymm4, %ymm5, %ymm5
	vpsrlq	$32, %ymm11, %ymm4
	vmovdqu	160(%rax), %ymm11
	vpsrlq	$32, %ymm1, %ymm8
	vpsllq	$32, %ymm5, %ymm9
	vpmuldq	160(%rax), %ymm1, %ymm1
	vpmuldq	%ymm4, %ymm8, %ymm4
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpblendd	$170, %ymm9, %ymm3, %ymm9
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm5, %ymm5
	vpsrlq	$32, %ymm11, %ymm3
	vmovdqu	384(%rdi), %ymm11
	vpmuldq	%ymm3, %ymm8, %ymm3
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm7, %ymm1, %ymm1
	vpsrlq	$32, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm3, %ymm3
	vpsubd	416(%rdi), %ymm11, %ymm4
	vmovdqu	416(%rdi), %ymm11
	vpmuldq	704(%rax), %ymm4, %ymm8
	vpblendd	$170, %ymm3, %ymm1, %ymm1
	vpaddd	384(%rdi), %ymm11, %ymm7
	vmovdqu	192(%rax), %ymm11
	vpsllq	$32, %ymm1, %ymm12
	vpsrlq	$32, %ymm4, %ymm10
	vpmuldq	192(%rax), %ymm4, %ymm4
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpsrlq	$32, %ymm11, %ymm3
	vpblendd	$170, %ymm12, %ymm6, %ymm12
	vmovdqu	480(%rdi), %ymm11
	vpsrlq	$32, %ymm6, %ymm6
	vpmuldq	%ymm3, %ymm10, %ymm3
	vpblendd	$85, %ymm6, %ymm1, %ymm1
	vpsrlq	$32, %ymm14, %ymm6
	vmovdqu	448(%rdi), %ymm14
	vpmuldq	%ymm6, %ymm10, %ymm6
	vpsubd	%ymm8, %ymm4, %ymm4
	vpaddd	%ymm14, %ymm11, %ymm8
	vpsrlq	$32, %ymm4, %ymm4
	vpmuldq	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsubd	480(%rdi), %ymm14, %ymm6
	vpmuldq	736(%rax), %ymm6, %ymm11
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpblendd	$170, %ymm3, %ymm4, %ymm4
	vmovdqu	736(%rax), %ymm3
	vpsllq	$32, %ymm4, %ymm10
	vpsrlq	$32, %ymm6, %ymm14
	vpmuldq	224(%rax), %ymm6, %ymm6
	vpblendd	$170, %ymm10, %ymm7, %ymm10
	vpsrlq	$32, %ymm7, %ymm7
	vpblendd	$85, %ymm7, %ymm4, %ymm4
	vpsrlq	$32, %ymm3, %ymm7
	vmovdqu	224(%rax), %ymm3
	vpmuldq	%ymm7, %ymm14, %ymm7
	vpsubd	%ymm11, %ymm6, %ymm6
	vpsrlq	$32, %ymm3, %ymm3
	vpsrlq	$32, %ymm6, %ymm6
	vpmuldq	%ymm3, %ymm14, %ymm3
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpsubd	%ymm7, %ymm3, %ymm3
	vpblendd	$170, %ymm3, %ymm6, %ymm3
	vpsubd	%ymm5, %ymm9, %ymm6
	vpaddd	%ymm5, %ymm9, %ymm9
	vpsllq	$32, %ymm3, %ymm11
	vpsrlq	$32, %ymm6, %ymm5
	vpblendd	$170, %ymm11, %ymm8, %ymm11
	vpsrlq	$32, %ymm8, %ymm8
	vpblendd	$85, %ymm8, %ymm3, %ymm3
	vmovdqu	1152(%rax), %ymm8
	vpsrlq	$32, %ymm8, %ymm7
	vpmuldq	%ymm6, %ymm7, %ymm14
	vpmuldq	%ymm7, %ymm5, %ymm7
	vpmuldq	%ymm8, %ymm6, %ymm6
	vpmuldq	%ymm8, %ymm5, %ymm5
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpsubd	%ymm14, %ymm6, %ymm6
	vmovdqu	1184(%rax), %ymm14
	vpsubd	%ymm7, %ymm5, %ymm5
	vpsrlq	$32, %ymm6, %ymm6
	vpsubd	%ymm1, %ymm12, %ymm7
	vpaddd	%ymm1, %ymm12, %ymm1
	vpblendd	$170, %ymm5, %ymm6, %ymm5
	vpsrlq	$32, %ymm14, %ymm8
	vpunpcklqdq	%ymm5, %ymm9, %ymm6
	vpmuldq	%ymm7, %ymm8, %ymm12
	vpunpckhqdq	%ymm5, %ymm9, %ymm9
	vpsrlq	$32, %ymm7, %ymm5
	vpmuldq	%ymm14, %ymm7, %ymm7
	vpmuldq	%ymm8, %ymm5, %ymm8
	vpmuldq	%ymm14, %ymm5, %ymm5
	vmovdqu	1216(%rax), %ymm14
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpsubd	%ymm12, %ymm7, %ymm7
	vpsrlq	$32, %ymm14, %ymm12
	vpsrlq	$32, %ymm7, %ymm7
	vpsubd	%ymm8, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm10, %ymm8
	vpblendd	$170, %ymm5, %ymm7, %ymm5
	vpaddd	%ymm4, %ymm10, %ymm4
	vpunpcklqdq	%ymm5, %ymm1, %ymm7
	vpmuldq	%ymm8, %ymm12, %ymm10
	vpunpckhqdq	%ymm5, %ymm1, %ymm1
	vpsrlq	$32, %ymm8, %ymm5
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm12, %ymm5, %ymm12
	vpmuldq	%ymm14, %ymm5, %ymm5
	vmovdqu	1248(%rax), %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm10, %ymm8, %ymm8
	vpsubd	%ymm3, %ymm11, %ymm10
	vpsrlq	$32, %ymm8, %ymm8
	vpaddd	%ymm3, %ymm11, %ymm3
	vpsubd	%ymm12, %ymm5, %ymm5
	vpsrlq	$32, %ymm14, %ymm12
	vpblendd	$170, %ymm5, %ymm8, %ymm5
	vpmuldq	%ymm10, %ymm12, %ymm11
	vpunpcklqdq	%ymm5, %ymm4, %ymm8
	vpunpckhqdq	%ymm5, %ymm4, %ymm4
	vpsrlq	$32, %ymm10, %ymm5
	vpmuldq	%ymm14, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm5, %ymm12
	vpmuldq	%ymm14, %ymm5, %ymm5
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm11, %ymm10, %ymm10
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm12, %ymm5, %ymm5
	vmovdqu	1664(%rax), %ymm12
	vpblendd	$170, %ymm5, %ymm10, %ymm10
	vpunpcklqdq	%ymm10, %ymm3, %ymm5
	vpsrlq	$32, %ymm12, %ymm11
	vpunpckhqdq	%ymm10, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm6, %ymm10
	vpaddd	%ymm6, %ymm9, %ymm9
	vpmuldq	%ymm10, %ymm11, %ymm14
	vpsrlq	$32, %ymm10, %ymm6
	vpmuldq	%ymm11, %ymm6, %ymm11
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm6, %ymm6
	vmovdqu	1696(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm6, %ymm6
	vpsrlq	$32, %ymm10, %ymm10
	vpblendd	$170, %ymm6, %ymm10, %ymm10
	vpsrlq	$32, %ymm12, %ymm11
	vperm2i128	$32, %ymm10, %ymm9, %ymm6
	vperm2i128	$49, %ymm10, %ymm9, %ymm9
	vpsubd	%ymm1, %ymm7, %ymm10
	vpmuldq	%ymm10, %ymm11, %ymm14
	vpaddd	%ymm7, %ymm1, %ymm1
	vpsrlq	$32, %ymm10, %ymm7
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm11, %ymm7, %ymm11
	vpmuldq	%ymm12, %ymm7, %ymm7
	vmovdqu	1728(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm10, %ymm10
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm7, %ymm7
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm7, %ymm10, %ymm10
	vperm2i128	$32, %ymm10, %ymm1, %ymm7
	vperm2i128	$49, %ymm10, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm8, %ymm10
	vpmuldq	%ymm10, %ymm11, %ymm14
	vpaddd	%ymm8, %ymm4, %ymm4
	vpsrlq	$32, %ymm10, %ymm8
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpmuldq	%ymm12, %ymm8, %ymm8
	vmovdqu	1760(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm10, %ymm10
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm8, %ymm8
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm8, %ymm10, %ymm8
	vperm2i128	$32, %ymm8, %ymm4, %ymm10
	vperm2i128	$49, %ymm8, %ymm4, %ymm4
	vpsubd	%ymm3, %ymm5, %ymm8
	vpmuldq	%ymm8, %ymm11, %ymm14
	vpaddd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm8, %ymm5
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm11, %ymm5, %ymm11
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpbroadcastq	56(%rdx), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm8, %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm5, %ymm8, %ymm5
	vperm2i128	$32, %ymm5, %ymm3, %ymm8
	vperm2i128	$49, %ymm5, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm6, %ymm5
	vpmuldq	%ymm5, %ymm11, %ymm14
	vpaddd	%ymm6, %ymm9, %ymm9
	vpsrlq	$32, %ymm5, %ymm6
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm11, %ymm6, %ymm11
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpbroadcastq	64(%rdx), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm11, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm6, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm7, %ymm6
	vpaddd	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm6, %ymm11, %ymm14
	vpsrlq	$32, %ymm6, %ymm7
	vpmuldq	%ymm11, %ymm7, %ymm11
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpbroadcastq	72(%rdx), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm6, %ymm6
	vpsubd	%ymm11, %ymm7, %ymm7
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm7, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm11
	vpsubd	%ymm4, %ymm10, %ymm7
	vpaddd	%ymm10, %ymm4, %ymm4
	vpsrlq	$32, %ymm7, %ymm10
	vpmuldq	%ymm7, %ymm11, %ymm14
	vpmuldq	%ymm11, %ymm10, %ymm11
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpmuldq	%ymm12, %ymm10, %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm11, %ymm12, %ymm10
	vpsubd	%ymm14, %ymm7, %ymm7
	vpbroadcastq	80(%rdx), %ymm12
	vpsrlq	$32, %ymm7, %ymm7
	vpblendd	$170, %ymm10, %ymm7, %ymm10
	vpsrlq	$32, %ymm12, %ymm11
	vpsubd	%ymm3, %ymm8, %ymm7
	vpmuldq	%ymm7, %ymm11, %ymm14
	vpaddd	%ymm8, %ymm3, %ymm3
	vpsrlq	$32, %ymm7, %ymm8
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm7, %ymm7
	vpbroadcastq	88(%rdx), %ymm14
	vpsrlq	$32, %ymm7, %ymm7
	vpsubd	%ymm11, %ymm8, %ymm8
	vpsrlq	$32, %ymm14, %ymm11
	vpblendd	$170, %ymm8, %ymm7, %ymm7
	vpsubd	%ymm1, %ymm9, %ymm8
	vpaddd	%ymm9, %ymm1, %ymm1
	vpsrlq	$32, %ymm8, %ymm12
	vpmuldq	%ymm8, %ymm11, %ymm9
	vpmuldq	%ymm11, %ymm12, %ymm15
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm12, %ymm12
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpsubd	%ymm9, %ymm8, %ymm9
	vpsubd	%ymm6, %ymm5, %ymm8
	vpsubd	%ymm15, %ymm12, %ymm12
	vpsrlq	$32, %ymm9, %ymm9
	vpaddd	%ymm6, %ymm5, %ymm5
	vpblendd	$170, %ymm12, %ymm9, %ymm9
	vpsrlq	$32, %ymm8, %ymm6
	vpmuldq	%ymm8, %ymm11, %ymm12
	vpmuldq	%ymm11, %ymm6, %ymm11
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm6, %ymm14
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm12, %ymm8, %ymm8
	vpbroadcastq	96(%rdx), %ymm12
	vpsubd	%ymm11, %ymm14, %ymm6
	vpsrlq	$32, %ymm8, %ymm8
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm6, %ymm8, %ymm6
	vpsubd	%ymm3, %ymm4, %ymm8
	vpmuldq	%ymm8, %ymm11, %ymm15
	vpaddd	%ymm4, %ymm3, %ymm3
	vpsrlq	$32, %ymm8, %ymm4
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm11, %ymm4, %ymm14
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm8, %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm14, %ymm4, %ymm4
	vpblendd	$170, %ymm4, %ymm8, %ymm14
	vpsubd	%ymm7, %ymm10, %ymm4
	vpaddd	%ymm7, %ymm10, %ymm7
	vpsrlq	$32, %ymm4, %ymm8
	vpmuldq	%ymm4, %ymm11, %ymm10
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm12, %ymm8, %ymm12
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm10, %ymm4, %ymm4
	vpbroadcastq	104(%rdx), %ymm10
	vpsubd	%ymm11, %ymm12, %ymm8
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm3, %ymm1, %ymm11
	vpblendd	$170, %ymm8, %ymm4, %ymm8
	vpsrlq	$32, %ymm10, %ymm4
	vpaddd	%ymm1, %ymm3, %ymm1
	vmovdqa	%ymm1, 616(%rsp)
	vpmuldq	%ymm11, %ymm4, %ymm12
	vpsrlq	$32, %ymm11, %ymm1
	vpmuldq	%ymm4, %ymm1, %ymm3
	vpmuldq	%ymm10, %ymm11, %ymm11
	vpmuldq	%ymm10, %ymm1, %ymm1
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpmuldq	%ymm3, %ymm0, %ymm3
	vpsubd	%ymm12, %ymm11, %ymm11
	vpsubd	%ymm3, %ymm1, %ymm1
	vpsrlq	$32, %ymm11, %ymm11
	vpblendd	$170, %ymm1, %ymm11, %ymm11
	vpsubd	%ymm7, %ymm5, %ymm1
	vpaddd	%ymm5, %ymm7, %ymm5
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	%ymm1, %ymm4, %ymm7
	vmovdqa	%ymm5, 648(%rsp)
	vpmuldq	%ymm4, %ymm3, %ymm5
	vpmuldq	%ymm10, %ymm1, %ymm1
	vmovdqa	%ymm11, 264(%rsp)
	vpmuldq	%ymm10, %ymm3, %ymm3
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm7, %ymm1, %ymm1
	vpsubd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm3, %ymm1, %ymm12
	vpsubd	%ymm14, %ymm9, %ymm1
	vpaddd	%ymm14, %ymm9, %ymm3
	vmovdqa	%ymm3, 680(%rsp)
	vpmuldq	%ymm1, %ymm4, %ymm7
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	%ymm4, %ymm3, %ymm5
	vpmuldq	%ymm10, %ymm1, %ymm1
	vmovdqa	%ymm12, 232(%rsp)
	vpmuldq	%ymm10, %ymm3, %ymm3
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm7, %ymm1, %ymm1
	vpsubd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm3, %ymm1, %ymm7
	vpsubd	%ymm8, %ymm6, %ymm1
	vpaddd	%ymm8, %ymm6, %ymm8
	vpmuldq	%ymm1, %ymm4, %ymm5
	vpsrlq	$32, %ymm1, %ymm3
	vmovdqa	%ymm7, 200(%rsp)
	vpmuldq	%ymm4, %ymm3, %ymm4
	vpmuldq	%ymm10, %ymm1, %ymm1
	vmovdqa	%ymm8, 712(%rsp)
	vpmuldq	%ymm10, %ymm3, %ymm3
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm5, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm1
	vmovdqu	512(%rdi), %ymm4
	vpblendd	$170, %ymm3, %ymm1, %ymm10
	vpsubd	544(%rdi), %ymm4, %ymm3
	vmovdqu	544(%rdi), %ymm4
	vpmuldq	768(%rax), %ymm3, %ymm6
	vpaddd	512(%rdi), %ymm4, %ymm5
	vpmuldq	%ymm6, %ymm0, %ymm6
	vmovdqu	768(%rax), %ymm4
	vmovdqa	%ymm10, 168(%rsp)
	vpsrlq	$32, %ymm3, %ymm7
	vmovdqu	256(%rax), %ymm1
	vpmuldq	256(%rax), %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm4
	vpmuldq	%ymm4, %ymm7, %ymm4
	vpsrlq	$32, %ymm1, %ymm1
	vpmuldq	%ymm1, %ymm7, %ymm1
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsrlq	$32, %ymm3, %ymm3
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm4, %ymm1, %ymm1
	vmovdqu	576(%rdi), %ymm4
	vpblendd	$170, %ymm1, %ymm3, %ymm6
	vpsubd	608(%rdi), %ymm4, %ymm3
	vmovdqu	608(%rdi), %ymm4
	vpaddd	576(%rdi), %ymm4, %ymm8
	vmovdqu	800(%rax), %ymm4
	vpsllq	$32, %ymm6, %ymm9
	vpsrlq	$32, %ymm3, %ymm7
	vpblendd	$170, %ymm9, %ymm5, %ymm9
	vpsrlq	$32, %ymm4, %ymm4
	vpsrlq	$32, %ymm5, %ymm5
	vpmuldq	%ymm4, %ymm7, %ymm4
	vpblendd	$85, %ymm5, %ymm6, %ymm6
	vpmuldq	800(%rax), %ymm3, %ymm5
	vpmuldq	288(%rax), %ymm3, %ymm3
	vmovdqu	288(%rax), %ymm1
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsrlq	$32, %ymm1, %ymm1
	vpmuldq	%ymm1, %ymm7, %ymm1
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm4, %ymm1, %ymm1
	vmovdqu	640(%rdi), %ymm4
	vpblendd	$170, %ymm1, %ymm3, %ymm5
	vpsubd	672(%rdi), %ymm4, %ymm3
	vmovdqu	672(%rdi), %ymm4
	vpmuldq	832(%rax), %ymm3, %ymm10
	vpsllq	$32, %ymm5, %ymm7
	vmovdqu	320(%rax), %ymm1
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpblendd	$170, %ymm7, %ymm8, %ymm7
	vpsrlq	$32, %ymm8, %ymm8
	vpsrlq	$32, %ymm3, %ymm11
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$85, %ymm8, %ymm5, %ymm5
	vpmuldq	320(%rax), %ymm3, %ymm3
	vpaddd	640(%rdi), %ymm4, %ymm8
	vmovdqu	832(%rax), %ymm4
	vpmuldq	%ymm1, %ymm11, %ymm1
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm10, %ymm3, %ymm3
	vpmuldq	%ymm4, %ymm11, %ymm4
	vpsrlq	$32, %ymm3, %ymm3
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm4, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm3, %ymm4
	vmovdqu	704(%rdi), %ymm1
	vpsubd	736(%rdi), %ymm1, %ymm3
	vpmuldq	864(%rax), %ymm3, %ymm11
	vmovdqu	736(%rdi), %ymm1
	vpsllq	$32, %ymm4, %ymm10
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpaddd	704(%rdi), %ymm1, %ymm12
	vmovdqu	864(%rax), %ymm1
	vpblendd	$170, %ymm10, %ymm8, %ymm10
	vpsrlq	$32, %ymm8, %ymm8
	vpsrlq	$32, %ymm3, %ymm14
	vpblendd	$85, %ymm8, %ymm4, %ymm4
	vpmuldq	352(%rax), %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm8
	vmovdqu	352(%rax), %ymm1
	vpmuldq	%ymm8, %ymm14, %ymm8
	vpsrlq	$32, %ymm1, %ymm1
	vpsubd	%ymm11, %ymm3, %ymm3
	vpmuldq	%ymm1, %ymm14, %ymm1
	vpsrlq	$32, %ymm3, %ymm3
	vmovdqu	1280(%rax), %ymm14
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpsubd	%ymm8, %ymm1, %ymm1
	vpsubd	%ymm6, %ymm9, %ymm8
	vpblendd	$170, %ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm8, %ymm1
	vpaddd	%ymm6, %ymm9, %ymm9
	vpsllq	$32, %ymm3, %ymm11
	vpblendd	$170, %ymm11, %ymm12, %ymm11
	vpsrlq	$32, %ymm12, %ymm12
	vpblendd	$85, %ymm12, %ymm3, %ymm3
	vpsrlq	$32, %ymm14, %ymm12
	vpmuldq	%ymm8, %ymm12, %ymm6
	vpmuldq	%ymm12, %ymm1, %ymm12
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm1, %ymm1
	vmovdqu	1312(%rax), %ymm14
	vpmuldq	%ymm6, %ymm0, %ymm6
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm6, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm1, %ymm1
	vpsrlq	$32, %ymm14, %ymm12
	vpsrlq	$32, %ymm8, %ymm8
	vpblendd	$170, %ymm1, %ymm8, %ymm1
	vpsubd	%ymm5, %ymm7, %ymm8
	vpunpcklqdq	%ymm1, %ymm9, %ymm6
	vpunpckhqdq	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm5, %ymm7, %ymm1
	vpmuldq	%ymm8, %ymm12, %ymm5
	vpsrlq	$32, %ymm8, %ymm7
	vpmuldq	%ymm12, %ymm7, %ymm12
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm7, %ymm7
	vmovdqu	1344(%rax), %ymm14
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm5, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm7, %ymm7
	vpsrlq	$32, %ymm8, %ymm8
	vpblendd	$170, %ymm7, %ymm8, %ymm5
	vpsrlq	$32, %ymm14, %ymm12
	vpsubd	%ymm4, %ymm10, %ymm8
	vpunpcklqdq	%ymm5, %ymm1, %ymm7
	vpaddd	%ymm4, %ymm10, %ymm4
	vpunpckhqdq	%ymm5, %ymm1, %ymm1
	vpmuldq	%ymm8, %ymm12, %ymm10
	vpsrlq	$32, %ymm8, %ymm5
	vpmuldq	%ymm12, %ymm5, %ymm12
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm5, %ymm5
	vmovdqu	1376(%rax), %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm10, %ymm8, %ymm8
	vpsubd	%ymm3, %ymm11, %ymm10
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm5, %ymm5
	vpaddd	%ymm3, %ymm11, %ymm3
	vpblendd	$170, %ymm5, %ymm8, %ymm5
	vpsrlq	$32, %ymm14, %ymm12
	vpunpcklqdq	%ymm5, %ymm4, %ymm8
	vpmuldq	%ymm10, %ymm12, %ymm11
	vpunpckhqdq	%ymm5, %ymm4, %ymm4
	vpsrlq	$32, %ymm10, %ymm5
	vpmuldq	%ymm14, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm5, %ymm12
	vpmuldq	%ymm14, %ymm5, %ymm5
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm11, %ymm10, %ymm10
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm12, %ymm5, %ymm5
	vmovdqu	1792(%rax), %ymm12
	vpblendd	$170, %ymm5, %ymm10, %ymm10
	vpunpcklqdq	%ymm10, %ymm3, %ymm5
	vpsrlq	$32, %ymm12, %ymm11
	vpunpckhqdq	%ymm10, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm6, %ymm10
	vpaddd	%ymm6, %ymm9, %ymm9
	vpmuldq	%ymm10, %ymm11, %ymm14
	vpsrlq	$32, %ymm10, %ymm6
	vpmuldq	%ymm11, %ymm6, %ymm11
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm6, %ymm6
	vmovdqu	1824(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm6, %ymm6
	vpsrlq	$32, %ymm10, %ymm10
	vpblendd	$170, %ymm6, %ymm10, %ymm10
	vpsrlq	$32, %ymm12, %ymm11
	vperm2i128	$32, %ymm10, %ymm9, %ymm6
	vperm2i128	$49, %ymm10, %ymm9, %ymm9
	vpsubd	%ymm1, %ymm7, %ymm10
	vpmuldq	%ymm10, %ymm11, %ymm14
	vpaddd	%ymm7, %ymm1, %ymm1
	vpsrlq	$32, %ymm10, %ymm7
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm11, %ymm7, %ymm11
	vpmuldq	%ymm12, %ymm7, %ymm7
	vmovdqu	1856(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm10, %ymm10
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm7, %ymm7
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm7, %ymm10, %ymm10
	vperm2i128	$32, %ymm10, %ymm1, %ymm7
	vperm2i128	$49, %ymm10, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm8, %ymm10
	vpmuldq	%ymm10, %ymm11, %ymm14
	vpaddd	%ymm8, %ymm4, %ymm4
	vpsrlq	$32, %ymm10, %ymm8
	vpmuldq	%ymm12, %ymm10, %ymm10
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpmuldq	%ymm12, %ymm8, %ymm8
	vmovdqu	1888(%rax), %ymm12
	movq	%rdx, %rax
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm10, %ymm10
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm11, %ymm8, %ymm8
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm8, %ymm10, %ymm8
	vperm2i128	$32, %ymm8, %ymm4, %ymm10
	vperm2i128	$49, %ymm8, %ymm4, %ymm4
	vpsubd	%ymm3, %ymm5, %ymm8
	vpmuldq	%ymm8, %ymm11, %ymm14
	vpaddd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm8, %ymm5
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm11, %ymm5, %ymm11
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpbroadcastq	112(%rdx), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm8, %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm11, %ymm5, %ymm5
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm5, %ymm8, %ymm5
	vperm2i128	$32, %ymm5, %ymm3, %ymm8
	vperm2i128	$49, %ymm5, %ymm3, %ymm3
	vpsubd	%ymm9, %ymm6, %ymm5
	vpmuldq	%ymm5, %ymm11, %ymm14
	vpaddd	%ymm6, %ymm9, %ymm9
	vpsrlq	$32, %ymm5, %ymm6
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm11, %ymm6, %ymm11
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpbroadcastq	120(%rdx), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm5, %ymm5
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm11, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm6, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm7, %ymm6
	vpaddd	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm6, %ymm11, %ymm14
	vpsrlq	$32, %ymm6, %ymm7
	vpmuldq	%ymm11, %ymm7, %ymm11
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpbroadcastq	128(%rdx), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm6, %ymm6
	vpsubd	%ymm11, %ymm7, %ymm7
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm7, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm11
	vpsubd	%ymm4, %ymm10, %ymm7
	vpaddd	%ymm10, %ymm4, %ymm4
	vpsrlq	$32, %ymm7, %ymm10
	vpmuldq	%ymm7, %ymm11, %ymm14
	vpmuldq	%ymm11, %ymm10, %ymm11
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpmuldq	%ymm12, %ymm10, %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm11, %ymm12, %ymm10
	vpsubd	%ymm14, %ymm7, %ymm7
	vpbroadcastq	136(%rdx), %ymm12
	vpsrlq	$32, %ymm7, %ymm7
	vpblendd	$170, %ymm10, %ymm7, %ymm10
	vpsrlq	$32, %ymm12, %ymm11
	vpsubd	%ymm3, %ymm8, %ymm7
	vpmuldq	%ymm7, %ymm11, %ymm14
	vpaddd	%ymm8, %ymm3, %ymm3
	vpsrlq	$32, %ymm7, %ymm8
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm14, %ymm7, %ymm7
	vpbroadcastq	144(%rdx), %ymm14
	vpsrlq	$32, %ymm7, %ymm7
	vpsubd	%ymm11, %ymm8, %ymm8
	vpsrlq	$32, %ymm14, %ymm11
	vpblendd	$170, %ymm8, %ymm7, %ymm7
	vpsubd	%ymm1, %ymm9, %ymm8
	vpaddd	%ymm9, %ymm1, %ymm1
	vpsrlq	$32, %ymm8, %ymm12
	vpmuldq	%ymm8, %ymm11, %ymm9
	vpmuldq	%ymm11, %ymm12, %ymm15
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm12, %ymm12
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpsubd	%ymm9, %ymm8, %ymm9
	vpsubd	%ymm6, %ymm5, %ymm8
	vpsubd	%ymm15, %ymm12, %ymm12
	vpsrlq	$32, %ymm9, %ymm9
	vpaddd	%ymm6, %ymm5, %ymm5
	vpblendd	$170, %ymm12, %ymm9, %ymm9
	vpsrlq	$32, %ymm8, %ymm6
	vpmuldq	%ymm8, %ymm11, %ymm12
	vpmuldq	%ymm11, %ymm6, %ymm11
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm6, %ymm14
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm12, %ymm8, %ymm8
	vpsubd	%ymm11, %ymm14, %ymm6
	vpbroadcastq	152(%rdx), %ymm12
	vpsrlq	$32, %ymm8, %ymm8
	vpsrlq	$32, %ymm12, %ymm11
	vpblendd	$170, %ymm6, %ymm8, %ymm6
	vpsubd	%ymm3, %ymm4, %ymm8
	vpmuldq	%ymm8, %ymm11, %ymm15
	vpaddd	%ymm4, %ymm3, %ymm3
	vpsrlq	$32, %ymm8, %ymm4
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm11, %ymm4, %ymm14
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm8, %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm14, %ymm4, %ymm4
	vpblendd	$170, %ymm4, %ymm8, %ymm14
	vpsubd	%ymm7, %ymm10, %ymm4
	vpaddd	%ymm7, %ymm10, %ymm7
	vpsrlq	$32, %ymm4, %ymm8
	vpmuldq	%ymm4, %ymm11, %ymm10
	vpmuldq	%ymm11, %ymm8, %ymm11
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm12, %ymm8, %ymm12
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm10, %ymm4, %ymm4
	vpbroadcastq	160(%rdx), %ymm10
	leaq	inv_qdata(%rip), %rdx
	vpsubd	%ymm11, %ymm12, %ymm8
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm3, %ymm1, %ymm11
	vpblendd	$170, %ymm8, %ymm4, %ymm8
	vpsrlq	$32, %ymm10, %ymm4
	vpaddd	%ymm1, %ymm3, %ymm1
	vmovdqa	%ymm1, 488(%rsp)
	vpmuldq	%ymm11, %ymm4, %ymm12
	vpsrlq	$32, %ymm11, %ymm1
	vpmuldq	%ymm4, %ymm1, %ymm3
	vpmuldq	%ymm10, %ymm11, %ymm11
	vpmuldq	%ymm10, %ymm1, %ymm1
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpmuldq	%ymm3, %ymm0, %ymm3
	vpsubd	%ymm12, %ymm11, %ymm11
	vpaddd	%ymm5, %ymm7, %ymm12
	vpsubd	%ymm3, %ymm1, %ymm1
	vpsrlq	$32, %ymm11, %ymm11
	vmovdqa	%ymm12, 520(%rsp)
	vmovdqu	960(%rdx), %ymm12
	vpblendd	$170, %ymm1, %ymm11, %ymm11
	vpsubd	%ymm7, %ymm5, %ymm1
	vpmuldq	%ymm1, %ymm4, %ymm7
	vpsrlq	$32, %ymm1, %ymm3
	vmovdqa	%ymm11, 136(%rsp)
	vpaddd	%ymm14, %ymm9, %ymm11
	vpmuldq	%ymm4, %ymm3, %ymm5
	vpmuldq	%ymm10, %ymm1, %ymm1
	vmovdqa	%ymm11, 552(%rsp)
	vpmuldq	%ymm10, %ymm3, %ymm3
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm7, %ymm1, %ymm1
	vpsrlq	$32, %ymm1, %ymm1
	vpsubd	%ymm5, %ymm3, %ymm3
	vpblendd	$170, %ymm3, %ymm1, %ymm3
	vpsubd	%ymm14, %ymm9, %ymm1
	vpmuldq	%ymm1, %ymm4, %ymm7
	vmovdqa	%ymm3, 104(%rsp)
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	%ymm4, %ymm3, %ymm5
	vpmuldq	%ymm10, %ymm1, %ymm1
	vpmuldq	%ymm10, %ymm3, %ymm3
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm7, %ymm1, %ymm1
	vpsubd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm3, %ymm1, %ymm1
	vmovdqa	%ymm1, 72(%rsp)
	vpsubd	%ymm8, %ymm6, %ymm1
	vpaddd	%ymm8, %ymm6, %ymm6
	vpmuldq	%ymm1, %ymm4, %ymm5
	vpsrlq	$32, %ymm1, %ymm3
	vmovdqa	%ymm6, 584(%rsp)
	vpmuldq	%ymm4, %ymm3, %ymm4
	vpmuldq	%ymm10, %ymm1, %ymm1
	vpmuldq	%ymm10, %ymm3, %ymm3
	vmovdqu	768(%rdi), %ymm10
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm5, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm3, %ymm1, %ymm8
	vpsubd	800(%rdi), %ymm10, %ymm3
	vmovdqu	800(%rdi), %ymm10
	vpmuldq	896(%rdx), %ymm3, %ymm5
	vpaddd	768(%rdi), %ymm10, %ymm6
	vmovdqu	896(%rdx), %ymm10
	vpmuldq	%ymm5, %ymm0, %ymm5
	vmovdqa	%ymm8, 40(%rsp)
	vpsrlq	$32, %ymm3, %ymm7
	vpmuldq	384(%rdx), %ymm3, %ymm3
	vpsrlq	$32, %ymm10, %ymm4
	vmovdqu	384(%rdx), %ymm10
	vpmuldq	%ymm4, %ymm7, %ymm4
	vpsrlq	$32, %ymm10, %ymm1
	vmovdqu	832(%rdi), %ymm10
	vpmuldq	%ymm1, %ymm7, %ymm1
	vpsubd	%ymm5, %ymm3, %ymm3
	vpsrlq	$32, %ymm3, %ymm3
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm4, %ymm1, %ymm1
	vpblendd	$170, %ymm1, %ymm3, %ymm5
	vpsubd	864(%rdi), %ymm10, %ymm3
	vmovdqu	864(%rdi), %ymm10
	vpaddd	832(%rdi), %ymm10, %ymm7
	vmovdqu	928(%rdx), %ymm10
	vpsllq	$32, %ymm5, %ymm11
	vpsrlq	$32, %ymm3, %ymm8
	vpblendd	$170, %ymm11, %ymm6, %ymm11
	vpsrlq	$32, %ymm10, %ymm4
	vmovdqu	416(%rdx), %ymm10
	vpsrlq	$32, %ymm6, %ymm6
	vpmuldq	%ymm4, %ymm8, %ymm4
	vpblendd	$85, %ymm6, %ymm5, %ymm5
	vpmuldq	928(%rdx), %ymm3, %ymm6
	vpmuldq	416(%rdx), %ymm3, %ymm3
	vpmuldq	%ymm6, %ymm0, %ymm6
	vpsrlq	$32, %ymm10, %ymm1
	vmovdqu	896(%rdi), %ymm10
	vpmuldq	%ymm1, %ymm8, %ymm1
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm6, %ymm3, %ymm3
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsubd	928(%rdi), %ymm10, %ymm4
	vmovdqu	928(%rdi), %ymm10
	vpmuldq	960(%rdx), %ymm4, %ymm9
	vpblendd	$170, %ymm1, %ymm3, %ymm3
	vpaddd	896(%rdi), %ymm10, %ymm8
	vpsllq	$32, %ymm3, %ymm6
	vpsrlq	$32, %ymm4, %ymm10
	vpmuldq	448(%rdx), %ymm4, %ymm4
	vpblendd	$170, %ymm6, %ymm7, %ymm6
	vpsrlq	$32, %ymm7, %ymm7
	vpblendd	$85, %ymm7, %ymm3, %ymm3
	vpsrlq	$32, %ymm12, %ymm7
	vmovdqu	448(%rdx), %ymm12
	vpmuldq	%ymm7, %ymm10, %ymm7
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpsrlq	$32, %ymm12, %ymm1
	vpmuldq	%ymm1, %ymm10, %ymm1
	vmovdqu	960(%rdi), %ymm10
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpsubd	%ymm9, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm7, %ymm1, %ymm1
	vpsubd	992(%rdi), %ymm10, %ymm7
	vmovdqu	992(%rdi), %ymm10
	vpblendd	$170, %ymm1, %ymm4, %ymm4
	vmovdqu	480(%rdx), %ymm1
	vpaddd	960(%rdi), %ymm10, %ymm12
	vpmuldq	992(%rdx), %ymm7, %ymm10
	vpsllq	$32, %ymm4, %ymm9
	vpsrlq	$32, %ymm7, %ymm14
	vpmuldq	480(%rdx), %ymm7, %ymm7
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm9, %ymm8, %ymm9
	vpsrlq	$32, %ymm8, %ymm8
	vpmuldq	%ymm1, %ymm14, %ymm1
	vpblendd	$85, %ymm8, %ymm4, %ymm4
	vmovdqu	992(%rdx), %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpmuldq	%ymm8, %ymm14, %ymm8
	vpsubd	%ymm10, %ymm7, %ymm7
	vmovdqu	1408(%rdx), %ymm14
	vpsrlq	$32, %ymm7, %ymm7
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpsubd	%ymm8, %ymm1, %ymm1
	vpsubd	%ymm5, %ymm11, %ymm8
	vpblendd	$170, %ymm1, %ymm7, %ymm7
	vpsrlq	$32, %ymm8, %ymm1
	vpaddd	%ymm5, %ymm11, %ymm11
	vpsllq	$32, %ymm7, %ymm10
	vpblendd	$170, %ymm10, %ymm12, %ymm10
	vpsrlq	$32, %ymm12, %ymm12
	vpblendd	$85, %ymm12, %ymm7, %ymm7
	vpsrlq	$32, %ymm14, %ymm12
	vpmuldq	%ymm8, %ymm12, %ymm5
	vpmuldq	%ymm12, %ymm1, %ymm12
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm1, %ymm1
	vmovdqu	1440(%rdx), %ymm14
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm5, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm1, %ymm1
	vpsrlq	$32, %ymm14, %ymm12
	vpsrlq	$32, %ymm8, %ymm8
	vpblendd	$170, %ymm1, %ymm8, %ymm1
	vpsubd	%ymm3, %ymm6, %ymm8
	vpunpcklqdq	%ymm1, %ymm11, %ymm5
	vpunpckhqdq	%ymm1, %ymm11, %ymm11
	vpaddd	%ymm3, %ymm6, %ymm1
	vpmuldq	%ymm8, %ymm12, %ymm3
	vpsrlq	$32, %ymm8, %ymm6
	vpmuldq	%ymm12, %ymm6, %ymm12
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm6, %ymm6
	vmovdqu	1472(%rdx), %ymm14
	vpmuldq	%ymm3, %ymm0, %ymm3
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm3, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm6, %ymm6
	vpsrlq	$32, %ymm8, %ymm8
	vpblendd	$170, %ymm6, %ymm8, %ymm3
	vpsrlq	$32, %ymm14, %ymm12
	vpsubd	%ymm4, %ymm9, %ymm8
	vpunpcklqdq	%ymm3, %ymm1, %ymm6
	vpaddd	%ymm4, %ymm9, %ymm4
	vpunpckhqdq	%ymm3, %ymm1, %ymm1
	vpmuldq	%ymm8, %ymm12, %ymm9
	vpsrlq	$32, %ymm8, %ymm3
	vpmuldq	%ymm12, %ymm3, %ymm12
	vpmuldq	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm14, %ymm3, %ymm3
	vmovdqu	1504(%rdx), %ymm14
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm9, %ymm8, %ymm8
	vpsubd	%ymm7, %ymm10, %ymm9
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm12, %ymm3, %ymm3
	vpaddd	%ymm7, %ymm10, %ymm7
	vpblendd	$170, %ymm3, %ymm8, %ymm3
	vpsrlq	$32, %ymm14, %ymm12
	vpunpcklqdq	%ymm3, %ymm4, %ymm8
	vpmuldq	%ymm9, %ymm12, %ymm10
	vpunpckhqdq	%ymm3, %ymm4, %ymm4
	vpsrlq	$32, %ymm9, %ymm3
	vpmuldq	%ymm14, %ymm9, %ymm9
	vpmuldq	%ymm12, %ymm3, %ymm12
	vpmuldq	%ymm14, %ymm3, %ymm3
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm10, %ymm9, %ymm9
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm12, %ymm3, %ymm3
	vmovdqu	1920(%rdx), %ymm12
	vpblendd	$170, %ymm3, %ymm9, %ymm9
	vpunpcklqdq	%ymm9, %ymm7, %ymm3
	vpsrlq	$32, %ymm12, %ymm10
	vpunpckhqdq	%ymm9, %ymm7, %ymm7
	vpsubd	%ymm11, %ymm5, %ymm9
	vpaddd	%ymm5, %ymm11, %ymm11
	vpmuldq	%ymm9, %ymm10, %ymm14
	vpsrlq	$32, %ymm9, %ymm5
	vpmuldq	%ymm10, %ymm5, %ymm10
	vpmuldq	%ymm12, %ymm9, %ymm9
	vpmuldq	%ymm12, %ymm5, %ymm5
	vmovdqu	1952(%rdx), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm14, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm5, %ymm5
	vpsrlq	$32, %ymm9, %ymm9
	vpblendd	$170, %ymm5, %ymm9, %ymm9
	vpsrlq	$32, %ymm12, %ymm10
	vperm2i128	$32, %ymm9, %ymm11, %ymm5
	vperm2i128	$49, %ymm9, %ymm11, %ymm11
	vpsubd	%ymm1, %ymm6, %ymm9
	vpmuldq	%ymm9, %ymm10, %ymm14
	vpaddd	%ymm6, %ymm1, %ymm1
	vpsrlq	$32, %ymm9, %ymm6
	vpmuldq	%ymm12, %ymm9, %ymm9
	vpmuldq	%ymm10, %ymm6, %ymm10
	vpmuldq	%ymm12, %ymm6, %ymm6
	vmovdqu	1984(%rdx), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm14, %ymm9, %ymm9
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm6, %ymm9, %ymm9
	vperm2i128	$32, %ymm9, %ymm1, %ymm6
	vperm2i128	$49, %ymm9, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm8, %ymm9
	vpmuldq	%ymm9, %ymm10, %ymm14
	vpaddd	%ymm8, %ymm4, %ymm4
	vpsrlq	$32, %ymm9, %ymm8
	vpmuldq	%ymm12, %ymm9, %ymm9
	vpmuldq	%ymm10, %ymm8, %ymm10
	vpmuldq	%ymm12, %ymm8, %ymm8
	vmovdqu	2016(%rdx), %ymm12
	leaq	1024(%rdi), %rdx
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm14, %ymm9, %ymm9
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm8, %ymm8
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm8, %ymm9, %ymm8
	vperm2i128	$32, %ymm8, %ymm4, %ymm9
	vperm2i128	$49, %ymm8, %ymm4, %ymm4
	vpsubd	%ymm7, %ymm3, %ymm8
	vpmuldq	%ymm8, %ymm10, %ymm14
	vpaddd	%ymm3, %ymm7, %ymm7
	vpsrlq	$32, %ymm8, %ymm3
	vpmuldq	%ymm12, %ymm8, %ymm8
	vpmuldq	%ymm10, %ymm3, %ymm10
	vpmuldq	%ymm12, %ymm3, %ymm3
	vpbroadcastq	168(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm14, %ymm8, %ymm8
	vpsrlq	$32, %ymm8, %ymm8
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm3, %ymm8, %ymm3
	vperm2i128	$32, %ymm3, %ymm7, %ymm8
	vperm2i128	$49, %ymm3, %ymm7, %ymm7
	vpsubd	%ymm11, %ymm5, %ymm3
	vpaddd	%ymm5, %ymm11, %ymm11
	vpsrlq	$32, %ymm3, %ymm5
	vpmuldq	%ymm3, %ymm10, %ymm14
	vpmuldq	%ymm10, %ymm5, %ymm10
	vpmuldq	%ymm12, %ymm3, %ymm3
	vpmuldq	%ymm12, %ymm5, %ymm12
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm10, %ymm12, %ymm5
	vpsubd	%ymm14, %ymm3, %ymm3
	vpbroadcastq	176(%rax), %ymm12
	vpsrlq	$32, %ymm3, %ymm3
	vpblendd	$170, %ymm5, %ymm3, %ymm5
	vpsrlq	$32, %ymm12, %ymm10
	vpsubd	%ymm1, %ymm6, %ymm3
	vpmuldq	%ymm3, %ymm10, %ymm14
	vpaddd	%ymm6, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm6
	vpmuldq	%ymm12, %ymm3, %ymm3
	vpmuldq	%ymm10, %ymm6, %ymm10
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpbroadcastq	184(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm14, %ymm3, %ymm3
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm10, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm6, %ymm3, %ymm3
	vpsubd	%ymm4, %ymm9, %ymm6
	vpaddd	%ymm9, %ymm4, %ymm4
	vpmuldq	%ymm6, %ymm10, %ymm14
	vpsrlq	$32, %ymm6, %ymm9
	vpmuldq	%ymm10, %ymm9, %ymm10
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm12, %ymm9, %ymm9
	vpbroadcastq	192(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm14, %ymm6, %ymm6
	vpsubd	%ymm10, %ymm9, %ymm9
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm9, %ymm6, %ymm6
	vpsrlq	$32, %ymm12, %ymm10
	vpsubd	%ymm7, %ymm8, %ymm9
	vpmuldq	%ymm9, %ymm10, %ymm14
	vpaddd	%ymm7, %ymm8, %ymm8
	vpsrlq	$32, %ymm9, %ymm7
	vpmuldq	%ymm12, %ymm9, %ymm9
	vpmuldq	%ymm10, %ymm7, %ymm10
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpbroadcastq	200(%rax), %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm14, %ymm9, %ymm9
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm10, %ymm7, %ymm7
	vpsrlq	$32, %ymm12, %ymm10
	vpblendd	$170, %ymm7, %ymm9, %ymm9
	vpsubd	%ymm1, %ymm11, %ymm7
	vpaddd	%ymm11, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm10, %ymm14
	vpsrlq	$32, %ymm7, %ymm11
	vpmuldq	%ymm10, %ymm11, %ymm15
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpmuldq	%ymm12, %ymm11, %ymm11
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpsubd	%ymm14, %ymm7, %ymm14
	vpsubd	%ymm3, %ymm5, %ymm7
	vpsubd	%ymm15, %ymm11, %ymm11
	vpsrlq	$32, %ymm14, %ymm14
	vpaddd	%ymm5, %ymm3, %ymm3
	vpblendd	$170, %ymm11, %ymm14, %ymm14
	vpsrlq	$32, %ymm7, %ymm5
	vpmuldq	%ymm7, %ymm10, %ymm11
	vpmuldq	%ymm10, %ymm5, %ymm10
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpbroadcastq	208(%rax), %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm11, %ymm7, %ymm7
	vpsubd	%ymm10, %ymm5, %ymm5
	vpsrlq	$32, %ymm12, %ymm10
	vpsrlq	$32, %ymm7, %ymm11
	vpblendd	$170, %ymm5, %ymm11, %ymm11
	vpsubd	%ymm8, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm8, %ymm8
	vpmuldq	%ymm5, %ymm10, %ymm15
	vpsrlq	$32, %ymm5, %ymm4
	vpmuldq	%ymm10, %ymm4, %ymm7
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpsubd	%ymm15, %ymm5, %ymm5
	vpsubd	%ymm7, %ymm4, %ymm4
	vpsrlq	$32, %ymm5, %ymm5
	vpblendd	$170, %ymm4, %ymm5, %ymm5
	vpsubd	%ymm9, %ymm6, %ymm4
	vpaddd	%ymm6, %ymm9, %ymm9
	vpsrlq	$32, %ymm4, %ymm6
	vpmuldq	%ymm4, %ymm10, %ymm7
	vpmuldq	%ymm10, %ymm6, %ymm10
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm12, %ymm6, %ymm12
	vpmuldq	%ymm7, %ymm0, %ymm7
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm7, %ymm4, %ymm4
	vpsubd	%ymm10, %ymm12, %ymm6
	vpsrlq	$32, %ymm4, %ymm4
	vpbroadcastq	216(%rax), %ymm12
	vpblendd	$170, %ymm6, %ymm4, %ymm4
	vpsubd	%ymm8, %ymm1, %ymm6
	vpaddd	%ymm8, %ymm1, %ymm1
	vpsrlq	$32, %ymm12, %ymm10
	vpsrlq	$32, %ymm6, %ymm7
	vpmuldq	%ymm6, %ymm10, %ymm15
	vpmuldq	%ymm10, %ymm7, %ymm8
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpsubd	%ymm15, %ymm6, %ymm6
	vpsubd	%ymm8, %ymm7, %ymm7
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm7, %ymm6, %ymm8
	vpsubd	%ymm9, %ymm3, %ymm6
	vpaddd	%ymm9, %ymm3, %ymm3
	vpmuldq	%ymm6, %ymm10, %ymm15
	vpsrlq	$32, %ymm6, %ymm7
	vpmuldq	%ymm10, %ymm7, %ymm9
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm12, %ymm7, %ymm7
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpsubd	%ymm15, %ymm6, %ymm6
	vpsubd	%ymm9, %ymm7, %ymm7
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm7, %ymm6, %ymm6
	vpaddd	%ymm14, %ymm5, %ymm7
	vmovdqa	%ymm6, 8(%rsp)
	vpsubd	%ymm5, %ymm14, %ymm6
	vpmuldq	%ymm6, %ymm10, %ymm14
	vpsrlq	$32, %ymm6, %ymm5
	vpmuldq	%ymm10, %ymm5, %ymm9
	vpmuldq	%ymm12, %ymm6, %ymm6
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpsubd	%ymm14, %ymm6, %ymm6
	vmovdqa	616(%rsp), %ymm14
	vpsrlq	$32, %ymm6, %ymm6
	vpsubd	%ymm9, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm6, %ymm9
	vpsubd	%ymm4, %ymm11, %ymm5
	vpaddd	%ymm11, %ymm4, %ymm6
	vmovdqa	%ymm9, -24(%rsp)
	vpsrlq	$32, %ymm5, %ymm4
	vpmuldq	%ymm5, %ymm10, %ymm9
	vpmuldq	%ymm10, %ymm4, %ymm10
	vpmuldq	%ymm12, %ymm5, %ymm5
	vpmuldq	%ymm12, %ymm4, %ymm4
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm9, %ymm5, %ymm5
	vpsubd	%ymm14, %ymm2, %ymm9
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm10, %ymm4, %ymm4
	vpaddd	%ymm14, %ymm2, %ymm2
	vmovdqa	648(%rsp), %ymm14
	vpblendd	$170, %ymm4, %ymm5, %ymm10
	vpbroadcastq	224(%rax), %ymm5
	vmovdqa	%ymm10, -56(%rsp)
	vpsrlq	$32, %ymm9, %ymm10
	vpsrlq	$32, %ymm5, %ymm4
	vpmuldq	%ymm9, %ymm4, %ymm12
	vpmuldq	%ymm4, %ymm10, %ymm11
	vpmuldq	%ymm5, %ymm9, %ymm9
	vpmuldq	%ymm5, %ymm10, %ymm10
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm12, %ymm9, %ymm9
	vpsubd	%ymm11, %ymm10, %ymm10
	vpsrlq	$32, %ymm9, %ymm9
	vpaddd	%ymm14, %ymm13, %ymm11
	vpblendd	$170, %ymm10, %ymm9, %ymm10
	vpsubd	%ymm14, %ymm13, %ymm9
	vpmuldq	%ymm9, %ymm4, %ymm13
	vmovdqa	%ymm10, -88(%rsp)
	vpsrlq	$32, %ymm9, %ymm10
	vpmuldq	%ymm4, %ymm10, %ymm12
	vpmuldq	%ymm5, %ymm9, %ymm9
	vpmuldq	%ymm5, %ymm10, %ymm10
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm13, %ymm9, %ymm9
	vpsubd	%ymm12, %ymm10, %ymm10
	vpsrlq	$32, %ymm9, %ymm9
	vpblendd	$170, %ymm10, %ymm9, %ymm14
	vmovdqa	%ymm14, -120(%rsp)
	vmovdqa	424(%rsp), %ymm13
	vmovdqa	680(%rsp), %ymm14
	vpsubd	%ymm14, %ymm13, %ymm9
	vpaddd	%ymm13, %ymm14, %ymm10
	vpsrlq	$32, %ymm9, %ymm12
	vpmuldq	%ymm9, %ymm4, %ymm14
	vpmuldq	%ymm4, %ymm12, %ymm13
	vpmuldq	%ymm5, %ymm9, %ymm9
	vpmuldq	%ymm5, %ymm12, %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpsubd	%ymm14, %ymm9, %ymm9
	vpsubd	%ymm13, %ymm12, %ymm12
	vpsrlq	$32, %ymm9, %ymm9
	vmovdqa	456(%rsp), %ymm13
	vpblendd	$170, %ymm12, %ymm9, %ymm14
	vmovdqa	712(%rsp), %ymm9
	vmovdqa	%ymm14, 424(%rsp)
	vpsubd	%ymm9, %ymm13, %ymm12
	vpaddd	%ymm13, %ymm9, %ymm9
	vpmuldq	%ymm12, %ymm4, %ymm15
	vpsrlq	$32, %ymm12, %ymm13
	vpmuldq	%ymm4, %ymm13, %ymm14
	vpmuldq	%ymm5, %ymm12, %ymm12
	vpmuldq	%ymm5, %ymm13, %ymm13
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm12, %ymm12
	vmovdqa	392(%rsp), %ymm15
	vpsrlq	$32, %ymm12, %ymm12
	vpsubd	%ymm14, %ymm13, %ymm13
	vpblendd	$170, %ymm13, %ymm12, %ymm14
	vmovdqa	264(%rsp), %ymm13
	vmovdqa	%ymm14, 456(%rsp)
	vpsubd	%ymm13, %ymm15, %ymm12
	vpaddd	%ymm15, %ymm13, %ymm14
	vpmuldq	%ymm12, %ymm4, %ymm15
	vpsrlq	$32, %ymm12, %ymm13
	vmovdqa	%ymm14, 712(%rsp)
	vpmuldq	%ymm4, %ymm13, %ymm14
	vpmuldq	%ymm5, %ymm12, %ymm12
	vpmuldq	%ymm5, %ymm13, %ymm13
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm12, %ymm12
	vmovdqa	360(%rsp), %ymm15
	vpsubd	%ymm14, %ymm13, %ymm13
	vpsrlq	$32, %ymm12, %ymm12
	vpblendd	$170, %ymm13, %ymm12, %ymm12
	vmovdqa	232(%rsp), %ymm13
	vmovdqa	%ymm12, 392(%rsp)
	vpsubd	%ymm13, %ymm15, %ymm12
	vpaddd	%ymm15, %ymm13, %ymm13
	vmovdqa	%ymm13, 680(%rsp)
	vpmuldq	%ymm12, %ymm4, %ymm15
	vpsrlq	$32, %ymm12, %ymm13
	vpmuldq	%ymm4, %ymm13, %ymm14
	vpmuldq	%ymm5, %ymm12, %ymm12
	vpmuldq	%ymm5, %ymm13, %ymm13
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm12, %ymm12
	vmovdqa	328(%rsp), %ymm15
	vpsubd	%ymm14, %ymm13, %ymm13
	vpsrlq	$32, %ymm12, %ymm12
	vpblendd	$170, %ymm13, %ymm12, %ymm12
	vmovdqa	200(%rsp), %ymm13
	vmovdqa	%ymm12, 360(%rsp)
	vpsubd	%ymm13, %ymm15, %ymm12
	vpaddd	%ymm15, %ymm13, %ymm13
	vmovdqa	%ymm13, 648(%rsp)
	vpmuldq	%ymm12, %ymm4, %ymm15
	vpsrlq	$32, %ymm12, %ymm13
	vpmuldq	%ymm4, %ymm13, %ymm14
	vpmuldq	%ymm5, %ymm12, %ymm12
	vpmuldq	%ymm5, %ymm13, %ymm13
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm12, %ymm12
	vmovdqa	296(%rsp), %ymm15
	vpsubd	%ymm14, %ymm13, %ymm13
	vpsrlq	$32, %ymm12, %ymm12
	vpblendd	$170, %ymm13, %ymm12, %ymm12
	vmovdqa	168(%rsp), %ymm13
	vmovdqa	%ymm12, 328(%rsp)
	vpsubd	%ymm13, %ymm15, %ymm12
	vpaddd	%ymm15, %ymm13, %ymm13
	vmovdqa	%ymm13, 616(%rsp)
	vpmuldq	%ymm12, %ymm4, %ymm14
	vpsrlq	$32, %ymm12, %ymm13
	vpmuldq	%ymm4, %ymm13, %ymm4
	vpmuldq	%ymm5, %ymm12, %ymm12
	vpmuldq	%ymm5, %ymm13, %ymm13
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm14, %ymm12, %ymm12
	vpsubd	%ymm4, %ymm13, %ymm13
	vpsrlq	$32, %ymm12, %ymm12
	vpblendd	$170, %ymm13, %ymm12, %ymm5
	vpbroadcastq	232(%rax), %ymm13
	vmovdqa	%ymm5, 296(%rsp)
	vmovdqa	488(%rsp), %ymm5
	vpsrlq	$32, %ymm13, %ymm12
	vpsubd	%ymm1, %ymm5, %ymm4
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmuldq	%ymm4, %ymm12, %ymm15
	vpsrlq	$32, %ymm4, %ymm5
	vpmuldq	%ymm12, %ymm5, %ymm14
	vpmuldq	%ymm13, %ymm4, %ymm4
	vpmuldq	%ymm13, %ymm5, %ymm5
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm14, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm4, %ymm5
	vmovdqa	%ymm5, 264(%rsp)
	vmovdqa	520(%rsp), %ymm5
	vpsubd	%ymm3, %ymm5, %ymm4
	vpaddd	%ymm5, %ymm3, %ymm3
	vpmuldq	%ymm4, %ymm12, %ymm15
	vpsrlq	$32, %ymm4, %ymm5
	vpmuldq	%ymm12, %ymm5, %ymm14
	vpmuldq	%ymm13, %ymm4, %ymm4
	vpmuldq	%ymm13, %ymm5, %ymm5
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm14, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm4, %ymm5
	vmovdqa	%ymm5, 232(%rsp)
	vmovdqa	552(%rsp), %ymm5
	vpsubd	%ymm7, %ymm5, %ymm4
	vpaddd	%ymm5, %ymm7, %ymm5
	vpmuldq	%ymm4, %ymm12, %ymm15
	vpsrlq	$32, %ymm4, %ymm7
	vpmuldq	%ymm12, %ymm7, %ymm14
	vpmuldq	%ymm13, %ymm4, %ymm4
	vpmuldq	%ymm13, %ymm7, %ymm7
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm14, %ymm7, %ymm7
	vpblendd	$170, %ymm7, %ymm4, %ymm7
	vmovdqa	584(%rsp), %ymm4
	vmovdqa	%ymm7, 200(%rsp)
	vpsubd	%ymm6, %ymm4, %ymm7
	vpaddd	%ymm4, %ymm6, %ymm4
	vpmuldq	%ymm7, %ymm12, %ymm15
	vpsrlq	$32, %ymm7, %ymm6
	vpmuldq	%ymm12, %ymm6, %ymm14
	vpmuldq	%ymm13, %ymm7, %ymm7
	vpmuldq	%ymm13, %ymm6, %ymm6
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm7, %ymm7
	vpsrlq	$32, %ymm7, %ymm7
	vpsubd	%ymm14, %ymm6, %ymm6
	vpblendd	$170, %ymm6, %ymm7, %ymm6
	vmovdqa	136(%rsp), %ymm7
	vmovdqa	%ymm6, 168(%rsp)
	vpsubd	%ymm8, %ymm7, %ymm6
	vpaddd	%ymm7, %ymm8, %ymm8
	vpmuldq	%ymm6, %ymm12, %ymm14
	vpsrlq	$32, %ymm6, %ymm7
	vmovdqa	%ymm8, 584(%rsp)
	vmovdqa	8(%rsp), %ymm15
	vpmuldq	%ymm12, %ymm7, %ymm8
	vpmuldq	%ymm13, %ymm6, %ymm6
	vpmuldq	%ymm13, %ymm7, %ymm7
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpsubd	%ymm14, %ymm6, %ymm6
	vpsubd	%ymm8, %ymm7, %ymm7
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm7, %ymm6, %ymm6
	vmovdqa	104(%rsp), %ymm7
	vmovdqa	%ymm6, 136(%rsp)
	vpsubd	%ymm15, %ymm7, %ymm6
	vpaddd	%ymm7, %ymm15, %ymm8
	vmovdqa	-24(%rsp), %ymm15
	vpmuldq	%ymm6, %ymm12, %ymm14
	vpsrlq	$32, %ymm6, %ymm7
	vmovdqa	%ymm8, 552(%rsp)
	vpmuldq	%ymm12, %ymm7, %ymm8
	vpmuldq	%ymm13, %ymm6, %ymm6
	vpmuldq	%ymm13, %ymm7, %ymm7
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpsubd	%ymm14, %ymm6, %ymm6
	vpsubd	%ymm8, %ymm7, %ymm7
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm7, %ymm6, %ymm6
	vmovdqa	72(%rsp), %ymm7
	vmovdqa	%ymm6, 104(%rsp)
	vpsubd	%ymm15, %ymm7, %ymm6
	vpaddd	%ymm7, %ymm15, %ymm7
	vmovdqa	-56(%rsp), %ymm15
	vmovdqa	%ymm7, 520(%rsp)
	vpmuldq	%ymm6, %ymm12, %ymm14
	vpsrlq	$32, %ymm6, %ymm7
	vpmuldq	%ymm12, %ymm7, %ymm8
	vpmuldq	%ymm13, %ymm6, %ymm6
	vpmuldq	%ymm13, %ymm7, %ymm7
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpsubd	%ymm14, %ymm6, %ymm6
	vpsubd	%ymm8, %ymm7, %ymm7
	vpsrlq	$32, %ymm6, %ymm6
	vpblendd	$170, %ymm7, %ymm6, %ymm6
	vmovdqa	40(%rsp), %ymm7
	vmovdqa	%ymm6, 72(%rsp)
	vpsubd	%ymm15, %ymm7, %ymm6
	vpaddd	%ymm7, %ymm15, %ymm7
	vmovdqa	%ymm7, 488(%rsp)
	vpmuldq	%ymm6, %ymm12, %ymm8
	vpsrlq	$32, %ymm6, %ymm7
	vpmuldq	%ymm12, %ymm7, %ymm12
	vpmuldq	%ymm13, %ymm6, %ymm6
	vpmuldq	%ymm13, %ymm7, %ymm7
	vpmuldq	%ymm8, %ymm0, %ymm8
	vpmuldq	%ymm12, %ymm0, %ymm12
	vpsubd	%ymm8, %ymm6, %ymm6
	vpsubd	%ymm1, %ymm2, %ymm8
	vpsubd	%ymm12, %ymm7, %ymm7
	vpsrlq	$32, %ymm6, %ymm6
	vpaddd	%ymm1, %ymm2, %ymm1
	vpblendd	$170, %ymm7, %ymm6, %ymm15
	vpsrlq	$32, %ymm8, %ymm2
	vpbroadcastq	240(%rax), %ymm7
	movq	%rdi, %rax
	vmovdqa	%ymm15, 40(%rsp)
	vpsrlq	$32, %ymm7, %ymm6
	vpmuldq	%ymm8, %ymm6, %ymm13
	vpmuldq	%ymm6, %ymm2, %ymm12
	vpmuldq	%ymm7, %ymm8, %ymm8
	vpmuldq	%ymm7, %ymm2, %ymm2
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm12, %ymm0, %ymm14
	vpsubd	%ymm13, %ymm8, %ymm8
	vpsubd	%ymm14, %ymm2, %ymm2
	vpsrlq	$32, %ymm8, %ymm12
	vpblendd	$170, %ymm2, %ymm12, %ymm12
	vpsubd	%ymm3, %ymm11, %ymm2
	vpaddd	%ymm3, %ymm11, %ymm3
	vpmuldq	%ymm2, %ymm6, %ymm13
	vpsrlq	$32, %ymm2, %ymm8
	vmovdqu	%ymm12, 512(%rdi)
	vpmuldq	%ymm6, %ymm8, %ymm11
	vpmuldq	%ymm7, %ymm2, %ymm2
	vpmuldq	%ymm7, %ymm8, %ymm8
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm11, %ymm0, %ymm14
	vpsubd	%ymm13, %ymm2, %ymm2
	vpsrlq	$32, %ymm2, %ymm11
	vpsubd	%ymm5, %ymm10, %ymm2
	vpsubd	%ymm14, %ymm8, %ymm8
	vpmuldq	%ymm2, %ymm6, %ymm13
	vpblendd	$170, %ymm8, %ymm11, %ymm11
	vpaddd	%ymm5, %ymm10, %ymm5
	vpsrlq	$32, %ymm2, %ymm8
	vpmuldq	%ymm7, %ymm2, %ymm2
	vmovdqu	%ymm11, 544(%rdi)
	vpmuldq	%ymm6, %ymm8, %ymm10
	vpmuldq	%ymm7, %ymm8, %ymm8
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm10, %ymm0, %ymm14
	vpsubd	%ymm13, %ymm2, %ymm2
	vpsrlq	$32, %ymm2, %ymm10
	vpsubd	%ymm4, %ymm9, %ymm2
	vpaddd	%ymm4, %ymm9, %ymm4
	vpmuldq	%ymm2, %ymm6, %ymm13
	vpsubd	%ymm14, %ymm8, %ymm8
	vpblendd	$170, %ymm8, %ymm10, %ymm10
	vpsrlq	$32, %ymm2, %ymm8
	vpmuldq	%ymm6, %ymm8, %ymm9
	vpmuldq	%ymm7, %ymm2, %ymm2
	vmovdqu	%ymm10, 576(%rdi)
	vpmuldq	%ymm7, %ymm8, %ymm8
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm9, %ymm0, %ymm14
	vpsubd	%ymm13, %ymm2, %ymm2
	vpsrlq	$32, %ymm2, %ymm9
	vmovdqa	.iLC1(%rip), %ymm2
	vpsubd	%ymm14, %ymm8, %ymm8
	vpsrlq	$32, %ymm1, %ymm14
	vpmuldq	%ymm1, %ymm2, %ymm15
	vpmuldq	%ymm2, %ymm14, %ymm13
	vpblendd	$170, %ymm8, %ymm9, %ymm9
	vmovdqa	.iLC2(%rip), %ymm8
	vmovdqu	%ymm9, 608(%rdi)
	vmovdqa	584(%rsp), %ymm9
	vpmuldq	%ymm8, %ymm1, %ymm1
	vpmuldq	%ymm8, %ymm14, %ymm14
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpsubd	%ymm15, %ymm1, %ymm1
	vpsubd	%ymm13, %ymm14, %ymm14
	vpmuldq	%ymm3, %ymm2, %ymm15
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm14, %ymm1, %ymm13
	vpsrlq	$32, %ymm3, %ymm1
	vpmuldq	%ymm2, %ymm1, %ymm14
	vpmuldq	%ymm8, %ymm3, %ymm3
	vmovdqu	%ymm13, (%rdi)
	vmovdqa	680(%rsp), %ymm13
	vpmuldq	%ymm8, %ymm1, %ymm1
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm3, %ymm3
	vpmuldq	%ymm5, %ymm2, %ymm15
	vpsrlq	$32, %ymm3, %ymm3
	vpsubd	%ymm14, %ymm1, %ymm1
	vpsrlq	$32, %ymm5, %ymm14
	vpblendd	$170, %ymm1, %ymm3, %ymm3
	vpmuldq	%ymm2, %ymm14, %ymm1
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm8, %ymm5, %ymm5
	vmovdqu	%ymm3, 32(%rdi)
	vpmuldq	%ymm8, %ymm14, %ymm14
	vpmuldq	%ymm1, %ymm0, %ymm1
	vpsubd	%ymm15, %ymm5, %ymm5
	vpmuldq	%ymm4, %ymm2, %ymm15
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm14, %ymm14
	vpblendd	$170, %ymm14, %ymm5, %ymm1
	vpsrlq	$32, %ymm4, %ymm5
	vpmuldq	%ymm2, %ymm5, %ymm14
	vpmuldq	%ymm15, %ymm0, %ymm15
	vmovdqu	%ymm1, 64(%rdi)
	vpmuldq	%ymm8, %ymm4, %ymm4
	vpmuldq	%ymm8, %ymm5, %ymm5
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm4, %ymm4
	vpsrlq	$32, %ymm4, %ymm4
	vpsubd	%ymm14, %ymm5, %ymm5
	vpblendd	$170, %ymm5, %ymm4, %ymm4
	vmovdqa	712(%rsp), %ymm5
	vmovdqu	%ymm4, 96(%rdi)
	vpsubd	%ymm9, %ymm5, %ymm1
	vpaddd	%ymm5, %ymm9, %ymm5
	vpmuldq	%ymm1, %ymm6, %ymm9
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	%ymm6, %ymm3, %ymm4
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm3, %ymm3
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpmuldq	%ymm4, %ymm0, %ymm10
	vpsubd	%ymm9, %ymm1, %ymm1
	vmovdqa	552(%rsp), %ymm9
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm4
	vpsubd	%ymm9, %ymm13, %ymm1
	vpblendd	$170, %ymm3, %ymm4, %ymm4
	vpaddd	%ymm13, %ymm9, %ymm10
	vmovdqa	648(%rsp), %ymm13
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	%ymm1, %ymm6, %ymm11
	vpmuldq	%ymm6, %ymm3, %ymm9
	vpmuldq	%ymm7, %ymm3, %ymm12
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpsubd	%ymm11, %ymm1, %ymm1
	vpsubd	%ymm9, %ymm12, %ymm3
	vpsrlq	$32, %ymm1, %ymm1
	vmovdqa	520(%rsp), %ymm9
	vpblendd	$170, %ymm3, %ymm1, %ymm3
	vpsubd	%ymm9, %ymm13, %ymm1
	vpaddd	%ymm13, %ymm9, %ymm11
	vpmuldq	%ymm1, %ymm6, %ymm13
	vpsrlq	$32, %ymm1, %ymm9
	vpmuldq	%ymm6, %ymm9, %ymm12
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm9, %ymm9
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm12, %ymm0, %ymm14
	vpsubd	%ymm13, %ymm1, %ymm1
	vmovdqa	616(%rsp), %ymm13
	vpsubd	%ymm14, %ymm9, %ymm9
	vpsrlq	$32, %ymm1, %ymm12
	vpblendd	$170, %ymm9, %ymm12, %ymm12
	vmovdqa	488(%rsp), %ymm9
	vpsubd	%ymm9, %ymm13, %ymm1
	vpaddd	%ymm13, %ymm9, %ymm9
	vpmuldq	%ymm1, %ymm6, %ymm15
	vpsrlq	$32, %ymm1, %ymm13
	vpmuldq	%ymm6, %ymm13, %ymm14
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm13, %ymm13
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm1, %ymm1
	vpmuldq	%ymm5, %ymm2, %ymm15
	vpsubd	%ymm14, %ymm13, %ymm13
	vpsrlq	$32, %ymm1, %ymm1
	vpsrlq	$32, %ymm5, %ymm14
	vpmuldq	%ymm8, %ymm5, %ymm5
	vpblendd	$170, %ymm13, %ymm1, %ymm1
	vpmuldq	%ymm2, %ymm14, %ymm13
	vpmuldq	%ymm8, %ymm14, %ymm14
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpsubd	%ymm15, %ymm5, %ymm5
	vpmuldq	%ymm10, %ymm2, %ymm15
	vpsrlq	$32, %ymm5, %ymm5
	vpsubd	%ymm13, %ymm14, %ymm14
	vpblendd	$170, %ymm14, %ymm5, %ymm13
	vpsrlq	$32, %ymm10, %ymm5
	vpmuldq	%ymm2, %ymm5, %ymm14
	vpmuldq	%ymm15, %ymm0, %ymm15
	vmovdqu	%ymm13, 128(%rdi)
	vmovdqa	264(%rsp), %ymm13
	vpmuldq	%ymm8, %ymm10, %ymm10
	vpmuldq	%ymm8, %ymm5, %ymm5
	vmovdqu	%ymm4, 640(%rdi)
	vmovdqa	-88(%rsp), %ymm4
	vmovdqu	%ymm1, 736(%rdi)
	vpsubd	%ymm13, %ymm4, %ymm1
	vmovdqu	%ymm3, 672(%rdi)
	vpsrlq	$32, %ymm1, %ymm3
	vmovdqu	%ymm12, 704(%rdi)
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm10, %ymm10
	vpmuldq	%ymm11, %ymm2, %ymm15
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm14, %ymm5, %ymm5
	vpsrlq	$32, %ymm11, %ymm14
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm8, %ymm11, %ymm11
	vpblendd	$170, %ymm5, %ymm10, %ymm10
	vpmuldq	%ymm2, %ymm14, %ymm5
	vpmuldq	%ymm8, %ymm14, %ymm14
	vmovdqu	%ymm10, 160(%rdi)
	vpsubd	%ymm15, %ymm11, %ymm11
	vpmuldq	%ymm9, %ymm2, %ymm15
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsrlq	$32, %ymm11, %ymm11
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpsubd	%ymm5, %ymm14, %ymm14
	vpblendd	$170, %ymm14, %ymm11, %ymm5
	vpsrlq	$32, %ymm9, %ymm11
	vpmuldq	%ymm2, %ymm11, %ymm14
	vpmuldq	%ymm8, %ymm9, %ymm9
	vmovdqu	%ymm5, 192(%rdi)
	vpmuldq	%ymm8, %ymm11, %ymm11
	vpmuldq	%ymm1, %ymm6, %ymm5
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm9, %ymm9
	vmovdqa	456(%rsp), %ymm15
	vpsrlq	$32, %ymm9, %ymm9
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm14, %ymm11, %ymm11
	vpblendd	$170, %ymm11, %ymm9, %ymm9
	vpaddd	%ymm4, %ymm13, %ymm11
	vpsubd	%ymm5, %ymm1, %ymm1
	vmovdqa	232(%rsp), %ymm13
	vpmuldq	%ymm6, %ymm3, %ymm4
	vpmuldq	%ymm7, %ymm3, %ymm3
	vmovdqu	%ymm9, 224(%rdi)
	vpsrlq	$32, %ymm1, %ymm5
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vmovdqa	-120(%rsp), %ymm4
	vpblendd	$170, %ymm3, %ymm5, %ymm5
	vpsubd	%ymm13, %ymm4, %ymm1
	vpaddd	%ymm4, %ymm13, %ymm12
	vmovdqu	%ymm5, 768(%rdi)
	vmovdqa	200(%rsp), %ymm13
	vpmuldq	%ymm1, %ymm6, %ymm9
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	%ymm6, %ymm3, %ymm4
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm3, %ymm3
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpmuldq	%ymm4, %ymm0, %ymm10
	vpsubd	%ymm9, %ymm1, %ymm1
	vpsubd	%ymm10, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm4
	vpblendd	$170, %ymm3, %ymm4, %ymm4
	vmovdqa	424(%rsp), %ymm3
	vmovdqu	%ymm4, 800(%rdi)
	vmovdqa	392(%rsp), %ymm4
	vpsubd	%ymm13, %ymm3, %ymm1
	vpaddd	%ymm3, %ymm13, %ymm10
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	%ymm1, %ymm6, %ymm13
	vpmuldq	%ymm6, %ymm3, %ymm9
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm3, %ymm14
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm9, %ymm0, %ymm9
	vpsubd	%ymm13, %ymm1, %ymm1
	vmovdqa	168(%rsp), %ymm13
	vpsubd	%ymm9, %ymm14, %ymm3
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm3, %ymm1, %ymm3
	vpsubd	%ymm13, %ymm15, %ymm1
	vpaddd	%ymm15, %ymm13, %ymm9
	vpmuldq	%ymm1, %ymm6, %ymm15
	vpsrlq	$32, %ymm1, %ymm13
	vmovdqu	%ymm3, 832(%rdi)
	vmovdqa	136(%rsp), %ymm3
	vpmuldq	%ymm6, %ymm13, %ymm14
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm13, %ymm13
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm1, %ymm1
	vpmuldq	%ymm11, %ymm2, %ymm15
	vpsubd	%ymm14, %ymm13, %ymm13
	vpsrlq	$32, %ymm1, %ymm1
	vpsrlq	$32, %ymm11, %ymm14
	vpmuldq	%ymm8, %ymm11, %ymm11
	vpblendd	$170, %ymm13, %ymm1, %ymm1
	vpmuldq	%ymm2, %ymm14, %ymm13
	vpmuldq	%ymm8, %ymm14, %ymm14
	vmovdqu	%ymm1, 864(%rdi)
	vpsubd	%ymm3, %ymm4, %ymm1
	vpmuldq	%ymm1, %ymm6, %ymm5
	vpmuldq	%ymm15, %ymm0, %ymm15
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm15, %ymm11, %ymm11
	vpmuldq	%ymm12, %ymm2, %ymm15
	vpsrlq	$32, %ymm11, %ymm11
	vpsubd	%ymm13, %ymm14, %ymm14
	vpblendd	$170, %ymm14, %ymm11, %ymm13
	vpsrlq	$32, %ymm12, %ymm14
	vpmuldq	%ymm2, %ymm14, %ymm11
	vpmuldq	%ymm15, %ymm0, %ymm15
	vmovdqu	%ymm13, 256(%rdi)
	vmovdqa	104(%rsp), %ymm13
	vpmuldq	%ymm8, %ymm12, %ymm12
	vpmuldq	%ymm8, %ymm14, %ymm14
	vpmuldq	%ymm11, %ymm0, %ymm11
	vpsubd	%ymm15, %ymm12, %ymm12
	vpmuldq	%ymm10, %ymm2, %ymm15
	vpsrlq	$32, %ymm12, %ymm12
	vpsubd	%ymm11, %ymm14, %ymm14
	vpblendd	$170, %ymm14, %ymm12, %ymm11
	vpsrlq	$32, %ymm10, %ymm12
	vpmuldq	%ymm2, %ymm12, %ymm14
	vpmuldq	%ymm15, %ymm0, %ymm15
	vmovdqu	%ymm11, 288(%rdi)
	vpmuldq	%ymm8, %ymm10, %ymm10
	vpmuldq	%ymm8, %ymm12, %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm10, %ymm10
	vpmuldq	%ymm9, %ymm2, %ymm15
	vpsrlq	$32, %ymm10, %ymm10
	vpsubd	%ymm14, %ymm12, %ymm12
	vpblendd	$170, %ymm12, %ymm10, %ymm10
	vpsrlq	$32, %ymm9, %ymm12
	vpmuldq	%ymm2, %ymm12, %ymm14
	vpmuldq	%ymm15, %ymm0, %ymm15
	vmovdqu	%ymm10, 320(%rdi)
	vpmuldq	%ymm8, %ymm9, %ymm9
	vpmuldq	%ymm8, %ymm12, %ymm12
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpsubd	%ymm15, %ymm9, %ymm9
	vmovdqa	296(%rsp), %ymm15
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm14, %ymm12, %ymm12
	vpblendd	$170, %ymm12, %ymm9, %ymm9
	vmovdqu	%ymm9, 352(%rdi)
	vpaddd	%ymm4, %ymm3, %ymm9
	vpsrlq	$32, %ymm1, %ymm3
	vpmuldq	%ymm6, %ymm3, %ymm4
	vpmuldq	%ymm7, %ymm3, %ymm10
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm4, %ymm0, %ymm4
	vpsubd	%ymm5, %ymm1, %ymm1
	vpsrlq	$32, %ymm1, %ymm1
	vpsubd	%ymm4, %ymm10, %ymm3
	vmovdqa	360(%rsp), %ymm4
	vpblendd	$170, %ymm3, %ymm1, %ymm3
	vpsubd	%ymm13, %ymm4, %ymm1
	vpaddd	%ymm4, %ymm13, %ymm11
	vmovdqa	72(%rsp), %ymm13
	vpmuldq	%ymm1, %ymm6, %ymm10
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm6, %ymm4, %ymm5
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm4, %ymm4
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpmuldq	%ymm5, %ymm0, %ymm12
	vpsubd	%ymm10, %ymm1, %ymm1
	vpsubd	%ymm12, %ymm4, %ymm4
	vpsrlq	$32, %ymm1, %ymm5
	vpblendd	$170, %ymm4, %ymm5, %ymm5
	vmovdqa	328(%rsp), %ymm4
	vpsubd	%ymm13, %ymm4, %ymm1
	vpaddd	%ymm4, %ymm13, %ymm12
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm1, %ymm6, %ymm13
	vpmuldq	%ymm6, %ymm4, %ymm10
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm4, %ymm14
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpmuldq	%ymm10, %ymm0, %ymm10
	vpsubd	%ymm13, %ymm1, %ymm1
	vmovdqa	40(%rsp), %ymm13
	vpsubd	%ymm10, %ymm14, %ymm4
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm4, %ymm1, %ymm4
	vpsubd	%ymm13, %ymm15, %ymm1
	vpaddd	%ymm15, %ymm13, %ymm10
	vpmuldq	%ymm1, %ymm6, %ymm14
	vpsrlq	$32, %ymm1, %ymm13
	vpmuldq	%ymm6, %ymm13, %ymm6
	vpmuldq	%ymm7, %ymm1, %ymm1
	vpmuldq	%ymm7, %ymm13, %ymm13
	vpsrlq	$32, %ymm9, %ymm7
	vpmuldq	%ymm14, %ymm0, %ymm14
	vpmuldq	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm14, %ymm1, %ymm1
	vpmuldq	%ymm9, %ymm2, %ymm14
	vpsubd	%ymm6, %ymm13, %ymm13
	vpsrlq	$32, %ymm1, %ymm1
	vpblendd	$170, %ymm13, %ymm1, %ymm1
	vpmuldq	%ymm2, %ymm7, %ymm13
	vpmuldq	%ymm8, %ymm9, %ymm6
	vpmuldq	%ymm8, %ymm7, %ymm7
	vpmuldq	%ymm14, %ymm0, %ymm9
	vpmuldq	%ymm11, %ymm2, %ymm14
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpsubd	%ymm9, %ymm6, %ymm6
	vpsrlq	$32, %ymm11, %ymm9
	vpsrlq	$32, %ymm6, %ymm6
	vpsubd	%ymm13, %ymm7, %ymm7
	vpmuldq	%ymm2, %ymm9, %ymm13
	vpblendd	$170, %ymm7, %ymm6, %ymm6
	vpmuldq	%ymm8, %ymm11, %ymm7
	vpmuldq	%ymm14, %ymm0, %ymm11
	vpmuldq	%ymm8, %ymm9, %ymm9
	vmovdqu	%ymm6, 384(%rdi)
	vpmuldq	%ymm12, %ymm2, %ymm14
	vpmuldq	%ymm13, %ymm0, %ymm13
	vpsubd	%ymm11, %ymm7, %ymm7
	vpsrlq	$32, %ymm12, %ymm11
	vpsrlq	$32, %ymm7, %ymm7
	vpsubd	%ymm13, %ymm9, %ymm9
	vpmuldq	%ymm2, %ymm11, %ymm13
	vpblendd	$170, %ymm9, %ymm7, %ymm7
	vpmuldq	%ymm8, %ymm12, %ymm9
	vpmuldq	%ymm14, %ymm0, %ymm12
	vpmuldq	%ymm8, %ymm11, %ymm11
	vmovdqu	%ymm7, 416(%rdi)
	vmovdqu	%ymm3, 896(%rdi)
	vmovdqu	%ymm5, 928(%rdi)
	vpmuldq	%ymm13, %ymm0, %ymm13
	vmovdqu	%ymm4, 960(%rdi)
	vmovdqu	%ymm1, 992(%rdi)
	vpsubd	%ymm12, %ymm9, %ymm9
	vpmuldq	%ymm10, %ymm2, %ymm12
	vpsrlq	$32, %ymm9, %ymm9
	vpsubd	%ymm13, %ymm11, %ymm11
	vpblendd	$170, %ymm11, %ymm9, %ymm9
	vpsrlq	$32, %ymm10, %ymm11
	vpmuldq	%ymm2, %ymm11, %ymm2
	vpmuldq	%ymm8, %ymm10, %ymm10
	vmovdqu	%ymm9, 448(%rdi)
	vpmuldq	%ymm8, %ymm11, %ymm11
	vpmuldq	%ymm2, %ymm0, %ymm2
	vpmuldq	%ymm12, %ymm0, %ymm0
	vpsubd	%ymm0, %ymm10, %ymm0
	vpsubd	%ymm2, %ymm11, %ymm11
	vmovdqa	.iLC3(%rip), %ymm2
	vpsrlq	$32, %ymm0, %ymm0
	vpblendd	$170, %ymm11, %ymm0, %ymm0
	vmovdqu	%ymm0, 480(%rdi)
	.p2align 4,,10
	.p2align 3
.iL2:
	vpaddd	(%rax), %ymm2, %ymm1
	vmovdqu	(%rax), %ymm7
	addq	$32, %rax
	vpsrad	$23, %ymm1, %ymm1
	vpslld	$10, %ymm1, %ymm0
	vpsubd	%ymm1, %ymm0, %ymm0
	vpslld	$13, %ymm0, %ymm0
	vpaddd	%ymm1, %ymm0, %ymm0
	vpsubd	%ymm0, %ymm7, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %rdx
	jne	.iL2
	vmovdqa	.iLC4(%rip), %ymm2
	vmovdqa	.iLC5(%rip), %ymm3
	.p2align 4,,10
	.p2align 3
.iL3:
	vmovdqu	(%rdi), %ymm6
	addq	$32, %rdi
	vpsrad	$31, %ymm6, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm6, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rdi)
	cmpq	%rdi, %rdx
	jne	.iL3
	vzeroupper
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.iLFE5823:
	.size	ml_dsa_avx_ntt_inverse_so_impl, .-ml_dsa_avx_ntt_inverse_so_impl
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.iLC0:
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.long	8380417
	.align 32
.iLC1:
	.long	-8395782
	.long	-8395782
	.long	-8395782
	.long	-8395782
	.long	-8395782
	.long	-8395782
	.long	-8395782
	.long	-8395782
	.align 32
.iLC2:
	.long	41978
	.long	41978
	.long	41978
	.long	41978
	.long	41978
	.long	41978
	.long	41978
	.long	41978
	.align 32
.iLC3:
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.long	4194304
	.set	.iLC4,.iLC0
	.align 32
.iLC5:
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417

.text
	.p2align 4
	.globl	ossl_ml_dsa_avx_poly_shuffle
	.type	ossl_ml_dsa_avx_poly_shuffle, @function
ossl_ml_dsa_avx_poly_shuffle:
.sLFB5665:
	.cfi_startproc
	endbr64
	vmovdqu	(%rdi), %ymm4
	vpunpckhdq	32(%rdi), %ymm4, %ymm0
	vpunpckldq	32(%rdi), %ymm4, %ymm1
	vmovdqu	64(%rdi), %ymm7
	vpunpckldq	96(%rdi), %ymm7, %ymm2
	vpunpcklqdq	%ymm0, %ymm1, %ymm6
	vpunpckhqdq	%ymm0, %ymm1, %ymm1
	vmovdqa	.sLC0(%rip), %ymm0
	vpermd	%ymm1, %ymm0, %ymm5
	vpunpckhdq	96(%rdi), %ymm7, %ymm1
	vpermd	%ymm6, %ymm0, %ymm6
	vmovdqu	128(%rdi), %ymm7
	vmovdqu	%ymm5, 32(%rdi)
	vmovdqu	256(%rdi), %ymm5
	vpunpcklqdq	%ymm1, %ymm2, %ymm8
	vpunpckhqdq	%ymm1, %ymm2, %ymm2
	vpunpckldq	160(%rdi), %ymm7, %ymm1
	vmovdqu	%ymm6, (%rdi)
	vpermd	%ymm2, %ymm0, %ymm4
	vpunpckhdq	160(%rdi), %ymm7, %ymm2
	vpermd	%ymm8, %ymm0, %ymm8
	vmovdqu	192(%rdi), %ymm7
	vpunpckhdq	224(%rdi), %ymm7, %ymm3
	vmovdqu	%ymm4, 96(%rdi)
	vmovdqu	320(%rdi), %ymm4
	vpunpcklqdq	%ymm2, %ymm1, %ymm9
	vpunpckhqdq	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm8, 64(%rdi)
	vpermd	%ymm1, %ymm0, %ymm2
	vpunpckldq	224(%rdi), %ymm7, %ymm1
	vpermd	%ymm9, %ymm0, %ymm9
	vmovdqu	%ymm2, 160(%rdi)
	vpunpckldq	288(%rdi), %ymm5, %ymm2
	vpunpcklqdq	%ymm3, %ymm1, %ymm7
	vpunpckhqdq	%ymm3, %ymm1, %ymm1
	vmovdqu	%ymm9, 128(%rdi)
	vpermd	%ymm1, %ymm0, %ymm1
	vpermd	%ymm7, %ymm0, %ymm3
	vmovdqu	384(%rdi), %ymm7
	vmovdqu	%ymm1, 224(%rdi)
	vpunpckhdq	288(%rdi), %ymm5, %ymm1
	vmovdqu	%ymm3, 192(%rdi)
	vpunpcklqdq	%ymm1, %ymm2, %ymm6
	vpunpckhqdq	%ymm1, %ymm2, %ymm2
	vpunpckhdq	352(%rdi), %ymm4, %ymm1
	vpermd	%ymm2, %ymm0, %ymm5
	vpunpckldq	352(%rdi), %ymm4, %ymm2
	vpermd	%ymm6, %ymm0, %ymm6
	vpunpcklqdq	%ymm1, %ymm2, %ymm8
	vpunpckhqdq	%ymm1, %ymm2, %ymm2
	vpunpckldq	416(%rdi), %ymm7, %ymm1
	vpermd	%ymm2, %ymm0, %ymm4
	vpunpckhdq	416(%rdi), %ymm7, %ymm2
	vpermd	%ymm8, %ymm0, %ymm8
	vmovdqu	448(%rdi), %ymm7
	vpunpcklqdq	%ymm2, %ymm1, %ymm9
	vpunpckhqdq	%ymm2, %ymm1, %ymm1
	vpermd	%ymm1, %ymm0, %ymm2
	vpunpckldq	480(%rdi), %ymm7, %ymm1
	vpermd	%ymm9, %ymm0, %ymm9
	vpunpckhdq	480(%rdi), %ymm7, %ymm3
	vmovdqu	%ymm5, 288(%rdi)
	vmovdqu	512(%rdi), %ymm5
	vmovdqu	%ymm2, 416(%rdi)
	vpunpckldq	544(%rdi), %ymm5, %ymm2
	vpunpcklqdq	%ymm3, %ymm1, %ymm7
	vpunpckhqdq	%ymm3, %ymm1, %ymm1
	vmovdqu	%ymm6, 256(%rdi)
	vpermd	%ymm1, %ymm0, %ymm1
	vmovdqu	%ymm4, 352(%rdi)
	vpermd	%ymm7, %ymm0, %ymm3
	vmovdqu	576(%rdi), %ymm4
	vmovdqu	%ymm1, 480(%rdi)
	vpunpckhdq	544(%rdi), %ymm5, %ymm1
	vmovdqu	640(%rdi), %ymm7
	vmovdqu	%ymm8, 320(%rdi)
	vpunpcklqdq	%ymm1, %ymm2, %ymm6
	vpunpckhqdq	%ymm1, %ymm2, %ymm2
	vpunpckhdq	608(%rdi), %ymm4, %ymm1
	vmovdqu	%ymm9, 384(%rdi)
	vpermd	%ymm2, %ymm0, %ymm5
	vpunpckldq	608(%rdi), %ymm4, %ymm2
	vmovdqu	%ymm3, 448(%rdi)
	vpermd	%ymm6, %ymm0, %ymm6
	vmovdqu	%ymm5, 544(%rdi)
	vmovdqu	768(%rdi), %ymm5
	vpunpcklqdq	%ymm1, %ymm2, %ymm8
	vpunpckhqdq	%ymm1, %ymm2, %ymm2
	vpunpckldq	672(%rdi), %ymm7, %ymm1
	vmovdqu	%ymm6, 512(%rdi)
	vpermd	%ymm2, %ymm0, %ymm4
	vpunpckhdq	672(%rdi), %ymm7, %ymm2
	vpermd	%ymm8, %ymm0, %ymm8
	vmovdqu	704(%rdi), %ymm7
	vpunpckhdq	736(%rdi), %ymm7, %ymm3
	vmovdqu	%ymm8, 576(%rdi)
	vpunpcklqdq	%ymm2, %ymm1, %ymm9
	vpunpckhqdq	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm4, 608(%rdi)
	vpermd	%ymm1, %ymm0, %ymm2
	vpunpckldq	736(%rdi), %ymm7, %ymm1
	vpermd	%ymm9, %ymm0, %ymm9
	vmovdqu	%ymm2, 672(%rdi)
	vpunpckldq	800(%rdi), %ymm5, %ymm2
	vpunpcklqdq	%ymm3, %ymm1, %ymm7
	vpunpckhqdq	%ymm3, %ymm1, %ymm1
	vmovdqu	%ymm9, 640(%rdi)
	vpermd	%ymm1, %ymm0, %ymm1
	vpermd	%ymm7, %ymm0, %ymm3
	vmovdqu	%ymm1, 736(%rdi)
	vpunpckhdq	800(%rdi), %ymm5, %ymm1
	vmovdqu	%ymm3, 704(%rdi)
	vmovdqu	832(%rdi), %ymm4
	vmovdqu	896(%rdi), %ymm7
	vpunpcklqdq	%ymm1, %ymm2, %ymm6
	vpunpckhqdq	%ymm1, %ymm2, %ymm2
	vpunpckhdq	864(%rdi), %ymm4, %ymm1
	vpermd	%ymm2, %ymm0, %ymm5
	vpunpckldq	864(%rdi), %ymm4, %ymm2
	vpermd	%ymm6, %ymm0, %ymm6
	vmovdqu	%ymm6, 768(%rdi)
	vpunpcklqdq	%ymm1, %ymm2, %ymm8
	vpunpckhqdq	%ymm1, %ymm2, %ymm2
	vpunpckldq	928(%rdi), %ymm7, %ymm1
	vmovdqu	%ymm5, 800(%rdi)
	vpermd	%ymm2, %ymm0, %ymm4
	vpunpckhdq	928(%rdi), %ymm7, %ymm2
	vpermd	%ymm8, %ymm0, %ymm8
	vmovdqu	960(%rdi), %ymm7
	vpunpckhdq	992(%rdi), %ymm7, %ymm3
	vmovdqu	%ymm8, 832(%rdi)
	vpunpcklqdq	%ymm2, %ymm1, %ymm9
	vpunpckhqdq	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm4, 864(%rdi)
	vpermd	%ymm1, %ymm0, %ymm2
	vpunpckldq	992(%rdi), %ymm7, %ymm1
	vpermd	%ymm9, %ymm0, %ymm9
	vmovdqu	%ymm9, 896(%rdi)
	vpunpcklqdq	%ymm3, %ymm1, %ymm7
	vpunpckhqdq	%ymm3, %ymm1, %ymm1
	vmovdqu	%ymm2, 928(%rdi)
	vpermd	%ymm7, %ymm0, %ymm3
	vpermd	%ymm1, %ymm0, %ymm1
	vmovdqu	%ymm3, 960(%rdi)
	vmovdqu	%ymm1, 992(%rdi)
	vzeroupper
	ret
	.cfi_endproc
.sLFE5665:
	.size	ossl_ml_dsa_avx_poly_shuffle, .-ossl_ml_dsa_avx_poly_shuffle
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.sLC0:
	.long	0
	.long	2
	.long	4
	.long	6
	.long	1
	.long	3
	.long	5
	.long	7

	.section	.rodata
	.align 32
inte_qdata:
	.type	inte_qdata, @object
	.long	2706023, -1846138265, 2706023, -1846138265, 95776, -1631226336, 95776, -1631226336
	.long	3077325, -1404529459, 3077325, -1404529459, 3530437, 1838055109, 3530437, 1838055109
	.long	-1661693, 1594295555, -1661693, 1594295555, -3592148, -1076973524, -3592148, -1076973524
	.long	-2537516, -1898723372, -2537516, -1898723372, 3915439, -594436433, 3915439, -594436433
	.long	-3861115, -202001019, -3861115, -202001019, -3043716, -475984260, -3043716, -475984260
	.long	3574422, -561427818, 3574422, -561427818, -2867647, 1797021249, -2867647, 1797021249
	.long	3539968, -1061813248, 3539968, -1061813248, -300467, 2059733581, -300467, 2059733581
	.long	2348700, -1661512036, 2348700, -1661512036, -539299, -1104976547, -539299, -1104976547
	.long	-1699267, -1750224323, -1699267, -1750224323, -1643818, -901666090, -1643818, -901666090
	.long	3505694, 418987550, 3505694, 418987550, -3821735, 1831915353, -3821735, 1831915353
	.long	3507263, -1925356481, 3507263, -1925356481, -2140649, 992097815, -2140649, 992097815
	.long	-1600420, 879957084, -1600420, 879957084, 3699596, 2024403852, 3699596, 2024403852
	.long	811944, 1484874664, 811944, 1484874664, 531354, -1636082790, 531354, -1636082790
	.long	954230, -285388938, 954230, -285388938, 3881043, -1983539117, 3881043, -1983539117
	.long	3900724, -1495136972, 3900724, -1495136972, -2556880, -950076368, -2556880, -950076368
	.long	2071892, -1714807468, 2071892, -1714807468, -2797779, -952438995, -2797779, -952438995
	.long	-3930395, -1574918427, -1528703, -654783359, -3677745, 1350681039, -3041255, -1974159335
	.long	-1452451, -2143979939, 3475950, 1651689966, 2176455, 1599739335, -1585221, 140455867
	.long	-1257611, -1285853323, 1939314, -1039411342, -4083598, -993005454, -1000202, 1955560694
	.long	-3190144, -1440787840, -3157330, 1529189038, -3632928, 568627424, 126922, -2131021878
	.long	3412210, -783134478, -983419, -247357819, 2147896, -588790216, 2715295, 1518161567
	.long	-2967645, 289871779, -3693493, -86965173, -411027, -1262003603, -2477047, 1708872713
	.long	-671102, 2135294594, -1228525, 1787797779, -22981, -1018755525, -1308169, 1638590967
	.long	-381987, -889861155, 1349076, -120646188, 1852771, 1665705315, -1430430, -1669960606
	.long	-3343383, 1321868265, 264944, -916321552, 508951, 1225434135, 3097992, 1155548552
	.long	44288, -1784632064, -1100098, 2143745726, 904516, 666258756, 3958618, 1210558298
	.long	-3724342, 675310538, -8578, -1261461890, 1653064, -1555941048, -3249728, -318346816
	.long	2389356, -1999506068, -210977, 628664287, 759969, -1499481951, -1316856, -1729304568
	.long	189548, -695180180, -3553272, 1422575624, 3159746, -1375177022, -1851402, 1424130038
	.long	-2409325, 1777179795, -177440, -1185330464, 1315589, 334803717, 1341330, 235321234
	.long	1285669, -178766299, -1584928, 168022240, -812732, -518252220, -1439742, 1206536194
	.long	-3019102, 1957047970, -3881060, 985155484, -3628969, 1146323031, 3839961, -894060583
	.long	2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462
	.long	266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378
	.long	900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500
	.long	-655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838
	.long	342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044
	.long	2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974
	.long	-3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970
	.long	-1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642
	.long	-1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031
	.long	-542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993
	.long	-2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385
	.long	-3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107
	.long	-3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078
	.long	-426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893
	.long	-2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687
	.long	-554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782
	.long	-898413, 991903578, 1363007700, 746144248, -1363460238, 912367099, 30313375, -1420958686
	.long	-605900043, -44694137, -326425360, 2032221021, 2027833504, 1176904444, 1683520342, 1904936414
	.long	14253662, -421552614, -517299994, 1257750362, 1014493059, -818371958, 2027935492, 1926727420
	.long	863641633, 1747917558, -1372618620, 1931587462, 1819892093, -325927722, 128353682, 1258381762
	.long	2124962073, 908452108, -1123881663, 885133339, -1223601433, 1851023419, 137583815, 1629985060
	.long	-1920467227, -1176751719, -635454918, 1967222129, -1637785316, -1354528380, -642772911, 6363718
	.long	-1536588520, -72690498, 45766801, -1287922800, 694382729, -314284737, 671509323, 1136965286
	.long	235104446, 985022747, -2070602178, 1779436847, -1045062172, 963438279, 419615363, 1116720494
	.long	831969619, -1078959975, 1216882040, 1042326957, -300448763, 604552167, -270590488, 1405999311
	.long	756955444, -1021949428, -1276805128, 713994583, -260312805, 608791570, 371462360, 940195359
	.long	1554794072, 173440395, -1357098057, -1542497137, 1339088280, -2126092136, -384158533, 2061661095
	.long	-2040058690, -1316619236, 827959816, -883155599, -853476187, -1039370342, -596344473, 1726753853
	.long	-2047270596, 6087993, 702390549, -1547952704, -1723816713, -110126092, -279505433, 394851342
	.long	-1591599803, 565464272, -260424530, 283780712, -440824168, -1758099917, -71875110, 776003547
	.long	1119856484, -1600929361, -1208667171, 1123958025, 1544891539, 879867909, -1499603926, 201262505
	.long	155290192, -1809756372, 2036925262, 1934038751, -973777462, 400711272, -540420426, 374860238
	.size	inte_qdata, .-inte_qdata
	.align 32
inv_qdata:
	.type	inv_qdata, @object
	.long	-1976782, 846154, -1400424, -3937738, 1362209, 48306, -3919660, 554416
	.long	3545687, -1612842, 976891, -183443, 2286327, 420899, 2235985, 2939036
	.long	3833893, 260646, 1104333, 1667432, -1910376, 1803090, -1723600, 426683
	.long	-472078, -1717735, 975884, -2213111, -269760, -3866901, -3523897, 3038916
	.long	1799107, 3694233, -1652634, -810149, -3014001, -1616392, -162844, 3183426
	.long	1207385, -185531, -3369112, -1957272, 164721, -2454455, -2432395, 2013608
	.long	3776993, -594136, 3724270, 2584293, 1846953, 1671176, 2831860, 542412
	.long	-3406031, -2235880, -777191, -1500165, 1374803, 2546312, -1917081, 1279661
	.long	1962642, -3306115, -1312455, 451100, 1430225, 3318210, -1237275, 1333058
	.long	1050970, -1903435, -1869119, 2994039, 3548272, -2635921, -1250494, 3767016
	.long	-1595974, -2486353, -1247620, -4055324, -1265009, 2590150, -2691481, -2842341
	.long	-203044, -1735879, 3342277, -3437287, -4108315, 2437823, -286988, -342297
	.long	3595838, 768622, 525098, 3556995, -3207046, -2031748, 3122442, 655327
	.long	522500, 43260, 1613174, -495491, -819034, -909542, -1859098, -900702
	.long	3193378, 1197226, 3759364, 3520352, -3513181, 1235728, -2434439, -266997
	.long	3562462, 2446433, -2244091, 3342478, -3817976, -2316500, -3407706, -2091667
	.long	-374860238, 540420426, -400711272, 973777462, -1934038751, -2036925262, 1809756372, -155290192
	.long	-201262505, 1499603926, -879867909, -1544891539, -1123958025, 1208667171, 1600929361, -1119856484
	.long	-776003547, 71875110, 1758099917, 440824168, -283780712, 260424530, -565464272, 1591599803
	.long	-394851342, 279505433, 110126092, 1723816713, 1547952704, -702390549, -6087993, 2047270596
	.long	-1726753853, 596344473, 1039370342, 853476187, 883155599, -827959816, 1316619236, 2040058690
	.long	-2061661095, 384158533, 2126092136, -1339088280, 1542497137, 1357098057, -173440395, -1554794072
	.long	-940195359, -371462360, -608791570, 260312805, -713994583, 1276805128, 1021949428, -756955444
	.long	-1405999311, 270590488, -604552167, 300448763, -1042326957, -1216882040, 1078959975, -831969619
	.long	-1116720494, -419615363, -963438279, 1045062172, -1779436847, 2070602178, -985022747, -235104446
	.long	-1136965286, -671509323, 314284737, -694382729, 1287922800, -45766801, 72690498, 1536588520
	.long	-6363718, 642772911, 1354528380, 1637785316, -1967222129, 635454918, 1176751719, 1920467227
	.long	-1629985060, -137583815, -1851023419, 1223601433, -885133339, 1123881663, -908452108, -2124962073
	.long	-1258381762, -128353682, 325927722, -1819892093, -1931587462, 1372618620, -1747917558, -863641633
	.long	-1926727420, -2027935492, 818371958, -1014493059, -1257750362, 517299994, 421552614, -14253662
	.long	-1904936414, -1683520342, -1176904444, -2027833504, -2032221021, 326425360, 44694137, 605900043
	.long	1420958686, -30313375, -912367099, 1363460238, -746144248, -1363007700, -991903578, 898413
	.long	-3839961, 894060583, 3628969, -1146323031, 3881060, -985155484, 3019102, -1957047970
	.long	1439742, -1206536194, 812732, 518252220, 1584928, -168022240, -1285669, 178766299
	.long	-1341330, -235321234, -1315589, -334803717, 177440, 1185330464, 2409325, -1777179795
	.long	1851402, -1424130038, -3159746, 1375177022, 3553272, -1422575624, -189548, 695180180
	.long	1316856, 1729304568, -759969, 1499481951, 210977, -628664287, -2389356, 1999506068
	.long	3249728, 318346816, -1653064, 1555941048, 8578, 1261461890, 3724342, -675310538
	.long	-3958618, -1210558298, -904516, -666258756, 1100098, -2143745726, -44288, 1784632064
	.long	-3097992, -1155548552, -508951, -1225434135, -264944, 916321552, 3343383, -1321868265
	.long	1430430, 1669960606, -1852771, -1665705315, -1349076, 120646188, 381987, 889861155
	.long	1308169, -1638590967, 22981, 1018755525, 1228525, -1787797779, 671102, -2135294594
	.long	2477047, -1708872713, 411027, 1262003603, 3693493, 86965173, 2967645, -289871779
	.long	-2715295, -1518161567, -2147896, 588790216, 983419, 247357819, -3412210, 783134478
	.long	-126922, 2131021878, 3632928, -568627424, 3157330, -1529189038, 3190144, 1440787840
	.long	1000202, -1955560694, 4083598, 993005454, -1939314, 1039411342, 1257611, 1285853323
	.long	1585221, -140455867, -2176455, -1599739335, -3475950, -1651689966, 1452451, 2143979939
	.long	3041255, 1974159335, 3677745, -1350681039, 1528703, 654783359, 3930395, 1574918427
	.long	2797779, 952438995, 2797779, 952438995, -2071892, 1714807468, -2071892, 1714807468
	.long	2556880, 950076368, 2556880, 950076368, -3900724, 1495136972, -3900724, 1495136972
	.long	-3881043, 1983539117, -3881043, 1983539117, -954230, 285388938, -954230, 285388938
	.long	-531354, 1636082790, -531354, 1636082790, -811944, -1484874664, -811944, -1484874664
	.long	-3699596, -2024403852, -3699596, -2024403852, 1600420, -879957084, 1600420, -879957084
	.long	2140649, -992097815, 2140649, -992097815, -3507263, 1925356481, -3507263, 1925356481
	.long	3821735, -1831915353, 3821735, -1831915353, -3505694, -418987550, -3505694, -418987550
	.long	1643818, 901666090, 1643818, 901666090, 1699267, 1750224323, 1699267, 1750224323
	.long	539299, 1104976547, 539299, 1104976547, -2348700, 1661512036, -2348700, 1661512036
	.long	300467, -2059733581, 300467, -2059733581, -3539968, 1061813248, -3539968, 1061813248
	.long	2867647, -1797021249, 2867647, -1797021249, -3574422, 561427818, -3574422, 561427818
	.long	3043716, 475984260, 3043716, 475984260, 3861115, 202001019, 3861115, 202001019
	.long	-3915439, 594436433, -3915439, 594436433, 2537516, 1898723372, 2537516, 1898723372
	.long	3592148, 1076973524, 3592148, 1076973524, 1661693, -1594295555, 1661693, -1594295555
	.long	-3530437, -1838055109, -3530437, -1838055109, -3077325, 1404529459, -3077325, 1404529459
	.long	-95776, 1631226336, -95776, 1631226336, -2706023, 1846138265, -2706023, 1846138265
	.size	inv_qdata, .-inv_qdata
	.align 32
inte_data2:
	.type	inte_data2, @object
	.quad	5026890454075685435, 6197707352234446335, 10555324674760264670, 17032208947096137675
	.quad	-2688021319612163367, 1227061264427025847, -7046899915112783396, 3215292404180583272
	.quad	5401640081663810313, 3773459142719235353, 11341631945690862122, 16234039556321314039
	.quad	8287121994421396875, 11522563928434237144, 15506118388641442949, 1489291355973224088
	.quad	17491160029839037792, 10688838998786859632, 4688259860773464961, 5904178786035137363
	.quad	12099165486945394408, 14760627463231457400, 5862554612997847644, 9503263240079040400
	.quad	11028024287114455464, 7797620835075495637, 17122335958174540245, 11399703283669688764
	.quad	8279739259175824125, 8288750860774133502, 648740589428058657, 0
	.size	inte_data2, .-inte_data2
	.section	.note.GNU-stack,"",@progbits
