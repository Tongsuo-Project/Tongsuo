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
# ML-DSA AVX2 sparse challenge multiply (c·s / c·t0)
#
# Implemented:
#   poly_sparse_cs_table_u8
#   poly_sparse_cs_table_u16
#   poly_sparse_ct_table_i32
#   poly_sparse_cs_mult_u8_pos
#   poly_sparse_cs_mult_u16_pos
#   poly_sparse_ct_mult_i32_pos
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

.globl  poly_sparse_cs_table_u8
.globl  poly_sparse_cs_table_u16
.globl  poly_sparse_ct_table_i32
.globl  poly_sparse_cs_mult_u8_pos
.globl  poly_sparse_cs_mult_u16_pos
.globl  poly_sparse_ct_mult_i32_pos
.type   poly_sparse_cs_table_u8,\@abi-omnipotent
.align 32
poly_sparse_cs_table_u8:
poly_sparse_cs_table_u16:
poly_sparse_ct_table_i32:
poly_sparse_cs_mult_u8_pos:
poly_sparse_cs_mult_u16_pos:
poly_sparse_ct_mult_i32_pos:
    .byte   0x0f,0x0b       # ud2
    ret
.size   poly_sparse_cs_table_u8, .-poly_sparse_cs_table_u8
___

    open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
      or die "can't call $xlate: $!";
    print OUT $code;
    close OUT or die "error closing STDOUT: $!";
}}}

__DATA__
	.file	"ml_dsa_avx_pspm.c"
	.text
	.p2align 4
	.globl	poly_sparse_cs_table_u8
	.type	poly_sparse_cs_table_u8, @function
poly_sparse_cs_table_u8:
.LFB5687:
	.cfi_startproc
	endbr64
	leaq	1024(%rdi), %rax
	cmpq	%rax, %rsi
	jnb	.L7
	leaq	768(%rsi), %rax
	cmpq	%rax, %rdi
	jb	.L6
.L7:
	vmovdqa	.LC0(%rip), %ymm1
	vmovdqu	(%rdi), %ymm6
	vmovdqa	.LC1(%rip), %ymm0
	vmovdqu	32(%rdi), %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vmovdqu	64(%rdi), %ymm3
	vmovdqu	96(%rdi), %ymm2
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vpminud	%ymm1, %ymm4, %ymm7
	vpaddd	%ymm0, %ymm4, %ymm6
	vpcmpeqd	%ymm7, %ymm4, %ymm7
	vpblendvb	%ymm7, %ymm4, %ymm6, %ymm6
	vpminud	%ymm1, %ymm3, %ymm7
	vpaddd	%ymm0, %ymm3, %ymm4
	vpcmpeqd	%ymm7, %ymm3, %ymm7
	vpblendvb	%ymm7, %ymm3, %ymm4, %ymm4
	vpminud	%ymm1, %ymm2, %ymm7
	vpaddd	%ymm0, %ymm2, %ymm3
	vpcmpeqd	%ymm7, %ymm2, %ymm7
	vpblendvb	%ymm7, %ymm2, %ymm3, %ymm3
	vmovdqa	.LC2(%rip), %ymm2
	vpand	%ymm6, %ymm2, %ymm6
	vpand	%ymm3, %ymm2, %ymm3
	vpand	%ymm5, %ymm2, %ymm5
	vpand	%ymm4, %ymm2, %ymm4
	vpackusdw	%ymm6, %ymm5, %ymm5
	vpackusdw	%ymm3, %ymm4, %ymm4
	vmovdqa	.LC3(%rip), %ymm3
	vpermq	$216, %ymm5, %ymm5
	vpermq	$216, %ymm4, %ymm4
	vpand	%ymm4, %ymm3, %ymm4
	vpand	%ymm5, %ymm3, %ymm5
	vpackuswb	%ymm4, %ymm5, %ymm5
	vpxor	%xmm4, %xmm4, %xmm4
	vpermq	$216, %ymm5, %ymm5
	vpsubb	%ymm5, %ymm4, %ymm6
	vmovdqu	%ymm5, 256(%rsi)
	vmovdqu	%ymm6, (%rsi)
	vmovdqu	%ymm6, 512(%rsi)
	vmovdqu	128(%rdi), %ymm8
	vmovdqu	160(%rdi), %ymm6
	vmovdqu	192(%rdi), %ymm7
	vmovdqu	224(%rdi), %ymm9
	vpminud	%ymm1, %ymm8, %ymm10
	vpaddd	%ymm0, %ymm8, %ymm5
	vpcmpeqd	%ymm10, %ymm8, %ymm10
	vpblendvb	%ymm10, %ymm8, %ymm5, %ymm5
	vpminud	%ymm1, %ymm6, %ymm10
	vpaddd	%ymm0, %ymm6, %ymm8
	vpcmpeqd	%ymm10, %ymm6, %ymm10
	vpand	%ymm5, %ymm2, %ymm5
	vpblendvb	%ymm10, %ymm6, %ymm8, %ymm8
	vpminud	%ymm1, %ymm7, %ymm10
	vpaddd	%ymm0, %ymm7, %ymm6
	vpcmpeqd	%ymm10, %ymm7, %ymm10
	vpand	%ymm8, %ymm2, %ymm8
	vpackusdw	%ymm8, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpblendvb	%ymm10, %ymm7, %ymm6, %ymm6
	vpminud	%ymm1, %ymm9, %ymm10
	vpaddd	%ymm0, %ymm9, %ymm7
	vpcmpeqd	%ymm10, %ymm9, %ymm10
	vpand	%ymm6, %ymm2, %ymm6
	vpand	%ymm5, %ymm3, %ymm5
	vpblendvb	%ymm10, %ymm9, %ymm7, %ymm7
	vpand	%ymm7, %ymm2, %ymm7
	vpackusdw	%ymm7, %ymm6, %ymm6
	vpermq	$216, %ymm6, %ymm6
	vpand	%ymm6, %ymm3, %ymm6
	vpackuswb	%ymm6, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpsubb	%ymm5, %ymm4, %ymm6
	vmovdqu	%ymm5, 288(%rsi)
	vmovdqu	%ymm6, 32(%rsi)
	vmovdqu	%ymm6, 544(%rsi)
	vmovdqu	256(%rdi), %ymm8
	vmovdqu	288(%rdi), %ymm6
	vmovdqu	320(%rdi), %ymm7
	vmovdqu	352(%rdi), %ymm9
	vpminud	%ymm1, %ymm8, %ymm10
	vpaddd	%ymm0, %ymm8, %ymm5
	vpcmpeqd	%ymm10, %ymm8, %ymm10
	vpblendvb	%ymm10, %ymm8, %ymm5, %ymm5
	vpminud	%ymm1, %ymm6, %ymm10
	vpaddd	%ymm0, %ymm6, %ymm8
	vpcmpeqd	%ymm10, %ymm6, %ymm10
	vpand	%ymm5, %ymm2, %ymm5
	vpblendvb	%ymm10, %ymm6, %ymm8, %ymm8
	vpminud	%ymm1, %ymm7, %ymm10
	vpaddd	%ymm0, %ymm7, %ymm6
	vpcmpeqd	%ymm10, %ymm7, %ymm10
	vpand	%ymm8, %ymm2, %ymm8
	vpackusdw	%ymm8, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpblendvb	%ymm10, %ymm7, %ymm6, %ymm6
	vpminud	%ymm1, %ymm9, %ymm10
	vpaddd	%ymm0, %ymm9, %ymm7
	vpcmpeqd	%ymm10, %ymm9, %ymm10
	vpand	%ymm6, %ymm2, %ymm6
	vpand	%ymm5, %ymm3, %ymm5
	vpblendvb	%ymm10, %ymm9, %ymm7, %ymm7
	vpand	%ymm7, %ymm2, %ymm7
	vpackusdw	%ymm7, %ymm6, %ymm6
	vpermq	$216, %ymm6, %ymm6
	vpand	%ymm6, %ymm3, %ymm6
	vpackuswb	%ymm6, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpsubb	%ymm5, %ymm4, %ymm6
	vmovdqu	%ymm5, 320(%rsi)
	vmovdqu	%ymm6, 64(%rsi)
	vmovdqu	%ymm6, 576(%rsi)
	vmovdqu	384(%rdi), %ymm8
	vmovdqu	416(%rdi), %ymm6
	vmovdqu	448(%rdi), %ymm7
	vmovdqu	480(%rdi), %ymm9
	vpminud	%ymm1, %ymm8, %ymm10
	vpaddd	%ymm0, %ymm8, %ymm5
	vpcmpeqd	%ymm10, %ymm8, %ymm10
	vpblendvb	%ymm10, %ymm8, %ymm5, %ymm5
	vpminud	%ymm1, %ymm6, %ymm10
	vpaddd	%ymm0, %ymm6, %ymm8
	vpcmpeqd	%ymm10, %ymm6, %ymm10
	vpand	%ymm5, %ymm2, %ymm5
	vpblendvb	%ymm10, %ymm6, %ymm8, %ymm8
	vpminud	%ymm1, %ymm7, %ymm10
	vpaddd	%ymm0, %ymm7, %ymm6
	vpcmpeqd	%ymm10, %ymm7, %ymm10
	vpand	%ymm8, %ymm2, %ymm8
	vpackusdw	%ymm8, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpblendvb	%ymm10, %ymm7, %ymm6, %ymm6
	vpminud	%ymm1, %ymm9, %ymm10
	vpaddd	%ymm0, %ymm9, %ymm7
	vpcmpeqd	%ymm10, %ymm9, %ymm10
	vpand	%ymm6, %ymm2, %ymm6
	vpand	%ymm5, %ymm3, %ymm5
	vpblendvb	%ymm10, %ymm9, %ymm7, %ymm7
	vpand	%ymm7, %ymm2, %ymm7
	vpackusdw	%ymm7, %ymm6, %ymm6
	vpermq	$216, %ymm6, %ymm6
	vpand	%ymm6, %ymm3, %ymm6
	vpackuswb	%ymm6, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpsubb	%ymm5, %ymm4, %ymm6
	vmovdqu	%ymm5, 352(%rsi)
	vmovdqu	%ymm6, 96(%rsi)
	vmovdqu	%ymm6, 608(%rsi)
	vmovdqu	512(%rdi), %ymm8
	vmovdqu	544(%rdi), %ymm6
	vmovdqu	576(%rdi), %ymm7
	vmovdqu	608(%rdi), %ymm9
	vpminud	%ymm1, %ymm8, %ymm10
	vpaddd	%ymm0, %ymm8, %ymm5
	vpcmpeqd	%ymm10, %ymm8, %ymm10
	vpblendvb	%ymm10, %ymm8, %ymm5, %ymm5
	vpminud	%ymm1, %ymm6, %ymm10
	vpaddd	%ymm0, %ymm6, %ymm8
	vpcmpeqd	%ymm10, %ymm6, %ymm10
	vpand	%ymm5, %ymm2, %ymm5
	vpblendvb	%ymm10, %ymm6, %ymm8, %ymm8
	vpminud	%ymm1, %ymm7, %ymm10
	vpaddd	%ymm0, %ymm7, %ymm6
	vpcmpeqd	%ymm10, %ymm7, %ymm10
	vpand	%ymm8, %ymm2, %ymm8
	vpackusdw	%ymm8, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpblendvb	%ymm10, %ymm7, %ymm6, %ymm6
	vpminud	%ymm1, %ymm9, %ymm10
	vpaddd	%ymm0, %ymm9, %ymm7
	vpcmpeqd	%ymm10, %ymm9, %ymm10
	vpand	%ymm6, %ymm2, %ymm6
	vpand	%ymm5, %ymm3, %ymm5
	vpblendvb	%ymm10, %ymm9, %ymm7, %ymm7
	vpand	%ymm7, %ymm2, %ymm7
	vpackusdw	%ymm7, %ymm6, %ymm6
	vpermq	$216, %ymm6, %ymm6
	vpand	%ymm6, %ymm3, %ymm6
	vpackuswb	%ymm6, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpsubb	%ymm5, %ymm4, %ymm6
	vmovdqu	%ymm5, 384(%rsi)
	vmovdqu	%ymm6, 128(%rsi)
	vmovdqu	%ymm6, 640(%rsi)
	vmovdqu	640(%rdi), %ymm8
	vmovdqu	672(%rdi), %ymm6
	vmovdqu	704(%rdi), %ymm7
	vmovdqu	736(%rdi), %ymm9
	vpminud	%ymm1, %ymm8, %ymm10
	vpaddd	%ymm0, %ymm8, %ymm5
	vpcmpeqd	%ymm10, %ymm8, %ymm10
	vpblendvb	%ymm10, %ymm8, %ymm5, %ymm5
	vpminud	%ymm1, %ymm6, %ymm10
	vpaddd	%ymm0, %ymm6, %ymm8
	vpcmpeqd	%ymm10, %ymm6, %ymm10
	vpand	%ymm5, %ymm2, %ymm5
	vpblendvb	%ymm10, %ymm6, %ymm8, %ymm8
	vpminud	%ymm1, %ymm7, %ymm10
	vpaddd	%ymm0, %ymm7, %ymm6
	vpcmpeqd	%ymm10, %ymm7, %ymm10
	vpand	%ymm8, %ymm2, %ymm8
	vpackusdw	%ymm8, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpblendvb	%ymm10, %ymm7, %ymm6, %ymm6
	vpminud	%ymm1, %ymm9, %ymm10
	vpaddd	%ymm0, %ymm9, %ymm7
	vpcmpeqd	%ymm10, %ymm9, %ymm10
	vpand	%ymm6, %ymm2, %ymm6
	vpand	%ymm5, %ymm3, %ymm5
	vpblendvb	%ymm10, %ymm9, %ymm7, %ymm7
	vpand	%ymm7, %ymm2, %ymm7
	vpackusdw	%ymm7, %ymm6, %ymm6
	vpermq	$216, %ymm6, %ymm6
	vpand	%ymm6, %ymm3, %ymm6
	vpackuswb	%ymm6, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpsubb	%ymm5, %ymm4, %ymm6
	vmovdqu	%ymm5, 416(%rsi)
	vmovdqu	%ymm6, 160(%rsi)
	vmovdqu	%ymm6, 672(%rsi)
	vmovdqu	768(%rdi), %ymm8
	vmovdqu	800(%rdi), %ymm6
	vmovdqu	832(%rdi), %ymm7
	vmovdqu	864(%rdi), %ymm9
	vpminud	%ymm1, %ymm8, %ymm10
	vpaddd	%ymm0, %ymm8, %ymm5
	vpcmpeqd	%ymm10, %ymm8, %ymm10
	vpblendvb	%ymm10, %ymm8, %ymm5, %ymm5
	vpminud	%ymm1, %ymm6, %ymm10
	vpaddd	%ymm0, %ymm6, %ymm8
	vpcmpeqd	%ymm10, %ymm6, %ymm10
	vpand	%ymm5, %ymm2, %ymm5
	vpblendvb	%ymm10, %ymm6, %ymm8, %ymm8
	vpminud	%ymm1, %ymm7, %ymm10
	vpaddd	%ymm0, %ymm7, %ymm6
	vpcmpeqd	%ymm10, %ymm7, %ymm10
	vpand	%ymm8, %ymm2, %ymm8
	vpackusdw	%ymm8, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpblendvb	%ymm10, %ymm7, %ymm6, %ymm6
	vpminud	%ymm1, %ymm9, %ymm10
	vpaddd	%ymm0, %ymm9, %ymm7
	vpcmpeqd	%ymm10, %ymm9, %ymm10
	vpand	%ymm6, %ymm2, %ymm6
	vpand	%ymm5, %ymm3, %ymm5
	vpblendvb	%ymm10, %ymm9, %ymm7, %ymm7
	vpand	%ymm7, %ymm2, %ymm7
	vpackusdw	%ymm7, %ymm6, %ymm6
	vpermq	$216, %ymm6, %ymm6
	vpand	%ymm6, %ymm3, %ymm6
	vpackuswb	%ymm6, %ymm5, %ymm5
	vpermq	$216, %ymm5, %ymm5
	vpsubb	%ymm5, %ymm4, %ymm6
	vmovdqu	%ymm5, 448(%rsi)
	vmovdqu	%ymm6, 192(%rsi)
	vmovdqu	%ymm6, 704(%rsi)
	vmovdqu	896(%rdi), %ymm8
	vmovdqu	928(%rdi), %ymm6
	vmovdqu	960(%rdi), %ymm7
	vmovdqu	992(%rdi), %ymm9
	vpminud	%ymm1, %ymm8, %ymm10
	vpaddd	%ymm0, %ymm8, %ymm5
	vpcmpeqd	%ymm10, %ymm8, %ymm10
	vpblendvb	%ymm10, %ymm8, %ymm5, %ymm5
	vpminud	%ymm1, %ymm6, %ymm10
	vpaddd	%ymm0, %ymm6, %ymm8
	vpcmpeqd	%ymm10, %ymm6, %ymm10
	vpblendvb	%ymm10, %ymm6, %ymm8, %ymm8
	vpminud	%ymm1, %ymm7, %ymm10
	vpminud	%ymm1, %ymm9, %ymm1
	vpcmpeqd	%ymm1, %ymm9, %ymm1
	vpcmpeqd	%ymm10, %ymm7, %ymm10
	vpaddd	%ymm0, %ymm7, %ymm6
	vpaddd	%ymm0, %ymm9, %ymm0
	vpblendvb	%ymm1, %ymm9, %ymm0, %ymm0
	vpblendvb	%ymm10, %ymm7, %ymm6, %ymm6
	vpand	%ymm5, %ymm2, %ymm1
	vpand	%ymm8, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm1, %ymm1
	vpand	%ymm6, %ymm2, %ymm5
	vpand	%ymm0, %ymm2, %ymm2
	vpackusdw	%ymm2, %ymm5, %ymm2
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm2, %ymm2
	vpand	%ymm1, %ymm3, %ymm0
	vpand	%ymm2, %ymm3, %ymm3
	vpackuswb	%ymm3, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpsubb	%ymm0, %ymm4, %ymm4
	vmovdqu	%ymm0, 480(%rsi)
	vmovdqu	%ymm4, 224(%rsi)
	vmovdqu	%ymm4, 736(%rsi)
	vzeroupper
	ret
.L6:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L2:
	movl	(%rdi,%rax,4), %edx
	cmpl	$4190208, %edx
	leal	-8380417(%rdx), %ecx
	cmova	%ecx, %edx
	movl	%edx, %ecx
	movb	%dl, 256(%rsi,%rax)
	negl	%ecx
	movb	%cl, (%rsi,%rax)
	movb	%cl, 512(%rsi,%rax)
	addq	$1, %rax
	cmpq	$256, %rax
	jne	.L2
	ret
	.cfi_endproc
.LFE5687:
	.size	poly_sparse_cs_table_u8, .-poly_sparse_cs_table_u8
	.p2align 4
	.globl	poly_sparse_cs_table_u16
	.type	poly_sparse_cs_table_u16, @function
poly_sparse_cs_table_u16:
.LFB5688:
	.cfi_startproc
	endbr64
	vmovdqa	.LC0(%rip), %ymm1
	vmovdqu	(%rdi), %ymm3
	vmovdqa	.LC1(%rip), %ymm0
	vmovdqu	32(%rdi), %ymm2
	vpminud	%ymm1, %ymm3, %ymm5
	vmovdqu	96(%rdi), %ymm6
	vpcmpeqd	%ymm5, %ymm3, %ymm5
	vpaddd	%ymm0, %ymm3, %ymm4
	vpblendvb	%ymm5, %ymm3, %ymm4, %ymm4
	vpminud	%ymm1, %ymm2, %ymm5
	vpaddd	%ymm0, %ymm2, %ymm3
	vpcmpeqd	%ymm5, %ymm2, %ymm5
	vpblendvb	%ymm5, %ymm2, %ymm3, %ymm3
	vmovdqa	.LC2(%rip), %ymm2
	vpand	%ymm3, %ymm2, %ymm3
	vpand	%ymm4, %ymm2, %ymm4
	vpackusdw	%ymm3, %ymm4, %ymm4
	vpxor	%xmm3, %xmm3, %xmm3
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 512(%rsi)
	vmovdqu	%ymm5, (%rsi)
	vmovdqu	%ymm5, 1024(%rsi)
	vmovdqu	64(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	160(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 544(%rsi)
	vmovdqu	%ymm5, 32(%rsi)
	vmovdqu	%ymm5, 1056(%rsi)
	vmovdqu	128(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	224(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 576(%rsi)
	vmovdqu	%ymm5, 64(%rsi)
	vmovdqu	%ymm5, 1088(%rsi)
	vmovdqu	192(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	288(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 608(%rsi)
	vmovdqu	%ymm5, 96(%rsi)
	vmovdqu	%ymm5, 1120(%rsi)
	vmovdqu	256(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	352(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 640(%rsi)
	vmovdqu	%ymm5, 128(%rsi)
	vmovdqu	%ymm5, 1152(%rsi)
	vmovdqu	320(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 672(%rsi)
	vmovdqu	%ymm5, 160(%rsi)
	vmovdqu	%ymm5, 1184(%rsi)
	vmovdqu	384(%rdi), %ymm5
	vmovdqu	416(%rdi), %ymm6
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	480(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 704(%rsi)
	vmovdqu	%ymm5, 192(%rsi)
	vmovdqu	%ymm5, 1216(%rsi)
	vmovdqu	448(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	544(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 736(%rsi)
	vmovdqu	%ymm5, 224(%rsi)
	vmovdqu	%ymm5, 1248(%rsi)
	vmovdqu	512(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	608(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 768(%rsi)
	vmovdqu	%ymm5, 256(%rsi)
	vmovdqu	%ymm5, 1280(%rsi)
	vmovdqu	576(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	672(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 800(%rsi)
	vmovdqu	%ymm5, 288(%rsi)
	vmovdqu	%ymm5, 1312(%rsi)
	vmovdqu	640(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	736(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 832(%rsi)
	vmovdqu	%ymm5, 320(%rsi)
	vmovdqu	%ymm5, 1344(%rsi)
	vmovdqu	704(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	800(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 864(%rsi)
	vmovdqu	%ymm5, 352(%rsi)
	vmovdqu	%ymm5, 1376(%rsi)
	vmovdqu	768(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm5, 384(%rsi)
	vmovdqu	864(%rdi), %ymm6
	vmovdqu	%ymm5, 1408(%rsi)
	vmovdqu	832(%rdi), %ymm5
	vmovdqu	%ymm4, 896(%rsi)
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	928(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpermq	$216, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 928(%rsi)
	vmovdqu	%ymm5, 416(%rsi)
	vmovdqu	%ymm5, 1440(%rsi)
	vmovdqu	896(%rdi), %ymm5
	vpminud	%ymm1, %ymm5, %ymm7
	vpaddd	%ymm0, %ymm5, %ymm4
	vpcmpeqd	%ymm7, %ymm5, %ymm7
	vpblendvb	%ymm7, %ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpaddd	%ymm0, %ymm6, %ymm5
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpand	%ymm4, %ymm2, %ymm4
	vpblendvb	%ymm7, %ymm6, %ymm5, %ymm5
	vmovdqu	960(%rdi), %ymm6
	vpand	%ymm5, %ymm2, %ymm5
	vpackusdw	%ymm5, %ymm4, %ymm4
	vpminud	%ymm1, %ymm6, %ymm7
	vpermq	$216, %ymm4, %ymm4
	vpcmpeqd	%ymm7, %ymm6, %ymm7
	vpsubw	%ymm4, %ymm3, %ymm5
	vmovdqu	%ymm4, 960(%rsi)
	vpaddd	%ymm0, %ymm6, %ymm4
	vmovdqu	%ymm5, 448(%rsi)
	vmovdqu	%ymm5, 1472(%rsi)
	vmovdqu	992(%rdi), %ymm5
	vpblendvb	%ymm7, %ymm6, %ymm4, %ymm4
	vpminud	%ymm1, %ymm5, %ymm1
	vpaddd	%ymm0, %ymm5, %ymm0
	vpcmpeqd	%ymm1, %ymm5, %ymm1
	vpblendvb	%ymm1, %ymm5, %ymm0, %ymm0
	vpand	%ymm4, %ymm2, %ymm1
	vpand	%ymm0, %ymm2, %ymm2
	vpackusdw	%ymm2, %ymm1, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm3, %ymm3
	vmovdqu	%ymm0, 992(%rsi)
	vmovdqu	%ymm3, 480(%rsi)
	vmovdqu	%ymm3, 1504(%rsi)
	vzeroupper
	ret
	.cfi_endproc
.LFE5688:
	.size	poly_sparse_cs_table_u16, .-poly_sparse_cs_table_u16
	.p2align 4
	.globl	poly_sparse_ct_table_i32
	.type	poly_sparse_ct_table_i32, @function
poly_sparse_ct_table_i32:
.LFB5689:
	.cfi_startproc
	endbr64
	vmovdqa	.LC0(%rip), %ymm4
	vmovdqa	.LC4(%rip), %ymm3
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L13:
	vmovdqu	(%rdi,%rax), %ymm0
	vpcmpgtd	%ymm4, %ymm0, %ymm1
	vpand	%ymm1, %ymm3, %ymm1
	vpsubd	%ymm0, %ymm1, %ymm2
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm2, (%rsi,%rax)
	vmovdqu	%ymm2, 2048(%rsi,%rax)
	vmovdqu	%ymm0, 1024(%rsi,%rax)
	addq	$32, %rax
	cmpq	$1024, %rax
	jne	.L13
	vzeroupper
	ret
	.cfi_endproc
.LFE5689:
	.size	poly_sparse_ct_table_i32, .-poly_sparse_ct_table_i32
	.p2align 4
	.globl	poly_sparse_cs_mult_u8_pos
	.type	poly_sparse_cs_mult_u8_pos, @function
poly_sparse_cs_mult_u8_pos:
.LFB5690:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rdi, %r9
	movl	%ecx, %r10d
	movl	$32, %ecx
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	andq	$-32, %rsp
	subq	$288, %rsp
	movq	%fs:40, %rax
	movq	%rax, 280(%rsp)
	xorl	%eax, %eax
	movq	%rsp, %r11
	movq	%r11, %rdi
	rep stosq
	testl	%r10d, %r10d
	jle	.L16
	vpxor	%xmm0, %xmm0, %xmm0
	leal	-1(%r10), %eax
	leaq	4(%rdx,%rax,4), %rdi
	vmovdqa	%ymm0, %ymm1
	vmovdqa	%ymm0, %ymm2
	vmovdqa	%ymm0, %ymm3
	vmovdqa	%ymm0, %ymm4
	vmovdqa	%ymm0, %ymm5
	vmovdqa	%ymm0, %ymm6
	vmovdqa	%ymm0, %ymm7
	.p2align 4,,10
	.p2align 3
.L17:
	movslq	(%rdx), %rcx
	addq	$4, %rdx
	movl	(%rsi,%rcx,4), %eax
	sarl	$31, %eax
	andl	$256, %eax
	subq	%rcx, %rax
	vpaddb	256(%r9,%rax), %ymm7, %ymm7
	vpaddb	288(%r9,%rax), %ymm6, %ymm6
	vpaddb	320(%r9,%rax), %ymm5, %ymm5
	vpaddb	352(%r9,%rax), %ymm4, %ymm4
	vpaddb	384(%r9,%rax), %ymm3, %ymm3
	vpaddb	416(%r9,%rax), %ymm2, %ymm2
	vpaddb	448(%r9,%rax), %ymm1, %ymm1
	vpaddb	480(%r9,%rax), %ymm0, %ymm0
	cmpq	%rdx, %rdi
	jne	.L17
	vmovdqa	%ymm7, (%rsp)
	vmovdqa	%ymm6, 32(%rsp)
	vmovdqa	%ymm5, 64(%rsp)
	vmovdqa	%ymm4, 96(%rsp)
	vmovdqa	%ymm3, 128(%rsp)
	vmovdqa	%ymm2, 160(%rsp)
	vmovdqa	%ymm1, 192(%rsp)
	vmovdqa	%ymm0, 224(%rsp)
.L16:
	vmovdqa	(%rsp), %ymm0
	leaq	1024(%r8), %rax
	vpsrldq	$8, %ymm0, %ymm1
	vpmovsxbd	%xmm0, %ymm3
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovsxbd	%xmm0, %ymm0
	vpmovsxbd	%xmm1, %ymm2
	vextracti128	$0x1, %ymm1, %xmm1
	vmovdqu	%ymm3, (%r8)
	vmovdqu	%ymm0, 64(%r8)
	vmovdqa	32(%rsp), %ymm0
	vpmovsxbd	%xmm1, %ymm1
	vmovdqu	%ymm1, 96(%r8)
	vpmovsxbd	%xmm0, %ymm3
	vpsrldq	$8, %ymm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vmovdqu	%ymm2, 32(%r8)
	vpmovsxbd	%xmm0, %ymm0
	vpmovsxbd	%xmm1, %ymm2
	vextracti128	$0x1, %ymm1, %xmm1
	vmovdqu	%ymm3, 128(%r8)
	vmovdqu	%ymm0, 192(%r8)
	vmovdqa	64(%rsp), %ymm0
	vpmovsxbd	%xmm1, %ymm1
	vmovdqu	%ymm1, 224(%r8)
	vpmovsxbd	%xmm0, %ymm3
	vpsrldq	$8, %ymm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vmovdqu	%ymm2, 160(%r8)
	vpmovsxbd	%xmm0, %ymm0
	vpmovsxbd	%xmm1, %ymm2
	vextracti128	$0x1, %ymm1, %xmm1
	vmovdqu	%ymm3, 256(%r8)
	vmovdqu	%ymm0, 320(%r8)
	vmovdqa	96(%rsp), %ymm0
	vpmovsxbd	%xmm1, %ymm1
	vmovdqu	%ymm1, 352(%r8)
	vpmovsxbd	%xmm0, %ymm3
	vpsrldq	$8, %ymm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vmovdqu	%ymm2, 288(%r8)
	vpmovsxbd	%xmm0, %ymm0
	vpmovsxbd	%xmm1, %ymm2
	vextracti128	$0x1, %ymm1, %xmm1
	vmovdqu	%ymm3, 384(%r8)
	vmovdqu	%ymm0, 448(%r8)
	vpmovsxbd	%xmm1, %ymm1
	vmovdqa	128(%rsp), %ymm0
	vmovdqu	%ymm1, 480(%r8)
	vpmovsxbd	%xmm0, %ymm3
	vpsrldq	$8, %ymm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vmovdqu	%ymm2, 416(%r8)
	vpmovsxbd	%xmm0, %ymm0
	vpmovsxbd	%xmm1, %ymm2
	vextracti128	$0x1, %ymm1, %xmm1
	vmovdqu	%ymm3, 512(%r8)
	vmovdqu	%ymm0, 576(%r8)
	vpmovsxbd	%xmm1, %ymm1
	vmovdqa	160(%rsp), %ymm0
	vmovdqu	%ymm1, 608(%r8)
	vpmovsxbd	%xmm0, %ymm3
	vpsrldq	$8, %ymm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vmovdqu	%ymm2, 544(%r8)
	vpmovsxbd	%xmm0, %ymm0
	vpmovsxbd	%xmm1, %ymm2
	vextracti128	$0x1, %ymm1, %xmm1
	vmovdqu	%ymm3, 640(%r8)
	vmovdqu	%ymm0, 704(%r8)
	vpmovsxbd	%xmm1, %ymm1
	vmovdqa	192(%rsp), %ymm0
	vmovdqu	%ymm1, 736(%r8)
	vpmovsxbd	%xmm0, %ymm3
	vpsrldq	$8, %ymm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vmovdqu	%ymm2, 672(%r8)
	vpmovsxbd	%xmm0, %ymm0
	vpmovsxbd	%xmm1, %ymm2
	vmovdqu	%ymm3, 768(%r8)
	vextracti128	$0x1, %ymm1, %xmm1
	vmovdqu	%ymm2, 800(%r8)
	vpmovsxbd	%xmm1, %ymm1
	vmovdqu	%ymm0, 832(%r8)
	vmovdqa	224(%rsp), %ymm0
	vmovdqu	%ymm1, 864(%r8)
	vpsrldq	$8, %ymm0, %ymm1
	vpmovsxbd	%xmm0, %ymm3
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovsxbd	%xmm1, %ymm2
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovsxbd	%xmm0, %ymm0
	vmovdqu	%ymm3, 896(%r8)
	vmovdqu	%ymm2, 928(%r8)
	vpmovsxbd	%xmm1, %ymm1
	vmovdqu	%ymm1, 992(%r8)
	vmovdqa	.LC4(%rip), %ymm1
	vmovdqu	%ymm0, 960(%r8)
	.p2align 4,,10
	.p2align 3
.L18:
	vmovdqu	(%r8), %ymm4
	addq	$32, %r8
	vpsrad	$31, %ymm4, %ymm0
	vpand	%ymm0, %ymm1, %ymm0
	vpaddd	%ymm4, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%r8)
	cmpq	%r8, %rax
	jne	.L18
	movq	280(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L24
	vzeroupper
	leave
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L24:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5690:
	.size	poly_sparse_cs_mult_u8_pos, .-poly_sparse_cs_mult_u8_pos
	.p2align 4
	.globl	poly_sparse_cs_mult_u16_pos
	.type	poly_sparse_cs_mult_u16_pos, @function
poly_sparse_cs_mult_u16_pos:
.LFB5691:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rdi, %r9
	movl	%ecx, %r10d
	movl	$64, %ecx
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	andq	$-32, %rsp
	subq	$544, %rsp
	movq	%fs:40, %rax
	movq	%rax, 536(%rsp)
	xorl	%eax, %eax
	movq	%rsp, %r11
	movq	%r11, %rdi
	rep stosq
	testl	%r10d, %r10d
	jle	.L26
	vpxor	%xmm0, %xmm0, %xmm0
	leal	-1(%r10), %eax
	leaq	4(%rdx,%rax,4), %rdi
	vmovdqa	%ymm0, %ymm1
	vmovdqa	%ymm0, %ymm2
	vmovdqa	%ymm0, %ymm3
	vmovdqa	%ymm0, %ymm4
	vmovdqa	%ymm0, %ymm5
	vmovdqa	%ymm0, %ymm6
	vmovdqa	%ymm0, %ymm7
	vmovdqa	%ymm0, %ymm8
	vmovdqa	%ymm0, %ymm9
	vmovdqa	%ymm0, %ymm10
	vmovdqa	%ymm0, %ymm11
	vmovdqa	%ymm0, %ymm12
	vmovdqa	%ymm0, %ymm13
	vmovdqa	%ymm0, %ymm14
	vmovdqa	%ymm0, %ymm15
	.p2align 4,,10
	.p2align 3
.L27:
	movslq	(%rdx), %rcx
	addq	$4, %rdx
	movl	(%rsi,%rcx,4), %eax
	sarl	$31, %eax
	andl	$256, %eax
	subq	%rcx, %rax
	vpaddw	512(%r9,%rax,2), %ymm15, %ymm15
	vpaddw	544(%r9,%rax,2), %ymm14, %ymm14
	vpaddw	576(%r9,%rax,2), %ymm13, %ymm13
	vpaddw	608(%r9,%rax,2), %ymm12, %ymm12
	vpaddw	640(%r9,%rax,2), %ymm11, %ymm11
	vpaddw	672(%r9,%rax,2), %ymm10, %ymm10
	vpaddw	704(%r9,%rax,2), %ymm9, %ymm9
	vpaddw	736(%r9,%rax,2), %ymm8, %ymm8
	vpaddw	768(%r9,%rax,2), %ymm7, %ymm7
	vpaddw	800(%r9,%rax,2), %ymm6, %ymm6
	vpaddw	832(%r9,%rax,2), %ymm5, %ymm5
	vpaddw	864(%r9,%rax,2), %ymm4, %ymm4
	vpaddw	896(%r9,%rax,2), %ymm3, %ymm3
	vpaddw	928(%r9,%rax,2), %ymm2, %ymm2
	vpaddw	960(%r9,%rax,2), %ymm1, %ymm1
	vpaddw	992(%r9,%rax,2), %ymm0, %ymm0
	cmpq	%rdx, %rdi
	jne	.L27
	vmovdqa	%ymm15, (%rsp)
	vmovdqa	%ymm14, 32(%rsp)
	vmovdqa	%ymm13, 64(%rsp)
	vmovdqa	%ymm12, 96(%rsp)
	vmovdqa	%ymm11, 128(%rsp)
	vmovdqa	%ymm10, 160(%rsp)
	vmovdqa	%ymm9, 192(%rsp)
	vmovdqa	%ymm8, 224(%rsp)
	vmovdqa	%ymm7, 256(%rsp)
	vmovdqa	%ymm6, 288(%rsp)
	vmovdqa	%ymm5, 320(%rsp)
	vmovdqa	%ymm4, 352(%rsp)
	vmovdqa	%ymm3, 384(%rsp)
	vmovdqa	%ymm2, 416(%rsp)
	vmovdqa	%ymm1, 448(%rsp)
	vmovdqa	%ymm0, 480(%rsp)
.L26:
	vmovdqa	(%rsp), %xmm1
	vmovdqa	(%rsp), %ymm3
	movq	%r8, %rax
	leaq	1024(%r8), %rdx
	vmovdqa	32(%rsp), %ymm4
	vmovdqa	64(%rsp), %ymm5
	vpmovsxwd	%xmm1, %ymm1
	vextracti128	$0x1, %ymm3, %xmm0
	vmovdqa	96(%rsp), %ymm6
	vmovdqa	128(%rsp), %ymm7
	vmovdqu	%ymm1, (%r8)
	vmovdqa	32(%rsp), %xmm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqa	160(%rsp), %ymm3
	vmovdqu	%ymm0, 32(%r8)
	vextracti128	$0x1, %ymm4, %xmm0
	vmovdqa	192(%rsp), %ymm4
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 64(%r8)
	vmovdqa	64(%rsp), %xmm1
	vmovdqu	%ymm0, 96(%r8)
	vextracti128	$0x1, %ymm5, %xmm0
	vmovdqa	224(%rsp), %ymm5
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 128(%r8)
	vmovdqa	96(%rsp), %xmm1
	vmovdqu	%ymm0, 160(%r8)
	vextracti128	$0x1, %ymm6, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 192(%r8)
	vmovdqa	128(%rsp), %xmm1
	vmovdqu	%ymm0, 224(%r8)
	vextracti128	$0x1, %ymm7, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 256(%r8)
	vmovdqa	160(%rsp), %xmm1
	vmovdqu	%ymm0, 288(%r8)
	vextracti128	$0x1, %ymm3, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 320(%r8)
	vmovdqa	192(%rsp), %xmm1
	vmovdqu	%ymm0, 352(%r8)
	vextracti128	$0x1, %ymm4, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 384(%r8)
	vmovdqa	224(%rsp), %xmm1
	vmovdqu	%ymm0, 416(%r8)
	vextracti128	$0x1, %ymm5, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm0, 480(%r8)
	vmovdqu	%ymm1, 448(%r8)
	vmovdqa	256(%rsp), %xmm1
	vmovdqa	256(%rsp), %ymm6
	vmovdqa	288(%rsp), %ymm7
	vmovdqa	320(%rsp), %ymm3
	vpmovsxwd	%xmm1, %ymm1
	vextracti128	$0x1, %ymm6, %xmm0
	vmovdqa	352(%rsp), %ymm4
	vmovdqa	384(%rsp), %ymm5
	vmovdqu	%ymm1, 512(%r8)
	vpmovsxwd	%xmm0, %ymm0
	vmovdqa	288(%rsp), %xmm1
	vmovdqa	416(%rsp), %ymm6
	vmovdqu	%ymm0, 544(%r8)
	vextracti128	$0x1, %ymm7, %xmm0
	vmovdqa	448(%rsp), %ymm7
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 576(%r8)
	vmovdqa	320(%rsp), %xmm1
	vmovdqu	%ymm0, 608(%r8)
	vextracti128	$0x1, %ymm3, %xmm0
	vmovdqa	480(%rsp), %ymm3
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 640(%r8)
	vmovdqa	352(%rsp), %xmm1
	vmovdqu	%ymm0, 672(%r8)
	vextracti128	$0x1, %ymm4, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 704(%r8)
	vmovdqa	384(%rsp), %xmm1
	vmovdqu	%ymm0, 736(%r8)
	vextracti128	$0x1, %ymm5, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 768(%r8)
	vmovdqa	416(%rsp), %xmm1
	vmovdqu	%ymm0, 800(%r8)
	vextracti128	$0x1, %ymm6, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 832(%r8)
	vmovdqa	448(%rsp), %xmm1
	vmovdqu	%ymm0, 864(%r8)
	vextracti128	$0x1, %ymm7, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 896(%r8)
	vmovdqa	480(%rsp), %xmm1
	vmovdqu	%ymm0, 928(%r8)
	vextracti128	$0x1, %ymm3, %xmm0
	vpmovsxwd	%xmm1, %ymm1
	vpmovsxwd	%xmm0, %ymm0
	vmovdqu	%ymm1, 960(%r8)
	vmovdqu	%ymm0, 992(%r8)
	vmovdqa	.LC4(%rip), %ymm1
	.p2align 4,,10
	.p2align 3
.L28:
	vmovdqu	(%rax), %ymm2
	addq	$32, %rax
	vpsrad	$31, %ymm2, %ymm0
	vpand	%ymm0, %ymm1, %ymm0
	vpaddd	%ymm2, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %rdx
	jne	.L28
	movq	536(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L34
	vzeroupper
	leave
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L34:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5691:
	.size	poly_sparse_cs_mult_u16_pos, .-poly_sparse_cs_mult_u16_pos
	.p2align 4
	.globl	poly_sparse_ct_mult_i32_pos
	.type	poly_sparse_ct_mult_i32_pos, @function
poly_sparse_ct_mult_i32_pos:
.LFB5692:
	.cfi_startproc
	endbr64
	movq	%rdi, %r9
	leaq	8(%r8), %rdi
	movq	%rdx, %r10
	movl	%ecx, %edx
	andq	$-8, %rdi
	movq	%r8, %rcx
	xorl	%eax, %eax
	movq	$0, (%r8)
	movq	$0, 1016(%r8)
	subq	%rdi, %rcx
	addl	$1024, %ecx
	shrl	$3, %ecx
	rep stosq
	testl	%edx, %edx
	jle	.L40
	leal	-1(%rdx), %eax
	movq	%r10, %rcx
	leaq	4(%r10,%rax,4), %r11
	movl	$256, %r10d
	.p2align 4,,10
	.p2align 3
.L38:
	movslq	(%rcx), %rdx
	movq	%r10, %rdi
	movl	(%rsi,%rdx,4), %eax
	subq	%rdx, %rdi
	sarl	$31, %eax
	andl	$256, %eax
	addq	%rdi, %rax
	leaq	(%r9,%rax,4), %rdx
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L37:
	vmovdqu	(%r8,%rax), %ymm3
	vpaddd	(%rdx,%rax), %ymm3, %ymm0
	vmovdqu	%ymm0, (%r8,%rax)
	addq	$32, %rax
	cmpq	$1024, %rax
	jne	.L37
	addq	$4, %rcx
	vmovdqu	(%r8), %ymm0
	cmpq	%rcx, %r11
	jne	.L38
	vpsrad	$31, %ymm0, %ymm2
.L36:
	vmovdqa	.LC4(%rip), %ymm1
	leaq	32(%r8), %rax
	addq	$1024, %r8
	vpand	%ymm2, %ymm1, %ymm2
	vpaddd	%ymm0, %ymm2, %ymm0
	vmovdqu	%ymm0, -1024(%r8)
	.p2align 4,,10
	.p2align 3
.L39:
	vmovdqu	(%rax), %ymm4
	addq	$32, %rax
	vpsrad	$31, %ymm4, %ymm0
	vpand	%ymm0, %ymm1, %ymm0
	vpaddd	%ymm4, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %r8
	jne	.L39
	vzeroupper
	ret
.L40:
	vmovdqu	(%r8), %ymm0
	vpxor	%xmm2, %xmm2, %xmm2
	jmp	.L36
	.cfi_endproc
.LFE5692:
	.size	poly_sparse_ct_mult_i32_pos, .-poly_sparse_ct_mult_i32_pos
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC0:
	.long	4190208
	.long	4190208
	.long	4190208
	.long	4190208
	.long	4190208
	.long	4190208
	.long	4190208
	.long	4190208
	.align 32
.LC1:
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.align 32
.LC2:
	.long	65535
	.long	65535
	.long	65535
	.long	65535
	.long	65535
	.long	65535
	.long	65535
	.long	65535
	.align 32
.LC3:
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.align 32
.LC4:
	.quad	35993616950222849
	.quad	35993616950222849
	.quad	35993616950222849
	.quad	35993616950222849
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
