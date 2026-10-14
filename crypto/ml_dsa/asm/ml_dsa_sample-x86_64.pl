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
# ML-DSA AVX2 sampling (ExpandA, ExpandS, ExpandMask)
#
# Implemented:
#   ossl_ml_dsa_expand_A_44
#   ossl_ml_dsa_expand_A_65
#   ossl_ml_dsa_expand_A_87
#   ossl_ml_dsa_expand_S_44
#   ossl_ml_dsa_expand_S_65
#   ossl_ml_dsa_expand_S_87
#   ossl_ml_dsa_expand_mask_avx2
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

.globl  ossl_ml_dsa_expand_A_44
.globl  ossl_ml_dsa_expand_A_65
.globl  ossl_ml_dsa_expand_A_87
.globl  ossl_ml_dsa_expand_S_44
.globl  ossl_ml_dsa_expand_S_65
.globl  ossl_ml_dsa_expand_S_87
.globl  ossl_ml_dsa_expand_mask_avx2
.type   ossl_ml_dsa_expand_A_44,\@abi-omnipotent
.align 32
ossl_ml_dsa_expand_A_44:
ossl_ml_dsa_expand_A_65:
ossl_ml_dsa_expand_A_87:
ossl_ml_dsa_expand_S_44:
ossl_ml_dsa_expand_S_65:
ossl_ml_dsa_expand_S_87:
ossl_ml_dsa_expand_mask_avx2:
    .byte   0x0f,0x0b       # ud2
    ret
.size   ossl_ml_dsa_expand_A_44, .-ossl_ml_dsa_expand_A_44
___

    open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
      or die "can't call $xlate: $!";
    print OUT $code;
    close OUT or die "error closing STDOUT: $!";
}}}

__DATA__
	.file	"ml_dsa_sample_regen.c"
	.text
	.p2align 4
	.type	rej_eta_2, @function
rej_eta_2:
.LFB5718:
	.cfi_startproc
	movl	%esi, %ecx
	movq	%rdi, %r8
	movq	%rdx, %r9
	cmpl	$255, %ecx
	ja	.L9
	movl	$1, %esi
	movl	$2, %r10d
	.p2align 4,,10
	.p2align 3
.L6:
	movzbl	-1(%r9,%rsi), %eax
	movl	%eax, %edx
	shrb	$4, %al
	andl	$15, %edx
	movzbl	%al, %eax
	cmpb	$15, %dl
	je	.L3
	movzbl	%dl, %edx
	leal	(%rdx,%rdx,2), %edi
	leal	(%rdx,%rdi,4), %edi
	sarl	$6, %edi
	leal	(%rdi,%rdi,4), %r11d
	movl	%ecx, %edi
	addl	$1, %ecx
	subl	%r11d, %edx
	movl	%r10d, %r11d
	subl	%edx, %r11d
	movl	%r11d, (%r8,%rdi,4)
.L3:
	cmpl	$255, %ecx
	setbe	%dl
	cmpl	$14, %eax
	jg	.L4
	testb	%dl, %dl
	je	.L4
	leal	(%rax,%rax,2), %edx
	leal	1(%rcx), %r11d
	leal	(%rax,%rdx,4), %edx
	sarl	$6, %edx
	leal	(%rdx,%rdx,4), %edx
	subl	%edx, %eax
	movl	%r10d, %edx
	subl	%eax, %edx
	cmpl	$135, %esi
	movl	%edx, (%r8,%rcx,4)
	setle	%dl
	cmpl	$255, %r11d
	setbe	%al
	addq	$1, %rsi
	testb	%al, %dl
	je	.L1
	movl	%r11d, %ecx
	jmp	.L6
	.p2align 4,,10
	.p2align 3
.L4:
	cmpl	$135, %esi
	setle	%al
	addq	$1, %rsi
	testb	%dl, %al
	jne	.L6
.L9:
	movl	%ecx, %r11d
.L1:
	movl	%r11d, %eax
	ret
	.cfi_endproc
.LFE5718:
	.size	rej_eta_2, .-rej_eta_2
	.p2align 4
	.type	ml_dsa_rej_uniform_avx_s1s3_final, @function
ml_dsa_rej_uniform_avx_s1s3_final:
.LFB5696:
	.cfi_startproc
	vpermq	$148, (%rsi), %ymm0
	movl	%edx, %ecx
	leal	8(%rdx), %r8d
	vmovdqa	.LC0(%rip), %ymm2
	vmovdqa	.LC1(%rip), %ymm3
	vmovdqa	.LC2(%rip), %ymm4
	leaq	(%rdi,%rcx,4), %rcx
	vpshufb	%ymm2, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpaddd	%ymm0, %ymm4, %ymm1
	vmovmskps	%ymm1, %eax
	cmpl	$255, %eax
	je	.L22
	movl	%eax, %r9d
	leaq	idxlut(%rip), %r8
	popcntl	%eax, %eax
	vpmovzxbd	(%r8,%r9,8), %ymm1
	leal	(%rax,%rdx), %r8d
	vpermd	%ymm0, %ymm1, %ymm0
.L22:
	vmovdqu	%ymm0, (%rcx)
	vpermq	$148, 24(%rsi), %ymm0
	movl	%r8d, %edx
	leaq	(%rdi,%rdx,4), %rdx
	vpshufb	%ymm2, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpaddd	%ymm0, %ymm4, %ymm1
	vmovmskps	%ymm1, %eax
	cmpl	$255, %eax
	je	.L23
	movl	%eax, %r9d
	leaq	idxlut(%rip), %rcx
	popcntl	%eax, %eax
	addl	%eax, %r8d
	vpmovzxbd	(%rcx,%r9,8), %ymm1
	vpermd	%ymm0, %ymm1, %ymm0
.L24:
	vmovdqu	%ymm0, (%rdx)
	vpermq	$148, 48(%rsi), %ymm0
	movl	%r8d, %edx
	leaq	(%rdi,%rdx,4), %rdx
	vpshufb	%ymm2, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpaddd	%ymm0, %ymm4, %ymm1
	vmovmskps	%ymm1, %eax
	cmpl	$255, %eax
	je	.L51
	movl	%eax, %r9d
	leaq	idxlut(%rip), %rcx
	popcntl	%eax, %eax
	addl	%eax, %r8d
	vpmovzxbd	(%rcx,%r9,8), %ymm1
	vpermd	%ymm0, %ymm1, %ymm0
.L26:
	vmovdqu	%ymm0, (%rdx)
	movl	$72, %edx
	cmpl	$247, %r8d
	ja	.L27
	leaq	idxlut(%rip), %r10
	.p2align 4,,10
	.p2align 3
.L32:
	movl	%edx, %eax
	movl	%r8d, %ecx
	addl	$24, %edx
	vpermq	$148, (%rsi,%rax), %ymm0
	leaq	(%rdi,%rcx,4), %rcx
	vpshufb	%ymm2, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpaddd	%ymm0, %ymm4, %ymm1
	vmovmskps	%ymm1, %eax
	cmpl	$255, %eax
	je	.L52
	movl	%eax, %r9d
	popcntl	%eax, %eax
	addl	%eax, %r8d
	vpmovzxbd	(%r10,%r9,8), %ymm1
	vpermd	%ymm0, %ymm1, %ymm0
	vmovdqu	%ymm0, (%rcx)
	cmpl	$247, %r8d
	ja	.L27
	cmpl	$144, %edx
	jbe	.L32
.L27:
	cmpl	$255, %r8d
	ja	.L20
.L31:
	leal	1(%rdx), %r9d
	addq	%rsi, %r9
	.p2align 4,,10
	.p2align 3
.L35:
	movl	%edx, %eax
	movzbl	(%r9), %ecx
	addl	$3, %edx
	movzbl	(%rsi,%rax), %eax
	sall	$8, %ecx
	orl	%eax, %ecx
	movzbl	1(%r9), %eax
	sall	$16, %eax
	orl	%ecx, %eax
	andl	$8388607, %eax
	cmpl	$8380416, %eax
	ja	.L34
	movl	%r8d, %ecx
	addl	$1, %r8d
	movl	%eax, (%rdi,%rcx,4)
.L34:
	addq	$3, %r9
	cmpl	$168, %edx
	ja	.L20
	cmpl	$255, %r8d
	jbe	.L35
.L20:
	movl	%r8d, %eax
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L52:
	addl	$8, %r8d
	vmovdqu	%ymm0, (%rcx)
	cmpl	$144, %edx
	ja	.L31
	cmpl	$247, %r8d
	jbe	.L32
	jmp	.L31
	.p2align 4,,10
	.p2align 3
.L23:
	addl	$8, %r8d
	jmp	.L24
	.p2align 4,,10
	.p2align 3
.L51:
	addl	$8, %r8d
	jmp	.L26
	.cfi_endproc
.LFE5696:
	.size	ml_dsa_rej_uniform_avx_s1s3_final, .-ml_dsa_rej_uniform_avx_s1s3_final
	.p2align 4
	.type	ml_dsa_rej_eta_avx_4, @function
ml_dsa_rej_eta_avx_4:
.LFB5720:
	.cfi_startproc
	movq	%rsi, %r9
	xorl	%eax, %eax
	xorl	%esi, %esi
	vmovdqa	.LC3(%rip), %ymm4
	vmovdqa	.LC4(%rip), %ymm3
	vmovdqa	.LC5(%rip), %ymm2
	leaq	idxlut(%rip), %r8
	jmp	.L61
	.p2align 4,,10
	.p2align 3
.L54:
	movzbl	%cl, %r10d
	vpsrldq	$8, %xmm0, %xmm1
	vmovq	(%r8,%r10,8), %xmm5
	movq	%r10, %rcx
	movl	%eax, %r10d
	popcntl	%ecx, %ecx
	addl	%ecx, %eax
	movl	%edx, %ecx
	vpshufb	%xmm5, %xmm1, %xmm1
	shrl	$16, %ecx
	vpmovsxbd	%xmm1, %ymm1
	vmovdqu	%ymm1, (%rdi,%r10,4)
	cmpl	$248, %eax
	ja	.L83
	movzbl	%cl, %r10d
	vextracti128	$0x1, %ymm0, %xmm0
	shrl	$24, %edx
	vmovq	(%r8,%r10,8), %xmm1
	movq	%r10, %rcx
	movl	%eax, %r10d
	popcntl	%ecx, %ecx
	addl	%ecx, %eax
	vpshufb	%xmm1, %xmm0, %xmm1
	vpmovsxbd	%xmm1, %ymm1
	vmovdqu	%ymm1, (%rdi,%r10,4)
	cmpl	$248, %eax
	ja	.L84
	movl	%edx, %ecx
	vpsrldq	$8, %xmm0, %xmm0
	popcntl	%edx, %edx
	addl	$16, %esi
	vmovq	(%r8,%rcx,8), %xmm1
	movl	%eax, %ecx
	addl	%edx, %eax
	vpshufb	%xmm1, %xmm0, %xmm0
	vpmovsxbd	%xmm0, %ymm0
	vmovdqu	%ymm0, (%rdi,%rcx,4)
	cmpl	$248, %eax
	ja	.L55
	cmpl	$120, %esi
	ja	.L55
.L61:
	movl	%esi, %edx
	vpmovzxbw	(%r9,%rdx), %ymm1
	vpsllw	$4, %ymm1, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpand	%ymm4, %ymm1, %ymm1
	vpsubb	%ymm1, %ymm3, %ymm0
	vpaddb	%ymm1, %ymm2, %ymm1
	vpmovmskb	%ymm1, %edx
	movzbl	%dl, %r10d
	vmovq	(%r8,%r10,8), %xmm5
	movq	%r10, %rcx
	movl	%eax, %r10d
	popcntl	%ecx, %ecx
	addl	%ecx, %eax
	movl	%edx, %ecx
	vpshufb	%xmm5, %xmm0, %xmm5
	shrl	$8, %ecx
	vpmovsxbd	%xmm5, %ymm5
	vmovdqu	%ymm5, (%rdi,%r10,4)
	cmpl	$248, %eax
	jbe	.L54
	addl	$4, %esi
.L55:
	cmpl	$135, %esi
	ja	.L53
	cmpl	$255, %eax
	ja	.L53
	movl	%esi, %ecx
	leal	1(%rsi), %r8d
	addq	%r9, %rcx
	movl	$4, %r9d
	subl	%ecx, %r8d
	.p2align 4,,10
	.p2align 3
.L66:
	movzbl	(%rcx), %edx
	movl	%edx, %esi
	shrb	$4, %dl
	andl	$15, %esi
	movzbl	%dl, %edx
	cmpb	$8, %sil
	ja	.L63
	movzbl	%sil, %esi
	movl	%r9d, %r11d
	movl	%eax, %r10d
	addl	$1, %eax
	subl	%esi, %r11d
	movl	%r11d, (%rdi,%r10,4)
.L63:
	cmpl	$255, %eax
	setbe	%sil
	cmpl	$8, %edx
	ja	.L64
	testb	%sil, %sil
	je	.L64
	movl	%r9d, %r10d
	movl	%eax, %esi
	addl	$1, %eax
	subl	%edx, %r10d
	leal	(%r8,%rcx), %edx
	cmpl	$135, %edx
	movl	%r10d, (%rdi,%rsi,4)
	setbe	%sil
	cmpl	$255, %eax
	setbe	%dl
	addq	$1, %rcx
	testb	%dl, %sil
	jne	.L66
.L53:
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L64:
	leal	(%r8,%rcx), %edx
	cmpl	$135, %edx
	setbe	%dl
	addq	$1, %rcx
	testb	%sil, %dl
	jne	.L66
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L83:
	addl	$8, %esi
	jmp	.L55
	.p2align 4,,10
	.p2align 3
.L84:
	addl	$12, %esi
	jmp	.L55
	.cfi_endproc
.LFE5720:
	.size	ml_dsa_rej_eta_avx_4, .-ml_dsa_rej_eta_avx_4
	.p2align 4
	.type	ml_dsa_rej_eta_avx_2, @function
ml_dsa_rej_eta_avx_2:
.LFB5717:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	vmovdqa	.LC3(%rip), %ymm7
	movq	%rdi, %rax
	movq	%rsi, %r9
	xorl	%r8d, %r8d
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	.cfi_offset 14, -24
	.cfi_offset 13, -32
	.cfi_offset 12, -40
	.cfi_offset 3, -48
	vmovdqu	(%rsi), %xmm2
	vmovdqu	(%rsi), %ymm6
	vmovdqu	32(%rsi), %xmm10
	vpmovzxbw	%xmm2, %ymm2
	vpsllw	$4, %ymm2, %ymm5
	vextracti128	$0x1, %ymm6, %xmm1
	vmovdqu	32(%rsi), %ymm6
	vpmovzxbw	%xmm10, %ymm10
	vpor	%ymm5, %ymm2, %ymm2
	vpsllw	$4, %ymm10, %ymm3
	vpmovzxbw	%xmm1, %ymm1
	vpand	%ymm7, %ymm2, %ymm2
	vextracti128	$0x1, %ymm6, %xmm9
	vpor	%ymm3, %ymm10, %ymm10
	vmovdqa	.LC6(%rip), %ymm3
	vpsllw	$1, %ymm2, %ymm5
	vpmovzxbw	%xmm9, %ymm9
	vpand	%ymm7, %ymm10, %ymm10
	vmovdqa	.LC7(%rip), %ymm6
	vpsllw	$4, %ymm1, %ymm4
	vpsllw	$4, %ymm9, %ymm0
	vpaddw	%ymm2, %ymm5, %ymm5
	vpsllw	$2, %ymm5, %ymm5
	vpor	%ymm4, %ymm1, %ymm1
	vpor	%ymm0, %ymm9, %ymm9
	vpaddw	%ymm2, %ymm5, %ymm5
	vpand	%ymm7, %ymm1, %ymm1
	vpaddb	%ymm2, %ymm3, %ymm0
	vpsrld	$6, %ymm5, %ymm5
	vpmovmskb	%ymm0, %edx
	vpaddb	%ymm1, %ymm3, %ymm0
	vpand	%ymm6, %ymm5, %ymm5
	vpsllw	$1, %ymm1, %ymm4
	vpand	%ymm7, %ymm9, %ymm9
	movzbl	%dh, %ecx
	vpmovmskb	%ymm0, %r10d
	vpaddw	%ymm1, %ymm4, %ymm4
	vpaddb	%ymm10, %ymm3, %ymm0
	movzbl	%dl, %r12d
	vpsllw	$1, %ymm10, %ymm11
	vpsllw	$2, %ymm5, %ymm8
	vpmovmskb	%ymm0, %ebx
	movl	%edx, %edi
	vpaddb	%ymm9, %ymm3, %ymm0
	vpaddw	%ymm10, %ymm11, %ymm11
	vpsllw	$2, %ymm4, %ymm4
	shrl	$24, %edx
	vpaddw	%ymm5, %ymm8, %ymm8
	vpmovmskb	%ymm0, %r13d
	vpaddw	%ymm1, %ymm4, %ymm4
	movl	%edx, %r11d
	vpsllw	$1, %ymm9, %ymm0
	vpsllw	$2, %ymm11, %ymm11
	movq	%r12, %rsi
	shrl	$16, %edi
	vpaddw	%ymm10, %ymm11, %ymm11
	vpaddw	%ymm9, %ymm0, %ymm0
	vpsrld	$6, %ymm4, %ymm4
	vmovdqa	.LC8(%rip), %ymm5
	vpsrld	$6, %ymm11, %ymm11
	vpsllw	$2, %ymm0, %ymm0
	movzbl	%dil, %edi
	popcntl	%esi, %esi
	vpaddb	%ymm5, %ymm8, %ymm8
	vpand	%ymm6, %ymm11, %ymm11
	vpaddw	%ymm9, %ymm0, %ymm0
	popcntl	%ecx, %r8d
	vpsubb	%ymm2, %ymm8, %ymm8
	vpsrld	$6, %ymm0, %ymm0
	vpand	%ymm6, %ymm4, %ymm2
	addl	%esi, %r8d
	vpsllw	$2, %ymm2, %ymm4
	leaq	idxlut(%rip), %rdx
	vpand	%ymm6, %ymm0, %ymm0
	vpaddw	%ymm2, %ymm4, %ymm4
	vpsllw	$2, %ymm11, %ymm2
	vpaddb	%ymm5, %ymm4, %ymm4
	vpaddw	%ymm11, %ymm2, %ymm2
	vmovq	(%rdx,%r12,8), %xmm11
	movl	%ecx, %r12d
	vpsubb	%ymm1, %ymm4, %ymm4
	vpaddb	%ymm5, %ymm2, %ymm2
	vpsllw	$2, %ymm0, %ymm1
	movl	%r10d, %ecx
	vpsubb	%ymm10, %ymm2, %ymm2
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovdqa	%xmm8, %xmm10
	vpaddb	%ymm5, %ymm1, %ymm1
	vpshufb	%xmm11, %xmm10, %xmm10
	vmovq	(%rdx,%r12,8), %xmm11
	movl	%edi, %r12d
	vpsubb	%ymm9, %ymm1, %ymm1
	vpsrldq	$8, %xmm8, %xmm9
	vextracti128	$0x1, %ymm8, %xmm0
	popcntl	%edi, %edi
	vpshufb	%xmm11, %xmm9, %xmm9
	vpsrldq	$8, %xmm0, %xmm8
	vpmovsxbd	%xmm10, %ymm10
	addl	%r8d, %edi
	vmovq	(%rdx,%r12,8), %xmm11
	movl	%r11d, %r12d
	vpmovsxbd	%xmm9, %ymm9
	vmovdqu	%ymm10, (%rax)
	popcntl	%r11d, %r11d
	addl	%edi, %r11d
	vpshufb	%xmm11, %xmm0, %xmm0
	vmovq	(%rdx,%r12,8), %xmm11
	movslq	%esi, %r12
	movl	%r10d, %esi
	vmovdqu	%ymm9, (%rax,%r12,4)
	vpmovsxbd	%xmm0, %ymm0
	movzbl	%r10b, %r12d
	shrl	$16, %esi
	vpshufb	%xmm11, %xmm8, %xmm8
	vmovdqu	%ymm0, (%rax,%r8,4)
	movq	%r12, %r8
	movzbl	%sil, %esi
	vpmovsxbd	%xmm8, %ymm8
	vmovq	(%rdx,%r12,8), %xmm10
	vpsrldq	$8, %xmm4, %xmm9
	shrl	$24, %r10d
	vmovdqu	%ymm8, (%rax,%rdi,4)
	movzbl	%ch, %edi
	vmovdqa	%xmm4, %xmm8
	movl	%r13d, %ecx
	movl	%edi, %r12d
	vpshufb	%xmm10, %xmm8, %xmm8
	vextracti128	$0x1, %ymm4, %xmm0
	popcntl	%r8d, %r8d
	vmovq	(%rdx,%r12,8), %xmm10
	movl	%esi, %r12d
	vpsrldq	$8, %xmm0, %xmm4
	popcntl	%edi, %edi
	vpmovsxbd	%xmm8, %ymm8
	popcntl	%esi, %esi
	vpshufb	%xmm10, %xmm9, %xmm9
	vmovq	(%rdx,%r12,8), %xmm10
	movl	%r10d, %r12d
	popcntl	%r10d, %r10d
	vpmovsxbd	%xmm9, %ymm9
	vpshufb	%xmm10, %xmm0, %xmm0
	vmovq	(%rdx,%r12,8), %xmm10
	movl	%r11d, %r12d
	addl	%r8d, %r11d
	movq	%r11, %r8
	vmovdqu	%ymm8, (%rax,%r12,4)
	vpmovsxbd	%xmm0, %ymm0
	addl	%edi, %r8d
	vpshufb	%xmm10, %xmm4, %xmm4
	vmovdqu	%ymm9, (%rax,%r11,4)
	movzbl	%bl, %r11d
	movq	%r8, %rdi
	vpsrldq	$8, %xmm2, %xmm8
	vpmovsxbd	%xmm4, %ymm4
	vmovq	(%rdx,%r11,8), %xmm9
	addl	%esi, %edi
	vmovdqu	%ymm0, (%rax,%r8,4)
	movl	%ebx, %esi
	vmovdqa	%xmm2, %xmm0
	addl	%edi, %r10d
	vmovdqu	%ymm4, (%rax,%rdi,4)
	movzbl	%bh, %edi
	movq	%r11, %r8
	shrl	$16, %esi
	movl	%edi, %r11d
	vpshufb	%xmm9, %xmm0, %xmm0
	shrl	$24, %ebx
	vmovq	(%rdx,%r11,8), %xmm9
	movzbl	%sil, %esi
	vextracti128	$0x1, %ymm2, %xmm2
	popcntl	%r8d, %r8d
	movl	%esi, %r11d
	vpsrldq	$8, %xmm2, %xmm4
	popcntl	%edi, %edi
	vpmovsxbd	%xmm0, %ymm0
	vpshufb	%xmm9, %xmm8, %xmm8
	vmovq	(%rdx,%r11,8), %xmm9
	movl	%ebx, %r11d
	popcntl	%esi, %esi
	vpmovsxbd	%xmm8, %ymm8
	popcntl	%ebx, %ebx
	vpshufb	%xmm9, %xmm2, %xmm2
	vmovq	(%rdx,%r11,8), %xmm9
	movl	%r10d, %r11d
	addl	%r8d, %r10d
	movq	%r10, %r8
	vmovdqu	%ymm0, (%rax,%r11,4)
	vpmovsxbd	%xmm2, %ymm2
	vmovdqa	%xmm1, %xmm0
	addl	%edi, %r8d
	vpshufb	%xmm9, %xmm4, %xmm4
	vmovdqu	%ymm8, (%rax,%r10,4)
	movzbl	%r13b, %r10d
	movq	%r8, %rdi
	vpmovsxbd	%xmm4, %ymm4
	vmovdqu	%ymm2, (%rax,%r8,4)
	movq	%r10, %r8
	addl	%esi, %edi
	vmovq	(%rdx,%r10,8), %xmm8
	vmovdqu	%ymm4, (%rax,%rdi,4)
	addl	%edi, %ebx
	vpsrldq	$8, %xmm1, %xmm4
	movzbl	%ch, %edi
	movl	%edi, %r10d
	shrl	$16, %ecx
	vpshufb	%xmm8, %xmm0, %xmm0
	vextracti128	$0x1, %ymm1, %xmm1
	vmovq	(%rdx,%r10,8), %xmm8
	movzbl	%cl, %esi
	movl	%r13d, %ecx
	vpmovsxbd	%xmm0, %ymm0
	movl	%esi, %r10d
	shrl	$24, %ecx
	vpsrldq	$8, %xmm1, %xmm2
	popcntl	%r8d, %r8d
	vpshufb	%xmm8, %xmm4, %xmm4
	popcntl	%edi, %edi
	popcntl	%esi, %esi
	xorl	%r12d, %r12d
	vmovq	(%rdx,%r10,8), %xmm8
	movl	%ecx, %r10d
	vpmovsxbd	%xmm4, %ymm4
	popcntl	%ecx, %r12d
	vpshufb	%xmm8, %xmm1, %xmm1
	vmovq	(%rdx,%r10,8), %xmm8
	movl	%ebx, %r10d
	vmovdqu	%ymm0, (%rax,%r10,4)
	leal	(%r8,%rbx), %r10d
	vpmovsxbd	%xmm1, %ymm1
	movq	%r10, %r8
	vpshufb	%xmm8, %xmm2, %xmm2
	vmovdqu	%ymm4, (%rax,%r10,4)
	vmovdqu	96(%r9), %ymm4
	addl	%edi, %r8d
	vpmovsxbd	%xmm2, %ymm2
	vmovdqu	96(%r9), %xmm8
	movq	%r8, %rdi
	vmovdqu	%ymm1, (%rax,%r8,4)
	vmovdqu	64(%r9), %ymm1
	vextracti128	$0x1, %ymm4, %xmm4
	addl	%esi, %edi
	vpmovzxbw	%xmm8, %ymm8
	vpmovzxbw	%xmm4, %ymm4
	vmovdqu	%ymm2, (%rax,%rdi,4)
	vmovdqu	64(%r9), %xmm2
	vextracti128	$0x1, %ymm1, %xmm1
	addl	%edi, %r12d
	vpsllw	$4, %ymm8, %ymm9
	vpsllw	$4, %ymm4, %ymm0
	vpmovzxbw	%xmm1, %ymm1
	vpmovzxbw	%xmm2, %ymm2
	vpsllw	$4, %ymm1, %ymm10
	vpor	%ymm9, %ymm8, %ymm8
	vpsllw	$4, %ymm2, %ymm11
	vpor	%ymm10, %ymm1, %ymm1
	vpor	%ymm0, %ymm4, %ymm4
	vpor	%ymm11, %ymm2, %ymm2
	vpand	%ymm7, %ymm1, %ymm1
	vpand	%ymm7, %ymm8, %ymm8
	vpand	%ymm7, %ymm2, %ymm2
	vpsllw	$1, %ymm1, %ymm9
	vpand	%ymm7, %ymm4, %ymm4
	vpaddb	%ymm2, %ymm3, %ymm0
	vpaddw	%ymm1, %ymm9, %ymm9
	vpsllw	$1, %ymm8, %ymm7
	vpmovmskb	%ymm0, %r11d
	vpaddb	%ymm1, %ymm3, %ymm0
	vpaddw	%ymm8, %ymm7, %ymm7
	vpmovmskb	%ymm0, %r10d
	vpaddb	%ymm8, %ymm3, %ymm0
	movzbl	%r11b, %r13d
	movl	%r11d, %ecx
	vpmovmskb	%ymm0, %ebx
	vpaddb	%ymm4, %ymm3, %ymm0
	movzbl	%ch, %edi
	movl	%r11d, %esi
	vpsllw	$1, %ymm2, %ymm3
	vpmovmskb	%ymm0, %r14d
	movq	%r13, %r8
	shrl	$16, %esi
	vpaddw	%ymm2, %ymm3, %ymm3
	vpsllw	$1, %ymm4, %ymm0
	movzbl	%sil, %esi
	movl	%r10d, %ecx
	vpsllw	$2, %ymm3, %ymm3
	vpsllw	$2, %ymm9, %ymm9
	vpaddw	%ymm4, %ymm0, %ymm0
	shrl	$24, %r11d
	vpaddw	%ymm2, %ymm3, %ymm3
	vpaddw	%ymm1, %ymm9, %ymm9
	vpsllw	$2, %ymm7, %ymm7
	popcntl	%r8d, %r8d
	vpsrld	$6, %ymm3, %ymm3
	vpsrld	$6, %ymm9, %ymm9
	vpaddw	%ymm8, %ymm7, %ymm7
	vpand	%ymm6, %ymm3, %ymm10
	vpsllw	$2, %ymm0, %ymm0
	vpand	%ymm6, %ymm9, %ymm9
	vpsllw	$2, %ymm10, %ymm3
	vpsrld	$6, %ymm7, %ymm7
	vpaddw	%ymm4, %ymm0, %ymm0
	vpaddw	%ymm10, %ymm3, %ymm3
	vpsrld	$6, %ymm0, %ymm0
	vpand	%ymm6, %ymm7, %ymm7
	vpaddb	%ymm5, %ymm3, %ymm3
	vpand	%ymm6, %ymm0, %ymm6
	vpsubb	%ymm2, %ymm3, %ymm3
	vpsllw	$2, %ymm9, %ymm2
	vpaddw	%ymm9, %ymm2, %ymm2
	vpsllw	$2, %ymm6, %ymm0
	vpaddb	%ymm5, %ymm2, %ymm2
	vpaddw	%ymm6, %ymm0, %ymm0
	vpsrldq	$8, %xmm3, %xmm6
	vpsubb	%ymm1, %ymm2, %ymm2
	vpsllw	$2, %ymm7, %ymm1
	vpaddb	%ymm5, %ymm0, %ymm0
	vpaddw	%ymm7, %ymm1, %ymm1
	vmovq	(%rdx,%r13,8), %xmm7
	vpsubb	%ymm4, %ymm0, %ymm0
	movl	%edi, %r13d
	vmovdqa	%xmm3, %xmm4
	vextracti128	$0x1, %ymm3, %xmm3
	vpaddb	%ymm5, %ymm1, %ymm1
	popcntl	%edi, %edi
	vpshufb	%xmm7, %xmm4, %xmm4
	vmovq	(%rdx,%r13,8), %xmm7
	movl	%esi, %r13d
	popcntl	%esi, %esi
	vpsrldq	$8, %xmm3, %xmm5
	vpmovsxbd	%xmm4, %ymm4
	vpsubb	%ymm8, %ymm1, %ymm1
	vpshufb	%xmm7, %xmm6, %xmm6
	vmovq	(%rdx,%r13,8), %xmm7
	movl	%r11d, %r13d
	vpmovsxbd	%xmm6, %ymm6
	vpshufb	%xmm7, %xmm3, %xmm3
	vmovq	(%rdx,%r13,8), %xmm7
	movl	%r12d, %r13d
	addl	%r8d, %r12d
	movq	%r12, %r8
	vpmovsxbd	%xmm3, %ymm3
	vmovdqu	%ymm4, (%rax,%r13,4)
	addl	%edi, %r8d
	vpshufb	%xmm7, %xmm5, %xmm5
	vmovdqu	%ymm6, (%rax,%r12,4)
	movzbl	%r10b, %r12d
	movq	%r8, %rdi
	vpmovsxbd	%xmm5, %ymm5
	vmovdqu	%ymm3, (%rax,%r8,4)
	vmovdqa	%xmm2, %xmm3
	addl	%esi, %edi
	vmovq	(%rdx,%r12,8), %xmm6
	movq	%r12, %r8
	vmovdqu	%ymm5, (%rax,%rdi,4)
	movq	%rdi, %rsi
	xorl	%edi, %edi
	popcntl	%r8d, %r8d
	popcntl	%r11d, %edi
	leal	(%rdi,%rsi), %r11d
	movzbl	%ch, %edi
	movl	%r10d, %esi
	movl	%edi, %r12d
	shrl	$16, %esi
	vpshufb	%xmm6, %xmm3, %xmm3
	popcntl	%edi, %edi
	movzbl	%sil, %esi
	vpsrldq	$8, %xmm2, %xmm5
	shrl	$24, %r10d
	movl	%r14d, %ecx
	vmovq	(%rdx,%r12,8), %xmm6
	movl	%esi, %r12d
	vextracti128	$0x1, %ymm2, %xmm2
	vpmovsxbd	%xmm3, %ymm3
	vpsrldq	$8, %xmm2, %xmm4
	popcntl	%esi, %esi
	vpshufb	%xmm6, %xmm5, %xmm5
	vmovq	(%rdx,%r12,8), %xmm6
	movl	%r10d, %r12d
	popcntl	%r10d, %r10d
	vpmovsxbd	%xmm5, %ymm5
	vpshufb	%xmm6, %xmm2, %xmm2
	vmovq	(%rdx,%r12,8), %xmm6
	movl	%r11d, %r12d
	addl	%r8d, %r11d
	movq	%r11, %r8
	vmovdqu	%ymm3, (%rax,%r12,4)
	vpmovsxbd	%xmm2, %ymm2
	addl	%edi, %r8d
	vpshufb	%xmm6, %xmm4, %xmm4
	vmovdqu	%ymm5, (%rax,%r11,4)
	movzbl	%bl, %r11d
	movq	%r8, %rdi
	vpmovsxbd	%xmm4, %ymm4
	vmovdqu	%ymm2, (%rax,%r8,4)
	vmovdqa	%xmm1, %xmm2
	addl	%esi, %edi
	movl	%ebx, %esi
	movq	%r11, %r8
	vmovdqu	%ymm4, (%rax,%rdi,4)
	addl	%edi, %r10d
	movzbl	%bh, %edi
	shrl	$16, %esi
	vmovq	(%rdx,%r11,8), %xmm5
	movl	%edi, %r11d
	movzbl	%sil, %esi
	shrl	$24, %ebx
	vpsrldq	$8, %xmm1, %xmm4
	vextracti128	$0x1, %ymm1, %xmm1
	popcntl	%r8d, %r8d
	vpshufb	%xmm5, %xmm2, %xmm2
	vmovq	(%rdx,%r11,8), %xmm5
	movl	%esi, %r11d
	vpsrldq	$8, %xmm1, %xmm3
	vpmovsxbd	%xmm2, %ymm2
	vpshufb	%xmm5, %xmm4, %xmm4
	vmovq	(%rdx,%r11,8), %xmm5
	movl	%ebx, %r11d
	vpmovsxbd	%xmm4, %ymm4
	vpshufb	%xmm5, %xmm1, %xmm1
	vmovq	(%rdx,%r11,8), %xmm5
	movl	%r10d, %r11d
	addl	%r8d, %r10d
	movq	%r10, %r8
	popcntl	%edi, %edi
	vmovdqu	%ymm2, (%rax,%r11,4)
	vpmovsxbd	%xmm1, %ymm1
	addl	%edi, %r8d
	vpshufb	%xmm5, %xmm3, %xmm3
	popcntl	%esi, %esi
	popcntl	%ebx, %ebx
	movq	%r8, %rdi
	vmovdqu	%ymm4, (%rax,%r10,4)
	vpmovsxbd	%xmm3, %ymm3
	movzbl	%r14b, %r10d
	addl	%esi, %edi
	vmovdqu	%ymm1, (%rax,%r8,4)
	vmovdqa	%xmm0, %xmm1
	movq	%r10, %r8
	vmovdqu	%ymm3, (%rax,%rdi,4)
	vmovq	(%rdx,%r10,8), %xmm4
	addl	%edi, %ebx
	movzbl	%ch, %edi
	movl	%edi, %r10d
	shrl	$16, %ecx
	vpsrldq	$8, %xmm0, %xmm3
	popcntl	%r8d, %r8d
	movzbl	%cl, %esi
	vpshufb	%xmm4, %xmm1, %xmm1
	movl	%r14d, %ecx
	popcntl	%edi, %edi
	vmovq	(%rdx,%r10,8), %xmm4
	movl	%esi, %r10d
	shrl	$24, %ecx
	vpmovsxbd	%xmm1, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	popcntl	%esi, %esi
	vpshufb	%xmm4, %xmm3, %xmm3
	vmovq	(%rdx,%r10,8), %xmm4
	movl	%ecx, %r10d
	popcntl	%ecx, %ecx
	vpsrldq	$8, %xmm0, %xmm2
	vpmovsxbd	%xmm3, %ymm3
	vpshufb	%xmm4, %xmm0, %xmm0
	vmovq	(%rdx,%r10,8), %xmm4
	movl	%ebx, %r10d
	vmovdqu	%ymm1, (%rax,%r10,4)
	leal	(%r8,%rbx), %r10d
	vpmovsxbd	%xmm0, %ymm0
	movq	%r10, %r8
	vpshufb	%xmm4, %xmm2, %xmm2
	vmovdqu	%ymm3, (%rax,%r10,4)
	addl	%edi, %r8d
	vpmovsxbd	%xmm2, %ymm2
	movq	%r8, %rdi
	vmovdqu	%ymm0, (%rax,%r8,4)
	addl	%esi, %edi
	leal	(%rcx,%rdi), %r8d
	vmovdqu	%ymm2, (%rax,%rdi,4)
	cmpl	$256, %r8d
	je	.L85
	vpmovzxbw	128(%r9), %xmm2
	vpsllw	$4, %xmm2, %xmm0
	vpor	%xmm0, %xmm2, %xmm2
	vpand	.LC9(%rip), %xmm2, %xmm2
	vpaddb	.LC10(%rip), %xmm2, %xmm0
	vpmovmskb	%xmm0, %ecx
	vpsllw	$1, %xmm2, %xmm0
	vpaddw	%xmm2, %xmm0, %xmm0
	movzbl	%cl, %edi
	movzbl	%ch, %ecx
	vpsllw	$2, %xmm0, %xmm0
	movq	%rdi, %rsi
	vpaddw	%xmm2, %xmm0, %xmm0
	vpsrlw	$6, %xmm0, %xmm0
	vpand	.LC11(%rip), %xmm0, %xmm0
	vpsllw	$2, %xmm0, %xmm1
	vpaddw	%xmm0, %xmm1, %xmm0
	vmovq	(%rdx,%rdi,8), %xmm1
	xorl	%edi, %edi
	vpsubb	%xmm2, %xmm0, %xmm0
	vpaddb	.LC12(%rip), %xmm0, %xmm0
	popcntl	%ecx, %edi
	vpshufb	%xmm1, %xmm0, %xmm1
	vpmovsxbd	%xmm1, %ymm1
	cmpl	$240, %r8d
	jbe	.L196
	cmpl	$248, %r8d
	jbe	.L197
	testl	%ecx, %ecx
	je	.L85
	movl	%r8d, %edx
	leal	-1(%rdi), %ecx
	vmovd	%xmm1, (%rax,%rdx,4)
	leal	1(%r8), %edx
	testl	%ecx, %ecx
	jle	.L104
	cmpl	$255, %edx
	ja	.L104
	leal	-2(%rdi), %ecx
	vpextrd	$1, %xmm1, (%rax,%rdx,4)
	leal	2(%r8), %edx
	testl	%ecx, %ecx
	jle	.L104
	cmpl	$255, %edx
	ja	.L104
	leal	-3(%rdi), %ecx
	vpextrd	$2, %xmm1, (%rax,%rdx,4)
	leal	3(%r8), %edx
	testl	%ecx, %ecx
	jle	.L104
	cmpl	$255, %edx
	ja	.L104
	leal	-4(%rdi), %ecx
	vpextrd	$3, %xmm1, (%rax,%rdx,4)
	leal	4(%r8), %edx
	testl	%ecx, %ecx
	jle	.L104
	cmpl	$255, %edx
	ja	.L104
	vextracti128	$0x1, %ymm1, %xmm1
	leal	-5(%rdi), %ecx
	vmovd	%xmm1, (%rax,%rdx,4)
	leal	5(%r8), %edx
	testl	%ecx, %ecx
	jle	.L104
	cmpl	$255, %edx
	ja	.L104
	addl	$6, %r8d
	vpextrd	$1, %xmm1, (%rax,%rdx,4)
	cmpl	$6, %edi
	jle	.L85
	cmpl	$255, %r8d
	ja	.L85
	vpextrd	$2, %xmm1, 1020(%rax)
	movl	$256, %r8d
.L85:
	movl	%r8d, %eax
	vzeroupper
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
	.p2align 4,,10
	.p2align 3
.L196:
	.cfi_restore_state
	movl	%ecx, %ecx
	vpsrldq	$8, %xmm0, %xmm0
	popcntl	%esi, %esi
	vmovq	(%rdx,%rcx,8), %xmm2
	movl	%r8d, %edx
	vmovdqu	%ymm1, (%rax,%rdx,4)
	leal	(%rsi,%r8), %edx
	vpshufb	%xmm2, %xmm0, %xmm0
	leal	(%rdi,%rdx), %r8d
	vpmovsxbd	%xmm0, %ymm0
	vmovdqu	%ymm0, (%rax,%rdx,4)
	movl	%r8d, %eax
	vzeroupper
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
	.p2align 4,,10
	.p2align 3
.L104:
	.cfi_restore_state
	movl	%edx, %r8d
	movl	%r8d, %eax
	vzeroupper
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
	.p2align 4,,10
	.p2align 3
.L197:
	.cfi_restore_state
	movl	%ecx, %r9d
	vpsrldq	$8, %xmm0, %xmm0
	popcntl	%esi, %esi
	vmovq	(%rdx,%r9,8), %xmm2
	movl	%r8d, %edx
	addl	%esi, %r8d
	vmovdqu	%ymm1, (%rax,%rdx,4)
	vpshufb	%xmm2, %xmm0, %xmm0
	vpmovsxbd	%xmm0, %ymm0
	cmpl	$255, %r8d
	ja	.L85
	testl	%ecx, %ecx
	je	.L85
	movl	%r8d, %edx
	vmovd	%xmm0, (%rax,%rdx,4)
	leal	1(%r8), %edx
	cmpl	$1, %edi
	je	.L104
	cmpl	$255, %edx
	ja	.L104
	vpextrd	$1, %xmm0, (%rax,%rdx,4)
	leal	2(%r8), %edx
	cmpl	$2, %edi
	je	.L104
	cmpl	$255, %edx
	ja	.L104
	vpextrd	$2, %xmm0, (%rax,%rdx,4)
	leal	3(%r8), %edx
	cmpl	$3, %edi
	je	.L104
	cmpl	$255, %edx
	ja	.L104
	vpextrd	$3, %xmm0, (%rax,%rdx,4)
	leal	4(%r8), %edx
	cmpl	$4, %edi
	je	.L104
	cmpl	$255, %edx
	ja	.L104
	vextracti128	$0x1, %ymm0, %xmm0
	vmovd	%xmm0, (%rax,%rdx,4)
	leal	5(%r8), %edx
	cmpl	$5, %edi
	je	.L104
	cmpl	$255, %edx
	ja	.L104
	vpextrd	$1, %xmm0, (%rax,%rdx,4)
	leal	-6(%rdi), %ecx
	leal	6(%r8), %edx
	cmpl	$6, %edi
	je	.L104
	cmpl	$255, %edx
	ja	.L104
	vpextrd	$2, %xmm0, (%rax,%rdx,4)
	leal	7(%r8), %edx
	cmpl	$1, %ecx
	je	.L104
	cmpl	$255, %edx
	ja	.L104
	addl	$8, %r8d
	vpextrd	$3, %xmm0, (%rax,%rdx,4)
	jmp	.L85
	.cfi_endproc
.LFE5717:
	.size	ml_dsa_rej_eta_avx_2, .-ml_dsa_rej_eta_avx_2
	.p2align 4
	.type	ml_dsa_polyz_unpack_17, @function
ml_dsa_polyz_unpack_17:
.LFB5725:
	.cfi_startproc
	vmovdqa	.LC13(%rip), %ymm3
	vpermq	$148, (%rsi), %ymm6
	vpermq	$148, 18(%rsi), %ymm5
	vpermq	$148, 36(%rsi), %ymm4
	vmovdqa	.LC14(%rip), %ymm2
	vpshufb	%ymm3, %ymm6, %ymm6
	vmovdqa	.LC15(%rip), %ymm1
	vpshufb	%ymm3, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vmovdqa	.LC16(%rip), %ymm0
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, (%rdi)
	vmovdqu	%ymm5, 32(%rdi)
	vmovdqu	%ymm4, 64(%rdi)
	vpermq	$148, 54(%rsi), %ymm6
	vpermq	$148, 72(%rsi), %ymm5
	vpermq	$148, 90(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 96(%rdi)
	vmovdqu	%ymm5, 128(%rdi)
	vmovdqu	%ymm4, 160(%rdi)
	vpermq	$148, 108(%rsi), %ymm6
	vpermq	$148, 126(%rsi), %ymm5
	vpermq	$148, 144(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 192(%rdi)
	vmovdqu	%ymm5, 224(%rdi)
	vmovdqu	%ymm4, 256(%rdi)
	vpermq	$148, 162(%rsi), %ymm6
	vpermq	$148, 180(%rsi), %ymm5
	vpermq	$148, 198(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 288(%rdi)
	vmovdqu	%ymm5, 320(%rdi)
	vmovdqu	%ymm4, 352(%rdi)
	vpermq	$148, 216(%rsi), %ymm6
	vpermq	$148, 234(%rsi), %ymm5
	vpermq	$148, 252(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 384(%rdi)
	vmovdqu	%ymm5, 416(%rdi)
	vmovdqu	%ymm4, 448(%rdi)
	vpermq	$148, 270(%rsi), %ymm6
	vpermq	$148, 288(%rsi), %ymm5
	vpermq	$148, 306(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 480(%rdi)
	vmovdqu	%ymm5, 512(%rdi)
	vmovdqu	%ymm4, 544(%rdi)
	vpermq	$148, 324(%rsi), %ymm6
	vpermq	$148, 342(%rsi), %ymm5
	vpermq	$148, 360(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 576(%rdi)
	vmovdqu	%ymm5, 608(%rdi)
	vmovdqu	%ymm4, 640(%rdi)
	vpermq	$148, 378(%rsi), %ymm6
	vpermq	$148, 396(%rsi), %ymm5
	vpermq	$148, 414(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 672(%rdi)
	vmovdqu	%ymm5, 704(%rdi)
	vmovdqu	%ymm4, 736(%rdi)
	vpermq	$148, 432(%rsi), %ymm6
	vpermq	$148, 450(%rsi), %ymm5
	vpermq	$148, 468(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 768(%rdi)
	vmovdqu	%ymm5, 800(%rdi)
	vmovdqu	%ymm4, 832(%rdi)
	vpermq	$148, 486(%rsi), %ymm6
	vpermq	$148, 504(%rsi), %ymm5
	vpermq	$148, 522(%rsi), %ymm4
	vpshufb	%ymm3, %ymm6, %ymm6
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm6, %ymm6
	vpsrlvd	%ymm2, %ymm5, %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpsrlvd	%ymm2, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm1, %ymm4, %ymm4
	vpsubd	%ymm6, %ymm0, %ymm6
	vpsubd	%ymm5, %ymm0, %ymm5
	vpsubd	%ymm4, %ymm0, %ymm4
	vmovdqu	%ymm6, 864(%rdi)
	vmovdqu	%ymm5, 896(%rdi)
	vmovdqu	%ymm4, 928(%rdi)
	vpermq	$148, 540(%rsi), %ymm4
	vpermq	$148, 558(%rsi), %ymm5
	vpshufb	%ymm3, %ymm4, %ymm4
	vpshufb	%ymm3, %ymm5, %ymm5
	vpsrlvd	%ymm2, %ymm4, %ymm3
	vpsrlvd	%ymm2, %ymm5, %ymm4
	vpand	%ymm1, %ymm3, %ymm2
	vpand	%ymm1, %ymm4, %ymm1
	vpsubd	%ymm2, %ymm0, %ymm2
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm2, 960(%rdi)
	vmovdqu	%ymm0, 992(%rdi)
	vzeroupper
	ret
	.cfi_endproc
.LFE5725:
	.size	ml_dsa_polyz_unpack_17, .-ml_dsa_polyz_unpack_17
	.p2align 4
	.type	ml_dsa_poly_generate_gamma1_4x, @function
ml_dsa_poly_generate_gamma1_4x:
.LFB5726:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$3680, %rsp
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	vmovdqu	(%r9), %xmm3
	vmovdqu	32(%r9), %xmm1
	movq	%rsi, 48(%rsp)
	vmovdqu	48(%r9), %xmm0
	leaq	96(%rsp), %r15
	leaq	928(%rsp), %rbx
	movq	%rdx, 40(%rsp)
	vmovdqu	16(%r9), %xmm2
	leaq	1616(%rsp), %r14
	leaq	2304(%rsp), %r13
	movq	%rcx, 32(%rsp)
	leaq	2992(%rsp), %r12
	movl	%r8d, 68(%rsp)
	movq	%rdi, 56(%rsp)
	movq	%r15, %rdi
	movq	%fs:40, %rax
	movq	%rax, 3672(%rsp)
	xorl	%eax, %eax
	movl	16(%rbp), %eax
	movq	%rbx, 88(%rsp)
	vmovdqa	%xmm3, 928(%rsp)
	movw	%ax, 992(%rsp)
	movl	24(%rbp), %eax
	vmovdqa	%xmm2, 944(%rsp)
	vmovdqa	%xmm1, 960(%rsp)
	vmovdqa	%xmm0, 976(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	vmovdqa	%xmm3, 2304(%rsp)
	movw	%ax, 1680(%rsp)
	vmovdqa	%xmm2, 2320(%rsp)
	movl	32(%rbp), %eax
	vmovdqa	%xmm1, 2336(%rsp)
	movw	%ax, 2368(%rsp)
	movl	40(%rbp), %eax
	vmovdqa	%xmm0, 2352(%rsp)
	movw	%ax, 3056(%rsp)
	vmovdqa	%xmm3, 2992(%rsp)
	vmovdqa	%xmm2, 3008(%rsp)
	vmovdqa	%xmm1, 3024(%rsp)
	vmovdqa	%xmm0, 3040(%rsp)
	movq	%r12, 24(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	%r13, %rcx
	movq	%r14, %rdx
	movq	%rbx, %rsi
	movq	%r15, %rdi
	movl	$66, %r9d
	movq	%r12, %r8
	movq	%r13, %rbx
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	movq	%r14, %rax
	xorl	%r11d, %r11d
	movq	%r15, %r14
	movq	%r11, %r13
	movq	%rax, %r15
	.p2align 4,,10
	.p2align 3
.L200:
	movq	88(%rsp), %rax
	leaq	(%r12,%r13), %rcx
	leaq	(%rbx,%r13), %rdx
	movq	%r14, %r9
	leaq	(%r15,%r13), %rsi
	movl	$136, %r8d
	movq	%r12, 72(%rsp)
	leaq	(%rax,%r13), %rdi
	addq	$136, %r13
	movq	%rax, 80(%rsp)
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	cmpq	$680, %r13
	jne	.L200
	movq	%rbx, %r12
	movq	%rbx, %r13
	movq	80(%rsp), %r10
	movq	72(%rsp), %rbx
	cmpl	$131072, 68(%rsp)
	movq	%r15, %rax
	movq	%r15, %r14
	je	.L215
	movq	56(%rsp), %rdx
	vmovdqa	.LC17(%rip), %ymm1
	leaq	1568(%rsp), %rcx
	vmovdqa	.LC18(%rip), %ymm2
	vmovdqa	.LC19(%rip), %ymm3
	vmovdqa	.LC20(%rip), %ymm4
	.p2align 4,,10
	.p2align 3
.L203:
	vpermq	$148, (%r10), %ymm0
	addq	$20, %r10
	addq	$32, %rdx
	vpshufb	%ymm1, %ymm0, %ymm0
	vpsrlvd	%ymm2, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpsubd	%ymm0, %ymm4, %ymm0
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%r10, %rcx
	jne	.L203
	movq	48(%rsp), %rdx
	addq	$640, %r14
	.p2align 4,,10
	.p2align 3
.L204:
	vpermq	$148, (%rax), %ymm0
	addq	$20, %rax
	addq	$32, %rdx
	vpshufb	%ymm1, %ymm0, %ymm0
	vpsrlvd	%ymm2, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpsubd	%ymm0, %ymm4, %ymm0
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%rax, %r14
	jne	.L204
	movq	40(%rsp), %rax
	addq	$640, %r13
	.p2align 4,,10
	.p2align 3
.L205:
	vpermq	$148, (%r12), %ymm0
	addq	$20, %r12
	addq	$32, %rax
	vpshufb	%ymm1, %ymm0, %ymm0
	vpsrlvd	%ymm2, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpsubd	%ymm0, %ymm4, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%r13, %r12
	jne	.L205
	movq	24(%rsp), %rdx
	movq	32(%rsp), %rax
	addq	$640, %rdx
	.p2align 4,,10
	.p2align 3
.L206:
	vpermq	$148, (%rbx), %ymm0
	addq	$20, %rbx
	addq	$32, %rax
	vpshufb	%ymm1, %ymm0, %ymm0
	vpsrlvd	%ymm2, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpsubd	%ymm0, %ymm4, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rbx, %rdx
	jne	.L206
	vzeroupper
.L199:
	movq	3672(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L216
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L215:
	.cfi_restore_state
	movq	88(%rsp), %rsi
	movq	56(%rsp), %rdi
	call	ml_dsa_polyz_unpack_17
	movq	48(%rsp), %rdi
	movq	%r15, %rsi
	call	ml_dsa_polyz_unpack_17
	movq	40(%rsp), %rdi
	movq	%r12, %rsi
	call	ml_dsa_polyz_unpack_17
	movq	24(%rsp), %rsi
	movq	32(%rsp), %rdi
	call	ml_dsa_polyz_unpack_17
	jmp	.L199
.L216:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5726:
	.size	ml_dsa_poly_generate_gamma1_4x, .-ml_dsa_poly_generate_gamma1_4x
	.p2align 4
	.type	poly_uniform_4x_op13, @function
poly_uniform_4x_op13:
.LFB5698:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	.cfi_offset 15, -24
	movq	%rcx, %r15
	pushq	%r14
	.cfi_offset 14, -32
	movq	%rsi, %r14
	pushq	%r13
	pushq	%r12
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	movq	%rdx, %r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$1888, %rsp
	.cfi_offset 3, -56
	vmovdqu	(%r8), %xmm1
	vmovdqu	16(%r8), %xmm0
	movq	%rdi, 32(%rsp)
	leaq	1696(%rsp), %rsi
	leaq	1792(%rsp), %rcx
	leaq	1744(%rsp), %r13
	leaq	1840(%rsp), %rbx
	movq	%fs:40, %rax
	movq	%rax, 1880(%rsp)
	xorl	%eax, %eax
	movl	16(%rbp), %eax
	movq	%rsi, 80(%rsp)
	movw	%r9w, 1728(%rsp)
	movw	%ax, 1776(%rsp)
	movl	24(%rbp), %eax
	movq	%rcx, 88(%rsp)
	movw	%ax, 1824(%rsp)
	movl	32(%rbp), %eax
	vmovdqa	%xmm1, 1696(%rsp)
	movw	%ax, 1872(%rsp)
	leaq	864(%rsp), %rax
	movq	%rax, %rdi
	movq	%rax, 24(%rsp)
	vmovdqa	%xmm0, 1712(%rsp)
	vmovdqa	%xmm1, 1744(%rsp)
	vmovdqa	%xmm0, 1760(%rsp)
	vmovdqa	%xmm1, 1792(%rsp)
	vmovdqa	%xmm0, 1808(%rsp)
	vmovdqa	%xmm1, 1840(%rsp)
	vmovdqa	%xmm0, 1856(%rsp)
	call	ossl_sha3_shake128_x4_inc_init_avx2@PLT
	movq	88(%rsp), %rcx
	movq	%rbx, %r8
	movq	%r13, %rdx
	movq	80(%rsp), %rsi
	movq	24(%rsp), %rdi
	movl	$34, %r9d
	xorl	%r13d, %r13d
	leaq	idxlut(%rip), %rbx
	call	ossl_sha3_shake128_x4_inc_absorb_avx2@PLT
	leaq	96(%rsp), %rax
	xorl	%r11d, %r11d
	movq	%r12, %r10
	movq	%rax, 40(%rsp)
	leaq	672(%rsp), %rax
	movq	%r14, %r12
	movl	%r11d, %r14d
	movq	%rax, 64(%rsp)
	leaq	480(%rsp), %rax
	movq	%rax, 48(%rsp)
	leaq	288(%rsp), %rax
	movl	$4, 72(%rsp)
	movl	$0, 76(%rsp)
	movl	$0, 88(%rsp)
	movq	%rax, 56(%rsp)
	movq	%r15, %rax
	movq	32(%rsp), %r15
	movq	%rax, %r11
.L275:
	movq	64(%rsp), %rcx
	movq	48(%rsp), %rdx
	movl	$168, %r8d
	movq	%r11, 32(%rsp)
	movq	56(%rsp), %rsi
	movq	24(%rsp), %r9
	movq	%r10, 80(%rsp)
	movq	40(%rsp), %rdi
	call	ossl_sha3_shake128_x4_inc_squeeze_avx2@PLT
	vpermq	$148, 96(%rsp), %ymm3
	vmovdqa	.LC0(%rip), %ymm2
	vmovdqa	.LC1(%rip), %ymm1
	vmovdqa	.LC2(%rip), %ymm0
	vpshufb	%ymm2, %ymm3, %ymm3
	movl	88(%rsp), %ecx
	movq	80(%rsp), %r10
	vpand	%ymm3, %ymm1, %ymm3
	movq	32(%rsp), %r11
	vpaddd	%ymm3, %ymm0, %ymm4
	movq	%rcx, %rax
	leaq	(%r15,%rcx,4), %rsi
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L218
	movl	%edx, %ecx
	vpmovzxbd	(%rbx,%rcx,8), %ymm4
	xorl	%ecx, %ecx
	popcntl	%edx, %ecx
	addl	%eax, %ecx
	vpermd	%ymm3, %ymm4, %ymm3
.L219:
	vmovdqu	%ymm3, (%rsi)
	vpermq	$148, 120(%rsp), %ymm3
	movl	%ecx, %esi
	leaq	(%r15,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L220
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L221:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 144(%rsp), %ymm3
	leaq	(%r15,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L222
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L223:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 168(%rsp), %ymm3
	leaq	(%r15,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L224
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L225:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 192(%rsp), %ymm3
	leaq	(%r15,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L226
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L227:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 216(%rsp), %ymm3
	leaq	(%r15,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L228
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L229:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 240(%rsp), %ymm3
	leaq	(%r15,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L230
	movl	%edx, %edi
	popcntl	%edx, %edx
	leal	(%rdx,%rcx), %eax
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	movl	%eax, 88(%rsp)
	vpermd	%ymm3, %ymm4, %ymm3
.L231:
	vmovdqu	%ymm3, (%rsi)
	movl	%r13d, %ecx
	vpermq	$148, 288(%rsp), %ymm3
	leaq	(%r12,%rcx,4), %rsi
	leal	8(%r13), %ecx
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L233
	movl	%edx, %ecx
	popcntl	%edx, %edx
	vpmovzxbd	(%rbx,%rcx,8), %ymm4
	leal	(%rdx,%r13), %ecx
	vpermd	%ymm3, %ymm4, %ymm3
.L233:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 312(%rsp), %ymm3
	leaq	(%r12,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L234
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L235:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 336(%rsp), %ymm3
	leaq	(%r12,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L236
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L237:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 360(%rsp), %ymm3
	leaq	(%r12,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L238
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L239:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 384(%rsp), %ymm3
	leaq	(%r12,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L240
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L241:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 408(%rsp), %ymm3
	leaq	(%r12,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L242
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L243:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	leal	8(%rcx), %r13d
	vpermq	$148, 432(%rsp), %ymm3
	leaq	(%r12,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L245
	movl	%edx, %edi
	popcntl	%edx, %edx
	leal	(%rdx,%rcx), %r13d
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L245:
	vmovdqu	%ymm3, (%rsi)
	movl	76(%rsp), %ecx
	vpermq	$148, 480(%rsp), %ymm3
	vpshufb	%ymm2, %ymm3, %ymm3
	movq	%rcx, %rax
	leaq	(%r10,%rcx,4), %rsi
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L246
	movl	%edx, %ecx
	popcntl	%edx, %edx
	addl	%edx, %eax
	vpmovzxbd	(%rbx,%rcx,8), %ymm4
	movl	%eax, %ecx
	vpermd	%ymm3, %ymm4, %ymm3
.L247:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 504(%rsp), %ymm3
	leaq	(%r10,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L248
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L249:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 528(%rsp), %ymm3
	leaq	(%r10,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L250
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L251:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 552(%rsp), %ymm3
	leaq	(%r10,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L252
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L253:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 576(%rsp), %ymm3
	leaq	(%r10,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L254
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L255:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 600(%rsp), %ymm3
	leaq	(%r10,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L256
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L257:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 624(%rsp), %ymm3
	leaq	(%r10,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L258
	movl	%edx, %edi
	popcntl	%edx, %edx
	leal	(%rdx,%rcx), %eax
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	movl	%eax, 76(%rsp)
	vpermd	%ymm3, %ymm4, %ymm3
.L259:
	vmovdqu	%ymm3, (%rsi)
	movl	%r14d, %ecx
	vpermq	$148, 672(%rsp), %ymm3
	leaq	(%r11,%rcx,4), %rsi
	leal	8(%r14), %ecx
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L261
	movl	%edx, %ecx
	popcntl	%edx, %edx
	vpmovzxbd	(%rbx,%rcx,8), %ymm4
	leal	(%rdx,%r14), %ecx
	vpermd	%ymm3, %ymm4, %ymm3
.L261:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 696(%rsp), %ymm3
	leaq	(%r11,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L262
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L263:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 720(%rsp), %ymm3
	leaq	(%r11,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L264
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L265:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 744(%rsp), %ymm3
	leaq	(%r11,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L266
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L267:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 768(%rsp), %ymm3
	leaq	(%r11,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L268
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L269:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 792(%rsp), %ymm3
	leaq	(%r11,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L270
	movl	%edx, %edi
	popcntl	%edx, %edx
	addl	%edx, %ecx
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
.L271:
	vmovdqu	%ymm3, (%rsi)
	movl	%ecx, %esi
	vpermq	$148, 816(%rsp), %ymm3
	leaq	(%r11,%rsi,4), %rsi
	vpshufb	%ymm2, %ymm3, %ymm3
	vpand	%ymm3, %ymm1, %ymm3
	vpaddd	%ymm3, %ymm0, %ymm4
	vmovmskps	%ymm4, %edx
	cmpl	$255, %edx
	je	.L272
	movl	%edx, %edi
	popcntl	%edx, %edx
	subl	$1, 72(%rsp)
	leal	(%rdx,%rcx), %r14d
	vpmovzxbd	(%rbx,%rdi,8), %ymm4
	vpermd	%ymm3, %ymm4, %ymm3
	vmovdqu	%ymm3, (%rsi)
	je	.L312
.L309:
	vzeroupper
	jmp	.L275
.L258:
	leal	8(%rcx), %eax
	movl	%eax, 76(%rsp)
	jmp	.L259
.L272:
	subl	$1, 72(%rsp)
	leal	8(%rcx), %r14d
	vmovdqu	%ymm3, (%rsi)
	jne	.L309
.L312:
	movq	40(%rsp), %rbx
	movq	%r11, %rax
	movq	24(%rsp), %r9
	movl	%r14d, %r11d
	movq	64(%rsp), %rcx
	movq	48(%rsp), %rdx
	movq	%r12, %r14
	movl	$168, %r8d
	movq	56(%rsp), %rsi
	movq	%r10, %r12
	movq	%rbx, %rdi
	movq	%r15, %r10
	movq	%rax, %r15
	movq	%r10, 80(%rsp)
	movl	%r11d, 72(%rsp)
	vzeroupper
	call	ossl_sha3_shake128_x4_inc_squeeze_avx2@PLT
	movq	80(%rsp), %r10
	movl	88(%rsp), %edx
	movq	%rbx, %rsi
	movq	%r10, %rdi
	movq	%r10, 32(%rsp)
	call	ml_dsa_rej_uniform_avx_s1s3_final
	movq	56(%rsp), %rsi
	movl	%r13d, %edx
	movq	%r14, %rdi
	movl	%eax, 88(%rsp)
	call	ml_dsa_rej_uniform_avx_s1s3_final
	movl	76(%rsp), %edx
	movq	48(%rsp), %rsi
	movq	%r12, %rdi
	movl	%eax, %ebx
	movl	%eax, 80(%rsp)
	call	ml_dsa_rej_uniform_avx_s1s3_final
	movl	72(%rsp), %edx
	movq	64(%rsp), %rsi
	movq	%r15, %rdi
	movl	%eax, %r13d
	call	ml_dsa_rej_uniform_avx_s1s3_final
	cmpl	$255, %ebx
	movq	32(%rsp), %r10
	movl	%eax, 76(%rsp)
	movl	%eax, %esi
	setbe	%al
	cmpl	$255, 88(%rsp)
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r13d
	setbe	%dl
	orb	%dl, %al
	jne	.L301
	cmpl	$255, %esi
	ja	.L217
.L301:
	movq	%r15, %rax
	movl	$256, %ebx
	movq	%r12, %r15
	movq	%r10, %r12
	movq	%rax, %r10
	.p2align 4,,10
	.p2align 3
.L306:
	movq	24(%rsp), %r9
	movq	64(%rsp), %rcx
	movl	$168, %r8d
	movq	%r10, 32(%rsp)
	movq	48(%rsp), %rdx
	movq	56(%rsp), %rsi
	movq	40(%rsp), %rdi
	call	ossl_sha3_shake128_x4_inc_squeeze_avx2@PLT
	movl	88(%rsp), %r11d
	movl	%ebx, %r8d
	movq	32(%rsp), %r10
	subl	%r11d, %r8d
	je	.L295
	movq	40(%rsp), %rdx
	leaq	264(%rsp), %r9
	xorl	%esi, %esi
	jmp	.L280
	.p2align 4,,10
	.p2align 3
.L279:
	addq	$3, %rdx
	cmpq	%r9, %rdx
	je	.L313
.L280:
	movzbl	1(%rdx), %eax
	movzbl	2(%rdx), %edi
	movzbl	(%rdx), %ecx
	sall	$8, %eax
	sall	$16, %edi
	orl	%edi, %eax
	orl	%ecx, %eax
	andl	$8388607, %eax
	cmpl	$8380416, %eax
	ja	.L278
	movl	%esi, %ecx
	addl	$1, %esi
	addq	%r11, %rcx
	movl	%eax, (%r12,%rcx,4)
.L278:
	cmpl	%esi, %r8d
	ja	.L279
.L313:
	movl	80(%rsp), %r11d
	movl	%ebx, %r8d
	addl	%esi, 88(%rsp)
	subl	%r11d, %r8d
	je	.L296
.L318:
	movq	56(%rsp), %rdx
	leaq	456(%rsp), %r9
	xorl	%esi, %esi
	jmp	.L284
	.p2align 4,,10
	.p2align 3
.L283:
	addq	$3, %rdx
	cmpq	%rdx, %r9
	je	.L314
.L284:
	movzbl	1(%rdx), %eax
	movzbl	2(%rdx), %edi
	movzbl	(%rdx), %ecx
	sall	$8, %eax
	sall	$16, %edi
	orl	%edi, %eax
	orl	%ecx, %eax
	andl	$8388607, %eax
	cmpl	$8380416, %eax
	ja	.L282
	movl	%esi, %ecx
	addl	$1, %esi
	addq	%r11, %rcx
	movl	%eax, (%r14,%rcx,4)
.L282:
	cmpl	%esi, %r8d
	ja	.L283
.L314:
	addl	%esi, 80(%rsp)
.L281:
	movl	%ebx, %r8d
	movl	%r13d, %r11d
	subl	%r13d, %r8d
	je	.L297
	movq	48(%rsp), %rdx
	leaq	648(%rsp), %r9
	xorl	%esi, %esi
	jmp	.L288
	.p2align 4,,10
	.p2align 3
.L287:
	addq	$3, %rdx
	cmpq	%rdx, %r9
	je	.L315
.L288:
	movzbl	1(%rdx), %eax
	movzbl	2(%rdx), %edi
	movzbl	(%rdx), %ecx
	sall	$8, %eax
	sall	$16, %edi
	orl	%edi, %eax
	orl	%ecx, %eax
	andl	$8388607, %eax
	cmpl	$8380416, %eax
	ja	.L286
	movl	%esi, %ecx
	addl	$1, %esi
	addq	%r11, %rcx
	movl	%eax, (%r15,%rcx,4)
.L286:
	cmpl	%esi, %r8d
	ja	.L287
.L315:
	addl	%esi, %r13d
.L285:
	movl	76(%rsp), %r11d
	movl	%ebx, %r8d
	subl	%r11d, %r8d
	je	.L298
	movq	64(%rsp), %rdx
	leaq	840(%rsp), %r9
	xorl	%esi, %esi
	jmp	.L292
	.p2align 4,,10
	.p2align 3
.L291:
	addq	$3, %rdx
	cmpq	%rdx, %r9
	je	.L316
.L292:
	movzbl	1(%rdx), %eax
	movzbl	2(%rdx), %edi
	movzbl	(%rdx), %ecx
	sall	$8, %eax
	sall	$16, %edi
	orl	%edi, %eax
	orl	%ecx, %eax
	andl	$8388607, %eax
	cmpl	$8380416, %eax
	ja	.L290
	movl	%esi, %ecx
	addl	$1, %esi
	addq	%r11, %rcx
	movl	%eax, (%r10,%rcx,4)
.L290:
	cmpl	%esi, %r8d
	ja	.L291
.L316:
	addl	%esi, 76(%rsp)
.L289:
	cmpl	$255, 80(%rsp)
	setbe	%al
	cmpl	$255, 88(%rsp)
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r13d
	setbe	%dl
	orb	%dl, %al
	jne	.L306
	cmpl	$255, 76(%rsp)
	jbe	.L306
.L217:
	movq	1880(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L317
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L298:
	.cfi_restore_state
	movl	$256, 76(%rsp)
	jmp	.L289
.L297:
	movl	$256, %r13d
	jmp	.L285
.L295:
	movl	80(%rsp), %r11d
	movl	%ebx, %r8d
	movl	$256, 88(%rsp)
	subl	%r11d, %r8d
	jne	.L318
.L296:
	movl	$256, 80(%rsp)
	jmp	.L281
.L270:
	addl	$8, %ecx
	jmp	.L271
.L268:
	addl	$8, %ecx
	jmp	.L269
.L266:
	addl	$8, %ecx
	jmp	.L267
.L264:
	addl	$8, %ecx
	jmp	.L265
.L262:
	addl	$8, %ecx
	jmp	.L263
.L256:
	addl	$8, %ecx
	jmp	.L257
.L254:
	addl	$8, %ecx
	jmp	.L255
.L252:
	addl	$8, %ecx
	jmp	.L253
.L250:
	addl	$8, %ecx
	jmp	.L251
.L248:
	addl	$8, %ecx
	jmp	.L249
.L246:
	addl	$8, %ecx
	jmp	.L247
.L242:
	addl	$8, %ecx
	jmp	.L243
.L240:
	addl	$8, %ecx
	jmp	.L241
.L238:
	addl	$8, %ecx
	jmp	.L239
.L236:
	addl	$8, %ecx
	jmp	.L237
.L234:
	addl	$8, %ecx
	jmp	.L235
.L230:
	leal	8(%rcx), %eax
	movl	%eax, 88(%rsp)
	jmp	.L231
.L228:
	addl	$8, %ecx
	jmp	.L229
.L226:
	addl	$8, %ecx
	jmp	.L227
.L224:
	addl	$8, %ecx
	jmp	.L225
.L222:
	addl	$8, %ecx
	jmp	.L223
.L220:
	addl	$8, %ecx
	jmp	.L221
.L218:
	addl	$8, %ecx
	jmp	.L219
.L317:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5698:
	.size	poly_uniform_4x_op13, .-poly_uniform_4x_op13
	.p2align 4
	.globl	ossl_ml_dsa_expand_A_44
	.type	ossl_ml_dsa_expand_A_44, @function
ossl_ml_dsa_expand_A_44:
.LFB5699:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsi, %rbp
	xorl	%r9d, %r9d
	pushq	%rbx
	.cfi_def_cfa_offset 24
	.cfi_offset 3, -24
	movq	%rbp, %r8
	subq	$16, %rsp
	.cfi_def_cfa_offset 40
	movq	(%rdi), %rbx
	pushq	$3
	.cfi_def_cfa_offset 48
	pushq	$2
	.cfi_def_cfa_offset 56
	leaq	3072(%rbx), %rcx
	movq	%rbx, %rdi
	leaq	2048(%rbx), %rdx
	pushq	$1
	.cfi_def_cfa_offset 64
	leaq	1024(%rbx), %rsi
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	7168(%rbx), %rcx
	pushq	$259
	.cfi_def_cfa_offset 48
	leaq	6144(%rbx), %rdx
	leaq	5120(%rbx), %rsi
	movl	$256, %r9d
	pushq	$258
	.cfi_def_cfa_offset 56
	leaq	4096(%rbx), %rdi
	pushq	$257
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	11264(%rbx), %rcx
	pushq	$515
	.cfi_def_cfa_offset 48
	leaq	10240(%rbx), %rdx
	leaq	9216(%rbx), %rsi
	movl	$512, %r9d
	pushq	$514
	.cfi_def_cfa_offset 56
	leaq	8192(%rbx), %rdi
	pushq	$513
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	15360(%rbx), %rcx
	pushq	$771
	.cfi_def_cfa_offset 48
	leaq	14336(%rbx), %rdx
	leaq	13312(%rbx), %rsi
	movl	$768, %r9d
	pushq	$770
	.cfi_def_cfa_offset 56
	leaq	12288(%rbx), %rdi
	pushq	$769
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$40, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE5699:
	.size	ossl_ml_dsa_expand_A_44, .-ossl_ml_dsa_expand_A_44
	.p2align 4
	.globl	ossl_ml_dsa_expand_A_65
	.type	ossl_ml_dsa_expand_A_65, @function
ossl_ml_dsa_expand_A_65:
.LFB5706:
	.cfi_startproc
	endbr64
	pushq	%r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	pushq	%rbp
	.cfi_def_cfa_offset 24
	.cfi_offset 6, -24
	movq	%rsi, %rbp
	movl	$1024, %esi
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset 3, -32
	movq	(%rdi), %rbx
	movl	$2, %edi
	call	calloc@PLT
	subq	$8, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	movq	%rbx, %rdi
	pushq	$3
	.cfi_def_cfa_offset 48
	leaq	3072(%rbx), %rcx
	xorl	%r9d, %r9d
	movq	%rax, %r12
	pushq	$2
	.cfi_def_cfa_offset 56
	leaq	2048(%rbx), %rdx
	leaq	1024(%rbx), %rsi
	pushq	$1
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	7168(%rbx), %rcx
	pushq	$258
	.cfi_def_cfa_offset 48
	leaq	6144(%rbx), %rdx
	leaq	5120(%rbx), %rsi
	movl	$4, %r9d
	pushq	$257
	.cfi_def_cfa_offset 56
	leaq	4096(%rbx), %rdi
	pushq	$256
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	11264(%rbx), %rcx
	pushq	$513
	.cfi_def_cfa_offset 48
	leaq	10240(%rbx), %rdx
	leaq	9216(%rbx), %rsi
	movl	$259, %r9d
	pushq	$512
	.cfi_def_cfa_offset 56
	leaq	8192(%rbx), %rdi
	pushq	$260
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	15360(%rbx), %rcx
	pushq	$768
	.cfi_def_cfa_offset 48
	leaq	14336(%rbx), %rdx
	leaq	13312(%rbx), %rsi
	movl	$514, %r9d
	pushq	$516
	.cfi_def_cfa_offset 56
	leaq	12288(%rbx), %rdi
	pushq	$515
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	19456(%rbx), %rcx
	pushq	$772
	.cfi_def_cfa_offset 48
	leaq	18432(%rbx), %rdx
	leaq	17408(%rbx), %rsi
	movl	$769, %r9d
	pushq	$771
	.cfi_def_cfa_offset 56
	leaq	16384(%rbx), %rdi
	pushq	$770
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	23552(%rbx), %rcx
	pushq	$1027
	.cfi_def_cfa_offset 48
	leaq	22528(%rbx), %rdx
	leaq	21504(%rbx), %rsi
	movl	$1024, %r9d
	pushq	$1026
	.cfi_def_cfa_offset 56
	leaq	20480(%rbx), %rdi
	pushq	$1025
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	27648(%rbx), %rcx
	pushq	$1282
	.cfi_def_cfa_offset 48
	leaq	26624(%rbx), %rdx
	leaq	25600(%rbx), %rsi
	movl	$1028, %r9d
	pushq	$1281
	.cfi_def_cfa_offset 56
	leaq	24576(%rbx), %rdi
	pushq	$1280
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	movq	%r12, %rdx
	pushq	$1537
	.cfi_def_cfa_offset 48
	leaq	1024(%r12), %rcx
	leaq	29696(%rbx), %rsi
	movl	$1283, %r9d
	pushq	$1536
	.cfi_def_cfa_offset 56
	leaq	28672(%rbx), %rdi
	pushq	$1284
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$32, %rsp
	.cfi_def_cfa_offset 32
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%rbp
	.cfi_def_cfa_offset 16
	popq	%r12
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE5706:
	.size	ossl_ml_dsa_expand_A_65, .-ossl_ml_dsa_expand_A_65
	.p2align 4
	.globl	ossl_ml_dsa_expand_A_87
	.type	ossl_ml_dsa_expand_A_87, @function
ossl_ml_dsa_expand_A_87:
.LFB5715:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsi, %rbp
	xorl	%r9d, %r9d
	pushq	%rbx
	.cfi_def_cfa_offset 24
	.cfi_offset 3, -24
	movq	%rbp, %r8
	subq	$16, %rsp
	.cfi_def_cfa_offset 40
	movq	(%rdi), %rbx
	pushq	$3
	.cfi_def_cfa_offset 48
	pushq	$2
	.cfi_def_cfa_offset 56
	leaq	3072(%rbx), %rcx
	movq	%rbx, %rdi
	leaq	2048(%rbx), %rdx
	pushq	$1
	.cfi_def_cfa_offset 64
	leaq	1024(%rbx), %rsi
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	7168(%rbx), %rcx
	pushq	$256
	.cfi_def_cfa_offset 48
	leaq	6144(%rbx), %rdx
	leaq	5120(%rbx), %rsi
	movl	$4, %r9d
	pushq	$6
	.cfi_def_cfa_offset 56
	leaq	4096(%rbx), %rdi
	pushq	$5
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	11264(%rbx), %rcx
	pushq	$260
	.cfi_def_cfa_offset 48
	leaq	10240(%rbx), %rdx
	leaq	9216(%rbx), %rsi
	movl	$257, %r9d
	pushq	$259
	.cfi_def_cfa_offset 56
	leaq	8192(%rbx), %rdi
	pushq	$258
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	15360(%rbx), %rcx
	pushq	$513
	.cfi_def_cfa_offset 48
	leaq	14336(%rbx), %rdx
	leaq	13312(%rbx), %rsi
	movl	$261, %r9d
	pushq	$512
	.cfi_def_cfa_offset 56
	leaq	12288(%rbx), %rdi
	pushq	$262
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	19456(%rbx), %rcx
	pushq	$517
	.cfi_def_cfa_offset 48
	leaq	18432(%rbx), %rdx
	leaq	17408(%rbx), %rsi
	movl	$514, %r9d
	pushq	$516
	.cfi_def_cfa_offset 56
	leaq	16384(%rbx), %rdi
	pushq	$515
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	23552(%rbx), %rcx
	pushq	$770
	.cfi_def_cfa_offset 48
	leaq	22528(%rbx), %rdx
	leaq	21504(%rbx), %rsi
	movl	$518, %r9d
	pushq	$769
	.cfi_def_cfa_offset 56
	leaq	20480(%rbx), %rdi
	pushq	$768
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	27648(%rbx), %rcx
	pushq	$774
	.cfi_def_cfa_offset 48
	leaq	26624(%rbx), %rdx
	leaq	25600(%rbx), %rsi
	movl	$771, %r9d
	pushq	$773
	.cfi_def_cfa_offset 56
	leaq	24576(%rbx), %rdi
	pushq	$772
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	31744(%rbx), %rcx
	pushq	$1027
	.cfi_def_cfa_offset 48
	leaq	30720(%rbx), %rdx
	leaq	29696(%rbx), %rsi
	movl	$1024, %r9d
	pushq	$1026
	.cfi_def_cfa_offset 56
	leaq	28672(%rbx), %rdi
	pushq	$1025
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	35840(%rbx), %rcx
	pushq	$1280
	.cfi_def_cfa_offset 48
	leaq	34816(%rbx), %rdx
	leaq	33792(%rbx), %rsi
	movl	$1028, %r9d
	pushq	$1030
	.cfi_def_cfa_offset 56
	leaq	32768(%rbx), %rdi
	pushq	$1029
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	39936(%rbx), %rcx
	pushq	$1284
	.cfi_def_cfa_offset 48
	leaq	38912(%rbx), %rdx
	leaq	37888(%rbx), %rsi
	movl	$1281, %r9d
	pushq	$1283
	.cfi_def_cfa_offset 56
	leaq	36864(%rbx), %rdi
	pushq	$1282
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	44032(%rbx), %rcx
	pushq	$1537
	.cfi_def_cfa_offset 48
	leaq	43008(%rbx), %rdx
	leaq	41984(%rbx), %rsi
	movl	$1285, %r9d
	pushq	$1536
	.cfi_def_cfa_offset 56
	leaq	40960(%rbx), %rdi
	pushq	$1286
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	48128(%rbx), %rcx
	pushq	$1541
	.cfi_def_cfa_offset 48
	leaq	47104(%rbx), %rdx
	leaq	46080(%rbx), %rsi
	movl	$1538, %r9d
	pushq	$1540
	.cfi_def_cfa_offset 56
	leaq	45056(%rbx), %rdi
	pushq	$1539
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	52224(%rbx), %rcx
	pushq	$1794
	.cfi_def_cfa_offset 48
	leaq	51200(%rbx), %rdx
	leaq	50176(%rbx), %rsi
	movl	$1542, %r9d
	pushq	$1793
	.cfi_def_cfa_offset 56
	leaq	49152(%rbx), %rdi
	pushq	$1792
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	movq	%rbp, %r8
	leaq	56320(%rbx), %rcx
	pushq	$1798
	.cfi_def_cfa_offset 48
	leaq	55296(%rbx), %rdx
	leaq	54272(%rbx), %rsi
	movl	$1795, %r9d
	pushq	$1797
	.cfi_def_cfa_offset 56
	leaq	53248(%rbx), %rdi
	pushq	$1796
	.cfi_def_cfa_offset 64
	call	poly_uniform_4x_op13
	addq	$40, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE5715:
	.size	ossl_ml_dsa_expand_A_87, .-ossl_ml_dsa_expand_A_87
	.p2align 4
	.globl	ossl_ml_dsa_expand_S_44
	.type	ossl_ml_dsa_expand_S_44, @function
ossl_ml_dsa_expand_S_44:
.LFB5719:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movl	$3, %r10d
	movl	$1, %r8d
	movl	$2, %r9d
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$1856, %rsp
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	vmovdqu	16(%rdx), %xmm2
	vmovdqu	32(%rdx), %xmm1
	movq	%rsi, 64(%rsp)
	movq	(%rdi), %r14
	leaq	704(%rsp), %r13
	leaq	1536(%rsp), %rbx
	vmovdqu	48(%rdx), %xmm0
	vmovdqu	(%rdx), %xmm3
	movq	%rdx, 56(%rsp)
	leaq	1616(%rsp), %r15
	movq	%rdi, 72(%rsp)
	xorl	%edi, %edi
	leaq	1696(%rsp), %r12
	movq	%fs:40, %rax
	movq	%rax, 1848(%rsp)
	xorl	%eax, %eax
	movq	(%rsi), %rax
	movw	%di, 1600(%rsp)
	movq	%r13, %rdi
	vmovdqa	%xmm3, 1536(%rsp)
	movq	%rax, 120(%rsp)
	leaq	1776(%rsp), %rax
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	movw	%r8w, 1680(%rsp)
	movq	%rbx, 32(%rsp)
	movq	%r15, 40(%rsp)
	movq	%r12, 48(%rsp)
	vmovdqa	%xmm3, 1696(%rsp)
	movw	%r10w, 1840(%rsp)
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movq	%rax, 80(%rsp)
	movw	%r9w, 1760(%rsp)
	movq	%r13, 128(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	80(%rsp), %r8
	movq	%r12, %rcx
	movq	%r15, %rdx
	movq	%rbx, %rsi
	movq	%r13, %rdi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	leaq	160(%rsp), %r15
	leaq	432(%rsp), %rax
	movq	%r13, %r9
	leaq	296(%rsp), %rdi
	leaq	568(%rsp), %rbx
	movq	%rax, %rdx
	movl	$136, %r8d
	movq	%rbx, %rcx
	movq	%rdi, 144(%rsp)
	movq	%rdi, %r13
	movq	%rdi, %rsi
	movq	%r15, %rdi
	movq	%rax, 152(%rsp)
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	%r15, %rsi
	movq	%r14, %rdi
	movq	%r14, 24(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	%r13, %rsi
	movl	%eax, %r12d
	leaq	1024(%r14), %rax
	movq	%rax, %rdi
	movq	%rax, 104(%rsp)
	call	ml_dsa_rej_eta_avx_2
	leaq	2048(%r14), %rcx
	movq	%r14, 112(%rsp)
	movq	152(%rsp), %rsi
	movq	%rcx, %rdi
	movq	%rcx, 96(%rsp)
	movl	%eax, %r13d
	call	ml_dsa_rej_eta_avx_2
	movq	%rbx, %rsi
	movl	%eax, %r14d
	movq	112(%rsp), %rax
	addq	$3072, %rax
	movq	%rax, %rdi
	movq	%rax, 88(%rsp)
	call	ml_dsa_rej_eta_avx_2
	jmp	.L351
	.p2align 4,,10
	.p2align 3
.L341:
	movq	128(%rsp), %r9
	movl	$136, %r8d
	movq	%rbx, %rcx
	movq	%r15, %rdi
	movq	152(%rsp), %rdx
	movq	144(%rsp), %rsi
	movl	%r10d, 140(%rsp)
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	112(%rsp), %rdi
	movl	%r12d, %esi
	movq	%r15, %rdx
	call	rej_eta_2
	movq	144(%rsp), %rdx
	movq	104(%rsp), %rdi
	movl	%r13d, %esi
	movl	%eax, %r12d
	call	rej_eta_2
	movq	152(%rsp), %rdx
	movq	96(%rsp), %rdi
	movl	%r14d, %esi
	movl	%eax, %r13d
	call	rej_eta_2
	movl	140(%rsp), %esi
	movq	88(%rsp), %rdi
	movq	%rbx, %rdx
	movl	%eax, %r14d
	call	rej_eta_2
.L351:
	cmpl	$255, %r12d
	movl	%eax, %r10d
	setbe	%al
	cmpl	$255, %r13d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r14d
	setbe	%dl
	orb	%dl, %al
	jne	.L341
	cmpl	$255, %r10d
	jbe	.L341
	movq	56(%rsp), %rax
	movl	$5, %edx
	movl	$6, %ecx
	movq	128(%rsp), %r14
	movl	$7, %esi
	movw	%dx, 1680(%rsp)
	vmovdqu	(%rax), %xmm3
	vmovdqu	16(%rax), %xmm2
	movq	%r14, %rdi
	movw	%cx, 1760(%rsp)
	vmovdqu	32(%rax), %xmm1
	vmovdqu	48(%rax), %xmm0
	movl	$4, %eax
	movw	%si, 1840(%rsp)
	vmovdqa	%xmm3, 1536(%rsp)
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	vmovdqa	%xmm3, 1696(%rsp)
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movw	%ax, 1600(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	80(%rsp), %r8
	movq	48(%rsp), %rcx
	movq	%r14, %rdi
	movq	40(%rsp), %rdx
	movq	32(%rsp), %rsi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	movq	%r14, %r9
	movq	%rbx, %rcx
	movq	%r15, %rdi
	movq	144(%rsp), %r14
	movq	152(%rsp), %rdx
	movl	$136, %r8d
	movq	%r14, %rsi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	120(%rsp), %r12
	movq	%r15, %rsi
	movq	%r12, %rdi
	movq	%r12, 80(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	%r14, %rsi
	movl	%eax, %r13d
	leaq	1024(%r12), %rax
	movq	%rax, %rdi
	movq	%rax, 112(%rsp)
	call	ml_dsa_rej_eta_avx_2
	leaq	2048(%r12), %rcx
	movq	%r12, 120(%rsp)
	movq	152(%rsp), %rsi
	movq	%rcx, %rdi
	movq	%rcx, 96(%rsp)
	movl	%eax, %r14d
	call	ml_dsa_rej_eta_avx_2
	movq	%rbx, %rsi
	movl	%eax, %r12d
	movq	120(%rsp), %rax
	addq	$3072, %rax
	movq	%rax, %rdi
	movq	%rax, 88(%rsp)
	call	ml_dsa_rej_eta_avx_2
	cmpl	$255, %r14d
	movl	%eax, 140(%rsp)
	movl	%eax, %ecx
	setbe	%al
	cmpl	$255, %r13d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r12d
	setbe	%dl
	orb	%dl, %al
	jne	.L346
	cmpl	$255, %ecx
	ja	.L328
.L346:
	movq	%r15, %rax
	movq	%rbx, %r15
	movq	%rax, %rbx
	.p2align 4,,10
	.p2align 3
.L342:
	movq	128(%rsp), %r9
	movq	%r15, %rcx
	movl	$136, %r8d
	movq	%rbx, %rdi
	movq	152(%rsp), %rdx
	movq	144(%rsp), %rsi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	120(%rsp), %rdi
	movl	%r13d, %esi
	movq	%rbx, %rdx
	call	rej_eta_2
	movq	144(%rsp), %rdx
	movq	112(%rsp), %rdi
	movl	%r14d, %esi
	addl	%eax, %r13d
	call	rej_eta_2
	movq	152(%rsp), %rdx
	movq	96(%rsp), %rdi
	movl	%r12d, %esi
	addl	%eax, %r14d
	call	rej_eta_2
	movl	140(%rsp), %esi
	movq	88(%rsp), %rdi
	movq	%r15, %rdx
	addl	%eax, %r12d
	call	rej_eta_2
	addl	%eax, 140(%rsp)
	cmpl	$255, %r14d
	movl	140(%rsp), %ecx
	setbe	%al
	cmpl	$255, %r13d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r12d
	setbe	%dl
	orb	%dl, %al
	jne	.L342
	cmpl	$255, %ecx
	jbe	.L342
.L328:
	movq	72(%rsp), %rdi
	cmpq	$0, 8(%rdi)
	je	.L330
	movq	104(%rsp), %rdx
	vmovdqa	.LC21(%rip), %ymm2
	xorl	%ecx, %ecx
	vmovdqa	.LC2(%rip), %ymm3
	movq	24(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L331:
	movq	%rsi, %rax
	.p2align 4,,10
	.p2align 3
.L332:
	vmovdqu	(%rax), %ymm4
	addq	$32, %rax
	vpsrad	$31, %ymm4, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm4, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rdx, %rax
	jne	.L332
	addq	$1, %rcx
	addq	$1024, %rdx
	cmpq	%rcx, 8(%rdi)
	jbe	.L330
	addq	$1024, %rsi
	jmp	.L331
.L330:
	movq	64(%rsp), %rdi
	cmpq	$0, 8(%rdi)
	je	.L325
	movq	112(%rsp), %rdx
	vmovdqa	.LC21(%rip), %ymm2
	xorl	%ecx, %ecx
	vmovdqa	.LC2(%rip), %ymm3
	movq	80(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L335:
	movq	%rsi, %rax
	.p2align 4,,10
	.p2align 3
.L334:
	vmovdqu	(%rax), %ymm5
	addq	$32, %rax
	vpsrad	$31, %ymm5, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm5, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %rdx
	jne	.L334
	addq	$1, %rcx
	addq	$1024, %rdx
	cmpq	8(%rdi), %rcx
	jnb	.L325
	addq	$1024, %rsi
	jmp	.L335
.L325:
	movq	1848(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L352
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L352:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5719:
	.size	ossl_ml_dsa_expand_S_44, .-ossl_ml_dsa_expand_S_44
	.p2align 4
	.globl	ossl_ml_dsa_expand_S_65
	.type	ossl_ml_dsa_expand_S_65, @function
ossl_ml_dsa_expand_S_65:
.LFB5722:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	xorl	%r11d, %r11d
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	.cfi_offset 15, -24
	movl	$2, %r15d
	pushq	%r14
	pushq	%r13
	pushq	%r12
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	movl	$1, %r12d
	pushq	%rbx
	andq	$-32, %rsp
	subq	$1856, %rsp
	.cfi_offset 3, -56
	vmovdqu	(%rdx), %xmm3
	movq	(%rdi), %rbx
	vmovdqu	16(%rdx), %xmm2
	vmovdqu	32(%rdx), %xmm1
	movq	%rsi, 16(%rsp)
	leaq	1536(%rsp), %r14
	movq	%rdx, 56(%rsp)
	vmovdqu	48(%rdx), %xmm0
	leaq	1616(%rsp), %r13
	movq	%rdi, 24(%rsp)
	movq	%fs:40, %rax
	movq	%rax, 1848(%rsp)
	xorl	%eax, %eax
	movq	(%rsi), %rax
	movq	%rbx, 144(%rsp)
	movw	%r12w, 1680(%rsp)
	leaq	1696(%rsp), %r12
	movw	%r11w, 1600(%rsp)
	vmovdqa	%xmm3, 1536(%rsp)
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	movq	%rax, 152(%rsp)
	leaq	1776(%rsp), %rax
	movq	%r14, 48(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r12, 32(%rsp)
	movw	%r15w, 1760(%rsp)
	leaq	704(%rsp), %r15
	movq	%r15, %rdi
	movq	%rax, 64(%rsp)
	movl	$3, %eax
	vmovdqa	%xmm3, 1696(%rsp)
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movw	%ax, 1840(%rsp)
	movq	%r15, 88(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	64(%rsp), %r8
	movq	%r12, %rcx
	movq	%r13, %rdx
	movq	%r14, %rsi
	movq	%r15, %rdi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	leaq	568(%rsp), %r14
	leaq	160(%rsp), %rax
	movq	%r15, %r9
	leaq	432(%rsp), %r13
	movq	%rax, %rdi
	movq	%r14, %rcx
	movl	$136, %r8d
	leaq	296(%rsp), %r12
	movq	%r13, %rdx
	movq	%rax, 104(%rsp)
	movq	%r12, %rsi
	movq	%r14, 112(%rsp)
	movq	%r13, 96(%rsp)
	movq	%r12, 80(%rsp)
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	%r14, %rdx
	movq	%r15, %r9
	movq	%r15, %rcx
	movl	$136, %r8d
	movq	%r13, %rsi
	movq	%r12, %rdi
	movq	%rbx, %r15
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	104(%rsp), %rsi
	movq	%rbx, %rdi
	movq	%rbx, 8(%rsp)
	call	ml_dsa_rej_eta_avx_4
	movq	%r12, %rsi
	movl	%eax, %ebx
	leaq	1024(%r15), %rax
	movq	%rax, %rdi
	movq	%rax, 136(%rsp)
	call	ml_dsa_rej_eta_avx_4
	movq	%r13, %rsi
	movl	%eax, %r12d
	leaq	2048(%r15), %rax
	movq	%rax, %rdi
	movq	%rax, 128(%rsp)
	call	ml_dsa_rej_eta_avx_4
	movq	%r14, %rsi
	movl	%eax, %r13d
	leaq	3072(%r15), %rax
	movq	%rax, %rdi
	movq	%rax, 120(%rsp)
	call	ml_dsa_rej_eta_avx_4
	cmpl	$255, %ebx
	movl	%eax, %r14d
	setbe	%al
	cmpl	$255, %r12d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r13d
	setbe	%dl
	orb	%dl, %al
	jne	.L354
	cmpl	$255, %r14d
	ja	.L355
.L354:
	leaq	159(%rsp), %r11
	movl	$4, %r15d
	.p2align 4,,10
	.p2align 3
.L540:
	movq	96(%rsp), %rdx
	movq	104(%rsp), %rdi
	movl	$136, %r8d
	movq	%r11, 72(%rsp)
	movq	88(%rsp), %r9
	movq	112(%rsp), %rcx
	movq	80(%rsp), %rsi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	xorl	%edi, %edi
	cmpl	$255, %ebx
	movq	72(%rsp), %r11
	movl	$1, %edx
	ja	.L359
	.p2align 4,,10
	.p2align 3
.L360:
	movzbl	(%r11,%rdx), %eax
	movl	%eax, %ecx
	shrb	$4, %al
	andl	$15, %ecx
	movzbl	%al, %eax
	cmpb	$8, %cl
	ja	.L356
	movzbl	%cl, %ecx
	movl	%r15d, %edi
	movl	%ebx, %esi
	addl	$1, %ebx
	subl	%ecx, %edi
	movq	144(%rsp), %rcx
	movl	%edi, (%rcx,%rsi,4)
.L356:
	cmpl	$255, %ebx
	setbe	%dil
	cmpl	$8, %eax
	jg	.L357
	testb	%dil, %dil
	je	.L357
	movl	%r15d, %esi
	movl	%ebx, %ecx
	addl	$1, %ebx
	subl	%eax, %esi
	movq	144(%rsp), %rax
	cmpl	$255, %ebx
	setbe	%dil
	movl	%esi, (%rax,%rcx,4)
.L357:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%dil, %al
	jne	.L360
.L359:
	cmpl	$255, %r12d
	ja	.L436
	movl	$1, %edx
	leaq	295(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L365:
	movzbl	(%rsi,%rdx), %eax
	movl	%eax, %ecx
	shrb	$4, %al
	andl	$15, %ecx
	movzbl	%al, %eax
	cmpb	$8, %cl
	ja	.L362
	movzbl	%cl, %ecx
	movl	%r15d, %r9d
	movl	%r12d, %r8d
	addl	$1, %r12d
	subl	%ecx, %r9d
	movq	136(%rsp), %rcx
	movl	%r9d, (%rcx,%r8,4)
.L362:
	cmpl	$255, %r12d
	setbe	%cl
	cmpl	$8, %eax
	jg	.L363
	testb	%cl, %cl
	je	.L363
	movl	%r15d, %r8d
	movl	%r12d, %ecx
	addl	$1, %r12d
	subl	%eax, %r8d
	movq	136(%rsp), %rax
	cmpl	$255, %r12d
	movl	%r8d, (%rax,%rcx,4)
	setbe	%cl
.L363:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%cl, %al
	jne	.L365
	cmpl	$255, %r13d
	ja	.L437
.L599:
	movl	$1, %edx
	leaq	431(%rsp), %r9
	.p2align 4,,10
	.p2align 3
.L370:
	movzbl	(%r9,%rdx), %eax
	movl	%eax, %esi
	shrb	$4, %al
	andl	$15, %esi
	movzbl	%al, %eax
	cmpb	$8, %sil
	ja	.L367
	movzbl	%sil, %esi
	movl	%r15d, %r10d
	movl	%r13d, %r8d
	addl	$1, %r13d
	subl	%esi, %r10d
	movq	128(%rsp), %rsi
	movl	%r10d, (%rsi,%r8,4)
.L367:
	cmpl	$255, %r13d
	setbe	%r8b
	cmpl	$8, %eax
	jg	.L368
	testb	%r8b, %r8b
	je	.L368
	movl	%r15d, %r8d
	movl	%r13d, %esi
	addl	$1, %r13d
	subl	%eax, %r8d
	movq	128(%rsp), %rax
	cmpl	$255, %r13d
	movl	%r8d, (%rax,%rsi,4)
	setbe	%r8b
.L368:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%r8b, %al
	jne	.L370
.L366:
	cmpl	$255, %r14d
	ja	.L438
	movb	%cl, 72(%rsp)
	movl	$1, %edx
	leaq	567(%rsp), %r9
	movl	%edi, %r10d
	.p2align 4,,10
	.p2align 3
.L375:
	movzbl	(%r9,%rdx), %eax
	movl	%eax, %esi
	shrb	$4, %al
	andl	$15, %esi
	movzbl	%al, %eax
	cmpb	$8, %sil
	ja	.L372
	movzbl	%sil, %esi
	movl	%r15d, %ecx
	movl	%r14d, %edi
	addl	$1, %r14d
	subl	%esi, %ecx
	movq	120(%rsp), %rsi
	movl	%ecx, (%rsi,%rdi,4)
.L372:
	cmpl	$255, %r14d
	setbe	%sil
	cmpl	$8, %eax
	jg	.L373
	testb	%sil, %sil
	je	.L373
	movl	%r15d, %edi
	movl	%r14d, %esi
	addl	$1, %r14d
	subl	%eax, %edi
	movq	120(%rsp), %rax
	cmpl	$255, %r14d
	movl	%edi, (%rax,%rsi,4)
	setbe	%sil
.L373:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%sil, %al
	jne	.L375
	movzbl	72(%rsp), %ecx
	movl	%r10d, %edi
.L371:
	orl	%edi, %ecx
	orb	%r8b, %cl
	jne	.L540
	testb	%sil, %sil
	jne	.L540
.L355:
	movq	56(%rsp), %rax
	movq	88(%rsp), %rbx
	movl	$4, %edi
	movl	$7, %r10d
	movl	$5, %r8d
	movl	$6, %r9d
	movw	%di, 1600(%rsp)
	vmovdqu	(%rax), %xmm3
	vmovdqu	16(%rax), %xmm2
	movq	%rbx, %rdi
	movw	%r10w, 1840(%rsp)
	vmovdqu	32(%rax), %xmm1
	vmovdqu	48(%rax), %xmm0
	movw	%r8w, 1680(%rsp)
	vmovdqa	%xmm3, 1536(%rsp)
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	vmovdqa	%xmm3, 1696(%rsp)
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movw	%r9w, 1760(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	64(%rsp), %r8
	movq	32(%rsp), %rcx
	movq	%rbx, %rdi
	movq	40(%rsp), %rdx
	movq	48(%rsp), %rsi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	movq	112(%rsp), %r15
	movq	96(%rsp), %r13
	movq	%rbx, %r9
	movq	80(%rsp), %r14
	movq	104(%rsp), %r12
	movl	$136, %r8d
	movq	%r15, %rcx
	movq	%r13, %rdx
	movq	%r14, %rsi
	movq	%r12, %rdi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	%r15, %rdx
	movq	%rbx, %r9
	movq	%rbx, %rcx
	movl	$136, %r8d
	movq	%r13, %rsi
	movq	%r14, %rdi
	movq	%r15, 112(%rsp)
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	144(%rsp), %rax
	movq	%r12, %rsi
	addq	$4096, %rax
	movq	%rax, %rdi
	movq	%rax, 128(%rsp)
	call	ml_dsa_rej_eta_avx_4
	movq	152(%rsp), %r15
	movq	%r14, %rsi
	movl	%eax, %ebx
	movq	%r15, %rdi
	movq	%r15, (%rsp)
	call	ml_dsa_rej_eta_avx_4
	movq	%r13, %rsi
	movl	%eax, %r12d
	leaq	1024(%r15), %rax
	movq	%rax, %rdi
	movq	%rax, 144(%rsp)
	call	ml_dsa_rej_eta_avx_4
	movq	112(%rsp), %rsi
	movl	%eax, %r13d
	leaq	2048(%r15), %rax
	movq	%rax, %rdi
	movq	%rax, 120(%rsp)
	call	ml_dsa_rej_eta_avx_4
	cmpl	$255, %ebx
	movl	%eax, %r14d
	setbe	%al
	cmpl	$255, %r12d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r13d
	setbe	%dl
	orb	%dl, %al
	jne	.L377
	cmpl	$255, %r14d
	ja	.L378
.L377:
	leaq	159(%rsp), %r11
	movl	$4, %r15d
	.p2align 4,,10
	.p2align 3
.L541:
	movq	96(%rsp), %rdx
	movq	104(%rsp), %rdi
	movl	$136, %r8d
	movq	%r11, 72(%rsp)
	movq	88(%rsp), %r9
	movq	112(%rsp), %rcx
	movq	80(%rsp), %rsi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	xorl	%edi, %edi
	cmpl	$255, %ebx
	movq	72(%rsp), %r11
	movl	$1, %edx
	ja	.L382
	.p2align 4,,10
	.p2align 3
.L383:
	movzbl	(%r11,%rdx), %eax
	movl	%eax, %ecx
	shrb	$4, %al
	andl	$15, %ecx
	movzbl	%al, %eax
	cmpb	$8, %cl
	ja	.L379
	movzbl	%cl, %ecx
	movl	%r15d, %edi
	movl	%ebx, %esi
	addl	$1, %ebx
	subl	%ecx, %edi
	movq	128(%rsp), %rcx
	movl	%edi, (%rcx,%rsi,4)
.L379:
	cmpl	$255, %ebx
	setbe	%dil
	cmpl	$8, %eax
	jg	.L380
	testb	%dil, %dil
	je	.L380
	movl	%r15d, %esi
	movl	%ebx, %ecx
	addl	$1, %ebx
	subl	%eax, %esi
	movq	128(%rsp), %rax
	cmpl	$255, %ebx
	setbe	%dil
	movl	%esi, (%rax,%rcx,4)
.L380:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%dil, %al
	jne	.L383
.L382:
	cmpl	$255, %r12d
	ja	.L440
	movl	$1, %edx
	leaq	295(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L388:
	movzbl	(%rsi,%rdx), %eax
	movl	%eax, %ecx
	shrb	$4, %al
	andl	$15, %ecx
	movzbl	%al, %eax
	cmpb	$8, %cl
	ja	.L385
	movzbl	%cl, %ecx
	movl	%r15d, %r9d
	movl	%r12d, %r8d
	addl	$1, %r12d
	subl	%ecx, %r9d
	movq	152(%rsp), %rcx
	movl	%r9d, (%rcx,%r8,4)
.L385:
	cmpl	$255, %r12d
	setbe	%cl
	cmpl	$8, %eax
	jg	.L386
	testb	%cl, %cl
	je	.L386
	movl	%r15d, %r8d
	movl	%r12d, %ecx
	addl	$1, %r12d
	subl	%eax, %r8d
	movq	152(%rsp), %rax
	cmpl	$255, %r12d
	movl	%r8d, (%rax,%rcx,4)
	setbe	%cl
.L386:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%cl, %al
	jne	.L388
	cmpl	$255, %r13d
	ja	.L441
.L598:
	movl	$1, %edx
	leaq	431(%rsp), %r9
	.p2align 4,,10
	.p2align 3
.L393:
	movzbl	(%r9,%rdx), %eax
	movl	%eax, %esi
	shrb	$4, %al
	andl	$15, %esi
	movzbl	%al, %eax
	cmpb	$8, %sil
	ja	.L390
	movzbl	%sil, %esi
	movl	%r15d, %r10d
	movl	%r13d, %r8d
	addl	$1, %r13d
	subl	%esi, %r10d
	movq	144(%rsp), %rsi
	movl	%r10d, (%rsi,%r8,4)
.L390:
	cmpl	$255, %r13d
	setbe	%r8b
	cmpl	$8, %eax
	jg	.L391
	testb	%r8b, %r8b
	je	.L391
	movl	%r15d, %r8d
	movl	%r13d, %esi
	addl	$1, %r13d
	subl	%eax, %r8d
	movq	144(%rsp), %rax
	cmpl	$255, %r13d
	movl	%r8d, (%rax,%rsi,4)
	setbe	%r8b
.L391:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%r8b, %al
	jne	.L393
.L389:
	cmpl	$255, %r14d
	ja	.L442
	movb	%cl, 72(%rsp)
	movl	$1, %edx
	leaq	567(%rsp), %r9
	movl	%edi, %r10d
	.p2align 4,,10
	.p2align 3
.L398:
	movzbl	(%r9,%rdx), %eax
	movl	%eax, %esi
	shrb	$4, %al
	andl	$15, %esi
	movzbl	%al, %eax
	cmpb	$8, %sil
	ja	.L395
	movzbl	%sil, %esi
	movl	%r15d, %ecx
	movl	%r14d, %edi
	addl	$1, %r14d
	subl	%esi, %ecx
	movq	120(%rsp), %rsi
	movl	%ecx, (%rsi,%rdi,4)
.L395:
	cmpl	$255, %r14d
	setbe	%sil
	cmpl	$8, %eax
	jg	.L396
	testb	%sil, %sil
	je	.L396
	movl	%r15d, %edi
	movl	%r14d, %esi
	addl	$1, %r14d
	subl	%eax, %edi
	movq	120(%rsp), %rax
	cmpl	$255, %r14d
	movl	%edi, (%rax,%rsi,4)
	setbe	%sil
.L396:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%sil, %al
	jne	.L398
	movzbl	72(%rsp), %ecx
	movl	%r10d, %edi
.L394:
	orl	%edi, %ecx
	orb	%r8b, %cl
	jne	.L541
	testb	%sil, %sil
	jne	.L541
.L378:
	movq	56(%rsp), %rax
	movq	88(%rsp), %rbx
	movl	$9, %edx
	movl	$10, %ecx
	movl	$11, %esi
	movw	%dx, 1680(%rsp)
	vmovdqu	(%rax), %xmm3
	vmovdqu	16(%rax), %xmm2
	movq	%rbx, %rdi
	movw	%cx, 1760(%rsp)
	vmovdqu	32(%rax), %xmm1
	vmovdqu	48(%rax), %xmm0
	movl	$8, %eax
	movw	%si, 1840(%rsp)
	vmovdqa	%xmm3, 1536(%rsp)
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	vmovdqa	%xmm3, 1696(%rsp)
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movw	%ax, 1600(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	64(%rsp), %r8
	movq	32(%rsp), %rcx
	movq	%rbx, %rdi
	movq	40(%rsp), %rdx
	movq	48(%rsp), %rsi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	movq	96(%rsp), %r12
	movq	112(%rsp), %r14
	movq	%rbx, %r9
	movq	80(%rsp), %r13
	movq	104(%rsp), %r15
	movl	$136, %r8d
	movq	%r14, %rcx
	movq	%r12, %rdx
	movq	%r15, %rdi
	movq	%r13, %rsi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	%r14, %rdx
	movq	%rbx, %r9
	movq	%rbx, %rcx
	movl	$136, %r8d
	movq	%r12, %rsi
	movq	%r13, %rdi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	152(%rsp), %rbx
	movq	%r15, %rsi
	leaq	3072(%rbx), %rax
	leaq	4096(%rbx), %r14
	movq	%rbx, %r15
	movq	%rax, %rdi
	movq	%rax, 152(%rsp)
	call	ml_dsa_rej_eta_avx_4
	movq	%r13, %rsi
	movq	%r14, %rdi
	movl	%eax, 128(%rsp)
	call	ml_dsa_rej_eta_avx_4
	leaq	5120(%r15), %r11
	movq	%r12, %rsi
	movq	%r11, %rdi
	movq	%r11, 120(%rsp)
	movl	%eax, %ebx
	call	ml_dsa_rej_eta_avx_4
	movq	120(%rsp), %r11
	cmpl	$255, 128(%rsp)
	movl	%eax, %r12d
	setbe	%al
	cmpl	$255, %ebx
	setbe	%dl
	orb	%dl, %al
	jne	.L400
	cmpl	$255, %r12d
	ja	.L418
.L400:
	leaq	159(%rsp), %r10
	movl	$4, %r15d
	.p2align 4,,10
	.p2align 3
.L585:
	movq	96(%rsp), %rdx
	movq	104(%rsp), %rdi
	movl	$136, %r8d
	movq	%r10, 72(%rsp)
	movq	88(%rsp), %r9
	movq	112(%rsp), %rcx
	movq	%r11, 120(%rsp)
	movq	80(%rsp), %rsi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movl	128(%rsp), %eax
	xorl	%edi, %edi
	movq	120(%rsp), %r11
	movq	72(%rsp), %r10
	movl	$1, %edx
	cmpl	$255, %eax
	movl	%eax, %r13d
	ja	.L406
	.p2align 4,,10
	.p2align 3
.L407:
	movzbl	(%r10,%rdx), %eax
	movl	%eax, %ecx
	shrb	$4, %al
	andl	$15, %ecx
	movzbl	%al, %eax
	cmpb	$8, %cl
	ja	.L403
	movzbl	%cl, %ecx
	movl	%r15d, %edi
	movl	%r13d, %esi
	addl	$1, %r13d
	subl	%ecx, %edi
	movq	152(%rsp), %rcx
	movl	%edi, (%rcx,%rsi,4)
.L403:
	cmpl	$255, %r13d
	setbe	%dil
	cmpl	$8, %eax
	jg	.L404
	testb	%dil, %dil
	je	.L404
	movl	%r15d, %esi
	movl	%r13d, %ecx
	addl	$1, %r13d
	subl	%eax, %esi
	movq	152(%rsp), %rax
	cmpl	$255, %r13d
	setbe	%dil
	movl	%esi, (%rax,%rcx,4)
.L404:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%dil, %al
	jne	.L407
.L406:
	cmpl	$255, %ebx
	ja	.L444
	movl	$1, %edx
	leaq	295(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L412:
	movzbl	(%rsi,%rdx), %eax
	movl	%eax, %ecx
	shrb	$4, %al
	andl	$15, %ecx
	movzbl	%al, %eax
	cmpb	$8, %cl
	ja	.L409
	movzbl	%cl, %ecx
	movl	%r15d, %r9d
	movl	%ebx, %r8d
	addl	$1, %ebx
	subl	%ecx, %r9d
	movl	%r9d, (%r14,%r8,4)
.L409:
	cmpl	$255, %ebx
	setbe	%cl
	cmpl	$8, %eax
	jg	.L410
	testb	%cl, %cl
	je	.L410
	movl	%ebx, %ecx
	movl	%r15d, %r8d
	addl	$1, %ebx
	subl	%eax, %r8d
	cmpl	$255, %ebx
	movl	%r8d, (%r14,%rcx,4)
	setbe	%cl
.L410:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%cl, %al
	jne	.L412
	cmpl	$255, %r12d
	ja	.L445
.L600:
	movb	%cl, 120(%rsp)
	movl	$1, %edx
	leaq	431(%rsp), %r8
	.p2align 4,,10
	.p2align 3
.L417:
	movzbl	(%r8,%rdx), %eax
	movl	%eax, %esi
	shrb	$4, %al
	andl	$15, %esi
	movzbl	%al, %eax
	cmpb	$8, %sil
	ja	.L414
	movzbl	%sil, %esi
	movl	%r15d, %ecx
	movl	%r12d, %r9d
	addl	$1, %r12d
	subl	%esi, %ecx
	movl	%ecx, (%r11,%r9,4)
.L414:
	cmpl	$255, %r12d
	setbe	%sil
	cmpl	$8, %eax
	jg	.L415
	testb	%sil, %sil
	je	.L415
	movl	%r12d, %esi
	movl	%r15d, %r9d
	addl	$1, %r12d
	subl	%eax, %r9d
	cmpl	$255, %r12d
	movl	%r9d, (%r11,%rsi,4)
	setbe	%sil
.L415:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%sil, %al
	jne	.L417
	movzbl	120(%rsp), %ecx
.L413:
	orb	%dil, %cl
	jne	.L450
	testb	%sil, %sil
	je	.L418
.L450:
	cmpl	$255, 128(%rsp)
	ja	.L597
	movl	%r13d, 128(%rsp)
	jmp	.L585
	.p2align 4,,10
	.p2align 3
.L597:
	movl	%r13d, %eax
	movl	$4, %r15d
	movq	%r11, %r13
	leaq	295(%rsp), %r10
	movl	%eax, %r11d
.L542:
	movq	88(%rsp), %r9
	movq	112(%rsp), %rcx
	movl	$136, %r8d
	movq	%r10, 128(%rsp)
	movq	96(%rsp), %rdx
	movq	80(%rsp), %rsi
	movl	%r11d, 152(%rsp)
	movq	104(%rsp), %rdi
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movl	152(%rsp), %r11d
	movq	128(%rsp), %r10
	cmpl	$255, %r11d
	setbe	152(%rsp)
	cmpl	$255, %ebx
	ja	.L447
	movl	$1, %edx
	.p2align 4,,10
	.p2align 3
.L424:
	movzbl	(%r10,%rdx), %eax
	movl	%eax, %ecx
	shrb	$4, %al
	andl	$15, %ecx
	movzbl	%al, %eax
	cmpb	$8, %cl
	ja	.L421
	movzbl	%cl, %ecx
	movl	%r15d, %edi
	movl	%ebx, %esi
	addl	$1, %ebx
	subl	%ecx, %edi
	movl	%edi, (%r14,%rsi,4)
.L421:
	cmpl	$255, %ebx
	setbe	%cl
	cmpl	$8, %eax
	jg	.L422
	testb	%cl, %cl
	je	.L422
	movl	%ebx, %ecx
	movl	%r15d, %esi
	addl	$1, %ebx
	subl	%eax, %esi
	cmpl	$255, %ebx
	movl	%esi, (%r14,%rcx,4)
	setbe	%cl
.L422:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%cl, %al
	jne	.L424
.L420:
	cmpl	$255, %r12d
	ja	.L448
	movl	$1, %edx
	leaq	431(%rsp), %rdi
	.p2align 4,,10
	.p2align 3
.L429:
	movzbl	(%rdi,%rdx), %eax
	movl	%eax, %esi
	shrb	$4, %al
	andl	$15, %esi
	movzbl	%al, %eax
	cmpb	$8, %sil
	ja	.L426
	movzbl	%sil, %esi
	movl	%r15d, %r9d
	movl	%r12d, %r8d
	addl	$1, %r12d
	subl	%esi, %r9d
	movl	%r9d, 0(%r13,%r8,4)
.L426:
	cmpl	$255, %r12d
	setbe	%sil
	cmpl	$8, %eax
	jg	.L427
	testb	%sil, %sil
	je	.L427
	movl	%r12d, %esi
	movl	%r15d, %r8d
	addl	$1, %r12d
	subl	%eax, %r8d
	cmpl	$255, %r12d
	movl	%r8d, 0(%r13,%rsi,4)
	setbe	%sil
.L427:
	cmpl	$135, %edx
	setle	%al
	addq	$1, %rdx
	testb	%sil, %al
	jne	.L429
.L425:
	orb	152(%rsp), %cl
	jne	.L542
	testb	%sil, %sil
	jne	.L542
.L418:
	movq	24(%rsp), %rdi
	cmpq	$0, 8(%rdi)
	je	.L401
	movq	136(%rsp), %rdx
	vmovdqa	.LC21(%rip), %ymm2
	xorl	%ecx, %ecx
	vmovdqa	.LC2(%rip), %ymm3
	movq	8(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L402:
	movq	%rsi, %rax
	.p2align 4,,10
	.p2align 3
.L431:
	vmovdqu	(%rax), %ymm4
	addq	$32, %rax
	vpsrad	$31, %ymm4, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm4, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %rdx
	jne	.L431
	addq	$1, %rcx
	addq	$1024, %rdx
	cmpq	%rcx, 8(%rdi)
	jbe	.L401
	addq	$1024, %rsi
	jmp	.L402
	.p2align 4,,10
	.p2align 3
.L442:
	xorl	%esi, %esi
	jmp	.L394
	.p2align 4,,10
	.p2align 3
.L440:
	xorl	%ecx, %ecx
	cmpl	$255, %r13d
	jbe	.L598
	.p2align 4,,10
	.p2align 3
.L441:
	xorl	%r8d, %r8d
	jmp	.L389
	.p2align 4,,10
	.p2align 3
.L438:
	xorl	%esi, %esi
	jmp	.L371
	.p2align 4,,10
	.p2align 3
.L436:
	xorl	%ecx, %ecx
	cmpl	$255, %r13d
	jbe	.L599
	.p2align 4,,10
	.p2align 3
.L437:
	xorl	%r8d, %r8d
	jmp	.L366
.L448:
	xorl	%esi, %esi
	jmp	.L425
.L447:
	xorl	%ecx, %ecx
	jmp	.L420
.L444:
	xorl	%ecx, %ecx
	cmpl	$255, %r12d
	jbe	.L600
.L445:
	xorl	%esi, %esi
	jmp	.L413
.L401:
	movq	16(%rsp), %rdi
	cmpq	$0, 8(%rdi)
	je	.L353
	movq	144(%rsp), %rdx
	vmovdqa	.LC21(%rip), %ymm2
	xorl	%ecx, %ecx
	vmovdqa	.LC2(%rip), %ymm3
	movq	(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L434:
	movq	%rsi, %rax
	.p2align 4,,10
	.p2align 3
.L433:
	vmovdqu	(%rax), %ymm5
	addq	$32, %rax
	vpsrad	$31, %ymm5, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm5, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %rdx
	jne	.L433
	addq	$1, %rcx
	addq	$1024, %rdx
	cmpq	%rcx, 8(%rdi)
	jbe	.L353
	addq	$1024, %rsi
	jmp	.L434
.L353:
	movq	1848(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L601
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L601:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5722:
	.size	ossl_ml_dsa_expand_S_65, .-ossl_ml_dsa_expand_S_65
	.p2align 4
	.globl	ossl_ml_dsa_expand_S_87
	.type	ossl_ml_dsa_expand_S_87, @function
ossl_ml_dsa_expand_S_87:
.LFB5723:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	.cfi_offset 15, -24
	xorl	%r15d, %r15d
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$1856, %rsp
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	vmovdqu	16(%rdx), %xmm2
	vmovdqu	32(%rdx), %xmm1
	movq	%rsi, 32(%rsp)
	leaq	1536(%rsp), %rbx
	movq	(%rdi), %r14
	leaq	1696(%rsp), %r13
	vmovdqu	48(%rdx), %xmm0
	vmovdqu	(%rdx), %xmm3
	movq	%rdx, 72(%rsp)
	leaq	704(%rsp), %r12
	movq	%rdi, 40(%rsp)
	movq	%r12, %rdi
	movq	%fs:40, %rax
	movq	%rax, 1848(%rsp)
	xorl	%eax, %eax
	movq	(%rsi), %rax
	movq	%rbx, 56(%rsp)
	movw	%r15w, 1600(%rsp)
	leaq	1616(%rsp), %r15
	movq	%rax, 120(%rsp)
	movl	$1, %eax
	movw	%ax, 1680(%rsp)
	movl	$2, %eax
	vmovdqa	%xmm3, 1536(%rsp)
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	movq	%r15, 48(%rsp)
	movq	%r13, 64(%rsp)
	vmovdqa	%xmm3, 1696(%rsp)
	movw	%ax, 1760(%rsp)
	leaq	1776(%rsp), %rax
	movq	%rax, 80(%rsp)
	movl	$3, %eax
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movw	%ax, 1840(%rsp)
	movq	%r12, 128(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	80(%rsp), %r8
	movq	%r13, %rcx
	movq	%r15, %rdx
	movq	%rbx, %rsi
	movq	%r12, %rdi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	leaq	160(%rsp), %r15
	leaq	568(%rsp), %rax
	movq	%r12, %r9
	leaq	432(%rsp), %rdi
	leaq	296(%rsp), %rbx
	movq	%rax, %rcx
	movl	$136, %r8d
	movq	%rdi, %rdx
	movq	%rdi, 152(%rsp)
	movq	%rbx, %rsi
	movq	%r15, %rdi
	movq	%rax, 144(%rsp)
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	%r14, %rdi
	movq	%r15, %rsi
	movq	%r14, 24(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	%rbx, %rsi
	movl	%eax, %r12d
	leaq	1024(%r14), %rax
	movq	%rax, %rdi
	movq	%rax, 104(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	152(%rsp), %rsi
	movq	%r14, 112(%rsp)
	leaq	2048(%r14), %rdi
	movq	%rdi, 96(%rsp)
	movl	%eax, %r13d
	call	ml_dsa_rej_eta_avx_2
	movq	144(%rsp), %rsi
	movl	%eax, %r14d
	movq	112(%rsp), %rax
	addq	$3072, %rax
	movq	%rax, %rdi
	movq	%rax, 88(%rsp)
	call	ml_dsa_rej_eta_avx_2
	cmpl	$255, %r12d
	movl	%eax, %r10d
	setbe	%al
	cmpl	$255, %r13d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r14d
	setbe	%dl
	orb	%dl, %al
	jne	.L629
	cmpl	$255, %r10d
	ja	.L606
.L629:
	movq	%rbx, %r11
	movq	%r15, %rbx
	movl	%r10d, %r15d
	.p2align 4,,10
	.p2align 3
.L624:
	movq	128(%rsp), %r9
	movq	%r11, %rsi
	movl	$136, %r8d
	movq	%rbx, %rdi
	movq	144(%rsp), %rcx
	movq	152(%rsp), %rdx
	movq	%r11, 136(%rsp)
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	112(%rsp), %rdi
	movl	%r12d, %esi
	movq	%rbx, %rdx
	call	rej_eta_2
	movq	136(%rsp), %rdx
	movq	104(%rsp), %rdi
	movl	%r13d, %esi
	movl	%eax, %r12d
	call	rej_eta_2
	movq	152(%rsp), %rdx
	movq	96(%rsp), %rdi
	movl	%r14d, %esi
	movl	%eax, %r13d
	call	rej_eta_2
	movq	144(%rsp), %rdx
	movq	88(%rsp), %rdi
	movl	%r15d, %esi
	movl	%eax, %r14d
	call	rej_eta_2
	cmpl	$255, %r12d
	movq	136(%rsp), %r11
	movl	%eax, %r15d
	setbe	%al
	cmpl	$255, %r13d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r14d
	setbe	%dl
	orb	%dl, %al
	jne	.L624
	cmpl	$255, %r15d
	jbe	.L624
	movq	%rbx, %r15
	movq	%r11, %rbx
.L606:
	movq	72(%rsp), %rax
	movl	$7, %r14d
	movl	$4, %r11d
	movl	$5, %r12d
	movw	%r14w, 1840(%rsp)
	movl	$6, %r13d
	movq	128(%rsp), %r14
	vmovdqu	(%rax), %xmm3
	vmovdqu	16(%rax), %xmm2
	movw	%r11w, 1600(%rsp)
	vmovdqu	32(%rax), %xmm1
	vmovdqu	48(%rax), %xmm0
	movq	%r14, %rdi
	movw	%r12w, 1680(%rsp)
	vmovdqa	%xmm3, 1536(%rsp)
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	vmovdqa	%xmm3, 1696(%rsp)
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movw	%r13w, 1760(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	80(%rsp), %r8
	movq	64(%rsp), %rcx
	movq	%r14, %rdi
	movq	48(%rsp), %rdx
	movq	56(%rsp), %rsi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	movq	%r14, %r9
	movq	%rbx, %rsi
	movq	%r15, %rdi
	movq	152(%rsp), %rdx
	movq	144(%rsp), %rcx
	movl	$136, %r8d
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	112(%rsp), %r14
	movq	%r15, %rsi
	leaq	4096(%r14), %rax
	movq	%rax, %rdi
	movq	%rax, 136(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	%rbx, %rsi
	movl	%eax, %r12d
	leaq	5120(%r14), %rax
	movq	%rax, %rdi
	movq	%rax, 112(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	152(%rsp), %rsi
	movl	%eax, %r13d
	leaq	6144(%r14), %rax
	movq	%rax, %rdi
	movq	%rax, 96(%rsp)
	call	ml_dsa_rej_eta_avx_2
	cmpl	$255, %r12d
	movl	%eax, %r14d
	setbe	%al
	cmpl	$255, %r13d
	setbe	%dl
	orb	%dl, %al
	je	.L639
	.p2align 4,,10
	.p2align 3
.L625:
	movq	128(%rsp), %r9
	movl	$136, %r8d
	movq	%rbx, %rsi
	movq	%r15, %rdi
	movq	144(%rsp), %rcx
	movq	152(%rsp), %rdx
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	136(%rsp), %rdi
	movl	%r12d, %esi
	movq	%r15, %rdx
	call	rej_eta_2
	movq	112(%rsp), %rdi
	movl	%r13d, %esi
	movq	%rbx, %rdx
	movl	%eax, %r12d
	call	rej_eta_2
	movq	152(%rsp), %rdx
	movq	96(%rsp), %rdi
	movl	%r14d, %esi
	movl	%eax, %r13d
	call	rej_eta_2
	cmpl	$255, %r13d
	movl	%eax, %r14d
	setbe	%al
	cmpl	$255, %r12d
	setbe	%dl
	orb	%dl, %al
	jne	.L625
.L639:
	cmpl	$255, %r14d
	jbe	.L625
	movq	72(%rsp), %rax
	movq	128(%rsp), %r14
	movl	$7, %edi
	movl	$10, %r10d
	movl	$8, %r8d
	movl	$9, %r9d
	movw	%di, 1600(%rsp)
	vmovdqu	(%rax), %xmm3
	vmovdqu	16(%rax), %xmm2
	movq	%r14, %rdi
	movw	%r10w, 1840(%rsp)
	vmovdqu	32(%rax), %xmm1
	vmovdqu	48(%rax), %xmm0
	movw	%r8w, 1680(%rsp)
	vmovdqa	%xmm3, 1536(%rsp)
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	vmovdqa	%xmm3, 1696(%rsp)
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movw	%r9w, 1760(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	80(%rsp), %r8
	movq	64(%rsp), %rcx
	movq	%r14, %rdi
	movq	48(%rsp), %rdx
	movq	56(%rsp), %rsi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	movq	%r14, %r9
	movq	%rbx, %rsi
	movq	%r15, %rdi
	movq	144(%rsp), %rcx
	movq	152(%rsp), %rdx
	movl	$136, %r8d
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	120(%rsp), %r14
	movq	%r15, %rsi
	movq	%r14, %rdi
	movq	%r14, 16(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	%rbx, %rsi
	movl	%eax, %r12d
	leaq	1024(%r14), %rax
	movq	%rax, %rdi
	movq	%rax, 112(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	152(%rsp), %rsi
	movq	%r14, 120(%rsp)
	leaq	2048(%r14), %rdi
	movq	%rdi, 96(%rsp)
	movl	%eax, %r13d
	call	ml_dsa_rej_eta_avx_2
	movq	144(%rsp), %rsi
	movl	%eax, %r14d
	movq	120(%rsp), %rax
	addq	$3072, %rax
	movq	%rax, %rdi
	movq	%rax, 88(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movl	%eax, 136(%rsp)
	movl	%eax, %ecx
	jmp	.L642
	.p2align 4,,10
	.p2align 3
.L626:
	movq	144(%rsp), %rcx
	movl	$136, %r8d
	movq	%rbx, %rsi
	movq	%r15, %rdi
	movq	128(%rsp), %r9
	movq	152(%rsp), %rdx
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	120(%rsp), %rdi
	movl	%r12d, %esi
	movq	%r15, %rdx
	call	rej_eta_2
	movq	112(%rsp), %rdi
	movl	%r13d, %esi
	movq	%rbx, %rdx
	addl	%eax, %r12d
	call	rej_eta_2
	movq	152(%rsp), %rdx
	movq	96(%rsp), %rdi
	movl	%r14d, %esi
	addl	%eax, %r13d
	call	rej_eta_2
	movq	144(%rsp), %rdx
	movq	88(%rsp), %rdi
	movl	136(%rsp), %esi
	addl	%eax, %r14d
	call	rej_eta_2
	addl	%eax, 136(%rsp)
	movl	136(%rsp), %ecx
.L642:
	cmpl	$255, %r12d
	setbe	%al
	cmpl	$255, %r13d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r14d
	setbe	%dl
	orb	%dl, %al
	jne	.L626
	cmpl	$255, %ecx
	jbe	.L626
	movq	72(%rsp), %rax
	movl	$12, %edx
	movl	$13, %ecx
	movq	128(%rsp), %r14
	movl	$14, %esi
	movw	%dx, 1680(%rsp)
	vmovdqu	(%rax), %xmm3
	vmovdqu	16(%rax), %xmm2
	movq	%r14, %rdi
	movw	%cx, 1760(%rsp)
	vmovdqu	32(%rax), %xmm1
	vmovdqu	48(%rax), %xmm0
	movl	$11, %eax
	movw	%si, 1840(%rsp)
	vmovdqa	%xmm3, 1536(%rsp)
	vmovdqa	%xmm2, 1552(%rsp)
	vmovdqa	%xmm1, 1568(%rsp)
	vmovdqa	%xmm0, 1584(%rsp)
	vmovdqa	%xmm3, 1616(%rsp)
	vmovdqa	%xmm2, 1632(%rsp)
	vmovdqa	%xmm1, 1648(%rsp)
	vmovdqa	%xmm0, 1664(%rsp)
	vmovdqa	%xmm3, 1696(%rsp)
	vmovdqa	%xmm2, 1712(%rsp)
	vmovdqa	%xmm1, 1728(%rsp)
	vmovdqa	%xmm0, 1744(%rsp)
	vmovdqa	%xmm3, 1776(%rsp)
	vmovdqa	%xmm2, 1792(%rsp)
	vmovdqa	%xmm1, 1808(%rsp)
	vmovdqa	%xmm0, 1824(%rsp)
	movw	%ax, 1600(%rsp)
	call	ossl_sha3_shake256_x4_inc_init_avx2@PLT
	movq	80(%rsp), %r8
	movq	64(%rsp), %rcx
	movq	%r14, %rdi
	movq	48(%rsp), %rdx
	movq	56(%rsp), %rsi
	movl	$66, %r9d
	call	ossl_sha3_shake256_x4_inc_absorb_avx2@PLT
	movq	%r14, %r9
	movq	%rbx, %rsi
	movq	%r15, %rdi
	movq	144(%rsp), %rcx
	movq	152(%rsp), %rdx
	movl	$136, %r8d
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	120(%rsp), %r14
	movq	%r15, %rsi
	leaq	4096(%r14), %rax
	movq	%rax, %rdi
	movq	%rax, 96(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	%rbx, %rsi
	movl	%eax, %r12d
	leaq	5120(%r14), %rax
	movq	%rax, %rdi
	movq	%rax, 88(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movq	152(%rsp), %rsi
	movq	%r14, 120(%rsp)
	leaq	6144(%r14), %rdi
	movq	%rdi, 80(%rsp)
	movl	%eax, %r13d
	call	ml_dsa_rej_eta_avx_2
	movq	144(%rsp), %rsi
	movl	%eax, %r14d
	movq	120(%rsp), %rax
	addq	$7168, %rax
	movq	%rax, %rdi
	movq	%rax, 120(%rsp)
	call	ml_dsa_rej_eta_avx_2
	movl	%eax, 136(%rsp)
	movl	%eax, %ecx
	jmp	.L645
	.p2align 4,,10
	.p2align 3
.L627:
	movq	144(%rsp), %rcx
	movl	$136, %r8d
	movq	%rbx, %rsi
	movq	%r15, %rdi
	movq	128(%rsp), %r9
	movq	152(%rsp), %rdx
	call	ossl_sha3_shake256_x4_inc_squeeze_avx2@PLT
	movq	96(%rsp), %rdi
	movl	%r12d, %esi
	movq	%r15, %rdx
	call	rej_eta_2
	movq	88(%rsp), %rdi
	movl	%r13d, %esi
	movq	%rbx, %rdx
	addl	%eax, %r12d
	call	rej_eta_2
	movq	152(%rsp), %rdx
	movq	80(%rsp), %rdi
	movl	%r14d, %esi
	addl	%eax, %r13d
	call	rej_eta_2
	movq	144(%rsp), %rdx
	movq	120(%rsp), %rdi
	movl	136(%rsp), %esi
	addl	%eax, %r14d
	call	rej_eta_2
	addl	%eax, 136(%rsp)
	movl	136(%rsp), %ecx
.L645:
	cmpl	$255, %r13d
	setbe	%al
	cmpl	$255, %r12d
	setbe	%dl
	orl	%edx, %eax
	cmpl	$255, %r14d
	setbe	%dl
	orb	%dl, %al
	jne	.L627
	cmpl	$255, %ecx
	jbe	.L627
	movq	40(%rsp), %rdi
	cmpq	$0, 8(%rdi)
	je	.L611
	movq	104(%rsp), %rdx
	vmovdqa	.LC21(%rip), %ymm2
	xorl	%ecx, %ecx
	vmovdqa	.LC2(%rip), %ymm3
	movq	24(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L612:
	movq	%rsi, %rax
	.p2align 4,,10
	.p2align 3
.L613:
	vmovdqu	(%rax), %ymm4
	addq	$32, %rax
	vpsrad	$31, %ymm4, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm4, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %rdx
	jne	.L613
	addq	$1, %rcx
	addq	$1024, %rdx
	cmpq	%rcx, 8(%rdi)
	jbe	.L611
	addq	$1024, %rsi
	jmp	.L612
.L611:
	movq	32(%rsp), %rdi
	cmpq	$0, 8(%rdi)
	je	.L602
	movq	112(%rsp), %rdx
	vmovdqa	.LC21(%rip), %ymm2
	xorl	%ecx, %ecx
	vmovdqa	.LC2(%rip), %ymm3
	movq	16(%rsp), %rsi
	.p2align 4,,10
	.p2align 3
.L616:
	movq	%rsi, %rax
	.p2align 4,,10
	.p2align 3
.L615:
	vmovdqu	(%rax), %ymm5
	addq	$32, %rax
	vpsrad	$31, %ymm5, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm5, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rax, %rdx
	jne	.L615
	addq	$1, %rcx
	addq	$1024, %rdx
	cmpq	8(%rdi), %rcx
	jnb	.L602
	addq	$1024, %rsi
	jmp	.L616
.L602:
	movq	1848(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L646
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L646:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5723:
	.size	ossl_ml_dsa_expand_S_87, .-ossl_ml_dsa_expand_S_87
	.p2align 4
	.globl	ossl_ml_dsa_expand_mask_avx2
	.type	ossl_ml_dsa_expand_mask_avx2, @function
ossl_ml_dsa_expand_mask_avx2:
.LFB5727:
	.cfi_startproc
	endbr64
	leaq	8(%rsp), %r10
	.cfi_def_cfa 10, 0
	andq	$-32, %rsp
	movq	%rsi, %r9
	pushq	-8(%r10)
	pushq	%rbp
	movq	%rsp, %rbp
	.cfi_escape 0x10,0x6,0x2,0x76,0
	pushq	%r15
	.cfi_escape 0x10,0xf,0x2,0x76,0x78
	movl	%ecx, %r15d
	leal	3(%rdx), %ecx
	pushq	%r14
	movzwl	%cx, %ecx
	pushq	%r13
	.cfi_escape 0x10,0xe,0x2,0x76,0x70
	.cfi_escape 0x10,0xd,0x2,0x76,0x68
	movq	%rdi, %r13
	pushq	%r12
	pushq	%r10
	.cfi_escape 0xf,0x3,0x76,0x58,0x6
	.cfi_escape 0x10,0xc,0x2,0x76,0x60
	movl	%edx, %r10d
	addl	$2, %edx
	pushq	%rbx
	movzwl	%dx, %edx
	movzwl	%r10w, %r8d
	subq	$3136, %rsp
	.cfi_escape 0x10,0x3,0x2,0x76,0x50
	movq	(%rdi), %r12
	movq	8(%rdi), %rdi
	movq	%fs:40, %rax
	movq	%rax, -56(%rbp)
	xorl	%eax, %eax
	leal	1(%r10), %eax
	movzwl	%ax, %eax
	leaq	3072(%r12), %rsi
	leaq	2048(%r12), %r11
	leaq	1024(%r12), %rbx
	cmpq	$4, %rdi
	je	.L660
	leal	7(%r10), %r14d
	movzwl	%r14w, %r14d
	movl	%r14d, -3140(%rbp)
	leal	6(%r10), %r14d
	movzwl	%r14w, %r14d
	movl	%r14d, -3144(%rbp)
	leal	5(%r10), %r14d
	addl	$4, %r10d
	movzwl	%r10w, %r10d
	movzwl	%r14w, %r14d
	movl	%r10d, -3148(%rbp)
	leaq	4096(%r12), %r10
	movq	%r10, -3168(%rbp)
	cmpq	$5, %rdi
	je	.L661
	pushq	%rcx
	movq	%r12, %rdi
	movq	%rsi, %rcx
	movq	%rbx, %rsi
	pushq	%rdx
	movq	%r11, %rdx
	pushq	%rax
	pushq	%r8
	movl	%r15d, %r8d
	movq	%r9, -3160(%rbp)
	call	ml_dsa_poly_generate_gamma1_4x
	addq	$32, %rsp
	leaq	-3136(%rbp), %rcx
	leaq	6144(%r12), %rdx
	leaq	5120(%r12), %rsi
.L659:
	movl	-3140(%rbp), %eax
	movq	-3160(%rbp), %r9
	movl	%r15d, %r8d
	movq	-3168(%rbp), %rdi
	pushq	%rax
	movl	-3144(%rbp), %eax
	pushq	%rax
	movl	-3148(%rbp), %eax
	pushq	%r14
	pushq	%rax
	call	ml_dsa_poly_generate_gamma1_4x
	addq	$32, %rsp
.L649:
	movl	8(%r13), %eax
	testl	%eax, %eax
	jle	.L647
	vmovdqa	.LC21(%rip), %ymm2
	vmovdqa	.LC2(%rip), %ymm3
	xorl	%edx, %edx
	.p2align 4,,10
	.p2align 3
.L652:
	movq	%r12, %rax
	.p2align 4,,10
	.p2align 3
.L653:
	vmovdqu	(%rax), %ymm4
	addq	$32, %rax
	vpsrad	$31, %ymm4, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpaddd	%ymm4, %ymm0, %ymm0
	vpaddd	%ymm3, %ymm0, %ymm1
	vpsrad	$31, %ymm1, %ymm1
	vpandn	%ymm2, %ymm1, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rbx, %rax
	jne	.L653
	addl	$1, %edx
	addq	$1024, %rbx
	addq	$1024, %r12
	cmpl	8(%r13), %edx
	jl	.L652
	vzeroupper
.L647:
	movq	-56(%rbp), %rax
	subq	%fs:40, %rax
	jne	.L662
	leaq	-48(%rbp), %rsp
	popq	%rbx
	popq	%r10
	.cfi_remember_state
	.cfi_def_cfa 10, 0
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	leaq	-8(%r10), %rsp
	.cfi_def_cfa 7, 8
	ret
.L661:
	.cfi_restore_state
	pushq	%rcx
	movq	%r12, %rdi
	movq	%rsi, %rcx
	movq	%rbx, %rsi
	pushq	%rdx
	movq	%r11, %rdx
	pushq	%rax
	pushq	%r8
	movl	%r15d, %r8d
	movq	%r9, -3160(%rbp)
	call	ml_dsa_poly_generate_gamma1_4x
	addq	$32, %rsp
	leaq	-1088(%rbp), %rcx
	leaq	-2112(%rbp), %rdx
	leaq	-3136(%rbp), %rsi
	jmp	.L659
.L660:
	pushq	%rcx
	movq	%r12, %rdi
	movq	%rsi, %rcx
	movq	%rbx, %rsi
	pushq	%rdx
	movq	%r11, %rdx
	pushq	%rax
	pushq	%r8
	movl	%r15d, %r8d
	call	ml_dsa_poly_generate_gamma1_4x
	addq	$32, %rsp
	jmp	.L649
.L662:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE5727:
	.size	ossl_ml_dsa_expand_mask_avx2, .-ossl_ml_dsa_expand_mask_avx2
	.section	.rodata
	.align 32
	.type	idxlut, @object
	.size	idxlut, 2048
idxlut:
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003"
	.string	""
	.string	""
	.string	""
	.string	"\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004"
	.string	""
	.string	""
	.string	""
	.string	"\003\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004"
	.string	""
	.string	""
	.string	""
	.string	"\002\003\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\004"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\004"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\004"
	.string	""
	.string	""
	.string	"\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\005"
	.string	""
	.string	""
	.string	""
	.string	"\003\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\005"
	.string	""
	.string	""
	.string	""
	.string	"\002\003\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\005"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\005"
	.string	""
	.string	""
	.string	"\004\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\004\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\005"
	.string	""
	.string	""
	.string	""
	.string	"\002\004\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\004\005"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\005"
	.string	""
	.string	""
	.string	"\003\004\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\004\005"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\005"
	.string	""
	.string	""
	.string	"\002\003\004\005"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\004\005"
	.string	""
	.string	""
	.string	"\001\002\003\004\005"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\004\005"
	.string	""
	.string	"\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\006"
	.string	""
	.string	""
	.string	""
	.string	"\003\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\006"
	.string	""
	.string	""
	.string	""
	.string	"\002\003\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\006"
	.string	""
	.string	""
	.string	"\004\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\004\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\006"
	.string	""
	.string	""
	.string	""
	.string	"\002\004\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\004\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\006"
	.string	""
	.string	""
	.string	"\003\004\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\004\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\006"
	.string	""
	.string	""
	.string	"\002\003\004\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\004\006"
	.string	""
	.string	""
	.string	"\001\002\003\004\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\004\006"
	.string	""
	.string	"\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\005\006"
	.string	""
	.string	""
	.string	""
	.string	"\002\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\005\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\005\006"
	.string	""
	.string	""
	.string	"\003\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\005\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\005\006"
	.string	""
	.string	""
	.string	"\002\003\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\005\006"
	.string	""
	.string	""
	.string	"\001\002\003\005\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\005\006"
	.string	""
	.string	"\004\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\004\005\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\004\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\005\006"
	.string	""
	.string	""
	.string	"\002\004\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\004\005\006"
	.string	""
	.string	""
	.string	"\001\002\004\005\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\005\006"
	.string	""
	.string	"\003\004\005\006"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\004\005\006"
	.string	""
	.string	""
	.string	"\001\003\004\005\006"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\005\006"
	.string	""
	.string	"\002\003\004\005\006"
	.string	""
	.string	""
	.string	""
	.string	"\002\003\004\005\006"
	.string	""
	.string	"\001\002\003\004\005\006"
	.string	""
	.string	""
	.string	"\001\002\003\004\005\006"
	.string	"\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\007"
	.string	""
	.string	""
	.string	""
	.string	"\003\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\007"
	.string	""
	.string	""
	.string	""
	.string	"\002\003\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\007"
	.string	""
	.string	""
	.string	"\004\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\004\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\007"
	.string	""
	.string	""
	.string	""
	.string	"\002\004\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\004\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\007"
	.string	""
	.string	""
	.string	"\003\004\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\004\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\007"
	.string	""
	.string	""
	.string	"\002\003\004\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\004\007"
	.string	""
	.string	""
	.string	"\001\002\003\004\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\004\007"
	.string	""
	.string	"\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\005\007"
	.string	""
	.string	""
	.string	""
	.string	"\002\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\005\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\005\007"
	.string	""
	.string	""
	.string	"\003\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\005\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\005\007"
	.string	""
	.string	""
	.string	"\002\003\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\005\007"
	.string	""
	.string	""
	.string	"\001\002\003\005\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\005\007"
	.string	""
	.string	"\004\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\004\005\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\004\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\005\007"
	.string	""
	.string	""
	.string	"\002\004\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\004\005\007"
	.string	""
	.string	""
	.string	"\001\002\004\005\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\005\007"
	.string	""
	.string	"\003\004\005\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\004\005\007"
	.string	""
	.string	""
	.string	"\001\003\004\005\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\005\007"
	.string	""
	.string	"\002\003\004\005\007"
	.string	""
	.string	""
	.string	""
	.string	"\002\003\004\005\007"
	.string	""
	.string	"\001\002\003\004\005\007"
	.string	""
	.string	""
	.string	"\001\002\003\004\005\007"
	.string	"\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\002\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\002\006\007"
	.string	""
	.string	""
	.string	"\003\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\003\006\007"
	.string	""
	.string	""
	.string	"\002\003\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\003\006\007"
	.string	""
	.string	""
	.string	"\001\002\003\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\003\006\007"
	.string	""
	.string	"\004\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\004\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\004\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\004\006\007"
	.string	""
	.string	""
	.string	"\002\004\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\004\006\007"
	.string	""
	.string	""
	.string	"\001\002\004\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\004\006\007"
	.string	""
	.string	"\003\004\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\004\006\007"
	.string	""
	.string	""
	.string	"\001\003\004\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\004\006\007"
	.string	""
	.string	"\002\003\004\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\002\003\004\006\007"
	.string	""
	.string	"\001\002\003\004\006\007"
	.string	""
	.string	""
	.string	"\001\002\003\004\006\007"
	.string	"\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001\005\006\007"
	.string	""
	.string	""
	.string	"\002\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\002\005\006\007"
	.string	""
	.string	""
	.string	"\001\002\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\002\005\006\007"
	.string	""
	.string	"\003\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\003\005\006\007"
	.string	""
	.string	""
	.string	"\001\003\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\003\005\006\007"
	.string	""
	.string	"\002\003\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\002\003\005\006\007"
	.string	""
	.string	"\001\002\003\005\006\007"
	.string	""
	.string	""
	.string	"\001\002\003\005\006\007"
	.string	"\004\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\004\005\006\007"
	.string	""
	.string	""
	.string	"\001\004\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\001\004\005\006\007"
	.string	""
	.string	"\002\004\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\002\004\005\006\007"
	.string	""
	.string	"\001\002\004\005\006\007"
	.string	""
	.string	""
	.string	"\001\002\004\005\006\007"
	.string	"\003\004\005\006\007"
	.string	""
	.string	""
	.string	""
	.string	"\003\004\005\006\007"
	.string	""
	.string	"\001\003\004\005\006\007"
	.string	""
	.string	""
	.string	"\001\003\004\005\006\007"
	.string	"\002\003\004\005\006\007"
	.string	""
	.string	""
	.string	"\002\003\004\005\006\007"
	.string	"\001\002\003\004\005\006\007"
	.string	""
	.ascii	"\001\002\003\004\005\006\007"
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC0:
	.byte	0
	.byte	1
	.byte	2
	.byte	-1
	.byte	3
	.byte	4
	.byte	5
	.byte	-1
	.byte	6
	.byte	7
	.byte	8
	.byte	-1
	.byte	9
	.byte	10
	.byte	11
	.byte	-1
	.byte	4
	.byte	5
	.byte	6
	.byte	-1
	.byte	7
	.byte	8
	.byte	9
	.byte	-1
	.byte	10
	.byte	11
	.byte	12
	.byte	-1
	.byte	13
	.byte	14
	.byte	15
	.byte	-1
	.align 32
.LC1:
	.quad	36028792732385279
	.quad	36028792732385279
	.quad	36028792732385279
	.quad	36028792732385279
	.align 32
.LC2:
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.long	-8380417
	.align 32
.LC3:
	.quad	1085102592571150095
	.quad	1085102592571150095
	.quad	1085102592571150095
	.quad	1085102592571150095
	.align 32
.LC4:
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.align 32
.LC5:
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.byte	-9
	.align 32
.LC6:
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.byte	-15
	.align 32
.LC7:
	.quad	217020518514230019
	.quad	217020518514230019
	.quad	217020518514230019
	.quad	217020518514230019
	.align 32
.LC8:
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.set	.LC9,.LC3
	.set	.LC10,.LC6
	.set	.LC11,.LC7
	.set	.LC12,.LC8
	.align 32
.LC13:
	.byte	0
	.byte	1
	.byte	2
	.byte	-1
	.byte	2
	.byte	3
	.byte	4
	.byte	-1
	.byte	4
	.byte	5
	.byte	6
	.byte	-1
	.byte	6
	.byte	7
	.byte	8
	.byte	-1
	.byte	1
	.byte	2
	.byte	3
	.byte	-1
	.byte	3
	.byte	4
	.byte	5
	.byte	-1
	.byte	5
	.byte	6
	.byte	7
	.byte	-1
	.byte	7
	.byte	8
	.byte	9
	.byte	-1
	.align 32
.LC14:
	.long	0
	.long	2
	.long	4
	.long	6
	.long	0
	.long	2
	.long	4
	.long	6
	.align 32
.LC15:
	.quad	1125895612137471
	.quad	1125895612137471
	.quad	1125895612137471
	.quad	1125895612137471
	.align 32
.LC16:
	.long	131072
	.long	131072
	.long	131072
	.long	131072
	.long	131072
	.long	131072
	.long	131072
	.long	131072
	.align 32
.LC17:
	.byte	0
	.byte	1
	.byte	2
	.byte	-1
	.byte	2
	.byte	3
	.byte	4
	.byte	-1
	.byte	5
	.byte	6
	.byte	7
	.byte	-1
	.byte	7
	.byte	8
	.byte	9
	.byte	-1
	.byte	2
	.byte	3
	.byte	4
	.byte	-1
	.byte	4
	.byte	5
	.byte	6
	.byte	-1
	.byte	7
	.byte	8
	.byte	9
	.byte	-1
	.byte	9
	.byte	10
	.byte	11
	.byte	-1
	.align 32
.LC18:
	.long	0
	.long	4
	.long	0
	.long	4
	.long	0
	.long	4
	.long	0
	.long	4
	.align 32
.LC19:
	.quad	4503595333451775
	.quad	4503595333451775
	.quad	4503595333451775
	.quad	4503595333451775
	.align 32
.LC20:
	.long	524288
	.long	524288
	.long	524288
	.long	524288
	.long	524288
	.long	524288
	.long	524288
	.long	524288
	.align 32
.LC21:
	.quad	35993616950222849
	.quad	35993616950222849
	.quad	35993616950222849
	.quad	35993616950222849
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
