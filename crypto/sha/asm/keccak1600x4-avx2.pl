#!/usr/bin/env perl
#
# Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
#
# Keccak / SHAKE x4 for AVX2 — perlasm output: keccak1600x4-avx2.s
#
# AVX2 body is GNU gas (elf) after the DATA section marker (gcc -O3 -S snapshot).
# No separate .inc files; regenerate by re-running gcc on the XKCP AVX2 C sources.

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

die "keccak1600x4-avx2.pl: missing output path\n" if !defined($output);

$win64 = 0;
$win64 = 1 if (defined($flavour) && $flavour =~ /[nm]asm|mingw64/)
          || (defined($output) && $output =~ /\.asm$/);

$avx2 = 0;
my $cc = $ENV{CC};
$cc = "gcc" if !defined($cc) || $cc eq "";

if (`$cc -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
    =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
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
    $avx2 = ($2 >= 3.3);
}

$0 =~ m/(.*[\/\\])[^\/\\]+$/;
my $asmdir = $1;

($xlate = "${asmdir}x86_64-xlate.pl" and -f $xlate)
  or ($xlate = "${asmdir}../../perlasm/x86_64-xlate.pl" and -f $xlate)
  or die "can't locate x86_64-xlate.pl";

sub emit_stubs_via_xlate {
    my ($stub_src) = @_;
    open my $OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
        or die "can't call $xlate: $!";
    print $OUT $stub_src;
    close $OUT;
}

if ($avx2 <= 0 || $win64) {
    my $stub = <<'___';
.text
.globl  SHA3_avx2_capable
.type   SHA3_avx2_capable,@abi-omnipotent
SHA3_avx2_capable:
    xor     %eax, %eax
    ret
.size   SHA3_avx2_capable, .-SHA3_avx2_capable

.globl  SHA3_shake128_x4_inc_absorb_avx2
.globl  SHA3_shake256_x4_inc_absorb_avx2
.globl  SHA3_shake128_x4_inc_finalize_avx2
.globl  SHA3_shake256_x4_inc_finalize_avx2
.globl  SHA3_shake128_x4_inc_squeeze_avx2
.globl  SHA3_shake256_x4_inc_squeeze_avx2
.globl  SHA3_shake128_x4_avx2
.globl  SHA3_shake256_x4_avx2
SHA3_shake128_x4_inc_absorb_avx2:
SHA3_shake256_x4_inc_absorb_avx2:
SHA3_shake128_x4_inc_finalize_avx2:
SHA3_shake256_x4_inc_finalize_avx2:
SHA3_shake128_x4_inc_squeeze_avx2:
SHA3_shake256_x4_inc_squeeze_avx2:
SHA3_shake128_x4_avx2:
SHA3_shake256_x4_avx2:
    .byte   0x0f,0x0b
    ret
___
    emit_stubs_via_xlate($stub);
    exit 0;
}

open my $out, '>', $output or die "can't write $output: $!";
while (<DATA>) {
    print $out $_;
}
close $out or die "can't close $output: $!";

__DATA__
.text	


.globl	SHA3_avx2_capable
.type	SHA3_avx2_capable,@function
.align	16
SHA3_avx2_capable:
	movl	OPENSSL_ia32cap_P+8(%rip),%eax
	andl	$32,%eax
	.byte	0xf3,0xc3
.size	SHA3_avx2_capable, .-SHA3_avx2_capable

	.text
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_InitializeAll
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_InitializeAll, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_InitializeAll:
	endbr64
	movq	$0, (%rdi)
	movq	%rdi, %rcx
	leaq	8(%rdi), %rdi
	xorl	%eax, %eax
	movq	$0, 784(%rdi)
	andq	$-8, %rdi
	subq	%rdi, %rcx
	addl	$800, %ecx
	shrl	$3, %ecx
	rep stosq
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_InitializeAll, .-ossl_keccak1600x4_avx2_KeccakP1600times4_InitializeAll
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_AddBytes
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_AddBytes, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_AddBytes:
	endbr64
	pushq	%r12
	movl	%ecx, %r12d
	movq	%rdx, %rax
	andl	$7, %ecx
	pushq	%rbp
	shrl	$3, %r12d
	movl	%esi, %ebp
	pushq	%rbx
	movq	%rdi, %rbx
	subq	$16, %rsp
	movq	%fs:40, %rdx
	movq	%rdx, 8(%rsp)
	xorl	%edx, %edx
	testl	%r8d, %r8d
	je	.L4
	testl	%ecx, %ecx
	jne	.L28
.L4:
	cmpl	$7, %r8d
	jbe	.L11
.L31:
	leal	-8(%r8), %edx
	leal	0(%rbp,%r12,4), %ecx
	shrl	$3, %edx
	leal	1(%rdx), %esi
	leaq	(%rax,%rsi,8), %r9
	.p2align 4,,10
	.p2align 3
.L8:
	movq	(%rax), %rdi
	movl	%ecx, %esi
	addq	$8, %rax
	addl	$4, %ecx
	xorq	%rdi, (%rbx,%rsi,8)
	cmpq	%r9, %rax
	jne	.L8
	andl	$7, %r8d
	leal	1(%r12,%rdx), %r12d
	testl	%r8d, %r8d
	jne	.L29
.L3:
	movq	8(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L30
	addq	$16, %rsp
	popq	%rbx
	popq	%rbp
	popq	%r12
	ret
	.p2align 4,,10
	.p2align 3
.L28:
	movl	$8, %esi
	movq	$0, (%rsp)
	leaq	(%rsp,%rcx), %r9
	subl	%ecx, %esi
	cmpl	%r8d, %esi
	cmova	%r8d, %esi
	movl	%esi, %r10d
	testl	%esi, %esi
	je	.L6
.L5:
	movl	%edx, %ecx
	addl	$1, %edx
	movzbl	(%rax,%rcx), %edi
	movb	%dil, (%r9,%rcx)
	cmpl	%esi, %edx
	jb	.L5
.L6:
	leal	0(%rbp,%r12,4), %edx
	subl	%esi, %r8d
	movq	(%rsp), %rcx
	addl	$1, %r12d
	xorq	%rcx, (%rbx,%rdx,8)
	addq	%r10, %rax
	cmpl	$7, %r8d
	ja	.L31
.L11:
	movq	%rax, %r9
	testl	%r8d, %r8d
	je	.L3
	.p2align 4,,10
	.p2align 3
.L29:
	movl	%r8d, %edx
	movq	%rsp, %rdi
	movl	$8, %ecx
	movq	%r9, %rsi
	movq	$0, (%rsp)
	call	__memcpy_chk@PLT
	leal	0(%rbp,%r12,4), %eax
	movq	(%rsp), %rdx
	xorq	%rdx, (%rbx,%rax,8)
	jmp	.L3
.L30:
	call	__stack_chk_fail@PLT
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_AddBytes, .-ossl_keccak1600x4_avx2_KeccakP1600times4_AddBytes
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_AddLanesAll
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_AddLanesAll, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_AddLanesAll:
	endbr64
	movl	%ecx, %r8d
	movq	%rdi, %rax
	leal	0(,%rcx,8), %edi
	leal	(%rcx,%rcx,2), %ecx
	sall	$4, %r8d
	addq	%rsi, %rdi
	sall	$3, %ecx
	addq	%rsi, %r8
	addq	%rsi, %rcx
	cmpl	$15, %edx
	ja	.L33
	testl	%edx, %edx
	je	.L103
	vmovq	(%r8), %xmm7
	vmovq	(%rsi), %xmm5
	vpinsrq	$1, (%rcx), %xmm7, %xmm1
	vpinsrq	$1, (%rdi), %xmm5, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, (%rax)
	cmpl	$1, %edx
	je	.L101
	vmovq	8(%r8), %xmm6
	vmovq	8(%rsi), %xmm4
	vpinsrq	$1, 8(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 8(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	32(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 32(%rax)
	cmpl	$2, %edx
	je	.L101
	vmovq	16(%r8), %xmm6
	vmovq	16(%rsi), %xmm7
	vpinsrq	$1, 16(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 16(%rdi), %xmm7, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	64(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 64(%rax)
	cmpl	$3, %edx
	je	.L101
	vmovq	24(%r8), %xmm5
	vmovq	24(%rsi), %xmm4
	vpinsrq	$1, 24(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 24(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	96(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 96(%rax)
	cmpl	$4, %edx
	je	.L101
	vmovq	32(%r8), %xmm6
	vmovq	32(%rsi), %xmm5
	vpinsrq	$1, 32(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 32(%rdi), %xmm5, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	128(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 128(%rax)
	cmpl	$5, %edx
	je	.L101
	vmovq	40(%r8), %xmm5
	vmovq	40(%rsi), %xmm4
	vpinsrq	$1, 40(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 40(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	160(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 160(%rax)
	cmpl	$6, %edx
	je	.L101
	vmovq	48(%r8), %xmm7
	vmovq	48(%rsi), %xmm6
	vpinsrq	$1, 48(%rcx), %xmm7, %xmm1
	vpinsrq	$1, 48(%rdi), %xmm6, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	192(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 192(%rax)
	cmpl	$7, %edx
	je	.L101
	vmovq	56(%r8), %xmm5
	vmovq	56(%rsi), %xmm4
	vpinsrq	$1, 56(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 56(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	224(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 224(%rax)
	cmpl	$8, %edx
	je	.L101
	vmovq	64(%r8), %xmm6
	vmovq	64(%rsi), %xmm4
	vpinsrq	$1, 64(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 64(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	256(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 256(%rax)
	cmpl	$9, %edx
	je	.L101
	vmovq	72(%r8), %xmm5
	vmovq	72(%rsi), %xmm6
	vpinsrq	$1, 72(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 72(%rdi), %xmm6, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	288(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 288(%rax)
	cmpl	$10, %edx
	je	.L101
	vmovq	80(%r8), %xmm7
	vmovq	80(%rsi), %xmm5
	vpinsrq	$1, 80(%rcx), %xmm7, %xmm1
	vpinsrq	$1, 80(%rdi), %xmm5, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	320(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 320(%rax)
	cmpl	$11, %edx
	je	.L101
	vmovq	88(%r8), %xmm6
	vmovq	88(%rsi), %xmm4
	vpinsrq	$1, 88(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 88(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	352(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 352(%rax)
	cmpl	$12, %edx
	je	.L101
	vmovq	96(%r8), %xmm6
	vmovq	96(%rsi), %xmm7
	vpinsrq	$1, 96(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 96(%rdi), %xmm7, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	384(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 384(%rax)
	cmpl	$13, %edx
	je	.L101
	vmovq	104(%r8), %xmm5
	vpinsrq	$1, 104(%rcx), %xmm5, %xmm1
	vmovq	104(%rsi), %xmm5
	vpinsrq	$1, 104(%rdi), %xmm5, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	416(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 416(%rax)
	cmpl	$15, %edx
	jne	.L101
	vmovq	112(%r8), %xmm1
	vmovq	112(%rsi), %xmm0
	vpinsrq	$1, 112(%rcx), %xmm1, %xmm1
	vpinsrq	$1, 112(%rdi), %xmm0, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	448(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 448(%rax)
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L33:
	vmovups	(%rsi), %ymm7
	vinsertf128	$1, (%r8), %ymm7, %ymm1
	vmovups	(%rdi), %ymm7
	vinsertf128	$1, (%rcx), %ymm7, %ymm3
	vmovups	(%rsi), %ymm7
	vperm2f128	$49, (%r8), %ymm7, %ymm0
	vunpcklpd	%ymm3, %ymm1, %ymm4
	vmovups	(%rdi), %ymm7
	vunpckhpd	%ymm3, %ymm1, %ymm1
	vperm2f128	$49, (%rcx), %ymm7, %ymm2
	vpxor	32(%rax), %ymm1, %ymm1
	vunpcklpd	%ymm2, %ymm0, %ymm3
	vunpckhpd	%ymm2, %ymm0, %ymm0
	vpxor	(%rax), %ymm4, %ymm2
	vmovdqa	%ymm1, 32(%rax)
	vpxor	96(%rax), %ymm0, %ymm0
	vpxor	64(%rax), %ymm3, %ymm1
	vmovdqa	%ymm2, (%rax)
	vmovdqa	%ymm1, 64(%rax)
	vmovdqa	%ymm0, 96(%rax)
	vmovups	32(%rsi), %ymm7
	vmovups	32(%rdi), %ymm5
	vinsertf128	$1, 32(%r8), %ymm7, %ymm1
	vinsertf128	$1, 32(%rcx), %ymm5, %ymm3
	vperm2f128	$49, 32(%r8), %ymm7, %ymm0
	vperm2f128	$49, 32(%rcx), %ymm5, %ymm2
	vunpcklpd	%ymm3, %ymm1, %ymm4
	vunpckhpd	%ymm3, %ymm1, %ymm1
	vpxor	160(%rax), %ymm1, %ymm1
	vunpcklpd	%ymm2, %ymm0, %ymm3
	vunpckhpd	%ymm2, %ymm0, %ymm0
	vpxor	128(%rax), %ymm4, %ymm2
	vmovdqa	%ymm1, 160(%rax)
	vpxor	224(%rax), %ymm0, %ymm0
	vpxor	192(%rax), %ymm3, %ymm1
	vmovdqa	%ymm2, 128(%rax)
	vmovdqa	%ymm0, 224(%rax)
	vmovdqa	%ymm1, 192(%rax)
	vmovups	64(%rsi), %ymm7
	vinsertf128	$1, 64(%r8), %ymm7, %ymm1
	vmovups	64(%rdi), %ymm5
	vinsertf128	$1, 64(%rcx), %ymm5, %ymm3
	vperm2f128	$49, 64(%rcx), %ymm5, %ymm2
	vperm2f128	$49, 64(%r8), %ymm7, %ymm0
	vunpcklpd	%ymm3, %ymm1, %ymm4
	vunpckhpd	%ymm3, %ymm1, %ymm1
	vpxor	288(%rax), %ymm1, %ymm1
	vunpcklpd	%ymm2, %ymm0, %ymm3
	vunpckhpd	%ymm2, %ymm0, %ymm0
	vpxor	256(%rax), %ymm4, %ymm2
	vmovdqa	%ymm1, 288(%rax)
	vpxor	352(%rax), %ymm0, %ymm0
	vpxor	320(%rax), %ymm3, %ymm1
	vmovdqa	%ymm2, 256(%rax)
	vmovdqa	%ymm1, 320(%rax)
	vmovdqa	%ymm0, 352(%rax)
	vmovups	96(%rsi), %ymm7
	vmovups	96(%rdi), %ymm5
	vinsertf128	$1, 96(%r8), %ymm7, %ymm1
	vinsertf128	$1, 96(%rcx), %ymm5, %ymm3
	vperm2f128	$49, 96(%rcx), %ymm5, %ymm2
	vperm2f128	$49, 96(%r8), %ymm7, %ymm0
	vunpcklpd	%ymm3, %ymm1, %ymm4
	vunpckhpd	%ymm3, %ymm1, %ymm1
	vpxor	416(%rax), %ymm1, %ymm1
	vunpcklpd	%ymm2, %ymm0, %ymm3
	vunpckhpd	%ymm2, %ymm0, %ymm0
	vpxor	384(%rax), %ymm4, %ymm2
	vpxor	480(%rax), %ymm0, %ymm0
	vmovdqa	%ymm1, 416(%rax)
	vpxor	448(%rax), %ymm3, %ymm1
	vmovdqa	%ymm2, 384(%rax)
	vmovdqa	%ymm1, 448(%rax)
	vmovdqa	%ymm0, 480(%rax)
	cmpl	$19, %edx
	jbe	.L104
	vmovups	128(%rdi), %ymm4
	vmovups	128(%rsi), %ymm7
	vinsertf128	$1, 128(%rcx), %ymm4, %ymm3
	vinsertf128	$1, 128(%r8), %ymm7, %ymm1
	vperm2f128	$49, 128(%rcx), %ymm4, %ymm2
	vperm2f128	$49, 128(%r8), %ymm7, %ymm0
	vunpcklpd	%ymm3, %ymm1, %ymm4
	vunpckhpd	%ymm3, %ymm1, %ymm1
	vpxor	544(%rax), %ymm1, %ymm1
	vunpcklpd	%ymm2, %ymm0, %ymm3
	vunpckhpd	%ymm2, %ymm0, %ymm0
	vpxor	512(%rax), %ymm4, %ymm2
	vpxor	608(%rax), %ymm0, %ymm0
	vmovdqa	%ymm1, 544(%rax)
	vpxor	576(%rax), %ymm3, %ymm1
	vmovdqa	%ymm2, 512(%rax)
	vmovdqa	%ymm1, 576(%rax)
	vmovdqa	%ymm0, 608(%rax)
	cmpl	$20, %edx
	je	.L101
	movl	%edx, %edx
	leaq	0(,%rdx,8), %r9
	movl	$160, %edx
	.p2align 4,,10
	.p2align 3
.L38:
	vmovq	(%r8,%rdx), %xmm5
	vmovq	(%rsi,%rdx), %xmm6
	vpinsrq	$1, (%rcx,%rdx), %xmm5, %xmm1
	vpinsrq	$1, (%rdi,%rdx), %xmm6, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	(%rax,%rdx,4), %ymm0, %ymm0
	vmovdqa	%ymm0, (%rax,%rdx,4)
	addq	$8, %rdx
	cmpq	%r9, %rdx
	jne	.L38
.L101:
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L104:
	cmpl	$16, %edx
	je	.L101
	vmovq	128(%r8), %xmm5
	vmovq	128(%rsi), %xmm7
	vpinsrq	$1, 128(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 128(%rdi), %xmm7, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	512(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 512(%rax)
	cmpl	$17, %edx
	je	.L101
	vmovq	136(%r8), %xmm7
	vmovq	136(%rsi), %xmm4
	vpinsrq	$1, 136(%rcx), %xmm7, %xmm1
	vpinsrq	$1, 136(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	544(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 544(%rax)
	cmpl	$19, %edx
	jne	.L101
	vmovq	144(%r8), %xmm1
	vmovq	144(%rsi), %xmm0
	vpinsrq	$1, 144(%rcx), %xmm1, %xmm1
	vpinsrq	$1, 144(%rdi), %xmm0, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	576(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 576(%rax)
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L103:
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_AddLanesAll, .-ossl_keccak1600x4_avx2_KeccakP1600times4_AddLanesAll
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteBytes
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteBytes, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteBytes:
	endbr64
	movl	%ecx, %r11d
	pushq	%rbp
	movl	%esi, %r10d
	movq	%rdx, %rax
	pushq	%rbx
	shrl	$3, %r11d
	andl	$7, %ecx
	testl	%r8d, %r8d
	je	.L106
	testl	%ecx, %ecx
	jne	.L135
.L106:
	cmpl	$7, %r8d
	jbe	.L114
.L137:
	leal	-8(%r8), %ebx
	leal	(%r10,%r11,4), %edx
	shrl	$3, %ebx
	leal	1(%rbx), %ecx
	leaq	(%rax,%rcx,8), %r9
	.p2align 4,,10
	.p2align 3
.L110:
	movq	(%rax), %rsi
	movl	%edx, %ecx
	addq	$8, %rax
	addl	$4, %edx
	movq	%rsi, (%rdi,%rcx,8)
	cmpq	%rax, %r9
	jne	.L110
	andl	$7, %r8d
	leal	1(%r11,%rbx), %r11d
	testl	%r8d, %r8d
	jne	.L136
.L133:
	popq	%rbx
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L135:
	movl	$8, %esi
	leal	(%r10,%r11,4), %edx
	subl	%ecx, %esi
	leaq	(%rcx,%rdx,8), %r9
	cmpl	%r8d, %esi
	cmova	%r8d, %esi
	addq	%rdi, %r9
	movl	%esi, %ebp
	testl	%esi, %esi
	je	.L108
	xorl	%edx, %edx
.L107:
	movl	%edx, %ecx
	addl	$1, %edx
	movzbl	(%rax,%rcx), %ebx
	movb	%bl, (%r9,%rcx)
	cmpl	%esi, %edx
	jb	.L107
.L108:
	subl	%esi, %r8d
	addl	$1, %r11d
	addq	%rbp, %rax
	cmpl	$7, %r8d
	ja	.L137
.L114:
	movq	%rax, %r9
	testl	%r8d, %r8d
	je	.L133
	.p2align 4,,10
	.p2align 3
.L136:
	leal	(%r10,%r11,4), %eax
	leaq	(%rdi,%rax,8), %rsi
	xorl	%eax, %eax
.L112:
	movl	%eax, %edx
	addl	$1, %eax
	movzbl	(%r9,%rdx), %ecx
	movb	%cl, (%rsi,%rdx)
	cmpl	%r8d, %eax
	jb	.L112
	popq	%rbx
	popq	%rbp
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteBytes, .-ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteBytes
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteLanesAll
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteLanesAll, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteLanesAll:
	endbr64
	movl	%ecx, %r8d
	movq	%rdi, %rax
	leal	0(,%rcx,8), %edi
	leal	(%rcx,%rcx,2), %ecx
	sall	$4, %r8d
	addq	%rsi, %rdi
	sall	$3, %ecx
	addq	%rsi, %r8
	addq	%rsi, %rcx
	cmpl	$15, %edx
	ja	.L139
	testl	%edx, %edx
	je	.L209
	vmovq	(%r8), %xmm7
	vmovq	(%rsi), %xmm5
	vpinsrq	$1, (%rcx), %xmm7, %xmm1
	vpinsrq	$1, (%rdi), %xmm5, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, (%rax)
	cmpl	$1, %edx
	je	.L207
	vmovq	8(%r8), %xmm6
	vmovq	8(%rsi), %xmm4
	vpinsrq	$1, 8(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 8(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 32(%rax)
	cmpl	$2, %edx
	je	.L207
	vmovq	16(%r8), %xmm6
	vmovq	16(%rsi), %xmm7
	vpinsrq	$1, 16(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 16(%rdi), %xmm7, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 64(%rax)
	cmpl	$3, %edx
	je	.L207
	vmovq	24(%r8), %xmm5
	vmovq	24(%rsi), %xmm4
	vpinsrq	$1, 24(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 24(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 96(%rax)
	cmpl	$4, %edx
	je	.L207
	vmovq	32(%r8), %xmm6
	vmovq	32(%rsi), %xmm5
	vpinsrq	$1, 32(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 32(%rdi), %xmm5, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 128(%rax)
	cmpl	$5, %edx
	je	.L207
	vmovq	40(%r8), %xmm5
	vmovq	40(%rsi), %xmm4
	vpinsrq	$1, 40(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 40(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 160(%rax)
	cmpl	$6, %edx
	je	.L207
	vmovq	48(%r8), %xmm7
	vmovq	48(%rsi), %xmm6
	vpinsrq	$1, 48(%rcx), %xmm7, %xmm1
	vpinsrq	$1, 48(%rdi), %xmm6, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 192(%rax)
	cmpl	$7, %edx
	je	.L207
	vmovq	56(%r8), %xmm5
	vmovq	56(%rsi), %xmm4
	vpinsrq	$1, 56(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 56(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 224(%rax)
	cmpl	$8, %edx
	je	.L207
	vmovq	64(%r8), %xmm6
	vmovq	64(%rsi), %xmm4
	vpinsrq	$1, 64(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 64(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 256(%rax)
	cmpl	$9, %edx
	je	.L207
	vmovq	72(%r8), %xmm5
	vmovq	72(%rsi), %xmm6
	vpinsrq	$1, 72(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 72(%rdi), %xmm6, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 288(%rax)
	cmpl	$10, %edx
	je	.L207
	vmovq	80(%r8), %xmm7
	vmovq	80(%rsi), %xmm5
	vpinsrq	$1, 80(%rcx), %xmm7, %xmm1
	vpinsrq	$1, 80(%rdi), %xmm5, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 320(%rax)
	cmpl	$11, %edx
	je	.L207
	vmovq	88(%r8), %xmm6
	vmovq	88(%rsi), %xmm4
	vpinsrq	$1, 88(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 88(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 352(%rax)
	cmpl	$12, %edx
	je	.L207
	vmovq	96(%r8), %xmm6
	vmovq	96(%rsi), %xmm7
	vpinsrq	$1, 96(%rcx), %xmm6, %xmm1
	vpinsrq	$1, 96(%rdi), %xmm7, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 384(%rax)
	cmpl	$13, %edx
	je	.L207
	vmovq	104(%r8), %xmm5
	vpinsrq	$1, 104(%rcx), %xmm5, %xmm1
	vmovq	104(%rsi), %xmm5
	vpinsrq	$1, 104(%rdi), %xmm5, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 416(%rax)
	cmpl	$15, %edx
	jne	.L207
	vmovq	112(%r8), %xmm1
	vmovq	112(%rsi), %xmm0
	vpinsrq	$1, 112(%rcx), %xmm1, %xmm1
	vpinsrq	$1, 112(%rdi), %xmm0, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 448(%rax)
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L139:
	vmovups	(%rsi), %ymm7
	vinsertf128	$1, (%r8), %ymm7, %ymm2
	vmovups	(%rdi), %ymm7
	vinsertf128	$1, (%rcx), %ymm7, %ymm3
	vmovups	(%rsi), %ymm7
	vperm2f128	$49, (%r8), %ymm7, %ymm0
	vmovups	(%rdi), %ymm7
	vperm2f128	$49, (%rcx), %ymm7, %ymm1
	vunpcklpd	%ymm3, %ymm2, %ymm4
	vunpckhpd	%ymm3, %ymm2, %ymm2
	vmovapd	%ymm4, (%rax)
	vunpcklpd	%ymm1, %ymm0, %ymm3
	vunpckhpd	%ymm1, %ymm0, %ymm0
	vmovapd	%ymm2, 32(%rax)
	vmovapd	%ymm3, 64(%rax)
	vmovapd	%ymm0, 96(%rax)
	vmovups	32(%rsi), %ymm7
	vmovups	32(%rdi), %ymm5
	vinsertf128	$1, 32(%r8), %ymm7, %ymm2
	vinsertf128	$1, 32(%rcx), %ymm5, %ymm3
	vperm2f128	$49, 32(%rcx), %ymm5, %ymm1
	vperm2f128	$49, 32(%r8), %ymm7, %ymm0
	vunpcklpd	%ymm3, %ymm2, %ymm4
	vunpckhpd	%ymm3, %ymm2, %ymm2
	vunpcklpd	%ymm1, %ymm0, %ymm3
	vunpckhpd	%ymm1, %ymm0, %ymm0
	vmovapd	%ymm4, 128(%rax)
	vmovapd	%ymm2, 160(%rax)
	vmovapd	%ymm3, 192(%rax)
	vmovapd	%ymm0, 224(%rax)
	vmovups	64(%rdi), %ymm5
	vmovups	64(%rsi), %ymm7
	vinsertf128	$1, 64(%rcx), %ymm5, %ymm3
	vperm2f128	$49, 64(%rcx), %ymm5, %ymm1
	vinsertf128	$1, 64(%r8), %ymm7, %ymm2
	vperm2f128	$49, 64(%r8), %ymm7, %ymm0
	vunpcklpd	%ymm3, %ymm2, %ymm4
	vunpckhpd	%ymm3, %ymm2, %ymm2
	vunpcklpd	%ymm1, %ymm0, %ymm3
	vunpckhpd	%ymm1, %ymm0, %ymm0
	vmovapd	%ymm4, 256(%rax)
	vmovapd	%ymm2, 288(%rax)
	vmovapd	%ymm3, 320(%rax)
	vmovapd	%ymm0, 352(%rax)
	vmovups	96(%rsi), %ymm7
	vmovups	96(%rdi), %ymm5
	vinsertf128	$1, 96(%r8), %ymm7, %ymm2
	vinsertf128	$1, 96(%rcx), %ymm5, %ymm3
	vperm2f128	$49, 96(%r8), %ymm7, %ymm0
	vperm2f128	$49, 96(%rcx), %ymm5, %ymm1
	vunpcklpd	%ymm3, %ymm2, %ymm4
	vunpckhpd	%ymm3, %ymm2, %ymm2
	vunpcklpd	%ymm1, %ymm0, %ymm3
	vunpckhpd	%ymm1, %ymm0, %ymm0
	vmovapd	%ymm4, 384(%rax)
	vmovapd	%ymm2, 416(%rax)
	vmovapd	%ymm3, 448(%rax)
	vmovapd	%ymm0, 480(%rax)
	cmpl	$19, %edx
	jbe	.L210
	vmovups	128(%rdi), %ymm4
	vmovups	128(%rsi), %ymm7
	vinsertf128	$1, 128(%rcx), %ymm4, %ymm3
	vperm2f128	$49, 128(%rcx), %ymm4, %ymm1
	vinsertf128	$1, 128(%r8), %ymm7, %ymm2
	vperm2f128	$49, 128(%r8), %ymm7, %ymm0
	vunpcklpd	%ymm3, %ymm2, %ymm4
	vunpckhpd	%ymm3, %ymm2, %ymm2
	vunpcklpd	%ymm1, %ymm0, %ymm3
	vunpckhpd	%ymm1, %ymm0, %ymm0
	vmovapd	%ymm4, 512(%rax)
	vmovapd	%ymm2, 544(%rax)
	vmovapd	%ymm3, 576(%rax)
	vmovapd	%ymm0, 608(%rax)
	cmpl	$20, %edx
	je	.L207
	movl	%edx, %edx
	leaq	0(,%rdx,8), %r9
	movl	$160, %edx
	.p2align 4,,10
	.p2align 3
.L144:
	vmovq	(%r8,%rdx), %xmm5
	vmovq	(%rsi,%rdx), %xmm6
	vpinsrq	$1, (%rcx,%rdx), %xmm5, %xmm1
	vpinsrq	$1, (%rdi,%rdx), %xmm6, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, (%rax,%rdx,4)
	addq	$8, %rdx
	cmpq	%r9, %rdx
	jne	.L144
.L207:
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L210:
	cmpl	$16, %edx
	je	.L207
	vmovq	128(%r8), %xmm5
	vmovq	128(%rsi), %xmm7
	vpinsrq	$1, 128(%rcx), %xmm5, %xmm1
	vpinsrq	$1, 128(%rdi), %xmm7, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 512(%rax)
	cmpl	$17, %edx
	je	.L207
	vmovq	136(%r8), %xmm7
	vmovq	136(%rsi), %xmm4
	vpinsrq	$1, 136(%rcx), %xmm7, %xmm1
	vpinsrq	$1, 136(%rdi), %xmm4, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 544(%rax)
	cmpl	$19, %edx
	jne	.L207
	vmovq	144(%r8), %xmm1
	vmovq	144(%rsi), %xmm0
	vpinsrq	$1, 144(%rcx), %xmm1, %xmm1
	vpinsrq	$1, 144(%rdi), %xmm0, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 576(%rax)
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L209:
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteLanesAll, .-ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteLanesAll
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteWithZeroes
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteWithZeroes, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteWithZeroes:
	endbr64
	cmpl	$7, %edx
	jbe	.L217
	leal	-8(%rdx), %r9d
	movl	%esi, %eax
	shrl	$3, %r9d
	leal	4(%rsi,%r9,4), %r8d
	.p2align 4,,10
	.p2align 3
.L213:
	movl	%eax, %ecx
	addl	$4, %eax
	movq	$0, (%rdi,%rcx,8)
	cmpl	%eax, %r8d
	jne	.L213
	andl	$7, %edx
	addl	$1, %r9d
.L212:
	testl	%edx, %edx
	jne	.L227
	ret
	.p2align 4,,10
	.p2align 3
.L227:
	leal	(%rsi,%r9,4), %eax
	leaq	(%rdi,%rax,8), %rsi
	xorl	%eax, %eax
.L215:
	movl	%eax, %ecx
	addl	$1, %eax
	movb	$0, (%rsi,%rcx)
	cmpl	%edx, %eax
	jb	.L215
	ret
	.p2align 4,,10
	.p2align 3
.L217:
	xorl	%r9d, %r9d
	jmp	.L212
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteWithZeroes, .-ossl_keccak1600x4_avx2_KeccakP1600times4_OverwriteWithZeroes
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractBytes
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractBytes, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractBytes:
	endbr64
	movl	%ecx, %r10d
	pushq	%r14
	movl	%esi, %r9d
	movq	%rdx, %rax
	pushq	%rbx
	shrl	$3, %r10d
	andl	$7, %ecx
	testl	%r8d, %r8d
	je	.L229
	testl	%ecx, %ecx
	jne	.L258
.L229:
	cmpl	$7, %r8d
	jbe	.L237
.L260:
	leal	-8(%r8), %r11d
	leal	(%r9,%r10,4), %edx
	shrl	$3, %r11d
	leal	1(%r11), %ecx
	leaq	(%rax,%rcx,8), %rsi
	.p2align 4,,10
	.p2align 3
.L233:
	movl	%edx, %ecx
	addq	$8, %rax
	addl	$4, %edx
	movq	(%rdi,%rcx,8), %rcx
	movq	%rcx, -8(%rax)
	cmpq	%rax, %rsi
	jne	.L233
	andl	$7, %r8d
	leal	1(%r10,%r11), %r10d
	testl	%r8d, %r8d
	jne	.L259
.L256:
	popq	%rbx
	popq	%r14
	ret
	.p2align 4,,10
	.p2align 3
.L258:
	movl	$8, %esi
	leal	(%r9,%r10,4), %edx
	subl	%ecx, %esi
	leaq	(%rcx,%rdx,8), %r11
	cmpl	%r8d, %esi
	cmova	%r8d, %esi
	addq	%rdi, %r11
	movl	%esi, %ebx
	testl	%esi, %esi
	je	.L231
	xorl	%edx, %edx
.L230:
	movl	%edx, %ecx
	addl	$1, %edx
	movzbl	(%r11,%rcx), %r14d
	movb	%r14b, (%rax,%rcx)
	cmpl	%esi, %edx
	jb	.L230
.L231:
	subl	%esi, %r8d
	addl	$1, %r10d
	addq	%rbx, %rax
	cmpl	$7, %r8d
	ja	.L260
.L237:
	movq	%rax, %rsi
	testl	%r8d, %r8d
	je	.L256
	.p2align 4,,10
	.p2align 3
.L259:
	leal	(%r9,%r10,4), %eax
	leaq	(%rdi,%rax,8), %rdi
	xorl	%eax, %eax
.L235:
	movl	%eax, %edx
	addl	$1, %eax
	movzbl	(%rdi,%rdx), %ecx
	movb	%cl, (%rsi,%rdx)
	cmpl	%r8d, %eax
	jb	.L235
	popq	%rbx
	popq	%r14
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractBytes, .-ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractBytes
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractLanesAll
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractLanesAll, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractLanesAll:
	endbr64
	movl	%ecx, %r11d
	leal	(%rcx,%rcx,2), %r9d
	leal	0(,%rcx,8), %r10d
	movq	%rdi, %rax
	sall	$4, %r11d
	sall	$3, %r9d
	leaq	(%rsi,%r10), %r8
	leaq	(%rsi,%r11), %rdi
	leaq	(%rsi,%r9), %rcx
	cmpl	$15, %edx
	ja	.L262
	testl	%edx, %edx
	je	.L343
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	leaq	-8(%r9), %r14
	pushq	%r13
	pushq	%r12
	movl	%edx, %r12d
	pushq	%rbx
	movq	%r12, %r13
	salq	$3, %r12
	salq	$5, %r13
	leaq	(%rsi,%r12), %rbx
	addq	%rax, %r13
	andq	$-32, %rsp
	cmpq	%rbx, %rax
	setnb	%bl
	cmpq	%r13, %rsi
	setnb	%r15b
	orl	%r15d, %ebx
	cmpl	$1, %edx
	setne	%r15b
	andl	%r15d, %ebx
	leaq	-8(%r10), %r15
	cmpq	$16, %r15
	seta	%r15b
	andl	%r15d, %ebx
	leaq	-8(%r11), %r15
	cmpq	$16, %r15
	seta	-1(%rsp)
	andb	-1(%rsp), %bl
	cmpq	$16, %r14
	seta	-1(%rsp)
	subq	%r10, %r15
	andb	-1(%rsp), %bl
	cmpq	$16, %r15
	seta	%r15b
	andl	%r15d, %ebx
	movq	%r14, %r15
	subq	%r10, %r15
	cmpq	$16, %r15
	seta	%r15b
	addq	%r12, %r10
	addq	%rsi, %r10
	andl	%r15d, %ebx
	cmpq	%r10, %rax
	setnb	%r10b
	cmpq	%r13, %r8
	setnb	%r15b
	subq	%r11, %r14
	orl	%r15d, %r10d
	andl	%r10d, %ebx
	cmpq	$16, %r14
	seta	%r10b
	addq	%r12, %r11
	addq	%rsi, %r11
	andl	%r10d, %ebx
	cmpq	%r11, %rax
	setnb	%r10b
	cmpq	%r13, %rdi
	setnb	%r11b
	orl	%r11d, %r10d
	testb	%r10b, %bl
	je	.L268
	addq	%r12, %r9
	addq	%rsi, %r9
	cmpq	%r9, %rax
	setnb	%r9b
	cmpq	%r13, %rcx
	setnb	%r10b
	orb	%r10b, %r9b
	je	.L268
	leal	-1(%rdx), %r9d
	cmpl	$2, %r9d
	jbe	.L275
	vmovdqu	(%rax), %ymm6
	vpunpcklqdq	32(%rax), %ymm6, %ymm1
	movl	%edx, %r9d
	vpunpckhqdq	32(%rax), %ymm6, %ymm0
	vmovdqu	64(%rax), %ymm6
	shrl	$2, %r9d
	vpunpcklqdq	96(%rax), %ymm6, %ymm3
	vpunpckhqdq	96(%rax), %ymm6, %ymm2
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm0, %ymm0
	vpermq	$216, %ymm3, %ymm3
	vpermq	$216, %ymm2, %ymm2
	vpunpcklqdq	%ymm3, %ymm1, %ymm4
	vpunpckhqdq	%ymm3, %ymm1, %ymm1
	vpermq	$216, %ymm4, %ymm4
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm4, (%rsi)
	vpunpcklqdq	%ymm2, %ymm0, %ymm4
	vpunpckhqdq	%ymm2, %ymm0, %ymm0
	vpermq	$216, %ymm4, %ymm4
	vpermq	$216, %ymm0, %ymm0
	vmovdqu	%ymm4, (%r8)
	vmovdqu	%ymm1, (%rdi)
	vmovdqu	%ymm0, (%rcx)
	cmpl	$1, %r9d
	je	.L270
	vmovdqu	128(%rax), %ymm6
	vmovdqu	192(%rax), %ymm5
	vpunpcklqdq	160(%rax), %ymm6, %ymm1
	vpunpcklqdq	224(%rax), %ymm5, %ymm3
	vpunpckhqdq	160(%rax), %ymm6, %ymm0
	vpunpckhqdq	224(%rax), %ymm5, %ymm2
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm3, %ymm3
	vpunpcklqdq	%ymm3, %ymm1, %ymm4
	vpermq	$216, %ymm0, %ymm0
	vpermq	$216, %ymm2, %ymm2
	vpermq	$216, %ymm4, %ymm4
	vpunpckhqdq	%ymm3, %ymm1, %ymm1
	vmovdqu	%ymm4, 32(%rsi)
	vpunpcklqdq	%ymm2, %ymm0, %ymm4
	vpunpckhqdq	%ymm2, %ymm0, %ymm0
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm4, %ymm4
	vpermq	$216, %ymm0, %ymm0
	vmovdqu	%ymm4, 32(%r8)
	vmovdqu	%ymm1, 32(%rdi)
	vmovdqu	%ymm0, 32(%rcx)
	cmpl	$3, %r9d
	jne	.L270
	vmovdqu	256(%rax), %ymm7
	vpunpcklqdq	288(%rax), %ymm7, %ymm1
	vpunpckhqdq	288(%rax), %ymm7, %ymm0
	vmovdqu	320(%rax), %ymm7
	vpunpcklqdq	352(%rax), %ymm7, %ymm3
	vpunpckhqdq	352(%rax), %ymm7, %ymm2
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm0, %ymm0
	vpermq	$216, %ymm3, %ymm3
	vpermq	$216, %ymm2, %ymm2
	vpunpcklqdq	%ymm3, %ymm1, %ymm4
	vpunpckhqdq	%ymm3, %ymm1, %ymm1
	vpermq	$216, %ymm4, %ymm4
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm4, 64(%rsi)
	vpunpcklqdq	%ymm2, %ymm0, %ymm4
	vpunpckhqdq	%ymm2, %ymm0, %ymm0
	vpermq	$216, %ymm4, %ymm4
	vpermq	$216, %ymm0, %ymm0
	vmovdqu	%ymm4, 64(%r8)
	vmovdqu	%ymm1, 64(%rdi)
	vmovdqu	%ymm0, 64(%rcx)
.L270:
	movl	%edx, %r10d
	andl	$-4, %r10d
	testb	$3, %dl
	je	.L337
	subl	%r10d, %edx
	cmpl	$1, %edx
	je	.L344
	vzeroupper
.L269:
	movl	%r10d, %ebx
	movq	%rbx, %r9
	leaq	0(,%rbx,8), %r11
	salq	$5, %r9
	addq	%rax, %r9
	vmovdqu	16(%r9), %xmm3
	vmovdqu	48(%r9), %xmm4
	vmovdqu	(%r9), %xmm0
	vmovdqu	32(%r9), %xmm1
	movl	%edx, %r9d
	andl	$-2, %r9d
	vpunpcklqdq	%xmm3, %xmm0, %xmm2
	vpunpckhqdq	%xmm3, %xmm0, %xmm0
	vpunpcklqdq	%xmm4, %xmm1, %xmm3
	addl	%r9d, %r10d
	vpunpckhqdq	%xmm4, %xmm1, %xmm1
	vpunpcklqdq	%xmm3, %xmm2, %xmm4
	vpunpckhqdq	%xmm3, %xmm2, %xmm2
	vmovdqu	%xmm4, (%rsi,%rbx,8)
	vpunpcklqdq	%xmm1, %xmm0, %xmm4
	vpunpckhqdq	%xmm1, %xmm0, %xmm0
	vmovdqu	%xmm4, (%r8,%r11)
	vmovdqu	%xmm2, (%rdi,%r11)
	vmovdqu	%xmm0, (%rcx,%r11)
	cmpl	%r9d, %edx
	je	.L339
.L272:
	leal	0(,%r10,4), %r9d
	movl	%r10d, %edx
	movl	%r9d, %r10d
	movq	(%rax,%r10,8), %r10
	movq	%r10, (%rsi,%rdx,8)
	leal	1(%r9), %esi
	movq	(%rax,%rsi,8), %rsi
	movq	%rsi, (%r8,%rdx,8)
	leal	2(%r9), %esi
	movq	(%rax,%rsi,8), %rsi
	movq	%rsi, (%rdi,%rdx,8)
	leal	3(%r9), %esi
	movq	(%rax,%rsi,8), %rax
	movq	%rax, (%rcx,%rdx,8)
.L339:
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L262:
	vmovdqa	(%rax), %ymm5
	vmovdqa	64(%rax), %ymm7
	vpunpcklqdq	32(%rax), %ymm5, %ymm2
	vpunpcklqdq	96(%rax), %ymm7, %ymm3
	vpunpckhqdq	96(%rax), %ymm7, %ymm1
	vpunpckhqdq	32(%rax), %ymm5, %ymm0
	vinsertf128	$1, %xmm3, %ymm2, %ymm4
	vperm2f128	$49, %ymm3, %ymm2, %ymm2
	vinsertf128	$1, %xmm1, %ymm0, %ymm3
	vperm2f128	$49, %ymm1, %ymm0, %ymm0
	vmovdqu	%ymm4, (%rsi)
	vmovdqu	%ymm3, (%r8)
	vmovdqu	%ymm2, (%rdi)
	vmovdqu	%ymm0, (%rcx)
	vmovdqa	128(%rax), %ymm6
	vmovdqa	192(%rax), %ymm5
	vpunpcklqdq	160(%rax), %ymm6, %ymm2
	vpunpcklqdq	224(%rax), %ymm5, %ymm3
	vpunpckhqdq	224(%rax), %ymm5, %ymm1
	vpunpckhqdq	160(%rax), %ymm6, %ymm0
	vinsertf128	$1, %xmm3, %ymm2, %ymm4
	vperm2f128	$49, %ymm3, %ymm2, %ymm2
	vinsertf128	$1, %xmm1, %ymm0, %ymm3
	vperm2f128	$49, %ymm1, %ymm0, %ymm0
	vmovdqu	%ymm4, 32(%rsi)
	vmovdqu	%ymm3, 32(%r8)
	vmovdqu	%ymm2, 32(%rdi)
	vmovdqu	%ymm0, 32(%rcx)
	vmovdqa	256(%rax), %ymm7
	vmovdqa	320(%rax), %ymm6
	vpunpcklqdq	288(%rax), %ymm7, %ymm2
	vpunpckhqdq	288(%rax), %ymm7, %ymm0
	vpunpcklqdq	352(%rax), %ymm6, %ymm3
	vpunpckhqdq	352(%rax), %ymm6, %ymm1
	vinsertf128	$1, %xmm3, %ymm2, %ymm4
	vperm2f128	$49, %ymm3, %ymm2, %ymm2
	vinsertf128	$1, %xmm1, %ymm0, %ymm3
	vperm2f128	$49, %ymm1, %ymm0, %ymm0
	vmovdqu	%ymm4, 64(%rsi)
	vmovdqu	%ymm3, 64(%r8)
	vmovdqu	%ymm2, 64(%rdi)
	vmovdqu	%ymm0, 64(%rcx)
	vmovdqa	384(%rax), %ymm5
	vpunpcklqdq	416(%rax), %ymm5, %ymm2
	vpunpckhqdq	416(%rax), %ymm5, %ymm0
	vmovdqa	448(%rax), %ymm7
	vpunpcklqdq	480(%rax), %ymm7, %ymm3
	vpunpckhqdq	480(%rax), %ymm7, %ymm1
	vinsertf128	$1, %xmm3, %ymm2, %ymm4
	vperm2f128	$49, %ymm3, %ymm2, %ymm2
	vinsertf128	$1, %xmm1, %ymm0, %ymm3
	vperm2f128	$49, %ymm1, %ymm0, %ymm0
	vmovdqu	%ymm4, 96(%rsi)
	vmovdqu	%ymm3, 96(%r8)
	vmovdqu	%ymm2, 96(%rdi)
	vmovdqu	%ymm0, 96(%rcx)
	cmpl	$19, %edx
	jbe	.L345
	vmovdqa	512(%rax), %ymm5
	vmovdqa	576(%rax), %ymm7
	vpunpcklqdq	544(%rax), %ymm5, %ymm2
	vpunpcklqdq	608(%rax), %ymm7, %ymm3
	vpunpckhqdq	544(%rax), %ymm5, %ymm0
	vpunpckhqdq	608(%rax), %ymm7, %ymm1
	vinsertf128	$1, %xmm3, %ymm2, %ymm4
	vperm2f128	$49, %ymm3, %ymm2, %ymm2
	vinsertf128	$1, %xmm1, %ymm0, %ymm3
	vperm2f128	$49, %ymm1, %ymm0, %ymm0
	vmovdqu	%ymm4, 128(%rsi)
	vmovdqu	%ymm3, 128(%r8)
	vmovdqu	%ymm2, 128(%rdi)
	vmovdqu	%ymm0, 128(%rcx)
	cmpl	$20, %edx
	je	.L336
	movl	%edx, %edx
	movl	$80, %r10d
	movl	$20, %r9d
	.p2align 4,,10
	.p2align 3
.L267:
	movl	%r10d, %r11d
	movq	(%rax,%r11,8), %r11
	movq	%r11, (%rsi,%r9,8)
	leal	1(%r10), %r11d
	movq	(%rax,%r11,8), %r11
	movq	%r11, (%r8,%r9,8)
	leal	2(%r10), %r11d
	movq	(%rax,%r11,8), %r11
	movq	%r11, (%rdi,%r9,8)
	leal	3(%r10), %r11d
	addl	$4, %r10d
	movq	(%rax,%r11,8), %r11
	movq	%r11, (%rcx,%r9,8)
	addq	$1, %r9
	cmpq	%r9, %rdx
	jne	.L267
.L336:
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L345:
	cmpl	$16, %edx
	je	.L336
	movq	512(%rax), %r9
	movq	%r9, 128(%rsi)
	movq	520(%rax), %r9
	movq	%r9, 128(%r8)
	movq	528(%rax), %r9
	movq	%r9, 128(%rdi)
	movq	536(%rax), %r9
	movq	%r9, 128(%rcx)
	cmpl	$17, %edx
	je	.L336
	movq	544(%rax), %r9
	movq	%r9, 136(%rsi)
	movq	552(%rax), %r9
	movq	%r9, 136(%r8)
	movq	560(%rax), %r9
	movq	%r9, 136(%rdi)
	movq	568(%rax), %r9
	movq	%r9, 136(%rcx)
	cmpl	$19, %edx
	jne	.L336
	movq	576(%rax), %rdx
	movq	%rdx, 144(%rsi)
	movq	584(%rax), %rdx
	movq	%rdx, 144(%r8)
	movq	592(%rax), %rdx
	movq	%rdx, 144(%rdi)
	movq	600(%rax), %rax
	movq	%rax, 144(%rcx)
	vzeroupper
	ret
	.p2align 4,,10
	.p2align 3
.L343:
	ret
	.p2align 4,,10
	.p2align 3
.L268:
	movq	(%rax), %r9
	movq	%r9, (%rsi)
	movq	8(%rax), %r9
	movq	%r9, (%r8)
	movq	16(%rax), %r9
	movq	%r9, (%rdi)
	movq	24(%rax), %r9
	movq	%r9, (%rcx)
	cmpl	$1, %edx
	je	.L339
	movq	32(%rax), %r9
	movq	%r9, 8(%rsi)
	movq	40(%rax), %r9
	movq	%r9, 8(%r8)
	movq	48(%rax), %r9
	movq	%r9, 8(%rdi)
	movq	56(%rax), %r9
	movq	%r9, 8(%rcx)
	cmpl	$2, %edx
	je	.L339
	movq	64(%rax), %r9
	movq	%r9, 16(%rsi)
	movq	72(%rax), %r9
	movq	%r9, 16(%r8)
	movq	80(%rax), %r9
	movq	%r9, 16(%rdi)
	movq	88(%rax), %r9
	movq	%r9, 16(%rcx)
	cmpl	$3, %edx
	je	.L339
	movq	96(%rax), %r9
	movq	%r9, 24(%rsi)
	movq	104(%rax), %r9
	movq	%r9, 24(%r8)
	movq	112(%rax), %r9
	movq	%r9, 24(%rdi)
	movq	120(%rax), %r9
	movq	%r9, 24(%rcx)
	cmpl	$4, %edx
	je	.L339
	movq	128(%rax), %r9
	movq	%r9, 32(%rsi)
	movq	136(%rax), %r9
	movq	%r9, 32(%r8)
	movq	144(%rax), %r9
	movq	%r9, 32(%rdi)
	movq	152(%rax), %r9
	movq	%r9, 32(%rcx)
	cmpl	$5, %edx
	je	.L339
	movq	160(%rax), %r9
	movq	%r9, 40(%rsi)
	movq	168(%rax), %r9
	movq	%r9, 40(%r8)
	movq	176(%rax), %r9
	movq	%r9, 40(%rdi)
	movq	184(%rax), %r9
	movq	%r9, 40(%rcx)
	cmpl	$6, %edx
	je	.L339
	movq	192(%rax), %r9
	movq	%r9, 48(%rsi)
	movq	200(%rax), %r9
	movq	%r9, 48(%r8)
	movq	208(%rax), %r9
	movq	%r9, 48(%rdi)
	movq	216(%rax), %r9
	movq	%r9, 48(%rcx)
	cmpl	$7, %edx
	je	.L339
	movq	224(%rax), %r9
	movq	%r9, 56(%rsi)
	movq	232(%rax), %r9
	movq	%r9, 56(%r8)
	movq	240(%rax), %r9
	movq	%r9, 56(%rdi)
	movq	248(%rax), %r9
	movq	%r9, 56(%rcx)
	cmpl	$8, %edx
	je	.L339
	movq	256(%rax), %r9
	movq	%r9, 64(%rsi)
	movq	264(%rax), %r9
	movq	%r9, 64(%r8)
	movq	272(%rax), %r9
	movq	%r9, 64(%rdi)
	movq	280(%rax), %r9
	movq	%r9, 64(%rcx)
	cmpl	$9, %edx
	je	.L339
	movq	288(%rax), %r9
	movq	%r9, 72(%rsi)
	movq	296(%rax), %r9
	movq	%r9, 72(%r8)
	movq	304(%rax), %r9
	movq	%r9, 72(%rdi)
	movq	312(%rax), %r9
	movq	%r9, 72(%rcx)
	cmpl	$10, %edx
	je	.L339
	movq	320(%rax), %r9
	movq	%r9, 80(%rsi)
	movq	328(%rax), %r9
	movq	%r9, 80(%r8)
	movq	336(%rax), %r9
	movq	%r9, 80(%rdi)
	movq	344(%rax), %r9
	movq	%r9, 80(%rcx)
	cmpl	$11, %edx
	je	.L339
	movq	352(%rax), %r9
	movq	%r9, 88(%rsi)
	movq	360(%rax), %r9
	movq	%r9, 88(%r8)
	movq	368(%rax), %r9
	movq	%r9, 88(%rdi)
	movq	376(%rax), %r9
	movq	%r9, 88(%rcx)
	cmpl	$12, %edx
	je	.L339
	movq	384(%rax), %r9
	movq	%r9, 96(%rsi)
	movq	392(%rax), %r9
	movq	%r9, 96(%r8)
	movq	400(%rax), %r9
	movq	%r9, 96(%rdi)
	movq	408(%rax), %r9
	movq	%r9, 96(%rcx)
	cmpl	$13, %edx
	je	.L339
	movq	416(%rax), %r9
	movq	%r9, 104(%rsi)
	movq	424(%rax), %r9
	movq	%r9, 104(%r8)
	movq	432(%rax), %r9
	movq	%r9, 104(%rdi)
	movq	440(%rax), %r9
	movq	%r9, 104(%rcx)
	cmpl	$15, %edx
	jne	.L339
	movq	448(%rax), %rdx
	movq	%rdx, 112(%rsi)
	movq	456(%rax), %rdx
	movq	%rdx, 112(%r8)
	movq	464(%rax), %rdx
	movq	%rdx, 112(%rdi)
	movq	472(%rax), %rax
	movq	%rax, 112(%rcx)
	jmp	.L339
	.p2align 4,,10
	.p2align 3
.L337:
	vzeroupper
	jmp	.L339
.L275:
	xorl	%r10d, %r10d
	jmp	.L269
.L344:
	vzeroupper
	jmp	.L272
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractLanesAll, .-ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractLanesAll
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddBytes
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddBytes, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddBytes:
	endbr64
	pushq	%rbp
	movq	%rdi, %r10
	movl	%esi, %r11d
	movq	%rdx, %rdi
	pushq	%rbx
	movl	%r8d, %ebx
	movq	%rcx, %rsi
	andl	$7, %r8d
	shrl	$3, %ebx
	testl	%r9d, %r9d
	je	.L347
	testl	%r8d, %r8d
	je	.L347
	leal	(%r11,%rbx,4), %eax
	leal	0(,%r8,8), %ecx
	movq	(%r10,%rax,8), %rdx
	movl	$8, %eax
	subl	%r8d, %eax
	shrx	%rcx, %rdx, %rdx
	movzbl	(%rdi), %ecx
	cmpl	%r9d, %eax
	cmova	%r9d, %eax
	xorl	%edx, %ecx
	movb	%cl, (%rsi)
	movq	%rdx, %rcx
	subl	%eax, %r9d
	shrq	$8, %rcx
	cmpl	$1, %eax
	je	.L348
	xorb	1(%rdi), %cl
	movb	%cl, 1(%rsi)
	movq	%rdx, %rcx
	shrq	$16, %rcx
	cmpl	$2, %eax
	je	.L348
	xorb	2(%rdi), %cl
	movb	%cl, 2(%rsi)
	movq	%rdx, %rcx
	shrq	$24, %rcx
	cmpl	$3, %eax
	je	.L348
	xorb	3(%rdi), %cl
	movb	%cl, 3(%rsi)
	movq	%rdx, %rcx
	shrq	$32, %rcx
	cmpl	$4, %eax
	je	.L348
	xorb	4(%rdi), %cl
	movl	%eax, %r8d
	movb	%cl, 4(%rsi)
	movq	%rdx, %rcx
	shrq	$40, %rcx
	subl	$5, %r8d
	je	.L348
	xorb	5(%rdi), %cl
	shrq	$48, %rdx
	movb	%cl, 5(%rsi)
	cmpl	$1, %r8d
	je	.L348
	xorb	6(%rdi), %dl
	movb	%dl, 6(%rsi)
.L348:
	movl	%eax, %eax
	addl	$1, %ebx
	addq	%rax, %rdi
	addq	%rax, %rsi
.L347:
	cmpl	$7, %r9d
	jbe	.L349
	leal	-8(%r9), %ebp
	leal	(%r11,%rbx,4), %ecx
	xorl	%eax, %eax
	shrl	$3, %ebp
	leal	1(%rbp), %r8d
	salq	$3, %r8
	.p2align 4,,10
	.p2align 3
.L350:
	movl	%ecx, %edx
	addl	$4, %ecx
	movq	(%r10,%rdx,8), %rdx
	xorq	(%rdi,%rax), %rdx
	movq	%rdx, (%rsi,%rax)
	addq	$8, %rax
	cmpq	%r8, %rax
	jne	.L350
	andl	$7, %r9d
	leal	1(%rbx,%rbp), %ebx
	addq	%rax, %rdi
	addq	%rax, %rsi
.L349:
	testl	%r9d, %r9d
	je	.L398
	leal	(%r11,%rbx,4), %eax
	movzbl	(%rdi), %edx
	movq	(%r10,%rax,8), %rax
	xorl	%eax, %edx
	movb	%dl, (%rsi)
	movq	%rax, %rdx
	shrq	$8, %rdx
	cmpl	$1, %r9d
	je	.L398
	xorb	1(%rdi), %dl
	movb	%dl, 1(%rsi)
	movq	%rax, %rdx
	shrq	$16, %rdx
	cmpl	$2, %r9d
	je	.L398
	xorb	2(%rdi), %dl
	movb	%dl, 2(%rsi)
	movq	%rax, %rdx
	shrq	$24, %rdx
	cmpl	$3, %r9d
	je	.L398
	xorb	3(%rdi), %dl
	movb	%dl, 3(%rsi)
	movq	%rax, %rdx
	shrq	$32, %rdx
	cmpl	$4, %r9d
	je	.L398
	xorb	4(%rdi), %dl
	movb	%dl, 4(%rsi)
	movq	%rax, %rdx
	shrq	$40, %rdx
	subl	$5, %r9d
	je	.L398
	xorb	5(%rdi), %dl
	shrq	$48, %rax
	movb	%dl, 5(%rsi)
	cmpl	$1, %r9d
	je	.L398
	xorb	6(%rdi), %al
	movb	%al, 6(%rsi)
.L398:
	popq	%rbx
	popq	%rbp
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddBytes, .-ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddBytes
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddLanesAll
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddLanesAll, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddLanesAll:
	endbr64
	pushq	%rbp
	leal	0(,%r8,8), %eax
	movq	%rdx, %r9
	movq	%rsi, %r10
	leal	(%r8,%r8,2), %edx
	sall	$3, %edx
	movq	%rsp, %rbp
	pushq	%r14
	leaq	(%r10,%rdx), %r11
	addq	%r9, %rdx
	pushq	%r13
	pushq	%r12
	leaq	(%rsi,%rax), %r12
	movl	%r8d, %esi
	leaq	(%r9,%rax), %r8
	sall	$4, %esi
	pushq	%rbx
	leaq	(%r10,%rsi), %rbx
	addq	%r9, %rsi
	cmpl	$15, %ecx
	ja	.L401
	movl	%ecx, %r13d
	xorl	%eax, %eax
	salq	$3, %r13
	testl	%ecx, %ecx
	je	.L420
	.p2align 4,,10
	.p2align 3
.L407:
	movq	(%r10,%rax), %rcx
	xorq	(%rdi,%rax,4), %rcx
	movq	%rcx, (%r9,%rax)
	movq	(%r12,%rax), %rcx
	xorq	8(%rdi,%rax,4), %rcx
	movq	%rcx, (%r8,%rax)
	movq	(%rbx,%rax), %rcx
	xorq	16(%rdi,%rax,4), %rcx
	movq	%rcx, (%rsi,%rax)
	movq	(%r11,%rax), %rcx
	xorq	24(%rdi,%rax,4), %rcx
	movq	%rcx, (%rdx,%rax)
	addq	$8, %rax
	cmpq	%r13, %rax
	jne	.L407
.L420:
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L401:
	vmovdqa	(%rdi), %ymm5
	vmovdqa	64(%rdi), %ymm7
	vpunpcklqdq	32(%rdi), %ymm5, %ymm1
	vpunpcklqdq	96(%rdi), %ymm7, %ymm3
	vpunpckhqdq	96(%rdi), %ymm7, %ymm2
	vpunpckhqdq	32(%rdi), %ymm5, %ymm0
	vinsertf128	$1, %xmm3, %ymm1, %ymm4
	vperm2f128	$49, %ymm3, %ymm1, %ymm1
	vpxor	(%rbx), %ymm1, %ymm1
	vinsertf128	$1, %xmm2, %ymm0, %ymm3
	vperm2f128	$49, %ymm2, %ymm0, %ymm0
	vpxor	(%r12), %ymm3, %ymm2
	vpxor	(%r11), %ymm0, %ymm0
	vpxor	(%r10), %ymm4, %ymm3
	vmovdqu	%ymm3, (%r9)
	vmovdqu	%ymm2, (%r8)
	vmovdqu	%ymm1, (%rsi)
	vmovdqu	%ymm0, (%rdx)
	vmovdqa	128(%rdi), %ymm6
	vmovdqa	192(%rdi), %ymm5
	vpunpcklqdq	160(%rdi), %ymm6, %ymm1
	vpunpcklqdq	224(%rdi), %ymm5, %ymm3
	vpunpckhqdq	224(%rdi), %ymm5, %ymm2
	vpunpckhqdq	160(%rdi), %ymm6, %ymm0
	vinsertf128	$1, %xmm3, %ymm1, %ymm4
	vperm2f128	$49, %ymm3, %ymm1, %ymm1
	vpxor	32(%rbx), %ymm1, %ymm1
	vinsertf128	$1, %xmm2, %ymm0, %ymm3
	vperm2f128	$49, %ymm2, %ymm0, %ymm0
	vpxor	32(%r12), %ymm3, %ymm2
	vpxor	32(%r11), %ymm0, %ymm0
	vpxor	32(%r10), %ymm4, %ymm3
	vmovdqu	%ymm3, 32(%r9)
	vmovdqu	%ymm2, 32(%r8)
	vmovdqu	%ymm1, 32(%rsi)
	vmovdqu	%ymm0, 32(%rdx)
	vmovdqa	256(%rdi), %ymm7
	vmovdqa	320(%rdi), %ymm6
	vpunpcklqdq	288(%rdi), %ymm7, %ymm1
	vpunpckhqdq	288(%rdi), %ymm7, %ymm0
	vpunpcklqdq	352(%rdi), %ymm6, %ymm3
	vpunpckhqdq	352(%rdi), %ymm6, %ymm2
	vinsertf128	$1, %xmm3, %ymm1, %ymm4
	vperm2f128	$49, %ymm3, %ymm1, %ymm1
	vinsertf128	$1, %xmm2, %ymm0, %ymm3
	vpxor	64(%rbx), %ymm1, %ymm1
	vperm2f128	$49, %ymm2, %ymm0, %ymm0
	vpxor	64(%r12), %ymm3, %ymm2
	vpxor	64(%r11), %ymm0, %ymm0
	vpxor	64(%r10), %ymm4, %ymm3
	vmovdqu	%ymm3, 64(%r9)
	vmovdqu	%ymm2, 64(%r8)
	vmovdqu	%ymm1, 64(%rsi)
	vmovdqu	%ymm0, 64(%rdx)
	vmovdqa	384(%rdi), %ymm5
	vmovdqa	448(%rdi), %ymm7
	vpunpcklqdq	416(%rdi), %ymm5, %ymm1
	vpunpcklqdq	480(%rdi), %ymm7, %ymm3
	vpunpckhqdq	480(%rdi), %ymm7, %ymm2
	vpunpckhqdq	416(%rdi), %ymm5, %ymm0
	vinsertf128	$1, %xmm3, %ymm1, %ymm4
	vperm2f128	$49, %ymm3, %ymm1, %ymm1
	vpxor	96(%rbx), %ymm1, %ymm1
	vinsertf128	$1, %xmm2, %ymm0, %ymm3
	vperm2f128	$49, %ymm2, %ymm0, %ymm0
	vpxor	96(%r12), %ymm3, %ymm2
	vpxor	96(%r11), %ymm0, %ymm0
	vpxor	96(%r10), %ymm4, %ymm3
	vmovdqu	%ymm3, 96(%r9)
	vmovdqu	%ymm2, 96(%r8)
	vmovdqu	%ymm1, 96(%rsi)
	vmovdqu	%ymm0, 96(%rdx)
	cmpl	$19, %ecx
	jbe	.L422
	vmovdqa	512(%rdi), %ymm5
	vmovdqa	576(%rdi), %ymm7
	vpunpcklqdq	544(%rdi), %ymm5, %ymm1
	vpunpcklqdq	608(%rdi), %ymm7, %ymm3
	vpunpckhqdq	608(%rdi), %ymm7, %ymm2
	vpunpckhqdq	544(%rdi), %ymm5, %ymm0
	vinsertf128	$1, %xmm3, %ymm1, %ymm4
	vperm2f128	$49, %ymm3, %ymm1, %ymm1
	vpxor	128(%rbx), %ymm1, %ymm1
	vinsertf128	$1, %xmm2, %ymm0, %ymm3
	vperm2f128	$49, %ymm2, %ymm0, %ymm0
	vpxor	128(%r12), %ymm3, %ymm2
	vpxor	128(%r11), %ymm0, %ymm0
	vpxor	128(%r10), %ymm4, %ymm3
	vmovdqu	%ymm3, 128(%r9)
	vmovdqu	%ymm2, 128(%r8)
	vmovdqu	%ymm1, 128(%rsi)
	vmovdqu	%ymm0, 128(%rdx)
	cmpl	$20, %ecx
	je	.L419
	movl	%ecx, %r13d
	movl	$20, %eax
	.p2align 4,,10
	.p2align 3
.L406:
	leal	0(,%rax,4), %r14d
	movq	%r14, %rcx
	movq	(%rdi,%r14,8), %r14
	xorq	(%r10,%rax,8), %r14
	movq	%r14, (%r9,%rax,8)
	leal	1(%rcx), %r14d
	movq	(%rdi,%r14,8), %r14
	xorq	(%r12,%rax,8), %r14
	movq	%r14, (%r8,%rax,8)
	leal	2(%rcx), %r14d
	addl	$3, %ecx
	movq	(%rdi,%r14,8), %r14
	xorq	(%rbx,%rax,8), %r14
	movq	%r14, (%rsi,%rax,8)
	movq	(%rdi,%rcx,8), %rcx
	xorq	(%r11,%rax,8), %rcx
	movq	%rcx, (%rdx,%rax,8)
	addq	$1, %rax
	cmpq	%r13, %rax
	jne	.L406
.L419:
	vzeroupper
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L422:
	cmpl	$16, %ecx
	je	.L419
	movq	128(%r10), %rax
	xorq	512(%rdi), %rax
	movq	%rax, 128(%r9)
	movq	128(%r12), %rax
	xorq	520(%rdi), %rax
	movq	%rax, 128(%r8)
	movq	128(%rbx), %rax
	xorq	528(%rdi), %rax
	movq	%rax, 128(%rsi)
	movq	128(%r11), %rax
	xorq	536(%rdi), %rax
	movq	%rax, 128(%rdx)
	cmpl	$17, %ecx
	je	.L419
	movq	136(%r10), %rax
	xorq	544(%rdi), %rax
	movq	%rax, 136(%r9)
	movq	552(%rdi), %rax
	xorq	136(%r12), %rax
	movq	%rax, 136(%r8)
	movq	560(%rdi), %rax
	xorq	136(%rbx), %rax
	movq	%rax, 136(%rsi)
	movq	568(%rdi), %rax
	xorq	136(%r11), %rax
	movq	%rax, 136(%rdx)
	cmpl	$19, %ecx
	jne	.L419
	movq	144(%r10), %rax
	xorq	576(%rdi), %rax
	movq	%rax, 144(%r9)
	movq	144(%r12), %rax
	xorq	584(%rdi), %rax
	movq	%rax, 144(%r8)
	movq	144(%rbx), %rax
	xorq	592(%rdi), %rax
	movq	%rax, 144(%rsi)
	movq	144(%r11), %rax
	xorq	600(%rdi), %rax
	movq	%rax, 144(%rdx)
	vzeroupper
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%rbp
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddLanesAll, .-ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractAndAddLanesAll
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds:
	endbr64
	pushq	%rbp
	movq	%rsp, %rbp
	andq	$-32, %rsp
	subq	$1096, %rsp
	vmovdqa	480(%rdi), %ymm4
	vpxor	640(%rdi), %ymm4, %ymm0
	vmovdqa	160(%rdi), %ymm4
	vpxor	320(%rdi), %ymm4, %ymm1
	vmovdqa	512(%rdi), %ymm4
	vpxor	672(%rdi), %ymm4, %ymm7
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	192(%rdi), %ymm4
	vpxor	(%rdi), %ymm0, %ymm0
	vpxor	352(%rdi), %ymm4, %ymm1
	vmovdqa	544(%rdi), %ymm4
	vpxor	704(%rdi), %ymm4, %ymm6
	vmovdqa	224(%rdi), %ymm4
	vpxor	%ymm1, %ymm7, %ymm7
	vpxor	384(%rdi), %ymm4, %ymm1
	vpxor	32(%rdi), %ymm7, %ymm7
	vmovdqa	576(%rdi), %ymm4
	vpxor	736(%rdi), %ymm4, %ymm2
	vpxor	%ymm1, %ymm6, %ymm6
	vmovdqa	256(%rdi), %ymm4
	vpxor	64(%rdi), %ymm6, %ymm6
	vpxor	416(%rdi), %ymm4, %ymm1
	vmovdqa	608(%rdi), %ymm4
	vpsllq	$1, %ymm6, %ymm5
	vpxor	%ymm1, %ymm2, %ymm2
	vpxor	768(%rdi), %ymm4, %ymm1
	vpxor	96(%rdi), %ymm2, %ymm2
	vmovdqa	288(%rdi), %ymm4
	vpxor	448(%rdi), %ymm4, %ymm3
	vpsllq	$1, %ymm7, %ymm4
	vpsrlq	$63, %ymm2, %ymm8
	vpxor	%ymm3, %ymm1, %ymm1
	vpsrlq	$63, %ymm7, %ymm3
	vpxor	128(%rdi), %ymm1, %ymm1
	vpor	%ymm3, %ymm4, %ymm4
	vpsrlq	$63, %ymm6, %ymm3
	vpor	%ymm3, %ymm5, %ymm5
	vpsllq	$1, %ymm2, %ymm3
	vpxor	%ymm1, %ymm4, %ymm4
	vpor	%ymm8, %ymm3, %ymm3
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	(%rdi), %ymm4, %ymm8
	vpxor	%ymm7, %ymm3, %ymm3
	vpsrlq	$63, %ymm1, %ymm7
	vpxor	384(%rdi), %ymm3, %ymm9
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpsrlq	$63, %ymm0, %ymm6
	vpsllq	$1, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm0
	vpxor	192(%rdi), %ymm5, %ymm6
	vpxor	%ymm2, %ymm0, %ymm0
	vpsrlq	$20, %ymm6, %ymm2
	vpsllq	$44, %ymm6, %ymm6
	vpor	%ymm2, %ymm6, %ymm6
	vpsrlq	$21, %ymm9, %ymm2
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm2, %ymm9, %ymm9
	vbroadcastsd	KeccakF1600RoundConstants(%rip), %ymm2
	vpxor	576(%rdi), %ymm1, %ymm7
	vpandn	%ymm9, %ymm6, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vpsrlq	$43, %ymm7, %ymm2
	vpsllq	$21, %ymm7, %ymm7
	vpxor	%ymm8, %ymm11, %ymm11
	vpor	%ymm2, %ymm7, %ymm7
	vpandn	%ymm7, %ymm9, %ymm2
	vpxor	%ymm6, %ymm2, %ymm14
	vpxor	768(%rdi), %ymm0, %ymm2
	vpsrlq	$50, %ymm2, %ymm10
	vpsllq	$14, %ymm2, %ymm2
	vpor	%ymm10, %ymm2, %ymm2
	vpandn	%ymm2, %ymm7, %ymm10
	vpxor	%ymm9, %ymm10, %ymm15
	vpandn	%ymm8, %ymm2, %ymm9
	vpandn	%ymm6, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm2
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	320(%rdi), %ymm4, %ymm9
	vmovdqa	%ymm15, 520(%rsp)
	vmovdqa	%ymm2, 552(%rsp)
	vpxor	96(%rdi), %ymm1, %ymm2
	vpxor	512(%rdi), %ymm5, %ymm8
	vmovdqa	%ymm7, 872(%rsp)
	vpxor	288(%rdi), %ymm0, %ymm7
	vpsrlq	$36, %ymm2, %ymm6
	vpsllq	$28, %ymm2, %ymm2
	vpor	%ymm6, %ymm2, %ymm2
	vpsrlq	$44, %ymm7, %ymm6
	vpsllq	$20, %ymm7, %ymm7
	vpor	%ymm6, %ymm7, %ymm7
	vpsrlq	$61, %ymm9, %ymm6
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm6, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm6
	vpxor	%ymm2, %ymm6, %ymm6
	vmovdqa	%ymm6, %ymm15
	vpsrlq	$19, %ymm8, %ymm6
	vpsllq	$45, %ymm8, %ymm8
	vpor	%ymm6, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm6
	vpxor	%ymm7, %ymm6, %ymm13
	vpxor	704(%rdi), %ymm3, %ymm6
	vmovdqa	%ymm13, 968(%rsp)
	vpsrlq	$3, %ymm6, %ymm10
	vpsllq	$61, %ymm6, %ymm6
	vpor	%ymm10, %ymm6, %ymm6
	vpandn	%ymm6, %ymm8, %ymm10
	vpxor	%ymm9, %ymm10, %ymm9
	vmovdqa	%ymm9, 744(%rsp)
	vpandn	%ymm2, %ymm6, %ymm9
	vpandn	%ymm7, %ymm2, %ymm2
	vpxor	224(%rdi), %ymm3, %ymm7
	vpxor	%ymm6, %ymm2, %ymm6
	vpxor	32(%rdi), %ymm5, %ymm2
	vpxor	%ymm8, %ymm9, %ymm8
	vmovdqa	%ymm8, 648(%rsp)
	vpxor	416(%rdi), %ymm1, %ymm8
	vpxor	608(%rdi), %ymm0, %ymm9
	vmovdqa	%ymm6, 904(%rsp)
	vpsrlq	$63, %ymm2, %ymm6
	vpsllq	$1, %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm9, %ymm9
	vpor	%ymm6, %ymm2, %ymm2
	vpsrlq	$58, %ymm7, %ymm6
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm6, %ymm7, %ymm7
	vpsrlq	$39, %ymm8, %ymm6
	vpsllq	$25, %ymm8, %ymm8
	vpor	%ymm6, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm6
	vpxor	%ymm2, %ymm6, %ymm10
	vpandn	%ymm9, %ymm8, %ymm6
	vmovdqa	%ymm10, 1000(%rsp)
	vpxor	%ymm7, %ymm6, %ymm6
	vmovdqa	%ymm6, 776(%rsp)
	vpxor	640(%rdi), %ymm4, %ymm6
	vpsrlq	$46, %ymm6, %ymm10
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm10, %ymm6, %ymm6
	vpandn	%ymm6, %ymm9, %ymm10
	vpxor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm2, %ymm6, %ymm8
	vpandn	%ymm7, %ymm2, %ymm2
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm6, %ymm2, %ymm9
	vpxor	128(%rdi), %ymm0, %ymm2
	vmovdqa	%ymm9, 680(%rsp)
	vpxor	352(%rdi), %ymm5, %ymm9
	vmovdqa	%ymm8, 1032(%rsp)
	vpsrlq	$37, %ymm2, %ymm6
	vpsllq	$27, %ymm2, %ymm2
	vpor	%ymm6, %ymm2, %ymm2
	vpxor	160(%rdi), %ymm4, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm9, %ymm7
	vpsllq	$10, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm6, %ymm7
	vpxor	%ymm2, %ymm7, %ymm12
	vpxor	544(%rdi), %ymm3, %ymm7
	vmovdqa	%ymm12, 808(%rsp)
	vpxor	736(%rdi), %ymm1, %ymm12
	vpsrlq	$49, %ymm7, %ymm8
	vpsllq	$15, %ymm7, %ymm7
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm12, %ymm7, %ymm13
	vpandn	%ymm7, %ymm9, %ymm8
	vpxor	%ymm9, %ymm13, %ymm13
	vpandn	%ymm2, %ymm12, %ymm9
	vpandn	%ymm6, %ymm2, %ymm2
	vpxor	%ymm12, %ymm2, %ymm2
	vpxor	%ymm6, %ymm8, %ymm8
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm13, 936(%rsp)
	vpxor	64(%rdi), %ymm3, %ymm3
	vpxor	256(%rdi), %ymm1, %ymm1
	vmovdqa	%ymm2, 1064(%rsp)
	vpxor	448(%rdi), %ymm0, %ymm12
	vpxor	480(%rdi), %ymm4, %ymm4
	vmovdqa	%ymm15, 360(%rsp)
	vmovdqa	968(%rsp), %ymm13
	vpsrlq	$2, %ymm3, %ymm2
	vpsllq	$62, %ymm3, %ymm3
	vmovdqa	%ymm14, 616(%rsp)
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$25, %ymm12, %ymm0
	vpsrlq	$9, %ymm1, %ymm2
	vpsllq	$39, %ymm12, %ymm12
	vpxor	%ymm14, %ymm13, %ymm14
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm0, %ymm12, %ymm12
	vpor	%ymm2, %ymm1, %ymm1
	vmovdqa	1000(%rsp), %ymm2
	vpandn	%ymm12, %ymm1, %ymm6
	vpxor	%ymm3, %ymm6, %ymm6
	vpxor	%ymm15, %ymm2, %ymm2
	vpxor	808(%rsp), %ymm6, %ymm0
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$23, %ymm4, %ymm0
	vpsllq	$41, %ymm4, %ymm4
	vpxor	%ymm11, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpandn	%ymm4, %ymm12, %ymm0
	vpxor	%ymm1, %ymm0, %ymm15
	vpxor	776(%rsp), %ymm8, %ymm0
	vpxor	%ymm0, %ymm14, %ymm14
	vpxor	672(%rdi), %ymm5, %ymm0
	vpxor	%ymm15, %ymm14, %ymm14
	vpsrlq	$62, %ymm0, %ymm5
	vpsllq	$2, %ymm0, %ymm0
	vpor	%ymm5, %ymm0, %ymm0
	vpxor	936(%rsp), %ymm10, %ymm5
	vpandn	%ymm0, %ymm4, %ymm7
	vpxor	%ymm12, %ymm7, %ymm7
	vmovdqa	744(%rsp), %ymm12
	vpxor	520(%rsp), %ymm12, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpandn	%ymm3, %ymm0, %ymm5
	vpandn	%ymm1, %ymm3, %ymm3
	vpxor	%ymm4, %ymm5, %ymm4
	vpxor	%ymm0, %ymm3, %ymm3
	vpxor	%ymm7, %ymm13, %ymm13
	vmovdqa	648(%rsp), %ymm5
	vpxor	872(%rsp), %ymm5, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vmovdqa	%ymm4, 392(%rsp)
	vpxor	%ymm4, %ymm9, %ymm4
	vpxor	680(%rsp), %ymm3, %ymm0
	vpxor	%ymm4, %ymm12, %ymm12
	vmovdqa	904(%rsp), %ymm4
	vpxor	552(%rsp), %ymm4, %ymm1
	vpxor	1032(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1064(%rsp), %ymm1, %ymm1
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm1, %ymm5, %ymm5
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm11, %ymm5, %ymm11
	vpxor	%ymm6, %ymm5, %ymm6
	vmovdqa	%ymm0, 840(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpor	840(%rsp), %ymm0, %ymm0
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm1, %ymm14
	vpsllq	$1, %ymm1, %ymm1
	vpxor	%ymm10, %ymm0, %ymm10
	vpxor	%ymm7, %ymm0, %ymm7
	vpor	%ymm14, %ymm1, %ymm1
	vbroadcastsd	8+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm1, %ymm1
	vpsrlq	$63, %ymm2, %ymm13
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm1, %ymm9
	vpor	%ymm13, %ymm2, %ymm2
	vpxor	%ymm12, %ymm2, %ymm2
	vpxor	968(%rsp), %ymm4, %ymm12
	vpxor	%ymm3, %ymm2, %ymm3
	vpsrlq	$20, %ymm12, %ymm13
	vpsllq	$44, %ymm12, %ymm12
	vpor	%ymm13, %ymm12, %ymm12
	vpsrlq	$21, %ymm10, %ymm13
	vpsllq	$43, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm12, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	%ymm13, 968(%rsp)
	vpsrlq	$43, %ymm9, %ymm13
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm10, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$50, %ymm3, %ymm13
	vmovdqa	%ymm14, 712(%rsp)
	vpsllq	$14, %ymm3, %ymm3
	vpor	%ymm13, %ymm3, %ymm3
	vpandn	%ymm3, %ymm9, %ymm13
	vpxor	%ymm10, %ymm13, %ymm10
	vmovdqa	%ymm10, 424(%rsp)
	vpandn	%ymm11, %ymm3, %ymm10
	vpandn	%ymm12, %ymm11, %ymm11
	vpxor	%ymm9, %ymm10, %ymm9
	vpsrlq	$3, %ymm7, %ymm12
	vpxor	%ymm3, %ymm11, %ymm11
	vmovdqa	%ymm9, 840(%rsp)
	vpsllq	$61, %ymm7, %ymm7
	vmovdqa	%ymm11, 456(%rsp)
	vpor	%ymm12, %ymm7, %ymm7
	vpxor	872(%rsp), %ymm1, %ymm3
	vpxor	904(%rsp), %ymm2, %ymm10
	vpxor	1000(%rsp), %ymm5, %ymm11
	vpsrlq	$36, %ymm3, %ymm9
	vpsllq	$28, %ymm3, %ymm3
	vpor	%ymm9, %ymm3, %ymm3
	vpsrlq	$44, %ymm10, %ymm9
	vpsllq	$20, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm3, %ymm9, %ymm9
	vmovdqa	%ymm9, 488(%rsp)
	vpsrlq	$19, %ymm8, %ymm9
	vpsllq	$45, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm7, %ymm8, %ymm12
	vpandn	%ymm8, %ymm11, %ymm9
	vpxor	%ymm11, %ymm12, %ymm11
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	392(%rsp), %ymm1, %ymm12
	vmovdqa	%ymm11, 872(%rsp)
	vpandn	%ymm3, %ymm7, %ymm11
	vpandn	%ymm10, %ymm3, %ymm3
	vpxor	%ymm7, %ymm3, %ymm10
	vpxor	%ymm8, %ymm11, %ymm8
	vpxor	616(%rsp), %ymm4, %ymm3
	vmovdqa	%ymm10, 1000(%rsp)
	vpxor	1032(%rsp), %ymm1, %ymm10
	vpxor	1064(%rsp), %ymm2, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vmovdqa	%ymm8, 584(%rsp)
	vpsrlq	$63, %ymm3, %ymm7
	vpsllq	$1, %ymm3, %ymm3
	vpxor	648(%rsp), %ymm1, %ymm1
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpor	%ymm7, %ymm3, %ymm3
	vpxor	744(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm8
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm8
	vpxor	%ymm3, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpandn	%ymm11, %ymm10, %ymm8
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm8, 904(%rsp)
	vpsrlq	$46, %ymm6, %ymm8
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm8
	vpxor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm3, %ymm6, %ymm10
	vpandn	%ymm7, %ymm3, %ymm3
	vpxor	%ymm6, %ymm3, %ymm6
	vpxor	%ymm11, %ymm10, %ymm11
	vpxor	552(%rsp), %ymm2, %ymm3
	vmovdqa	%ymm6, 616(%rsp)
	vpxor	776(%rsp), %ymm4, %ymm10
	vpxor	%ymm15, %ymm4, %ymm4
	vpxor	680(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm11, 1032(%rsp)
	vpsrlq	$37, %ymm3, %ymm6
	vpsllq	$27, %ymm3, %ymm3
	vpxor	936(%rsp), %ymm0, %ymm11
	vpxor	520(%rsp), %ymm0, %ymm0
	vpor	%ymm6, %ymm3, %ymm3
	vpxor	360(%rsp), %ymm5, %ymm6
	vmovdqa	%ymm14, 680(%rsp)
	vpxor	808(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm3, %ymm7, %ymm7
	vmovdqa	%ymm7, 744(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm13
	vpandn	%ymm3, %ymm12, %ymm10
	vpandn	%ymm6, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm3, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm13, 776(%rsp)
	vmovdqa	%ymm6, 1064(%rsp)
	vpsrlq	$2, %ymm0, %ymm3
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm3, %ymm0, %ymm0
	vpsrlq	$9, %ymm1, %ymm3
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsrlq	$25, %ymm2, %ymm3
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vpxor	488(%rsp), %ymm14, %ymm3
	vpandn	%ymm2, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpxor	744(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	968(%rsp), %ymm3, %ymm3
	vpxor	712(%rsp), %ymm9, %ymm14
	vpsllq	$41, %ymm5, %ymm5
	vmovdqa	872(%rsp), %ymm15
	vpxor	424(%rsp), %ymm15, %ymm13
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm2, %ymm11
	vpxor	%ymm1, %ymm11, %ymm12
	vpxor	904(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm12, 392(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	584(%rsp), %ymm12
	vpxor	840(%rsp), %ymm12, %ymm12
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vpxor	776(%rsp), %ymm8, %ymm2
	vpxor	%ymm2, %ymm13, %ymm13
	vpandn	%ymm0, %ymm4, %ymm2
	vpandn	%ymm1, %ymm0, %ymm0
	vmovdqa	1000(%rsp), %ymm1
	vpxor	%ymm5, %ymm2, %ymm15
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm11, %ymm13, %ymm13
	vpsllq	$1, %ymm14, %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm10, %ymm15, %ymm2
	vpxor	%ymm2, %ymm12, %ymm12
	vpxor	456(%rsp), %ymm1, %ymm2
	vpxor	616(%rsp), %ymm0, %ymm1
	vpxor	1032(%rsp), %ymm12, %ymm12
	vpxor	%ymm1, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm1
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm1, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm1, 936(%rsp)
	vpsllq	$1, %ymm12, %ymm1
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	936(%rsp), %ymm1, %ymm1
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm1, %ymm1
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm1, %ymm8
	vpxor	%ymm11, %ymm1, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	16+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	968(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpxor	%ymm0, %ymm3, %ymm0
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm13, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 936(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm13
	vmovdqa	%ymm13, 808(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm13, %ymm0, %ymm0
	vpandn	%ymm0, %ymm10, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 520(%rsp)
	vpandn	%ymm12, %ymm0, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	1000(%rsp), %ymm3, %ymm9
	vpxor	%ymm0, %ymm12, %ymm0
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm8, %ymm8
	vmovdqa	%ymm0, 552(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	840(%rsp), %ymm2, %ymm0
	vpxor	680(%rsp), %ymm5, %ymm10
	vmovdqa	%ymm8, 968(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpsrlq	$36, %ymm0, %ymm8
	vpsllq	$28, %ymm0, %ymm0
	vpor	%ymm8, %ymm0, %ymm0
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 648(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm15, %ymm2, %ymm12
	vmovdqa	%ymm10, 840(%rsp)
	vpandn	%ymm0, %ymm11, %ymm10
	vpandn	%ymm9, %ymm0, %ymm0
	vpxor	%ymm11, %ymm0, %ymm9
	vpxor	%ymm7, %ymm10, %ymm10
	vpxor	712(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm10, 680(%rsp)
	vpxor	1032(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm9, 1000(%rsp)
	vpsrlq	$63, %ymm0, %ymm7
	vpsllq	$1, %ymm0, %ymm0
	vpor	%ymm7, %ymm0, %ymm0
	vpxor	872(%rsp), %ymm1, %ymm7
	vpxor	1064(%rsp), %ymm3, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	584(%rsp), %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm0, %ymm9, %ymm14
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 872(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm0, %ymm6, %ymm10
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	456(%rsp), %ymm3, %ymm0
	vmovdqa	%ymm6, 712(%rsp)
	vpxor	776(%rsp), %ymm1, %ymm11
	vpxor	424(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm10, 1032(%rsp)
	vpsrlq	$37, %ymm0, %ymm6
	vpsllq	$27, %ymm0, %ymm0
	vpxor	904(%rsp), %ymm4, %ymm10
	vpxor	616(%rsp), %ymm3, %ymm3
	vpor	%ymm6, %ymm0, %ymm0
	vpxor	488(%rsp), %ymm5, %ymm6
	vmovdqa	%ymm14, 776(%rsp)
	vpxor	744(%rsp), %ymm5, %ymm5
	vpxor	392(%rsp), %ymm4, %ymm4
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vmovdqa	%ymm7, 904(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm15
	vpandn	%ymm0, %ymm12, %ymm10
	vpandn	%ymm6, %ymm0, %ymm0
	vmovdqa	%ymm15, 1064(%rsp)
	vpxor	%ymm12, %ymm0, %ymm15
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm11, %ymm10, %ymm10
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm0, %ymm1, %ymm1
	vpsrlq	$25, %ymm3, %ymm6
	vpsrlq	$9, %ymm2, %ymm0
	vpsllq	$39, %ymm3, %ymm3
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	648(%rsp), %ymm14, %ymm3
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	904(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	936(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm14
	vpxor	872(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm14, %ymm12
	vpxor	808(%rsp), %ymm8, %ymm14
	vmovdqa	%ymm12, 328(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	840(%rsp), %ymm12
	vpxor	520(%rsp), %ymm12, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1064(%rsp), %ymm9, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	1000(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	680(%rsp), %ymm0
	vpxor	968(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 392(%rsp)
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1032(%rsp), %ymm12, %ymm12
	vpxor	552(%rsp), %ymm2, %ymm2
	vpxor	712(%rsp), %ymm1, %ymm0
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpxor	%ymm15, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 744(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	744(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	24+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	936(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 936(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 424(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 456(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm10
	vmovdqa	%ymm1, 488(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	968(%rsp), %ymm2, %ymm1
	vpxor	1000(%rsp), %ymm3, %ymm9
	vmovdqa	%ymm10, 744(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	776(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 584(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	392(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 776(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1032(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm1, 968(%rsp)
	vpxor	%ymm15, %ymm3, %ymm11
	vpxor	808(%rsp), %ymm4, %ymm1
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vmovdqa	%ymm7, 616(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	840(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1000(%rsp)
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm15, 808(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm15
	vpxor	552(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 840(%rsp)
	vpxor	872(%rsp), %ymm4, %ymm10
	vpxor	1064(%rsp), %ymm0, %ymm11
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	648(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 872(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm14, 1032(%rsp)
	vpxor	520(%rsp), %ymm0, %ymm0
	vpxor	680(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm1, 1064(%rsp)
	vpxor	712(%rsp), %ymm3, %ymm3
	vpxor	904(%rsp), %ymm5, %ymm5
	vmovdqa	1000(%rsp), %ymm14
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpxor	328(%rsp), %ymm4, %ymm4
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	584(%rsp), %ymm14, %ymm3
	vpxor	424(%rsp), %ymm8, %ymm14
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	872(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	936(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vmovdqa	%ymm11, %ymm12
	vpxor	808(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm12, 360(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	776(%rsp), %ymm12
	vpxor	456(%rsp), %ymm12, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1032(%rsp), %ymm9, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	968(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	616(%rsp), %ymm0
	vpxor	744(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 392(%rsp)
	vpxor	488(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	840(%rsp), %ymm1, %ymm0
	vpxor	%ymm15, %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 904(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	904(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	32+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	936(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 904(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 648(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 520(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm9, 936(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm8, 552(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	744(%rsp), %ymm2, %ymm1
	vpxor	968(%rsp), %ymm3, %ymm9
	vpxor	1000(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	392(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm14, 392(%rsp)
	vmovdqa	%ymm10, 680(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm10
	vpxor	1064(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm1, 968(%rsp)
	vpxor	424(%rsp), %ymm4, %ymm1
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vmovdqa	%ymm10, 712(%rsp)
	vpxor	%ymm15, %ymm2, %ymm10
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpxor	616(%rsp), %ymm2, %ymm2
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	776(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm15
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 744(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm7
	vpxor	%ymm11, %ymm10, %ymm11
	vpxor	488(%rsp), %ymm3, %ymm1
	vpxor	808(%rsp), %ymm4, %ymm10
	vmovdqa	%ymm7, 776(%rsp)
	vpxor	840(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm11, 1000(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	1032(%rsp), %ymm0, %ymm11
	vpxor	456(%rsp), %ymm0, %ymm0
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	584(%rsp), %ymm5, %ymm6
	vpxor	872(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 808(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm10, 1032(%rsp)
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm1, 1064(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	%ymm14, %ymm15, %ymm3
	vpxor	648(%rsp), %ymm8, %ymm14
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	808(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	904(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm12
	vpxor	744(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm12, 328(%rsp)
	vpxor	360(%rsp), %ymm4, %ymm4
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	680(%rsp), %ymm12
	vpxor	520(%rsp), %ymm12, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1032(%rsp), %ymm9, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	968(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	712(%rsp), %ymm0
	vpxor	936(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 488(%rsp)
	vpxor	552(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	776(%rsp), %ymm1, %ymm0
	vpxor	1000(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 872(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	872(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	40+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	904(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 904(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 424(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 456(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpxor	%ymm10, %ymm9, %ymm10
	vpxor	936(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm8, 584(%rsp)
	vmovdqa	%ymm10, 840(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpxor	968(%rsp), %ymm3, %ymm8
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm15, %ymm5, %ymm9
	vpsrlq	$61, %ymm9, %ymm10
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm10
	vpxor	%ymm1, %ymm10, %ymm15
	vpsrlq	$19, %ymm7, %ymm10
	vpsllq	$45, %ymm7, %ymm7
	vmovdqa	%ymm15, %ymm13
	vpor	%ymm10, %ymm7, %ymm7
	vpandn	%ymm7, %ymm9, %ymm10
	vpxor	%ymm8, %ymm10, %ymm15
	vpsrlq	$3, %ymm11, %ymm10
	vpsllq	$61, %ymm11, %ymm11
	vpor	%ymm10, %ymm11, %ymm11
	vpandn	%ymm11, %ymm7, %ymm10
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	1064(%rsp), %ymm3, %ymm10
	vmovdqa	%ymm9, 872(%rsp)
	vpandn	%ymm1, %ymm11, %ymm9
	vpandn	%ymm8, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	1000(%rsp), %ymm2, %ymm9
	vmovdqa	%ymm1, 936(%rsp)
	vpxor	648(%rsp), %ymm4, %ymm1
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vmovdqa	%ymm7, 616(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	680(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm9, %ymm8
	vpsllq	$25, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 968(%rsp)
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm8, 648(%rsp)
	vpsrlq	$46, %ymm6, %ymm8
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm10, %ymm8
	vpxor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm1, %ymm6, %ymm9
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	552(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 680(%rsp)
	vpxor	1032(%rsp), %ymm0, %ymm10
	vpxor	520(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm9, 1000(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	744(%rsp), %ymm4, %ymm9
	vpxor	776(%rsp), %ymm3, %ymm3
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	392(%rsp), %ymm5, %ymm6
	vmovdqa	%ymm13, 392(%rsp)
	vpxor	808(%rsp), %ymm5, %ymm5
	vpxor	328(%rsp), %ymm4, %ymm4
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm9, %ymm7
	vpsllq	$10, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm11
	vpsrlq	$49, %ymm10, %ymm7
	vmovdqa	%ymm11, 744(%rsp)
	vpsllq	$15, %ymm10, %ymm10
	vpxor	488(%rsp), %ymm2, %ymm11
	vpxor	712(%rsp), %ymm2, %ymm2
	vpor	%ymm7, %ymm10, %ymm10
	vpshufb	.LC1(%rip), %ymm11, %ymm11
	vpandn	%ymm10, %ymm9, %ymm7
	vpandn	%ymm11, %ymm10, %ymm12
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm9, %ymm12, %ymm14
	vpandn	%ymm1, %ymm11, %ymm9
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpsrlq	$25, %ymm3, %ymm6
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm14, 1032(%rsp)
	vmovdqa	%ymm1, 1064(%rsp)
	vpsrlq	$2, %ymm0, %ymm1
	vpsllq	$62, %ymm0, %ymm0
	vmovdqa	968(%rsp), %ymm14
	vpor	%ymm1, %ymm0, %ymm0
	vpsllq	$39, %ymm3, %ymm3
	vpsrlq	$9, %ymm2, %ymm1
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm1, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm1
	vpxor	%ymm13, %ymm14, %ymm3
	vpxor	424(%rsp), %ymm15, %ymm14
	vpandn	%ymm1, %ymm2, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpxor	744(%rsp), %ymm6, %ymm10
	vpxor	%ymm10, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm10
	vpxor	904(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm10, %ymm5, %ymm5
	vpandn	%ymm5, %ymm1, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vmovdqa	%ymm10, %ymm12
	vpxor	648(%rsp), %ymm7, %ymm10
	vmovdqa	%ymm12, 360(%rsp)
	vpxor	%ymm10, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm10
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	872(%rsp), %ymm12
	vpxor	456(%rsp), %ymm12, %ymm13
	vpor	%ymm10, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm10
	vpandn	%ymm0, %ymm4, %ymm12
	vpandn	%ymm2, %ymm0, %ymm0
	vmovdqa	936(%rsp), %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	1032(%rsp), %ymm8, %ymm1
	vpxor	584(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	616(%rsp), %ymm1
	vpxor	840(%rsp), %ymm1, %ymm11
	vpxor	%ymm9, %ymm12, %ymm1
	vpxor	%ymm10, %ymm13, %ymm13
	vpxor	%ymm1, %ymm11, %ymm11
	vpsllq	$1, %ymm13, %ymm4
	vpxor	680(%rsp), %ymm0, %ymm1
	vpxor	1000(%rsp), %ymm11, %ymm11
	vpxor	%ymm1, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm1
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm1, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm1, 808(%rsp)
	vpsllq	$1, %ymm11, %ymm1
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	808(%rsp), %ymm1, %ymm1
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm1, %ymm1
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm1, %ymm8
	vpxor	%ymm10, %ymm1, %ymm10
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm9, %ymm2, %ymm9
	vpxor	%ymm12, %ymm2, %ymm12
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpor	%ymm13, %ymm3, %ymm3
	vpxor	904(%rsp), %ymm5, %ymm13
	vpxor	%ymm11, %ymm3, %ymm3
	vpxor	%ymm15, %ymm4, %ymm11
	vbroadcastsd	48+KeccakF1600RoundConstants(%rip), %ymm15
	vpsrlq	$20, %ymm11, %ymm14
	vpsllq	$44, %ymm11, %ymm11
	vpxor	%ymm0, %ymm3, %ymm0
	vpor	%ymm14, %ymm11, %ymm11
	vpsrlq	$21, %ymm8, %ymm14
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm14, %ymm8, %ymm8
	vpandn	%ymm8, %ymm11, %ymm14
	vpxor	%ymm15, %ymm14, %ymm14
	vpxor	%ymm13, %ymm14, %ymm15
	vpsrlq	$43, %ymm9, %ymm14
	vmovdqa	%ymm15, 776(%rsp)
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm14, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm14
	vpxor	%ymm11, %ymm14, %ymm14
	vmovdqa	%ymm14, 808(%rsp)
	vpsrlq	$50, %ymm0, %ymm14
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm14, %ymm0, %ymm0
	vpandn	%ymm0, %ymm9, %ymm14
	vpxor	%ymm8, %ymm14, %ymm8
	vmovdqa	%ymm8, 488(%rsp)
	vpandn	%ymm13, %ymm0, %ymm8
	vpandn	%ymm11, %ymm13, %ymm13
	vpxor	968(%rsp), %ymm5, %ymm11
	vpxor	%ymm0, %ymm13, %ymm0
	vpsrlq	$3, %ymm10, %ymm13
	vpxor	%ymm9, %ymm8, %ymm9
	vmovdqa	%ymm0, 520(%rsp)
	vpsllq	$61, %ymm10, %ymm10
	vpxor	840(%rsp), %ymm2, %ymm0
	vmovdqa	%ymm9, 904(%rsp)
	vpor	%ymm13, %ymm10, %ymm10
	vpsrlq	$36, %ymm0, %ymm8
	vpsllq	$28, %ymm0, %ymm0
	vpor	%ymm8, %ymm0, %ymm0
	vpxor	936(%rsp), %ymm3, %ymm8
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm8, %ymm9
	vpxor	%ymm0, %ymm9, %ymm9
	vmovdqa	%ymm9, 552(%rsp)
	vpsrlq	$19, %ymm7, %ymm9
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpandn	%ymm10, %ymm7, %ymm13
	vpandn	%ymm7, %ymm11, %ymm9
	vpxor	%ymm11, %ymm13, %ymm14
	vpandn	%ymm0, %ymm10, %ymm11
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	%ymm10, %ymm0, %ymm0
	vpxor	%ymm7, %ymm11, %ymm15
	vpxor	%ymm8, %ymm9, %ymm9
	vmovdqa	%ymm14, 840(%rsp)
	vmovdqa	%ymm0, 936(%rsp)
	vpxor	424(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm15, 712(%rsp)
	vpsrlq	$63, %ymm0, %ymm7
	vpsllq	$1, %ymm0, %ymm0
	vpor	%ymm7, %ymm0, %ymm0
	vpxor	872(%rsp), %ymm1, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1000(%rsp), %ymm2, %ymm8
	vpsrlq	$39, %ymm8, %ymm10
	vpsllq	$25, %ymm8, %ymm8
	vpor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm10
	vpxor	%ymm0, %ymm10, %ymm11
	vpxor	1064(%rsp), %ymm3, %ymm10
	vmovdqa	%ymm11, %ymm14
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm11
	vpxor	%ymm7, %ymm11, %ymm15
	vpsrlq	$46, %ymm6, %ymm11
	vmovdqa	%ymm15, 872(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm11, %ymm6, %ymm6
	vpandn	%ymm6, %ymm10, %ymm11
	vpxor	%ymm8, %ymm11, %ymm11
	vpandn	%ymm0, %ymm6, %ymm8
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm6
	vpxor	%ymm10, %ymm8, %ymm10
	vpxor	584(%rsp), %ymm3, %ymm0
	vmovdqa	%ymm6, 968(%rsp)
	vmovdqa	%ymm10, 1000(%rsp)
	vpsrlq	$37, %ymm0, %ymm6
	vpsllq	$27, %ymm0, %ymm0
	vpxor	648(%rsp), %ymm4, %ymm10
	vpor	%ymm6, %ymm0, %ymm0
	vpxor	392(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm0, %ymm7, %ymm8
	vpxor	1032(%rsp), %ymm1, %ymm7
	vmovdqa	%ymm8, %ymm15
	vpsrlq	$49, %ymm7, %ymm8
	vpsllq	$15, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm12, %ymm7, %ymm13
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm8, %ymm8
	vmovdqa	%ymm10, 1032(%rsp)
	vpandn	%ymm0, %ymm12, %ymm10
	vpandn	%ymm6, %ymm0, %ymm0
	vpxor	%ymm12, %ymm0, %ymm0
	vpxor	%ymm7, %ymm10, %ymm10
	vmovdqa	%ymm0, 1064(%rsp)
	vpxor	456(%rsp), %ymm1, %ymm1
	vpxor	616(%rsp), %ymm2, %ymm2
	vpxor	680(%rsp), %ymm3, %ymm3
	vpxor	744(%rsp), %ymm5, %ymm5
	vmovdqa	%ymm14, 680(%rsp)
	vpxor	360(%rsp), %ymm4, %ymm4
	vpsrlq	$2, %ymm1, %ymm0
	vmovdqa	840(%rsp), %ymm13
	vmovdqa	%ymm15, 392(%rsp)
	vpsllq	$62, %ymm1, %ymm1
	vpsrlq	$25, %ymm3, %ymm6
	vpxor	488(%rsp), %ymm13, %ymm13
	vpor	%ymm0, %ymm1, %ymm1
	vpsllq	$39, %ymm3, %ymm3
	vpsrlq	$9, %ymm2, %ymm0
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	552(%rsp), %ymm14, %ymm3
	vpxor	808(%rsp), %ymm9, %ymm14
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm15, %ymm6, %ymm7
	vpxor	%ymm7, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm7
	vpxor	776(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm7, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm7
	vpxor	%ymm2, %ymm7, %ymm7
	vmovdqa	%ymm7, %ymm12
	vpxor	872(%rsp), %ymm8, %ymm7
	vmovdqa	%ymm12, 456(%rsp)
	vpxor	%ymm7, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm7
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	712(%rsp), %ymm12
	vpxor	904(%rsp), %ymm12, %ymm12
	vpor	%ymm7, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vpxor	1032(%rsp), %ymm11, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	936(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm15
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm7, %ymm13, %ymm13
	vpsllq	$1, %ymm14, %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm10, %ymm15, %ymm0
	vpxor	520(%rsp), %ymm2, %ymm2
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	968(%rsp), %ymm1, %ymm0
	vpxor	1000(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 744(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	744(%rsp), %ymm0, %ymm0
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm11, %ymm0, %ymm11
	vpxor	%ymm7, %ymm0, %ymm7
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	56+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	776(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm11, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm11, %ymm11
	vpor	%ymm13, %ymm11, %ymm11
	vpandn	%ymm11, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm11, %ymm13
	vpxor	%ymm9, %ymm13, %ymm13
	vmovdqa	%ymm13, 424(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm11, %ymm13, %ymm11
	vmovdqa	%ymm11, 584(%rsp)
	vpandn	%ymm12, %ymm1, %ymm11
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm7, %ymm12
	vpxor	%ymm10, %ymm11, %ymm10
	vmovdqa	%ymm1, 616(%rsp)
	vpsllq	$61, %ymm7, %ymm7
	vpxor	904(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm10, 744(%rsp)
	vpor	%ymm12, %ymm7, %ymm7
	vpxor	936(%rsp), %ymm3, %ymm10
	vpxor	680(%rsp), %ymm5, %ymm11
	vpsrlq	$36, %ymm1, %ymm9
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm9, %ymm1, %ymm1
	vpsrlq	$44, %ymm10, %ymm9
	vpsllq	$20, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 648(%rsp)
	vpsrlq	$19, %ymm8, %ymm9
	vpsllq	$45, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm7, %ymm8, %ymm12
	vpandn	%ymm8, %ymm11, %ymm9
	vpxor	%ymm11, %ymm12, %ymm11
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	%ymm15, %ymm2, %ymm12
	vmovdqa	%ymm11, 776(%rsp)
	vpandn	%ymm1, %ymm7, %ymm11
	vpandn	%ymm10, %ymm1, %ymm1
	vpxor	1000(%rsp), %ymm2, %ymm10
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	%ymm8, %ymm11, %ymm8
	vpxor	1064(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm8, 680(%rsp)
	vpxor	%ymm7, %ymm1, %ymm8
	vpxor	808(%rsp), %ymm4, %ymm1
	vpxor	712(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm8, 904(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	840(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm8
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm13
	vpandn	%ymm11, %ymm10, %ymm8
	vmovdqa	%ymm13, 1000(%rsp)
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm8, 808(%rsp)
	vpsrlq	$46, %ymm6, %ymm8
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm8
	vpxor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	1032(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm14, 1032(%rsp)
	vmovdqa	%ymm1, 840(%rsp)
	vpxor	520(%rsp), %ymm3, %ymm1
	vpxor	488(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 936(%rsp)
	vpxor	872(%rsp), %ymm4, %ymm10
	vpxor	968(%rsp), %ymm3, %ymm3
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	552(%rsp), %ymm5, %ymm6
	vpxor	392(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 872(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm15
	vpxor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm1, %ymm12, %ymm10
	vmovdqa	1000(%rsp), %ymm13
	vpandn	%ymm6, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm15, 1064(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpxor	%ymm12, %ymm1, %ymm15
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	648(%rsp), %ymm13, %ymm3
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	872(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpsllq	$41, %ymm5, %ymm5
	vpxor	%ymm14, %ymm3, %ymm3
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm14
	vpxor	808(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm14, %ymm13
	vpxor	424(%rsp), %ymm9, %ymm14
	vmovdqa	%ymm13, 360(%rsp)
	vpxor	456(%rsp), %ymm4, %ymm4
	vmovdqa	776(%rsp), %ymm12
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	584(%rsp), %ymm12, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1064(%rsp), %ymm8, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	904(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	680(%rsp), %ymm0
	vpxor	744(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 392(%rsp)
	vpxor	616(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	840(%rsp), %ymm1, %ymm0
	vpxor	936(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpxor	%ymm15, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 968(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	968(%rsp), %ymm0, %ymm0
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm0, %ymm8
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	64+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1032(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm13, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1032(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 712(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 456(%rsp)
	vpandn	%ymm12, %ymm1, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm9
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm8, %ymm8
	vpxor	744(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm9, 488(%rsp)
	vpxor	904(%rsp), %ymm3, %ymm9
	vpxor	1000(%rsp), %ymm5, %ymm10
	vpor	%ymm12, %ymm11, %ymm11
	vmovdqa	%ymm8, 968(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 520(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 904(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm9
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	%ymm15, %ymm3, %ymm11
	vpxor	424(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 552(%rsp)
	vpxor	936(%rsp), %ymm2, %ymm10
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vmovdqa	%ymm9, 1000(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	776(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, %ymm14
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm15, 744(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm15
	vpxor	%ymm6, %ymm1, %ymm10
	vmovdqa	%ymm10, 776(%rsp)
	vpxor	616(%rsp), %ymm3, %ymm1
	vpxor	808(%rsp), %ymm4, %ymm10
	vpxor	1064(%rsp), %ymm0, %ymm11
	vpxor	392(%rsp), %ymm2, %ymm12
	vpxor	584(%rsp), %ymm0, %ymm0
	vpsrlq	$37, %ymm1, %ymm6
	vpxor	680(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm14, 680(%rsp)
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpsllq	$27, %ymm1, %ymm1
	vpxor	840(%rsp), %ymm3, %ymm3
	vpxor	360(%rsp), %ymm4, %ymm4
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	648(%rsp), %ymm5, %ymm6
	vpxor	872(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 808(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm10, 936(%rsp)
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm1, 1064(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	520(%rsp), %ymm14, %ymm3
	vpxor	712(%rsp), %ymm8, %ymm14
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	808(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1032(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm13
	vpxor	744(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm13, 328(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vmovdqa	904(%rsp), %ymm13
	vpxor	456(%rsp), %ymm13, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	936(%rsp), %ymm9, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	1000(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	552(%rsp), %ymm0
	vpxor	968(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 392(%rsp)
	vpxor	488(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	776(%rsp), %ymm1, %ymm0
	vpxor	%ymm15, %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 872(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	872(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	72+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1032(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1032(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 584(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 424(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm10
	vmovdqa	%ymm1, 616(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	968(%rsp), %ymm2, %ymm1
	vpxor	1000(%rsp), %ymm3, %ymm9
	vmovdqa	%ymm10, 840(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	680(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 648(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	392(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 872(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm9
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	712(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 680(%rsp)
	vpxor	%ymm15, %ymm2, %ymm10
	vpxor	1064(%rsp), %ymm3, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vmovdqa	%ymm9, 968(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	904(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm15
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 904(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm1, 712(%rsp)
	vpxor	488(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm10, 1000(%rsp)
	vpxor	744(%rsp), %ymm4, %ymm10
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	520(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm11
	vmovdqa	%ymm11, 744(%rsp)
	vpxor	936(%rsp), %ymm0, %ymm11
	vpxor	456(%rsp), %ymm0, %ymm0
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm14, 936(%rsp)
	vmovdqa	%ymm6, 1064(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	552(%rsp), %ymm2, %ymm2
	vpxor	776(%rsp), %ymm3, %ymm3
	vpxor	808(%rsp), %ymm5, %ymm5
	vpsllq	$62, %ymm0, %ymm0
	vpxor	584(%rsp), %ymm8, %ymm14
	vpxor	328(%rsp), %ymm4, %ymm4
	vpor	%ymm6, %ymm0, %ymm1
	vmovdqa	872(%rsp), %ymm13
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpxor	424(%rsp), %ymm13, %ymm13
	vpsllq	$39, %ymm3, %ymm3
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	648(%rsp), %ymm15, %ymm3
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	744(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1032(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm12
	vpxor	904(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm12, 360(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	936(%rsp), %ymm9, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	968(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	680(%rsp), %ymm0
	vpxor	840(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 392(%rsp)
	vpxor	616(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	712(%rsp), %ymm1, %ymm0
	vpxor	1000(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 808(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	808(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	80+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1032(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1032(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 456(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	840(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm8, 488(%rsp)
	vmovdqa	%ymm9, 776(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpxor	968(%rsp), %ymm3, %ymm8
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm15, %ymm5, %ymm9
	vpsrlq	$61, %ymm9, %ymm10
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm10
	vpxor	%ymm1, %ymm10, %ymm15
	vpsrlq	$19, %ymm7, %ymm10
	vmovdqa	%ymm15, 808(%rsp)
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm10, %ymm7, %ymm7
	vpandn	%ymm7, %ymm9, %ymm10
	vpxor	%ymm8, %ymm10, %ymm15
	vpsrlq	$3, %ymm11, %ymm10
	vpsllq	$61, %ymm11, %ymm11
	vpor	%ymm10, %ymm11, %ymm11
	vpandn	%ymm11, %ymm7, %ymm10
	vpxor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm1, %ymm11, %ymm9
	vpandn	%ymm8, %ymm1, %ymm1
	vmovdqa	%ymm10, 840(%rsp)
	vpxor	%ymm11, %ymm1, %ymm8
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	584(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 520(%rsp)
	vpxor	1000(%rsp), %ymm2, %ymm9
	vpxor	1064(%rsp), %ymm3, %ymm10
	vmovdqa	%ymm8, 968(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpxor	392(%rsp), %ymm2, %ymm11
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	872(%rsp), %ymm0, %ymm7
	vmovdqa	%ymm14, 392(%rsp)
	vpshufb	.LC1(%rip), %ymm11, %ymm11
	vpxor	%ymm14, %ymm15, %ymm14
	vpxor	680(%rsp), %ymm2, %ymm2
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm9, %ymm8
	vpsllq	$25, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm13
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm7, %ymm8, %ymm12
	vpsrlq	$46, %ymm6, %ymm8
	vmovdqa	%ymm12, 872(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm10, %ymm8
	vpxor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm1, %ymm6, %ymm9
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm10, %ymm9, %ymm10
	vpxor	616(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 552(%rsp)
	vpxor	904(%rsp), %ymm4, %ymm9
	vpxor	712(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm10, 1000(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	936(%rsp), %ymm0, %ymm10
	vpxor	424(%rsp), %ymm0, %ymm0
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	648(%rsp), %ymm5, %ymm6
	vmovdqa	%ymm13, 712(%rsp)
	vpxor	744(%rsp), %ymm5, %ymm5
	vpxor	360(%rsp), %ymm4, %ymm4
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm9, %ymm7
	vpsllq	$10, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 584(%rsp)
	vpsrlq	$49, %ymm10, %ymm7
	vpsllq	$15, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm11, %ymm10, %ymm12
	vpandn	%ymm10, %ymm9, %ymm7
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	840(%rsp), %ymm12
	vmovdqa	%ymm9, 904(%rsp)
	vpandn	%ymm1, %ymm11, %ymm9
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpsrlq	$25, %ymm3, %ymm6
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm1, 1064(%rsp)
	vpsrlq	$2, %ymm0, %ymm1
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm1, %ymm0, %ymm0
	vpsllq	$39, %ymm3, %ymm3
	vpsrlq	$9, %ymm2, %ymm1
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm1, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm1
	vpxor	808(%rsp), %ymm13, %ymm3
	vpandn	%ymm1, %ymm2, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpxor	584(%rsp), %ymm6, %ymm10
	vpxor	%ymm10, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm10
	vpxor	1032(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm10, %ymm5, %ymm5
	vpandn	%ymm5, %ymm1, %ymm10
	vpxor	%ymm2, %ymm10, %ymm11
	vpxor	872(%rsp), %ymm7, %ymm10
	vmovdqa	%ymm11, 424(%rsp)
	vpxor	456(%rsp), %ymm12, %ymm13
	vpxor	%ymm10, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm10
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm11, %ymm14, %ymm14
	vpor	%ymm10, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm10
	vpandn	%ymm0, %ymm4, %ymm12
	vpandn	%ymm2, %ymm0, %ymm0
	vmovdqa	968(%rsp), %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	904(%rsp), %ymm8, %ymm1
	vpxor	488(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	520(%rsp), %ymm1
	vpxor	776(%rsp), %ymm1, %ymm11
	vpxor	%ymm9, %ymm12, %ymm1
	vpxor	%ymm10, %ymm13, %ymm13
	vpxor	%ymm1, %ymm11, %ymm11
	vpsllq	$1, %ymm13, %ymm4
	vpxor	552(%rsp), %ymm0, %ymm1
	vpxor	1000(%rsp), %ymm11, %ymm11
	vpxor	%ymm1, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm1
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm1, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm1, 936(%rsp)
	vpsllq	$1, %ymm11, %ymm1
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	936(%rsp), %ymm1, %ymm1
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm1, %ymm1
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm1, %ymm8
	vpxor	%ymm10, %ymm1, %ymm10
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm9, %ymm2, %ymm9
	vpxor	%ymm12, %ymm2, %ymm12
	vpor	%ymm13, %ymm3, %ymm3
	vpxor	1032(%rsp), %ymm5, %ymm13
	vpxor	%ymm11, %ymm3, %ymm3
	vpxor	%ymm15, %ymm4, %ymm11
	vbroadcastsd	88+KeccakF1600RoundConstants(%rip), %ymm15
	vpsrlq	$20, %ymm11, %ymm14
	vpsllq	$44, %ymm11, %ymm11
	vpxor	%ymm0, %ymm3, %ymm0
	vpor	%ymm14, %ymm11, %ymm11
	vpsrlq	$21, %ymm8, %ymm14
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm14, %ymm8, %ymm8
	vpandn	%ymm8, %ymm11, %ymm14
	vpxor	%ymm15, %ymm14, %ymm14
	vpxor	%ymm13, %ymm14, %ymm14
	vmovdqa	%ymm14, 1032(%rsp)
	vpsrlq	$43, %ymm9, %ymm14
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm14, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm14
	vpxor	%ymm11, %ymm14, %ymm15
	vpsrlq	$50, %ymm0, %ymm14
	vmovdqa	%ymm15, 616(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm14, %ymm0, %ymm0
	vpandn	%ymm0, %ymm9, %ymm14
	vpxor	%ymm8, %ymm14, %ymm8
	vmovdqa	%ymm8, 648(%rsp)
	vpandn	%ymm13, %ymm0, %ymm8
	vpandn	%ymm11, %ymm13, %ymm13
	vpxor	712(%rsp), %ymm5, %ymm11
	vpxor	%ymm0, %ymm13, %ymm0
	vpsrlq	$3, %ymm10, %ymm13
	vpxor	%ymm9, %ymm8, %ymm9
	vmovdqa	%ymm0, 680(%rsp)
	vpsllq	$61, %ymm10, %ymm10
	vpxor	776(%rsp), %ymm2, %ymm0
	vmovdqa	%ymm9, 936(%rsp)
	vpor	%ymm13, %ymm10, %ymm10
	vpsrlq	$36, %ymm0, %ymm8
	vpsllq	$28, %ymm0, %ymm0
	vpor	%ymm8, %ymm0, %ymm0
	vpxor	968(%rsp), %ymm3, %ymm8
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm8, %ymm9
	vpxor	%ymm0, %ymm9, %ymm9
	vmovdqa	%ymm9, %ymm14
	vpsrlq	$19, %ymm7, %ymm9
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpandn	%ymm10, %ymm7, %ymm13
	vpandn	%ymm7, %ymm11, %ymm9
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm10, %ymm11
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	%ymm10, %ymm0, %ymm0
	vpxor	%ymm7, %ymm11, %ymm15
	vpxor	%ymm8, %ymm9, %ymm9
	vmovdqa	%ymm13, 712(%rsp)
	vmovdqa	%ymm0, 968(%rsp)
	vpxor	392(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm15, 744(%rsp)
	vpsrlq	$63, %ymm0, %ymm7
	vpsllq	$1, %ymm0, %ymm0
	vpor	%ymm7, %ymm0, %ymm0
	vpxor	840(%rsp), %ymm1, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1000(%rsp), %ymm2, %ymm8
	vpsrlq	$39, %ymm8, %ymm10
	vpsllq	$25, %ymm8, %ymm8
	vpor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm10
	vpxor	%ymm0, %ymm10, %ymm11
	vpxor	1064(%rsp), %ymm3, %ymm10
	vmovdqa	%ymm11, 1000(%rsp)
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm11
	vpxor	%ymm7, %ymm11, %ymm15
	vpsrlq	$46, %ymm6, %ymm11
	vmovdqa	%ymm15, 840(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm11, %ymm6, %ymm6
	vpandn	%ymm6, %ymm10, %ymm11
	vpxor	%ymm8, %ymm11, %ymm11
	vpandn	%ymm0, %ymm6, %ymm8
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm10, %ymm8, %ymm15
	vpxor	%ymm6, %ymm0, %ymm10
	vmovdqa	%ymm10, 776(%rsp)
	vpxor	488(%rsp), %ymm3, %ymm0
	vpxor	872(%rsp), %ymm4, %ymm10
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	520(%rsp), %ymm2, %ymm2
	vpxor	552(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm14, 328(%rsp)
	vpxor	424(%rsp), %ymm4, %ymm4
	vpsrlq	$37, %ymm0, %ymm6
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm0
	vpxor	808(%rsp), %ymm5, %ymm6
	vpxor	584(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm0, %ymm7, %ymm8
	vpxor	904(%rsp), %ymm1, %ymm7
	vpxor	456(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm8, 808(%rsp)
	vpsrlq	$49, %ymm7, %ymm8
	vpsllq	$15, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm12, %ymm7, %ymm13
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm8, %ymm8
	vmovdqa	%ymm10, 872(%rsp)
	vpandn	%ymm0, %ymm12, %ymm10
	vpandn	%ymm6, %ymm0, %ymm0
	vpxor	%ymm12, %ymm0, %ymm6
	vpsrlq	$2, %ymm1, %ymm0
	vpxor	%ymm7, %ymm10, %ymm10
	vmovdqa	1000(%rsp), %ymm7
	vmovdqa	%ymm6, 1064(%rsp)
	vpsllq	$62, %ymm1, %ymm1
	vpsrlq	$25, %ymm3, %ymm6
	vpor	%ymm0, %ymm1, %ymm1
	vpsllq	$39, %ymm3, %ymm3
	vpsrlq	$9, %ymm2, %ymm0
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	%ymm14, %ymm7, %ymm3
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	808(%rsp), %ymm6, %ymm7
	vpxor	%ymm7, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm7
	vpxor	1032(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm7, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm7
	vpxor	%ymm2, %ymm7, %ymm14
	vpxor	840(%rsp), %ymm8, %ymm7
	vmovdqa	%ymm14, %ymm12
	vpxor	616(%rsp), %ymm9, %ymm14
	vmovdqa	%ymm12, 360(%rsp)
	vpxor	%ymm7, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm7
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	712(%rsp), %ymm12
	vpxor	648(%rsp), %ymm12, %ymm13
	vpor	%ymm7, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vpxor	872(%rsp), %ymm11, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	968(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm7, %ymm13, %ymm13
	vmovdqa	744(%rsp), %ymm0
	vpxor	936(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 424(%rsp)
	vpxor	680(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	776(%rsp), %ymm1, %ymm0
	vpxor	%ymm15, %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 904(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	904(%rsp), %ymm0, %ymm0
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm11, %ymm0, %ymm11
	vpxor	%ymm7, %ymm0, %ymm7
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1032(%rsp), %ymm5, %ymm12
	vbroadcastsd	96+KeccakF1600RoundConstants(%rip), %ymm14
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm11, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm11, %ymm11
	vpor	%ymm13, %ymm11, %ymm11
	vpandn	%ymm11, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 1032(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm11, %ymm13
	vpxor	%ymm9, %ymm13, %ymm13
	vmovdqa	%ymm13, 392(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm11, %ymm13, %ymm11
	vmovdqa	%ymm11, 456(%rsp)
	vpandn	%ymm12, %ymm1, %ymm11
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm7, %ymm12
	vpxor	%ymm10, %ymm11, %ymm10
	vmovdqa	%ymm1, 488(%rsp)
	vpsllq	$61, %ymm7, %ymm7
	vpxor	936(%rsp), %ymm2, %ymm1
	vpxor	1000(%rsp), %ymm5, %ymm11
	vmovdqa	%ymm10, 904(%rsp)
	vpor	%ymm12, %ymm7, %ymm7
	vpxor	968(%rsp), %ymm3, %ymm10
	vpsrlq	$36, %ymm1, %ymm9
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm9, %ymm1, %ymm1
	vpsrlq	$44, %ymm10, %ymm9
	vpsllq	$20, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 520(%rsp)
	vpsrlq	$19, %ymm8, %ymm9
	vpsllq	$45, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm7, %ymm8, %ymm12
	vpandn	%ymm8, %ymm11, %ymm9
	vpxor	%ymm11, %ymm12, %ymm11
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	424(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm11, 936(%rsp)
	vpandn	%ymm1, %ymm7, %ymm11
	vpandn	%ymm10, %ymm1, %ymm1
	vpxor	%ymm15, %ymm2, %ymm10
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm8, %ymm11, %ymm8
	vpxor	1064(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm1, 968(%rsp)
	vpxor	616(%rsp), %ymm4, %ymm1
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	744(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm8, 552(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	712(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm8
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm15
	vpandn	%ymm11, %ymm10, %ymm8
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm8, 584(%rsp)
	vpsrlq	$46, %ymm6, %ymm8
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm8
	vpxor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	680(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 616(%rsp)
	vpxor	872(%rsp), %ymm0, %ymm11
	vpxor	648(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1000(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	840(%rsp), %ymm4, %ymm10
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	328(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 680(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm14, 840(%rsp)
	vmovdqa	%ymm1, 1064(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	776(%rsp), %ymm3, %ymm3
	vpxor	808(%rsp), %ymm5, %ymm5
	vpxor	360(%rsp), %ymm4, %ymm4
	vpsllq	$62, %ymm0, %ymm0
	vpxor	392(%rsp), %ymm9, %ymm14
	vmovdqa	936(%rsp), %ymm12
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	520(%rsp), %ymm15, %ymm3
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	680(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1032(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm13
	vpxor	584(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm13, 296(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	456(%rsp), %ymm12, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	840(%rsp), %ymm8, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	968(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	552(%rsp), %ymm0
	vpxor	904(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 360(%rsp)
	vpxor	488(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	616(%rsp), %ymm1, %ymm0
	vpxor	1000(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1064(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 872(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	872(%rsp), %ymm0, %ymm0
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm0, %ymm8
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	104+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1032(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm13, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1032(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 648(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 424(%rsp)
	vpandn	%ymm12, %ymm1, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpxor	%ymm10, %ymm8, %ymm8
	vmovdqa	%ymm1, 744(%rsp)
	vpxor	904(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm8, 712(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpxor	968(%rsp), %ymm3, %ymm8
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm15, %ymm5, %ymm9
	vpsrlq	$61, %ymm9, %ymm10
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm10
	vpxor	%ymm1, %ymm10, %ymm15
	vpsrlq	$19, %ymm7, %ymm10
	vpsllq	$45, %ymm7, %ymm7
	vmovdqa	%ymm15, %ymm14
	vpor	%ymm10, %ymm7, %ymm7
	vpandn	%ymm7, %ymm9, %ymm10
	vpxor	%ymm8, %ymm10, %ymm15
	vpsrlq	$3, %ymm11, %ymm10
	vpsllq	$61, %ymm11, %ymm11
	vpor	%ymm10, %ymm11, %ymm11
	vpandn	%ymm11, %ymm7, %ymm10
	vpxor	%ymm9, %ymm10, %ymm9
	vmovdqa	%ymm9, 776(%rsp)
	vpandn	%ymm1, %ymm11, %ymm9
	vpandn	%ymm8, %ymm1, %ymm1
	vpxor	%ymm7, %ymm9, %ymm7
	vmovdqa	%ymm7, 808(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	392(%rsp), %ymm4, %ymm1
	vpxor	1000(%rsp), %ymm2, %ymm9
	vmovdqa	%ymm7, 872(%rsp)
	vmovdqa	%ymm14, 328(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	936(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm9, %ymm8
	vpsllq	$25, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm10
	vmovdqa	%ymm10, 904(%rsp)
	vpxor	1064(%rsp), %ymm3, %ymm10
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm7, %ymm8, %ymm11
	vpsrlq	$46, %ymm6, %ymm8
	vmovdqa	%ymm11, 936(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpxor	360(%rsp), %ymm2, %ymm11
	vpxor	552(%rsp), %ymm2, %ymm2
	vpor	%ymm8, %ymm6, %ymm6
	vpshufb	.LC1(%rip), %ymm11, %ymm11
	vpandn	%ymm6, %ymm10, %ymm8
	vpxor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm1, %ymm6, %ymm9
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm7
	vpxor	%ymm10, %ymm9, %ymm10
	vpxor	488(%rsp), %ymm3, %ymm1
	vpxor	584(%rsp), %ymm4, %ymm9
	vmovdqa	%ymm7, 1000(%rsp)
	vpxor	616(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm10, 968(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	840(%rsp), %ymm0, %ymm10
	vpxor	456(%rsp), %ymm0, %ymm0
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	520(%rsp), %ymm5, %ymm6
	vpxor	680(%rsp), %ymm5, %ymm5
	vpxor	296(%rsp), %ymm4, %ymm4
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm9, %ymm7
	vpsllq	$10, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm13
	vpsrlq	$49, %ymm10, %ymm7
	vmovdqa	%ymm13, 360(%rsp)
	vpsllq	$15, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm11, %ymm10, %ymm12
	vpandn	%ymm10, %ymm9, %ymm7
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm9, %ymm12
	vpandn	%ymm1, %ymm11, %ymm9
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpsrlq	$9, %ymm2, %ymm6
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	904(%rsp), %ymm10
	vmovdqa	%ymm1, 1064(%rsp)
	vpsllq	$55, %ymm2, %ymm2
	vpsrlq	$2, %ymm0, %ymm1
	vmovdqa	%ymm12, 616(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm1, %ymm0, %ymm0
	vpor	%ymm6, %ymm2, %ymm1
	vpsrlq	$25, %ymm3, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm14, %ymm10, %ymm2
	vpxor	648(%rsp), %ymm15, %ymm14
	vpandn	%ymm3, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpxor	%ymm13, %ymm6, %ymm10
	vmovdqa	776(%rsp), %ymm13
	vpxor	424(%rsp), %ymm13, %ymm13
	vpxor	%ymm10, %ymm2, %ymm2
	vpsrlq	$23, %ymm5, %ymm10
	vpxor	1032(%rsp), %ymm2, %ymm2
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm10, %ymm5, %ymm11
	vpandn	%ymm11, %ymm3, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vmovdqa	%ymm5, %ymm10
	vpxor	936(%rsp), %ymm7, %ymm5
	vmovdqa	%ymm10, 392(%rsp)
	vpxor	%ymm5, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm5
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm10, %ymm14, %ymm14
	vpor	%ymm5, %ymm4, %ymm4
	vpandn	%ymm4, %ymm11, %ymm10
	vpandn	%ymm0, %ymm4, %ymm5
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm10, %ymm10
	vpxor	%ymm12, %ymm8, %ymm3
	vpxor	%ymm11, %ymm5, %ymm5
	vpxor	%ymm3, %ymm13, %ymm13
	vpsllq	$1, %ymm14, %ymm11
	vpxor	%ymm4, %ymm0, %ymm0
	vmovdqa	808(%rsp), %ymm3
	vpxor	712(%rsp), %ymm3, %ymm12
	vpxor	%ymm9, %ymm5, %ymm3
	vpxor	%ymm10, %ymm13, %ymm13
	vmovdqa	872(%rsp), %ymm4
	vpxor	744(%rsp), %ymm4, %ymm1
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm3, %ymm12, %ymm12
	vpxor	1000(%rsp), %ymm0, %ymm3
	vpxor	968(%rsp), %ymm12, %ymm12
	vpxor	%ymm3, %ymm1, %ymm1
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1064(%rsp), %ymm1, %ymm1
	vpor	%ymm3, %ymm11, %ymm11
	vpsrlq	$63, %ymm13, %ymm3
	vpor	%ymm3, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm3
	vpxor	%ymm1, %ymm11, %ymm11
	vmovdqa	%ymm3, 840(%rsp)
	vpsllq	$1, %ymm12, %ymm3
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm6, %ymm11, %ymm6
	vpor	840(%rsp), %ymm3, %ymm3
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm3, %ymm3
	vpsrlq	$63, %ymm1, %ymm14
	vpsllq	$1, %ymm1, %ymm1
	vpxor	%ymm8, %ymm3, %ymm8
	vpxor	%ymm10, %ymm3, %ymm10
	vpor	%ymm14, %ymm1, %ymm1
	vpxor	%ymm13, %ymm1, %ymm1
	vpsrlq	$63, %ymm2, %ymm13
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm1, %ymm9
	vpxor	%ymm5, %ymm1, %ymm5
	vpor	%ymm13, %ymm2, %ymm2
	vpxor	1032(%rsp), %ymm11, %ymm13
	vpxor	%ymm12, %ymm2, %ymm2
	vpxor	%ymm15, %ymm4, %ymm12
	vbroadcastsd	112+KeccakF1600RoundConstants(%rip), %ymm15
	vpsrlq	$20, %ymm12, %ymm14
	vpsllq	$44, %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm0
	vpor	%ymm14, %ymm12, %ymm12
	vpsrlq	$21, %ymm8, %ymm14
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm14, %ymm8, %ymm8
	vpandn	%ymm8, %ymm12, %ymm14
	vpxor	%ymm15, %ymm14, %ymm14
	vpxor	%ymm13, %ymm14, %ymm15
	vpsrlq	$43, %ymm9, %ymm14
	vmovdqa	%ymm15, 1032(%rsp)
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm14, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm14
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	%ymm14, 680(%rsp)
	vpsrlq	$50, %ymm0, %ymm14
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm14, %ymm0, %ymm0
	vpandn	%ymm0, %ymm9, %ymm14
	vpxor	%ymm8, %ymm14, %ymm8
	vmovdqa	%ymm8, 456(%rsp)
	vpandn	%ymm13, %ymm0, %ymm8
	vpandn	%ymm12, %ymm13, %ymm13
	vpxor	904(%rsp), %ymm11, %ymm12
	vpxor	%ymm0, %ymm13, %ymm0
	vpsrlq	$3, %ymm10, %ymm13
	vpxor	%ymm9, %ymm8, %ymm9
	vmovdqa	%ymm0, 488(%rsp)
	vpsllq	$61, %ymm10, %ymm10
	vpxor	712(%rsp), %ymm1, %ymm0
	vmovdqa	%ymm9, 840(%rsp)
	vpor	%ymm13, %ymm10, %ymm10
	vpsrlq	$36, %ymm0, %ymm8
	vpsllq	$28, %ymm0, %ymm0
	vpor	%ymm8, %ymm0, %ymm0
	vpxor	872(%rsp), %ymm2, %ymm8
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpsrlq	$61, %ymm12, %ymm9
	vpsllq	$3, %ymm12, %ymm12
	vpor	%ymm9, %ymm12, %ymm12
	vpandn	%ymm12, %ymm8, %ymm9
	vpxor	%ymm0, %ymm9, %ymm15
	vpsrlq	$19, %ymm7, %ymm9
	vmovdqa	%ymm15, 520(%rsp)
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpandn	%ymm10, %ymm7, %ymm13
	vpandn	%ymm7, %ymm12, %ymm9
	vpxor	%ymm12, %ymm13, %ymm15
	vpandn	%ymm0, %ymm10, %ymm12
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	%ymm8, %ymm9, %ymm9
	vpxor	%ymm10, %ymm0, %ymm8
	vpxor	648(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm15, 712(%rsp)
	vpxor	968(%rsp), %ymm1, %ymm10
	vpxor	%ymm7, %ymm12, %ymm7
	vmovdqa	%ymm8, 872(%rsp)
	vpxor	1064(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm7, 552(%rsp)
	vpsrlq	$63, %ymm0, %ymm7
	vpsllq	$1, %ymm0, %ymm0
	vpshufb	.LC0(%rip), %ymm12, %ymm12
	vpor	%ymm7, %ymm0, %ymm0
	vpxor	776(%rsp), %ymm3, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm8
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 904(%rsp)
	vpandn	%ymm12, %ymm10, %ymm8
	vpxor	%ymm7, %ymm8, %ymm15
	vpsrlq	$46, %ymm6, %ymm8
	vmovdqa	%ymm15, 648(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm12, %ymm8
	vpxor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm0, %ymm6, %ymm10
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm7
	vpxor	%ymm12, %ymm10, %ymm10
	vmovdqa	%ymm10, 776(%rsp)
	vmovdqa	%ymm7, 584(%rsp)
	vpxor	744(%rsp), %ymm2, %ymm0
	vpxor	328(%rsp), %ymm11, %ymm10
	vpshufb	.LC1(%rip), %ymm5, %ymm5
	vpxor	936(%rsp), %ymm4, %ymm7
	vpxor	616(%rsp), %ymm3, %ymm12
	vpxor	424(%rsp), %ymm3, %ymm3
	vpsrlq	$37, %ymm0, %ymm6
	vpxor	808(%rsp), %ymm1, %ymm1
	vpxor	1000(%rsp), %ymm2, %ymm2
	vpsllq	$27, %ymm0, %ymm0
	vpxor	360(%rsp), %ymm11, %ymm11
	vpxor	392(%rsp), %ymm4, %ymm4
	vpor	%ymm6, %ymm0, %ymm0
	vpsrlq	$28, %ymm10, %ymm6
	vpsllq	$36, %ymm10, %ymm10
	vpor	%ymm6, %ymm10, %ymm10
	vpsrlq	$54, %ymm7, %ymm6
	vpsllq	$10, %ymm7, %ymm7
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm10, %ymm6
	vpxor	%ymm0, %ymm6, %ymm15
	vpsrlq	$49, %ymm12, %ymm6
	vpsllq	$15, %ymm12, %ymm12
	vpor	%ymm6, %ymm12, %ymm12
	vpandn	%ymm5, %ymm12, %ymm13
	vpandn	%ymm12, %ymm7, %ymm6
	vpxor	%ymm7, %ymm13, %ymm14
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm10, %ymm0, %ymm0
	vmovdqa	712(%rsp), %ymm13
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	%ymm5, %ymm0, %ymm12
	vmovdqa	%ymm14, 616(%rsp)
	vpxor	%ymm10, %ymm6, %ymm6
	vmovdqa	904(%rsp), %ymm14
	vpsrlq	$2, %ymm3, %ymm5
	vpsllq	$62, %ymm3, %ymm3
	vpxor	520(%rsp), %ymm14, %ymm10
	vpxor	456(%rsp), %ymm13, %ymm13
	vpor	%ymm5, %ymm3, %ymm0
	vmovdqa	%ymm12, 744(%rsp)
	vpsrlq	$9, %ymm1, %ymm3
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsrlq	$25, %ymm2, %ymm3
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vpandn	%ymm2, %ymm1, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm15, %ymm5, %ymm3
	vpxor	%ymm3, %ymm10, %ymm10
	vpsrlq	$23, %ymm11, %ymm3
	vpxor	1032(%rsp), %ymm10, %ymm14
	vpsllq	$41, %ymm11, %ymm11
	vmovdqa	%ymm14, 1064(%rsp)
	vpor	%ymm11, %ymm3, %ymm11
	vpxor	680(%rsp), %ymm9, %ymm14
	vpandn	%ymm11, %ymm2, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, %ymm10
	vpxor	648(%rsp), %ymm6, %ymm3
	vmovdqa	%ymm10, 424(%rsp)
	vpxor	%ymm3, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm3
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm10, %ymm14, %ymm14
	vpor	%ymm4, %ymm3, %ymm4
	vpandn	%ymm4, %ymm11, %ymm3
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	616(%rsp), %ymm8, %ymm2
	vpxor	%ymm2, %ymm13, %ymm13
	vpandn	%ymm0, %ymm4, %ymm2
	vpandn	%ymm1, %ymm0, %ymm0
	vmovdqa	872(%rsp), %ymm1
	vpxor	%ymm11, %ymm2, %ymm11
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm13, %ymm13
	vmovdqa	552(%rsp), %ymm2
	vmovdqa	%ymm11, 392(%rsp)
	vpsrlq	$63, %ymm13, %ymm4
	vpxor	840(%rsp), %ymm2, %ymm12
	vpxor	%ymm11, %ymm7, %ymm2
	vpxor	488(%rsp), %ymm1, %ymm11
	vpxor	584(%rsp), %ymm0, %ymm1
	vpxor	%ymm2, %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm2
	vpxor	776(%rsp), %ymm12, %ymm12
	vpxor	%ymm1, %ymm11, %ymm11
	vpsrlq	$63, %ymm14, %ymm1
	vpxor	744(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm1, %ymm1
	vpsllq	$1, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm10
	vpor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm11, %ymm1, %ymm1
	vpsrlq	$63, %ymm12, %ymm2
	vpxor	%ymm5, %ymm1, %ymm5
	vpxor	1064(%rsp), %ymm4, %ymm4
	vpor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm14, %ymm2, %ymm2
	vpsrlq	$63, %ymm11, %ymm14
	vpxor	%ymm9, %ymm4, %ymm9
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm8, %ymm2, %ymm8
	vpxor	%ymm6, %ymm4, %ymm6
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm2, %ymm3, %ymm3
	vmovdqa	1064(%rsp), %ymm14
	vpxor	%ymm13, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm10
	vpsrlq	$63, %ymm14, %ymm13
	vpxor	%ymm7, %ymm11, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1032(%rsp), %ymm1, %ymm12
	vbroadcastsd	120+KeccakF1600RoundConstants(%rip), %ymm14
	vpor	%ymm9, %ymm13, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm8, %ymm13, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 1064(%rsp)
	vpsrlq	$43, %ymm7, %ymm13
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 1032(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 1000(%rsp)
	vpandn	%ymm12, %ymm0, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm7, %ymm8, %ymm7
	vpxor	%ymm0, %ymm12, %ymm9
	vmovdqa	%ymm7, 968(%rsp)
	vpsrlq	$3, %ymm3, %ymm12
	vpsllq	$61, %ymm3, %ymm3
	vpxor	840(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm9, 936(%rsp)
	vpor	%ymm3, %ymm12, %ymm3
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpxor	872(%rsp), %ymm10, %ymm7
	vpsrlq	$44, %ymm7, %ymm8
	vpsllq	$20, %ymm7, %ymm7
	vpor	%ymm7, %ymm8, %ymm8
	vpxor	904(%rsp), %ymm1, %ymm7
	vpsrlq	$61, %ymm7, %ymm9
	vpsllq	$3, %ymm7, %ymm7
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vmovdqa	%ymm7, 904(%rsp)
	vpsrlq	$19, %ymm6, %ymm7
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm6
	vpandn	%ymm3, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm7
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm8, %ymm7, %ymm7
	vmovdqa	%ymm9, 872(%rsp)
	vpandn	%ymm0, %ymm3, %ymm9
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	%ymm3, %ymm0, %ymm8
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	680(%rsp), %ymm4, %ymm3
	vmovdqa	%ymm6, 840(%rsp)
	vpxor	712(%rsp), %ymm2, %ymm6
	vmovdqa	%ymm8, 808(%rsp)
	vpsrlq	$63, %ymm3, %ymm0
	vpsllq	$1, %ymm3, %ymm3
	vpor	%ymm3, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm3
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm3, %ymm3
	vpxor	776(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm8
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm8
	vpandn	%ymm8, %ymm3, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 776(%rsp)
	vpxor	744(%rsp), %ymm10, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm8, %ymm9
	vpxor	%ymm3, %ymm9, %ymm12
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm12, 744(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm8
	vpandn	%ymm3, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm6, %ymm8, %ymm12
	vpxor	488(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm5, 680(%rsp)
	vmovdqa	%ymm12, 712(%rsp)
	vpsrlq	$37, %ymm0, %ymm3
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm3, %ymm3
	vpxor	520(%rsp), %ymm1, %ymm0
	vpxor	%ymm15, %ymm1, %ymm1
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	648(%rsp), %ymm4, %ymm0
	vpsrlq	$54, %ymm0, %ymm8
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm8, %ymm8
	vpandn	%ymm8, %ymm5, %ymm0
	vpxor	%ymm3, %ymm0, %ymm0
	vmovdqa	%ymm0, 648(%rsp)
	vpxor	616(%rsp), %ymm2, %ymm0
	vpxor	456(%rsp), %ymm2, %ymm2
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	392(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm8, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpandn	%ymm3, %ymm0, %ymm8
	vpandn	%ymm5, %ymm3, %ymm3
	vpxor	%ymm0, %ymm3, %ymm0
	vpxor	%ymm12, %ymm8, %ymm8
	vmovdqa	%ymm14, %ymm13
	vmovdqa	%ymm0, 616(%rsp)
	vpsrlq	$2, %ymm2, %ymm0
	vpxor	552(%rsp), %ymm11, %ymm11
	vpxor	584(%rsp), %ymm10, %ymm10
	vmovdqa	%ymm13, 456(%rsp)
	vpsllq	$62, %ymm2, %ymm2
	vpor	%ymm2, %ymm0, %ymm0
	vpsrlq	$9, %ymm11, %ymm2
	vpsllq	$55, %ymm11, %ymm11
	vpor	%ymm11, %ymm2, %ymm11
	vpsrlq	$25, %ymm10, %ymm2
	vpsllq	$39, %ymm10, %ymm10
	vpor	%ymm10, %ymm2, %ymm10
	vmovdqa	776(%rsp), %ymm2
	vpxor	904(%rsp), %ymm2, %ymm12
	vpandn	%ymm10, %ymm11, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	648(%rsp), %ymm5, %ymm2
	vpxor	%ymm2, %ymm12, %ymm12
	vpsrlq	$23, %ymm1, %ymm2
	vpxor	1064(%rsp), %ymm12, %ymm12
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm1
	vpandn	%ymm1, %ymm10, %ymm2
	vpxor	%ymm11, %ymm2, %ymm15
	vpxor	744(%rsp), %ymm6, %ymm2
	vmovdqa	%ymm15, %ymm3
	vpxor	1032(%rsp), %ymm7, %ymm15
	vmovdqa	%ymm3, 392(%rsp)
	vpxor	%ymm2, %ymm15, %ymm15
	vpxor	%ymm3, %ymm15, %ymm15
	vpxor	424(%rsp), %ymm4, %ymm3
	vpxor	%ymm13, %ymm9, %ymm4
	vpsrlq	$62, %ymm3, %ymm2
	vpsllq	$2, %ymm3, %ymm3
	vpor	%ymm3, %ymm2, %ymm2
	vpandn	%ymm2, %ymm1, %ymm3
	vpxor	%ymm10, %ymm3, %ymm3
	vmovdqa	872(%rsp), %ymm10
	vpxor	1000(%rsp), %ymm10, %ymm14
	vpxor	%ymm4, %ymm14, %ymm14
	vpandn	%ymm0, %ymm2, %ymm4
	vpandn	%ymm11, %ymm0, %ymm0
	vmovdqa	808(%rsp), %ymm11
	vpxor	%ymm1, %ymm4, %ymm10
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm3, %ymm14, %ymm14
	vmovdqa	840(%rsp), %ymm4
	vpxor	968(%rsp), %ymm4, %ymm13
	vpsrlq	$63, %ymm15, %ymm2
	vpxor	%ymm10, %ymm8, %ymm1
	vmovdqa	%ymm10, 424(%rsp)
	vpxor	936(%rsp), %ymm11, %ymm10
	vpsllq	$1, %ymm14, %ymm4
	vpxor	%ymm1, %ymm13, %ymm13
	vpxor	680(%rsp), %ymm0, %ymm1
	vpxor	712(%rsp), %ymm13, %ymm13
	vpxor	%ymm1, %ymm10, %ymm10
	vpsllq	$1, %ymm15, %ymm1
	vpxor	616(%rsp), %ymm10, %ymm10
	vpor	%ymm1, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm1
	vpsllq	$1, %ymm13, %ymm11
	vpor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm10, %ymm2, %ymm2
	vpsrlq	$63, %ymm13, %ymm4
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpor	%ymm11, %ymm4, %ymm4
	vpsrlq	$63, %ymm10, %ymm11
	vpxor	%ymm1, %ymm7, %ymm7
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm1, %ymm6, %ymm6
	vpor	%ymm10, %ymm11, %ymm10
	vpsrlq	$63, %ymm12, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpsllq	$1, %ymm12, %ymm12
	vpxor	%ymm14, %ymm10, %ymm10
	vpxor	%ymm4, %ymm3, %ymm3
	vbroadcastsd	128+KeccakF1600RoundConstants(%rip), %ymm14
	vpor	%ymm12, %ymm11, %ymm12
	vpxor	%ymm10, %ymm8, %ymm8
	vpxor	1064(%rsp), %ymm2, %ymm11
	vpxor	%ymm13, %ymm12, %ymm12
	vpsrlq	$20, %ymm7, %ymm13
	vpsllq	$44, %ymm7, %ymm7
	vpxor	%ymm12, %ymm0, %ymm0
	vpor	%ymm7, %ymm13, %ymm7
	vpsrlq	$21, %ymm9, %ymm13
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm7, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	%ymm13, 1064(%rsp)
	vpsrlq	$43, %ymm8, %ymm13
	vpsllq	$21, %ymm8, %ymm8
	vpor	%ymm8, %ymm13, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm7, %ymm13, %ymm15
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm15, 584(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 552(%rsp)
	vpandn	%ymm11, %ymm0, %ymm9
	vpandn	%ymm7, %ymm11, %ymm11
	vpxor	968(%rsp), %ymm10, %ymm7
	vpxor	%ymm8, %ymm9, %ymm8
	vpxor	%ymm0, %ymm11, %ymm0
	vpxor	776(%rsp), %ymm2, %ymm9
	vmovdqa	%ymm8, 520(%rsp)
	vpxor	808(%rsp), %ymm12, %ymm8
	vmovdqa	%ymm0, 488(%rsp)
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$61, %ymm9, %ymm8
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm9
	vpxor	%ymm0, %ymm9, %ymm13
	vpsrlq	$19, %ymm6, %ymm9
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm9, %ymm6
	vpandn	%ymm6, %ymm8, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$3, %ymm3, %ymm9
	vpsllq	$61, %ymm3, %ymm3
	vpor	%ymm3, %ymm9, %ymm3
	vpandn	%ymm3, %ymm6, %ymm9
	vpxor	%ymm8, %ymm9, %ymm8
	vmovdqa	%ymm8, 968(%rsp)
	vpandn	%ymm0, %ymm3, %ymm8
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm6, %ymm8, %ymm6
	vmovdqa	%ymm6, 808(%rsp)
	vpxor	%ymm3, %ymm0, %ymm6
	vpxor	1032(%rsp), %ymm1, %ymm3
	vmovdqa	%ymm6, 776(%rsp)
	vpxor	872(%rsp), %ymm4, %ymm6
	vpsrlq	$63, %ymm3, %ymm0
	vpsllq	$1, %ymm3, %ymm3
	vpor	%ymm3, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm3
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm3, %ymm3
	vpxor	712(%rsp), %ymm10, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm3, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 1032(%rsp)
	vpxor	616(%rsp), %ymm12, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm8
	vpxor	%ymm3, %ymm8, %ymm11
	vpsrlq	$46, %ymm5, %ymm8
	vmovdqa	%ymm11, 872(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm8, %ymm5
	vpandn	%ymm5, %ymm6, %ymm8
	vpxor	%ymm7, %ymm8, %ymm8
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm3, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	936(%rsp), %ymm12, %ymm0
	vmovdqa	%ymm3, 616(%rsp)
	vmovdqa	%ymm7, 712(%rsp)
	vpsrlq	$37, %ymm0, %ymm3
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm3, %ymm3
	vpxor	904(%rsp), %ymm2, %ymm0
	vpxor	648(%rsp), %ymm2, %ymm2
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	744(%rsp), %ymm1, %ymm0
	vpxor	392(%rsp), %ymm1, %ymm1
	vpsrlq	$54, %ymm0, %ymm9
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm9, %ymm9
	vpandn	%ymm9, %ymm5, %ymm0
	vpxor	%ymm3, %ymm0, %ymm7
	vpxor	456(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm7, 936(%rsp)
	vpsrlq	$49, %ymm0, %ymm6
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpxor	424(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm13, 424(%rsp)
	vpandn	%ymm6, %ymm9, %ymm7
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm7, %ymm7
	vpandn	%ymm0, %ymm6, %ymm11
	vpxor	%ymm9, %ymm11, %ymm14
	vpandn	%ymm3, %ymm0, %ymm9
	vpandn	%ymm5, %ymm3, %ymm3
	vpxor	%ymm0, %ymm3, %ymm0
	vpxor	%ymm6, %ymm9, %ymm9
	vpxor	1000(%rsp), %ymm4, %ymm3
	vmovdqa	%ymm14, 904(%rsp)
	vpxor	840(%rsp), %ymm10, %ymm4
	vpsrlq	$23, %ymm2, %ymm5
	vmovdqa	%ymm0, 744(%rsp)
	vmovdqa	1032(%rsp), %ymm10
	vpsrlq	$2, %ymm3, %ymm0
	vpsllq	$62, %ymm3, %ymm3
	vpor	%ymm3, %ymm0, %ymm0
	vpsrlq	$9, %ymm4, %ymm3
	vpsllq	$55, %ymm4, %ymm4
	vpsllq	$41, %ymm2, %ymm2
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm2, %ymm5, %ymm5
	vpxor	680(%rsp), %ymm12, %ymm4
	vpxor	%ymm13, %ymm10, %ymm12
	vpxor	584(%rsp), %ymm15, %ymm10
	vpsrlq	$25, %ymm4, %ymm11
	vpsllq	$39, %ymm4, %ymm4
	vpor	%ymm4, %ymm11, %ymm11
	vpandn	%ymm11, %ymm3, %ymm6
	vpandn	%ymm5, %ymm11, %ymm2
	vpxor	%ymm0, %ymm6, %ymm4
	vmovdqa	%ymm4, 360(%rsp)
	vpxor	936(%rsp), %ymm4, %ymm4
	vpxor	%ymm4, %ymm12, %ymm12
	vpxor	%ymm3, %ymm2, %ymm4
	vpxor	872(%rsp), %ymm7, %ymm2
	vmovdqa	%ymm4, 328(%rsp)
	vpxor	1064(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm10, %ymm10
	vpxor	%ymm4, %ymm10, %ymm10
	vpsrlq	$62, %ymm1, %ymm4
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	968(%rsp), %ymm11
	vpxor	904(%rsp), %ymm8, %ymm2
	vpxor	552(%rsp), %ymm11, %ymm14
	vmovdqa	808(%rsp), %ymm11
	vpxor	520(%rsp), %ymm11, %ymm13
	vpxor	%ymm2, %ymm14, %ymm14
	vpandn	%ymm0, %ymm4, %ymm2
	vpandn	%ymm3, %ymm0, %ymm0
	vmovdqa	776(%rsp), %ymm3
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm1, %ymm14, %ymm14
	vpsrlq	$63, %ymm10, %ymm4
	vpsllq	$1, %ymm14, %ymm11
	vpxor	%ymm2, %ymm9, %ymm5
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	488(%rsp), %ymm3, %ymm5
	vpxor	616(%rsp), %ymm0, %ymm3
	vpxor	712(%rsp), %ymm13, %ymm13
	vpxor	%ymm3, %ymm5, %ymm5
	vpsllq	$1, %ymm10, %ymm3
	vpxor	744(%rsp), %ymm5, %ymm5
	vpor	%ymm3, %ymm4, %ymm4
	vpsrlq	$63, %ymm14, %ymm3
	vpsllq	$1, %ymm13, %ymm6
	vpor	%ymm11, %ymm3, %ymm3
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrlq	$63, %ymm13, %ymm11
	vpxor	%ymm12, %ymm3, %ymm3
	vpor	%ymm6, %ymm11, %ymm11
	vpxor	%ymm3, %ymm7, %ymm7
	vpxor	360(%rsp), %ymm4, %ymm6
	vpxor	%ymm10, %ymm11, %ymm11
	vpsrlq	$63, %ymm5, %ymm10
	vpsllq	$1, %ymm5, %ymm5
	vpxor	%ymm11, %ymm8, %ymm8
	vpxor	%ymm11, %ymm1, %ymm1
	vpor	%ymm5, %ymm10, %ymm10
	vpsrlq	$63, %ymm12, %ymm5
	vpsllq	$1, %ymm12, %ymm12
	vpxor	%ymm14, %ymm10, %ymm10
	vpxor	%ymm3, %ymm15, %ymm14
	vbroadcastsd	136+KeccakF1600RoundConstants(%rip), %ymm15
	vpor	%ymm12, %ymm5, %ymm5
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	1064(%rsp), %ymm4, %ymm12
	vpxor	%ymm13, %ymm5, %ymm5
	vpsrlq	$20, %ymm14, %ymm13
	vpsllq	$44, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpor	%ymm14, %ymm13, %ymm13
	vpsrlq	$21, %ymm8, %ymm14
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm8, %ymm14, %ymm8
	vpandn	%ymm8, %ymm13, %ymm14
	vpxor	%ymm15, %ymm14, %ymm14
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	%ymm14, 1064(%rsp)
	vpsrlq	$43, %ymm9, %ymm14
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm9, %ymm14, %ymm9
	vpandn	%ymm9, %ymm8, %ymm14
	vpxor	%ymm13, %ymm14, %ymm15
	vpsrlq	$50, %ymm0, %ymm14
	vmovdqa	%ymm15, 1000(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm14, %ymm0
	vpandn	%ymm0, %ymm9, %ymm14
	vpxor	%ymm8, %ymm14, %ymm14
	vpandn	%ymm12, %ymm0, %ymm8
	vpandn	%ymm13, %ymm12, %ymm12
	vpxor	%ymm9, %ymm8, %ymm9
	vpxor	%ymm0, %ymm12, %ymm13
	vpxor	520(%rsp), %ymm10, %ymm8
	vmovdqa	%ymm14, 840(%rsp)
	vmovdqa	%ymm9, 680(%rsp)
	vpxor	776(%rsp), %ymm5, %ymm9
	vmovdqa	%ymm13, 648(%rsp)
	vpsrlq	$36, %ymm8, %ymm0
	vpsllq	$28, %ymm8, %ymm8
	vpor	%ymm8, %ymm0, %ymm0
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpsrlq	$3, %ymm1, %ymm13
	vpor	%ymm9, %ymm8, %ymm8
	vpsllq	$61, %ymm1, %ymm1
	vpxor	1032(%rsp), %ymm4, %ymm9
	vpor	%ymm1, %ymm13, %ymm1
	vpsrlq	$61, %ymm9, %ymm12
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm9, %ymm12, %ymm12
	vpandn	%ymm12, %ymm8, %ymm9
	vpxor	%ymm0, %ymm9, %ymm9
	vmovdqa	%ymm9, 1032(%rsp)
	vpsrlq	$19, %ymm7, %ymm9
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm7, %ymm9, %ymm7
	vpandn	%ymm1, %ymm7, %ymm13
	vpandn	%ymm7, %ymm12, %ymm9
	vpxor	%ymm12, %ymm13, %ymm13
	vpandn	%ymm0, %ymm1, %ymm12
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	%ymm7, %ymm12, %ymm7
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	584(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm13, 776(%rsp)
	vmovdqa	%ymm7, 520(%rsp)
	vpxor	%ymm8, %ymm9, %ymm9
	vpxor	968(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm0, 456(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm7, %ymm1
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	712(%rsp), %ymm10, %ymm7
	vpsrlq	$39, %ymm7, %ymm12
	vpsllq	$25, %ymm7, %ymm7
	vpor	%ymm7, %ymm12, %ymm12
	vpandn	%ymm12, %ymm1, %ymm7
	vpxor	%ymm0, %ymm7, %ymm8
	vpxor	744(%rsp), %ymm5, %ymm7
	vmovdqa	%ymm8, %ymm15
	vpshufb	.LC0(%rip), %ymm7, %ymm7
	vpandn	%ymm7, %ymm12, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpsrlq	$46, %ymm6, %ymm8
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm6, %ymm7, %ymm8
	vpxor	%ymm12, %ymm8, %ymm8
	vpandn	%ymm0, %ymm6, %ymm12
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm7, %ymm12, %ymm7
	vpxor	%ymm6, %ymm0, %ymm6
	vmovdqa	%ymm7, 968(%rsp)
	vmovdqa	%ymm6, 744(%rsp)
	vpxor	488(%rsp), %ymm5, %ymm1
	vpxor	424(%rsp), %ymm4, %ymm6
	vpshufb	.LC1(%rip), %ymm2, %ymm2
	vmovdqa	%ymm14, 488(%rsp)
	vpsrlq	$37, %ymm1, %ymm0
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$28, %ymm6, %ymm1
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	872(%rsp), %ymm3, %ymm6
	vpsrlq	$54, %ymm6, %ymm7
	vpsllq	$10, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm12
	vpxor	904(%rsp), %ymm11, %ymm6
	vmovdqa	%ymm12, 872(%rsp)
	vpsrlq	$49, %ymm6, %ymm12
	vpsllq	$15, %ymm6, %ymm6
	vpor	%ymm6, %ymm12, %ymm12
	vpandn	%ymm12, %ymm7, %ymm6
	vpandn	%ymm2, %ymm12, %ymm13
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm7, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	552(%rsp), %ymm11, %ymm1
	vmovdqa	%ymm13, 424(%rsp)
	vpxor	%ymm2, %ymm0, %ymm2
	vpxor	%ymm14, %ymm6, %ymm14
	vpxor	%ymm13, %ymm8, %ymm13
	vmovdqa	%ymm2, 904(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	808(%rsp), %ymm10, %ymm1
	vpsrlq	$9, %ymm1, %ymm2
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpxor	616(%rsp), %ymm5, %ymm1
	vmovdqa	%ymm15, 616(%rsp)
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpxor	1032(%rsp), %ymm15, %ymm1
	vpandn	%ymm11, %ymm2, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	872(%rsp), %ymm5, %ymm10
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	936(%rsp), %ymm4, %ymm1
	vpxor	1064(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm4
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpandn	%ymm4, %ymm11, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, %ymm12
	vpxor	1000(%rsp), %ymm9, %ymm1
	vmovdqa	%ymm12, 392(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	328(%rsp), %ymm3, %ymm1
	vpxor	%ymm12, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm3
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm4, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	776(%rsp), %ymm11
	vpxor	840(%rsp), %ymm11, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm3, %ymm11
	vpandn	%ymm2, %ymm0, %ymm0
	vmovdqa	456(%rsp), %ymm2
	vpxor	%ymm4, %ymm11, %ymm15
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	520(%rsp), %ymm11
	vpxor	680(%rsp), %ymm11, %ymm4
	vpxor	%ymm3, %ymm0, %ymm11
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	%ymm15, %ymm7, %ymm12
	vpxor	648(%rsp), %ymm2, %ymm2
	vpxor	%ymm4, %ymm12, %ymm12
	vmovdqa	%ymm11, 936(%rsp)
	vpxor	744(%rsp), %ymm11, %ymm11
	vpxor	968(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpxor	904(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm0
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm0, %ymm4, %ymm4
	vpxor	%ymm2, %ymm9, %ymm9
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm8, %ymm8
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vbroadcastsd	144+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1064(%rsp), %ymm3, %ymm12
	vpor	%ymm9, %ymm13, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm8, %ymm13, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm13
	vmovdqa	%ymm13, 1064(%rsp)
	vpxor	936(%rsp), %ymm10, %ymm0
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 936(%rsp)
	vpandn	%ymm12, %ymm0, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm7, %ymm8, %ymm7
	vpxor	%ymm0, %ymm12, %ymm0
	vpxor	456(%rsp), %ymm10, %ymm8
	vmovdqa	%ymm7, 808(%rsp)
	vpsrlq	$3, %ymm1, %ymm12
	vpsllq	$61, %ymm1, %ymm1
	vpxor	680(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm0, 712(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	616(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 680(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 616(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm6, %ymm9, %ymm9
	vpxor	1000(%rsp), %ymm2, %ymm1
	vpxor	776(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm0, 552(%rsp)
	vmovdqa	%ymm9, 584(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	968(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 1000(%rsp)
	vpxor	904(%rsp), %ymm10, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 968(%rsp)
	vpsrlq	$46, %ymm5, %ymm9
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	648(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm5, 776(%rsp)
	vmovdqa	%ymm7, 904(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	1032(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	488(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm6
	vpxor	424(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm6, 1032(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	%ymm11, %ymm15, %ymm0
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm5, %ymm6, %ymm6
	vpxor	%ymm7, %ymm13, %ymm15
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm13
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	840(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm15, 648(%rsp)
	vmovdqa	%ymm13, 488(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	520(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	744(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	1032(%rsp), %ymm5, %ymm10
	vmovdqa	1000(%rsp), %ymm13
	vmovdqa	%ymm14, 840(%rsp)
	vpxor	680(%rsp), %ymm13, %ymm1
	vpxor	648(%rsp), %ymm9, %ymm13
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	872(%rsp), %ymm3, %ymm1
	vpxor	%ymm14, %ymm10, %ymm10
	vpxor	968(%rsp), %ymm6, %ymm14
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm12
	vpxor	1064(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm12, 424(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	392(%rsp), %ymm2, %ymm1
	vpxor	%ymm12, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	616(%rsp), %ymm11
	vpxor	936(%rsp), %ymm11, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm3
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	584(%rsp), %ymm11
	vmovdqa	552(%rsp), %ymm2
	vpxor	%ymm3, %ymm7, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	712(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm3, 392(%rsp)
	vpxor	808(%rsp), %ymm11, %ymm3
	vpxor	776(%rsp), %ymm0, %ymm11
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	%ymm2, %ymm11, %ymm11
	vpxor	904(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm2
	vpxor	488(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vbroadcastsd	152+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	840(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 872(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 840(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 744(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm0, %ymm12, %ymm8
	vpsrlq	$3, %ymm1, %ymm12
	vpxor	%ymm7, %ymm9, %ymm9
	vpxor	808(%rsp), %ymm11, %ymm7
	vpsllq	$61, %ymm1, %ymm1
	vmovdqa	%ymm8, 456(%rsp)
	vpxor	552(%rsp), %ymm10, %ymm8
	vmovdqa	%ymm9, 520(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1000(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm13
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm7, %ymm8, %ymm8
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	%ymm1, %ymm0, %ymm7
	vmovdqa	%ymm13, 1000(%rsp)
	vmovdqa	%ymm6, 808(%rsp)
	vmovdqa	%ymm7, 552(%rsp)
	vpxor	1064(%rsp), %ymm2, %ymm1
	vpxor	616(%rsp), %ymm4, %ymm6
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	904(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm13
	vpxor	488(%rsp), %ymm10, %ymm6
	vmovdqa	%ymm13, 1064(%rsp)
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm15
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm15, 904(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm6, %ymm7, %ymm13
	vpxor	%ymm5, %ymm0, %ymm7
	vpxor	712(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm7, 488(%rsp)
	vmovdqa	%ymm13, 616(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	680(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	968(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 968(%rsp)
	vpxor	648(%rsp), %ymm4, %ymm0
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	392(%rsp), %ymm11, %ymm0
	vmovdqa	%ymm14, 392(%rsp)
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	936(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm13, 712(%rsp)
	vmovdqa	%ymm0, %ymm15
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	584(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	776(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vmovdqa	1064(%rsp), %ymm1
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm14, %ymm1, %ymm1
	vpxor	968(%rsp), %ymm5, %ymm10
	vpxor	904(%rsp), %ymm6, %ymm14
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	1032(%rsp), %ymm3, %ymm1
	vpxor	872(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm13
	vpxor	840(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm13, 360(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	424(%rsp), %ymm2, %ymm1
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	712(%rsp), %ymm9, %ymm13
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	1000(%rsp), %ymm11
	vpxor	744(%rsp), %ymm11, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm3
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	%ymm3, 328(%rsp)
	vpxor	%ymm3, %ymm7, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vmovdqa	808(%rsp), %ymm11
	vmovdqa	552(%rsp), %ymm2
	vpxor	520(%rsp), %ymm11, %ymm3
	vmovdqa	%ymm15, 424(%rsp)
	vpxor	488(%rsp), %ymm0, %ymm11
	vpxor	456(%rsp), %ymm2, %ymm2
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	616(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpxor	%ymm15, %ymm11, %ymm11
	vpor	%ymm4, %ymm2, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vbroadcastsd	160+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	872(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 1032(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 936(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 872(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	552(%rsp), %ymm10, %ymm8
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	%ymm0, %ymm12, %ymm0
	vmovdqa	%ymm7, 776(%rsp)
	vpsrlq	$3, %ymm1, %ymm12
	vpsllq	$61, %ymm1, %ymm1
	vpxor	520(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm0, 680(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1064(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 1064(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 648(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm7
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	840(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 584(%rsp)
	vpxor	1000(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm7, 552(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	616(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm13
	vpxor	424(%rsp), %ymm10, %ymm6
	vmovdqa	%ymm13, 1000(%rsp)
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 840(%rsp)
	vpsrlq	$46, %ymm5, %ymm9
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm6, %ymm7, %ymm6
	vpxor	456(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm5, 520(%rsp)
	vmovdqa	%ymm6, 616(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	392(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	904(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm14
	vpxor	712(%rsp), %ymm4, %ymm0
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	328(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm7
	vmovdqa	%ymm7, %ymm13
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	744(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm13, 456(%rsp)
	vmovdqa	%ymm0, %ymm15
	vpxor	%ymm13, %ymm9, %ymm13
	vmovdqa	%ymm15, 424(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	808(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	488(%rsp), %ymm10, %ymm1
	vmovdqa	%ymm14, 488(%rsp)
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vmovdqa	1000(%rsp), %ymm1
	vpxor	1064(%rsp), %ymm1, %ymm1
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm14, %ymm5, %ymm10
	vpxor	840(%rsp), %ymm6, %ymm14
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	968(%rsp), %ymm3, %ymm1
	vpxor	1032(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vmovdqa	%ymm1, %ymm12
	vpxor	936(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm12, 392(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	360(%rsp), %ymm2, %ymm1
	vpxor	%ymm12, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	648(%rsp), %ymm11
	vpxor	872(%rsp), %ymm11, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm11
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	552(%rsp), %ymm2
	vmovdqa	%ymm11, 360(%rsp)
	vpxor	%ymm11, %ymm7, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vmovdqa	584(%rsp), %ymm11
	vpxor	680(%rsp), %ymm2, %ymm2
	vpxor	776(%rsp), %ymm11, %ymm3
	vpxor	520(%rsp), %ymm0, %ymm11
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	616(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpxor	%ymm15, %ymm11, %ymm11
	vpor	%ymm4, %ymm2, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vbroadcastsd	168+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1032(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1032(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm13
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm0, %ymm12, %ymm8
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm13, 968(%rsp)
	vmovdqa	%ymm9, 904(%rsp)
	vmovdqa	%ymm8, 808(%rsp)
	vpxor	776(%rsp), %ymm11, %ymm7
	vpxor	552(%rsp), %ymm10, %ymm8
	vpxor	1000(%rsp), %ymm3, %ymm9
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$61, %ymm9, %ymm8
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm9
	vpxor	%ymm0, %ymm9, %ymm15
	vpsrlq	$19, %ymm6, %ymm9
	vmovdqa	%ymm15, 1000(%rsp)
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm9, %ymm6
	vpandn	%ymm6, %ymm8, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$3, %ymm1, %ymm9
	vpsllq	$61, %ymm1, %ymm1
	vpor	%ymm1, %ymm9, %ymm1
	vpandn	%ymm1, %ymm6, %ymm9
	vpxor	%ymm8, %ymm9, %ymm8
	vmovdqa	%ymm8, 776(%rsp)
	vpandn	%ymm0, %ymm1, %ymm8
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm7
	vpxor	%ymm6, %ymm8, %ymm6
	vpxor	936(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 744(%rsp)
	vpxor	648(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm7, 712(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	616(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm9
	vpxor	424(%rsp), %ymm10, %ymm6
	vmovdqa	%ymm9, 936(%rsp)
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 648(%rsp)
	vpsrlq	$46, %ymm5, %ymm8
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm8, %ymm5
	vpandn	%ymm5, %ymm6, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm7, 616(%rsp)
	vpxor	%ymm5, %ymm0, %ymm7
	vpxor	680(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm7, 552(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	1064(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	840(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 1064(%rsp)
	vpxor	456(%rsp), %ymm4, %ymm0
	vpsrlq	$49, %ymm0, %ymm6
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm5, %ymm9, %ymm0
	vmovdqa	%ymm0, 840(%rsp)
	vpxor	360(%rsp), %ymm11, %ymm0
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpandn	%ymm0, %ymm6, %ymm8
	vpxor	%ymm7, %ymm8, %ymm13
	vmovdqa	%ymm13, 680(%rsp)
	vpandn	%ymm1, %ymm0, %ymm13
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpxor	%ymm6, %ymm13, %ymm13
	vmovdqa	%ymm1, %ymm9
	vpxor	872(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm14, 872(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	584(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	520(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm6
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm6, %ymm6
	vmovdqa	936(%rsp), %ymm1
	vpxor	1000(%rsp), %ymm1, %ymm1
	vpandn	%ymm6, %ymm4, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vpxor	1064(%rsp), %ymm7, %ymm10
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	488(%rsp), %ymm3, %ymm1
	vmovdqa	776(%rsp), %ymm11
	vmovdqa	%ymm9, 424(%rsp)
	vpxor	%ymm14, %ymm10, %ymm10
	vmovdqa	840(%rsp), %ymm14
	vpxor	648(%rsp), %ymm14, %ymm8
	vpxor	680(%rsp), %ymm12, %ymm14
	vpsrlq	$23, %ymm1, %ymm5
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm5, %ymm5
	vpandn	%ymm5, %ymm6, %ymm1
	vpxor	%ymm4, %ymm1, %ymm3
	vpxor	1032(%rsp), %ymm15, %ymm1
	vmovdqa	%ymm3, 360(%rsp)
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	392(%rsp), %ymm2, %ymm1
	vpxor	968(%rsp), %ymm11, %ymm2
	vpxor	%ymm3, %ymm8, %ymm8
	vpsrlq	$62, %ymm1, %ymm3
	vpsllq	$2, %ymm1, %ymm1
	vpxor	%ymm2, %ymm14, %ymm14
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm0, %ymm3, %ymm2
	vpandn	%ymm3, %ymm5, %ymm1
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm3, %ymm0, %ymm0
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	744(%rsp), %ymm5
	vpxor	%ymm2, %ymm13, %ymm11
	vpsrlq	$63, %ymm8, %ymm4
	vpxor	%ymm1, %ymm14, %ymm14
	vmovdqa	712(%rsp), %ymm3
	vpxor	904(%rsp), %ymm5, %ymm5
	vpsllq	$1, %ymm14, %ymm6
	vpxor	808(%rsp), %ymm3, %ymm3
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	552(%rsp), %ymm0, %ymm5
	vpxor	616(%rsp), %ymm11, %ymm11
	vpxor	%ymm3, %ymm5, %ymm5
	vpsllq	$1, %ymm8, %ymm3
	vpor	%ymm3, %ymm4, %ymm4
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	%ymm9, %ymm5, %ymm5
	vpor	%ymm6, %ymm3, %ymm3
	vpsllq	$1, %ymm11, %ymm9
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm6
	vpxor	%ymm10, %ymm3, %ymm3
	vpxor	%ymm4, %ymm7, %ymm7
	vpor	%ymm9, %ymm6, %ymm6
	vpxor	840(%rsp), %ymm3, %ymm9
	vpxor	%ymm8, %ymm6, %ymm6
	vpsrlq	$63, %ymm5, %ymm8
	vpsllq	$1, %ymm5, %ymm5
	vpxor	%ymm6, %ymm12, %ymm12
	vpxor	%ymm6, %ymm1, %ymm1
	vpor	%ymm5, %ymm8, %ymm8
	vpsrlq	$63, %ymm10, %ymm5
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm14, %ymm8, %ymm8
	vpxor	%ymm3, %ymm15, %ymm14
	vbroadcastsd	176+KeccakF1600RoundConstants(%rip), %ymm15
	vpor	%ymm10, %ymm5, %ymm5
	vpxor	%ymm8, %ymm13, %ymm13
	vpxor	%ymm8, %ymm2, %ymm2
	vpxor	872(%rsp), %ymm4, %ymm10
	vpxor	%ymm11, %ymm5, %ymm5
	vpsrlq	$20, %ymm14, %ymm11
	vpsllq	$44, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpor	%ymm14, %ymm11, %ymm11
	vpsrlq	$21, %ymm12, %ymm14
	vpsllq	$43, %ymm12, %ymm12
	vpor	%ymm12, %ymm14, %ymm12
	vpandn	%ymm12, %ymm11, %ymm14
	vpxor	%ymm15, %ymm14, %ymm14
	vpxor	%ymm10, %ymm14, %ymm15
	vpsrlq	$43, %ymm13, %ymm14
	vmovdqa	%ymm15, 872(%rsp)
	vpsllq	$21, %ymm13, %ymm13
	vpor	%ymm13, %ymm14, %ymm13
	vpandn	%ymm13, %ymm12, %ymm14
	vpxor	%ymm11, %ymm14, %ymm14
	vmovdqa	%ymm14, 584(%rsp)
	vpsrlq	$50, %ymm0, %ymm14
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm14, %ymm0
	vpandn	%ymm0, %ymm13, %ymm14
	vpxor	%ymm12, %ymm14, %ymm12
	vmovdqa	%ymm12, 520(%rsp)
	vpandn	%ymm10, %ymm0, %ymm12
	vpandn	%ymm11, %ymm10, %ymm10
	vpxor	712(%rsp), %ymm5, %ymm11
	vpxor	%ymm0, %ymm10, %ymm10
	vpxor	%ymm13, %ymm12, %ymm13
	vpxor	936(%rsp), %ymm4, %ymm12
	vmovdqa	%ymm10, 488(%rsp)
	vpxor	904(%rsp), %ymm8, %ymm10
	vpsrlq	$36, %ymm10, %ymm0
	vpsllq	$28, %ymm10, %ymm10
	vpor	%ymm10, %ymm0, %ymm0
	vpsrlq	$44, %ymm11, %ymm10
	vpsllq	$20, %ymm11, %ymm11
	vpor	%ymm11, %ymm10, %ymm10
	vpsrlq	$61, %ymm12, %ymm11
	vpsllq	$3, %ymm12, %ymm12
	vpor	%ymm12, %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm12
	vpxor	%ymm0, %ymm12, %ymm15
	vpsrlq	$19, %ymm9, %ymm12
	vmovdqa	%ymm15, 936(%rsp)
	vpsllq	$45, %ymm9, %ymm9
	vpor	%ymm9, %ymm12, %ymm9
	vpandn	%ymm9, %ymm11, %ymm12
	vpxor	%ymm10, %ymm12, %ymm12
	vmovdqa	%ymm12, 904(%rsp)
	vpsrlq	$3, %ymm1, %ymm12
	vpsllq	$61, %ymm1, %ymm1
	vpor	%ymm1, %ymm12, %ymm1
	vpandn	%ymm1, %ymm9, %ymm12
	vpxor	%ymm11, %ymm12, %ymm14
	vpandn	%ymm0, %ymm1, %ymm11
	vpandn	%ymm10, %ymm0, %ymm0
	vmovdqa	%ymm14, 840(%rsp)
	vpxor	%ymm9, %ymm11, %ymm9
	vmovdqa	%ymm9, 712(%rsp)
	vpxor	%ymm1, %ymm0, %ymm9
	vpxor	1032(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm9, 456(%rsp)
	vpxor	776(%rsp), %ymm6, %ymm9
	vpxor	424(%rsp), %ymm5, %ymm10
	vpshufb	.LC1(%rip), %ymm2, %ymm2
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm9, %ymm1
	vpsllq	$6, %ymm9, %ymm9
	vpor	%ymm9, %ymm1, %ymm1
	vpxor	616(%rsp), %ymm8, %ymm9
	vpsrlq	$39, %ymm9, %ymm11
	vpsllq	$25, %ymm9, %ymm9
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm1, %ymm9
	vpxor	%ymm0, %ymm9, %ymm9
	vmovdqa	%ymm9, %ymm15
	vpandn	%ymm10, %ymm11, %ymm9
	vpxor	%ymm1, %ymm9, %ymm14
	vpsrlq	$46, %ymm7, %ymm9
	vmovdqa	%ymm14, 1032(%rsp)
	vpsllq	$18, %ymm7, %ymm7
	vpor	%ymm7, %ymm9, %ymm7
	vpandn	%ymm7, %ymm10, %ymm9
	vpxor	%ymm11, %ymm9, %ymm9
	vpandn	%ymm0, %ymm7, %ymm11
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm7, %ymm0, %ymm1
	vpxor	%ymm10, %ymm11, %ymm10
	vmovdqa	%ymm1, 616(%rsp)
	vpxor	808(%rsp), %ymm5, %ymm1
	vmovdqa	%ymm10, 776(%rsp)
	vpsrlq	$37, %ymm1, %ymm0
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	1000(%rsp), %ymm4, %ymm1
	vpsrlq	$28, %ymm1, %ymm10
	vpsllq	$36, %ymm1, %ymm1
	vpor	%ymm1, %ymm10, %ymm10
	vpxor	648(%rsp), %ymm3, %ymm1
	vpsrlq	$54, %ymm1, %ymm7
	vpsllq	$10, %ymm1, %ymm1
	vpor	%ymm1, %ymm7, %ymm7
	vpandn	%ymm7, %ymm10, %ymm1
	vpxor	%ymm0, %ymm1, %ymm11
	vpxor	680(%rsp), %ymm6, %ymm1
	vmovdqa	%ymm11, %ymm14
	vpsrlq	$49, %ymm1, %ymm11
	vpsllq	$15, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpandn	%ymm2, %ymm11, %ymm12
	vpandn	%ymm11, %ymm7, %ymm1
	vpxor	%ymm7, %ymm12, %ymm7
	vpxor	%ymm10, %ymm1, %ymm1
	vmovdqa	840(%rsp), %ymm12
	vmovdqa	%ymm7, 1000(%rsp)
	vpandn	%ymm0, %ymm2, %ymm7
	vpandn	%ymm10, %ymm0, %ymm0
	vpxor	%ymm11, %ymm7, %ymm7
	vpxor	%ymm2, %ymm0, %ymm11
	vpxor	968(%rsp), %ymm6, %ymm0
	vmovdqa	%ymm15, 968(%rsp)
	vmovdqa	%ymm11, 808(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpxor	744(%rsp), %ymm8, %ymm0
	vmovdqa	%ymm14, 744(%rsp)
	vpsrlq	$9, %ymm0, %ymm2
	vpsllq	$55, %ymm0, %ymm0
	vpor	%ymm0, %ymm2, %ymm2
	vpxor	552(%rsp), %ymm5, %ymm0
	vpxor	1032(%rsp), %ymm1, %ymm5
	vpsrlq	$25, %ymm0, %ymm11
	vpsllq	$39, %ymm0, %ymm0
	vpor	%ymm0, %ymm11, %ymm11
	vpandn	%ymm11, %ymm2, %ymm0
	vpxor	%ymm6, %ymm0, %ymm8
	vpxor	936(%rsp), %ymm15, %ymm0
	vpxor	%ymm14, %ymm8, %ymm10
	vmovdqa	904(%rsp), %ymm14
	vpxor	%ymm0, %ymm10, %ymm10
	vpxor	1064(%rsp), %ymm4, %ymm0
	vpxor	872(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm0, %ymm4
	vpsllq	$41, %ymm0, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpandn	%ymm4, %ymm11, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, %ymm15
	vpxor	584(%rsp), %ymm14, %ymm0
	vpxor	1000(%rsp), %ymm9, %ymm14
	vmovdqa	%ymm15, 1064(%rsp)
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	360(%rsp), %ymm3, %ymm0
	vpxor	%ymm15, %ymm5, %ymm5
	vpsrlq	$62, %ymm0, %ymm3
	vpsllq	$2, %ymm0, %ymm0
	vpor	%ymm0, %ymm3, %ymm3
	vpandn	%ymm3, %ymm4, %ymm0
	vpxor	%ymm11, %ymm0, %ymm0
	vpxor	520(%rsp), %ymm12, %ymm11
	vpxor	%ymm11, %ymm14, %ymm14
	vpandn	%ymm6, %ymm3, %ymm11
	vpandn	%ymm2, %ymm6, %ymm6
	vpxor	%ymm4, %ymm11, %ymm4
	vpxor	%ymm3, %ymm6, %ymm6
	vpxor	%ymm0, %ymm14, %ymm14
	vpsrlq	$63, %ymm5, %ymm3
	vpsrlq	$63, %ymm14, %ymm12
	vpxor	%ymm4, %ymm7, %ymm11
	vmovdqa	%ymm4, 680(%rsp)
	vpxor	712(%rsp), %ymm13, %ymm4
	vpxor	%ymm4, %ymm11, %ymm11
	vpxor	776(%rsp), %ymm11, %ymm11
	vpxor	616(%rsp), %ymm6, %ymm4
	vmovdqa	456(%rsp), %ymm2
	vpxor	488(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm11, %ymm15
	vpxor	%ymm2, %ymm4, %ymm4
	vpsllq	$1, %ymm5, %ymm2
	vpxor	808(%rsp), %ymm4, %ymm4
	vpor	%ymm2, %ymm3, %ymm3
	vpsllq	$1, %ymm14, %ymm2
	vpor	%ymm2, %ymm12, %ymm12
	vpsrlq	$63, %ymm11, %ymm2
	vpxor	%ymm4, %ymm3, %ymm3
	vpor	%ymm15, %ymm2, %ymm2
	vpxor	%ymm10, %ymm12, %ymm12
	vpxor	%ymm5, %ymm2, %ymm2
	vpsrlq	$63, %ymm4, %ymm5
	vpxor	%ymm12, %ymm1, %ymm1
	vpsllq	$1, %ymm4, %ymm4
	vpxor	%ymm2, %ymm9, %ymm9
	vpxor	%ymm2, %ymm0, %ymm0
	vpor	%ymm4, %ymm5, %ymm5
	vpsrlq	$63, %ymm10, %ymm4
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm14, %ymm5, %ymm5
	vpxor	872(%rsp), %ymm3, %ymm14
	vpor	%ymm10, %ymm4, %ymm4
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	904(%rsp), %ymm12, %ymm10
	vmovdqa	%ymm14, 904(%rsp)
	vpxor	%ymm11, %ymm4, %ymm4
	vpsrlq	$20, %ymm10, %ymm11
	vpsllq	$44, %ymm10, %ymm10
	vpxor	%ymm4, %ymm6, %ymm6
	vpor	%ymm10, %ymm11, %ymm11
	vpsrlq	$21, %ymm9, %ymm10
	vmovdqa	%ymm11, 872(%rsp)
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm10, %ymm10
	vpsrlq	$43, %ymm7, %ymm9
	vpsllq	$21, %ymm7, %ymm7
	vpandn	%ymm10, %ymm11, %ymm15
	vmovdqa	%ymm10, 648(%rsp)
	vmovdqa	%ymm15, 296(%rsp)
	vpor	%ymm7, %ymm9, %ymm9
	vbroadcastsd	184+KeccakF1600RoundConstants(%rip), %ymm15
	vmovdqa	%ymm9, 552(%rsp)
	vpandn	%ymm9, %ymm10, %ymm7
	vmovdqa	%ymm7, 232(%rsp)
	vpsrlq	$50, %ymm6, %ymm7
	vpsllq	$14, %ymm6, %ymm6
	vmovapd	%ymm15, 264(%rsp)
	vpor	%ymm6, %ymm7, %ymm6
	vmovdqa	%ymm6, 424(%rsp)
	vpandn	%ymm6, %ymm9, %ymm15
	vpandn	%ymm14, %ymm6, %ymm6
	vmovdqa	%ymm6, 168(%rsp)
	vpandn	%ymm11, %ymm14, %ymm6
	vmovdqa	%ymm6, 136(%rsp)
	vpxor	%ymm5, %ymm13, %ymm6
	vmovdqa	%ymm15, 200(%rsp)
	vpsrlq	$36, %ymm6, %ymm7
	vpsllq	$28, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm13
	vpxor	456(%rsp), %ymm4, %ymm6
	vpsrlq	$44, %ymm6, %ymm7
	vpsllq	$20, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpxor	968(%rsp), %ymm3, %ymm6
	vmovdqa	%ymm13, 968(%rsp)
	vmovdqa	%ymm7, %ymm11
	vpsrlq	$61, %ymm6, %ymm7
	vpsllq	$3, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm7, %ymm6
	vmovdqa	%ymm11, %ymm7
	vpandn	%ymm6, %ymm7, %ymm15
	vmovdqa	%ymm6, %ymm11
	vmovdqa	%ymm7, 456(%rsp)
	vpandn	%ymm7, %ymm13, %ymm7
	vpsrlq	$19, %ymm1, %ymm6
	vpsllq	$45, %ymm1, %ymm1
	vmovdqa	%ymm15, 104(%rsp)
	vpor	%ymm1, %ymm6, %ymm1
	vmovdqa	%ymm7, -24(%rsp)
	vmovdqa	%ymm11, 392(%rsp)
	vmovdqa	%ymm1, %ymm6
	vpandn	%ymm1, %ymm11, %ymm1
	vmovdqa	%ymm1, 72(%rsp)
	vpsrlq	$3, %ymm0, %ymm1
	vpsllq	$61, %ymm0, %ymm0
	vmovdqa	%ymm6, 360(%rsp)
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	584(%rsp), %ymm12, %ymm0
	vpandn	%ymm1, %ymm6, %ymm9
	vpandn	%ymm13, %ymm1, %ymm10
	vmovdqa	%ymm1, 328(%rsp)
	vpsrlq	$63, %ymm0, %ymm1
	vpsllq	$1, %ymm0, %ymm0
	vmovdqa	%ymm9, 40(%rsp)
	vpor	%ymm0, %ymm1, %ymm7
	vmovdqa	%ymm10, 8(%rsp)
	vpxor	840(%rsp), %ymm2, %ymm0
	vmovdqa	264(%rsp), %ymm14
	vmovdqa	%ymm7, 840(%rsp)
	vpsrlq	$58, %ymm0, %ymm1
	vpsllq	$6, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm15
	vpxor	776(%rsp), %ymm5, %ymm0
	vpsrlq	$39, %ymm0, %ymm1
	vpsllq	$25, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm6
	vpxor	%ymm3, %ymm8, %ymm0
	vpxor	808(%rsp), %ymm4, %ymm1
	vpsrlq	$46, %ymm0, %ymm11
	vpsllq	$18, %ymm0, %ymm0
	vpandn	%ymm6, %ymm15, %ymm10
	vmovdqa	%ymm6, 808(%rsp)
	vmovdqa	%ymm10, 776(%rsp)
	vpor	%ymm0, %ymm11, %ymm11
	vpxor	488(%rsp), %ymm4, %ymm0
	vpshufb	.LC0(%rip), %ymm1, %ymm1
	vpandn	%ymm1, %ymm6, %ymm9
	vpandn	%ymm11, %ymm1, %ymm8
	vpandn	%ymm7, %ymm11, %ymm13
	vpsrlq	$37, %ymm0, %ymm10
	vpsllq	$27, %ymm0, %ymm0
	vmovdqa	%ymm9, 584(%rsp)
	vpor	%ymm0, %ymm10, %ymm10
	vmovdqa	%ymm8, -56(%rsp)
	vpandn	%ymm15, %ymm7, %ymm8
	vpxor	936(%rsp), %ymm3, %ymm0
	vmovdqa	%ymm8, -120(%rsp)
	vpsrlq	$28, %ymm0, %ymm9
	vpsllq	$36, %ymm0, %ymm0
	vmovdqa	%ymm13, -88(%rsp)
	vpor	%ymm0, %ymm9, %ymm9
	vpxor	1032(%rsp), %ymm12, %ymm0
	vpxor	1064(%rsp), %ymm12, %ymm12
	vpsrlq	$54, %ymm0, %ymm8
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm0
	vmovdqa	%ymm0, 1032(%rsp)
	vpxor	1000(%rsp), %ymm2, %ymm0
	vpxor	520(%rsp), %ymm2, %ymm2
	vpsrlq	$49, %ymm0, %ymm7
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm8, %ymm0
	vmovdqa	%ymm0, 1000(%rsp)
	vpxor	680(%rsp), %ymm5, %ymm0
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpandn	%ymm10, %ymm0, %ymm6
	vpandn	%ymm0, %ymm7, %ymm13
	vmovdqa	%ymm6, 680(%rsp)
	vpsrlq	$2, %ymm2, %ymm6
	vpsllq	$62, %ymm2, %ymm2
	vmovdqa	%ymm13, 936(%rsp)
	vpor	%ymm2, %ymm6, %ymm6
	vpxor	712(%rsp), %ymm5, %ymm2
	vpandn	%ymm9, %ymm10, %ymm13
	vmovdqa	%ymm13, 488(%rsp)
	vpsrlq	$9, %ymm2, %ymm5
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm2, %ymm5, %ymm5
	vpxor	616(%rsp), %ymm4, %ymm2
	vpsrlq	$25, %ymm2, %ymm4
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm2, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm2
	vmovdqa	%ymm2, 712(%rsp)
	vpxor	744(%rsp), %ymm3, %ymm2
	vpsrlq	$23, %ymm2, %ymm3
	vpsllq	$41, %ymm2, %ymm2
	vpor	%ymm2, %ymm3, %ymm3
	vpandn	%ymm3, %ymm4, %ymm2
	vmovdqa	%ymm2, 744(%rsp)
	vpsrlq	$62, %ymm12, %ymm2
	vpsllq	$2, %ymm12, %ymm12
	vpor	%ymm12, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm13
	vmovdqa	%ymm13, 1064(%rsp)
	vpandn	%ymm6, %ymm2, %ymm13
	vmovdqa	%ymm13, 616(%rsp)
	vpandn	%ymm5, %ymm6, %ymm13
	vpxor	296(%rsp), %ymm14, %ymm12
	vpxor	904(%rsp), %ymm12, %ymm12
	vmovdqa	200(%rsp), %ymm14
	vpxor	%ymm2, %ymm13, %ymm13
	vmovdqa	%ymm12, (%rdi)
	vmovdqa	872(%rsp), %ymm12
	vpxor	232(%rsp), %ymm12, %ymm12
	vmovdqa	%ymm12, 32(%rdi)
	vpxor	648(%rsp), %ymm14, %ymm12
	vmovdqa	168(%rsp), %ymm14
	vmovdqa	%ymm12, 64(%rdi)
	vpxor	552(%rsp), %ymm14, %ymm12
	vmovdqa	136(%rsp), %ymm14
	vmovdqa	%ymm12, 96(%rdi)
	vpxor	424(%rsp), %ymm14, %ymm12
	vmovdqa	40(%rsp), %ymm14
	vmovdqa	%ymm12, 128(%rdi)
	vmovdqa	968(%rsp), %ymm12
	vpxor	104(%rsp), %ymm12, %ymm12
	vmovdqa	%ymm12, 160(%rdi)
	vmovdqa	456(%rsp), %ymm12
	vpxor	72(%rsp), %ymm12, %ymm12
	vmovdqa	%ymm12, 192(%rdi)
	vpxor	392(%rsp), %ymm14, %ymm12
	vmovdqa	8(%rsp), %ymm14
	vmovdqa	%ymm12, 224(%rdi)
	vpxor	360(%rsp), %ymm14, %ymm12
	vmovdqa	-24(%rsp), %ymm14
	vmovdqa	%ymm12, 256(%rdi)
	vpxor	328(%rsp), %ymm14, %ymm12
	vmovdqa	%ymm12, 288(%rdi)
	vmovdqa	840(%rsp), %ymm12
	vpxor	776(%rsp), %ymm12, %ymm12
	vmovdqa	%ymm12, 320(%rdi)
	vpxor	-88(%rsp), %ymm1, %ymm1
	vpxor	488(%rsp), %ymm0, %ymm0
	vpxor	584(%rsp), %ymm15, %ymm12
	vmovdqa	%ymm13, 768(%rdi)
	vmovdqa	808(%rsp), %ymm15
	vmovdqa	%ymm1, 416(%rdi)
	vpxor	-120(%rsp), %ymm11, %ymm1
	vpxor	616(%rsp), %ymm3, %ymm14
	vmovdqa	%ymm0, 608(%rdi)
	vpxor	712(%rsp), %ymm6, %ymm0
	vmovdqa	%ymm1, 448(%rdi)
	vpxor	1032(%rsp), %ymm10, %ymm1
	vmovdqa	%ymm12, 352(%rdi)
	vpxor	-56(%rsp), %ymm15, %ymm12
	vpxor	1064(%rsp), %ymm4, %ymm15
	vmovdqa	%ymm1, 480(%rdi)
	vpxor	1000(%rsp), %ymm9, %ymm1
	vmovdqa	%ymm0, 640(%rdi)
	vpxor	744(%rsp), %ymm5, %ymm0
	vmovdqa	%ymm1, 512(%rdi)
	vpxor	936(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm12, 384(%rdi)
	vmovdqa	%ymm1, 544(%rdi)
	vpxor	680(%rsp), %ymm7, %ymm1
	vmovdqa	%ymm0, 672(%rdi)
	vmovdqa	%ymm1, 576(%rdi)
	vmovdqa	%ymm15, 704(%rdi)
	vmovdqa	%ymm14, 736(%rdi)
	vzeroupper
	leave
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds, .-ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_12rounds
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_12rounds, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_12rounds:
	endbr64
	pushq	%rbp
	movq	%rsp, %rbp
	andq	$-32, %rsp
	subq	$1064, %rsp
	vmovdqa	480(%rdi), %ymm5
	vpxor	640(%rdi), %ymm5, %ymm0
	vmovdqa	160(%rdi), %ymm5
	vpxor	320(%rdi), %ymm5, %ymm1
	vmovdqa	512(%rdi), %ymm5
	vpxor	672(%rdi), %ymm5, %ymm7
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	192(%rdi), %ymm5
	vpxor	(%rdi), %ymm0, %ymm0
	vpxor	352(%rdi), %ymm5, %ymm1
	vmovdqa	224(%rdi), %ymm4
	vmovdqa	544(%rdi), %ymm5
	vpxor	704(%rdi), %ymm5, %ymm6
	vpxor	%ymm1, %ymm7, %ymm7
	vpxor	384(%rdi), %ymm4, %ymm1
	vpxor	32(%rdi), %ymm7, %ymm7
	vmovdqa	576(%rdi), %ymm5
	vmovdqa	256(%rdi), %ymm4
	vpxor	736(%rdi), %ymm5, %ymm2
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	416(%rdi), %ymm4, %ymm1
	vmovdqa	608(%rdi), %ymm5
	vmovdqa	288(%rdi), %ymm4
	vpxor	%ymm1, %ymm2, %ymm2
	vpxor	64(%rdi), %ymm6, %ymm6
	vpxor	96(%rdi), %ymm2, %ymm2
	vpxor	448(%rdi), %ymm4, %ymm3
	vpxor	768(%rdi), %ymm5, %ymm1
	vpsllq	$1, %ymm7, %ymm4
	vpsllq	$1, %ymm6, %ymm5
	vpxor	%ymm3, %ymm1, %ymm1
	vpsrlq	$63, %ymm7, %ymm3
	vpxor	128(%rdi), %ymm1, %ymm1
	vpor	%ymm3, %ymm4, %ymm4
	vpsrlq	$63, %ymm6, %ymm3
	vpsrlq	$63, %ymm2, %ymm8
	vpor	%ymm3, %ymm5, %ymm5
	vpxor	%ymm1, %ymm4, %ymm4
	vpsllq	$1, %ymm2, %ymm3
	vpxor	%ymm0, %ymm5, %ymm5
	vpor	%ymm8, %ymm3, %ymm3
	vpxor	(%rdi), %ymm4, %ymm8
	vpxor	%ymm7, %ymm3, %ymm3
	vpsrlq	$63, %ymm1, %ymm7
	vpxor	384(%rdi), %ymm3, %ymm9
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpsrlq	$63, %ymm0, %ymm6
	vpsllq	$1, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm0
	vpxor	192(%rdi), %ymm5, %ymm6
	vpxor	%ymm2, %ymm0, %ymm0
	vpsrlq	$20, %ymm6, %ymm2
	vpsllq	$44, %ymm6, %ymm6
	vpor	%ymm2, %ymm6, %ymm6
	vpsrlq	$21, %ymm9, %ymm2
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm2, %ymm9, %ymm9
	vbroadcastsd	96+KeccakF1600RoundConstants(%rip), %ymm2
	vpxor	576(%rdi), %ymm1, %ymm7
	vpandn	%ymm9, %ymm6, %ymm11
	vpxor	736(%rdi), %ymm1, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsrlq	$43, %ymm7, %ymm2
	vpsllq	$21, %ymm7, %ymm7
	vpxor	%ymm8, %ymm11, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpor	%ymm2, %ymm7, %ymm7
	vpandn	%ymm7, %ymm9, %ymm2
	vpxor	%ymm6, %ymm2, %ymm14
	vpxor	768(%rdi), %ymm0, %ymm2
	vpsrlq	$50, %ymm2, %ymm10
	vpsllq	$14, %ymm2, %ymm2
	vpor	%ymm10, %ymm2, %ymm2
	vpandn	%ymm2, %ymm7, %ymm10
	vpxor	%ymm9, %ymm10, %ymm15
	vpandn	%ymm8, %ymm2, %ymm9
	vpandn	%ymm6, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm2
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	320(%rdi), %ymm4, %ymm9
	vmovdqa	%ymm15, 520(%rsp)
	vmovdqa	%ymm2, 552(%rsp)
	vpxor	96(%rdi), %ymm1, %ymm2
	vpxor	512(%rdi), %ymm5, %ymm8
	vmovdqa	%ymm7, 712(%rsp)
	vpxor	288(%rdi), %ymm0, %ymm7
	vpsrlq	$36, %ymm2, %ymm6
	vpsllq	$28, %ymm2, %ymm2
	vpor	%ymm6, %ymm2, %ymm2
	vpsrlq	$44, %ymm7, %ymm6
	vpsllq	$20, %ymm7, %ymm7
	vpor	%ymm6, %ymm7, %ymm7
	vpsrlq	$61, %ymm9, %ymm6
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm6, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm6
	vpxor	%ymm2, %ymm6, %ymm6
	vmovdqa	%ymm6, %ymm15
	vpsrlq	$19, %ymm8, %ymm6
	vpsllq	$45, %ymm8, %ymm8
	vpor	%ymm6, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm6
	vpxor	%ymm7, %ymm6, %ymm13
	vpxor	704(%rdi), %ymm3, %ymm6
	vmovdqa	%ymm13, 872(%rsp)
	vpsrlq	$3, %ymm6, %ymm10
	vpsllq	$61, %ymm6, %ymm6
	vpor	%ymm10, %ymm6, %ymm6
	vpandn	%ymm6, %ymm8, %ymm10
	vpxor	%ymm9, %ymm10, %ymm9
	vmovdqa	%ymm9, 744(%rsp)
	vpandn	%ymm2, %ymm6, %ymm9
	vpandn	%ymm7, %ymm2, %ymm2
	vpxor	224(%rdi), %ymm3, %ymm7
	vpxor	%ymm6, %ymm2, %ymm6
	vpxor	32(%rdi), %ymm5, %ymm2
	vpxor	%ymm8, %ymm9, %ymm8
	vmovdqa	%ymm8, 584(%rsp)
	vpxor	416(%rdi), %ymm1, %ymm8
	vpxor	608(%rdi), %ymm0, %ymm9
	vmovdqa	%ymm6, 904(%rsp)
	vpsrlq	$63, %ymm2, %ymm6
	vpsllq	$1, %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm9, %ymm9
	vpor	%ymm6, %ymm2, %ymm2
	vpsrlq	$58, %ymm7, %ymm6
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm6, %ymm7, %ymm7
	vpsrlq	$39, %ymm8, %ymm6
	vpsllq	$25, %ymm8, %ymm8
	vpor	%ymm6, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm6
	vpxor	%ymm2, %ymm6, %ymm10
	vpandn	%ymm9, %ymm8, %ymm6
	vmovdqa	%ymm10, 936(%rsp)
	vpxor	%ymm7, %ymm6, %ymm6
	vmovdqa	%ymm6, 616(%rsp)
	vpxor	640(%rdi), %ymm4, %ymm6
	vpsrlq	$46, %ymm6, %ymm10
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm10, %ymm6, %ymm6
	vpandn	%ymm6, %ymm9, %ymm10
	vpxor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm2, %ymm6, %ymm8
	vpandn	%ymm7, %ymm2, %ymm2
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm6, %ymm2, %ymm9
	vpxor	128(%rdi), %ymm0, %ymm2
	vmovdqa	%ymm9, 648(%rsp)
	vpxor	352(%rdi), %ymm5, %ymm9
	vmovdqa	%ymm8, 1000(%rsp)
	vpsrlq	$37, %ymm2, %ymm6
	vpsllq	$27, %ymm2, %ymm2
	vpor	%ymm6, %ymm2, %ymm2
	vpxor	160(%rdi), %ymm4, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm9, %ymm7
	vpsllq	$10, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm6, %ymm7
	vpxor	%ymm2, %ymm7, %ymm13
	vpxor	544(%rdi), %ymm3, %ymm7
	vmovdqa	%ymm13, 776(%rsp)
	vpsrlq	$49, %ymm7, %ymm8
	vpsllq	$15, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm12, %ymm7, %ymm13
	vpandn	%ymm7, %ymm9, %ymm8
	vpxor	%ymm9, %ymm13, %ymm9
	vpxor	%ymm6, %ymm8, %ymm8
	vmovdqa	%ymm9, 968(%rsp)
	vpxor	64(%rdi), %ymm3, %ymm3
	vpandn	%ymm2, %ymm12, %ymm9
	vpandn	%ymm6, %ymm2, %ymm2
	vpxor	256(%rdi), %ymm1, %ymm1
	vpxor	%ymm12, %ymm2, %ymm2
	vpxor	448(%rdi), %ymm0, %ymm12
	vmovdqa	%ymm15, 328(%rsp)
	vmovdqa	%ymm2, 1032(%rsp)
	vpsrlq	$2, %ymm3, %ymm2
	vpsllq	$62, %ymm3, %ymm3
	vpxor	480(%rdi), %ymm4, %ymm4
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$25, %ymm12, %ymm0
	vmovdqa	872(%rsp), %ymm13
	vmovdqa	%ymm14, 296(%rsp)
	vpsrlq	$9, %ymm1, %ymm2
	vpsllq	$39, %ymm12, %ymm12
	vpxor	%ymm7, %ymm9, %ymm9
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	%ymm14, %ymm13, %ymm14
	vpor	%ymm2, %ymm1, %ymm1
	vmovdqa	936(%rsp), %ymm2
	vpandn	%ymm12, %ymm1, %ymm6
	vpxor	%ymm3, %ymm6, %ymm6
	vpxor	%ymm15, %ymm2, %ymm2
	vpxor	776(%rsp), %ymm6, %ymm0
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$23, %ymm4, %ymm0
	vpsllq	$41, %ymm4, %ymm4
	vpxor	%ymm11, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpandn	%ymm4, %ymm12, %ymm0
	vpxor	%ymm1, %ymm0, %ymm15
	vpxor	616(%rsp), %ymm8, %ymm0
	vpxor	%ymm0, %ymm14, %ymm14
	vpxor	672(%rdi), %ymm5, %ymm0
	vpxor	%ymm15, %ymm14, %ymm14
	vpsrlq	$62, %ymm0, %ymm5
	vpsllq	$2, %ymm0, %ymm0
	vpor	%ymm5, %ymm0, %ymm0
	vpxor	968(%rsp), %ymm10, %ymm5
	vpandn	%ymm0, %ymm4, %ymm7
	vpxor	%ymm12, %ymm7, %ymm7
	vmovdqa	744(%rsp), %ymm12
	vpxor	520(%rsp), %ymm12, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpandn	%ymm3, %ymm0, %ymm5
	vpandn	%ymm1, %ymm3, %ymm3
	vpxor	%ymm4, %ymm5, %ymm4
	vpxor	%ymm0, %ymm3, %ymm3
	vpxor	%ymm7, %ymm13, %ymm13
	vmovdqa	584(%rsp), %ymm5
	vpxor	712(%rsp), %ymm5, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vmovdqa	%ymm4, 360(%rsp)
	vpxor	%ymm4, %ymm9, %ymm4
	vpxor	648(%rsp), %ymm3, %ymm0
	vpxor	%ymm4, %ymm12, %ymm12
	vmovdqa	904(%rsp), %ymm4
	vpxor	552(%rsp), %ymm4, %ymm1
	vpxor	1000(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1032(%rsp), %ymm1, %ymm1
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm1, %ymm5, %ymm5
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm11, %ymm5, %ymm11
	vpxor	%ymm6, %ymm5, %ymm6
	vmovdqa	%ymm0, 840(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpor	840(%rsp), %ymm0, %ymm0
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm1, %ymm14
	vpsllq	$1, %ymm1, %ymm1
	vpxor	%ymm10, %ymm0, %ymm10
	vpxor	%ymm7, %ymm0, %ymm7
	vpor	%ymm14, %ymm1, %ymm1
	vbroadcastsd	104+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm1, %ymm1
	vpsrlq	$63, %ymm2, %ymm13
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm1, %ymm9
	vpor	%ymm13, %ymm2, %ymm2
	vpxor	%ymm12, %ymm2, %ymm2
	vpxor	872(%rsp), %ymm4, %ymm12
	vpxor	%ymm3, %ymm2, %ymm3
	vpsrlq	$20, %ymm12, %ymm13
	vpsllq	$44, %ymm12, %ymm12
	vpor	%ymm13, %ymm12, %ymm12
	vpsrlq	$21, %ymm10, %ymm13
	vpsllq	$43, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm12, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	%ymm13, 808(%rsp)
	vpsrlq	$43, %ymm9, %ymm13
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm10, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 392(%rsp)
	vpsrlq	$50, %ymm3, %ymm13
	vpsllq	$14, %ymm3, %ymm3
	vpor	%ymm13, %ymm3, %ymm3
	vpandn	%ymm3, %ymm9, %ymm13
	vpxor	%ymm10, %ymm13, %ymm10
	vmovdqa	%ymm10, 424(%rsp)
	vpandn	%ymm11, %ymm3, %ymm10
	vpandn	%ymm12, %ymm11, %ymm11
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	%ymm3, %ymm11, %ymm11
	vmovdqa	%ymm9, 840(%rsp)
	vmovdqa	%ymm11, 456(%rsp)
	vpxor	712(%rsp), %ymm1, %ymm3
	vpxor	904(%rsp), %ymm2, %ymm10
	vpxor	936(%rsp), %ymm5, %ymm11
	vpsrlq	$36, %ymm3, %ymm9
	vpsllq	$28, %ymm3, %ymm3
	vpor	%ymm9, %ymm3, %ymm3
	vpsrlq	$44, %ymm10, %ymm9
	vpsllq	$20, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm3, %ymm9, %ymm12
	vpsrlq	$19, %ymm8, %ymm9
	vmovdqa	%ymm12, 488(%rsp)
	vpsllq	$45, %ymm8, %ymm8
	vpsrlq	$3, %ymm7, %ymm12
	vpsllq	$61, %ymm7, %ymm7
	vpor	%ymm9, %ymm8, %ymm8
	vpor	%ymm12, %ymm7, %ymm7
	vpandn	%ymm8, %ymm11, %ymm9
	vpandn	%ymm7, %ymm8, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	%ymm11, %ymm12, %ymm11
	vmovdqa	%ymm11, 680(%rsp)
	vpandn	%ymm3, %ymm7, %ymm11
	vpandn	%ymm10, %ymm3, %ymm3
	vpxor	%ymm7, %ymm3, %ymm10
	vpxor	%ymm8, %ymm11, %ymm8
	vpxor	296(%rsp), %ymm4, %ymm3
	vmovdqa	%ymm10, 872(%rsp)
	vpxor	1000(%rsp), %ymm1, %ymm10
	vpxor	1032(%rsp), %ymm2, %ymm11
	vmovdqa	%ymm8, 712(%rsp)
	vpsrlq	$63, %ymm3, %ymm7
	vpsllq	$1, %ymm3, %ymm3
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpor	%ymm7, %ymm3, %ymm3
	vpxor	744(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm8
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm8
	vpxor	%ymm3, %ymm8, %ymm8
	vmovdqa	%ymm8, 936(%rsp)
	vpandn	%ymm11, %ymm10, %ymm8
	vpxor	%ymm7, %ymm8, %ymm14
	vpsrlq	$46, %ymm6, %ymm8
	vmovdqa	%ymm14, 904(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm8
	vpxor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm3, %ymm6, %ymm10
	vpandn	%ymm7, %ymm3, %ymm3
	vpxor	%ymm6, %ymm3, %ymm6
	vpxor	%ymm11, %ymm10, %ymm12
	vpxor	552(%rsp), %ymm2, %ymm3
	vmovdqa	%ymm6, 744(%rsp)
	vpxor	616(%rsp), %ymm4, %ymm10
	vpxor	%ymm15, %ymm4, %ymm4
	vpxor	968(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm12, 1000(%rsp)
	vpsrlq	$37, %ymm3, %ymm6
	vpsllq	$27, %ymm3, %ymm3
	vpxor	360(%rsp), %ymm1, %ymm12
	vpxor	520(%rsp), %ymm0, %ymm0
	vpor	%ymm6, %ymm3, %ymm3
	vpxor	328(%rsp), %ymm5, %ymm6
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	584(%rsp), %ymm1, %ymm1
	vpxor	648(%rsp), %ymm2, %ymm2
	vpxor	776(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm3, %ymm7, %ymm7
	vmovdqa	%ymm7, %ymm14
	vpsrlq	$49, %ymm11, %ymm7
	vmovdqa	%ymm14, 328(%rsp)
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm10, 968(%rsp)
	vpandn	%ymm3, %ymm12, %ymm10
	vpandn	%ymm6, %ymm3, %ymm3
	vpxor	%ymm12, %ymm3, %ymm6
	vpsrlq	$2, %ymm0, %ymm3
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm6, 1032(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm3, %ymm0, %ymm0
	vpsrlq	$9, %ymm1, %ymm3
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsrlq	$25, %ymm2, %ymm3
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vmovdqa	936(%rsp), %ymm3
	vpxor	488(%rsp), %ymm3, %ymm3
	vpandn	%ymm2, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpxor	%ymm14, %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	808(%rsp), %ymm3, %ymm3
	vpxor	392(%rsp), %ymm9, %ymm14
	vpsllq	$41, %ymm5, %ymm5
	vmovdqa	680(%rsp), %ymm15
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm2, %ymm11
	vpxor	%ymm1, %ymm11, %ymm13
	vpxor	904(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm13, 360(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	424(%rsp), %ymm15, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vpxor	968(%rsp), %ymm8, %ymm2
	vpxor	%ymm2, %ymm13, %ymm13
	vpandn	%ymm0, %ymm4, %ymm2
	vpandn	%ymm1, %ymm0, %ymm0
	vmovdqa	872(%rsp), %ymm1
	vpxor	%ymm5, %ymm2, %ymm15
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	712(%rsp), %ymm2
	vpxor	840(%rsp), %ymm2, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm10, %ymm15, %ymm2
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm2, %ymm12, %ymm12
	vpxor	456(%rsp), %ymm1, %ymm2
	vpxor	744(%rsp), %ymm0, %ymm1
	vpxor	1000(%rsp), %ymm12, %ymm12
	vpxor	%ymm1, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm1
	vpxor	1032(%rsp), %ymm2, %ymm2
	vpor	%ymm1, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm1, 776(%rsp)
	vpsllq	$1, %ymm12, %ymm1
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	776(%rsp), %ymm1, %ymm1
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm1, %ymm1
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm1, %ymm8
	vpxor	%ymm11, %ymm1, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	112+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	808(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpxor	%ymm0, %ymm3, %ymm0
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm13, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm13
	vmovdqa	%ymm13, 520(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm13, %ymm0, %ymm0
	vpandn	%ymm0, %ymm10, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 552(%rsp)
	vpandn	%ymm12, %ymm0, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	872(%rsp), %ymm3, %ymm9
	vpxor	%ymm0, %ymm12, %ymm0
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm8, %ymm10
	vmovdqa	%ymm0, 584(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	840(%rsp), %ymm2, %ymm0
	vmovdqa	%ymm10, 808(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	936(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm0, %ymm8
	vpsllq	$28, %ymm0, %ymm0
	vpor	%ymm8, %ymm0, %ymm0
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 616(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm15, %ymm2, %ymm12
	vmovdqa	%ymm10, 776(%rsp)
	vpandn	%ymm0, %ymm11, %ymm10
	vpandn	%ymm9, %ymm0, %ymm0
	vpxor	%ymm11, %ymm0, %ymm9
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	392(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm7, 648(%rsp)
	vpxor	1000(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm9, 840(%rsp)
	vpsrlq	$63, %ymm0, %ymm7
	vpsllq	$1, %ymm0, %ymm0
	vpor	%ymm7, %ymm0, %ymm0
	vpxor	680(%rsp), %ymm1, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm0, %ymm9, %ymm11
	vmovdqa	%ymm11, 1000(%rsp)
	vpxor	1032(%rsp), %ymm3, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	712(%rsp), %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 872(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm0, %ymm6, %ymm10
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm7
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	456(%rsp), %ymm3, %ymm0
	vmovdqa	%ymm10, 936(%rsp)
	vpxor	904(%rsp), %ymm4, %ymm10
	vpxor	968(%rsp), %ymm1, %ymm11
	vmovdqa	%ymm7, 680(%rsp)
	vpsrlq	$37, %ymm0, %ymm6
	vpsllq	$27, %ymm0, %ymm0
	vpxor	424(%rsp), %ymm1, %ymm1
	vpxor	744(%rsp), %ymm3, %ymm3
	vpor	%ymm6, %ymm0, %ymm0
	vpxor	488(%rsp), %ymm5, %ymm6
	vmovdqa	%ymm14, 968(%rsp)
	vpxor	328(%rsp), %ymm5, %ymm5
	vpxor	360(%rsp), %ymm4, %ymm4
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vmovdqa	%ymm7, 904(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm15
	vpandn	%ymm0, %ymm12, %ymm10
	vpandn	%ymm6, %ymm0, %ymm0
	vmovdqa	%ymm15, 1032(%rsp)
	vpxor	%ymm12, %ymm0, %ymm15
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm11, %ymm10, %ymm10
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vmovdqa	1000(%rsp), %ymm11
	vmovdqa	776(%rsp), %ymm12
	vpor	%ymm0, %ymm1, %ymm1
	vpsrlq	$25, %ymm3, %ymm6
	vpsrlq	$9, %ymm2, %ymm0
	vpsllq	$39, %ymm3, %ymm3
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	616(%rsp), %ymm11, %ymm3
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	904(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpsllq	$41, %ymm5, %ymm5
	vpxor	%ymm14, %ymm3, %ymm3
	vpxor	520(%rsp), %ymm8, %ymm14
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm13
	vpxor	872(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm13, 296(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	552(%rsp), %ymm12, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1032(%rsp), %ymm9, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	840(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	648(%rsp), %ymm0
	vpxor	808(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 360(%rsp)
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	936(%rsp), %ymm12, %ymm12
	vpxor	584(%rsp), %ymm2, %ymm2
	vpxor	680(%rsp), %ymm1, %ymm0
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpxor	%ymm15, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 744(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	744(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	120+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	968(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 968(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 712(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 392(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	808(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm9, 744(%rsp)
	vpxor	840(%rsp), %ymm3, %ymm9
	vpxor	1000(%rsp), %ymm5, %ymm10
	vpor	%ymm12, %ymm11, %ymm11
	vmovdqa	%ymm8, 424(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 456(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 808(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	936(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm1, 1000(%rsp)
	vpxor	520(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 488(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	776(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm11
	vmovdqa	%ymm11, %ymm14
	vpxor	%ymm15, %ymm3, %ymm11
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm15, 776(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm15
	vpxor	584(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 840(%rsp)
	vpxor	872(%rsp), %ymm4, %ymm10
	vpxor	1032(%rsp), %ymm0, %ymm11
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	616(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm12
	vpsrlq	$49, %ymm11, %ymm7
	vmovdqa	%ymm12, 872(%rsp)
	vpsllq	$15, %ymm11, %ymm11
	vpxor	360(%rsp), %ymm2, %ymm12
	vpor	%ymm7, %ymm11, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpandn	%ymm11, %ymm10, %ymm7
	vpandn	%ymm12, %ymm11, %ymm13
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vmovdqa	%ymm10, 936(%rsp)
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm1, 1032(%rsp)
	vpxor	552(%rsp), %ymm0, %ymm0
	vpxor	680(%rsp), %ymm3, %ymm3
	vpxor	648(%rsp), %ymm2, %ymm2
	vpxor	904(%rsp), %ymm5, %ymm5
	vmovdqa	%ymm14, 680(%rsp)
	vpxor	296(%rsp), %ymm4, %ymm4
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	456(%rsp), %ymm14, %ymm3
	vpxor	712(%rsp), %ymm8, %ymm14
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	872(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	968(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vmovdqa	%ymm11, %ymm13
	vpxor	776(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm13, 328(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vmovdqa	808(%rsp), %ymm13
	vpxor	392(%rsp), %ymm13, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	936(%rsp), %ymm9, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	1000(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	488(%rsp), %ymm0
	vpxor	744(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 360(%rsp)
	vpxor	424(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	840(%rsp), %ymm1, %ymm0
	vpxor	%ymm15, %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1032(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 904(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	904(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	128+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	968(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 968(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 520(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 552(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm10
	vpxor	744(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm10, 904(%rsp)
	vmovdqa	%ymm8, 584(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1000(%rsp), %ymm3, %ymm9
	vpxor	680(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 616(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	360(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 648(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	%ymm15, %ymm2, %ymm10
	vmovdqa	%ymm1, 1000(%rsp)
	vpxor	712(%rsp), %ymm4, %ymm1
	vpxor	1032(%rsp), %ymm3, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vmovdqa	%ymm7, 680(%rsp)
	vpxor	488(%rsp), %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	808(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm15
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 712(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	424(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 744(%rsp)
	vpxor	936(%rsp), %ymm0, %ymm11
	vpxor	392(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 808(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	776(%rsp), %ymm4, %ymm10
	vpxor	840(%rsp), %ymm3, %ymm3
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	456(%rsp), %ymm5, %ymm6
	vpxor	872(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 776(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm14, 936(%rsp)
	vmovdqa	%ymm1, 1032(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpxor	520(%rsp), %ymm8, %ymm14
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	616(%rsp), %ymm15, %ymm3
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	776(%rsp), %ymm6, %ymm11
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	968(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm12
	vpxor	712(%rsp), %ymm7, %ymm11
	vmovdqa	%ymm12, 360(%rsp)
	vpxor	328(%rsp), %ymm4, %ymm4
	vmovdqa	648(%rsp), %ymm13
	vpxor	552(%rsp), %ymm13, %ymm13
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	936(%rsp), %ymm9, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vmovdqa	1000(%rsp), %ymm2
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	680(%rsp), %ymm0
	vpxor	904(%rsp), %ymm0, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm0
	vmovdqa	%ymm5, 392(%rsp)
	vpxor	584(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	744(%rsp), %ymm1, %ymm0
	vpxor	808(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1032(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 872(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	872(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	136+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	968(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 968(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 840(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 424(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	904(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm8, 456(%rsp)
	vmovdqa	%ymm9, 872(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpxor	1000(%rsp), %ymm3, %ymm8
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm15, %ymm5, %ymm9
	vpsrlq	$61, %ymm9, %ymm10
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm10
	vpxor	%ymm1, %ymm10, %ymm15
	vpsrlq	$19, %ymm7, %ymm10
	vpsllq	$45, %ymm7, %ymm7
	vmovdqa	%ymm15, %ymm14
	vpor	%ymm10, %ymm7, %ymm7
	vpandn	%ymm7, %ymm9, %ymm10
	vpxor	%ymm8, %ymm10, %ymm15
	vpsrlq	$3, %ymm11, %ymm10
	vpsllq	$61, %ymm11, %ymm11
	vpor	%ymm10, %ymm11, %ymm11
	vpandn	%ymm11, %ymm7, %ymm10
	vpxor	%ymm9, %ymm10, %ymm12
	vpandn	%ymm1, %ymm11, %ymm9
	vpandn	%ymm8, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	808(%rsp), %ymm2, %ymm9
	vmovdqa	%ymm12, 904(%rsp)
	vmovdqa	%ymm1, 1000(%rsp)
	vpxor	520(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 488(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	648(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm9, %ymm8
	vpsllq	$25, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm10
	vmovdqa	%ymm10, %ymm13
	vpxor	1032(%rsp), %ymm3, %ymm10
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm8, 808(%rsp)
	vpsrlq	$46, %ymm6, %ymm8
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm10, %ymm8
	vpxor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm1, %ymm6, %ymm9
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm10, %ymm9, %ymm10
	vpxor	%ymm6, %ymm1, %ymm6
	vmovdqa	%ymm10, 1032(%rsp)
	vpxor	584(%rsp), %ymm3, %ymm1
	vpxor	712(%rsp), %ymm4, %ymm9
	vmovdqa	%ymm6, 520(%rsp)
	vpxor	936(%rsp), %ymm0, %ymm10
	vpxor	392(%rsp), %ymm2, %ymm11
	vpxor	552(%rsp), %ymm0, %ymm0
	vpsrlq	$37, %ymm1, %ymm6
	vpxor	680(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm13, 712(%rsp)
	vpshufb	.LC1(%rip), %ymm11, %ymm11
	vpsllq	$27, %ymm1, %ymm1
	vpxor	744(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm14, 328(%rsp)
	vpxor	360(%rsp), %ymm4, %ymm4
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	616(%rsp), %ymm5, %ymm6
	vpxor	776(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm9, %ymm7
	vpsllq	$10, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 616(%rsp)
	vpsrlq	$49, %ymm10, %ymm7
	vpsllq	$15, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm11, %ymm10, %ymm12
	vpandn	%ymm10, %ymm9, %ymm7
	vpxor	%ymm9, %ymm12, %ymm12
	vpandn	%ymm1, %ymm11, %ymm9
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm11, %ymm1, %ymm11
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm12, 360(%rsp)
	vpsrlq	$2, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm6
	vmovdqa	%ymm11, 936(%rsp)
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm1, %ymm0, %ymm0
	vpor	%ymm6, %ymm2, %ymm1
	vpsrlq	$25, %ymm3, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm14, %ymm13, %ymm2
	vpxor	840(%rsp), %ymm15, %ymm14
	vpandn	%ymm3, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpxor	616(%rsp), %ymm6, %ymm10
	vpxor	%ymm10, %ymm2, %ymm2
	vpsrlq	$23, %ymm5, %ymm10
	vpxor	968(%rsp), %ymm2, %ymm2
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm10, %ymm5, %ymm5
	vpandn	%ymm5, %ymm3, %ymm10
	vpxor	%ymm1, %ymm10, %ymm13
	vpxor	808(%rsp), %ymm7, %ymm10
	vmovdqa	%ymm13, 392(%rsp)
	vpxor	%ymm10, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm10
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vmovdqa	904(%rsp), %ymm13
	vpxor	424(%rsp), %ymm13, %ymm13
	vpor	%ymm10, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm10
	vpandn	%ymm0, %ymm4, %ymm11
	vpandn	%ymm1, %ymm0, %ymm0
	vmovdqa	1000(%rsp), %ymm1
	vpxor	%ymm3, %ymm10, %ymm10
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm12, %ymm8, %ymm3
	vmovdqa	488(%rsp), %ymm12
	vpxor	%ymm3, %ymm13, %ymm13
	vpxor	%ymm9, %ymm11, %ymm3
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	872(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm10, %ymm13, %ymm13
	vpxor	456(%rsp), %ymm1, %ymm1
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm3, %ymm12, %ymm12
	vpxor	520(%rsp), %ymm0, %ymm3
	vpxor	1032(%rsp), %ymm12, %ymm12
	vpxor	%ymm3, %ymm1, %ymm1
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	936(%rsp), %ymm1, %ymm1
	vpor	%ymm3, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm3
	vpor	%ymm3, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm3
	vpxor	%ymm1, %ymm5, %ymm5
	vmovdqa	%ymm3, 776(%rsp)
	vpsllq	$1, %ymm12, %ymm3
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	776(%rsp), %ymm3, %ymm3
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm3, %ymm3
	vpsrlq	$63, %ymm1, %ymm14
	vpsllq	$1, %ymm1, %ymm1
	vpxor	%ymm8, %ymm3, %ymm8
	vpxor	%ymm10, %ymm3, %ymm10
	vpor	%ymm14, %ymm1, %ymm1
	vpxor	%ymm13, %ymm1, %ymm1
	vpsrlq	$63, %ymm2, %ymm13
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm1, %ymm9
	vpxor	%ymm11, %ymm1, %ymm11
	vpshufb	.LC1(%rip), %ymm11, %ymm11
	vpor	%ymm13, %ymm2, %ymm2
	vpxor	968(%rsp), %ymm5, %ymm13
	vpxor	%ymm12, %ymm2, %ymm2
	vpxor	%ymm15, %ymm4, %ymm12
	vbroadcastsd	144+KeccakF1600RoundConstants(%rip), %ymm15
	vpsrlq	$20, %ymm12, %ymm14
	vpsllq	$44, %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm0
	vpor	%ymm14, %ymm12, %ymm12
	vpsrlq	$21, %ymm8, %ymm14
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm14, %ymm8, %ymm8
	vpandn	%ymm8, %ymm12, %ymm14
	vpxor	%ymm15, %ymm14, %ymm14
	vpxor	%ymm13, %ymm14, %ymm14
	vmovdqa	%ymm14, 744(%rsp)
	vpsrlq	$43, %ymm9, %ymm14
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm14, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm14
	vpxor	%ymm12, %ymm14, %ymm15
	vpsrlq	$50, %ymm0, %ymm14
	vmovdqa	%ymm15, 552(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm14, %ymm0, %ymm0
	vpandn	%ymm0, %ymm9, %ymm14
	vpxor	%ymm8, %ymm14, %ymm8
	vmovdqa	%ymm8, 584(%rsp)
	vpandn	%ymm13, %ymm0, %ymm8
	vpandn	%ymm12, %ymm13, %ymm13
	vpxor	712(%rsp), %ymm5, %ymm12
	vpxor	%ymm0, %ymm13, %ymm0
	vpsrlq	$3, %ymm10, %ymm13
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm0, 648(%rsp)
	vpsllq	$61, %ymm10, %ymm10
	vpxor	872(%rsp), %ymm1, %ymm0
	vpxor	1000(%rsp), %ymm2, %ymm9
	vmovdqa	%ymm8, 968(%rsp)
	vpor	%ymm13, %ymm10, %ymm10
	vpsrlq	$36, %ymm0, %ymm8
	vpsllq	$28, %ymm0, %ymm0
	vpor	%ymm8, %ymm0, %ymm0
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm12, %ymm8
	vpsllq	$3, %ymm12, %ymm12
	vpor	%ymm8, %ymm12, %ymm12
	vpandn	%ymm12, %ymm9, %ymm8
	vpxor	%ymm0, %ymm8, %ymm15
	vpsrlq	$19, %ymm7, %ymm8
	vmovdqa	%ymm15, 776(%rsp)
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm10, %ymm7, %ymm13
	vpandn	%ymm7, %ymm12, %ymm8
	vpxor	%ymm12, %ymm13, %ymm15
	vpandn	%ymm0, %ymm10, %ymm12
	vpandn	%ymm9, %ymm0, %ymm0
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm10, %ymm0, %ymm9
	vpxor	840(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm15, 872(%rsp)
	vmovdqa	%ymm9, 1000(%rsp)
	vpxor	%ymm7, %ymm12, %ymm7
	vpxor	936(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm7, 680(%rsp)
	vpsrlq	$63, %ymm0, %ymm7
	vpsllq	$1, %ymm0, %ymm0
	vpshufb	.LC0(%rip), %ymm12, %ymm12
	vpor	%ymm7, %ymm0, %ymm0
	vpxor	904(%rsp), %ymm3, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpxor	1032(%rsp), %ymm1, %ymm9
	vpsrlq	$39, %ymm9, %ymm10
	vpsllq	$25, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm10
	vpxor	%ymm0, %ymm10, %ymm10
	vmovdqa	%ymm10, 1032(%rsp)
	vpandn	%ymm12, %ymm9, %ymm10
	vpxor	%ymm7, %ymm10, %ymm10
	vmovdqa	%ymm10, 840(%rsp)
	vpsrlq	$46, %ymm6, %ymm10
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm10, %ymm6, %ymm6
	vpandn	%ymm6, %ymm12, %ymm10
	vpxor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm0, %ymm6, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vpxor	%ymm12, %ymm9, %ymm9
	vpxor	360(%rsp), %ymm3, %ymm12
	vmovdqa	%ymm0, 712(%rsp)
	vpxor	456(%rsp), %ymm2, %ymm0
	vpxor	424(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm9, 904(%rsp)
	vpxor	808(%rsp), %ymm4, %ymm9
	vpsrlq	$37, %ymm0, %ymm6
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm0
	vpxor	328(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm9, %ymm7
	vpsllq	$10, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm6, %ymm7
	vpxor	%ymm0, %ymm7, %ymm15
	vpsrlq	$49, %ymm12, %ymm7
	vpsllq	$15, %ymm12, %ymm12
	vpor	%ymm7, %ymm12, %ymm12
	vpandn	%ymm11, %ymm12, %ymm13
	vpandn	%ymm12, %ymm9, %ymm7
	vpxor	%ymm9, %ymm13, %ymm14
	vpandn	%ymm0, %ymm11, %ymm9
	vpandn	%ymm6, %ymm0, %ymm0
	vpxor	%ymm11, %ymm0, %ymm11
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm9, %ymm9
	vmovdqa	%ymm14, 808(%rsp)
	vmovdqa	%ymm11, 936(%rsp)
	vpsrlq	$2, %ymm3, %ymm6
	vpxor	488(%rsp), %ymm1, %ymm1
	vpxor	520(%rsp), %ymm2, %ymm2
	vpxor	616(%rsp), %ymm5, %ymm5
	vpsllq	$62, %ymm3, %ymm3
	vmovdqa	1032(%rsp), %ymm12
	vpxor	392(%rsp), %ymm4, %ymm4
	vpor	%ymm6, %ymm3, %ymm0
	vpxor	552(%rsp), %ymm8, %ymm14
	vpsrlq	$9, %ymm1, %ymm6
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm3
	vpsrlq	$25, %ymm2, %ymm1
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm1, %ymm2, %ymm2
	vpxor	776(%rsp), %ymm12, %ymm1
	vmovdqa	680(%rsp), %ymm12
	vpxor	968(%rsp), %ymm12, %ymm12
	vpandn	%ymm2, %ymm3, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	%ymm15, %ymm11, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vpsrlq	$23, %ymm5, %ymm6
	vpxor	744(%rsp), %ymm1, %ymm1
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm6, %ymm5, %ymm5
	vpandn	%ymm5, %ymm2, %ymm6
	vpxor	%ymm3, %ymm6, %ymm6
	vmovdqa	%ymm6, %ymm13
	vpxor	840(%rsp), %ymm7, %ymm6
	vmovdqa	%ymm13, 360(%rsp)
	vpxor	%ymm6, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm6
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vmovdqa	872(%rsp), %ymm13
	vpxor	584(%rsp), %ymm13, %ymm13
	vpor	%ymm6, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm6
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	808(%rsp), %ymm10, %ymm2
	vpxor	%ymm2, %ymm13, %ymm13
	vpandn	%ymm0, %ymm4, %ymm2
	vpandn	%ymm3, %ymm0, %ymm0
	vmovdqa	1000(%rsp), %ymm3
	vpxor	%ymm5, %ymm2, %ymm5
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm6, %ymm13, %ymm13
	vpxor	%ymm5, %ymm9, %ymm2
	vpsllq	$1, %ymm14, %ymm4
	vmovdqa	%ymm5, 392(%rsp)
	vpxor	%ymm2, %ymm12, %ymm12
	vpsrlq	$63, %ymm13, %ymm5
	vpxor	648(%rsp), %ymm3, %ymm2
	vpxor	712(%rsp), %ymm0, %ymm3
	vpxor	904(%rsp), %ymm12, %ymm12
	vpxor	%ymm3, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	936(%rsp), %ymm2, %ymm2
	vpor	%ymm3, %ymm4, %ymm4
	vpsllq	$1, %ymm13, %ymm3
	vpor	%ymm5, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm5
	vpxor	%ymm2, %ymm4, %ymm4
	vmovdqa	%ymm5, 616(%rsp)
	vpsllq	$1, %ymm12, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm11, %ymm4, %ymm11
	vpor	616(%rsp), %ymm5, %ymm5
	vpxor	%ymm8, %ymm3, %ymm8
	vpxor	%ymm7, %ymm3, %ymm7
	vpxor	%ymm14, %ymm5, %ymm5
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm10, %ymm5, %ymm10
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	%ymm14, %ymm2, %ymm2
	vbroadcastsd	152+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm1, %ymm13
	vpsllq	$1, %ymm1, %ymm1
	vpxor	%ymm9, %ymm2, %ymm9
	vpor	%ymm13, %ymm1, %ymm1
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	744(%rsp), %ymm4, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm10, %ymm13
	vpxor	%ymm0, %ymm1, %ymm0
	vpsllq	$43, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm9, %ymm13
	vmovdqa	%ymm14, 744(%rsp)
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm10, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 424(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm13, %ymm0, %ymm0
	vpandn	%ymm0, %ymm9, %ymm13
	vpxor	%ymm10, %ymm13, %ymm10
	vmovdqa	%ymm10, 456(%rsp)
	vpandn	%ymm12, %ymm0, %ymm10
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm0, %ymm12, %ymm8
	vpsrlq	$3, %ymm6, %ymm12
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	968(%rsp), %ymm2, %ymm0
	vpsllq	$61, %ymm6, %ymm6
	vmovdqa	%ymm8, 488(%rsp)
	vmovdqa	%ymm9, 616(%rsp)
	vpor	%ymm6, %ymm12, %ymm6
	vpsrlq	$36, %ymm0, %ymm8
	vpsllq	$28, %ymm0, %ymm0
	vpor	%ymm8, %ymm0, %ymm0
	vpxor	1000(%rsp), %ymm1, %ymm8
	vpxor	1032(%rsp), %ymm4, %ymm10
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpsrlq	$61, %ymm10, %ymm9
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm9
	vpxor	%ymm0, %ymm9, %ymm9
	vmovdqa	%ymm9, 520(%rsp)
	vpsrlq	$19, %ymm7, %ymm9
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpandn	%ymm6, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm9
	vpxor	%ymm10, %ymm12, %ymm12
	vpandn	%ymm0, %ymm6, %ymm10
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	%ymm8, %ymm9, %ymm9
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	%ymm6, %ymm0, %ymm8
	vmovdqa	%ymm12, 1032(%rsp)
	vpxor	552(%rsp), %ymm3, %ymm6
	vmovdqa	%ymm7, 1000(%rsp)
	vpxor	872(%rsp), %ymm5, %ymm7
	vmovdqa	%ymm8, 968(%rsp)
	vpsrlq	$63, %ymm6, %ymm0
	vpsllq	$1, %ymm6, %ymm6
	vpor	%ymm6, %ymm0, %ymm0
	vpsrlq	$58, %ymm7, %ymm6
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm7, %ymm6, %ymm6
	vpxor	904(%rsp), %ymm2, %ymm7
	vpsrlq	$39, %ymm7, %ymm8
	vpsllq	$25, %ymm7, %ymm7
	vpor	%ymm7, %ymm8, %ymm8
	vpandn	%ymm8, %ymm6, %ymm7
	vpxor	%ymm0, %ymm7, %ymm12
	vpxor	936(%rsp), %ymm1, %ymm7
	vmovdqa	%ymm12, %ymm14
	vpshufb	.LC0(%rip), %ymm7, %ymm7
	vpandn	%ymm7, %ymm8, %ymm10
	vpxor	%ymm6, %ymm10, %ymm13
	vpsrlq	$46, %ymm11, %ymm10
	vmovdqa	%ymm13, 936(%rsp)
	vpsllq	$18, %ymm11, %ymm11
	vpor	%ymm11, %ymm10, %ymm11
	vpandn	%ymm11, %ymm7, %ymm12
	vpxor	%ymm8, %ymm12, %ymm12
	vpandn	%ymm0, %ymm11, %ymm8
	vpandn	%ymm6, %ymm0, %ymm0
	vpxor	%ymm11, %ymm0, %ymm11
	vpxor	%ymm7, %ymm8, %ymm8
	vpxor	648(%rsp), %ymm1, %ymm0
	vmovdqa	%ymm11, 872(%rsp)
	vpxor	712(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm8, 904(%rsp)
	vpsrlq	$37, %ymm0, %ymm6
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpxor	776(%rsp), %ymm4, %ymm0
	vpxor	%ymm15, %ymm4, %ymm4
	vpsrlq	$28, %ymm0, %ymm7
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpxor	840(%rsp), %ymm3, %ymm0
	vpsrlq	$54, %ymm0, %ymm10
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vmovdqa	%ymm0, 840(%rsp)
	vpxor	808(%rsp), %ymm5, %ymm0
	vpxor	584(%rsp), %ymm5, %ymm5
	vmovdqa	%ymm14, 584(%rsp)
	vpsrlq	$49, %ymm0, %ymm11
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm11, %ymm11
	vpxor	392(%rsp), %ymm2, %ymm0
	vpxor	680(%rsp), %ymm2, %ymm2
	vpandn	%ymm11, %ymm10, %ymm8
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm7, %ymm8, %ymm8
	vpandn	%ymm0, %ymm11, %ymm13
	vpxor	%ymm10, %ymm13, %ymm10
	vmovdqa	%ymm10, 808(%rsp)
	vpandn	%ymm6, %ymm0, %ymm10
	vpandn	%ymm7, %ymm6, %ymm6
	vpxor	%ymm0, %ymm6, %ymm0
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	520(%rsp), %ymm14, %ymm11
	vmovdqa	%ymm0, 776(%rsp)
	vpsrlq	$2, %ymm5, %ymm0
	vpsllq	$62, %ymm5, %ymm5
	vpor	%ymm5, %ymm0, %ymm0
	vpsrlq	$9, %ymm2, %ymm5
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm2, %ymm5, %ymm2
	vpsrlq	$25, %ymm1, %ymm5
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm5, %ymm1
	vpandn	%ymm1, %ymm2, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vpxor	840(%rsp), %ymm7, %ymm5
	vpxor	%ymm5, %ymm11, %ymm11
	vpsrlq	$23, %ymm4, %ymm5
	vpxor	744(%rsp), %ymm11, %ymm11
	vpsllq	$41, %ymm4, %ymm4
	vpor	%ymm4, %ymm5, %ymm4
	vpandn	%ymm4, %ymm1, %ymm5
	vpxor	%ymm2, %ymm5, %ymm15
	vpxor	936(%rsp), %ymm8, %ymm5
	vmovdqa	%ymm15, %ymm14
	vpxor	424(%rsp), %ymm9, %ymm15
	vmovdqa	%ymm14, 392(%rsp)
	vpxor	360(%rsp), %ymm3, %ymm3
	vmovdqa	1032(%rsp), %ymm13
	vpxor	%ymm5, %ymm15, %ymm15
	vpsrlq	$62, %ymm3, %ymm5
	vpsllq	$2, %ymm3, %ymm3
	vpxor	%ymm14, %ymm15, %ymm15
	vpxor	456(%rsp), %ymm13, %ymm14
	vpor	%ymm3, %ymm5, %ymm3
	vpandn	%ymm3, %ymm4, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	808(%rsp), %ymm12, %ymm1
	vpxor	%ymm1, %ymm14, %ymm14
	vpandn	%ymm0, %ymm3, %ymm1
	vpandn	%ymm2, %ymm0, %ymm0
	vmovdqa	968(%rsp), %ymm2
	vpxor	%ymm4, %ymm1, %ymm4
	vpxor	%ymm3, %ymm0, %ymm0
	vpxor	%ymm6, %ymm14, %ymm14
	vmovdqa	1000(%rsp), %ymm1
	vpxor	616(%rsp), %ymm1, %ymm13
	vpsrlq	$63, %ymm15, %ymm3
	vpxor	%ymm4, %ymm10, %ymm1
	vmovdqa	%ymm4, 360(%rsp)
	vpxor	488(%rsp), %ymm2, %ymm4
	vpsrlq	$63, %ymm14, %ymm2
	vpxor	%ymm1, %ymm13, %ymm13
	vpxor	872(%rsp), %ymm0, %ymm1
	vpxor	904(%rsp), %ymm13, %ymm13
	vpxor	%ymm1, %ymm4, %ymm4
	vpsllq	$1, %ymm15, %ymm1
	vpxor	776(%rsp), %ymm4, %ymm4
	vpor	%ymm1, %ymm3, %ymm3
	vpsllq	$1, %ymm14, %ymm1
	vpsllq	$1, %ymm13, %ymm5
	vpor	%ymm1, %ymm2, %ymm2
	vpxor	%ymm4, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm1
	vpxor	%ymm11, %ymm2, %ymm2
	vpxor	%ymm3, %ymm7, %ymm7
	vpor	%ymm5, %ymm1, %ymm1
	vpsrlq	$63, %ymm4, %ymm5
	vpxor	%ymm2, %ymm9, %ymm9
	vpsllq	$1, %ymm4, %ymm4
	vpxor	%ymm15, %ymm1, %ymm1
	vpxor	%ymm2, %ymm8, %ymm8
	vpor	%ymm4, %ymm5, %ymm4
	vpsrlq	$63, %ymm11, %ymm5
	vpxor	%ymm1, %ymm12, %ymm12
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm14, %ymm4, %ymm4
	vpxor	%ymm1, %ymm6, %ymm6
	vbroadcastsd	160+KeccakF1600RoundConstants(%rip), %ymm14
	vpor	%ymm11, %ymm5, %ymm11
	vpxor	%ymm4, %ymm10, %ymm10
	vpxor	744(%rsp), %ymm3, %ymm5
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm11, %ymm0, %ymm0
	vpor	%ymm9, %ymm13, %ymm9
	vpsrlq	$21, %ymm12, %ymm13
	vpsllq	$43, %ymm12, %ymm12
	vpor	%ymm12, %ymm13, %ymm12
	vpandn	%ymm12, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm10, %ymm13, %ymm10
	vpandn	%ymm10, %ymm12, %ymm13
	vpxor	%ymm9, %ymm13, %ymm15
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm15, 744(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm10, %ymm13
	vpxor	%ymm12, %ymm13, %ymm12
	vmovdqa	%ymm12, 712(%rsp)
	vpandn	%ymm5, %ymm0, %ymm12
	vpandn	%ymm9, %ymm5, %ymm5
	vpxor	968(%rsp), %ymm11, %ymm9
	vpxor	%ymm0, %ymm5, %ymm0
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	616(%rsp), %ymm4, %ymm5
	vmovdqa	%ymm0, 648(%rsp)
	vpsrlq	$3, %ymm6, %ymm12
	vpsllq	$61, %ymm6, %ymm6
	vpsrlq	$36, %ymm5, %ymm0
	vpsllq	$28, %ymm5, %ymm5
	vpor	%ymm6, %ymm12, %ymm6
	vmovdqa	%ymm10, 680(%rsp)
	vpor	%ymm5, %ymm0, %ymm0
	vpsrlq	$44, %ymm9, %ymm5
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm9, %ymm5, %ymm5
	vpxor	584(%rsp), %ymm3, %ymm9
	vpsrlq	$61, %ymm9, %ymm10
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm5, %ymm9
	vpxor	%ymm0, %ymm9, %ymm9
	vmovdqa	%ymm9, 968(%rsp)
	vpsrlq	$19, %ymm8, %ymm9
	vpsllq	$45, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm8
	vpandn	%ymm6, %ymm8, %ymm12
	vpandn	%ymm8, %ymm10, %ymm9
	vpxor	%ymm10, %ymm12, %ymm15
	vpxor	%ymm5, %ymm9, %ymm9
	vpandn	%ymm0, %ymm6, %ymm10
	vpandn	%ymm5, %ymm0, %ymm0
	vpxor	%ymm8, %ymm10, %ymm8
	vpxor	424(%rsp), %ymm2, %ymm5
	vmovdqa	%ymm15, 616(%rsp)
	vmovdqa	%ymm8, 584(%rsp)
	vpxor	%ymm6, %ymm0, %ymm0
	vpxor	1032(%rsp), %ymm1, %ymm6
	vmovdqa	%ymm0, 552(%rsp)
	vpsrlq	$63, %ymm5, %ymm0
	vpsllq	$1, %ymm5, %ymm5
	vpor	%ymm5, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm5
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm5, %ymm5
	vpxor	904(%rsp), %ymm4, %ymm6
	vpsrlq	$39, %ymm6, %ymm10
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm10, %ymm10
	vpandn	%ymm10, %ymm5, %ymm6
	vpxor	%ymm0, %ymm6, %ymm8
	vpxor	776(%rsp), %ymm11, %ymm6
	vmovdqa	%ymm8, 1032(%rsp)
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm10, %ymm8
	vpxor	%ymm5, %ymm8, %ymm13
	vpsrlq	$46, %ymm7, %ymm8
	vmovdqa	%ymm13, 904(%rsp)
	vpsllq	$18, %ymm7, %ymm7
	vpor	%ymm7, %ymm8, %ymm7
	vpandn	%ymm7, %ymm6, %ymm8
	vpxor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm0, %ymm7, %ymm10
	vpandn	%ymm5, %ymm0, %ymm0
	vpxor	%ymm7, %ymm0, %ymm7
	vpxor	%ymm6, %ymm10, %ymm15
	vmovdqa	%ymm7, 776(%rsp)
	vpxor	488(%rsp), %ymm11, %ymm0
	vpsrlq	$37, %ymm0, %ymm5
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	520(%rsp), %ymm3, %ymm0
	vpxor	840(%rsp), %ymm3, %ymm3
	vpsrlq	$28, %ymm0, %ymm10
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm10, %ymm10
	vpxor	936(%rsp), %ymm2, %ymm0
	vpxor	392(%rsp), %ymm2, %ymm2
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm10, %ymm0
	vpxor	%ymm5, %ymm0, %ymm6
	vpxor	808(%rsp), %ymm1, %ymm0
	vpxor	456(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm6, 936(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	360(%rsp), %ymm4, %ymm0
	vpxor	1000(%rsp), %ymm4, %ymm4
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm10, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm7
	vmovdqa	%ymm7, 808(%rsp)
	vpandn	%ymm5, %ymm0, %ymm7
	vpandn	%ymm10, %ymm5, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlq	$2, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vmovdqa	%ymm5, 520(%rsp)
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$9, %ymm4, %ymm1
	vpsllq	$55, %ymm4, %ymm4
	vpor	%ymm4, %ymm1, %ymm1
	vpxor	872(%rsp), %ymm11, %ymm4
	vmovdqa	%ymm14, 872(%rsp)
	vpsrlq	$25, %ymm4, %ymm11
	vpsllq	$39, %ymm4, %ymm4
	vpor	%ymm4, %ymm11, %ymm11
	vmovdqa	1032(%rsp), %ymm4
	vpxor	968(%rsp), %ymm4, %ymm4
	vpandn	%ymm11, %ymm1, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	936(%rsp), %ymm5, %ymm10
	vpxor	%ymm4, %ymm10, %ymm10
	vpsrlq	$23, %ymm3, %ymm4
	vpsllq	$41, %ymm3, %ymm3
	vpxor	%ymm14, %ymm10, %ymm10
	vpxor	904(%rsp), %ymm6, %ymm14
	vpor	%ymm3, %ymm4, %ymm4
	vpandn	%ymm4, %ymm11, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, %ymm13
	vpxor	744(%rsp), %ymm9, %ymm3
	vmovdqa	%ymm13, 360(%rsp)
	vpxor	%ymm3, %ymm14, %ymm14
	vpsrlq	$62, %ymm2, %ymm3
	vpsllq	$2, %ymm2, %ymm2
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	808(%rsp), %ymm8, %ymm13
	vpor	%ymm2, %ymm3, %ymm3
	vpandn	%ymm3, %ymm4, %ymm2
	vpxor	%ymm11, %ymm2, %ymm12
	vmovdqa	%ymm12, 1000(%rsp)
	vmovdqa	616(%rsp), %ymm12
	vpxor	712(%rsp), %ymm12, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm3, %ymm11
	vpandn	%ymm1, %ymm0, %ymm0
	vmovdqa	552(%rsp), %ymm1
	vpxor	%ymm4, %ymm11, %ymm4
	vpxor	%ymm3, %ymm0, %ymm0
	vmovdqa	584(%rsp), %ymm11
	vpxor	648(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm4, 392(%rsp)
	vpxor	%ymm4, %ymm7, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	680(%rsp), %ymm11, %ymm4
	vpxor	776(%rsp), %ymm0, %ymm11
	vpxor	1000(%rsp), %ymm13, %ymm13
	vpxor	%ymm4, %ymm12, %ymm12
	vpxor	%ymm1, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm1
	vpxor	%ymm15, %ymm12, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpsllq	$1, %ymm12, %ymm2
	vpor	%ymm1, %ymm3, %ymm3
	vpxor	520(%rsp), %ymm11, %ymm11
	vpsrlq	$63, %ymm13, %ymm1
	vpor	%ymm4, %ymm1, %ymm1
	vpsrlq	$63, %ymm12, %ymm4
	vpor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm11, %ymm3, %ymm3
	vpxor	%ymm10, %ymm1, %ymm1
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpxor	%ymm1, %ymm9, %ymm9
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm8, %ymm8
	vpxor	%ymm1, %ymm6, %ymm6
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm3, %ymm5, %ymm5
	vbroadcastsd	168+KeccakF1600RoundConstants(%rip), %ymm14
	vpxor	1000(%rsp), %ymm4, %ymm2
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	872(%rsp), %ymm3, %ymm12
	vpor	%ymm9, %ymm13, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm8, %ymm13, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm13
	vmovdqa	%ymm13, 872(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 840(%rsp)
	vpandn	%ymm12, %ymm0, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm7, %ymm8, %ymm8
	vpxor	%ymm0, %ymm12, %ymm9
	vpxor	680(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm8, 488(%rsp)
	vpsrlq	$3, %ymm2, %ymm12
	vpsllq	$61, %ymm2, %ymm2
	vpxor	552(%rsp), %ymm10, %ymm8
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm2, %ymm12, %ymm2
	vmovdqa	%ymm9, 456(%rsp)
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1032(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 1032(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm2, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 1000(%rsp)
	vpandn	%ymm0, %ymm2, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm2
	vpxor	%ymm6, %ymm9, %ymm6
	vmovdqa	%ymm2, 552(%rsp)
	vpxor	744(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm6, 680(%rsp)
	vpxor	616(%rsp), %ymm4, %ymm6
	vpsrlq	$63, %ymm2, %ymm0
	vpsllq	$1, %ymm2, %ymm2
	vpor	%ymm2, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm2
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm2, %ymm2
	vpxor	%ymm11, %ymm15, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm2, %ymm6
	vpxor	%ymm0, %ymm6, %ymm15
	vpxor	520(%rsp), %ymm10, %ymm6
	vmovdqa	%ymm15, 744(%rsp)
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm2, %ymm9, %ymm12
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm12, 616(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm2, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm2
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	648(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm2, 424(%rsp)
	vmovdqa	%ymm7, 520(%rsp)
	vpsrlq	$37, %ymm0, %ymm2
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm2, %ymm2
	vpxor	968(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	904(%rsp), %ymm1, %ymm0
	vpsrlq	$54, %ymm0, %ymm12
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpandn	%ymm12, %ymm5, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, 968(%rsp)
	vpxor	808(%rsp), %ymm4, %ymm0
	vpsrlq	$49, %ymm0, %ymm6
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpxor	392(%rsp), %ymm11, %ymm0
	vpandn	%ymm6, %ymm12, %ymm7
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm7, %ymm7
	vpandn	%ymm0, %ymm6, %ymm13
	vpxor	%ymm12, %ymm13, %ymm12
	vmovdqa	%ymm12, %ymm13
	vpandn	%ymm2, %ymm0, %ymm12
	vpandn	%ymm5, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm0
	vpxor	%ymm6, %ymm12, %ymm12
	vpxor	712(%rsp), %ymm4, %ymm2
	vpxor	584(%rsp), %ymm11, %ymm4
	vmovdqa	%ymm0, %ymm15
	vpsrlq	$2, %ymm2, %ymm0
	vpsllq	$62, %ymm2, %ymm2
	vpor	%ymm2, %ymm0, %ymm0
	vpsrlq	$9, %ymm4, %ymm2
	vpsllq	$55, %ymm4, %ymm4
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	776(%rsp), %ymm10, %ymm4
	vpxor	936(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm14, 904(%rsp)
	vpxor	360(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm13, 392(%rsp)
	vmovdqa	%ymm15, 360(%rsp)
	vpsrlq	$25, %ymm4, %ymm6
	vpsllq	$39, %ymm4, %ymm4
	vpor	%ymm4, %ymm6, %ymm6
	vmovdqa	744(%rsp), %ymm4
	vpxor	1032(%rsp), %ymm4, %ymm4
	vpandn	%ymm6, %ymm2, %ymm10
	vpxor	%ymm0, %ymm10, %ymm10
	vpxor	968(%rsp), %ymm10, %ymm11
	vpxor	%ymm4, %ymm11, %ymm11
	vpsrlq	$23, %ymm3, %ymm4
	vpsllq	$41, %ymm3, %ymm3
	vpxor	%ymm14, %ymm11, %ymm11
	vpor	%ymm3, %ymm4, %ymm4
	vpandn	%ymm4, %ymm6, %ymm3
	vpxor	%ymm2, %ymm3, %ymm5
	vpxor	872(%rsp), %ymm8, %ymm3
	vmovdqa	%ymm5, %ymm14
	vpxor	616(%rsp), %ymm7, %ymm5
	vmovdqa	%ymm14, 328(%rsp)
	vpxor	%ymm3, %ymm5, %ymm5
	vpsrlq	$62, %ymm1, %ymm3
	vpsllq	$2, %ymm1, %ymm1
	vpxor	%ymm14, %ymm5, %ymm5
	vpxor	%ymm13, %ymm9, %ymm14
	vmovdqa	1000(%rsp), %ymm13
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm4, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	840(%rsp), %ymm13, %ymm6
	vpxor	%ymm6, %ymm14, %ymm14
	vpandn	%ymm0, %ymm3, %ymm6
	vpandn	%ymm2, %ymm0, %ymm0
	vmovdqa	552(%rsp), %ymm2
	vpxor	%ymm4, %ymm6, %ymm4
	vpxor	%ymm3, %ymm0, %ymm0
	vpxor	%ymm1, %ymm14, %ymm14
	vmovdqa	680(%rsp), %ymm6
	vmovdqa	%ymm4, 296(%rsp)
	vpxor	%ymm4, %ymm12, %ymm13
	vpsrlq	$63, %ymm5, %ymm3
	vpxor	488(%rsp), %ymm6, %ymm4
	vpxor	456(%rsp), %ymm2, %ymm2
	vpsllq	$1, %ymm14, %ymm6
	vpxor	%ymm4, %ymm13, %ymm13
	vpxor	424(%rsp), %ymm0, %ymm4
	vpxor	520(%rsp), %ymm13, %ymm13
	vpxor	%ymm2, %ymm4, %ymm4
	vpsllq	$1, %ymm5, %ymm2
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm14, %ymm2
	vpxor	%ymm15, %ymm4, %ymm4
	vpor	%ymm6, %ymm2, %ymm2
	vpsllq	$1, %ymm13, %ymm15
	vpxor	%ymm4, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm6
	vpxor	%ymm11, %ymm2, %ymm2
	vpxor	%ymm3, %ymm10, %ymm10
	vpor	%ymm15, %ymm6, %ymm6
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm5, %ymm6, %ymm6
	vpsrlq	$63, %ymm4, %ymm5
	vpsllq	$1, %ymm4, %ymm4
	vpxor	%ymm6, %ymm9, %ymm9
	vpxor	%ymm6, %ymm1, %ymm1
	vpor	%ymm4, %ymm5, %ymm5
	vpsrlq	$63, %ymm11, %ymm4
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm14, %ymm5, %ymm5
	vbroadcastsd	176+KeccakF1600RoundConstants(%rip), %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	904(%rsp), %ymm3, %ymm11
	vpxor	%ymm13, %ymm4, %ymm4
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm4, %ymm0, %ymm0
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	%ymm14, %ymm13, %ymm13
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	%ymm13, 936(%rsp)
	vpsrlq	$43, %ymm12, %ymm13
	vpsllq	$21, %ymm12, %ymm12
	vpor	%ymm12, %ymm13, %ymm12
	vpandn	%ymm12, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 904(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm9, %ymm13, %ymm13
	vpandn	%ymm11, %ymm0, %ymm9
	vpandn	%ymm8, %ymm11, %ymm11
	vpxor	%ymm0, %ymm11, %ymm8
	vpxor	%ymm12, %ymm9, %ymm9
	vpxor	744(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm8, 776(%rsp)
	vpxor	488(%rsp), %ymm5, %ymm8
	vmovdqa	%ymm9, 808(%rsp)
	vpxor	552(%rsp), %ymm4, %ymm9
	vpsrlq	$36, %ymm8, %ymm0
	vpsllq	$28, %ymm8, %ymm8
	vpor	%ymm8, %ymm0, %ymm0
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm9, %ymm8, %ymm8
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm11, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm11
	vpxor	%ymm0, %ymm11, %ymm15
	vpsrlq	$19, %ymm7, %ymm11
	vpsllq	$45, %ymm7, %ymm7
	vmovdqa	%ymm15, %ymm14
	vpor	%ymm7, %ymm11, %ymm7
	vpandn	%ymm7, %ymm9, %ymm11
	vpxor	%ymm8, %ymm11, %ymm15
	vpsrlq	$3, %ymm1, %ymm11
	vmovdqa	%ymm15, 744(%rsp)
	vpsllq	$61, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm1
	vpandn	%ymm1, %ymm7, %ymm11
	vpxor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	%ymm1, %ymm0, %ymm8
	vmovdqa	%ymm11, 712(%rsp)
	vmovdqa	%ymm7, 648(%rsp)
	vpxor	872(%rsp), %ymm2, %ymm1
	vpxor	1000(%rsp), %ymm6, %ymm7
	vmovdqa	%ymm8, 584(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm7, %ymm1
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	520(%rsp), %ymm5, %ymm7
	vpsrlq	$39, %ymm7, %ymm8
	vpsllq	$25, %ymm7, %ymm7
	vpor	%ymm7, %ymm8, %ymm8
	vpandn	%ymm8, %ymm1, %ymm7
	vpxor	%ymm0, %ymm7, %ymm9
	vpxor	360(%rsp), %ymm4, %ymm7
	vmovdqa	%ymm9, 1000(%rsp)
	vpshufb	.LC0(%rip), %ymm7, %ymm7
	vpandn	%ymm7, %ymm8, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 872(%rsp)
	vpsrlq	$46, %ymm10, %ymm9
	vpsllq	$18, %ymm10, %ymm10
	vpor	%ymm10, %ymm9, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm0, %ymm10, %ymm8
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm10, %ymm0, %ymm10
	vpxor	%ymm7, %ymm8, %ymm7
	vpxor	456(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm10, 520(%rsp)
	vmovdqa	%ymm7, 552(%rsp)
	vpsrlq	$37, %ymm0, %ymm8
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm8, %ymm8
	vpxor	1032(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm10
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm10, %ymm10
	vpxor	616(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm10, %ymm0
	vpxor	%ymm8, %ymm0, %ymm1
	vpxor	392(%rsp), %ymm6, %ymm0
	vmovdqa	%ymm1, 1032(%rsp)
	vpsrlq	$49, %ymm0, %ymm11
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm11, %ymm11
	vpxor	296(%rsp), %ymm5, %ymm0
	vpandn	%ymm11, %ymm7, %ymm1
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm10, %ymm1, %ymm1
	vpandn	%ymm0, %ymm11, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpandn	%ymm8, %ymm0, %ymm7
	vpandn	%ymm10, %ymm8, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm12, %ymm15
	vpxor	%ymm11, %ymm7, %ymm7
	vpxor	840(%rsp), %ymm6, %ymm0
	vmovdqa	%ymm14, 840(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpxor	680(%rsp), %ymm5, %ymm0
	vpxor	872(%rsp), %ymm1, %ymm5
	vpsrlq	$9, %ymm0, %ymm12
	vpsllq	$55, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	424(%rsp), %ymm4, %ymm0
	vpsrlq	$25, %ymm0, %ymm4
	vpsllq	$39, %ymm0, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpandn	%ymm4, %ymm12, %ymm0
	vpxor	%ymm6, %ymm0, %ymm10
	vmovdqa	1000(%rsp), %ymm0
	vmovdqa	%ymm10, 680(%rsp)
	vpxor	1032(%rsp), %ymm10, %ymm10
	vpxor	%ymm14, %ymm0, %ymm0
	vpxor	%ymm0, %ymm10, %ymm10
	vpxor	968(%rsp), %ymm3, %ymm0
	vpxor	936(%rsp), %ymm10, %ymm10
	vmovdqa	%ymm15, 968(%rsp)
	vpsrlq	$23, %ymm0, %ymm3
	vpsllq	$41, %ymm0, %ymm0
	vpor	%ymm0, %ymm3, %ymm3
	vpandn	%ymm3, %ymm4, %ymm0
	vpxor	%ymm12, %ymm0, %ymm11
	vmovdqa	%ymm11, %ymm14
	vmovdqa	744(%rsp), %ymm11
	vpxor	904(%rsp), %ymm11, %ymm0
	vmovdqa	%ymm14, 616(%rsp)
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	328(%rsp), %ymm2, %ymm0
	vpxor	%ymm14, %ymm5, %ymm5
	vpxor	%ymm15, %ymm9, %ymm14
	vpsrlq	$62, %ymm0, %ymm2
	vpsllq	$2, %ymm0, %ymm0
	vpor	%ymm0, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	712(%rsp), %ymm13, %ymm4
	vpxor	%ymm4, %ymm14, %ymm14
	vpandn	%ymm6, %ymm2, %ymm4
	vpandn	%ymm12, %ymm6, %ymm6
	vmovdqa	584(%rsp), %ymm12
	vpxor	%ymm3, %ymm4, %ymm3
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm0, %ymm14, %ymm14
	vpxor	776(%rsp), %ymm12, %ymm2
	vpsrlq	$63, %ymm14, %ymm12
	vpxor	%ymm3, %ymm7, %ymm11
	vmovdqa	%ymm3, 488(%rsp)
	vpxor	520(%rsp), %ymm6, %ymm4
	vmovdqa	648(%rsp), %ymm3
	vpxor	808(%rsp), %ymm3, %ymm3
	vpxor	%ymm2, %ymm4, %ymm4
	vpsllq	$1, %ymm5, %ymm2
	vpxor	%ymm3, %ymm11, %ymm11
	vpsrlq	$63, %ymm5, %ymm3
	vpxor	%ymm8, %ymm4, %ymm4
	vpxor	552(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsllq	$1, %ymm14, %ymm2
	vpxor	%ymm4, %ymm3, %ymm3
	vpsllq	$1, %ymm11, %ymm15
	vpor	%ymm2, %ymm12, %ymm12
	vpsrlq	$63, %ymm11, %ymm2
	vpxor	%ymm10, %ymm12, %ymm12
	vpor	%ymm15, %ymm2, %ymm2
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm5, %ymm2, %ymm2
	vpsrlq	$63, %ymm4, %ymm5
	vpsllq	$1, %ymm4, %ymm4
	vpxor	%ymm2, %ymm9, %ymm9
	vpxor	%ymm2, %ymm0, %ymm0
	vpor	%ymm4, %ymm5, %ymm5
	vpsrlq	$63, %ymm10, %ymm4
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm14, %ymm5, %ymm5
	vpxor	936(%rsp), %ymm3, %ymm14
	vpor	%ymm10, %ymm4, %ymm4
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	744(%rsp), %ymm12, %ymm10
	vmovdqa	%ymm14, 936(%rsp)
	vpxor	%ymm11, %ymm4, %ymm4
	vpsrlq	$20, %ymm10, %ymm11
	vpsllq	$44, %ymm10, %ymm10
	vpxor	%ymm4, %ymm6, %ymm6
	vpor	%ymm10, %ymm11, %ymm11
	vpsrlq	$21, %ymm9, %ymm10
	vmovdqa	%ymm11, 744(%rsp)
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm10, %ymm10
	vbroadcastsd	184+KeccakF1600RoundConstants(%rip), %ymm9
	vmovdqa	%ymm10, 456(%rsp)
	vpandn	%ymm10, %ymm11, %ymm15
	vmovapd	%ymm9, 264(%rsp)
	vpsrlq	$43, %ymm7, %ymm9
	vpsllq	$21, %ymm7, %ymm7
	vmovdqa	%ymm15, 296(%rsp)
	vpor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 424(%rsp)
	vpandn	%ymm9, %ymm10, %ymm7
	vmovdqa	%ymm7, 232(%rsp)
	vpsrlq	$50, %ymm6, %ymm7
	vpsllq	$14, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpxor	808(%rsp), %ymm5, %ymm6
	vmovdqa	%ymm7, 392(%rsp)
	vpandn	%ymm7, %ymm9, %ymm15
	vmovdqa	%ymm15, 200(%rsp)
	vpandn	%ymm14, %ymm7, %ymm15
	vpandn	%ymm11, %ymm14, %ymm7
	vmovdqa	%ymm7, 136(%rsp)
	vpsrlq	$36, %ymm6, %ymm7
	vpsllq	$28, %ymm6, %ymm6
	vmovdqa	%ymm15, 168(%rsp)
	vpor	%ymm6, %ymm7, %ymm6
	vmovdqa	%ymm6, %ymm11
	vpxor	584(%rsp), %ymm4, %ymm6
	vpsrlq	$44, %ymm6, %ymm7
	vpsllq	$20, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm6
	vmovdqa	%ymm6, %ymm9
	vpxor	1000(%rsp), %ymm3, %ymm6
	vpsrlq	$61, %ymm6, %ymm7
	vpsllq	$3, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm6
	vmovdqa	%ymm6, %ymm10
	vpandn	%ymm6, %ymm9, %ymm6
	vmovdqa	%ymm6, 104(%rsp)
	vpsrlq	$19, %ymm1, %ymm6
	vpsllq	$45, %ymm1, %ymm1
	vmovdqa	%ymm10, 584(%rsp)
	vpor	%ymm1, %ymm6, %ymm6
	vmovdqa	%ymm6, 360(%rsp)
	vpandn	%ymm6, %ymm10, %ymm1
	vmovdqa	%ymm1, 72(%rsp)
	vpsrlq	$3, %ymm0, %ymm1
	vpsllq	$61, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm0
	vpandn	%ymm0, %ymm6, %ymm1
	vpandn	%ymm11, %ymm0, %ymm15
	vmovdqa	%ymm0, 328(%rsp)
	vmovdqa	%ymm1, 40(%rsp)
	vmovdqa	%ymm15, 8(%rsp)
	vmovdqa	%ymm11, 1000(%rsp)
	vpandn	%ymm9, %ymm11, %ymm11
	vpxor	904(%rsp), %ymm12, %ymm0
	vmovdqa	%ymm11, -24(%rsp)
	vmovdqa	%ymm9, 808(%rsp)
	vpsrlq	$63, %ymm0, %ymm1
	vpsllq	$1, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm6
	vpxor	712(%rsp), %ymm2, %ymm0
	vmovdqa	%ymm6, 904(%rsp)
	vpsrlq	$58, %ymm0, %ymm1
	vpsllq	$6, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm15
	vpxor	552(%rsp), %ymm5, %ymm0
	vpsrlq	$39, %ymm0, %ymm1
	vpsllq	$25, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm7
	vpxor	%ymm4, %ymm8, %ymm1
	vpshufb	.LC0(%rip), %ymm1, %ymm1
	vpandn	%ymm7, %ymm15, %ymm0
	vmovdqa	%ymm7, 712(%rsp)
	vmovdqa	%ymm0, 552(%rsp)
	vpandn	%ymm1, %ymm7, %ymm8
	vpxor	680(%rsp), %ymm3, %ymm0
	vmovdqa	%ymm8, -56(%rsp)
	vpsrlq	$46, %ymm0, %ymm11
	vpsllq	$18, %ymm0, %ymm0
	vpor	%ymm0, %ymm11, %ymm11
	vpandn	%ymm15, %ymm6, %ymm0
	vpandn	%ymm11, %ymm1, %ymm10
	vmovdqa	%ymm0, -120(%rsp)
	vpxor	776(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm10, 680(%rsp)
	vpandn	%ymm6, %ymm11, %ymm10
	vmovdqa	%ymm10, -88(%rsp)
	vpsrlq	$37, %ymm0, %ymm10
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm10, %ymm10
	vpxor	840(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm9
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm9, %ymm9
	vpxor	872(%rsp), %ymm12, %ymm0
	vpxor	616(%rsp), %ymm12, %ymm12
	vpsrlq	$54, %ymm0, %ymm8
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm8, %ymm8
	vpxor	968(%rsp), %ymm2, %ymm0
	vpxor	%ymm2, %ymm13, %ymm2
	vpandn	%ymm8, %ymm9, %ymm7
	vmovdqa	%ymm7, 872(%rsp)
	vpsrlq	$49, %ymm0, %ymm7
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpxor	488(%rsp), %ymm5, %ymm0
	vpandn	%ymm7, %ymm8, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vmovdqa	%ymm6, 968(%rsp)
	vpandn	%ymm0, %ymm7, %ymm6
	vmovdqa	%ymm6, 840(%rsp)
	vpandn	%ymm10, %ymm0, %ymm6
	vmovdqa	%ymm6, 776(%rsp)
	vpandn	%ymm9, %ymm10, %ymm6
	vmovdqa	%ymm6, 488(%rsp)
	vpsrlq	$2, %ymm2, %ymm6
	vpsllq	$62, %ymm2, %ymm2
	vpor	%ymm2, %ymm6, %ymm6
	vpxor	648(%rsp), %ymm5, %ymm2
	vpsrlq	$9, %ymm2, %ymm5
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm2, %ymm5, %ymm5
	vpxor	520(%rsp), %ymm4, %ymm2
	vpsrlq	$25, %ymm2, %ymm4
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm2, %ymm4, %ymm4
	vpxor	1032(%rsp), %ymm3, %ymm2
	vpandn	%ymm4, %ymm5, %ymm13
	vmovdqa	%ymm13, 648(%rsp)
	vpsrlq	$23, %ymm2, %ymm3
	vpsllq	$41, %ymm2, %ymm2
	vpor	%ymm2, %ymm3, %ymm3
	vpandn	%ymm3, %ymm4, %ymm2
	vmovdqa	%ymm2, 1032(%rsp)
	vpsrlq	$62, %ymm12, %ymm2
	vpsllq	$2, %ymm12, %ymm12
	vpor	%ymm12, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm13
	vmovdqa	%ymm13, 616(%rsp)
	vpandn	%ymm6, %ymm2, %ymm13
	vmovdqa	%ymm13, 520(%rsp)
	vpandn	%ymm5, %ymm6, %ymm13
	vmovdqa	264(%rsp), %ymm14
	vpxor	296(%rsp), %ymm14, %ymm12
	vpxor	936(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm13, %ymm13
	vmovdqa	200(%rsp), %ymm14
	vmovdqa	%ymm12, (%rdi)
	vmovdqa	744(%rsp), %ymm12
	vpxor	232(%rsp), %ymm12, %ymm12
	vmovdqa	%ymm12, 32(%rdi)
	vpxor	456(%rsp), %ymm14, %ymm12
	vmovdqa	168(%rsp), %ymm14
	vmovdqa	%ymm12, 64(%rdi)
	vpxor	424(%rsp), %ymm14, %ymm12
	vmovdqa	136(%rsp), %ymm14
	vmovdqa	%ymm12, 96(%rdi)
	vpxor	392(%rsp), %ymm14, %ymm12
	vmovdqa	40(%rsp), %ymm14
	vmovdqa	%ymm12, 128(%rdi)
	vmovdqa	1000(%rsp), %ymm12
	vpxor	104(%rsp), %ymm12, %ymm12
	vmovdqa	%ymm12, 160(%rdi)
	vmovdqa	808(%rsp), %ymm12
	vpxor	72(%rsp), %ymm12, %ymm12
	vmovdqa	%ymm12, 192(%rdi)
	vpxor	584(%rsp), %ymm14, %ymm12
	vmovdqa	8(%rsp), %ymm14
	vmovdqa	%ymm12, 224(%rdi)
	vpxor	360(%rsp), %ymm14, %ymm12
	vmovdqa	-24(%rsp), %ymm14
	vmovdqa	%ymm12, 256(%rdi)
	vpxor	328(%rsp), %ymm14, %ymm12
	vmovdqa	%ymm12, 288(%rdi)
	vmovdqa	904(%rsp), %ymm12
	vpxor	552(%rsp), %ymm12, %ymm12
	vpxor	-88(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm13, 768(%rdi)
	vpxor	488(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm12, 320(%rdi)
	vpxor	-56(%rsp), %ymm15, %ymm12
	vpxor	520(%rsp), %ymm3, %ymm14
	vmovdqa	%ymm1, 416(%rdi)
	vpxor	-120(%rsp), %ymm11, %ymm1
	vmovdqa	712(%rsp), %ymm15
	vmovdqa	%ymm0, 608(%rdi)
	vpxor	648(%rsp), %ymm6, %ymm0
	vmovdqa	%ymm1, 448(%rdi)
	vpxor	872(%rsp), %ymm10, %ymm1
	vmovdqa	%ymm12, 352(%rdi)
	vpxor	680(%rsp), %ymm15, %ymm12
	vpxor	616(%rsp), %ymm4, %ymm15
	vmovdqa	%ymm1, 480(%rdi)
	vpxor	968(%rsp), %ymm9, %ymm1
	vmovdqa	%ymm0, 640(%rdi)
	vpxor	1032(%rsp), %ymm5, %ymm0
	vmovdqa	%ymm1, 512(%rdi)
	vpxor	840(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm12, 384(%rdi)
	vmovdqa	%ymm1, 544(%rdi)
	vpxor	776(%rsp), %ymm7, %ymm1
	vmovdqa	%ymm0, 672(%rdi)
	vmovdqa	%ymm1, 576(%rdi)
	vmovdqa	%ymm15, 704(%rdi)
	vmovdqa	%ymm14, 736(%rdi)
	vzeroupper
	leave
	ret
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_12rounds, .-ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_12rounds
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakF1600times4_FastLoop_Absorb
	.type	ossl_keccak1600x4_avx2_KeccakF1600times4_FastLoop_Absorb, @function
ossl_keccak1600x4_avx2_KeccakF1600times4_FastLoop_Absorb:
	endbr64
	pushq	%rbp
	movl	%ecx, %eax
	movq	%rsp, %rbp
	pushq	%r15
	leal	(%rdx,%rdx,2), %r15d
	pushq	%r14
	movq	%rdi, %r14
	pushq	%r13
	movl	%edx, %r13d
	pushq	%r12
	movq	%r9, %r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$1600, %rsp
	movq	%r8, 24(%rsp)
	cmpl	$21, %esi
	je	.L428
	addl	%esi, %r15d
	movl	%esi, %r10d
	movq	%r8, %rbx
	xorl	%eax, %eax
	leal	0(,%r15,8), %esi
	leal	0(,%rcx,8), %r15d
	movq	%rsi, 1568(%rsp)
	cmpq	%rsi, %r9
	jb	.L427
	movl	%r10d, 1536(%rsp)
	.p2align 4,,10
	.p2align 3
.L434:
	movl	1536(%rsp), %edx
	movq	%rbx, %rsi
	movl	%r13d, %ecx
	movq	%r14, %rdi
	addq	%r15, %rbx
	subq	%r15, %r12
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_AddLanesAll@PLT
	movq	%r14, %rdi
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds@PLT
	cmpq	1568(%rsp), %r12
	jnb	.L434
	movq	%rbx, %rax
	subq	24(%rsp), %rax
.L427:
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L428:
	vmovdqa	32(%r14), %ymm4
	sall	$4, %r13d
	vmovdqa	128(%r14), %ymm11
	leal	0(,%r15,8), %ecx
	vmovdqa	352(%r14), %ymm9
	vmovdqa	(%r14), %ymm14
	movq	%rcx, %r15
	movq	%r8, %rbx
	vmovdqa	%ymm4, 1408(%rsp)
	addq	%r8, %rcx
	vmovdqa	%ymm11, %ymm3
	vmovdqa	96(%r14), %ymm4
	vmovdqa	544(%r14), %ymm8
	vmovdqa	64(%r14), %ymm12
	leal	0(,%rdx,8), %edi
	movl	%r13d, %edx
	vmovdqa	%ymm4, 1248(%rsp)
	addq	%r8, %rdi
	addq	%r8, %rdx
	leal	168(%r15), %r8d
	vmovdqa	160(%r14), %ymm4
	vmovdqa	%ymm9, %ymm2
	vmovdqa	%ymm8, %ymm6
	vmovdqa	224(%r14), %ymm15
	vmovdqa	320(%r14), %ymm13
	vmovdqa	%ymm4, 1152(%rsp)
	vmovdqa	192(%r14), %ymm4
	vmovdqa	%ymm4, 1056(%rsp)
	vmovdqa	256(%r14), %ymm4
	vmovdqa	%ymm4, 992(%rsp)
	vmovdqa	288(%r14), %ymm4
	vmovdqa	%ymm4, 960(%rsp)
	vmovdqa	384(%r14), %ymm4
	vmovdqa	%ymm4, 1440(%rsp)
	vmovdqa	416(%r14), %ymm4
	vmovdqa	%ymm4, 1344(%rsp)
	vmovdqa	448(%r14), %ymm4
	vmovdqa	%ymm4, 1216(%rsp)
	vmovdqa	480(%r14), %ymm4
	vmovdqa	%ymm4, 928(%rsp)
	vmovdqa	512(%r14), %ymm4
	vmovdqa	%ymm4, 1312(%rsp)
	vmovdqa	576(%r14), %ymm4
	vmovdqa	%ymm4, 896(%rsp)
	vmovdqa	608(%r14), %ymm4
	vmovdqa	%ymm4, 864(%rsp)
	vmovdqa	672(%r14), %ymm4
	vmovdqa	640(%r14), %ymm5
	vmovdqa	%ymm4, 1568(%rsp)
	vmovdqa	704(%r14), %ymm4
	vmovdqa	%ymm4, 1536(%rsp)
	vmovdqa	736(%r14), %ymm4
	vmovdqa	%ymm4, 1504(%rsp)
	vmovdqa	768(%r14), %ymm4
	vmovdqa	%ymm4, 1472(%rsp)
	cmpq	%r8, %r9
	jb	.L435
	vbroadcastsd	KeccakF1600RoundConstants(%rip), %ymm4
	movl	%eax, %esi
	leal	0(,%rax,8), %r10d
	movq	%rbx, %rax
	salq	$3, %rsi
	vmovapd	%ymm4, 32(%rsp)
	vbroadcastsd	8+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 768(%rsp)
	vbroadcastsd	16+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 736(%rsp)
	vbroadcastsd	24+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 704(%rsp)
	vbroadcastsd	32+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 672(%rsp)
	vbroadcastsd	40+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 640(%rsp)
	vbroadcastsd	48+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 608(%rsp)
	vbroadcastsd	56+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 576(%rsp)
	vbroadcastsd	64+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 544(%rsp)
	vbroadcastsd	72+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 512(%rsp)
	vbroadcastsd	80+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 480(%rsp)
	vbroadcastsd	88+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 448(%rsp)
	vbroadcastsd	96+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 416(%rsp)
	vbroadcastsd	104+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 384(%rsp)
	vbroadcastsd	112+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 352(%rsp)
	vbroadcastsd	120+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 320(%rsp)
	vbroadcastsd	128+KeccakF1600RoundConstants(%rip), %ymm4
	vmovdqa	%ymm14, 1088(%rsp)
	vmovapd	%ymm4, 288(%rsp)
	vbroadcastsd	136+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 256(%rsp)
	vbroadcastsd	144+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 224(%rsp)
	vbroadcastsd	152+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 192(%rsp)
	vbroadcastsd	160+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 160(%rsp)
	vbroadcastsd	168+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 128(%rsp)
	vbroadcastsd	176+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 96(%rsp)
	vbroadcastsd	184+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 64(%rsp)
	.p2align 4,,10
	.p2align 3
.L432:
	vmovq	(%rdx), %xmm4
	vpinsrq	$1, (%rcx), %xmm4, %xmm1
	subq	%r10, %r12
	vmovq	(%rax), %xmm4
	vpinsrq	$1, (%rdi), %xmm4, %xmm0
	vmovq	8(%rdx), %xmm3
	vmovq	16(%rdx), %xmm2
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovq	24(%rdx), %xmm6
	vmovq	32(%rdx), %xmm7
	vpxor	1088(%rsp), %ymm0, %ymm4
	vpinsrq	$1, 8(%rcx), %xmm3, %xmm1
	vmovq	8(%rax), %xmm3
	vpinsrq	$1, 8(%rdi), %xmm3, %xmm0
	vmovq	40(%rdx), %xmm14
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 16(%rcx), %xmm2, %xmm1
	vpxor	1408(%rsp), %ymm0, %ymm3
	vmovq	16(%rax), %xmm2
	vpinsrq	$1, 16(%rdi), %xmm2, %xmm0
	vmovdqa	%ymm3, 1280(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 24(%rcx), %xmm6, %xmm1
	vmovq	24(%rax), %xmm6
	vpxor	%ymm12, %ymm0, %ymm2
	vpinsrq	$1, 24(%rdi), %xmm6, %xmm0
	vmovdqa	%ymm2, 1088(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 32(%rcx), %xmm7, %xmm1
	vpxor	1248(%rsp), %ymm0, %ymm6
	vmovq	32(%rax), %xmm7
	vpinsrq	$1, 32(%rdi), %xmm7, %xmm0
	vmovdqa	%ymm6, 1376(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 40(%rcx), %xmm14, %xmm1
	vmovq	40(%rax), %xmm14
	vpxor	%ymm11, %ymm0, %ymm7
	vpinsrq	$1, 40(%rdi), %xmm14, %xmm0
	vmovdqa	%ymm7, 1120(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	1152(%rsp), %ymm0, %ymm14
	vmovq	48(%rdx), %xmm12
	vpinsrq	$1, 48(%rcx), %xmm12, %xmm0
	vmovq	48(%rax), %xmm12
	vpinsrq	$1, 48(%rdi), %xmm12, %xmm7
	vmovq	56(%rdx), %xmm12
	vpinsrq	$1, 56(%rcx), %xmm12, %xmm1
	vmovq	56(%rax), %xmm12
	vinserti128	$0x1, %xmm0, %ymm7, %ymm7
	vmovq	72(%rdx), %xmm10
	vmovq	80(%rdx), %xmm11
	vpxor	1056(%rsp), %ymm7, %ymm7
	vpinsrq	$1, 56(%rdi), %xmm12, %xmm0
	vmovq	64(%rdx), %xmm12
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 64(%rcx), %xmm12, %xmm1
	vmovq	64(%rax), %xmm12
	vpxor	%ymm15, %ymm0, %ymm15
	vpinsrq	$1, 64(%rdi), %xmm12, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 72(%rcx), %xmm10, %xmm1
	vpxor	992(%rsp), %ymm0, %ymm12
	vmovq	72(%rax), %xmm10
	vpinsrq	$1, 72(%rdi), %xmm10, %xmm0
	vmovdqa	%ymm12, 1152(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 80(%rcx), %xmm11, %xmm1
	vpxor	960(%rsp), %ymm0, %ymm10
	vmovq	80(%rax), %xmm11
	vpinsrq	$1, 80(%rdi), %xmm11, %xmm0
	vmovdqa	%ymm10, 1408(%rsp)
	vmovq	88(%rdx), %xmm11
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 88(%rcx), %xmm11, %xmm1
	vmovq	88(%rax), %xmm11
	vpxor	%ymm13, %ymm0, %ymm13
	vpinsrq	$1, 88(%rdi), %xmm11, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	%ymm9, %ymm0, %ymm11
	vmovq	96(%rdx), %xmm9
	vpinsrq	$1, 96(%rcx), %xmm9, %xmm0
	vmovq	96(%rax), %xmm9
	vpinsrq	$1, 96(%rdi), %xmm9, %xmm9
	vmovq	104(%rdx), %xmm3
	vpinsrq	$1, 104(%rcx), %xmm3, %xmm1
	vinserti128	$0x1, %xmm0, %ymm9, %ymm9
	vmovq	104(%rax), %xmm3
	vmovq	112(%rdx), %xmm2
	vpinsrq	$1, 104(%rdi), %xmm3, %xmm0
	vmovq	120(%rdx), %xmm6
	vpxor	1440(%rsp), %ymm9, %ymm9
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 112(%rcx), %xmm2, %xmm1
	vpxor	1344(%rsp), %ymm0, %ymm3
	vmovq	112(%rax), %xmm2
	vpinsrq	$1, 112(%rdi), %xmm2, %xmm0
	vmovdqa	%ymm3, 1440(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 120(%rcx), %xmm6, %xmm1
	vpxor	1216(%rsp), %ymm0, %ymm2
	vmovq	120(%rax), %xmm6
	vpinsrq	$1, 120(%rdi), %xmm6, %xmm0
	vmovq	128(%rdx), %xmm6
	vmovdqa	%ymm2, 1184(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	928(%rsp), %ymm0, %ymm12
	vpinsrq	$1, 128(%rcx), %xmm6, %xmm0
	vmovq	128(%rax), %xmm6
	vpinsrq	$1, 128(%rdi), %xmm6, %xmm6
	vpxor	%ymm12, %ymm13, %ymm2
	vinserti128	$0x1, %xmm0, %ymm6, %ymm6
	vmovq	136(%rdx), %xmm0
	vpinsrq	$1, 136(%rcx), %xmm0, %xmm1
	vmovq	136(%rax), %xmm0
	vpinsrq	$1, 136(%rdi), %xmm0, %xmm0
	vpxor	1312(%rsp), %ymm6, %ymm6
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	%ymm8, %ymm0, %ymm8
	vmovdqa	%ymm8, %ymm1
	vmovq	144(%rdx), %xmm8
	vpinsrq	$1, 144(%rcx), %xmm8, %xmm0
	vmovq	144(%rax), %xmm8
	vpinsrq	$1, 144(%rdi), %xmm8, %xmm8
	vinserti128	$0x1, %xmm0, %ymm8, %ymm8
	vpxor	896(%rsp), %ymm8, %ymm8
	vmovq	152(%rdx), %xmm0
	vmovdqa	%ymm14, 800(%rsp)
	vmovq	152(%rax), %xmm10
	vpinsrq	$1, 152(%rcx), %xmm0, %xmm0
	vmovdqa	%ymm11, 832(%rsp)
	vpinsrq	$1, 152(%rdi), %xmm10, %xmm10
	vmovq	160(%rax), %xmm3
	addq	%rsi, %rax
	vmovdqa	%ymm1, 896(%rsp)
	vpinsrq	$1, 160(%rdi), %xmm3, %xmm3
	addq	%rsi, %rdi
	vmovdqa	%ymm4, 1344(%rsp)
	vinserti128	$0x1, %xmm0, %ymm10, %ymm10
	vmovq	160(%rdx), %xmm0
	vpinsrq	$1, 160(%rcx), %xmm0, %xmm0
	addq	%rsi, %rdx
	vpxor	864(%rsp), %ymm10, %ymm10
	addq	%rsi, %rcx
	vmovdqa	%ymm12, 864(%rsp)
	vpxor	%ymm1, %ymm9, %ymm12
	vmovdqa	1408(%rsp), %ymm1
	vinserti128	$0x1, %xmm0, %ymm3, %ymm3
	vpxor	%ymm4, %ymm14, %ymm0
	vpxor	%ymm11, %ymm6, %ymm14
	vpxor	%ymm0, %ymm2, %ymm2
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	1280(%rsp), %ymm7, %ymm0
	vpxor	1440(%rsp), %ymm8, %ymm11
	vpxor	%ymm3, %ymm2, %ymm2
	vpxor	1120(%rsp), %ymm1, %ymm1
	vpxor	%ymm0, %ymm14, %ymm14
	vpxor	1088(%rsp), %ymm15, %ymm0
	vpxor	1568(%rsp), %ymm14, %ymm14
	vpxor	%ymm0, %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vmovdqa	1152(%rsp), %ymm0
	vpxor	1376(%rsp), %ymm0, %ymm0
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1184(%rsp), %ymm10, %ymm0
	vpxor	1504(%rsp), %ymm11, %ymm11
	vpsllq	$1, %ymm12, %ymm4
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlq	$63, %ymm14, %ymm1
	vpxor	1472(%rsp), %ymm0, %ymm0
	vpor	%ymm1, %ymm5, %ymm5
	vpsrlq	$63, %ymm12, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm1
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm5, %ymm13
	vpxor	%ymm3, %ymm5, %ymm3
	vmovdqa	%ymm1, 1312(%rsp)
	vpsllq	$1, %ymm11, %ymm1
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm6, %ymm4, %ymm6
	vpor	1312(%rsp), %ymm1, %ymm1
	vpxor	%ymm14, %ymm1, %ymm1
	vpsrlq	$63, %ymm0, %ymm14
	vpsllq	$1, %ymm0, %ymm0
	vpxor	%ymm9, %ymm1, %ymm9
	vpor	%ymm14, %ymm0, %ymm0
	vpxor	%ymm12, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm12
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm0, %ymm8
	vpor	%ymm12, %ymm2, %ymm2
	vpsrlq	$20, %ymm7, %ymm12
	vpsllq	$44, %ymm7, %ymm7
	vpxor	%ymm11, %ymm2, %ymm2
	vpxor	1344(%rsp), %ymm5, %ymm11
	vpor	%ymm12, %ymm7, %ymm7
	vpsrlq	$21, %ymm9, %ymm12
	vpxor	%ymm10, %ymm2, %ymm10
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm12, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm12
	vpxor	32(%rsp), %ymm12, %ymm12
	vpxor	%ymm11, %ymm12, %ymm14
	vpsrlq	$43, %ymm8, %ymm12
	vmovdqa	%ymm14, 1312(%rsp)
	vpsllq	$21, %ymm8, %ymm8
	vpor	%ymm12, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vmovdqa	%ymm12, 928(%rsp)
	vpxor	1472(%rsp), %ymm2, %ymm12
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vpsrlq	$50, %ymm12, %ymm14
	vpsllq	$14, %ymm12, %ymm12
	vpor	%ymm14, %ymm12, %ymm12
	vpandn	%ymm12, %ymm8, %ymm14
	vpxor	%ymm9, %ymm14, %ymm9
	vmovdqa	%ymm9, 960(%rsp)
	vpandn	%ymm11, %ymm12, %ymm9
	vpandn	%ymm7, %ymm11, %ymm11
	vpxor	1376(%rsp), %ymm0, %ymm7
	vpxor	%ymm8, %ymm9, %ymm8
	vpxor	%ymm12, %ymm11, %ymm9
	vpxor	1536(%rsp), %ymm1, %ymm11
	vmovdqa	%ymm8, 1216(%rsp)
	vpsrlq	$36, %ymm7, %ymm8
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	1408(%rsp), %ymm2, %ymm8
	vmovdqa	%ymm9, 992(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm12, %ymm11, %ymm11
	vpor	%ymm9, %ymm8, %ymm8
	vpsrlq	$61, %ymm13, %ymm9
	vpsllq	$3, %ymm13, %ymm13
	vpor	%ymm9, %ymm13, %ymm13
	vpandn	%ymm13, %ymm8, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 1024(%rsp)
	vpsrlq	$19, %ymm6, %ymm9
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm11, %ymm6, %ymm12
	vpandn	%ymm6, %ymm13, %ymm9
	vpxor	%ymm13, %ymm12, %ymm13
	vpandn	%ymm7, %ymm11, %ymm12
	vpandn	%ymm8, %ymm7, %ymm7
	vpxor	%ymm6, %ymm12, %ymm6
	vpxor	%ymm8, %ymm9, %ymm9
	vpxor	%ymm11, %ymm7, %ymm8
	vmovdqa	%ymm13, 1248(%rsp)
	vmovdqa	%ymm6, 1056(%rsp)
	vpxor	1280(%rsp), %ymm4, %ymm6
	vpxor	1504(%rsp), %ymm0, %ymm12
	vmovdqa	%ymm8, 1344(%rsp)
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpsrlq	$63, %ymm6, %ymm7
	vpsllq	$1, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm15, %ymm1, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1440(%rsp), %ymm0, %ymm8
	vpxor	1152(%rsp), %ymm0, %ymm0
	vpsrlq	$39, %ymm8, %ymm11
	vpsllq	$25, %ymm8, %ymm8
	vpor	%ymm11, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm11
	vpxor	%ymm6, %ymm11, %ymm15
	vpandn	%ymm10, %ymm8, %ymm11
	vmovdqa	%ymm15, 1376(%rsp)
	vpxor	%ymm7, %ymm11, %ymm15
	vpsrlq	$46, %ymm3, %ymm11
	vmovdqa	%ymm15, 1408(%rsp)
	vpsllq	$18, %ymm3, %ymm3
	vpor	%ymm11, %ymm3, %ymm3
	vpandn	%ymm3, %ymm10, %ymm11
	vpxor	%ymm8, %ymm11, %ymm11
	vpandn	%ymm6, %ymm3, %ymm8
	vpandn	%ymm7, %ymm6, %ymm6
	vpxor	%ymm3, %ymm6, %ymm6
	vpxor	%ymm10, %ymm8, %ymm10
	vpxor	1120(%rsp), %ymm2, %ymm3
	vmovdqa	%ymm6, 1280(%rsp)
	vpxor	1184(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm10, 1536(%rsp)
	vpsrlq	$37, %ymm3, %ymm6
	vpsllq	$27, %ymm3, %ymm3
	vpxor	832(%rsp), %ymm4, %ymm10
	vpor	%ymm6, %ymm3, %ymm3
	vpxor	800(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm3, %ymm7, %ymm14
	vpxor	896(%rsp), %ymm1, %ymm7
	vpxor	1088(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm14, 896(%rsp)
	vpsrlq	$49, %ymm7, %ymm8
	vpsllq	$15, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm12, %ymm7, %ymm13
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm8, %ymm8
	vmovdqa	%ymm10, 1440(%rsp)
	vpandn	%ymm3, %ymm12, %ymm10
	vpandn	%ymm6, %ymm3, %ymm3
	vpxor	%ymm12, %ymm3, %ymm15
	vpsrlq	$2, %ymm1, %ymm3
	vpxor	%ymm7, %ymm10, %ymm10
	vmovdqa	1376(%rsp), %ymm7
	vpxor	1024(%rsp), %ymm7, %ymm7
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsrlq	$9, %ymm0, %ymm3
	vpsllq	$55, %ymm0, %ymm0
	vpor	%ymm3, %ymm0, %ymm0
	vpsrlq	$25, %ymm2, %ymm3
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vpandn	%ymm2, %ymm0, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm14, %ymm6, %ymm3
	vpxor	%ymm7, %ymm3, %ymm3
	vpxor	1312(%rsp), %ymm3, %ymm3
	vpxor	864(%rsp), %ymm5, %ymm5
	vpxor	1568(%rsp), %ymm4, %ymm4
	vpxor	1408(%rsp), %ymm8, %ymm14
	vmovdqa	1248(%rsp), %ymm12
	vpsrlq	$23, %ymm5, %ymm7
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm7, %ymm5, %ymm5
	vpandn	%ymm5, %ymm2, %ymm7
	vpxor	%ymm0, %ymm7, %ymm13
	vpxor	928(%rsp), %ymm9, %ymm7
	vmovdqa	%ymm13, 832(%rsp)
	vpxor	%ymm7, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm7
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1440(%rsp), %ymm11, %ymm13
	vpor	%ymm7, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm7
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	960(%rsp), %ymm12, %ymm2
	vpxor	%ymm2, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm2
	vpandn	%ymm0, %ymm1, %ymm1
	vmovdqa	1344(%rsp), %ymm0
	vpxor	%ymm5, %ymm2, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm7, %ymm13, %ymm13
	vmovdqa	1056(%rsp), %ymm2
	vpxor	1216(%rsp), %ymm2, %ymm2
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	992(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm5, 1568(%rsp)
	vpsllq	$1, %ymm14, %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm2, %ymm12, %ymm12
	vpxor	1280(%rsp), %ymm1, %ymm2
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpxor	%ymm15, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1504(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1504(%rsp), %ymm0, %ymm0
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm11, %ymm0, %ymm11
	vpxor	%ymm7, %ymm0, %ymm7
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1312(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm11, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm11, %ymm11
	vpor	%ymm13, %ymm11, %ymm11
	vpandn	%ymm11, %ymm9, %ymm13
	vpxor	768(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1472(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm11, %ymm13
	vpxor	%ymm9, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 1088(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm11, %ymm13, %ymm11
	vmovdqa	%ymm11, 1120(%rsp)
	vpandn	%ymm12, %ymm1, %ymm11
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm9
	vpsrlq	$3, %ymm7, %ymm12
	vpxor	%ymm10, %ymm11, %ymm10
	vpxor	1216(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm7, %ymm7
	vmovdqa	%ymm10, 1312(%rsp)
	vpxor	1344(%rsp), %ymm3, %ymm10
	vpxor	1376(%rsp), %ymm5, %ymm11
	vpor	%ymm12, %ymm7, %ymm7
	vmovdqa	%ymm9, 1152(%rsp)
	vpsrlq	$36, %ymm1, %ymm9
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm9, %ymm1, %ymm1
	vpsrlq	$44, %ymm10, %ymm9
	vpsllq	$20, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, %ymm14
	vpsrlq	$19, %ymm8, %ymm9
	vpsllq	$45, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm7, %ymm8, %ymm12
	vpandn	%ymm8, %ymm11, %ymm9
	vpxor	%ymm11, %ymm12, %ymm11
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm11, 1344(%rsp)
	vpandn	%ymm1, %ymm7, %ymm11
	vpandn	%ymm10, %ymm1, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm8, %ymm11, %ymm8
	vpxor	%ymm15, %ymm3, %ymm11
	vmovdqa	%ymm1, 1376(%rsp)
	vpxor	928(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm8, 1184(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1248(%rsp), %ymm0, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm14, 864(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpxor	1568(%rsp), %ymm2, %ymm12
	vpxor	1056(%rsp), %ymm2, %ymm2
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm8
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1504(%rsp)
	vpandn	%ymm11, %ymm10, %ymm8
	vpxor	%ymm7, %ymm8, %ymm15
	vpsrlq	$46, %ymm6, %ymm8
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm8
	vpxor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	1440(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm1, 1216(%rsp)
	vpxor	992(%rsp), %ymm3, %ymm1
	vpxor	960(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1536(%rsp)
	vpxor	1408(%rsp), %ymm4, %ymm10
	vpxor	1280(%rsp), %ymm3, %ymm3
	vpxor	832(%rsp), %ymm4, %ymm4
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1024(%rsp), %ymm5, %ymm6
	vpxor	896(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 1248(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	1504(%rsp), %ymm13
	vmovdqa	%ymm10, 1408(%rsp)
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpxor	%ymm12, %ymm1, %ymm12
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm12, 1568(%rsp)
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpxor	%ymm14, %ymm13, %ymm11
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpxor	%ymm15, %ymm7, %ymm14
	vpxor	1408(%rsp), %ymm8, %ymm13
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	1248(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1472(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm12
	vpxor	1088(%rsp), %ymm9, %ymm11
	vmovdqa	%ymm12, 896(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	1344(%rsp), %ymm12
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1120(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1184(%rsp), %ymm0
	vpxor	1312(%rsp), %ymm0, %ymm0
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm12
	vmovdqa	%ymm5, 1056(%rsp)
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpxor	1216(%rsp), %ymm1, %ymm2
	vmovdqa	1376(%rsp), %ymm5
	vpxor	1152(%rsp), %ymm5, %ymm0
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1440(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1440(%rsp), %ymm0, %ymm0
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm0, %ymm8
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1472(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm13, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	736(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1472(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 1280(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 928(%rsp)
	vpandn	%ymm12, %ymm1, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	1376(%rsp), %ymm3, %ymm9
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm8, %ymm8
	vmovdqa	%ymm1, 960(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1312(%rsp), %ymm2, %ymm1
	vpxor	1504(%rsp), %ymm5, %ymm10
	vmovdqa	%ymm8, 1440(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm13
	vpsrlq	$19, %ymm7, %ymm8
	vmovdqa	%ymm13, 992(%rsp)
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	1056(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 1312(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm9
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1088(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 1024(%rsp)
	vpxor	1536(%rsp), %ymm2, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm9, 1504(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1344(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, %ymm14
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 1376(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	1408(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm1, 1344(%rsp)
	vpxor	1152(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm10, 1536(%rsp)
	vpxor	%ymm15, %ymm4, %ymm10
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	864(%rsp), %ymm5, %ymm6
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	1120(%rsp), %ymm0, %ymm0
	vpxor	1216(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm14, 1216(%rsp)
	vpxor	1184(%rsp), %ymm2, %ymm2
	vpsrlq	$28, %ymm6, %ymm7
	vpxor	1248(%rsp), %ymm5, %ymm5
	vpxor	896(%rsp), %ymm4, %ymm4
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm15
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm10, 1408(%rsp)
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	992(%rsp), %ymm11
	vmovdqa	1312(%rsp), %ymm12
	vmovdqa	%ymm6, 1568(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpxor	%ymm14, %ymm11, %ymm11
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpxor	1376(%rsp), %ymm7, %ymm14
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm15, %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1472(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vmovdqa	%ymm11, %ymm13
	vpxor	1280(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm13, 864(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1408(%rsp), %ymm9, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	928(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1024(%rsp), %ymm0
	vpxor	1440(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1344(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 896(%rsp)
	vmovdqa	1504(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	960(%rsp), %ymm5, %ymm0
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1248(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1248(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1472(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	704(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1472(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1056(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1088(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm10, %ymm9, %ymm10
	vpxor	%ymm1, %ymm12, %ymm1
	vmovdqa	%ymm10, 1120(%rsp)
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	1504(%rsp), %ymm3, %ymm9
	vpxor	1216(%rsp), %ymm5, %ymm10
	vmovdqa	%ymm1, 1152(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1440(%rsp), %ymm2, %ymm1
	vpor	%ymm12, %ymm11, %ymm11
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1184(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	896(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 1216(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm7, 1248(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	1280(%rsp), %ymm4, %ymm1
	vpxor	1568(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm7, 1440(%rsp)
	vpxor	1024(%rsp), %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1312(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1504(%rsp)
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 1280(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm11
	vpxor	960(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 1312(%rsp)
	vpxor	1376(%rsp), %ymm4, %ymm10
	vpxor	1344(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm11, 1536(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	1408(%rsp), %ymm0, %ymm11
	vpxor	928(%rsp), %ymm0, %ymm0
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	992(%rsp), %ymm5, %ymm6
	vpxor	%ymm15, %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 1376(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1504(%rsp), %ymm11
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vmovdqa	%ymm14, %ymm13
	vmovdqa	%ymm1, 1568(%rsp)
	vpxor	1184(%rsp), %ymm11, %ymm11
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	1376(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1472(%rsp), %ymm3, %ymm3
	vpxor	1280(%rsp), %ymm7, %ymm14
	vpsllq	$41, %ymm5, %ymm5
	vpxor	864(%rsp), %ymm4, %ymm4
	vmovdqa	%ymm13, 832(%rsp)
	vpor	%ymm11, %ymm5, %ymm5
	vpxor	%ymm13, %ymm9, %ymm13
	vmovdqa	1216(%rsp), %ymm12
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm15
	vpxor	1056(%rsp), %ymm8, %ymm11
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm15, %ymm14, %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1088(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1248(%rsp), %ymm0
	vpxor	1120(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1312(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 864(%rsp)
	vmovdqa	1440(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1152(%rsp), %ymm5, %ymm0
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1408(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1408(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1472(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	672(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 1408(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 1344(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 896(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	1120(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm9, 1472(%rsp)
	vpxor	1440(%rsp), %ymm3, %ymm9
	vpxor	1504(%rsp), %ymm5, %ymm10
	vpor	%ymm12, %ymm11, %ymm11
	vmovdqa	%ymm8, 928(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 960(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 1440(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vmovdqa	%ymm7, 992(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	1056(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 1504(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1216(%rsp), %ymm0, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm11
	vpxor	864(%rsp), %ymm2, %ymm12
	vpxor	1248(%rsp), %ymm2, %ymm2
	vpsrlq	$58, %ymm7, %ymm9
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsllq	$6, %ymm7, %ymm7
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm14
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 1024(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm1, 1056(%rsp)
	vpxor	1152(%rsp), %ymm3, %ymm1
	vpxor	1312(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm10, 1536(%rsp)
	vpxor	1280(%rsp), %ymm4, %ymm10
	vpxor	%ymm15, %ymm4, %ymm4
	vmovdqa	1440(%rsp), %ymm15
	vmovdqa	%ymm14, 1312(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1184(%rsp), %ymm5, %ymm6
	vpxor	1376(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm11
	vmovdqa	%ymm11, 1216(%rsp)
	vpxor	832(%rsp), %ymm0, %ymm11
	vpxor	1088(%rsp), %ymm0, %ymm0
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm13
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm13, 1280(%rsp)
	vmovdqa	%ymm1, 1568(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpxor	960(%rsp), %ymm14, %ymm11
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	1216(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1408(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm14
	vpxor	1344(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm14, %ymm13
	vpxor	1024(%rsp), %ymm7, %ymm14
	vmovdqa	%ymm13, 832(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1280(%rsp), %ymm9, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	896(%rsp), %ymm15, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm15
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	992(%rsp), %ymm0
	vpxor	1472(%rsp), %ymm0, %ymm0
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm10, %ymm15, %ymm12
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpxor	1056(%rsp), %ymm1, %ymm2
	vmovdqa	1504(%rsp), %ymm5
	vpxor	928(%rsp), %ymm5, %ymm0
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1376(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1376(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1408(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	640(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1376(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 1088(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1120(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm1, 1152(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1472(%rsp), %ymm2, %ymm1
	vpxor	1312(%rsp), %ymm5, %ymm10
	vmovdqa	%ymm9, 1408(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1504(%rsp), %ymm3, %ymm9
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1248(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm15, %ymm2, %ymm12
	vmovdqa	%ymm10, 1312(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm1, 1472(%rsp)
	vpxor	1344(%rsp), %ymm4, %ymm1
	vpxor	1568(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm7, 1184(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1440(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1504(%rsp)
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm14
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm14, 1344(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	928(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 1440(%rsp)
	vmovdqa	%ymm10, 1536(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	1024(%rsp), %ymm4, %ymm10
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	960(%rsp), %ymm5, %ymm6
	vpxor	1280(%rsp), %ymm0, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	896(%rsp), %ymm0, %ymm0
	vpxor	992(%rsp), %ymm2, %ymm2
	vpxor	1056(%rsp), %ymm3, %ymm3
	vpsrlq	$28, %ymm6, %ymm7
	vpxor	1216(%rsp), %ymm5, %ymm5
	vpxor	832(%rsp), %ymm4, %ymm4
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, %ymm14
	vpsrlq	$49, %ymm11, %ymm7
	vmovdqa	%ymm14, 864(%rsp)
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm15
	vpxor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm15, 1568(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpxor	%ymm12, %ymm1, %ymm15
	vmovdqa	1504(%rsp), %ymm11
	vpxor	1248(%rsp), %ymm11, %ymm11
	vmovdqa	1312(%rsp), %ymm12
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm14, %ymm6, %ymm3
	vpxor	1344(%rsp), %ymm7, %ymm14
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1376(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vmovdqa	%ymm11, %ymm13
	vpxor	1088(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm13, 896(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1568(%rsp), %ymm9, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1120(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1184(%rsp), %ymm0
	vpxor	1408(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1440(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 928(%rsp)
	vmovdqa	1472(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1152(%rsp), %ymm5, %ymm0
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpxor	%ymm15, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1280(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1280(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1376(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	608(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1216(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 960(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm9, 1376(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm8, 992(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1408(%rsp), %ymm2, %ymm1
	vpxor	1472(%rsp), %ymm3, %ymm9
	vpxor	1504(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1280(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	928(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 1408(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm7, 1024(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	1088(%rsp), %ymm4, %ymm1
	vpxor	%ymm15, %ymm3, %ymm11
	vmovdqa	%ymm7, 1472(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpxor	1184(%rsp), %ymm2, %ymm2
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1312(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1504(%rsp)
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm1, 1056(%rsp)
	vpxor	1152(%rsp), %ymm3, %ymm1
	vpxor	1440(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm10, 1536(%rsp)
	vpxor	1344(%rsp), %ymm4, %ymm10
	vmovdqa	%ymm14, 1440(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1248(%rsp), %ymm5, %ymm6
	vpxor	864(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm11
	vmovdqa	%ymm11, 1248(%rsp)
	vpxor	1568(%rsp), %ymm0, %ymm11
	vpxor	1120(%rsp), %ymm0, %ymm0
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm13
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1504(%rsp), %ymm11
	vmovdqa	%ymm1, 1568(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpxor	1280(%rsp), %ymm11, %ymm11
	vmovdqa	%ymm13, 1312(%rsp)
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	1248(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpsllq	$41, %ymm5, %ymm5
	vpxor	%ymm14, %ymm3, %ymm3
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm14
	vpxor	1216(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm14, %ymm13
	vpxor	%ymm15, %ymm7, %ymm14
	vmovdqa	%ymm13, 832(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpxor	896(%rsp), %ymm4, %ymm4
	vmovdqa	1408(%rsp), %ymm12
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1312(%rsp), %ymm9, %ymm13
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	960(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1024(%rsp), %ymm0
	vpxor	1376(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1056(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 896(%rsp)
	vmovdqa	1472(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	992(%rsp), %ymm5, %ymm0
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1344(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1344(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1440(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	576(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1440(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1088(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 928(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm1, 1120(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1376(%rsp), %ymm2, %ymm1
	vpxor	1504(%rsp), %ymm5, %ymm10
	vmovdqa	%ymm9, 1344(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1472(%rsp), %ymm3, %ymm9
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1152(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 1376(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm1, 1472(%rsp)
	vpxor	1216(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 1184(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1408(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1504(%rsp)
	vpxor	1568(%rsp), %ymm3, %ymm11
	vpxor	896(%rsp), %ymm2, %ymm12
	vpxor	1024(%rsp), %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 1408(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	992(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 1216(%rsp)
	vpxor	1312(%rsp), %ymm0, %ymm11
	vpxor	960(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1536(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	%ymm15, %ymm4, %ymm10
	vpxor	1056(%rsp), %ymm3, %ymm3
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1280(%rsp), %ymm5, %ymm6
	vpxor	1248(%rsp), %ymm5, %ymm5
	vpxor	832(%rsp), %ymm4, %ymm4
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm15
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm14, 1280(%rsp)
	vmovdqa	%ymm1, 1568(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vmovdqa	1504(%rsp), %ymm14
	vpxor	1152(%rsp), %ymm14, %ymm11
	vpor	%ymm6, %ymm0, %ymm1
	vpxor	1408(%rsp), %ymm7, %ymm14
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vmovdqa	1376(%rsp), %ymm12
	vpsllq	$39, %ymm3, %ymm3
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm15, %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1440(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vmovdqa	%ymm11, %ymm13
	vpxor	1088(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm13, 864(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1280(%rsp), %ymm9, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	928(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1184(%rsp), %ymm0
	vpxor	1344(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1216(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 896(%rsp)
	vmovdqa	1472(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpxor	1120(%rsp), %ymm5, %ymm0
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1312(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1312(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1440(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	544(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1440(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1248(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 960(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm10
	vpxor	1344(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1472(%rsp), %ymm3, %ymm9
	vmovdqa	%ymm10, 1312(%rsp)
	vmovdqa	%ymm8, 992(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1504(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1024(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm14
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm14, 1344(%rsp)
	vmovdqa	%ymm7, 1056(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	1088(%rsp), %ymm4, %ymm1
	vpxor	1568(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm7, 1472(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1376(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1504(%rsp)
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 1376(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm1, 1088(%rsp)
	vpxor	1120(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm10, 1536(%rsp)
	vpxor	1408(%rsp), %ymm4, %ymm10
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1152(%rsp), %ymm5, %ymm6
	vpxor	%ymm15, %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm11
	vmovdqa	%ymm11, 1408(%rsp)
	vpxor	1280(%rsp), %ymm0, %ymm11
	vpxor	896(%rsp), %ymm2, %ymm12
	vpxor	928(%rsp), %ymm0, %ymm0
	vpxor	1184(%rsp), %ymm2, %ymm2
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpsrlq	$49, %ymm11, %ymm7
	vpxor	1216(%rsp), %ymm3, %ymm3
	vpxor	864(%rsp), %ymm4, %ymm4
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1504(%rsp), %ymm12
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vmovdqa	%ymm14, %ymm13
	vmovdqa	%ymm1, 1568(%rsp)
	vpxor	1024(%rsp), %ymm12, %ymm11
	vpor	%ymm6, %ymm0, %ymm1
	vpxor	1376(%rsp), %ymm7, %ymm14
	vmovdqa	%ymm13, 832(%rsp)
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpxor	%ymm13, %ymm9, %ymm13
	vmovdqa	1344(%rsp), %ymm12
	vpsllq	$39, %ymm3, %ymm3
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	1408(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1440(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm15
	vpxor	1248(%rsp), %ymm8, %ymm11
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm15, %ymm14, %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	960(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1056(%rsp), %ymm0
	vpxor	1312(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1088(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 864(%rsp)
	vmovdqa	1472(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	992(%rsp), %ymm5, %ymm0
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1280(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1280(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1440(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	512(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1440(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1120(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 896(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	%ymm1, %ymm12, %ymm1
	vmovdqa	%ymm9, 1280(%rsp)
	vpsrlq	$3, %ymm11, %ymm12
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm1, 928(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1312(%rsp), %ymm2, %ymm1
	vpxor	1472(%rsp), %ymm3, %ymm9
	vpxor	1504(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1152(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 1184(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm1, 1472(%rsp)
	vpxor	1248(%rsp), %ymm4, %ymm1
	vpxor	1568(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm7, 1216(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1344(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm12
	vpandn	%ymm11, %ymm10, %ymm9
	vmovdqa	%ymm12, 1504(%rsp)
	vpxor	%ymm7, %ymm9, %ymm12
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm12, 1312(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpxor	864(%rsp), %ymm2, %ymm12
	vpxor	1056(%rsp), %ymm2, %ymm2
	vpor	%ymm9, %ymm6, %ymm6
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	992(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 1248(%rsp)
	vpxor	832(%rsp), %ymm0, %ymm11
	vpxor	960(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1536(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	1376(%rsp), %ymm4, %ymm10
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm15, %ymm4, %ymm4
	vpxor	1024(%rsp), %ymm5, %ymm6
	vpxor	1088(%rsp), %ymm3, %ymm3
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 1344(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpxor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1504(%rsp), %ymm11
	vpsllq	$62, %ymm0, %ymm0
	vpxor	%ymm12, %ymm1, %ymm13
	vpxor	1152(%rsp), %ymm11, %ymm11
	vmovdqa	%ymm14, 1376(%rsp)
	vmovdqa	%ymm13, 1568(%rsp)
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	1344(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpxor	1440(%rsp), %ymm3, %ymm3
	vpxor	1408(%rsp), %ymm5, %ymm5
	vpxor	1312(%rsp), %ymm7, %ymm14
	vpxor	1376(%rsp), %ymm9, %ymm13
	vmovdqa	1184(%rsp), %ymm15
	vpsrlq	$23, %ymm5, %ymm11
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm12
	vpxor	1120(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm12, 832(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	896(%rsp), %ymm15, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm15
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1216(%rsp), %ymm0
	vpxor	1280(%rsp), %ymm0, %ymm0
	vpxor	%ymm10, %ymm15, %ymm12
	vmovdqa	1472(%rsp), %ymm5
	vpxor	1248(%rsp), %ymm1, %ymm2
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	928(%rsp), %ymm5, %ymm0
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1408(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1408(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1440(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	480(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1408(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 960(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 992(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	1280(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm9, 1440(%rsp)
	vpxor	1472(%rsp), %ymm3, %ymm9
	vpxor	1504(%rsp), %ymm5, %ymm10
	vpor	%ymm12, %ymm11, %ymm11
	vmovdqa	%ymm8, 1024(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	%ymm15, %ymm2, %ymm12
	vmovdqa	%ymm10, 1280(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm7, 1056(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	1120(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 1472(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1184(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm13
	vmovdqa	%ymm13, 1504(%rsp)
	vpxor	1568(%rsp), %ymm3, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	1216(%rsp), %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm13
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm13, 1088(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	1376(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm1, 1120(%rsp)
	vpxor	928(%rsp), %ymm3, %ymm1
	vpxor	896(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1536(%rsp)
	vpxor	1312(%rsp), %ymm4, %ymm10
	vpxor	1248(%rsp), %ymm3, %ymm3
	vpxor	832(%rsp), %ymm4, %ymm4
	vpsrlq	$37, %ymm1, %ymm6
	vmovdqa	%ymm14, 896(%rsp)
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1152(%rsp), %ymm5, %ymm6
	vpxor	1344(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 1312(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm15
	vpxor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm15, 1568(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpxor	%ymm12, %ymm1, %ymm15
	vmovdqa	1504(%rsp), %ymm11
	vmovdqa	1280(%rsp), %ymm12
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpxor	%ymm14, %ymm11, %ymm11
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpxor	1088(%rsp), %ymm7, %ymm14
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	1312(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1408(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm13
	vpxor	960(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm13, 864(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1568(%rsp), %ymm9, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	992(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1056(%rsp), %ymm0
	vpxor	1440(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1120(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 928(%rsp)
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1536(%rsp), %ymm12, %ymm12
	vmovdqa	1472(%rsp), %ymm5
	vpxor	1024(%rsp), %ymm5, %ymm0
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpxor	%ymm15, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1376(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1376(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1408(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	448(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1376(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 1344(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1152(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm10
	vmovdqa	%ymm1, 1184(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1440(%rsp), %ymm2, %ymm1
	vpxor	1472(%rsp), %ymm3, %ymm9
	vmovdqa	%ymm10, 1408(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1504(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1216(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	928(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 1440(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm9
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	960(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 1248(%rsp)
	vpxor	%ymm15, %ymm3, %ymm11
	vpxor	1536(%rsp), %ymm2, %ymm10
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vmovdqa	%ymm9, 1472(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1280(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1504(%rsp)
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	1568(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm1, 1280(%rsp)
	vpxor	1024(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm10, 1536(%rsp)
	vpxor	1088(%rsp), %ymm4, %ymm10
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	896(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, %ymm14
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm13
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	%ymm12, %ymm1, %ymm11
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm11, 1568(%rsp)
	vpxor	992(%rsp), %ymm0, %ymm0
	vpxor	1120(%rsp), %ymm3, %ymm3
	vpxor	1056(%rsp), %ymm2, %ymm2
	vpxor	1312(%rsp), %ymm5, %ymm5
	vmovdqa	%ymm14, 832(%rsp)
	vmovdqa	1504(%rsp), %ymm11
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpxor	1216(%rsp), %ymm11, %ymm11
	vpxor	864(%rsp), %ymm4, %ymm4
	vpor	%ymm6, %ymm0, %ymm1
	vmovdqa	%ymm13, 864(%rsp)
	vpxor	%ymm13, %ymm9, %ymm13
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm14, %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1376(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm14
	vpxor	1344(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm14, %ymm12
	vpxor	%ymm15, %ymm7, %ymm14
	vmovdqa	%ymm12, 896(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	1440(%rsp), %ymm12
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1152(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1248(%rsp), %ymm0
	vpxor	1408(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1280(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 1120(%rsp)
	vmovdqa	1472(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1184(%rsp), %ymm5, %ymm0
	vpxor	1536(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1568(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1312(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1312(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1376(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	416(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 928(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 960(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	1408(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm9, 1312(%rsp)
	vpxor	1472(%rsp), %ymm3, %ymm9
	vmovdqa	%ymm8, 992(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1504(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1024(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	1120(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 1376(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1536(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm7, 1056(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	1344(%rsp), %ymm4, %ymm1
	vpxor	1248(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm7, 1408(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1440(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm11
	vmovdqa	%ymm11, 1440(%rsp)
	vpxor	1568(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm14, 1568(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 1088(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	864(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm1, 1344(%rsp)
	vpxor	1184(%rsp), %ymm3, %ymm1
	vpxor	1152(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1472(%rsp)
	vpxor	%ymm15, %ymm4, %ymm10
	vpxor	1280(%rsp), %ymm3, %ymm3
	vpxor	896(%rsp), %ymm4, %ymm4
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1216(%rsp), %ymm5, %ymm6
	vpxor	832(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm15
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm13
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1440(%rsp), %ymm11
	vmovdqa	%ymm1, 1536(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpxor	1024(%rsp), %ymm11, %ymm11
	vmovdqa	%ymm13, 1504(%rsp)
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm15, %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpsllq	$41, %ymm5, %ymm5
	vpxor	%ymm14, %ymm3, %ymm3
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm14
	vpxor	928(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm14, %ymm12
	vpxor	1088(%rsp), %ymm7, %ymm14
	vmovdqa	%ymm12, 800(%rsp)
	vpxor	1504(%rsp), %ymm9, %ymm13
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	1376(%rsp), %ymm12
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	960(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	1056(%rsp), %ymm0
	vpxor	1312(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1344(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 832(%rsp)
	vmovdqa	1408(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	992(%rsp), %ymm5, %ymm0
	vpxor	1472(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1536(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1280(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1280(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1568(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	384(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 1568(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 1184(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 864(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm10
	vmovdqa	%ymm1, 1120(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1312(%rsp), %ymm2, %ymm1
	vpxor	1408(%rsp), %ymm3, %ymm9
	vmovdqa	%ymm10, 1216(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1440(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1152(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 1248(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1472(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm1, 1280(%rsp)
	vpxor	928(%rsp), %ymm4, %ymm1
	vpxor	1536(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm7, 896(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1376(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1376(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpxor	832(%rsp), %ymm2, %ymm12
	vpxor	1056(%rsp), %ymm2, %ymm2
	vpandn	%ymm11, %ymm10, %ymm9
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 1312(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	992(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 1440(%rsp)
	vpxor	1504(%rsp), %ymm0, %ymm11
	vpxor	960(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1408(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	1088(%rsp), %ymm4, %ymm10
	vpxor	1344(%rsp), %ymm3, %ymm3
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1024(%rsp), %ymm5, %ymm6
	vpxor	800(%rsp), %ymm4, %ymm4
	vpxor	%ymm15, %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 1472(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm14
	vpxor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1376(%rsp), %ymm11
	vpsllq	$62, %ymm0, %ymm0
	vpxor	%ymm12, %ymm1, %ymm13
	vpxor	1152(%rsp), %ymm11, %ymm11
	vmovdqa	%ymm14, 1504(%rsp)
	vpxor	1312(%rsp), %ymm7, %ymm14
	vpor	%ymm6, %ymm0, %ymm1
	vmovdqa	1248(%rsp), %ymm12
	vmovdqa	%ymm13, 1536(%rsp)
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpxor	1504(%rsp), %ymm9, %ymm13
	vpsllq	$39, %ymm3, %ymm3
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	1472(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1568(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm15
	vpxor	1184(%rsp), %ymm8, %ymm11
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm15, %ymm14, %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	864(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	896(%rsp), %ymm0
	vpxor	1216(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	1440(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 832(%rsp)
	vmovdqa	1280(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1408(%rsp), %ymm12, %ymm12
	vpxor	1120(%rsp), %ymm5, %ymm0
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1536(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1344(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1344(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1568(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	352(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 1568(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 928(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 960(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	1216(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm9, 1344(%rsp)
	vpxor	1280(%rsp), %ymm3, %ymm9
	vpxor	1376(%rsp), %ymm5, %ymm10
	vpor	%ymm12, %ymm11, %ymm11
	vmovdqa	%ymm8, 992(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 1024(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm12
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm12, 1216(%rsp)
	vmovdqa	%ymm7, 1056(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	1184(%rsp), %ymm4, %ymm1
	vpxor	1536(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm7, 1376(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	1248(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpxor	1408(%rsp), %ymm2, %ymm9
	vpsrlq	$39, %ymm9, %ymm10
	vpsllq	$25, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm10
	vpxor	%ymm1, %ymm10, %ymm10
	vmovdqa	%ymm10, 1408(%rsp)
	vpandn	%ymm11, %ymm9, %ymm10
	vpxor	%ymm7, %ymm10, %ymm10
	vmovdqa	%ymm10, 1184(%rsp)
	vpsrlq	$46, %ymm6, %ymm10
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm10, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm10
	vpxor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm1, %ymm6, %ymm9
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm11, %ymm9, %ymm12
	vpxor	%ymm6, %ymm1, %ymm11
	vpxor	1120(%rsp), %ymm3, %ymm1
	vpxor	1312(%rsp), %ymm4, %ymm9
	vpxor	%ymm15, %ymm4, %ymm4
	vmovdqa	%ymm11, 1088(%rsp)
	vmovdqa	%ymm12, 1248(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1152(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm9, %ymm7
	vpsllq	$10, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm9, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm11
	vmovdqa	%ymm11, 1120(%rsp)
	vpxor	1504(%rsp), %ymm0, %ymm11
	vpxor	832(%rsp), %ymm2, %ymm12
	vpxor	864(%rsp), %ymm0, %ymm0
	vpxor	896(%rsp), %ymm2, %ymm2
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpsrlq	$49, %ymm11, %ymm7
	vpxor	1440(%rsp), %ymm3, %ymm3
	vmovdqa	1216(%rsp), %ymm15
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm9, %ymm7
	vpxor	%ymm9, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm9
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpsrlq	$25, %ymm3, %ymm12
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm14, 1152(%rsp)
	vmovdqa	%ymm1, 1280(%rsp)
	vpsrlq	$2, %ymm0, %ymm1
	vpsllq	$62, %ymm0, %ymm0
	vmovdqa	1408(%rsp), %ymm14
	vpor	%ymm1, %ymm0, %ymm0
	vpsllq	$39, %ymm3, %ymm3
	vpxor	%ymm11, %ymm9, %ymm9
	vpsrlq	$9, %ymm2, %ymm1
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm3, %ymm12, %ymm12
	vpxor	1152(%rsp), %ymm10, %ymm13
	vpor	%ymm1, %ymm2, %ymm2
	vpxor	1024(%rsp), %ymm14, %ymm1
	vpxor	1184(%rsp), %ymm7, %ymm14
	vpandn	%ymm12, %ymm2, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpxor	1120(%rsp), %ymm6, %ymm11
	vpxor	%ymm1, %ymm11, %ymm11
	vpxor	1472(%rsp), %ymm5, %ymm1
	vpxor	1568(%rsp), %ymm11, %ymm11
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm5
	vpor	%ymm5, %ymm3, %ymm5
	vpandn	%ymm5, %ymm12, %ymm1
	vpxor	%ymm2, %ymm1, %ymm3
	vpxor	928(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm3, 896(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm1
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm3, %ymm14, %ymm14
	vpor	%ymm4, %ymm1, %ymm1
	vpxor	960(%rsp), %ymm15, %ymm4
	vpandn	%ymm1, %ymm5, %ymm3
	vpxor	%ymm4, %ymm13, %ymm13
	vpandn	%ymm0, %ymm1, %ymm4
	vpandn	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm1
	vpxor	%ymm5, %ymm4, %ymm15
	vpxor	%ymm12, %ymm3, %ymm3
	vmovdqa	1056(%rsp), %ymm4
	vpxor	%ymm9, %ymm15, %ymm12
	vpsllq	$1, %ymm14, %ymm2
	vpxor	%ymm3, %ymm13, %ymm13
	vmovdqa	%ymm1, 1504(%rsp)
	vpxor	1344(%rsp), %ymm4, %ymm4
	vpxor	1088(%rsp), %ymm1, %ymm5
	vmovdqa	1376(%rsp), %ymm1
	vpxor	992(%rsp), %ymm1, %ymm1
	vpxor	%ymm4, %ymm12, %ymm12
	vpsrlq	$63, %ymm13, %ymm4
	vpxor	1248(%rsp), %ymm12, %ymm12
	vpxor	%ymm1, %ymm5, %ymm5
	vpsrlq	$63, %ymm14, %ymm1
	vpxor	1280(%rsp), %ymm5, %ymm5
	vpor	%ymm2, %ymm1, %ymm1
	vpsllq	$1, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm0
	vpor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm5, %ymm1, %ymm1
	vpsrlq	$63, %ymm12, %ymm2
	vpxor	%ymm11, %ymm4, %ymm4
	vpxor	%ymm1, %ymm6, %ymm6
	vpor	%ymm0, %ymm2, %ymm2
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm2, %ymm2
	vpsrlq	$63, %ymm5, %ymm14
	vpsllq	$1, %ymm5, %ymm5
	vpxor	%ymm10, %ymm2, %ymm10
	vpxor	%ymm2, %ymm3, %ymm3
	vpor	%ymm5, %ymm14, %ymm14
	vpsrlq	$63, %ymm11, %ymm5
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm13, %ymm14, %ymm13
	vpor	%ymm11, %ymm5, %ymm5
	vpxor	%ymm9, %ymm13, %ymm9
	vpxor	1568(%rsp), %ymm1, %ymm11
	vpxor	%ymm12, %ymm5, %ymm5
	vpsrlq	$20, %ymm8, %ymm12
	vpxor	1504(%rsp), %ymm5, %ymm0
	vpsllq	$44, %ymm8, %ymm8
	vpor	%ymm8, %ymm12, %ymm8
	vpsrlq	$21, %ymm10, %ymm12
	vpsllq	$43, %ymm10, %ymm10
	vpor	%ymm10, %ymm12, %ymm10
	vpandn	%ymm10, %ymm8, %ymm12
	vpxor	320(%rsp), %ymm12, %ymm12
	vpxor	%ymm11, %ymm12, %ymm12
	vmovdqa	%ymm12, 1568(%rsp)
	vpsrlq	$43, %ymm9, %ymm12
	vpsllq	$21, %ymm9, %ymm9
	vpor	%ymm9, %ymm12, %ymm9
	vpandn	%ymm9, %ymm10, %ymm12
	vpxor	%ymm8, %ymm12, %ymm14
	vpsrlq	$50, %ymm0, %ymm12
	vmovdqa	%ymm14, 1536(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm0
	vpandn	%ymm0, %ymm9, %ymm12
	vpxor	%ymm10, %ymm12, %ymm10
	vmovdqa	%ymm10, 1504(%rsp)
	vpandn	%ymm11, %ymm0, %ymm10
	vpandn	%ymm8, %ymm11, %ymm11
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	%ymm0, %ymm11, %ymm0
	vmovdqa	%ymm9, 1472(%rsp)
	vpsrlq	$3, %ymm3, %ymm11
	vpxor	1344(%rsp), %ymm13, %ymm8
	vpxor	1376(%rsp), %ymm5, %ymm9
	vpxor	1408(%rsp), %ymm1, %ymm10
	vpsllq	$61, %ymm3, %ymm3
	vmovdqa	%ymm0, 1440(%rsp)
	vpsrlq	$36, %ymm8, %ymm0
	vpsllq	$28, %ymm8, %ymm8
	vpor	%ymm3, %ymm11, %ymm3
	vpor	%ymm8, %ymm0, %ymm0
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm9, %ymm8, %ymm8
	vpsrlq	$61, %ymm10, %ymm9
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm10
	vpxor	%ymm0, %ymm10, %ymm10
	vmovdqa	%ymm10, 1408(%rsp)
	vpsrlq	$19, %ymm7, %ymm10
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm3, %ymm10, %ymm11
	vpandn	%ymm10, %ymm9, %ymm7
	vpxor	%ymm9, %ymm11, %ymm9
	vpxor	%ymm8, %ymm7, %ymm7
	vmovdqa	%ymm9, 1376(%rsp)
	vpandn	%ymm0, %ymm3, %ymm9
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	1216(%rsp), %ymm2, %ymm8
	vpxor	%ymm3, %ymm0, %ymm0
	vpxor	%ymm10, %ymm9, %ymm10
	vpxor	928(%rsp), %ymm4, %ymm3
	vmovdqa	%ymm0, 1312(%rsp)
	vmovdqa	%ymm10, 1344(%rsp)
	vpsrlq	$63, %ymm3, %ymm0
	vpsllq	$1, %ymm3, %ymm3
	vpor	%ymm3, %ymm0, %ymm0
	vpsrlq	$58, %ymm8, %ymm3
	vpsllq	$6, %ymm8, %ymm8
	vpor	%ymm8, %ymm3, %ymm3
	vpxor	1248(%rsp), %ymm13, %ymm8
	vpsrlq	$39, %ymm8, %ymm10
	vpsllq	$25, %ymm8, %ymm8
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm3, %ymm8
	vpxor	%ymm0, %ymm8, %ymm14
	vpxor	1280(%rsp), %ymm5, %ymm8
	vpshufb	.LC0(%rip), %ymm8, %ymm8
	vpandn	%ymm8, %ymm10, %ymm9
	vpxor	%ymm3, %ymm9, %ymm12
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm12, 1280(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm6, %ymm9, %ymm6
	vpandn	%ymm6, %ymm8, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm0, %ymm6, %ymm10
	vpandn	%ymm3, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm6
	vpxor	%ymm8, %ymm10, %ymm8
	vpxor	992(%rsp), %ymm5, %ymm0
	vmovdqa	%ymm14, 992(%rsp)
	vmovdqa	%ymm8, 1248(%rsp)
	vpxor	1088(%rsp), %ymm5, %ymm5
	vmovdqa	%ymm6, 1216(%rsp)
	vpsrlq	$37, %ymm0, %ymm3
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm3, %ymm3
	vpxor	1024(%rsp), %ymm1, %ymm0
	vpxor	1120(%rsp), %ymm1, %ymm1
	vpsrlq	$28, %ymm0, %ymm10
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm10, %ymm10
	vpxor	1184(%rsp), %ymm4, %ymm0
	vpsrlq	$54, %ymm0, %ymm8
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm8, %ymm8
	vpandn	%ymm8, %ymm10, %ymm0
	vpxor	%ymm3, %ymm0, %ymm6
	vpxor	1152(%rsp), %ymm2, %ymm0
	vpxor	960(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm6, 1184(%rsp)
	vpsrlq	$49, %ymm0, %ymm11
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm11, %ymm11
	vpxor	%ymm13, %ymm15, %ymm0
	vpxor	1056(%rsp), %ymm13, %ymm13
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpandn	%ymm11, %ymm8, %ymm6
	vpandn	%ymm0, %ymm11, %ymm12
	vpxor	%ymm10, %ymm6, %ymm6
	vpxor	%ymm8, %ymm12, %ymm15
	vpandn	%ymm3, %ymm0, %ymm8
	vpandn	%ymm10, %ymm3, %ymm3
	vpxor	%ymm0, %ymm3, %ymm12
	vpsrlq	$2, %ymm2, %ymm0
	vpxor	%ymm11, %ymm8, %ymm8
	vpsllq	$62, %ymm2, %ymm2
	vpsrlq	$23, %ymm1, %ymm11
	vmovdqa	%ymm12, 1152(%rsp)
	vpxor	1408(%rsp), %ymm14, %ymm3
	vpsrlq	$25, %ymm5, %ymm12
	vpor	%ymm2, %ymm0, %ymm0
	vpxor	1280(%rsp), %ymm6, %ymm14
	vpsrlq	$9, %ymm13, %ymm2
	vpsllq	$39, %ymm5, %ymm5
	vpsllq	$55, %ymm13, %ymm13
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm5, %ymm12, %ymm12
	vpor	%ymm13, %ymm2, %ymm2
	vpor	%ymm1, %ymm11, %ymm11
	vpxor	%ymm15, %ymm9, %ymm13
	vpandn	%ymm12, %ymm2, %ymm5
	vpandn	%ymm11, %ymm12, %ymm1
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	1184(%rsp), %ymm5, %ymm10
	vpxor	%ymm3, %ymm10, %ymm10
	vpxor	%ymm2, %ymm1, %ymm3
	vpxor	1568(%rsp), %ymm10, %ymm10
	vpxor	1536(%rsp), %ymm7, %ymm1
	vmovdqa	%ymm3, 928(%rsp)
	vmovdqa	%ymm15, 960(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	896(%rsp), %ymm4, %ymm1
	vpxor	%ymm3, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm3
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vmovdqa	1376(%rsp), %ymm12
	vpxor	1504(%rsp), %ymm12, %ymm4
	vpxor	%ymm4, %ymm13, %ymm13
	vpandn	%ymm0, %ymm3, %ymm4
	vpandn	%ymm2, %ymm0, %ymm0
	vpxor	%ymm11, %ymm4, %ymm11
	vpxor	%ymm3, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	1312(%rsp), %ymm3
	vmovdqa	1344(%rsp), %ymm4
	vpxor	%ymm11, %ymm8, %ymm12
	vpxor	1472(%rsp), %ymm4, %ymm4
	vmovdqa	%ymm11, 896(%rsp)
	vpxor	1440(%rsp), %ymm3, %ymm2
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1216(%rsp), %ymm0, %ymm11
	vpxor	%ymm4, %ymm12, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	1248(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpxor	1152(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm8, %ymm8
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm7, %ymm13
	vpsllq	$44, %ymm7, %ymm7
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm12
	vpor	%ymm7, %ymm13, %ymm7
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm7, %ymm13
	vpxor	288(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 1568(%rsp)
	vpsrlq	$43, %ymm8, %ymm13
	vpsllq	$21, %ymm8, %ymm8
	vpor	%ymm8, %ymm13, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm7, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 1120(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1088(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm7, %ymm12, %ymm12
	vpxor	1472(%rsp), %ymm11, %ymm7
	vpxor	%ymm8, %ymm9, %ymm8
	vmovdqa	%ymm8, 1056(%rsp)
	vpxor	%ymm0, %ymm12, %ymm8
	vpsrlq	$36, %ymm7, %ymm0
	vmovdqa	%ymm8, 1024(%rsp)
	vpsllq	$28, %ymm7, %ymm7
	vpsrlq	$3, %ymm1, %ymm12
	vpxor	1312(%rsp), %ymm10, %ymm8
	vpor	%ymm7, %ymm0, %ymm0
	vpsllq	$61, %ymm1, %ymm1
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm1, %ymm12, %ymm1
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	992(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm14
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 1472(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm7
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	1536(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 1312(%rsp)
	vpxor	1376(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm7, 992(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1248(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 1536(%rsp)
	vpxor	1152(%rsp), %ymm10, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm12
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm12, 1376(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	1440(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm5, 1152(%rsp)
	vmovdqa	%ymm7, 1248(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	1408(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1280(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 1440(%rsp)
	vpxor	960(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm14, 960(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	896(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	1504(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm13, 1408(%rsp)
	vpxor	1408(%rsp), %ymm9, %ymm13
	vmovdqa	%ymm0, %ymm15
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	1344(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	1216(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vmovdqa	1536(%rsp), %ymm1
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm14, %ymm1, %ymm1
	vpxor	1440(%rsp), %ymm5, %ymm10
	vpxor	1376(%rsp), %ymm6, %ymm14
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	1184(%rsp), %ymm3, %ymm1
	vpxor	1568(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm12
	vpxor	1120(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm12, 896(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	928(%rsp), %ymm2, %ymm1
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	1472(%rsp), %ymm12
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	1088(%rsp), %ymm12, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm3
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	1312(%rsp), %ymm11
	vpxor	%ymm3, %ymm7, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vmovdqa	%ymm3, 864(%rsp)
	vpxor	1056(%rsp), %ymm11, %ymm3
	vpxor	1152(%rsp), %ymm0, %ymm11
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1248(%rsp), %ymm12, %ymm12
	vmovdqa	992(%rsp), %ymm2
	vpxor	1024(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm15, 928(%rsp)
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpxor	%ymm15, %ymm11, %ymm11
	vpor	%ymm4, %ymm2, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	256(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 1568(%rsp)
	vpsrlq	$43, %ymm7, %ymm13
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1504(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1344(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	992(%rsp), %ymm10, %ymm8
	vpxor	%ymm7, %ymm9, %ymm9
	vpxor	%ymm0, %ymm12, %ymm0
	vpxor	1056(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm0, 1216(%rsp)
	vpsrlq	$3, %ymm1, %ymm12
	vpsllq	$61, %ymm1, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm1, %ymm12, %ymm1
	vmovdqa	%ymm9, 1280(%rsp)
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1536(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 1536(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 1184(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm7
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	1120(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 1056(%rsp)
	vpxor	1472(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm7, 992(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1248(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, %ymm15
	vpxor	928(%rsp), %ymm10, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm12
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm12, 1472(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	1024(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm5, 1120(%rsp)
	vmovdqa	%ymm7, 1248(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	960(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1376(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm14
	vpxor	1408(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm14, 1376(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	864(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm14
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vmovdqa	%ymm14, %ymm13
	vpxor	%ymm12, %ymm7, %ymm7
	vmovdqa	%ymm0, 1408(%rsp)
	vpxor	1088(%rsp), %ymm4, %ymm1
	vpxor	1472(%rsp), %ymm6, %ymm14
	vmovdqa	%ymm15, 1024(%rsp)
	vmovdqa	1184(%rsp), %ymm12
	vmovdqa	%ymm13, 928(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpxor	%ymm13, %ymm9, %ymm13
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	1312(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	1152(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpxor	1536(%rsp), %ymm15, %ymm1
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	1376(%rsp), %ymm5, %ymm10
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	1440(%rsp), %ymm3, %ymm1
	vpxor	1568(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vmovdqa	%ymm1, %ymm15
	vpxor	1504(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm15, 864(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	896(%rsp), %ymm2, %ymm1
	vpxor	%ymm15, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	1344(%rsp), %ymm12, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm3
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	1056(%rsp), %ymm11
	vpxor	%ymm3, %ymm7, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vmovdqa	992(%rsp), %ymm2
	vmovdqa	%ymm3, 896(%rsp)
	vpxor	1216(%rsp), %ymm2, %ymm2
	vpxor	1280(%rsp), %ymm11, %ymm3
	vpxor	1120(%rsp), %ymm0, %ymm11
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1248(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpxor	1408(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	224(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 1568(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1440(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1312(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	%ymm0, %ymm12, %ymm8
	vmovdqa	%ymm7, 1152(%rsp)
	vpsrlq	$3, %ymm1, %ymm12
	vpsllq	$61, %ymm1, %ymm1
	vpxor	1280(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm8, 1088(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpxor	992(%rsp), %ymm10, %ymm8
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1024(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 1280(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 1024(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm6, %ymm9, %ymm6
	vmovdqa	%ymm6, 992(%rsp)
	vpxor	%ymm1, %ymm0, %ymm6
	vpxor	1504(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 960(%rsp)
	vpxor	1184(%rsp), %ymm4, %ymm6
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1248(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm9
	vpxor	1408(%rsp), %ymm10, %ymm6
	vmovdqa	%ymm9, 1504(%rsp)
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm12
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm12, 1408(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	1216(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm5, 1184(%rsp)
	vmovdqa	%ymm7, 1248(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	1536(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1472(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, %ymm14
	vpxor	928(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm14, 928(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	896(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	1344(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm0, %ymm15
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	1056(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	1120(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm14, %ymm5, %ymm10
	vmovdqa	1504(%rsp), %ymm14
	vpxor	1280(%rsp), %ymm14, %ymm1
	vpxor	1408(%rsp), %ymm6, %ymm14
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	1376(%rsp), %ymm3, %ymm1
	vpxor	1568(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm12
	vpxor	1440(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm12, 832(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	864(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm13, 896(%rsp)
	vpxor	%ymm13, %ymm9, %ymm13
	vmovdqa	%ymm15, 1120(%rsp)
	vpxor	%ymm12, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	1024(%rsp), %ymm11
	vpxor	1312(%rsp), %ymm11, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm3
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	992(%rsp), %ymm11
	vpxor	%ymm3, %ymm7, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vmovdqa	960(%rsp), %ymm2
	vmovdqa	%ymm3, 864(%rsp)
	vpxor	1088(%rsp), %ymm2, %ymm2
	vpxor	1152(%rsp), %ymm11, %ymm3
	vpxor	1184(%rsp), %ymm0, %ymm11
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1248(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpxor	%ymm15, %ymm11, %ymm11
	vpor	%ymm4, %ymm2, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	192(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 1568(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1536(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1472(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm0, %ymm12, %ymm8
	vpsrlq	$3, %ymm1, %ymm12
	vpxor	%ymm7, %ymm9, %ymm9
	vpxor	1152(%rsp), %ymm11, %ymm7
	vpsllq	$61, %ymm1, %ymm1
	vmovdqa	%ymm8, 1344(%rsp)
	vpxor	960(%rsp), %ymm10, %ymm8
	vmovdqa	%ymm9, 1376(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1504(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 1504(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm1
	vpxor	%ymm6, %ymm9, %ymm6
	vmovdqa	%ymm1, 1152(%rsp)
	vpxor	1440(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 1216(%rsp)
	vpxor	1024(%rsp), %ymm4, %ymm6
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1248(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 1440(%rsp)
	vpxor	1120(%rsp), %ymm10, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm13
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm13, 1248(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm5, %ymm0, %ymm0
	vmovdqa	%ymm7, 1120(%rsp)
	vmovdqa	%ymm0, 1056(%rsp)
	vpxor	1088(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm14, 960(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	1280(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1408(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm6
	vpxor	896(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm6, 1408(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	864(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm7
	vmovdqa	%ymm7, %ymm15
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm15, %ymm9, %ymm13
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	1312(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm0, 1280(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	992(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	1184(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vmovdqa	1440(%rsp), %ymm1
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm14, %ymm1, %ymm1
	vpxor	1408(%rsp), %ymm5, %ymm10
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	928(%rsp), %ymm3, %ymm1
	vpxor	1568(%rsp), %ymm10, %ymm14
	vmovdqa	%ymm15, 928(%rsp)
	vmovdqa	%ymm14, 1312(%rsp)
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpxor	1248(%rsp), %ymm6, %ymm14
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vmovdqa	%ymm1, %ymm10
	vpxor	1536(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm10, 896(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	832(%rsp), %ymm2, %ymm1
	vpxor	%ymm10, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	1504(%rsp), %ymm11
	vpxor	1472(%rsp), %ymm11, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm15
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	1216(%rsp), %ymm11
	vmovdqa	1152(%rsp), %ymm2
	vpxor	%ymm15, %ymm7, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	1376(%rsp), %ymm11, %ymm3
	vpxor	1344(%rsp), %ymm2, %ymm2
	vpxor	1056(%rsp), %ymm0, %ymm11
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1120(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpxor	1280(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm10
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm3, %ymm5, %ymm5
	vpxor	1312(%rsp), %ymm2, %ymm2
	vpor	%ymm10, %ymm4, %ymm4
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpxor	%ymm2, %ymm8, %ymm8
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm2, %ymm6, %ymm6
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm4, %ymm1, %ymm1
	vmovdqa	1312(%rsp), %ymm14
	vpxor	%ymm13, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm10
	vpsrlq	$63, %ymm14, %ymm13
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	160(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 1568(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1312(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm14
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	%ymm0, %ymm12, %ymm0
	vpxor	1152(%rsp), %ymm10, %ymm8
	vmovdqa	%ymm14, 1184(%rsp)
	vmovdqa	%ymm7, 1088(%rsp)
	vpsrlq	$3, %ymm1, %ymm12
	vpsllq	$61, %ymm1, %ymm1
	vpxor	1376(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm0, 1024(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1440(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 1440(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 1376(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm6, %ymm9, %ymm6
	vmovdqa	%ymm6, 1152(%rsp)
	vpxor	%ymm1, %ymm0, %ymm6
	vpxor	1536(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 992(%rsp)
	vpxor	1504(%rsp), %ymm4, %ymm6
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1120(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm9
	vpxor	1280(%rsp), %ymm10, %ymm6
	vmovdqa	%ymm9, 1536(%rsp)
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1504(%rsp)
	vpsrlq	$46, %ymm5, %ymm9
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	1344(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm5, 1120(%rsp)
	vmovdqa	%ymm7, 1280(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	960(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1248(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm14
	vpxor	928(%rsp), %ymm4, %ymm0
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	%ymm11, %ymm15, %ymm0
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm5, %ymm6, %ymm6
	vpxor	%ymm7, %ymm13, %ymm15
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpxor	%ymm12, %ymm7, %ymm7
	vmovdqa	%ymm15, 1344(%rsp)
	vmovdqa	%ymm1, 1248(%rsp)
	vpxor	1472(%rsp), %ymm4, %ymm1
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	1216(%rsp), %ymm11, %ymm1
	vmovdqa	%ymm14, 960(%rsp)
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	1056(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vmovdqa	1536(%rsp), %ymm1
	vpxor	1440(%rsp), %ymm1, %ymm1
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm14, %ymm5, %ymm10
	vpxor	1504(%rsp), %ymm6, %ymm14
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	1408(%rsp), %ymm3, %ymm1
	vpxor	1568(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm12
	vpxor	1312(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm12, 928(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	896(%rsp), %ymm2, %ymm1
	vpxor	%ymm12, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	1376(%rsp), %ymm11
	vpxor	1184(%rsp), %ymm11, %ymm13
	vpxor	1344(%rsp), %ymm9, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm3
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	1152(%rsp), %ymm11
	vmovdqa	992(%rsp), %ymm2
	vpsllq	$1, %ymm13, %ymm4
	vpxor	1088(%rsp), %ymm11, %ymm12
	vmovdqa	%ymm3, 896(%rsp)
	vpxor	1024(%rsp), %ymm2, %ymm11
	vpxor	%ymm3, %ymm7, %ymm3
	vpxor	1120(%rsp), %ymm0, %ymm2
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1280(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpxor	1248(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	128(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 1568(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 1472(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1408(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm0, %ymm12, %ymm8
	vpsrlq	$3, %ymm1, %ymm12
	vpxor	%ymm7, %ymm9, %ymm9
	vpxor	1088(%rsp), %ymm11, %ymm7
	vpsllq	$61, %ymm1, %ymm1
	vmovdqa	%ymm8, 1056(%rsp)
	vpxor	992(%rsp), %ymm10, %ymm8
	vmovdqa	%ymm9, 1216(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1536(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 1536(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm1
	vpxor	%ymm6, %ymm9, %ymm6
	vmovdqa	%ymm1, 992(%rsp)
	vpxor	1312(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 1088(%rsp)
	vpxor	1376(%rsp), %ymm4, %ymm6
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1280(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 1376(%rsp)
	vpxor	1248(%rsp), %ymm10, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm15
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm15, 1312(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm6, %ymm7, %ymm6
	vpxor	%ymm5, %ymm0, %ymm7
	vpxor	1024(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm7, 1248(%rsp)
	vmovdqa	%ymm6, 1280(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	1440(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1504(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 1504(%rsp)
	vpxor	1344(%rsp), %ymm4, %ymm0
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	896(%rsp), %ymm11, %ymm0
	vmovdqa	%ymm14, 896(%rsp)
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm7
	vmovdqa	%ymm7, %ymm15
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	1184(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm0, 1440(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	1152(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	1120(%rsp), %ymm10, %ymm1
	vmovdqa	1376(%rsp), %ymm10
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpxor	%ymm14, %ymm10, %ymm10
	vpxor	1472(%rsp), %ymm8, %ymm14
	vpor	%ymm1, %ymm11, %ymm11
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	1504(%rsp), %ymm5, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	960(%rsp), %ymm3, %ymm1
	vpxor	1568(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm12
	vpxor	1312(%rsp), %ymm6, %ymm1
	vmovdqa	%ymm12, 864(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	928(%rsp), %ymm2, %ymm1
	vpxor	%ymm12, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	1536(%rsp), %ymm11
	vpxor	1408(%rsp), %ymm11, %ymm13
	vpxor	%ymm15, %ymm9, %ymm11
	vmovdqa	%ymm15, 960(%rsp)
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm3
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	992(%rsp), %ymm2
	vmovdqa	1088(%rsp), %ymm11
	vpsllq	$1, %ymm13, %ymm4
	vpxor	1216(%rsp), %ymm11, %ymm12
	vmovdqa	%ymm3, 928(%rsp)
	vpxor	1056(%rsp), %ymm2, %ymm11
	vpxor	%ymm3, %ymm7, %ymm3
	vpxor	1248(%rsp), %ymm0, %ymm2
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1280(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpxor	1440(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1568(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	96(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 1568(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 1344(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 1184(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	992(%rsp), %ymm10, %ymm8
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	%ymm0, %ymm12, %ymm0
	vmovdqa	%ymm7, 1152(%rsp)
	vpsrlq	$3, %ymm1, %ymm12
	vpsllq	$61, %ymm1, %ymm1
	vpxor	1216(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm0, 1120(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1376(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 1376(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 1216(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm7
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	1472(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 1024(%rsp)
	vpxor	1536(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm7, 992(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	1280(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm12
	vpxor	1440(%rsp), %ymm10, %ymm6
	vmovdqa	%ymm12, 1536(%rsp)
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm13
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm13, 1472(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm1
	vpxor	%ymm6, %ymm7, %ymm6
	vmovdqa	%ymm6, 1440(%rsp)
	vmovdqa	%ymm1, 1280(%rsp)
	vpxor	1056(%rsp), %ymm10, %ymm0
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	896(%rsp), %ymm3, %ymm0
	vpxor	1504(%rsp), %ymm3, %ymm3
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1312(%rsp), %ymm2, %ymm0
	vpxor	864(%rsp), %ymm2, %ymm2
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm14
	vpxor	960(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm14, 832(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	928(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	1408(%rsp), %ymm4, %ymm1
	vmovdqa	1536(%rsp), %ymm12
	vmovdqa	%ymm13, 1312(%rsp)
	vmovdqa	%ymm0, %ymm15
	vmovdqa	%ymm15, 1504(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	1088(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	1248(%rsp), %ymm10, %ymm1
	vpxor	1376(%rsp), %ymm12, %ymm10
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpandn	%ymm11, %ymm4, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpxor	%ymm14, %ymm1, %ymm5
	vpxor	1344(%rsp), %ymm8, %ymm14
	vpxor	%ymm5, %ymm10, %ymm10
	vpsrlq	$23, %ymm3, %ymm5
	vpxor	1568(%rsp), %ymm10, %ymm10
	vpsllq	$41, %ymm3, %ymm3
	vpor	%ymm3, %ymm5, %ymm5
	vpandn	%ymm5, %ymm11, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vmovdqa	%ymm3, %ymm12
	vpxor	1472(%rsp), %ymm6, %ymm3
	vmovdqa	%ymm12, 800(%rsp)
	vpxor	%ymm3, %ymm14, %ymm14
	vpsrlq	$62, %ymm2, %ymm3
	vpsllq	$2, %ymm2, %ymm2
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	1024(%rsp), %ymm12
	vpxor	1152(%rsp), %ymm12, %ymm12
	vpor	%ymm2, %ymm3, %ymm3
	vpandn	%ymm3, %ymm5, %ymm2
	vpxor	%ymm11, %ymm2, %ymm2
	vmovdqa	1216(%rsp), %ymm11
	vpxor	1184(%rsp), %ymm11, %ymm13
	vpxor	1312(%rsp), %ymm9, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm3, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm3, %ymm0, %ymm0
	vpxor	%ymm2, %ymm13, %ymm13
	vmovdqa	992(%rsp), %ymm3
	vpxor	%ymm11, %ymm7, %ymm5
	vpsrlq	$63, %ymm14, %ymm4
	vmovdqa	%ymm11, 896(%rsp)
	vpxor	1120(%rsp), %ymm3, %ymm11
	vpxor	1280(%rsp), %ymm0, %ymm3
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	1440(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm13, %ymm5
	vpxor	%ymm3, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm3
	vpor	%ymm3, %ymm4, %ymm4
	vpsrlq	$63, %ymm13, %ymm3
	vpxor	%ymm15, %ymm11, %ymm11
	vpor	%ymm5, %ymm3, %ymm3
	vpsllq	$1, %ymm12, %ymm15
	vpxor	%ymm11, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm5
	vpxor	%ymm10, %ymm3, %ymm3
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm15, %ymm5, %ymm5
	vpxor	%ymm3, %ymm8, %ymm8
	vpxor	%ymm3, %ymm6, %ymm6
	vpxor	%ymm14, %ymm5, %ymm5
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm5, %ymm2, %ymm2
	vpor	%ymm11, %ymm14, %ymm14
	vpsrlq	$63, %ymm10, %ymm11
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm13, %ymm14, %ymm14
	vpor	%ymm10, %ymm11, %ymm10
	vpxor	%ymm14, %ymm7, %ymm7
	vpxor	1568(%rsp), %ymm4, %ymm11
	vpxor	%ymm12, %ymm10, %ymm10
	vpsrlq	$20, %ymm8, %ymm12
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm10, %ymm0, %ymm0
	vpor	%ymm8, %ymm12, %ymm8
	vpsrlq	$21, %ymm9, %ymm12
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm12, %ymm9
	vpandn	%ymm9, %ymm8, %ymm12
	vpxor	64(%rsp), %ymm12, %ymm12
	vpxor	%ymm11, %ymm12, %ymm15
	vpsrlq	$43, %ymm7, %ymm12
	vmovdqa	%ymm15, 1088(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm12, %ymm7
	vpandn	%ymm7, %ymm9, %ymm12
	vpxor	%ymm8, %ymm12, %ymm15
	vpsrlq	$50, %ymm0, %ymm12
	vmovdqa	%ymm15, 1408(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm0
	vpandn	%ymm0, %ymm7, %ymm12
	vpxor	%ymm9, %ymm12, %ymm12
	vpandn	%ymm11, %ymm0, %ymm9
	vpandn	%ymm8, %ymm11, %ymm11
	vpxor	%ymm7, %ymm9, %ymm15
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	1152(%rsp), %ymm14, %ymm7
	vpxor	992(%rsp), %ymm10, %ymm8
	vpxor	1536(%rsp), %ymm4, %ymm9
	vmovdqa	%ymm15, 1248(%rsp)
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$61, %ymm9, %ymm8
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm9
	vpxor	%ymm0, %ymm9, %ymm15
	vpsrlq	$19, %ymm6, %ymm9
	vmovdqa	%ymm15, 1152(%rsp)
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm9, %ymm6
	vpandn	%ymm6, %ymm8, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$3, %ymm2, %ymm9
	vmovdqa	%ymm15, 1056(%rsp)
	vpsllq	$61, %ymm2, %ymm2
	vpor	%ymm2, %ymm9, %ymm2
	vpandn	%ymm2, %ymm6, %ymm15
	vpxor	%ymm8, %ymm15, %ymm15
	vpandn	%ymm0, %ymm2, %ymm8
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	1440(%rsp), %ymm14, %ymm7
	vpxor	%ymm6, %ymm8, %ymm6
	vmovdqa	%ymm6, 992(%rsp)
	vpxor	%ymm2, %ymm0, %ymm6
	vpxor	1344(%rsp), %ymm3, %ymm2
	vmovdqa	%ymm6, 960(%rsp)
	vpxor	1216(%rsp), %ymm5, %ymm6
	vpsrlq	$63, %ymm2, %ymm0
	vpsllq	$1, %ymm2, %ymm2
	vpor	%ymm2, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm2
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm2, %ymm2
	vpsrlq	$39, %ymm7, %ymm6
	vpsllq	$25, %ymm7, %ymm7
	vpor	%ymm7, %ymm6, %ymm6
	vpxor	1504(%rsp), %ymm10, %ymm7
	vpandn	%ymm6, %ymm2, %ymm13
	vpshufb	.LC0(%rip), %ymm7, %ymm7
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm7, %ymm6, %ymm8
	vpxor	%ymm2, %ymm8, %ymm9
	vpsrlq	$46, %ymm1, %ymm8
	vpsllq	$18, %ymm1, %ymm1
	vpor	%ymm1, %ymm8, %ymm1
	vpandn	%ymm1, %ymm7, %ymm8
	vpxor	%ymm6, %ymm8, %ymm6
	vmovdqa	%ymm6, 1440(%rsp)
	vpandn	%ymm0, %ymm1, %ymm6
	vpandn	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	1120(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm1, 1216(%rsp)
	vmovdqa	%ymm6, 1344(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	1376(%rsp), %ymm4, %ymm0
	vpxor	832(%rsp), %ymm4, %ymm4
	vpsrlq	$28, %ymm0, %ymm2
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm2, %ymm2
	vpxor	1472(%rsp), %ymm3, %ymm0
	vpsrlq	$54, %ymm0, %ymm6
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpandn	%ymm6, %ymm2, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 928(%rsp)
	vpxor	1312(%rsp), %ymm5, %ymm0
	vpsrlq	$49, %ymm0, %ymm7
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm0
	vpandn	%ymm0, %ymm6, %ymm7
	vpxor	%ymm2, %ymm7, %ymm8
	vpxor	896(%rsp), %ymm14, %ymm7
	vmovdqa	%ymm8, 1312(%rsp)
	vpshufb	.LC1(%rip), %ymm7, %ymm7
	vpandn	%ymm7, %ymm0, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpandn	%ymm1, %ymm7, %ymm6
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm7, %ymm1, %ymm7
	vpxor	%ymm0, %ymm6, %ymm0
	vpxor	1184(%rsp), %ymm5, %ymm1
	vpxor	1024(%rsp), %ymm14, %ymm2
	vpsrlq	$23, %ymm4, %ymm6
	vpxor	1280(%rsp), %ymm10, %ymm5
	vmovdqa	%ymm0, 896(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vmovdqa	%ymm7, 864(%rsp)
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$9, %ymm2, %ymm1
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$41, %ymm4, %ymm4
	vpor	%ymm2, %ymm1, %ymm1
	vpsrlq	$25, %ymm5, %ymm2
	vpor	%ymm4, %ymm6, %ymm4
	vpsllq	$39, %ymm5, %ymm5
	vpor	%ymm5, %ymm2, %ymm2
	vpandn	%ymm4, %ymm2, %ymm6
	vpandn	%ymm2, %ymm1, %ymm5
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm0, %ymm5, %ymm5
	vmovdqa	%ymm6, 1568(%rsp)
	vpxor	800(%rsp), %ymm3, %ymm3
	vpsrlq	$62, %ymm3, %ymm6
	vpsllq	$2, %ymm3, %ymm3
	vpor	%ymm3, %ymm6, %ymm3
	vpandn	%ymm3, %ymm4, %ymm6
	vpxor	%ymm2, %ymm6, %ymm2
	vmovdqa	%ymm2, 1536(%rsp)
	vpandn	%ymm0, %ymm3, %ymm2
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm4, %ymm2, %ymm4
	vmovdqa	%ymm4, 1504(%rsp)
	vpxor	%ymm3, %ymm0, %ymm4
	vmovdqa	%ymm4, 1472(%rsp)
	cmpq	%r8, %r12
	jnb	.L432
	vmovdqa	%ymm11, %ymm3
	vmovdqa	%ymm9, %ymm2
	vmovdqa	%ymm8, %ymm6
	vmovdqa	1088(%rsp), %ymm14
	subq	24(%rsp), %rax
.L431:
	vmovdqa	1408(%rsp), %ymm4
	vmovdqa	%ymm14, (%r14)
	vmovdqa	%ymm12, 64(%r14)
	vmovdqa	%ymm4, 32(%r14)
	vmovdqa	1248(%rsp), %ymm4
	vmovdqa	%ymm3, 128(%r14)
	vmovdqa	%ymm4, 96(%r14)
	vmovdqa	1152(%rsp), %ymm4
	vmovdqa	%ymm15, 224(%r14)
	vmovdqa	%ymm4, 160(%r14)
	vmovdqa	1056(%rsp), %ymm4
	vmovdqa	%ymm13, 320(%r14)
	vmovdqa	%ymm4, 192(%r14)
	vmovdqa	992(%rsp), %ymm4
	vmovdqa	%ymm2, 352(%r14)
	vmovdqa	%ymm4, 256(%r14)
	vmovdqa	960(%rsp), %ymm4
	vmovdqa	%ymm6, 544(%r14)
	vmovdqa	%ymm4, 288(%r14)
	vmovdqa	1440(%rsp), %ymm4
	vmovdqa	%ymm4, 384(%r14)
	vmovdqa	1344(%rsp), %ymm4
	vmovdqa	%ymm4, 416(%r14)
	vmovdqa	1216(%rsp), %ymm4
	vmovdqa	%ymm4, 448(%r14)
	vmovdqa	928(%rsp), %ymm4
	vmovdqa	%ymm4, 480(%r14)
	vmovdqa	1312(%rsp), %ymm4
	vmovdqa	%ymm4, 512(%r14)
	vmovdqa	896(%rsp), %ymm4
	vmovdqa	%ymm4, 576(%r14)
	vmovdqa	864(%rsp), %ymm4
	vmovdqa	%ymm4, 608(%r14)
	vmovdqa	1568(%rsp), %ymm4
	vmovdqa	%ymm5, 640(%r14)
	vmovdqa	%ymm4, 672(%r14)
	vmovdqa	1536(%rsp), %ymm4
	vmovdqa	%ymm4, 704(%r14)
	vmovdqa	1504(%rsp), %ymm4
	vmovdqa	%ymm4, 736(%r14)
	vmovdqa	1472(%rsp), %ymm4
	vmovdqa	%ymm4, 768(%r14)
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
.L435:
	xorl	%eax, %eax
	jmp	.L431
	.size	ossl_keccak1600x4_avx2_KeccakF1600times4_FastLoop_Absorb, .-ossl_keccak1600x4_avx2_KeccakF1600times4_FastLoop_Absorb
	.p2align 4
	.globl	ossl_keccak1600x4_avx2_KeccakP1600times4_12rounds_FastLoop_Absorb
	.type	ossl_keccak1600x4_avx2_KeccakP1600times4_12rounds_FastLoop_Absorb, @function
ossl_keccak1600x4_avx2_KeccakP1600times4_12rounds_FastLoop_Absorb:
	endbr64
	pushq	%rbp
	movl	%ecx, %eax
	movq	%rsp, %rbp
	pushq	%r15
	leal	(%rdx,%rdx,2), %r15d
	pushq	%r14
	movq	%rdi, %r14
	pushq	%r13
	movl	%edx, %r13d
	pushq	%r12
	movq	%r9, %r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$1216, %rsp
	movq	%r8, 24(%rsp)
	cmpl	$21, %esi
	je	.L442
	addl	%esi, %r15d
	movl	%esi, %r10d
	movq	%r8, %rbx
	xorl	%eax, %eax
	leal	0(,%r15,8), %esi
	leal	0(,%rcx,8), %r15d
	movq	%rsi, 1184(%rsp)
	cmpq	%rsi, %r9
	jb	.L441
	movl	%r10d, 1152(%rsp)
	.p2align 4,,10
	.p2align 3
.L448:
	movl	1152(%rsp), %edx
	movq	%rbx, %rsi
	movl	%r13d, %ecx
	movq	%r14, %rdi
	addq	%r15, %rbx
	subq	%r15, %r12
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_AddLanesAll@PLT
	movq	%r14, %rdi
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_12rounds@PLT
	cmpq	1184(%rsp), %r12
	jnb	.L448
	movq	%rbx, %rax
	subq	24(%rsp), %rax
.L441:
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L442:
	vmovdqa	32(%r14), %ymm4
	sall	$4, %r13d
	vmovdqa	128(%r14), %ymm11
	leal	0(,%r15,8), %ecx
	vmovdqa	352(%r14), %ymm9
	vmovdqa	(%r14), %ymm14
	movq	%rcx, %r15
	movq	%r8, %rbx
	vmovdqa	%ymm4, 960(%rsp)
	addq	%r8, %rcx
	vmovdqa	%ymm11, %ymm3
	vmovdqa	96(%r14), %ymm4
	vmovdqa	544(%r14), %ymm8
	vmovdqa	64(%r14), %ymm12
	leal	0(,%rdx,8), %edi
	movl	%r13d, %edx
	vmovdqa	%ymm4, 896(%rsp)
	addq	%r8, %rdi
	addq	%r8, %rdx
	leal	168(%r15), %r8d
	vmovdqa	160(%r14), %ymm4
	vmovdqa	%ymm9, %ymm5
	vmovdqa	%ymm8, %ymm6
	vmovdqa	224(%r14), %ymm15
	vmovdqa	320(%r14), %ymm13
	vmovdqa	%ymm4, 1024(%rsp)
	vmovdqa	192(%r14), %ymm4
	vmovdqa	%ymm4, 768(%rsp)
	vmovdqa	256(%r14), %ymm4
	vmovdqa	%ymm4, 736(%rsp)
	vmovdqa	288(%r14), %ymm4
	vmovdqa	%ymm4, 672(%rsp)
	vmovdqa	384(%r14), %ymm4
	vmovdqa	%ymm4, 928(%rsp)
	vmovdqa	416(%r14), %ymm4
	vmovdqa	%ymm4, 864(%rsp)
	vmovdqa	448(%r14), %ymm4
	vmovdqa	%ymm4, 544(%rsp)
	vmovdqa	480(%r14), %ymm4
	vmovdqa	%ymm4, 704(%rsp)
	vmovdqa	512(%r14), %ymm4
	vmovdqa	%ymm4, 1056(%rsp)
	vmovdqa	576(%r14), %ymm4
	vmovdqa	%ymm4, 512(%rsp)
	vmovdqa	608(%r14), %ymm4
	vmovdqa	%ymm4, 480(%rsp)
	vmovdqa	672(%r14), %ymm4
	vmovdqa	640(%r14), %ymm2
	vmovdqa	%ymm4, 1184(%rsp)
	vmovdqa	704(%r14), %ymm4
	vmovdqa	%ymm4, 1152(%rsp)
	vmovdqa	736(%r14), %ymm4
	vmovdqa	%ymm4, 1120(%rsp)
	vmovdqa	768(%r14), %ymm4
	vmovdqa	%ymm4, 1088(%rsp)
	cmpq	%r8, %r9
	jb	.L449
	vbroadcastsd	96+KeccakF1600RoundConstants(%rip), %ymm4
	movl	%eax, %esi
	leal	0(,%rax,8), %r10d
	movq	%rbx, %rax
	vmovdqa	%ymm14, 576(%rsp)
	salq	$3, %rsi
	vmovapd	%ymm4, 384(%rsp)
	vbroadcastsd	104+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 352(%rsp)
	vbroadcastsd	112+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 320(%rsp)
	vbroadcastsd	120+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 288(%rsp)
	vbroadcastsd	128+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 256(%rsp)
	vbroadcastsd	136+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 224(%rsp)
	vbroadcastsd	144+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 192(%rsp)
	vbroadcastsd	152+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 160(%rsp)
	vbroadcastsd	160+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 128(%rsp)
	vbroadcastsd	168+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 96(%rsp)
	vbroadcastsd	176+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 64(%rsp)
	vbroadcastsd	184+KeccakF1600RoundConstants(%rip), %ymm4
	vmovapd	%ymm4, 32(%rsp)
	.p2align 4,,10
	.p2align 3
.L446:
	vmovq	(%rdx), %xmm4
	vpinsrq	$1, (%rcx), %xmm4, %xmm1
	subq	%r10, %r12
	vmovq	(%rax), %xmm4
	vpinsrq	$1, (%rdi), %xmm4, %xmm0
	vmovq	8(%rdx), %xmm3
	vmovq	24(%rdx), %xmm6
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vmovq	32(%rdx), %xmm7
	vmovq	40(%rdx), %xmm14
	vpxor	576(%rsp), %ymm0, %ymm4
	vpinsrq	$1, 8(%rcx), %xmm3, %xmm1
	vmovq	8(%rax), %xmm3
	vpinsrq	$1, 8(%rdi), %xmm3, %xmm0
	vmovq	16(%rdx), %xmm3
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 16(%rcx), %xmm3, %xmm1
	vpxor	960(%rsp), %ymm0, %ymm5
	vmovq	16(%rax), %xmm3
	vpinsrq	$1, 16(%rdi), %xmm3, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 24(%rcx), %xmm6, %xmm1
	vmovq	24(%rax), %xmm6
	vpxor	%ymm12, %ymm0, %ymm3
	vpinsrq	$1, 24(%rdi), %xmm6, %xmm0
	vmovq	48(%rdx), %xmm12
	vmovdqa	%ymm3, 576(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 32(%rcx), %xmm7, %xmm1
	vpxor	896(%rsp), %ymm0, %ymm6
	vmovq	32(%rax), %xmm7
	vpinsrq	$1, 32(%rdi), %xmm7, %xmm0
	vmovdqa	%ymm6, 960(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 40(%rcx), %xmm14, %xmm1
	vmovq	40(%rax), %xmm14
	vpxor	%ymm11, %ymm0, %ymm7
	vpinsrq	$1, 40(%rdi), %xmm14, %xmm0
	vmovdqa	%ymm7, 608(%rsp)
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	1024(%rsp), %ymm0, %ymm14
	vpinsrq	$1, 48(%rcx), %xmm12, %xmm0
	vmovq	48(%rax), %xmm12
	vpinsrq	$1, 48(%rdi), %xmm12, %xmm7
	vmovq	56(%rdx), %xmm12
	vpinsrq	$1, 56(%rcx), %xmm12, %xmm1
	vinserti128	$0x1, %xmm0, %ymm7, %ymm7
	vmovq	56(%rax), %xmm12
	vmovq	72(%rdx), %xmm10
	vpxor	768(%rsp), %ymm7, %ymm7
	vpinsrq	$1, 56(%rdi), %xmm12, %xmm0
	vmovq	64(%rdx), %xmm12
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 64(%rcx), %xmm12, %xmm1
	vmovq	64(%rax), %xmm12
	vpxor	%ymm15, %ymm0, %ymm15
	vpinsrq	$1, 64(%rdi), %xmm12, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 72(%rcx), %xmm10, %xmm1
	vpxor	736(%rsp), %ymm0, %ymm12
	vmovq	72(%rax), %xmm10
	vpinsrq	$1, 72(%rdi), %xmm10, %xmm0
	vmovdqa	%ymm12, 640(%rsp)
	vmovq	80(%rdx), %xmm10
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 80(%rcx), %xmm10, %xmm1
	vpxor	672(%rsp), %ymm0, %ymm11
	vmovq	80(%rax), %xmm10
	vpinsrq	$1, 80(%rdi), %xmm10, %xmm0
	vmovdqa	%ymm11, 992(%rsp)
	vmovq	88(%rdx), %xmm10
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 88(%rcx), %xmm10, %xmm1
	vmovq	88(%rax), %xmm10
	vpxor	%ymm13, %ymm0, %ymm13
	vpinsrq	$1, 88(%rdi), %xmm10, %xmm0
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	%ymm9, %ymm0, %ymm9
	vmovdqa	%ymm9, %ymm11
	vmovq	96(%rdx), %xmm9
	vpinsrq	$1, 96(%rcx), %xmm9, %xmm0
	vmovq	96(%rax), %xmm9
	vpinsrq	$1, 96(%rdi), %xmm9, %xmm9
	vinserti128	$0x1, %xmm0, %ymm9, %ymm9
	vpxor	928(%rsp), %ymm9, %ymm9
	vmovq	104(%rdx), %xmm10
	vpinsrq	$1, 104(%rcx), %xmm10, %xmm1
	vmovq	104(%rax), %xmm10
	vpinsrq	$1, 104(%rdi), %xmm10, %xmm0
	vmovq	112(%rdx), %xmm6
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpinsrq	$1, 112(%rcx), %xmm6, %xmm1
	vpxor	864(%rsp), %ymm0, %ymm10
	vmovq	112(%rax), %xmm6
	vpinsrq	$1, 112(%rdi), %xmm6, %xmm0
	vmovdqa	%ymm10, 1024(%rsp)
	vmovq	128(%rax), %xmm10
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	544(%rsp), %ymm0, %ymm6
	vmovq	120(%rdx), %xmm0
	vpinsrq	$1, 120(%rcx), %xmm0, %xmm1
	vmovq	120(%rax), %xmm0
	vmovdqa	%ymm6, 896(%rsp)
	vpinsrq	$1, 120(%rdi), %xmm0, %xmm0
	vpinsrq	$1, 128(%rdi), %xmm10, %xmm6
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	704(%rsp), %ymm0, %ymm12
	vmovq	128(%rdx), %xmm0
	vpinsrq	$1, 128(%rcx), %xmm0, %xmm0
	vinserti128	$0x1, %xmm0, %ymm6, %ymm6
	vmovq	136(%rdx), %xmm0
	vpinsrq	$1, 136(%rcx), %xmm0, %xmm1
	vmovq	136(%rax), %xmm0
	vpinsrq	$1, 136(%rdi), %xmm0, %xmm0
	vpxor	1056(%rsp), %ymm6, %ymm6
	vinserti128	$0x1, %xmm1, %ymm0, %ymm0
	vpxor	%ymm8, %ymm0, %ymm8
	vmovdqa	%ymm8, %ymm1
	vmovq	144(%rdx), %xmm8
	vpinsrq	$1, 144(%rcx), %xmm8, %xmm0
	vmovq	144(%rax), %xmm8
	vpinsrq	$1, 144(%rdi), %xmm8, %xmm8
	vinserti128	$0x1, %xmm0, %ymm8, %ymm8
	vpxor	512(%rsp), %ymm8, %ymm8
	vmovq	152(%rdx), %xmm0
	vmovdqa	%ymm14, 416(%rsp)
	vmovq	152(%rax), %xmm10
	vpinsrq	$1, 152(%rcx), %xmm0, %xmm0
	vmovdqa	%ymm11, 448(%rsp)
	vpinsrq	$1, 152(%rdi), %xmm10, %xmm10
	vmovq	160(%rax), %xmm3
	addq	%rsi, %rax
	vmovdqa	%ymm1, 544(%rsp)
	vpinsrq	$1, 160(%rdi), %xmm3, %xmm3
	addq	%rsi, %rdi
	vmovdqa	%ymm4, 1056(%rsp)
	vmovdqa	%ymm5, 864(%rsp)
	vinserti128	$0x1, %xmm0, %ymm10, %ymm10
	vmovq	160(%rdx), %xmm0
	vpinsrq	$1, 160(%rcx), %xmm0, %xmm0
	vpxor	480(%rsp), %ymm10, %ymm10
	addq	%rsi, %rdx
	addq	%rsi, %rcx
	vmovdqa	%ymm12, 480(%rsp)
	vinserti128	$0x1, %xmm0, %ymm3, %ymm3
	vpxor	%ymm4, %ymm14, %ymm0
	vpxor	%ymm11, %ymm6, %ymm14
	vmovdqa	992(%rsp), %ymm4
	vpxor	1024(%rsp), %ymm8, %ymm11
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm12, %ymm13, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpxor	%ymm5, %ymm7, %ymm0
	vpxor	%ymm1, %ymm9, %ymm12
	vmovdqa	640(%rsp), %ymm1
	vpxor	%ymm0, %ymm14, %ymm14
	vpxor	%ymm3, %ymm2, %ymm2
	vpxor	576(%rsp), %ymm15, %ymm0
	vpxor	1184(%rsp), %ymm14, %ymm14
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	960(%rsp), %ymm1, %ymm0
	vpxor	608(%rsp), %ymm4, %ymm1
	vpxor	1152(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	896(%rsp), %ymm10, %ymm0
	vpxor	1120(%rsp), %ymm11, %ymm11
	vpsllq	$1, %ymm12, %ymm4
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlq	$63, %ymm14, %ymm1
	vpxor	1088(%rsp), %ymm0, %ymm0
	vpor	%ymm1, %ymm5, %ymm5
	vpsrlq	$63, %ymm12, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm1
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm5, %ymm13
	vpxor	%ymm3, %ymm5, %ymm3
	vmovdqa	%ymm1, 928(%rsp)
	vpsllq	$1, %ymm11, %ymm1
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm6, %ymm4, %ymm6
	vpor	928(%rsp), %ymm1, %ymm1
	vpxor	%ymm14, %ymm1, %ymm1
	vpsrlq	$63, %ymm0, %ymm14
	vpsllq	$1, %ymm0, %ymm0
	vpxor	%ymm9, %ymm1, %ymm9
	vpor	%ymm14, %ymm0, %ymm0
	vpxor	%ymm12, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm12
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm0, %ymm8
	vpor	%ymm12, %ymm2, %ymm2
	vpsrlq	$20, %ymm7, %ymm12
	vpsllq	$44, %ymm7, %ymm7
	vpxor	%ymm11, %ymm2, %ymm2
	vpxor	1056(%rsp), %ymm5, %ymm11
	vpor	%ymm12, %ymm7, %ymm7
	vpsrlq	$21, %ymm9, %ymm12
	vpxor	%ymm10, %ymm2, %ymm10
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm12, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm12
	vpxor	384(%rsp), %ymm12, %ymm12
	vpxor	%ymm11, %ymm12, %ymm14
	vpsrlq	$43, %ymm8, %ymm12
	vmovdqa	%ymm14, 1056(%rsp)
	vpsllq	$21, %ymm8, %ymm8
	vpor	%ymm12, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vmovdqa	%ymm12, 672(%rsp)
	vpxor	1088(%rsp), %ymm2, %ymm12
	vpshufb	.LC0(%rip), %ymm10, %ymm10
	vpsrlq	$50, %ymm12, %ymm14
	vpsllq	$14, %ymm12, %ymm12
	vpor	%ymm14, %ymm12, %ymm12
	vpandn	%ymm12, %ymm8, %ymm14
	vpxor	%ymm9, %ymm14, %ymm9
	vmovdqa	%ymm9, 512(%rsp)
	vpandn	%ymm11, %ymm12, %ymm9
	vpandn	%ymm7, %ymm11, %ymm11
	vpxor	960(%rsp), %ymm0, %ymm7
	vpxor	%ymm8, %ymm9, %ymm8
	vmovdqa	%ymm8, 928(%rsp)
	vpxor	%ymm12, %ymm11, %ymm8
	vpxor	1152(%rsp), %ymm1, %ymm11
	vmovdqa	%ymm8, 704(%rsp)
	vpsrlq	$36, %ymm7, %ymm8
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	992(%rsp), %ymm2, %ymm8
	vpsllq	$61, %ymm11, %ymm11
	vpsrlq	$44, %ymm8, %ymm9
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm12, %ymm11, %ymm11
	vpor	%ymm9, %ymm8, %ymm8
	vpsrlq	$61, %ymm13, %ymm9
	vpsllq	$3, %ymm13, %ymm13
	vpor	%ymm9, %ymm13, %ymm13
	vpandn	%ymm13, %ymm8, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 736(%rsp)
	vpsrlq	$19, %ymm6, %ymm9
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm11, %ymm6, %ymm12
	vpandn	%ymm6, %ymm13, %ymm9
	vpxor	%ymm13, %ymm12, %ymm13
	vpandn	%ymm7, %ymm11, %ymm12
	vpandn	%ymm8, %ymm7, %ymm7
	vmovdqa	%ymm13, 768(%rsp)
	vpxor	%ymm6, %ymm12, %ymm13
	vpxor	%ymm11, %ymm7, %ymm11
	vpxor	%ymm8, %ymm9, %ymm9
	vpxor	864(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm11, 960(%rsp)
	vpxor	1120(%rsp), %ymm0, %ymm12
	vmovdqa	%ymm13, 800(%rsp)
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpsrlq	$63, %ymm6, %ymm7
	vpsllq	$1, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm15, %ymm1, %ymm7
	vpsrlq	$58, %ymm7, %ymm8
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	1024(%rsp), %ymm0, %ymm8
	vpxor	640(%rsp), %ymm0, %ymm0
	vpsrlq	$39, %ymm8, %ymm11
	vpsllq	$25, %ymm8, %ymm8
	vpor	%ymm11, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm11
	vpxor	%ymm6, %ymm11, %ymm15
	vpandn	%ymm10, %ymm8, %ymm11
	vmovdqa	%ymm15, %ymm14
	vpxor	%ymm7, %ymm11, %ymm15
	vmovdqa	%ymm15, 832(%rsp)
	vpsrlq	$46, %ymm3, %ymm11
	vpsllq	$18, %ymm3, %ymm3
	vmovdqa	%ymm14, 1120(%rsp)
	vpor	%ymm11, %ymm3, %ymm3
	vpandn	%ymm3, %ymm10, %ymm11
	vpxor	%ymm8, %ymm11, %ymm11
	vpandn	%ymm6, %ymm3, %ymm8
	vpandn	%ymm7, %ymm6, %ymm6
	vpxor	%ymm3, %ymm6, %ymm3
	vpxor	%ymm10, %ymm8, %ymm10
	vmovdqa	%ymm3, 864(%rsp)
	vpxor	608(%rsp), %ymm2, %ymm3
	vpxor	896(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm10, 992(%rsp)
	vpxor	448(%rsp), %ymm4, %ymm10
	vpsrlq	$37, %ymm3, %ymm6
	vpsllq	$27, %ymm3, %ymm3
	vpor	%ymm6, %ymm3, %ymm3
	vpxor	416(%rsp), %ymm5, %ymm6
	vpxor	480(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm3, %ymm7, %ymm15
	vpxor	544(%rsp), %ymm1, %ymm7
	vpxor	576(%rsp), %ymm1, %ymm1
	vpsrlq	$49, %ymm7, %ymm8
	vpsllq	$15, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm12, %ymm7, %ymm13
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm8, %ymm8
	vmovdqa	%ymm10, 1024(%rsp)
	vpandn	%ymm3, %ymm12, %ymm10
	vpandn	%ymm6, %ymm3, %ymm3
	vpxor	%ymm12, %ymm3, %ymm6
	vpsrlq	$2, %ymm1, %ymm3
	vpxor	%ymm7, %ymm10, %ymm10
	vmovdqa	736(%rsp), %ymm7
	vmovdqa	%ymm6, 1152(%rsp)
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsrlq	$9, %ymm0, %ymm3
	vpxor	%ymm14, %ymm7, %ymm7
	vpsllq	$55, %ymm0, %ymm0
	vpor	%ymm3, %ymm0, %ymm0
	vpsrlq	$25, %ymm2, %ymm3
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vpandn	%ymm2, %ymm0, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm15, %ymm6, %ymm3
	vpxor	%ymm7, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm7
	vpxor	1056(%rsp), %ymm3, %ymm3
	vpxor	832(%rsp), %ymm8, %ymm14
	vpsllq	$41, %ymm5, %ymm5
	vpxor	1184(%rsp), %ymm4, %ymm4
	vmovdqa	768(%rsp), %ymm12
	vpor	%ymm7, %ymm5, %ymm5
	vpandn	%ymm5, %ymm2, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vmovdqa	%ymm7, %ymm13
	vpxor	672(%rsp), %ymm9, %ymm7
	vmovdqa	%ymm13, 480(%rsp)
	vpxor	%ymm7, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm7
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1024(%rsp), %ymm11, %ymm13
	vpor	%ymm7, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm7
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	512(%rsp), %ymm12, %ymm2
	vpxor	%ymm2, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm2
	vpandn	%ymm0, %ymm1, %ymm1
	vmovdqa	960(%rsp), %ymm0
	vpxor	%ymm5, %ymm2, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm7, %ymm13, %ymm13
	vmovdqa	800(%rsp), %ymm2
	vpxor	928(%rsp), %ymm2, %ymm2
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	704(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm5, 1184(%rsp)
	vpsllq	$1, %ymm14, %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm2, %ymm12, %ymm12
	vpxor	864(%rsp), %ymm1, %ymm2
	vpxor	992(%rsp), %ymm12, %ymm12
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1152(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1088(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1088(%rsp), %ymm0, %ymm0
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm11, %ymm0, %ymm11
	vpxor	%ymm7, %ymm0, %ymm7
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1056(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm11, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm11, %ymm11
	vpor	%ymm13, %ymm11, %ymm11
	vpandn	%ymm11, %ymm9, %ymm13
	vpxor	352(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1056(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm11, %ymm13
	vpxor	%ymm9, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 896(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm11, %ymm13, %ymm11
	vmovdqa	%ymm11, 544(%rsp)
	vpandn	%ymm12, %ymm1, %ymm11
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm9
	vpsrlq	$3, %ymm7, %ymm12
	vpxor	%ymm10, %ymm11, %ymm10
	vpxor	928(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm7, %ymm7
	vmovdqa	%ymm10, 1088(%rsp)
	vpxor	960(%rsp), %ymm3, %ymm10
	vpxor	1120(%rsp), %ymm5, %ymm11
	vpor	%ymm12, %ymm7, %ymm7
	vmovdqa	%ymm9, 576(%rsp)
	vpsrlq	$36, %ymm1, %ymm9
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm9, %ymm1, %ymm1
	vpsrlq	$44, %ymm10, %ymm9
	vpsllq	$20, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpsrlq	$61, %ymm11, %ymm9
	vpsllq	$3, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 608(%rsp)
	vpsrlq	$19, %ymm8, %ymm9
	vpsllq	$45, %ymm8, %ymm8
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm7, %ymm8, %ymm12
	vpandn	%ymm8, %ymm11, %ymm9
	vpxor	%ymm11, %ymm12, %ymm11
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm11, 928(%rsp)
	vpandn	%ymm1, %ymm7, %ymm11
	vpandn	%ymm10, %ymm1, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm8, %ymm11, %ymm8
	vmovdqa	%ymm1, 1120(%rsp)
	vpxor	672(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm8, 640(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	768(%rsp), %ymm0, %ymm7
	vpxor	992(%rsp), %ymm2, %ymm10
	vpxor	1152(%rsp), %ymm3, %ymm11
	vpxor	1184(%rsp), %ymm2, %ymm12
	vpxor	800(%rsp), %ymm2, %ymm2
	vpsrlq	$58, %ymm7, %ymm8
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsllq	$6, %ymm7, %ymm7
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm8
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpandn	%ymm11, %ymm10, %ymm8
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm8, 960(%rsp)
	vpsrlq	$46, %ymm6, %ymm8
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm8, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm8
	vpxor	%ymm10, %ymm8, %ymm8
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	1024(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm1, 672(%rsp)
	vpxor	704(%rsp), %ymm3, %ymm1
	vpxor	512(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1152(%rsp)
	vpxor	832(%rsp), %ymm4, %ymm10
	vpxor	864(%rsp), %ymm3, %ymm3
	vpxor	480(%rsp), %ymm4, %ymm4
	vpsrlq	$37, %ymm1, %ymm6
	vmovdqa	%ymm14, 864(%rsp)
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	736(%rsp), %ymm5, %ymm6
	vpxor	%ymm15, %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 736(%rsp)
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm10, 992(%rsp)
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	992(%rsp), %ymm8, %ymm13
	vpxor	%ymm12, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	608(%rsp), %ymm14, %ymm11
	vmovdqa	928(%rsp), %ymm12
	vmovdqa	%ymm6, 1184(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vpxor	960(%rsp), %ymm7, %ymm14
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	736(%rsp), %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1056(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm15
	vpxor	896(%rsp), %ymm9, %ymm11
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm15, %ymm14, %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	544(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	640(%rsp), %ymm0
	vpxor	1088(%rsp), %ymm0, %ymm0
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm12
	vmovdqa	%ymm5, 480(%rsp)
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1152(%rsp), %ymm12, %ymm12
	vmovdqa	1120(%rsp), %ymm5
	vpxor	672(%rsp), %ymm1, %ymm2
	vpxor	576(%rsp), %ymm5, %ymm0
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1184(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1024(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1024(%rsp), %ymm0, %ymm0
	vpxor	%ymm9, %ymm4, %ymm9
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm8, %ymm0, %ymm8
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm9, %ymm13
	vpsllq	$44, %ymm9, %ymm9
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1056(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm9, %ymm9
	vpsrlq	$21, %ymm8, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm8, %ymm8
	vpor	%ymm13, %ymm8, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	320(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1024(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 800(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 512(%rsp)
	vpandn	%ymm12, %ymm1, %ymm8
	vpandn	%ymm9, %ymm12, %ymm12
	vpxor	1120(%rsp), %ymm3, %ymm9
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm8, %ymm8
	vmovdqa	%ymm1, 704(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1088(%rsp), %ymm2, %ymm1
	vpxor	864(%rsp), %ymm5, %ymm10
	vmovdqa	%ymm8, 1056(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm13
	vpsrlq	$19, %ymm7, %ymm8
	vmovdqa	%ymm13, 768(%rsp)
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 832(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm9
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	896(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 864(%rsp)
	vpxor	1152(%rsp), %ymm2, %ymm10
	vpxor	1184(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm9, 1088(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	928(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1120(%rsp)
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm13
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm13, 896(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm1, 928(%rsp)
	vpxor	576(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm10, 1152(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	608(%rsp), %ymm5, %ymm6
	vpxor	960(%rsp), %ymm4, %ymm10
	vpxor	992(%rsp), %ymm0, %ymm11
	vpxor	%ymm15, %ymm4, %ymm4
	vpxor	544(%rsp), %ymm0, %ymm0
	vpxor	672(%rsp), %ymm3, %ymm3
	vpsrlq	$28, %ymm6, %ymm7
	vpxor	736(%rsp), %ymm5, %ymm5
	vmovdqa	832(%rsp), %ymm15
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm12
	vpsrlq	$49, %ymm11, %ymm7
	vmovdqa	%ymm12, %ymm14
	vpsllq	$15, %ymm11, %ymm11
	vpxor	480(%rsp), %ymm2, %ymm12
	vpxor	640(%rsp), %ymm2, %ymm2
	vpor	%ymm7, %ymm11, %ymm11
	vmovdqa	%ymm14, 448(%rsp)
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpandn	%ymm11, %ymm10, %ymm7
	vpandn	%ymm12, %ymm11, %ymm13
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	%ymm10, %ymm13, %ymm13
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1120(%rsp), %ymm12
	vpxor	768(%rsp), %ymm12, %ymm11
	vmovdqa	%ymm6, 1184(%rsp)
	vpsrlq	$2, %ymm0, %ymm6
	vpsllq	$62, %ymm0, %ymm0
	vmovdqa	%ymm13, 960(%rsp)
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpxor	960(%rsp), %ymm9, %ymm13
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm14, %ymm6, %ymm3
	vpxor	896(%rsp), %ymm7, %ymm14
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	1024(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm12
	vpxor	800(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm12, 480(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm12, %ymm14, %ymm14
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	512(%rsp), %ymm15, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm15
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	864(%rsp), %ymm0
	vpxor	1056(%rsp), %ymm0, %ymm0
	vpxor	%ymm10, %ymm15, %ymm12
	vpxor	928(%rsp), %ymm1, %ymm2
	vmovdqa	1088(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	704(%rsp), %ymm5, %ymm0
	vpxor	1152(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1184(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 992(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	992(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1024(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	288(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 992(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 544(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 576(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm1, 608(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	1056(%rsp), %ymm2, %ymm1
	vpxor	1120(%rsp), %ymm5, %ymm10
	vmovdqa	%ymm9, 1024(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1088(%rsp), %ymm3, %ymm9
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 640(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 672(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1152(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm7, 736(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	800(%rsp), %ymm4, %ymm1
	vpxor	1184(%rsp), %ymm3, %ymm11
	vmovdqa	%ymm7, 1056(%rsp)
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	832(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm9, 1088(%rsp)
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm12
	vpsrlq	$46, %ymm6, %ymm9
	vmovdqa	%ymm12, 1120(%rsp)
	vpsllq	$18, %ymm6, %ymm6
	vpxor	%ymm15, %ymm2, %ymm12
	vpxor	864(%rsp), %ymm2, %ymm2
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	704(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 800(%rsp)
	vpxor	960(%rsp), %ymm0, %ymm11
	vpxor	512(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1152(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	896(%rsp), %ymm4, %ymm10
	vpxor	928(%rsp), %ymm3, %ymm3
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	768(%rsp), %ymm5, %ymm6
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, %ymm14
	vpsrlq	$49, %ymm11, %ymm7
	vmovdqa	%ymm14, 416(%rsp)
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm15
	vpxor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	%ymm15, 1184(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpxor	%ymm12, %ymm1, %ymm15
	vmovdqa	1088(%rsp), %ymm11
	vpxor	640(%rsp), %ymm11, %ymm11
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm14, %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpxor	992(%rsp), %ymm3, %ymm3
	vpxor	448(%rsp), %ymm5, %ymm5
	vpxor	1120(%rsp), %ymm7, %ymm14
	vpxor	480(%rsp), %ymm4, %ymm4
	vmovdqa	672(%rsp), %ymm12
	vpsrlq	$23, %ymm5, %ymm11
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm13
	vpxor	544(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm13, 448(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1184(%rsp), %ymm9, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	576(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	736(%rsp), %ymm0
	vpxor	1024(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	800(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 512(%rsp)
	vmovdqa	1056(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	608(%rsp), %ymm5, %ymm0
	vpxor	1152(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpxor	%ymm15, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 960(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	960(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	992(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	256(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm13
	vmovdqa	%ymm13, 992(%rsp)
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm1, %ymm13
	vmovdqa	%ymm14, 832(%rsp)
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 704(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm8
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	1024(%rsp), %ymm2, %ymm1
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm9, 928(%rsp)
	vpxor	1056(%rsp), %ymm3, %ymm9
	vpxor	1088(%rsp), %ymm5, %ymm10
	vpor	%ymm12, %ymm11, %ymm11
	vmovdqa	%ymm8, 768(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 864(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vmovdqa	%ymm10, 896(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vmovdqa	%ymm7, 960(%rsp)
	vpxor	%ymm11, %ymm1, %ymm7
	vpxor	544(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm7, 1024(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	672(%rsp), %ymm0, %ymm7
	vpxor	1152(%rsp), %ymm2, %ymm10
	vpxor	512(%rsp), %ymm2, %ymm12
	vpxor	736(%rsp), %ymm2, %ymm2
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm11
	vmovdqa	%ymm11, 1056(%rsp)
	vpxor	%ymm15, %ymm3, %ymm11
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	1184(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm1, 1088(%rsp)
	vpxor	608(%rsp), %ymm3, %ymm1
	vpxor	576(%rsp), %ymm0, %ymm0
	vmovdqa	%ymm10, 1152(%rsp)
	vpxor	1120(%rsp), %ymm4, %ymm10
	vpxor	800(%rsp), %ymm3, %ymm3
	vpxor	448(%rsp), %ymm4, %ymm4
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	640(%rsp), %ymm5, %ymm6
	vpxor	416(%rsp), %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm7
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm14
	vpsrlq	$49, %ymm11, %ymm7
	vmovdqa	%ymm14, 480(%rsp)
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm10, 1120(%rsp)
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1056(%rsp), %ymm11
	vmovdqa	%ymm1, 1184(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpxor	864(%rsp), %ymm11, %ymm11
	vmovdqa	896(%rsp), %ymm12
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm14, %ymm6, %ymm3
	vpxor	%ymm15, %ymm7, %ymm14
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpxor	992(%rsp), %ymm3, %ymm3
	vpsllq	$41, %ymm5, %ymm5
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm11
	vmovdqa	%ymm11, %ymm13
	vpxor	832(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm13, 512(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	1120(%rsp), %ymm9, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	704(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	960(%rsp), %ymm0
	vpxor	928(%rsp), %ymm0, %ymm0
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm5, %ymm10, %ymm12
	vmovdqa	%ymm5, 672(%rsp)
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	1152(%rsp), %ymm12, %ymm12
	vpxor	1088(%rsp), %ymm1, %ymm2
	vmovdqa	1024(%rsp), %ymm5
	vpxor	768(%rsp), %ymm5, %ymm0
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1184(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 800(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	800(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	992(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	224(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 800(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 544(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	%ymm10, %ymm9, %ymm10
	vmovdqa	%ymm1, 576(%rsp)
	vpsllq	$61, %ymm11, %ymm11
	vpxor	928(%rsp), %ymm2, %ymm1
	vpxor	1024(%rsp), %ymm3, %ymm9
	vmovdqa	%ymm10, 992(%rsp)
	vpor	%ymm12, %ymm11, %ymm11
	vpxor	1056(%rsp), %ymm5, %ymm10
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 608(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm13
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1152(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm13, 928(%rsp)
	vmovdqa	%ymm1, 1024(%rsp)
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	832(%rsp), %ymm4, %ymm1
	vpxor	672(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm7, 640(%rsp)
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpxor	896(%rsp), %ymm0, %ymm7
	vpsrlq	$58, %ymm7, %ymm9
	vpsllq	$6, %ymm7, %ymm7
	vpor	%ymm9, %ymm7, %ymm7
	vpsrlq	$39, %ymm10, %ymm9
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm11
	vmovdqa	%ymm11, 1152(%rsp)
	vpxor	1184(%rsp), %ymm3, %ymm11
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 832(%rsp)
	vpsrlq	$46, %ymm6, %ymm9
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm7, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	768(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm6, 736(%rsp)
	vpxor	1120(%rsp), %ymm0, %ymm11
	vmovdqa	%ymm10, 1184(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpxor	%ymm15, %ymm4, %ymm10
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	864(%rsp), %ymm5, %ymm6
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vmovdqa	%ymm14, 1120(%rsp)
	vpxor	704(%rsp), %ymm0, %ymm0
	vpxor	1088(%rsp), %ymm3, %ymm3
	vpxor	960(%rsp), %ymm2, %ymm2
	vpsrlq	$28, %ymm6, %ymm7
	vpxor	480(%rsp), %ymm5, %ymm5
	vpxor	512(%rsp), %ymm4, %ymm4
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm7
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm7
	vpxor	%ymm1, %ymm7, %ymm15
	vpsrlq	$49, %ymm11, %ymm7
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm7, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm10, %ymm13, %ymm10
	vpxor	%ymm6, %ymm7, %ymm7
	vmovdqa	%ymm10, 864(%rsp)
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpsrlq	$2, %ymm0, %ymm6
	vpxor	%ymm11, %ymm10, %ymm10
	vmovdqa	1152(%rsp), %ymm11
	vmovdqa	%ymm1, 1056(%rsp)
	vpsllq	$62, %ymm0, %ymm0
	vpxor	608(%rsp), %ymm11, %ymm11
	vmovdqa	928(%rsp), %ymm12
	vpor	%ymm6, %ymm0, %ymm1
	vpsrlq	$9, %ymm2, %ymm0
	vpsrlq	$25, %ymm3, %ymm6
	vpsllq	$55, %ymm2, %ymm2
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm0, %ymm2, %ymm2
	vpor	%ymm6, %ymm3, %ymm0
	vpandn	%ymm0, %ymm2, %ymm6
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm15, %ymm6, %ymm3
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$23, %ymm5, %ymm11
	vpsllq	$41, %ymm5, %ymm5
	vpxor	%ymm14, %ymm3, %ymm3
	vpor	%ymm11, %ymm5, %ymm5
	vpandn	%ymm5, %ymm0, %ymm11
	vpxor	%ymm2, %ymm11, %ymm14
	vpxor	800(%rsp), %ymm8, %ymm11
	vmovdqa	%ymm14, %ymm13
	vpxor	832(%rsp), %ymm7, %ymm14
	vmovdqa	%ymm13, 480(%rsp)
	vpxor	%ymm11, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm11
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm13, %ymm14, %ymm14
	vpxor	864(%rsp), %ymm9, %ymm13
	vpor	%ymm11, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	544(%rsp), %ymm12, %ymm0
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm1, %ymm4, %ymm0
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm13, %ymm13
	vmovdqa	640(%rsp), %ymm0
	vpxor	992(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm10, %ymm12
	vpxor	736(%rsp), %ymm1, %ymm2
	vmovdqa	%ymm5, 512(%rsp)
	vmovdqa	1024(%rsp), %ymm5
	vpsllq	$1, %ymm13, %ymm4
	vpxor	%ymm0, %ymm12, %ymm12
	vpxor	576(%rsp), %ymm5, %ymm0
	vpxor	1184(%rsp), %ymm12, %ymm12
	vpsllq	$1, %ymm14, %ymm5
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm0
	vpxor	1056(%rsp), %ymm2, %ymm2
	vpor	%ymm0, %ymm5, %ymm5
	vpsrlq	$63, %ymm13, %ymm0
	vpor	%ymm0, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm0
	vpxor	%ymm2, %ymm5, %ymm5
	vmovdqa	%ymm0, 1088(%rsp)
	vpsllq	$1, %ymm12, %ymm0
	vpxor	%ymm3, %ymm4, %ymm4
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	1088(%rsp), %ymm0, %ymm0
	vpxor	%ymm8, %ymm4, %ymm8
	vpxor	%ymm7, %ymm4, %ymm7
	vpxor	%ymm14, %ymm0, %ymm0
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm9, %ymm0, %ymm9
	vpxor	%ymm11, %ymm0, %ymm11
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm3, %ymm13
	vpsllq	$1, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm3, %ymm3
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm3, %ymm3
	vpxor	1120(%rsp), %ymm5, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm1, %ymm3, %ymm1
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm13, %ymm9, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	192(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 1088(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 960(%rsp)
	vpsrlq	$50, %ymm1, %ymm13
	vpsllq	$14, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpandn	%ymm1, %ymm10, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 672(%rsp)
	vpandn	%ymm12, %ymm1, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm10, %ymm9, %ymm9
	vpxor	%ymm1, %ymm12, %ymm8
	vmovdqa	%ymm9, 1120(%rsp)
	vpsrlq	$3, %ymm11, %ymm12
	vpxor	992(%rsp), %ymm2, %ymm1
	vpxor	1024(%rsp), %ymm3, %ymm9
	vpxor	1152(%rsp), %ymm5, %ymm10
	vpsllq	$61, %ymm11, %ymm11
	vmovdqa	%ymm8, 704(%rsp)
	vpsrlq	$36, %ymm1, %ymm8
	vpsllq	$28, %ymm1, %ymm1
	vpor	%ymm12, %ymm11, %ymm11
	vpor	%ymm8, %ymm1, %ymm1
	vpsrlq	$44, %ymm9, %ymm8
	vpsllq	$20, %ymm9, %ymm9
	vpor	%ymm8, %ymm9, %ymm9
	vpsrlq	$61, %ymm10, %ymm8
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm8, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm8
	vpxor	%ymm1, %ymm8, %ymm8
	vmovdqa	%ymm8, 896(%rsp)
	vpsrlq	$19, %ymm7, %ymm8
	vpsllq	$45, %ymm7, %ymm7
	vpor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm11, %ymm7, %ymm12
	vpandn	%ymm7, %ymm10, %ymm8
	vpxor	%ymm10, %ymm12, %ymm10
	vpxor	%ymm9, %ymm8, %ymm8
	vpxor	512(%rsp), %ymm2, %ymm12
	vmovdqa	%ymm10, 992(%rsp)
	vpandn	%ymm1, %ymm11, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	928(%rsp), %ymm0, %ymm9
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm7, %ymm10, %ymm7
	vpxor	1184(%rsp), %ymm2, %ymm10
	vmovdqa	%ymm1, 1152(%rsp)
	vpxor	800(%rsp), %ymm4, %ymm1
	vpxor	1056(%rsp), %ymm3, %ymm11
	vpshufb	.LC1(%rip), %ymm12, %ymm12
	vmovdqa	%ymm7, 768(%rsp)
	vpxor	640(%rsp), %ymm2, %ymm2
	vpshufb	.LC0(%rip), %ymm11, %ymm11
	vpsrlq	$63, %ymm1, %ymm7
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpsrlq	$58, %ymm9, %ymm7
	vpsllq	$6, %ymm9, %ymm9
	vpor	%ymm7, %ymm9, %ymm9
	vpsrlq	$39, %ymm10, %ymm7
	vpsllq	$25, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm9, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 1184(%rsp)
	vpandn	%ymm11, %ymm10, %ymm7
	vpxor	%ymm9, %ymm7, %ymm7
	vmovdqa	%ymm7, 928(%rsp)
	vpsrlq	$46, %ymm6, %ymm7
	vpsllq	$18, %ymm6, %ymm6
	vpor	%ymm7, %ymm6, %ymm6
	vpandn	%ymm6, %ymm11, %ymm7
	vpxor	%ymm10, %ymm7, %ymm7
	vpandn	%ymm1, %ymm6, %ymm10
	vpandn	%ymm9, %ymm1, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpxor	%ymm6, %ymm1, %ymm11
	vpxor	576(%rsp), %ymm3, %ymm1
	vmovdqa	%ymm10, 1024(%rsp)
	vpxor	832(%rsp), %ymm4, %ymm10
	vpxor	736(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm11, 800(%rsp)
	vpsrlq	$37, %ymm1, %ymm6
	vpsllq	$27, %ymm1, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	608(%rsp), %ymm5, %ymm6
	vpxor	%ymm15, %ymm5, %ymm5
	vpsrlq	$28, %ymm6, %ymm9
	vpsllq	$36, %ymm6, %ymm6
	vpor	%ymm9, %ymm6, %ymm6
	vpsrlq	$54, %ymm10, %ymm9
	vpsllq	$10, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpandn	%ymm10, %ymm6, %ymm9
	vpxor	%ymm1, %ymm9, %ymm11
	vmovdqa	%ymm11, 832(%rsp)
	vpxor	864(%rsp), %ymm0, %ymm11
	vpxor	544(%rsp), %ymm0, %ymm0
	vpsrlq	$49, %ymm11, %ymm9
	vpsllq	$15, %ymm11, %ymm11
	vpor	%ymm9, %ymm11, %ymm11
	vpandn	%ymm12, %ymm11, %ymm13
	vpandn	%ymm11, %ymm10, %ymm9
	vpxor	%ymm10, %ymm13, %ymm14
	vpandn	%ymm1, %ymm12, %ymm10
	vpandn	%ymm6, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm12
	vpsrlq	$2, %ymm0, %ymm1
	vpxor	%ymm11, %ymm10, %ymm10
	vpsllq	$62, %ymm0, %ymm0
	vpxor	%ymm6, %ymm9, %ymm9
	vmovdqa	1184(%rsp), %ymm6
	vpxor	896(%rsp), %ymm6, %ymm6
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$9, %ymm2, %ymm1
	vmovdqa	%ymm14, %ymm13
	vmovdqa	%ymm12, 1056(%rsp)
	vpsllq	$55, %ymm2, %ymm2
	vpor	%ymm1, %ymm2, %ymm2
	vpsrlq	$25, %ymm3, %ymm1
	vpsllq	$39, %ymm3, %ymm3
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm2, %ymm11
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	832(%rsp), %ymm11, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpsrlq	$23, %ymm5, %ymm6
	vpxor	1088(%rsp), %ymm1, %ymm1
	vpxor	928(%rsp), %ymm9, %ymm14
	vpsllq	$41, %ymm5, %ymm5
	vpxor	480(%rsp), %ymm4, %ymm4
	vmovdqa	%ymm13, 512(%rsp)
	vpor	%ymm6, %ymm5, %ymm5
	vpxor	%ymm13, %ymm7, %ymm13
	vmovdqa	992(%rsp), %ymm12
	vpandn	%ymm5, %ymm3, %ymm6
	vpxor	%ymm2, %ymm6, %ymm15
	vpxor	960(%rsp), %ymm8, %ymm6
	vpxor	%ymm6, %ymm14, %ymm14
	vpsrlq	$62, %ymm4, %ymm6
	vpsllq	$2, %ymm4, %ymm4
	vpxor	%ymm15, %ymm14, %ymm14
	vpor	%ymm6, %ymm4, %ymm4
	vpandn	%ymm4, %ymm5, %ymm6
	vpxor	%ymm3, %ymm6, %ymm6
	vpxor	672(%rsp), %ymm12, %ymm3
	vpxor	%ymm3, %ymm13, %ymm13
	vpandn	%ymm0, %ymm4, %ymm3
	vpandn	%ymm2, %ymm0, %ymm0
	vpxor	%ymm5, %ymm3, %ymm5
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm6, %ymm13, %ymm13
	vmovdqa	768(%rsp), %ymm3
	vpxor	1120(%rsp), %ymm3, %ymm3
	vpsllq	$1, %ymm14, %ymm4
	vpxor	%ymm5, %ymm10, %ymm12
	vmovdqa	%ymm5, 544(%rsp)
	vpxor	800(%rsp), %ymm0, %ymm2
	vpsrlq	$63, %ymm13, %ymm5
	vpxor	%ymm3, %ymm12, %ymm12
	vmovdqa	1152(%rsp), %ymm3
	vpxor	704(%rsp), %ymm3, %ymm3
	vpxor	1024(%rsp), %ymm12, %ymm12
	vpxor	%ymm3, %ymm2, %ymm2
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	1056(%rsp), %ymm2, %ymm2
	vpor	%ymm3, %ymm4, %ymm4
	vpsllq	$1, %ymm13, %ymm3
	vpor	%ymm5, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm5
	vpxor	%ymm2, %ymm4, %ymm4
	vmovdqa	%ymm5, 864(%rsp)
	vpsllq	$1, %ymm12, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm11, %ymm4, %ymm11
	vpor	864(%rsp), %ymm5, %ymm5
	vpxor	%ymm8, %ymm3, %ymm8
	vpxor	%ymm14, %ymm5, %ymm5
	vpsrlq	$63, %ymm2, %ymm14
	vpsllq	$1, %ymm2, %ymm2
	vpxor	%ymm7, %ymm5, %ymm7
	vpxor	%ymm6, %ymm5, %ymm6
	vpor	%ymm14, %ymm2, %ymm2
	vpxor	%ymm13, %ymm2, %ymm2
	vpsrlq	$63, %ymm1, %ymm13
	vpsllq	$1, %ymm1, %ymm1
	vpxor	%ymm10, %ymm2, %ymm10
	vpor	%ymm13, %ymm1, %ymm1
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	1088(%rsp), %ymm4, %ymm12
	vpor	%ymm13, %ymm8, %ymm8
	vpsrlq	$21, %ymm7, %ymm13
	vpxor	%ymm0, %ymm1, %ymm0
	vpsllq	$43, %ymm7, %ymm7
	vpor	%ymm13, %ymm7, %ymm7
	vpandn	%ymm7, %ymm8, %ymm13
	vpxor	160(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm10, %ymm13
	vmovdqa	%ymm14, 864(%rsp)
	vpsllq	$21, %ymm10, %ymm10
	vpor	%ymm13, %ymm10, %ymm10
	vpandn	%ymm10, %ymm7, %ymm13
	vpxor	%ymm8, %ymm13, %ymm13
	vmovdqa	%ymm13, 640(%rsp)
	vpsrlq	$50, %ymm0, %ymm13
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm13, %ymm0, %ymm0
	vpandn	%ymm0, %ymm10, %ymm13
	vpxor	%ymm7, %ymm13, %ymm14
	vpandn	%ymm12, %ymm0, %ymm7
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm0, %ymm12, %ymm0
	vpxor	%ymm10, %ymm7, %ymm10
	vpxor	1152(%rsp), %ymm1, %ymm8
	vmovdqa	%ymm14, 576(%rsp)
	vmovdqa	%ymm0, 608(%rsp)
	vpxor	1120(%rsp), %ymm2, %ymm0
	vmovdqa	%ymm10, 736(%rsp)
	vpxor	1184(%rsp), %ymm4, %ymm10
	vpsrlq	$36, %ymm0, %ymm7
	vpsllq	$28, %ymm0, %ymm0
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm7, %ymm8, %ymm8
	vpsrlq	$61, %ymm10, %ymm7
	vpsllq	$3, %ymm10, %ymm10
	vpor	%ymm7, %ymm10, %ymm10
	vpandn	%ymm10, %ymm8, %ymm7
	vpxor	%ymm0, %ymm7, %ymm7
	vmovdqa	%ymm7, 1184(%rsp)
	vpxor	%ymm9, %ymm3, %ymm7
	vpsrlq	$19, %ymm7, %ymm12
	vpsllq	$45, %ymm7, %ymm9
	vpor	%ymm9, %ymm12, %ymm9
	vpsrlq	$3, %ymm6, %ymm12
	vpsllq	$61, %ymm6, %ymm6
	vpandn	%ymm9, %ymm10, %ymm7
	vpor	%ymm6, %ymm12, %ymm6
	vpxor	%ymm8, %ymm7, %ymm7
	vpandn	%ymm6, %ymm9, %ymm12
	vpxor	%ymm10, %ymm12, %ymm12
	vpandn	%ymm0, %ymm6, %ymm10
	vpandn	%ymm8, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm8
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	960(%rsp), %ymm3, %ymm6
	vmovdqa	%ymm12, 1152(%rsp)
	vmovdqa	%ymm8, 1088(%rsp)
	vpxor	992(%rsp), %ymm5, %ymm8
	vmovdqa	%ymm9, 1120(%rsp)
	vpsrlq	$63, %ymm6, %ymm0
	vpsllq	$1, %ymm6, %ymm6
	vpor	%ymm6, %ymm0, %ymm0
	vpsrlq	$58, %ymm8, %ymm6
	vpsllq	$6, %ymm8, %ymm8
	vpor	%ymm8, %ymm6, %ymm6
	vpxor	1024(%rsp), %ymm2, %ymm8
	vpsrlq	$39, %ymm8, %ymm12
	vpsllq	$25, %ymm8, %ymm8
	vpor	%ymm8, %ymm12, %ymm12
	vpandn	%ymm12, %ymm6, %ymm8
	vpxor	%ymm0, %ymm8, %ymm10
	vpxor	1056(%rsp), %ymm1, %ymm8
	vmovdqa	%ymm10, %ymm14
	vpsrlq	$46, %ymm11, %ymm10
	vpshufb	.LC0(%rip), %ymm8, %ymm8
	vpsllq	$18, %ymm11, %ymm11
	vpandn	%ymm8, %ymm12, %ymm9
	vpor	%ymm11, %ymm10, %ymm10
	vpxor	%ymm6, %ymm9, %ymm9
	vmovdqa	%ymm9, 1056(%rsp)
	vpandn	%ymm10, %ymm8, %ymm9
	vpxor	%ymm12, %ymm9, %ymm11
	vmovdqa	%ymm11, 1024(%rsp)
	vpandn	%ymm0, %ymm10, %ymm11
	vpandn	%ymm6, %ymm0, %ymm0
	vpxor	%ymm10, %ymm0, %ymm6
	vpxor	%ymm8, %ymm11, %ymm11
	vpxor	704(%rsp), %ymm1, %ymm0
	vmovdqa	%ymm14, 704(%rsp)
	vmovdqa	%ymm11, 992(%rsp)
	vpxor	800(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm6, 960(%rsp)
	vpsrlq	$37, %ymm0, %ymm10
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm10, %ymm10
	vpxor	896(%rsp), %ymm4, %ymm0
	vpsrlq	$28, %ymm0, %ymm11
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm11, %ymm11
	vpxor	928(%rsp), %ymm3, %ymm0
	vpxor	%ymm15, %ymm3, %ymm3
	vmovdqa	1152(%rsp), %ymm15
	vpsrlq	$54, %ymm0, %ymm8
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm8, %ymm8
	vpandn	%ymm8, %ymm11, %ymm0
	vpxor	%ymm10, %ymm0, %ymm6
	vpxor	512(%rsp), %ymm5, %ymm0
	vpxor	672(%rsp), %ymm5, %ymm5
	vmovdqa	%ymm6, 928(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	544(%rsp), %ymm2, %ymm0
	vpxor	768(%rsp), %ymm2, %ymm2
	vpandn	%ymm12, %ymm8, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm11, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm8, %ymm13, %ymm8
	vmovdqa	%ymm8, 896(%rsp)
	vpandn	%ymm10, %ymm0, %ymm8
	vpandn	%ymm11, %ymm10, %ymm10
	vpxor	%ymm12, %ymm8, %ymm8
	vpsrlq	$9, %ymm2, %ymm11
	vpxor	%ymm0, %ymm10, %ymm12
	vpsllq	$55, %ymm2, %ymm2
	vpsrlq	$2, %ymm5, %ymm0
	vmovdqa	%ymm12, %ymm9
	vpsrlq	$25, %ymm1, %ymm12
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm2, %ymm11, %ymm11
	vpor	%ymm1, %ymm12, %ymm12
	vpsllq	$62, %ymm5, %ymm5
	vpxor	1184(%rsp), %ymm14, %ymm1
	vpxor	1056(%rsp), %ymm6, %ymm14
	vpor	%ymm5, %ymm0, %ymm0
	vpandn	%ymm12, %ymm11, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	928(%rsp), %ymm5, %ymm10
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	832(%rsp), %ymm4, %ymm1
	vpxor	864(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm2
	vpsllq	$41, %ymm1, %ymm4
	vpor	%ymm4, %ymm2, %ymm4
	vpandn	%ymm4, %ymm12, %ymm1
	vpxor	%ymm11, %ymm1, %ymm2
	vpxor	640(%rsp), %ymm7, %ymm1
	vmovdqa	%ymm2, 512(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpsrlq	$62, %ymm3, %ymm1
	vpsllq	$2, %ymm3, %ymm3
	vpxor	%ymm2, %ymm14, %ymm14
	vpor	%ymm3, %ymm1, %ymm1
	vmovdqa	1024(%rsp), %ymm3
	vpxor	896(%rsp), %ymm3, %ymm13
	vpxor	576(%rsp), %ymm15, %ymm3
	vpandn	%ymm1, %ymm4, %ymm2
	vpxor	%ymm12, %ymm2, %ymm2
	vpxor	%ymm3, %ymm13, %ymm13
	vpandn	%ymm0, %ymm1, %ymm3
	vpandn	%ymm11, %ymm0, %ymm0
	vpxor	%ymm4, %ymm3, %ymm15
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm13, %ymm13
	vmovdqa	1120(%rsp), %ymm3
	vpxor	736(%rsp), %ymm3, %ymm3
	vpxor	%ymm15, %ymm8, %ymm12
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm13, %ymm3
	vpxor	992(%rsp), %ymm12, %ymm12
	vmovdqa	1088(%rsp), %ymm4
	vpxor	960(%rsp), %ymm0, %ymm11
	vpxor	608(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm9, 544(%rsp)
	vpsrlq	$63, %ymm14, %ymm4
	vpxor	%ymm1, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpsllq	$1, %ymm13, %ymm1
	vpxor	%ymm9, %ymm11, %ymm11
	vpor	%ymm1, %ymm3, %ymm3
	vpsllq	$1, %ymm12, %ymm9
	vpxor	%ymm11, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm1
	vpxor	%ymm10, %ymm3, %ymm3
	vpxor	%ymm4, %ymm5, %ymm5
	vpor	%ymm9, %ymm1, %ymm1
	vpxor	%ymm3, %ymm7, %ymm7
	vpxor	%ymm3, %ymm6, %ymm6
	vpxor	%ymm14, %ymm1, %ymm1
	vpsrlq	$63, %ymm11, %ymm14
	vpxor	1024(%rsp), %ymm1, %ymm9
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm1, %ymm2, %ymm2
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm8, %ymm8
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm7, %ymm13
	vpsllq	$44, %ymm7, %ymm7
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	864(%rsp), %ymm4, %ymm12
	vpor	%ymm7, %ymm13, %ymm7
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm7, %ymm13
	vpxor	128(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm8, %ymm13
	vmovdqa	%ymm14, 1024(%rsp)
	vpsllq	$21, %ymm8, %ymm8
	vpor	%ymm8, %ymm13, %ymm8
	vpandn	%ymm8, %ymm9, %ymm13
	vpxor	%ymm7, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 864(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm8, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 832(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm7, %ymm12, %ymm12
	vpxor	736(%rsp), %ymm11, %ymm7
	vpxor	%ymm8, %ymm9, %ymm9
	vpxor	1088(%rsp), %ymm10, %ymm8
	vmovdqa	%ymm9, 800(%rsp)
	vpxor	%ymm0, %ymm12, %ymm9
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpsrlq	$3, %ymm2, %ymm12
	vmovdqa	%ymm9, 768(%rsp)
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpsllq	$61, %ymm2, %ymm2
	vpor	%ymm8, %ymm7, %ymm7
	vpor	%ymm2, %ymm12, %ymm2
	vpxor	704(%rsp), %ymm4, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 1088(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm2, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 736(%rsp)
	vpandn	%ymm0, %ymm2, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm7
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	640(%rsp), %ymm3, %ymm2
	vmovdqa	%ymm6, 704(%rsp)
	vpxor	1152(%rsp), %ymm1, %ymm6
	vmovdqa	%ymm7, 672(%rsp)
	vpsrlq	$63, %ymm2, %ymm0
	vpsllq	$1, %ymm2, %ymm2
	vpor	%ymm2, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm2
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm2, %ymm2
	vpxor	992(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm2, %ymm6
	vpxor	%ymm0, %ymm6, %ymm13
	vpxor	544(%rsp), %ymm10, %ymm6
	vmovdqa	%ymm13, %ymm14
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm2, %ymm9, %ymm12
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm12, 1152(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm2, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm5
	vpxor	%ymm6, %ymm7, %ymm6
	vpxor	608(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm5, 640(%rsp)
	vmovdqa	%ymm6, 992(%rsp)
	vpsrlq	$37, %ymm0, %ymm2
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm2, %ymm2
	vpxor	1184(%rsp), %ymm4, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1056(%rsp), %ymm3, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, 1184(%rsp)
	vpxor	896(%rsp), %ymm1, %ymm0
	vpxor	576(%rsp), %ymm1, %ymm1
	vmovdqa	%ymm14, 608(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	%ymm11, %ymm15, %ymm0
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm5, %ymm6, %ymm6
	vpxor	%ymm7, %ymm13, %ymm15
	vpandn	%ymm2, %ymm0, %ymm7
	vpandn	%ymm5, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlq	$2, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vmovdqa	%ymm15, 576(%rsp)
	vmovdqa	%ymm2, 1056(%rsp)
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	1120(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm2
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpxor	960(%rsp), %ymm10, %ymm1
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpxor	1088(%rsp), %ymm14, %ymm1
	vpxor	1152(%rsp), %ymm6, %ymm14
	vpandn	%ymm11, %ymm2, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	1184(%rsp), %ymm5, %ymm10
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	928(%rsp), %ymm4, %ymm1
	vpxor	1024(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm4
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpandn	%ymm4, %ymm11, %ymm1
	vpxor	%ymm2, %ymm1, %ymm12
	vpxor	864(%rsp), %ymm8, %ymm1
	vmovdqa	%ymm12, 544(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	512(%rsp), %ymm3, %ymm1
	vpxor	%ymm12, %ymm14, %ymm14
	vpsrlq	$62, %ymm1, %ymm3
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm4, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vmovdqa	736(%rsp), %ymm11
	vpxor	832(%rsp), %ymm11, %ymm13
	vpxor	%ymm15, %ymm9, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm3, %ymm11
	vpandn	%ymm2, %ymm0, %ymm0
	vmovdqa	672(%rsp), %ymm2
	vpxor	%ymm4, %ymm11, %ymm4
	vpxor	%ymm3, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	704(%rsp), %ymm11
	vpxor	800(%rsp), %ymm11, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	768(%rsp), %ymm2, %ymm11
	vmovdqa	%ymm4, 512(%rsp)
	vpxor	640(%rsp), %ymm0, %ymm2
	vpxor	%ymm4, %ymm7, %ymm4
	vpxor	%ymm4, %ymm12, %ymm12
	vpsllq	$1, %ymm13, %ymm4
	vpxor	992(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpxor	1056(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1024(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	96(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 1120(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 1024(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 960(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	%ymm0, %ymm12, %ymm8
	vpsrlq	$3, %ymm1, %ymm12
	vpxor	%ymm7, %ymm9, %ymm9
	vmovdqa	%ymm9, 928(%rsp)
	vpsllq	$61, %ymm1, %ymm1
	vmovdqa	%ymm8, 896(%rsp)
	vpor	%ymm1, %ymm12, %ymm1
	vpxor	800(%rsp), %ymm11, %ymm7
	vpxor	672(%rsp), %ymm10, %ymm8
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	608(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, %ymm14
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 800(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm7
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	864(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 672(%rsp)
	vpxor	736(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm7, 608(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	992(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 992(%rsp)
	vpxor	1056(%rsp), %ymm10, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm15
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm15, 1056(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm6, %ymm7, %ymm6
	vmovdqa	%ymm0, 736(%rsp)
	vpxor	768(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm6, 864(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	1088(%rsp), %ymm3, %ymm0
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1152(%rsp), %ymm2, %ymm0
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm13
	vpxor	576(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm14, 576(%rsp)
	vmovdqa	%ymm13, 1152(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	512(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm7
	vmovdqa	%ymm7, %ymm15
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	832(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm0, 1088(%rsp)
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	704(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	640(%rsp), %ymm10, %ymm1
	vmovdqa	992(%rsp), %ymm10
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpxor	%ymm14, %ymm10, %ymm10
	vpxor	1024(%rsp), %ymm8, %ymm14
	vpor	%ymm1, %ymm11, %ymm11
	vpandn	%ymm11, %ymm4, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpxor	1152(%rsp), %ymm5, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	1184(%rsp), %ymm3, %ymm1
	vpxor	1120(%rsp), %ymm10, %ymm10
	vpsrlq	$23, %ymm1, %ymm3
	vpsllq	$41, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm3
	vpandn	%ymm3, %ymm11, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vmovdqa	%ymm1, %ymm12
	vpxor	1056(%rsp), %ymm6, %ymm1
	vmovdqa	%ymm12, 512(%rsp)
	vpxor	%ymm1, %ymm14, %ymm14
	vpxor	544(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm15, 544(%rsp)
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	800(%rsp), %ymm12
	vpxor	960(%rsp), %ymm12, %ymm13
	vpsrlq	$62, %ymm1, %ymm2
	vpsllq	$2, %ymm1, %ymm1
	vpor	%ymm1, %ymm2, %ymm2
	vpandn	%ymm2, %ymm3, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpxor	%ymm15, %ymm9, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm2, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm3, %ymm11, %ymm3
	vpxor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm13, %ymm13
	vmovdqa	608(%rsp), %ymm2
	vmovdqa	672(%rsp), %ymm11
	vpsllq	$1, %ymm13, %ymm4
	vpxor	928(%rsp), %ymm11, %ymm12
	vmovdqa	%ymm3, 480(%rsp)
	vpxor	896(%rsp), %ymm2, %ymm11
	vpxor	%ymm3, %ymm7, %ymm3
	vpxor	736(%rsp), %ymm0, %ymm2
	vpxor	%ymm3, %ymm12, %ymm12
	vpsrlq	$63, %ymm14, %ymm3
	vpxor	864(%rsp), %ymm12, %ymm12
	vpxor	%ymm2, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm2
	vpxor	1088(%rsp), %ymm11, %ymm11
	vpor	%ymm2, %ymm3, %ymm3
	vpsrlq	$63, %ymm13, %ymm2
	vpsllq	$1, %ymm12, %ymm15
	vpor	%ymm4, %ymm2, %ymm2
	vpxor	%ymm11, %ymm3, %ymm3
	vpsrlq	$63, %ymm12, %ymm4
	vpxor	%ymm10, %ymm2, %ymm2
	vpxor	%ymm3, %ymm5, %ymm5
	vpor	%ymm15, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm2, %ymm6, %ymm6
	vpxor	%ymm14, %ymm4, %ymm4
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm4, %ymm9, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm11, %ymm14, %ymm11
	vpxor	%ymm13, %ymm11, %ymm11
	vpsrlq	$63, %ymm10, %ymm13
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm11, %ymm7, %ymm7
	vpor	%ymm10, %ymm13, %ymm10
	vpsrlq	$20, %ymm8, %ymm13
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm12, %ymm10, %ymm10
	vpxor	1120(%rsp), %ymm3, %ymm12
	vpor	%ymm8, %ymm13, %ymm8
	vpsrlq	$21, %ymm9, %ymm13
	vpxor	%ymm10, %ymm0, %ymm0
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm13, %ymm9
	vpandn	%ymm9, %ymm8, %ymm13
	vpxor	64(%rsp), %ymm13, %ymm13
	vpxor	%ymm12, %ymm13, %ymm14
	vpsrlq	$43, %ymm7, %ymm13
	vmovdqa	%ymm14, 1184(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm13, %ymm7
	vpandn	%ymm7, %ymm9, %ymm13
	vpxor	%ymm8, %ymm13, %ymm14
	vpsrlq	$50, %ymm0, %ymm13
	vmovdqa	%ymm14, 1120(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm13, %ymm0
	vpandn	%ymm0, %ymm7, %ymm13
	vpxor	%ymm9, %ymm13, %ymm9
	vmovdqa	%ymm9, 832(%rsp)
	vpandn	%ymm12, %ymm0, %ymm9
	vpandn	%ymm8, %ymm12, %ymm12
	vpxor	608(%rsp), %ymm10, %ymm8
	vpxor	%ymm7, %ymm9, %ymm9
	vpxor	%ymm0, %ymm12, %ymm0
	vpxor	928(%rsp), %ymm11, %ymm7
	vmovdqa	%ymm0, 704(%rsp)
	vpsrlq	$3, %ymm1, %ymm12
	vpsllq	$61, %ymm1, %ymm1
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm1, %ymm12, %ymm1
	vmovdqa	%ymm9, 768(%rsp)
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpxor	992(%rsp), %ymm3, %ymm8
	vpsrlq	$61, %ymm8, %ymm9
	vpsllq	$3, %ymm8, %ymm8
	vpor	%ymm8, %ymm9, %ymm9
	vpandn	%ymm9, %ymm7, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 992(%rsp)
	vpsrlq	$19, %ymm6, %ymm8
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm8, %ymm6
	vpandn	%ymm1, %ymm6, %ymm12
	vpandn	%ymm6, %ymm9, %ymm8
	vpxor	%ymm9, %ymm12, %ymm9
	vpxor	%ymm7, %ymm8, %ymm8
	vmovdqa	%ymm9, 928(%rsp)
	vpandn	%ymm0, %ymm1, %ymm9
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm7
	vpxor	%ymm6, %ymm9, %ymm6
	vpxor	1024(%rsp), %ymm2, %ymm1
	vmovdqa	%ymm6, 640(%rsp)
	vpxor	800(%rsp), %ymm4, %ymm6
	vmovdqa	%ymm7, 608(%rsp)
	vpsrlq	$63, %ymm1, %ymm0
	vpsllq	$1, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm1
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm1, %ymm1
	vpxor	864(%rsp), %ymm11, %ymm6
	vpsrlq	$39, %ymm6, %ymm7
	vpsllq	$25, %ymm6, %ymm6
	vpor	%ymm6, %ymm7, %ymm7
	vpandn	%ymm7, %ymm1, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 1024(%rsp)
	vpxor	1088(%rsp), %ymm10, %ymm6
	vpshufb	.LC0(%rip), %ymm6, %ymm6
	vpandn	%ymm6, %ymm7, %ymm9
	vpxor	%ymm1, %ymm9, %ymm12
	vpsrlq	$46, %ymm5, %ymm9
	vmovdqa	%ymm12, 1088(%rsp)
	vpsllq	$18, %ymm5, %ymm5
	vpor	%ymm5, %ymm9, %ymm5
	vpandn	%ymm5, %ymm6, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpandn	%ymm0, %ymm5, %ymm7
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm1
	vpxor	%ymm6, %ymm7, %ymm7
	vpxor	896(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm1, 800(%rsp)
	vmovdqa	%ymm7, 864(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	576(%rsp), %ymm3, %ymm0
	vpxor	1152(%rsp), %ymm3, %ymm3
	vpsrlq	$28, %ymm0, %ymm5
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm5, %ymm5
	vpxor	1056(%rsp), %ymm2, %ymm0
	vpxor	512(%rsp), %ymm2, %ymm2
	vpsrlq	$54, %ymm0, %ymm7
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm7
	vpandn	%ymm7, %ymm5, %ymm0
	vpxor	%ymm1, %ymm0, %ymm14
	vpxor	544(%rsp), %ymm4, %ymm0
	vmovdqa	%ymm14, 448(%rsp)
	vpsrlq	$49, %ymm0, %ymm12
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm12
	vpxor	480(%rsp), %ymm11, %ymm0
	vpandn	%ymm12, %ymm7, %ymm6
	vpshufb	.LC1(%rip), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm6
	vpandn	%ymm0, %ymm12, %ymm13
	vpxor	%ymm7, %ymm13, %ymm7
	vmovdqa	1024(%rsp), %ymm13
	vmovdqa	%ymm7, 1056(%rsp)
	vpandn	%ymm1, %ymm0, %ymm7
	vpandn	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm12, %ymm7, %ymm7
	vpxor	960(%rsp), %ymm4, %ymm1
	vmovdqa	%ymm0, %ymm15
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpxor	672(%rsp), %ymm11, %ymm1
	vpsrlq	$9, %ymm1, %ymm4
	vpsllq	$55, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	736(%rsp), %ymm10, %ymm1
	vpxor	992(%rsp), %ymm13, %ymm10
	vpsrlq	$25, %ymm1, %ymm11
	vpsllq	$39, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpandn	%ymm11, %ymm4, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpxor	%ymm14, %ymm1, %ymm5
	vpxor	1120(%rsp), %ymm8, %ymm14
	vpxor	%ymm5, %ymm10, %ymm10
	vpsrlq	$23, %ymm3, %ymm5
	vpxor	1184(%rsp), %ymm10, %ymm10
	vpsllq	$41, %ymm3, %ymm3
	vpor	%ymm3, %ymm5, %ymm5
	vpandn	%ymm5, %ymm11, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vmovdqa	%ymm3, %ymm12
	vpxor	1088(%rsp), %ymm6, %ymm3
	vmovdqa	%ymm12, 416(%rsp)
	vpxor	%ymm3, %ymm14, %ymm14
	vpsrlq	$62, %ymm2, %ymm3
	vpsllq	$2, %ymm2, %ymm2
	vpxor	%ymm12, %ymm14, %ymm14
	vmovdqa	640(%rsp), %ymm12
	vpxor	768(%rsp), %ymm12, %ymm12
	vpor	%ymm2, %ymm3, %ymm3
	vpandn	%ymm3, %ymm5, %ymm2
	vpxor	%ymm11, %ymm2, %ymm2
	vmovdqa	928(%rsp), %ymm11
	vpxor	832(%rsp), %ymm11, %ymm13
	vpxor	1056(%rsp), %ymm9, %ymm11
	vpxor	%ymm11, %ymm13, %ymm13
	vpandn	%ymm0, %ymm3, %ymm11
	vpandn	%ymm4, %ymm0, %ymm0
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm3, %ymm0, %ymm0
	vpxor	%ymm2, %ymm13, %ymm13
	vmovdqa	608(%rsp), %ymm3
	vpxor	%ymm11, %ymm7, %ymm5
	vpsrlq	$63, %ymm14, %ymm4
	vmovdqa	%ymm11, 512(%rsp)
	vpxor	%ymm5, %ymm12, %ymm12
	vpsllq	$1, %ymm13, %ymm5
	vpxor	864(%rsp), %ymm12, %ymm12
	vpxor	704(%rsp), %ymm3, %ymm11
	vpxor	800(%rsp), %ymm0, %ymm3
	vmovdqa	%ymm15, 1152(%rsp)
	vpxor	%ymm3, %ymm11, %ymm11
	vpsllq	$1, %ymm14, %ymm3
	vpor	%ymm3, %ymm4, %ymm4
	vpsrlq	$63, %ymm13, %ymm3
	vpxor	%ymm15, %ymm11, %ymm11
	vpor	%ymm5, %ymm3, %ymm3
	vpsllq	$1, %ymm12, %ymm15
	vpxor	%ymm11, %ymm4, %ymm4
	vpsrlq	$63, %ymm12, %ymm5
	vpxor	%ymm10, %ymm3, %ymm3
	vpxor	%ymm4, %ymm1, %ymm1
	vpor	%ymm15, %ymm5, %ymm5
	vpxor	%ymm3, %ymm8, %ymm8
	vpxor	%ymm3, %ymm6, %ymm6
	vpxor	%ymm14, %ymm5, %ymm5
	vpsrlq	$63, %ymm11, %ymm14
	vpsllq	$1, %ymm11, %ymm11
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm5, %ymm2, %ymm2
	vpor	%ymm11, %ymm14, %ymm14
	vpsrlq	$63, %ymm10, %ymm11
	vpsllq	$1, %ymm10, %ymm10
	vpxor	%ymm13, %ymm14, %ymm14
	vpor	%ymm10, %ymm11, %ymm10
	vpxor	%ymm14, %ymm7, %ymm7
	vpxor	1184(%rsp), %ymm4, %ymm11
	vpxor	%ymm12, %ymm10, %ymm10
	vpsrlq	$20, %ymm8, %ymm12
	vpsllq	$44, %ymm8, %ymm8
	vpxor	%ymm10, %ymm0, %ymm0
	vpor	%ymm8, %ymm12, %ymm8
	vpsrlq	$21, %ymm9, %ymm12
	vpsllq	$43, %ymm9, %ymm9
	vpor	%ymm9, %ymm12, %ymm9
	vpandn	%ymm9, %ymm8, %ymm12
	vpxor	32(%rsp), %ymm12, %ymm12
	vpxor	%ymm11, %ymm12, %ymm15
	vpsrlq	$43, %ymm7, %ymm12
	vmovdqa	%ymm15, 576(%rsp)
	vpsllq	$21, %ymm7, %ymm7
	vpor	%ymm7, %ymm12, %ymm7
	vpandn	%ymm7, %ymm9, %ymm12
	vpxor	%ymm8, %ymm12, %ymm15
	vpsrlq	$50, %ymm0, %ymm12
	vmovdqa	%ymm15, 960(%rsp)
	vpsllq	$14, %ymm0, %ymm0
	vpor	%ymm0, %ymm12, %ymm0
	vpandn	%ymm0, %ymm7, %ymm12
	vpxor	%ymm9, %ymm12, %ymm12
	vpandn	%ymm11, %ymm0, %ymm9
	vpandn	%ymm8, %ymm11, %ymm11
	vpxor	%ymm7, %ymm9, %ymm15
	vpxor	%ymm0, %ymm11, %ymm11
	vpxor	768(%rsp), %ymm14, %ymm7
	vpxor	608(%rsp), %ymm10, %ymm8
	vpxor	1024(%rsp), %ymm4, %ymm9
	vmovdqa	%ymm15, 896(%rsp)
	vpsrlq	$36, %ymm7, %ymm0
	vpsllq	$28, %ymm7, %ymm7
	vpor	%ymm7, %ymm0, %ymm0
	vpsrlq	$44, %ymm8, %ymm7
	vpsllq	$20, %ymm8, %ymm8
	vpor	%ymm8, %ymm7, %ymm7
	vpsrlq	$61, %ymm9, %ymm8
	vpsllq	$3, %ymm9, %ymm9
	vpor	%ymm9, %ymm8, %ymm8
	vpandn	%ymm8, %ymm7, %ymm9
	vpxor	%ymm0, %ymm9, %ymm15
	vpsrlq	$19, %ymm6, %ymm9
	vmovdqa	%ymm15, 1024(%rsp)
	vpsllq	$45, %ymm6, %ymm6
	vpor	%ymm6, %ymm9, %ymm6
	vpandn	%ymm6, %ymm8, %ymm9
	vpxor	%ymm7, %ymm9, %ymm15
	vpsrlq	$3, %ymm2, %ymm9
	vmovdqa	%ymm15, 768(%rsp)
	vpsllq	$61, %ymm2, %ymm2
	vpor	%ymm2, %ymm9, %ymm2
	vpandn	%ymm2, %ymm6, %ymm15
	vpxor	%ymm8, %ymm15, %ymm15
	vpandn	%ymm0, %ymm2, %ymm8
	vpandn	%ymm7, %ymm0, %ymm0
	vpxor	864(%rsp), %ymm14, %ymm7
	vpxor	%ymm6, %ymm8, %ymm13
	vpxor	928(%rsp), %ymm5, %ymm6
	vmovdqa	%ymm13, 736(%rsp)
	vpxor	%ymm2, %ymm0, %ymm13
	vpxor	1120(%rsp), %ymm3, %ymm2
	vmovdqa	%ymm13, 672(%rsp)
	vpsrlq	$63, %ymm2, %ymm0
	vpsllq	$1, %ymm2, %ymm2
	vpor	%ymm2, %ymm0, %ymm0
	vpsrlq	$58, %ymm6, %ymm2
	vpsllq	$6, %ymm6, %ymm6
	vpor	%ymm6, %ymm2, %ymm2
	vpsrlq	$39, %ymm7, %ymm6
	vpsllq	$25, %ymm7, %ymm7
	vpor	%ymm7, %ymm6, %ymm6
	vpxor	1152(%rsp), %ymm10, %ymm7
	vpandn	%ymm6, %ymm2, %ymm13
	vpshufb	.LC0(%rip), %ymm7, %ymm7
	vpxor	%ymm0, %ymm13, %ymm13
	vpandn	%ymm7, %ymm6, %ymm8
	vpxor	%ymm2, %ymm8, %ymm9
	vpsrlq	$46, %ymm1, %ymm8
	vpsllq	$18, %ymm1, %ymm1
	vpor	%ymm1, %ymm8, %ymm1
	vpandn	%ymm1, %ymm7, %ymm8
	vpxor	%ymm6, %ymm8, %ymm6
	vmovdqa	%ymm6, 928(%rsp)
	vpandn	%ymm0, %ymm1, %ymm6
	vpandn	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	704(%rsp), %ymm10, %ymm0
	vmovdqa	%ymm1, 544(%rsp)
	vmovdqa	%ymm6, 864(%rsp)
	vpsrlq	$37, %ymm0, %ymm1
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm0, %ymm1, %ymm1
	vpxor	992(%rsp), %ymm4, %ymm0
	vpsrlq	$28, %ymm0, %ymm2
	vpsllq	$36, %ymm0, %ymm0
	vpor	%ymm0, %ymm2, %ymm2
	vpxor	1088(%rsp), %ymm3, %ymm0
	vpsrlq	$54, %ymm0, %ymm6
	vpsllq	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpandn	%ymm6, %ymm2, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 704(%rsp)
	vpxor	1056(%rsp), %ymm5, %ymm0
	vpsrlq	$49, %ymm0, %ymm7
	vpsllq	$15, %ymm0, %ymm0
	vpor	%ymm0, %ymm7, %ymm0
	vpandn	%ymm0, %ymm6, %ymm7
	vpxor	%ymm2, %ymm7, %ymm8
	vpxor	512(%rsp), %ymm14, %ymm7
	vmovdqa	%ymm8, 1056(%rsp)
	vpshufb	.LC1(%rip), %ymm7, %ymm7
	vpandn	%ymm7, %ymm0, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpandn	%ymm1, %ymm7, %ymm6
	vpandn	%ymm2, %ymm1, %ymm1
	vpxor	%ymm0, %ymm6, %ymm0
	vpxor	%ymm7, %ymm1, %ymm7
	vmovdqa	%ymm0, 512(%rsp)
	vmovdqa	%ymm7, 480(%rsp)
	vpxor	832(%rsp), %ymm5, %ymm1
	vpxor	640(%rsp), %ymm14, %ymm2
	vpxor	448(%rsp), %ymm4, %ymm4
	vpxor	416(%rsp), %ymm3, %ymm3
	vpsrlq	$2, %ymm1, %ymm0
	vpsllq	$62, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vpsrlq	$9, %ymm2, %ymm1
	vpsllq	$55, %ymm2, %ymm2
	vpsrlq	$23, %ymm4, %ymm6
	vpor	%ymm2, %ymm1, %ymm1
	vpsllq	$41, %ymm4, %ymm4
	vpxor	800(%rsp), %ymm10, %ymm2
	vpor	%ymm4, %ymm6, %ymm4
	vpsrlq	$25, %ymm2, %ymm5
	vpsllq	$39, %ymm2, %ymm2
	vpor	%ymm2, %ymm5, %ymm5
	vpandn	%ymm4, %ymm5, %ymm6
	vpandn	%ymm5, %ymm1, %ymm2
	vpxor	%ymm1, %ymm6, %ymm6
	vpxor	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm6, 1184(%rsp)
	vpsrlq	$62, %ymm3, %ymm6
	vpsllq	$2, %ymm3, %ymm3
	vpor	%ymm3, %ymm6, %ymm3
	vpandn	%ymm3, %ymm4, %ymm6
	vpxor	%ymm5, %ymm6, %ymm5
	vmovdqa	%ymm5, 1152(%rsp)
	vpandn	%ymm0, %ymm3, %ymm5
	vpandn	%ymm1, %ymm0, %ymm0
	vpxor	%ymm4, %ymm5, %ymm4
	vmovdqa	%ymm4, 1120(%rsp)
	vpxor	%ymm3, %ymm0, %ymm4
	vmovdqa	%ymm4, 1088(%rsp)
	cmpq	%r8, %r12
	jnb	.L446
	vmovdqa	%ymm11, %ymm3
	vmovdqa	%ymm9, %ymm5
	vmovdqa	%ymm8, %ymm6
	vmovdqa	576(%rsp), %ymm14
	subq	24(%rsp), %rax
.L445:
	vmovdqa	960(%rsp), %ymm4
	vmovdqa	%ymm14, (%r14)
	vmovdqa	%ymm12, 64(%r14)
	vmovdqa	%ymm4, 32(%r14)
	vmovdqa	896(%rsp), %ymm4
	vmovdqa	%ymm3, 128(%r14)
	vmovdqa	%ymm4, 96(%r14)
	vmovdqa	1024(%rsp), %ymm4
	vmovdqa	%ymm15, 224(%r14)
	vmovdqa	%ymm4, 160(%r14)
	vmovdqa	768(%rsp), %ymm4
	vmovdqa	%ymm13, 320(%r14)
	vmovdqa	%ymm4, 192(%r14)
	vmovdqa	736(%rsp), %ymm4
	vmovdqa	%ymm5, 352(%r14)
	vmovdqa	%ymm4, 256(%r14)
	vmovdqa	672(%rsp), %ymm4
	vmovdqa	%ymm6, 544(%r14)
	vmovdqa	%ymm4, 288(%r14)
	vmovdqa	928(%rsp), %ymm4
	vmovdqa	%ymm4, 384(%r14)
	vmovdqa	864(%rsp), %ymm4
	vmovdqa	%ymm4, 416(%r14)
	vmovdqa	544(%rsp), %ymm4
	vmovdqa	%ymm4, 448(%r14)
	vmovdqa	704(%rsp), %ymm4
	vmovdqa	%ymm4, 480(%r14)
	vmovdqa	1056(%rsp), %ymm4
	vmovdqa	%ymm4, 512(%r14)
	vmovdqa	512(%rsp), %ymm4
	vmovdqa	%ymm4, 576(%r14)
	vmovdqa	480(%rsp), %ymm4
	vmovdqa	%ymm4, 608(%r14)
	vmovdqa	1184(%rsp), %ymm4
	vmovdqa	%ymm2, 640(%r14)
	vmovdqa	%ymm4, 672(%r14)
	vmovdqa	1152(%rsp), %ymm4
	vmovdqa	%ymm4, 704(%r14)
	vmovdqa	1120(%rsp), %ymm4
	vmovdqa	%ymm4, 736(%r14)
	vmovdqa	1088(%rsp), %ymm4
	vmovdqa	%ymm4, 768(%r14)
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
.L449:
	xorl	%eax, %eax
	jmp	.L445
	.size	ossl_keccak1600x4_avx2_KeccakP1600times4_12rounds_FastLoop_Absorb, .-ossl_keccak1600x4_avx2_KeccakP1600times4_12rounds_FastLoop_Absorb
	.p2align 4
	.globl	SHA3_shake128_x4_inc_absorb_avx2
	.type	SHA3_shake128_x4_inc_absorb_avx2, @function
SHA3_shake128_x4_inc_absorb_avx2:
	endbr64
	pushq	%rbp
	vmovq	%rcx, %xmm6
	vmovq	%rsi, %xmm7
	vpinsrq	$1, %r8, %xmm6, %xmm0
	vpinsrq	$1, %rdx, %xmm7, %xmm1
	vinserti128	$0x1, %xmm0, %ymm1, %ymm5
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	movq	%rdi, %r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	addq	$-128, %rsp
	movq	%r9, 48(%rsp)
	movq	%fs:40, %rax
	movq	%rax, 120(%rsp)
	xorl	%eax, %eax
	movq	800(%rdi), %rax
	vmovdqa	%ymm5, (%rsp)
	vmovdqa	%ymm5, 64(%rsp)
	movq	%rax, 56(%rsp)
	testq	%r9, %r9
	je	.L470
	leaq	64(%rsp), %r15
	.p2align 4,,10
	.p2align 3
.L460:
	movq	56(%rsp), %rdi
	movq	48(%rsp), %rcx
	movl	$168, %eax
	subq	%rdi, %rax
	movl	%edi, %r13d
	cmpq	%rcx, %rax
	cmova	%rcx, %rax
	xorl	%ebx, %ebx
	vmovq	%rax, %xmm1
	movl	%eax, %r12d
	movq	%rax, 40(%rsp)
	vpbroadcastq	%xmm1, %ymm0
	vpaddq	(%rsp), %ymm0, %ymm2
	vmovdqa	%ymm2, (%rsp)
	vzeroupper
.L457:
	movq	(%r15,%rbx,8), %rdx
	movl	%ebx, %esi
	movl	%r12d, %r8d
	movl	%r13d, %ecx
	movq	%r14, %rdi
	addq	$1, %rbx
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_AddBytes@PLT
	cmpq	$4, %rbx
	jne	.L457
	movq	40(%rsp), %rdi
	vmovdqa	(%rsp), %ymm4
	addq	%rdi, 56(%rsp)
	movq	56(%rsp), %rax
	subq	%rdi, 48(%rsp)
	vmovdqa	%ymm4, 64(%rsp)
	cmpq	$168, %rax
	je	.L473
	cmpq	$0, 48(%rsp)
	jne	.L460
.L470:
	vzeroupper
.L456:
	movq	%rax, 800(%r14)
	movq	120(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L474
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L473:
	movq	%r14, %rdi
	vzeroupper
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds@PLT
	cmpq	$0, 48(%rsp)
	movq	$0, 56(%rsp)
	jne	.L460
	movq	56(%rsp), %rax
	jmp	.L456
.L474:
	call	__stack_chk_fail@PLT
	.size	SHA3_shake128_x4_inc_absorb_avx2, .-SHA3_shake128_x4_inc_absorb_avx2
	.p2align 4
	.globl	SHA3_shake256_x4_inc_absorb_avx2
	.type	SHA3_shake256_x4_inc_absorb_avx2, @function
SHA3_shake256_x4_inc_absorb_avx2:
	endbr64
	pushq	%rbp
	vmovq	%rcx, %xmm6
	vmovq	%rsi, %xmm7
	vpinsrq	$1, %r8, %xmm6, %xmm0
	vpinsrq	$1, %rdx, %xmm7, %xmm1
	vinserti128	$0x1, %xmm0, %ymm1, %ymm5
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	movq	%rdi, %r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	addq	$-128, %rsp
	movq	%r9, 48(%rsp)
	movq	%fs:40, %rax
	movq	%rax, 120(%rsp)
	xorl	%eax, %eax
	movq	800(%rdi), %rax
	vmovdqa	%ymm5, (%rsp)
	vmovdqa	%ymm5, 64(%rsp)
	movq	%rax, 56(%rsp)
	testq	%r9, %r9
	je	.L490
	leaq	64(%rsp), %r15
	.p2align 4,,10
	.p2align 3
.L480:
	movq	56(%rsp), %rdi
	movq	48(%rsp), %rcx
	movl	$136, %eax
	subq	%rdi, %rax
	movl	%edi, %r13d
	cmpq	%rcx, %rax
	cmova	%rcx, %rax
	xorl	%ebx, %ebx
	vmovq	%rax, %xmm1
	movl	%eax, %r12d
	movq	%rax, 40(%rsp)
	vpbroadcastq	%xmm1, %ymm0
	vpaddq	(%rsp), %ymm0, %ymm2
	vmovdqa	%ymm2, (%rsp)
	vzeroupper
.L477:
	movq	(%r15,%rbx,8), %rdx
	movl	%ebx, %esi
	movl	%r12d, %r8d
	movl	%r13d, %ecx
	movq	%r14, %rdi
	addq	$1, %rbx
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_AddBytes@PLT
	cmpq	$4, %rbx
	jne	.L477
	movq	40(%rsp), %rdi
	vmovdqa	(%rsp), %ymm4
	addq	%rdi, 56(%rsp)
	movq	56(%rsp), %rax
	subq	%rdi, 48(%rsp)
	vmovdqa	%ymm4, 64(%rsp)
	cmpq	$136, %rax
	je	.L493
	cmpq	$0, 48(%rsp)
	jne	.L480
.L490:
	vzeroupper
.L476:
	movq	%rax, 800(%r14)
	movq	120(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L494
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L493:
	movq	%r14, %rdi
	vzeroupper
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds@PLT
	cmpq	$0, 48(%rsp)
	movq	$0, 56(%rsp)
	jne	.L480
	movq	56(%rsp), %rax
	jmp	.L476
.L494:
	call	__stack_chk_fail@PLT
	.size	SHA3_shake256_x4_inc_absorb_avx2, .-SHA3_shake256_x4_inc_absorb_avx2
	.p2align 4
	.globl	SHA3_shake128_x4_inc_finalize_avx2
	.type	SHA3_shake128_x4_inc_finalize_avx2, @function
SHA3_shake128_x4_inc_finalize_avx2:
	endbr64
	movq	800(%rdi), %rax
	movl	%eax, %edx
	andl	$7, %eax
	shrl	$3, %edx
	movl	%edx, %ecx
	leal	1(,%rdx,4), %edx
	sall	$5, %ecx
	sall	$3, %edx
	addl	%eax, %ecx
	movl	%ecx, %ecx
	xorb	$31, (%rdi,%rcx)
	leal	(%rax,%rdx), %ecx
	addb	$-128, 647(%rdi)
	xorb	$31, (%rdi,%rcx)
	leal	8(%rax,%rdx), %ecx
	leal	16(%rax,%rdx), %eax
	addb	$-128, 655(%rdi)
	xorb	$31, (%rdi,%rcx)
	addb	$-128, 663(%rdi)
	xorb	$31, (%rdi,%rax)
	movq	$0, 800(%rdi)
	addb	$-128, 671(%rdi)
	ret
	.size	SHA3_shake128_x4_inc_finalize_avx2, .-SHA3_shake128_x4_inc_finalize_avx2
	.p2align 4
	.globl	SHA3_shake256_x4_inc_finalize_avx2
	.type	SHA3_shake256_x4_inc_finalize_avx2, @function
SHA3_shake256_x4_inc_finalize_avx2:
	endbr64
	movq	800(%rdi), %rax
	movl	%eax, %edx
	andl	$7, %eax
	shrl	$3, %edx
	movl	%edx, %ecx
	leal	1(,%rdx,4), %edx
	sall	$5, %ecx
	sall	$3, %edx
	addl	%eax, %ecx
	movl	%ecx, %ecx
	xorb	$31, (%rdi,%rcx)
	leal	(%rax,%rdx), %ecx
	addb	$-128, 519(%rdi)
	xorb	$31, (%rdi,%rcx)
	leal	8(%rax,%rdx), %ecx
	leal	16(%rax,%rdx), %eax
	addb	$-128, 527(%rdi)
	xorb	$31, (%rdi,%rcx)
	addb	$-128, 535(%rdi)
	xorb	$31, (%rdi,%rax)
	movq	$0, 800(%rdi)
	addb	$-128, 543(%rdi)
	ret
	.size	SHA3_shake256_x4_inc_finalize_avx2, .-SHA3_shake256_x4_inc_finalize_avx2
	.p2align 4
	.globl	SHA3_shake128_x4_inc_squeeze_avx2
	.type	SHA3_shake128_x4_inc_squeeze_avx2, @function
SHA3_shake128_x4_inc_squeeze_avx2:
	endbr64
	pushq	%rbp
	vmovq	%rdx, %xmm6
	vmovq	%rdi, %xmm7
	vpinsrq	$1, %rcx, %xmm6, %xmm0
	vpinsrq	$1, %rsi, %xmm7, %xmm1
	vinserti128	$0x1, %xmm0, %ymm1, %ymm5
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	movq	%r9, %r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	addq	$-128, %rsp
	movq	%r8, 48(%rsp)
	movq	%fs:40, %rax
	movq	%rax, 120(%rsp)
	xorl	%eax, %eax
	movq	800(%r9), %rax
	vmovdqa	%ymm5, (%rsp)
	vmovdqa	%ymm5, 64(%rsp)
	movq	%rax, 56(%rsp)
	testq	%r8, %r8
	je	.L498
	leaq	64(%rsp), %r15
	.p2align 4,,10
	.p2align 3
.L502:
	movq	56(%rsp), %rax
	testq	%rax, %rax
	je	.L499
	movl	$168, %ebx
	subl	%eax, %ebx
.L500:
	movq	56(%rsp), %rcx
	movq	48(%rsp), %rax
	cmpq	%rax, %rcx
	cmovbe	%rcx, %rax
	xorl	%r13d, %r13d
	vmovq	%rax, %xmm1
	movl	%eax, %r12d
	movq	%rax, 40(%rsp)
	vpbroadcastq	%xmm1, %ymm0
	vpaddq	(%rsp), %ymm0, %ymm2
	vmovdqa	%ymm2, (%rsp)
	vzeroupper
.L501:
	movq	(%r15,%r13,8), %rdx
	movl	%r13d, %esi
	movl	%r12d, %r8d
	movl	%ebx, %ecx
	movq	%r14, %rdi
	addq	$1, %r13
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractBytes@PLT
	cmpq	$4, %r13
	jne	.L501
	movq	40(%rsp), %rdi
	subq	%rdi, 56(%rsp)
	subq	%rdi, 48(%rsp)
	vmovdqa	(%rsp), %ymm4
	vmovdqa	%ymm4, 64(%rsp)
	jne	.L502
.L498:
	movq	56(%rsp), %rax
	movq	%rax, 800(%r14)
	movq	120(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L511
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L499:
	movq	%r14, %rdi
	vzeroupper
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds@PLT
	xorl	%ebx, %ebx
	movq	$168, 56(%rsp)
	jmp	.L500
.L511:
	vzeroupper
	call	__stack_chk_fail@PLT
	.size	SHA3_shake128_x4_inc_squeeze_avx2, .-SHA3_shake128_x4_inc_squeeze_avx2
	.p2align 4
	.globl	SHA3_shake256_x4_inc_squeeze_avx2
	.type	SHA3_shake256_x4_inc_squeeze_avx2, @function
SHA3_shake256_x4_inc_squeeze_avx2:
	endbr64
	pushq	%rbp
	vmovq	%rdx, %xmm6
	vmovq	%rdi, %xmm7
	vpinsrq	$1, %rcx, %xmm6, %xmm0
	vpinsrq	$1, %rsi, %xmm7, %xmm1
	vinserti128	$0x1, %xmm0, %ymm1, %ymm5
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	movq	%r9, %r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	addq	$-128, %rsp
	movq	%r8, 48(%rsp)
	movq	%fs:40, %rax
	movq	%rax, 120(%rsp)
	xorl	%eax, %eax
	movq	800(%r9), %rax
	vmovdqa	%ymm5, (%rsp)
	vmovdqa	%ymm5, 64(%rsp)
	movq	%rax, 56(%rsp)
	testq	%r8, %r8
	je	.L513
	leaq	64(%rsp), %r15
	.p2align 4,,10
	.p2align 3
.L517:
	movq	56(%rsp), %rax
	testq	%rax, %rax
	je	.L514
	movl	$136, %ebx
	subl	%eax, %ebx
.L515:
	movq	56(%rsp), %rcx
	movq	48(%rsp), %rax
	cmpq	%rax, %rcx
	cmovbe	%rcx, %rax
	xorl	%r13d, %r13d
	vmovq	%rax, %xmm1
	movl	%eax, %r12d
	movq	%rax, 40(%rsp)
	vpbroadcastq	%xmm1, %ymm0
	vpaddq	(%rsp), %ymm0, %ymm2
	vmovdqa	%ymm2, (%rsp)
	vzeroupper
.L516:
	movq	(%r15,%r13,8), %rdx
	movl	%r13d, %esi
	movl	%r12d, %r8d
	movl	%ebx, %ecx
	movq	%r14, %rdi
	addq	$1, %r13
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_ExtractBytes@PLT
	cmpq	$4, %r13
	jne	.L516
	movq	40(%rsp), %rdi
	subq	%rdi, 56(%rsp)
	subq	%rdi, 48(%rsp)
	vmovdqa	(%rsp), %ymm4
	vmovdqa	%ymm4, 64(%rsp)
	jne	.L517
.L513:
	movq	56(%rsp), %rax
	movq	%rax, 800(%r14)
	movq	120(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L526
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L514:
	movq	%r14, %rdi
	vzeroupper
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_PermuteAll_24rounds@PLT
	xorl	%ebx, %ebx
	movq	$136, 56(%rsp)
	jmp	.L515
.L526:
	vzeroupper
	call	__stack_chk_fail@PLT
	.size	SHA3_shake256_x4_inc_squeeze_avx2, .-SHA3_shake256_x4_inc_squeeze_avx2
	.p2align 4
	.globl	SHA3_shake128_x4_avx2
	.type	SHA3_shake128_x4_avx2, @function
SHA3_shake128_x4_avx2:
	endbr64
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	movq	%rcx, %r15
	pushq	%r14
	movq	%rdx, %r14
	pushq	%r13
	movq	%rsi, %r13
	pushq	%r12
	movq	%rdi, %r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$896, %rsp
	movq	16(%rbp), %rdx
	movq	24(%rbp), %rcx
	movq	%r8, 24(%rsp)
	movq	32(%rbp), %r8
	leaq	64(%rsp), %rbx
	movq	%r9, 32(%rsp)
	movq	%rdx, 40(%rsp)
	movq	%rcx, 48(%rsp)
	movq	%r8, 56(%rsp)
	movq	%fs:40, %rdi
	movq	%rdi, 888(%rsp)
	xorl	%edi, %edi
	movq	%rbx, %rdi
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_InitializeAll@PLT
	movq	40(%rbp), %r9
	movq	56(%rsp), %r8
	movq	%rbx, %rdi
	movq	48(%rsp), %rcx
	movq	40(%rsp), %rdx
	movq	$0, 864(%rsp)
	movq	32(%rsp), %rsi
	call	SHA3_shake128_x4_inc_absorb_avx2@PLT
	movq	%rbx, %rdi
	call	SHA3_shake128_x4_inc_finalize_avx2@PLT
	movq	24(%rsp), %r8
	movq	%rbx, %r9
	movq	%r15, %rcx
	movq	%r14, %rdx
	movq	%r13, %rsi
	movq	%r12, %rdi
	call	SHA3_shake128_x4_inc_squeeze_avx2@PLT
	movq	888(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L531
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
.L531:
	call	__stack_chk_fail@PLT
	.size	SHA3_shake128_x4_avx2, .-SHA3_shake128_x4_avx2
	.p2align 4
	.globl	SHA3_shake256_x4_avx2
	.type	SHA3_shake256_x4_avx2, @function
SHA3_shake256_x4_avx2:
	endbr64
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	movq	%rcx, %r15
	pushq	%r14
	movq	%rdx, %r14
	pushq	%r13
	movq	%rsi, %r13
	pushq	%r12
	movq	%rdi, %r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$896, %rsp
	movq	16(%rbp), %rdx
	movq	24(%rbp), %rcx
	movq	%r8, 24(%rsp)
	movq	32(%rbp), %r8
	leaq	64(%rsp), %rbx
	movq	%r9, 32(%rsp)
	movq	%rdx, 40(%rsp)
	movq	%rcx, 48(%rsp)
	movq	%r8, 56(%rsp)
	movq	%fs:40, %rdi
	movq	%rdi, 888(%rsp)
	xorl	%edi, %edi
	movq	%rbx, %rdi
	call	ossl_keccak1600x4_avx2_KeccakP1600times4_InitializeAll@PLT
	movq	40(%rbp), %r9
	movq	56(%rsp), %r8
	movq	%rbx, %rdi
	movq	48(%rsp), %rcx
	movq	40(%rsp), %rdx
	movq	$0, 864(%rsp)
	movq	32(%rsp), %rsi
	call	SHA3_shake256_x4_inc_absorb_avx2@PLT
	movq	%rbx, %rdi
	call	SHA3_shake256_x4_inc_finalize_avx2@PLT
	movq	24(%rsp), %r8
	movq	%rbx, %r9
	movq	%r15, %rcx
	movq	%r14, %rdx
	movq	%r13, %rsi
	movq	%r12, %rdi
	call	SHA3_shake256_x4_inc_squeeze_avx2@PLT
	movq	888(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L536
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
.L536:
	call	__stack_chk_fail@PLT
	.size	SHA3_shake256_x4_avx2, .-SHA3_shake256_x4_avx2
	.section	.rodata
	.align 32
	.type	KeccakF1600RoundConstants, @object
	.size	KeccakF1600RoundConstants, 192
KeccakF1600RoundConstants:
	.quad	1
	.quad	32898
	.quad	-9223372036854742902
	.quad	-9223372034707259392
	.quad	32907
	.quad	2147483649
	.quad	-9223372034707259263
	.quad	-9223372036854743031
	.quad	138
	.quad	136
	.quad	2147516425
	.quad	2147483658
	.quad	2147516555
	.quad	-9223372036854775669
	.quad	-9223372036854742903
	.quad	-9223372036854743037
	.quad	-9223372036854743038
	.quad	-9223372036854775680
	.quad	32778
	.quad	-9223372034707292150
	.quad	-9223372034707259263
	.quad	-9223372036854742912
	.quad	2147483649
	.quad	-9223372034707259384
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC0:
	.byte	7
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	15
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	23
	.byte	16
	.byte	17
	.byte	18
	.byte	19
	.byte	20
	.byte	21
	.byte	22
	.byte	31
	.byte	24
	.byte	25
	.byte	26
	.byte	27
	.byte	28
	.byte	29
	.byte	30
	.align 32
.LC1:
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	0
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	8
	.byte	17
	.byte	18
	.byte	19
	.byte	20
	.byte	21
	.byte	22
	.byte	23
	.byte	16
	.byte	25
	.byte	26
	.byte	27
	.byte	28
	.byte	29
	.byte	30
	.byte	31
	.byte	24
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
	.section ".note.gnu.property", "a"
	.p2align 3
	.long 1f - 0f
	.long 4f - 1f
	.long 5
0:
	.byte 0x47
	.byte 0x4e
	.byte 0x55
	.byte 0
1:
	.p2align 3
	.long 0xc0000002
	.long 3f - 2f
2:
	.long 3
3:
	.p2align 3
4:
