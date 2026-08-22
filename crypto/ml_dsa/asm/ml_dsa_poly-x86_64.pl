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
# ML-DSA AVX2 polynomial compression / hint routines
#
# Implemented:
#   power2_round_avx
#   decompose_avx
#   high_bits_avx
#   low_bits_avx
#   make_hint_avx
#   use_hint_avx
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

# AVX2 detection invokes $CC -Wa,-v.  OpenSSL/Tongsuo make passes CC="$(CC)",
# but a bare "perl .../ml_dsa_poly-x86_64.pl" leaves CC unset and the probe
# fails, so $avx2 stays 0 and the ud2 stub branch is emitted.
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

# ML-DSA constants (ml_dsa_local.h)
my $q              = 8380417;
my $d_bits         = 13;
my $half           = (1 << ($d_bits - 1)) - 1;          # 4095
my $mask           = -(1 << $d_bits);                     # 0xffffe000
my $gamma2_div32   = ($q - 1) / 32;                       # 261887
my $off127         = 127;
my $v1025          = 1025;
my $shift512       = 512;
my $mask15         = 15;
my $v11275         = 11275;
my $shift128       = 128;
my $max43          = 43;
my $poly_bytes     = 256 * 4;
my $stack_scratch  = $poly_bytes + 8;                     # a0[256] + alignment slop

sub broadcastd {
    my ($val, $xmm, $ymm) = @_;
    return <<___;
    mov     \$$val, %eax
    vmovd   %eax, $xmm
    vpbroadcastd $xmm, $ymm
___
}

sub row32 {
    my @v = @_;
    return "    .long   " . join(",", @v) . "\n";
}

my $code = "";

if ($avx2>0) {{{

$code .= <<___;
.text

.extern qdata

.globl  power2_round_avx
.type   power2_round_avx,\@function,3
.align 32
power2_round_avx:
.cfi_startproc
    @{[broadcastd($half, "%xmm2", "%ymm2")]}
    @{[broadcastd($mask, "%xmm3", "%ymm3")]}
    vmovdqa qdata+32(%rip), %ymm4           # _8XQ: broadcast q
    xor     %eax, %eax
    mov     \$32, %r8d

.align 32
.Lpower2_loop:
    vmovdqu (%rdi,%rax), %ymm0              # f
    vpaddd  %ymm2, %ymm0, %ymm1             # f + half
    vpand   %ymm3, %ymm1, %ymm5             # (f + half) & mask
    vpsrld  \$$d_bits, %ymm1, %ymm1         # f1
    vpsubd  %ymm5, %ymm0, %ymm5             # f0 = f - masked
    vpxor   %ymm6, %ymm6, %ymm6
    vpcmpgtd %ymm5, %ymm6, %ymm7            # f0 < 0
    vpand   %ymm4, %ymm7, %ymm7             # q if f0 < 0
    vpaddd  %ymm7, %ymm5, %ymm5             # canonical f0
    vmovdqu %ymm1, (%rsi,%rax)
    vmovdqu %ymm5, (%rdx,%rax)
    add     \$32, %rax
    dec     %r8d
    jnz     .Lpower2_loop

    vzeroupper
    ret
.cfi_endproc
.size   power2_round_avx, .-power2_round_avx

.globl  decompose_avx
.type   decompose_avx,\@function,4
.align 32
decompose_avx:
.cfi_startproc
    cmp     \$$gamma2_div32, %esi
    je      .Ldecompose_div32
    jmp     .Ldecompose_div88

.align 32
.Ldecompose_div32:
    @{[broadcastd($off127, "%xmm4", "%ymm4")]}
    @{[broadcastd($v1025, "%xmm5", "%ymm5")]}
    @{[broadcastd($shift512, "%xmm6", "%ymm6")]}
    @{[broadcastd($mask15, "%xmm7", "%ymm7")]}
    lea     (%rsi,%rsi,1), %r9d             # alpha = 2 * gamma2
    vmovd   %r9d, %xmm8
    vpbroadcastd %xmm8, %ymm8
    vmovdqa qdata+32(%rip), %ymm9           # q
    vpsrld  \$1, %ymm9, %ymm10              # hq = q/2
    xor     %eax, %eax
    mov     \$32, %r8d

.align 32
.Ldecompose_div32_loop:
    vmovdqu (%rdi,%rax), %ymm0
    vpaddd  %ymm4, %ymm0, %ymm1
    vpsrld  \$7, %ymm1, %ymm1
    vpmulhuw %ymm5, %ymm1, %ymm1
    vpmulhrsw %ymm6, %ymm1, %ymm1
    vpand   %ymm7, %ymm1, %ymm1
    vpmulld %ymm8, %ymm1, %ymm2
    vpsubd  %ymm2, %ymm0, %ymm2
    vpcmpgtd %ymm10, %ymm2, %ymm3
    vpand   %ymm9, %ymm3, %ymm3
    vpsubd  %ymm3, %ymm2, %ymm2
    vmovdqu %ymm1, (%rdx,%rax)
    vmovdqu %ymm2, (%rcx,%rax)
    add     \$32, %rax
    dec     %r8d
    jnz     .Ldecompose_div32_loop
    vzeroupper
    ret

.align 32
.Ldecompose_div88:
    @{[broadcastd($off127, "%xmm4", "%ymm4")]}
    @{[broadcastd($v11275, "%xmm5", "%ymm5")]}
    @{[broadcastd($shift128, "%xmm6", "%ymm6")]}
    @{[broadcastd($max43, "%xmm7", "%ymm7")]}
    lea     (%rsi,%rsi,1), %r9d
    vmovd   %r9d, %xmm8
    vpbroadcastd %xmm8, %ymm8
    vmovdqa qdata+32(%rip), %ymm9
    vpsrld  \$1, %ymm9, %ymm10
    vpxor   %ymm11, %ymm11, %ymm11
    xor     %eax, %eax
    mov     \$32, %r8d

.align 32
.Ldecompose_div88_loop:
    vmovdqu (%rdi,%rax), %ymm0
    vpaddd  %ymm4, %ymm0, %ymm1
    vpsrld  \$7, %ymm1, %ymm1
    vpmulhuw %ymm5, %ymm1, %ymm1
    vpmulhrsw %ymm6, %ymm1, %ymm1
    vpcmpgtd %ymm7, %ymm1, %ymm12
    vblendvps %ymm12, %ymm11, %ymm1, %ymm1
    vpmulld %ymm8, %ymm1, %ymm2
    vpsubd  %ymm2, %ymm0, %ymm2
    vpcmpgtd %ymm10, %ymm2, %ymm3
    vpand   %ymm9, %ymm3, %ymm3
    vpsubd  %ymm3, %ymm2, %ymm2
    vmovdqu %ymm1, (%rdx,%rax)
    vmovdqu %ymm2, (%rcx,%rax)
    add     \$32, %rax
    dec     %r8d
    jnz     .Ldecompose_div88_loop
    vzeroupper
    ret
.cfi_endproc
.size   decompose_avx, .-decompose_avx

.globl  high_bits_avx
.type   high_bits_avx,\@function,3
.align 32
high_bits_avx:
.cfi_startproc
    sub     \$$stack_scratch, %rsp
    mov     %rsp, %rcx
    call    decompose_avx
    add     \$$stack_scratch, %rsp
    vzeroupper
    ret
.cfi_endproc
.size   high_bits_avx, .-high_bits_avx

.globl  low_bits_avx
.type   low_bits_avx,\@function,3
.align 32
low_bits_avx:
.cfi_startproc
    mov     %rdx, %r8                       # preserve a0 output pointer
    sub     \$$stack_scratch, %rsp
    mov     %rsp, %rdx                      # a1 scratch (discarded)
    mov     %r8, %rcx                       # a0 output
    call    decompose_avx
    add     \$$stack_scratch, %rsp
    vzeroupper
    ret
.cfi_endproc
.size   low_bits_avx, .-low_bits_avx

.globl  make_hint_avx
.type   make_hint_avx,\@function,3
.align 32
make_hint_avx:
.cfi_startproc
    @{[broadcastd(1, "%xmm3", "%ymm3")]}
    xor     %eax, %eax
    mov     \$32, %r8d

.align 32
.Lmake_hint_loop:
    vmovdqu (%rdi,%rax), %ymm0
    vmovdqu (%rsi,%rax), %ymm1
    vpcmpeqd %ymm1, %ymm0, %ymm2
    vpandn   %ymm3, %ymm2, %ymm2            # (~v_eq) & 1
    vmovdqu %ymm2, (%rdx,%rax)
    add     \$32, %rax
    dec     %r8d
    jnz     .Lmake_hint_loop

    vzeroupper
    ret
.cfi_endproc
.size   make_hint_avx, .-make_hint_avx

.globl  use_hint_avx
.type   use_hint_avx,\@function,4
.align 32
use_hint_avx:
.cfi_startproc
    push    %rbp
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    sub     \$$stack_scratch, %rsp
    mov     %rdi, %r12                    # hint
    mov     %rsi, %r13                    # a
    mov     %rdx, %r14                    # gamma2
    mov     %rcx, %rbx                    # b (high bits out)
    mov     %r13, %rdi
    mov     %r14, %rsi
    mov     %rbx, %rdx
    mov     %rsp, %rcx
    call    decompose_avx

    cmp     \$$gamma2_div32, %r14d
    je      .Luse_hint_div32
    jmp     .Luse_hint_div88

.align 32
.Luse_hint_div32:
    @{[broadcastd($mask15, "%xmm7", "%ymm7")]}
    vpxor   %ymm11, %ymm11, %ymm11
    xor     %eax, %eax
    mov     \$32, %r8d

.align 32
.Luse_hint_div32_loop:
    vmovdqu (%rsp,%rax), %ymm0            # a0
    vmovdqu (%rbx,%rax), %ymm1            # r1 (b)
    vmovdqu (%r12,%rax), %ymm2            # hint
    vblendvps %ymm0, %ymm2, %ymm11, %ymm3
    vpslld  \$1, %ymm3, %ymm3
    vpsubd  %ymm3, %ymm2, %ymm2
    vpaddd  %ymm2, %ymm1, %ymm1
    vpand   %ymm7, %ymm1, %ymm1
    vmovdqu %ymm1, (%rbx,%rax)
    add     \$32, %rax
    dec     %r8d
    jnz     .Luse_hint_div32_loop
    add     \$$stack_scratch, %rsp
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx
    pop     %rbp
    vzeroupper
    ret

.align 32
.Luse_hint_div88:
    @{[broadcastd($max43, "%xmm7", "%ymm7")]}
    vpxor   %ymm11, %ymm11, %ymm11
    xor     %eax, %eax
    mov     \$32, %r8d

.align 32
.Luse_hint_div88_loop:
    vmovdqu (%rsp,%rax), %ymm0
    vmovdqu (%rbx,%rax), %ymm1
    vmovdqu (%r12,%rax), %ymm2
    vblendvps %ymm0, %ymm2, %ymm11, %ymm3
    vpslld  \$1, %ymm3, %ymm3
    vpsubd  %ymm3, %ymm2, %ymm2
    vpaddd  %ymm2, %ymm1, %ymm1
    vblendvps %ymm1, %ymm7, %ymm1, %ymm1
    vpcmpgtd %ymm7, %ymm1, %ymm4
    vblendvps %ymm4, %ymm11, %ymm1, %ymm1
    vmovdqu %ymm1, (%rbx,%rax)
    add     \$32, %rax
    dec     %r8d
    jnz     .Luse_hint_div88_loop
    add     \$$stack_scratch, %rsp
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx
    pop     %rbp
    vzeroupper
    ret
.cfi_endproc
.size   use_hint_avx, .-use_hint_avx
___

}}} else {{{
$code .= <<___;
.text

.globl  power2_round_avx
.globl  decompose_avx
.globl  high_bits_avx
.globl  low_bits_avx
.globl  make_hint_avx
.globl  use_hint_avx
.type   power2_round_avx,\@abi-omnipotent
power2_round_avx:
decompose_avx:
high_bits_avx:
low_bits_avx:
make_hint_avx:
use_hint_avx:
    .byte   0x0f,0x0b       # ud2
    ret
.size   power2_round_avx, .-power2_round_avx
___
}}}

print $code;
close STDOUT or die "error closing STDOUT: $!";
