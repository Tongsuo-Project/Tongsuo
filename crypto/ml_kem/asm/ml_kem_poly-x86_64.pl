#! /usr/bin/env perl
# Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

###############################################################################
# ML-KEM AVX2 Vectorized Polynomial Assembly Routines
#
# Description:
#   This file provides optimized x86_64 assembly implementations of
#   polynomial arithmetic building blocks for the ML-KEM scheme.
#
#   The routines are vectorized using AVX2 instructions, operating on
#   16 16-bit coefficients per YMM register.  The mathematical structure
#   strictly follows the corresponding C code (ml_kem.c), providing a
#   drop-in backend with identical semantics and data layout.
#
#   Currently implemented:
#     - ml_kem_scalar_add_avx2: coefficient-wise addition with canonical
#       reduction, matching scalar_add()/reduce_once() in ml_kem.c.
#     - ml_kem_scalar_sub_avx2: coefficient-wise subtraction with canonical
#       reduction, matching scalar_sub() in ml_kem.c.
#     - ml_kem_ntt_avx2: in-place forward NTT, matching scalar_ntt() in
#       ml_kem.c layer by layer (Phase 1a: every butterfly output is
#       canonically reduced; no lazy reduction, no layer merging).
#     - ml_kem_intt_avx2: in-place inverse NTT including the 1/128 scaling,
#       matching scalar_inverse_ntt() + scalar_mult_const() in ml_kem.c
#       under the same Phase 1a contract.
#     - ml_kem_basemul_avx2: NTT-domain base multiplication, matching
#       scalar_mult() in ml_kem.c via a signed Montgomery product chain.
#
# Notes:
#   - Inputs are canonical coefficients in [0, q), q = 3329.  The sum is
#     at most 2q - 2 = 6656, which fits comfortably in a signed 16-bit
#     lane, so signed AVX2 arithmetic is safe throughout.
#   - The conditional subtraction of q is branch-free (subtract, arithmetic
#     shift for the sign mask, masked add-back), matching the constant-time
#     contract of reduce_once() without relying on compiler behavior.
#   - Vector register usage by routine: add/sub use ymm0-ymm3; ntt/intt and
#     basemul use ymm0-ymm5.  All of these map to xmm0-xmm5, which are
#     volatile (caller-saved) under both the SysV and Windows x64 ABIs, so no
#     xmm save/restore or SEH unwind bookkeeping is emitted.  The integer
#     scratch registers (rax, rcx, rdx, rsi, rdi, r8, r9) are ABI argument or
#     volatile registers under SysV; the perlasm translator saves and restores
#     rsi/rdi as required on Windows, where they are callee-saved.  No routine
#     touches ymm6-ymm15 or allocates stack space.
#   - Must be kept functionally synchronized with ml_kem.c.
###############################################################################

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
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

# Check for AVX2 support in assembler
if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1` =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
  $avx2 = ($1 >= 2.22);
}

if (!$avx2
  && $win64
  && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/)
  && `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)(?:\.([0-9]+))?/)
{
  $avx2 = ($1 >= 2.10);
}

if (!$avx2 && `$ENV{CC} -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
    $avx2 = ($2>=3.3); # minimal tested version for AVX2
}

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
  or die "can't call $xlate: $!";
*STDOUT = *OUT;

# ML-KEM constants
my $q = 3329;
my $qinv = 62209;               # q^-1 mod 2^16 (for 16-bit Montgomery reduction)

# AVX2 feature bit: OPENSSL_ia32cap_P[2] bit 5
my $avx2_mask = (1<<5);

###############################################################################
# NTT twiddle-factor tables, computed here from first principles so that the
# generated tables cannot drift from their definition.
#
# zeta[i] = 17^BitRev7(i) mod q (FIPS 203), identical to kNTTRoots in ml_kem.c.
# zm[i]   = zeta[i] * 2^16 mod q, the Montgomery form consumed by the
#           vpmullw/vpmulhw reduction sequence in the butterfly below.
#
# The first four NTT layers (offset >= 16 coefficients) broadcast one zeta per
# block, consuming zm[1..15] sequentially.  The last three layers (offset 8,
# 4, 2) operate inside YMM registers after an unpack/permute network; their
# zetas are pre-expanded per lane in the block order produced by that network:
#   offset 8: vperm2i128 pairs two 16-coefficient blocks per iteration,
#             lane block order (2k, 2k+1)
#   offset 4: vpunpck[lh]qdq groups four 8-coefficient blocks per iteration,
#             lane block order (4m, 4m+2, 4m+1, 4m+3)
#   offset 2: vpshufd 0xD8 + vpunpck[lh]qdq groups eight 4-coefficient blocks,
#             lane block order (8m+0, 8m+1, 8m+4, 8m+5, 8m+2, 8m+3, 8m+6, 8m+7)
# These orders were validated lane-exactly against the scalar reference.
###############################################################################
sub bitrev7 { my ($x)=@_; my $r=0; for (1..7) { $r=($r<<1)|($x&1); $x>>=1; } return $r; }
my (@zeta16, @zm16);
for my $i (0..127) {
    my $e = bitrev7($i); my $z = 1;
    $z = ($z*17) % $q for (1..$e);
    $zeta16[$i] = $z;
    $zm16[$i] = ($z * 65536) % $q;
}
my (@zv8, @zv4, @zv2);
for my $k (0..7) { push @zv8, [ ($zm16[16+2*$k]) x 8, ($zm16[17+2*$k]) x 8 ]; }
for my $m (0..7) { my @o=(0,2,1,3);          push @zv4, [ map { ($zm16[32+4*$m+$_]) x 4 } @o ]; }
for my $m (0..7) { my @o=(0,1,4,5,2,3,6,7);  push @zv2, [ map { ($zm16[64+8*$m+$_]) x 2 } @o ]; }

###############################################################################
# Inverse NTT tables.  kInverseNTTRoots in ml_kem.c stores
# 17^(-BitRev7(i)) mod q listed in order of use by the inverse NTT loop:
# i = 0, 64..127, 32..63, 16..31, 8..15, 4..7, 2..3, 1.  We derive the same
# sequence here (verified element-wise against the C table) and store the
# Montgomery forms.  The inverse transform runs the in-register layers first
# (offset 2, 4, 8, consuming entries 1..64, 65..96, 97..112, pre-expanded in
# the same lane block orders as the forward tables), then the generic block
# layers (offset 16..128, entries 113..127 sequential), then scales by
# kInverseDegree = 3303 = (n/2)^-1 mod q, folded into the kernel as one
# Montgomery multiplication pass.
###############################################################################
my @iorder = (0, 64..127, 32..63, 16..31, 8..15, 4..7, 2..3, 1);
my @izm;
for my $k (0..127) {
    my $e = bitrev7($iorder[$k]); my $z = 1;
    $z = ($z*17) % $q for (1..$e);
    my ($acc, $base, $ee) = (1, $z, $q-2);          # z^-1 via Fermat
    while ($ee) { $acc = ($acc*$base) % $q if $ee & 1; $base = ($base*$base) % $q; $ee >>= 1; }
    $izm[$k] = ($acc * 65536) % $q;
}
my (@izv8, @izv4, @izv2);
for my $k (0..7) { push @izv8, [ ($izm[97+2*$k]) x 8, ($izm[98+2*$k]) x 8 ]; }
for my $m (0..7) { my @o=(0,2,1,3);          push @izv4, [ map { ($izm[65+4*$m+$_]) x 4 } @o ]; }
for my $m (0..7) { my @o=(0,1,4,5,2,3,6,7);  push @izv2, [ map { ($izm[1+8*$m+$_]) x 2 } @o ]; }
my $invdeg_m = (($q - 26) * 65536) % $q;            # kInverseDegree * 2^16 mod q

###############################################################################
# Base multiplication tables.  kModRoots[i] = 17^(2*BitRev7(i)+1) mod q
# (verified element-wise against the C table); we store the Montgomery forms
# in the lane layout produced by the vpshufb even/odd split below: each row
# serves 8 coefficient pairs, with the four zetas of pairs 0..3 in lanes 0..3
# and of pairs 4..7 in lanes 8..11 (remaining lanes are zero and unused).
# R2 = 2^32 mod q converts a Montgomery-domain sum back to the plain domain
# with one further Montgomery multiplication.
###############################################################################
my @kmodm;
for my $i (0..127) {
    my $e = 2*bitrev7($i) + 1; my $z = 1;
    $z = ($z*17) % $q for (1..$e);
    $kmodm[$i] = ($z * 65536) % $q;
}
my @zmodrow;
for my $k (0..15) {
    my @row = (0) x 16;
    for my $j (0..3) { $row[$j] = $kmodm[8*$k+$j]; $row[8+$j] = $kmodm[8*$k+4+$j]; }
    push @zmodrow, [ @row ];
}
my $r2 = (65536 * 65536) % $q;                      # 1353

# Pack one row of 32 byte values into eight .long words (little endian).
sub rowbytes {
    my @b = @_;
    return "    .long   " . join(",", map { sprintf("0x%08x",
        $b[4*$_] | ($b[4*$_+1]<<8) | ($b[4*$_+2]<<16) | ($b[4*$_+3]<<24)) } (0..7)) . "\n";
}
# vpshufb masks splitting 16-bit lanes into even/odd halves (per 128-bit lane;
# index 0x80 zeroes the byte).
my @shuf_even = ((0,1,4,5,8,9,12,13, (0x80) x 8) x 2);
my @shuf_odd  = ((2,3,6,7,10,11,14,15, (0x80) x 8) x 2);

###############################################################################
# In-place Montgomery multiplication of one vector by a preserved operand:
#   $a = $a * $b * 2^-16 mod q, signed result in (-q, q)
# $b (register or memory row) is preserved; $s is a scratch register.
# Valid for signed $a in (-2q, 2q) and canonical $b, since
# |a * b| < 2q * q < q * 2^15 keeps the standard Montgomery bound.
###############################################################################
sub fq_inplace {
    my ($a, $b, $s) = @_;
    return <<___;
    vpmullw $b, $a, $s                   # lo16(a * b)
    vpmulhw $b, $a, $a                   # hi16(a * b), signed
    vpmullw .Lqinv16(%rip), $s, $s       # m = lo * qinv mod 2^16
    vpmulhw .Lq16(%rip), $s, $s          # hi16(m * q), signed
    vpsubw  $s, $a, $a                   # a = (a*b - m*q) >> 16, in (-q, q)
___
}

# Canonicalize signed (-q, q) to [0, q) in place; $s is scratch.
sub canon_inplace {
    my ($a, $s) = @_;
    return <<___;
    vpsraw  \$15, $a, $s
    vpand   .Lq16(%rip), $s, $s
    vpaddw  $s, $a, $a                   # in [0, q)
___
}

# Pack one row of 16 16-bit values into eight .long words (little endian).
sub row16 {
    my @v = @_;
    return "    .long   " . join(",", map { sprintf("0x%08x", $v[2*$_] | ($v[2*$_+1]<<16)) } (0..7)) . "\n";
}

###############################################################################
# Forward NTT butterfly on one pair of coefficient vectors.
#
#   E (ymm0), O (ymm1): 16 canonical coefficients each, in [0, q)
#   $zeta: Montgomery-form zeta, as a broadcast register or a memory row
#
# Steps (bounds annotated per lane; all arithmetic is 16-bit):
#   t   = O * zeta * 2^-16 mod q      Montgomery product, t in (-q, q)
#         [|O * zm| < q^2 < q * 2^15, standard Montgomery bound]
#   odd = t + (q if t < 0)            canonical, [0, q)
#   E'  = csubq(E + odd)              E + odd in [0, 2q), result [0, q)
#   O'  = csubq(E - odd + q)          E - odd + q in (0, 2q), result [0, q)
# Matches scalar_ntt's reduce()/reduce_once() outputs exactly per butterfly.
# Clobbers ymm2, ymm3.  Results: E' in ymm0, O' in ymm1.
###############################################################################
sub fwd_butterfly {
    my ($zeta) = @_;
    return <<___;
    vpmullw $zeta, %ymm1, %ymm2          # lo16(O * zm)
    vpmulhw $zeta, %ymm1, %ymm3          # hi16(O * zm), signed
    vpmullw .Lqinv16(%rip), %ymm2, %ymm2 # m = lo * qinv mod 2^16
    vpmulhw .Lq16(%rip), %ymm2, %ymm2    # hi16(m * q), signed
    vpsubw  %ymm2, %ymm3, %ymm3          # t = (O*zm - m*q) >> 16, in (-q, q)
    vpsraw  \$15, %ymm3, %ymm2           # bound: mask = t < 0
    vpand   .Lq16(%rip), %ymm2, %ymm2
    vpaddw  %ymm2, %ymm3, %ymm1          # odd in [0, q)
    vpaddw  %ymm1, %ymm0, %ymm2          # bound: E + odd in [0, 2q)
    vpsubw  %ymm1, %ymm0, %ymm3          # E - odd in (-q, q)
    vpaddw  .Lq16(%rip), %ymm3, %ymm3    # bound: E - odd + q in (0, 2q)
    vpsubw  .Lq16(%rip), %ymm2, %ymm0    # csubq(E + odd)
    vpsraw  \$15, %ymm0, %ymm1
    vpand   .Lq16(%rip), %ymm1, %ymm1
    vpaddw  %ymm1, %ymm0, %ymm0          # E' in [0, q)
    vpsubw  .Lq16(%rip), %ymm3, %ymm1    # csubq(E - odd + q)
    vpsraw  \$15, %ymm1, %ymm2
    vpand   .Lq16(%rip), %ymm2, %ymm2
    vpaddw  %ymm2, %ymm1, %ymm1          # O' in [0, q)
___
}

###############################################################################
# Inverse (Gentleman-Sande) butterfly on one pair of coefficient vectors.
#
#   E (ymm0), O (ymm1): 16 canonical coefficients each, in [0, q)
#   $zeta: Montgomery-form inverse zeta, broadcast register or memory row
#
# Steps (bounds annotated; matches scalar_inverse_ntt exactly per butterfly):
#   E' = csubq(E + O)                 E + O in [0, 2q), result [0, q)
#   t  = E - O + q                    in (0, 2q)
#   O' = t * zeta * 2^-16 mod q, canonicalized
#        [|t * izm| < 2q * q < q * 2^15, Montgomery bound holds]
# Clobbers ymm2, ymm3.  Results: E' in ymm0, O' in ymm1.
###############################################################################
sub inv_butterfly {
    my ($zeta) = @_;
    return <<___;
    vpsubw  %ymm1, %ymm0, %ymm2          # E - O in (-q, q)
    vpaddw  .Lq16(%rip), %ymm2, %ymm2    # bound: t = E - O + q in (0, 2q)
    vpaddw  %ymm1, %ymm0, %ymm0          # bound: E + O in [0, 2q)
    vpsubw  .Lq16(%rip), %ymm0, %ymm1    # csubq(E + O)
    vpsraw  \$15, %ymm1, %ymm0
    vpand   .Lq16(%rip), %ymm0, %ymm0
    vpaddw  %ymm1, %ymm0, %ymm0          # E' in [0, q)
    vpmullw $zeta, %ymm2, %ymm1          # lo16(t * izm)
    vpmulhw $zeta, %ymm2, %ymm3          # hi16(t * izm), signed
    vpmullw .Lqinv16(%rip), %ymm1, %ymm1 # m = lo * qinv mod 2^16
    vpmulhw .Lq16(%rip), %ymm1, %ymm1    # hi16(m * q), signed
    vpsubw  %ymm1, %ymm3, %ymm3          # t' = (t*izm - m*q) >> 16, in (-q, q)
    vpsraw  \$15, %ymm3, %ymm1
    vpand   .Lq16(%rip), %ymm1, %ymm1
    vpaddw  %ymm1, %ymm3, %ymm1          # O' in [0, q)
___
}

if ($avx2>0) {{{

$code .= <<___;
.text

.extern OPENSSL_ia32cap_P

.globl  ml_kem_poly_avx2_capable
.type   ml_kem_poly_avx2_capable,\@abi-omnipotent
.align 32
ml_kem_poly_avx2_capable:
    mov     OPENSSL_ia32cap_P+8(%rip), %rcx
    xor     %eax, %eax
    and     \$$avx2_mask, %ecx
    cmovnz  %ecx, %eax
    ret
.size   ml_kem_poly_avx2_capable, .-ml_kem_poly_avx2_capable
___

###############################################################################
# ml_kem_scalar_add_avx2
#
# Description:
#   Coefficient-wise addition of two degree-256 ML-KEM polynomials with
#   canonical reduction, updating the left operand in place:
#
#     lhs[i] = reduce_once(lhs[i] + rhs[i]),  i = 0..255
#
#   where reduce_once(x) = x - q if x >= q else x, for x < 2q.
#
#   Each iteration processes one YMM register holding 16 16-bit
#   coefficients; 16 iterations cover all 256 coefficients.
#
# Parameters:
#   rdi - uint16_t *lhs      (in/out, 256 coefficients, canonical)
#   rsi - const uint16_t *rhs (in, 256 coefficients, canonical)
#
# Register usage (all volatile on both SysV and Windows ABIs):
#   ymm0 - sum a + b, then final result staging
#   ymm1 - sum - q
#   ymm2 - sign mask, then masked add-back value
#   ymm3 - broadcast q
#   eax  - loop counter
###############################################################################
$code .= <<___;
.globl  ml_kem_scalar_add_avx2
.type   ml_kem_scalar_add_avx2,\@function,2
.align 32
ml_kem_scalar_add_avx2:
.cfi_startproc
    mov     \$$q, %eax
    vmovd   %eax, %xmm3
    vpbroadcastw %xmm3, %ymm3
    mov     \$16, %eax

.align 32
.Ladd_loop:
    vmovdqu (%rdi), %ymm0
    vpaddw  (%rsi), %ymm0, %ymm0     # a + b, at most 2q - 2
    vpsubw  %ymm3, %ymm0, %ymm1      # t = a + b - q
    vpsraw  \$15, %ymm1, %ymm2       # lane mask: t < 0 ? 0xffff : 0
    vpand   %ymm3, %ymm2, %ymm2      # q where t < 0, else 0
    vpaddw  %ymm2, %ymm1, %ymm1      # t + q if t < 0, else t
    vmovdqu %ymm1, (%rdi)
    add     \$32, %rdi
    add     \$32, %rsi
    dec     %eax
    jnz     .Ladd_loop

    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_scalar_add_avx2, .-ml_kem_scalar_add_avx2
___

###############################################################################
# ml_kem_scalar_sub_avx2
#
# Description:
#   Coefficient-wise subtraction with canonical reduction, in place:
#     lhs[i] = reduce_once(lhs[i] - rhs[i] + q),  i = 0..255
#   lhs - rhs is in (-q, q); adding q gives (0, 2q); csubq restores [0, q).
#
# Parameters:
#   rdi - uint16_t *lhs       (in/out, canonical)
#   rsi - const uint16_t *rhs (in, canonical)
###############################################################################
$code .= <<___;
.globl  ml_kem_scalar_sub_avx2
.type   ml_kem_scalar_sub_avx2,\@function,2
.align 32
ml_kem_scalar_sub_avx2:
.cfi_startproc
    mov     \$16, %eax

.align 32
.Lsub_loop:
    vmovdqu (%rdi), %ymm0
    vpsubw  (%rsi), %ymm0, %ymm0         # lhs - rhs, in (-q, q)
    vpaddw  .Lq16(%rip), %ymm0, %ymm0    # bound: in (0, 2q)
    vpsubw  .Lq16(%rip), %ymm0, %ymm1    # csubq
    vpsraw  \$15, %ymm1, %ymm2
    vpand   .Lq16(%rip), %ymm2, %ymm2
    vpaddw  %ymm2, %ymm1, %ymm1          # in [0, q)
    vmovdqu %ymm1, (%rdi)
    add     \$32, %rdi
    add     \$32, %rsi
    dec     %eax
    jnz     .Lsub_loop

    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_scalar_sub_avx2, .-ml_kem_scalar_sub_avx2
___

###############################################################################
# ml_kem_ntt_avx2
#
# Description:
#   In-place forward NTT, semantically identical to scalar_ntt() in ml_kem.c:
#   seven layers (offset 128 down to 2), zetas consumed in the same order,
#   every butterfly output canonically reduced to [0, q) (Phase 1a contract:
#   per-layer values match the scalar implementation exactly).
#
#   Layers with offset >= 16 use a generic block loop mirroring the scalar
#   code, with one broadcast zeta per block.  Layers with offset 8, 4, 2
#   pair coefficients inside YMM registers via a self-inverse permute
#   network (see table comments above); each runs 8 iterations over 64-byte
#   chunks with pre-expanded per-lane zeta rows.
#
# Parameters:
#   rdi - uint16_t *c (in/out, 256 canonical coefficients)
###############################################################################
$code .= <<___;
.globl  ml_kem_ntt_avx2
.type   ml_kem_ntt_avx2,\@function,1
.align 32
ml_kem_ntt_avx2:
.cfi_startproc
    lea     .Lzetas_seq(%rip), %rax
    lea     512(%rdi), %rdx              # end of coefficients
    mov     \$256, %r8d                  # offset in bytes (coeff offset 128)

.align 32
.Lntt_layer:
    mov     %rdi, %rsi                   # curr
.Lntt_block:
    vpbroadcastw (%rax), %ymm4           # zeta for this block
    add     \$2, %rax
    lea     (%rsi,%r8), %rcx             # peer = curr + offset
    mov     %r8, %r9
.Lntt_pair:
    vmovdqu (%rsi), %ymm0
    vmovdqu (%rcx), %ymm1
___
$code .= fwd_butterfly("%ymm4");
$code .= <<___;
    vmovdqu %ymm0, (%rsi)
    vmovdqu %ymm1, (%rcx)
    add     \$32, %rsi
    add     \$32, %rcx
    sub     \$32, %r9
    jnz     .Lntt_pair
    mov     %rcx, %rsi                   # curr = end of block
    cmp     %rdx, %rsi
    jb      .Lntt_block
    shr     \$1, %r8
    cmp     \$32, %r8
    jae     .Lntt_layer

    # ----- offset 8: pair 128-bit halves of two consecutive blocks -----
    lea     .Lzv8(%rip), %rax
    mov     %rdi, %rsi
    mov     \$8, %r9d
.align 32
.Lntt_off8:
    vmovdqu (%rsi), %ymm4
    vmovdqu 32(%rsi), %ymm5
    vperm2i128 \$0x20, %ymm5, %ymm4, %ymm0   # E = low halves
    vperm2i128 \$0x31, %ymm5, %ymm4, %ymm1   # O = high halves
___
$code .= fwd_butterfly("(%rax)");
$code .= <<___;
    vperm2i128 \$0x20, %ymm1, %ymm0, %ymm2   # restore (self-inverse)
    vperm2i128 \$0x31, %ymm1, %ymm0, %ymm3
    vmovdqu %ymm2, (%rsi)
    vmovdqu %ymm3, 32(%rsi)
    add     \$64, %rsi
    add     \$32, %rax
    dec     %r9d
    jnz     .Lntt_off8

    # ----- offset 4: pair 64-bit quarters via vpunpck[lh]qdq -----
    lea     .Lzv4(%rip), %rax
    mov     %rdi, %rsi
    mov     \$8, %r9d
.align 32
.Lntt_off4:
    vmovdqu (%rsi), %ymm4
    vmovdqu 32(%rsi), %ymm5
    vpunpcklqdq %ymm5, %ymm4, %ymm0          # E, lane block order (0,2,1,3)
    vpunpckhqdq %ymm5, %ymm4, %ymm1          # O
___
$code .= fwd_butterfly("(%rax)");
$code .= <<___;
    vpunpcklqdq %ymm1, %ymm0, %ymm2          # restore (self-inverse)
    vpunpckhqdq %ymm1, %ymm0, %ymm3
    vmovdqu %ymm2, (%rsi)
    vmovdqu %ymm3, 32(%rsi)
    add     \$64, %rsi
    add     \$32, %rax
    dec     %r9d
    jnz     .Lntt_off4

    # ----- offset 2: vpshufd groups pairs, then as offset 4 -----
    lea     .Lzv2(%rip), %rax
    mov     %rdi, %rsi
    mov     \$8, %r9d
.align 32
.Lntt_off2:
    vmovdqu (%rsi), %ymm4
    vmovdqu 32(%rsi), %ymm5
    vpshufd \$0xd8, %ymm4, %ymm4             # dwords (0,2,1,3) per lane
    vpshufd \$0xd8, %ymm5, %ymm5
    vpunpcklqdq %ymm5, %ymm4, %ymm0          # E, block order (0,1,4,5,2,3,6,7)
    vpunpckhqdq %ymm5, %ymm4, %ymm1          # O
___
$code .= fwd_butterfly("(%rax)");
$code .= <<___;
    vpunpcklqdq %ymm1, %ymm0, %ymm2
    vpunpckhqdq %ymm1, %ymm0, %ymm3
    vpshufd \$0xd8, %ymm2, %ymm2             # vpshufd 0xd8 is self-inverse
    vpshufd \$0xd8, %ymm3, %ymm3
    vmovdqu %ymm2, (%rsi)
    vmovdqu %ymm3, 32(%rsi)
    add     \$64, %rsi
    add     \$32, %rax
    dec     %r9d
    jnz     .Lntt_off2

    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_ntt_avx2, .-ml_kem_ntt_avx2
___

###############################################################################
# ml_kem_intt_avx2
#
# Description:
#   In-place inverse NTT, semantically identical to scalar_inverse_ntt()
#   followed by scalar_mult_const(s, kInverseDegree) in ml_kem.c: seven
#   Gentleman-Sande layers (offset 2 up to 128), inverse zetas consumed in
#   the same order, every butterfly output canonically reduced (Phase 1a
#   contract), and the final 1/128 scaling folded into the kernel as one
#   Montgomery multiplication pass.
#
#   The in-register layers (offset 2, 4, 8) run first, using the same
#   self-inverse permute networks as the forward transform; the generic
#   block loop then covers offsets 16 through 128 with the offset doubling.
#
# Parameters:
#   rdi - uint16_t *c (in/out, 256 canonical coefficients)
###############################################################################
$code .= <<___;
.globl  ml_kem_intt_avx2
.type   ml_kem_intt_avx2,\@function,1
.align 32
ml_kem_intt_avx2:
.cfi_startproc
    # ----- offset 2 -----
    lea     .Lizv2(%rip), %rax
    mov     %rdi, %rsi
    mov     \$8, %r9d
.align 32
.Lintt_off2:
    vmovdqu (%rsi), %ymm4
    vmovdqu 32(%rsi), %ymm5
    vpshufd \$0xd8, %ymm4, %ymm4
    vpshufd \$0xd8, %ymm5, %ymm5
    vpunpcklqdq %ymm5, %ymm4, %ymm0
    vpunpckhqdq %ymm5, %ymm4, %ymm1
___
$code .= inv_butterfly("(%rax)");
$code .= <<___;
    vpunpcklqdq %ymm1, %ymm0, %ymm2
    vpunpckhqdq %ymm1, %ymm0, %ymm3
    vpshufd \$0xd8, %ymm2, %ymm2
    vpshufd \$0xd8, %ymm3, %ymm3
    vmovdqu %ymm2, (%rsi)
    vmovdqu %ymm3, 32(%rsi)
    add     \$64, %rsi
    add     \$32, %rax
    dec     %r9d
    jnz     .Lintt_off2

    # ----- offset 4 -----
    lea     .Lizv4(%rip), %rax
    mov     %rdi, %rsi
    mov     \$8, %r9d
.align 32
.Lintt_off4:
    vmovdqu (%rsi), %ymm4
    vmovdqu 32(%rsi), %ymm5
    vpunpcklqdq %ymm5, %ymm4, %ymm0
    vpunpckhqdq %ymm5, %ymm4, %ymm1
___
$code .= inv_butterfly("(%rax)");
$code .= <<___;
    vpunpcklqdq %ymm1, %ymm0, %ymm2
    vpunpckhqdq %ymm1, %ymm0, %ymm3
    vmovdqu %ymm2, (%rsi)
    vmovdqu %ymm3, 32(%rsi)
    add     \$64, %rsi
    add     \$32, %rax
    dec     %r9d
    jnz     .Lintt_off4

    # ----- offset 8 -----
    lea     .Lizv8(%rip), %rax
    mov     %rdi, %rsi
    mov     \$8, %r9d
.align 32
.Lintt_off8:
    vmovdqu (%rsi), %ymm4
    vmovdqu 32(%rsi), %ymm5
    vperm2i128 \$0x20, %ymm5, %ymm4, %ymm0
    vperm2i128 \$0x31, %ymm5, %ymm4, %ymm1
___
$code .= inv_butterfly("(%rax)");
$code .= <<___;
    vperm2i128 \$0x20, %ymm1, %ymm0, %ymm2
    vperm2i128 \$0x31, %ymm1, %ymm0, %ymm3
    vmovdqu %ymm2, (%rsi)
    vmovdqu %ymm3, 32(%rsi)
    add     \$64, %rsi
    add     \$32, %rax
    dec     %r9d
    jnz     .Lintt_off8

    # ----- offsets 16..128: generic block loop, offset doubling -----
    lea     .Lizetas_seq(%rip), %rax
    lea     512(%rdi), %rdx
    mov     \$32, %r8d                   # offset in bytes (coeff offset 16)
.align 32
.Lintt_layer:
    mov     %rdi, %rsi
.Lintt_block:
    vpbroadcastw (%rax), %ymm4
    add     \$2, %rax
    lea     (%rsi,%r8), %rcx
    mov     %r8, %r9
.Lintt_pair:
    vmovdqu (%rsi), %ymm0
    vmovdqu (%rcx), %ymm1
___
$code .= inv_butterfly("%ymm4");
$code .= <<___;
    vmovdqu %ymm0, (%rsi)
    vmovdqu %ymm1, (%rcx)
    add     \$32, %rsi
    add     \$32, %rcx
    sub     \$32, %r9
    jnz     .Lintt_pair
    mov     %rcx, %rsi
    cmp     %rdx, %rsi
    jb      .Lintt_block
    shl     \$1, %r8
    cmp     \$256, %r8
    jbe     .Lintt_layer

    # ----- scale by kInverseDegree (Montgomery form), canonicalize -----
    mov     %rdi, %rsi
    mov     \$16, %r9d
.align 32
.Lintt_scale:
    vmovdqu (%rsi), %ymm0
    vpmullw .Linvdeg16(%rip), %ymm0, %ymm1   # lo16(c * dm)
    vpmulhw .Linvdeg16(%rip), %ymm0, %ymm2   # hi16(c * dm), signed
    vpmullw .Lqinv16(%rip), %ymm1, %ymm1
    vpmulhw .Lq16(%rip), %ymm1, %ymm1
    vpsubw  %ymm1, %ymm2, %ymm2              # t in (-q, q)
    vpsraw  \$15, %ymm2, %ymm1
    vpand   .Lq16(%rip), %ymm1, %ymm1
    vpaddw  %ymm1, %ymm2, %ymm2              # c * 3303 mod q, in [0, q)
    vmovdqu %ymm2, (%rsi)
    add     \$32, %rsi
    dec     %r9d
    jnz     .Lintt_scale

    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_intt_avx2, .-ml_kem_intt_avx2
___

###############################################################################
# ml_kem_basemul_avx2
#
# Description:
#   NTT-domain base multiplication, semantically identical to scalar_mult()
#   in ml_kem.c.  Pairs (c[2i], c[2i+1]) are elements of
#   GF(q)[X]/(X^2 - kModRoots[i]):
#     out0 = l0*r0 + l1*r1*zeta mod q
#     out1 = l0*r1 + l1*r0     mod q
#
#   Strategy: vpshufb splits each 16-coefficient vector into even/odd
#   halves; all products run through the in-place Montgomery multiply,
#   keeping intermediates in the R^-1 domain as signed values in (-q, q);
#   sums stay in (-2q, 2q); one final multiplication by R^2 mod q returns
#   to the plain domain, then canonicalization gives [0, q).  Outputs match
#   scalar_mult()'s reduce()-based results exactly.
#
# Parameters:
#   rdi - uint16_t *out
#   rsi - const uint16_t *lhs (canonical)
#   rdx - const uint16_t *rhs (canonical)
###############################################################################
# One iteration of the base-multiplication loop.  $acc selects the tail:
#   $acc == 0 -> out  = l*r          (ml_kem_basemul_avx2)
#   $acc == 1 -> out += l*r          (ml_kem_basemul_acc_avx2)
# Both variants reach a canonical [0, q) result before the store.  In the
# accumulate case the loaded out is canonical, the product is canonical, so
# the sum is in [0, 2q) and one csubq restores [0, q).  $label names the loop.
sub basemul_body {
    my ($label, $acc) = @_;
    my $code = <<___;
.align 32
$label:
    vmovdqu (%rsi), %ymm0
    vpshufb .Lshuf_even(%rip), %ymm0, %ymm1  # l0 lanes (0..3, 8..11)
    vpshufb .Lshuf_odd(%rip), %ymm0, %ymm2   # l1
    vmovdqu (%rdx), %ymm0
    vpshufb .Lshuf_even(%rip), %ymm0, %ymm3  # r0
    vpshufb .Lshuf_odd(%rip), %ymm0, %ymm4   # r1
    vmovdqa %ymm1, %ymm5                     # keep l0 for the odd output
___
    $code .= fq_inplace("%ymm5", "%ymm4", "%ymm0");     # D1 = l0*r1*R^-1
    $code .= fq_inplace("%ymm1", "%ymm3", "%ymm0");     # A  = l0*r0*R^-1
    $code .= fq_inplace("%ymm3", "%ymm2", "%ymm0");     # X2 = l1*r0*R^-1
    $code .= <<___;
    vpaddw  %ymm5, %ymm3, %ymm3              # bound: D = D1 + X2 in (-2q, 2q)
___
    $code .= fq_inplace("%ymm3", ".Lr2_16(%rip)", "%ymm0"); # D*R^2*R^-1 = out1
    $code .= canon_inplace("%ymm3", "%ymm0");
    $code .= fq_inplace("%ymm2", "%ymm4", "%ymm0");     # B = l1*r1*R^-1
    $code .= fq_inplace("%ymm2", "(%rax)", "%ymm0");    # C = l1*r1*zeta*R^-1
    $code .= <<___;
    vpaddw  %ymm2, %ymm1, %ymm1              # bound: T = A + C in (-2q, 2q)
___
    $code .= fq_inplace("%ymm1", ".Lr2_16(%rip)", "%ymm0"); # T*R^2*R^-1 = out0
    $code .= canon_inplace("%ymm1", "%ymm0");
    $code .= <<___;
    vpunpcklwd %ymm3, %ymm1, %ymm0           # interleave out0/out1 pairs
___
    $code .= <<___ if ($acc);
    vpaddw  (%rdi), %ymm0, %ymm0             # bound: out + product in [0, 2q)
    vpsubw  .Lq16(%rip), %ymm0, %ymm1        # csubq
    vpsraw  \$15, %ymm1, %ymm2
    vpand   .Lq16(%rip), %ymm2, %ymm2
    vpaddw  %ymm2, %ymm1, %ymm0              # in [0, q)
___
    $code .= <<___;
    vmovdqu %ymm0, (%rdi)
    add     \$32, %rsi
    add     \$32, %rdx
    add     \$32, %rdi
    add     \$32, %rax
    dec     %r9d
    jnz     $label

    vzeroupper
    ret
___
    return $code;
}

$code .= <<___;
.globl  ml_kem_basemul_avx2
.type   ml_kem_basemul_avx2,\@function,3
.align 32
ml_kem_basemul_avx2:
.cfi_startproc
    lea     .Lzmodm(%rip), %rax
    mov     \$16, %r9d
___
$code .= basemul_body(".Lbasemul_loop", 0);
$code .= <<___;
.cfi_endproc
.size   ml_kem_basemul_avx2, .-ml_kem_basemul_avx2
___

###############################################################################
# ml_kem_basemul_acc_avx2
#
# Description:
#   NTT-domain base multiply-accumulate, semantically identical to
#   scalar_mult_add() in ml_kem.c:  out += l*r  in GF(q)[X]/(X^2 - kModRoots[i]).
#   Used by inner_product(), matrix_mult_intt() and matrix_mult_transpose_add()
#   for the second and later terms of each dot product, so that the ML-KEM
#   matrix/vector multiplications run on the AVX2 backend as well.
#
# Parameters:
#   rdi - uint16_t *out (canonical, read-modify-write)
#   rsi - const uint16_t *lhs (canonical)
#   rdx - const uint16_t *rhs (canonical)
###############################################################################
$code .= <<___;
.globl  ml_kem_basemul_acc_avx2
.type   ml_kem_basemul_acc_avx2,\@function,3
.align 32
ml_kem_basemul_acc_avx2:
.cfi_startproc
    lea     .Lzmodm(%rip), %rax
    mov     \$16, %r9d
___
$code .= basemul_body(".Lbasemul_acc_loop", 1);
$code .= <<___;
.cfi_endproc
.size   ml_kem_basemul_acc_avx2, .-ml_kem_basemul_acc_avx2
___

###############################################################################
# Data section
###############################################################################
$code .= ".section .rodata\n";
$code .= ".align 32\n.Lq16:\n"     . row16(($q) x 16);
$code .= ".align 32\n.Lqinv16:\n"  . row16(($qinv) x 16);
$code .= ".align 32\n.Lzetas_seq:\n" . row16(@zm16[1..15], 0);
$code .= ".align 32\n.Lzv8:\n";  $code .= row16(@{$_}) for @zv8;
$code .= ".align 32\n.Lzv4:\n";  $code .= row16(@{$_}) for @zv4;
$code .= ".align 32\n.Lzv2:\n";  $code .= row16(@{$_}) for @zv2;
$code .= ".align 32\n.Lizetas_seq:\n" . row16(@izm[113..127], 0);
$code .= ".align 32\n.Lizv8:\n"; $code .= row16(@{$_}) for @izv8;
$code .= ".align 32\n.Lizv4:\n"; $code .= row16(@{$_}) for @izv4;
$code .= ".align 32\n.Lizv2:\n"; $code .= row16(@{$_}) for @izv2;
$code .= ".align 32\n.Linvdeg16:\n" . row16(($invdeg_m) x 16);
$code .= ".align 32\n.Lshuf_even:\n" . rowbytes(@shuf_even);
$code .= ".align 32\n.Lshuf_odd:\n"  . rowbytes(@shuf_odd);
$code .= ".align 32\n.Lr2_16:\n"     . row16(($r2) x 16);
$code .= ".align 32\n.Lzmodm:\n";  $code .= row16(@{$_}) for @zmodrow;
$code .= ".text\n";

}}} else {{{
# When AVX2 is not available, output stub functions
# The capable function returns 0, and the operation functions trap if called
$code .= <<___;
.text

.globl  ml_kem_poly_avx2_capable
.type   ml_kem_poly_avx2_capable,\@abi-omnipotent
ml_kem_poly_avx2_capable:
    xor     %eax, %eax
    ret
.size   ml_kem_poly_avx2_capable, .-ml_kem_poly_avx2_capable

.globl  ml_kem_scalar_add_avx2
.globl  ml_kem_scalar_sub_avx2
.globl  ml_kem_ntt_avx2
.globl  ml_kem_intt_avx2
.globl  ml_kem_basemul_avx2
.globl  ml_kem_basemul_acc_avx2
.type   ml_kem_scalar_add_avx2,\@abi-omnipotent
ml_kem_scalar_add_avx2:
ml_kem_scalar_sub_avx2:
ml_kem_ntt_avx2:
ml_kem_intt_avx2:
ml_kem_basemul_avx2:
ml_kem_basemul_acc_avx2:
    .byte   0x0f,0x0b       # ud2
    ret
.size   ml_kem_scalar_add_avx2, .-ml_kem_scalar_add_avx2
___
}}}

print $code;
close STDOUT or die "error closing STDOUT: $!";
