#! /usr/bin/env perl
#
# Shared Win64 callee-saved XMM helpers for ML-DSA AVX asm.
#
# x86_64-xlate.pl's \@function gearing remaps GP args (rcx→rdi, …) and sets
# %rax = entry %rsp, but does NOT save xmm6–15. Linux gas dumps and many
# handwritten kernels clobber ymm6–15; on Win64 that corrupts the caller's
# non-volatile XMM state and shows up as wrap.pl "Can't spawn".
#
# Pattern (after xlate prologue has set %rax = entry rsp):
#   - allocate 168 bytes below entry rsp (0xa8; Win64 entry rsp≡8 mod 16,
#     so rsp becomes 16-byte aligned for vmovaps — 176 leaves rsp≡8 and #GPs)
#   - stash entry rsp at 160(%rsp) so the body may clobber %rax
#   - vmovaps save xmm6–15 at 0..144(%rsp)
#   - body runs (further push/sub OK if balanced back to this frame)
#   - restore xmm6–15; mov 160(%rsp),%rsp; ret (xlate epilogue uses 8/16(entry))

use strict;
use warnings;

sub ml_dsa_win64_xmm_save_gas {
    return <<'___';
	lea	-168(%rax), %rsp
	movq	%rax, 160(%rsp)
	vmovaps	%xmm6, 0(%rsp)
	vmovaps	%xmm7, 16(%rsp)
	vmovaps	%xmm8, 32(%rsp)
	vmovaps	%xmm9, 48(%rsp)
	vmovaps	%xmm10, 64(%rsp)
	vmovaps	%xmm11, 80(%rsp)
	vmovaps	%xmm12, 96(%rsp)
	vmovaps	%xmm13, 112(%rsp)
	vmovaps	%xmm14, 128(%rsp)
	vmovaps	%xmm15, 144(%rsp)
___
}

sub ml_dsa_win64_xmm_restore_gas {
    return <<'___';
	vmovaps	0(%rsp), %xmm6
	vmovaps	16(%rsp), %xmm7
	vmovaps	32(%rsp), %xmm8
	vmovaps	48(%rsp), %xmm9
	vmovaps	64(%rsp), %xmm10
	vmovaps	80(%rsp), %xmm11
	vmovaps	96(%rsp), %xmm12
	vmovaps	112(%rsp), %xmm13
	vmovaps	128(%rsp), %xmm14
	vmovaps	144(%rsp), %xmm15
	movq	160(%rsp), %rsp
___
}

# Perlasm (spaces / no hard tabs); same layout as gas helpers.
sub ml_dsa_win64_xmm_save_pl {
    return <<'___';
    lea     -168(%rax), %rsp
    mov     %rax, 160(%rsp)
    vmovaps %xmm6,   0(%rsp)
    vmovaps %xmm7,   16(%rsp)
    vmovaps %xmm8,   32(%rsp)
    vmovaps %xmm9,   48(%rsp)
    vmovaps %xmm10,  64(%rsp)
    vmovaps %xmm11,  80(%rsp)
    vmovaps %xmm12,  96(%rsp)
    vmovaps %xmm13,  112(%rsp)
    vmovaps %xmm14,  128(%rsp)
    vmovaps %xmm15,  144(%rsp)
___
}

sub ml_dsa_win64_xmm_restore_pl {
    return <<'___';
    vmovaps 0(%rsp),   %xmm6
    vmovaps 16(%rsp),  %xmm7
    vmovaps 32(%rsp),  %xmm8
    vmovaps 48(%rsp),  %xmm9
    vmovaps 64(%rsp),  %xmm10
    vmovaps 80(%rsp),  %xmm11
    vmovaps 96(%rsp),  %xmm12
    vmovaps 112(%rsp), %xmm13
    vmovaps 128(%rsp), %xmm14
    vmovaps 144(%rsp), %xmm15
    mov     160(%rsp), %rsp
___
}

# Post-process xlate MASM output so ml64 accepts AVX2 gas dumps.
# xlate often tags VPMOVZX* sources as YMMWORD (dest width) and omits BYTE PTR
# on SETcc memory ops; MASM then raises A2070 / A2023.
sub ml_dsa_fixup_masm_asm_file {
    my ($file) = @_;
    open my $fh, '<', $file or die "can't read $file: $!";
    local $/;
    my $asm = <$fh>;
    close $fh or die "can't close $file: $!";

    # VPMOVZXBD ymm, mem64; VPMOVZXBW ymm, mem128; VPMOVZXWD ymm, mem128; etc.
    $asm =~ s/\bvpmovzxbd\s+(ymm\w+)\s*,\s*YMMWORD\s+PTR/vpmovzxbd\t$1,QWORD PTR/gi;
    $asm =~ s/\bvpmovzxbw\s+(ymm\w+)\s*,\s*YMMWORD\s+PTR/vpmovzxbw\t$1,XMMWORD PTR/gi;
    $asm =~ s/\bvpmovzxwd\s+(ymm\w+)\s*,\s*YMMWORD\s+PTR/vpmovzxwd\t$1,XMMWORD PTR/gi;
    $asm =~ s/\bvpmovzxdq\s+(ymm\w+)\s*,\s*YMMWORD\s+PTR/vpmovzxdq\t$1,XMMWORD PTR/gi;
    $asm =~ s/\bvpmovzxbd\s+(xmm\w+)\s*,\s*(?:XMMWORD|YMMWORD)\s+PTR/vpmovzxbd\t$1,DWORD PTR/gi;
    $asm =~ s/\bvpmovzxbw\s+(xmm\w+)\s*,\s*(?:XMMWORD|YMMWORD)\s+PTR/vpmovzxbw\t$1,QWORD PTR/gi;

    # SETcc [mem] -> SETcc BYTE PTR[mem]
    $asm =~ s/\b(set(?:n?[abceglopsz]|[abgs]e|n[abgs]e|[poc]))\s+\[/$1\tBYTE PTR[/gi;

    # MASM prefers [base+index*scale] over [index*scale+base]
    $asm =~ s/\[([re](?:[a-d]x|[sb]p|[sd]i)|r(?:8|9|1[0-5])|[re](?:[a-d]x|[sb]p|[sd]i)d?|r(?:8|9|1[0-5])d)\*([1248])\+([re](?:[a-d]x|[sb]p|[sd]i)|r(?:8|9|1[0-5]))\]/[$3+$1*$2]/g;

    open $fh, '>', $file or die "can't write $file: $!";
    print {$fh} $asm;
    close $fh or die "can't close $file: $!";
}

# PE/COFF (mingw64 gas + NASM via xlate): gas dumps carry ELF .rodata.cst*
# section attrs that mingw as rejects; NASM path is fine via xlate rewrite but
# mingw64 flavour still emits gas. Also: only NASM/MASM want movslq->movsxd;
# mingw gas rejects xlate's movsxdl.
#
# MASM: bare `.section .rdata` becomes `SEGMENT ... ALIGN(8)`. AVX2 constant
# tables use `.align 32`, which then hits A2189 ("invalid combination with
# segment alignment : 32"). Pass align=32 so xlate emits ALIGN(32).
sub ml_dsa_prepare_pe_compat {
    my ($code, $flavour) = @_;
    $flavour = "" unless defined $flavour;

    if ($flavour =~ /nasm|masm/) {
        $code =~ s/\bmovslq\b/movsxd/g;
    }

    if ($flavour =~ /masm/) {
        $code =~ s/^\s*\.section\s+\.rodata\S*/\t.section\t.rdata align=32/mg;
        $code =~ s/^\s*\.section\s+\.data\.rel\.ro\S*/\t.section\t.rdata align=32/mg;
    } else {
        $code =~ s/^\s*\.section\s+\.rodata\S*/\t.section\t.rdata/mg;
        $code =~ s/^\s*\.section\s+\.data\.rel\.ro\S*/\t.section\t.rdata/mg;
    }

    return $code;
}

# Inject save after each .globl entry and restore before each of its ret's.
# Call only on the Win64 prepare path (after .type normalization).
sub ml_dsa_inject_win64_xmm_save_restore {
    my ($code) = @_;
    my %globl;
    while ($code =~ /^\s*\.glob(?:l|al)\s+([A-Za-z_][\w]*)/mg) {
        $globl{$1} = 1;
    }
    return $code unless %globl;

    my $save = ml_dsa_win64_xmm_save_gas();
    my $restore = ml_dsa_win64_xmm_restore_gas();

    my @lines = split /(?<=\n)/, $code;
    my $out = "";
    my $in_globl = 0;
    my $need_save = 0;

    foreach my $line (@lines) {
        if ($line =~ /^([A-Za-z_][\w]*):/) {
            my $lab = $1;
            if ($globl{$lab}) {
                $in_globl = 1;
                $need_save = 1;
            } else {
                # Non-.L file-local helper: leave xmm framing to the .globl caller.
                $in_globl = 0 if $lab !~ /^\./;
                $need_save = 0;
            }
            $out .= $line;
            next;
        }

        # Skip assembler meta / local labels before the first real insn.
        if ($need_save) {
            if ($line =~ /^\s*$/
                || $line =~ /^\s*\./
                || $line =~ /^\s*endbr64\b/) {
                $out .= $line;
                next;
            }
            $out .= $save;
            $need_save = 0;
        }

        if ($in_globl && $line =~ /^\s*retq?\b/) {
            $out .= $restore;
        }
        $out .= $line;
    }

    return $out;
}

1;
