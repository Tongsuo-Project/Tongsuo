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

# PE/COFF (mingw64 gas + NASM via xlate): gas dumps carry ELF .rodata.cst*
# section attrs that mingw as rejects; NASM path is fine via xlate rewrite but
# mingw64 flavour still emits gas. Also: only NASM/MASM want movslq->movsxd;
# mingw gas rejects xlate's movsxdl.
sub ml_dsa_prepare_pe_compat {
    my ($code, $flavour) = @_;
    $flavour = "" unless defined $flavour;

    if ($flavour =~ /nasm|masm/) {
        $code =~ s/\bmovslq\b/movsxd/g;
    }

    $code =~ s/^\s*\.section\s+\.rodata\S*/\t.section\t.rdata/mg;
    $code =~ s/^\s*\.section\s+\.data\.rel\.ro\S*/\t.section\t.rdata/mg;

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
