#! /usr/bin/env perl
#
# Local gate for ML-DSA Win64 asm (cannot run full nmake test on Linux).
# For each crypto/ml_dsa/asm/*-x86_64.pl:
#   1) generate NASM
#   2) assemble with nasm -f win64
#   3) assert each Win64-geared entry (has SEH_begin_*) also saves xmm6
#      -- see ML_DSA_AVX_CI_PITFALLS.md section 4.4
#
# Usage (from Tongsuo tree):
#   ./util/check-ml-dsa-win64-asm.pl
#   perl util/check-ml-dsa-win64-asm.pl /path/to/outdir

use strict;
use warnings;
use File::Basename;
use File::Spec;
use File::Temp qw(tempdir);
use Cwd qw(abs_path);

my $top = abs_path(File::Spec->catdir(dirname($0), ".."));
my $asmdir = File::Spec->catdir($top, "crypto", "ml_dsa", "asm");
my $outdir = @ARGV ? $ARGV[0] : tempdir(CLEANUP => 1);
if (@ARGV) {
    mkdir $outdir or $!{EEXIST} or die "mkdir $outdir: $!";
}

my $nasm = $ENV{NASM} // "nasm";
die "nasm not found (set NASM=...)\n"
  if system("command -v $nasm >/dev/null 2>&1") != 0;

opendir my $dh, $asmdir or die "opendir $asmdir: $!";
my @pls = sort grep { /-x86_64\.pl\z/ } readdir $dh;
closedir $dh;

my $failed = 0;
foreach my $base (@pls) {
    my $pl = File::Spec->catfile($asmdir, $base);
    (my $stem = $base) =~ s/\.pl\z//;
    my $asm = File::Spec->catfile($outdir, "$stem.asm");
    my $obj = File::Spec->catfile($outdir, "$stem.obj");

    print "==> $base (nasm)\n";
    {
        open my $null, ">", File::Spec->devnull() or die $!;
        my $pid = fork();
        die "fork: $!" unless defined $pid;
        if ($pid == 0) {
            open STDOUT, ">&", $null;
            open STDERR, ">&", $null;
            exec $^X, $pl, "nasm", $asm;
            exit 127;
        }
        waitpid($pid, 0);
        if ($? != 0) {
            warn "FAIL: generate $pl\n";
            $failed++;
            next;
        }
    }
    {
        open my $null, ">", File::Spec->devnull() or die $!;
        my $pid = fork();
        die "fork: $!" unless defined $pid;
        if ($pid == 0) {
            open STDOUT, ">&", $null;
            open STDERR, ">&", $null;
            exec $nasm, "-Ox", "-f", "win64", "-DNEAR", "-o", $obj, $asm;
            exit 127;
        }
        waitpid($pid, 0);
        if ($? != 0) {
            warn "FAIL: nasm $asm\n";
            $failed++;
            next;
        }
    }

    open my $fh, "<", $asm or die "read $asm: $!";
    local $/;
    my $text = <$fh>;
    close $fh;

    # Entries that received xlate Win64 @function gearing.
    my @entries;
    while ($text =~ /\$L\$SEH_begin_(\w+):/g) {
        push @entries, $1;
    }

    if (!@entries) {
        print "OK  $base (no SEH entries - stub)\n";
        next;
    }

    my $file_fail = 0;
    foreach my $name (@entries) {
        my $pos = index($text, "\n$name:");
        if ($pos < 0) {
            warn "FAIL: $base: missing label for SEH entry $name\n";
            $file_fail = 1;
            next;
        }
        my $window = substr($text, $pos, 1600);
        if ($window !~ /mov\s+rdi,\s*rcx/i) {
            warn "FAIL: $base: $name missing mov rdi,rcx\n";
            $file_fail = 1;
        }
        my $has_xmm =
             ($window =~ /(?:v)?movaps\s+.*\bxmm6\b/i)
          || ($window =~ /XMMWORD(?:\s+PTR)?\[rsp\],\s*xmm6/i);
        my $has_frame =
             # 168 (0xa8) only: Win64 entry rsp≡8 mod 16; 176 leaves
             # rsp misaligned for vmovaps and faults under Wine/Win64.
             ($window =~ /lea\s+rsp,\s*(?:QWORD\s+PTR)?\[\(-168\)\+rax\]/i)
          || ($window =~ /lea\s+rsp,\s*(?:QWORD\s+PTR)?\[\(\(-168\)\)\+rax\]/i)
          || ($window =~ /lea\s+.*-168\(%rax\)/);
        if (!$has_xmm || !$has_frame) {
            warn "FAIL: $base: $name missing Win64 xmm6-15 save frame\n";
            $file_fail = 1;
        }
    }

    if ($file_fail) {
        $failed++;
    } else {
        my $n = scalar @entries;
        print "OK  $base ($n entries)\n";
    }
}

exit($failed ? 1 : 0);
