#!/usr/bin/env perl
use strict;
use warnings;


use FindBin qw($RealBin);
my $python_script = "$RealBin/minimal.py"; 
my $result = qx(python "$python_script");
if ($? != 0) {
    die "minimal.py failed with exit code: $? and output: $result";
}

