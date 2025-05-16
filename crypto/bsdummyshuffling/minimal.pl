#!/usr/bin/env perl

# Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

use strict;
use warnings;
use FindBin qw($RealBin);

my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;

my $python_script = "$RealBin/minimal.py"; 
my $result = qx(python "$python_script");
if ($? != 0) {
    die "minimal.py failed with exit code: $? and output: $result";
}


my $file = "$RealBin/bsdummyshuffling.c";

$output and open STDOUT,">$output";
open(my $fh, '<', $file) or die "Could not open file '$file' $!";
while (my $line = <$fh>) {
    print $line;
}