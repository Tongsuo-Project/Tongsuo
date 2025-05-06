#!/usr/bin/env perl 
use strict;
use warnings;

my $result = `pypy minimal.py`;  # 捕获标准错误 
if ($? != 0) {
    die "minimal.py  failed: $result";
}