#!/usr/bin/env perl
use strict;
use warnings;

my $result = qx(python2 crypto/bsdummyshuffling/minimal.py);
if ($? != 0) {
    die "minimal.py failed with exit code: $? and output: $result";
}