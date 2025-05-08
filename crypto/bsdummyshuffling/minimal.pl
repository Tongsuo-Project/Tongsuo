#!/usr/bin/env perl
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
# if (-z $file) {
#     print STDERR "'$file' empty\n";
# } else {
#     print STDERR "'$file' !empty\n";
# }

$output and open STDOUT,">$output";
open(my $fh, '<', $file) or die "Could not open file '$file' $!";
while (my $line = <$fh>) {
    print $line;
}