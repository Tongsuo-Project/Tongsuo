#! /usr/bin/env perl
use strict;
use warnings;
use OpenSSL::Test;              
use OpenSSL::Test::Simple;      
use OpenSSL::Test::Utils;      

setup("test_internal_nonlinearwbsm4");

simple_test("test_internal_nonlinearwbsm4", "nonlinearwbsm4_internal_test", "nonlinearwbsm4");