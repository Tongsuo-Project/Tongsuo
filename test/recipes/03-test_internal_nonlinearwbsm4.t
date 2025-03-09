#! /usr/bin/env perl
use strict;
use warnings;
use OpenSSL::Test;              
use OpenSSL::Test::Simple;      
use OpenSSL::Test::Utils;      
# 初始化测试环境
setup("test_internal_nonlinearwbsm4");

# 运行测试
simple_test("test_internal_nonlinearwbsm4", "nonlinearwbsm4_internal_test", "nonlinearwbsm4");