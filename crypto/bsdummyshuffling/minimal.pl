#!/usr/bin/env perl
use strict;
use warnings;
use Cwd qw(getcwd);  # 导入 getcwd 函数

# 获取当前工作目录
my $current_dir = getcwd();

# 在当前目录前加上 minimal.py 的路径
my $script_path = "$current_dir/minimal.py";

# 执行 Python 脚本
my $result = qx(python $script_path);
if ($? != 0) {
    die "minimal.py failed with exit code: $? and output: $result";
}