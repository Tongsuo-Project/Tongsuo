#! /bin/sh
# Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

set -e

error()
{
    echo ===========================================
    echo Create asm file FAIL!
    echo ===========================================
    exit 1
}

success()
{
    echo ===========================================
    echo Create asm file Sucess!
    echo ===========================================
    exit 0
}

mkdir -p prebuilts/crypto/aes/asm/arm32
mkdir -p prebuilts/crypto/bn/asm/arm32
mkdir -p prebuilts/crypto/chacha/asm/arm32
mkdir -p prebuilts/crypto/ec/asm/arm32
mkdir -p prebuilts/crypto/modes/asm/arm32
mkdir -p prebuilts/crypto/poly1305/asm/arm32
mkdir -p prebuilts/crypto/sha/asm/arm32
# for arm32:
perl crypto/aes/asm/aes-armv4.pl void prebuilts/crypto/aes/asm/arm32/aes-armv4.S
perl crypto/aes/asm/aesv8-armx.pl void prebuilts/crypto/aes/asm/arm32/aesv8-armx.S
perl crypto/aes/asm/bsaes-armv7.pl void prebuilts/crypto/aes/asm/arm32/bsaes-armv7.S
perl crypto/armv4cpuid.pl void prebuilts/crypto/armv4cpuid.S
perl crypto/bn/asm/armv4-gf2m.pl void prebuilts/crypto/bn/asm/arm32/armv4-gf2m.S
perl crypto/bn/asm/armv4-mont.pl void prebuilts/crypto/bn/asm/arm32/armv4-mont.S
perl crypto/chacha/asm/chacha-armv4.pl void prebuilts/crypto/chacha/asm/arm32/chacha-armv4.S
perl crypto/ec/asm/ecp_nistz256-armv4.pl void prebuilts/crypto/ec/asm/arm32/ecp_nistz256-armv4.S
perl crypto/modes/asm/ghash-armv4.pl void prebuilts/crypto/modes/asm/arm32/ghash-armv4.S
perl crypto/modes/asm/ghashv8-armx.pl void prebuilts/crypto/modes/asm/arm32/ghashv8-armx.S
perl crypto/poly1305/asm/poly1305-armv4.pl void prebuilts/crypto/poly1305/asm/arm32/poly1305-armv4.S
perl crypto/sha/asm/keccak1600-armv4.pl void prebuilts/crypto/sha/asm/arm32/keccak1600-armv4.S
perl crypto/sha/asm/sha1-armv4-large.pl void prebuilts/crypto/sha/asm/arm32/sha1-armv4-large.S
perl crypto/sha/asm/sha256-armv4.pl void prebuilts/crypto/sha/asm/arm32/sha256-armv4.S
perl crypto/sha/asm/sha512-armv4.pl void prebuilts/crypto/sha/asm/arm32/sha512-armv4.S

mkdir -p prebuilts/crypto/aes/asm/arm64
mkdir -p prebuilts/crypto/bn/asm/arm64
mkdir -p prebuilts/crypto/chacha/asm/arm64
mkdir -p prebuilts/crypto/ec/asm/arm64
mkdir -p prebuilts/crypto/modes/asm/arm64
mkdir -p prebuilts/crypto/poly1305/asm/arm64
mkdir -p prebuilts/crypto/sha/asm/arm64
# for arm64:
perl crypto/aes/asm/aesv8-armx.pl linux64 prebuilts/crypto/aes/asm/arm64/aesv8-armx.S
perl crypto/aes/asm/vpaes-armv8.pl linux64 prebuilts/crypto/aes/asm/arm64/vpaes-armv8.S
perl crypto/arm64cpuid.pl linux64 prebuilts/crypto/arm64cpuid.S
perl crypto/bn/asm/armv8-mont.pl linux64 prebuilts/crypto/bn/asm/arm64/armv8-mont.S
perl crypto/chacha/asm/chacha-armv8.pl linux64 prebuilts/crypto/chacha/asm/arm64/chacha-armv8.S
perl crypto/ec/asm/ecp_nistz256-armv8.pl linux64 prebuilts/crypto/ec/asm/arm64/ecp_nistz256-armv8.S
perl crypto/modes/asm/ghashv8-armx.pl linux64 prebuilts/crypto/modes/asm/arm64/ghashv8-armx.S
perl crypto/poly1305/asm/poly1305-armv8.pl linux64 prebuilts/crypto/poly1305/asm/arm64/poly1305-armv8.S
perl crypto/sha/asm/keccak1600-armv8.pl linux64 prebuilts/crypto/sha/asm/arm64/keccak1600-armv8.S
perl crypto/sha/asm/sha1-armv8.pl linux64 prebuilts/crypto/sha/asm/arm64/sha1-armv8.S
perl crypto/sha/asm/sha512-armv8.pl linux64 prebuilts/crypto/sha/asm/arm64/sha256-armv8.S
perl crypto/sha/asm/sha512-armv8.pl linux64 prebuilts/crypto/sha/asm/arm64/sha512-armv8.S

#need x86_64-linux-android-clang cross compile chain in your environment path,
#otherwise the generated asm files cannot be used
x86_64-linux-android-clang -v

mkdir -p prebuilts/crypto/aes/asm/x86_64
mkdir -p prebuilts/crypto/bn/asm/x86_64
mkdir -p prebuilts/crypto/chacha/asm/x86_64
mkdir -p prebuilts/crypto/ec/asm/x86_64
mkdir -p prebuilts/crypto/md5/asm/x86_64
mkdir -p prebuilts/crypto/modes/asm/x86_64
mkdir -p prebuilts/crypto/poly1305/asm/x86_64
mkdir -p prebuilts/crypto/rc4/asm/x86_64
mkdir -p prebuilts/crypto/sha/asm/x86_64
mkdir -p prebuilts/crypto/whrlpool/asm/x86_64
# for x86_64:
CC="x86_64-linux-android-clang" perl crypto/aes/asm/aesni-mb-x86_64.pl elf prebuilts/crypto/aes/asm/x86_64/aesni-mb-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/aes/asm/aesni-sha1-x86_64.pl elf prebuilts/crypto/aes/asm/x86_64/aesni-sha1-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/aes/asm/aesni-sha256-x86_64.pl elf prebuilts/crypto/aes/asm/x86_64/aesni-sha256-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/aes/asm/aesni-x86_64.pl elf prebuilts/crypto/aes/asm/x86_64/aesni-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/aes/asm/vpaes-x86_64.pl elf prebuilts/crypto/aes/asm/x86_64/vpaes-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/bn/asm/rsaz-avx2.pl elf prebuilts/crypto/bn/asm/x86_64/rsaz-avx2.s
CC="x86_64-linux-android-clang" perl crypto/bn/asm/rsaz-x86_64.pl elf prebuilts/crypto/bn/asm/x86_64/rsaz-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/bn/asm/x86_64-gf2m.pl elf prebuilts/crypto/bn/asm/x86_64/x86_64-gf2m.s
CC="x86_64-linux-android-clang" perl crypto/bn/asm/x86_64-mont.pl elf prebuilts/crypto/bn/asm/x86_64/x86_64-mont.s
CC="x86_64-linux-android-clang" perl crypto/bn/asm/x86_64-mont5.pl elf prebuilts/crypto/bn/asm/x86_64/x86_64-mont5.s
CC="x86_64-linux-android-clang" perl crypto/chacha/asm/chacha-x86_64.pl elf prebuilts/crypto/chacha/asm/x86_64/chacha-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/ec/asm/ecp_nistz256-x86_64.pl elf prebuilts/crypto/ec/asm/x86_64/ecp_nistz256-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/ec/asm/x25519-x86_64.pl elf prebuilts/crypto/ec/asm/x86_64/x25519-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/md5/asm/md5-x86_64.pl elf prebuilts/crypto/md5/asm/x86_64/md5-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/modes/asm/aesni-gcm-x86_64.pl elf prebuilts/crypto/modes/asm/x86_64/aesni-gcm-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/modes/asm/ghash-x86_64.pl elf prebuilts/crypto/modes/asm/x86_64/ghash-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/poly1305/asm/poly1305-x86_64.pl elf prebuilts/crypto/poly1305/asm/x86_64/poly1305-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/rc4/asm/rc4-md5-x86_64.pl elf prebuilts/crypto/rc4/asm/x86_64/rc4-md5-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/rc4/asm/rc4-x86_64.pl elf prebuilts/crypto/rc4/asm/x86_64/rc4-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/sha/asm/keccak1600-x86_64.pl elf prebuilts/crypto/sha/asm/x86_64/keccak1600-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/sha/asm/sha1-mb-x86_64.pl elf prebuilts/crypto/sha/asm/x86_64/sha1-mb-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/sha/asm/sha1-x86_64.pl elf prebuilts/crypto/sha/asm/x86_64/sha1-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/sha/asm/sha256-mb-x86_64.pl elf prebuilts/crypto/sha/asm/x86_64/sha256-mb-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/sha/asm/sha512-x86_64.pl elf prebuilts/crypto/sha/asm/x86_64/sha256-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/sha/asm/sha512-x86_64.pl elf prebuilts/crypto/sha/asm/x86_64/sha512-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/whrlpool/asm/wp-x86_64.pl elf prebuilts/crypto/whrlpool/asm/x86_64/wp-x86_64.s
CC="x86_64-linux-android-clang" perl crypto/x86_64cpuid.pl elf prebuilts/crypto/x86_64cpuid.s
if [ $? -ne 0 ]; then
    error
else
    success
fi
