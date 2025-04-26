#!/bin/bash -e

rm -f build/code.bin || true

CC=$(which tcc || which gcc || which clang)
"$CC" build/code.c -o build/code.bin

>./build/plaintext.bin

echo "Encrypting..."
time ./build/code.bin <test_ciphertext >./build/plaintext.bin
# time ./build/code.bin <test_plaintext
echo

echo "Plaintext:"
xxd ./build/plaintext.bin
echo "true_plaintext:"
xxd test_plaintext
echo "Difference:"
diff <(xxd ./build/plaintext.bin) <(xxd test_plaintext)

echo ==========
