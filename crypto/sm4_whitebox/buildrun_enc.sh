#!/bin/bash -e

rm -f build/code.bin || true

CC=$(which tcc || which gcc || which clang)
"$CC" build/code.c -o build/code.bin

>./build/ciphertext.bin

echo "Encrypting..."
time ./build/code.bin <test_plaintext >./build/ciphertext.bin
# time ./build/code.bin <test_plaintext
echo

echo "Ciphertext:"
xxd ./build/ciphertext.bin
echo "true_ciphertext:"
xxd test_ciphertext
echo "Difference:"
diff <(xxd ./build/ciphertext.bin) <(xxd test_ciphertext)

echo ==========
