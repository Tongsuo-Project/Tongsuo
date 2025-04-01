SHELL := /bin/bash

all: tools/runcircuit whitebox/libfastcircuit.so

tools/runcircuit: tools/runcircuit.c whitebox/fastcircuit.c whitebox/fastcircuit.h
	gcc -Wall -O3 -Iwhitebox/ whitebox/fastcircuit.c tools/runcircuit.c -o tools/runcircuit

whitebox/libfastcircuit.so: whitebox/fastcircuit.c whitebox/fastcircuit.h
	gcc -Wall -O3 -Iwhitebox/ whitebox/fastcircuit.c -fPIC -shared -o whitebox/libfastcircuit.so

clean:
	rm -f tools/runcircuit whitebox/libfastcircuit.so

submit:
	gcc -O3 build/submit.c build/main.c -o build/submit
	diff <(./build/submit <build/plain | xxd) <(xxd build/cipher)
