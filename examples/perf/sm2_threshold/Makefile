CC=gcc
CFLAGS=-I/opt/tongsuo/include
LDFLAGS=-L/opt/tongsuo/lib

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -O2

threshold: threshold.o
	$(CC) -o threshold threshold.o -lcrypto $(LDFLAGS)

clean:
	rm -rf *.o threshold
