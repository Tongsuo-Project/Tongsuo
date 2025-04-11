CC=gcc
CFLAGS=-I/Users/Paul/work/tmp/tongsuo/include
LDFLAGS=-L/Users/Paul/work/tmp/tongsuo/lib

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -O2

perf: perf.o
	$(CC) -o perf perf.o -lcrypto $(LDFLAGS)

clean:
	rm -rf *.o perf
