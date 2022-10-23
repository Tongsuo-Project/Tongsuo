CC=gcc
CFLAGS=-I/Users/Paul/work/tmp/tongsuo/include
LDFLAGS=-L/Users/Paul/work/tmp/tongsuo/lib

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -O2

perf: main.o
	$(CC) -o perf main.o -lcrypto $(LDFLAGS)

clean:
	rm -rf *.o perf
