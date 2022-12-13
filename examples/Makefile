CC=gcc
CFLAGS=-I/Users/Paul/work/tmp/tongsuo/include
LDFLAGS=-L/Users/Paul/work/tmp/tongsuo/lib

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

perf: sm.o
	$(CC) -o sm sm.o -lcrypto $(LDFLAGS)

clean:
	rm -rf *.o sm
