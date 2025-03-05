Target:= main
CC=clang
CFALAGS= -Wall -Wextra
objs=wbsm4.o main.o

cins=wbsm4.c main.c 

head=wbsm4.h

all:$(Target)
	@echo "make done!"

$(Target):$(objs)
	$(CC) $^ -o $@

%.o: %.c $(head)
	$(CC) -c ${CFALAGS} $< -o $@


clean:
	rm -f $(objs)
