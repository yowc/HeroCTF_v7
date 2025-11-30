CC = gcc
CFLAGS = -g -O0 -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-function
LIBS = -lcrypto

all: cracker

cracker: main.c
	$(CC) $(CFLAGS) -o $@ main.c $(LIBS)

clean:
	rm -f cracker
