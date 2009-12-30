
CC=gcc
CFLAGS=-c -Wall -O3
LDFLAGS= -O3
SOURCES=aeslib.c aesenc.c aesdec.c
OBJECTS=$(SOURCES:.c=.o)

all: $(SOURCES) aesenc aesdec

clean:
	rm *.o aesenc aesdec

aesenc: aeslib.o aesenc.o 
	$(CC) $(LDFLAGS) aeslib.o aesenc.o -o $@

aesdec: aeslib.o aesdec.o 
	$(CC) $(LDFLAGS) aeslib.o aesdec.o -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@


