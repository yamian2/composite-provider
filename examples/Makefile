# Makefile for Examples
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I../src/common -I../src/kem -I../src/signature
LDFLAGS = -lcrypto

EXAMPLES = load_provider encoding_example

.PHONY: all clean

all: $(EXAMPLES)

load_provider: load_provider.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

encoding_example: encoding_example.c ../src/kem/composite_kem_encoding.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXAMPLES)
