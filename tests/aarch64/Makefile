# Tests for the aarch64-only code of lazer (docs/RPI4.md). modred.h is plain
# C, so this test also runs on other architectures.
CC ?= cc
CFLAGS = -O2 -Wall -Wextra

.PHONY: check clean
check: modred-test
	./modred-test

modred-test: modred-test.c ../../src/modred.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f modred-test
