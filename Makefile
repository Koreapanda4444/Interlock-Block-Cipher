CC = cc
AR = ar
PYTHON = python3
CFLAGS = -O2
CPPFLAGS =
LDFLAGS =
WARN = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
INCLUDES = -Iinclude -Isrc

.PHONY: all check clean
all: build/kat

build:
	mkdir -p build

build/kat: tests/kat.c src/interlock_internal.h | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) tests/kat.c $(LDFLAGS) -o $@

check: build/kat
	./build/kat

clean:
	rm -rf build
