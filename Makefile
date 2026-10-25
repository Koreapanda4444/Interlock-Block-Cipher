CC = cc
AR = ar
PYTHON = python3
CFLAGS = -O2
CPPFLAGS =
LDFLAGS =
WARN = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
INCLUDES = -Iinclude -Isrc

.PHONY: all check clean
all: build/libinterlock.a

SOURCES = src/interlock.c src/shake256.c
HEADERS = include/interlock.h src/shake256.h src/interlock_internal.h

build:
	mkdir -p build

build/%.o: src/%.c $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -c $< -o $@

build/libinterlock.a: build/interlock.o build/shake256.o
	$(AR) rcs $@ $^

build/kat: tests/kat.c $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) tests/kat.c $(SOURCES) $(LDFLAGS) -o $@

check: build/kat
	./build/kat

clean:
	rm -rf build
