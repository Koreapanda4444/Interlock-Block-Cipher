CC = cc
AR = ar
PYTHON = python3
CFLAGS = -O2
CPPFLAGS =
LDFLAGS =
WARN = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
INCLUDES = -Iinclude -Isrc

.PHONY: all check check-c verify research clean
all: build/libinterlock.a

SOURCES = src/interlock.c src/shake256.c
HEADERS = include/interlock.h src/shake256.h src/interlock_internal.h

build:
	mkdir -p build

build/%.o: src/%.c $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -c $< -o $@

build/libinterlock.a: build/interlock.o build/shake256.o
	$(AR) rcs $@ $^

build/kat: tests/kat.c tests/vectors.h $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) tests/kat.c $(SOURCES) $(LDFLAGS) -o $@

check-c: build/kat
	./build/kat

build/verify.so: tests/bridge.c $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -fPIC -shared tests/bridge.c $(SOURCES) $(LDFLAGS) -o $@

verify: build/verify.so
	$(PYTHON) tests/reference.py
	$(PYTHON) tests/verify.py

check: check-c verify

research: build/verify.so
	$(PYTHON) research/analyze.py

clean:
	rm -rf build
