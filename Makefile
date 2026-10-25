CC = cc
AR = ar
PYTHON = python3
CFLAGS = -O2
CPPFLAGS =
LDFLAGS =
WARN = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
INCLUDES = -Iinclude -Isrc

.PHONY: all check check-c verify research research-check sanitize clean
all: build/libinterlock.a

SOURCES = src/interlock.c src/shake256.c
HEADERS = include/interlock.h src/shake256.h src/interlock_internal.h

build:
	mkdir -p build

build/%.o: src/%.c $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -c $< -o $@

build/libinterlock.a: build/interlock.o build/shake256.o
	$(AR) rcs $@ $^

build/kat: tests/kat.c tests/vectors.h tests/bridge.c tests/bridge.h $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) tests/kat.c tests/bridge.c $(SOURCES) $(LDFLAGS) -o $@

check-c: build/kat
	./build/kat

build/verify.so: tests/bridge.c tests/bridge.h $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -fPIC -shared tests/bridge.c $(SOURCES) $(LDFLAGS) -o $@

verify: build/verify.so
	$(PYTHON) tests/reference.py
	$(PYTHON) tests/verify.py

research-check: build/verify.so
	$(PYTHON) research/common.py
	$(PYTHON) research/support.py
	$(PYTHON) research/components.py
	$(PYTHON) research/addition.py
	$(PYTHON) research/differential.py --check
	$(PYTHON) research/symmetry.py --check
	$(PYTHON) research/integral.py --check
	$(PYTHON) research/suite.py --check

check: check-c verify research-check

research: build/verify.so
	$(PYTHON) research/suite.py

sanitize:
	$(MAKE) clean
	$(MAKE) check-c CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined"

clean:
	rm -rf build
