CC = cc
AR = ar
PYTHON = python3
CFLAGS = -O2
CPPFLAGS =
RUNNER =
LDFLAGS =
WARN = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
INCLUDES = -Iinclude -Isrc

.PHONY: all check check-c verify research research-check smt-check smt-research ct-check fuzz-check fuzz measure sanitize clean
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
	$(RUNNER) ./build/kat

build/verify.so: tests/bridge.c tests/bridge.h $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -fPIC -shared tests/bridge.c $(SOURCES) $(LDFLAGS) -o $@

verify: build/verify.so
	$(PYTHON) tests/reference.py
	$(PYTHON) tests/verify.py

research-check: build/verify.so
	$(PYTHON) research/common.py
	$(PYTHON) research/support.py
	$(PYTHON) research/support.py --inverse
	$(PYTHON) research/components.py
	$(PYTHON) research/addition.py
	$(PYTHON) research/differential.py --check
	$(PYTHON) research/symmetry.py --check
	$(PYTHON) research/integral.py --check
	$(PYTHON) research/linear.py --check
	$(PYTHON) research/linear.py --cipher --check
	$(PYTHON) research/linear.py --cube --check
	$(PYTHON) research/boomerang.py --check
	$(PYTHON) research/boomerang.py --cipher --check
	$(PYTHON) research/algebra.py --check
	$(PYTHON) research/keys.py --check
	$(PYTHON) research/recovery.py --check
	$(PYTHON) research/suite.py --check

check: check-c verify research-check

research: build/verify.so
	$(PYTHON) research/suite.py

smt-check: build/verify.so
	$(PYTHON) research/smt.py --check
	$(PYTHON) research/smt.py --traces
	$(PYTHON) research/smt.py --pairs --check
	$(PYTHON) research/smt.py --count --check
	$(PYTHON) research/smt.py --search --check
	$(PYTHON) research/smt.py --recover --check
	$(PYTHON) research/smt.py --full --check
	$(PYTHON) research/smt_suite.py --check

smt-research: build/verify.so
	$(PYTHON) research/smt_suite.py

build/ctcheck: tests/ctcheck.c $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) tests/ctcheck.c $(SOURCES) $(LDFLAGS) -o $@

ct-check: build/ctcheck
	$(PYTHON) tests/ctcheck.py

build/fuzz-check: tests/fuzz.c $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -DIL_FUZZ_STANDALONE tests/fuzz.c $(SOURCES) $(LDFLAGS) -o $@

fuzz-check: build/fuzz-check
	$(RUNNER) ./build/fuzz-check

build/fuzz: tests/fuzz.c $(SOURCES) $(HEADERS) | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -fsanitize=fuzzer,address,undefined tests/fuzz.c $(SOURCES) $(LDFLAGS) -o $@

fuzz: build/fuzz
	mkdir -p build/fuzz-corpus
	./build/fuzz -seed=12345 -max_len=64 -runs=50000 -artifact_prefix=build/ build/fuzz-corpus

build/measure:
	mkdir -p $@

build/measure/%.o: src/%.c $(HEADERS) | build/measure
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -fstack-usage -c $< -o $@

build/measure/benchmark.o: research/benchmark.c include/interlock.h | build/measure
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARN) -fstack-usage -c $< -o $@

build/measure/libinterlock.a: build/measure/interlock.o build/measure/shake256.o
	$(AR) rcs $@ $^

build/measure/benchmark: build/measure/benchmark.o build/measure/libinterlock.a
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

measure: check-c build/measure/benchmark
	BENCH_CC="$(CC)" BENCH_CFLAGS="$(CFLAGS)" BENCH_CPPFLAGS="$(CPPFLAGS)" BENCH_LDFLAGS="$(LDFLAGS)" $(PYTHON) research/benchmark.py

sanitize:
	$(MAKE) clean
	$(MAKE) check-c fuzz-check CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined"

clean:
	rm -rf build
