CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra
CPPFLAGS += -std=gnu11 -D_GNU_SOURCE -D_DARWIN_C_SOURCE -Isrc
LDLIBS    = -lpcap
PREFIX   ?= /usr/local

# macOS: Command Line Tools sometimes ship an SDK newer than Xcode's linker can
# read ("tapi error: malformed file"). Prefer the SDK that matches the toolchain.
ifeq ($(shell uname -s),Darwin)
SDKROOT ?= $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null)
export SDKROOT
endif

SRC    = $(wildcard src/*.c)
LIBSRC = $(filter-out src/main.c,$(SRC))
SAN    = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
FUZZ_TIME ?= 60

lan-devices: $(SRC) src/lan.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

tests/test_parsers: tests/test_parsers.c $(LIBSRC) src/lan.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_parsers.c $(LIBSRC) $(LDLIBS)

check: tests/test_parsers
	./tests/test_parsers

# Same tests under AddressSanitizer + UBSan.
check-asan: tests/test_parsers.c $(LIBSRC) src/lan.h
	$(CC) $(CPPFLAGS) $(SAN) -Wall -Wextra -o tests/test_parsers_asan tests/test_parsers.c $(LIBSRC) $(LDLIBS)
	ASAN_OPTIONS=detect_leaks=1 ./tests/test_parsers_asan

# libFuzzer over every parser. Needs clang with the fuzzer runtime
# (Linux: apt install clang; macOS: brew install llvm, then CC=$(brew --prefix llvm)/bin/clang).
fuzz: tests/fuzz_parsers.c tests/test_parsers $(LIBSRC) src/lan.h
	mkdir -p tests/corpus
	./tests/test_parsers --dump-corpus tests/corpus
	$(CC) $(CPPFLAGS) $(SAN) -fsanitize=fuzzer -o tests/fuzz_parsers tests/fuzz_parsers.c $(LIBSRC) $(LDLIBS)
	./tests/fuzz_parsers -max_total_time=$(FUZZ_TIME) -max_len=4096 tests/corpus

install: lan-devices
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 lan-devices $(DESTDIR)$(PREFIX)/bin/lan-devices

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/lan-devices

clean:
	rm -rf lan-devices tests/test_parsers tests/test_parsers_asan tests/fuzz_parsers tests/corpus *.dSYM tests/*.dSYM

.PHONY: check check-asan fuzz install uninstall clean
