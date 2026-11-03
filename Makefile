CC      ?= cc
CFLAGS   ?= -O2 -Wall -Wextra
CPPFLAGS += -std=gnu11 -D_GNU_SOURCE -D_DARWIN_C_SOURCE
LDLIBS   = -lpcap -lpthread
PREFIX  ?= /usr/local

# macOS: Command Line Tools sometimes ship an SDK newer than Xcode's linker can
# read ("tapi error: malformed file"). Prefer the SDK that matches the toolchain.
ifeq ($(shell uname -s),Darwin)
SDKROOT ?= $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null)
export SDKROOT
endif
SRC      = $(wildcard src/*.c)

lan-devices: $(SRC) src/lan.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

install: lan-devices
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 lan-devices $(DESTDIR)$(PREFIX)/bin/lan-devices

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/lan-devices

clean:
	rm -f lan-devices

.PHONY: install uninstall clean
