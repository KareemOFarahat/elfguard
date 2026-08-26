# elfguard — build
#
# A tool that grades hardening had better be hardened itself, so the release
# build enables every mitigation the tool reports on. `make check-self` audits
# the resulting binary with the binary.
#
# Note the split between REQUIRED and CFLAGS: the feature-test macros and the
# include path are not style choices, so they must survive a `make CFLAGS=...`
# override. Folding them into CFLAGS makes the asan target silently fail to
# compile — exactly the sort of thing you only discover by running it.

CC      ?= cc
PREFIX  ?= /usr/local

CFLAGS  ?= -O2 -g

REQUIRED = -std=c11 -Iinclude -D_FILE_OFFSET_BITS=64 -D_DEFAULT_SOURCE

WARN = -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
       -Wstrict-prototypes -Wcast-qual -Wpointer-arith -Wwrite-strings

# Hardening: canary, fortified libc, full RELRO, PIE, non-exec stack.
HARDEN_CFLAGS  ?= -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
HARDEN_LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie

ALL_CFLAGS  = $(REQUIRED) $(WARN) $(CFLAGS) $(HARDEN_CFLAGS) $(EXTRA_CFLAGS)
ALL_LDFLAGS = $(LDFLAGS) $(HARDEN_LDFLAGS) $(EXTRA_LDFLAGS)

SRC = src/image.c src/notes.c src/surface.c src/checks.c src/deps.c src/reason.c src/diff.c src/trend.c src/report.c src/main.c
OBJ = $(SRC:.c=.o)
BIN = elfguard

.PHONY: all clean install uninstall test asan check-self help

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(ALL_CFLAGS) -o $@ $(OBJ) $(ALL_LDFLAGS)

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# Sanitiser build, for throwing malformed ELFs at the parser. Hardening flags
# are dropped because ASan and _FORTIFY_SOURCE fight over the same intercepts.
asan: clean
	$(MAKE) HARDEN_CFLAGS= HARDEN_LDFLAGS= \
	        CFLAGS="-O1 -g -fno-omit-frame-pointer" \
	        EXTRA_CFLAGS="-fsanitize=address,undefined" \
	        EXTRA_LDFLAGS="-fsanitize=address,undefined"

test: $(BIN)
	@./tests/run_tests.sh

check-self: $(BIN)
	@./$(BIN) --explain ./$(BIN)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(OBJ) $(BIN)
	rm -rf tests/tmp

help:
	@echo "make             build"
	@echo "make test        run the test suite"
	@echo "make asan        build with ASan + UBSan"
	@echo "make check-self  audit elfguard with elfguard"
	@echo "make install     install to \$$PREFIX/bin (default /usr/local)"
