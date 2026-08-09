# kofeng - build the SDK, the scanner, and the database toolchain.
#
# Three products and nothing else:
#
#   sdk         libkofeng.a plus the two public headers, staged under build/sdk
#   kofscanner  the scanner, built against that SDK and nothing else
#   db          signatures compiled and packed into .ksig
#
# Signature modules are NOT built with these flags: they are freestanding,
# position independent blobs produced by ksigbuilder/ksigcompiler.sh with its own
# flag set, and mixing the two sets in one place is how they end up applied to the
# wrong target.

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion \
           -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
           -fno-common -Ilibkofeng/core
LDFLAGS ?=

# Address and UB sanitizers are the default for development: the whole parser
# runs on untrusted input, so the cheapest way to find the bug class that
# matters is to make a corpus run trip over it.
ifeq ($(SAN),1)
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

BUILD := build
SDK   := $(BUILD)/sdk

all: sdk $(BUILD)/kofscanner $(BUILD)/ksigbuilder $(BUILD)/kofpat

$(BUILD):
	@mkdir -p $(BUILD)

# ---------------------------------------------------------------- the library

LIB_SRC := libkofeng/kofeng.c \
           libkofeng/kofdb/kofdb.c \
           libkofeng/kofdb/kofpackw.c \
           libkofeng/kofmatchers/kofmatch.c \
           libkofeng/kofparsers/elf/elf_parse.c \
           libkofeng/kofparsers/pe/pe_parse.c \
           libkofeng/kofscanners/scan.c \
           libkofeng/kofscanners/objctx.c

LIB_OBJ := $(patsubst libkofeng/%.c,$(BUILD)/lib_%.o,$(LIB_SRC))
LIB     := $(SDK)/lib/libkofeng.a

$(BUILD)/lib_%.o: libkofeng/%.c | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJ)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

# ------------------------------------------------------------------- the SDK
#
# Two public surfaces with different audiences, kept apart by path rather than by
# a note asking people to be careful:
#
#   <kofeng.h>            a host that wants to scan things
#   <kofmod/kofsig.h>     a signature module, which is a different ABI entirely
#
# Everything else under libkofeng is internal and is deliberately absent here, so
# reaching for it is a compile error rather than a habit. That is the constraint
# kofscanner is already built under, applied to anyone outside this tree.

SDK_HDR := $(SDK)/include/kofeng.h \
           $(SDK)/include/kofmod/kofsig.h \
           $(SDK)/include/kofmod/elf.h \
           $(SDK)/include/kofmod/pe.h

$(SDK)/include/kofeng.h: libkofeng/kofeng.h
	@mkdir -p $(dir $@)
	@cp $< $@

$(SDK)/include/kofmod/%.h: libkofeng/core/kofmod/%.h
	@mkdir -p $(dir $@)
	@cp $< $@

sdk: $(LIB) $(SDK_HDR)

# --------------------------------------------------------------- the scanner
#
# Built from the staged SDK, not from the source tree. That is what keeps the
# public header honest: anything it cannot express shows up here as a compile
# error instead of as a quiet reach into an internal include.

SCANNER_SRC := kofscanner/kofscanner.c

$(BUILD)/kofscanner: $(SCANNER_SRC) $(LIB) $(SDK_HDR)
	$(CC) $(CFLAGS) -I$(SDK)/include $(SCANNER_SRC) $(LIB) -o $@ $(LDFLAGS)

# ----------------------------------------------------- the database toolchain
#
# kofpat compiles the patterns written in a signature source; ksigbuilder packs
# the artefacts into .ksig. Both are build-time only and are deliberately not
# linked into anything that runs on an endpoint.

$(BUILD)/kofpat: tools/kofpat/main.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD)/ksigbuilder: ksigbuilder/ksigbuilder.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

# ------------------------------------------------------------- the database
#
# Compile every signature, then pack the artefacts.
#
# Parallelism lives here rather than inside either tool: one compile does not
# depend on another, xargs already knows how to run N at a time, and a --jobs
# flag in a C program would be a second implementation of one shell word.

# signatures/ holds detections meant to run on somebody's machine; signature/ holds
# the ones that exist to exercise the engine. The default is the real set, because a
# default pointing at the test set is a default that ships wrong exactly once.
#
#   make db                     the real signatures
#   make db SIGDIR=signature    the test set
SIGDIR    ?= signatures
SIGS      := $(wildcard $(SIGDIR)/*.c)
JOBS      ?= 8
ARTEFACTS ?= $(BUILD)/sig
DB        ?= $(BUILD)/db

sigs: $(BUILD)/kofpat $(SDK_HDR)
	@mkdir -p $(ARTEFACTS)
	@echo "$(SIGS)" | tr ' ' '\n' | KOF_OUTDIR=$(abspath $(ARTEFACTS)) \
		xargs -P $(JOBS) -n 1 ksigbuilder/ksigcompiler.sh >/dev/null

db: sigs $(BUILD)/ksigbuilder
	@mkdir -p $(DB)
	@$(BUILD)/ksigbuilder $(ARTEFACTS) $(DB)

# ------------------------------------------------------------------- testing
#
# Exhaustive differential checks over small inputs, for the routines where a
# corpus run would pass while the code is still wrong on an input the corpus does
# not happen to contain. Each is a standalone program that exits non-zero on
# failure, so this target is usable from CI. Not part of `all`.

UNIT_SRC := $(wildcard tests/unit/*.c)
UNIT_BIN := $(patsubst tests/unit/%.c,$(BUILD)/unit_%,$(UNIT_SRC))

# Linked against the library, so a unit test can exercise it rather than only
# whatever it can compile in on its own.
$(BUILD)/unit_%: tests/unit/%.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

unit: $(UNIT_BIN)
	@rc=0; for t in $(UNIT_BIN); do \
		printf '%-28s ' "$$(basename $$t)"; \
		if $$t; then :; else rc=1; echo "  FAILED"; fi; \
	done; exit $$rc

clean:
	rm -rf $(BUILD)

.PHONY: all sdk sigs db unit clean