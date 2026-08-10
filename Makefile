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

# Header dependencies, emitted as a side effect of every compile and included
# below. Without them a header edit rebuilds nothing: the object files are newer
# than the .c that did not change, so make has nothing to do and the tests run
# against the previous header. That is not a theoretical failure - a deliberately
# broken _Static_assert in a header was compiled away to a passing build here.
CFLAGS  += -MMD -MP
LDFLAGS ?=

# Address and UB sanitizers are the default for development: the whole parser
# runs on untrusted input, so the cheapest way to find the bug class that
# matters is to make a corpus run trip over it.
# -fno-sanitize-recover is not optional here. UndefinedBehaviorSanitizer defaults
# to printing a finding and carrying on, so a misaligned load or a signed overflow
# showed up as noise on stderr while every test still reported success - a safety
# net that reports green whatever it catches. Halting turns a finding into a failed
# build, which is the only form of it anyone acts on.
ifeq ($(SAN),1)
CFLAGS  += -fsanitize=address,undefined -fno-sanitize-recover=all \
           -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined -fno-sanitize-recover=all
endif

BUILD := build
SDK   := $(BUILD)/sdk

all: sdk $(BUILD)/kofscanner $(BUILD)/kofexamine $(BUILD)/ksigbuilder

$(BUILD):
	@mkdir -p $(BUILD)

# ------------------------------------------------------------ the flag stamp
#
# An object file does not record the flags it was built with, and make compares
# timestamps. So `make` followed by `make SAN=1` rebuilt nothing: every object was
# newer than its source, and the "sanitizer" run was a release binary reporting
# green. Same failure as missing header dependencies - a safety net that silently
# is not there - and it was caught by checking `ldd` for the sanitizer runtime,
# not by anything failing.
#
# Written by $(shell), which runs while the makefile is being read. That timing is
# the whole point: make decides what is out of date before it runs any recipe, so a
# stamp updated by a recipe updates it too late to matter.
FLAGSIG := $(CC) $(CFLAGS) $(LDFLAGS)
STAMP   := $(BUILD)/.flags

$(shell mkdir -p $(BUILD); \
	[ -f $(STAMP) ] && [ "$$(cat $(STAMP))" = "$(FLAGSIG)" ] || \
	printf '%s' '$(FLAGSIG)' > $(STAMP))

$(STAMP): ;

# ---------------------------------------------------------------- the library

LIB_SRC := libkofeng/kofeng.c \
           libkofeng/kofdb/kofdb.c \
           libkofeng/kofdb/kofpackw.c \
           libkofeng/kofmatchers/kofmatch.c \
           libkofeng/kofmatchers/hexcomp.c \
           libkofeng/kofparsers/binaries/elf_parse.c \
           libkofeng/kofparsers/binaries/pe_parse.c \
           libkofeng/kofparsers/containers/gzip_parse.c \
           libkofeng/kofdecomp/decomp.c \
           libkofeng/kofdecomp/inflate.c \
           libkofeng/kofdecomp/nrv2.c \
           libkofeng/kofscanners/scan.c \
           libkofeng/kofscanners/objctx.c \
           libkofeng/kofscanners/objsrc.c

LIB_OBJ := $(patsubst libkofeng/%.c,$(BUILD)/lib_%.o,$(LIB_SRC))
LIB     := $(SDK)/lib/libkofeng.a

$(BUILD)/lib_%.o: libkofeng/%.c $(STAMP) | $(BUILD)
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
           $(SDK)/include/kofmod/pe.h \
           $(SDK)/include/kofmod/gzip.h

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

$(BUILD)/kofscanner: $(SCANNER_SRC) $(LIB) $(SDK_HDR) $(STAMP)
	$(CC) $(CFLAGS) -I$(SDK)/include $(SCANNER_SRC) $(LIB) -o $@ $(LDFLAGS)

# --------------------------------------------------------------- the examiner
#
# Unlike the scanner, this links the internal collectors: it prints the parsed
# view, and no public surface offers one. The reason that is not a lapse is
# written at the top of the file.

$(BUILD)/kofexamine: kofexamine/kofexamine.c $(LIB) $(SDK_HDR) $(STAMP)
	$(CC) $(CFLAGS) -I$(SDK)/include $< $(LIB) -o $@ $(LDFLAGS)

# ----------------------------------------------------- the database toolchain
#
# One binary with two modes: --extract reads the declarations out of a signature
# source, and the default mode packs compiled artefacts into .ksig. Build-time
# only, and deliberately not linked into anything that runs on an endpoint.

$(BUILD)/ksigbuilder: ksigbuilder/ksigbuilder.c $(LIB) $(SDK_HDR) $(STAMP)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

# ------------------------------------------------------------- the database
#
# Compile every signature, then pack the artefacts.
#
# Parallelism lives here rather than inside either tool: one compile does not
# depend on another, xargs already knows how to run N at a time, and a --jobs
# flag in a C program would be a second implementation of one shell word.

# signatures/ holds detections meant to run on somebody's machine, and it is the
# only thing `make db` builds. Anything else - the engine's own test signatures in
# signature/, or a researcher's working set anywhere - is built by naming its
# directory:
#
#   make db                          the real signatures  -> build/signatures/db
#   make db SIGDIR=signature         the engine test set  -> build/signature/db
#   make db SIGDIR=~/work/mysigs     anywhere else        -> build/mysigs/db
#
# The work and output directories are DERIVED from SIGDIR rather than shared, and
# the artefact directory is emptied before each build. Both matter for one reason:
# ksigbuilder packs a DIRECTORY, not a list of files, so anything left in it from a
# previous run is in the database. Sharing one directory meant a test signature
# built five minutes ago was still in the next release build, and a detection
# deleted from the source kept shipping because its blob was never removed. Neither
# shows up as a failure - the build succeeds and the database is quietly wrong.
SIGDIR    ?= signatures
SIGSET    := $(notdir $(patsubst %/,%,$(SIGDIR)))
SIGS      := $(wildcard $(SIGDIR)/*.c)
JOBS      ?= 8
ARTEFACTS ?= $(BUILD)/$(SIGSET)/sig
DB        ?= $(BUILD)/$(SIGSET)/db

sigs: $(BUILD)/ksigbuilder $(SDK_HDR)
	@test -n "$(SIGS)" || { echo "make: no signature sources in $(SIGDIR)" >&2; \
		exit 2; }
	@rm -rf $(ARTEFACTS)
	@mkdir -p $(ARTEFACTS)
	@echo "$(SIGS)" | tr ' ' '\n' | KOF_OUTDIR=$(abspath $(ARTEFACTS)) \
		xargs -P $(JOBS) -n 1 ksigbuilder/ksigcompiler.sh >/dev/null

db: sigs $(BUILD)/ksigbuilder
	@rm -rf $(DB)
	@mkdir -p $(DB)
	@$(BUILD)/ksigbuilder $(ARTEFACTS) $(DB)
	@echo "   scan with: $(BUILD)/kofscanner --db $(DB) --scan-files <path>"

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
#
# UNIT_LIBS_<name> adds what one test needs. Only the differential decompressor
# test uses it: it links zlib as an ORACLE, to check our decoder against, which is
# the one thing the library must never do itself.
UNIT_LIBS_inflate_diff := -lz

$(BUILD)/unit_%: tests/unit/%.c $(LIB) $(STAMP) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

unit: $(UNIT_BIN)
	@rc=0; for t in $(UNIT_BIN); do \
		printf '%-28s ' "$$(basename $$t)"; \
		if $$t; then :; else rc=1; echo "  FAILED"; fi; \
	done; exit $$rc

# Everything -MMD wrote. Missing on a clean tree, which is why it is a soft
# include: nothing to rebuild yet, and the first compile creates them.
-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

clean:
	rm -rf $(BUILD)

.PHONY: all sdk sigs db unit clean