# kofeng - build the SDK, the scanner, and the database toolchain.
#
# Three products and nothing else:
#
#   sdk         libkofeng.a plus the public headers, staged under build/release
#   kofscanner  the scanner, built against that SDK and nothing else
#   db          bases compiled and packed into .ksig
#
#
# WHERE THINGS LAND
#
#   build/release  the product. Everything shippable and nothing else, so
#                  packaging is a copy of one directory rather than a list of
#                  paths that has to be kept in step with this file.
#   build/temp     intermediates: object files, dependency files, compiled base
#                  artefacts. Disposable by definition - deleting it costs a
#                  rebuild and nothing else.
#   build/test     test binaries and their working directories, kept out of the
#                  product so a test artefact cannot be shipped by accident.
#
# One caveat about the name: SAN=1 builds into these same directories, so
# build/release then holds sanitizer binaries. The flag stamp below makes sure they
# are REBUILT rather than mixed, so nothing is ever half one and half the other -
# but the directory is named after what it is for, not after how it was compiled.
#
# Signature modules are NOT built with these flags: they are freestanding,
# position independent blobs produced by ksigbuilder/ksigcompiler.sh with its own
# flag set, and mixing the two sets in one place is how they end up applied to the
# wrong target.

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -g
# The parallel walk in scan.c is pthreads. On this glibc the symbols are in libc
# and the link succeeds without it - measured, the flag changes the scan's speed
# by nothing either way - so it is here for the platforms where the link needs
# it rather than for anything it does on this one.
LDFLAGS += -pthread
CFLAGS  += -std=c11 -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion \
           -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
           -fno-common -Ilibkofeng/core

# A second tier of warnings, probed rather than assumed.
#
# The tree passes every one of these today with zero findings - that was
# measured across the engine, the four tools and every module, and the one
# violation it did turn up (a cast that dropped const in objctx.c) was fixed
# rather than excluded. Turning them on is therefore free right now, and the
# point of doing it is that it stops being free the moment somebody writes the
# thing they catch. A flag nobody enables protects nothing.
#
# Probed because this tree is built by more than one compiler: the Windows
# targets go through clang, and four of these are GCC's alone. An unknown -W
# option is an error to both, so each group is offered to the compiler in hand
# and dropped if it is not understood. That is why they are two lists and not
# one - losing the portable ten because clang lacks -Wlogical-op would be the
# worst of both.
KOF_WARN_PORTABLE := -Wcast-qual -Wwrite-strings -Wredundant-decls \
                     -Wmissing-declarations -Wundef -Wdouble-promotion \
                     -Wformat=2 -Wnull-dereference -Wcast-align -Wvla \
                     -Wshift-overflow=2 -Wold-style-definition
KOF_WARN_GCC      := -Wduplicated-cond -Wduplicated-branches -Wlogical-op \
                     -Wjump-misses-init

kof_probe = $(shell $(CC) -Werror $(1) -xc -c /dev/null -o /dev/null \
                    >/dev/null 2>&1 && printf '%s' "$(1)")

CFLAGS  += $(call kof_probe,$(KOF_WARN_PORTABLE)) \
           $(call kof_probe,$(KOF_WARN_GCC))

# Windows only: two problems neither POSIX convention nor this tree's own layout
# solves by itself, both worth fixing once here rather than in every recipe.
#
# TMP/TEMP, not TMPDIR. A linked binary needs a place to put its intermediates,
# and the native (non-MSYS) compiler that builds one on this target reads the
# Windows convention for that, not the POSIX one - TMPDIR is invisible to it
# however it is set. Worse, this shell's own TMP/TEMP do not reliably reach a
# recipe's child process at all: verified by printing them from inside a plain
# `bash -c` child spawned from a shell that had just exported them, empty on the
# other side. Exporting a real Windows path here, once, is unaffected by
# whatever the invoking shell did or did not pass through, because this
# Makefile now owns setting it rather than inheriting it.
#
# EXE - the suffix a linked image on this target gets REGARDLESS of what -o
# asked for: clang/lld-link append .exe to the file they write however $@ is
# spelled, so a target that did not already expect it would build a file make
# can never find and relink forever.
#
# Named here rather than papered over with a rename, because the far side of
# that rename is worse than the problem it hides: PowerShell and cmd.exe both
# refuse to start a program with no recognised extension at all - "cannot run
# a document" - and this project's users are exactly as likely to invoke
# kofscanner from a PowerShell prompt as from this Makefile. Every place in
# this tree that names one of these binaries - the targets below,
# ksigcompiler.sh's KOF_KSIGBUILDER default - spells $(EXE) after it instead.
#
# -pthread: clock_gettime is POSIX and every host tool that times a scan uses
# it, but on this target it resolves through winpthreads' pthread_time.h, and
# without this flag the link fails on an undefined clock_gettime64 rather than
# on anything this tree's own code did wrong.
#
# -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic: -pthread alone links libwinpthread-1.dll
# in dynamically, which is only ever on PATH inside an MSYS2 install - anyone who
# runs the built .exe from a plain PowerShell or cmd prompt gets no error and no
# output at all, because Windows refuses to start a process whose DLL cannot be
# found before main() ever runs; there is nothing to print if nothing started.
# Static linking just this one library removes the dependency - `ldd` on the
# result names only ntdll/KERNEL32/KERNELBASE/ucrtbase, which are already on
# every Windows install - while leaving the rest of the flag ordinary, since a
# tool is either fully dynamic or this is what breaks: -Bstatic/-Bdynamic are a
# stack, not a toggle, so only what is between them is affected.
#
# Detected via $(OS), not `uname`: $(OS) is a real environment variable every
# process on this platform inherits straight from the kernel, so it is there
# whatever else is or is not on PATH. `uname` is itself a POSIX tool that has
# to be found on PATH first - on a plain GNU Make install with no MSYS2/Git
# POSIX tools anywhere near PATH, `$(shell uname -s ...)` silently returns
# nothing, this whole block silently never activates, and every fix above
# (TMP/TEMP, .exe, static winpthread) silently does not apply. A check that
# depends on the exact class of tool this block exists to work around is not
# a check that survives the case it is meant to catch.
ifeq ($(OS),Windows_NT)
NATIVE_OS   := windows
EXE         := .exe
# GNU Make's own documented fallback when it cannot find a POSIX shell is
# cmd.exe - not a build failure, a different program entirely reading this
# Makefile, understanding none of its syntax. Every recipe then fails with
# cmd.exe's own error text ("The system cannot find the path specified",
# "'printf' is not recognized as an internal or external command") which
# names nothing about the real cause. This is exactly what a plain `make`
# install with no bundled POSIX shell (e.g. the ezwinports.make WinGet
# package) hits with zero MSYS2/Git-for-Windows tools on PATH. Checked once,
# explicitly, so the failure is one clear message instead of a build log full
# of recipe errors that look like unrelated bugs.
ifneq ($(shell sh -c "echo ok" 2>&1),ok)
$(error No working POSIX shell (sh.exe) found on PATH - this Makefile's \
recipes need one to run, and GNU Make silently falls back to cmd.exe \
without it, which cannot run them. Install MSYS2 (https://www.msys2.org/) \
and add its usr\bin (e.g. C:\msys64\usr\bin) to PATH, then retry. A C \
compiler also needs to be reachable the same way, e.g. \
C:\msys64\clangarm64\bin or C:\msys64\mingw64\bin)
endif
WINTMP      := $(shell cygpath -w "$(CURDIR)/build/temp" 2>/dev/null)
export TMP  := $(WINTMP)
export TEMP := $(WINTMP)
CFLAGS      += -pthread -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic
# Every signature blob this engine ever loads is x86_64 machine code, always,
# on every host - deliberate, see ksigcompiler.sh, since a database has to be
# one thing every scanner can load rather than a matrix of per-arch builds.
# A host tool that is not ALSO x86_64 cannot run one: jumping into raw
# x86_64 bytes from a differently-arched native process is an illegal
# instruction, not a slow path or a wrong answer, so nothing short of
# actually scanning a real object surfaces it - reproduced here as an
# immediate STATUS_ILLEGAL_INSTRUCTION (0xC000001D) on the first object any
# real scan reached, on a build that had linked and packed cleanly.
#
# Asked of the compiler itself (-dumpmachine), not the host CPU
# ($(PROCESSOR_ARCHITECTURE)): that variable reflects the architecture of
# the process reading it, and both this machine's own make.exe and the
# ezwinports one are x86-64 (or x86) binaries running under Windows's own
# emulation on ARM64 hardware - so from inside either one, PROCESSOR_ARCHITECTURE
# reads "AMD64" even though the only compiler actually installed
# (clangarm64) is genuinely ARM64-native and reports aarch64-w64-windows-gnu
# from -dumpmachine regardless of what emulated make invoked it. The
# compiler is the one thing here that cannot lie about what it targets.
#
# The fix is cross-compiling the host tools too, the same way
# ksigcompiler.sh already cross-compiles every blob: clang is a cross
# compiler by construction, so the only extra ingredient is an x86_64
# mingw-w64 sysroot (headers/crt/import libs) alongside whatever native one
# came with the compiler - KOF_X86_SYSROOT points at it, overridable for an
# MSYS2 install anywhere other than the default C:\msys64. Verified end to
# end on real ARM64 Windows hardware: a hosted hello-world built this way
# ran correctly under Windows's x64 emulation, and so did the full scanner
# against a real PE, where the native-ARM64 build had crashed instantly.
CC_MACHINE := $(shell $(CC) -dumpmachine 2>/dev/null)
ifeq ($(findstring x86_64,$(CC_MACHINE)),)
KOF_X86_SYSROOT ?= C:/msys64/mingw64
CFLAGS      += -target x86_64-w64-windows-gnu --sysroot=$(KOF_X86_SYSROOT) -fuse-ld=lld
endif
else
NATIVE_OS   := $(shell uname -s 2>/dev/null)
EXE         :=
endif

# Header dependencies, emitted as a side effect of every compile and included
# below. Without them a header edit rebuilds nothing: the object files are newer
# than the .c that did not change, so make has nothing to do and the tests run
# against the previous header. That is not a theoretical failure - a deliberately
# broken _Static_assert in a header was compiled away to a passing build here.
CFLAGS  += -MMD -MP

# Where the dependency files go.
#
# -MMD writes the .d beside the -o output, which for a linked binary means beside
# the PRODUCT. Intermediates in build/release defeat the only thing that directory
# is for - being copyable as-is - so every link redirects its .d into build/temp.
# The library objects already compile into build/temp and need no help.
DEPTO    = -MF $(INT)/dep-$(notdir $@).d
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
SAN_CFLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all \
              -fno-omit-frame-pointer
CFLAGS  += $(SAN_CFLAGS)
LDFLAGS += -fsanitize=address,undefined -fno-sanitize-recover=all
endif

# SAN=thread instead, for the parallel walk. A separate switch rather than a
# third value folded into the one above, because ThreadSanitizer cannot be
# combined with AddressSanitizer - asking for both is a build that does not
# link, and a build system should refuse that by construction rather than at
# the link step.
ifeq ($(SAN),thread)
CFLAGS  += -fsanitize=thread -fno-omit-frame-pointer
LDFLAGS += -fsanitize=thread
endif

BUILD := build
OUT   := $(BUILD)/release
INT   := $(BUILD)/temp
TEST  := $(BUILD)/test
SDK   := $(OUT)

all: sdk tools databases

# ------------------------------------------------------- building one tool
#
# Each tool by its own name, declared phony, and each with a recipe. All three
# details are load bearing and each fixes a different half of the same problem.
#
# There is a DIRECTORY called kofscanner in this tree, and one called kofexamine,
# and one called ksigbuilder. Without a rule, `make kofscanner` matched the
# DIRECTORY, found nothing to do for it and said so - from a clean tree it built
# no binary and reported success. Phony makes the name mean the tool.
#
# The recipe is what makes that visible. A target with prerequisites and no recipe
# still prints "Nothing to be done" once its prerequisites are built, which is the
# same sentence the broken version printed - so a working build and a build that
# does nothing were indistinguishable from the outside. Saying what exists costs a
# line and removes the ambiguity entirely.
kofscanner:  $(OUT)/bin/kofscanner$(EXE)
	@echo "  $<"
kofexamine:  $(OUT)/bin/kofexamine$(EXE)
	@echo "  $<"
ksigbuilder: $(OUT)/bin/ksigbuilder$(EXE)
	@echo "  $<"
kofviewer:   $(OUT)/bin/kofviewer$(EXE)
	@echo "  $<"

tools: kofscanner kofexamine ksigbuilder kofviewer

help:
	@echo "targets:"
	@echo "  all           the SDK, all three tools and the databases  (default)"
	@echo "  sdk           libkofeng.a and the public headers"
	@echo "  kofscanner    the scanner"
	@echo "  kofexamine    the file examiner"
	@echo "  ksigbuilder   the database builder"
	@echo "  kofviewer     the file examiner, navigable"
	@echo "  tools         all four of the above"
	@echo "  databases     compile bases/ into the shipping databases"
	@echo "                                                 -> $(OUT)/databases"
	@echo "  databases BASEDIR=D   compile D instead        -> $(TEST)/databases-<name>"
	@echo "  unit          build and run the tests"
	@echo "  fixtures      build the binaries the tests parse"
	@echo "  clean         remove $(BUILD)"

$(BUILD) $(OUT) $(INT) $(TEST):
	@mkdir -p $@

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
STAMP   := $(INT)/.flags

$(shell mkdir -p $(INT); \
	[ -f $(STAMP) ] && [ "$$(cat $(STAMP))" = "$(FLAGSIG)" ] || \
	printf '%s' '$(FLAGSIG)' > $(STAMP))

$(STAMP): ;

# ---------------------------------------------------------------- the library

LIB_SRC := libkofeng/kofeng.c \
           libkofeng/kofdb/kofdb.c \
           libkofeng/kofdb/kofpackw.c \
           libkofeng/kofheur/kofheur.c \
           libkofeng/kofmatchers/kofmatch.c \
           libkofeng/kofmatchers/hexcomp.c \
           libkofeng/kofparsers/binaries/elf_parse.c \
           libkofeng/kofparsers/binaries/elf_sym.c \
           libkofeng/kofparsers/binaries/pe_parse.c \
           libkofeng/kofparsers/containers/gzip_parse.c \
           libkofeng/kofparsers/containers/docole_parse.c \
           libkofeng/kofparsers/containers/zip_parse.c \
           libkofeng/kofparsers/containers/tar_parse.c \
           libkofeng/kofparsers/containers/sevenzip_parse.c \
           libkofeng/kofparsers/containers/rar_parse.c \
           libkofeng/kofparsers/containers/xz_parse.c \
           libkofeng/kofparsers/containers/rtf_parse.c \
           libkofeng/kofparsers/containers/pdf_parse.c \
           libkofeng/kofunpack/pe_rebuild.c \
           libkofeng/kofunpack/emu_unpack.c \
           libkofeng/kofunpack/elf_rebuild.c \
           libkofeng/kofunpack/embedded.c \
           libkofeng/kofdecomp/decomp.c \
           libkofeng/kofdecomp/inflate.c \
           libkofeng/kofdecomp/ovba.c \
           libkofeng/kofdecomp/bcj.c \
           libkofeng/kofdecomp/bcj2.c \
           libkofeng/kofdecomp/ppmd.c \
           libkofeng/kofdecomp/rar3.c \
           libkofeng/kofdecomp/rar5.c \
           libkofeng/kofdecomp/lzma.c \
           libkofeng/kofdecomp/nrv2.c \
           libkofeng/kofscanners/scan.c \
           libkofeng/kofscanners/objctx.c \
           libkofeng/kofscanners/objsrc.c

LIB_OBJ := $(patsubst libkofeng/%.c,$(INT)/lib_%.o,$(LIB_SRC))
LIB     := $(SDK)/lib/libkofeng.a

$(INT)/lib_%.o: libkofeng/%.c $(STAMP) | $(INT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# ---- libkofemu: the emulator, and the decoder it stands on -----------------
#
# TWO FLAG SETS, ON PURPOSE.
#
# libkofemu/*.c is kofeng's own and compiles under kofeng's warning policy like
# everything else. libkofemu/bddisasm/ is vendored and does not: bdx86_decoder.c
# alone raises 53 findings under -Wconversion and -Wsign-conversion, none of
# them bugs and all of them a house style it was never written to. Forcing it
# through would mean patching a third-party tree, and a patched tree turns every
# future upgrade from a copy into a merge - see libkofemu/bddisasm/README.kofeng.md.
#
# So the vendored files get their own set: upstream's own disable list, plus
# -Wno-error=incompatible-pointer-types because GCC 14 promoted that to an error
# and bddisasm 3.0.1 predates the change.
#
# What they do NOT get excused from is the sanitizers. This code decodes bytes
# an attacker chose, which is exactly the ground ASAN and UBSan exist to cover,
# so SAN_CFLAGS is threaded through here as well.
EMU_INC := -Ilibkofemu/bddisasm/inc -Ilibkofemu/bddisasm/src \
           -Ilibkofemu/bddisasm/src/include

VENDOR_CFLAGS := -O2 -g -std=c11 -fno-common -D_LIB -DAMD64 \
                 -Wall -Wextra \
                 -Wno-missing-field-initializers -Wno-missing-braces \
                 -Wno-unused-function -Wno-error=incompatible-pointer-types \
                 $(SAN_CFLAGS)

EMU_SRC    := $(wildcard libkofemu/*.c)
VENDOR_SRC := $(wildcard libkofemu/bddisasm/src/*.c)

EMU_OBJ    := $(patsubst libkofemu/%.c,$(INT)/emu_%.o,$(EMU_SRC))
VENDOR_OBJ := $(patsubst libkofemu/bddisasm/src/%.c,$(INT)/bdd_%.o,$(VENDOR_SRC))

$(INT)/emu_%.o: libkofemu/%.c $(STAMP) | $(INT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(EMU_INC) -c $< -o $@

$(INT)/bdd_%.o: libkofemu/bddisasm/src/%.c $(STAMP) | $(INT)
	@mkdir -p $(dir $@)
	$(CC) $(VENDOR_CFLAGS) $(EMU_INC) -c $< -o $@

$(LIB): $(LIB_OBJ) $(EMU_OBJ) $(VENDOR_OBJ)
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
           $(SDK)/include/kofmod/heur.h \
           $(SDK)/include/kofmod/kofsym.h \
           $(SDK)/include/kofmod/elf.h \
           $(SDK)/include/kofmod/pe.h \
           $(SDK)/include/kofmod/gzip.h \
           $(SDK)/include/kofmod/docole.h \
           $(SDK)/include/kofmod/zip.h \
           $(SDK)/include/kofmod/tar.h \
           $(SDK)/include/kofmod/sevenzip.h \
           $(SDK)/include/kofmod/rar.h \
           $(SDK)/include/kofmod/xz.h \
           $(SDK)/include/kofmod/rtf.h

$(SDK)/include/kofeng.h: libkofeng/kofeng.h
	@mkdir -p $(dir $@)
	@cp $< $@

$(SDK)/include/kofmod/%.h: libkofeng/core/kofmod/%.h
	@mkdir -p $(dir $@)
	@cp $< $@

sdk: $(LIB) $(SDK_HDR)
	@echo "  $(LIB)"

# --------------------------------------------------------------- the scanner
#
# Built from the staged SDK, not from the source tree. That is what keeps the
# public header honest: anything it cannot express shows up here as a compile
# error instead of as a quiet reach into an internal include.

SCANNER_SRC := kofscanner/kofscanner.c

$(OUT)/bin/kofscanner$(EXE): $(SCANNER_SRC) $(LIB) $(SDK_HDR) $(STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include $(SCANNER_SRC) $(LIB) -o $@ $(LDFLAGS)

# --------------------------------------------------------------- the examiner
#
# Unlike the scanner, this links the internal collectors: it prints the parsed
# view, and no public surface offers one. The reason that is not a lapse is
# written at the top of the file.

# kofinspect is the half of this tool that is not printing: it asks the loaded
# database what it already knows about an object. Separate because a second
# consumer is coming - the viewer - and because the two halves reach for
# different things: the printer wants the parse, this wants the engine.
EXAMINE_SRC := kofexamine/kofexamine.c kofexamine/kofinspect.c

$(OUT)/bin/kofexamine$(EXE): $(EXAMINE_SRC) $(LIB) $(SDK_HDR) $(STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include $(EXAMINE_SRC) $(LIB) -o $@ $(LDFLAGS)

# The other front end onto the same layer. Two binaries from one directory, and
# the directory is the toolchain rather than the tool: what they share is
# kofinspect, and what differs is only how a pane and a line are drawn.
VIEWER_SRC := kofexamine/kofviewer.c kofexamine/kofinspect.c

# EMU_INC because the viewer disassembles: bddisasm's definitions are already
# inside $(LIB) - the emulator put them there - so what is missing is only the
# header, and linking a second copy of the decoder would be the alternative.
$(OUT)/bin/kofviewer$(EXE): $(VIEWER_SRC) $(LIB) $(SDK_HDR) $(STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include $(EMU_INC) $(VIEWER_SRC) $(LIB) -o $@ $(LDFLAGS)

# ----------------------------------------------------- the database toolchain
#
# One binary with two modes: --extract reads the declarations out of a signature
# source, and the default mode packs compiled artefacts into .ksig. Build-time
# only, and deliberately not linked into anything that runs on an endpoint.

$(OUT)/bin/ksigbuilder$(EXE): ksigbuilder/ksigbuilder.c $(LIB) $(SDK_HDR) $(STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPTO) $< $(LIB) -o $@ $(LDFLAGS)

# ------------------------------------------------------------- the database
#
# Compile every signature, then pack the artefacts.
#
# Parallelism lives here rather than inside either tool: one compile does not
# depend on another, xargs already knows how to run N at a time, and a --jobs
# flag in a C program would be a second implementation of one shell word.

# bases/ is the content tree: everything that compiles to a module and ships in a
# database. Three kinds, one directory each, because they differ in what they do
# and in how often they change rather than merely in name:
#
#   bases/signatures/  detections. Name a family. Change weekly.
#   bases/decomp/      container openers - gzip, zip, tar. A file that is a
#                      wrapper around other files; yields many entries.
#   bases/unp/         executable unpackers - overlay, UPX. A file that IS the
#                      payload, transformed; yields one image.
#
# decomp and unp compile to the same pack kind and the engine does not tell them
# apart - the split is for the people who maintain them. The decompression
# ALGORITHMS are not here at all: they are host services in libkofeng/kofdecomp,
# reached through the module ABI, for the reason kofsig.h gives at the inflate
# entry. Same division Kaspersky shipped, where _nrv.c and _lzma.c live in the
# unpacker kernel and the per-packer modules call into them.
#
#   make databases                     the product        -> build/release/databases
#   make databases BASEDIR=tests/sigs  the engine's tests -> build/test/databases-sigs
#   make databases BASEDIR=~/work/mine anywhere else      -> build/test/databases-mine
#
# The work and output directories are DERIVED from BASEDIR rather than shared, and
# the artefact directory is emptied before each build. Both matter for one reason:
# ksigbuilder packs a DIRECTORY, not a list of files, so anything left in it from a
# previous run is in the database. Sharing one directory meant a test signature
# built five minutes ago was still in the next release build, and a detection
# deleted from the source kept shipping because its blob was never removed. Neither
# shows up as a failure - the build succeeds and the database is quietly wrong.
BASEDIR   ?= bases
BASESET   := $(notdir $(patsubst %/,%,$(BASEDIR)))

# One level down as well as at the top, so the three kinds are directories rather
# than a naming convention nothing enforces.
SIGS      := $(wildcard $(BASEDIR)/*.c $(BASEDIR)/*/*.c)
JOBS      ?= 8

# The product database goes to out/; anything else is a test or a working set and
# goes to test/, so no experiment can overwrite what ships.
ARTEFACTS ?= $(INT)/sig-$(BASESET)

# The product's databases ship, so they live with the binaries and are named for
# what they are. Anything else is a test set or a working set and goes to test/,
# where no experiment can overwrite what ships.
DB        ?= $(strip $(if $(filter bases,$(BASESET)),$(OUT)/databases,\
                                                     $(TEST)/databases-$(BASESET)))

# The per-source chatter is dropped and a count is printed in its place. It used
# to be dropped and nothing printed, so a compile of every base in the tree looked
# exactly like a target that had decided there was nothing to do.
sigs: $(OUT)/bin/ksigbuilder$(EXE) $(SDK_HDR)
	@test -n "$(SIGS)" || { echo "make: no base sources in $(BASEDIR)" >&2; \
		exit 2; }
	@rm -rf $(ARTEFACTS)
	@mkdir -p $(ARTEFACTS)
	@echo "$(SIGS)" | tr ' ' '\n' | KOF_OUTDIR=$(abspath $(ARTEFACTS)) \
		KOF_BASEDIR=$(abspath $(BASEDIR)) \
		xargs -P $(JOBS) -n 1 ksigbuilder/ksigcompiler.sh >/dev/null
	@echo "  $(words $(SIGS)) source(s) from $(BASEDIR) -> $(ARTEFACTS)"

databases: sigs $(OUT)/bin/ksigbuilder$(EXE)
	@rm -rf $(DB)
	@mkdir -p $(DB)
	@$(OUT)/bin/ksigbuilder$(EXE) $(ARTEFACTS) $(DB)
	@echo "   scan with: $(OUT)/bin/kofscanner$(EXE) --db $(DB) --scan-files <path>"

# ------------------------------------------------------------------- testing
#
# Exhaustive differential checks over small inputs, for the routines where a
# corpus run would pass while the code is still wrong on an input the corpus does
# not happen to contain. Each is a standalone program that exits non-zero on
# failure, so this target is usable from CI. Not part of `all`.

# The binaries the collectors are tested against, built from source rather than
# committed. What each one is for is written in tests/fixtures/*.c; what the local
# toolchain could not build is printed, because a format silently absent from the
# fixture directory is a format silently untested - which is exactly how PE
# coverage reached zero here without anything failing.
FIXTURES := $(TEST)/fixtures

fixtures: | $(TEST)
	@tests/mkfixtures.sh $(FIXTURES)

UNIT_SRC := $(wildcard tests/unit/*.c)
UNIT_BIN := $(patsubst tests/unit/%.c,$(TEST)/unit_%$(EXE),$(UNIT_SRC))

# Linked against the library, so a unit test can exercise it rather than only
# whatever it can compile in on its own.
#
# UNIT_LIBS_<name> adds what one test needs. Only the differential decompressor
# test uses it: it links zlib as an ORACLE, to check our decoder against, which is
# the one thing the library must never do itself.
UNIT_LIBS_inflate_diff := -lz

$(TEST)/unit_%$(EXE): tests/unit/%.c $(LIB) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) $< $(LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

# The engine's own signature set is BUILT here, not merely present.
#
# It is not part of `make db`, so nothing else compiles it - and a rename that
# missed it went unnoticed until somebody tried. A signature set that is never
# built is a signature set that has already rotted; building it with the tests is
# what keeps the module ABI's own examples honest about the ABI.
test-sigs:
	@$(MAKE) --no-print-directory databases BASEDIR=tests/sigs >/dev/null

unit: fixtures test-sigs $(UNIT_BIN)
	@rc=0; for t in $(UNIT_BIN); do \
		printf '%-28s ' "$$(basename $$t)"; \
		if $$t; then :; else rc=1; echo "  FAILED"; fi; \
	done; exit $$rc

# Everything -MMD wrote. Missing on a clean tree, which is why it is a soft
# include: nothing to rebuild yet, and the first compile creates them.
-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

#
# The same tests, under AddressSanitizer and UndefinedBehaviorSanitizer.
#
# A separate target rather than the default because it is roughly ten times slower
# and because the two answer different questions. `unit` asks whether the engine
# gets the right answer; this asks whether it stayed inside its own memory getting
# there - out of bounds reads and writes, use after free, double free, and the
# signed overflow that a size calculation reaches before any of those.
#
# Sources are compiled here rather than linked against the release library, so the
# sanitiser instruments the parsers and decoders themselves and not only the test.
#
ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer \
              -fno-sanitize-recover=undefined
ASAN_BIN := $(patsubst tests/unit/%.c,$(TEST)/asan_%$(EXE),$(UNIT_SRC))

ASAN_LIB := $(TEST)/libkofeng-asan.a

#
# The emulator goes in too. It is the newest code here and the one that owns the
# most raw memory - a sparse page table, lazily committed mappings and the
# payload snapshots - so leaving it out would exempt exactly what most needs
# checking. bddisasm comes along because the emulator cannot link without it,
# but with the vendor's own warning flags: it is not ours to fix.
#
$(ASAN_LIB): $(LIB_SRC) $(EMU_SRC) $(VENDOR_SRC) $(SDK_HDR) | $(TEST)
	@rm -rf $(TEST)/asan-obj && mkdir -p $(TEST)/asan-obj
	@for f in $(LIB_SRC); do \
		o=$(TEST)/asan-obj/$$(echo $$f | tr / _ | sed 's/\.c$$/.o/'); \
		$(CC) $(CFLAGS) $(ASAN_FLAGS) -c $$f -o $$o || exit 1; \
	done
	@for f in $(EMU_SRC); do \
		o=$(TEST)/asan-obj/$$(echo $$f | tr / _ | sed 's/\.c$$/.o/'); \
		$(CC) $(CFLAGS) $(ASAN_FLAGS) $(EMU_INC) -c $$f -o $$o || exit 1; \
	done
	@for f in $(VENDOR_SRC); do \
		o=$(TEST)/asan-obj/$$(echo $$f | tr / _ | sed 's/\.c$$/.o/'); \
		$(CC) $(VENDOR_CFLAGS) $(ASAN_FLAGS) $(EMU_INC) -c $$f -o $$o || exit 1; \
	done
	@$(AR) rcs $@ $(TEST)/asan-obj/*.o

$(TEST)/asan_%$(EXE): tests/unit/%.c $(ASAN_LIB) $(STAMP) | $(TEST)
	@$(CC) $(CFLAGS) $(ASAN_FLAGS) $< $(ASAN_LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

unit-asan: fixtures test-sigs $(ASAN_BIN)
	@rc=0; for t in $(ASAN_BIN); do \
		printf '%-28s ' "$$(basename $$t)"; \
		if ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 \
		   UBSAN_OPTIONS=print_stacktrace=1 $$t >/dev/null 2>$(TEST)/$$(basename $$t).log; \
		then echo "ok"; else rc=1; echo "FAILED - see $(TEST)/$$(basename $$t).log"; fi; \
	done; exit $$rc

clean:
	rm -rf $(BUILD)

.PHONY: all sdk sigs databases unit fixtures test-sigs clean \
        kofscanner kofexamine ksigbuilder kofviewer tools help