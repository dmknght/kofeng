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
# position independent blobs produced by ksigbuilder with its own
# flag set, and mixing the two sets in one place is how they end up applied to the
# wrong target.

#
# WHICH MAKE IS RUNNING THIS, ASKED BEFORE ANYTHING DEPENDS ON THE ANSWER.
#
# SHELL := cmd.exe below is what removed this build's POSIX dependency, and
# only a make BUILT FOR WINDOWS can drive it: handing a recipe to cmd as
# `/c "..."` is the w32 port's batch-mode-shell handling and exists nowhere
# else. A Cygwin or MSYS make reads the same assignment, execs cmd.exe with
# the POSIX argument conventions cmd does not understand, and gets an
# INTERACTIVE shell - so every $(shell) in this file comes back with cmd's
# startup banner instead of an answer. Measured here, that surfaced as:
#
#   - the compiler probe below reading the banner rather than "yes", so a
#     build with clang installed AND on PATH died saying there was none
#   - $(shell $(call MKDIR,...)) returning the banner too, make parsing it
#     as a rule, and the error being "missing separator" pointing at a line
#     that is perfectly fine
#   - with no stdin to close, hanging rather than failing
#
# THAT IS NOT A REASON TO REFUSE, and it is not a reason to send the build
# down the POSIX rules either. Both were tried here and both were wrong, for
# the same reason: they answer a question nobody asked.
#
# THERE ARE TWO QUESTIONS AND THIS FILE USED TO ASK ONE.
#
#   (a) Is this Windows? That decides $(EXE), TMP/TEMP, and linking
#       winpthread statically - see the note above on what a dynamic one
#       costs, which is an .exe that starts nothing and prints nothing.
#   (b) Can this make drive cmd.exe? That decides SHELL, and with it which
#       dialect MKDIR, RMRF, COPY and the rest are written in.
#
# They are independent, and an MSYS make is exactly the case that separates
# them: it is on Windows and it cannot drive cmd. Keyed on $(OS) alone, (a)
# came out NO for it - so it built binaries with no suffix that depended on
# a DLL only ever found inside an MSYS2 install, which is the failure the
# note above exists to prevent. Keyed on the shell, (b) is what actually
# has to change, and only that.
#
# So: (a) below is $(OS) OR what MAKE_HOST says, and (b) is its own flag.
# The POSIX operations are reached by a make that cannot drive cmd, on
# either platform, and every Windows-shaped decision still applies here.
#
# MAKE_HOST and not a probe, because a probe would have to run the shell
# that is the thing under suspicion. Make sets it itself and reading it
# costs nothing.
KOF_UNIXY_MAKE := $(if $(filter %-cygwin %-msys,$(MAKE_HOST)),yes)
#
# Windows, whoever is asking. $(OS) is inherited from the kernel and is the
# right answer wherever it survives; a Cygwin make drops it from its own
# variable set, and MAKE_HOST is how that make still says where it is.
KOF_ON_WINDOWS := $(if $(filter Windows_NT,$(OS)),yes)
ifeq ($(KOF_UNIXY_MAKE),yes)
KOF_ON_WINDOWS := yes
endif

#
# `cc` is a POSIX convention, and Windows does not have it.
#
# Not "usually does not": no Windows C toolchain installs a cc.exe. LLVM from
# winget or from llvm.org gives clang.exe, the Visual Studio tools give cl.exe,
# and the only cc.exe on a Windows box belongs to MSYS2 - which is exactly the
# thing this build no longer requires. So make's own built-in default sends the
# build looking for a program that was never going to be there, and someone who
# installed LLVM the ordinary Windows way still gets "cc is not recognized".
#
# $(origin) rather than ?=, because make PREDEFINES CC. Its origin is `default`,
# not `undefined`, and ?= only assigns to the latter - so `CC ?= clang` here
# would silently do nothing and leave `cc` in place. Command line and
# environment both still win, which is the whole point of testing the origin
# rather than overwriting.
ifeq ($(OS),Windows_NT)
ifneq ($(filter default undefined,$(origin CC)),)
CC := clang
endif
else
CC      ?= cc
endif
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
#
# -Wframe-larger-than is on the portable list, at 128KB.
#
# No function in this tree needs a frame that large, so the number is not tuned
# to anything - it is a tripwire for the case that already happened. A struct
# held as a local grew past what a stack holds, and the process exited with
# 0xC00000FD having printed nothing: the symptom read exactly like a library
# that had not been linked, and finding it meant measuring sizeof by hand.
# An eighth of the 1MB a thread gets on Windows leaves room for the call chain
# below whatever trips it.
#
# A warning and not an error, because a platform with a larger stack is not
# wrong to use it - and it is in the probed list, so a compiler without the
# flag simply does not get it.
#
KOF_WARN_PORTABLE := -Wcast-qual -Wwrite-strings -Wredundant-decls \
                     -Wmissing-declarations -Wundef \
                     -Wformat=2 -Wnull-dereference -Wvla \
                     -Wshift-overflow=2 -Wold-style-definition \
                     -Wframe-larger-than=131072
KOF_WARN_GCC      := -Wduplicated-cond -Wduplicated-branches -Wlogical-op \
                     -Wjump-misses-init

#
# Offered to the compiler and kept only if it compiled an empty translation
# unit without complaint.
#
# The status comes from make's own .SHELLSTATUS rather than from `&&`, which
# PowerShell 5.1 does not have. The compiler's complaint is silenced rather
# than captured, because PowerShell turns a native command's redirected stderr
# into error records and prints them - `2>&1` here would put every rejected
# flag on the console during an ordinary build.
#
# Output and status are concatenated with nothing between them, so the test is
# exactly "said nothing and exited zero": a compiler that printed a bare 0
# could not pass it by accident.
#
# It reads the null device rather than a temporary file, so the probe leaves
# nothing behind on either platform. That is also the bug this rewrite fixed:
# the old form hardcoded /dev/null, which on Windows is not a device but a
# path that does not exist, so the probe failed for the wrong reason and every
# second-tier warning was silently dropped on that platform.
kof_probe = $(if $(filter 0,$(shell $(CC) -Werror $(1) -xc -c $(DEVNULL) \
                                    -o $(DEVNULL) $(SILENCE))$(.SHELLSTATUS)),$(1))

#
# ONE FLAG AT A TIME, because the probe above is ALL OR NOTHING.
#
# Asked about a list, it compiles with the whole list and keeps the whole list
# or none of it. That is a trap the lists below were already split to avoid -
# see the note on them about "losing the portable ten because clang lacks
# -Wlogical-op" - and the split was not enough: ONE flag in the portable list,
# -Wshift-overflow=2, is spelled with a level that clang does not take, so on
# clang the probe threw away ELEVEN warnings that clang supports perfectly
# well. Measured: zero of them fire on this tree, so eleven checks were off
# and nothing anywhere said so - the failure mode of an all-or-nothing probe is
# silence by construction.
#
# Per flag costs 17 compiler runs instead of 2. Measured at 1.25 seconds
# against 0.15, ONCE per make - not per object file, which is the cost the
# note below is about and the reason := matters. A second of startup to stop
# losing a warning silently is the right way round.
#
kof_probe_each = $(foreach w,$(1),$(call kof_probe,$(w)))

# Applied further down, once the platform block has said what the null device
# is called here - the probe reads it, and on Windows it is not /dev/null.

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
# ksigbuilder's own default - spells $(EXE) after it instead.
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
ifeq ($(KOF_ON_WINDOWS),yes)
NATIVE_OS   := windows
EXE         := .exe
#
# CMD IS THE SHELL HERE, AND THAT IS THE WHOLE POSIX DEPENDENCY GONE.
#
# This used to require MSYS2: not for the compiler - clang has never needed it
# - but because every recipe was written in POSIX sh, and GNU Make's own
# documented fallback when it cannot find one is cmd.exe. That is not a build
# failure, it is a different program reading the recipes and understanding
# none of them, so the build died with cmd.exe's error text naming nothing
# about the real cause. So the recipes below do not speak either dialect
# directly: they are written in terms of the operations named further down,
# and each platform says how it performs them. A recipe that needed a loop or
# a conditional was rewritten as make's own foreach or as a per-target rule,
# which is a better Makefile on both platforms and not a concession to this
# one.
#
# NOT PowerShell, which is what this was first, and the reason is measured
# rather than aesthetic. Every recipe LINE is one shell process, and on this
# machine:
#
#     powershell.exe   1178 ms per recipe line
#     cmd.exe            70 ms per recipe line
#
# That is not a tax on the shell-ish parts of the build, it is a tax on all of
# it - make spawns the shell for `clang -c foo.c` too, and there is no fast
# path that skips it (measured: a recipe with no metacharacter at all costs
# the same). A clean build runs about 150 recipe lines, so the choice of shell
# alone was three minutes of a five minute build, against eight seconds of
# actual compiling. cmd is also on more Windows installs than PowerShell is,
# so nothing is given up for it.
#
# What cmd cannot do is answered by starting PowerShell deliberately, once -
# see NOW_UTC below. That is the shape to keep: PowerShell as a program this
# build occasionally runs, never as the thing that runs every line of it.
#
# ONLY WHERE IT CAN BE DRIVEN. A Cygwin or MSYS make would exec cmd with
# POSIX argument conventions and get an interactive shell - see the note on
# KOF_UNIXY_MAKE - so that make keeps its own /bin/sh and takes the POSIX
# operations below. Everything else in this block still applies to it,
# because everything else in this block is about Windows and not about the
# shell.
ifneq ($(KOF_UNIXY_MAKE),yes)
SHELL       := cmd.exe
.SHELLFLAGS := /c
endif
#
# IS THERE A COMPILER AT ALL - ASKED ONCE, ANSWERED IN ONE LINE.
#
# Without this the answer arrives as a wall: every flag probe below runs the
# compiler, and a compiler that is not there produces one "is not recognized"
# block per probe, each naming a warning list rather than the missing program.
# The one line that says what is actually wrong ends up several screens above
# where the reader is looking.
#
# `where`, not a trial compile, because the two failures want different words:
# a compiler that is absent is a PATH problem and a compiler that is present
# but broken is not, and running one to find out the first would print the wall
# this exists to prevent. Its own output and error are dropped - the one place
# a silent probe is right, because make's own $(error) below says everything
# instead, loudly and once.
#
# Recursive (=), not simple (:=), because it is asked TWICE and the answer
# between the two asks is allowed to change: once before the search below, once
# after it has put a toolchain on PATH.
# `where` is cmd's; a make on its own /bin/sh has `command -v` instead, and
# asking the wrong one answers "no compiler" for every build that took the
# other shell. One probe per dialect, chosen by the same flag as the shell.
ifeq ($(KOF_UNIXY_MAKE),yes)
KOF_CC_FOUND = $(shell command -v $(CC) >/dev/null 2>&1 && echo yes)
else
KOF_CC_FOUND = $(shell where $(CC) >NUL 2>NUL && echo yes)
endif

#
# NOT ON PATH IS NOT THE SAME AS NOT INSTALLED.
#
# The usual state of a Windows box: MSYS2 is installed, clang is in it, and
# nothing put its bin directory on PATH - so `make` from an ordinary Windows
# Terminal fails on a machine that has everything it needs. These are the
# directories a Windows toolchain actually lands in, and finding one is enough
# to build with.
#
# $(wildcard), not a shell: it is make's own file test, so this costs no
# process and works before anything has been established about the shell. None
# of these paths contain a space, which is why they can be a make word list at
# all - "C:\Program Files\LLVM\bin" cannot be, and is named in the error below
# rather than searched, because a path with a space in it is not one word to
# make and quoting it through to both platforms' shells is a bigger change than
# this problem is worth.
#
# PATH is PREPENDED rather than CC being rewritten to an absolute path, because
# the compiler is not the only thing needed from that directory: ksigbuilder
# starts ld.lld with CreateProcess, which searches PATH and knows nothing about
# this Makefile's variables. One prepend covers both, and the rest of PATH is
# untouched - verified, 21 entries in and 22 out.
#
# Announced with $(info), not done quietly. A build that works because
# something was found in a place the user did not ask for should say so: the
# alternative is a build that behaves differently on two machines for a reason
# neither of them prints.
KOF_TOOLDIRS := C:/msys64/clangarm64/bin C:/msys64/mingw64/bin \
                C:/msys64/clang64/bin C:/msys64/mingw32/bin
ifneq ($(KOF_CC_FOUND),yes)
KOF_TOOLDIR := $(patsubst %/,%,$(firstword $(dir \
                   $(wildcard $(addsuffix /$(CC).exe,$(KOF_TOOLDIRS))))))
ifneq ($(KOF_TOOLDIR),)
export PATH := $(subst /,\,$(KOF_TOOLDIR));$(PATH)
$(info make: $(CC) was not on PATH; using the one in $(KOF_TOOLDIR))
endif
endif

ifneq ($(KOF_CC_FOUND),yes)
$(error No C compiler: '$(CC)' is not on PATH. Install one and put it there, \
then retry. MSYS2 (https://www.msys2.org/) puts clang in \
C:\msys64\clangarm64\bin on ARM64 or C:\msys64\mingw64\bin on x86-64; LLVM \
from winget ("winget install LLVM.LLVM") puts it in \
C:\Program Files\LLVM\bin. Building the signature databases also needs \
ld.lld from the same place. A compiler that is installed but named something \
else can be given directly: make CC=clang-19)
endif
#
# TMP/TEMP: a linked binary needs somewhere to put its intermediates, and the
# native compiler reads the Windows convention for that rather than TMPDIR.
# $(CURDIR) is already a Windows path when make is native, and the mixed
# C:/... form is accepted by every tool here, so nothing has to convert it -
# which is one more POSIX tool (cygpath) the build no longer looks for.
#
# THE PATH HAS TO BE A WINDOWS ONE, AND $(CURDIR) IS NOT ALWAYS.
#
# Under a make on its own /bin/sh, $(CURDIR) is a POSIX path - so the
# substitution below turns /d/Code_projects/kofeng into
# \d\Code_projects\kofeng, a path with no drive letter, and the
# native compiler cannot create a file in one. It fails as "unable to make
# temporary file" - after every object has compiled, at the first link, a
# long way from anything that names a path.
#
# cygpath ships with the same install that supplies such a make, so it is
# there whenever this branch is taken and it is asked for nowhere else.
ifeq ($(KOF_UNIXY_MAKE),yes)
export TMP  := $(shell cygpath -w '$(CURDIR)')\build\temp
else
export TMP  := $(subst /,\,$(CURDIR))\build\temp
endif
export TEMP := $(TMP)
#
# -pthread in CFLAGS because it means something at both steps; the rest in
# LDFLAGS because it does not.
#
# They were all in CFLAGS, and every -c compile in the tree then printed three
# warnings it could do nothing about - "'linker' input unused" for each of
# -Wl,-Bstatic, -lwinpthread and -Wl,-Bdynamic - which is three lines per
# object file for a build that has nothing wrong with it. That is worse than
# untidy: a build whose normal output is warnings is a build where the warning
# that matters goes past unread. LDFLAGS is on every link command in this file,
# so nothing about the resulting binaries changes.
CFLAGS      += -pthread
LDFLAGS     += -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic
# By default every signature blob this engine loads is x86_64 machine code on
# every host - deliberate, see ksigbuilder, since a database has to be
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
# ksigbuilder already cross-compiles every blob: clang is a cross
# compiler by construction, so the only extra ingredient is an x86_64
# mingw-w64 sysroot (headers/crt/import libs) alongside whatever native one
# came with the compiler - KOF_X86_SYSROOT points at it, overridable for an
# MSYS2 install anywhere other than the default C:\msys64. Verified end to
# end on real ARM64 Windows hardware: a hosted hello-world built this way
# ran correctly under Windows's x64 emulation, and so did the full scanner
# against a real PE, where the native-ARM64 build had crashed instantly.
# That cross-compile is now what you ASK for rather than what you get.
#
# The default follows the compiler: whatever machine it says it targets is the
# machine the tools and every signature blob are built for, so on this ARM64
# box a plain `make` produces ARM64 throughout and nothing runs under Windows's
# x64 emulation. It used to force x86_64 on every host, which was right while
# an ARM64-native build did not work at all - jumping into an x86_64 blob from
# an ARM64 process is an illegal instruction - and stopped being right once it
# did. The failure it was avoiding is a mismatch between the tools and the
# blobs, and matching them to the compiler avoids it in the direction that
# costs nothing at run time instead of the one that pays the emulation tax
# forever.
#
# KOF_HOST_MACH still overrides in both directions - x86_64 for the machine
# every database shipped so far was built for, arm64 to force it the other way
# on an x86_64 host - and a forced machine that is not the compiler's own is
# what the sysroots below are for. WORTH KNOWING BEFORE SHIPPING: a database
# is machine-specific, so an ARM64 build now produces packs an x86_64 scanner
# refuses (kofdb says "built for machine 1, this is 2" and skips the file).
# Building what is distributed still means saying KOF_HOST_MACH=x86_64.
#
# Both machines build into the same tree, and switching between them is safe
# for one reason: this variable changes CFLAGS, so it changes FLAGSIG, so the
# flag stamp below rebuilds every object rather than leaving the previous
# machine's behind. That is not a nicety - a stale object of the other machine
# inside libkofeng.a does not fail at compile time, and at link time it is
# reported as "undefined symbol" against symbols the archive demonstrably
# holds. The blobs and the database need no such guard: sigs and databases
# both rm -rf their output before writing it.
#
# Same probe, same reasoning, mirrored: ask the compiler what it already is
# before forcing anything, so a build host that is already the target machine
# adds no cross-compile flags at all.
#
# Captured in its own variable, KOF_CROSS_FLAGS, rather than appended to
# CFLAGS alone - VENDOR_CFLAGS below (the vendored bddisasm decoder) is a
# deliberately separate flag list that does not inherit CFLAGS at all, and it
# still has to end up targeting the same machine as everything else. Missing
# on the first pass of this: on a build host whose native compiler target
# does not match the one being forced (this ARM64 box building the x86_64
# default, or the reverse cross direction for KOF_HOST_MACH=arm64), the
# vendored decoder silently compiled for whatever the compiler's own default
# was, landing wrong-machine objects in libkofeng.a next to correctly forced
# ones - which does not fail at compile time, only at final link, and not
# even with a machine-mismatch error for the files actually at fault: lld's
# default (non-whole-archive) archive symbol lookup came back "undefined
# symbol" for symbols that verifiably exist in the archive's own index,
# because a mismatched member anywhere in the archive broke lookup for every
# member, not only itself. Confirmed empirically: stripping the
# wrong-machine members out of a copy of the archive made the exact same
# link command resolve cleanly.
CC_MACHINE := $(shell $(CC) -dumpmachine)
KOF_CROSS_FLAGS :=
#
# The machine the SIGNATURE BLOBS are for, which has to be the same machine
# these tools are for and is not the same question. The tools' machine ends up
# in the pack header (KOF_PACK_MACH_HOST, stamped by whatever built
# ksigbuilder); the blobs' machine is whatever the compiler ksigbuilder runs
# defaults to. On a host where those differ - this ARM64 box building the
# x86_64 default - the pack says one thing and carries the other, and the
# scanner dies on STATUS_ILLEGAL_INSTRUCTION inside the first module. So both
# are decided here, once, and handed down.
#
# Unset means "whatever this compiler already is", which is the whole of
# building native without being asked to.
#
# Read from -dumpmachine and not from the CPU: $(PROCESSOR_ARCHITECTURE) is the
# architecture of the process that reads it, and make itself is an x86-64
# binary running under emulation on this ARM64 box - it reads "AMD64" on
# hardware that has no x86-64 in it. The compiler is the one thing here that
# cannot be wrong about what it targets, and it is also the thing whose answer
# actually matters: a native build is one where no cross flags are added at
# all, which is exactly the case where this agrees with the compiler.
ifeq ($(KOF_HOST_MACH),)
ifneq ($(findstring aarch64,$(CC_MACHINE)),)
KOF_HOST_MACH := arm64
else
KOF_HOST_MACH := x86_64
endif
endif

KOF_TARGET_TRIPLE :=
ifeq ($(KOF_HOST_MACH),arm64)
KOF_TARGET_TRIPLE := aarch64-w64-windows-gnu
ifeq ($(findstring aarch64,$(CC_MACHINE)),)
KOF_ARM64_SYSROOT ?= C:/msys64/clangarm64
KOF_CROSS_FLAGS += -target aarch64-w64-windows-gnu --sysroot=$(KOF_ARM64_SYSROOT) -fuse-ld=lld
endif
else
KOF_TARGET_TRIPLE := x86_64-w64-windows-gnu
ifeq ($(findstring x86_64,$(CC_MACHINE)),)
KOF_X86_SYSROOT ?= C:/msys64/mingw64
KOF_CROSS_FLAGS += -target x86_64-w64-windows-gnu --sysroot=$(KOF_X86_SYSROOT) -fuse-ld=lld
endif
endif
CFLAGS += $(KOF_CROSS_FLAGS)
else
NATIVE_OS   := $(shell uname -s 2>/dev/null)
EXE         :=
endif

# Said out loud, because a build that quietly takes a different path is one
# that behaves differently on two machines for a reason neither of them
# prints - the rule the toolchain search below follows too.
ifeq ($(KOF_UNIXY_MAKE),yes)
$(info make: $(MAKE_HOST) make - keeping the Windows settings and taking the \
POSIX operations, because this make cannot drive cmd.exe.)
endif

#
# THE FILE OPERATIONS A RECIPE IS ALLOWED TO USE.
#
# Every recipe below is written in terms of these and of the compiler, and
# nothing else. That is what lets one Makefile drive two shells that share no
# syntax: the recipes never spell a shell's own dialect, so there is one copy
# of every rule rather than a POSIX one and a Windows one drifting apart.
#
# The rules are: no `for`, no `if`, no `test`, no pipes and no redirection in
# a recipe. Where a loop was needed it became make's $(foreach) or a rule per
# target, which reads better on both platforms anyway; where a message was
# needed it became $(info), which make prints itself and no shell ever sees.
#
# MKDIR must not fail on a directory that already exists, and RMRF must not
# fail on one that does not - MKDIR says so with a flag on both platforms,
# RMRF only on POSIX, so it takes its path through $(call) instead.
# An empty variable, used only to stop $(info) losing a message's indent:
# make strips leading whitespace from a function argument, but keeps what
# follows an expansion.
SP       :=

#
# KEYED ON THE SHELL AND NOT ON THE PLATFORM, which is the whole point of
# the split described at the top of this file: these are cmd's spellings, so
# what decides between them is who is reading the recipe. A Windows build
# driven by a make on /bin/sh wants the POSIX ones below and wants every
# other Windows decision left alone.
# Windows, and a make that can drive cmd there. Spelled once, because it is
# read as a condition and a reader should not have to re-derive it.
KOF_CMD_SHELL := $(if $(KOF_UNIXY_MAKE),,$(if $(filter windows,$(NATIVE_OS)),yes))
ifeq ($(KOF_CMD_SHELL),yes)
#
# `mkdir` alone fails on a directory that is already there, and cmd has no
# -p. The guard is the flag: `if not exist` costs nothing and says the same.
# Paths are quoted because the build tree can sit under Program Files.
MKDIR    = if not exist "$(subst /,\,$(1))" mkdir "$(subst /,\,$(1))"
#
# rmdir /s /q fails on a path that is not there, so it is guarded the same
# way. Both take their argument through $(call) because each needs it twice,
# and both convert to backslashes: cmd's own file commands do not accept the
# forward slashes the rest of this Makefile writes.
RMRF     = if exist "$(subst /,\,$(1))" rmdir /s /q "$(subst /,\,$(1))"
COPY     = copy /y "$(subst /,\,$(1))" "$(subst /,\,$(2))" >NUL
#
# Running a program this build just produced, by the path it was written to.
#
# cmd splits a command word at '/' looking for switches, so
# `build/release/bin/ksigbuilder.exe` reaches it as the command `build` with
# the option `/release` - "'build' is not recognized". Only the PROGRAM word
# has this problem; the arguments after it are passed through untouched, which
# is why every other path in this file can stay in forward slashes.
EXEC     = $(subst /,\,$(1))
QUIET    = >NUL
DEVNULL  = NUL
# A command that does nothing, for a recipe whose only content is a message:
# make prints "Nothing to be done" for a target with no commands at all.
NOOP     = rem
SILENCE  = 2>NUL
# The two things the build asks the system rather than the compiler: when this
# is, and which dependency files exist. Both are one call, so they are spelled
# per platform here instead of reaching for `date` and `find`.
#
# The clock is the one thing cmd cannot answer: %DATE% is whatever the user's
# locale says and is not UTC. One PowerShell start, once per make run, is
# worth more than parsing a localised date string; everything else here is
# cmd, which is why the recipes are fast again.
NOW_UTC  = powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyyMMddHH')"
#
# `dir /s /b` lists full paths, and prints "File Not Found" to stderr on a
# tree that has not been built yet - which is the ONE error worth tolerating,
# so only that stream is dropped. `if exist` first, so a missing build/ is not
# an error at all rather than a silenced one.
FIND_DEPS = if exist "$(subst /,\,$(BUILD))" dir /s /b "$(subst /,\,$(BUILD))\*.d" 2>NUL
# The fixture builder, which is a program rather than a make recipe because it
# probes toolchains. It exists twice for the reason its own headers give: a
# PowerShell recipe cannot run a .sh - Windows hands it to a file association,
# so nothing runs and the recipe succeeds. -File, not a bare path, so the same
# is not true of the .ps1 on a host whose execution policy is restricted.
MKFIXTURES = powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File tests/mkfixtures.ps1
else
MKDIR    = mkdir -p '$(1)'
RMRF     = rm -rf '$(1)'
COPY     = cp -f '$(1)' '$(2)'
EXEC     = $(1)
QUIET    = >/dev/null
DEVNULL  = /dev/null
NOOP     = :
SILENCE  = 2>/dev/null
NOW_UTC  = date -u +%Y%m%d%H
FIND_DEPS = find $(BUILD) -name '*.d' 2>/dev/null
MKFIXTURES = tests/mkfixtures.sh
endif

#
# The second warning tier, now that the probe knows what to read - see
# kof_probe above for why it is a probe rather than a list.
#
# ASKED ONCE. := is not a style choice here, it is the difference between two
# compiler runs and a hundred and eighteen of them.
#
# CFLAGS is recursively expanded - `CFLAGS ?= -O2 -g` makes it so, and every
# += after that keeps it that way - which means a `$(call kof_probe,...)`
# appended to it is not a result, it is a recipe for getting one, re-run in
# full every single time anything expands $(CFLAGS). Every compile line does.
# Measured on this tree: 102 seconds of a 310 second `make sdk`, spent asking
# the same compiler the same two questions once per object file. Answering
# them into a simply-expanded variable first costs the two runs it should.
#
# WHAT IS OFF, AND EXACTLY WHAT IT WOULD SAY IF IT WERE ON.
#
# Turning the portable list back on (see kof_probe_each) showed 24 warnings
# that had never been seen, because the all-or-nothing probe had been dropping
# the flags that produce them. They are pre-existing and none of them is a
# defect in what this build was changed for, so they are held here rather than
# fixed in passing OR left to print 24 lines on every build - which would bury
# the next real one, and burying is the fault this whole note exists to undo.
#
# Held off, with the count as of the build that found them:
#
#   -Wcast-align               9   uint8_t* cast to a wider type. Fine on x86
#                                  and on the ARM64 this targets; real on a
#                                  strict-alignment target, so it is a port
#                                  question rather than a bug here.
#                                  kofpackw.c, kofemu.c, kofeditor.c,
#                                  kofviewer.c, wevt_etw.c, wchan.c
#   -Wdouble-promotion         6   float reaching a double parameter.
#                                  kofemu.c, kofpackw.c
#   -Wformat-nonliteral       10   printf handed a format built at run time.
#                                  Deliberate in these callers - a column
#                                  width or a label is chosen and then used -
#                                  so this is the one of the four most likely
#                                  to stay off. It is still counted, because
#                                  a NEW one is worth seeing and a count is
#                                  the only way to notice the number moved.
#                                  kofemu_crt.c, ksigbuilder.c, kofviewer.c
#   -Wmissing-format-attribute 9   printf wrappers with no format attribute,
#                                  which is the one of the three that a caller
#                                  can be hurt by: without it the compiler
#                                  cannot check the format string AT the call.
#                                  Suppressed as a sub-warning rather than by
#                                  dropping -Wformat=2, because the rest of
#                                  that flag - format-security above all - is
#                                  worth keeping on.
#
# Each line is a thing to fix and then delete from here. A flag that is off
# with a count beside it is a decision; a flag that is off because a probe
# threw it away is what this replaced.
#
KOF_WARN_PENDING := -Wno-missing-format-attribute -Wno-format-nonliteral

# Probed one at a time, so the two lists above are a statement of WHERE each
# flag is expected to work rather than a mechanism - a compiler that lacks any
# one of them loses that one and nothing else. The pending suppressions come
# after, so they win over whatever enabled them.
KOF_WARN_EXTRA := $(call kof_probe_each,$(KOF_WARN_PORTABLE) $(KOF_WARN_GCC)) \
                  $(call kof_probe_each,$(KOF_WARN_PENDING))
CFLAGS  += $(KOF_WARN_EXTRA)

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
	$(info $(SP)  $<)
	@$(NOOP)
kofexamine:  $(OUT)/bin/kofexamine$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)
ksigbuilder: $(OUT)/bin/ksigbuilder$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)
kofviewer:   $(OUT)/bin/kofviewer$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

tools: kofscanner kofexamine ksigbuilder kofviewer kofwatchman

help:
	$(info targets:)
	$(info $(SP)  all           the SDK, all three tools and the databases  (default))
	$(info $(SP)  sdk           libkofeng.a and the public headers)
	$(info $(SP)  kofscanner    the scanner)
	$(info $(SP)  kofexamine    the file examiner)
	$(info $(SP)  ksigbuilder   the database builder)
	$(info $(SP)  kofviewer     the file examiner, navigable)
	$(info $(SP)  kofwatchman   verdicts over a recorded event log)
	$(info $(SP)  kofwatchtower the event sensor)
	$(info $(SP)  kofmontrace   run a program and trace it)
	$(info $(SP)  kofmemscan    scan the memory of running processes (Windows only))
	$(info $(SP)  tools         all six of the above)
	$(info $(SP)  databases     compile bases/ into the shipping databases)
	$(info $(SP)                                                 -> $(OUT)/databases)
	$(info $(SP)  databases BASEDIR=D   compile D instead        -> $(TEST)/databases-<name>)
	$(info $(SP)  KOF_HOST_MACH=<m>     (Windows) build the tools and every signature)
	$(info $(SP)                        blob for machine <m>: x86_64 or arm64. The)
	$(info $(SP)                        default is whatever the compiler already)
	$(info $(SP)                        targets, here $(KOF_HOST_MACH). A database is)
	$(info $(SP)                        machine-specific, so say x86_64 to build the)
	$(info $(SP)                        one that is distributed.)
	$(info $(SP)  unit          build and run the tests)
	$(info $(SP)  fixtures      build the binaries the tests parse)
	$(info $(SP)  clean         remove $(BUILD))
	@$(NOOP)

$(BUILD) $(OUT) $(INT) $(TEST):
	@$(call MKDIR,$@)

# ------------------------------------------------------------ the flag stamp
#
# An object file does not record the flags it was built with, and make compares
# timestamps. So `make` followed by `make SAN=1` rebuilt nothing: every object was
# newer than its source, and the "sanitizer" run was a release binary reporting
# green. Same failure as missing header dependencies - a safety net that silently
# is not there - and it was caught by checking `ldd` for the sanitizer runtime,
# not by anything failing.
#
# Written while the makefile is being read rather than by a recipe. That timing
# is the whole point: make decides what is out of date before it runs any
# recipe, so a stamp updated by a recipe updates it too late to matter.
#
# Read and written with make's own $(file), not with a shell. It used to be a
# $(shell) running `[`, `cat` and `printf` - three POSIX tools for a
# compare-and-write make can do itself, and three more reasons the build
# needed MSYS2. The comparison is ifneq rather than $(filter-out) because a
# flag list is one string here and not a list of words: filter-out would
# compare word by word and call a reordering equal.
FLAGSIG := $(CC) $(CFLAGS) $(LDFLAGS)
STAMP   := $(INT)/.flags

$(shell $(call MKDIR,$(INT)))

STAMP_WAS := $(if $(wildcard $(STAMP)),$(file < $(STAMP)))
ifneq ($(STAMP_WAS),$(FLAGSIG))
$(file > $(STAMP),$(FLAGSIG))
endif

$(STAMP): ;

# ---------------------------------------------------------------- the library

LIB_SRC := libkofeng/kofeng.c \
           libkofeng/kofdb/kofdb.c \
           libkofeng/kofdb/kofpackw.c \
           libkofeng/kofheur/kofheur.c \
           libkofeng/kofmatchers/kofmatch.c \
           libkofeng/kofmatchers/kofmultimatch.c \
           libkofeng/kofmatchers/hexcomp.c \
           libkofeng/kofparsers/binaries/elf_parse.c \
           libkofeng/kofparsers/binaries/elf_sym.c \
           libkofeng/kofparsers/binaries/sym_any.c \
           libkofeng/kofparsers/kofformat.c \
           libkofeng/kofparsers/events/amsi_parse.c \
           libkofeng/kofparsers/events/proc_parse.c \
           libkofeng/kofdisasm/xref.c \
           libkofeng/kofparsers/binaries/pe_sym.c \
           libkofeng/kofparsers/binaries/pe_parse.c \
           libkofeng/kofparsers/binaries/clr_parse.c \
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
           libkofeng/kofunpack/pe_unmap.c \
           libkofeng/kofunpack/emu_unpack.c \
           libkofeng/kofunpack/elf_rebuild.c \
           libkofeng/kofdecomp/decomp.c \
           libkofeng/kofdecomp/inflate.c \
           libkofeng/kofdecomp/textcode.c \
           libkofeng/kofdecomp/lzw.c \
           libkofeng/kofdecomp/ovba.c \
           libkofeng/kofdecomp/bcj.c \
           libkofeng/kofdecomp/bcj2.c \
           libkofeng/kofdecomp/ppmd.c \
           libkofeng/kofdecomp/rar3.c \
           libkofeng/kofdecomp/rar5.c \
           libkofeng/kofdecomp/lzma.c \
           libkofeng/kofdecomp/nrv2.c \
           libkofeng/kofscanners/scan.c \
           libkofeng/kofscanners/objtree.c \
           libkofeng/kofscanners/objctx.c \
           libkofeng/kofscanners/objsrc.c \
           libkofeng/core/kofhash.c

LIB_OBJ := $(patsubst libkofeng/%.c,$(INT)/lib_%.o,$(LIB_SRC))
LIB     := $(SDK)/lib/libkofeng.a

$(INT)/lib_%.o: libkofeng/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) -c $< -o $@

# kofdisasm/ reads instructions, so it needs the decoder's headers. Only this
# one directory does; the rest of the engine is kept away from them on purpose,
# because a parser that can decode is a parser that will start to.
$(INT)/lib_kofdisasm/%.o: libkofeng/kofdisasm/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(EMU_INC) -c $< -o $@

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

# WHEN THIS DATABASE WAS BUILT, as YYYYMMDDHH in UTC - see KOF_PACK_BUILD.
#
# UTC and not local time: two build machines in different zones would otherwise
# stamp packs with numbers that do not increase with time, and ordering is the
# one thing this format is good for. Computed once per make run, so every pack
# in one build carries the same stamp.
KOF_BUILD_STAMP := $(shell $(NOW_UTC))
#
# TWO NAMES, ONE VALUE. The stamp is the same instant because both are built by
# the same make run; the names stay apart because the two things they describe
# can be shipped separately - an engine binary and a database built a week later
# are the ordinary case, and then the numbers differ on their own.
CFLAGS += -DKOF_PACK_BUILD=$(KOF_BUILD_STAMP)u
CFLAGS += -DKOFENG_BUILD=$(KOF_BUILD_STAMP)u

#
# A CLANG-ONLY WARNING IN VENDORED CODE, SILENCED FOR VENDORED CODE ONLY.
#
# clang reports, on by default and not via -Wall:
#
#   bdx86_decoder.c:2656: passing 'PND_IDBE *' to parameter of type
#   'const ND_IDBE **' discards qualifiers in nested pointer types
#
# It is upstream's and it is real: NdDecodeInstruction takes
# `const ND_IDBE **InsDef`, the caller's local is a plain `PND_IDBE pIns`, and
# C does not let a T** become a const T** without a cast. It is also harmless
# in fact - every use of pIns after that line reads a field and nothing ever
# writes through it - so upstream could have declared the local const and the
# whole thing would disappear.
#
# WE DO NOT PATCH IT, and that is the point of this comment rather than a
# one-line edit to the file. THIRD-PARTY.md states that the bddisasm files are
# unmodified, and says so specifically "so that a later reader does not have to
# diff a release to find out"; Apache 2.0 requires modified files be marked as
# changed. A patch here would cost that claim, would have to be re-applied at
# every version bump, and this tree has already removed one patch to vendored
# code for exactly that reason.
#
# So it is suppressed HERE, in the vendor flag set, which is what this variable
# is for and which already carries four suppressions of the same kind. The
# tree's own code is untouched by it and stays on the full warning tier.
#
# BOTH SPELLINGS OF THE SAME UPSTREAM ISSUE ARE SILENCED.
#
# clang calls it -Wincompatible-pointer-types-discards-qualifiers and reports
# it on by default; gcc reports the same call as -Wincompatible-pointer-types.
# The second was at -Wno-error= in VENDOR_CFLAGS, which demotes it to a warning
# that then prints on every build of a file this tree does not own. Silenced
# rather than demoted, for the vendor set only.
#
# PROBED VIA THE POSITIVE FORM, deliberately. Both compilers accept an unknown
# -Wno-<anything> in silence, so probing the negative form would prove nothing
# and would leave GCC carrying a flag it does not know. The positive spelling is
# rejected by a compiler that has never heard of the warning, which is the
# question actually being asked.
VENDOR_WNO_QUAL := $(if $(call kof_probe,-Wincompatible-pointer-types-discards-qualifiers),\
                        -Wno-incompatible-pointer-types-discards-qualifiers)

VENDOR_CFLAGS := -O2 -g -std=c11 -fno-common -D_LIB -DAMD64 \
                 -Wall -Wextra \
                 -Wno-missing-field-initializers -Wno-missing-braces \
                 -Wno-unused-function \
                 -Wno-incompatible-pointer-types \
                 $(VENDOR_WNO_QUAL) \
                 $(SAN_CFLAGS) $(KOF_CROSS_FLAGS)

EMU_SRC    := $(wildcard libkofemu/*.c)
VENDOR_SRC := $(wildcard libkofemu/bddisasm/src/*.c)

EMU_OBJ    := $(patsubst libkofemu/%.c,$(INT)/emu_%.o,$(EMU_SRC))
VENDOR_OBJ := $(patsubst libkofemu/bddisasm/src/%.c,$(INT)/bdd_%.o,$(VENDOR_SRC))

$(INT)/emu_%.o: libkofemu/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(EMU_INC) -c $< -o $@

$(INT)/bdd_%.o: libkofemu/bddisasm/src/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(CC) $(VENDOR_CFLAGS) $(EMU_INC) -c $< -o $@

$(LIB): $(LIB_OBJ) $(EMU_OBJ) $(VENDOR_OBJ)
	@$(call MKDIR,$(dir $@))
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
           $(SDK)/include/kofmod/wrap.h \
           $(SDK)/include/kofmod/elf.h \
           $(SDK)/include/kofmod/pe.h \
           $(SDK)/include/kofmod/gzip.h \
           $(SDK)/include/kofmod/docole.h \
           $(SDK)/include/kofmod/zip.h \
           $(SDK)/include/kofmod/tar.h \
           $(SDK)/include/kofmod/sevenzip.h \
           $(SDK)/include/kofmod/rar.h \
           $(SDK)/include/kofmod/xz.h \
           $(SDK)/include/kofmod/rtf.h \
           $(SDK)/include/kofmod/pdf.h \
           $(SDK)/include/kofmod/amsi.h \
           $(SDK)/include/kofmod/proc.h \
           $(SDK)/include/kofmod/clr.h

$(SDK)/include/kofeng.h: libkofeng/kofeng.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/kofmod/%.h: libkofeng/core/kofmod/%.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

sdk: $(LIB) $(SDK_HDR)
	$(info $(SP)  $(LIB))

# --------------------------------------------------------------- the scanner
#
# Built from the staged SDK, not from the source tree. That is what keeps the
# public header honest: anything it cannot express shows up here as a compile
# error instead of as a quiet reach into an internal include.

SCANNER_SRC := kofscanner/kofscanner.c

#
# THE SCANNER LINKS THE LINUX COLLECTOR ON LINUX.
#
# --scan-procs is the same scan over a different source of bytes, so it belongs
# in the scanner rather than in a tool of its own - see scan_procs. On Windows
# the collector is libkofgrille and that half is not wired here yet, so the
# option does not exist there and the sources are not linked.
#
# DEFERRED, NOT IMMEDIATE, and the file says why a few hundred lines up: a
# variable referring to one the blocks BELOW set must be `=` or it expands to
# nothing here. ANTARC_SRC and KOFPROC_SRC are defined after this rule.
ifeq ($(NATIVE_OS),windows)
SCANNER_EXTRA =
SCANNER_INC   =
else
SCANNER_EXTRA = $(ANTARC_SRC) libkofantarc/awalk.c $(KOFPROC_SRC) \
                $(KOFRIDGE_SRC) $(KOFEVT_SRC)
SCANNER_INC   = -Ilibkofantarc -Ilibkoforbit/kofevt -Ilibkoforbit/kofmon \
                -Ilibkoforbit/kofproc -Ilibkoforbit/koffridge \
                -Ilibkoforbit/kofwalk
endif

$(OUT)/bin/kofscanner$(EXE): $(SCANNER_SRC) $(SCANNER_EXTRA) $(LIB) \
                             $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include $(SCANNER_INC) \
	      $(SCANNER_SRC) $(SCANNER_EXTRA) $(LIB) -o $@ $(LDFLAGS)

# --------------------------------------------------------------- the examiner
#
# Unlike the scanner, this links the internal collectors: it prints the parsed
# view, and no public surface offers one. The reason that is not a lapse is
# written at the top of the file.

# kofinspect is the half of this tool that is not printing: it asks the loaded
# database what it already knows about an object. Separate because a second
# consumer is coming - the viewer - and because the two halves reach for
# different things: the printer wants the parse, this wants the engine.
# The event-log format, linked into anything that reads one. Defined here
# rather than beside its first user because two rules need it and a variable
# used before it is set expands to nothing - the trap this file has now been
# caught by twice.
KOFEVT_SRC := libkoforbit/kofevt/kofevt.c libkoforbit/kofevt/kofevtfmt.c \
              libkoforbit/kofevt/kofevtlog.c

# The verdict cache. Orbit, not the engine, for the reason koffridge.h gives:
# what an answer is keyed on and how long it stays good are a host's policy.
KOFRIDGE_SRC := libkoforbit/koffridge/koffridge.c

# The process record builder, shared by both collectors - see kofproc.h.
KOFPROC_SRC := libkoforbit/kofproc/kofproc.c

#
# THE LINUX COLLECTOR. Both halves: the snapshot walk over /proc and the
# fanotify stream. It is the mirror of libkofgrille and builds only on Linux,
# the way that one builds only for Windows - a collector is the one part of
# this tree that cannot be platform-neutral, which is why everything it hands
# over is.
ANTARC_SRC := libkofantarc/aproc.c \
              libkofantarc/apagemap.c \
              libkofantarc/afan.c

ifeq ($(NATIVE_OS),windows)
ANTARC_INC :=
else
ANTARC_INC := -Ilibkofantarc -Ilibkoforbit/kofevt -Ilibkoforbit/kofmon
endif

# The report. Orbit for the same reason the cache is: it hashes artefacts and
# asks the engine what they are, so it depends on libkofeng - and libkofeng
# must be able to ship without knowing that anything called a report exists.
KOFREPORT_SRC := libkoforbit/kofreport/kofreport.c \
                 libkoforbit/kofreport/kofrepart.c \
                 libkoforbit/kofreport/kofrepfmt.c

EXAMINE_SRC := kofexamine/kofexamine.c kofexamine/kofinspect.c kofexamine/kofeditor.c

$(OUT)/bin/kofexamine$(EXE): $(EXAMINE_SRC) $(KOFEVT_SRC) $(LIB) $(SDK_HDR) \
                            $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include $(EXAMINE_SRC) $(KOFEVT_SRC) \
	      $(LIB) -o $@ $(LDFLAGS)

# The other front end onto the same layer. Two binaries from one directory, and
# the directory is the toolchain rather than the tool: what they share is
# kofinspect, and what differs is only how a pane and a line are drawn.
#

VIEWER_SRC := kofexamine/kofviewer.c kofexamine/kofview.c kofexamine/kofinspect.c kofexamine/kofeditor.c

# EMU_INC because the viewer disassembles: bddisasm's definitions are already
# inside $(LIB) - the emulator put them there - so what is missing is only the
# header, and linking a second copy of the decoder would be the alternative.
#
# kofevt is linked in because the viewer BROWSES an event log: it reads the
# header, counts the records, and asks where each one is so a hex pane can be
# pointed at it. The engine cannot answer any of that - a log is not a scanned
# object - which is why the format lives beside the engine and not inside it.
$(OUT)/bin/kofviewer$(EXE): $(VIEWER_SRC) $(KOFEVT_SRC) $(LIB) $(SDK_HDR) \
                            $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include -Ilibkoforbit/kofevt $(EMU_INC) \
	      $(VIEWER_SRC) $(KOFEVT_SRC) $(LIB) -o $@ $(LDFLAGS)

# ----------------------------------------------------- the database toolchain
#
# One binary with two modes: --extract reads the declarations out of a signature
# source, and the default mode packs compiled artefacts into .ksig. Build-time
# only, and deliberately not linked into anything that runs on an endpoint.

#
# kofwatchman: THE ONE TOOL IN THIS FAMILY THAT IS NOT PLATFORM SPECIFIC.
#
# kofwatchtower and kofmontrace link libkofgrille and only build for Windows,
# because collecting is where the platform lives. kofwatchman does not collect
# - it reads a recorded log and decides - so it links the ENGINE and kofevt and
# nothing else, and it builds wherever the engine does.
#
# That is not a convenience, it is the point of the record having been
# normalised: a log written on Windows is analysed here, on the CI, by the same
# binary a Windows machine would run. Every event rule that ever exists becomes
# testable because of this line.
#
# On Windows it also links the collector, for the live channel - which is a
# Windows transport, so off Windows the recording path is the whole program.
# See the note at the top of kofwatchman.c.
#
# `=` AND NOT `:=`, AND THAT IS THE WHOLE OF THIS COMMENT.
#
# WINLIB and WIN_LDLIBS are set by the Windows block a hundred lines BELOW
# this. A `:=` here expands them immediately, which is to say to nothing, and
# the link then succeeds at finding no collector - undefined kofw_chan_* and a
# reader with no reason to suspect the Makefile. Deferred, they expand when the
# recipe runs, by which time the block has been read.
#
# This is the same trap the note on `tools:` further down describes. It has now
# caught two things in this file, so: anything referring to a variable the
# Windows block sets must be deferred, or must be inside the block.
#
# ONE CONTRACT, TWO BACKENDS, AND THE HOST PICKS. Until the channel moved into
# libkoforbit this was "Windows or nothing", because the only transport there
# had was CreateFileMapping. chan_posix.c is a real one, so a Linux build now
# attaches to a Linux sensor instead of being recording-only - which is the
# whole thing the move was for.
#
# KOF_HAVE_CHAN is what the client tests. Not _WIN32: that asked which OS this
# is, and what the code meant was whether a backend is linked.
ifeq ($(NATIVE_OS),windows)
WATCHMAN_CHAN = -DKOF_HAVE_CHAN -Ilibkoforbit/kofchan \
                libkoforbit/kofchan/chan_win.c $(WINLIB) $(WIN_LDLIBS)
else
WATCHMAN_CHAN = -DKOF_HAVE_CHAN -Ilibkoforbit/kofchan \
                libkoforbit/kofchan/chan_posix.c -lrt
endif

$(OUT)/bin/kofwatchman$(EXE): kofwatcher/kofwatchman.c $(KOFEVT_SRC) $(LIB) \
                              $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkofeng -Ilibkoforbit/kofevt $< \
	      $(KOFEVT_SRC) $(LIB) -o $@ $(LDFLAGS) $(WATCHMAN_CHAN)

kofwatchman: $(OUT)/bin/kofwatchman$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

#
# kofmemscan: THE ENGINE AND THE SNAPSHOT IN ONE PROGRAM, so Windows only.
#
# It is the first tool that needs both halves - libkofgrille to find what is
# mapped, libkofeng to say what it is - and it is built with the NATIVE
# compiler rather than the cross one, because it has to run on the machine it is
# inspecting. That is why it appears here beside kofwatchman and not in the
# cross-build block: the cross block produces binaries for a Windows host, and
# this one is only ever built ON that host.
#
# $(WINLIB) comes in through WATCHMAN_CHAN, which is empty off Windows - so this
# rule exists everywhere and the target below is only offered where it links.
#
# -Ilibkofgrille IS NAMED HERE, and that is the point rather than a detail. It
# used to arrive through WATCHMAN_CHAN, which is the variable that says how this
# host talks to a sensor - so the include path for wproc.h was riding on a
# variable about something else entirely. The day the channel moved into
# libkoforbit that flag went with it and this tool stopped compiling, while a
# binary from the previous build sat in build/release/bin looking like it had
# worked. A prerequisite that is real is cheaper stated than inherited.
$(OUT)/bin/kofmemscan$(EXE): kofwatcher/kofmemscan.c $(KOFRIDGE_SRC) $(LIB) \
                             $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkofeng -Ilibkofeng/kofparsers \
	      -Ilibkofgrille \
	      -Ilibkoforbit/koffridge -Ilibkoforbit/kofevt $< \
	      $(KOFRIDGE_SRC) $(LIB) -o $@ $(LDFLAGS) $(WATCHMAN_CHAN)

kofmemscan: $(OUT)/bin/kofmemscan$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

# kofmontrace is built like this one and for the same reason - it links the
# engine now - but its rule cannot live here: the target name needs $(WIN_EXE)
# and $(WINLIB), which the Windows block sets hundreds of lines BELOW. See the
# note beside `tools:` down there, where it is.

$(OUT)/bin/ksigbuilder$(EXE): ksigbuilder/ksigbuilder.c $(LIB) $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) $< $(LIB) -o $@ $(LDFLAGS)

# ------------------------------------------------ libkofgrille: Windows events
#
# A SIBLING OF libkofeng, NOT A PART OF IT.
#
# The engine takes bytes and says what they are; this takes the machine's own
# activity and turns it into records. Nothing here includes kofeng.h and nothing
# in libkofeng includes kofgrille.h, so the dependency runs one way and stays that
# way by failing to compile otherwise rather than by a note asking for care.
#
# WINDOWS TARGET, BUT NOT A WINDOWS-ONLY BUILD - AND THE DIFFERENCE IS THE
# WHOLE REASON THIS BLOCK IS SHAPED LIKE THIS.
#
# It used to be gated on `NATIVE_OS == windows`, so a Linux tree compiled not
# one line of it. That is not the same cost as "cannot be tested": the tree is
# built with -Wall -Wextra -Wconversion -Wsign-conversion and a second probed
# tier on top, and a warning is worth exactly as many times as somebody sees
# it. A directory no CI ever compiles is a directory where they pile up unseen,
# which is what had already happened - two -Wcast-qual findings sat in
# wevt_decode.c from the day it landed, in a tree whose Makefile says it passes
# that tier with zero findings.
#
# So the gate is now the TOOLCHAIN, not the host. On Windows nothing changes.
# On anything else a mingw cross-compiler builds it if one is installed, and if
# none is, this block quietly does not exist exactly as before.
#
# Cross-compiling still cannot RUN any of it - there is no ETW on Linux and no
# pretending otherwise. It type-checks every line and links every symbol, and
# the half that CAN run (wevt_ring.c, wfilter.c, wtext.c) is covered natively
# by tests/unit/grille_host.c.
ifeq ($(NATIVE_OS),windows)
WIN_CC ?= $(CC)
WIN_AR ?= $(AR)
else
WIN_CC ?= $(shell command -v x86_64-w64-mingw32-gcc 2>/dev/null)
WIN_AR ?= $(shell command -v x86_64-w64-mingw32-ar 2>/dev/null)
endif

# .exe whichever host built it, because the artefact is a Windows binary. $(EXE)
# is the NATIVE suffix and is empty on Linux, which would name a PE file
# something no Windows will execute by double-click.
WIN_EXE := .exe

ifneq ($(WIN_CC),)
ifneq ($(WIN_AR),)

#
# THE WARNING SET, RESTATED RATHER THAN TAKEN FROM $(CFLAGS).
#
# $(CFLAGS) carries the host's include paths, the build-stamp defines and
# whatever a sanitiser target appended - none of which a mingw cross-compiler
# can use. What has to match is the WARNINGS, so that a finding here is the
# same finding the rest of the tree would have reported. Natively there is no
# such distinction and $(CFLAGS) is used unchanged.
#
ifeq ($(NATIVE_OS),windows)
WIN_CFLAGS  := $(CFLAGS)
WIN_LDFLAGS := $(LDFLAGS)
else
WIN_CFLAGS  := -std=c11 -O2 -g -fno-common \
               -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion \
               -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
               $(KOF_WARN_PORTABLE) $(KOF_WARN_GCC) -MMD -MP \
               -DKOFENG_BUILD=$(KOF_BUILD_STAMP)u
WIN_LDFLAGS :=
endif

WIN_SRC := libkofgrille/wevt_ring.c \
           libkofgrille/wfilter.c \
           libkofgrille/wcmdline.c \
           libkofgrille/wproc.c \
           libkofgrille/wtext.c \
           libkofgrille/wevt_decode.c \
           libkofgrille/wevt_etw.c

#
# The log format is a component of its own under libkofeng, not part of the
# Windows collector - see libkoforbit/kofevt/kofevt.h for why it is there and why
# it includes nothing from the engine. It is compiled into libkofgrille.a so a
# tool links one archive, and the SAME source compiles natively for the host
# tests, which is the point of it having no Windows in it.
WIN_SRC += libkoforbit/kofevt/kofevt.c libkoforbit/kofevt/kofevtfmt.c \
           libkoforbit/kofevt/kofevtlog.c

WIN_OBJ := $(patsubst libkofgrille/%.c,$(INT)/win_%.o,\
                      $(filter libkofgrille/%,$(WIN_SRC))) \
           $(patsubst libkoforbit/kofevt/%.c,$(INT)/win_evt_%.o,\
                      $(filter libkoforbit/kofevt/%,$(WIN_SRC)))

$(INT)/win_evt_%.o: libkoforbit/kofevt/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(WIN_CC) $(WIN_CFLAGS) $(DEPTO) -Ilibkoforbit/kofevt -c $< -o $@
WINLIB  := $(SDK)/lib/libkofgrille.a

$(INT)/win_%.o: libkofgrille/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(WIN_CC) $(WIN_CFLAGS) $(DEPTO) -Ilibkofgrille -Ilibkoforbit/kofevt -c $< -o $@

$(WINLIB): $(WIN_OBJ)
	@$(call MKDIR,$(dir $@))
	$(WIN_AR) rcs $@ $^

# tdh for the one-time schema lookup, advapi32 for the session itself, psapi for
# the snapshot half - the module list, the mapped-file name, the working-set
# query. All three are import libraries that ship with every Windows toolchain,
# so this adds nothing the build did not already depend on.
WIN_LDLIBS := -ltdh -ladvapi32 -lpsapi

# Two programs out of one directory (kofwatcher/), over one collector:
# kofwatchtower is the
# SENSOR - it watches the machine and does nothing else with what it sees -
# and kofmontrace watches one program it launches. They are separate binaries
# because their arguments, lifetimes and exit conditions have nothing in common,
# and kofevtfmt.c holds the part that is genuinely the same - rendering an
# event, the tally, the health lines.
#
# ONLY THE SENSOR IS BUILT HERE NOW. kofmontrace grew a dependency on the
# engine and moved up beside kofmemscan, which is where the tools that link
# both halves live - see the note there for what that cost. The sensor links
# the collector and nothing else, so it still cross-builds, which is what keeps
# every line of libkofgrille type-checked on a host with no ETW.

# The channel is no longer part of the collector: it moved to
# libkoforbit/kofchan, which is one contract with two backends. The sensor
# names the Windows one.
$(OUT)/bin/kofwatchtower$(WIN_EXE): kofwatcher/kofwatchtower.c \
                                    libkoforbit/kofchan/chan_win.c \
                                    $(WINLIB) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(WIN_CC) $(WIN_CFLAGS) $(DEPTO) -Ilibkofgrille -Ilibkoforbit/kofevt \
	      -Ilibkoforbit/kofchan -Ikofwatcher \
	      kofwatcher/kofwatchtower.c libkoforbit/kofchan/chan_win.c \
	      $(WINLIB) -o $@ $(WIN_LDFLAGS) $(WIN_LDLIBS)

kofgrille: $(WINLIB)
	$(info $(SP)  $<)
	@$(NOOP)




# Added to `tools` here rather than in its own line above, because a
# prerequisite naming a variable this block sets would expand to nothing:
# make expands a rule's prerequisites when it reads the rule, and that happens
# hundreds of lines before this.
#
# ADDED TO `tools` ONLY WHERE THEY ARE THE HOST'S OWN BINARIES.
#
# A Linux `make tools` must not start requiring a cross-compiler, and a PE file
# it could not run has no business in a native tools build. Cross-building is
# what `make kofgrille` and `make kofwatchtower` are for, and the CI asks for those
# by name.
#
# Written here rather than beside the other `tools` prerequisites because make
# expands a rule's prerequisites when it READS the rule, hundreds of lines
# above this, where none of these variables are set yet.
ifeq ($(NATIVE_OS),windows)
tools: kofwatchtower kofmontrace kofmemscan

#
# kofmontrace: OUT OF THE CROSS BUILD, AND IT COST SOMETHING.
#
# It used to build with $(WIN_CC) beside kofwatchtower above, which meant a
# Linux tree with mingw installed type-checked every line of it. It now links
# the ENGINE - it hashes what the traced program created, asks what those files
# are, and checks whether an observed string is actually in the sample's bytes
# - and $(LIB) is built by $(CC) for the host, so a cross-build would hand a
# Linux archive to a mingw linker.
#
# So it is native, like kofmemscan: engine and collector in one binary, built
# only on the machine it runs on. What is lost is the cross type-check for
# THIS FILE. kofwatchtower stays above and still covers every line of
# libkofgrille, which is where the platform actually lives.
#
# AND IT IS HERE, INSIDE THIS ifeq, FOR THE REASON THE NOTE ABOVE GIVES ABOUT
# `tools`. Placed up beside kofmemscan it expanded $(WIN_EXE) to NOTHING -
# make expands a rule's target and prerequisites when it READS them, and
# WIN_EXE is set in this block. The rule then existed for a target called
# `kofmontrace` with no extension, `make kofmontrace` found the real .exe
# up to date with no rule to rebuild it, and printed a success line for a
# binary it had not touched. Which is this file's own trap, caught a third
# time: anything naming a variable this block sets must be inside it.
$(OUT)/bin/kofmontrace$(WIN_EXE): kofwatcher/kofmontrace.c $(KOFREPORT_SRC) \
                                  $(LIB) $(WINLIB) $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkofeng -Ilibkofeng/core -Ilibkofgrille \
	      -Ilibkoforbit/kofevt -Ilibkoforbit/kofreport -Ikofwatcher \
	      kofwatcher/kofmontrace.c $(KOFREPORT_SRC) $(WINLIB) $(LIB) \
	      -o $@ $(LDFLAGS) $(WIN_LDLIBS)

#
# THE COLLECTOR IS A PREREQUISITE OF kofwatchman ON WINDOWS, declared here
# because a prerequisite naming $(WINLIB) up where that rule lives would expand
# to nothing - make reads prerequisites when it reads the rule, and that is
# before this block. A target may collect prerequisites from more than one
# place, which is what makes this the fix rather than a duplicate rule.
#
# Without it the archive and the binary race: a clean `make tools` can link
# kofwatchman against a libkofgrille.a that has not been built yet.
$(OUT)/bin/kofwatchman$(EXE): $(WINLIB)
endif

endif
endif

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
#   bases/decomp/      the CONTAINER unpackers - gzip, zip, tar, rar, 7z, xz,
#                      docole, rtf, overlay. A file that carried other files.
#   bases/unp/         the PACKER unpackers - UPX, Ezuri, midgetpack, the msf
#                      encoders. A file that IS the payload, transformed.
#
# The directory is the module's KOF_UNPACK_KIND and nothing else, so the split
# is checkable in one line rather than remembered:
#
#   grep -L KOF_UNP_CONTAINER bases/decomp/*.c   # must print nothing
#   grep -L KOF_UNP_PACKER    bases/unp/*.c      # must print nothing
#
# It was not that before. The rule above was stated by EXAMPLE - "gzip, zip,
# tar" - and eight of the nine containers had drifted into bases/unp/ while zip
# and tar, named here as decomp, were among them. A split described by examples
# is a split nothing checks.
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
# The linker that links a MODULE, which is not always the one that links this
# project's own tools: a module is freestanding position-independent code with a
# script of its own, and on Windows that is lld rather than the system linker.
#
# $(EXE) is not decoration here. ksigbuilder starts the linker with
# CreateProcess, and Windows only appends ".exe" for a name that carries no
# extension at all - "ld.lld" already has one as far as it is concerned, so it
# looks for a file called exactly that, does not find it, and the build stops
# at "FAIL: link returned -1" naming nothing that would point here.
LD_FOR_SIGS ?= $(if $(filter windows,$(NATIVE_OS)),ld.lld$(EXE),ld)

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

#
# WHAT THE MODULE BUILD READS, exported once rather than prefixed per command.
#
# `VAR=value command` is sh's way of setting a variable for one process and
# PowerShell has no equivalent, so the settings that used to ride in front of
# every ksigbuilder invocation are put in the environment here instead. make
# does that identically on both platforms, and the recipe below is then a
# command and its arguments - which is the only shape both shells agree on.
export KOF_INCLUDE       := $(abspath $(OUT)/include)
export KOF_LDSCRIPT      := $(abspath ksigbuilder/module.ld)
export KOF_TARGET_TRIPLE
export LD                := $(LD_FOR_SIGS)
export CC

#
# One process for the whole tree - see ksigbuilder's --tree.
#
# This was a shell loop over $(SIGS) calling --module once per source, which
# needed `for`, `||` and a variable prefix, none of which mean anything to
# PowerShell. It is not replaced by a foreach that spawns a shell per source:
# walking the tree, the order, and packing what comes out are decisions
# ksigbuilder already owns, and it does them in one process on any host with a
# compiler and nothing else.
databases: $(OUT)/bin/ksigbuilder$(EXE) $(SDK_HDR)
	@$(call RMRF,$(ARTEFACTS))
	@$(call RMRF,$(DB))
	@$(call MKDIR,$(ARTEFACTS))
	@$(call MKDIR,$(DB))
	@$(call EXEC,$(OUT)/bin/ksigbuilder$(EXE)) --tree $(BASEDIR) $(ARTEFACTS) $(DB)
	$(info $(SP)   scan with: $(OUT)/bin/kofscanner$(EXE) --db $(DB) --scan-files <path>)

# Kept as a name because it is in muscle memory and in scripts; the artefacts
# and the database now come out of the same single command.
sigs: databases

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
	@$(MKFIXTURES) $(FIXTURES)

UNIT_SRC := $(wildcard tests/unit/*.c)
UNIT_BIN := $(patsubst tests/unit/%.c,$(TEST)/unit_%$(EXE),$(UNIT_SRC))

# Linked against the library, so a unit test can exercise it rather than only
# whatever it can compile in on its own.
#
# UNIT_LIBS_<name> adds what one test needs. Only the differential decompressor
# test uses it: it links zlib as an ORACLE, to check our decoder against, which is
# the one thing the library must never do itself.
#
# Statically on Windows, for the reason winpthread is static above: a
# dynamically linked zlib1.dll is only ever on PATH inside an MSYS2 shell, and
# from anywhere else the test does not report an error - Windows refuses to
# start the process before main() runs, so there is nothing to print. It comes
# back as exit code 0xC0000135 and no output at all, which reads like a crash
# in the test rather than a missing DLL.
ifeq ($(NATIVE_OS),windows)
UNIT_LIBS_inflate_diff := -Wl,-Bstatic -lz -Wl,-Bdynamic
else
UNIT_LIBS_inflate_diff := -lz
endif

#
# $(EXE) AND NOT $(WIN_EXE). These two used to name the cross-built PE
# unconditionally, which on Linux meant `make kofwatchtower` demanded mingw and
# `make kofmontrace` was a Windows-only line in the help - both tools now build
# for the host, and the name has to follow the host or the native binary has no
# way to be asked for. On Windows $(EXE) IS .exe, so the cross build is
# unchanged.
kofwatchtower: $(OUT)/bin/kofwatchtower$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

kofmontrace: $(OUT)/bin/kofmontrace$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

#
# THE SAME TOOLS, BUILT NATIVELY, ON A HOST THAT HAS A COLLECTOR FOR ITSELF.
#
# ONE SOURCE FILE EACH, NOT TWO. kofwatchtower.c and kofmontrace.c each carry a
# single adapter block that names the host's collector and how a subject is
# started and contained; everything below it is the same code on both. What
# changes between these recipes is therefore the LIBRARY and the INCLUDES, not
# the file - which is the only arrangement in which a fix to the drain loop
# cannot land on one platform and miss the other.
ifneq ($(NATIVE_OS),windows)

POSIX_TOOL_INC = -Ilibkofantarc -Ilibkoforbit/kofevt -Ilibkoforbit/kofmon \
                 -Ilibkoforbit/kofchan

$(OUT)/bin/kofwatchtower$(EXE): kofwatcher/kofwatchtower.c $(ANTARC_SRC) \
                                libkoforbit/kofchan/chan_posix.c \
                                $(KOFEVT_SRC) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) $(POSIX_TOOL_INC) \
	      kofwatcher/kofwatchtower.c $(ANTARC_SRC) \
	      libkoforbit/kofchan/chan_posix.c $(KOFEVT_SRC) \
	      -o $@ $(LDFLAGS) -lrt

# Links the ENGINE for the same reason the Windows recipe below does: the
# report hashes what the traced program created and asks what those files are.
$(OUT)/bin/kofmontrace$(EXE): kofwatcher/kofmontrace.c $(ANTARC_SRC) \
                              $(KOFREPORT_SRC) $(KOFEVT_SRC) $(LIB) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) $(POSIX_TOOL_INC) -Ilibkofeng \
	      -Ilibkofeng/core -Ilibkoforbit/kofreport -Ikofwatcher \
	      kofwatcher/kofmontrace.c $(ANTARC_SRC) $(KOFREPORT_SRC) \
	      $(KOFEVT_SRC) $(LIB) -o $@ $(LDFLAGS)

# The host's own binaries, so they belong in `tools` here - the Windows block
# below adds the .exe pair for the same reason and by the same mechanism.
tools: kofwatchtower kofmontrace

endif

$(TEST)/unit_%$(EXE): tests/unit/%.c $(LIB) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) $< $(LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

# The draft model is not in the library, so the one test over it says so here.
#
# A signature draft is what the viewer edits, not what the engine scans with, so
# kofeditor.c lives beside the tools rather than inside libkofeng - and a test
# over it has to compile that source. An explicit rule rather than another
# pattern variable: exactly one test needs this, and a rule states the whole
# dependency in the place somebody reading the recipe is already looking.
# kofinspect now describes events as well as objects, so whatever links it
# needs the event record with it - see kof_inspect_event.
# The verdict cache is not in the library either - it is orbit's - so the test
# over it compiles that source the same way.
# The process record builder is orbit's too, for the same reason, so the test
# that drives a process end to end compiles it the same way.
$(TEST)/unit_proc_rule$(EXE): tests/unit/proc_rule.c $(KOFPROC_SRC) $(LIB) \
                              $(SDK_HDR) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkoforbit/kofproc -I$(SDK)/include \
	      tests/unit/proc_rule.c $(KOFPROC_SRC) $(LIB) -o $@ $(LDFLAGS)

$(TEST)/unit_fridge$(EXE): tests/unit/fridge.c $(KOFRIDGE_SRC) $(LIB) $(STAMP) \
                           | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) tests/unit/fridge.c $(KOFRIDGE_SRC) $(LIB) \
	      -o $@ $(LDFLAGS)

#
# The report, over synthetic records and NOT over a trace.
#
# kofmontrace needs an elevated prompt, a live sample and an ETW session, so
# the report cannot be exercised by running the tool - and the collector is not
# the half worth testing anyway. What this covers is everything that happens
# after an event arrives, and it covers it by writing struct kof_evt by hand.
#
# Which is the property the fixed record was chosen for, and kofevtlog.h says
# so: a rule that cannot be run against a recorded trace cannot be regression
# tested. These records are a recorded trace that never needed a machine.
$(TEST)/unit_report_model$(EXE): tests/unit/report_model.c $(KOFREPORT_SRC) \
                                 $(KOFEVT_SRC) $(LIB) $(STAMP) | $(TEST)
#
# NO -D_GNU_SOURCE HERE ANY MORE, and that is the fix rather than the omission.
#
# kofplatform.h reaches for memmem, lstat and realpath and this test calls
# rmdir; none of those is declared under a bare -std=c11, and without them the
# translation unit compiles them as implicit int - four errors naming three
# files and saying nothing about the cause. The flag used to live here, with a
# note saying anything that later built libkoforbit/kofreport on Linux would
# need it too. Something did: the native kofmontrace. So the declaration moved
# INTO the two sources that need it, where it cannot be left off a new recipe,
# and is guarded there because those recipes also build sources that define it
# themselves.
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkoforbit/kofreport \
	      -Ilibkoforbit/kofevt -Ilibkofeng -Ilibkofeng/core \
	      tests/unit/report_model.c \
	      $(KOFREPORT_SRC) $(KOFEVT_SRC) $(LIB) -o $@ $(LDFLAGS)

EDITOR_SRC := kofexamine/kofeditor.c kofexamine/kofinspect.c $(KOFEVT_SRC)

#
# THE ETW-FREE HALF OF libkofgrille, TESTED ON WHATEVER HOST IS RUNNING.
#
# Not linked against $(LIB): libkofgrille is a SIBLING of libkofeng and nothing
# in either includes the other's header, so a test that pulled the engine in
# would be the first thing in the tree to cross that line.
#
# These three files are the ones their own headers promise call no Windows API,
# and the promise is worth what compiles it. It is checked here rather than
# assumed: the sources are listed explicitly, so the day somebody adds
# #include <windows.h> to one of them this test stops building on Linux and
# says which file did it. That is the whole enforcement mechanism, and it has
# already caught one - kofw_evt_image() and kofw_evt_object() were in
# wevt_decode.c, so wfilter.c could not link without the Windows half.
# The channel is not here either, and no longer could be: it left the collector
# for libkoforbit/kofchan, where the neutral contract has a Windows backend and
# a POSIX one. chan_posix.c is what this host can actually RUN, which the
# Windows transport never was. This list is
# exactly the files whose headers promise they call no OS API, and the promise
# is worth what compiles it - a file added here that includes windows.h stops
# the Linux build and names itself.
GRILLE_HOST_SRC := libkofgrille/wevt_ring.c libkofgrille/wfilter.c \
                   libkofgrille/wtext.c \
                   libkoforbit/kofevt/kofevt.c \
                   libkoforbit/kofevt/kofevtfmt.c \
                   libkoforbit/kofevt/kofevtlog.c

$(TEST)/unit_grille_host$(EXE): tests/unit/grille_host.c $(GRILLE_HOST_SRC) \
                                $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkofgrille -Ilibkoforbit/kofevt $< \
	      $(GRILLE_HOST_SRC) -o $@ $(LDFLAGS)

$(TEST)/asan_grille_host$(EXE): tests/unit/grille_host.c $(GRILLE_HOST_SRC) \
                                $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) $(DEPTO) -Ilibkofgrille \
	      -Ilibkoforbit/kofevt $< $(GRILLE_HOST_SRC) -o $@ \
	      $(LDFLAGS) $(ASAN_FLAGS)

$(TEST)/unit_cond_expr$(EXE): tests/unit/cond_expr.c $(EDITOR_SRC) $(LIB) \
                              $(SDK_HDR) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include $< $(EDITOR_SRC) $(LIB) \
	      -o $@ $(LDFLAGS)

$(TEST)/asan_cond_expr$(EXE): tests/unit/cond_expr.c $(EDITOR_SRC) \
                              $(ASAN_LIB) $(SDK_HDR) $(STAMP) | $(TEST)
	@$(CC) $(CFLAGS) $(ASAN_FLAGS) -I$(SDK)/include $< $(EDITOR_SRC) \
	       $(ASAN_LIB) -o $@ $(LDFLAGS)

# The engine's own signature set is BUILT here, not merely present.
#
# It is not part of `make db`, so nothing else compiles it - and a rename that
# missed it went unnoticed until somebody tried. A signature set that is never
# built is a signature set that has already rotted; building it with the tests is
# what keeps the module ABI's own examples honest about the ABI.
test-sigs:
	@$(MAKE) --no-print-directory databases BASEDIR=tests/sigs

#
# ONE TARGET PER TEST, rather than one recipe looping over all of them.
#
# The loop was sh - `for`, `if`, a shell variable holding the tally - and none
# of it survives a shell that is not sh. A target per binary is what make is
# for: it needs no shell control flow, it names the failing test in make's own
# error line, and `make -j` can run them at once.
#
# The one thing that changes is that the run now STOPS at the first failing
# test instead of running the rest and summarising. `make -k unit` restores
# the old behaviour where that is wanted, and a first failure is usually the
# one worth reading anyway.
UNIT_RUN := $(addprefix run-,$(UNIT_BIN))

$(UNIT_RUN): run-%: %
	$(info == $(notdir $*))
	@$(call EXEC,$*)

unit: fixtures test-sigs $(UNIT_RUN)
	$(info all $(words $(UNIT_BIN)) test(s) passed)
	@$(NOOP)

# Everything -MMD wrote. Missing on a clean tree, which is why it is a soft
# include: nothing to rebuild yet, and the first compile creates them.
#
# A PREREQUISITE THAT ONLY A STALE DEPENDENCY FILE STILL BELIEVES IN.
#
# -MMD -MP already covers headers: -MP emits a phony target for each one, so a
# header that moves does not stop the build. It does NOT cover sources, because
# a link rule's .d lists the .c files it was built from - and when one of those
# moves, make refuses with "No rule to make target '<old path>', needed by
# <binary>" until somebody works out that the answer is to delete build/temp.
#
# That has now cost this tree two file moves, and the second one was worse than
# the first: the build had been broken for an hour while every test appeared to
# pass, because the tools being run were the last ones that linked.
#
# Named per library rather than as a bare "%.c", which was tried and is too
# greedy: it let make believe it could produce tests/unit/<anything>.c, so a
# pattern rule matched a name that was never a source and the compiler was
# handed "elf_rebuild.d.c". These match only the trees that hold sources.
#
# What is lost: a source deleted by accident now fails at the compiler with
# "No such file or directory" naming the file, rather than at make. That is the
# better error of the two - it names what is missing rather than what wanted it.
libkofeng/%.c: ;
libkofeng/%.h: ;
libkoforbit/%.c: ;
libkoforbit/%.h: ;
libkofgrille/%.c: ;
libkofgrille/%.h: ;
kofexamine/%.c: ;
kofexamine/%.h: ;
kofwatcher/%.c: ;
kofwatcher/%.h: ;

#
# A DEPENDENCY FILE IS DATA, NEVER A TARGET.
#
# The include below is soft, so a missing .d is not an error - but make still
# asks whether it could MAKE one, and left to its built-in rules it decides
# that it can. `%: %.o` is built in, the object rules above match anything in
# their own tree, and the chain that falls out is: to get
# build/temp/lib_kofdb/kofdb.d, first build kofdb.d.o, which needs
# kofdb.d.c. The empty source rules just above then tell make that file is
# fine, so nothing stops it, and the compiler is handed a name no source ever
# had - "no such file or directory: libkofeng/kofdb/kofdb.d.c", once per
# library, naming a file nobody wrote.
#
# Reached whenever such a .d exists at all, because the intermediate .o it
# would be built from never does - so it is not a stale-tree problem that a
# clean would fix. It stays latent on the cmd build only because `dir /s /b`
# answers in absolute paths with backslashes, which match no pattern rule;
# POSIX FIND_DEPS answers in relative ones and they match at once.
#
# One empty rule ends it: a .d under the build tree is up to date by
# definition, so make stops hunting for a way to produce one. The files
# themselves are untouched and header tracking is unaffected - this says
# nothing about their CONTENT, only that they are not products.
$(BUILD)/%.d: ;

-include $(shell $(FIND_DEPS))

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
# One flat directory of objects, so a source's path becomes its name.
#
# This was `echo $f | tr / _ | sed 's/.c$/.o/'` - three POSIX tools to do what
# make's own $(subst) does in one, and three tools the Windows build would
# have had to find. The object list is then computed here rather than globbed
# in the recipe: make expands a whole recipe before running any of its lines,
# so a $(wildcard) would see the directory as it was BEFORE the compiles, and
# a shell glob would need a shell that globs - which PowerShell, for a native
# command, does not.
asan_obj = $(TEST)/asan-obj/$(subst /,_,$(1:.c=.o))
ASAN_OBJ := $(foreach f,$(LIB_SRC) $(EMU_SRC) $(VENDOR_SRC),$(call asan_obj,$(f)))

# A literal newline, so $(foreach) can put each command on its own recipe line
# - which is what makes make run them one at a time and stop at the first that
# fails, the same thing `|| exit 1` did inside the old loop.
define NL


endef

#
# The emulator goes in too. It is the newest code here and the one that owns the
# most raw memory - a sparse page table, lazily committed mappings and the
# payload snapshots - so leaving it out would exempt exactly what most needs
# checking. bddisasm comes along because the emulator cannot link without it,
# but with the vendor's own warning flags: it is not ours to fix.
#
$(ASAN_LIB): $(LIB_SRC) $(EMU_SRC) $(VENDOR_SRC) $(SDK_HDR) | $(TEST)
	@$(call RMRF,$(TEST)/asan-obj)
	@$(call MKDIR,$(TEST)/asan-obj)
	@# EMU_INC here as well as on the two loops below: libkofeng itself now
	@# contains a file that includes bddisasm - kofdisasm/xref.c - so the
	@# library's own sources need the decoder's include path. The release
	@# build gives it that through a per-directory rule; this loop has no
	@# per-directory anything, and without the flag it stopped building
	@# entirely ("fatal error: bddisasm.h: No such file or directory"), which
	@# is how the sanitizer target came to be broken while make unit stayed
	@# green. Two compiles of one library are two things to keep in step.
	@$(foreach f,$(LIB_SRC),$(CC) $(CFLAGS) $(ASAN_FLAGS) $(EMU_INC) \
		-c $(f) -o $(call asan_obj,$(f))$(NL))
	@$(foreach f,$(EMU_SRC),$(CC) $(CFLAGS) $(ASAN_FLAGS) $(EMU_INC) \
		-c $(f) -o $(call asan_obj,$(f))$(NL))
	@$(foreach f,$(VENDOR_SRC),$(CC) $(VENDOR_CFLAGS) $(ASAN_FLAGS) $(EMU_INC) \
		-c $(f) -o $(call asan_obj,$(f))$(NL))
	@$(AR) rcs $@ $(ASAN_OBJ)

$(TEST)/asan_%$(EXE): tests/unit/%.c $(ASAN_LIB) $(STAMP) | $(TEST)
	@$(CC) $(CFLAGS) $(ASAN_FLAGS) $< $(ASAN_LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

#
# The sanitizers' own settings, exported rather than written in front of each
# command for the reason the module build's settings are - `VAR=value cmd` is
# sh, and this Makefile no longer assumes one.
#
# detect_leaks and abort_on_error are the sanitizer's; halting on a finding is
# what -fno-sanitize-recover in ASAN_FLAGS already asks for, so a failing test
# fails the target through make rather than through a tally kept in a shell
# variable.
export ASAN_OPTIONS  := detect_leaks=1:abort_on_error=0
export UBSAN_OPTIONS := print_stacktrace=1

ASAN_RUN := $(addprefix run-,$(ASAN_BIN))

$(ASAN_RUN): run-%: %
	$(info == $(notdir $*))
	@$(call EXEC,$*)

unit-asan: fixtures test-sigs $(ASAN_RUN)
	$(info all $(words $(ASAN_BIN)) sanitized test(s) passed)
	@$(NOOP)

clean:
	@$(call RMRF,$(BUILD))

.PHONY: all sdk sigs databases unit fixtures test-sigs clean \
        kofscanner kofexamine ksigbuilder kofviewer kofgrille kofwatchtower kofwatchman \
        kofmontrace tools help

#
# THE LINUX COLLECTOR'S OWN TESTS.
#
# They fork, write files in a scratch directory and read the events back, so
# they need the collector's sources rather than the library - libkofantarc is
# not in $(LIB), for the same reason libkofgrille is not: a collector belongs
# to one platform and the engine belongs to neither.
#
# THEY RUN UNPRIVILEGED, AND THAT IS THE POINT. fanotify's unprivileged mode
# reports dirent events and hides the actor - see afan.h - which is useless as
# a sensor and is exactly enough to exercise the event walk, the name assembly,
# the verb mapping and the record. A CI has no root and this still tests.
$(TEST)/unit_antarc_fan$(EXE): tests/unit/antarc_fan.c $(ANTARC_SRC) \
                               $(KOFEVT_SRC) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) $(ANTARC_INC) tests/unit/antarc_fan.c \
	      $(ANTARC_SRC) $(KOFEVT_SRC) -o $@ $(LDFLAGS)
