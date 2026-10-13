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
#
# NO -g IN THE RELEASE BUILD, AND IT IS WORTH THE TWO LINES.
#
# Measured on this tree: kofscanner is 5.4MB built and 1.8MB stripped, kofviewer
# 6.7MB and 2.1MB. Two thirds of every shipped binary was debug info, and none
# of it is read on a machine the tool was delivered to.
#
# What is left is not libc - nothing here links it statically; `ldd` shows libc
# and ld-linux and nothing else. It is libkofeng.a, which is this project's own
# code. Its biggest single table is the x86 decoder's (genotype/x86/x86_tab.c),
# which is data by design.
#
# THE SANITISED BUILDS KEEP IT. A sanitiser report without file and line is a
# stack of addresses, which is the difference between "there is a leak" and
# "draft_from_source, kofeditor.c:4478" - so -g moves to SAN_CFLAGS and
# ASAN_FLAGS rather than disappearing. It is `?=`, so a developer who wants it
# back for a release build says CFLAGS='-O2 -g' and gets it.
#
# AND EVERY += BELOW IS `override`, WHICH IS WHAT MAKES THAT SENTENCE TRUE.
#
# A variable set on the command line beats the makefile, and GNU make applies
# that to `+=` as well: a plain `CFLAGS += -Ilibkofeng/kofcore` after a
# command-line `CFLAGS='-O2 -g'` appends nothing at all. So the very build the
# comment above offers was the one that did not work - `make CFLAGS='-O2 -g'`
# died on `fatal error: kofmod/kofsig.h: No such file or directory`, because
# the include path this file adds had been dropped.
#
# `override` restores the intent: the developer's value is kept and the flags
# the tree cannot compile without are still appended to it. It is on every
# CFLAGS += in this file for that reason, not on the first one only - one
# missed line puts the hole back.
CFLAGS  ?= -O2
# The parallel walk in scan.c is pthreads. On this glibc the symbols are in libc
# and the link succeeds without it - measured, the flag changes the scan's speed
# by nothing either way - so it is here for the platforms where the link needs
# it rather than for anything it does on this one.
LDFLAGS += -pthread -lm
# libm, because the emulator implements SQRTSD and SQRTSS.
#
# The link succeeded without it for a long time: gcc answers sqrt() with the
# SQRTSD instruction and only calls libm for the branch that sets errno, and
# whether it emits that branch at all depends on how the surrounding function
# was inlined. So this was a link that worked by accident and broke the first
# time kgenome_emu_run grew - which is exactly the kind of dependency to name
# rather than to keep getting away with.
override CFLAGS  += -std=c11 -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion \
           -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
           -fno-common -Ilibkofeng/kofcore -Ilibgenome -Ilibuncoat

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
override CFLAGS += -pthread
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
# refuses (dbloader says "built for machine 1, this is 2" and skips the file).
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
# CFLAGS alone - WIN_CFLAGS below is a separate flag list that does not inherit
# CFLAGS, and it still has to end up targeting the same machine as everything
# else. Missing on the first pass of this: on a build host whose native compiler
# target does not match the one being forced (this ARM64 box building the x86_64
# default, or the reverse cross direction for KOF_HOST_MACH=arm64), a separate
# list silently compiled for whatever the compiler's own default
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
override CFLAGS += $(KOF_CROSS_FLAGS)
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

