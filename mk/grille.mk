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
WIN_CFLAGS  := -std=c11 -O2 $(KOF_DEBUG_CFLAGS) -fno-common \
               -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion \
               -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
               $(KOF_WARN_PORTABLE) $(KOF_WARN_GCC) -MMD -MP \
               -DKOFENG_BUILD=$(KOF_BUILD_STAMP)u
#
# WINPTHREAD, AND IT IS NOT A FLAG THE CROSS BUILD CAN DO WITHOUT ANY MORE.
#
# This was empty, and natively $(LDFLAGS) carries -lwinpthread so the sensor
# linked on Windows and not from here. What made the difference reachable was
# libkoforbit/fridge/koffridge.c joining WIN_SRC: its sharded table takes a
# pthread mutex per shard, so every tool linking $(WINLIB) now needs the
# library that provides one - and the cross link had no way to get it.
#
# The cost was hidden because kofwatchtower.exe is not in `make all` on a
# POSIX host; it is a target somebody asks for by name. So the claim beside
# its rule - that the sensor "still cross-builds, which is what keeps every
# line of libkofgrille type-checked on a host with no ETW" - had quietly
# stopped being true, and the type-check it describes was not running.
#
# STATIC, exactly as the native side links it: -Bstatic around the name so the
# sensor does not arrive on a machine needing a winpthread DLL beside it.
WIN_LDFLAGS := -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic
endif

WIN_SRC := libkoforbit/grille/wevt_ring.c \
           libkoforbit/grille/wfilter.c \
           libkoforbit/grille/wcmdline.c \
           libkoforbit/grille/wproc.c \
           libkoforbit/grille/wtext.c \
           libkoforbit/grille/wevt_decode.c \
           libkoforbit/grille/wevt_etw.c

#
# The log format is a component of its own under libkofeng, not part of the
# Windows collector - see libkoforbit/evt/kofevt.h for why it is there and why
# it includes nothing from the engine. It is compiled into libkofgrille.a so a
# tool links one archive, and the SAME source compiles natively for the host
# tests, which is the point of it having no Windows in it.
WIN_SRC += libkoforbit/evt/kofevt.c libkoforbit/evt/kofevtfmt.c \
           libkoforbit/evt/kofevtlog.c

#
# THE VERDICT CACHE, which now also holds the duplicate-event table.
#
# AND THIS LINE COSTS SOMETHING THAT IS WORTH NAMING. koffridge.h includes
# kofeng.h, because a verdict is a struct kof_result. So compiling it into the
# collector puts the ENGINE'S header into libkofgrille - and kofgrille.h's first
# paragraph says it never includes kofeng.h, because the collector collects and
# does not judge.
#
# The dedup half needs none of that: it is stdint and stdlib, and it is its own
# file (koffridge_seen.c) so a build that wants only it can take only it. Both are
# listed here because the collector's library has always carried both.
WIN_SRC += libkoforbit/fridge/koffridge.c libkoforbit/fridge/koffridge_seen.c

WIN_OBJ := $(patsubst libkoforbit/grille/%.c,$(INT)/win_%.o,\
                      $(filter libkoforbit/grille/%,$(WIN_SRC))) \
           $(patsubst libkoforbit/evt/%.c,$(INT)/win_evt_%.o,\
                      $(filter libkoforbit/evt/%,$(WIN_SRC))) \
           $(patsubst libkoforbit/fridge/%.c,$(INT)/win_frg_%.o,\
                      $(filter libkoforbit/fridge/%,$(WIN_SRC)))

$(INT)/win_evt_%.o: libkoforbit/evt/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(WIN_CC) $(WIN_CFLAGS) $(DEPTO) -Ilibkoforbit/evt -c $< -o $@

$(INT)/win_frg_%.o: libkoforbit/fridge/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(WIN_CC) $(WIN_CFLAGS) $(DEPTO) -Ilibkoforbit/fridge -c $< -o $@
WINLIB  := $(SDK)/lib/libkofgrille.a

$(INT)/win_%.o: libkoforbit/grille/%.c $(STAMP) | $(INT)
	@$(call MKDIR,$(dir $@))
	$(WIN_CC) $(WIN_CFLAGS) $(DEPTO) -Ilibkoforbit/grille -Ilibkoforbit/evt \
	      -Ilibkoforbit/fridge -c $< -o $@

$(WINLIB): $(WIN_OBJ)
	@$(call MKDIR,$(dir $@))
	@$(call RM,$@)
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
# engine and moved up beside kofwatchman, which is where the tools that link
# both halves live - see the note there for what that cost. The sensor links
# the collector and nothing else, so it still cross-builds, which is what keeps
# every line of libkofgrille type-checked on a host with no ETW.

# The channel is no longer part of the collector: it moved to
# libkoforbit/chan, which is one contract with two backends. The sensor
# names the Windows one.
$(OUT)/bin/kofwatchtower$(WIN_EXE): kofwatcher/kofwatchtower.c \
                                    libkoforbit/chan/chan_win.c \
                                    $(WINLIB) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(WIN_CC) $(WIN_CFLAGS) $(DEPTO) -Ilibkoforbit/grille -Ilibkoforbit/evt \
	      -Ilibkoforbit/chan -Ikofwatcher -Ilibkofeng/kofcore \
	      kofwatcher/kofwatchtower.c libkoforbit/chan/chan_win.c \
	      $(WINLIB) -o $@ $(WIN_LDFLAGS) $(WIN_LDLIBS)

kofgrille: $(WINLIB)
	$(info $(SP)  $<)
	@$(NOOP)




ifeq ($(NATIVE_OS),windows)

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
# So it is native, like kofscanner: engine and collector in one binary, built
# only on the machine it runs on. What is lost is the cross type-check for
# THIS FILE. kofwatchtower stays above and still covers every line of
# libkofgrille, which is where the platform actually lives.
#
# AND IT IS HERE, INSIDE THIS ifeq. Placed up beside kofwatchman it expanded
# $(WIN_EXE) to NOTHING -
# make expands a rule's target and prerequisites when it READS them, and
# WIN_EXE is set in this block. The rule then existed for a target called
# `kofmontrace` with no extension, `make kofmontrace` found the real .exe
# up to date with no rule to rebuild it, and printed a success line for a
# binary it had not touched. Which is this file's own trap, caught a third
# time: anything naming a variable this block sets must be inside it.
$(OUT)/bin/kofmontrace$(WIN_EXE): $(KOFMONTRACE_SRC) $(KOFREPORT_SRC) \
                                  $(LIB) $(WINLIB) $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkofeng -Ilibkofeng/kofcore -Ilibkoforbit/grille \
	      -Ilibkoforbit/evt -Ilibkoforbit/report -Ikofwatcher \
	      $(KOFMONTRACE_SRC) $(KOFREPORT_SRC) $(WINLIB) $(LIB) \
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

