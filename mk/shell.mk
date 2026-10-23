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
# One FILE, not a tree - rmdir refuses one here and rm -rf would take a
# directory by the same name without asking. Used to rebuild an archive from
# empty; see the note above $(LIB).
RM       = if exist "$(subst /,\,$(1))" del /q "$(subst /,\,$(1))"
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
# The interpreter for the repository's own scripts (tools/*.py, tests/tui). `python3` is a
# POSIX name: the Windows installers put `python` on PATH and no `python3`.
PYTHON   ?= python
MKFIXTURES = powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File tests/mkfixtures.ps1
else
MKDIR    = mkdir -p '$(1)'
RMRF     = rm -rf '$(1)'
RM       = rm -f '$(1)'
COPY     = cp -f '$(1)' '$(2)'
EXEC     = $(1)
DEVNULL  = /dev/null
NOOP     = :
SILENCE  = 2>/dev/null
NOW_UTC  = date -u +%Y%m%d%H
FIND_DEPS = find $(BUILD) -name '*.d' 2>/dev/null
PYTHON   ?= python3
MKFIXTURES = tests/mkfixtures.sh
endif
