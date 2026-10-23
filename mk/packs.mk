# ------------------------------------------------------------- the database
#
# Compile every signature, then pack the artefacts.
#
# Parallelism lives here rather than inside either tool: one compile does not
# depend on another, xargs already knows how to run N at a time, and a --jobs
# flag in a C program would be a second implementation of one shell word.

# bases/ is the content tree: everything that compiles to a module and ships in a
# database. The directories differ in what the module DOES, not merely in name:
#
#   (signatures, heuristic modules and the diagnoses that were written by hand
#   are not here: they belonged to the verdict model that named an object from one
#   module's report, and are in docs/disabled/ - see CLAUDE.md. A diagnose is
#   packed apart from the modules, as a .kdig record, from a `diagnoses/` directory
#   of a content tree.)
#   bases/decomp/      the CONTAINER unpackers - gzip, zip, tar, rar, 7z, xz,
#                      docole, rtf, overlay. A file that carried other files.
#   bases/unp/         the PACKER unpackers - UPX, Ezuri, midgetpack.
#                      A file that IS the payload, transformed.
#   bases/decoders/    the modules that INVOKE a decoder - the msf encoders. A
#                      module here recognises a file and reads the key, the
#                      count and the offset out of it; the cipher itself is the
#                      libuncoat's (transform.h), asked for through
#                      kunp_decrypt - see kofmod/kofdecode.h.
#
# What `make check-rules` can tell about this split is one line: every module in
# unp/, decomp/ and decoders/ declares what it takes out (KOF_TARGET_CONTENT).
# The directory itself is a convention for the people who maintain the modules;
# the engine reads what a module declares, not where it lives. It was stated by
# EXAMPLE once - "gzip, zip, tar" - and eight of the nine containers had drifted
# into bases/unp/ while zip and tar, named as decomp, were among them. A split
# described by examples is a split nothing checks.
#
# bases/mutation/ WAS A SIXTH, for rules carrying a similarity block, and it is
# gone. A block rule declares the same macros, names a family the same way and
# is packed by the same builder; it is a detection that happens to measure a
# block, which is what dbcore.h already says about keeping the blocks a section
# rather than a pack kind. And the split cost something a comment cannot argue
# away: two directories let two files be called gafgyt_00.c, the number in the
# name IS the variant, so the database shipped two rules both saying
# Gafgyt.00. Eleven such pairs. The mutation ones were renumbered upward when
# they merged - see the note on variants in ksigbuilder.
#
# decomp and unp compile to the same pack kind and the engine does not tell them
# apart - the split is for the people who maintain them. The decompression
# ALGORITHMS are not here at all: they are host services in
# libuncoat, reached through the module ABI, for the reason
# kofsig.h gives at the inflate
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
# THEY ARE ARGUMENTS NOW, not exported variables - see ksb_opt_take in
# ksigbuilder/ksb_args.c. A command and its arguments is the shape both sh and
# PowerShell agree on, which is what the note above was reaching for, and it
# keeps the build from depending on what is in the environment it started in.
KSB_OPTS = --include $(abspath $(OUT)/include) \
           --ldscript $(abspath ksigbuilder/module.ld) \
           --basedir $(abspath $(BASEDIR)) \
           --cc $(CC) --ld $(LD_FOR_SIGS)
ifneq ($(KOF_TARGET_TRIPLE),)
KSB_OPTS += --triple $(KOF_TARGET_TRIPLE)
endif

#
# One process for the whole tree - see ksigbuilder's --tree - which builds the
# sources $(JOBS) at a time and packs what comes out once, serially.
#
# $(JOBS) IS THIS RECIPE'S OWN, not make's. `make -j` cannot divide this: the
# walk, the order and the packing are one program's decisions, so the recipe is
# one command whatever -j says, and the parallelism it has is the number passed
# here. ksigbuilder clamps it to the host's processors - see TREE_MAX_JOBS.
#
# This was a shell loop over every source calling --module once per source, which
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
	@$(call EXEC,$(OUT)/bin/ksigbuilder$(EXE)) --tree $(BASEDIR) $(ARTEFACTS) $(DB) --jobs $(JOBS) $(KSB_OPTS)
	$(info $(SP)   scan with: $(OUT)/bin/kofscanner$(EXE) --db $(DB) --scan-files <path>)

# Kept as a name because it is in muscle memory and in scripts; the artefacts
# and the database now come out of the same single command.
sigs: databases

