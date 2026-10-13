
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
# THE EXAMINER IS SPELLED kofexaminer FOR THE SAME REASON, ONE STEP FURTHER: the
# directory kofexamine/ holds the shared code that both it and the viewer are
# built from, so a tool of the same name read as the library and the library
# read as the tool. The tool is the examinER; what it is built from keeps the
# directory's name.
#
# The recipe is what makes that visible. A target with prerequisites and no recipe
# still prints "Nothing to be done" once its prerequisites are built, which is the
# same sentence the broken version printed - so a working build and a build that
# does nothing were indistinguishable from the outside. Saying what exists costs a
# line and removes the ambiguity entirely.
kofscanner:  $(OUT)/bin/kofscanner$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)
kofexaminer:  $(OUT)/bin/kofexaminer$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)
ksigbuilder: $(OUT)/bin/ksigbuilder$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)
kofviewer:   $(OUT)/bin/kofviewer$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

.PHONY: all debug sdk sigs databases unit unit-asan fixtures test-sigs clean \
        kofscanner kofexaminer ksigbuilder kofviewer kofgrille kofwatchtower kofwatchman \
        kofmontrace tools help

# Every tool that is the host's own binary. The cross-built Windows binaries
# (`make kofgrille`) are not in it: a Linux `make tools` must not start requiring
# a cross-compiler, and a PE file it could not run has no business in a native
# tools build. The CI asks for those by name.
tools: kofscanner kofexaminer ksigbuilder kofviewer kofwatchman kofwatchtower kofmontrace

help:
	$(info targets:)
	$(info $(SP)  all           the SDK, the tools and the databases  (default))
	$(info $(SP)  sdk           libkofeng.a and the public headers)
	$(info $(SP)  kofscanner    the scanner)
	$(info $(SP)  kofexaminer   the file examiner)
	$(info $(SP)  ksigbuilder   the database builder)
	$(info $(SP)  kofviewer     the file examiner, navigable)
	$(info $(SP)  kofwatchman   verdicts over a recorded event log)
	$(info $(SP)  kofwatchtower the event sensor)
	$(info $(SP)  kofmontrace   run a program and trace it)
	$(info $(SP)  tools         every tool above)
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
	$(info $(SP)  unit-asan     the same, under the sanitizers)
	$(info $(SP)  check-rules   the rules a grep can check, and the layer check)
	$(info $(SP)  fixtures      build the binaries the tests parse)
	$(info $(SP)  clean         remove $(BUILD))
	@$(NOOP)

$(BUILD) $(OUT) $(INT) $(TEST):
	@$(call MKDIR,$@)
