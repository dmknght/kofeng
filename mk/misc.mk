# THE TESTS THAT ARE NOT PART OF `unit`, and the one script that is not a test.
#
# tui-test drives the real kofviewer in a pseudo-terminal (tests/tui/): it needs
# python3 with pyte and takes minutes, so `unit` does not run it. TUI_ARGS is
# passed to run_all.py ("-j 8", "menu tree", "-k find"; see tests/tui/README.md).
# population generates N synthetic signature modules for the scale measurements
# (tests/gen_population.sh says what it is and is not evidence of); the sources go
# to build/pop unless DIR is given - pass it to `make databases BASEDIR=...`.
.PHONY: tui-test population
tui-test: kofviewer
	python3 tests/tui/run_all.py --viewer $(abspath $(OUT)/bin/kofviewer$(EXE)) $(TUI_ARGS)

population:
	tests/gen_population.sh $(or $(COUNT),100) $(DIR)

#
# EVERYTHING `all` BUILDS, WITH THE SYMBOLS IN.
#
# A recursive make rather than a variable, because DEBUG has to be set before
# CFLAGS is assembled and a target's recipe runs long after that. The stamp
# handles the rebuild - see FLAGSIG.
debug:
	@$(MAKE) --no-print-directory DEBUG=1 all

clean:
	@$(call RMRF,$(BUILD))
# A hand tool, not a test: it prints what the walk saw on the live machine and
# asserts nothing, so it is built on demand and never by `make unit`.
$(TEST)/antarc_dump$(EXE): tools/antarc/antarc_dump.c $(ANTARC_SRC) \
                           $(KOFEVT_SRC) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) $(ANTARC_INC) tools/antarc/antarc_dump.c \
	      $(ANTARC_SRC) $(KOFEVT_SRC) -o $@ $(LDFLAGS)

#
