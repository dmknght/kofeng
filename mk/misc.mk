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
	$(PYTHON) tests/tui/run_all.py --viewer $(abspath $(OUT)/bin/kofviewer$(EXE)) $(TUI_ARGS)

# THE MERGE GATE (tools/patch_gate.py says what it checks): code that was added without being asked for.
#   gate-test    the self-tests of the gate: each kind of unrequested addition (a function, an export, a menu item, a section
#                title, a hit zone, a key, a viewer-side derive loop, a removed test, a golden change or file outside the manifest) must
#                produce its FAIL line (tests/gate/, python only, about 3 s: cheap enough to run beside check-rules)
#   gate         the self-tests, the frozen API surface of the built tree (docs/api_surface.txt must be what the archives export) and the
#                golden screens of the built viewer (tests/tui/golden, about 2 minutes: run it under the heavy lock). With BASE and
#                MANIFEST (and PATCH, the `diff -ruN base tree` being delivered) it is the whole of tools/merge_gate.sh instead:
#                    make gate BASE=../base MANIFEST=../manifest.txt PATCH=../result.patch
.PHONY: gate-test gate gate-api gate-golden
gate-test:
	$(PYTHON) tests/gate/test_patch_gate.py
	$(PYTHON) tests/gate/test_merge_gate.py
	$(PYTHON) tests/gate/test_api_surface.py

ifneq ($(BASE),)
gate: gate-test kofviewer $(KGENOME_LIB) $(KUNCOAT_LIB)
	sh tools/merge_gate.sh $(BASE) . $(MANIFEST) $(PATCH)
else
gate: gate-test gate-api gate-golden
endif

gate-api: $(LIB) $(KGENOME_LIB) $(KUNCOAT_LIB)
	$(PYTHON) tools/api_surface.py verify .

gate-golden: kofviewer
	$(PYTHON) tests/tui/run_all.py --viewer $(abspath $(OUT)/bin/kofviewer$(EXE)) -j 2 golden

population:
ifeq ($(KOF_CMD_SHELL),yes)
	$(error population runs tests/gen_population.sh, a POSIX shell script: run it from an sh, or use a make with one)
else
	tests/gen_population.sh $(or $(COUNT),100) $(DIR)
endif

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
