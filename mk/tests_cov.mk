# ------------------------------------------------- line AND branch coverage of the public API
#
# The owner's condition (2026-10-29): the tests of a public API must take EVERY BRANCH of the code they cover, so the number is measured, per function, before a test is
# written and after. This builds ONLY the files of the public API and of the paths it drives (COV_SRC) with gcc's --coverage at -O0 (a branch the optimiser merged is
# not a branch to count), links each test against them BEFORE the release archive (the archive's own copy of the same file is then not pulled in), runs the tests of
# COV_TESTS and prints the table (tests/cov_report.py): file, function, line %, branch %, and the branches never taken with their line numbers.
#
#   flock /mnt/games/normtest/heavy.lock make -j2 cov-report          build, run COV_TESTS, print the table
#   make cov-clean                                                    delete build/cov (the objects and counters are several hundred MB)
#
# Not part of `make`, `make unit` or `make check-rules`; the engine's own build is untouched (the release archive is linked as it is).
COV_DIR := $(BUILD)/cov
COV_SRC := libkofeng/kofeng.c libkofeng/kofdetect.c libkofeng/verdictor/verdict.c \
           libkofeng/databases/dbloader.c libkofeng/databases/dbloader_packs.c libkofeng/databases/dbpackcheck.c \
           libkofeng/databases/pack/dbkix.c libkofeng/scanners/objctx_diag_form.c
COV_OBJ := $(patsubst libkofeng/%.c,$(COV_DIR)/obj/%.o,$(COV_SRC))
COV_FLAGS := -O0 -g --coverage -fprofile-update=prefer-atomic
# the tests that ask the API something (what the report is measured over); a test added to the list is run by cov-report. Those with a recipe of their own (UNIT_EXTRA: they link tool sources) are not built here.
COV_TESTS ?= $(filter-out $(UNIT_EXTRA) $(UNIT_SKIP_WINDOWS),$(shell grep -lE 'keng_|kscan_|kdb_|kverdict_|kdet_|kof_db_load' tests/unit/*.c | sed 's|tests/unit/||; s|\.c$$||'))

$(COV_DIR)/obj/%.o: libkofeng/%.c $(STAMP) | $(TEST)
	@$(call MKDIR,$(dir $@))
	@$(CC) $(CFLAGS) $(COV_FLAGS) $(EMU_INC) -c $< -o $@

$(COV_DIR)/bin/%$(EXE): tests/unit/%.c $(COV_OBJ) $(LIB) $(STAMP) | $(TEST)
	@$(call MKDIR,$(dir $@))
	@$(CC) $(CFLAGS) $(COV_FLAGS) $< $(COV_OBJ) $(LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

COV_BIN := $(addprefix $(COV_DIR)/bin/,$(addsuffix $(EXE),$(COV_TESTS)))

# every test runs under a 10 minute kill; one that fails is reported and the others still count (a test that fails still executed its lines)
cov-run: fixtures test-sigs $(COV_BIN)
	@for t in $(COV_TESTS); do echo "== $$t"; (ulimit -v 4194304; timeout -s KILL 600 $(COV_DIR)/bin/$$t$(EXE) > $(COV_DIR)/$$t.out 2>&1) || echo "   $$t exit $$?"; done

cov-report: cov-run
	@python3 -I tests/cov_report.py $(COV_DIR)/obj $(COV_SRC) --uncovered --json $(COV_DIR)/report.json

cov-clean:
	@$(call RMRF,$(COV_DIR))

.PHONY: cov-run cov-report cov-clean
