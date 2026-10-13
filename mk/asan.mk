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
ASAN_OBJ := $(foreach f,$(LIB_SRC) $(PH_SRC) $(GT_SRC) $(CL_SRC) $(UC_SRC),$(call asan_obj,$(f)))

# A literal newline, so $(foreach) can put each command on its own recipe line
# - which is what makes make run them one at a time and stop at the first that
# fails, the same thing `|| exit 1` did inside the old loop.
define NL


endef

#
# The emulator goes in too. It is the newest code here and the one that owns the
# most raw memory - a sparse page table, lazily committed mappings and the
# payload snapshots - so leaving it out would exempt exactly what most needs
# checking.
#
$(ASAN_LIB): $(LIB_SRC) $(PH_SRC) $(GT_SRC) $(CL_SRC) $(UC_SRC) $(SDK_HDR) | $(TEST)
	@$(call RMRF,$(TEST)/asan-obj)
	@$(call MKDIR,$(TEST)/asan-obj)
	@# EMU_INC on every loop: libkofeng's own sources include the decoder's
	@# header, and this target has no per-directory rules to supply the path.
	@$(foreach f,$(LIB_SRC),$(CC) $(CFLAGS) $(ASAN_FLAGS) $(EMU_INC) \
		-c $(f) -o $(call asan_obj,$(f))$(NL))
	@$(foreach f,$(PH_SRC),$(CC) $(CFLAGS) $(ASAN_FLAGS) \
		-c $(f) -o $(call asan_obj,$(f))$(NL))
	@$(foreach f,$(GT_SRC),$(CC) $(CFLAGS) $(ASAN_FLAGS) \
		-c $(f) -o $(call asan_obj,$(f))$(NL))
	@$(foreach f,$(CL_SRC),$(CC) $(CFLAGS) $(ASAN_FLAGS) \
		-c $(f) -o $(call asan_obj,$(f))$(NL))
	@$(foreach f,$(UC_SRC),$(CC) $(CFLAGS) $(ASAN_FLAGS) \
		-c $(f) -o $(call asan_obj,$(f))$(NL))
	@$(call RM,$@)
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

#
# The libs' own archives, sanitised: the same asan objects, grouped the way the
# release archives are, so the harness under tests/lib/ is checked linked against
# one lib alone here too. They are built from $(ASAN_LIB)'s objects and so after it.
ASAN_KGENOME_LIB := $(TEST)/libkgenome-asan.a
ASAN_KUNCOAT_LIB := $(TEST)/libkuncoat-asan.a

$(ASAN_KGENOME_LIB): $(ASAN_LIB)
	@$(call RM,$@)
	@$(AR) rcs $@ $(foreach f,$(PH_SRC) $(GT_SRC) $(CL_SRC) libkofeng/kofcore/kofentropy.c,$(call asan_obj,$(f)))

$(ASAN_KUNCOAT_LIB): $(ASAN_LIB)
	@$(call RM,$@)
	@$(AR) rcs $@ $(foreach f,$(UC_SRC),$(call asan_obj,$(f)))

$(TEST)/asan_libtest_genome_%$(EXE): tests/lib/genome/%.c $(ASAN_KGENOME_LIB) $(STAMP) | $(TEST)
	@$(CC) $(CFLAGS) $(ASAN_FLAGS) $< $(ASAN_KGENOME_LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

$(TEST)/asan_libtest_uncoat_%$(EXE): tests/lib/uncoat/%.c $(ASAN_KUNCOAT_LIB) $(STAMP) | $(TEST)
	@$(CC) $(CFLAGS) $(ASAN_FLAGS) $< $(ASAN_KUNCOAT_LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

ASAN_RUN := $(addprefix run-,$(ASAN_BIN)) $(addprefix run-,$(LIBTEST_ASAN_BIN))

$(ASAN_RUN): run-%: %
	$(info == $(notdir $*))
	@$(call EXEC,$*)

unit-asan: fixtures test-sigs $(ASAN_RUN)
	$(info all $(words $(ASAN_BIN) $(LIBTEST_ASAN_BIN)) sanitized test(s) passed)
	@$(NOOP)

#
