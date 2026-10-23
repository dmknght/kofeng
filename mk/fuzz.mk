# ------------------------------------------------------------------- fuzzing
#
# Hostile-input fuzzing with the kit of tests/lib/fuzz_kit.h (see tests/fuzz/README.txt). Linux only: the registry is a
# linker section and the fault seams are POSIX.
#
#   make fuzz-smoke                      every adapter, ASAN+UBSAN, fixed seed, a bounded number of iterations (counted,
#                                        never timed): deterministic, one digest line per adapter
#   make fuzz SEED=7 ITERS=5000 ONLY=kuncoat/inflate    longer; ONLY is an adapter name prefix
#   make fuzz-selftest                   the kit's planted defects must be caught
#   make fuzz-mutants                    the kit itself broken three ways: the self-test must then fail
#
# One BINARY PER STAGE, built from every tests/fuzz/<stage>/*.c, the driver (tests/lib/fuzz_drv.c) and the archive the
# stage's stage.mk names (FZ_LIB_<stage>: kuncoat, kgenome, engine or none). A work package adds its adapters as new files in
# its own directory and, when it needs a flag or a library, edits ITS stage.mk: no shared line is edited. A new directory
# with a stage.mk is a new stage, found by wildcard.
#
# Everything lands in build/fuzz (its own directory, sanitised objects of the libs included), never in build/test. Heavy
# runs: `flock /mnt/games/normtest/heavy.lock make fuzz-smoke`. ASAN cannot start under ulimit -v; the child's resident size
# is polled by the driver and the ASAN ceilings are in __asan_default_options (fuzz_drv.c).
ifneq ($(NATIVE_OS),windows)

FZB := $(BUILD)/fuzz

# The sanitised objects of the libs: the same lists as asan.mk, in the fuzz directory so that the two sets do not share a file.
FZ_OBJ = $(addprefix $(FZB)/obj/,$(1:.c=.o))
FZ_ALL_OBJ := $(call FZ_OBJ,$(LIB_SRC) $(PH_SRC) $(GT_SRC) $(CL_SRC) $(TX_SRC) $(UC_SRC) libkofeng/kofcore/kofentropy.c)

$(FZB)/obj/%.o: %.c $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(ASAN_FLAGS) $(FZ_EXTRA) -c $< -o $@

# libkofeng's own sources include the decoder's header (EMU_INC), as in asan.mk.
$(call FZ_OBJ,$(LIB_SRC)): FZ_EXTRA := $(EMU_INC)

$(FZB)/libkuncoat.a: $(call FZ_OBJ,$(UC_SRC))
	@$(call RM,$@)
	@$(AR) rcs $@ $^

$(FZB)/libkgenome.a: $(call FZ_OBJ,$(PH_SRC) $(GT_SRC) $(CL_SRC) $(TX_SRC) libkofeng/kofcore/kofentropy.c)
	@$(call RM,$@)
	@$(AR) rcs $@ $^

$(FZB)/libkofeng.a: $(call FZ_OBJ,$(LIB_SRC) $(PH_SRC) $(GT_SRC) $(CL_SRC) $(TX_SRC) $(UC_SRC))
	@$(call RM,$@)
	@$(AR) rcs $@ $^

-include $(wildcard $(FZ_ALL_OBJ:.o=.d))

FZ_ARCHIVE_kuncoat := $(FZB)/libkuncoat.a
FZ_ARCHIVE_kgenome := $(FZB)/libkgenome.a
FZ_ARCHIVE_engine  := $(FZB)/libkofeng.a
FZ_ARCHIVE_none    :=

# What the driver wraps at link time: the allocation caps and "fail the k-th allocation".
FZ_WRAP := -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free -Wl,--wrap=posix_memalign -Wl,--wrap=mmap
# The kit uses O_TMPFILE, memfd_create and strdup: the adapters include lib headers before the kit, so the macro is set on the command line.
FZ_DEF := -D_GNU_SOURCE
FZ_KIT_HDR := $(wildcard tests/lib/fuzz_*.h tests/lib/work_count.h tests/lib/genome/hk.h)

FZ_STAGES := $(sort $(patsubst tests/fuzz/%/stage.mk,%,$(wildcard tests/fuzz/*/stage.mk)))
include $(wildcard tests/fuzz/*/stage.mk)

define FZ_STAGE
FZ_SRC_$(1) := $$(wildcard tests/fuzz/$(1)/*.c)
$$(FZB)/fuzz_$(1): $$(FZ_SRC_$(1)) tests/lib/fuzz_drv.c $$(FZ_KIT_HDR) $$(FZ_ARCHIVE_$$(FZ_LIB_$(1))) $$(STAMP)
	@$$(call MKDIR,$$(FZB))
	$$(CC) $$(CFLAGS) $$(ASAN_FLAGS) $$(FZ_DEF) $$(FZ_CFLAGS_$(1)) $$(FZ_SRC_$(1)) tests/lib/fuzz_drv.c $$(FZ_ARCHIVE_$$(FZ_LIB_$(1))) \
	      -o $$@ $$(LDFLAGS) $$(FZ_LIBS_$(1)) $$(FZ_WRAP) $$(FZ_WRAP_$(1))
endef
$(foreach s,$(FZ_STAGES),$(eval $(call FZ_STAGE,$(s))))

FZ_BINS := $(addprefix $(FZB)/fuzz_,$(FZ_STAGES))

SEED  ?= 1
ITERS ?= 24
ONLY  ?=
# smoke: the same seed and a fixed iteration count for every adapter; the total time stays under about 90 s
FZ_SMOKE_SEED  := 1
FZ_SMOKE_ITERS := 2000

fuzz-build: $(FZ_BINS)
	@$(NOOP)

FZ_SMOKE_RUN := $(addprefix run-fuzz-smoke-,$(FZ_STAGES))
$(FZ_SMOKE_RUN): run-fuzz-smoke-%: $(FZB)/fuzz_%
	$(info == fuzz $*)
	@$(call EXEC,$(FZB)/fuzz_$*) --seed $(FZ_SMOKE_SEED) --iters $(FZ_SMOKE_ITERS) --out $(FZB)/found

fuzz-smoke: fuzz-selftest $(FZ_SMOKE_RUN)
	$(info fuzz-smoke: ok ($(words $(FZ_STAGES)) stages, seed $(FZ_SMOKE_SEED), $(FZ_SMOKE_ITERS) iterations each))
	@$(NOOP)

FZ_RUN := $(addprefix run-fuzz-,$(FZ_STAGES))
$(FZ_RUN): run-fuzz-%: $(FZB)/fuzz_%
	$(info == fuzz $* seed $(SEED) iters $(ITERS) $(ONLY))
	@$(call EXEC,$(FZB)/fuzz_$*) --seed $(SEED) --iters $(ITERS) --out $(FZB)/found $(if $(ONLY),--adapter $(ONLY) --nomatch-ok)

fuzz: $(FZ_RUN)
	@$(NOOP)

# The kit tests itself: planted defects must be CAUGHT, the good adapters (seams, limits) must pass.
fuzz-selftest: $(FZB)/fuzz_kit
	@$(call EXEC,$(FZB)/fuzz_kit) --selftest --seed 1 --iters 6 --out $(FZB)/found
	@$(call EXEC,$(FZB)/fuzz_kit) --seed 1 --iters 40 --out $(FZB)/found

# The kit broken on purpose: the self-test must FAIL for each (a planted defect that no broken harness path would miss proves nothing).
FZ_MUTANTS := SINK_NEVER_REFUSES NO_STEPS NO_LEAK_CHECK NO_DETERMINISM
FZ_MUT_BIN := $(addprefix $(FZB)/mut_,$(FZ_MUTANTS))
$(FZ_MUT_BIN): $(FZB)/mut_%: $(wildcard tests/fuzz/kit/*.c) tests/lib/fuzz_drv.c $(FZ_KIT_HDR) $(STAMP)
	@$(call MKDIR,$(FZB))
	$(CC) $(CFLAGS) $(ASAN_FLAGS) $(FZ_DEF) -DFZ_MUTANT_$* $(wildcard tests/fuzz/kit/*.c) tests/lib/fuzz_drv.c -o $@ $(LDFLAGS) $(FZ_WRAP)

fuzz-mutants: $(FZ_MUT_BIN)
	@$(foreach m,$(FZ_MUTANTS),$(PYTHON) tools/fuzz_expect.py --fail -- $(FZB)/mut_$(m) --selftest --seed 1 --iters 6 --out $(FZB)/found$(NL))
	$(info fuzz-mutants: every broken harness was caught by the self-test)
	@$(NOOP)

fuzz-clean:
	@$(call RMRF,$(FZB))

.PHONY: fuzz fuzz-build fuzz-smoke fuzz-selftest fuzz-mutants fuzz-clean $(FZ_SMOKE_RUN) $(FZ_RUN)

endif
