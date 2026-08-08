# kofeng - build for host side libraries and tools.
#
# Signature modules are NOT built here: they are freestanding, position
# independent blobs produced by a separate toolchain step with its own flags,
# and mixing the two sets of flags in one place is how they end up wrong.

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion \
           -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
           -fno-common -Ilibkofeng/core
LDFLAGS ?=

# Address and UB sanitizers are the default for development: the whole parser
# runs on untrusted input, so the cheapest way to find the bug class that
# matters is to make the corpus run trip over it.
ifeq ($(SAN),1)
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

BUILD   := build

PARSER_SRC := libkofeng/kofparsers/elf/elf_parse.c
PARSER_OBJ := $(BUILD)/elf_parse.o

MATCH_SRC := libkofeng/kofmatchers/kofmatch.c
MATCH_OBJ := $(BUILD)/match.o

DB_SRC := libkofeng/kofdb/kofdb.c
DB_OBJ := $(BUILD)/db.o

SCAN_SRC := libkofeng/kofscanners/scan.c
SCAN_OBJ := $(BUILD)/scan.o

SCANNERS_SRC := libkofeng/kofscanners/scanners.c
SCANNERS_OBJ := $(BUILD)/scanners.o

FACADE_SRC := libkofeng/kofeng.c
FACADE_OBJ := $(BUILD)/kofeng.o

# The library the tools link against. kofdump needs only the parser, so it is not
# listed there: a tool linking less is a tool that cannot depend on more.
LIB_OBJ := $(PARSER_OBJ) $(MATCH_OBJ) $(DB_OBJ) $(SCAN_OBJ) \
           $(SCANNERS_OBJ) $(FACADE_OBJ)

KOFDUMP_SRC := tools/kofdump/main.c
KOFDUMP_OBJ := $(BUILD)/kofdump_main.o

KOFRUN_SRC := tools/kofrun/main.c
KOFRUN_OBJ := $(BUILD)/kofrun_main.o

# Build-time only: compiles the patterns written in a signature source. Never
# shipped, and deliberately not linked into anything that runs on an endpoint.
KOFPAT_SRC := tools/kofpat/main.c
KOFPAT_OBJ := $(BUILD)/kofpat_main.o

all: $(BUILD)/kofscanner $(BUILD)/kofdump $(BUILD)/kofrun $(BUILD)/kofpat

# The scanner. Built from the public header alone, which is what keeps that header
# honest: anything it cannot express shows up here as a compile error rather than as a
# quiet reach into an internal include.
SCANNER_SRC := kofscanner/kofscanner.c
SCANNER_OBJ := $(BUILD)/kofscanner.o

$(SCANNER_OBJ): $(SCANNER_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/kofscanner: $(SCANNER_OBJ) $(LIB_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD):
	@mkdir -p $(BUILD)

$(PARSER_OBJ): $(PARSER_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(MATCH_OBJ): $(MATCH_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(DB_OBJ): $(DB_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(SCAN_OBJ): $(SCAN_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(SCANNERS_OBJ): $(SCANNERS_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(FACADE_OBJ): $(FACADE_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(KOFPAT_OBJ): $(KOFPAT_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/kofpat: $(KOFPAT_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(KOFDUMP_OBJ): $(KOFDUMP_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/kofdump: $(KOFDUMP_OBJ) $(PARSER_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(KOFRUN_OBJ): $(KOFRUN_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/kofrun: $(KOFRUN_OBJ) $(LIB_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Signature blobs are built by their own script with their own flag set: they
# are freestanding and position independent, the host tools are neither, and
# keeping both flag sets in one place is how they end up applied to the wrong
# target.
SIGS := $(wildcard signature/*.c)

sigs: $(BUILD)/kofrun $(BUILD)/kofpat
	@for s in $(SIGS); do signature/build.sh $$s || exit 1; done

# Run a blob over the corpus, one process per file, counting crashes separately
# from verdicts. SIG picks which blob.
SIG ?= $(BUILD)/sig/sig_entry_gt.blob

run_sig: sigs
	@tests/corpus/run_sig.sh $(SIG) $(CORPUS)

# Corpus run. Batched, so it is fast but a crash aborts the batch: use it as a
# quick look. tests/corpus/measure.sh runs one process per file and is what
# says whether the tool survived, which is the criterion that matters.
CORPUS ?= /usr/bin /usr/lib

corpus: $(BUILD)/kofdump
	@find $(CORPUS) -maxdepth 2 -type f -print0 2>/dev/null \
	  | xargs -0 -n 64 $(BUILD)/kofdump -1 > $(BUILD)/corpus.tsv
	@echo "rows: $$(wc -l < $(BUILD)/corpus.tsv)"
	@echo "elf:  $$(awk -F'\t' '$$2==1' $(BUILD)/corpus.tsv | wc -l)"
	@echo "--- class ---"
	@awk -F'\t' '$$2==1 {print $$3}' $(BUILD)/corpus.tsv | sort | uniq -c | sort -rn
	@echo "--- anomalies (split) ---"
	@awk -F'\t' '$$2==1 {print $$14}' $(BUILD)/corpus.tsv \
	  | tr '|' '\n' | sort | uniq -c | sort -rn

# Full measurement: isolates each file in its own process so a crash can be
# attributed and does not lose the rest of the run.
measure: $(BUILD)/kofdump
	@tests/corpus/measure.sh $(CORPUS)

# Unit tests. Exhaustive differential checks over small inputs, for the routines
# where a corpus run would pass while the code is still wrong on an input the
# corpus does not happen to contain. Each is a standalone program that exits
# non-zero on failure, so this target is usable from CI.
UNIT_SRC := $(wildcard tests/unit/*.c)
UNIT_BIN := $(patsubst tests/unit/%.c,$(BUILD)/unit_%,$(UNIT_SRC))

$(BUILD)/unit_%: tests/unit/%.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

unit: $(UNIT_BIN)
	@rc=0; for t in $(UNIT_BIN); do \
		printf '%-28s ' "$$(basename $$t)"; \
		if $$t; then :; else rc=1; echo "  FAILED"; fi; \
	done; exit $$rc

clean:
	rm -rf $(BUILD)

.PHONY: all corpus measure sigs run_sig unit clean
