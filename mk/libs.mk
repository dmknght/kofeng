# ---------------------------------------------------------------- the library

# Every .c under libkofeng/ is the engine - the same rule as the three libs below
# (a new file is picked up by wildcard; CLAUDE.md section 12). Nothing in the tree
# is excluded, so a file that must not be built does not live here. Four
# directories is the deepest the tree goes (analyzers/parsers/binaries/pe/).
LIB_SRC := $(sort $(wildcard libkofeng/*.c libkofeng/*/*.c libkofeng/*/*/*.c \
                             libkofeng/*/*/*/*.c libkofeng/*/*/*/*/*.c))

LIB_OBJ := $(patsubst libkofeng/%.c,$(INT)/lib_%.o,$(LIB_SRC))
LIB     := $(SDK)/lib/libkofeng.a

# ---- libgenome: the decoders (genotype) and the emulator (phenotype) -------
#
# Everything in libgenome is kofeng's own and compiles under kofeng's warning
# policy and the sanitizers like the rest of the tree. The lib reaches its own
# parts by `<genotype/...>`; EMU_INC is for the tools that disassemble and
# include the decoder's headers as `<x86/x86.h>`.
EMU_INC := -Ilibgenome/genotype

# WHEN THIS DATABASE WAS BUILT, as YYYYMMDDHH in UTC - see KOF_PACK_BUILD.
#
# UTC and not local time: two build machines in different zones would otherwise
# stamp packs with numbers that do not increase with time, and ordering is the
# one thing this format is good for. Computed once per make run, so every pack
# in one build carries the same stamp.
KOF_BUILD_STAMP := $(shell $(NOW_UTC))
#
# TWO NAMES, ONE VALUE. The stamp is the same instant because both are built by
# the same make run; the names stay apart because the two things they describe
# can be shipped separately - an engine binary and a database built a week later
# are the ordinary case, and then the numbers differ on their own.
# THE DIAGNOSTIC OUTPUT IS A BUILD CHOICE - see libkofeng/kofcore/kofdebug.h.
# `make` ships without it; `make DEBUG=1` compiles it in. It replaced a set of
# getenv() switches, which put an environment lookup on hot paths and let a
# shipped binary be talked into printing.
DEBUG ?= 0
override CFLAGS += -DKOF_DEBUG=$(DEBUG)
override CFLAGS += -DKOF_PACK_BUILD=$(KOF_BUILD_STAMP)u
override CFLAGS += -DKOFENG_BUILD=$(KOF_BUILD_STAMP)u

PH_SRC    := $(wildcard libgenome/phenotype/*.c)

PH_OBJ    := $(patsubst libgenome/phenotype/%.c,$(INT)/ph_%.o,$(PH_SRC))

#
# genotype: the instruction decoders, one directory per architecture. The tool
# that wrote the generated tables (tools/genotype/x86_gen.c: it links the
# reference decoder and has a main) is outside libgenome/, and the tables it wrote
# are checked in. See `make genotype-x86` for re-running it.
#
GT_SRC := $(wildcard libgenome/genotype/*/*.c)
GT_OBJ := $(patsubst libgenome/genotype/%.c,$(INT)/gt_%.o,$(GT_SRC))

#
# celllysis: reading code without running it, on top of what genotype decodes.
# Public API is libgenome/celllysis/celllysis.h; the engine reaches it through
# -Ilibgenome (`<celllysis/celllysis.h>`) and supplies the object's address space
# itself (libgenome/celllysis/space.c), the one file here that knows an object.
CL_SRC := $(wildcard libgenome/celllysis/*.c)
CL_OBJ := $(patsubst libgenome/celllysis/%.c,$(INT)/cl_%.o,$(CL_SRC))

# ---- libuncoat: the algorithms that grow without a forecast ---------------
#
# Decompression, decoding and decryption on bytes: buffers and a budget in,
# bytes and a status out. Three parts - libuncoat/decompressors, decryptors and
# decoders - and the top level (status, the transform dispatcher, the umbrella
# uncoat.h). Public headers are <uncoat.h> and <decompressors/xxx.h> through
# -Ilibuncoat
# (in CFLAGS above). The lib includes nothing of the engine - only the core
# headers under libkofeng/kofcore. Compiled under the same warning policy and
# the same sanitizers as the rest.
UC_SRC := $(wildcard libuncoat/*/*.c) $(wildcard libuncoat/*.c)
UC_OBJ := $(patsubst libuncoat/%.c,$(INT)/uc_%.o,$(UC_SRC))

# THE OBJECT RULES OF THE ENGINE AND THE TWO LIBS, ONE DEFINITION. An object is
# $(INT)/<prefix>_<path under its source directory>.o: lib_ is libkofeng/,
# gt_ / cl_ / ph_ are the three parts of libgenome/ (genotype, celllysis,
# phenotype), uc_ is libuncoat/. Only the include path differs, and EMU_INC is what
# the three genome parts need to find the decoder's headers.
define OBJ_RULE
$$(INT)/$(1)_%.o: $(2)/%.c $$(STAMP) | $$(INT)
	@$$(call MKDIR,$$(dir $$@))
	$$(CC) $$(CFLAGS) $(3) -c $$< -o $$@
endef
$(eval $(call OBJ_RULE,lib,libkofeng,))
$(eval $(call OBJ_RULE,gt,libgenome/genotype,$$(EMU_INC)))
$(eval $(call OBJ_RULE,cl,libgenome/celllysis,$$(EMU_INC)))
$(eval $(call OBJ_RULE,ph,libgenome/phenotype,$$(EMU_INC)))
$(eval $(call OBJ_RULE,uc,libuncoat,))


#

# THE ORACLE FOR THE ARM DECODERS IS NOT IN THIS TREE EITHER: Capstone, used on a
# developer's machine to check the ARM32 (ARM and Thumb state) and ARM64 decoders -
# the genotype tables under libgenome/genotype/arm32 and arm64 and the celllysis
# adapters that turn them into kgenome_cell_insn. Pass the header directory and the
# static library; match the two (a v5 header with a v6 library crashes).
CS_INC ?=
CS_LIB ?=
CS_ARM32_SRC := libgenome/celllysis/decode_arm32.c libgenome/celllysis/decode_thumb.c \
                libgenome/celllysis/decode_arm32_common.c \
                $(wildcard libgenome/genotype/arm32/*.c)
CS_ARM64_SRC := libgenome/celllysis/decode_arm64.c $(wildcard libgenome/genotype/arm64/*.c)
.PHONY: celllysis-arm32-diff celllysis-arm64-diff
celllysis-arm32-diff: CS_SRC = $(CS_ARM32_SRC)
celllysis-arm64-diff: CS_SRC = $(CS_ARM64_SRC)
celllysis-arm32-diff celllysis-arm64-diff: celllysis-%-diff:
	@test -n "$(CS_INC)" -a -n "$(CS_LIB)" || { echo "pass CS_INC=<capstone include dir> CS_LIB=<libcapstone.a>"; exit 1; }
	@$(call MKDIR,$(TEST))
	$(CC) -O2 -std=gnu11 -pthread -Ilibkofeng/kofcore -Ilibgenome -Ilibgenome/genotype -I$(CS_INC) tools/celllysis/$*_diff.c $(CS_SRC) $(CS_LIB) -o $(TEST)/$*_diff$(EXE)

# THE REFERENCE DECODER IS NOT IN THIS TREE. The x86 tables were produced by
# running tools/genotype/x86_gen.c against a reference decoder, and the checked-in
# tables are the product; nothing here links the reference. Re-running the
# generator, or the differential check, needs it on disk: REF=<its checkout>,
# the directory holding inc/ and src/. See THIRD-PARTY.md.
REF ?=
REF_SRC = $(wildcard $(REF)/src/*.c)
REF_FLAGS = -O2 -w -std=gnu11 -fno-common -Wno-incompatible-pointer-types -D_LIB -DAMD64 -I$(REF)/inc -I$(REF)/src -I$(REF)/src/include
X86_SRC = $(wildcard libgenome/genotype/x86/*.c)

.PHONY: genotype-x86 genotype-x86-diff
genotype-x86:
	@test -n "$(REF)" || { echo "genotype-x86: pass REF=<reference decoder checkout>"; exit 1; }
	@$(call MKDIR,$(TEST))
	$(CC) $(REF_FLAGS) tools/genotype/x86_gen.c tools/genotype/ref_shim.c $(REF_SRC) $(X86_SRC) -Ilibgenome/genotype -o $(TEST)/x86_gen$(EXE)
	$(TEST)/x86_gen$(EXE) $(REF)/inc/bdx86_constants.h libgenome/genotype/x86

genotype-x86-diff:
	@test -n "$(REF)" || { echo "genotype-x86-diff: pass REF=<reference decoder checkout>"; exit 1; }
	@$(call MKDIR,$(TEST))
	$(CC) $(REF_FLAGS) tools/genotype/x86_diff.c tools/genotype/ref_shim.c $(REF_SRC) $(X86_SRC) -Ilibgenome/genotype -o $(TEST)/x86_diff$(EXE)
	$(TEST)/x86_diff$(EXE)

#
# THE ARCHIVE IS REMOVED FIRST, AND THAT IS A FIX RATHER THAN TIDINESS.
#
# `ar r` REPLACES a member and adds a new one; it never removes one whose
# source has gone. So a file renamed between two builds leaves its old object
# in the archive beside the new one, and every symbol it defines is then in
# there twice - the stale copy silently winning for any link that reaches it
# first. Renaming dbloader.c and dbpacker.c produced exactly that: kofdb.o and
# kofpackw.o sat in libkofeng.a next to their replacements, and nothing said so
# because a duplicate member is not an error.
#
# An archive should hold what its prerequisites say and nothing else, so it is
# built from empty every time. It costs one unlink; ar then writes the same
# members it was going to write anyway.
#
$(LIB): $(LIB_OBJ) $(PH_OBJ) $(GT_OBJ) $(CL_OBJ) $(UC_OBJ)
	@$(call MKDIR,$(dir $@))
	@$(call RM,$@)
	$(AR) rcs $@ $^

#
# THE TWO LIBS AS ARCHIVES OF THEIR OWN, beside the one the SDK ships.
#
# libkofeng.a above stays the single archive every product links - a consumer
# names one library - and these two are built from the SAME objects, so there is
# one compile of each file and no second copy to drift. What they are for is the
# proof the layering rule asks for (CLAUDE.md section 12): a test linked against
# libkgenome.a or libkuncoat.a ALONE resolves, so neither lib reaches the engine.
# The harness in tests/lib/ links nothing else.
#
# libkgenome.a carries one object that is not under libgenome/: kofentropy.o, the
# foundation's entropy histogram, which the emulator's page statistics call. It
# is the only symbol of the foundation either lib uses (read off `nm -u`), and
# putting that one object in the archive is what lets it stand alone without a
# fourth archive for a single function. libkuncoat.a needs no foundation object.
KGENOME_CORE_OBJ := $(INT)/lib_kofcore/kofentropy.o
KGENOME_LIB := $(INT)/libkgenome.a
KUNCOAT_LIB := $(INT)/libkuncoat.a

$(KGENOME_LIB): $(PH_OBJ) $(GT_OBJ) $(CL_OBJ) $(KGENOME_CORE_OBJ)
	@$(call MKDIR,$(dir $@))
	@$(call RM,$@)
	$(AR) rcs $@ $^

$(KUNCOAT_LIB): $(UC_OBJ)
	@$(call MKDIR,$(dir $@))
	@$(call RM,$@)
	$(AR) rcs $@ $^

