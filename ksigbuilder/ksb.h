/*
 * ksigbuilder - the C half of the signature toolchain.
 *
 *   ksigbuilder --extract <signature.c> <out.pat.h> <out.names> <out.pre> <out.strs>
 *   ksigbuilder <artefact-dir> <out-dir>
 *
 * The toolchain is one program now: --module turns one signature
 * source into one artefact, and this turns artefacts into .ksig packs. Everything
 * written in C is here.
 *
 * The split is by what each language is good at. Compiling a module is a wrapper
 * around cc, ld, nm and readelf, which is what a shell script is for. Reading
 * declarations out of a source and laying out bytes are neither, and both are C -
 * so they are one program with several modes rather than several programs, because a third
 * binary in the toolchain is a third thing to build, install and keep in step for
 * no gain. --extract is what --module calls; the pack mode is what the
 * Makefile calls after every source has been compiled.
 *
 * The modes also share what matters: the region names --extract accepts are
 * bound to the enums in kofmod/, and the pack layout comes from the same
 * kof_pack_build the engine's loader was written against. A hand-kept copy of
 * either is a copy that drifts - the region table was one, and every PE signature
 * failed to compile until it was bound to the header instead.
 *
 * THE UNITS. This is the private header: the types the units share, the one
 * context they pass about (struct ksb_ctx), and what one unit offers another.
 * A unit is a mode or one responsibility inside a mode:
 *
 *   ksb_args.c      The usage text and the options every mode takes (toolchain
 *                   and paths).
 *   ksb_artefact.c  PACK: one artefact set read back from disk, and what
 *                   identifies it.
 *   ksb_build.c     --module, the compiler and linker: run the tools, produce
 *                   the raw blob.
 *   ksb_check.c     --module, the refusals: what each kind of module may not
 *                   be, checked in the source.
 *   ksb_diag.c      --diagnose: one diagnose source in, one record out.
 *   ksb_diagpack.c  The diagnoses of a database, in packs by kind:
 *                   diag-<kind>.kdig.
 *   ksb_disease.c   The diseases and the syndromes of a database.
 *   ksb_emit.c      --extract, the output: the generated header and the record
 *                   lines for one declaration.
 *   ksb_extract.c   --extract: one source in, the header, names, preconditions
 *                   and strings out.
 *   ksb_group.c     PACK: which pack an artefact goes in, and what the pack is
 *                   called.
 *   ksb_image.c     What a linked module has to be, asked of the engine's own
 *                   ELF and PE parsers.
 *   ksb_lint.c      The performance lint: what the build can see about a rule
 *                   that works and costs more than it needs.
 *   ksb_main.c      The entry point: the options every mode takes, then the
 *                   mode.
 *   ksb_masks.c     --arch-mask and --subtype-mask: a mask from names.
 *   ksb_module.c    --module: one signature source in, one artefact set out.
 *   ksb_pack.c      The default mode: artefacts to packs; and the small modes
 *                   that dispatch before it.
 *   ksb_read.c      Reading one declaration's arguments out of the source
 *                   text: strings, enums, masks, names.
 *   ksb_resolve.c   The one-per-module declarations (format, arch, subtype,
 *                   size, step, heuristic) and what they resolve to.
 *   ksb_scan.c      --extract, the scan: find each declaration macro in a line
 *                   and read it into the context.
 *   ksb_tree.c      --tree: a content directory in, a database out; the
 *                   sources built side by side.
 *   ksb_uses.c      Which diagnoses a source reads: the scan of the tree and
 *                   the reader's report hooks.
 *   ksb_util.c      The small shared helpers: the error report, whole-file
 *                   reads and writes, path joins.
 */
#ifndef KSIGBUILDER_KSB_H
#define KSIGBUILDER_KSB_H

/* Before any include, not after: opendir and readdir are POSIX, and a feature test
 * macro placed after the first include has no effect at all. */
#define _POSIX_C_SOURCE 200809L

/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h, whose
 * POSIX half calls memmem - a GNU extension that <string.h> only declares when
 * this is defined, and defining it after the first include is too late. The
 * same reason kofinspect.c and kofexamine.c give. */
#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofplatform.h>
#include <kofmod/proc.h>
#include <analyzers/diseases/kofdisease.h>
#include <databases/pack/dbcore.h>
#include <databases/pack/hexprog.h>

/* The process API the compiler run and the tree runner share. */
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#endif

#define MAX_PATTERNS 256
#define MAX_LITERAL  512
#define MAX_NAMES    256
#define PACK_NAME_MAX 64u

/*
 * One declared string.
 *
 * Named by the author rather than by __LINE__, which is what the previous shape
 * used. That removes the rule against two patterns on one line, and it means a
 * misspelled reference is an undefined identifier instead of a search that finds
 * nothing.
 */
struct pat {
	int      line;
	char     name[64];
	int      kind;              /* enum kof_pack_str_kind */
	int      icase;             /* literal only */
	int      fullword;          /* literal only */
	uint32_t len;               /* bytes, or the compiled program length */
	uint32_t open_gaps;         /* hex: jumps written open ("[n-]"), clamped */
	uint8_t  bytes[KOF_HEX_MAX_PROG];

	/*
	 * The text as it was WRITTEN, kept only for reporting.
	 *
	 * A wide pattern's bytes are the literal with zeros interleaved, so
	 * printing them - in the generated header's comment, in the build log -
	 * shows one character and stops at the first zero. What a reader needs
	 * to see in those places is the marker they typed.
	 *
	 * Empty for anything that is already readable as its own bytes.
	 */
	char     shown[MAX_LITERAL];
	int      wide;
};
/* A named set of regions. Separate from a string because the same marker can be
 * looked for in more than one place, so the range is named at the call site. */
struct rng {
	int      line;
	char     name[64];
	uint32_t mask;
};
/*
 * A declared similarity block.
 *
 * The hashes are written out by the generator, not typed, so the only thing
 * checked here is that there are enough of them to score with and not more than
 * a rule may carry - see KGENOME_MUTATION_MIN_HASH and KOF_MUTATION_MAX_HASH. What they
 * mean is nothing this program can know: they are what one particular block of
 * one particular sample came to, and the build cannot recompute them without
 * the sample.
 */
struct blk {
	int      line;
	char     name[64];
	uint32_t mask;
	uint32_t norm;
	uint32_t side;                  /* enum kgenome_mutation_side */
	uint32_t hash[KOF_MUTATION_MAX_HASH];
	uint32_t n_hash;
};
/*
 * Detection names.
 *
 * These go to a table beside the blob, never into it. A module reports a family by
 * line number and the host resolves it, so the string is absent from the artefact
 * and renaming a family is a data edit. It also means an out of date table produces
 * "unknown name" rather than the wrong name.
 */
struct dname {
	int  line;
	char text[MAX_LITERAL];
};

#define DECL_ARG_MAX 512

struct simple_decl {
	const char *name;
	/*
	 * A SECOND SPELLING OF THE SAME DECLARATION, or NULL.
	 *
	 * One slot, two names: KOF_TARGET_EVENT and KOF_TARGET_FORMAT say the
	 * same thing about the same axis, and an author writing a rule about a
	 * script submission should not have to call it a format. Sharing the
	 * slot rather than adding one is what keeps "declared twice" working -
	 * a module that uses both spellings has answered one question twice,
	 * and gets the same error as a module that repeated either.
	 */
	const char *alias;
	int         count;
	int         line;
	char        arg[DECL_ARG_MAX];
};

enum {
	SD_FORMAT = 0, SD_ARCH, SD_SUBTYPE, SD_SIZE_MIN, SD_ANALYZE_STEP,
	SD_HEUR_PHASE, SD_HEUR_LEVEL, SD_HEUR_WANT,
	SD_HEUR_NAME, SD_HEUR_PREDICT, SD_CONTENT, SD_COUNT
};

struct img_facts {
	int      have_reloc;
	char     extra_sec[128];   /* first unexpected section, or empty */
	char     undef[128];       /* first undefined symbol, or empty */
	char     entry_name[32];   /* kof_scan / kof_unpack / kof_heur */
	uint64_t entry_off;
	int      n_entry;
	/*
	 * AND THE SECOND ENTRY, WHICH IS NOT A KIND.
	 *
	 * kof_cure is not one of the three above and must not be counted as
	 * one: a module is still exactly one kind, and a cure is something a
	 * DETECTOR may additionally know how to do. The loader finds the
	 * first entry at offset zero and needs no symbols; this one has no
	 * such place, so its offset is resolved here, once, and written into
	 * the module's record - see kof_pack_mod.cure_off.
	 */
	uint64_t cure_off;
	int      have_cure;
	uint64_t blob_off, blob_len;
	uint64_t data_bytes, bss_bytes;
};

/* Which ranges each declared marker is searched in, and where. */
struct use {
	/* Searched for without naming a region - kof_find_str_where and its
	 * kind. Not a range, and still a use. */
	int      used_unranged;
	uint32_t n_rng;
	int      rng[KOF_MAX_RANGE_PER_MODULE];
	int      line[KOF_MAX_RANGE_PER_MODULE];
};

/* Everything read out of one artefact set, owned until its pack is written. */
struct artefact {
	char    *stem;                   /* the path without the .blob */
	char    *label;                  /* what the module is called; see below */
	char    *srcpath;                /* where it lives in the bases tree */
	uint8_t *code;
	uint32_t code_len;

	uint32_t kind;
	/* The targets as ids and a count, the way the pack carries them. An
	 * empty list is "any", which is why `any_target` is kept beside it -
	 * "named everything" and "named nothing" are both zero here and only
	 * one of them is a module. */
	uint8_t  target[KOF_TARGET_LIST_MAX];
	uint8_t  n_target;
	int      any_target;
	uint32_t scan_mask, arch_mask, subtype_mask, step;
	uint32_t heur_phase, heur_want, heur_level;
	/* Where kof_cure() sits inside the blob, 0 when there is none. Known
	 * only once the image is linked, so it travels in the metadata file
	 * beside the blob rather than out of the source. */
	uint32_t cure_off;
	uint64_t size_min;

	/* What KOF_TARGET_NAME declared - empty family / maltype 0 for an
	 * unpack-kind module, where it is not required. */
	char    *family;
	uint32_t maltype;
	/* What KOF_DECLARE_DISEASE declared; empty and 0 when it did not. */
	char    *disease;
	uint32_t disease_type;

	/* What KOF_HEUR_PREDICT declared, or NULL. Only a rule has one. */
	char    *heur_predict;
	/* What KOF_TARGET_CONTENT declared, or NULL. */
	char    *content;

	/* What this module fires on: preconditions plus the exact pattern/region
	 * set, order independent. See artefact_fingerprint. Not a security hash and
	 * not stored anywhere beyond this run - it exists only to warn when two
	 * artefacts have it in common. */
	uint32_t fp;

	struct kof_pw_str  *str;
	uint32_t            n_str;
	uint32_t           *rng;
	uint32_t            n_rng;
	struct kof_pw_name *name;
	uint32_t            n_names;

	/* The similarity blocks this module declared, and the hashes they are
	 * slices of. Empty for every module that declared none, which is most
	 * of them. */
	struct kof_mutation_block *blk;
	uint32_t                 n_blk;
	uint32_t                *pool;
	uint32_t                 n_pool;

	/* The literals and name texts the descriptors above point into. */
	uint8_t *str_bytes;
	char    *name_text;
};

/*
 * WHICH PACK A FORMAT BELONGS IN.
 *
 * Derived from enum kof_format by a switch with no default, so a format added
 * to the engine and not assigned here fails to compile rather than silently
 * landing in a pack somebody has to notice is wrong.
 *
 * Executables stay apart by format - an ELF pack and a PE pack - because that
 * is the split a person reading a database directory expects and because they
 * are the two that will grow. Archives and documents are gathered, because
 * "which container was it" is a question the per-module column answers and not
 * one worth a file each.
 */
enum pack_bucket {
	BUCKET_NONE = -1,
	BUCKET_ELF = 0, BUCKET_PE, BUCKET_MACHO,
	BUCKET_ARCHIVE, BUCKET_DOC, BUCKET_SCRIPT, BUCKET_RAW,

	/* Event targets, which are not file formats at all - see
	 * KOF_TARGET_FIRST_EVENT. A pack of their own so a host that never
	 * scans a process does not load rules about one. */
	BUCKET_PROC, BUCKET_AMSI
};

/* A set of artefacts sharing one grouping key, which is one pack. */
struct group {
	uint32_t  kind, arch_mask;
	/*
	 * A `mutation` FLAG STOOD HERE and split the groups, so a rule carrying
	 * a similarity block packed into mutation-elf.ksig instead of
	 * sigs-elf.ksig. The reason given was the person reading a directory
	 * listing, and its own words conceded the rest: "a detector by kind -
	 * it runs in the same loop, reports the same way".
	 *
	 * It went with the retired bases/mutation kind. The engine never read it - selection is
	 * per module, and the only pack-level fields are the unioned target
	 * and arch masks, which no prefilter consults yet; see the note at the
	 * grouping loop for why a wider union costs sweeps and never a
	 * detection. What the split did cost was real: two source directories
	 * meant two rules could both be called Gafgyt.00.
	 */
	uint64_t  target_set;            /* see target_set_of */
	int       bucket;                /* enum pack_bucket, or BUCKET_NONE */
	uint32_t *member;                /* indices into the artefact array */
	uint32_t  n, cap;
};

#define DIAG_USE_MAX 512u
#define DIAG_USER_LEN 40u
struct diag_use {
	char diag[64];
	char user[DIAG_USER_LEN];
};

#define DIS_TYPE_UNKNOWN 0xffu

/* Who named a disease: a detector declared it, a syndrome mentions it. A name only
 * a syndrome mentions can never be found, and a disease no syndrome mentions is
 * never typed by anything - both are what a database looks like part way through
 * being written, and both are warned about from this one table. */
#define DIS_BY_DETECTOR 1u
#define DIS_BY_SYNDROME 2u

struct dis_ent {
	uint32_t id;
	unsigned type;
	unsigned by;
	char     name[KOF_DIAG_DISEASE_LEN + 1u];
};

/*
 * THE STATE OF ONE RUN, in one place and passed to every function that reads or
 * writes it. It used to be file-scope statics spread over an eight thousand
 * line file, which is what made it impossible to tell, from a function's
 * signature, what it depended on: a function that takes no `ksb` touches none
 * of this.
 *
 * One group per owner. `decl` is what one signature source declares (the
 * --extract scan fills it and --module reads it back); `lint` is what the
 * performance lint counts; `opt` is what the command line set; `kept` is what
 * the last module build left for the caller; `diag` and `diseases` are the
 * tree and diagnose builds' registers. Allocated once, in main.
 */
struct ksb_decl {
	struct pat pats[MAX_PATTERNS];
	int npats;
	struct rng rngs[MAX_PATTERNS];
	int nrngs;
	struct blk blks[MAX_PATTERNS];
	int nblks;
	struct dname names[MAX_NAMES];
	int nnames;
	/*
	 * Scan mask of the whole module: the OR of every region it can search.
	 *
	 * A precondition that costs the author nothing, because it is read out of the
	 * declarations rather than declared separately - and it cannot go stale. If a module
	 * only searches KGENOME_SCAN_ELF_NOLOAD and the object has no section table, that region
	 * resolves to nothing and the module cannot match.
	 *
	 * A module with no searches gets 0, which reads correctly: it names no region, so no
	 * region's absence can excuse it from running.
	 */
	unsigned long scan_mask;
	/*
	 * KOF_TARGET_NAME's two fields, held like the target list and its siblings: one
	 * file, one family. Unlike those, read at this level rather than by the caller, because
	 * composing a detection name is this program's job already - see read_variant.
	 */
	char family[80];
	int  maltype;
	/*
	 * KOF_DECLARE_DISEASE(TYPE, "layer/behaviour"): what this detector's match finds,
	 * and the type of malware it belongs to. One per file, like KOF_TARGET_NAME and
	 * for the same reason: the module is one detector. Read at this level so the
	 * extract file can carry it to the packer, which is where it is registered.
	 */
	char dis_name[KOF_DIAG_DISEASE_LEN + 1u];
	int  dis_type;
	int  have_dis;
	/* The type the FILE NAME says, or -1 - see nameform_read. */
	int  name_type;
	/*
	 * The id at the end of the file name - "01" out of virus_sality_01.c - and
	 * empty when the name is of the old form.
	 *
	 * THIS IS THE VARIANT. KOF_MALVAR_AUTO resolves to it; see the note there for
	 * what it replaced and why. A variant names the SAMPLE a signature was
	 * written from, and one sample may be matched by a pattern, by a block
	 * similarity or by a capability chain - so it cannot belong to any one
	 * matcher, and retiring a matcher must not rename the finding.
	 *
	 * AND A RETIRED ID LEAVES A GAP, on purpose. 01 then 03 is the evidence that
	 * 02 was not handed to something else; closing the gap would make an old
	 * name mean a new sample, which is the one thing this scheme exists to
	 * prevent.
	 */
	char name_id[16];
	int  have_name;
	/* What the resolution below produces, for the caller that writes .pre. */
	/*
	 * The targets as IDS, not as a mask - see n_target in dbloader.h. An empty list
	 * is KOF_FMT_ANY, which is what the engine reads it as, so "everything" costs
	 * nothing to carry and cannot fall behind the enum the way a derived mask did.
	 */
	uint8_t  target[KOF_TARGET_LIST_MAX];
	uint32_t arch_mask, subtype_mask;
	uint64_t size_min;
	int      step, heur_phase, heur_level, heur_want;
	int      n_targets;
	/* KOF_FMT_ANY was written out, as opposed to nothing being written at all -
	 * both are an empty list, and only one of them is a module saying so. */
	int      any_target;
	char heur_name[64], heur_predict[64], content[48];
	/* What the module mode needs from the extract pass, which computes them. */
	unsigned long scan_mask_out;
	int           nstr_out;
	char  *src_text;
	size_t src_len;
	/* The one-per-module declarations, collected before they are resolved. */
	struct simple_decl simple[SD_COUNT];
};

struct ksb_lint {
	int warnings;
	struct use uses[MAX_PATTERNS];
	int rng_used[MAX_PATTERNS];
};

/* The toolchain and the paths, as arguments - see ksb_opt_take. */
struct ksb_opts {
	/*
	 * THE TOOLCHAIN AND THE PATHS, AS ARGUMENTS AND NOT AS ENVIRONMENT.
	 *
	 * These were read with getenv, and the Makefile exported them because
	 * `VAR=value command` is sh's way of setting one and PowerShell has no
	 * equivalent. A command and its arguments is the shape both shells agree
	 * on - which is what the Makefile's own note says - so they are options.
	 *
	 * It also means a build cannot be changed by what happens to be in the
	 * environment it was started from, which is the same reason the engine
	 * carries no getenv at all - see libkofeng/kofcore/kofdebug.h.
	 */
	const char *cc;
	const char *ld;
	const char *include;
	const char *ldscript;
	const char *basedir;
	const char *triple;
	const char *tmpdir;
	int         keep_work;
};

/* What the last module build leaves for its caller. */
struct ksb_kept {
	char entry[32];
	/* And where kof_cure() landed, 0 when the module has none - see
	 * img_facts.cure_off. */
	uint64_t cure;
};

/* The diagnoses each source reads, and the diagnoses this run has built. */
struct ksb_diaguse {
	struct diag_use uses[DIAG_USE_MAX];
	unsigned        n_uses;
	int             uses_known;    /* only a tree build knows them all */
	char            built[64][64];
	unsigned char   built_dis[64]; /* 1: it declares a disease, which the verdict reads */
	unsigned        n_built;
};

/* The registry of diseases the database is made of. */
struct ksb_diseases {
	struct dis_ent *ent;
	size_t n, cap;
};

struct ksb_ctx {
	const char *src_name;
	int errors;
	struct ksb_decl     decl;
	struct ksb_lint     lint;
	struct ksb_opts     opt;
	struct ksb_kept     kept;
	struct ksb_diaguse  diag;
	struct ksb_diseases diseases;
};

/* The words an option may be written with; n2 is NULL for a two-way option. */
struct ksb_enum_names {
	const char *n0, *n1, *n2;
};

/* ---- what one unit offers another ----------------------------------------- */

/* ksb_resolve.c */
void ksb_decl_init(struct ksb_ctx *ksb);

/* ksb_args.c */
int ksb_opt_take(struct ksb_ctx *ksb, int *argc, char **argv);
void ksb_usage(const char *argv0);

/* ksb_artefact.c */
void ksb_artefact_free(struct artefact *a);
int ksb_artefact_cmp(const void *a, const void *b);
int ksb_artefact_load(struct artefact *a, const char *blob_path);
void ksb_warn_duplicate_patterns(struct artefact *arts, uint32_t n_arts);

/* ksb_build.c */
int ksb_do_build(struct ksb_ctx *ksb, const char *src, const char *pat,
		 const char *obj, const char *img, const char *raw,
		 const char *lds, const char **entry_out);

/* ksb_check.c */
int ksb_check_format_headers(struct ksb_ctx *ksb);
int ksb_kind_checks(struct ksb_ctx *ksb, int kind);
int ksb_check_size_body(struct ksb_ctx *ksb);

/* ksb_diag.c */
int ksb_diagnose_main(struct ksb_ctx *ksb, int argc, char **argv);

/* ksb_diagpack.c */
char *ksb_dup_n(const char *p, size_t n);
int ksb_write_krec_pack(const char *path, const char *magic,
			unsigned char *const *rec, const size_t *rlen,
			size_t n, size_t *total_out);
int ksb_write_diag_packs(const char *db, char **recs, char **kinds,
			 size_t n_recs);

/* ksb_disease.c */
int ksb_disease_note(struct ksb_ctx *ksb, const char *name, unsigned type,
		     unsigned by);
int ksb_write_diseases(struct ksb_ctx *ksb, const char *db);
int ksb_build_syndromes(struct ksb_ctx *ksb, const char *base, const char *db);

/* ksb_emit.c */
void ksb_emit_str_id(FILE *out, const struct pat *p, int idx);
void ksb_emit_rng_id(FILE *out, const struct rng *r, int idx);
void ksb_emit_str_record(FILE *out, const struct pat *p, int idx);
void ksb_emit_rng_record(FILE *out, const struct rng *r, int idx);
void ksb_emit_blk_id(FILE *out, const struct blk *b, int idx);
void ksb_emit_blk_record(FILE *out, const struct blk *b, int idx);

/* ksb_extract.c */
int ksb_extract_main(struct ksb_ctx *ksb, int argc, char **argv);

/* ksb_group.c */
const char *ksb_bucket_name(int b);
int ksb_bucket_of_targets(const uint8_t *id, uint8_t n, int any);
uint64_t ksb_target_set_of(const struct artefact *a);
int ksb_group_cmp(const void *pa, const void *pb);
int ksb_group_add(struct group *g, uint32_t idx);
const char *ksb_group_name(const struct group *g);
void ksb_name_append(char *out, size_t cap, size_t *at, const char *s);
int ksb_format_list(uint64_t set, char *out, size_t cap);
int ksb_label_one(const struct artefact *arts, const uint32_t *member,
		  uint32_t n, char *out, size_t cap);

/* ksb_image.c */
int ksb_coff_read(const char *path, struct img_facts *out);
int ksb_pe_image_read(const char *path, struct img_facts *out);
int ksb_img_read(const char *path, const char *want_blob,
		 struct img_facts *out);

/* ksb_lint.c */
void ksb_lint_calls(struct ksb_ctx *ksb, const char *src, size_t len);
void ksb_lint_debug_in_headers(struct ksb_ctx *ksb, const char *src, size_t n);
void ksb_lint_report(struct ksb_ctx *ksb);

/* ksb_masks.c */
int ksb_arch_mask_main(int argc, char **argv);
int ksb_subtype_mask_main(int argc, char **argv);

/* ksb_module.c */
int ksb_module_main(struct ksb_ctx *ksb, int argc, char **argv);

/* ksb_pack.c */
int ksb_pack_main(struct ksb_ctx *ksb, int argc, char **argv);

/* ksb_read.c */
int ksb_arg_count(const char *p);
int ksb_read_literal(struct ksb_ctx *ksb, const char *p, int line,
		     struct pat *out);
int ksb_read_mask(struct ksb_ctx *ksb, const char *p, int line,
		  struct rng *out);
int ksb_read_regex_text(struct ksb_ctx *ksb, const char *p, int line,
			char *out, size_t cap);
int ksb_read_hex_text(struct ksb_ctx *ksb, const char *p, int line, char *out,
		      size_t cap);
int ksb_read_enum3(struct ksb_ctx *ksb, const char *p, int which, int line,
		   const char *what, const struct ksb_enum_names *names,
		   int *out);
int ksb_read_enum(struct ksb_ctx *ksb, const char *p, int which, int line,
		  const char *what, const char *n0, const char *n1, int *out);
int ksb_read_ident(struct ksb_ctx *ksb, const char *p, int line, char *out,
		   size_t cap);
int ksb_str_name_taken(struct ksb_ctx *ksb, const char *nm);
int ksb_rng_name_taken(struct ksb_ctx *ksb, const char *nm);
int ksb_blk_name_taken(struct ksb_ctx *ksb, const char *nm);
int ksb_read_norm(struct ksb_ctx *ksb, const char *p, int line,
		  struct blk *out);
int ksb_read_hashes(struct ksb_ctx *ksb, const char *p, int line,
		    struct blk *out);
int ksb_read_name(struct ksb_ctx *ksb, const char *p, int line, char *out,
		  size_t cap);
int ksb_read_maltype(struct ksb_ctx *ksb, const char *p, int line, int *out);
int ksb_read_family(struct ksb_ctx *ksb, const char *p, int line, char *out,
		    size_t cap);
int ksb_read_variant(struct ksb_ctx *ksb, const char *p, int line, char *out,
		     size_t cap);

/* ksb_resolve.c */
void ksb_decl_collect(struct ksb_ctx *ksb, const char *at, int lineno);
int ksb_target_named(struct ksb_ctx *ksb, uint8_t id);
void ksb_target_text(struct ksb_ctx *ksb, char *out, size_t cap);
void ksb_resolve_decls(struct ksb_ctx *ksb);

/* ksb_scan.c */
void ksb_scan_line(struct ksb_ctx *ksb, char *at, size_t line_len, int lineno);

/* ksb_tree.c */
int ksb_is_c_source(const char *name);
int ksb_tree_main(struct ksb_ctx *ksb, int argc, char **argv);

/* ksb_uses.c */
void ksb_uses_scan(struct ksb_ctx *ksb, const char *path);
void ksb_dsrc_error(void *ud, int line, const char *msg);
void ksb_dsrc_warn(void *ud, const char *msg);

/* ksb_util.c */
void ksb_err(struct ksb_ctx *ksb, int line, const char *msg);
char *ksb_slurp(const char *path, size_t *len_out);
char *ksb_sibling(const char *stem, const char *ext);
char *ksb_join_path(const char *dir, const char *leaf);
uint8_t *ksb_read_whole(const char *path, size_t cap, size_t *out_len);
int ksb_write_file(const char *path, const uint8_t *data, size_t len);

#endif /* KSIGBUILDER_KSB_H */
