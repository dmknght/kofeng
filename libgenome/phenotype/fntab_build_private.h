#ifndef KGENOME_FNTAB_BUILD_PRIVATE_H
#define KGENOME_FNTAB_BUILD_PRIVATE_H

/*
 * fntab_build_private.h - what the three parts of the function table's builder share (fntab_build.c: the run and what every format ends with; fntab_build_elf.c and
 * fntab_build_pe.c: the strategies a case of that format runs). One run of the builder is one `struct kgenome_fntab_run`.
 */
#include "diag_scan_private.h"
#include <genotype/image/fntab.h>

struct kgenome_fntab_run {
	const struct kgenome_obj *obj;
	const uint8_t *data;
	uint64_t data_n;
	kof_buf file;
	struct kgenome_diag_walk *walk;         /* the caller's, or `own` */
	struct kgenome_diag_walk *own;
	struct kgenome_fntab_meta meta;
	struct kgenome_fntab_plan plan;
	struct kgenome_fntab_list l;            /* the entries every strategy appended */
	const uint64_t *pad;                    /* the walk's runs of padding instructions, once the walk ran */
	uint32_t n_pad;
	int walked;
	uint16_t add_partial;                   /* what the CASE says about the table that the merge cannot know (KGENOME_FNTAB_P_*) */
	/* fntab_reach.c's own prologue recogniser for this object's architecture, resolved ONCE (kgenome_fntab_reach,
	 * from `obj->arch`) and read by graph_of() on every candidate - never re-derived from instruction bytes
	 * inside that hot per-candidate loop (kofeng/CLAUDE.md: a bound of work is sized once, from the object, not
	 * per use). NULL until kgenome_fntab_reach runs (nothing else in this struct's lifetime calls it). */
	int (*entry_insn)(const struct kgenome_cell_insn *);
};

/* THE PARTS OF FUNCTIONS: an extent that belongs to the function starting at `root` but is not its first range - a chained .pdata part that does not continue
 * its root's body, a derived function's block run that is not contiguous with its entry's. One list for both: they cover code, and they become ranges of their
 * root (kgenome_funcs_set_ranges) once the table's indices are final. */
struct kgenome_fntab_parts {
	struct kgenome_fntab_extent *at;
	uint64_t *root;
	uint32_t n, cap;
};

/* Append a part; 0 when memory was refused (nothing appended). */
int kgenome_fntab_parts_add(struct kgenome_fntab_parts *p, uint64_t at, uint64_t len, uint64_t root);

/* WHAT THE DERIVATION FOUND (fntab_derive.c), for the builder to put in the table: the functions (trust DERIVED, sorted by off), their further ranges (appended
 * to the builder's `parts`), and what it counted. `status` KGENOME_NOMEM: the derivation could not be held and derived nothing. */
struct kgenome_fntab_derived {
	struct kgenome_fntab_list fn;
	struct kgenome_fntab_parts *parts;
	uint32_t n_into_high;           /* kgenome_func_set.n_derive_into_high */
	uint32_t n_skipped;             /* kgenome_func_set.n_derive_skipped */
	int over;                       /* KGENOME_FNTAB_DERIVE_BYTES or the promotion passes' bound fired (KGENOME_FNTAB_P_DERIVE_CAP) */
	enum kgenome_status status;
};

/* Derive the functions of the undeclared code of `s` (its NONE units) from the declared starts in it (fntab_derive.c). `s` is read, not changed. */
void kgenome_fntab_derive(struct kgenome_fntab_run *r, const struct kgenome_func_set *s, struct kgenome_fntab_derived *out);

/* The strategies of an ELF case (fntab_build_elf.c) and of a PE case (fntab_build_pe.c): the selector's row, run. */
void kgenome_fntab_collect_elf(struct kgenome_fntab_run *r);
void kgenome_fntab_collect_pe(struct kgenome_fntab_run *r);
/* The entry walk (the one decode, with the trace), asked by a case that names it: the walk's entries are appended, and the padding runs are kept for the ends. 1 when it ran. */
int kgenome_fntab_run_walk(struct kgenome_fntab_run *r);

/* The REACH step (fntab_reach.c; PE x86/x64, after the merge, before the ends): ends from what the entries reach, starts from the gaps behind them. `cover` are ranges the merge left out of the table
 * that are bodies all the same (the chained fragments of an unwind table); the function sorts them. */
void kgenome_fntab_reach(struct kgenome_func_set *s, struct kgenome_fntab_run *r, const struct kgenome_fntab_extent *ext, uint32_t n_ext,
			 struct kgenome_fntab_extent *cover, uint32_t n_cover);

#endif /* KGENOME_FNTAB_BUILD_PRIVATE_H */
