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
};

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
