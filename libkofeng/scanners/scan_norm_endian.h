/*
 * scan_norm_endian.h - the byte-order step of the normalised view.
 *
 * One struct carries what the step decided between the three points the
 * normaliser (scan_norm.c) calls it from; the rules are in
 * libgenome/genotype/image/endian.h and the glue is scan_norm_endian.c.
 */
#ifndef KOF_SCAN_NORM_ENDIAN_H
#define KOF_SCAN_NORM_ENDIAN_H

#include <stdint.h>

#include <genotype/image/endian.h>
#include <genotype/image/funcs.h>
#include <kofcore.h>

struct kof_scanner;
struct kof_obj_ctx;

struct sx_endian {
	struct kgenome_endian_plan plan;
	uint32_t wide_runs;     /* UTF-16BE runs turned to UTF-16LE */
	uint8_t  eligible;      /* big-endian ELF and a loaded rule that can use the view */
	uint8_t  ran;           /* the plan was applied to the copy (whatever it changed) */
	uint8_t  applied;       /* bytes were changed: the view has a reason to exist */
};

/*
 * Decide, once, from the object: is it a big-endian ELF for which some loaded
 * detector could match the little-endian form. Builds the plan when the
 * architecture has a twin. Returns `eligible`. A limit the plan met is reported
 * to the scanner (oc_scan_limit) here.
 */
int sx_endian_begin(struct kof_scanner *sc, struct kof_obj_ctx *ctx, kof_buf buf,
		    struct sx_endian *en);

/* Before the decode passes, over the copy: UTF-16BE runs outside what is kept. */
void sx_endian_wide(struct sx_endian *en, uint8_t *tmp, uint64_t n, const uint8_t *keep);

/* After the kept bytes are put back: the plan. Returns 1 when it changed bytes. */
int sx_endian_apply(struct sx_endian *en, uint8_t *tmp, uint64_t n);

/* The description the view carries (a copy of the parent's), turned to the canonical form. */
void sx_endian_describe(const struct sx_endian *en, void *elf_info_copy);

/* The parent's functions, found again in the view whose bytes the plan changed. */
void sx_endian_funcs(struct kof_obj_ctx *ctx, kof_buf parent, const struct sx_endian *en,
		     kof_buf view, struct kgenome_func_set *out);

/*
 * After the stage: the view was needed and was not made, for a reason that is a
 * limit - report it. `produced` is whether a view was handed on.
 */
void sx_endian_finish(struct kof_scanner *sc, struct kof_obj_ctx *ctx, kof_buf buf,
		      struct sx_endian *en, int produced);

#endif /* KOF_SCAN_NORM_ENDIAN_H */
