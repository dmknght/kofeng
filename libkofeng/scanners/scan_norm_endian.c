/*
 * scan_norm_endian.c - the canonical byte order of a normalised view.
 *
 * A big-endian build of a program is the same instruction stream as its
 * little-endian twin, written the other way round, so a rule cut from one does
 * not match the other. The view the normaliser already makes is where the two are
 * put in one order: this file decides whether an object needs it, builds the
 * plan, and hands the three steps to scan_norm.c (before the decode, after the
 * kept bytes are restored, and when the view is described). What is swapped and
 * why is in libgenome/genotype/image/endian.h.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objctx_int.h"
#include "scan_norm_endian.h"
#include "../analyzers/genome_obj.h"
#include "../analyzers/normalize/executables.h"
#include <genotype/image/elf_types.h>
#include <phenotype/diag_scan.h>
#include <string.h>

/*
 * IS THERE A RULE THAT COULD USE THE VIEW. The canonical form costs a copy of
 * the object, and it is made for one purpose: a detector cut from the other byte
 * order matches it. A database holding no detector that can run on this
 * object - none that targets the format, the architecture and the size, and
 * carries a marker or a block - has nothing to match, so no view is made and the
 * object costs what it always did.
 *
 * Walked until the first hit, and asked only of a big-endian object, which is a
 * small share of what is scanned; a database with a rule that names no
 * architecture answers at the first module.
 */
static int rule_can_use_view(const struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
	const struct kof_engine *e = sc->eng;
	uint32_t i;

	if (!e || !e->mods)
		return 0;
	for (i = 0; i < e->n_mods; i++) {
		const struct kof_module *m = &e->mods[i];

		if (!m->n_str && !m->n_block)
			continue;
		if (kof_module_precond(m, ctx, ctx->obj_size) == KOF_PRECOND_OK)
			return 1;
	}
	return 0;
}

int sx_endian_begin(struct kof_scanner *sc, struct kof_obj_ctx *ctx, kof_buf buf,
		    struct sx_endian *en)
{
	struct kgenome_obj g;
	enum kgenome_status st;

	memset(en, 0, sizeof *en);
	if (!ctx || ctx->format != KOF_FMT_ELF || !ctx->file_header)
		return 0;
	kof_genome_obj(ctx, &g);
	if (!kgenome_obj_big_endian(&g))
		return 0;       /* little-endian: nothing here may change a byte */
	if (!rule_can_use_view(sc, ctx))
		return 0;
	en->eligible = 1;
	/* An architecture with no twin keeps its order; only UTF-16BE is handled. */
	if (!kgenome_endian_has_twin(g.arch))
		return 1;
	st = kgenome_endian_plan_build(buf, &g, &en->plan);
	/* A cut header is the parse's finding already; any other incomplete answer
	 * is ours to say, because the view will be the object half in each order.
	 * So is a span the plan refused because the object's tables overlap: the plan counted them
	 * (`dropped`) as "a fact about the file" and nothing read the count, so the bytes it left
	 * in the file's order went out in a view reported complete (endian_view plan_dropped). */
	if ((st != KGENOME_OK && st != KGENOME_BAD_INPUT) || en->plan.dropped)
		oc_scan_limit(sc);
	return 1;
}

void sx_endian_wide(struct sx_endian *en, uint8_t *tmp, uint64_t n, const uint8_t *keep)
{
	if (!en->eligible)
		return;
	en->wide_runs = kgenome_endian_wide(tmp, n, keep, &en->plan, KOF_EXE_NORM_WIDE_MIN);
	if (en->wide_runs)
		en->applied = 1;
}

int sx_endian_apply(struct sx_endian *en, uint8_t *tmp, uint64_t n)
{
	if (!en->eligible || !en->plan.n)
		return en->applied;
	en->ran = 1;
	if (kgenome_endian_apply(tmp, n, &en->plan))
		en->applied = 1;
	return en->applied;
}

void sx_endian_describe(const struct sx_endian *en, void *elf_info_copy)
{
	if (en->eligible && elf_info_copy)
		kgenome_endian_describe((struct kgenome_elf_info *)elf_info_copy, &en->plan);
}

void sx_endian_funcs(struct kof_obj_ctx *ctx, kof_buf parent, const struct sx_endian *en,
		     kof_buf view, struct kgenome_func_set *out)
{
	struct kgenome_obj g;
	struct kgenome_func_set own;
	const struct kgenome_func_set *pf = oc_funcs(ctx);

	memset(out, 0, sizeof *out);
	memset(&own, 0, sizeof own);
	kof_genome_obj(ctx, &g);
	if (!pf) {
		kgenome_diag_funcs_of(&g, parent.p, parent.n, &own);
		pf = &own;
	}
	kgenome_funcs_remap_endian(parent.p, parent.n, pf, &en->plan, view.p, view.n, out);
	kgenome_funcs_free(&own);
}

void sx_endian_finish(struct kof_scanner *sc, struct kof_obj_ctx *ctx, kof_buf buf,
		      struct sx_endian *en, int produced)
{
	/*
	 * A VIEW THAT WAS NEEDED AND WAS NOT MADE IS A LIMIT, unless it was not
	 * made for a reason that is not one. The reasons that are not: the object
	 * is too small to be worth a view, it is itself a view, or its code is
	 * still compressed (the same test norm_wanted applies - nothing is to be
	 * swapped in a stream). What is left is the ledger and the allocator, and
	 * a big-endian object that could not be put in the canonical form is an
	 * object whose little-endian rules did not run on it.
	 */
	if (produced || !en->eligible)
		return;
	if (buf.n < NORM_MIN_OBJ || kof_src_kind_of(sc->cur.src) == KOF_ENT_NORMALIZED)
		return;
	if (ctx->content && ctx->content->region_entropy &&
	    ctx->content->region_entropy(ctx, NORM_CODE_MASK) >= NORM_DENSE_EIGHTHS)
		return;
	/* Nothing the view would have changed: a big-endian object with no twin and no
	 * UTF-16BE, or whose rules were declined above, has no view to refuse. */
	if (!en->plan.n && !en->applied && !en->wide_runs)
		return;
	/* The swap ran and changed nothing: a view that was not needed. */
	if (en->ran && !en->applied && !en->wide_runs)
		return;
	oc_scan_limit(sc);
}
