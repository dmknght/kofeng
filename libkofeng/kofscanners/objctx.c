/*
 * objctx.c - the scan context, as a module sees it.
 *
 * Builds a kof_obj_ctx and serves every call made through it. That makes this the
 * entire untrusted boundary: module code comes out of a database and runs native, and
 * every byte it can reach it reaches through one of these functions - so each one
 * bounds checks, and an out of range read yields zero rather than faulting. Eight
 * functions audited once beats bounds arithmetic repeated in every module.
 *
 * It sits with the scanner rather than beside the ABI headers in core/kofmod because
 * every line of it reads the scanner's per-object state - the match context, the
 * loaded engine, what the running module has reported. Put next to the headers it
 * would declare, it would reach sideways for all of that and be less cohesive, not
 * more. The headers are the contract; this is the scanner honouring it.
 *
 * Its own file for one reason: a mistake here is a memory safety bug rather than a
 * wrong answer, so it should read end to end without the scan routine in the way.
 *
 * Nothing here decides anything. These read, compare, and hand a declared string to
 * the matcher; what to do with the answer is the scan routine's business.
 */

#include "scan.h"

#include <string.h>

static struct kof_match_ctx *mc(const struct kof_obj_ctx *ctx)
{
	return &kof_scan_of(ctx)->m;
}

static uint8_t c_rd8(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint8_t v = 0;
	kof_rd_u8(mc(ctx)->data, off, &v);
	return v;
}

static uint16_t c_rd16(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint16_t v = 0;
	kof_rd_u16(mc(ctx)->data, off, 0, &v);
	return v;
}

static uint32_t c_rd32(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint32_t v = 0;
	kof_rd_u32(mc(ctx)->data, off, 0, &v);
	return v;
}

static uint64_t c_rd64(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint64_t v = 0;
	kof_rd_u64(mc(ctx)->data, off, 0, &v);
	return v;
}

static int c_memeq(const struct kof_obj_ctx *ctx, uint64_t off, const void *pat,
		   uint32_t len)
{
	kof_buf s = kof_slice(mc(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return memcmp(s.p, pat, len) == 0;
}

static uint32_t c_csum(const struct kof_obj_ctx *ctx, uint64_t off, uint32_t len)
{
	kof_buf s = kof_slice(mc(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return kof_crc32(s.p, s.n);
}

static void c_report(const struct kof_obj_ctx *ctx, uint32_t level,
		     uint32_t name_id)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	sc->rep_level   = level;
	sc->rep_name_id = name_id;
	sc->rep_valid   = 1;
}

/* ---- searching a declared string ------------------------------------------- */

/*
 * The module facing search: resolve the range it named, then let the matcher answer.
 *
 * Everything about *how* to answer is the matcher's - the presence set, the memo, the
 * word boundaries. What is left here is the only part that needs the object's parse:
 * turning a named range into extents.
 */
static int c_find_str(const struct kof_obj_ctx *ctx, uint32_t str_id,
		      uint32_t range_id)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_module *m = sc->cur_mod;
	const struct kof_str_ent *e;
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t n;

	if (!m || str_id >= m->n_str || range_id >= m->n_rng)
		return 0;
	e = &sc->eng->str_tab[m->str_base + str_id];
	n = kof_scan_resolve_range(ctx, sc->eng->rng_tab[m->rng_base + range_id], ext);

	return kof_match_lookup(&sc->m,
				m->memo_base + str_id * m->n_rng + range_id,
				ext, n, e->bytes, e->len, e->icase, e->fullword,
				&sc->st.gram_answers);
}

static const struct kof_content kof_mod_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_csum
};

/*
 * Present an object to a module.
 *
 * Every field a module can reach is set here, so what a module is allowed to see is one
 * function rather than an assignment list the scan routine has to keep right.
 */
void kof_mod_attach(struct kof_obj_ctx *ctx, struct kof_scanner *sc)
{
	ctx->content = &kof_mod_vtable;
	ctx->report  = c_report;
	ctx->priv    = sc;
}
