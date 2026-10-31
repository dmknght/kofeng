/*
 * cfg_anchor.c - is a function worth hashing. The default is ONE reachable block (KGENOME_CFG_ANCHOR_MIN): the floor of 12 that stood
 * here is gone (owner, 2026-11-01), so a function with a reachable block is hashed and one with none is not. A caller may still ask for
 * a higher `min_blk` or the optional extensions below. The anchor must itself survive a rebuild, which a block COUNT does and a name does not.
 *
 * `min_blk` counts REACHABLE blocks. The optional extensions (a syscall, a diagnose site, a list of callee identities the
 * function must all call: the caller's own, 0 never matches) are other facts a caller may OR in; the first two measured the same
 * as the block count and all are off by default.
 */
#include "cfg.h"

int kgenome_cfg_anchor(const struct kgenome_cfg *g, const struct kgenome_cfg_anchor_req *r)
{
	const uint32_t min = r && r->min_blk ? r->min_blk : KGENOME_CFG_ANCHOR_MIN;
	const uint32_t fl = r ? r->or_flags : 0u;

	if (!g)
		return 0;
	if (g->n_blk >= min)
		return 1;
	if ((fl & KGENOME_CFG_ANCHOR_SYS) && g->n_sys)
		return 1;
	if ((fl & KGENOME_CFG_ANCHOR_SITE) && g->n_site)
		return 1;
	if ((fl & KGENOME_CFG_ANCHOR_CALLEES) && r->n_need && r->need) {
		uint32_t i, j;

		for (i = 0; i < r->n_need; i++) {
			for (j = 0; j < g->n_call && !(r->need[i] && g->call[j].id == r->need[i]); j++)
				;
			if (j == g->n_call)
				return 0;
		}
		return 1;
	}
	return 0;
}
