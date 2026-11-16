/*
 * cfg_anchor.c - is a function worth hashing. The default is KGENOME_CFG_ANCHOR_MIN reachable blocks (5, see cfg.h): a function
 * with fewer is hashed into a sketch that the engine computes but refuses to sign (KOF_CFGSIGN_BELOW_FLOOR), because a sketch of
 * 1-4 keys matches by SHAPE alone and not by behaviour (anchor-floor-1, cfg.h, measured). A caller may still ask for a higher
 * `min_blk` or the optional extensions below. The anchor must itself survive a rebuild, which a block COUNT does and a name does not.
 *
 * `min_blk` counts REACHABLE blocks. The optional extensions (a syscall, a diagnose site, a list of callee identities the
 * function must all call: the caller's own, 0 never matches) are other facts a caller may OR in; the first two measured the same
 * as the block count and all are off by default.
 *
 * ANCHOR-FLOOR-1 RESOLVED (owner, 2026-11-03 measured the problem at floor 1, not re-run; owner, 2026-11-07 raised the floor to
 * 5, measured on the current tree - see cfg.h's KGENOME_CFG_ANCHOR_MIN comment for the numbers and why the callee-identity
 * extension (KGENOME_CFG_ANCHOR_CALLEES, `ckey`) was measured and NOT adopted as the rescue: every call sampled inside the worst
 * collision group was a local, unresolved call (no import), and the engine has no identity source for a local call today. The
 * mechanism itself (KGENOME_CFG_ANCHOR_CALLEES below) is unchanged and still available to a caller that DOES have identities to
 * require (a diagnose that names specific APIs); it was not generalised into the default anchor decision.
 *
 * IMPROVE mutation-floor-edit-stability-1 (owner, 2026-11-06; NOTE ONLY, nothing built): the same
 * question as above in a different shape - today a function is either signed (any n_blk >= min,
 * one state, full confidence) or refused (nosig), with nothing in between. A function right at the
 * floor is as fragile to one changed branch as a window block right at KGENOME_MUTATION_MIN_HASH is
 * to one changed byte (mutation_window.h, same note id): both floors answer "is there enough data
 * to exist at all", neither answers "is there enough to survive the smallest real edit". See
 * mutation_window.h for the windows-side half of this and the measurement it still needs.
 */
#include "cfg.h"

/*
 * DISABLED by the owner 2026-11-15: CFG and its hash are not used by the scan or the viewer; kept for re-enable.
 * To re-enable: take this #if 0 out, the declarations in cfg.h ("the anchor") and its caller kof_cfgsign_function (analyzers/cfgsign.c).
 * The code below is inside #if 0 (it holds comments, and C block comments do not nest).
 */
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
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
#endif /* DISABLED by the owner 2026-11-15 (CFG) */
