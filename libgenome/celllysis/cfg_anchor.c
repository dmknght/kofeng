/*
 * cfg_anchor.c - is a function worth hashing. The default is ONE reachable block (KGENOME_CFG_ANCHOR_MIN): the floor of 12 that stood
 * here is gone (owner, 2026-11-01), so a function with a reachable block is hashed and one with none is not. A caller may still ask for
 * a higher `min_blk` or the optional extensions below. The anchor must itself survive a rebuild, which a block COUNT does and a name does not.
 *
 * `min_blk` counts REACHABLE blocks. The optional extensions (a syscall, a diagnose site, a list of callee identities the
 * function must all call: the caller's own, 0 never matches) are other facts a caller may OR in; the first two measured the same
 * as the block count and all are off by default.
 *
 * IMPROVE anchor-floor-1 (owner, 2026-11-03; measured by an agent, not re-run; NOT a wrong gene): a floor of ONE block lets a
 * function of 1 to 3 blocks be signed, and its sketch has 1 to 3 keys, which carry no content of the behaviour. Survey on MalwareLab
 * (3248 ELF, 2,042,512 units, before the S1 fix): the 1-block `main` of two 199-byte reverse shells matched 2651 files at pct 100
 * (82% of the corpus; frame_dummy, cpuid, getRandomIP...). So a block rule built from such a function matches by SHAPE and not by
 * behaviour: a false match that comes from the floor and the data, not from choosing the wrong function as the gene. Same limit for
 * 1-3 block wrappers (direct syscall). Not a defect of the overlap (the port matched the engine 20/20 pairs).
 * Next algorithms, none built: raise the floor per use (the caller's `min_blk` already exists); require the callee identities
 * (KGENOME_CFG_ANCHOR_CALLEES, `ckey`) so a small function is signed with what it calls; leave the content to lineage.
 * Decide with a measurement of the share of units a given floor drops against what it covers.
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
