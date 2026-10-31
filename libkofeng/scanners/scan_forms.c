/*
 * scan_forms.c - the forms of a script, as objects.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objtree.h"


/*
 * THE FORMS OF A SCRIPT, AS OBJECTS - and deliberately NOT inside
 * the open stage (scan_unpack.c).
 *
 * It was in there, which looked tidy and was wrong three ways, and the third
 * one is why nothing ever came of it:
 *
 *   - the open stage returns at its first line when the database has no
 *     unpacker modules. kofviewer opened with no --db is exactly that engine,
 *     so the reader who asked to see the folded form of a shell got a tree
 *     with no child in it and no reason given. Folding needs a lexical table
 *     and a parse; it does not need a database, and nothing about it should
 *     have been behind one.
 *   - it returns again once a signature has NAMED the object, unless the
 *     caller asked for every match. That is the right economy for a scan and
 *     the wrong one for these: a named webshell is the case where seeing what
 *     it builds matters most.
 *   - and it is under kof_mod_unpack_mode, which is about what a MODULE may
 *     do to the object it was handed. No module is involved here.
 *
 * What it does keep is the deep-scan gate, because that is the one condition
 * that is genuinely shared: everything here produces a child, and deep off
 * means do not descend.
 *
 * ONE CHILD AND NOT ONE PER PASS. The level is what the passes cost, not what
 * they are for: the form pass runs wherever the heuristics run, and level 2 -
 * the rung that already means "do the expensive thing the cheap things cannot"
 * - adds the fold, which walks every assignment looking for a constant right
 * hand side. What comes out is one object either way, in the LAST form the
 * levels asked for. A tree that carried the intermediate as well made the
 * reader decide which node to take a marker from, and the answer was never the
 * intermediate.
 */
int sx_script_forms(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt, uint32_t pdepth)
{
	if (sc->obj.open.broken || ctx->format != KOF_FMT_SCRIPT)
		return 0;
	if (!kof_objtree_may_open(opt) || pdepth > EMU_MAX_PACKER_DEPTH)
		return 0;

	return kof_scan_script_forms(ctx, opt->heur_level >= 2) != 0;
}
