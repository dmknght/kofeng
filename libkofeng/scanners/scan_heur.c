/*
 * scan_heur.c - the one model score over the whole object, and the forms of a script.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objtree.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofdebug.h"
#include "../kofcore/kofmod/elf.h"
#include <stdio.h>
#include <string.h>


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

/*
 * WHAT THE HEURISTIC IS ALLOWED TO SEE, AND WHY IT IS GATHERED HERE.
 *
 * Everything below already exists by the time this runs: the anomaly word came
 * out of the parse, the depth came down the walk, and whether an unpacker gave up
 * is the value sx_open_end just returned. Nothing is searched for and no pass is
 * made over the object, which is why this runs unless the caller switched it off
 * rather than only when the caller asked for it.
 *
 * Marker-derived evidence is deliberately absent. Knowing that a family has two
 * markers present but did not fire means asking about markers whose module's
 * logic never reached them, which is a pass over the object that would
 * otherwise not happen - so it is not free, and nothing here gathers it. There
 * was a --heur level for asking; it gathered nothing and changed no verdict, so
 * it is gone. If that evidence is ever collected it needs its own switch again,
 * and the switch should arrive with the collector rather than before it.
 */
void sx_heur_object(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt, uint32_t pdepth,
			uint32_t partial, struct kof_result *out)
{
	const struct kof_heur_model *m = kof_heur_default();
	struct kof_heur_facts f;
	int32_t score = 0;

	if (opt->heur_off)
		return;

	/*
	 * AN ELF THE MODEL WAS MEASURED ON, WHICH IS AN EXECUTABLE OR A SHARED
	 * OBJECT AND NOT A RELOCATABLE ONE.
	 *
	 * Every weight in kofheur.c came from a population of 6523 malware and
	 * 13638 clean ELF objects, and that population is programs. An ET_REL is
	 * a different shape: no program headers, no entry point, sections that
	 * the module loader relocates rather than maps. Asking the table about
	 * one is asking it a question it was never measured against, and the
	 * answer it gives is the one a machine sees most - every .ko under
	 * /lib/modules came back "ELF-x64/Heur:Truncated".
	 *
	 * The bar is what makes that serious. 747 centinats was chosen because
	 * no clean object in the measured corpus reached it; a population that
	 * was not in the corpus has no such guarantee, and a false positive on
	 * kernel modules is a false positive on the largest single group of ELF
	 * files most Linux hosts have.
	 *
	 * ONLY THE SCORE STOPS. The parse still records every anomaly and an
	 * examiner still prints them - what is withheld is a VERDICT from a
	 * model that has no evidence about this kind of object.
	 */
	if (ctx->format == KOF_FMT_ELF) {
		const struct kgenome_elf_info *ei = kof_elf(ctx);

		if (!ei || (ei->e_type != KGENOME_ELF_EXEC &&
			    ei->e_type != KGENOME_ELF_DYN))
			return;
	}

	memset(&f, 0, sizeof f);
	f.format       = ctx->format;
	/*
	 * PACKER layers, not tree depth.
	 *
	 * A file three directories down inside a tar is not three layers of
	 * packing, it is a directory tree - and depth counted every child the
	 * same way, so an ordinary archive of archives scored like something
	 * that had been wrapped to be hidden. Only a module that declared itself
	 * an UNPACK or DECRYPT step adds a layer now.
	 */
	f.anomalies    = kof_heur_anomalies(ctx);
	/*
	 * The object that WAS packed, not the one that came out.
	 *
	 * See kof_scanner.obj.open.packed_here. Both are true of a packed sample and they
	 * are different objects: this marks the file on disk, and packer_depth
	 * above marks what was inside it.
	 */
	if (sc->obj.open.packed_here)
		f.flags |= KOF_HEUR_FL(KOF_HEUR_F_PACKED);
	if (partial)
		f.flags |= KOF_HEUR_FL(KOF_HEUR_F_UNPACK_PARTIAL);
	if (!kof_heur_score(m, &f, &score, NULL))
		return;                 /* no model for this format - say nothing */

	/*
	 * Published for every object, whatever the bar: an examiner wants the score
	 * precisely so it can show how far short of the bar something came. Nothing
	 * here names the object - the model measures, it does not conclude.
	 */
	out->heur_scored    = 1;
	out->heur_score     = score;
	out->heur_flags     = f.flags;
	out->heur_anomalies = f.anomalies;
	out->heur_depth     = pdepth > 255u ? 255u : (uint8_t)pdepth;
	/* And whether the emulator produced anything from this object, which is
	 * the thing a caller offering "run it" has to know before offering it
	 * again. See kof_result.emu_unpacked. */
	out->emu_unpacked   = sc->obj.emu.produced;
}
