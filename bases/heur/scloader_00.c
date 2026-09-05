/*
 * scloader_00.c - a program that is mostly data, carrying one blob that is not.
 *
 * The SHAPE is the finding: a small executable whose code is a fraction of its
 * data, with one global whose contents are neither text nor a table. That is
 * what a shellcode loader looks like from the outside, and it is a heuristic
 * rather than a verdict because a legitimate program can look like it.
 *
 * The SEARCH is not here any more, and that is the point of this file being
 * short. It lives in bases/unp/scfind.h, because bases/unp/scpayload_00.c needs
 * the same answer for a different purpose: this file SCORES the loader, that one
 * PRODUCES the payload as an object so every signature gets a chance at it. Two
 * searches would be two chances to disagree about where the payload is.
 *
 * What stays here is what a heuristic owns: that the shape is worth reporting,
 * and the facts a reader needs to act on it.
 */
#include <kofmod/kofsig.h>
#include "../unp/scfind.h"

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/* EXAMINE: everything read here is a field of the parse or of the symbol block
 * the engine builds from it, and both are finished by then. */
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
/*
 * LEVEL 2, so a default scan does not pay for this.
 *
 * Everything above it in this rule is arithmetic over tables the parse has
 * already built, but the walk itself needs the SYMBOL BLOCK, and building that
 * means reading the symbol table and its string table - the one piece of real
 * work here. The gates in front keep it to 1.80% of objects, which is cheap
 * but not free, and it buys evidence that is a heuristic rather than a verdict.
 * A caller who wants that asks for it with --heur 2.
 */
KOF_HEUR_LEVEL(2);
KOF_HEUR_NAME("SCLoader");

KOF_DEFINE_HEUR
{
	struct scf_hit h;

	/* No buffer: this only says WHERE, so there is nothing to decode into.
	 * The unpacker next door is what needs the bytes themselves. */
	if (!scf_find(ctx, &h, 0, 0))
		return;
	/*
	 * WHERE, before THAT there is one.
	 *
	 * The finding says a payload was found; these say where, and a reader
	 * looking at the file needs the second to act on the first. Reported as
	 * the symbol's own value rather than a file offset into a block the
	 * engine built: anything that re-groups those records - kofviewer splits
	 * them into imports and exports - renumbers them, while the value is the
	 * symbol's own and survives.
	 *
	 * Size goes with it because "a payload at 0x4060" and "949 bytes at
	 * 0x4060" are different amounts of help. Width only when the payload
	 * said so; a zero here would be this file inventing one.
	 *
	 * Before KOF_HEUR_HIT because that macro returns.
	 */
	kof_debug("SCLoader.payload", h.va);
	kof_debug("SCLoader.length", h.len);
	if (h.bits)
		kof_debug("SCLoader.bits", h.bits);
	KOF_HEUR_HIT();
}
