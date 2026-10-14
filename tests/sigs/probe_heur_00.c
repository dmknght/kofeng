/*
 * probe_heur_00.c - a heuristic rule that fires on demand, to exercise the
 * heuristic half of the module ABI: the declarations (KOF_HEUR_PHASE,
 * KOF_HEUR_NAME, KOF_HEUR_PREDICT), the entry point (KOF_DEFINE_HEUR) and the two
 * ways it ends (KOF_HEUR_HIT, KOF_HEUR_ACT).
 *
 * It fires on the eight bytes "KOFPRB03" at offset 0; the byte at offset 8 picks
 * what it says: 1 is a hit, 2 is an act, anything else is silence. The sibling
 * probe_heur_01.c declares a level above the default and fires on its own magic,
 * so a test can show that a rule is not entered at a level below the one it asked
 * for.
 */

#include <kofmod/heur.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
KOF_HEUR_NAME("ProbeHeur");
KOF_HEUR_PREDICT("ProbeFam");

KOF_DEFINE_STR(magic, "KOFPRB03", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_HEUR
{
	if (!kof_find_str_at(0u, magic))
		return;
	if (kof_u8(8) == 1)
		KOF_HEUR_HIT();
	if (kof_u8(8) == 2)
		KOF_HEUR_ACT();
}
