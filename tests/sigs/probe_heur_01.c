/*
 * probe_heur_01.c - a heuristic rule that asks to run only at --heur 2.
 *
 * See probe_heur_00.c. The engine skips a module whose level is above the scan's:
 * a prefilter, so the rule is never entered at level 1. It fires on "KOFPRB04" at
 * offset 0.
 */

#include <kofmod/heur.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
KOF_HEUR_LEVEL(2);
KOF_HEUR_NAME("ProbeLvl2");

KOF_DEFINE_STR(magic, "KOFPRB04", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_HEUR
{
	if (kof_find_str_at(0u, magic))
		KOF_HEUR_HIT();
}
