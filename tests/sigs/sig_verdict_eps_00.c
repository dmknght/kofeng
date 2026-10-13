/*
 * sig_verdict_eps_00.c - a fixture: a detector whose only job is to put the
 * disease verdict/eps on an object that carries its marker, so that
 * tests/unit/verdict_branches.c can build an object with ANY SET of diseases and
 * read what the syndrome layer makes of it. See tests/sigs/syndromes/vd_*.c for
 * the verified samples it is read against.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_ANY);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "VerdictEps");
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "verdict/eps");

KOF_TARGET_RANGE(everything, KOF_SCAN_ALL);
KOF_DEFINE_STR(marker, "VERDICT_FIXTURE_EPS", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (kof_find_str(everything, marker))
		KOF_SCAN_INFECT("VerdictEps");
}
