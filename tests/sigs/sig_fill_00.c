/*
 * sig_fill_00.c - a fixture: one of sixteen detectors, in three groups (A: 0-6,
 * B: 7-13, C: 14-15) that fire on a marker each, so that a test can put 7, 14 or
 * 16 findings on an object and fill its finding array (KOF_MAX_FINDINGS, 16).
 * See tests/unit/verdict_branches.c.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_ANY);
KOF_TARGET_NAME(KOF_MALTYPE_ADWARE, "FindingsFill00");

KOF_TARGET_RANGE(everything, KOF_SCAN_ALL);
KOF_DEFINE_STR(marker, "FINDINGS_FILL_A", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (kof_find_str(everything, marker))
		KOF_SCAN_INFECT("FindingsFill00");
}
