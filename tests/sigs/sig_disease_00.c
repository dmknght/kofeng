/*
 * sig_disease_00.c - a fixture: a detector that says what its match FINDS.
 *
 * Any format and a plain byte search, so a unit test can hand the engine a
 * buffer and know which module reports. The disease is what a syndrome (see
 * tests/sigs/syndromes) is read against; this is the first kind of detector
 * besides a diagnose to declare one.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_ANY);
KOF_TARGET_NAME(KOF_MALTYPE_BOTNET, "DiseaseTest");
KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, "flood-network/udp");

KOF_TARGET_RANGE(everything, KOF_SCAN_ALL);
KOF_DEFINE_STR(marker, "DISEASE_FIXTURE_MARKER", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (ctx->obj_size < 64)
		return;

	if (kof_find_str(everything, marker))
		KOF_SCAN_INFECT("DiseaseTest");
}
