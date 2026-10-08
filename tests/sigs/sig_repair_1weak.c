/*
 * sig_repair_1weak - the FIRST detector to report on an object, and the weaker.
 *
 * Two fixtures exist for one question: when two detectors report on the same
 * object, whose finding is the object's verdict, whose repair goes out, and does
 * the first one to speak hide the second? This one sorts first in the database
 * and says only SUSPECTED; sig_repair_2strong.c sorts after it and says INFECTED.
 * tests/unit/scan_logic.c builds an object carrying both markers.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_TARGET_NAME(KOF_MALTYPE_VIRUS, "RepairWeak");

KOF_DEFINE_STR(s0, "KOFREPWEAK!", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (!kof_find_str_at(0u, s0))
		return;
	KOF_SCAN_CURABLE(0u);
	KOF_SCAN_SUSPECT(KOF_MALVAR_GENERIC);
}

void kof_cure(const struct kof_obj_ctx *ctx)
{
	static const uint8_t b[2] = { 0xA1, 0xA2 };

	kcure_patch(40u, b, 2u);
}
