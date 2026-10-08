/*
 * sig_repair_2strong - the SECOND detector to report, and the stronger. See
 * sig_repair_1weak.c for the question this pair asks.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_TARGET_NAME(KOF_MALTYPE_VIRUS, "RepairStrong");

KOF_DEFINE_STR(s0, "KOFREPSTRONG!", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (!kof_find_str_at(16u, s0))
		return;
	KOF_SCAN_CURABLE(16u);
	KOF_SCAN_INFECT(KOF_MALVAR_GENERIC);
}

void kof_cure(const struct kof_obj_ctx *ctx)
{
	static const uint8_t b[2] = { 0xB1, 0xB2 };

	kcure_patch(44u, b, 2u);
}
