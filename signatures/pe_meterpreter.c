#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

KOF_TARGET(KOF_FMT_PE); // File format elf. Prefilter will use this
KOF_DEFINE_RANGE(pe_range_data, KOF_SCAN_PE_DATA);
KOF_DEFINE_RANGE(pe_range_code, KOF_SCAN_PE_CODE);

/* The markers. Case and word handling belong to the literal; where to look does not,
 * so it is named at each use. */
KOF_DEFINE_STR(str_data_1, "zzzdbg", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_data_2, "PAYLOAD:", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_code_1, "AXAX^YZAXAYAZH", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_code_2, "VirtualProtect", KOF_CASE_EXACT, KOF_WORD_FULLWORD);

void kof_scan(const struct kof_obj_ctx *ctx)
{
	/*
	 * Two markers, and the second is what makes the first worth acting on. The
	 * busybox path alone appears in a great deal of legitimate embedded
	 * software, so on its own it is a family of false positives rather than a
	 * detection.
	 *
	 * Neither call holds pattern bytes: the host owns the literals and answers
	 * these, so both markers can be looked for in one pass over the object -
	 * together with every other module's markers.
	 */
	if (kof_find_str(ctx, str_data_1, pe_range_data) && kof_find_str(ctx, str_data_2, pe_range_data)) {
		if (kof_find_str(ctx, str_code_1, pe_range_code) && kof_find_str(ctx, str_code_2, pe_range_code))
		{
			KOF_MATCH(ctx, "Meter.Generic", KOF_LVL_INFECT);
		} else {
			KOF_MATCH(ctx, "Meter.Generic", KOF_LVL_SUSPECT);
		}
	}
}
