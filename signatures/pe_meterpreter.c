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

KOF_DEFINE_SCAN
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
	
	if (kof_find_str_all(pe_range_data, str_data_1, str_data_2)) {
		if (kof_find_str_all(pe_range_code, str_code_1, str_code_2))
		{
			KOF_MATCH("Meter.Generic", KOF_LVL_INFECT);
		} else {
			KOF_MATCH("Meter.Generic", KOF_LVL_SUSPECT);
		}
	}
}
