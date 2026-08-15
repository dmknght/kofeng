#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF); // File format elf. Prefilter will use this
KOF_TARGET_RANGE(scan_range_data, KOF_SCAN_ELF_DATA); // define variable scan_ragne as elf_code and elf_data (structure from elf file). This will limit scan range

/* The markers. Case and word handling belong to the literal; where to look does not,
 * so it is named at each use. */
KOF_DEFINE_STR(mirai_1,  "4r3s b0tn3t",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(mirai_2,  "31mip:%s",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(mirai_3,  "oanacroane",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(mirai_4,  "oanacroane",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(mirai_5,  "Tsunami successfully deployed!",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(mirai_6,  ".tsunami -l .t -g",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);

void kof_scan(const struct kof_obj_ctx *ctx)
{
	/*
	 * A threshold, written as one. Each call answers how many of the listed
	 * strings are present - distinct strings, not occurrences, so a file that
	 * repeats one marker forty times still counts one.
	 *
	 * None of the calls holds pattern bytes: the host owns the literals and
	 * answers these, so every marker here is looked for in one pass over the
	 * object, together with every other module's.
	 */
	if (kof_find_str_any(scan_range_data, mirai_1, mirai_2, mirai_3))
		KOF_SCAN_MATCH("Mirai.Generic", KOF_LVL_INFECT);
	if (kof_find_str_any(scan_range_data, mirai_4))
		KOF_SCAN_MATCH("Mirai.Variant-4c36", KOF_LVL_INFECT);
	if (kof_find_str_all(scan_range_data, mirai_5, mirai_6))
		KOF_SCAN_MATCH("Mirai.Variant-de1b", KOF_LVL_INFECT);
}
