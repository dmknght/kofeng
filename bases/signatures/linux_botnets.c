#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF); // File format elf. Prefilter will use this
KOF_TARGET_RANGE(scan_range_data, KOF_SCAN_ELF_DATA); // define variable scan_ragne as elf_code and elf_data (structure from elf file). This will limit scan range

/* The markers. Case and word handling belong to the literal; where to look does not,
 * so it is named at each use. */
KOF_DEFINE_STR(str_1, "Flooding %s", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_2, "ACKFLOOD %s", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_3, "RANDOMFLOOD %s", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_4, "HTTPLOOD %s", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_5, "Sending attack", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_6, "Starting flood", KOF_CASE_EXACT, KOF_WORD_FULLWORD);


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
	if (kof_find_str_any(scan_range_data, str_1, str_2, str_3, str_4, str_5, str_6))
		KOF_SCAN_MATCH("Botnet.Generic", KOF_LVL_SUSPECT);
}
