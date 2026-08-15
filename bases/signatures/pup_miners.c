#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF); // File format elf. Prefilter will use this
KOF_TARGET_RANGE(scan_range_data, KOF_SCAN_ELF_DATA); // define variable scan_ragne as elf_code and elf_data (structure from elf file). This will limit scan range

/* The markers. Case and word handling belong to the literal; where to look does not,
 * so it is named at each use. */
KOF_DEFINE_STR(str_1, "Started Mining", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_2, "Miner will restart", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_3, "Miner not responding", KOF_CASE_EXACT, KOF_WORD_FULLWORD);

KOF_DEFINE_STR(str_4, "stratum+ssl://", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_5, "stratum+tcp://", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_6, "daemon+https://", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_7, "daemon+http://", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_8, "xmr-stak", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_9, "xmrig.com", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_10, "xmrigMiner", KOF_CASE_EXACT, KOF_WORD_FULLWORD);


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
	if (kof_find_str_any(scan_range_data, str_1, str_2, str_3))
		KOF_SCAN_MATCH("Miner.Generic", KOF_LVL_SUSPECT);
    if (kof_find_str_any(scan_range_data, str_4, str_5, str_6, str_7))
        KOF_SCAN_MATCH("Miner.Generic", KOF_LVL_INFECT);
    if (kof_find_str_any(scan_range_data, str_8))
        KOF_SCAN_MATCH("Miner.XMRStak", KOF_LVL_INFECT);
    if (kof_find_str_any(scan_range_data, str_9, str_10))
        KOF_SCAN_MATCH("Miner.Xmrig", KOF_LVL_INFECT);
}
