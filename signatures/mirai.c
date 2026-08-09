#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET(KOF_FMT_ELF); // File format elf. Prefilter will use this
KOF_DEFINE_RANGE(scan_range_data, KOF_SCAN_ELF_DATA); // define variable scan_ragne as elf_code and elf_data (structure from elf file). This will limit scan range

/* The markers. Case and word handling belong to the literal; where to look does not,
 * so it is named at each use. */
KOF_DEFINE_STR(common_botnet_1, "WHO %s", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(common_botnet_2, "PONG %s", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(common_botnet_3, "NICK %s", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(common_botnet_4, "JOIN %s", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(mirai_1,  "4r3s b0tn3t",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(mirai_2,  "31mip:%s",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(mirai_3,  "oanacroane",  KOF_CASE_EXACT, KOF_WORD_FULLWORD);


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
	int threshold_mirai_str = kof_find_str(ctx, mirai_1, scan_range_data) + kof_find_str(ctx, mirai_2, scan_range_data) + kof_find_str(ctx, mirai_3, scan_range_data);
	if (threshold_mirai_str> 0) {
		KOF_MATCH(ctx, "Mirai.Generic", KOF_LVL_INFECT);
	} // else
	int threshold_common_str = kof_find_str(ctx, common_botnet_1, scan_range_data) + kof_find_str(ctx, common_botnet_2, scan_range_data) + kof_find_str(ctx, common_botnet_3, scan_range_data) + kof_find_str(ctx, common_botnet_4, scan_range_data);
	if (threshold_common_str > 0) {
		KOF_MATCH(ctx, "Botnet.IRCCom", KOF_LVL_SUSPECT);
	}
}
