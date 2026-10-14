/*
 * norm_view_elf_data.c - two markers in the DATA region of an ELF, and nothing
 * else about them.
 *
 * They sit in a segment with zero runs before, inside and after them, so the
 * view's collapse moves them. The rule fires on the view only if the DATA region
 * the view declares is where the markers went - a region carried through the
 * collapse wrongly (too short, shifted, dropped) loses it. On the parent it fires
 * anyway, which is what makes "the view agrees with the parent" a question with
 * an answer.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "NormViewData");

KOF_TARGET_RANGE(data, KOF_SCAN_ELF_DATA);

KOF_DEFINE_STR(mark1, "NormDataMarkOne-91c4", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(mark2, "NormDataMarkTwo-3d78", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (kof_find_str_multi(data, mark1, mark2) >= 2)
		KOF_SCAN_INFECT("NormViewData");
}
