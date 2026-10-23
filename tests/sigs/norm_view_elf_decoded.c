/*
 * norm_view_elf_decoded.c - a rule whose evidence is NOT in the file.
 *
 * Five strings, each present in an ELF only in a form this rule cannot read:
 * base64 behind `base64 -d`, a run of hex digits, a percent-encoded form body,
 * UTF-16LE, and a base64 run of exactly sixteen characters (twelve bytes, four
 * zeros left behind - too few to collapse, so the view is a 1:1 rewrite).
 * The normalised view says them plainly, so the rule can fire on the view and
 * never on the parent. tests/unit/normalizer_engine.c builds objects
 * that carry one of them at a time and asks which object the finding is on.
 *
 * The range is everything outside code - the bytes the view rewrites. It names
 * regions, so the view has to have carried the region table through the collapse
 * for this to find anything.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "NormViewDecoded");

KOF_TARGET_RANGE(plain, KOF_SCAN_ELF_UNCLAIMED | KOF_SCAN_ELF_NOLOAD | KOF_SCAN_ELF_DATA);

KOF_DEFINE_STR(from_b64, "NormCanaryB64-7f3a91", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(from_hex, "NormCanaryHEX-5e2b44", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(from_pct, "NormCanaryPCT-c9d012", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(from_wide, "NormCanaryWIDE-12ab9", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(from_tiny, "NormTiny-9ab", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (kof_find_str_multi(plain, from_b64, from_hex, from_pct, from_wide, from_tiny) >= 1)
		{ kof_debug("NormViewDecoded#NormViewDecoded", 0); return; }
}
