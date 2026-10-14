/*
 * norm_view_script.c - a rule whose evidence is in a script only after the view.
 *
 * The strings exist in a shell script as base64 behind `base64 -d`, as hex, or as
 * percent escapes; the script's own view says them plainly (the form pass, then
 * the decode). One string folded out of variables is here too: a php script that
 * builds it from pieces, which only the fold at heuristic level 2 puts together.
 */

#include <kofmod/kofsig.h>
#include <kofmod/script.h>

KOF_TARGET_FORMAT(KOF_FMT_SCRIPT);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "NormViewScript");

KOF_TARGET_RANGE(body, KOF_SCAN_SCRIPT_BODY);

KOF_DEFINE_STR(from_b64, "NormScriptB64-a1f0c2", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(from_hex, "NormScriptHEX-77d5e8", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(from_pct, "NormScriptPCT-04b9aa", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(from_fold, "NormScriptFOLD-9e61d3-built-from-pieces", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (kof_find_str_multi(body, from_b64, from_hex, from_pct, from_fold) >= 1)
		KOF_SCAN_INFECT("NormViewScript");
}
