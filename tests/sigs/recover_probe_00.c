/*
 * recover_probe_00.c - a recovering module that only says it was asked.
 *
 * The real one reports the APIs a PE resolves for itself. This one has a sign
 * a test can place anywhere - four bytes of "RCVR" at offset 4 - and answers
 * with a note, so the test can count how often and on which objects the step
 * ran. What it stands in for is the contract: the step runs on EVERY object that
 * carries its sign, whether or not an opening step produced a child from it and
 * whether or not a rule had already named it.
 */

#include <kofmod/kofsig.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_RECOVER);
KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_TARGET_CONTENT("Probe");

KOF_DEFINE_STR(magic, "RCVR", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_UNPACK
{
	if (kof_find_str_at(4u, magic))
		kof_debug("Probe.ran", 1);
}
