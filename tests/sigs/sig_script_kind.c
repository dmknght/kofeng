/*
 * sig_script_kind.c - the script subtype used as a precondition.
 *
 * Detects nothing anybody cares about. It exists so the whole path stays wired
 * up on every build: the sniff decides a text file is a script, the parse reads
 * the interpreter out of a shebang or a "<?php" tag, ksigbuilder turns the name
 * below into a mask, and the host declines to offer this module an object of
 * any other kind.
 *
 * THE POINT IS THE ONE NOT MATCHED. "eval(" appears in PHP and in Python and in
 * Perl; this module only ever sees the PHP ones, because a kind is a
 * precondition rather than a test inside kof_scan. A test that only checked the
 * positive case would pass with the subtype declaration deleted.
 */

#include <kofmod/kofsig.h>
#include <kofmod/script.h>

KOF_TARGET_FORMAT(KOF_FMT_SCRIPT);
KOF_TARGET_SUBTYPE(KOF_SCRIPT_PHP);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "ScriptKindTest");

KOF_TARGET_RANGE(body, KOF_SCAN_SCRIPT_BODY);

KOF_DEFINE_STR(ev, "eval(", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (kof_find_str(body, ev))
		KOF_SCAN_SUSPECT("PhpEval");
}
