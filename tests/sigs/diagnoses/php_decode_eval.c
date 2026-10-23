#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_decode_eval.c
 *
 * A script decoded something and ran what it made - eval(base64_decode(...)) and every spelling that reaches the same two
 * facts: a nested call, a variable that carries the decode's result into the eval, a function name kept in a literal.
 *
 * It names capabilities and not functions (data-decode, data-eval), which is the whole of the TEXT route: the table of PHP
 * names decides which functions are those, and a new spelling of either is a row there and not a new rule. It declares no
 * order and no distance, as no diagnose does.
 */

KOF_DIAG_NAME(php_decode_eval);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/decode-eval");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_DECODE, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EVAL);
