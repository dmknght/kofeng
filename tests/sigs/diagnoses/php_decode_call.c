#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_decode_call.c
 *
 * A script decoded something it does not hold the text of and used the result as the NAME of the function it calls:
 * `$f = base64_decode($blob); $f($cmd)`, `call_user_func(str_rot13($blob), $x)`. The function is not written anywhere a marker finds
 * it. A decode of a CONSTANT is a name the evaluator reads and is php_built_exec.c / php_built_call.c's, not this. Expected on the shells
 * that keep their callee encoded in a value the script gets elsewhere; not on a decode whose result is data for a callee that is written.
 */

KOF_DIAG_NAME(php_decode_call);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/decode-call");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_DECODE, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_DYNCALL);
