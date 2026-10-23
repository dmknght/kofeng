#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_built_call.c
 *
 * A call whose callee is a name the script BUILT: `$f = 'sys' . 'tem'; call_user_func($f, ...)`, `$n = strrev('metsys')`, an element of
 * $GLOBALS. The callee is not written where it is called, and it is not written anywhere. Expected on shells that hide the function
 * they call behind string operations.
 */

KOF_DIAG_NAME(php_built_call);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/built-call");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_DYNCALL, KOF_FLOWF_BUILT);
