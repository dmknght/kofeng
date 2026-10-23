#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_create_call.c
 *
 * A function was created from text and then CALLED THROUGH ITS HANDLE: `$s = create_function('', $code); $s();`. The handle is what
 * create_function returned, so the callee of the second call is the first call's result - the two-step form of eval, and the way hoho.php
 * runs the payload it assembled. Expected on every script that keeps the created function in a variable and calls it.
 */

KOF_DIAG_NAME(php_create_call);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/create-call");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_CREATE, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_DYNCALL);
