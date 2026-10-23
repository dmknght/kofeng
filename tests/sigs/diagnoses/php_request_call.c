#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_request_call.c
 *
 * The sender of the request chose WHICH FUNCTION RUNS: `$_POST[0]($_POST[1])`, `call_user_func($_GET['f'])`, `$f = $_REQUEST['f']; $f($x)`.
 * The request is the callee (the call's first argument, its TARGET role); a request value passed as an argument to a callee the program
 * wrote is data for it and is not this. Expected on: the one-line backdoors that take the function from the request, and the shells
 * that hide a fixed `system` behind it. NOT expected on a plugin registry looked up by a request key (an index selects an entry,
 * it is not the entry): tests/lib/genome/diag_text.c pins those as no link.
 */

KOF_DIAG_NAME(php_request_call);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/request-call");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_REQUEST, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_DYNCALL);
