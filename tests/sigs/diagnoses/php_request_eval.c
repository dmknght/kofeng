#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_request_eval.c
 *
 * What the sender of the request chose was run, now, as code: $_GET, $_POST, $_REQUEST, $_COOKIE or $_FILES reached the text an eval
 * or an assert takes. The anchor is the request value, which a page reads a few times and an eval is rarer still. A request that
 * names the FUNCTION to call is another act with another word (php_request_call.c), and one that builds a function out of text is
 * a third (php_request_create.c).
 */

KOF_DIAG_NAME(php_request_eval);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/request-eval");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_REQUEST, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EVAL);
