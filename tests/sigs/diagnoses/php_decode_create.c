#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_decode_create.c
 *
 * A script decoded something and made a function out of it: `create_function('', base64_decode(...))`, and the two-step form where the
 * handle is kept and called later (see php_create_call.c). The packed-script shape of hoho.php, which decodes nothing at all but
 * builds its text with str_replace (php_built_create.c). Expected on packed scripts that avoid eval.
 */

KOF_DIAG_NAME(php_decode_create);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/decode-create");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_DECODE, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_CREATE);
