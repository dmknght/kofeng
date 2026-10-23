#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_decode_load.c
 *
 * A script decoded something it does not hold the text of and used the result as the name of what it loads:
 * `$c = base64_decode($blob); new $c`, `unserialize(base64_decode($d))` - the usual shape of a serialized payload that is kept encoded.
 * Expected on packed object-injection payloads and class loaders that hide the class they instantiate.
 */

KOF_DIAG_NAME(php_decode_load);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/decode-load");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_DECODE, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_DYNLOAD);
