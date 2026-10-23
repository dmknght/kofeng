#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_built_create.c
 *
 * A function was made from text through a name the script BUILT - `$l = str_replace('k','','ckrekatek_fuknkkction'); $l('', $code)` -
 * so no marker of create_function is written anywhere. KOF_FLOWF_BUILT is the fact that the name was made. Expected on hoho.php and its
 * kin; the claim is the name, not the text: what the created function does is read from the text it was given, one layer down.
 */

KOF_DIAG_NAME(php_built_create);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/built-create");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_CREATE, KOF_FLOWF_BUILT);
