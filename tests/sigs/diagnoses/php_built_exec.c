#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_built_exec.c - a call the script made through a name it BUILT: the name is a join, a str_replace over a
 * scrambled one, a reversal, a chr() chain or an element of the $GLOBALS array, not a word written where it is used, so no marker
 * of the function finds it. The capability is the call's (exec), and KOF_FLOWF_BUILT is the fact that its name was made.
 */

KOF_DIAG_NAME(php_built_exec);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/built-exec");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_EXEC_IMAGE, KOF_FLOWF_BUILT);
