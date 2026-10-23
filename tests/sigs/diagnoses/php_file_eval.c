#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_file_eval.c - a script's value of one kind reached a call of another: what a file or a url held was run.
 */

KOF_DIAG_NAME(php_file_eval);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/file-eval");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_FILE_OPEN, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EVAL);
