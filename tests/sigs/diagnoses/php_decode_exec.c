#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_decode_exec.c - a script's value of one kind reached a call of another: what a decode made became a command.
 */

KOF_DIAG_NAME(php_decode_exec);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/decode-exec");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_DECODE, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_IMAGE);
