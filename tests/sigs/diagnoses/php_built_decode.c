#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_built_decode.c
 *
 * STATES: a decoder was called through a name the script BUILT (a join, a str_replace over a scrambled name, a reversal, chr), so no marker of the decoder finds it.
 * EXPECTED TO FIRE ON: MEASURED on the 76 shells of the corpus kept in /mnt/games/normtest/s3/php (numbered 001-111): 5 of them - alfa-shell-v4.1-tesla, alfa, alfateslav4, alfav4.1-tesla, alfav4.
 * MUST NOT FIRE ON: ordinary php applications - MEASURED: 0 of 1,073 php files of WordPress 6.8 and 0 of 13,392 mixed php files fire it (the synthetic texts it must
 * and must not match are in tests/unit/diag_text_golden.c).
 *
 * It names capabilities and not functions (the table of PHP names decides which function is which), a head and no tail, and no order.
 */

KOF_DIAG_NAME(php_built_decode);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/built-decode");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_DECODE, KOF_FLOWF_BUILT);
