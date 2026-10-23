#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_fetch_write.c
 *
 * STATES: what an http request returned was written to a file: a downloader, a remote file fetcher.
 * EXPECTED TO FIRE ON: MEASURED on the 76 shells of the corpus kept in /mnt/games/normtest/s3/php (numbered 001-111): 3 of them - indrajith, indrajith.v.2, indrajith2.2.
 * MUST NOT FIRE ON: ordinary php applications - MEASURED: 0 of 1,073 php files of WordPress 6.8 and 0 of 13,392 mixed php files fire it (the synthetic texts it must
 * and must not match are in tests/unit/diag_text_golden.c).
 *
 * It names capabilities and not functions (the table of PHP names decides which function is which), a head and one tail, and no order.
 */

KOF_DIAG_NAME(php_fetch_write);
KOF_DECLARE_DISEASE(KOF_MALTYPE_DROPPER, "script/fetch-write");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_HTTP_FETCH, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_WRITE);
