#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_request_write.c
 *
 * STATES: what the request chose became file content or a file's name: an upload, an editor, a dropper that writes what it was sent.
 * EXPECTED TO FIRE ON: MEASURED on the 76 shells of the corpus kept in /mnt/games/normtest/s3/php (numbered 001-111): 25 of them - 0byt3m1n1, Ani-Shell, Antichat_Shell, G6, UnknownSec, alfa-shell-v4.1-tesla, alfa, anonsecteam, b374k, ... (16 more).
 * MUST NOT FIRE ON: ordinary php applications - MEASURED: 0 of 1,073 php files of WordPress 6.8 and 0 of 13,392 mixed php files fire it (the synthetic texts it must
 * and must not match are in tests/unit/diag_text_golden.c).
 *
 * It names capabilities and not functions (the table of PHP names decides which function is which), a head and one tail, and no order.
 */

KOF_DIAG_NAME(php_request_write);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/request-write");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_REQUEST, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_WRITE);
