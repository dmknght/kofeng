#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_listen_accept.c
 *
 * STATES: a socket the script put to listen was accepted on - the stream API's server (`stream_socket_server` then `stream_socket_accept`): the script
 * waits to be connected to. (php_bind_shell is the same statement through the socket_* API, where the socket that is accepted on is the one that was
 * opened and not the one listen returned.)
 * EXPECTED TO FIRE ON: no sample of that corpus (0 of 76); a bind shell or bindport tool written with the stream API. [Unverified against a real sample]
 * MUST NOT FIRE ON: ordinary php applications - MEASURED: 0 of 1,073 php files of WordPress 6.8 and 0 of 13,392 mixed php files fire it (the synthetic texts it must
 * and must not match are in tests/unit/diag_text_golden.c).
 *
 * It names capabilities and not functions, a head and one tail, and no order.
 */

KOF_DIAG_NAME(php_listen_accept);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/listen-accept");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_LISTEN, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_ACCEPT);
