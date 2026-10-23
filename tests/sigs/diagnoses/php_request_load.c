#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_request_load.c
 *
 * The sender of the request chose WHAT IS LOADED: `$c = $_POST['m']; new $c`, `$c::run()`, `new ReflectionClass($_GET['c'])`,
 * `unserialize($_COOKIE['d'])`, `spl_autoload_register($_GET['f'])`. A library's plugin routing does the same with a name from its own
 * configuration, which is not this: the request is what reaches the name. Expected on object-injection and class-loading backdoors;
 * a request that only supplies a constructor's arguments is data for it and is not this (tests/lib/genome/diag_text.c pins it).
 */

KOF_DIAG_NAME(php_request_load);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/request-load");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_REQUEST, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_DYNLOAD);
