#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/php_request_create.c
 *
 * The sender of the request supplied the TEXT OF A NEW FUNCTION: `create_function('', $_POST['c'])`. The function is made from what the
 * request said and called later by its handle, so no eval is ever written. create_function runs its SECOND argument (the first is the
 * parameter list): a request that only supplies the parameters is not this. Expected on the create_function backdoors; PHP 8 removed
 * the function and the same act is spelled differently in the other languages' tables (new Function, compile, loadstring).
 */

KOF_DIAG_NAME(php_request_create);
KOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, "script/request-create");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_TEXT);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_REQUEST, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_CREATE);
