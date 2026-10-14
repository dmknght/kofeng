/*
 * diag_trace - which diagnose was called, through the debug callback, in a build with no
 * DEBUG: one fact "diag" per diagnose and event, in the one greppable shape documented
 * in scanners/objctx_diag_trace.c. Nothing is written per diagnose; the name comes from
 * the loaded database.
 *
 * Asserted on the kernel-module fixture (kmod_give_root matches, rwx_exec does not):
 * the callback hears the diagnose by NAME with its id, the gate, the declared routes, the
 * route the scan ran, the scan status and the answer; the asked-by field carries the
 * module that asked; with no callback registered nothing is said and the verdict is the
 * same.
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "../../libkofeng/kofeng.h"

static unsigned n_diag_facts;
static char first[400], asked[400];
static uint32_t f_diag;
static int saw_rwx;

static void on_dbg(uint32_t fact, const char *what, uint64_t value, void *user)
{
	(void)value; (void)user;
	if (fact != f_diag)
		return;
	n_diag_facts++;
	if (strstr(what, "rwx_exec "))
		saw_rwx = 1;
	if (!first[0])
		snprintf(first, sizeof first, "%s", what);
	if (strstr(what, "asked-by=-") == NULL && !asked[0])
		snprintf(asked, sizeof asked, "%s", what);
}

static uint8_t img[1u << 20];

int main(int argc, char **argv)
{
	struct e2e r;
	uint64_t len;
	unsigned plain;

	CK(e2e_open(argc > 1 ? argv[1] : NULL));
	f_diag = kverdict_fact_id("diag");
	len = cf_kmod(img, sizeof img, 0, 0);

	CK(e2e_scan(img, len, &r));
	plain = r.n ? r.o[0].n : 0;
	CK(n_diag_facts == 0);                         /* unset: nothing said */

	kscan_on_debug(e2e_sc, on_dbg, NULL);
	CK(e2e_scan(img, len, &r));
	CK(n_diag_facts > 0);
	CK(strstr(first, "kmod_give_root") != NULL);   /* the name comes from the .kdig */
	CK(saw_rwx);                                   /* every diagnose the database reads */
	CK(strstr(first, " id=") && strstr(first, " asked-by=") && strstr(first, " gate=") &&
	   strstr(first, " routes=") && strstr(first, " route=") && strstr(first, " stop=") &&
	   strstr(first, " answer="));
	CK(strstr(first, "gate=open") != NULL);
	CK(strstr(first, "answer=yes") != NULL);        /* kmod_give_root matched */
	CK(strstr(first, "asked-by=-") == NULL);        /* the module that asked is named */
	CK(r.n && r.o[0].n == plain);                  /* a callback changes no result */
	kscan_on_debug(e2e_sc, NULL, NULL);
	printf("diag trace: first fact: %s\n", first);
	printf("diag trace: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
