/*
 * diag_imports_status - the status of the import table a scan READS reaches the scan.
 *
 * kgenome_diag_imports returned the table the scanner handed over (`if (s->imports) return
 * s->imports;`) without noting its status; the note existed only in the symbol route and
 * for a table the scan built itself. A table whose thunk budget ran out (TRUNCATED) or
 * whose growth failed (NOMEM) is a partial import list whoever built it, and any route that
 * asks - the API-hash run too, not only the one that happens to note it - must leave the
 * scan saying so (kgenome_diag_scan_status).
 */

#include <kgenome.h>
#include <phenotype/diag_private.h>

#include "hk.h"

static struct hk_pe P;
static struct kgenome_pe_info pi;

static enum kgenome_status status_with(enum kgenome_status given, int pass_table)
{
	struct kgenome_obj o;
	struct kgenome_pe_imptab tab;
	struct kgenome_diag_inputs in;
	struct kgenome_diag_scan *s;
	enum kgenome_status st;

	memset(&pi, 0, sizeof pi);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));
	o.file_header = &pi;
	memset(&tab, 0, sizeof tab);
	tab.status = given;
	memset(&in, 0, sizeof in);
	in.imports = pass_table ? &tab : NULL;
	s = kgenome_diag_scan_with_inputs(&o, P.b, P.n, 0u, &in);
	CK(s != NULL);
	if (!s)
		return KGENOME_BAD_INPUT;
	(void)kgenome_diag_imports(s, &o);      /* what any route that wants the slots asks */
	st = kgenome_diag_scan_status(s);
	kgenome_diag_scan_free(s);
	return st;
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	hk_pe(&P, 1);
	CK(status_with(KGENOME_OK, 1) == KGENOME_OK);                 /* the control */
	CK(status_with(KGENOME_TRUNCATED, 1) == KGENOME_TRUNCATED);   /* a table the scanner handed over */
	CK(status_with(KGENOME_NOMEM, 1) == KGENOME_NOMEM);
	CK(status_with(KGENOME_OK, 0) == KGENOME_OK);                 /* one it built itself */
	printf("diag_imports_status: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
