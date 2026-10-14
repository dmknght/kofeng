#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/kmod_commit_only.c
 *
 * A fixture, and the one diagnose of this database that NOTHING reads: no
 * signature names it with kof_diag and it declares no disease, so no verdict
 * can use its answer. tests/unit/diag_gate.c scans with and without the report
 * option to show that a scan computes what something reads and that the report
 * (every diagnose) is asked for by the caller.
 *
 * A credential installed, nothing else: commit_creds imported by a module.
 */

KOF_DIAG_NAME(kmod_commit_only);
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYMBOL);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_CRED_SET, 0);
