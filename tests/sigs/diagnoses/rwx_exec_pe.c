#include <kofmod/kofdiagtree.h>

/*
 * tests/sigs/diagnoses/rwx_exec_pe.c
 *
 * rwx_exec's tree, declared for the route a PE takes. A PE offers its imports
 * and what it resolves for itself (APIHASH), and offers no syscall sweep, so a
 * diagnose that declares SYSCALL | SYMBOL - rwx_exec - is asked nothing on a PE
 * that builds its API calls through the loader data: the route it needs is not
 * one it declared. This one declares the two a PE has.
 *
 * IT IS HERE, A SECOND FIXTURE FOR THE SAME STATEMENT, so that the view/parent
 * and route-equivalence tests (tests/unit/view_equiv.c, flag_readers.c) can put
 * one payload through an ELF and a PE and compare what comes out. The disease
 * is the same one - exec/rwx-region - on purpose: it is the same behaviour, and
 * the syndrome that reads it must not care which format showed it.
 */

KOF_DIAG_NAME(rwx_exec_pe);
KOF_DECLARE_DISEASE(KOF_MALTYPE_DROPPER, "exec/rwx-region");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYMBOL | KOF_DIAG_ANALYSIS_APIHASH);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_REG);
