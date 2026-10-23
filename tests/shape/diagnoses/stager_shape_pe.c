#include <kofmod/kofdiagtree.h>

/*
 * tests/shape/diagnoses/stager_shape_pe.c
 *
 * The PE twin of stager_shape.c: the diagnose that asks for the analysis (and the
 * interpreter) on a PE that maps a section writable AND executable, the shape the
 * product's PE stager diagnoses had. A PE that resolves its own APIs by hash is found
 * through KOF_DIAG_ANALYSIS_APIHASH, which is what the tests that spin a small PE in the
 * interpreter (hunt_emu_tree.c, mem_engine.c, silent_loss_scan.c) need an asker for.
 * See stager_shape.c for why this is a tree of its own.
 */

KOF_DIAG_NAME(stager_shape_pe);
KOF_DECLARE_DISEASE(KOF_MALTYPE_DROPPER, "exec/rwx-region");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_APIHASH);
KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_DIAG_HAS_ATTRB(KOF_FACT_MAP_PERM, KOF_PE_PERM_W | KOF_PE_PERM_X);
KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_REG);
