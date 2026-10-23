#include <kofmod/kofdiagtree.h>

/*
 * tests/shape/diagnoses/stager_shape.c
 *
 * THE FIXTURE FOR THE ROUTING A DIAGNOSE'S OWN DECLARATION DOES: it says which FILES are
 * worth the analysis (KOF_DIAG_HAS_ATTRB) and that the object is worth interpreting
 * (KOF_DIAG_USE_EMU), and the engine routes on it with no module asking. The same shape as
 * the stager diagnoses the product used to ship, written to make that machinery run -
 * tests/unit/diag_shape_gate.c asserts what the engine does with it, and it carries a
 * disease so that the verdict reads it (a diagnose nobody reads does not ask).
 *
 * IT LIVES IN ITS OWN TREE, tests/shape, built to build/test/databases-shape, and NOT in
 * tests/sigs: the shape is the one every synthetic stager of the suite has, so in the
 * shared test database it would make all of them ask for the interpreter and move every
 * ledger and every count the other tests pin. A test that wants an asker opens a database
 * that holds the product's unpackers beside these (he_db_asking in hostile_engine.h).
 *
 * A MAPPING THAT IS WRITABLE AND EXECUTABLE, and no section table. A stager has nothing else
 * to recognise it by - no imports, no symbols, a few hundred bytes of shellcode. SOME mapping
 * and not the one holding the entry, and NOT "one program header": a condition here decides
 * what gets looked at, so one narrower than it needs to be is a detection in disguise.
 */

KOF_DIAG_NAME(stager_shape);
KOF_DECLARE_DISEASE(KOF_MALTYPE_DROPPER, "exec/rwx-region");
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);
KOF_DIAG_USE_EMU();
KOF_DIAG_HAS_ATTRB(KOF_FACT_MAP_PERM, KOF_PERM_W | KOF_PERM_X);
KOF_DIAG_HAS_ATTRB(KOF_FACT_SECTIONS, 0);
KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_REG);
