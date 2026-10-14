/*
 * dbloader.h - the loaded database.
 *
 * Turns whatever the database is on disk into a kof_engine: module code mapped
 * executable, plus the tables the host needs to decide which modules to run and
 * what to call a finding.
 *
 * Not scan logic. Nothing here looks at an object under scan; it only materialises
 * the database. The split matters for two reasons:
 *
 *   - a kof_engine is immutable once loaded, so one can be shared by every thread.
 *     Our modules make that genuinely safe rather than safe by convention: they
 *     have no writable data and need no relocation, so the mapped code is read-only
 *     and position independent.
 *   - the mutable, expensive per-scan state - the presence table, the memo, the
 *     match context - belongs to the scanner and is allocated per thread. Keeping
 *     it out of here is what stops a 32MB table from being paid per file.
 */

#ifndef KOFENG_DBLOADER_H
#define KOFENG_DBLOADER_H

#include <stddef.h>
#include <stdint.h>

#include "pack/dbtables.h"   /* struct kof_engine and what it holds - see there */
#include "../databases/pack/kofsyndrome.h"   /* kof_synd_build: the loader reads syndromes.kdig */

/*
 * Load from a single .ksig pack or a directory of them.
 *
 * A database is one or more packs; dbcore.h defines what is in one. Given a
 * directory, every *.ksig in it is loaded and the tables above are the concatenation
 * of theirs - a pack that fails validation is refused on its own and the rest still
 * load, so one corrupt file does not take the database with it.
 *
 * Returns NULL if nothing loaded.
 */
/*
 * THE DATABASE, LOADED. TABLES ONLY.
 *
 * Packs mapped, modules absorbed, the code arena taken, pattern ids made unique
 * and region masks made dense. What it does NOT do is build `mutation` and
 * `multi`, which are left NULL: those are indexes the DETECTOR owns, and a
 * loader that built them would have to call into the layer that consumes it.
 *
 * An engine from here is usable for everything that reads the tables and is
 * not ready to scan with. Use kof_db_load below unless you are the assembler.
 */
struct kof_engine *kof_db_load_tables(const char *path);

/*
 * Free what kof_db_load_tables took. It does not touch `mutation` or `multi` -
 * it cannot, for the same reason it did not build them - so a caller that
 * built them frees them first. kof_db_free does exactly that.
 */
void               kof_db_free_tables(struct kof_engine *);

/*
 * THE ENGINE, ASSEMBLED: the tables above plus the detector's indexes over
 * them. This is what everything except the assembler itself should call.
 *
 * DECLARED HERE AND DEFINED IN databases/dbindex.c, which is the same
 * arrangement kof_fid_of has in fidset.h: the name belongs beside the loader's
 * entry points, and the definition belongs in the file that knows what an index
 * is, so that the loader proper stops at the tables.
 *
 * Semantics are unchanged from when this was one function, and the name is
 * unchanged so that every caller is too.
 */
struct kof_engine *kof_db_load(const char *path);

void               kof_db_free(struct kof_engine *);

/*
 * THE SAME LOAD WITH THE CALLER'S LEDGER. Every size the similarity index chooses comes from
 * `budget` (kofcore/kofbudget.h): the filter is the default for the number of hashes, halved
 * until the ledger grants it, and what stays resident - directories, the filter, and the
 * bodies of packs that carry no index trailer - may take at most half of what is left. With
 * no ledger the default cap (KOF_ENGINE_MEM_CAP) stands in for one; there is no "unlimited"
 * and no flat allowance of its own. `max_index_bytes` lowers it further (0: the ledger's).
 * An index that does not fit is refused - the engine loads, `mutation` is NULL and
 * kdb_mutation_status says KOF_MTN_B_OVER_BUDGET, and a line goes to stderr - because the
 * alternative was an allocation the engine never agreed to. The load only ASKS the ledger;
 * keng_open charges what the whole load left in memory.
 */
struct kof_db_load_opt {
	uint64_t                 max_index_bytes;
	const struct kof_budget *budget;
};
struct kof_engine *kof_db_load_opt(const char *path, const struct kof_db_load_opt *opt);

#endif /* KOFENG_DBLOADER_H */
