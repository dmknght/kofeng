/*
 * dbindex.c - assembling the engine: the loaded tables, plus the indexes the
 * detector keeps over them.
 *
 * WHY THIS FILE EXISTS, WHICH IS A DIRECTION AND NOT A PREFERENCE.
 *
 * `struct kof_engine` spans two layers. Most of it is what dbloader.c read out
 * of the packs - modules, ranges, similarity blocks, the code arena. Two fields
 * are not: `plague` and `multi` are acceleration structures over that data,
 * built by detector/matchers and read by nothing else.
 *
 * Those two fields used to be filled inside kof_db_load, and that one decision
 * made the two directories mutually dependent:
 *
 *     dbloader.c  -> kof_plague_build, kof_multimatch_build   (matchers)
 *     kofmultimatch.c -> kof_db_str                           (dbloader)
 *
 * A cycle between directories in one archive costs no build and no link, which
 * is exactly why it survived: nothing fails. What it costs is the ability to
 * read either directory on its own, and the ability to ever make them separate
 * libraries.
 *
 * The edge that had to go is the upward one. A loader reaching into the layer
 * that consumes it is the wrong way round; a consumer composing what it needs
 * from the layer below is the ordinary way round. So the loader stops at the
 * tables and this file, one directory up in the detector, puts the two halves
 * together. The direction is now detector -> databases and nothing comes back.
 *
 *
 * THE NAME DID NOT CHANGE, AND THAT WAS THE CONSTRAINT.
 *
 * kof_db_load and kof_db_free have about twenty call sites, most of them in the
 * test suite, and every one of them wants a database it can scan with. Renaming
 * the assembled pair would have made all of them say which half they meant, and
 * the first one to say the wrong half would get an engine whose indexes are
 * NULL - which does not fail, it just searches one marker at a time and finds
 * fewer things. So the split is underneath: the new names are on the halves,
 * and the name everything already calls still means what it always meant.
 *
 *
 * ORDER, WHICH IS NOT FREE TO CHOOSE.
 *
 * kof_multimatch_build reads marker bytes through kof_db_str, so it cannot run
 * until the engine holds the pack mappings. It ran late inside the loader for
 * that reason and it runs later still here, which is the same constraint
 * satisfied more simply - by the time this sees the engine, loading is over.
 *
 * kof_plague_build needs only the block table and its pool, both final long
 * before the loader returns. It used to run in the middle of the load; moving
 * it after costs nothing, because nothing the loader does afterwards reads
 * `plague` and nothing it does afterwards writes the blocks.
 */

#include <stdio.h>

#include "../databases/dbloader.h"
#include "matchers/kofplague.h"
#include "matchers/kofmultimatch.h"

struct kof_engine *kof_db_load(const char *path)
{
	struct kof_engine *e = kof_db_load_tables(path);

	if (!e)
		return NULL;

	/*
	 * The similarity index, built once over every pack's blocks together.
	 *
	 * Over the whole database rather than per pack, because the point of
	 * one index is that a scan costs the same whatever is loaded - see the
	 * note on blk_tab in dbloader.h. No blocks is not a failure: a database
	 * with no plague rules leaves this NULL and the matcher is never asked.
	 */
	if (e->n_blk) {
		e->plague = kof_plague_build(e->blk_tab, e->n_blk,
					     e->blk_pool, e->n_blk_pool);
		if (!e->plague) {
			fprintf(stderr, "dbloader: the similarity blocks do "
				"not describe a consistent set\n");
			/*
			 * AND THE ENGINE GOES BACK, WHICH IS THE FIX TO A BUG
			 * THIS MOVE MADE VISIBLE.
			 *
			 * In the loader this path was a bare `goto out`, and
			 * `out:` returns `e`. Every other failure after the
			 * engine is allocated does `kof_db_free(e); e = NULL;`
			 * first - this one did not, so a database whose blocks
			 * do not agree produced a NON-NULL engine with a NULL
			 * plague set and none of the work that came after it.
			 * The caller had no way to tell, because a returned
			 * pointer was the success signal.
			 */
			kof_db_free_tables(e);
			return NULL;
		}
	}

	/*
	 * The multi-pattern matchers, one per region mask.
	 *
	 * A NULL result is not a failure. It is a database that will be
	 * searched one marker at a time, which is what this engine did before
	 * these existed.
	 */
	e->multi = kof_multimatch_build(e);

	return e;
}

void kof_db_free(struct kof_engine *e)
{
	if (!e)
		return;
	/*
	 * The indexes first, then the tables they were built over. The other
	 * order works today because neither free reads the other's memory, and
	 * it is still the wrong one to write down: an index that pointed into
	 * the pack mappings would be reading freed pages, and nothing about
	 * this call site would say so.
	 */
	kof_multimatch_free(e->multi);
	e->multi = NULL;
	kof_plague_set_free(e->plague);
	e->plague = NULL;
	kof_db_free_tables(e);
}
