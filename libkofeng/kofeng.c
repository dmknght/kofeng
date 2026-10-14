/*
 * kofeng.c - the API boundary.
 *
 * Delegation and nothing else: validate what came in, own the lifetimes, translate
 * between the public types and the internal ones. The work is in dbloader (materialise
 * the database) and scanners (walk an object).
 *
 * Worth being this thin. The public header is the promise; if the promise is kept by
 * a file small enough to read in one go, there is nowhere for it to be quietly broken.
 */

#define _GNU_SOURCE

#include "kofeng.h"
#include "databases/dbloader.h"
#include "detectors/pattern/kofpix.h"
#include "scanners/scan.h"
#include "kofcore/kofplatform.h"

/*
 * OPEN A DATABASE UNDER THE ENGINE'S MEMORY BUDGET (kofcore/kofbudget.h): 512 MiB unless
 * keng_set_memory_cap says otherwise. What the load left in private memory is what the
 * database costs and is charged first; it is measured as the growth of the allocator's own
 * count across the load (the load is single-threaded work of this call), because the loader
 * builds its index from many small blocks and a sum of its own sizes would be a second
 * accounting to keep in step. Where the allocator cannot say, the figure is 0 and the budget is
 * simply not reduced - which the doc below says.
 */
kof_engine *keng_open(const char *db_path)
{
	kof_engine *e;
	struct kof_db_load_opt opt;
	struct kof_budget *b;
	uint64_t before, after;

	if (!db_path)
		return NULL;
	/*
	 * THE LEDGER EXISTS BEFORE THE LOAD, because the load asks it: the similarity index
	 * chooses its filter and its allowance from what the ledger has left (kof_db_load_opt).
	 * Asking takes nothing; what the load left in memory is charged below, once.
	 */
	b = calloc(1, sizeof *b);
	if (!b)
		return NULL;
	kof_budget_init(b, KOF_ENGINE_MEM_CAP);
	memset(&opt, 0, sizeof opt);
	opt.budget = b;
	before = kof_heap_in_use();
	e = kof_db_load_opt(db_path, &opt);
	if (!e) {
		free(b);
		return NULL;
	}
	after = kof_heap_in_use();
	e->budget = b;
	e->budget->db = after > before ? after - before : 0;
	(void)kof_budget_charge(e->budget, e->budget->db);
	return e;
}

void keng_close(kof_engine *e)
{
	if (e)
		free(e->budget);
	kof_db_free(e);
}

uint32_t kdb_mutation_status(const kof_engine *e, uint64_t *bytes, uint32_t *keys)
{
	if (bytes)
		*bytes = e ? e->mutation_bytes : 0;
	if (keys)
		*keys = e ? e->mutation_keys : 0;
	return e ? e->mutation_status : 0;
}

uint64_t keng_memory_cap(const kof_engine *e)
{
	return e && e->budget ? e->budget->cap : 0;
}

int keng_set_memory_cap(kof_engine *e, uint64_t bytes)
{
	uint64_t used;

	if (!e || !e->budget)
		return 0;
	if (!bytes)
		bytes = KOF_ENGINE_MEM_CAP;
	used = atomic_load(&e->budget->used);
	if (bytes < used || bytes < KOF_ENGINE_MEM_MIN)
		return 0;       /* below what is held, or below the least that works: refused, nothing changes */
	e->budget->cap = bytes;
	return 1;
}

uint64_t keng_memory_db(const kof_engine *e)
{
	return e && e->budget ? e->budget->db : 0;
}

uint64_t keng_memory_peak(const kof_engine *e)
{
	return e && e->budget ? atomic_load(&e->budget->peak) : 0;
}

uint32_t kdb_records(const kof_engine *e)
{
	return e ? e->n_mods : 0;
}

uint32_t kdb_unpackers(const kof_engine *e)
{
	return e ? e->n_unp : 0;
}

uint32_t kmatch_rules(const kof_engine *e)
{
	return e ? e->n_heur : 0;
}

/*
 * THE NAME OF A DIAGNOSE, FROM ITS ID.
 *
 * An id and not an index, because that is what kof_result.diag carries and a
 * caller must never have to know that the database happens to number them
 * from one. The off-by-one lives here, once, rather than in each tool.
 *
 * The string is the engine's and lives as long as the engine does: it is read
 * out of the loaded .kdig and is not composed, so there is nothing to free
 * and nothing that can be stale while the engine is open.
 */

uint32_t kdb_diagnoses(const kof_engine *e)
{
	return e ? e->n_diag : 0;
}

int kdb_diag_full(const kof_engine *e)
{
	return e ? e->diag_full != 0 : 0;
}

uint32_t kdb_diag_collisions(const kof_engine *e)
{
	return e ? e->diag_collide : 0u;
}

uint32_t kdb_diag_refused(const kof_engine *e)
{
	return e ? e->diag_refused : 0u;
}

uint32_t kdb_diag_packs_refused(const kof_engine *e)
{
	return e ? e->diag_packs_refused : 0u;
}
int kmatch_tables(const kof_engine *e, uint64_t *bytes,
			  uint32_t *max_chain)
{
	if (bytes)
		*bytes = 0;
	if (max_chain)
		*max_chain = 0;
	if (!e || !e->pix_markers)
		return -1;
	if (bytes)
		*bytes = e->pix_bytes;
	if (max_chain)
		*max_chain = e->pix_max_run;
	return 0;
}

uint32_t kdb_pattern_status(const kof_engine *e, uint64_t *bytes, uint64_t *markers)
{
	if (bytes)
		*bytes = e ? e->pix_bytes : 0;
	if (markers)
		*markers = e ? e->pix_markers : 0;
	return e ? e->pix_status : 0;
}


/*
 * A reason in words, for whoever has to read the scan.
 *
 * Here and not in the caller because the vocabulary is the engine's: a host that
 * spelled these itself would drift from what the engine actually reports the day a
 * reason is added.
 *
 * NOUN PHRASES, SENTENCE CASE. They were clauses - "the content is encrypted" -
 * from when they only ever appeared after a colon. The scanner now prints the
 * most specific thing it knows in the first column, so a reason starts a line,
 * and a clause reads as a fragment there. A noun phrase reads correctly in both
 * places.
 */
const char *kverdict_broken_name(uint32_t reason)
{
	switch (reason) {
	case KOF_BROKEN_LIMIT:       return "Limit reached";
	case KOF_BROKEN_UNSUPPORTED: return "Unsupported by this build";
	case KOF_BROKEN_DAMAGED:     return "Damaged object";
	case KOF_BROKEN_ENCRYPTED:   return "Encrypted content";
	default:                     return "Unknown";
	}
}

/* The id of a debug note's field - see kof_on_debug in koftypes.h. The hash
 * has one definition, kof_fact_id in core, which the scan path uses too. */
uint32_t kverdict_fact_id(const char *field)
{
	return kof_fact_id(field);
}

/*
 * What this build of the library is. See kofeng.h for why it decides nothing.
 */
void keng_version(struct kof_version *out)
{
	if (!out)
		return;
	out->major = KOFENG_MAJOR;
	out->minor = KOFENG_MINOR;
	out->build = KOFENG_BUILD;
}

/*
 * The oldest version among the loaded packs - see kofeng.h for why oldest.
 *
 * The header is already resident: a pack is mapped and kof_db_pack keeps the
 * mapping, so this reads the bytes the loader validated rather than a copy made
 * beside them. Nothing stores these values anywhere, which is the point - one
 * source, and it is the file.
 */
uint64_t kdb_stamp(const kof_engine *e)
{
	uint64_t acc = 0;
	uint32_t i, n = 0;

	if (!e)
		return 0;
	for (i = 0; i < e->n_packs; i++) {
		const struct kof_pack_hdr *h = e->packs[i].map;
		uint64_t m;

		if (!h)
			continue;
		/*
		 * THE CHECKSUM IS THE PACK'S CONTENT, already computed and
		 * already verified at load - see dbcore.h, step 5. The length
		 * and the build go in beside it so that two files could not
		 * agree by a crc collision alone.
		 */
		m = (uint64_t)h->crc32;
		m = m * 1099511628211ull + h->file_len;
		m = m * 1099511628211ull + h->build;
		m = m * 1099511628211ull +
		    (((uint64_t)h->major << 48) | ((uint64_t)h->minor << 32) |
		     h->machine);
		/*
		 * ADDED, NOT CHAINED, so the answer does not depend on the
		 * order a directory walk happened to hand the packs over in -
		 * two runs over one database must agree, and nothing promises
		 * readdir order.
		 */
		acc += m;
		n++;
	}
	if (!n)
		return 0;
	/* The COUNT as well, so that a pack removed is not hidden by one added
	 * whose mix happens to sum the same. */
	acc = acc * 1099511628211ull + n;
	return acc ? acc : 1ull;
}

int kdb_version(const kof_engine *e, struct kof_db_version *out)
{
	uint32_t i;
	int have = 0;

	if (!out)
		return 0;
	out->major = out->minor = 0;
	out->build = out->machine = 0;
	if (!e)
		return 0;
	for (i = 0; i < e->n_packs; i++) {
		const struct kof_pack_hdr *h = e->packs[i].map;

		if (!h)
			continue;
		if (!have || h->major < out->major ||
		    (h->major == out->major && h->minor < out->minor) ||
		    (h->major == out->major && h->minor == out->minor &&
		     h->build < out->build)) {
			out->major   = h->major;
			out->minor   = h->minor;
			out->build   = h->build;
			out->machine = h->machine;
		}
		have = 1;
	}
	return have;
}

kof_scanner *kscan_new(const kof_engine *e)
{
	return kscan_new_ex(e, NULL);
}

kof_scanner *kscan_new_ex(const kof_engine *e, int *why)
{
	if (!e) {
		if (why)
			*why = KSCAN_NEW_NO_ENGINE;
		return NULL;
	}
	return kof_scan_make(e, why);
}

const char *kscan_new_why_str(int why)
{
	switch (why) {
	case KSCAN_NEW_OK:        return "made";
	case KSCAN_NEW_NO_ENGINE: return "no engine";
	case KSCAN_NEW_BUDGET:    return "the engine's memory budget cannot afford another scanner";
	case KSCAN_NEW_NOMEM:     return "out of memory";
	default:                  return "unknown";
	}
}

/*
 * Ask to be told what modules work out.
 *
 * Per scanner rather than per engine: the engine is shared by every thread and is
 * immutable, and one thread wanting diagnostics must not turn them on for the rest.
 */
void kscan_on_debug(kof_scanner *sc, kof_on_debug cb, void *user)
{
	if (!sc)
		return;
	sc->debug_cb = cb;
	sc->debug_user = user;
}

void kscan_free(kof_scanner *sc)
{
	kof_scan_free(sc);
}

void kscan_trim(kof_scanner *sc, unsigned flags)
{
	kof_scan_trim(sc, flags);
}

const struct kof_stats *kscan_stats(const kof_scanner *sc)
{
	return sc ? kof_scan_stats(sc) : NULL;
}

int kscan_bytes(kof_scanner *sc, const void *bytes, uint64_t n,
		const char *name, const struct kof_scan_option *opt,
		kof_on_object cb, void *user)
{
	return kof_scan_bytes(sc, bytes, n, name, opt, cb, user);
}

int kscan_path(kof_scanner *sc, const char *path,
		  const struct kof_scan_option *opt, kof_on_object cb, void *user)
{
	static const struct kof_scan_option conservative;   /* all zero: no recursion */

	if (!sc || !path)
		return KOF_ERR_ARG;
	return kof_scan_walk(sc, path, opt ? opt : &conservative, cb, user);
}

int kscan_path_mt(kof_scanner **scs, unsigned n_sc, const char *path,
		     const struct kof_scan_option *opt, kof_on_object cb,
		     void *user)
{
	static const struct kof_scan_option conservative;   /* all zero: no recursion */

	if (!scs || !n_sc || !path)
		return KOF_ERR_ARG;
	return kof_scan_walk_mt(scs, n_sc, path, opt ? opt : &conservative,
				cb, user);
}
