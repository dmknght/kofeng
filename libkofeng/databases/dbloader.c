/*
 * dbloader.c - load packed databases into an immutable engine.
 *
 * A database is one or more .ksig packs. Each is mapped read only, validated, and
 * its tables copied into the engine's - except the detection names, which are left
 * where they are and read from the mapping when a finding needs one. The mappings
 * therefore outlive the load and belong to the engine.
 *
 * WHY NAMES ARE THE EXCEPTION AND NOTHING ELSE IS. The measurement is in
 * tests/unit/db_scale.c: with names copied, a database costs 61 resident bytes per
 * record and half of that is names. They are also the only table read exclusively on
 * the way OUT - a name is looked up when a module has already decided an object is
 * infected, which over a corpus scan is a few dozen times against however many
 * millions of records are loaded. Everything else here is read on the way in, per
 * object, and copying it buys a flat array and no indirection.
 *
 * So the general rule stands and the exception is measured: point at the mapping
 * where the data is large, cold, and only wanted after a decision; copy where it is
 * hot. The format was laid out to allow either - that is what the fixed strides are
 * for.
 *
 * Copying at all is worth defending, because the alternative was not mapping:
 *
 *     4000 modules as loose artefacts: 16000 files, 83463 syscalls, 47ms per
 *     process with a warm page cache - none of it I/O, all of it syscall and
 *     parse, and all of it linear in the number of modules.
 *
 * Reading N packs is N opens and N mmaps whatever they contain.
 *
 * The validation order below is the one dbcore.h specifies, and the order is the
 * point: every step runs before anything it checks is dereferenced, and no step
 * trusts a value a later step has not yet bounded. Every bound comes from the
 * length fstat reported, never from a length the file states about itself.
 */

/* Before any include, not after: open, mmap and opendir are POSIX, and a feature
 * test macro placed after the first include has no effect at all.
 *
 * _GNU_SOURCE, not _POSIX_C_SOURCE: this file pulls in kofplatform.h (below),
 * and that header's POSIX branch defines kof_memmem as a thin wrapper around
 * the real memmem - a GNU/BSD extension, not POSIX. Whether or not this
 * specific translation unit ever calls kof_memmem, the compiler still has to
 * see memmem declared to compile that inline function's body at all, and on
 * glibc, _POSIX_C_SOURCE alone does not just fail to enable memmem, it
 * actively suppresses it (defining any of _POSIX_C_SOURCE/_XOPEN_SOURCE
 * without _GNU_SOURCE/_DEFAULT_SOURCE opts into strict-POSIX mode). Missed
 * here originally because every build so far ran on Windows, where
 * kofplatform.h's kof_memmem never touches the real memmem at all - a real
 * Linux build surfaces it immediately as "implicit declaration of function
 * 'memmem'". _GNU_SOURCE is a superset of what _POSIX_C_SOURCE 200809L gave
 * this file, so nothing else here changes. */

#define _GNU_SOURCE

#include "dbloader_int.h"

/*
 * Append a pack's tables to the engine's.
 *
 * Every index a module carries is rebased as it is copied: a module's string
 * slice is written as an offset into the engine's table, not the pack's, so
 * nothing on the scan path has to know which pack a module came from.
 */
/*
 * Fold one module's targets into the presence set - see any_target.
 *
 * A module with NO targets is for everything, so it sets every bit: that is
 * what KOF_FMT_ANY compiles to, and reading it as "targets nothing" would turn
 * the engine's cheapest early-out into a silent refusal to open children.
 *
 * Ids of 64 and above are not representable here and are simply not recorded.
 * The set is an OPTIMISATION - it answers "is anything interested in this
 * target at all" - so a missing bit costs a walk that finds nothing, never a
 * module that does not run. The assert beside KOF_TARGET_COUNT is what says
 * when this needs to become an array.
 */
static void any_target_add(uint64_t *set, const struct kof_module *m)
{
	uint8_t i;

	if (!m->n_target) {
		*set = ~(uint64_t)0;
		return;
	}
	for (i = 0; i < m->n_target; i++)
		if (m->target[i] < 64u)
			*set |= (uint64_t)1 << m->target[i];
}

static void absorb(struct kof_engine *e, const struct kof_db_pack *mp,
		   size_t code_at, uint32_t pack_id)
{
	const uint8_t *base = mp->map;
	const struct kof_pack_hdr *h = mp->map;
	/* Rows of bytes, not a uint32 array: a count and the ids it counts.
	 * See KOF_SEC_PRE_TARGET. */
	const uint8_t  *pt = base + h->sec[KOF_SEC_PRE_TARGET].off;
	const uint32_t *ps = (const void *)(base + h->sec[KOF_SEC_PRE_SCAN].off);
	const uint32_t *pa = (const void *)(base + h->sec[KOF_SEC_PRE_ARCH].off);
	const uint32_t *pk = (const void *)(base + h->sec[KOF_SEC_PRE_SUBTYPE].off);
	const uint64_t *pz = (const void *)(base + h->sec[KOF_SEC_PRE_SIZE].off);
	const struct kof_pack_mod *pm =
		(const void *)(base + h->sec[KOF_SEC_MODS].off);
	const uint32_t *prng = (const void *)(base + h->sec[KOF_SEC_RANGE].off);
	const struct kof_mutation_block *pblk =
		(const void *)(base + h->sec[KOF_SEC_MUTATION_BLK].off);
	const uint32_t *ppool =
		(const void *)(base + h->sec[KOF_SEC_MUTATION_POOL].off);

	uint32_t rng0 = e->n_rng;
	uint32_t blk0 = e->n_blk, pool0 = e->n_blk_pool;
	uint32_t i;
	int unpack = (h->kind == KOF_PACK_UNPACK);
	int heur   = (h->kind == KOF_PACK_HEUR);

	memcpy(e->code + code_at, base + h->sec[KOF_SEC_CODE].off,
	       (size_t)h->sec[KOF_SEC_CODE].len);

	e->n_str += h->n_str;
	for (i = 0; i < h->n_rng; i++)
		e->rng_tab[e->n_rng++] = prng[i];
	/*
	 * The blocks and their hashes, REBASED into the engine's tables the way
	 * the packer rebased them into the pack's. Two levels of the same move,
	 * because there are two levels of pooling: a module's blocks share a
	 * pack's pool, and a pack's blocks share the engine's.
	 */
	for (i = 0; i < h->n_pool; i++)
		e->blk_pool[e->n_blk_pool++] = ppool[i];
	for (i = 0; i < h->n_blk; i++) {
		e->blk_tab[e->n_blk] = pblk[i];
		e->blk_tab[e->n_blk].first_hash += pool0;
		e->n_blk++;
	}

	for (i = 0; i < h->n_mods; i++) {
		struct kof_module *m = unpack ? &e->unp[e->n_unp++]
				     : heur ? &e->heur[e->n_heur++]
					    : &e->mods[e->n_mods++];

		/* Entry offset is zero within each blob; the compiler asserts it,
		 * so the blob's place in the arena is the entry point. */
		m->fn = (kof_scan_fn)(void *)(e->code + code_at + pm[i].code_off);
		/* Zero means the module has none - an offset of zero would be
		 * kof_scan itself, which is never a cure. */
		m->cure = pm[i].cure_off
			  ? (kof_scan_fn)(void *)(e->code + code_at +
						  pm[i].code_off +
						  pm[i].cure_off)
			  : NULL;

		/*
		 * THE COUNT IS WHAT BOUNDS THE READ, which is the whole reason
		 * it is stored beside the ids rather than derived from them.
		 * A row that claims more targets than the row holds is clamped
		 * here - the pack is a file, and a file can say anything.
		 */
		{
			const uint8_t *row = pt + (size_t)i * KOF_PRE_TARGET_STRIDE;

			m->n_target = row[0] > KOF_TARGET_LIST_MAX
				    ? (uint8_t)KOF_TARGET_LIST_MAX : row[0];
			memcpy(m->target, row + 1, m->n_target);
		}
		m->scan_mask   = ps[i];
		m->arch_mask   = pa[i];
		m->subtype_mask = pk[i];
		m->size_min    = pz[i];

		m->str_base  = pm[i].str_first;     /* within that pack */
		m->n_str     = pm[i].n_str;
		m->rng_base  = rng0  + pm[i].rng_first;
		m->n_rng     = pm[i].n_rng;
		m->block_base = blk0 + pm[i].blk_first;
		m->n_block    = pm[i].n_blk;
		m->pack_id   = pack_id;
		m->name_base = pm[i].name_first;    /* within that pack */
		m->n_names   = pm[i].n_names;
		m->family_off = pm[i].family_off;
		m->maltype    = pm[i].maltype;
		m->disease    = pm[i].disease;
		m->disease_type = pm[i].disease_type;
		m->step       = pm[i].step;
		m->heur_phase = pm[i].heur_phase;
		/* Zero means unstated - a pack written before the field
		 * existed - and unstated is level 1, which is what every rule
		 * ran at before there was a choice. */
		m->heur_level = pm[i].heur_level ? pm[i].heur_level : 1u;
		m->heur_want  = pm[i].heur_want;
		m->heur_predict_off = pm[i].heur_predict_off;
		m->content_off = pm[i].content_off;
		m->kind       = (uint8_t)h->kind;
		m->src_off    = pm[i].src_off;


		/*
		 * Only a detector's regions go into the union the scanner
		 * resolves. An unpacker runs after the searching is done, and a
		 * heuristic reads what the parse already worked out, so a region
		 * either of them names must not make every object pay for
		 * resolving it.
		 */
		if (!unpack && !heur)
			e->scan_mask |= m->scan_mask;
		else if (heur)
			e->heur_scan_mask |= m->scan_mask;
	}
}

/* ---- the database: see pack/dbaccess.c for the accessors -------------------- */

/* What one load of a database holds between its steps. */
struct db_load {
	struct kof_engine *e;
	struct kof_db_pack *mp;
	const char **paths;
	const char *single[1];
	uint32_t n_paths, n_ok;
	uint64_t n_mods, n_str, n_rng, code;
	uint64_t n_blk, n_pool;
	int owned;
	const char *dir_for_diag;
};

/* The packs to load: every .ksig in a directory, or the one file. Zero when
 * a directory holds none. */
static int db_pack_paths(const char *path, struct db_load *L)
{
	struct stat sb;

	if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		L->dir_for_diag = path;
		L->paths = kof_db_collect_packs(path, &L->n_paths);
		L->owned = 1;
		if (!L->paths || L->n_paths == 0) {
			fprintf(stderr, "dbloader: no .ksig packs in %s\n", path);
			free(L->paths);
			return 0;
		}
	} else {
		L->single[0] = path;
		L->paths = L->single;
		L->n_paths = 1;
	}
	return 1;
}

/* Map and validate every pack, and total what they hold. */
static void db_map_packs(struct db_load *L)
{
	uint32_t i;

	/*
	 * Map and validate everything first, then allocate once from the totals.
	 * Growing the tables while reading would mean reallocating four arrays per
	 * pack, and the counts are already in the headers - there is nothing to
	 * discover by growing.
	 *
	 * A pack that will not load is refused and the rest are still read: one
	 * corrupt file in a directory should not take the whole database with it.
	 */
	for (i = 0; i < L->n_paths; i++) {
		const struct kof_pack_hdr *h;

		if (!kof_db_map_pack(&L->mp[L->n_ok], L->paths[i]))
			continue;
		h = L->mp[L->n_ok].map;
		L->n_mods += h->n_mods;
		L->n_str  += h->n_str;
		L->n_rng  += h->n_rng;
		L->n_blk  += h->n_blk;
		L->n_pool += h->n_pool;
		/* Padded to the same boundary the packer used inside each pool, so
		 * an aligned offset stays aligned once the pools are concatenated. */
		/* Each pack's blobs keep the offsets its own header gives them, so
		 * its code section is placed whole and aligned. */
		L->code = kof_round_up(L->code, KOF_PACK_BLOB_ALIGN) +
		       h->sec[KOF_SEC_CODE].len;
		L->n_ok++;
	}
}

/* Whether the totals fit the engine's indices. */
static int db_totals_fit(const struct db_load *L, const char *path)
{
	uint64_t n_mods = L->n_mods, n_str = L->n_str, n_rng = L->n_rng;
	uint64_t n_blk = L->n_blk, n_pool = L->n_pool;

	/*
	 * In 64 bits, then refused if a total does not fit the engine's uint32.
	 *
	 * Not defensive politeness: every one of these is an index into a table
	 * allocated from it. The memo is NOT summed here - it is not the sum of
	 * the packs' memo_slots but n_uid x n_masks, derived and bounds-checked
	 * further down where those are known - so a check on the sum here would
	 * reject on a number the allocation never uses.
	 */
	if (n_mods > 0xffffffffu || n_str > 0xffffffffu ||
	    n_rng > 0xffffffffu || n_blk > 0xffffffffu ||
	    n_pool > 0xffffffffu) {
		fprintf(stderr, "dbloader: %s: more entries than an index can hold\n",
			path);
		return 0;
	}
	return 1;
}

/* The engine and its tables, sized once from the totals. Zero on failure, with
 * nothing left allocated. */
static int db_alloc_tables(struct db_load *L)
{
	struct kof_engine *e;
	uint64_t n_mods = L->n_mods, n_rng = L->n_rng, n_blk = L->n_blk;
	uint64_t n_pool = L->n_pool, code = L->code;

	e = calloc(1, sizeof *e);
	L->e = e;
	if (!e)
		return 0;
	e->mods     = calloc(n_mods ? n_mods : 1, sizeof *e->mods);
	e->unp      = calloc(n_mods ? n_mods : 1, sizeof *e->unp);
	e->heur     = calloc(n_mods ? n_mods : 1, sizeof *e->heur);
	e->rng_tab  = calloc(n_rng  ? n_rng  : 1, sizeof *e->rng_tab);
	e->blk_tab  = calloc(n_blk  ? n_blk  : 1, sizeof *e->blk_tab);
	e->blk_pool = calloc(n_pool ? n_pool : 1, sizeof *e->blk_pool);
	if (!e->mods || !e->unp || !e->heur || !e->rng_tab ||
	    !kof_db_arena_open(e, (size_t)code)) {
		kof_db_free_tables(e);
		L->e = NULL;
		return 0;
	}
	return 1;
}

/*
 * Every pack's contents into the tables, each code section placed whole and
 * aligned.
 */
static void db_absorb_packs(struct db_load *L)
{
	struct kof_engine *e = L->e;
	struct kof_db_pack *mp = L->mp;
	uint32_t i;
	size_t at = 0;

	for (i = 0; i < L->n_ok; i++) {
		const struct kof_pack_hdr *h = mp[i].map;

		at = (size_t)kof_round_up(at, KOF_PACK_BLOB_ALIGN);
		absorb(e, &mp[i], at, i);
		at += (size_t)h->sec[KOF_SEC_CODE].len;
	}
}

/*
 * Pattern ids made unique across packs, and each pack's string section as two
 * pointers.
 */
static void db_pack_uids(struct db_load *L)
{
	struct kof_engine *e = L->e;
	struct kof_db_pack *mp = L->mp;
	uint32_t n_ok = L->n_ok;
	uint32_t i2, j2;

	e->n_uid = 0;
	for (i2 = 0; i2 < n_ok; i2++) {
		const struct kof_pack_hdr *ph = mp[i2].map;
		const struct kof_pack_str *ps =
			(const void *)((const uint8_t *)ph +
				       ph->sec[KOF_SEC_STR_DESC].off);
		uint32_t hi = 0;

		for (j2 = 0; j2 < ph->n_str; j2++)
			if (ps[j2].uid + 1u > hi)
				hi = ps[j2].uid + 1u;
		mp[i2].uid_base = e->n_uid;
		mp[i2].n_uid = hi;
		e->n_uid += hi;

		/*
		 * And the string section as two pointers - see
		 * kof_db_pack.desc. Every bound checked here once,
		 * against the length this mapping had when it was
		 * validated.
		 */
		{
			uint64_t maplen = mp[i2].len;
			uint64_t doff = ph->sec[KOF_SEC_STR_DESC].off;
			uint64_t poff = ph->sec[KOF_SEC_STR_POOL].off;
			uint64_t plen = ph->sec[KOF_SEC_STR_POOL].len;
			const uint8_t *b = (const uint8_t *)ph;

			mp[i2].desc = NULL;
			mp[i2].n_desc = 0;
			mp[i2].pool = NULL;
			mp[i2].pool_len = 0;
			if (doff <= maplen &&
			    (uint64_t)ph->n_str *
				    sizeof(struct kof_str_ent) <=
				    maplen - doff &&
			    poff <= maplen && plen <= maplen - poff) {
				mp[i2].desc = (const struct kof_str_ent *)
					(const void *)(b + doff);
				mp[i2].n_desc = ph->n_str;
				mp[i2].pool = b + poff;
				mp[i2].pool_len = plen;
			}
		}
	}
}

/*
 * Region masks made dense: every module range's mask as an index. Zero on
 * failure.
 */
static int db_rng_masks(struct db_load *L)
{
	struct kof_engine *e = L->e;
	uint32_t i2, j2;

	e->rng_uid = calloc(e->n_rng ? e->n_rng : 1, sizeof *e->rng_uid);
	if (!e->rng_uid) {
		kof_db_free_tables(e);
		L->e = NULL;
		return 0;
	}
	/*
	 * Against the DISTINCT masks, not against every earlier entry.
	 *
	 * rng_tab holds one entry per module per range, so it is as long as the
	 * database; the distinct values in it are one per way a module can name
	 * a region, which is a handful. Comparing against the whole table was
	 * quadratic in the database - two billion comparisons at sixty thousand
	 * modules, on the load path, to find fewer than thirty answers.
	 */
	{
		uint32_t seen[KOF_MAX_DISTINCT_MASKS];

		e->n_masks = 0;
		for (i2 = 0; i2 < e->n_rng; i2++) {
			for (j2 = 0; j2 < e->n_masks; j2++)
				if (seen[j2] == e->rng_tab[i2])
					break;
			if (j2 == e->n_masks) {
				if (e->n_masks == KOF_MAX_DISTINCT_MASKS) {
					/* More region vocabularies than any
					 * set of formats defines: refuse
					 * rather than share a slot. */
					kof_db_free_tables(e);
					L->e = NULL;
					return 0;
				}
				seen[e->n_masks++] = e->rng_tab[i2];
			}
			e->rng_uid[i2] = j2;
		}
	}
	return 1;
}

/* The memo, keyed by (pattern, mask). */
static void db_memo_size(struct kof_engine *e)
{
	/*
	 * The memo, keyed by (pattern, mask) instead of by (module, string,
	 * range).
	 *
	 * The old key gave every module its own slots, so a pattern two
	 * families happen to share was searched for twice. This one gives it
	 * one slot however many modules name it - and because identical
	 * patterns were merged at build time, the table SHRINKS by exactly the
	 * duplication factor rather than growing.
	 */
	if (e->n_masks && e->n_uid &&
	    (uint64_t)e->n_uid * e->n_masks <= 0xffffffffu)
		e->memo_size = e->n_uid * e->n_masks;
	else
		e->memo_size = 0;
}

/* Give back the unpacker table nobody filled. */
static void db_shrink_unp(struct kof_engine *e)
{
/*
 * Give back the unpacker table nobody filled.
 *
 * It was allocated for n_mods because which modules unpack is not known
 * until the packs have been walked, and one array sized for the worst case
 * is simpler than counting twice. The worst case is also absurd - a database
 * is detection records with a handful of unpackers beside them, so this holds
 * eleven entries out of however many were reserved.
 *
 * ADDRESS SPACE, NOT RESIDENT MEMORY - measured, having first assumed
 * otherwise. At four million records the slack is 64 bytes a record, and the
 * quarter gigabyte that suggests never becomes resident: calloc serves a block
 * that size from mmap, and a page of it costs nothing until something writes
 * to it. tests/unit/db_scale.c reports the same bytes per module with this
 * shrink and without it.
 *
 * It is still worth the four lines. The reservation is real at sizes the
 * allocator serves from the heap, where the pages ARE touched, and a mapping
 * whose size has nothing to do with its contents is a thing the next reader
 * has to work out from scratch. What it is not is the saving it looks like.
 *
 * A failed shrink is not an error. realloc declining to make a block smaller
 * leaves the original intact, which is exactly the state this started in.
 */
	struct kof_module *sm;
	size_t want = e->n_unp ? e->n_unp : 1u;

	sm = realloc(e->unp, want * sizeof *sm);
	if (sm)
		e->unp = sm;
}

/*
 * The per-format index of modules, by counting sort. Returns the entries in
 * it.
 */
static uint32_t db_index_by_target(struct kof_engine *e)
{
/*
 * The per-format index, once the module array is final.
 *
 * A counting sort: count the bits, run the counts into offsets, place.
 * Failure is not fatal - mod_by_target NULL means the scan walks the
 * flat array as it always did, which is slower and identical.
 */
	/* `m` rather than `i`: it indexes modules, and an `i` here
	 * shadowed the loader's own. */
	uint32_t b, m, total = 0, *fill;

	for (b = 0; b <= KOF_TARGET_COUNT; b++)
		e->mod_at[b] = 0;
	for (m = 0; m < e->n_mods; m++)
		for (b = 0; b < KOF_TARGET_COUNT; b++)
			if (kof_module_targets(&e->mods[m], (uint8_t)b))
				e->mod_at[b + 1u]++;
	for (b = 0; b < KOF_TARGET_COUNT; b++)
		e->mod_at[b + 1u] += e->mod_at[b];
	total = e->mod_at[KOF_TARGET_COUNT];

	fill = calloc(KOF_TARGET_COUNT, sizeof *fill);
	e->mod_by_target = total ? calloc(total, sizeof *e->mod_by_target)
				 : NULL;
	if (fill && (e->mod_by_target || !total)) {
		for (m = 0; m < e->n_mods; m++)
			for (b = 0; b < KOF_TARGET_COUNT; b++)
				if (kof_module_targets(&e->mods[m],
						       (uint8_t)b))
					e->mod_by_target[e->mod_at[b] +
							 fill[b]++] = m;
	} else {
		free(e->mod_by_target);
		e->mod_by_target = NULL;
	}
	free(fill);
	return total;
}

/* Within each format, the cheap questions first. */
static void db_index_tier_order(struct kof_engine *e, uint32_t total)
{
	uint32_t b;

	/*
	 * AND WITHIN EACH FORMAT, THE CHEAP QUESTIONS FIRST.
	 *
	 * The scan loop stops at the first module that reports, so the
	 * order inside a bucket decides what a verdict costs. A module
	 * is sorted by THE KIND OF DATA IT ASKS FOR, which is the one
	 * thing the loader knows without running it:
	 *
	 *   0  neither markers nor blocks - it reads what the parse
	 *      already established, so it needs no pass over the bytes
	 *   1  blocks - it needs the similarity feed
	 *   2  markers - it needs the multi-pattern sweep, the most
	 *      expensive of the three
	 *
	 * Paired with the deferred passes in the scanner (see
	 * need_multi and need_mutation there), this is what makes a
	 * structural verdict cost no sweep at all: the module that
	 * answers first is the one that asked for least.
	 *
	 * STABLE WITHIN A TIER, so two modules that ask for the same
	 * data keep the order the database gave them and a rebuild of
	 * the same packs cannot reshuffle which of them reports.
	 *
	 * Best effort: without the scratch the index is simply left in
	 * database order, which is what it was before this existed.
	 */
	if (e->mod_by_target && total) {
		uint32_t *tmp = calloc(total, sizeof *tmp);

		if (tmp) {
			for (b = 0; b < KOF_TARGET_COUNT; b++) {
				uint32_t lo = e->mod_at[b];
				uint32_t hi = e->mod_at[b + 1u];
				uint32_t n = 0, t, k;

				for (t = 0; t < 3u; t++)
					for (k = lo; k < hi; k++) {
						const struct kof_module *md =
							&e->mods[e->mod_by_target[k]];
						uint32_t tier = md->n_str ? 2u
							      : (md->n_block ? 1u : 0u);

						if (tier == t)
							tmp[n++] = e->mod_by_target[k];
					}
				for (k = 0; k < n; k++)
					e->mod_by_target[lo + k] = tmp[k];
			}
			free(tmp);
		}
	}
}

/* How many markers each region could have, per format. */
static void db_live_caps(struct kof_engine *e)
{
/*
 * AND HOW MANY MARKERS EACH REGION COULD HAVE, PER FORMAT - see
 * live_cap. Summed here because it cannot change once the module list
 * is final, and multi_prepass was recomputing it for every object.
 *
 * All three arrays, because all three run against an object and share
 * its memo - the same reason multi_prepass walks all three.
 */
	const struct kof_module *arr[3];
	uint32_t cnt[3], ai, mi, t, r, b;

	arr[0] = e->mods; cnt[0] = e->n_mods;
	arr[1] = e->unp;  cnt[1] = e->n_unp;
	arr[2] = e->heur; cnt[2] = e->n_heur;

	e->live_cap = calloc((size_t)KOF_TARGET_COUNT *
			     KOF_MULTIMATCH_BITS, sizeof *e->live_cap);
	if (e->live_cap) {
		for (ai = 0; ai < 3u; ai++)
			for (mi = 0; mi < cnt[ai]; mi++) {
				const struct kof_module *m =
					&arr[ai][mi];
				uint32_t bits = 0;

				if (!m->n_str)
					continue;
				for (r = 0; r < m->n_rng; r++) {
					if (m->rng_base + r >= e->n_rng)
						break;
					bits |= e->rng_tab[m->rng_base + r];
				}
				/*
				 * ONLY THE BITS THIS TABLE HAS ROOM
				 * FOR. A scan mask may name regions
				 * past KOF_MULTIMATCH_BITS - the symbol
				 * halves are the case - and the loop
				 * this replaced dropped them by only
				 * ever counting b below that bound.
				 * Iterating the set bits instead has to
				 * say so, or a high bit indexes off the
				 * end of live_cap.
				 */
				bits &= (KOF_MULTIMATCH_BITS >= 32u)
					? 0xffffffffu
					: ((1u << KOF_MULTIMATCH_BITS) - 1u);
				if (!bits)
					continue;
				/*
				 * THE TARGETS IT NAMES, NOT ALL OF
				 * THEM - and the bits that are set,
				 * not all thirty.
				 *
				 * Written as two full sweeps this is
				 * n_mods * KOF_TARGET_COUNT *
				 * KOF_MULTIMATCH_BITS, which at 200 000
				 * modules is 174 million rounds to add
				 * a handful of numbers. A module names
				 * one target and one or two regions;
				 * walking what it declared is the same
				 * sum in a fraction of the steps.
				 *
				 * n_target of zero still means "every
				 * format", so that case keeps the full
				 * walk - see kof_module_targets.
				 */
				if (m->n_target) {
					uint8_t ti;

					for (ti = 0; ti < m->n_target &&
					     ti < KOF_TARGET_LIST_MAX;
					     ti++) {
						uint32_t tv =
							m->target[ti];
						uint32_t rest = bits;

						if (tv >= KOF_TARGET_COUNT)
							continue;
						while (rest) {
							b = (uint32_t)
							  __builtin_ctz(rest);
							rest &= rest - 1u;
							e->live_cap[tv *
							  KOF_MULTIMATCH_BITS
							  + b] += m->n_str;
						}
					}
				} else {
					for (t = 0; t < KOF_TARGET_COUNT;
					     t++) {
						uint32_t rest = bits;

						while (rest) {
							b = (uint32_t)
							  __builtin_ctz(rest);
							rest &= rest - 1u;
							e->live_cap[t *
							  KOF_MULTIMATCH_BITS
							  + b] += m->n_str;
						}
					}
				}
			}
	}
}

/* What this database has business with: the union of its modules' targets. */
static void db_any_target(struct kof_engine *e)
{
	uint32_t j;

	e->any_target = 0;
	for (j = 0; j < e->n_mods; j++)
		any_target_add(&e->any_target, &e->mods[j]);
	for (j = 0; j < e->n_unp; j++)
		any_target_add(&e->any_target, &e->unp[j]);
	for (j = 0; j < e->n_heur; j++)
		any_target_add(&e->any_target, &e->heur[j]);
}

/* Make the code executable and hand the mappings to the engine. */
static void db_finish(struct db_load *L)
{
	/* Written once, then executable. */
	if (kof_mprotect_rx(L->e->code, L->e->code_cap) != 0) {
		fprintf(stderr, "dbloader: cannot make the L->code executable\n");
		kof_db_free_tables(L->e);
		L->e = NULL;
	} else {
		/*
		 * The engine takes the mappings.
		 *
		 * They used to be released here, because everything had been copied
		 * out of them and nothing pointed back. Detection names are no
		 * longer copied - kof_db_name reads them from the pack - so the
		 * mappings are now part of the loaded database and outlive this
		 * function. Clearing mp is what stops the cleanup below from
		 * unmapping tables the engine is about to use.
		 */
		L->e->packs = L->mp;
		L->e->n_packs = L->n_ok;
		L->mp = NULL;

		/*
		 * And what this database has business with - see any_target.
		 *
		 * Here rather than as each pack is walked, because it is the
		 * union over what was LOADED: a pack that failed to map
		 * contributes no modules and must contribute no targets
		 * either, or the engine would open children for rules it does
		 * not have.
		 */
		db_any_target(L->e);
		/*
		 * AND THE DIAGNOSES, from the same directory. A database
		 * with none is an ordinary database - they are new, and
		 * nothing yet depends on there being any.
		 */
		if (L->dir_for_diag) {
			kof_db_load_diagnoses(L->e, L->dir_for_diag);
			kof_db_load_syndromes(L->e, L->dir_for_diag);
			kof_db_load_diseases(L->e, L->dir_for_diag);
		}
	}
}

struct kof_engine *kof_db_load_tables(const char *path)
{
	struct db_load L = { 0 };
	uint32_t i;
	uint32_t total;

	if (!path)
		return NULL;

	if (!db_pack_paths(path, &L))
		return NULL;

	L.mp = calloc(L.n_paths, sizeof *L.mp);
	if (!L.mp)
		goto out;

	db_map_packs(&L);
	if (L.n_ok == 0)
		goto out;
	if (!db_totals_fit(&L, path))
		goto out;
	if (!db_alloc_tables(&L))
		goto out;
	db_absorb_packs(&L);

	/*
	 * Pattern ids, made unique across packs, and region masks made dense.
	 *
	 * Both are the memo's key, and both have to be settled before memo_size can
	 * be known - so this runs after every pack has been absorbed and before the
	 * scanner is ever made.
	 */
	db_pack_uids(&L);
	if (!db_rng_masks(&L))
		goto out;
	db_memo_size(L.e);
	db_shrink_unp(L.e);
	total = db_index_by_target(L.e);
	db_index_tier_order(L.e, total);
	db_live_caps(L.e);
	db_finish(&L);
out:
	if (L.mp) {
		for (i = 0; i < L.n_ok; i++)
			kof_db_unmap_pack(&L.mp[i]);
		free(L.mp);
	}
	if (L.owned) {
		for (i = 0; i < L.n_paths; i++)
			free((void *)(uintptr_t)L.paths[i]);
		free(L.paths);
	}
	return L.e;
}

void kof_db_free_tables(struct kof_engine *e)
{
	if (!e)
		return;
	free(e->mods);
	free(e->mod_by_target);
	free(e->live_cap);
	free(e->unp);
	free(e->heur);
	free(e->rng_tab);
	free(e->rng_uid);
	free(e->blk_tab);
	free(e->blk_pool);
	free(e->diag);
	free(e->diag_node);
	free(e->diag_name);
	free(e->diag_needs);
	kof_synd_free(e->synd);
	free(e->disease);
	free(e->disease_pool);
	if (e->packs) {
		uint32_t i;

		for (i = 0; i < e->n_packs; i++)
			kof_unmap_file(e->packs[i].map, e->packs[i].len);
		free(e->packs);
	}
	kof_unmap_anon(e->code, e->code_cap);
	free(e);
}
