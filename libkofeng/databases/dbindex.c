/*
 * dbindex.c - assembling the engine: the loaded tables, plus the indexes the
 * detector keeps over them.
 *
 * WHY THIS FILE EXISTS, WHICH IS A DIRECTION AND NOT A PREFERENCE.
 *
 * `struct kof_engine` spans two layers. Most of it is what dbloader.c read out
 * of the packs - modules, ranges, similarity blocks, the code arena. Two fields
 * are not: `mutation` and the packs' pattern tables are acceleration structures over that data,
 * built by the detectors and read by nothing else.
 *
 * Those used to be filled inside kof_db_load, and that one decision
 * made the two directories mutually dependent:
 *
 *     dbloader.c  -> kof_mutation_build, kofpix_open   (matchers)
 *     kofmultimatch.c -> kof_db_str                    (dbloader)
 *
 * A cycle between directories in one archive costs no build and no link, which
 * is exactly why it survived: nothing fails. What it costs is the ability to
 * read either directory on its own, and the ability to ever make them separate
 * libraries.
 *
 * The edge that had to go was the matchers' one, and it has: the layout of a
 * loaded pack and its accessors are in databases/pack/ (dbtables.h, dbaccess.c),
 * BELOW the detectors, so detectors/pattern reads them without including the
 * loader. This file sits in databases/, ABOVE the detectors: it is the one place
 * that builds the matchers over what the loader read, so its includes of
 * detectors/ point down, which is the order tools/check_layers.py enforces.
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
 * The pattern tables are opened over the pack mappings (a table built in memory reads the
 * pack's sections), so they cannot be made until the engine holds them. They ran late inside the
 * loader for that reason and they run later still here, which is the same constraint satisfied more
 * simply - by the time this sees the engine, loading is over.
 *
 * kof_mutation_build needs only the block table and its pool, both final long
 * before the loader returns. It used to run in the middle of the load; moving
 * it after costs nothing, because nothing the loader does afterwards reads
 * `mutation` and nothing it does afterwards writes the blocks.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "dbloader.h"
#include "../detectors/mutations/kofmutation.h"
#include "../detectors/pattern/kofpix.h"
#include "pack/dbcore.h"
#include "../kofcore/kofplatform.h"


/*
 * THE PATTERN TABLES, one per pack (detectors/pattern/kofpix.h): a pack that carries one in its tail
 * opens it where it lies (pread, a few megabytes resident whatever the database holds); a pack that
 * does not - a table too small to be worth writing (KOFPIX_EMBED_MIN) or a pack from before the part
 * existed - has the same table built in memory from its own sections, under what the ledger
 * leaves. Either way the sweep, the verification and the answers are the same code, so what a
 * database detects does not depend on where its table lives.
 *
 * What the ledger grants and how it falls short, in this order, each said and none silent:
 *   - the filter (a bit table in front of the exact key set) is the default size, or the largest
 *     level the ledger grants (a quarter of what is left, at most KOFPIX_FILTER_DEFAULT): a coarser
 *     level is slower and never less exact  -> KOF_PIX_B_DEGRADED
 *   - a table that has to be built in memory and is not small is built under half of what is left,
 *     or refused  -> KOF_PIX_B_IN_RAM (it was built: repack to keep it in the pack), KOF_PIX_B_OVER_BUDGET
 *     (it was not: that pack's markers are answered one at a time, exactly)
 *   - a table in the pack that does not open (a format this build does not read, a checksum, a
 *     file shorter than it says) is not used, and the pack's markers are answered one at a time
 *     -> KOF_PIX_B_OPEN_FAILED
 * No marker is ever lost to any of these; they cost the sweep, which the per-marker path replaces
 * exactly.
 */
static void attach_pattern(struct kof_engine *e, const struct kof_db_load_opt *opt)
{
	uint64_t room = opt && opt->budget ? kof_budget_room(opt->budget) : KOF_ENGINE_MEM_CAP;
	uint64_t f_def = KOFPIX_FILTER_DEFAULT, f_grant = f_def < room / 4u ? f_def : room / 4u;
	uint64_t ram_left = room / 2u, total = 0;
	uint32_t i;

	for (i = 0; i < e->n_packs; i++)
		total += ((const struct kof_pack_hdr *)e->packs[i].map)->n_str;
	if (!total)
		return;
	for (i = 0; i < e->n_packs; i++) {
		struct kof_db_pack *mp = &e->packs[i];
		const struct kof_pack_hdr *h = mp->map;
		struct kofpix_open_req rq;
		struct kofpix_open_res res;
		uint8_t *sec = NULL;
		uint64_t sec_len = 0;

		if (!h->n_str)
			continue;
		memset(&rq, 0, sizeof rq);
		rq.uid_base = mp->uid_base;
		rq.src.fd = mp->fd;
		rq.src.pool_off = h->sec[KOF_SEC_STR_POOL].off;
		rq.src.pool_len = h->sec[KOF_SEC_STR_POOL].len;
		rq.filter_budget = f_grant / 8u * h->n_str / total * 8u;
		rq.filter_default = f_def / 8u * h->n_str / total * 8u;
		if (mp->has_pix) {
			rq.src.sec = &mp->pix_sl;
			rq.src.sec_len = mp->pix_foot.body_len;
		} else {
			struct kofpix_pack_view v;
			struct kofpix_build_stat st;
			const uint8_t *b = mp->map;

			/* The most this build can cost: a section of ~36 bytes a marker and the builder's own
			 * copies of the records (two arrays of 24). Refused before it is made, not after. */
			if ((uint64_t)h->n_str * 84u > ram_left && (uint64_t)h->n_str * 84u > KOFPIX_EMBED_MIN) {
				e->pix_status |= KOF_PIX_B_OVER_BUDGET;
				fprintf(stderr, "dbloader: pack %u: the pattern table (%u strings) does not fit what the "
					"engine's ledger leaves; its markers are searched one at a time\n", i, h->n_str);
				continue;
			}
			memset(&v, 0, sizeof v);
			v.mod = (const void *)(b + h->sec[KOF_SEC_MODS].off);   v.n_mod = h->n_mods;
			v.str = (const void *)(b + h->sec[KOF_SEC_STR_DESC].off); v.n_str = h->n_str;
			v.rng = (const void *)(b + h->sec[KOF_SEC_RANGE].off);  v.n_rng = h->n_rng;
			v.pool = b + h->sec[KOF_SEC_STR_POOL].off;
			v.pool_len = h->sec[KOF_SEC_STR_POOL].len;
			sec = kofpix_build_pack(&v, &sec_len, &st);
			if (!sec) {
				if (sec_len == ~(uint64_t)0) {
					e->pix_status |= KOF_PIX_B_NOMEM;
					fprintf(stderr, "dbloader: pack %u: no memory for the pattern table\n", i);
				}
				continue;          /* nothing keyable: every marker is answered one at a time */
			}
			if (sec_len > ram_left) {
				free(sec);
				e->pix_status |= KOF_PIX_B_OVER_BUDGET;
				fprintf(stderr, "dbloader: pack %u: the pattern table (%llu bytes) does not fit what the "
					"engine's ledger leaves; its markers are searched one at a time\n", i,
					(unsigned long long)sec_len);
				continue;
			}
			if (sec_len >= KOFPIX_EMBED_MIN) {
				e->pix_status |= KOF_PIX_B_IN_RAM;
				fprintf(stderr, "dbloader: pack %u has %llu markers and no pattern table; it is built in "
					"memory (repack to keep it in the pack)\n", i, (unsigned long long)st.n_rec);
			}
			ram_left -= sec_len;
			rq.src.mem = sec;
			rq.src.sec_len = sec_len;
			rq.src.pool_mem = b + h->sec[KOF_SEC_STR_POOL].off;
			rq.own_mem = 1;
			mp->pix_in_ram = 1;
		}
		mp->pix = kofpix_open(&rq, &res);
		if (!mp->pix) {
			free(sec);
			mp->pix_in_ram = 0;
			e->pix_status |= KOF_PIX_B_OPEN_FAILED;
			fprintf(stderr, "dbloader: pack %u: the pattern table does not open (status %d: %s); its "
				"markers are searched one at a time\n", i, (int)res.status,
				res.status == KOFPIX_E_IO ? "a read failed or the file is shorter than it says"
				: res.status == KOFPIX_E_CRC ? "a slice does not match its checksum"
				: res.status == KOFPIX_E_NOMEM ? "no memory" : "the table does not hold together");
			continue;
		}
		if (res.degraded)
			e->pix_status |= KOF_PIX_B_DEGRADED;
		e->pix_markers += res.n_ent;
		if (res.max_run > e->pix_max_run)
			e->pix_max_run = res.max_run;
		/* Ask the system to start reading the table now, so that the first objects do not wait on
		 * the disk for it: a hint, page cache and not resident memory (cold numbers in the report). */
		if (mp->has_pix)
			kof_prefetch(mp->fd, mp->pix_foot.trailer_off, mp->pix_foot.body_len);
	}
	/* The tables, swept together: a region is read once for every pack that has it. */
	{
		struct kofpix **px = calloc(e->n_packs ? e->n_packs : 1u, sizeof *px);
		uint32_t n = 0;

		for (i = 0; px && i < e->n_packs; i++)
			if (e->packs[i].pix)
				px[n++] = e->packs[i].pix;
		if (n) {
			e->pix_set = px ? kofpix_set_make(px, n) : NULL;
			if (!e->pix_set) {
				/* no sweep at all: every marker is searched one at a time, exactly */
				e->pix_status |= KOF_PIX_B_NOMEM;
				fprintf(stderr, "dbloader: no memory for the pattern set; markers are searched one at a time\n");
			} else {
				e->pix_regions = kofpix_set_regions(e->pix_set);
				e->pix_bytes = kofpix_set_resident(e->pix_set);
				for (i = 0; i < e->n_packs; i++)
					if (e->packs[i].pix)
						e->pix_bytes += kofpix_resident(e->packs[i].pix);
			}
		}
		free(px);
	}
	if (e->pix_status & KOF_PIX_B_DEGRADED)
		fprintf(stderr, "dbloader: the pattern filter is degraded: the ledger granted less than the "
			"default (%llu bytes of %llu)\n", (unsigned long long)f_grant, (unsigned long long)f_def);
}

/* The pre-built filter of a pack's trailer, read where it lies: ctx is the trailer handle the set owns. */
static int kix_xf_rd(void *ctx, uint64_t off, void *buf, size_t n)
{
	return kof_kix_xf_read(ctx, off, buf, n);
}

struct kof_engine *kof_db_load(const char *path)
{
	return kof_db_load_opt(path, NULL);
}

struct kof_engine *kof_db_load_opt(const char *path, const struct kof_db_load_opt *opt)
{
	struct kof_engine *e = kof_db_load_tables(path);

	if (!e)
		return NULL;

	/*
	 * The similarity index, one over every pack's blocks together.
	 *
	 * Over the whole database rather than per pack, because the point of
	 * one index is that a scan costs the same whatever is loaded - see the
	 * note on blk_tab in dbtables.h. No blocks is not a failure: a database
	 * with no mutation rules leaves this NULL and the matcher is never asked.
	 *
	 * A pack that carries the index trailer (pack/dbkix.h) hands over the index it opened at
	 * load: the matcher uses it where it lies and holds only its directory and a filter. A
	 * pack that does not (built before the trailer existed) hands over its block arrays and
	 * the matcher builds the same structure in memory, under the allowance the engine's ledger
	 * leaves, or is refused and says so.
	 */
	if (e->n_blk) {
		struct kof_mutation_build_res res;
		struct kof_mutation_build_req rq;
		struct kof_mutation_src *src = calloc(e->n_packs ? e->n_packs : 1u, sizeof *src);
		uint32_t i, n_src = 0, base = 0;

		if (!src) {
			fprintf(stderr, "dbloader: no memory for the similarity index\n");
			kof_db_free_tables(e);
			return NULL;
		}
		for (i = 0; i < e->n_packs; i++) {
			struct kof_db_pack *mp = &e->packs[i];
			const struct kof_pack_hdr *h = mp->map;

			if (!h->n_blk)
				continue;
			src[n_src].base = base;
			base += h->n_blk;
			if (mp->kix) {
				struct kof_kix_info ki;

				src[n_src].kix = mp->kix;
				mp->kix = NULL;               /* the matcher owns it now */
				src[n_src].n_blocks = h->n_blk;
				kof_kix_info(src[n_src].kix, &ki);
				if (ki.xf_bytes) {
					src[n_src].xf.read = kix_xf_rd;
					src[n_src].xf.ctx = src[n_src].kix;
					src[n_src].xf.len = ki.xf_bytes;
					src[n_src].xf_crc = ki.xf_crc;
				}
			} else {
				const uint8_t *m = mp->map;

				src[n_src].blocks = (const void *)(m + h->sec[KOF_SEC_MUTATION_BLK].off);
				src[n_src].n_blocks = h->n_blk;
				src[n_src].pool = (const void *)(m + h->sec[KOF_SEC_MUTATION_POOL].off);
				src[n_src].n_pool = h->n_pool;
				fprintf(stderr, "dbloader: pack %u has similarity blocks and no index trailer; "
					"the index is built in memory (repack to keep it in the pack)\n", i);
			}
			n_src++;
		}
		memset(&rq, 0, sizeof rq);
		rq.src = src;
		rq.n_src = n_src;
		rq.budget = opt ? opt->budget : NULL;
		rq.max_bytes = opt ? opt->max_index_bytes : 0;
		rq.res = &res;
		e->mutation = kof_mutation_build_req(&rq);
		free(src);
		e->mutation_status = res.status;
		e->mutation_bytes = res.bytes;
		e->mutation_keys = res.n_key;
		if (res.status & KOF_MTN_B_FILTER_DEGRADED)
			fprintf(stderr, "dbloader: the similarity filter is degraded: %llu bits "
				"for %u distinct hashes (ceiling %llu bytes%s)\n",
				(unsigned long long)res.bloom_bits, res.n_key, (unsigned long long)res.flt_ceiling,
				res.flt_w ? (res.flt_res < res.flt_parts ? ", pre-built, partitions left out"
					     : ", pre-built, fewer bits of every entry") : "");
		if (!e->mutation) {
			/* Said by cause: a pack that does not describe a set and an
			 * index that does not fit the allowance are different faults. */
			if (res.status & (KOF_MTN_B_OVER_BUDGET | KOF_MTN_B_TOO_MANY_CLASSES)) {
				fprintf(stderr, "dbloader: the similarity index does not fit "
					"the engine's memory ledger (reached %llu bytes) or has more "
					"classes than it can name; similarity rules will not score\n",
					(unsigned long long)res.bytes);
				goto indexed;
			}
			if (res.status & KOF_MTN_B_TOO_MANY_BLOCKS)
				fprintf(stderr, "dbloader: more similarity blocks than an index "
					"addresses (16777215)\n");
			else if (res.status & KOF_MTN_B_NOMEM)
				fprintf(stderr, "dbloader: no memory for the similarity index\n");
			else if (res.status & KOF_MTN_B_TOO_BIG)
				fprintf(stderr, "dbloader: the similarity index is past 32-bit ids\n");
			else
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
			 * mutation set and none of the work that came after it.
			 * The caller had no way to tell, because a returned
			 * pointer was the success signal.
			 */
			kof_db_free_tables(e);
			return NULL;
		}
	}
indexed:

	/*
	 * The pattern tables, one per pack. None is not a failure: a database that will be searched
	 * one marker at a time, which is what this engine did before these existed.
	 */
	attach_pattern(e, opt);

	/*
	 * WHAT THE LOAD TOUCHED IS GIVEN BACK. Validating a pack and copying its tables into the engine read every
	 * page of the module records, the prefilter columns and the code (153 bytes a rule: 122 MB resident at
	 * 800,000 rules, measured), and those pages are not needed again until a finding asks for a name or a
	 * string. They are clean file pages, so this costs nothing but the fault that brings one back, and a
	 * resident set that follows the database is what the cap is against.
	 */
	{
		uint32_t i;

		for (i = 0; i < e->n_packs; i++)
			kof_map_drop(e->packs[i].map, e->packs[i].len);
	}

	return e;
}

void kof_db_free(struct kof_engine *e)
{
	if (!e)
		return;
	/*
	 * The indexes first (the pattern tables are closed with their packs, below), then the tables
	 * they were built over. The other
	 * order works today because neither free reads the other's memory, and
	 * it is still the wrong one to write down: an index that pointed into
	 * the pack mappings would be reading freed pages, and nothing about
	 * this call site would say so.
	 */
	kofpix_set_free(e->pix_set);
	e->pix_set = NULL;
	kof_mutation_set_free(e->mutation);
	e->mutation = NULL;
	kof_db_free_tables(e);
}
