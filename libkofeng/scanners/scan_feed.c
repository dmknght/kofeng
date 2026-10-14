/*
 * scan_feed.c - the shared work done once per object before modules are asked:
 * the similarity feeds and the multi-pattern prepass.
 *
 * need_* are the lazy entry points; each runs its feed at most once per object
 * (sc->latch), so the cost is paid by the first module that needs it and by nobody
 * that does not.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objctx_int.h"
#include "../detectors/pattern/kofpix.h"
#include "../analyzers/parsers/kofformat.h"
#include <string.h>


/*
 * Count every declared similarity block against this object, once.
 *
 * THE OBJECT IS CUT INTO UNITS THE WAY A BLOCK WAS CUT - kgenome_mutation_units is the
 * one cut, for the tool that makes a block and for this - and each unit is
 * sketched and credited. One pass per (region, normalizer) that some block asked
 * for, and no pass at all otherwise: the set is NULL unless a pack carried
 * blocks, so a database without mutation rules does not reach this, and
 * kof_mutation_set_norms answers which normalizers a region needs.
 *
 * BEFORE ANY MODULE, for the reason sx_multi_prepass runs first: a rule's
 * kof_mutation_score has to be a division rather than a search, and the only way
 * to make it one is to have counted already.
 *
 * THE FUNCTIONS AND THE LIBRARY ARE THE PARSE'S - see kof_scanner.cur.lib - and
 * a normalised view is fed on its own bytes: see sx_mutation_feed.
 */
struct mutation_feed {
	struct kof_mutation_ctx *pc;
	uint32_t mask, norms;
	const uint8_t *p;
};

static int mutation_feed_unit(void *user, uint64_t off, uint64_t len, uint32_t side,
			    const struct kgenome_func *first)
{
	struct mutation_feed *f = user;
	uint32_t k;

	(void)first;
	for (k = 0; k < KGENOME_MUTATION_NORM_COUNT; k++)
		if (f->norms & (1u << k))
			kof_mutation_unit(f->pc, f->mask, k, side,
					f->p + off, len);
	return 0;
}

/*
 * EVERY UNIT OF AN OBJECT, region by region - the one list both the scanner's
 * feed (for a block declared "anywhere") and a tool's table of candidate blocks
 * are made from, so a row in the viewer is a unit the scanner will sketch and
 * the viewer decides nothing about which regions or which cut. The regions are
 * the parse's, except the ones that are not hashed - a header describes the
 * object rather than being part of what it does, and the symbol regions are not
 * bytes of the file at all. A parse with no regions is one region, ALL.
 */
struct obj_units {
	kof_scan_unit_fn fn;
	void *user;
	uint32_t mask;
	int stopped;
};

static int obj_unit_cb(void *user, uint64_t off, uint64_t len, uint32_t side,
		       const struct kgenome_func *first)
{
	struct obj_units *u = user;

	u->stopped = u->fn(u->user, u->mask, off, len, side, first) != 0;
	return u->stopped;
}

/*
 * WHICH REGIONS "ANYWHERE IN THE OBJECT" COVERS - the one test, asked by the
 * tool's list of units (kof_scan_mutation_units) and by the scanner's feed
 * (kof_scan_mutation_feed), so a row the viewer shows is a unit the scanner
 * credits as ALL. Not hashed: a header, the symbol halves, a static library's
 * tail (kof_parser_region_unoffered); and a region the parse does not have.
 */
static int region_in_all(const struct kof_parser *fp, uint32_t rm,
			 uint32_t present)
{
	return (present & rm) && !(rm & kof_parser_region_unoffered(fp));
}

static int has_regions(const struct kof_parser *fp)
{
	return fp && fp->regions && fp->n_regions && fp->region_name;
}

static int is_region_of(const struct kof_parser *fp, uint32_t m)
{
	uint32_t i;

	for (i = 0; i < fp->n_regions; i++)
		if (fp->regions[i] == m)
			return 1;
	return 0;
}

void kof_scan_mutation_units(const struct kof_obj_ctx *ctx, kof_buf b,
			   uint32_t present, const struct kgenome_func_set *funcs,
			   const struct kgenome_true_all *lib, struct kof_ext_buf *eb,
			   kof_scan_unit_fn fn, void *user)
{
	const struct kof_parser *fp = kof_parser_of(ctx->format);
	struct obj_units u;
	uint32_t ri, n;

	if (!b.p || !fn)
		return;
	u.fn = fn;
	u.user = user;
	u.stopped = 0;
	if (!has_regions(fp)) {
		struct kof_range whole;

		whole.off = 0;
		whole.len = b.n;
		u.mask = KOF_SCAN_ALL;
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = b.p,
				.n_obj = b.n,
				.format = ctx->format,
				.mask = KOF_SCAN_ALL,
				.ext = &whole,
				.n_ext = 1,
				.funcs = funcs,
				.lib = lib,
				.fn = obj_unit_cb,
				.user = &u,
			});
		return;
	}
	for (ri = 0; ri < fp->n_regions; ri++) {
		uint32_t rm = fp->regions[ri];

		if (!region_in_all(fp, rm, present))
			continue;
		u.mask = rm;
		n = kof_scan_resolve_range(ctx, rm, eb);
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = b.p,
				.n_obj = b.n,
				.format = ctx->format,
				.mask = rm,
				.ext = eb->v,
				.n_ext = n,
				.funcs = funcs,
				.lib = lib,
				.fn = obj_unit_cb,
				.user = &u,
			});
		if (u.stopped)
			return;
	}
}

void kof_scan_mutation_feed(struct kof_mutation_ctx *pc, const struct kof_obj_ctx *ctx,
			  kof_buf b, uint32_t present, int from_packer,
			  const struct kgenome_func_set *funcs,
			  const struct kgenome_true_all *lib, struct kof_ext_buf *eb)
{
	const struct kof_parser *fp;
	struct mutation_feed f;
	uint32_t mi;

	if (!pc || !pc->set || !b.p)
		return;
	fp = kof_parser_of(ctx->format);
	f.pc = pc;
	f.p  = b.p;

	/*
	 * WHAT AN UNPACKER PRODUCED IS CUT WHOLE, WITHOUT THE REGION ANCHOR.
	 *
	 * Which region a blob lands in after a rebuild is a property of the
	 * packer, not of the malware - and very often there are no regions at
	 * all, because nothing parses the output. Anchored, every block would
	 * score zero on precisely the object the unpacker was run to produce.
	 * See kof_mutation_any_region.
	 */
	if (from_packer) {
		struct kof_range whole;

		whole.off = 0;
		whole.len = b.n;
		f.mask  = KOF_SCAN_ALL;
		f.norms = kof_mutation_set_norms(pc->set, 0);
		kof_mutation_any_region(pc, 1);
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = b.p,
				.n_obj = b.n,
				.format = 0,
				.mask = KOF_SCAN_ALL,
				.ext = &whole,
				.n_ext = 1,
				.funcs = NULL,
				.lib = NULL,
				.fn = mutation_feed_unit,
				.user = &f,
			});
		return;
	}

	/*
	 * EACH REGION IS CUT AND SKETCHED ONCE, AND CREDITED TO EVERY MASK IT
	 * COUNTS FOR.
	 *
	 * A region's units are the same bytes whether a block names the region
	 * or says "anywhere" (KOF_SCAN_ALL): the cut depends on the format, the
	 * region and the functions, never on which block is asking. The two
	 * used to be two passes - the region under its own mask, and again as
	 * part of ALL through kof_scan_mutation_units - and the window
	 * hashing, which is the cost, ran twice per normalizer.
	 *
	 * Now one pass credits the mask set (own region | ALL): a block counts
	 * an entry when its scan_mask meets the set (mtn_credit_run), and an entry
	 * is one bit of its block's state, set once per object, so crediting two
	 * masks in one pass is the same fact as two passes. The normalizers are those of the
	 * masks named, which set_norms already unions per bit.
	 *
	 * KOF_SCAN_ALL is "wherever in the object", not "every byte": it covers
	 * the regions of the parse except the ones that are not hashed - see
	 * region_in_all. A parse with no regions is one region, ALL.
	 */
	if (!has_regions(fp)) {
		uint32_t n;

		f.mask  = KOF_SCAN_ALL;
		f.norms = kof_mutation_set_norms(pc->set, KOF_SCAN_ALL);
		if (f.norms) {
			n = kof_scan_resolve_range(ctx, KOF_SCAN_ALL, eb);
			kgenome_mutation_units(&(const struct kgenome_mutation_req){
					.p = b.p,
					.n_obj = b.n,
					.format = ctx->format,
					.mask = KOF_SCAN_ALL,
					.ext = eb->v,
					.n_ext = n,
					.funcs = funcs,
					.lib = lib,
					.fn = mutation_feed_unit,
					.user = &f,
				});
		}
		fp = NULL;
	}
	for (mi = 1; mi < 16u + (fp ? fp->n_regions : 0u); mi++) {
		uint32_t m, own = 0, an = 0, n;

		if (mi < 16u) {
			m = 1u << mi;
			own = kof_mutation_set_norms(pc->set, m);
		} else {
			/* A region of the parse that is none of the sixteen
			 * masks: it is fed for ALL and for nothing else. */
			m = fp->regions[mi - 16u];
			if (m < (1u << 16))
				continue;
		}
		if (!(present & m))
			continue;
		if (fp && is_region_of(fp, m) && region_in_all(fp, m, present))
			an = kof_mutation_set_norms(pc->set, KOF_SCAN_ALL);
		f.mask  = (own ? m : 0u) | (an ? KOF_SCAN_ALL : 0u);
		f.norms = own | an;
		if (!f.norms)
			continue;
		n = kof_scan_resolve_range(ctx, m, eb);
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = b.p,
				.n_obj = b.n,
				.format = ctx->format,
				.mask = m,
				.ext = eb->v,
				.n_ext = n,
				.funcs = funcs,
				.lib = lib,
				.fn = mutation_feed_unit,
				.user = &f,
			});
	}
}

/*
 * DOES THIS FEED READ THE OBJECT'S FUNCTIONS AT ALL.
 *
 * Only a region that is cut a function at a time (kgenome_mutation_by_function) does,
 * and only when some block would be credited from it: under the region's own
 * mask or as ALL. Anything else is cut from the bytes alone, so the functions
 * - which on a stripped ELF cost an entry walk of the whole code - are not
 * asked for. Same walk of regions as kof_scan_mutation_feed, so the answer
 * cannot say "no" where the feed would have used them.
 */
static int feed_wants_funcs(const struct kof_mutation_set *set,
			    const struct kof_obj_ctx *ctx, uint32_t present)
{
	const struct kof_parser *fp = kof_parser_of(ctx->format);
	uint32_t i;

	if (!set || !has_regions(fp))
		return 0;
	for (i = 0; i < fp->n_regions; i++) {
		uint32_t rm = fp->regions[i];

		if (!(present & rm) || !kgenome_mutation_by_function(ctx->format, rm))
			continue;
		if ((rm < (1u << 16) && kof_mutation_set_norms(set, rm)) ||
		    (region_in_all(fp, rm, present) &&
		     kof_mutation_set_norms(set, KOF_SCAN_ALL)))
			return 1;
	}
	return 0;
}

int sx_mutation_loaded(const struct kof_scanner *sc)
{
	return sc->eng && sc->eng->mutation && sc->mutation.set;
}

void sx_mutation_feed(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			   uint32_t present, int from_packer)
{
	kof_buf b;

	if (!sc->eng->mutation || !sc->mutation.set)
		return;
	/*
	 * A NORMALISED VIEW IS FED ON ITS OWN BYTES, like any object.
	 *
	 * Its headers describe the file before the padding came out, so its
	 * functions cannot be read from them (oc_funcs is NULL for it) and
	 * its library is already moved to the SLIB regions, which are not
	 * hashed. What is cut from it is what the bytes hold: string clusters
	 * and pieces. The parent is fed as well - the view is known only after
	 * the detectors have run - so a block can be met in either.
	 */
	b = kof_src_buf(sc->cur.src);
	/* What the matcher's state may take is what the object's ledger has left on top of
	 * what it already holds for this object; it is charged below, once the feed has run. */
	kof_mutation_limit(&sc->mutation, kof_mutation_held(&sc->mutation) + oc_scan_room(sc));
	kof_scan_mutation_feed(&sc->mutation, ctx, b, present, from_packer,
			     (!from_packer &&
			      feed_wants_funcs(sc->mutation.set, ctx, present))
				     ? oc_funcs(ctx) : NULL,
			     sc->cur.lib_ok ? &sc->cur.lib : NULL,
			     kof_scan_ext_buf(sc, 1));
	/* The matcher's counters, read where its bound would be noticed: see
	 * kof_stats.mutation_trunc_objects. The object in hand is counted too. */
	{
		struct kof_mutation_stat ms;

		uint64_t held = kof_mutation_held(&sc->mutation);

		kof_mutation_stat(&sc->mutation, &ms);
		sc->st.mutation_visits = ms.life_visits + ms.visits;
		sc->st.mutation_trunc_objects = ms.life_trunc_objects;
		sc->st.mutation_io_objects = ms.life_io_objects;
		sc->st.mutation_io_bytes = ms.life_io_bytes + ms.io_bytes;
		/* The state the feed grew is the object's: charged to the ledger the way a produced
		 * buffer is, and given back when the next object begins (scan_pipeline.c). */
		if (held > sc->mutation.ledgered) {
			scan_charge(sc, held - sc->mutation.ledgered);
			sc->mutation.ledgered = held;
		}
	}
}

static void sx_multi_prepass(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			  uint32_t present)
{
	const struct kof_engine *e = sc->eng;
	const struct kof_module *arrays[3];
	uint32_t counts[3], a, i, r, b, u;
	struct kof_ext_buf *eb;
	uint32_t swept = 0;

	if (!e->pix_regions || !sc->match.live || !sc->match.pix_ready || !e->n_masks)
		return;

	memset(sc->match.live, 0, KOF_MULTIMATCH_BITS * sizeof *sc->match.live);
	/* What the last object found, forgotten: its table was charged to the ledger as it grew and
	 * was given back when the object began (scan_pipeline.c). */
	kofpix_ctx_begin(&sc->match.pix);
	kofpix_ctx_limit(&sc->match.pix, oc_scan_room(sc));
	memset(sc->match.mask_ok, 0, (size_t)e->n_masks * sizeof *sc->match.mask_ok);

	/*
	 * THE TOTALS ARE ALREADY KNOWN - see kof_engine.live_cap.
	 *
	 * They depend on the format and not on the bytes, so they were summed
	 * when the database was loaded. This is what the walk below used to
	 * compute per object: with 200 000 modules it was 4.16 billion
	 * instructions, 15.4% of the scan, to compare totals against eight.
	 */
	if (e->live_cap && ctx->format < KOF_TARGET_COUNT) {
		const uint32_t *row = e->live_cap +
				      (size_t)ctx->format * KOF_MULTIMATCH_BITS;

		for (b = 0; b < KOF_MULTIMATCH_BITS; b++)
			sc->match.live[b] = row[b];
		goto counted;
	}

	arrays[0] = e->mods; counts[0] = e->n_mods;
	arrays[1] = e->unp;  counts[1] = e->n_unp;
	arrays[2] = e->heur; counts[2] = e->n_heur;

	/*
	 * All three arrays, because all three run against THIS object and share
	 * THIS memo. Counting only detectors would under-report a region that
	 * the unpackers and the rules between them make worth sweeping.
	 *
	 * Counted per REGION rather than per mask: a module naming CODE|DATA
	 * makes both of them worth sweeping, and it is the regions that get
	 * swept.
	 */
	for (a = 0; a < 3; a++) {
		for (i = 0; i < counts[a]; i++) {
			const struct kof_module *m = &arrays[a][i];
			uint32_t bits = 0;

			if (kof_module_precond(m, ctx, ctx->obj_size) !=
			    KOF_PRECOND_OK)
				continue;
			if (m->scan_mask && !(m->scan_mask & present))
				continue;
			for (r = 0; r < m->n_rng; r++) {
				if (m->rng_base + r >= e->n_rng)
					break;
				bits |= e->mask_bits[e->rng_uid[m->rng_base + r]];
			}
			for (b = 0; b < KOF_MULTIMATCH_BITS; b++)
				if (bits & (1u << b))
					sc->match.live[b] += m->n_str;
		}
	}
counted:;

	/*
	 * ONE PASS PER REGION, NOT PER MASK.
	 *
	 * Regions partition the object, so this reads every byte at most once;
	 * the masks that name several of them are answered afterwards by an OR,
	 * which is arithmetic rather than another pass. Keyed on masks instead,
	 * the same corpus swept 2972 MB of a 1704 MB tree - CODE once for CODE
	 * and again for CODE|DATA, DATA three times over.
	 */
	eb = kof_scan_ext_buf(sc, 0);
	for (b = 0; b < KOF_MULTIMATCH_BITS; b++) {
		uint32_t bit = 1u << b;
		uint32_t n_ext;

		/* No table reaches this region, or too few markers are live on it to pay for a pass:
		 * the per-marker path answers it. This is the only place the object gets a say, and it
		 * can only say no. */
		if (!(e->pix_regions & bit) || sc->match.live[b] < KOF_MULTIMATCH_MIN_LIVE)
			continue;
		/*
		 * The symbol halves are not the object's bytes - they are
		 * searched by a second matcher over a buffer this one has never
		 * seen - and KOF_MULTIMATCH_BITS already stops short of them.
		 * A region the object does not have has nothing to sweep, and
		 * counts as swept: it contributes no hits either way.
		 */
		if (!(bit & KOF_SCAN_ALL) && !(bit & present)) {
			swept |= bit;
			continue;
		}
		n_ext = kof_scan_resolve_range(ctx, bit, eb);
		if (!n_ext) {
			swept |= bit;
			continue;
		}
		/*
		 * EVERY PACK'S TABLE FOR THIS REGION, in one pass (kofpix_set), and the region is swept
		 * only when it finished: a sweep that stopped (the object's read bound, a pack that is
		 * shorter than it says, a slice that failed its checksum, a full table of what was found)
		 * has a "not found" that means "not looked", and writing ABSENT from it would be a lost
		 * detection that nothing would report. The region is left unswept and counted; the masks
		 * that name it are answered by the per-marker path, which is exact.
		 */
		{
			uint64_t reads_before = sc->match.pix.n_slice_reads + sc->match.pix.n_pool_reads;

			sc->st.multi_bytes += kofpix_sweep(e->pix_set, &sc->match.pix, b, &sc->match.m,
							   eb->v, n_ext);
			sc->st.multi_passes++;
			sc->st.multi_reads += sc->match.pix.n_slice_reads + sc->match.pix.n_pool_reads - reads_before;
		}
		if (sc->match.pix.last) {
			sc->st.multi_degraded++;
			continue;
		}
		swept |= bit;
	}
	/* What the table of found markers grew to is the object's, like any produced buffer. */
	{
		uint64_t held = kofpix_ctx_held(&sc->match.pix);

		if (held > sc->match.pix_ledgered) {
			scan_charge(sc, held - sc->match.pix_ledgered);
			sc->match.pix_ledgered = held;
		}
	}

	/*
	 * Now the masks, from what the sweeps found.
	 *
	 * A mask is answerable only when every region it names that THIS OBJECT
	 * HAS was swept - otherwise "found in none of them" is not a fact about
	 * the object, it is a fact about which passes ran, and writing ABSENT
	 * from it would be a lost detection that nothing would report. A region
	 * the object lacks is not a gap: it has no bytes to hide a marker in.
	 */
	for (u = 0; u < e->n_masks; u++) {
		uint32_t bits = e->mask_bits[u];

		if (!bits || (bits & KOF_SCAN_SYM))
			continue;
		if (bits & ~(KOF_SCAN_ALL | ((1u << KOF_MULTIMATCH_BITS) - 1u)))
			continue;
		if (bits & present & ~swept)
			continue;
		if (!(bits & KOF_SCAN_ALL) && !(bits & present))
			continue;
		if ((bits & KOF_SCAN_ALL) && !(swept & KOF_SCAN_ALL))
			continue;
		/*
		 * RECORDED, NOT DISTRIBUTED. The mask is answerable; which
		 * markers are present stays in the sweep's table of found
		 * markers until something asks (c_find_str). Handing every
		 * marker its answer in advance cost 67 million memo cells for
		 * nine hundred searches at 200,000 rules.
		 */
		sc->match.mask_ok[u] = 1;
	}
}

/*
 * THE TWO BATCHED PASSES, ON FIRST ASK.
 *
 * Both were called unconditionally at the top of sx_scan_object. They are called
 * from the three module loops now - detectors, heuristics and unpackers - by
 * the first module in each that declares it needs one. See the note on
 * kof_scanner.multi_ready for what that buys and why a declaration is the
 * right test.
 *
 * Idempotent and cheap to ask twice: the flag is the whole guard, so a loop
 * can call it per module without thinking about which module came first.
 */
void sx_need_multi(struct kof_scanner *sc, struct kof_obj_ctx *ctx)
{
	if (sc->obj.latch[KOF_OL_MULTI])
		return;
	sc->obj.latch[KOF_OL_MULTI] = 1;
	sx_multi_prepass(sc, ctx, sc->cur.present);
}

void sx_need_mutation(struct kof_scanner *sc, struct kof_obj_ctx *ctx)
{
	if (sc->obj.latch[KOF_OL_MUTATION])
		return;
	sc->obj.latch[KOF_OL_MUTATION] = 1;
	sx_mutation_feed(sc, ctx, sc->cur.present, sc->cur.from_packer);
}
