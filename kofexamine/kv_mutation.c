#define _GNU_SOURCE
#include "kv.h"


/*
 * THE TABLE'S ROWS are units the engine cut - see kof_scan_mutation_units, which
 * the scanner feeds from - so a block made here is a unit the scanner will
 * sketch. A function when the object's symbols (or, with none, its call targets)
 * name them, a content-defined piece or a string cluster otherwise; what touches
 * the static library is cut on its own side.
 */
struct mtn_slot {
	uint32_t mask, n, quota, taken, stride;
	uint64_t bytes, seen;
};

struct mtn_cut {
	struct view *v;
	struct object *o;
	const struct kof_parser *fp;
	struct mtn_slot slot[MTN_MAX_REGION];
	uint32_t n_slot;
};


/* ---- mutation mode: blocks a researcher marked ------------------------------- */



/* Is any block in the list one carried from another sample - which is the only
 * thing the score column has a number for. */
int mtn_kept_any(const struct view *v)
{
	uint32_t i;

	for (i = 0; i < v->ed.dr.n_blk; i++)
		if (v->ed.dr.blk[i].kept)
			return 1;
	return 0;
}

/*
 * WHICH BLOCK COVERS THE BYTE THE MENU WAS OPENED ON.
 *
 * menu_off IS ALREADY A FILE OFFSET, and this used to map it again.
 *
 * Both places that set it - the hex pane's right click and the panel's
 * selection - store view_map(...) of the row they were on, so the conversion
 * from what the pane was showing to where it is in the file has already
 * happened. A block records a file offset too, so the two are directly
 * comparable and there is nothing left to convert.
 *
 * Mapping twice was invisible on the whole object, because a node covering all
 * of it has ONE extent and view_map is then the identity. On a REGION it was
 * not: the file offset went back through that region's runs and came out
 * somewhere no block covers, so "Which mutation block" greyed itself out - the
 * item is offered only when there is an answer - and the feature looked as
 * though it had never been wired up at all.
 *
 * mtn_lit_at goes the other way, from a block's file offset to a place on the
 * screen, and it still needs view_unmap. The two are not symmetric because
 * only one of them starts from something the pane measured.
 *
 * n_blk when nothing covers it, which is most bytes of most objects.
 */
uint32_t mtn_at_byte(const struct view *v)
{
	uint64_t fo = v->menu_off;
	uint32_t i;

	if (fo == KGENOME_BROKEN)
		return v->ed.dr.n_blk;
	for (i = 0; i < v->ed.dr.n_blk; i++) {
		const struct mtn_block *b = &v->ed.dr.blk[i];

		if (b->len && fo >= b->off && fo < b->off + b->len)
			return i;
	}
	return v->ed.dr.n_blk;
}

static uint32_t mtn_mask(const struct mtn_block *b)
{
	return b->anywhere ? (uint32_t)KOF_SCAN_ALL : b->mask;
}

/*
 * Is this REGION offset inside a lit block, and in what colour.
 *
 * Region offsets rather than file offsets because that is what the hex pane
 * walks; a block records the file offsets it was cut from, so the comparison
 * happens in one space after view_unmap. NULL when nothing lit covers it.
 */
const char *mtn_lit_at(const struct view *v, uint64_t rgn_off)
{
	uint32_t i;

	for (i = 0; i < v->ed.dr.n_blk; i++) {
		const struct mtn_block *b = &v->ed.dr.blk[i];
		uint64_t lo;

		if (!b->lit || !b->len)
			continue;
		lo = view_unmap(v, b->off);
		if (lo == KGENOME_BROKEN)
			continue;
		if (rgn_off >= lo && rgn_off < lo + b->len)
			return mtn_colour[b->colour % MTN_COLOURS];
	}
	return NULL;
}

/*
 * Mark the current hex selection as a block.
 *
 * The hashes are taken NOW, from the bytes on screen, so the table can say what
 * the span is worth before the author commits to it. A span that yields eleven
 * hashes cannot be a rule - KGENOME_MUTATION_MIN_HASH is sixteen - and the honest
 * moment to say so is while the selection is still there to widen.
 */
static int mtn_mark(struct view *v, const uint8_t *base, uint64_t base_n,
		    uint64_t lo, uint64_t hi, uint32_t mask, const char *rgn,
		    const char *rgn_enum, uint32_t norm, uint8_t side,
		    const char *sym)
{
	struct mtn_block *b;
	uint64_t len;

	if (v->ed.dr.n_blk >= MTN_MAX_BLOCK || lo >= hi || lo >= base_n)
		return 0;
	len = hi - lo;
	if (len > base_n - lo)
		len = base_n - lo;

	b = &v->ed.dr.blk[v->ed.dr.n_blk];
	memset(b, 0, sizeof *b);
	/* Which half of the object this came from, carried with it from here to
	 * the panel and into the generated rule - see enum kgenome_mutation_side. */
	b->side = side;
	b->off = lo;
	/* Filled below; the duplicate test needs the hashes first - see the
	 * end of this function. */
	b->len = len;
	b->mask = mask;
	snprintf(b->rgn, sizeof b->rgn, "%s", rgn ? rgn : "ALL");
	snprintf(b->rgn_enum, sizeof b->rgn_enum, "%s",
		 rgn_enum ? rgn_enum : "KOF_SCAN_ALL");
	b->norm = (uint8_t)norm;
	if (sym)
		snprintf(b->sym, sizeof b->sym, "%s", sym);
	b->n_hash = kgenome_mutation_minhash(base + lo, len, norm, b->hash);
	if (b->n_hash < KGENOME_MUTATION_MIN_HASH) {
		/*
		 * A SPAN THAT CANNOT BE SCORED IS NOT A BLOCK.
		 *
		 * Listing it with a warning beside it was the first shape and
		 * it filled the table with padding: a run of zeroes is one
		 * distinct window however long it is, and an object's alignment
		 * gaps are most of what a carve produces. The list is what a
		 * reader can choose from, so what cannot be chosen is not in
		 * it.
		 */
		return 0;
	}
	b->id = kof_mutation_fold(b->hash, b->n_hash);
	{
		/*
		 * ONE BLOCK IS ONE ROW.
		 *
		 * Opening an infected file loads the rule that caught it, and
		 * the carve then finds the same span in the sample. Both would
		 * be rows about one block. What counts as the same block is
		 * kof_mutation_same_block's to say - see the note there on why it
		 * is not a comparison of ids.
		 */
		uint32_t d;

		for (d = 0; d < v->ed.dr.n_blk; d++) {
			struct mtn_block *o2 = &v->ed.dr.blk[d];

			if (!kof_mutation_same_block(o2->hash, o2->n_hash,
						   b->hash, b->n_hash))
				continue;
			/*
			 * AND THE ROW THAT IS ALREADY THERE LEARNS WHERE IT IS.
			 *
			 * A block loaded from a rule has no offsets - they
			 * belonged to the sample it was cut from - so its row
			 * showed a size of zero and could not be lit. The carve
			 * has just found it IN THIS FILE, which is the position
			 * it was missing. Its hashes and its score stay what the
			 * rule declared and what was measured against them; only
			 * the place is new.
			 */
			if (!o2->len) {
				o2->off = b->off;
				o2->len = b->len;
				snprintf(o2->rgn, sizeof o2->rgn, "%s",
					 b->rgn);
				snprintf(o2->sym, sizeof o2->sym, "%s", b->sym);
			}
			return 0;
		}
	}
	/* Cycled by position so neighbours never share - see mtn_colour. */
	b->colour = (uint8_t)(v->ed.dr.n_blk % MTN_COLOURS);
	v->ed.dr.n_blk++;
	return 1;
}

/*
 * CARVE THE OBJECT INTO BLOCKS. The engine's half of the job.
 *
 * Content defined boundaries, not fixed sizes: a cut chosen by a rolling hash
 * over the bytes reappears in the same place in a variant that had something
 * inserted before it, and a cut chosen by counting to four kilobytes does not.
 * That is the property the whole mode rests on - a block has to be recognisable
 * in the next sample, and a block whose edges move with every byte inserted
 * ahead of it is not.
 *
 * Per REGION, because a block is a place as much as a span - the region is what
 * a rule anchors to, and a cut that ran across the boundary between code and
 * data would produce a block belonging to neither.
 *
 * NO JUDGEMENT IS MADE HERE. Every block of the object is offered; which of
 * them identifies anything is the question the tick answers, and the one this
 * code is deliberately not qualified to.
 */
/*
 * THE BLOCK SIZES FOLLOW FROM THE SAMPLING RATE, they are not a taste.
 *
 * A block keeps the smallest KGENOME_MUTATION_MINHASH_K of its windows, so any span
 * of 23 varying bytes or more yields KGENOME_MUTATION_MIN_HASH of them and a large
 * one yields the same count. A run of padding is one window repeated and
 * collapses to a single distinct value however long it is.
 */
/*
 * THE SAME LIBRARY THE ENGINE WILL SEE - see lib_facts in the scanner.
 *
 * Not a convenience. The panel carves blocks and shows which side of enum
 * kgenome_mutation_side each one is on, and the engine decides that again when it
 * scores the rule that comes out. If the two worked the library out
 * differently, a block ticked here as the author's would be scored there as the
 * library's and the rule would match nothing - with nothing on screen to say
 * why.
 *
 * So the rule is stated once, in the same words: the marker tier only of a
 * STATIC build, because on a dynamic one its span runs between strings that are
 * the program's own, and the symbol tier of everything.
 */

static void obj_lib_find(const struct object *o, struct kgenome_true_all *out)
{
	const struct kgenome_elf_info *e;

	memset(out, 0, sizeof *out);
	if (!o || !o->info || o->ctx.format != KOF_FMT_ELF)
		return;
	if (!o->buf.p || !o->buf.n)
		return;
	e = (const struct kgenome_elf_info *)o->info;
	/* One place picks the tier - see kgenome_true_find_object. */
	kgenome_true_find_object(o->buf, e, out);
}

static struct mtn_slot *mtn_slot_of(struct mtn_cut *c, uint32_t mask)
{
	uint32_t i;

	for (i = 0; i < c->n_slot; i++)
		if (c->slot[i].mask == mask)
			return &c->slot[i];
	if (c->n_slot >= MTN_MAX_REGION)
		return NULL;
	memset(&c->slot[c->n_slot], 0, sizeof c->slot[0]);
	c->slot[c->n_slot].mask = mask;
	return &c->slot[c->n_slot++];
}

static int mtn_count_cb(void *user, uint32_t mask, uint64_t off, uint64_t len,
			uint32_t side, const struct kgenome_func *first)
{
	struct mtn_slot *s = mtn_slot_of(user, mask);

	(void)off; (void)side; (void)first;
	if (s) {
		s->n++;
		s->bytes += len;
	}
	return 0;
}

/* Rows per region: see the note in mtn_segment. */
static void mtn_share(struct mtn_cut *c, uint32_t format)
{
	uint32_t i, used = 0, left, big = 0;
	uint64_t total = 0;

	for (i = 0; i < c->n_slot; i++) {
		struct mtn_slot *s = &c->slot[i];

		if (kgenome_mutation_by_function(format, s->mask)) {
			s->quota = s->n;
			continue;
		}
		s->quota = 1;
		used++;
		total += s->bytes;
		if (s->bytes > c->slot[big].bytes ||
		    kgenome_mutation_by_function(format, c->slot[big].mask))
			big = i;
	}
	left = MTN_DATA_BLOCKS > used ? MTN_DATA_BLOCKS - used : 0u;
	for (i = 0; i < c->n_slot && total; i++)
		if (!kgenome_mutation_by_function(format, c->slot[i].mask))
			c->slot[i].quota += (uint32_t)
				((uint64_t)left * c->slot[i].bytes / total);
	if (total) {
		uint32_t sum = 0;

		for (i = 0; i < c->n_slot; i++)
			if (!kgenome_mutation_by_function(format, c->slot[i].mask))
				sum += c->slot[i].quota;
		if (sum < MTN_DATA_BLOCKS)
			c->slot[big].quota += MTN_DATA_BLOCKS - sum;
	}
	for (i = 0; i < c->n_slot; i++) {
		struct mtn_slot *s = &c->slot[i];

		s->stride = s->quota && s->n > s->quota
			  ? (s->n + s->quota - 1u) / s->quota : 1u;
	}
}

static int mtn_take_cb(void *user, uint32_t mask, uint64_t off, uint64_t len,
		       uint32_t side, const struct kgenome_func *first)
{
	struct mtn_cut *c = user;
	struct mtn_slot *s = mtn_slot_of(c, mask);
	const char *rn, *lbl;
	char sym[sizeof ((struct mtn_block *)0)->sym];

	if (c->v->ed.dr.n_blk >= MTN_MAX_BLOCK)
		return 1;
	if (!s || s->taken >= s->quota || s->seen++ % s->stride)
		return 0;
	s->taken++;
	rn = (c->fp && c->fp->region_name && mask != KOF_SCAN_ALL)
	   ? c->fp->region_name(mask) : NULL;
	lbl = rn ? kof_region_label(rn) : "ALL";
	kof_sym_name_at(c->o->sym, c->o->sym_n, first ? first->value : 0,
		    first ? (int)first->shndx : -1, sym, sizeof sym);
	mtn_mark(c->v, c->o->buf.p, c->o->buf.n, off, off + len, mask, lbl, rn,
		 KGENOME_MUTATION_RAW, (uint8_t)side, sym);
	return 0;
}

/*
 * The object's functions, built once - see kgenome_diag_funcs_of. A normalised view
 * has no headers to build them from, so they are its parent's, found again in
 * its bytes: the same kgenome_funcs_remap the scanner maps them with when it makes
 * the view, so the table lists the units the scanner will sketch.
 */
const struct kgenome_func_set *mtn_funcs(struct view *v, struct object *o)
{
	if (!o->funcs_done) {
		o->funcs_done = 1;
		if (o->n_rgn) {
			const struct object *anc[MAX_OBJ];
			uint32_t n = obj_ancestors(v, o, anc, MAX_OBJ);

			if (n) {
				struct object *par = &v->obj[anc[n - 1u] - v->obj];

				struct kgenome_obj pobj;

				kof_genome_obj(&par->ctx, &pobj);
				kgenome_diag_funcs_of_view(&pobj, par->buf,
						       mtn_funcs(v, par), o->buf,
						       &o->funcs);
			}
		} else {
			struct kgenome_obj gobj;

			kof_genome_obj(&o->ctx, &gobj);
			kgenome_diag_funcs_of(&gobj, o->buf.p, o->buf.n, &o->funcs);
		}
	}
	return &o->funcs;
}

void mtn_segment(struct view *v)
{
	struct object *o = cur_obj(v);
	const struct kof_parser *fp;
	uint32_t keep = 0, i;
	struct mtn_cut cut;
	struct kgenome_true_all lib;

	/*
	 * TICKED BLOCKS ARE CARRIED, everything else is carved again.
	 *
	 * Moving to another sample is the measurement: the blocks chosen on the
	 * first one are fed to the second, and the score column finally says
	 * something other than a hundred. What is not ticked was the engine's
	 * suggestion about the object being left behind and has no business in
	 * a list about this one.
	 */
	for (i = 0; i < v->ed.dr.n_blk; i++) {
		if (!v->ed.dr.blk[i].picked)
			continue;
		blk_moved(&v->ed, i, keep);
		v->ed.dr.blk[keep] = v->ed.dr.blk[i];
		v->ed.dr.blk[keep].kept = 1;
		v->ed.dr.blk[keep].lit = 0;   /* its offsets are another file's */
		v->ed.dr.blk[keep].off = 0;
		v->ed.dr.blk[keep].len = 0;   /* so mtn_mark can learn where it is HERE */
		keep++;
	}
	v->ed.dr.n_blk = keep;
	v->mtn_scored = 0;
	if (!o || !o->buf.p || !o->buf.n || !v->ext2)
		return;
	/*
	 * A NORMALISED VIEW HAS ITS BLOCKS TOO: the scanner feeds it on its own
	 * bytes - see sx_mutation_feed - so the rows here are the units it will
	 * sketch. Its functions are its parent's, found again in its bytes
	 * (mtn_funcs); it has no library to place, the library having been moved
	 * to regions that are not offered.
	 */
	/*
	 * WHAT THIS OBJECT'S CARVE PRODUCED LAST TIME - see object.carve. Only
	 * when nothing is ticked, which is when the answer is identical.
	 */
	if (!keep && o->carve_done && o->carve) {
		for (i = 0; i < o->n_carve && v->ed.dr.n_blk < MTN_MAX_BLOCK;
		     i++)
			v->ed.dr.blk[v->ed.dr.n_blk++] = o->carve[i];
		/*
		 * AND THEIR SCORES CAME WITH THEM, which is not a shortcut.
		 * A block carved from this object scores a hundred on it BY
		 * CONSTRUCTION - every hash came out of these bytes, see the
		 * note on mtn_block.score - so re-running the matcher over the
		 * whole object would be measuring an arithmetic certainty.
		 * Only ever taken when nothing is ticked, so every row here is
		 * this object's own carve and there is nothing else in the
		 * table to have a real number.
		 */
		v->mtn_scores_known = 1;
		return;
	}
	/*
	 * THE REGION VOCABULARY, NOT THE OBJECT'S PARSER, and here the two are
	 * not the same thing.
	 *
	 * `fp` is used for one purpose in this function - naming a region bit,
	 * to label a block and to ask whether that region is excluded from
	 * hashing at all. A normalised view has no parser and its bits are the
	 * parent's, so taking o->fmt gave NULL: every block came out labelled
	 * "ALL", and kof_mutation_region_excluded was never consulted, so the
	 * regions that are deliberately not hashed were hashed.
	 */
	fp = obj_region_vocab(o);
	/* Where the library is, so no block is cut from it - see the note in
	 * the carve loop. Empty for anything that is not an ELF, and for an ELF
	 * this cannot place a library in, which is the same answer: cut
	 * nothing. */
	memset(&lib, 0, sizeof lib);
	/* Not on a view - its segment offsets are the parent's and are stale;
	 * see the same test where the scoring set is built. */
	if (!o->n_rgn)
		obj_lib_find(o, &lib);

	/*
	 * THE UNITS ARE THE ENGINE'S - kof_scan_mutation_units, the list the scanner
	 * feeds from - and so are the regions they come from and which of them are
	 * left out. What is the viewer's is only the size of the table: counted
	 * first, then every region gets a row for existing and a share of the rest
	 * by its bytes, the remainder to the largest, so a 3.85 MB CODE cannot
	 * leave DATA without a row. A region offered a function at a time keeps a
	 * row per unit. A region with more units than rows offers every n-th: the
	 * cut is the scanner's and does not move to fit a table. The ticked rows
	 * are not in the sum, so ticking one never moves where the next begins.
	 */
	memset(&cut, 0, sizeof cut);
	cut.v = v; cut.o = o; cut.fp = fp;
	{
		struct kof_ext_buf eb = kof_ext_fixed(v->ext2, KOF_SCAN_MAX_EXTENTS);
		const struct kof_scan_cut basis = { mtn_funcs(v, o), &lib, o->fixed, o->n_fixed };

		kof_scan_mutation_units(&o->ctx, o->buf, ~0u, &basis, &eb, mtn_count_cb, &cut);
		mtn_share(&cut, o->ctx.format);
		kof_scan_mutation_units(&o->ctx, o->buf, ~0u, &basis, &eb, mtn_take_cb, &cut);
	}
	/*
	 * AND KEPT, so arriving here again costs nothing - see object.carve.
	 * Only the rows this carve produced: a ticked one is the draft's and
	 * travels with it, not with the object.
	 */
	if (!keep && !o->carve_done) {
		o->carve_done = 1;
		if (v->ed.dr.n_blk) {
			o->carve = malloc(v->ed.dr.n_blk * sizeof *o->carve);
			if (o->carve) {
				memcpy(o->carve, v->ed.dr.blk,
				       v->ed.dr.n_blk * sizeof *o->carve);
				o->n_carve = v->ed.dr.n_blk;
			} else {
				o->carve_done = 0;   /* no room: ask again */
			}
		}
	}

}

/*
 * Score every marked block against the object on screen.
 *
 * THROUGH THE ENGINE'S OWN MATCHER, not a second implementation. The set is
 * built from the blocks this view holds and thrown away again - a few hundred
 * hashes, indexed in microseconds - and then fed exactly the way scan.c feeds
 * it: one pass per (region, normalizer) a block asked for, and the region
 * resolved by the object's own parse.
 *
 * That matters more than it sounds. A viewer that computed a percentage its own
 * way would be showing an author a number the engine will not reproduce, and
 * the author would tune a threshold against it. The only defensible number here
 * is one produced by the code that will produce it later.
 *
 * Re-run only when the blocks or the object changed - see mtn_scored_obj.
 */
/*
 * THE SHAPE MEASURE, against the object the panel is showing.
 *
 * It answers the question its matcher asks, with the same call the matcher will
 * make at scan time - so a row that reads 64 is the number the generated rule
 * will see, not an approximation of it. Zero where the draft carries nothing to
 * compare against, which is the state a fresh draft is in.
 */


void mtn_rescore(struct view *v)
{
	struct kgenome_true_all slib;
	struct kof_mutation_block *blk;
	uint32_t *pool;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx ctx;
	struct object *o;
	uint32_t i, j, np = 0, nb = 0;

	if (!v->ed.dr.n_blk || !v->ext2)
		return;
	o = cur_obj(v);
	if (!o || !o->buf.p)
		return;
	/* On the heap: a table of thousands of blocks is megabytes, and the
	 * blocks in it hold at most KOF_MUTATION_MAX_HASH hashes each. */
	blk = malloc((size_t)v->ed.dr.n_blk * sizeof *blk);
	pool = malloc((size_t)v->ed.dr.n_blk * KOF_MUTATION_MAX_HASH * sizeof *pool);
	if (!blk || !pool) {
		free(blk);
		free(pool);
		return;
	}

	for (i = 0; i < v->ed.dr.n_blk; i++) {
		const struct mtn_block *b = &v->ed.dr.blk[i];

		v->ed.dr.blk[i].score = 0;
		/* A block too thin to score is not put in the set: the matcher
		 * refuses one and would refuse the whole set with it. */
		if (b->n_hash < KGENOME_MUTATION_MIN_HASH)
			continue;
		memset(&blk[nb], 0, sizeof blk[nb]);
		blk[nb].first_hash = np;
		blk[nb].n_hash = b->n_hash;
		blk[nb].scan_mask = mtn_mask(b);
		blk[nb].norm = b->norm;
		/* And the side, or a library block would be scored here by
		 * author-code windows and read as a number the engine will
		 * never reproduce - see enum kgenome_mutation_side. */
		blk[nb].side = b->side;
		for (j = 0; j < b->n_hash; j++)
			pool[np++] = b->hash[j];
		nb++;
	}
	if (!nb) {
		free(blk);
		free(pool);
		return;
	}

	/* The set borrows both arrays, so they are released after it is. */
	set = kof_mutation_build(blk, nb, pool, np);
	if (!set) {
		free(blk);
		free(pool);
		return;
	}
	if (!kof_mutation_ctx_init(&ctx, set)) {
		kof_mutation_set_free(set);
		free(blk);
		free(pool);
		return;
	}
	kof_mutation_begin(&ctx);
	/*
	 * THE ENGINE'S OWN FEED, with the library and the functions the engine
	 * would hand it: the number shown here is the one the scanner computes.
	 * Neither on a view - its headers describe its parent, so there is no
	 * library to place and no functions to name; see kgenome_mutation_units.
	 */
	memset(&slib, 0, sizeof slib);
	if (!o->n_rgn)
		obj_lib_find(o, &slib);
	{
		struct kof_ext_buf eb = kof_ext_fixed(v->ext2, KOF_SCAN_MAX_EXTENTS);
		const struct kof_scan_cut basis = { mtn_funcs(v, o), o->n_rgn ? NULL : &slib,
						    o->fixed, o->n_fixed };

		kof_scan_mutation_feed(&ctx, &o->ctx, o->buf, ~0u, 0, &basis, &eb);
	}
	for (i = 0, nb = 0; i < v->ed.dr.n_blk; i++) {
		if (v->ed.dr.blk[i].n_hash < KGENOME_MUTATION_MIN_HASH)
			continue;
		v->ed.dr.blk[i].score = (uint8_t)kof_mutation_pct(&ctx, nb);
		nb++;
	}
	kof_mutation_ctx_done(&ctx);
	kof_mutation_set_free(set);
	free(blk);
	free(pool);
}
