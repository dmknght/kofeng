/*
 * scan_feed.c - the shared work done once per object before modules are asked:
 * the similarity feeds and the multi-pattern prepass.
 *
 * need_* are the lazy entry points; each runs its feed at most once per object
 * (sc->latch), so the cost is paid by the first module that needs it and by nobody
 * that does not.
 */

#define _GNU_SOURCE

#include "../kofcore/kofdebug.h"
#include "scan_int.h"
#include "objctx_int.h"
#include "../detectors/pattern/kofpix.h"
#include "../analyzers/parsers/kofformat.h"
#include "../analyzers/cfgsign.h"
#include "../analyzers/parsers/scripts/script_route.h"
#include <celllysis/script_islands.h>
#include <stdlib.h>
#include <string.h>


/*
 * Count every declared similarity block against this object, once.
 *
 * THE OBJECT IS CUT INTO UNITS THE WAY A BLOCK WAS CUT - kgenome_mutation_units is the
 * one cut, for the tool that makes a block and for this - and each unit is
 * sketched and credited. One pass per region that some block asked
 * for, and no pass at all otherwise: the set is NULL unless a pack carried
 * blocks, so a database without mutation rules does not reach this, and
 * kof_mutation_set_asks answers whether a region is asked for.
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
	uint32_t mask;
	int asks;
	const uint8_t *p;
	const struct kof_obj_ctx *ctx;
	kof_buf b;
#if 0 /* DISABLED by the owner 2026-11-15 (CFG): the ledger of a function unit's CFG signature; re-enable with mutation_feed_func */
	const struct kof_cfgsign_host *cfg;
#endif
	uint32_t n_units;       /* DEBUG: how many units the pass sketched, and their bytes */
	uint64_t n_bytes;
	uint32_t n_nosig;       /* function units listed and not signed (KGENOME_MUTATION_SIG_NONE: CFG signing disabled by the owner 2026-11-15) */
	struct kgenome_mutation_tally tally;    /* what the cut left out of the function region(s): said on the object (KOF_MTN_S_FUNC_DROPPED) */
};

/*
 * DISABLED by the owner 2026-11-15: CFG and its hash are not used by the scan or the viewer; kept for re-enable.
 * To re-enable: take this #if 0 out, the call in mutation_feed_unit below, the `cfg` members of struct mutation_feed and struct kof_scan_cut and sx_feed_cut's ledger set-up (all in #if 0), with kof_cfgsign_function (analyzers/cfgsign.c), kof_mutation_cfg_unit (kofmutation.c) and kgenome_mutation_signature answering KGENOME_MUTATION_SIG_CFG.
 * The code below is inside #if 0 (it holds comments, and C block comments do not nest).
 */
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
/*
 * A FUNCTION UNIT is signed by the shape of its function - kof_cfgsign_function, the one place a function is decoded for a
 * graph - and the sketch is credited to the blocks of the region by the matcher's second scoring kind (kof_mutation_cfg_unit: containment
 * is not what a CFG sketch means, the Jaccard of two sketches is). The window sketch of a function unit is not computed any more (measured
 * ineffective, exp_cfg/report.md). A CFG block is region CODE, norm RAW. A unit below the
 * floor is met, counted and said (KOF_MTN_S_FUNC_UNSIGNED), not scored.
 */
static int mutation_feed_func(struct mutation_feed *f, uint64_t len, uint32_t side, const struct kgenome_func *first)
{
	struct kof_cfgsign cs;
	struct kof_cfgsign_req rq;
	/*
	 * BUG FIX (2026-11-06, CFG-CRASH-1): kof_scan_mutation_feed is also called OUTSIDE a live
	 * scan (kv_mutation.c's mtn_rescore, re-running the engine's own matcher on screen to show
	 * a real score - by design, see that function's own header) with a ctx kofviewer built
	 * through kof_inspect_identify, which never sets ctx->priv: kof_scan_of(ctx) then answers
	 * NULL, and the three lines below used to dereference it unconditionally (->obj.diag.walk
	 * directly, oc_funcs/oc_frames internally) - segfault on every object with a function,
	 * every redraw. kof_cfgsign_function and kgenome_frame_of_extent already treat a NULL
	 * wk/fs/frames as "nothing to reuse, decode fresh" (checked: no other caller relies on
	 * these being non-NULL), so the degraded answer here is correct, not just crash-free.
	 */
	struct kof_scanner *sc = kof_scan_of(f->ctx);

	if (!f->asks)
		return 0;       /* no block asked for this region's bytes: nothing a CFG sketch could be credited to */
	memset(&rq, 0, sizeof rq);
	rq.ctx = f->ctx;
	rq.data = f->b;
	rq.off = first->off;
	rq.len = first->len;
	rq.host = f->cfg;
	if (sc) {
		rq.wk = sc->obj.diag.walk;              /* the table's decode, read and not made again */
		rq.fs = oc_funcs(f->ctx);               /* the unit is an entry of the table: its frame is the object's, made once for every reader */
		rq.frames = oc_frames(f->ctx);
	}
	if (kof_cfgsign_function(&rq, &cs) != KOF_CFGSIGN_SIGNED) {
		if (!f->n_nosig++)
			kof_mutation_note_unsigned(f->pc);
		return 0;
	}
	f->n_cfg++;
	kof_mutation_cfg_unit(f->pc, f->mask, side, &cs.sign, len);
	return 0;
}
#endif /* DISABLED by the owner 2026-11-15 (CFG) */

static int mutation_feed_unit(void *user, uint64_t off, uint64_t len, uint32_t side,
			    const struct kgenome_func *first)
{
	struct mutation_feed *f = user;

	/* A FUNCTION UNIT HAS NO SIGNATURE (KGENOME_MUTATION_SIG_NONE): met, counted and said on the object (KOF_MTN_S_FUNC_UNSIGNED, kof_stats.mutation_unsigned_objects),
	 * scores nothing (a CFG block a pack carries holds 0), and nothing is decoded for it. */
	if (kgenome_mutation_signature(first) == KGENOME_MUTATION_SIG_NONE) {
		if (f->asks && !f->n_nosig++)
			kof_mutation_note_unsigned(f->pc);
		return 0;
	}
	/* DISABLED by the owner 2026-11-15: the CFG signing of a function unit. To re-enable: take this #if 0 out with mutation_feed_func's above. */
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
	if (kgenome_mutation_signature(first) == KGENOME_MUTATION_SIG_CFG)
		return mutation_feed_func(f, len, side, first);
#endif /* DISABLED by the owner 2026-11-15 (CFG) */
	f->n_units++;
	f->n_bytes += len;
	if (f->asks)
		kof_mutation_unit(f->pc, f->mask, side, f->p + off, len);
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

static int has_regions(const struct kof_obj_ctx *ctx, const struct kof_parser *fp)
{
	return fp && fp->regions && fp->n_regions && fp->region_name && !kof_obj_regionless(ctx);
}

static int is_region_of(const struct kof_parser *fp, uint32_t m)
{
	uint32_t i;

	for (i = 0; i < fp->n_regions; i++)
		if (fp->regions[i] == m)
			return 1;
	return 0;
}

/*
 * THE SIMILARITY CUT OF A SCRIPT IS ITS ISLANDS (owner, 2026-11-14: "island lấy từ engine"; design points 1, 2, 7), read from the one
 * product (objctx_diag.c's script_parts: the function table and the islands from one lex) and never lexed again here. It used to resolve
 * its own extents (sx_resolve_script_islands, a lex per call) into the caller's range buffer, which a tool's fixed buffer cut with
 * nothing said (SP-16): the product is allocated to what the file holds and has no cap.
 *
 * WHICH LEVEL IS FED, AND WHY ONE IS ENOUGH. A window is eight bytes rolled over a unit (mutation.h), so every window of a unit inside
 * an island is a window of the island; the level-0 islands' windows are a SUPERSET of the level-1 units' and of the content pieces the
 * cut made of a page before (script_remainder). A block scores by containment over the whole object (kof_mutation_unit credits the
 * object, not the unit), so a block made from a function, from a run or from a whole piece is found by the level-0 feed, and feeding
 * level 1 as well would hash the same windows a second time. So a signature need not record its level for the matcher: the level is the
 * generator's choice of unit (both are offered, kof_scan_mutation_units), and the matcher reads the superset. No pack record moved.
 *
 * A context with no live scan (kofexaminer, kofviewer) builds the product itself (kof_script_parts_build) and frees it; one whose
 * language has no lexer, or whose islands the ledger refused, is one unit, the whole object, as a script with no islands always was.
 */
struct script_cut {
	struct kgenome_script_parts own;        /* the product built here, for a context with no live scan */
	const struct kgenome_script_islands *isl;
};

static void script_cut_begin(const struct kof_obj_ctx *ctx, kof_buf b, struct script_cut *c)
{
	memset(c, 0, sizeof *c);
	if (ctx->format != KOF_FMT_SCRIPT || !kof_script_textual_lang(ctx->subtype) || !b.p || !b.n)
		return;
	if (kof_scan_of(ctx)) {
		c->isl = oc_script_islands(ctx);
		return;
	}
	kof_script_parts_build(ctx, b.p, b.n, KGENOME_SCRIPT_PART_ISLANDS | KGENOME_SCRIPT_PART_CLIENT, &c->own);
	if (c->own.isl.status == KGENOME_OK)
		c->isl = &c->own.isl;
}

static void script_cut_end(struct script_cut *c)
{
	kgenome_script_parts_free(&c->own);
}

/*
 * ONE (LAYER, LEVEL) OF THE ISLANDS AS UNITS: each island is one unit whole - handed to the cut as the extent AND the function that
 * fills it, so the cut neither cuts it by content nor finds a remainder in it - with the name of its function when it is one
 * (kof_func_name). `skip_same`: a level-1 island that is its whole level-0 island (a piece with no function) is not offered twice.
 * Memory for the two tables is transient, the island count of one level (at most the object's bytes).
 */
struct script_level_req {
	const struct kgenome_script_islands *isl;
	const struct kgenome_func_set *server_funcs;    /* the layer's function table, for a FUNC island's name */
	uint32_t layer, level;
	int skip_same;
	kgenome_mutation_unit_fn fn;
	void *user;
	struct kgenome_mutation_tally *tally;
};

static void script_level(const struct kof_obj_ctx *ctx, kof_buf b, const struct kof_scan_cut *cut, const struct script_level_req *rq)
{
	const struct kgenome_script_islands *isl = rq->isl;
	const uint32_t layer = rq->layer, level = rq->level;
	const int skip_same = rq->skip_same;
	const struct kgenome_func_set *server_funcs = rq->server_funcs;
	const struct kgenome_script_isl_list *L = &isl->lv[layer][level];
	const struct kgenome_func_set *fs = layer == KGENOME_SCRIPT_ISL_SERVER ? server_funcs : &isl->client_funcs;
	struct kgenome_func_set units;
	struct kof_range *ext;
	uint32_t i, n = 0;

	if (!L->n)
		return;
	ext = malloc((size_t)L->n * sizeof *ext);
	units.v = calloc((size_t)L->n, sizeof *units.v);
	if (!ext || !units.v) {
		free(ext);
		free(units.v);
		if (kof_scan_of(ctx))
			oc_scan_limit(kof_scan_of(ctx));
		return;
	}
	for (i = 0; i < L->n; i++) {
		const struct kgenome_script_island *e = &L->v[i];
		struct kgenome_func *u = &units.v[n];

		if (skip_same && e->parent < isl->lv[layer][0].n && isl->lv[layer][0].v[e->parent].off == e->off &&
		    isl->lv[layer][0].v[e->parent].len == e->len)
			continue;
		ext[n].off = e->off;
		ext[n].len = e->len;
		u->off = e->off;
		u->len = e->len;
		u->kind = KGENOME_FN_SCRIPT;
		u->end_source = KGENOME_FN_E_SCRIPT;
		if (e->kind == KGENOME_SCRIPT_ISL_FUNC && fs && e->func < fs->n) {
			u->name_off = fs->v[e->func].name_off;
			u->name_len = fs->v[e->func].name_len;
			u->flags = fs->v[e->func].flags;
		}
		n++;
	}
	units.n = n;
	units.status = KGENOME_OK;
	if (n)
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = b.p,
				.n_obj = b.n,
				.format = ctx->format,
				.mask = KOF_SCAN_ALL,
				.ext = ext,
				.n_ext = n,
				.funcs = &units,
				.lib = cut->lib,
				.fixed = cut->fixed,
				.n_fixed = cut->n_fixed,
				.fn = rq->fn,
				.user = rq->user,
				.tally = rq->tally,
			});
	free(ext);
	free(units.v);
}

/* The whole object, one extent: a parse with no regions and no islands. */
static uint32_t whole_range(kof_buf b, struct kof_ext_buf *eb)
{
	eb->v[0].off = 0;
	eb->v[0].len = b.n;
	return b.n ? 1u : 0u;
}

void kof_scan_mutation_units(const struct kof_obj_ctx *ctx, kof_buf b, uint32_t present,
			   const struct kof_scan_cut *cut, struct kof_ext_buf *eb,
			   kof_scan_unit_fn fn, void *user)
{
	static const struct kof_scan_cut none;
	const struct kof_parser *fp = kof_parser_of(ctx->format);
	struct obj_units u;
	uint32_t ri, n;

	if (!b.p || !fn)
		return;
	if (!cut)
		cut = &none;
	u.fn = fn;
	u.user = user;
	u.stopped = 0;
	if (!has_regions(ctx, fp)) {
		/*
		 * BUG FIX 2026-11-10: this used to resolve "the whole object" by hand
		 * (whole.off=0, whole.len=b.n), the same whole-buffer answer for every
		 * script regardless of its own tag bytes - kof_scan_resolve_range's own
		 * script-island exclusion (scan_ext.c, Merge 161) never reached
		 * kofexaminer --blocks, kofviewer's own Blocks table, or either of
		 * THIS function's own engine-side callers (scan_norm.c, scan_explain.c),
		 * only the real scanner's separate similarity feed
		 * (kof_scan_mutation_feed) did. Now both read the object's one island table
		 * (script_cut_begin, island package 2026-11-14), so this and kof_scan_mutation_feed
		 * cannot drift apart on it a second time.
		 */
		struct script_cut sc_cut;

		u.mask = KOF_SCAN_ALL;
		script_cut_begin(ctx, b, &sc_cut);
		if (sc_cut.isl) {
			/* a script: BOTH levels of each layer are offered (design point 1: the generator chooses the level a block is made from) */
			uint32_t layer, level;

			for (layer = 0; layer < KGENOME_SCRIPT_ISL_LAYERS && !u.stopped; layer++)
				for (level = 0; level < 2u && !u.stopped; level++) {
					const struct script_level_req lq = { .isl = sc_cut.isl, .layer = layer, .level = level,
									     .server_funcs = kof_scan_of(ctx) ? oc_funcs(ctx) : &sc_cut.own.funcs,
									     .skip_same = level == 1u, .fn = obj_unit_cb, .user = &u };

					script_level(ctx, b, cut, &lq);
				}
			script_cut_end(&sc_cut);
			return;
		}
		script_cut_end(&sc_cut);
		n = whole_range(b, eb);
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = b.p,
				.n_obj = b.n,
				.format = ctx->format,
				.mask = KOF_SCAN_ALL,
				.ext = eb->v,
				.n_ext = n,
				.funcs = cut->funcs,
				.lib = cut->lib,
				.fixed = cut->fixed,
				.n_fixed = cut->n_fixed,
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
				.funcs = cut->funcs,
				.lib = cut->lib,
				.fixed = cut->fixed,
				.n_fixed = cut->n_fixed,
				.fn = obj_unit_cb,
				.user = &u,
			});
		if (u.stopped)
			return;
	}
}

void kof_scan_mutation_feed(struct kof_mutation_ctx *pc, const struct kof_obj_ctx *ctx,
			  kof_buf b, uint32_t present, int from_packer,
			  const struct kof_scan_cut *cut, struct kof_ext_buf *eb)
{
	static const struct kof_scan_cut none;
	const struct kof_parser *fp;
	struct mutation_feed f;
	uint32_t mi;

	if (!pc || !pc->set || !b.p)
		return;
	if (!cut)
		cut = &none;
	fp = kof_parser_of(ctx->format);
	f.pc = pc;
	f.p  = b.p;
	f.ctx = ctx;
	f.b = b;
	f.n_units = 0;
	f.n_bytes = 0;
	f.n_nosig = 0;
	memset(&f.tally, 0, sizeof f.tally);
	KOF_TRACE("[feed] format %u, %s, %llu byte(s), present %x, from_packer %d\n", (unsigned)ctx->format,
		  has_regions(ctx, fp) ? "parsed regions" : "no regions (one region, ALL)", (unsigned long long)b.n,
		  (unsigned)present, from_packer);

	/*
	 * WHAT AN UNPACKER PRODUCED IS SCORED WITHOUT THE REGION ANCHOR, through the SAME cut every
	 * other object uses below.
	 *
	 * Which region a blob lands in after a rebuild is a property of the packer, not of the
	 * malware, so a from_packer object's matches are not anchored to one declared region
	 * (kof_mutation_any_region) - a block built from a non-packed reference still scores on an
	 * unpacked child whatever region the rebuild put it in. THE CUT ITSELF IS NOT SPECIAL-CASED:
	 * the has_regions/per-region pass below already reads the object's own format and function
	 * table when it has them (cut->funcs, from oc_funcs) and falls back to one whole-object pass
	 * when it does not (most layers: a formatless shellcode body with no header at all). A
	 * hand-rolled pass here that forced format 0 and no functions on EVERY from_packer object -
	 * including one that parsed as a real format, msf_xor_00's reconstructed ELF child of rc4_1 -
	 * cut it a different way than the per-function cut its matching, non-packed reference sample
	 * (cleartext) was signed with, and it scored 0 against a hash-identical signature (measured;
	 * see rc4_1 in the sample set, and kofexaminer --blocks against trojan_meter_msf-execution_01).
	 */
	if (from_packer)
		kof_mutation_any_region(pc, 1);

	/*
	 * EACH REGION IS CUT AND SKETCHED ONCE, AND CREDITED TO EVERY MASK IT
	 * COUNTS FOR.
	 *
	 * A region's units are the same bytes whether a block names the region
	 * or says "anywhere" (KOF_SCAN_ALL): the cut depends on the format, the
	 * region and the functions, never on which block is asking. The two
	 * used to be two passes - the region under its own mask, and again as
	 * part of ALL through kof_scan_mutation_units - and the window
	 * hashing, which is the cost, ran twice.
	 *
	 * Now one pass credits the mask set (own region | ALL): a block counts
	 * an entry when its scan_mask meets the set (mtn_credit_run), and an entry
	 * is one bit of its block's state, set once per object, so crediting two
	 * masks in one pass is the same fact as two passes. Whether a block asked is that of the
	 * masks named, which set_asks already unions per bit.
	 *
	 * KOF_SCAN_ALL is "wherever in the object", not "every byte": it covers
	 * the regions of the parse except the ones that are not hashed - see
	 * region_in_all. A parse with no regions is one region, ALL.
	 */
	if (!has_regions(ctx, fp)) {
		uint32_t n;

		f.mask  = KOF_SCAN_ALL;
		f.asks = kof_mutation_set_asks(pc->set, KOF_SCAN_ALL);
		if (f.asks) {
			struct script_cut sc_cut;

			script_cut_begin(ctx, b, &sc_cut);
			if (sc_cut.isl) {
				/* a script: level 0 of each layer, the superset of every level's windows (see script_cut_begin) */
				uint32_t layer;

				for (layer = 0; layer < KGENOME_SCRIPT_ISL_LAYERS; layer++) {
					const struct script_level_req lq = { .isl = sc_cut.isl, .server_funcs = oc_funcs(ctx), .layer = layer,
									     .fn = mutation_feed_unit, .user = &f, .tally = &f.tally };

					script_level(ctx, b, cut, &lq);
				}
			} else {
				n = whole_range(b, eb);
				kgenome_mutation_units(&(const struct kgenome_mutation_req){
						.p = b.p,
						.n_obj = b.n,
						.format = ctx->format,
						.mask = KOF_SCAN_ALL,
						.ext = eb->v,
						.n_ext = n,
						.funcs = cut->funcs,
						.lib = cut->lib,
						.fixed = cut->fixed,
						.n_fixed = cut->n_fixed,
						.fn = mutation_feed_unit,
						.user = &f,
						.tally = &f.tally,
					});
			}
			script_cut_end(&sc_cut);
		}
		fp = NULL;
	}
	for (mi = 1; mi < 16u + (fp ? fp->n_regions : 0u); mi++) {
		uint32_t m, n;
		int own = 0, an = 0;

		if (mi < 16u) {
			m = 1u << mi;
			own = kof_mutation_set_asks(pc->set, m);
		} else {
			/* A region of the parse that is none of the sixteen
			 * masks: it is fed for ALL and for nothing else. */
			m = fp->regions[mi - 16u];
			if (m < (1u << 16))
				continue;
		}
		/* KNOWN DEFECT DF-7 (2026-10-30, M) [sev H]: a region that is not in `present` is skipped here although ALL is credited from every region of the parse (the comment above says so); `present` holds only regions some block names (see DF-8).
		 * Trigger: a PE with a block in its overlay (region ALL, even with another block naming PE_DATA). Effect: never fed, never scored; the same bytes in .data score. [cause Inference: the overlay bit is not in scan_mask, not run]
		 * Reproducer: /mnt/games/normtest/fix_detacc2_fmt/defects/df_repro.c (prints "DF-7 REPRODUCED").
		 * Fix: as DF-8, plus the regions a block of ALL is credited from must be resolved for the object, overlay and unclaimed tail included. */
		if (!(present & m))
			continue;
		if (fp && is_region_of(fp, m) && region_in_all(fp, m, present))
			an = kof_mutation_set_asks(pc->set, KOF_SCAN_ALL);
		f.mask  = (own ? m : 0u) | (an ? KOF_SCAN_ALL : 0u);
		f.asks = own || an;
		KOF_TRACE("[feed] region %x credited as %x, asked %d\n", (unsigned)m, (unsigned)f.mask, f.asks);
		if (!f.asks)
			continue;
		n = kof_scan_resolve_range(ctx, m, eb);
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = b.p,
				.n_obj = b.n,
				.format = ctx->format,
				.mask = m,
				.ext = eb->v,
				.n_ext = n,
				.funcs = cut->funcs,
				.lib = cut->lib,
				.fixed = cut->fixed,
				.n_fixed = cut->n_fixed,
				.fn = mutation_feed_unit,
				.user = &f,
				.tally = &f.tally,
			});
	}
	kof_mutation_note_dropped(pc, f.tally.lib, f.tally.outside);
	KOF_TRACE("[feed] done: %u unit(s) sketched, %llu byte(s), %u function unit(s) unsigned (" KGENOME_MUTATION_SIG_NONE_WHY ")\n", (unsigned)f.n_units, (unsigned long long)f.n_bytes, (unsigned)f.n_nosig);
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
 *
 * A REGIONLESS OBJECT (kof_obj_regionless: every script the lib lexes, PHP included) has no
 * `fp->n_regions` to walk - kof_scan_mutation_feed's own "no regions" branch credits it as ALL
 * unconditionally, not by asking region_in_all of anything - so the answer here has to be the
 * same single question kgenome_mutation_by_function(ctx->format, KOF_SCAN_ALL) is for every other
 * regionless format, or this always answered no for a script and oc_funcs was never called
 * (confirmed 2026-11-05 on a real kofexaminer --blocks run before this line existed: the engine's
 * own funcs_of was unreachable for any script no matter what kgenome_mutation_by_function said).
 */
static int feed_wants_funcs(const struct kof_mutation_set *set,
			    const struct kof_obj_ctx *ctx, uint32_t present)
{
	const struct kof_parser *fp = kof_parser_of(ctx->format);
	uint32_t i;

	if (!set)
		return 0;
	if (!has_regions(ctx, fp))
		return kgenome_mutation_by_function(ctx->format, KOF_SCAN_ALL) &&
		       kof_mutation_set_asks(set, KOF_SCAN_ALL);
	for (i = 0; i < fp->n_regions; i++) {
		uint32_t rm = fp->regions[i];

		if (!(present & rm) || !kgenome_mutation_by_function(ctx->format, rm))
			continue;
		if ((rm < (1u << 16) && kof_mutation_set_asks(set, rm)) ||
		    (region_in_all(fp, rm, present) &&
		     kof_mutation_set_asks(set, KOF_SCAN_ALL)))
			return 1;
	}
	return 0;
}

int sx_mutation_loaded(const struct kof_scanner *sc)
{
	return sc->eng && sc->eng->mutation && sc->mutation.set;
}

/*
 * WHAT THE CUT IS TOLD ABOUT THE OBJECT IN HAND - the one place it is made, for the feed above and for the report that locates a block
 * (scan_explain.c): the object's functions when some block would be credited from a region cut a function at a time, its library, the
 * units a producer cut already.
 */
void sx_feed_cut(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, uint32_t present,
		 struct kof_scan_cut *cut)
{
	cut->funcs = feed_wants_funcs(sc->mutation.set, ctx, present)
			     ? oc_funcs(ctx) : NULL;
	cut->lib = sc->cur.lib_ok ? &sc->cur.lib : NULL;
	cut->fixed = kof_src_fixed_of(sc->cur.src, &cut->n_fixed);
	/* DISABLED by the owner 2026-11-15: the ledger a function unit's CFG signature was made under. To re-enable: take this #if 0 out with mutation_feed_func's. */
#if 0 /* DISABLED by the owner 2026-11-15 (CFG) */
	sc->cfgsign.mem.alloc = oc_cfg_alloc;
	sc->cfgsign.mem.release = oc_cfg_release;
	sc->cfgsign.mem.user = sc;
	cut->cfg = &sc->cfgsign;
#endif /* DISABLED by the owner 2026-11-15 (CFG) */
}

void sx_mutation_feed(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			   uint32_t present, int from_packer)
{
	struct kof_scan_cut cut;
	kof_buf b;

	if (!sc->eng->mutation || !sc->mutation.set) {
		KOF_TRACE("[feed] NOT RUN: %s\n", !sc->eng->mutation ? "the engine has no similarity set (no block in any pack or form)"
								       : "this scanner has no matcher state");
		return;
	}
	/*
	 * A NORMALISED VIEW IS FED ON ITS OWN BYTES, like any object.
	 *
	 * Its headers describe the file before the padding came out, so its
	 * functions cannot be read from them (oc_funcs is NULL for it) and
	 * its library is already moved to the SLIB regions, which are not
	 * hashed. What is cut from it is what the bytes hold: string clusters
	 * and pieces - except the units the decode rewrote, which are the
	 * parent's and are given whole (cut.fixed). The parent is fed as well - the
	 * view is known only after the detectors have run - so a block can be met
	 * in either.
	 */
	b = kof_src_buf(sc->cur.src);
	/* The regions the feed may credit are `present`, which holds only the regions in kof_engine.scan_mask: a block
	 * whose region is not in it is never fed (the run1 defect). */
	KOF_TRACE("[feed] present=%x scan_mask=%x from_packer=%d bytes=%llu\n", (unsigned)present, (unsigned)sc->eng->scan_mask,
		  from_packer, (unsigned long long)b.n);
	/* What the matcher's state may take is what the object's ledger has left on top of
	 * what it already holds for this object; it is charged below, once the feed has run. */
	kof_mutation_limit(&sc->mutation, kof_mutation_held(&sc->mutation) + oc_scan_room(sc));
	sx_feed_cut(sc, ctx, present, &cut);
	sc->st.work_feeds++;
	KOF_TRACE("[work] similarity feed #%llu of this scanner (objects so far %llu): the object's windows are hashed now\n",
		  (unsigned long long)sc->st.work_feeds, (unsigned long long)sc->st.objects);
	kof_scan_mutation_feed(&sc->mutation, ctx, b, present, from_packer, &cut,
			     kof_scan_ext_buf(sc, 1));
	/* The matcher's counters, read where its bound would be noticed: see
	 * kof_stats.mutation_trunc_objects. The object in hand is counted too. */
	{
		struct kof_mutation_stat ms;

		uint64_t held = kof_mutation_held(&sc->mutation);

		kof_mutation_stat(&sc->mutation, &ms);
		KOF_TRACE("[feed] matcher state: status %x, %u chunk(s), %u touched, %llu visit(s), %llu probe(s), %llu byte(s) held\n",
			  (unsigned)ms.status, (unsigned)ms.n_chunks, (unsigned)ms.touched, (unsigned long long)ms.visits,
			  (unsigned long long)ms.probes, (unsigned long long)ms.state_bytes);
		sc->st.mutation_visits = ms.life_visits + ms.visits;
		sc->st.mutation_trunc_objects = ms.life_trunc_objects;
		sc->st.mutation_io_objects = ms.life_io_objects;
		sc->st.mutation_unsigned_objects = ms.life_unsigned_objects;
		sc->st.mutation_dropped_objects = ms.life_dropped_objects;
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
	const struct kof_module *arrays[2];
	uint32_t counts[2], a, i, r, b, u;
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

	/*
	 * Both arrays, because both run against THIS object and share THIS memo.
	 * Counting only detectors would under-report a region that the unpackers
	 * make worth sweeping.
	 *
	 * Counted per REGION rather than per mask: a module naming CODE|DATA
	 * makes both of them worth sweeping, and it is the regions that get
	 * swept.
	 */
	for (a = 0; a < 2; a++) {
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
 * from the module loops now - detectors and unpackers - by the first module in
 * each that declares it needs one. See the note on
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
	KOF_TRACE("[feed] first ask for the similarity counts of this object (format %u, present %x)\n", (unsigned)ctx->format,
		  (unsigned)sc->cur.present);
	sc->obj.latch[KOF_OL_MUTATION] = 1;
	sx_mutation_feed(sc, ctx, sc->cur.present, sc->cur.from_packer);
}
