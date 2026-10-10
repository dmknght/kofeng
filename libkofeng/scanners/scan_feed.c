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
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include <celllysis/xref.h>
#include "../analyzers/trueline/trueline.h"
#include "../kofcore/kofmod/elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"
#include "../analyzers/normalize/executables.h"
#include "scan_int.h"


/*
 * Count every declared similarity block against this object, once.
 *
 * THE OBJECT IS CUT INTO UNITS THE WAY A BLOCK WAS CUT - kof_plague_units is the
 * one cut, for the tool that makes a block and for this - and each unit is
 * sketched and credited. One pass per (region, normalizer) that some block asked
 * for, and no pass at all otherwise: the set is NULL unless a pack carried
 * blocks, so a database without plague rules does not reach this, and
 * kof_plague_set_norms answers which normalizers a region needs.
 *
 * BEFORE ANY MODULE, for the reason sx_multi_prepass runs first: a rule's
 * kof_plague_score has to be a division rather than a search, and the only way
 * to make it one is to have counted already.
 *
 * THE FUNCTIONS AND THE LIBRARY ARE THE PARSE'S - see kof_scanner.cur_lib - and
 * a normalised view is fed on its own bytes: see sx_plague_feed.
 */
struct plague_feed {
	struct kof_plague_ctx *pc;
	uint32_t mask, norms;
	const uint8_t *p;
};

static int plague_feed_unit(void *user, uint64_t off, uint64_t len, uint32_t side,
			    const struct kof_func *first)
{
	struct plague_feed *f = user;
	uint32_t k;

	(void)first;
	for (k = 0; k < KOF_PLAGUE_NORM_COUNT; k++)
		if (f->norms & (1u << k))
			kof_plague_unit(f->pc, f->mask, k, side,
					f->p + off, len);
	return 0;
}

/* A unit of whichever region it lies in, credited as ALL: f->mask stays ALL. */
static int plague_feed_any(void *user, uint32_t region, uint64_t off,
			   uint64_t len, uint32_t side, const struct kof_func *first)
{
	(void)region;
	return plague_feed_unit(user, off, len, side, first);
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
		       const struct kof_func *first)
{
	struct obj_units *u = user;

	u->stopped = u->fn(u->user, u->mask, off, len, side, first) != 0;
	return u->stopped;
}

void kof_scan_plague_units(const struct kof_obj_ctx *ctx, kof_buf b,
			   uint32_t present, const struct kof_func_set *funcs,
			   const struct kof_true_all *lib, struct kof_range *ext,
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
	if (!fp || !fp->regions || !fp->n_regions || !fp->region_name) {
		struct kof_range whole;

		whole.off = 0;
		whole.len = b.n;
		u.mask = KOF_SCAN_ALL;
		kof_plague_units(b.p, b.n, ctx->format, KOF_SCAN_ALL, &whole, 1,
				 funcs, lib, obj_unit_cb, &u);
		return;
	}
	for (ri = 0; ri < fp->n_regions; ri++) {
		uint32_t rm = fp->regions[ri];

		if (kof_plague_region_excluded(fp->region_name(rm)) ||
		    !(present & rm))
			continue;
		u.mask = rm;
		n = kof_scan_resolve_range(ctx, rm, ext);
		kof_plague_units(b.p, b.n, ctx->format, rm, ext, n, funcs, lib,
				 obj_unit_cb, &u);
		if (u.stopped)
			return;
	}
}

void kof_scan_plague_feed(struct kof_plague_ctx *pc, const struct kof_obj_ctx *ctx,
			  kof_buf b, uint32_t present, int from_packer,
			  const struct kof_func_set *funcs,
			  const struct kof_true_all *lib, struct kof_range *ext)
{
	static const uint32_t all_masks[] = {
		KOF_SCAN_ALL, 1u << 1, 1u << 2, 1u << 3, 1u << 4, 1u << 5,
		1u << 6, 1u << 7, 1u << 8, 1u << 9, 1u << 10, 1u << 11,
		1u << 12, 1u << 13, 1u << 14, 1u << 15
	};
	const struct kof_parser *fp;
	struct plague_feed f;
	size_t mi;

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
	 * See kof_plague_any_region.
	 */
	if (from_packer) {
		struct kof_range whole;

		whole.off = 0;
		whole.len = b.n;
		f.mask  = KOF_SCAN_ALL;
		f.norms = kof_plague_set_norms(pc->set, 0);
		kof_plague_any_region(pc, 1);
		kof_plague_units(b.p, b.n, 0, KOF_SCAN_ALL, &whole, 1, NULL, NULL,
				 plague_feed_unit, &f);
		return;
	}

	for (mi = 0; mi < sizeof all_masks / sizeof all_masks[0]; mi++) {
		uint32_t mask = all_masks[mi];
		uint32_t n;

		f.mask  = mask;
		f.norms = kof_plague_set_norms(pc->set, mask);
		if (!f.norms)
			continue;
		/*
		 * A region the parse does not have is not fed, and that is the
		 * same answer as a region with nothing in it - see the note on
		 * plague_score in kofsig.h about why a rule cannot tell them
		 * apart and must not try.
		 */
		if (mask != KOF_SCAN_ALL && !(present & mask))
			continue;
		/*
		 * KOF_SCAN_ALL IS "WHEREVER IN THE OBJECT", NOT "EVERY BYTE".
		 *
		 * A block declared over the whole file has no region to anchor
		 * it, so it is looked for in the units of every region the
		 * parse has except the ones that are not hashed - a header
		 * describes the object rather than being part of what it does,
		 * and the symbol regions are not bytes of the file at all. The
		 * units are those of the region they lie in, credited as ALL.
		 */
		if (mask == KOF_SCAN_ALL && fp && fp->regions && fp->n_regions &&
		    fp->region_name) {
			kof_scan_plague_units(ctx, b, present, funcs, lib, ext,
					      plague_feed_any, &f);
			continue;
		}
		n = kof_scan_resolve_range(ctx, mask, ext);
		kof_plague_units(b.p, b.n, ctx->format, mask, ext, n, funcs, lib,
				 plague_feed_unit, &f);
	}
}

void sx_plague_feed(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			   uint32_t present, int from_packer)
{
	kof_buf b;

	if (!sc->eng->plague || !sc->plague.set)
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
	b = kof_src_buf(sc->cur_src);
	kof_scan_plague_feed(&sc->plague, ctx, b, present, from_packer,
			     oc_funcs(ctx),
			     sc->cur_lib_ok ? &sc->cur_lib : NULL, sc->ext_gather);
}

void sx_multi_prepass(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			  uint32_t present)
{
	const struct kof_engine *e = sc->eng;
	const struct kof_module *arrays[3];
	uint32_t counts[3], a, i, r, b, u;
	uint32_t swept = 0;

	if (!e->multi || !e->multi->n_pat || !sc->live || !sc->found ||
	    !e->n_masks)
		return;

	memset(sc->live, 0, KOF_MULTIMATCH_BITS * sizeof *sc->live);
	memset(sc->found, 0, (size_t)e->multi->n_pat * sizeof *sc->found);
	if (sc->mask_ok)
		memset(sc->mask_ok, 0, (size_t)e->n_masks * sizeof *sc->mask_ok);

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
			sc->live[b] = row[b];
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
				bits |= e->rng_tab[m->rng_base + r];
			}
			for (b = 0; b < KOF_MULTIMATCH_BITS; b++)
				if (bits & (1u << b))
					sc->live[b] += m->n_str;
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
	for (b = 0; b < KOF_MULTIMATCH_BITS; b++) {
		const struct kof_multimatch *t = &e->multi->tab[b];
		enum kof_multimatch_kind kind = kof_multimatch_pick(t, sc->live[b]);
		uint32_t bit = 1u << b;
		uint32_t n_ext;

		if (kind == KOF_MULTIMATCH_NONE)
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
		n_ext = kof_scan_resolve_range(ctx, bit, sc->ext);
		if (!n_ext) {
			swept |= bit;
			continue;
		}
		sc->st.multi_bytes += kof_multimatch_sweep(e->multi, b, kind,
							   &sc->m, sc->ext,
							   n_ext, sc->found);
		sc->st.multi_passes++;
		if (kind == KOF_MULTIMATCH_WUMANBER)
			sc->st.multi_wumanber++;
		else
			sc->st.multi_hash4++;
		swept |= bit;
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
		uint32_t bits = e->multi->mask_bits[u];

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
		 * markers are present stays in `found` until something asks -
		 * see uid_slot in kofmultimatch.h.
		 *
		 * THE OLD WAY IS STILL THE FALLBACK. Reading the answer needs
		 * uid_slot, and that is an allocation the loader is allowed to
		 * fail. Without it kof_multimatch_answer says "I do not know"
		 * for every marker and each one becomes a search - correct, and
		 * far slower than the sweep it wasted. So when the map is
		 * missing this hands the answers out exactly as it always did.
		 */
		if (sc->mask_ok && e->multi->uid_slot) {
			sc->mask_ok[u] = 1;
		} else {
			sc->st.multi_answers +=
				kof_multimatch_fold(e->multi, &sc->m, u, bits,
						    sc->found, e->n_masks);
		}
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
	if (sc->latch[KOF_OL_MULTI])
		return;
	sc->latch[KOF_OL_MULTI] = 1;
	sx_multi_prepass(sc, ctx, sc->cur_present);
}

void sx_need_plague(struct kof_scanner *sc, struct kof_obj_ctx *ctx)
{
	if (sc->latch[KOF_OL_PLAGUE])
		return;
	sc->latch[KOF_OL_PLAGUE] = 1;
	sx_plague_feed(sc, ctx, sc->cur_present, sc->cur_from_packer);
}
