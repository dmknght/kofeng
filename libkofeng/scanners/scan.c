/*
 * scan.c - process objects.
 *
 * One job in three steps, and the order is the point:
 *
 *   parse         format facts, so the filter has something to filter on
 *   derive        which regions exist - paid once for all modules
 *   filter + run  per module, cheapest test first
 *
 * The derive step is InitCache from the old Kaspersky engine: a small per-object
 * precomputation so each of very many records can be decided with one instruction.
 *
 * Producing the objects is here too, because it is the same job seen from one step out.
 * A file becomes one object; a directory yields many. When there is an unpacker, a
 * container will yield many the same way, through the same stack. What is *not* here:
 * the untrusted boundary a module reads through (objctx.c), and how a search is
 * answered (the matcher).
 */

/* lstat and the dirent walk are POSIX and the tree builds as strict ISO C11, so the
 * feature level has to be asked for - and before any include, or it does nothing.
 *
 * _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h (below),
 * whose POSIX branch defines kof_memmem by calling the real memmem - a
 * GNU/BSD extension the compiler must still see declared to compile that
 * inline function, whether or not scan.c itself calls it. _POSIX_C_SOURCE
 * alone does not just omit memmem on glibc, it suppresses it (any of
 * _POSIX_C_SOURCE/_XOPEN_SOURCE defined without _GNU_SOURCE/_DEFAULT_SOURCE
 * opts into strict POSIX). Missed originally because this project's builds
 * so far all ran on Windows, where kof_memmem never touches the real memmem
 * - a real Linux build fails immediately with "implicit declaration of
 * function 'memmem'". _GNU_SOURCE is a superset of _POSIX_C_SOURCE 200809L,
 * so nothing else this file relied on changes. */
#define _GNU_SOURCE

#include "scan.h"
#include "objtree.h"
#include "../detector/matchers/kofmultimatch.h"
#include "../detector/heur/kofheur.h"
/* The rule ABI: the phase ids and what a rule may ask the engine for. The
 * engine-side model next door is a different file with a similar name - see the
 * note at the top of kofmod/heur.h. */
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzer/parsers/kofformat.h"
#include "../analyzer/disasm/xref.h"
#include "../detector/overlord/koflib.h"
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
#include "../analyzer/normalize/executables.h"

struct kof_scanner *kof_scan_of(const struct kof_obj_ctx *ctx)
{
	return (struct kof_scanner *)(void *)(uintptr_t)ctx->priv;
}

struct kof_scanner *kof_scan_new(const struct kof_engine *eng)
{
	struct kof_scanner *sc = calloc(1, sizeof *sc);

	if (!sc)
		return NULL;
	sc->eng = eng;
	sc->sink_fd = -1;   /* 0 is stdin; calloc would have made this a live fd */

	/* The matcher owns the search state: the presence set and the memo are how a
	 * search is answered, not how a scan is bookkept. */
	if (!kof_match_state_init(&sc->m, eng->n_str, eng->memo_size))
		goto fail;
	/*
	 * The symbol block's matcher: its own presence table, sized for a
	 * block rather than for a file, and no memo.
	 *
	 * 20 bits is 1M slots - 2MB against the file table's 32MB - and the
	 * block is capped at KOF_SYM_MAX_BYTES, a quarter megabyte, so
	 * occupancy stays under a quarter even at the cap and is a fraction of
	 * a percent at the median few kilobytes.
	 *
	 * The threshold is 2 rather than 140 because the arithmetic behind 140
	 * is about a buffer of megabytes: stamping costs one pass, and over a
	 * block this small the second search already pays it back.
	 *
	 * No memo here - c_find_str keeps the cell in sc->m, where the slot is
	 * already allocated by the database. See the note there.
	 */
	sc->msym.gram_bits = 20;
	sc->msym.gram_min = 2;
	if (!kof_match_state_init(&sc->msym, eng->n_str, 0))
		goto fail;

	/*
	 * The similarity counters, when the database brought any blocks.
	 *
	 * Skipped entirely when it did not, which is the common case: no
	 * allocation, and the feed below is never reached because the set is
	 * NULL. A database with no plague rules costs nothing here.
	 */
	if (eng->plague && !kof_plague_ctx_init(&sc->plague, eng->plague))
		goto fail;

	/* One counter per region, and one word per marker for where it was seen.
	 * A failure here is not fatal: the prepass needs both and simply does
	 * not run without them. */
	sc->live = calloc(KOF_MULTIMATCH_BITS, sizeof *sc->live);
	if (eng->multi && eng->multi->n_pat)
		sc->found = calloc(eng->multi->n_pat, sizeof *sc->found);
	return sc;

fail:
	kof_scan_free(sc);
	return NULL;
}

void kof_scan_free(struct kof_scanner *sc)
{
	uint32_t i;

	if (!sc)
		return;
	kof_match_state_free(&sc->m);
	kof_match_state_free(&sc->msym);
	free(sc->live);
	free(sc->found);
	sc->live = NULL;
	sc->found = NULL;
	kof_scan_kids_reset(sc);
	free(sc->kids);
	free(sc->kid_packer);
	free(sc->kid_family);
	/*
	 * KOF_TARGET_COUNT AND NOT KOF_FMT_COUNT.
	 *
	 * The array is the width of the target axis, and event verbs are
	 * numbered in the same space as the file formats - so a loop bounded by
	 * formats freed the file-format views and leaked every event one. It
	 * was one allocation per scanner for AMSI and is now two; the bound
	 * that sizes the array is the bound that must empty it.
	 */
	for (i = 0; i < KOF_TARGET_COUNT; i++)
		free(sc->view[i]);
	free(sc->inf);
	free(sc->lzw);
	free(sc->bz);
	free(sc->lzx);
	kof_plague_ctx_done(&sc->plague);
	free(sc->ovl);
	free(sc->fchain);
	free(sc->lzh);
	kof_xref_free(sc->use);
	free(sc->sym);
	free(sc->pend_syms);
	free(sc->sym_ext[0]);
	free(sc->sym_ext[1]);
	free(sc);
}

const struct kof_stats *kof_scan_stats(const struct kof_scanner *sc)
{
	return &sc->st;
}

/* ---- the byte accessors handed to a module --------------------------------- */

/*
 * Turn a named range into extents.
 *
 * Here rather than in objctx.c because only the parse knows where a region is, and this
 * is the file that ran it. KOF_SCAN_ALL needs no parse at all, which is what lets a
 * module naming only that region run against input nothing identified.
 */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *ctx, uint32_t scan_mask,
				struct kof_range *ext)
{
	uint32_t n;

	if (scan_mask & KOF_SCAN_ALL) {
		ext[0].off = 0;
		ext[0].len = ctx->obj_size;
		return ctx->obj_size ? 1u : 0u;
	}
	if (!ctx->resolve_scan)
		return 0;
	n = ctx->resolve_scan(ctx, scan_mask, ext, KOF_SCAN_MAX_EXTENTS);
	if (n >= KOF_SCAN_MAX_EXTENTS) {
		/*
		 * The region did not fit, so what follows searches part of it.
		 *
		 * Said rather than swallowed. A buffer that filled exactly is
		 * indistinguishable from one that filled and had more to write, and
		 * the two lead to the same place: a search over some of a region,
		 * reported as a search over the region. That is the one answer this
		 * engine must never give quietly, so it is a limit like any other -
		 * the caller set the size, and the caller can be told it bound.
		 */
		struct kof_scanner *sc = kof_scan_of(ctx);

		if (!sc->broken)
			sc->broken = KOF_BROKEN_LIMIT;
		n = KOF_SCAN_MAX_EXTENTS;
	}
	return n;
}

/* ---- deriving per-object facts --------------------------------------------- */

/*
 * Which regions this object has, as a mask of region bits.
 *
 * Computed once per object, not once per module. Resolving a region walks the segment
 * and section tables and sorts the result, so doing it per module would cost more than
 * running the cheap modules it is meant to save. Done once, the per-module test is a
 * single AND.
 */
static uint32_t regions_present(const struct kof_obj_ctx *ctx, uint32_t wanted)
{
	struct kof_range *ext = kof_scan_of(ctx)->ext;
	uint32_t present = 0, bit;

	if (ctx->obj_size)
		present |= KOF_SCAN_ALL;
	if (!ctx->resolve_scan)
		return present;

	/*
	 * Only the regions some module names. A region nobody asks about does not
	 * need an answer, and one of them is a complement - it builds and sorts the
	 * whole claimed set to produce one range.
	 *
	 * Every bit, not the first sixteen. The ceiling used to be 16 because no
	 * format defined a region above bit 7, which made adding one a silent loss:
	 * the region would never be marked present, so the prefilter would skip
	 * every module that named it, and a detection that does not happen is not
	 * something a test notices. Thirty-one masked tests cost nothing.
	 */
	for (bit = 1; bit < 32; bit++) {
		uint32_t m = 1u << bit;

		if (!(wanted & m) || (m & KOF_SCAN_SYM))
			continue;
		if (ctx->resolve_scan(ctx, m, ext, KOF_SCAN_MAX_EXTENTS))
			present |= m;
	}
	return present;
}

/*
 * The same question about the two halves of the symbol block.
 *
 * Separate from the loop above because resolve_scan answers about the FILE, and
 * these are not in it - asked there, a format's resolver would say no to bits it
 * has never heard of and the prefilter would skip every module naming them.
 * Silent, and exactly the loss the note above describes.
 *
 * Still gated on `wanted`, so the block is not built for an object no module
 * asks about - which is nearly all of them.
 */
static uint32_t sym_halves_present(const struct kof_obj_ctx *ctx,
				   uint32_t wanted)
{
	uint32_t n = 0, total, i, present = 0;
	const uint8_t *b;

	if (!(wanted & KOF_SCAN_SYM) || !ctx->content || !ctx->content->syms)
		return 0;
	b = ctx->content->syms(ctx, &n);
	total = kof_sym_count(b, n);
	for (i = 0; i < total && present != KOF_SCAN_SYM; i++) {
		const uint8_t *r = kof_sym_rec(b, n, i);

		if (!r)
			continue;
		present |= (r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED)
			 ? KOF_SCAN_SYM_IMP : KOF_SCAN_SYM_EXP;
	}
	return present & wanted;
}

/*
 * Can this module be ruled out without calling it?
 *
 * Every test reads a field of the module's record against a fact already produced.
 * None touches the blob, which is what makes this a pre-use filter rather than the
 * same conditions written inside the module - those are correct and save nothing,
 * because reaching them costs the call.
 *
 * Absent constraints mean unconstrained, so a module with an empty record runs. The
 * default has to fall that way: over-running costs time, under-running costs
 * detections and would not show up as a failure anywhere.
 */
/*
 * `out` is the per-object result and may be NULL - the unpack pass has no
 * result to fill yet. Passed rather than derived from the stats, because those
 * are cumulative and a per-object number taken by differencing them is wrong
 * the moment two objects are in flight.
 */
static int prefilter(const struct kof_module *m, const struct kof_obj_ctx *ctx,
		     uint32_t present, struct kof_stats *st,
		     struct kof_result *out)
{
	st->considered++;

	/* The declared preconditions, from kof_module_precond - the one place
	 * that applies them. What is left here is only the counting. */
	switch (kof_module_precond(m, ctx, ctx->obj_size)) {
	case KOF_PRECOND_TARGET:  st->by_target++;  return 0;
	case KOF_PRECOND_SIZE:    st->by_size++;    return 0;
	case KOF_PRECOND_ARCH:    st->by_arch++;    return 0;
	case KOF_PRECOND_SUBTYPE: st->by_subtype++; return 0;
	case KOF_PRECOND_OK:      break;
	}
	/* A module that names regions cannot match if none exist here: every search
	 * it performs would be over an empty range. One that names none - scalar
	 * only - has nothing to be excused by, and runs. */
	if (m->scan_mask && !(m->scan_mask & present)) {
		st->by_region++;
		return 0;
	}

	st->ran++;
	if (out)
		out->examined++;
	return 1;
}


/* ---- the multi-pattern prepass ----------------------------------------------------- */

/*
 * Answer every marker of every worthwhile region, before any module runs.
 *
 * WHY THIS IS A SEPARATE PASS AND NOT PART OF THE MODULE LOOP
 *
 * Because the saving is shared. A region's markers are asked about by many
 * modules, and the lazy path reads the region once for each of them; read once
 * for all of them, the cost stops growing with the database. Doing it inside
 * the loop would mean the first module to name a region paid for every other
 * module's markers, which is the same total but attributed to whoever happened
 * to be first - and it would have to happen before that module's own logic
 * ran, which is this function.
 *
 * It writes nothing but memo cells, so it is invisible: a cell means "is this
 * marker in this region mask of this object" and has one answer whoever fills
 * it. kof_match_lookup reads the cell before it does anything else, so a
 * module's calls turn into table reads without knowing it. See find_str in
 * kofmod/kofsig.h, which reserved exactly this.
 *
 * THE PRECONDITIONS ARE EVALUATED TWICE, ON PURPOSE
 *
 * Once here to count what is live, once in the loop below to decide what runs.
 * They are integer comparisons against a record already in cache, and the
 * alternative - a survivor list built here and consumed there - is a second
 * representation of the same decision that could disagree with the first.
 */
/*
 * Count every declared similarity block against this object, once.
 *
 * ONE PASS PER (REGION, NORMALIZER) THAT SOME BLOCK ASKED FOR, and no pass at
 * all otherwise. The set is NULL unless a pack carried blocks, so a database
 * without plague rules does not reach this; within it, kof_plague_set_norms
 * answers which normalizers a region needs, so a pack whose blocks all hash raw
 * bytes pays one pass rather than three.
 *
 * BEFORE ANY MODULE, for the reason multi_prepass runs first: a rule's
 * kof_plague_score has to be a division rather than a search, and the only way
 * to make it one is to have counted already. A rule may then ask about the same
 * block in any order and as often as it likes for nothing.
 */
static void plague_prepass(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			   uint32_t present, int from_packer)
{
	static const uint32_t all_masks[] = {
		KOF_SCAN_ALL, 1u << 1, 1u << 2, 1u << 3, 1u << 4, 1u << 5,
		1u << 6, 1u << 7, 1u << 8, 1u << 9, 1u << 10, 1u << 11,
		1u << 12, 1u << 13, 1u << 14, 1u << 15
	};
	struct kof_range *ext = sc->ext_gather;
	const struct kof_parser *fp;
	kof_buf b;
	size_t mi;

	if (!sc->eng->plague || !sc->plague.set)
		return;
	fp = kof_parser_of(ctx->format);
	kof_plague_begin(&sc->plague);
	b = kof_src_buf(sc->cur_src);
	if (!b.p)
		return;

	/*
	 * THE STATIC LIBRARY OF THIS OBJECT IS NOT HASHED.
	 *
	 * A block cut from libc matches every program that linked the same libc,
	 * so it identifies a toolchain and not a family - see kof_plague_object.
	 * Found here rather than inside the matcher because it needs the parse,
	 * and handed over rather than subtracted from the ranges below because
	 * the ranges are also what the region anchor is expressed in: cutting
	 * holes in them would make a rule's region mean something different for
	 * an object that happens to have a library in it.
	 *
	 * `lib` lives for the rest of this call, which is exactly as long as the
	 * feeds do.
	 */
	/*
	 * AND NOT ON A NORMALISED VIEW, whose segment offsets are its parent's.
	 *
	 * The view is declared as its parent's format, so it parses - but its
	 * headers describe the file before the padding came out, and
	 * kof_lib_find works from markers found inside a loadable SEGMENT.
	 * Given stale offsets it would name spans over the wrong bytes and put
	 * blocks on the wrong side of enum kof_plague_side.
	 *
	 * An object with a declared region table is exactly the one that has
	 * this problem, which is why that is the test.
	 */
	/*
	 * INHERITED FROM THE PARSE - see kof_scanner.cur_lib and lib_facts.
	 *
	 * This used to call kof_lib_find for itself, with its own gate: not on
	 * an object carrying a declared region table, because that is a view
	 * and a view's segment offsets are its parent's. The gate moved into
	 * lib_facts with the answer, where it is stated once and where the
	 * normaliser reads the same one.
	 */
	if (sc->cur_lib_ok)
		kof_plague_object(&sc->plague, b.p,
				  sc->cur_lib.span, sc->cur_lib.n);

	/*
	 * WHAT AN UNPACKER PRODUCED IS FED WHOLE, WITHOUT THE REGION ANCHOR.
	 *
	 * Which region a blob lands in after a rebuild is a property of the
	 * packer, not of the malware - and very often there are no regions at
	 * all, because nothing parses the output. Anchored, every block would
	 * score zero on precisely the object the unpacker was run to produce.
	 * See kof_plague_any_region.
	 *
	 * One pass per normalizer over the whole thing, which is also fewer
	 * passes than the region walk below.
	 */
	if (from_packer) {
		uint32_t norms = kof_plague_set_norms(sc->eng->plague, 0), k;

		kof_plague_any_region(&sc->plague, 1);
		for (k = 0; k < KOF_PLAGUE_NORM_COUNT; k++)
			if (norms & (1u << k))
				kof_plague_feed(&sc->plague,
						(uint32_t)KOF_SCAN_ALL, k,
						b.p, b.n);
		return;
	}

	for (mi = 0; mi < sizeof all_masks / sizeof all_masks[0]; mi++) {
		uint32_t mask = all_masks[mi];
		uint32_t norms = kof_plague_set_norms(sc->eng->plague, mask);
		uint32_t n, i, k;

		if (!norms)
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
		 * it, so the pass that serves it resolves to one extent
		 * covering everything - headers, symbol tables, alignment gaps
		 * and all. A header describes the object rather than being part
		 * of what it does and nothing is ever cut from one, so hashing
		 * it can only produce an accidental match. The symbol regions
		 * are not bytes of the file at all.
		 *
		 * PADDING NEEDS NO RULE HERE, and one was written and taken out
		 * again. A span too poor to yield hashes never became a block,
		 * so nothing in the database is anchored to padding, and a
		 * padding window can only score by colliding with a real
		 * block's hash - which a test on the region would not prevent
		 * anyway. What the test WOULD do is disagree with the carve: a
		 * block cut from a region the test then refuses to feed is a
		 * rule that matches at the moment it is written and never
		 * again. The pipeline already decides this at the step that
		 * takes the hashes; the matcher inherits that decision.
		 */
		if (mask == KOF_SCAN_ALL && fp && fp->regions && fp->n_regions &&
		    fp->region_name) {
			uint32_t ri;

			for (ri = 0; ri < fp->n_regions; ri++) {
				uint32_t rm = fp->regions[ri];
				const char *rn = fp->region_name(rm);

				if (kof_plague_region_excluded(rn))
					continue;
				if (!(present & rm))
					continue;
				n = kof_scan_resolve_range(ctx, rm, ext);
				for (i = 0; i < n; i++) {
					uint64_t off = ext[i].off;
					uint64_t len = kof_clip_len(b.n, off,
								   ext[i].len);

					if (!len)
						continue;
					for (k = 0; k < KOF_PLAGUE_NORM_COUNT;
					     k++)
						if (norms & (1u << k))
							kof_plague_feed(
								&sc->plague,
								mask, k,
								b.p + off, len);
				}
			}
			continue;
		}
		n = kof_scan_resolve_range(ctx, mask, ext);
		for (i = 0; i < n; i++) {
			uint64_t off = ext[i].off;
			uint64_t len = kof_clip_len(b.n, off, ext[i].len);

			if (!len)
				continue;
			for (k = 0; k < KOF_PLAGUE_NORM_COUNT; k++)
				if (norms & (1u << k))
					kof_plague_feed(&sc->plague, mask, k,
							b.p + off, len);
		}
	}
}

static void multi_prepass(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
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
		sc->st.multi_answers +=
			kof_multimatch_fold(e->multi, &sc->m, u, bits,
					    sc->found, e->n_masks);
	}
}

/* ---- naming a finding ------------------------------------------------------ */

/*
 * <target>/<what the author wrote>
 *
 *     ELF-x64/Botnet:Mirai-04gix              (KOF_MALVAR_AUTO)
 *     PE-x86/Hacktool:Meterpreter-Generic     (KOF_MALVAR_GENERIC)
 *     Zip/Exploit:ZipSlip-CVE-2018-1002200    (a custom variant)
 *
 * The target is composed and not authored: it is what the engine established by
 * parsing, so a module cannot claim a format it was not run against or an
 * architecture the object does not have. Everything after the "/" is authored -
 * a type from enum kof_maltype, a family, a variant - which is the part that
 * needs a person, and the "/" marks exactly that boundary: computed fact on the
 * left, human classification on the right.
 *
 * Three different separators past the "/", one per boundary, each chosen not to
 * collide with what a variant already tends to contain: KOF_MALVAR_AUTO's own
 * output and hand written variants like "CVE-2018-1002200" both use "-"
 * internally, so "-" is spent on exactly one boundary (family/variant) and nowhere
 * else, or "Mirai-CVE-2018-1002200" would read as a run of hyphens with no visible
 * structure. ":" separates type from family, matching how a reader already parses
 * "Category: Item" elsewhere; "." is avoided entirely here for the same collision
 * reason "-" is only used once.
 *
 * Format and architecture are one token joined by a dash rather than two parts.
 * They answer one question - what does this run on - and splitting them made every
 * name carry a separator that never told anyone anything.
 *
 * The operating system is absent on purpose. ELF does not say it, so "Linux" would
 * be a guess wearing the clothes of a fact, which is also why this reads "ELF-x64"
 * and not the "Linux/x64" other engines write.
 *
 * An object with no architecture - a script, or one nothing identified - gets the
 * format alone. A "-any" suffix would be a field describing nothing.
 */
/*
 * The one spelling. See kof_name_compose in kofeng.h for why it is a function.
 *
 * "#" between the family and the variant, not "-": a family name may contain a
 * hyphen and several in bases/ do, so the old separator could not be told from
 * the name around it by eye or by anything reading the string back. "#" appears
 * in no family and in no variant.
 */
void kof_name_compose(char *out, size_t cap, const char *target,
		      const char *maltype, const char *family,
		      const char *variant)
{
	int has_t = target && target[0];
	int has_v = variant && variant[0];

	if (!out || !cap)
		return;
	if (has_t && has_v)
		snprintf(out, cap, "%s/%s:%s#%s", target, maltype, family,
			 variant);
	else if (has_t)
		snprintf(out, cap, "%s/%s:%s", target, maltype, family);
	else if (has_v)
		snprintf(out, cap, "%s:%s#%s", maltype, family, variant);
	else
		snprintf(out, cap, "%s:%s", maltype, family);
}

/*
 * Compose onto a finding, and say where each part went.
 *
 * Written once, forward, so the offsets fall out of the writing rather than
 * being searched for afterwards - which is the whole point: nothing downstream
 * should ever have to look for a separator this function just placed.
 */
static void span_put(struct kof_finding *f, struct kof_name_span *sp,
		     size_t *at, const char *text)
{
	size_t n = 0;

	sp->at = (uint16_t)*at;
	if (text)
		while (text[n] && *at + n + 1u < sizeof f->name) {
			f->name[*at + n] = text[n];
			n++;
		}
	sp->n = (uint16_t)n;
	*at += n;
}

static void sep_put(struct kof_finding *f, size_t *at, char c)
{
	if (*at + 1u < sizeof f->name)
		f->name[(*at)++] = c;
}

void kof_finding_name(struct kof_finding *f, const char *target,
		      const char *maltype, const char *family,
		      const char *variant, const char *shape)
{
	size_t at = 0;

	if (!f)
		return;
	f->target.at = f->target.n = 0;
	f->maltype = f->family = f->variant = f->shape = f->target;

	if (target && target[0]) {
		span_put(f, &f->target, &at, target);
		sep_put(f, &at, '/');
	}
	span_put(f, &f->maltype, &at, maltype);
	sep_put(f, &at, ':');
	span_put(f, &f->family, &at, family);
	if (variant && variant[0]) {
		sep_put(f, &at, '#');
		span_put(f, &f->variant, &at, variant);
	}
	if (shape && shape[0]) {
		/*
		 * "!" AND NOT "?".
		 *
		 * The mark says HOW the verdict was reached - a shape a
		 * heuristic recognised, a similarity measurement - and "?"
		 * reads as doubt about the whole name rather than as a label on
		 * the part after it. A reader scanning a log sees
		 * "Heur:Meterp#3!Shellcode" as a finding with its method
		 * attached, where the same line with a question mark reads as
		 * the engine being unsure it found anything.
		 */
		sep_put(f, &at, '!');
		span_put(f, &f->shape, &at, shape);
	}
	f->name[at] = 0;
}

/*
 * "ELF-x64", or "ELF" when there is no architecture to name.
 *
 * An object with no architecture - a script, or one nothing identified - gets
 * the format alone: a "-any" suffix would be a field describing nothing.
 */
void kof_name_target(char *out, size_t cap, uint8_t format, uint8_t arch)
{
	const char *fmt = kof_format_name(format);

	if (arch == KOF_ARCH_ANY || format == KOF_FMT_UNKNOWN)
		snprintf(out, cap, "%s", fmt);
	else
		snprintf(out, cap, "%s-%s", fmt, kof_arch_name(arch));
}

static void finding_str(const struct kof_scanner *sc,
			const struct kof_obj_ctx *ctx,
			const struct kof_module *m, struct kof_finding *f)
{
	const char *variant = kof_db_name(sc->eng, m, sc->rep_name_id);
	const char *family  = kof_db_family(sc->eng, m);
	/*
	 * "Heur" where a maltype would be, for a rule.
	 *
	 * A maltype is a claim about what something DOES - trojan, rootkit,
	 * miner - and a rule has not established one. Writing the word here
	 * rather than adding it to the maltype enum keeps it out of the
	 * vocabulary a signature chooses from, which is what stops a signature
	 * from ever being able to claim it.
	 */
	const char *maltype = m->kind == KOF_PACK_HEUR
			      ? "Heur" : kof_maltype_name(m->maltype);
	char fmtarch[32];

	kof_name_target(fmtarch, sizeof fmtarch, ctx->format, ctx->arch);
	/*
	 * A SIMILARITY VERDICT CARRIES ITS SCORE AND SAYS WHAT IT IS.
	 *
	 * <target>/<type>:<family>#<score>!Plague. The slot that holds a
	 * variant for a pattern rule holds the MEASUREMENT for this one,
	 * because that is what a reader of such a verdict needs: a rule
	 * demanding fifty and a sample scoring eighty-three are different
	 * facts, and the variant a hand-written rule could put there cannot
	 * know either. The mark names the method, exactly as a heuristic's
	 * does - see kof_finding_name.
	 *
	 * ASKED IS NOT THE SAME AS ANSWERED, and reading it as though it were
	 * was a bug with a name on it. sc->plague_asked only says
	 * kof_plague_score was CALLED. A rule written as
	 *
	 *     if (kof_plague_score(blk) >= 50u) ...
	 *     if (kof_find_str_all(rng, s0, s1)) ...
	 *
	 * calls it on every object, so a file that matched the STRING was
	 * named "#<the block>!Plague?0" - a verdict announcing the method
	 * that did not reach it, and a score of nought beside a detection.
	 *
	 * So the block has to have matched something. Not "reached the rule's
	 * threshold", which the engine cannot know - the threshold is a
	 * number in the module's own code - but at least one hash in common.
	 * A rule whose block scored under its threshold while a string
	 * carried the verdict still reports the block's number, and that is
	 * the honest residue: the block did find something, just not enough.
	 */
	if (sc->plague_asked >= 0 && sc->n_plague_blk && sc->plague_hit) {
		char sv[16], shape[16];
		/* The SET's containment - see kof_plague_counts - so a rule
		 * made of two blocks reports how much of both is here rather
		 * than how much of its better half. */
		unsigned pct = sc->plague_tot
			     ? (unsigned)(sc->plague_hit * 100u / sc->plague_tot)
			     : 0u;

		if (pct > 100u)
			pct = 100u;

		/*
		 * <family>#<the blocks>!Plague?<how much of them>.
		 *
		 * The variant names the SET of blocks the rule asked about, not
		 * one of them: a condition may be "block A and block B", and
		 * naming it after whichever scored higher described half the
		 * rule and left the other half unsaid - two rules of one family
		 * that shared a block then reported the same "#83". The name is
		 * the fold of the set (kof_plague_name_of sorts it, so the order
		 * a C expression evaluated the blocks in cannot change it), and
		 * for one block that fold is the block's own name, so a
		 * single-block rule reads exactly as before and leads straight
		 * back to its KOF_PLAGUE_BLOCK line.
		 *
		 * The measurement is the set's too - matched hashes over
		 * declared hashes across every block asked - and moves in behind
		 * the mark, where the rest of the engine already puts what a
		 * verdict is BASED on.
		 */
		/* The number first, then the name made from it - see
		 * kof_finding.sim_pct. */
		f->sim_pct = (uint8_t)pct;
		f->sim_kind = (uint8_t)KOF_SIM_PLAGUE;
		f->sim_of = kof_plague_name_of(sc->plague_blk,
					       sc->n_plague_blk);
		snprintf(sv, sizeof sv, "%08x", f->sim_of);
		snprintf(shape, sizeof shape, "Plague?%u", pct);
		kof_finding_name(f, fmtarch, maltype,
				 (family && family[0]) ? family : "unknown",
				 sv, shape);
		return;
	}
	/*
	 * AND THE SAME FOR A SIMILARITY MEASURE THAT CARRIES ITS OWN
	 * REFERENCE - kof_ovl_strings, kof_ovl_blocks, kof_ovl_chain,
	 * kof_ovl_shape.
	 *
	 * The mark goes BEHIND the variant, where every other method's does,
	 * and not in front of it. It was a prefix on the variant for one
	 * revision - "Ovl-3f2ka" - which put the method inside the field that
	 * names the pattern, so the two could no longer be told apart by
	 * anything reading the name. A variant is a variant; what recognised
	 * it is the shape.
	 *
	 * ASKED AND ANSWERED, as above: a measure that returned nothing did
	 * not reach this verdict and does not get to name it.
	 */
	if (sc->ovl_asked >= 0 && sc->ovl_pct) {
		char shape[16];

		f->sim_pct = (uint8_t)(sc->ovl_pct > 100u ? 100u
							  : sc->ovl_pct);
		f->sim_kind = (uint8_t)KOF_SIM_OVERLORD;
		snprintf(shape, sizeof shape, "Ovl?%u", sc->ovl_pct);
		kof_finding_name(f, fmtarch, maltype,
				 (family && family[0]) ? family : "unknown",
				 variant ? variant : "unknown", shape);
		return;
	}
	kof_finding_name(f, fmtarch, maltype,
			 (family && family[0]) ? family : "unknown",
			 variant ? variant : "unknown", NULL);
}

/* ---- identify -------------------------------------------------------------- */

/*
 * The format table.
 *
 * Each collector answers two questions separately: does this object look like
 * mine, and - once a buffer exists - what does it say. The split is what lets the
 * view be allocated only for formats actually met, and it is why sniff takes no
 * buffer.
 *
 * Order is priority. It matters as soon as two formats can claim one object, and
 * writing it down here is cheaper than discovering it is implied by the order of
 * two if statements somewhere.
 */

/*
 * Decide what the object is and fill the matching view.
 *
 * Nothing is allocated for a format the sniff rejected, and a view once allocated
 * is kept: a directory of ELF binaries allocates one view for the whole walk, and
 * a scanner that never meets a PE never allocates a PE view.
 *
 * An allocation failure leaves the object unidentified rather than failing the
 * scan. That is the same answer an unrecognised format gets, and it is the right
 * one: the object still gets scanned by every module whose target covers unknown.
 */
/*
 * THE RESOLVER FOR AN OBJECT WHOSE REGIONS WERE DECLARED.
 *
 * Same shape as every parser's: a mask in, the ranges that answer it out. The
 * difference is only where the answer comes from - a table the producer filled
 * rather than a walk over headers - and the callers cannot tell, which is the
 * point. A rule naming scan_range_data on a normalised view gets the view's
 * data, at the view's offsets, through the same call it always used.
 */
static uint32_t declared_resolve_scan(const struct kof_obj_ctx *ctx,
				      uint32_t scan_mask, struct kof_range *out,
				      uint32_t max_out)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t i, n = 0;

	if (!sc || !out || !max_out)
		return 0;
	for (i = 0; i < sc->n_cur_rgn && n < max_out; i++) {
		if (!(sc->cur_rgn[i].mask & scan_mask))
			continue;
		/* An empty region is not a range. A parser would not return one
		 * and a matcher asked to search it would search nothing. */
		if (!sc->cur_rgn[i].len)
			continue;
		out[n].off = sc->cur_rgn[i].off;
		out[n].len = sc->cur_rgn[i].len;
		n++;
	}
	return n;
}

static void identify(struct kof_scanner *sc, kof_buf buf, struct kof_obj_ctx *ctx,
		     uint8_t as_format, const void *as_view, uint32_t as_view_len)
{
	const struct kof_parser *parsers;
	uint32_t i, n;

	/*
	 * A FORMAT THE CALLER DECLARED, which is not something any sniff can
	 * answer.
	 *
	 * Every format below is recognised from its bytes. A collected event is
	 * not: a record has no magic, and a submitted script block is a
	 * PowerShell fragment that no file format claims - so a submission
	 * scanned through the sniff chain comes out "unrecognised", and every
	 * rule written about it is filtered out before it runs. That was the
	 * whole gap: the viewer could show the thing and the scanner could not
	 * be told what it was.
	 *
	 * The caller knows. It read the record off a channel or out of a log,
	 * and it is the only side that can know - so it says, and the sniff
	 * chain is skipped rather than consulted and overruled.
	 *
	 * The parse still runs and may still refuse. Being told is not being
	 * right, and a declaration that does not survive its own parser leaves
	 * the object unidentified exactly as a failed sniff would.
	 */
	/*
	 * DECLARED RAW, WHICH IS A CLAIM AND NOT A FORMAT.
	 *
	 * The caller is not saying "this is format 0", it is saying "do not ask
	 * the bytes". The two differ for one producer that matters: a
	 * normalised view still begins with its parent's magic and is no longer
	 * that format, so a sniff gets the right answer to the wrong question.
	 *
	 * Left at KOF_FMT_UNKNOWN, with no parser run, which is what the object
	 * now is - and every rule written for raw still searches it, because
	 * raw is what those rules target.
	 */
	if (as_format == KOF_FMT_DECLARED_RAW)
		return;
	if (as_format) {
		const struct kof_parser *p = kof_parser_of(as_format);

		/*
		 * SAID WHEN THERE IS NOTHING TO PARSE - AND ONLY THEN.
		 *
		 * KOF_FMT_TEXT and KOF_FMT_SCRIPT have no row in the parser
		 * table: there is no header to read and no region to carve, so
		 * there is nothing for a parser to do. For those the id IS the
		 * whole claim, and it matters because ctx->format is what
		 * kof_module_precond tests FIRST - an object left at zero is
		 * offered only to the modules that target unknown, so a
		 * container that knew it had handed over a script got the rules
		 * for a bare blob.
		 *
		 * A FORMAT WITH A PARSER IS DIFFERENT, AND SETTING IT HERE
		 * CRASHED. This was written to set the id unconditionally, on
		 * the argument that failing to read a structure is no reason to
		 * forget what the thing was said to be. True of a claim; false
		 * of this field. A module that targets a format reads that
		 * format's VIEW - kof_pdf(ctx) is a cast of ctx->file_header,
		 * with no null check anywhere, because a module reached for a
		 * format is entitled to assume it was parsed.
		 *
		 * So a declared format whose parse then REFUSES used to leave
		 * the id set and file_header NULL, and the first module to
		 * accept it dereferenced nothing. Reproduced: declare
		 * KOF_FMT_PDF for an /ObjStm - whose decoded form has no %PDF-
		 * header, so the parse correctly refuses - and the scan
		 * segfaults. That is exactly the shape "decide what to parse
		 * from the description" would produce, so it is not a
		 * hypothetical.
		 *
		 * The rule: the id survives a refusal only where a refusal
		 * cannot happen. With a parser present it is set below, after
		 * the parse agreed.
		 */
		if (!p)
			ctx->format = as_format;
		if (p) {
			if (!sc->view[as_format]) {
				sc->view[as_format] = malloc(p->view_size);
				if (!sc->view[as_format])
					return;
			}
			/*
			 * ZEROED EVERY TIME, not once when it was allocated.
			 *
			 * A view is reused across objects, and the sniff path
			 * can do that because each of those parsers fills every
			 * field it later reads. This path cannot: the fields the
			 * CALLER supplies are exactly the ones the parse does
			 * not compute, so a view left as the last object found
			 * it hands this object the last one's answers. That was
			 * the bug - the first event in a run resolved its
			 * regions from a zero extent and every event after it
			 * from the previous event's.
			 */
			memset(sc->view[as_format], 0, p->view_size);
			if (as_view && as_view_len &&
			    as_view_len <= p->view_size)
				memcpy(sc->view[as_format], as_view,
				       as_view_len);
			/*
			 * The parse sets ctx->format itself when it succeeds -
			 * every collector does, and one row even chooses
			 * between two formats while doing it. So there is
			 * nothing to set here on success, and nothing to undo
			 * on failure: an object whose declared parse refused is
			 * unidentified, which is the same answer a failed sniff
			 * gives and is the honest one.
			 */
			(void)p->parse(buf, sc->view[as_format], ctx);
		}
		return;
	}

	parsers = kof_parser_list(&n);
	for (i = 0; i < n; i++) {
		const struct kof_parser *p = &parsers[i];

		if (!p->sniff(buf))
			continue;
		if (!sc->view[p->format]) {
			sc->view[p->format] = malloc(p->view_size);
			if (!sc->view[p->format])
				return;
		}
		/*
		 * ZEROED HERE TOO, AND THE REASON THE SNIFF PATH WAS EXEMPT HAS
		 * EXPIRED.
		 *
		 * The exemption was written down: a view is reused across
		 * objects and the sniff path can do that "because each of those
		 * parsers fills every field it later reads". That stopped being
		 * true when a parser gained a field the CALLER fills -
		 * kof_pe_info.layout, which pe_parse deliberately preserves
		 * across its own memset because clearing it would make every
		 * declared mapped image parse as a file.
		 *
		 * A sniffed object has no caller-supplied anything, so it must
		 * not inherit one. It did: scanning a manually-mapped image
		 * (declared MAPPED) left that in the view, and the next PE this
		 * scanner SNIFFED - an ordinary file - was parsed as though its
		 * sections were at virtual addresses. Every region then resolved
		 * to the wrong bytes, quietly, for the rest of that scanner's
		 * life or until another declared scan happened to reset it.
		 *
		 * Measured as a heuristic firing twice on one module: once on
		 * the mapped image and once on the file-layout copy un-mapped
		 * from it, which cannot be mapped and said it was.
		 */
		memset(sc->view[p->format], 0, p->view_size);
		if (p->parse(buf, sc->view[p->format], ctx))
			return;
	}
}

/* ---- the routine ---------------------------------------------------------- */

/*
 * Run the unpackers, once the detectors have had their say.
 *
 * After, not before, and that ordering is a decision rather than a convenience. An
 * archive whose entry names carry "../" is an exploit against whatever will open
 * it, and it has already been named by the time this runs - so unless the caller
 * asked for everything, there is nothing to gain from opening it and a budget to
 * lose. The same policy that already decides whether to keep running detectors
 * decides whether to open the container.
 */
/*
 * HOW MANY LAYERS OF PACKING THE INTERPRETER WILL GO THROUGH.
 *
 * Counted in PACKER layers, not tree depth - a tar inside a tar is not two
 * layers of packing, and pdepth already makes that distinction for the
 * heuristic. Emulator output is marked as a packer's, so it adds a layer like
 * any other unpacked payload.
 *
 * Two, because a packer wrapped in another packer is a real thing and a third
 * layer has not been seen: no object in the malware corpus reaches even the
 * second by this route. The reason for a ceiling at all is cost - each layer is
 * its own budget, up to 256 million instructions, so an object crafted to nest
 * could otherwise spend minutes of a scan on itself.
 */
#define EMU_MAX_PACKER_DEPTH 1u

/*
 * How many times one scan will honour a rule's ask for the emulator.
 *
 * A number and not a fraction of the tree, because the thing being bounded is
 * wall time on a tree of any size. 512 is what the measured population supports
 * with room to spare: the rule that asks today fires on 18 of 4398 malware
 * objects and on none of 5252 clean ones, so a scan that reaches this ceiling
 * is looking at something no measured corpus resembles - and the honest thing
 * then is to stop interpreting, not to keep going.
 */
#define HEUR_EMU_MAX 512u

/*
 * The preconditions an unpacker gets, the same a detector does minus the region
 * test an unpacker has no use for. Its own function because the two passes below
 * both apply it, and a check that lived in one loop and not the other would let
 * the family pass run a module the general pass would have ruled out.
 */
static int unp_eligible(const struct kof_module *m,
			const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt)
{
	/*
	 * KOF_EMU_ONLY replaces the packer modules and only those. A container
	 * still has to be opened by the code that knows its format - there is
	 * nothing to interpret in a zip.
	 */
	if (opt->emu_use == KOF_EMU_ONLY && m->unp_kind == KOF_UNP_PACKER)
		return 0;
	/*
	 * Same preconditions as a detector's, from the same place.
	 *
	 * This loop used to spell out three of the four and leave subtype out,
	 * so KOF_TARGET_SUBTYPE on an unpacker built, reported "require subtype"
	 * and then did nothing. No unpacker in bases/ declares one, so honouring
	 * it changes no scan today - it makes the declaration mean what the
	 * build tool already says it means.
	 */
	return kof_module_precond(m, ctx, ctx->obj_size) == KOF_PRECOND_OK;
}

/* Whether an unpacker's declared family is the one a rule predicted. Both are
 * strings; NULL on either side is "no", so an unpacker that declares no family
 * never matches and an object with no prediction never has a family pass. */
static int unp_is_family(const struct kof_scanner *sc,
			 const struct kof_module *m, const char *predict)
{
	const char *fam;

	if (!predict)
		return 0;
	fam = kof_db_family(sc->eng, m);
	return fam && strcmp(fam, predict) == 0;
}

static uint32_t unpack_object(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			 const struct kof_scan_option *opt,
			 const struct kof_result *res, uint32_t pdepth,
			 uint32_t want, const char *predict)
{
	uint32_t i;
	int applies = 0, family_opened = 0;

	if (sc->eng->n_unp == 0)
		return 0;
	/*
	 * A NAMED OBJECT NEED NOT BE OPENED. A GUESSED ONE MUST BE.
	 *
	 * The findings are counted, not just tested: a heuristic says the object
	 * has a shape, which is the opposite of knowing what is in it - and the
	 * one rule that exists says "this is a payload and I cannot read it",
	 * which is a reason to open the object rather than to stop. Testing
	 * res->n alone made a rule firing at EXAMINE cancel the unpacking of the
	 * very object it fired on, so a sample that used to yield three children
	 * yielded none and the payload inside was never scanned.
	 */
	if (res->n && !opt->all_matches) {
		uint32_t k, named = 0;

		for (k = 0; k < res->n; k++)
			if (res->v[k].level != KOF_LEVEL_HEUR)
				named++;
		if (named)
			return 0;
	}

	/*
	 * A fresh attempt for every object.
	 *
	 * Hitting a limit while unpacking one container does not mean the tree is
	 * finished: the memory ceiling is about what is alive at this instant, and
	 * by the time a child is being unpacked its siblings have been scanned and
	 * released, so there is room again. What does carry across the whole tree
	 * is `budget`, which is never reset - that is the bomb defence, and it is
	 * the one that has to be cumulative.
	 *
	 * Sticky exhaustion looked harmless and quietly halved the engine: the
	 * first container to reach the ceiling stopped every container after it.
	 */
	sc->broken = 0;
	/* Per object, like sc->broken: whether a packer opened the LAST object
	 * says nothing about this one. */
	sc->packed_here = 0;
	/*
	 * Cleared with it, and per OBJECT rather than per file.
	 *
	 * The two are set together and have to be cleared together: a ceiling that
	 * stopped one object must not stop the next, because the next is scanned
	 * after this one has been released and the room it held is back. Clearing
	 * only at the root made one limit anywhere in a tree end the tree.
	 */
	sc->stop = 0;

	/*
	 * AND WHETHER A RULE ASKED FOR WHAT THIS OBJECT CARRIES.
	 *
	 * From `want`, which the EXAMINE pass in the caller already collected -
	 * the same mask KOF_ENG_USE_EMU rides in. Assigned rather than or-ed,
	 * which is what makes it per object: the object being opened now either
	 * had a rule fire that asked, or it did not.
	 *
	 * IN THIS BLOCK, above the early return below, because that is what
	 * hygiene means here - see the note on the three fields above. A scan
	 * that refused to open one object must not leave it looking as though
	 * the next object's rules had asked for anything.
	 */
	sc->raise_carried = (want & KOF_ENG_OPEN_CARRIED) != 0;

	/*
	 * DEEP SCAN OFF MEANS DO NOT OPEN IT, and this is the only place that
	 * can honour that - everything below produces children.
	 *
	 * It was honoured only at the far end of the walk, where children are
	 * PUSHED, so every container was decompressed in full and the results
	 * dropped on the floor. Measured: --heur 0 --max-produced 1 on a gzip
	 * still reported "the engine could not finish", which is a scan that
	 * paid for work nobody asked for AND then failed at it.
	 *
	 * Nothing is lost by refusing here. What is inside a container is
	 * declared by its parse - ctx->entries - and its bytes are still
	 * covered by a region, so a rule still searches them. That is the
	 * distinction kofeng.h draws on the field itself: off means "do not
	 * descend", never "do not look".
	 *
	 * Returning 0 and not sc->broken: refusing to open something is not a
	 * failure to examine it. `broken` means "something wanted to look and
	 * could not", and here nothing wanted to.
	 *
	 * AFTER the per-object resets just above and not before them. Those
	 * three fields are hygiene - the note on them says why sticky
	 * exhaustion "looked harmless and quietly halved the engine" - so an
	 * early return that skipped them would leave the previous object's
	 * state standing for this one.
	 */
	if (!kof_objtree_may_open(opt))
		return 0;

	/*
	 * A VIEW IS NOT OPENED, ONLY MATCHED.
	 *
	 * Everything openable in a normalised view was openable in the object
	 * it was made from, and was opened there - the parent is scanned whole
	 * and before this. Opening the view again produces the same content a
	 * second time: measured on an ELF carrying 4.2 MB past its last
	 * segment, which came out once as a child of the file and again as a
	 * child of its view, the same bytes with the padding taken out.
	 *
	 * THE OBJECT SAYS SO ITSELF - see kof_src_declare_view. It was "has a
	 * declared region table", which is a consequence of being a view and
	 * not the fact: a view of an object whose regions could not be resolved
	 * carries no table, and its parent's appendix came out twice.
	 *
	 * WHAT THIS GIVES UP, because it is not nothing. A decoded payload can
	 * be a whole file that exists nowhere in the parent - base64 in, an ELF
	 * out - and that file is then not parsed as one. Its BYTES are in the
	 * view and every rule searches them, which is what the view is for; it
	 * is the structure that is not recovered.
	 */
	if (sc->cur_is_view)
		return 0;

	kof_mod_unpack_mode(ctx, 1);

	/*
	 * FAMILY FIRST, when a rule predicted one.
	 *
	 * A heuristic that fired on this object may have named the family it
	 * expects - see KOF_HEUR_PREDICT. The decoders of that family are tried
	 * before any other, so an object correctly predicted is opened by the
	 * one module written for it and the rest are never entered.
	 *
	 * This is a REORDERING and never a filter, and the distinction is the
	 * whole safety of it. If the predicted family's decoders open the object
	 * the general pass is skipped - the best case, and the only time
	 * anything is saved. If they do not, the general pass runs every
	 * eligible unpacker exactly as it always has. So a wrong prediction
	 * costs the order it imposed and misses nothing: the worst case is the
	 * old case. The number of children before and after is how "did it open
	 * it" is answered, because producing a child is the only thing an
	 * unpacker does that the next pass would want to know about.
	 */
	if (predict) {
		uint32_t kids0 = sc->n_kids;
		uint32_t carved0 = sc->n_carved;

		for (i = 0; i < sc->eng->n_unp && !sc->broken; i++) {
			const struct kof_module *m = &sc->eng->unp[i];

			if (!unp_eligible(m, ctx, opt) ||
			    !unp_is_family(sc, m, predict))
				continue;
			applies = 1;
			sc->cur_mod = m;
			{
				uint32_t k0 = sc->n_kids;

				m->fn(ctx);
				/* What a carve produced does not make its host
				 * a wrapper - see KOF_UNP_CARVE. */
				if (m->unp_kind == KOF_UNP_CARVE &&
				    sc->n_kids > k0)
					sc->n_carved += sc->n_kids - k0;
			}
			sc->cur_mod = NULL;
		}
		/*
		 * OPENED, AND A CARVE DID NOT OPEN ANYTHING - the same rule
		 * analyze_object applies one level up, and for the same
		 * reason: a carved child is a file that was glued on, so the
		 * host is still an unopened object and the general pass below
		 * is still owed to it. Counted as an opening, one family's
		 * carver would stand in for every other unpacker in the
		 * database.
		 *
		 * Both counters are the whole object's, so both marks are
		 * this pass's - see the note on the same subtraction in
		 * analyze_object.
		 */
		family_opened = sc->n_kids - kids0 > sc->n_carved - carved0;
	}

	/*
	 * The general pass, unless the predicted family already opened it.
	 *
	 * It skips the family-matched modules when a prediction was made,
	 * because the family pass above already ran them - re-running one that
	 * declined would be doing its work twice.
	 */
	for (i = 0; !family_opened && i < sc->eng->n_unp; i++) {
		const struct kof_module *m = &sc->eng->unp[i];

		if (!unp_eligible(m, ctx, opt))
			continue;
		/* Skip what the family pass already tried. Guarded on `predict`
		 * so the resolve-and-compare is not paid on the overwhelming
		 * majority of objects, which no rule spoke for. */
		if (predict && unp_is_family(sc, m, predict))
			continue;

		applies = 1;
		if (sc->broken)
			break;          /* nothing left to spend on this tree */

		sc->cur_mod = m;
		{
			uint32_t k0 = sc->n_kids;

			m->fn(ctx);
			if (m->unp_kind == KOF_UNP_CARVE && sc->n_kids > k0)
				sc->n_carved += sc->n_kids - k0;
		}
		sc->cur_mod = NULL;
	}
	/*
	 * A COMPLETE FILE SITTING AT AN OFFSET IS NOT AN UNPACKING PROBLEM -
	 * AND IT IS NOT THE ENGINE'S SEARCH EITHER, ANY MORE.
	 *
	 * It was: two magics written into the scanner, run over every object of
	 * every format, before the loop above had even been consulted about
	 * what the object's structure already said. Three consequences, all one
	 * fault.
	 *
	 * Finding a THIRD kind of carried file meant editing the engine, so
	 * what the engine could find was a property of its own build rather
	 * than of the database - which is the one thing every other kind of
	 * detection here avoids.
	 *
	 * NOT searching was worse. A format that names its own attachments -
	 * PDF /EF, a zip directory - has already produced them, so a search
	 * finds the same bytes again: measured, one attachment became two
	 * children and 0.69MB was scanned twice. Expressing "do not search a
	 * PDF" needed a table in the engine naming formats, which is the
	 * engine deciding a module's business.
	 *
	 * And WHERE to look - a PE's overlay and resources, an ELF's data,
	 * never their code - is format knowledge that was sitting in the
	 * scanner.
	 *
	 * So it is gone, and NOTHING REPLACES IT YET. Its successor is not
	 * another sweep: a rescan of every object for two-byte magics is the
	 * cost that made the old one wrong, whatever declared it. What comes
	 * instead is per studied case - a rule's ASK honoured here rather than
	 * a search performed here.
	 *
	 * THE PLACE FOR THAT ASK NOW EXISTS, which is worth saying because it
	 * was the missing half. A rule that fires at EXAMINE can declare
	 * KOF_ENG_OPEN_CARRIED and the engine honours it on THIS object - see
	 * that bit in kofmod/heur.h. What is still unwritten is the search
	 * itself: an object whose structure names nothing, where a rule has
	 * said the bytes are worth looking through anyway. The ask is the hook
	 * it will hang on, and the reason to write it per case is unchanged -
	 * whoever knows a family knows where in it to look.
	 *
	 * What remains is step 4 below: the carried files the STRUCTURE named,
	 * which needs no search at all.
	 */
	/*
	 * NOTHING OPENED IT, SO RUN IT.
	 *
	 * Last, and only when every module that declared this format has had
	 * its turn and none of them produced anything. That ordering is the
	 * whole economy of it: a family with a static unpacker is opened by
	 * reading, which costs a pass over the object, and emulating it as well
	 * would pay a million instructions to learn the same thing. What is
	 * left when they all decline is either a packer nobody here has written
	 * a module for, or an object too damaged to read - and both are cases
	 * where running it is the only remaining way to see inside.
	 *
	 * `broken` is checked first for the same reason the module loop checks
	 * it: once the tree's budget is gone there is nothing to spend.
	 */
	/*
	 * A RULE MAY ASK FOR THE EMULATOR ON THIS OBJECT, and only this one.
	 *
	 * `want` came back from the EXAMINE phase in the caller and is passed
	 * down rather than stored, so it cannot outlive the object it was asked
	 * for. Three things still say no:
	 *
	 *   - an explicit --emu never, which is what emu_forbidden is for. The
	 *     option word alone cannot tell that apart from the NEVER that
	 *     --heur 1 leaves behind, and turning the second into emulation is
	 *     the whole point of the ask.
	 *   - the packer depth ceiling, unchanged.
	 *   - a ceiling on how many asks a whole scan honours. Without it a
	 *     directory of objects that all match one rule turns a five second
	 *     scan into minutes, and that is a cost a file's contents would be
	 *     choosing.
	 */
	/*
	 * A RULE'S ASK IS THE GATE when it fires, in any mode that permits the
	 * emulator at all.
	 *
	 *   - it does not fire under --emu never (emu_forbidden), which is the
	 *     one refusal a rule may not talk past;
	 *   - it yields to a static unpacker that already opened the object
	 *     (!packed_here) - the same guard the AUTO fallback carries, because
	 *     a payload peeled without running anything must not be run as well;
	 *   - it is bounded by the packer depth and by HEUR_EMU_MAX.
	 *
	 * When it does fire, the emulator is FORCED - the entropy gate below is
	 * skipped. That is the performance point and a correctness fix at once.
	 * Cheaper: the rule read a few parse fields where the gate makes a
	 * byte-histogram pass over every executable segment. Stricter: the gate
	 * needs DENSE_MIN bytes of code before its estimate means anything, and a
	 * meterpreter payload is smaller than that - so the gate returned NO on
	 * exactly the objects the rule fires on, and --heur 2 missed a shikata
	 * sample --heur 1 caught. The shape fires on 0 of 5252 clean objects, so
	 * it is a safe thing to force emulation on.
	 */
	if (!sc->broken && (want & KOF_ENG_USE_EMU) &&
	    !opt->emu_forbidden && !sc->packed_here &&
	    pdepth <= EMU_MAX_PACKER_DEPTH &&
	    sc->st.heur_emu < HEUR_EMU_MAX) {
		sc->st.heur_emu++;
		if (kof_scan_emu_unpack(ctx, 1))
			applies = 1;
	} else if (!sc->broken && opt->emu_use != KOF_EMU_NEVER &&
		   pdepth <= EMU_MAX_PACKER_DEPTH &&
		   (opt->emu_use == KOF_EMU_ONLY || !sc->packed_here)) {
		/* The entropy gate, for objects no rule spoke for. */
		if (kof_scan_emu_unpack(ctx, opt->emu_use == KOF_EMU_ONLY))
			applies = 1;
	}
	/*
	 * THE CARRIED FILES THE STRUCTURE NAMED, AND THIS IS LAST ON PURPOSE.
	 *
	 * The order of this whole function is the pipeline, and the pipeline is:
	 *
	 *   1. the PARSE has already said what the object is made of - which
	 *      bytes are which region, and which of them are files it carries.
	 *      That happened in identify(), before any module ran.
	 *   2. the DETECTORS have had their say, in the caller.
	 *   3. the UNPACKERS and the emulator have finished above: whatever was
	 *      compressed or encoded is now an object of its own.
	 *   4. ONLY THEN are declared carried files opened.
	 *
	 * Last because every step before it can change the answer. An object
	 * that was packed is not the file the author wrote, so its structure's
	 * claims about what it carries are claims about the wrapper; the
	 * unpacked child is where those claims are worth acting on, and the
	 * child is scanned as an object in its own right, so it reaches this
	 * same step with its own parse behind it. Running this first would open
	 * attachments named by a wrapper before anything had established that
	 * the wrapper was the file.
	 *
	 * AND IT ONLY RUNS UNDER DEEP SCAN, which is not a saving but the
	 * definition of the two levels:
	 *
	 *   deep OFF   the carried file stays BYTES IN A REGION. Its own format
	 *              names that region - KOF_SCAN_EMBEDDED where the format
	 *              has carried files at all - so a rule still searches it,
	 *              the parse still says how many there are and how big, and
	 *              nothing is decompressed or copied to learn that.
	 *   deep ON    the same ranges become children, from the same table, so
	 *              a file cannot be searchable and unextractable or the
	 *              reverse.
	 *
	 * kof_objtree_may_open is checked inside, at the top, so this is one
	 * call rather than a call and a guard that could disagree.
	 */
	if (!sc->broken && kof_objtree_declared(ctx, opt))
		applies = 1;

	kof_mod_unpack_mode(ctx, 0);

	/*
	 * "Not fully examined" means both halves: something wanted to open this
	 * object, and the budget was gone. The budget is shared by the whole tree,
	 * so once it runs out every later object inherits the flag - and reporting
	 * that on an object no unpacker would have touched anyway is noise that
	 * makes the real case harder to see.
	 */
	return applies ? sc->broken : 0;
}

/*
 * THE FORMS OF A SCRIPT, AS OBJECTS - and deliberately NOT inside
 * unpack_object.
 *
 * It was in there, which looked tidy and was wrong three ways, and the third
 * one is why nothing ever came of it:
 *
 *   - unpack_object returns at its first line when the database has no
 *     unpacker modules. kofviewer opened with no --db is exactly that engine,
 *     so the reader who asked to see the folded form of a shell got a tree
 *     with no child in it and no reason given. Folding needs a lexical table
 *     and a parse; it does not need a database, and nothing about it should
 *     have been behind one.
 *   - it returns again once a signature has NAMED the object, unless the
 *     caller asked for every match. That is the right economy for a scan and
 *     the wrong one for these: a named webshell is the case where seeing what
 *     it builds matters most.
 *   - and it is under kof_mod_unpack_mode, which is about what a MODULE may
 *     do to the object it was handed. No module is involved here.
 *
 * What it does keep is the deep-scan gate, because that is the one condition
 * that is genuinely shared: everything here produces a child, and deep off
 * means do not descend.
 *
 * ONE CHILD AND NOT ONE PER PASS. The level is what the passes cost, not what
 * they are for: the form pass runs wherever the heuristics run, and level 2 -
 * the rung that already means "do the expensive thing the cheap things cannot"
 * - adds the fold, which walks every assignment looking for a constant right
 * hand side. What comes out is one object either way, in the LAST form the
 * levels asked for. A tree that carried the intermediate as well made the
 * reader decide which node to take a marker from, and the answer was never the
 * intermediate.
 */
static int script_forms(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt, uint32_t pdepth)
{
	if (sc->broken || ctx->format != KOF_FMT_SCRIPT)
		return 0;
	if (!kof_objtree_may_open(opt) || pdepth > EMU_MAX_PACKER_DEPTH)
		return 0;

	return kof_scan_script_forms(ctx, opt->heur_level >= 2) != 0;
}

/*
 * WHAT THE HEURISTIC IS ALLOWED TO SEE, AND WHY IT IS GATHERED HERE.
 *
 * Everything below already exists by the time this runs: the anomaly word came
 * out of the parse, the depth came down the walk, and whether an unpacker gave up
 * is the value unpack_object just returned. Nothing is searched for and no pass is
 * made over the object, which is why this runs unless the caller switched it off
 * rather than only when the caller asked for it.
 *
 * Marker-derived evidence is deliberately absent. Knowing that a family has two
 * markers present but did not fire means asking about markers whose module's
 * logic never reached them, which is a pass over the object that would
 * otherwise not happen - so it is not free, and nothing here gathers it. There
 * was a --heur level for asking; it gathered nothing and changed no verdict, so
 * it is gone. If that evidence is ever collected it needs its own switch again,
 * and the switch should arrive with the collector rather than before it.
 */
static void heur_object(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			const struct kof_scan_option *opt, uint32_t pdepth,
			uint32_t partial, struct kof_result *out)
{
	const struct kof_heur_model *m = kof_heur_default();
	struct kof_heur_facts f;
	const char *guess = "Unknown";
	int32_t score = 0;

	if (opt->heur_off)
		return;

	/*
	 * AN ELF THE MODEL WAS MEASURED ON, WHICH IS AN EXECUTABLE OR A SHARED
	 * OBJECT AND NOT A RELOCATABLE ONE.
	 *
	 * Every weight in kofheur.c came from a population of 6523 malware and
	 * 13638 clean ELF objects, and that population is programs. An ET_REL is
	 * a different shape: no program headers, no entry point, sections that
	 * the module loader relocates rather than maps. Asking the table about
	 * one is asking it a question it was never measured against, and the
	 * answer it gives is the one a machine sees most - every .ko under
	 * /lib/modules came back "ELF-x64/Heur:Truncated".
	 *
	 * The bar is what makes that serious. 747 centinats was chosen because
	 * no clean object in the measured corpus reached it; a population that
	 * was not in the corpus has no such guarantee, and a false positive on
	 * kernel modules is a false positive on the largest single group of ELF
	 * files most Linux hosts have.
	 *
	 * ONLY THE SCORE STOPS. The parse still records every anomaly and an
	 * examiner still prints them - what is withheld is a VERDICT from a
	 * model that has no evidence about this kind of object.
	 */
	if (ctx->format == KOF_FMT_ELF) {
		const struct kof_elf_info *ei = kof_elf(ctx);

		if (!ei || (ei->e_type != KOF_ELF_EXEC &&
			    ei->e_type != KOF_ELF_DYN))
			return;
	}

	memset(&f, 0, sizeof f);
	f.format       = ctx->format;
	/*
	 * PACKER layers, not tree depth.
	 *
	 * A file three directories down inside a tar is not three layers of
	 * packing, it is a directory tree - and depth counted every child the
	 * same way, so an ordinary archive of archives scored like something
	 * that had been wrapped to be hidden. Only a module that declared itself
	 * KOF_UNP_PACKER adds a layer now.
	 */
	f.anomalies    = kof_heur_anomalies(ctx);
	/*
	 * The object that WAS packed, not the one that came out.
	 *
	 * See kof_scanner.packed_here. Both are true of a packed sample and they
	 * are different objects: this marks the file on disk, and packer_depth
	 * above marks what was inside it.
	 */
	if (sc->packed_here)
		f.flags |= KOF_HEUR_FL(KOF_HEUR_F_PACKED);
	if (partial)
		f.flags |= KOF_HEUR_FL(KOF_HEUR_F_UNPACK_PARTIAL);
	if (!kof_heur_score(m, &f, &score, &guess))
		return;                 /* no model for this format - say nothing */

	/*
	 * Published before the bar is consulted.
	 *
	 * The bar decides whether this becomes a FINDING; it does not decide
	 * whether the caller is allowed to know the number. An examiner wants
	 * the score on every object precisely so it can show how far short of
	 * the bar something came.
	 */
	out->heur_scored    = 1;
	out->heur_score     = score;
	out->heur_flags     = f.flags;
	out->heur_anomalies = f.anomalies;
	out->heur_depth     = pdepth > 255u ? 255u : (uint8_t)pdepth;

	if (score < m->bar_centinats || out->n >= KOF_MAX_FINDINGS)
		return;

	/*
	 * A NAMED FAMILY SUPERSEDES A GUESS ABOUT THE SHAPE.
	 *
	 * The heuristic's measured worth is on objects the database MISSED -
	 * eleven percent of those, at this bar. On an object it did not miss it
	 * contributes nothing to the verdict, and printing both put two
	 * verdicts on one object: "Botnet:Mirai" and "Heur:Truncated" for the
	 * same bytes, leaving a reader to work out which one the scanner
	 * actually means.
	 *
	 * The SCORE is still published above, so an examiner shows how the
	 * object scored either way. What is suppressed is the second verdict,
	 * not the second fact.
	 */
	{
		uint32_t k;

		for (k = 0; k < out->n; k++)
			if (out->v[k].level != KOF_LEVEL_HEUR)
				return;
	}

	{
		struct kof_finding *fi = &out->v[out->n++];

		char fmtarch[32], sv[16];

		fi->level = KOF_LEVEL_HEUR;
		/*
		 * <target>/Heur:<what it looks like>:<how strongly>.
		 *
		 * Three parts because a reader asks three things and a bare
		 * number answers none of them: which population it was judged
		 * against, what the evidence suggests, and how far past the bar
		 * it went. The middle word comes from the model's own table -
		 * the engine does not know these words - so a heuristic
		 * authored elsewhere names its own findings.
		 *
		 * Heur is not a family and never becomes one. It is the engine
		 * saying it recognised a shape, not a thing.
		 */
		kof_name_target(fmtarch, sizeof fmtarch, ctx->format, ctx->arch);
		snprintf(sv, sizeof sv, "s%d", score);
		kof_finding_name(fi, fmtarch, "Heur", guess, sv, NULL);
	}
}

/*
 * THE HEURISTIC RULES, at one of their two points in an object's life.
 *
 * Returns the OR of what the rules that FIRED asked the engine for - see
 * KOF_HEUR_WANT in kofmod/heur.h. An OR and not a last-writer, so two rules
 * asking for the same thing is the same request and the answer does not depend
 * on the order the packs happened to load in. That matters: --jobs must not
 * change a verdict, and scan_mt is the test that says so.
 *
 * The mask is returned rather than stored on the scanner. A field would be
 * state, and state is exactly how "this object asked for the emulator" becomes
 * "the rest of the scan uses it" - the bug this is shaped to make impossible.
 */
static uint32_t heur_run(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			 const struct kof_scan_option *opt,
			 struct kof_result *out, uint32_t phase,
			 uint32_t present, const char **predict)
{
	uint32_t want = 0, i;
	/*
	 * ZERO MEANS UNSTATED, and unstated is level 1.
	 *
	 * Not a default written into the struct, because there is no
	 * initialiser to write it in: every caller declares a
	 * kof_scan_option on the stack and clears it, so a field whose
	 * useful value is 1 arrives as 0. Reading 0 as "the level every rule
	 * ran at before there was a choice" is what keeps kofexaminer, the
	 * unit tests and any embedder working unchanged - the alternative
	 * silently disabled every heuristic for all of them.
	 *
	 * Level 0 is not spelled here: it is opt->heur_off, tested above.
	 */
	uint32_t lvl = opt->heur_level ? opt->heur_level : 1u;

	if (predict)
		*predict = NULL;
	if (opt->heur_off)
		return 0;
	for (i = 0; i < sc->eng->n_heur; i++) {
		const struct kof_module *m = &sc->eng->heur[i];

		if (m->heur_phase != phase)
			continue;
		/*
		 * A rule gated above this scan's level is not ENTERED, not
		 * merely ignored afterwards. That is the whole point of the
		 * declaration: the cost it was gated for - and for a rule that
		 * walks a symbol table, that cost is real - must not be paid by
		 * a caller who did not ask for it. Beside the phase test
		 * because they are the same kind of thing, a property of the
		 * rule that the scan compares against without running anything.
		 */
		if (m->heur_level > lvl)
			continue;
		if (!prefilter(m, ctx, present, &sc->st, out))
			continue;

		sc->rep_valid = 0;
		/* Nothing asked yet - see scan.h. Reset beside rep_valid
		 * because it is the same kind of thing: what THIS module
		 * reported about this object. */
		sc->plague_asked = -1;
		sc->n_plague_blk = 0;
		sc->plague_hit = 0;
		sc->plague_tot = 0;
		sc->cur_mod   = m;
		m->fn(ctx);
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;
		want |= m->heur_want;
		/*
		 * The FIRST prediction wins, and it is kept whether or not this
		 * rule's finding survives the named-family test below.
		 *
		 * Kept, because a prediction is used for two different things: it
		 * is written into the finding, and it decides which decoder is
		 * tried first. The second is worth having even on an object a
		 * signature already named - the name is about the container, the
		 * decoder is about what is inside it.
		 */
		if (predict && !*predict) {
			const char *pf = kof_db_heur_predict(sc->eng, m);

			if (pf && pf[0])
				*predict = pf;
		}
		/*
		 * FIRED FOR THE ACTION, NOT FOR A VERDICT - see KOF_HEUR_ACT.
		 * After `want`, so the ask it fired for is honoured, and after
		 * the prediction, so the decoder it would have steered is
		 * still steered. Before the finding, because the finding is
		 * the whole of what it declines to make.
		 */
		if (sc->rep_level == (uint32_t)KOF_LVL_ACT)
			continue;
		/*
		 * A NAMED FAMILY SUPERSEDES A GUESS ABOUT THE SHAPE, and the
		 * rule is the same one the scored model follows a few functions
		 * down. The ASK is not suppressed with it: whether the object
		 * is worth interpreting was decided before anything was named,
		 * and withdrawing it here would leave a rule that fires and
		 * does nothing on precisely the objects a signature already
		 * half-recognised.
		 */
		{
			uint32_t k;
			int named = 0;

			for (k = 0; k < out->n; k++)
				if (out->v[k].level != KOF_LEVEL_HEUR)
					named = 1;
			if (named)
				continue;
		}
		if (out->n < KOF_MAX_FINDINGS) {
			struct kof_finding *f = &out->v[out->n++];
			const char *pf = kof_db_heur_predict(sc->eng, m);

			/* Before anything can renumber the slots: the bit is
			 * this finding's index, and the drop below reads it. */
			if (m->heur_want & KOF_ENG_KEEP_ON_OPEN)
				sc->heur_keep |= 1u << (out->n - 1u);
			f->level = KOF_LEVEL_HEUR;
			/*
			 * <target>/Heur:<family>#<variant>?<shape>.
			 *
			 * The name follows the shape a detector's does - maltype,
			 * family, variant - and reads the same way: the FAMILY is what
			 * the object is, here what the rule PREDICTS it is, and the "?"
			 * carries the one thing a heuristic must admit - that the family
			 * is a guess and the SHAPE after the mark is the only thing
			 * actually shown. A rule that recognises a shellcode layout and
			 * expects Meterp reads Heur:Meterp#<variant>?Shellcode: the
			 * guessed family where a reader looks for one, the evidence
			 * behind the mark.
			 *
			 * Composed here and not through finding_str because that one is
			 * shared with the detectors and puts the MODULE's declared
			 * family in that slot - which for a rule is the shape it is
			 * named for, not the family it guesses. With no prediction the
			 * shape is all there is, and finding_str writing it as the
			 * family is exactly right.
			 */
			if (pf && pf[0]) {
				const char *variant =
					kof_db_name(sc->eng, m, sc->rep_name_id);
				const char *shape = kof_db_family(sc->eng, m);
				char fmtarch[32];

				kof_name_target(fmtarch, sizeof fmtarch,
						ctx->format, ctx->arch);
				kof_finding_name(f, fmtarch, "Heur", pf,
						 variant ? variant : "unknown",
						 shape);
			} else {
				finding_str(sc, ctx, m, f);
			}
		} else {
			out->dropped++;
		}
		/* One HEUR line per object, the same way the detector loop
		 * stops at the first family - and for the same reason: the
		 * rules after it can only lengthen a list that already says
		 * what the object looks like. */
		if (!opt->all_matches)
			break;
	}
	return want;
}


/*
 * THE SAME EXECUTABLE, SAID PLAINLY, AS ONE CHILD.
 *
 * A UTF-16 marker is the same letters with a zero between each one, so an
 * ASCII pattern does not match it; a long run of padding is bytes every rule
 * is swept across for nothing. executables.h turns both into a shorter view
 * that says the same thing, and this is where that view becomes an object.
 *
 * A CHILD, NEVER A REWRITE. The parent keeps every byte and every offset it
 * had: cure_patch writes the file at an offset, kof_find_str_where hands a
 * module an offset to read a layout from, and a module author has no way to
 * know which view an offset came from. So the view gets its own object with
 * its own offset space and its own name, which is what the scan tree is for.
 *
 * ONE CHILD AND NOT ONE PER REGION. The presence table is 32MB built per
 * object, so N children cost N builds; one child costs one. The view is the
 * whole object normalised rather than a bag of pieces, so the ranges inside it
 * still mean what they meant.
 *
 * WHAT IT IS WORTH, measured before it was written: 2.6% of bytes on 293 ELF64
 * from /usr/bin and 1.1% on 1129 PE. That is not the reason it is here - the
 * reason is the wide marker and, later, the decoded payload - and the floor
 * below exists so the 97% of objects with nothing to gain do not pay for a
 * copy to find that out.
 */
#define NORM_MIN_OBJ   (4u << 10)   /* below this there is nothing to save */
#define NORM_MIN_SAVE  16u          /* per cent, or it is not worth an object */

/*
 * THE PARENT'S REGIONS, GATHERED SO THE VIEW CAN CARRY THEM.
 *
 * One entry per extent rather than per region, because a region is a list: an
 * ELF with three executable segments has three CODE extents and a view that
 * named one of them would hide the other two.
 *
 * Bits 1 to 7, which covers both vocabularies - an ELF names five kinds and a
 * PE seven, and both number from 1. Bit 0 is KOF_SCAN_ALL, which is the whole
 * object and needs no carrying; the symbol bits are 30 and 31 and are extents
 * over the canonical RECORDS, not over the file, so no byte of this buffer is
 * ever theirs.
 */
#define NORM_RGN_BITS 7u

static uint32_t norm_gather(struct kof_obj_ctx *ctx, struct kof_src_region *r,
			    uint32_t cap)
{
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t b, n = 0;

	if (!ctx->resolve_scan)
		return 0;
	for (b = 1; b <= NORM_RGN_BITS && n < cap; b++) {
		uint32_t mask = 1u << b, k, i;

		k = ctx->resolve_scan(ctx, mask, ext, KOF_SCAN_MAX_EXTENTS);
		for (i = 0; i < k && n < cap; i++) {
			if (!ext[i].len)
				continue;
			r[n].mask = mask;
			r[n].off = ext[i].off;
			r[n].len = ext[i].len;
			n++;
		}
	}
	return n;
}


/*
 * WHICH OF THEM MUST NOT MOVE, AS A BIT PER BYTE.
 *
 * HEADERS and CODE, and the two share their bit numbers across the formats -
 * KOF_SCAN_ELF_HEADERS and KOF_SCAN_PE_HEADERS are both 1u << 1, CODE both
 * 1u << 2 - so one test serves an ELF and a PE without asking which this is.
 * That is a coincidence of two independent choices and not a rule, so it is
 * checked here rather than relied on silently.
 */
#define NORM_KEEP_MASK ((1u << 1) | (1u << 2))

static void norm_keep_bits(uint8_t *keep, uint64_t n,
			   const struct kof_src_region *r, uint32_t nr)
{
	uint32_t i;

	memset(keep, 0, (size_t)((n + 7u) / 8u));
	for (i = 0; i < nr; i++) {
		uint64_t j, e;

		if (!(r[i].mask & NORM_KEEP_MASK))
			continue;
		if (r[i].off >= n)
			continue;
		e = r[i].off + r[i].len;
		if (e > n)
			e = n;
		for (j = r[i].off; j < e; j++)
			keep[j >> 3] |= (uint8_t)(1u << (j & 7u));
	}
}

/*
 * WHICH BYTES OF THIS OBJECT BELONG TO THE STATIC LIBRARY - ASKED ONCE, HERE.
 *
 * Beside the parse, because that is what it needs and because every consumer
 * of the answer runs after it: the normaliser leaves these bytes out of the
 * view, the block builder puts a block on the library side of enum
 * kof_plague_side when it lands in one, and both used to work it out for
 * themselves. See kof_scanner.cur_lib.
 *
 * TWO TIERS, AND THE SECOND IS GATED ON HOW THE OBJECT WAS LINKED.
 *
 * The marker span runs from a loadable segment's first library string to its
 * last and takes everything between. In a STATIC build that is right - the
 * library is laid down in one run and the strings bound it. In a DYNAMIC one
 * there is no static library at all, so the strings it finds are the
 * program's own and the span between them is the program: measured, an 8MB
 * miner with a PT_INTERP yielded a 7MB "library" across its CODE.
 *
 * So the marker tier is asked only when nothing is going to be loaded in
 * beside this file, and the symbol tier - which claims exactly what a symbol
 * covers and nothing between symbols - is asked always.
 */
static int lib_is_static(const struct kof_elf_info *e)
{
	uint32_t i;

	if (!e)
		return 0;
	for (i = 0; i < e->seg_count; i++)
		if (e->seg[i].type == 3u)       /* PT_INTERP */
			return 0;
	return 1;
}

static void lib_facts(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	sc->cur_lib.n = 0;
	sc->cur_lib_ok = 0;
	if (sc->cur_is_view) {
		/*
		 * A VIEW KNOWS WHERE ITS LIBRARY IS BECAUSE IT WAS TOLD.
		 *
		 * The bytes are in it - moved to the end under SLIB_CODE and
		 * SLIB_DATA, see KOF_SCAN_ELF_SLIB_CODE - and nothing here can
		 * work them out a second time: kof_lib_find reads segment
		 * offsets, and a view's headers describe the file before the
		 * transform. The declared table is the answer, and it came from
		 * this same field one object ago.
		 *
		 * WITHOUT THIS THEY ARE THE AUTHOR'S. Every window is then
		 * KOF_PLAGUE_SIDE_USER, so a block cut from somebody's own code
		 * is credited by libc - which is the one thing the side
		 * mechanism exists to stop. Measured when it was missing: ten
		 * files dropped from infected to suspected, because a rule that
		 * now scored 10 on library bytes reported before the rule that
		 * actually recognised them.
		 */
		uint32_t i;

		for (i = 0; i < sc->n_cur_rgn &&
			    sc->cur_lib.n < KOF_LIB_MAX_SPANS_ALL; i++) {
			if (!(sc->cur_rgn[i].mask &
			      (KOF_SCAN_ELF_SLIB_CODE |
			       KOF_SCAN_ELF_SLIB_DATA)))
				continue;
			if (!sc->cur_rgn[i].len)
				continue;
			sc->cur_lib.span[sc->cur_lib.n].off =
				sc->cur_rgn[i].off;
			sc->cur_lib.span[sc->cur_lib.n].len =
				sc->cur_rgn[i].len;
			sc->cur_lib.n++;
		}
		sc->cur_lib_ok = sc->cur_lib.n != 0;
		return;
	}
	if (!ctx || ctx->format != KOF_FMT_ELF || !ctx->file_header)
		return;
	if (!buf.p || !buf.n)
		return;
	if (lib_is_static(kof_elf(ctx)))
		kof_lib_find_all(buf, kof_elf(ctx), &sc->cur_lib);
	else
		kof_lib_find_syms(buf, kof_elf(ctx), &sc->cur_lib);
	sc->cur_lib_ok = 1;
}

/*
 * THE VIEW'S SYMBOLS: THE PARENT'S, WITHOUT THE TOOLCHAIN'S.
 *
 * WHY IT CANNOT BE BUILT FROM THE VIEW. A symbol block is read out of the
 * object's own section table, and a view's headers describe the file before the
 * padding came out: every offset in them is stale wherever something collapsed
 * ahead of it. Measured on a uclibc bot - the file yields 677 records and its
 * view yields none, so the view carried no SYM_EXP and no SYM_IMP at all.
 *
 * AND WHY IT IS WORTH CARRYING. Two unrelated static binaries export the same
 * hundreds of libc names, so a symbol-set similarity between them measures the
 * toolchain exactly as a string-set one does. The view exists to be the
 * object's own content; its symbol half has to mean the same thing, or a
 * question asked of SYM_EXP on a view is answered by uclibc.
 *
 * THE SAME CLASSIFICATION AND NOT A SECOND ONE. A record is dropped when the
 * address it covers falls in the library spans lib_facts already worked out -
 * see kof_lib_has_addr. Nothing here decides what the library is.
 *
 * `_start` GOES WITH IT, and the header's index of it is cleared rather than
 * left pointing at whatever record now sits there: crt is the toolchain's, so
 * the record is dropped, and an index into a table that has moved underneath it
 * is worse than no index - kof_sym_start's callers read it as a place to begin.
 */
static uint32_t norm_syms(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			  uint8_t *out, uint32_t cap)
{
	const struct kof_elf_info *e;
	const uint8_t *in;
	uint32_t n_in = 0, total, i, kept = 0;
	uint32_t start_at, start_new = KOF_SYM_NO_START;

	if (!ctx->content || !ctx->content->syms || !sc->cur_lib_ok)
		return 0;
	if (ctx->format != KOF_FMT_ELF || !ctx->file_header)
		return 0;
	e = kof_elf(ctx);
	in = ctx->content->syms(ctx, &n_in);
	total = kof_sym_count(in, n_in);
	if (!total || cap < KOF_SYM_HDRLEN)
		return 0;

	memcpy(out, in, KOF_SYM_HDRLEN);
	/* Where the parent said `_start` was, so the copy can say where it
	 * ended up - see the note below on why it is not simply cleared. */
	start_at = (uint32_t)in[KOF_SYM_H_START] |
		   ((uint32_t)in[KOF_SYM_H_START + 1] << 8);
	for (i = 0; i < total; i++) {
		const uint8_t *r = kof_sym_rec(in, n_in, i);
		uint64_t va, sz;
		uint32_t k;

		if (!r)
			continue;
		va = 0;
		sz = 0;
		for (k = 0; k < 8u; k++) {
			va |= (uint64_t)r[KOF_SYM_R_VALUE + k] << (8u * k);
			sz |= (uint64_t)r[KOF_SYM_R_SIZE + k] << (8u * k);
		}
		if (kof_lib_has_addr(e, &sc->cur_lib, va, sz))
			continue;
		/*
		 * AND NOTHING ELSE DECIDES THIS.
		 *
		 * A name test was here, dropping every `__CTOR_LIST__` and
		 * `__EH_FRAME_BEGIN__` the toolchain plants, because a symbol
		 * with no size covers no bytes and no span can reach it. It
		 * was wrong for a reason worth writing down: the block
		 * describes THE VIEW, and the view still contains those bytes.
		 * A record dropped here that the cut did not drop says the
		 * library was taken out where it was not - the symbol half and
		 * the byte half would be describing two different files.
		 *
		 * So the only question asked of a record is the one the bytes
		 * were asked: is what it covers inside what was cut. A symbol
		 * covering nothing was cut from nothing, and stays.
		 */
		if (KOF_SYM_HDRLEN + (kept + 1u) * KOF_SYM_RECLEN > cap)
			break;
		/* After the room test, not before it: a record the cap stopped
		 * short of is not at an index, so the header must not name one
		 * for it. */
		if (i == start_at)
			start_new = kept;
		memcpy(out + KOF_SYM_HDRLEN + (uint64_t)kept * KOF_SYM_RECLEN,
		       r, KOF_SYM_RECLEN);
		kept++;
	}
	if (!kept)
		return 0;
	out[KOF_SYM_H_COUNT + 0] = (uint8_t)kept;
	out[KOF_SYM_H_COUNT + 1] = (uint8_t)(kept >> 8);
	out[KOF_SYM_H_COUNT + 2] = (uint8_t)(kept >> 16);
	out[KOF_SYM_H_COUNT + 3] = (uint8_t)(kept >> 24);
	/*
	 * AND WHERE `_start` ENDED UP, WHICH IS ALSO NOT A NEW FACT.
	 *
	 * The header carries the index of the `_start` record so a reader can
	 * begin there. Filtering moves every index after the first drop, so
	 * copying the parent's number would point at whichever record now sits
	 * at it - a false statement rather than a missing one. This writes the
	 * index the SAME record landed at, or NO_START when the cut took it;
	 * both come out of what the loop above did, and nothing here decides
	 * which records those are.
	 */
	out[KOF_SYM_H_START + 0] = (uint8_t)(start_new & 0xffu);
	out[KOF_SYM_H_START + 1] = (uint8_t)((start_new >> 8) & 0xffu);
	return KOF_SYM_HDRLEN + kept * KOF_SYM_RECLEN;
}

/*
 * CODE IS A SEGMENT, AND THE INSTRUCTIONS ARE ONLY PART OF IT.
 *
 * KOF_SCAN_ELF_CODE is the loadable segment with PF_X, and a linker puts
 * .rodata in there beside .text - so "CODE" holds every string literal the
 * program has as well as its opcodes. Kept byte for byte, as the whole region
 * was, those strings could not be rewritten: an IoT dropper's exploits are
 * percent-encoded form bodies sitting in .rodata, the decode pass rewrote them
 * and the restore put them straight back. Measured on one: the payload at
 * offset 162554, every executable section ending at 134934.
 *
 * The reason for keeping CODE is about INSTRUCTIONS - "opcodes are what a hex
 * rule is written against, byte for byte" - and it is still true of them. So
 * what is kept is the executable SECTIONS, which is what that sentence was
 * always about, and the rest of the segment is rewritten like any other data.
 *
 * ONLY WHERE THE FILE SAYS SO. A stripped object with no section table cannot
 * tell its instructions from its strings, and guessing would move opcodes. It
 * keeps the whole region, exactly as before.
 */
static void norm_keep_exec(uint8_t *keep, uint64_t n,
			   const struct kof_elf_info *e,
			   const struct kof_src_region *r, uint32_t nr)
{
	uint32_t i;

	if (!e || !e->sec_count)
		return;
	/* Take the whole of CODE back... */
	for (i = 0; i < nr; i++) {
		uint64_t j, end;

		if (r[i].mask != (uint32_t)KOF_SCAN_ELF_CODE)
			continue;
		if (r[i].off >= n)
			continue;
		end = r[i].len > n - r[i].off ? n : r[i].off + r[i].len;
		for (j = r[i].off; j < end; j++)
			keep[j >> 3] &= (uint8_t)~(1u << (j & 7u));
	}
	/* ...and give back only what is instructions. */
	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++) {
		const struct kof_elf_sec *c = &e->sec[i];
		uint64_t j, end;

		if (!(c->flags & 0x4u))         /* SHF_EXECINSTR */
			continue;
		if (!c->file_size || c->file_off >= n)
			continue;
		end = c->file_size > n - c->file_off ? n
						     : c->file_off + c->file_size;
		for (j = c->file_off; j < end; j++)
			keep[j >> 3] |= (uint8_t)(1u << (j & 7u));
	}
}

static void norm_emit(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	uint8_t *out, *tmp, *keep, *drop;
	const struct kof_lib_all *lib;
	uint64_t n, sent = 0;
	int changed;
	struct kof_src_region rgn[KOF_SRC_MAX_REGIONS];
	struct kof_src_region rgn0[KOF_SRC_MAX_REGIONS];
	uint64_t mark[2u * KOF_SRC_MAX_REGIONS];
	uint64_t mark_out[2u * KOF_SRC_MAX_REGIONS];
	uint32_t midx[2u * KOF_SRC_MAX_REGIONS];
	uint32_t nr, n_rgn0, n_mark = 0, fired = 0;

	/*
	 * PE AND ELF ONLY, AND ONLY WHAT WAS NOT ITSELF PRODUCED.
	 *
	 * Other formats have their own openers - an archive yields its entries,
	 * a document its streams - and normalising those would be a second
	 * answer to a question already answered.
	 *
	 * A VIEW IS NOT NORMALISED AGAIN, AND IT IS STOPPED HERE RATHER THAN
	 * BY ARITHMETIC.
	 *
	 * This used to say that nothing had to stop it because the transform is
	 * idempotent - no zero run survives eight long, no UTF-16 run survives
	 * at all - so a second pass would change nothing and produce no child.
	 * That reasoning was true of the transform and false of the OBJECT.
	 *
	 * Collapsing a zero run MOVES the bytes after it. Two stretches that
	 * were far apart end up adjacent, and a run of hex characters long
	 * enough to decode can exist in the view that existed nowhere in the
	 * parent. The decode then reports a change, a view of the view is made,
	 * and its own collapse creates the next one: measured on a 4.5 MB
	 * miner, norm//norm//norm to the depth budget, every level carrying the
	 * same detection.
	 *
	 * THE OBJECT SAYS SO ITSELF - see kof_src_declare_view - rather than
	 * being recognised by a side effect. This was "has a declared region
	 * table", which every view has EXCEPT one made from an object whose
	 * regions could not be resolved, and that exception was a real one.
	 */
	if (sc->cur_is_view)
		return;
	if (!ctx || (ctx->format != KOF_FMT_ELF && ctx->format != KOF_FMT_PE))
		return;
	if (buf.n < NORM_MIN_OBJ)
		return;

	/*
	 * AND NOT AN OBJECT TOO LARGE TO HOLD TWICE, WHICH IS ASKED HERE AND
	 * NOT AT THE END.
	 *
	 * The two working buffers below are the OBJECT'S size each - the
	 * transform reads one and writes the other - and neither is charged to
	 * the resident budget, because the sink only charges the view when it
	 * is handed over and that is after all the work. The test at the end of
	 * this function asks about the VIEW, which by then has already cost
	 * twice the input to produce.
	 *
	 * Measured, and this is why it is here: an 800 MB ELF - a real binary
	 * with zeros appended - took the scanner to 1.6 GB of peak RSS to build
	 * a view that the ceiling at the end then refused. The file is mapped,
	 * so its size is not the scanner's to choose; what the scanner chooses
	 * is whether to copy it, and it cannot afford to copy this one twice.
	 *
	 * HALF THE HEADROOM, in the same terms the rest of the engine uses,
	 * rather than a number of its own: resident_max is the ceiling the
	 * caller set and two buffers is what this costs. An object over that is
	 * left unnormalised - it is still parsed, still scanned, still carved.
	 */
	if (sc->resident > sc->resident_max ||
	    buf.n > (sc->resident_max - sc->resident) / 2u)
		return;

	/*
	 * A VIEW, NOT A SECOND EXECUTABLE - AND THE ORDER OF THE THREE PASSES
	 * IS DECIDED RATHER THAN INCIDENTAL.
	 *
	 *   1  unwide    UTF-16 ASCII becomes ASCII. Length preserving: the
	 *                vacated half of the run is zeroed.
	 *   2  unb64     the payload of `... | base64 -d` becomes what it
	 *                decodes to. Also length preserving, also zero filled.
	 *   3  nullrun   every zero run of eight or more becomes TWO zeros.
	 *                This one SHORTENS, and it is what makes the view a
	 *                view rather than a copy.
	 *
	 * Narrow before decoding, because a payload stored as UTF-16 is not
	 * base64 until it has been narrowed, and nothing decoded can turn into
	 * wide text. Collapse LAST, because the two passes above each leave a
	 * zero run behind them and collapsing first would leave those uncollapsed
	 * - the fill from a 4 KB payload is a kilobyte of zeros that nothing
	 * will ever match.
	 *
	 * TWO ZEROS AND NOT ONE, which is the whole safety argument and is set
	 * out in executables.h: a literal pattern cannot contain a zero byte,
	 * so collapsing to two never puts two non-zero bytes beside each other
	 * that were not beside each other before. Collapsing to ONE would - and
	 * a single zero also reads as the high half of a UTF-16 character that
	 * is not there, which is the thing pass 1 exists to find.
	 *
	 * THE PARENT IS STILL SCANNED, so nothing is traded away by this. The
	 * view is an ADDITIONAL object, and a pattern that only matches the
	 * original still matches the original.
	 */
	/*
	 * THE PARENT'S REGIONS FIRST, because they decide what may be rewritten
	 * and they are also what the view will carry.
	 *
	 * An object nothing could parse yields none. That is not a reason to
	 * refuse: a view of it is still worth having, it simply has nothing to
	 * keep and nothing to declare, and the transform runs over the whole of
	 * it exactly as it did before regions were understood here.
	 */
	nr = norm_gather(ctx, rgn, KOF_SRC_MAX_REGIONS);
	/*
	 * THE PARENT'S OWN COORDINATES, KEPT. `rgn` is rewritten into the
	 * view's below, and the library spans are file offsets - so deciding
	 * which region a span came out of has to be done against the table as
	 * it was.
	 */
	memcpy(rgn0, rgn, nr * sizeof rgn[0]);
	n_rgn0 = nr;

	/*
	 * AND THE STATIC LIBRARY, WHICH LEAVES THE VIEW ALTOGETHER.
	 *
	 * Those bytes are the toolchain's, not the author's: measured over 226
	 * Linux malware samples the library is a mean 22% of CODE and past half
	 * of it in 46, and two unrelated CLEAN binaries reach a string-set
	 * Jaccard of 0.99 through nothing but a shared libc. A view of what the
	 * object actually carries is a view without them.
	 *
	 * FOUND ON THE PARENT, WHERE THE PARSE IS TRUE. kof_lib_find works from
	 * markers inside a loadable segment, so it needs segment offsets that
	 * describe the bytes it is reading - which is the case here and is not
	 * the case on a view, whose headers still describe the file before the
	 * padding came out. That is why it is refused there and used here.
	 */
	/*
	 * INHERITED, NOT WORKED OUT AGAIN - see kof_scanner.cur_lib. The gate
	 * that used to be here, refusing the cut on a dynamically linked
	 * object, moved with it: lib_facts asks the marker tier only of a
	 * static build and the symbol tier of everything.
	 */
	lib = &sc->cur_lib;

	out = malloc((size_t)buf.n);
	tmp = malloc((size_t)buf.n);
	keep = nr ? malloc((size_t)((buf.n + 7u) / 8u)) : NULL;
	drop = lib->n ? malloc((size_t)((buf.n + 7u) / 8u)) : NULL;
	if (!out || !tmp || (nr && !keep) || (lib->n && !drop)) {
		free(out);
		free(tmp);
		free(keep);
		free(drop);
		return;
	}
	if (nr) {
		norm_keep_bits(keep, buf.n, rgn, nr);
		/* And CODE narrowed to the instructions in it - see
		 * norm_keep_exec. */
		if (ctx->format == KOF_FMT_ELF && ctx->file_header)
			norm_keep_exec(keep, buf.n, kof_elf(ctx), rgn, nr);
	}
	if (lib->n) {
		uint32_t a;

		memset(drop, 0, (size_t)((buf.n + 7u) / 8u));
		for (a = 0; a < lib->n; a++) {
			uint64_t j, e;

			if (lib->span[a].off >= buf.n)
				continue;
			/*
			 * Clipped by the room LEFT rather than by the sum:
			 * off + len is the natural way to write this and it
			 * wraps on a length the parse got wrong, landing below
			 * off - where the loop runs zero times and the span
			 * silently drops nothing at all. Subtraction cannot
			 * wrap here, off being known smaller than buf.n.
			 */
			e = lib->span[a].len > buf.n - lib->span[a].off
				  ? buf.n
				  : lib->span[a].off + lib->span[a].len;
			for (j = lib->span[a].off; j < e; j++)
				drop[j >> 3] |= (uint8_t)(1u << (j & 7u));
		}
	}

	/*
	 * THE DECODE PASSES, THEN THE KEPT BYTES PUT BACK.
	 *
	 * kof_exe_decode runs base64 and hex, layer by layer, rewriting in
	 * place and preserving length - so running it over everything and then
	 * restoring what must not change is exact, and it is far simpler than
	 * teaching each anchor walk about a bitmap.
	 * A payload that straddles a kept boundary is decoded on the unkept
	 * side and undone on the other, which is the same answer a masked walk
	 * would give and costs nothing to arrive at.
	 *
	 * Before the collapse, because the collapse is what moves bytes and the
	 * decode has to happen while offsets still mean what the bitmap says.
	 */
	memcpy(tmp, buf.p, (size_t)buf.n);
	changed = kof_exe_decode(tmp, buf.n);
	if (nr && changed) {
		uint64_t j;

		for (j = 0; j < buf.n; j++)
			if (keep[j >> 3] & (uint8_t)(1u << (j & 7u)))
				tmp[j] = buf.p[j];
		/*
		 * AND THE ANSWER IS WHAT SURVIVED THE RESTORE, NOT WHAT THE
		 * DECODE DID.
		 *
		 * `changed` decides below whether this view is worth making at
		 * all, and a decode that happened entirely inside a KEPT region
		 * has just been undone byte for byte - so the view it would
		 * justify shows nothing the parent does not already show. It is
		 * not a hypothetical: a run of hex digits long enough to decode
		 * turns up inside an instruction stream by accident, and CODE
		 * is kept whole. Measured over 459 malware objects, 35 of them
		 * report a decode that the restore takes straight back out.
		 *
		 * Compared rather than tracked, because the restore loop cannot
		 * tell a byte it put back from a byte the decode never touched,
		 * and the comparison is one pass over an object that has
		 * already had several.
		 */
		changed = memcmp(tmp, buf.p, (size_t)buf.n) != 0;
	}

	/*
	 * AND THE COLLAPSE, WHICH IS THE ONLY PASS THAT MOVES ANYTHING - so it
	 * is the only one that has to report where the boundaries went.
	 *
	 * The marks are every region's start and end, sorted, because the
	 * walk that answers them runs forward once and regions overlap: an
	 * ELF's header tables sit inside its first loadable segment, so the
	 * starts and ends do not arrive in order by themselves.
	 */
	{
		uint32_t a, b;

		for (a = 0; a < nr; a++) {
			mark[2u * a] = rgn[a].off;
			mark[2u * a + 1u] = rgn[a].off + rgn[a].len;
			midx[2u * a] = 2u * a;
			midx[2u * a + 1u] = 2u * a + 1u;
		}
		n_mark = 2u * nr;
		/* Insertion sort: at most 32 entries, and a qsort here would be
		 * a comparator and a context pointer for a list this size. */
		for (a = 1; a < n_mark; a++) {
			uint64_t v = mark[a];
			uint32_t vi = midx[a];

			for (b = a; b > 0 && mark[b - 1u] > v; b--) {
				mark[b] = mark[b - 1u];
				midx[b] = midx[b - 1u];
			}
			mark[b] = v;
			midx[b] = vi;
		}
	}

	n = kof_exe_norm_masked(tmp, buf.n, keep, drop,
				KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
				out, buf.n, mark, mark_out, n_mark, &fired);
	/*
	 * A VIEW IS MADE ONLY WHEN IT CAN SHOW SOMETHING THE PARENT CANNOT.
	 *
	 * `changed` is the decode passes; kof_exe_norm_masked reports whether
	 * it narrowed wide text or collapsed a zero run, and those two are not
	 * worth the same:
	 *
	 *   DE-WIDENING REVEALS. "41 00 42 00" becomes "AB", and an ASCII
	 *   pattern that could not match the parent matches the view. Same for
	 *   a decoded payload.
	 *
	 *   COLLAPSING ZEROS REVEALS NOTHING, and that is proved rather than
	 *   assumed - see the safety note in executables.h. A literal cannot
	 *   contain a zero byte, so a pattern matches a run of consecutive
	 *   NON-ZERO bytes, and collapsing to two zeros never puts two
	 *   non-zero bytes beside each other that were not beside each other
	 *   before. No match is created. A view that only collapsed zeros
	 *   therefore matches exactly what its parent matches, and scanning it
	 *   is provably redundant work.
	 *
	 * It is still done on a view that IS made, because it makes that view
	 * smaller and cheaper. It is just not a reason to make one.
	 *
	 * MEASURED, because the saving is most of the cost: of 846 ELF in
	 * /usr/bin, 746 produce a view that only collapsed zeros - 88% of the
	 * second scan, buying nothing. In a corpus of 243 Linux malware
	 * samples it is 82 of them.
	 */
	/*
	 * CUTTING THE LIBRARY IS A REASON ON ITS OWN, beside de-widening and
	 * decoding. All three REVEAL: two make unreadable bytes readable, and
	 * this one takes away bytes that belong to somebody else, so what is
	 * left is the object's own content and a similarity measured over it
	 * means something. Collapsing zeros is still not a reason - it is
	 * proved to create no match that the parent does not already have.
	 */
	if (!(fired & (KOF_EXE_NORM_UNWIDE | KOF_EXE_NORM_CUTLIB)) && !changed) {
		free(out);
		free(tmp);
		free(keep);
		free(drop);
		return;
	}
	/*
	 * A LENGTH OF ZERO MEANS TWO DIFFERENT THINGS AND THEY ARE TOLD APART
	 * BY `fired`, NOT BY THE LENGTH.
	 *
	 * kof_exe_norm_masked returns 0 when it rewrote nothing, and it also
	 * returns 0 when it rewrote everything AWAY - an object whose every
	 * byte was dropped as library has an empty view and a length to match.
	 * `fired` is set for exactly the ops that did something, so it is the
	 * one that separates them: nothing fired means nothing moved.
	 *
	 * The first case is the 1:1 rewrite - the decode found something but
	 * there was no wide text, no zero run and nothing to cut, so the view
	 * is tmp as it stands and the boundaries are where they were.
	 *
	 * The second is refused. An empty view has no bytes to scan and a
	 * region table describing none of them, and handing one over would put
	 * an object into the tree that says it is an executable and contains
	 * nothing. It takes a library covering the whole object, header
	 * included, which is not something kof_lib_find can currently produce -
	 * the test is here so that the day it can, this says no rather than
	 * building a copy of the parent and calling it a view.
	 */
	if (!fired) {
		memcpy(out, tmp, (size_t)buf.n);
		n = buf.n;
		for (n_mark = 0; n_mark < 2u * nr; n_mark++)
			mark_out[n_mark] = mark[n_mark];
	} else if (!n) {
		free(out);
		free(tmp);
		free(keep);
		free(drop);
		return;
	}
	free(tmp);
	tmp = NULL;
	free(drop);
	drop = NULL;

	/*
	 * THE REGIONS, IN THE VIEW'S OWN COORDINATES.
	 *
	 * Scattered back through the sort, so each region gets its own two
	 * answers rather than whichever two happened to be next. A region whose
	 * end no longer follows its start is dropped: that cannot happen from
	 * this transform, and a region of negative length is the sort of thing
	 * that should stop here rather than reach a matcher.
	 */
	{
		uint32_t a;

		for (a = 0; a < 2u * nr; a++)
			mark[midx[a]] = mark_out[a];
		for (a = 0; a < nr; a++) {
			uint64_t o0 = mark[2u * a], o1 = mark[2u * a + 1u];

			/*
			 * Back into rgn[] rather than straight onto the
			 * scanner: kof_mod_unpack_mode clears the pending
			 * claims, and it has not run yet. Written there and
			 * this table would be wiped before the child it
			 * describes was ever made.
			 */
			rgn[a].off = o0;
			rgn[a].len = o1 > o0 ? o1 - o0 : 0u;
		}
	}
	free(keep);
	keep = NULL;

	/*
	 * AND THE LIBRARY BACK ON THE END, UNDER A NAME THAT SAYS WHAT IT IS.
	 *
	 * Cut and discarded, those bytes were a blindspot: nothing could look
	 * at them, no rule could be written about them, and the difference
	 * between the file and its view could not be accounted for. They are
	 * moved instead - appended in file order and given a region of their
	 * own, SLIB_CODE for what came out of CODE and SLIB_DATA for what came
	 * out of DATA - see KOF_SCAN_ELF_SLIB_CODE.
	 *
	 * WHAT THE CUT WAS FOR STILL HOLDS. A block or a measure anchored to
	 * CODE no longer reaches them, because they are not in CODE any more;
	 * a similarity taken over the view's own regions is still over the
	 * author's bytes alone. What changes is that the toolchain's half is
	 * describable rather than gone.
	 *
	 * IT FITS, AND NOT BY LUCK. The body is the input less what was
	 * dropped and less what the collapse took out; adding the dropped
	 * bytes back gives the input less the collapse, which is at most the
	 * input - and `out` is the input's size.
	 *
	 * IN FILE ORDER AND IN ONE RUN PER REGION, so each region is one
	 * extent: the spans are already sorted, so walking them twice - once
	 * for the code side, once for the data side - lays each down
	 * contiguously.
	 */
	if (lib->n && n_rgn0 && n < buf.n) {
		static const uint32_t pair[2][2] = {
			{ (uint32_t)KOF_SCAN_ELF_CODE,
			  (uint32_t)KOF_SCAN_ELF_SLIB_CODE },
			{ (uint32_t)KOF_SCAN_ELF_DATA,
			  (uint32_t)KOF_SCAN_ELF_SLIB_DATA }
		};
		uint32_t side, a, b;

		for (side = 0; side < 2u && nr < KOF_SRC_MAX_REGIONS; side++) {
			uint64_t begin = n;

			for (a = 0; a < lib->n && n < buf.n; a++) {
				uint64_t off = lib->span[a].off, e, j;
				int mine = 0;

				if (off >= buf.n)
					continue;
				e = lib->span[a].len > buf.n - off
				  ? buf.n : off + lib->span[a].len;
				/* Which of the parent's regions these bytes
				 * came out of - the same table the view's own
				 * regions were resolved from. */
				for (b = 0; b < n_rgn0; b++)
					if (rgn0[b].mask == pair[side][0] &&
					    off >= rgn0[b].off &&
					    off < rgn0[b].off + rgn0[b].len) {
						mine = 1;
						break;
					}
				if (!mine)
					continue;
				for (j = off; j < e && n < buf.n; j++)
					out[n++] = buf.p[j];
			}
			if (n > begin) {
				rgn[nr].mask = pair[side][1];
				rgn[nr].off = begin;
				rgn[nr].len = n - begin;
				nr++;
			}
		}
	}

	/*
	 * THE UNPACK VTABLE, BORROWED FOR THE LENGTH OF ONE CHILD.
	 *
	 * emit and child are NULL on the detect vtable - a detector may not
	 * produce objects, which is the rule that keeps a signature from
	 * inventing evidence - and by here the context is back in detect mode.
	 * The host is not a detector, so it turns the producing half on, makes
	 * the one child it came to make, and puts the context back exactly as
	 * it found it.
	 *
	 * Through the module sink, so the view is charged, capped and spilled
	 * by exactly the code that does that for a decompressed child. There is
	 * no second budget here and no path by which this can exceed the
	 * ceiling the caller set.
	 */
	/*
	 * A VIEW THAT WILL NOT FIT IS NOT PRODUCED AT ALL, and finding that out
	 * HERE rather than from the sink is the whole of this test.
	 *
	 * c_emit closes what it is holding as a CHILD when the object cap is
	 * reached and then refuses the rest. For a decompressor that is right:
	 * the first 16 MB of an entry is a prefix of a real file and is worth
	 * scanning. For a view it is not. A prefix of a view still carries the
	 * parent's header, which describes a file three times its length, so
	 * the object handed over is an executable whose sections run off the
	 * end - and the structural heuristics say so.
	 *
	 * Measured, before this: /usr/bin/doxygen normalises to 25.4 MB against
	 * a 16 MB cap, the sink closed the first 16 MB as a child, and it came
	 * back ELF-other/Heur:Appended. doxygen has no overlay at all - its
	 * section table ends exactly at end of file. The finding was entirely
	 * this function's. /usr/bin/lto-dump was the same.
	 *
	 * Both ceilings are asked about, in the same terms c_emit uses, because
	 * either of them produces the same half object.
	 */
	if (n > sc->obj_cap ||
	    sc->resident > sc->resident_max ||
	    n > sc->resident_max - sc->resident) {
		free(out);
		return;
	}
	kof_mod_unpack_mode(ctx, 1);
	/*
	 * DECLARED BEFORE THE FIRST BYTE, NOT AFTER THE LAST.
	 *
	 * kof_mod_unpack_mode clears the pending claims, so this cannot be said
	 * any earlier - and it must not be said any later. c_child is what
	 * spends them, and c_emit calls c_child by itself on any ceiling it
	 * hits. A claim made after the emit loop is a claim made after the
	 * child it was about has already been pushed.
	 *
	 * The test above means that should no longer happen. This is here so
	 * that if it does, the object that goes out is still labelled and still
	 * raw, rather than an unnamed ELF-looking blob.
	 */
	/* The word itself is in kofeng.h, because the tools read it back out
	 * of the object's name - see kof_obj_label. */
	sc->pend_label_len = (uint32_t)snprintf(sc->pend_label,
						sizeof sc->pend_label, "%s",
						KOF_OBJ_LABEL_NORM);
	sc->pend_fmt = nr ? ctx->format : (uint8_t)KOF_FMT_DECLARED_RAW;
	/* What this object IS, said rather than inferred - see
	 * kof_src_declare_view. */
	sc->pend_view = 1;
	{
		uint32_t a;

		for (a = 0; a < nr; a++)
			sc->pend_rgn[a] = rgn[a];
		sc->n_pend_rgn = nr;
		/*
		 * IN THE PARENT'S VOCABULARY, and that has to travel with the
		 * table. These bits were resolved out of the parent, and a bit
		 * alone says nothing: 1u << 5 is UNCLAIMED in an ELF and
		 * OVERLAY in a PE. Without it the viewer had five region rows
		 * it could not name and dropped every one - the view showed no
		 * regions at all, which looked like the table never arrived.
		 */
		sc->pend_rgn_fmt = ctx->format;
	}
	/*
	 * AND THE SYMBOLS, HERE FOR THE REASON THE REGIONS ARE: this is after
	 * kof_mod_unpack_mode cleared the pending claims and before c_child
	 * spends them. See norm_syms.
	 */
	if (!sc->pend_syms)
		sc->pend_syms = malloc(KOF_SYM_MAX_BYTES);
	if (sc->pend_syms)
		sc->n_pend_syms = norm_syms(sc, ctx, sc->pend_syms,
					    KOF_SYM_MAX_BYTES);
	while (sent < n) {
		uint64_t take = n - sent;

		if (take > (1u << 20))
			take = 1u << 20;
		if (!ctx->content->emit(ctx, out + sent, (uint32_t)take))
			break;                  /* a limit said no; keep what is */
		sent += take;
	}
	free(out);
	if (sent == n) {
		/*
		 * AND DECLARED RAW, WHICH IS WHAT IT NOW IS.
		 *
		 * Collapsing a zero run moves every byte after it, so the
		 * view's headers describe a file that is no longer under them:
		 * section offsets point past their sections, the last program
		 * header runs off the end. It is not an ELF any more and it is
		 * not a PE - it is a run of bytes that happens to start with
		 * one's magic.
		 *
		 * Left as its parent's format, the structural heuristics read
		 * it as a broken executable and say so. Measured on the first
		 * run of this: gawk's view came back
		 * "ELF-other/Heur:Appended", which is a finding about the
		 * normaliser rather than about gawk.
		 *
		 * Raw is the right target and needs no new format - every
		 * string and hex rule that asks for raw still searches the
		 * view, which is the whole reason it exists, and nothing that
		 * reasons about a header is offered one to reason about.
		 *
		 * SAID WITH KOF_FMT_DECLARED_RAW AND NOT WITH
		 * KOF_FMT_UNKNOWN, which is the gap this used to fall into.
		 * UNKNOWN is 0, the child builder reads the pending format as
		 * `if (sc->pend_fmt)`, and so "declared raw" and "declared
		 * nothing" were one value: the view was sniffed from its own
		 * bytes, those bytes still begin \x7fELF, and it came back a
		 * damaged executable. See the sentinel in scan.h.
		 */
		{
			uint32_t k0 = sc->n_kids;
			(void)ctx->content->child(ctx);
			/* Counted only if it was actually taken: the child cap
			 * can refuse it, and a view that was refused is not a
			 * view that has to be discounted later. */
			if (sc->n_kids > k0)
				sc->n_views++;
		}
	}
	kof_mod_unpack_mode(ctx, 0);
}

/*
 * OPENING AN OBJECT, IN ORDER.
 *
 * The steps of enum kof_analyze, each one a runner, tried from the top until
 * one of them produces something. What comes out is a child, and a child comes
 * back round to the top of this same list on its own pass - so the order below
 * is not "what to do to this object", it is "what to try first", and the rest
 * happens by recursion.
 *
 * WHY A TABLE AND NOT THE THREE CALLS IT REPLACES.
 *
 * The rule "stop at the first step that yields" was already here, written out
 * by hand: unpack_object, then a kids0 comparison, then norm_emit under an if.
 * Written that way it holds for exactly the two things that were wired up, and
 * the next step added has to re-derive it - which is how norm_emit came to be
 * called BEFORE unpacking in its first version, and gave a UPX stub a view of
 * its own compressed payload. Here the rule is the loop, once, and a new step
 * is a row.
 *
 * WHAT THE FIRST ROW IS HIDING, WHICH IS THE POINT OF THE first/last FIELDS.
 *
 * One runner covers four steps, because today a module cannot ask for anything
 * finer: every module in bases/unp/ declares KOF_UNPACK_KIND(KOF_UNP_PACKER) -
 * the packers, the AES decryptor, the five msf decoders and the payload carver,
 * all the same word - and unpack_object walks them in database order. So the
 * row says UNWRAP..CARVE and means it: those four are not ordered with respect
 * to each other yet. When a module starts declaring its real step, this row
 * splits into rows and the loop above it does not change.
 *
 * The last row is the host's own and has no modules: NORMZ is norm_emit.
 */
struct analyze_arg {
	struct kof_scanner              *sc;
	struct kof_obj_ctx              *ctx;
	const struct kof_scan_option    *opt;
	struct kof_result               *out;
	kof_buf                          buf;
	uint32_t                         pdepth;
	uint32_t                         want;
	const char                      *predict;
};

static void step_open(struct analyze_arg *a)
{
	a->out->broken = unpack_object(a->sc, a->ctx, a->opt, a->out,
				       a->pdepth, a->want, a->predict);
}

static void step_normz(struct analyze_arg *a)
{
	norm_emit(a->sc, a->ctx, a->buf);
}

static const struct analyze_step {
	enum kof_analyze  first;	/* the steps this runner serves, */
	enum kof_analyze  last;		/* inclusive - see above	 */
	void            (*run)(struct analyze_arg *);
} analyze_steps[] = {
	{ KOF_ANALYZE_UNWRAP, KOF_ANALYZE_CARVE, step_open  },
	{ KOF_ANALYZE_NORMZ,  KOF_ANALYZE_NORMZ, step_normz }
};

static void analyze_object(struct analyze_arg *a)
{
	uint32_t i;

	for (i = 0; i < sizeof analyze_steps / sizeof analyze_steps[0]; i++) {
		uint32_t kids0 = a->sc->n_kids;
		uint32_t carved0 = a->sc->n_carved;

		analyze_steps[i].run(a);
		/*
		 * PRODUCED SOMETHING, SO STOP.
		 *
		 * The object is a wrapper around the thing that just came out,
		 * and the thing is what is worth looking at. Asking a later
		 * step about the wrapper cannot help: normalising a compressed
		 * or encrypted blob finds no zero runs and no text, because
		 * there is none to find until it has been opened.
		 *
		 * n_kids is how the rest of this file already asks "was it
		 * opened" - see family_opened in unpack_object, which compares
		 * the same counter across the same call. A container yields
		 * too, and stops the chain for the same reason: an archive's
		 * bytes ARE its members, and each member is normalised as
		 * itself when its own pass reaches this loop.
		 */
		/*
		 * A CARVED CHILD DOES NOT STOP THE CHAIN.
		 *
		 * The rule is "something came out of this, so the thing that
		 * came out is the subject" - true of a container's member and
		 * of an unpacked image, and false of a payload found by
		 * searching. Nothing declared that an ELF is carrying a file,
		 * so the host is a whole program that happens to have one glued
		 * on, and it still deserves the steps below.
		 *
		 * Measured before this: an 8.6 MB ELF with 4.2 MB appended had
		 * the appendix extracted and then no normalised view of itself
		 * at all, so the 4.4 MB that is the actual program - with a
		 * static library inside it to cut - was never rendered.
		 */
		/*
		 * WHAT THIS STEP PRODUCED, not what the object has.
		 *
		 * Both counters run for the whole object while `kids0` is this
		 * step's, so subtracting the total carved from the total kids
		 * and comparing against a per-step mark mixes two scopes. An
		 * earlier step's carve then reads as a shortfall in this one -
		 * harmless only because NORMZ happens to be last, which is the
		 * kind of accident that stops being true when a step is added.
		 */
		if (a->sc->n_kids - kids0 != a->sc->n_carved - carved0)
			return;
		/*
		 * And between steps, because a step is the unit of work that
		 * is worth interrupting: unpacking a large object is where the
		 * time goes, and a cancel asked for during it should not then
		 * pay for a normalisation nobody is waiting for.
		 */
		if (a->opt->should_stop && a->opt->should_stop(a->opt->stop_user))
			return;
	}
}


static void scan_object(struct kof_scanner *sc, kof_buf buf,
			const struct kof_scan_option *opt, struct kof_result *out,
			uint32_t pdepth, int from_packer,
			const char *inherit_predict, uint8_t as_fmt)
{
	struct kof_obj_ctx ctx;
	uint32_t present, want;
	const char *predict = NULL;

	out->from_packer = (uint8_t)(from_packer != 0);
	memset(&ctx, 0, sizeof ctx);
	kof_mod_attach(&ctx, sc);

	/*
	 * How big the object is, before anything tries to identify it.
	 *
	 * It is a property of the bytes, not of the parse, and leaving it to the
	 * collectors meant an object nothing recognised reported a size of zero.
	 * Everything downstream reads that as an empty file: KOF_SCAN_ALL resolves
	 * to no extents, so regions_present drops it, so the prefilter skips every
	 * module that names it - which is precisely the modules written to run on
	 * anything, the ones with no format header at all. They could not match an
	 * unidentified object, ever, and nothing said so.
	 */
	ctx.obj_size = buf.n;

	kof_match_begin(&sc->m, buf);
	/* A new object: whatever block the last one had is not this one's, and
	 * neither is the matcher bound to it. */
	/* The sentinel and not zero: zero is entry 0. Reset per object, like
	 * every other pending declaration, so one object's claim cannot be
	 * worn by the next. */
	sc->pend_entry = KOF_ENTRY_NONE;
	/* And no finding of the last object's is protected from this one's
	 * drop: the bits are slot numbers in a result about to be refilled, so
	 * a stale one would shelter whatever lands in that slot next. */
	sc->heur_keep = 0;
	sc->sym_done = 0;
	sc->sym_n = 0;
	sc->msym_bound = 0;
	sc->sym_ext_done[0] = sc->sym_ext_done[1] = 0;
	/* And whatever the last object's code did with its addresses. Freed
	 * rather than kept the way `sym` is: the block has a fixed cap and is
	 * reused, this is sized by what a sweep found and reusing it would mean
	 * carrying the largest one met so far for the rest of the walk. */
	kof_xref_free(sc->use);
	sc->use = NULL;
	sc->use_done = 0;

	/*
	 * THE CHILD'S OWN DECLARATION FIRST, then the caller's.
	 *
	 * opt->as_format is about the object the CALLER handed in - a submitted
	 * event record, which has no magic for a sniff to find. as_fmt is what
	 * the thing that produced THIS child said about it, and for a child the
	 * second is the specific claim: the caller's applies to the root of the
	 * walk and would otherwise be re-applied to every object under it.
	 */
	identify(sc, buf, &ctx,
		 as_fmt ? as_fmt : (opt ? opt->as_format : 0u),
		 opt ? opt->as_view : NULL, opt ? opt->as_view_len : 0u);
	/* And the one fact about it that three later steps would each have
	 * worked out for themselves - see lib_facts. */
	lib_facts(sc, &ctx, buf);

	/*
	 * A DECLARED REGION TABLE BEATS A PARSED ONE, and for an object that
	 * has one there is no parsed one to beat.
	 *
	 * Installed after identify rather than inside it because identify's job
	 * is to say WHAT the object is, and this says where its parts are -
	 * which the producer knew and no reading of the bytes can recover. See
	 * kof_src_declare_regions.
	 */
	if (sc->n_cur_rgn) {
		uint32_t g;

		ctx.resolve_scan = declared_resolve_scan;
		/* And out to the caller, which has the same problem the engine
		 * had: it cannot work these out from the bytes either. */
		for (g = 0; g < sc->n_cur_rgn && g < KOF_MAX_REGIONS; g++) {
			out->region[g].mask = sc->cur_rgn[g].mask;
			out->region[g].off = sc->cur_rgn[g].off;
			out->region[g].len = sc->cur_rgn[g].len;
		}
		out->n_region = g;
		out->region_fmt = sc->cur_rgn_fmt;
	}

	present = regions_present(&ctx, sc->eng->scan_mask);
	present |= sym_halves_present(&ctx, sc->eng->scan_mask);
	sc->st.objects++;
	sc->st.object_bytes += buf.n;

	/* Before any module: one pass per region worth one, filling the memo the
	 * modules' own calls are about to read. */
	multi_prepass(sc, &ctx, present);

	/*
	 * And the same for similarity: every block any loaded rule declared is
	 * counted here, once, so a module's kof_plague_score is a division.
	 *
	 * Gated twice on purpose. The set is NULL unless some pack carried a
	 * block, so a database without plague rules never reaches this. And
	 * within it, a region is fed only for the normalizers some block of
	 * that region actually asked for - a pack whose blocks all hash raw
	 * bytes pays one pass, not three.
	 */
	plague_prepass(sc, &ctx, present, from_packer);
	/*
	 * THIS OBJECT'S STRING SET IS NOT THE LAST ONE'S.
	 *
	 * Here and not inside plague_prepass, which returns early when no pack
	 * carried a block: a database with no plague rules would then have left
	 * the previous object's set in place, and every kof_ovl_strings rule
	 * would have measured the wrong file. Built on the first ask - see
	 * c_ovl_strings - so this costs a store.
	 */
	sc->ovl_ready = 0;
	sc->cure_have = 0;
	sc->cure_at = 0;
	sc->n_cure_fix = 0;
	sc->cure_trunc_set = 0;
	sc->ovl_asked = -1;
	sc->ovl_pct = 0;
	/* And the swept chains, for the same reason and at the same cost. */
	sc->fchain_ready = 0;
	/* What the two gated measures compare themselves against - see
	 * kof_scanner.heur_lvl. Unstated is level 1, exactly as heur_object
	 * reads it, so the two cannot drift. */
	sc->heur_lvl = opt->heur_off ? 0u
		     : (opt->heur_level ? opt->heur_level : 1u);

	/*
	 * ONLY THE MODULES THAT COULD TARGET THIS FORMAT - see kof_engine.mod_at.
	 * The ones outside the run are excluded for exactly the reason
	 * kof_module_precond would have excluded them, so they are counted as
	 * such and the stats keep meaning what they meant.
	 */
	{
		const struct kof_engine *e = sc->eng;
		uint32_t lo = 0, hi = e->n_mods, k;
		const uint32_t *ix = NULL;

		if (e->mod_by_target && ctx.format < KOF_TARGET_COUNT) {
			ix = e->mod_by_target;
			lo = e->mod_at[ctx.format];
			hi = e->mod_at[ctx.format + 1u];
			sc->st.considered += e->n_mods - (hi - lo);
			sc->st.by_target  += e->n_mods - (hi - lo);
		}

	for (k = lo; k < hi; k++) {
		const struct kof_module *m = &e->mods[ix ? ix[k] : k];

		/*
		 * BETWEEN MODULES, WHICH IS WHERE A SLOW OBJECT CAN BE LEFT.
		 *
		 * The callback is the host's other way out and it runs once
		 * the object is finished; on a large shared object that is
		 * hundreds of milliseconds after the host asked to stop. This
		 * is the same question asked where the time is actually
		 * spent - see should_stop in kofeng.h.
		 *
		 * Before prefilter rather than after: a module ruled out by
		 * the prefilter costs almost nothing, so asking first is what
		 * puts the check on the path that is slow.
		 */
		if (opt->should_stop && opt->should_stop(opt->stop_user))
			break;

		if (!prefilter(m, &ctx, present, &sc->st, out))
			continue;

		sc->rep_valid = 0;
		/* Nothing asked yet - see scan.h. Reset beside rep_valid
		 * because it is the same kind of thing: what THIS module
		 * reported about this object. */
		sc->plague_asked = -1;
		sc->n_plague_blk = 0;
		sc->plague_hit = 0;
		sc->plague_tot = 0;
		sc->cur_mod   = m;
		sc->cure_have = 0;
		sc->cure_at   = 0;
		m->fn(&ctx);

		/*
		 * AND, IF IT BOTH FOUND SOMETHING AND KNOWS HOW TO UNDO IT,
		 * ASK IT WHAT THE REPAIR WOULD BE.
		 *
		 * Three conditions and every one of them is needed. The module
		 * has to have REPORTED, because a repair with no detection
		 * behind it is a file being rewritten for no stated reason. It
		 * has to have OFFERED - KOF_SCAN_CURABLE - because finding a
		 * family says nothing about where its payload starts and a
		 * repair without an offset has nothing to act on. And it has
		 * to HAVE a cure at all, which nearly no module does.
		 *
		 * WHAT COMES BACK IS A DESCRIPTION, not a changed file: see
		 * kof_content.cure_patch. Nothing on disk is touched here, by
		 * anybody, ever. A scan that repaired what it found would be a
		 * scan nobody could run twice.
		 */
		if (sc->rep_valid && sc->cure_have && m->cure) {
			uint32_t q;

			m->cure(&ctx);
			/*
			 * AND OUT TO THE CALLER, once, for the first module
			 * that described one. A second rule offering a second
			 * repair of the same object is two rules disagreeing
			 * about what it is, and applying either would be
			 * picking a side the engine has no basis to pick.
			 */
			if (!out->repair.n_fix && !out->repair.truncate) {
				for (q = 0; q < sc->n_cure_fix &&
					    q < KOF_MAX_FIX; q++) {
					out->repair.fix[q].off =
						sc->cure_fix[q].off;
					out->repair.fix[q].n =
						sc->cure_fix[q].n;
					memcpy(out->repair.fix[q].b,
					       sc->cure_fix[q].b,
					       sc->cure_fix[q].n);
				}
				out->repair.n_fix = q;
				out->repair.truncate = sc->cure_trunc_set
						       ? sc->cure_trunc : 0u;
			}
		}
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;

		/* Accumulate. Keeping only the last would drop a finding whenever two
		 * families match one object, and the cap is counted rather than
		 * silently applied. */
		if (out->n < KOF_MAX_FINDINGS) {
			struct kof_finding *f = &out->v[out->n++];
			f->level = sc->rep_level;
			finding_str(sc, &ctx, m, f);
		} else {
			out->dropped++;
		}

		/*
		 * Stop unless the caller asked for everything. The remaining modules
		 * can only lengthen a list that already says the object is not clean,
		 * and on a database of any size that is most of the work.
		 *
		 * It saves nothing on a clean object, which is nearly every object -
		 * this is a bound on the worst case, not a throughput win.
		 */
		if (!opt->all_matches)
			break;
	}
	}

	/* Before the next kof_match_begin clears them. */
	sc->st.searches       += sc->m.n_calls;
	sc->st.bytes_searched += sc->m.n_bytes_scanned;
	sc->st.gram_bytes     += sc->m.n_bytes_indexed;

	/*
	 * EXAMINE: what the object IS, asked before it is opened.
	 *
	 * Here and not earlier so a rule knows whether a family was named, and
	 * here and not later because this is the last moment at which what it
	 * asks for can still change what happens to the object.
	 */
	want = heur_run(sc, &ctx, opt, out, KOF_HEUR_EXAMINE, present, &predict);
	/*
	 * A rule's own guess wins; the inherited one is the fallback.
	 *
	 * A heuristic firing on THIS object knows more about it than its parent
	 * did - so its prediction takes precedence. The inherited family is for
	 * the case no rule fired at all, which is exactly the formatless
	 * intermediate layer a decoder peels: nothing recognises it, but its
	 * parent was a Meterp payload, so it very probably is one too, and
	 * trying that decoder first is the whole point of carrying the guess
	 * down.
	 */
	if (!predict)
		predict = inherit_predict;

	{
		struct analyze_arg a;

		a.sc = sc; a.ctx = &ctx; a.opt = opt; a.out = out;
		a.buf = buf; a.pdepth = pdepth; a.want = want;
		a.predict = predict;
		analyze_object(&a);
	}
	/*
	 * After, so a script that was packed is normalised as the source it
	 * turned out to be rather than as the wrapper - the unpacked child
	 * reaches this same step with its own parse behind it. The flag follows
	 * unpack_object's rule: "not fully examined" is only worth saying about
	 * an object something actually tried to open.
	 */
	if (script_forms(sc, &ctx, opt, pdepth) && sc->broken)
		out->broken = sc->broken;

	/* VERDICT: how it was reached, which only exists once it has been. */
	(void)heur_run(sc, &ctx, opt, out, KOF_HEUR_VERDICT, present, NULL);

	/*
	 * A RULE'S HEUR IS A LAST RESORT, and an object that OPENED is not the
	 * last resort - its children are.
	 *
	 * A rule says "I could not identify this, but here is its shape". When
	 * the object unpacks, the thing worth identifying is what came out, not
	 * the wrapper: rc4_1 is an encrypted stager, and the reader wants the
	 * Trojan:Meterp on the payload three layers down, not a Heur:Shellcode
	 * on the ciphertext that carried it. So a rule's heur on an object that
	 * produced children is dropped.
	 *
	 * THE SIGNAL IS NOT LOST, it MOVES. The same shape rule fires on the
	 * decoded child; if nothing can name that child either, the child
	 * produces no children of its own, so its heur is kept. The prediction
	 * ends up on the leaf that nothing could open or name, which is where
	 * "I could not identify this" belongs.
	 *
	 * DONE BEFORE heur_object, so only the RULE heur is dropped. The scored
	 * model that follows is about the object's own structure - a truncated
	 * header is truncated whether or not the object unpacked - so it is
	 * added after this and stays. Only children this object PRODUCED count;
	 * sc->n_kids is reset before it was scanned, and a container's members
	 * are its children too, but a container carries no rule heur to drop.
	 */
	/*
	 * A RULE MAY SAY ITS FINDING IS ABOUT THIS OBJECT.
	 *
	 * The assumption above - that a rule heur on an object which opened is
	 * always a failure to identify the wrapper - holds for every rule that
	 * guesses at a payload and for none that recognises a CARRIER. "This
	 * executable has a second executable glued to it" is true of the parent
	 * and of nothing else, and the child it names is an ordinary file that
	 * no shape rule fires on - so there is no leaf for the signal to move
	 * to and the drop would simply delete it.
	 *
	 * KOF_ENG_KEEP_ON_OPEN is how such a rule says so, per finding rather
	 * than per object: two rules may fire here and only one of them mean
	 * it. See sc->heur_keep and the note in kofmod/heur.h.
	 */
	/*
	 * VIEWS DO NOT COUNT, because nothing came out of the object when one
	 * was made - see kof_scanner.n_views. Subtracted rather than tested
	 * separately so the question stays the one it always was: did this
	 * object YIELD anything.
	 *
	 * AND NEITHER DOES A CARVE, for the reason that decides the same
	 * question in analyze_object and in the family pass: a carved child
	 * was not declared by anything, so the host did not turn out to be a
	 * wrapper around it. The drop above rests on "the finding belongs to
	 * the child that came out" - true of a container's member and of an
	 * unpacked image, and false of a file glued past the last segment. A
	 * shape rule that says "this object is packed" is not answered by
	 * finding something appended to it, and dropping it there deletes a
	 * verdict about the host with nowhere for it to go: the carved child
	 * is an ordinary file that no shape rule fires on.
	 *
	 * That is what KOF_ENG_KEEP_ON_OPEN was carrying on its own - see the
	 * note in bases/heur/appended_00.c, where the bit was added because
	 * three samples came back clean with the carried ELF extracted. The
	 * bit is still right for what it says, and it is still honoured below;
	 * it is simply no longer the only thing standing between a carve and
	 * a deleted finding, which would have needed every future rule to
	 * remember it.
	 */
	if (sc->n_kids > sc->n_views + sc->n_carved && out->n > 0) {
		uint32_t r, w = 0, keep = sc->heur_keep;

		for (r = 0; r < out->n; r++)
			if (out->v[r].level != KOF_LEVEL_HEUR ||
			    (keep & (1u << r)))
				out->v[w++] = out->v[r];
		out->n = w;
	}

	/*
	 * Last, because the unpack result is one of the facts - and NOT FOR A
	 * VIEW, whose structure is not its own.
	 *
	 * The scored model reads the parse: where the sections end against
	 * where the file ends, whether a segment runs past it. A normalised
	 * view keeps its parent's headers byte for byte and is SHORTER than
	 * they describe, so every one of those questions has the wrong answer
	 * about it - measured before this, an ordinary view came back
	 * ELF-other/Heur:Appended, which is a finding about the normaliser.
	 *
	 * The RULE heuristics still run: those read bytes, and the bytes are
	 * the point of having a view. Only the model that reasons about layout
	 * is skipped, because the layout belongs to the parent and the parent
	 * is scanned too.
	 */
	if (!sc->n_cur_rgn)
		heur_object(sc, &ctx, opt, pdepth,
			    out->broken == KOF_BROKEN_DAMAGED, out);
}

/*
 * Iterative, with its own stack of pending directories.
 *
 * Not recursive, and no depth ceiling: a filesystem may legally be deeper than any
 * number picked here, and putting the limit on the C stack makes the failure mode a
 * stack overflow - a crash, in a library, out of a directory tree. On the heap, running
 * out is reported instead. max_depth is policy for callers who want it, not a safety
 * net.
 *
 * Paths grow rather than living in a fixed buffer, so an over-long one fails visibly
 * instead of being skipped without a word.
 */
struct pending {
	char    *path;
	uint32_t depth;
};

/*
 * The work queue of a parallel walk: paths in, one worker each takes one out.
 *
 * BOUNDED, and that is the only interesting decision in it. An unbounded queue
 * would let the producer run the whole directory tree ahead of the workers and
 * hold every path in the tree at once - 14 000 strings here, and no bound at all
 * on a larger one. A bound makes the producer wait when the workers are behind,
 * which is exactly when it should.
 *
 * A ring of pointers rather than a list: the paths are strdup'd by the producer
 * and freed by whoever takes them, so ownership moves with the pointer and there
 * is nothing to walk on shutdown but the slots still holding one.
 */
struct mtq {
	pthread_mutex_t lock;
	pthread_cond_t  can_put, can_take;
	char          **slot;
	size_t          cap, head, tail, n;
	int             closed;      /* the producer has finished enumerating */
	int             aborted;     /* a callback asked to stop */
};

struct walk;
static void mtq_put(struct walk *w, const char *path, size_t len);

struct walk {
	struct kof_scanner *sc;
	const struct kof_scan_option *opt;
	kof_on_object cb;
	void *user;

	struct pending *stack;
	size_t          n, cap;

	char   *path_buf;     /* reusable, holds the entry currently being examined */
	size_t  path_cap;

	int      aborted;
	int      out_of_memory;
	uint64_t objects;
	/* Objects that reported something, or that the scan could not finish.
	 * Read across one file by scan_file - see the note there on why a file
	 * with either is never remembered. */
	uint64_t found;

	/* Set only on the producer of a parallel walk: where a regular file goes
	 * instead of being scanned here. NULL in every single threaded walk, and
	 * the one branch that tests it is the whole difference between them. */
	struct mtq *q;
};

static int push_dir(struct walk *w, const char *path, size_t len, uint32_t depth)
{
	if (w->n == w->cap) {
		size_t nc = w->cap ? w->cap * 2 : 64;
		struct pending *nv = realloc(w->stack, nc * sizeof *nv);
		if (!nv) {
			w->out_of_memory = 1;
			return 0;
		}
		w->stack = nv;
		w->cap = nc;
	}
	w->stack[w->n].path = kof_strdup_n(path, len);
	if (!w->stack[w->n].path) {
		w->out_of_memory = 1;
		return 0;
	}
	w->stack[w->n].depth = depth;
	w->n++;
	return 1;
}

/* Grow the reusable buffer to hold at least `need` bytes including the terminator. */
static int path_reserve(struct walk *w, size_t need)
{
	if (need <= w->path_cap)
		return 1;
	{
		size_t nc = w->path_cap ? w->path_cap : 256;
		char *nv;
		/* The ceiling is what keeps this a loop and not a wrap: nc past
		 * half of size_t doubles to zero, which is not less than `need`
		 * and so ends the loop with a zero-byte allocation. */
		while (nc < need) {
			if (nc > (size_t)-1 / 2u) {
				w->out_of_memory = 1;
				return 0;
			}
			nc *= 2;
		}
		nv = realloc(w->path_buf, nc);
		if (!nv) {
			w->out_of_memory = 1;
			return 0;
		}
		w->path_buf = nv;
		w->path_cap = nc;
	}
	return 1;
}

/*
 * Scan one object and everything it turns out to contain.
 *
 * Iterative, with its own stack, for the same reason the directory walk is: the
 * depth of an object tree is chosen by whoever built the file, and putting it on
 * the C stack makes the failure mode a crash inside a library. It also keeps
 * exactly one parsed view of each format in use at a time - a child parsed while
 * its parent's view was still live would overwrite it, since there is one view per
 * format per scanner.
 *
 * A child holds a reference to whatever its bytes live in, so the parent's mapping
 * survives exactly as long as something still points into it and no longer.
 */
/*
 * HOW DEEP AN OBJECT MAY BE UNPACKED, AND WHY IT IS NOT A NUMBER.
 *
 * A fixed depth is wrong in both directions at once. Twenty layers of a
 * meterpreter payload is twenty passes over about a kilobyte - measured, a
 * twenty deep chain of this engine's own XOR unwrapper is 21 objects and
 * finishes instantly - while twenty layers of a five megabyte archive is a
 * hundred megabytes of decompression, which is the shape a bomb takes. Pick a
 * number that allows the first and it permits the second; pick one that refuses
 * the second and it truncates the first.
 *
 * So the allowance is derived from what a layer COSTS, which is the size of the
 * object about to be opened:
 *
 *     allowed = CHAIN_BYTES / size, clamped to [CHAIN_MIN, CHAIN_MAX]
 *
 *        200 B  ->  64   a stager encoded over and over
 *      64 KB    ->  64   still nothing
 *       1 MB    ->  64
 *       5 MB    ->  12   an archive: roughly the ten to twenty a reader expects
 *      16 MB    ->   4
 *      64 MB+   ->   4   the floor, so something is always looked at
 *
 * The floor matters as much as the ceiling: an object too large to descend far
 * into still gets four levels, because refusing outright would hide a payload
 * behind one big container. And this bounds LAYERS, not bytes - the produced
 * byte budget already bounds those, tree wide, and a second byte limit here
 * would be the same rule written twice.
 */
#define CHAIN_BYTES  (64u << 20)
#define CHAIN_MIN    4u
#define CHAIN_MAX    64u

static uint32_t depth_allowance(uint64_t size)
{
	uint64_t n;

	if (!size)
		return CHAIN_MAX;
	n = (uint64_t)CHAIN_BYTES / size;
	if (n > CHAIN_MAX)
		return CHAIN_MAX;
	if (n < CHAIN_MIN)
		return CHAIN_MIN;
	return (uint32_t)n;
}

struct layer {
	struct kof_objsrc *src;
	char              *name;
	uint32_t           depth;    /* in the object tree, for max_depth */
	/*
	 * PACKER layers only.
	 *
	 * Separate from `depth` because the two answer different questions and
	 * conflating them was the bug: max_depth bounds how far the walk goes and
	 * must count every child, while the heuristic weighs how many times this
	 * program was wrapped to be hidden and must count none of the containers.
	 */
	uint32_t           pdepth;
	int                from_packer;  /* its producer was a packer */
	/*
	 * The family its producer decodes, inherited as a prediction, or NULL.
	 *
	 * A pointer into a pack mapping, valid for the life of the engine, so it
	 * is copied here as-is. It is what carries the Meterp guess down through
	 * the formatless intermediate layers a decoder peels, on which no
	 * heuristic fires - see scan_object.
	 */
	const char        *inherit_predict;
};

static void scan_tree(struct walk *w, struct kof_objsrc *root, const char *path)
{
	struct layer *stack = NULL;
	uint32_t n = 0, cap = 0;

	/* The root is not copied into the stack; it is scanned first and its
	 * children seed it. */
	struct kof_objsrc *src = kof_src_ref(root);
	char *name = kof_strdup_n(path, strlen(path));
	uint32_t depth = 0, pdepth = 0;
	int from_packer = 0;            /* the root came off the disk */
	const char *inherit = NULL;     /* the root inherits no prediction */

	/* Every other allocation failure in this function sets out_of_memory so
	 * the walk is reported incomplete rather than clean - this one didn't,
	 * which meant an OOM here dropped the root's finding silently instead
	 * (the callback guard below already tolerates a NULL name, so nothing
	 * crashes; it just never gets called). */
	if (!name)
		w->out_of_memory = 1;

	kof_scan_budget(w->sc, kof_src_buf(root).n, w->opt);

	for (;;) {
		struct kof_result res;
		uint32_t i;

		/*
		 * Cleared WHOLE, not field by field.
		 *
		 * It was three assignments, and that is a shape that goes stale
		 * the moment the struct grows: the heuristic fields were added
		 * and every object carried whatever the stack happened to hold,
		 * so a zip reported itself packed. A memset cannot forget a
		 * field, which is the only property worth having here.
		 */
		memset(&res, 0, sizeof res);

		/*
		 * What the producer said this object is the content of, put
		 * where a host can read it. Set before the scan rather than
		 * after, so a callback fired from inside it sees the same
		 * answer as one fired after.
		 */
		res.entry_of = kof_src_entry_of(src);
		res.entry_kind = kof_src_kind_of(src);
		w->sc->cur_src = src;
		/*
		 * And the regions, if the producer named any - the one object
		 * that does is a normalised view. Copied onto the scanner here
		 * because a resolver is reached through ctx, and ctx is built
		 * inside scan_object with nowhere to carry a table of its own.
		 *
		 * Cleared for every other object, unconditionally, because a
		 * table left standing would describe the PREVIOUS object and
		 * the ranges it names are ranges into different bytes.
		 */
		{
			const struct kof_src_region *r = NULL;
			uint32_t g, nr = kof_src_regions_of(src, &r);

			for (g = 0; g < nr; g++)
				w->sc->cur_rgn[g] = r[g];
			w->sc->n_cur_rgn = nr;
			w->sc->cur_rgn_fmt = kof_src_region_fmt_of(src);
			w->sc->cur_is_view = (uint8_t)kof_src_is_view(src);
		}
		kof_scan_kids_reset(w->sc);
		scan_object(w->sc, kof_src_buf(src), w->opt, &res, pdepth,
			    from_packer, inherit, kof_src_fmt_of(src));
		w->sc->cur_src = NULL;

		/*
		 * A LAYER LEFT UNOPENED IS SAID SO, BEFORE THE VERDICT IS.
		 *
		 * The cost limit below refuses children, and refusing one in
		 * silence would report an object as examined when a layer of it
		 * was never looked at - the failure this engine's budgets are
		 * careful never to produce. Decided here rather than at the push
		 * because the callback has not fired yet: after it, the verdict
		 * for this object is already out.
		 *
		 * It reads as "not fully examined", the same channel a
		 * decompressor uses when its budget runs out, because it is the
		 * same statement: something was produced and nobody looked at it.
		 * Measured over 12.9GB and 60 248 objects it never once fires -
		 * so this is a guard for the file that has not turned up yet
		 * rather than a thing the scan does today.
		 */
		if (!res.broken) {
			for (i = 0; i < w->sc->n_kids; i++)
				if (depth + 1u >
				    depth_allowance(kof_src_buf(w->sc->kids[i]).n)) {
					res.broken = KOF_BROKEN_LIMIT;
					break;
				}
		}

		w->objects++;
		/*
		 * WHETHER THIS FILE PRODUCED ANYTHING, counted where the answer
		 * is - see scan_file, which will not remember a file that did.
		 *
		 * `broken` counts too. An object the scan could not finish is
		 * not a clean one: remembering it would turn a truncated read,
		 * a budget that ran out or a parse that gave up into a
		 * permanent verdict of "nothing here".
		 */
		if (res.n || res.broken)
			w->found++;
		{
			kof_buf ob = kof_src_buf(src);

			/* What the producer declared this object is to be read
			 * with, passed on rather than rebuilt by the host -
			 * see kof_result.syms. */
			res.syms = kof_src_syms_of(src, &res.n_syms);
			if (w->cb && name &&
			    w->cb(name, ob.p, ob.n, &res, w->user) != 0)
				w->aborted = 1;
		}

		/*
		 * Take the children before anything else can reset them.
		 *
		 * On max_object_depth and not on max_depth: the second is how
		 * deep into DIRECTORIES the walk goes, and reading it here was
		 * what made one number mean two policies. See the note on both
		 * in kofeng.h.
		 *
		 * The built-in allowance below still applies whatever these
		 * say, so a caller that sets neither is bounded exactly as
		 * before - the difference is only that it can now bound one
		 * axis without the other.
		 */
		if (!w->aborted && !w->out_of_memory &&
		    kof_objtree_may_open(w->opt) &&
		    (!w->opt->max_object_depth ||
		     depth + 1 <= w->opt->max_object_depth)) {
			/*
			 * PUSHED BACKWARDS SO THEY COME OUT FORWARDS.
			 *
			 * The stack is what makes this depth-first without
			 * recursion, and a stack reverses whatever order things
			 * go onto it. Pushed 0..n-1, the children came back
			 * n-1..0 - so an archive listed its last entry first,
			 * and a dropper carrying one payload per architecture
			 * showed them bottom to top in the viewer's tree. The
			 * numbering was right all along; only the order they
			 * were walked in was backwards.
			 */
			for (i = w->sc->n_kids; i-- > 0; ) {
				char kid[512];

				if (n == cap) {
					uint32_t nc = cap ? cap * 2 : 16;
					struct layer *nv = realloc(stack,
								   nc * sizeof *nv);
					if (!nv) {
						w->out_of_memory = 1;
						break;
					}
					stack = nv;
					cap = nc;
				}
				/*
				 * The index AND the name, not the name alone.
				 *
				 * An index on its own says nothing about which of
				 * fifty entries was found, which is what this used
				 * to print. A name on its own is not unique: an
				 * archive may hold two entries with the same name,
				 * and sanitising two different names can collapse
				 * them into one string. Together they are always
				 * exactly one entry.
				 */
				{
					const char *lab =
						kof_src_label_of(w->sc->kids[i]);

					if (*lab)
						snprintf(kid, sizeof kid,
							 "%s//%u:%s",
							 name ? name : "?", i, lab);
					else
						snprintf(kid, sizeof kid, "%s//%u",
							 name ? name : "?", i);
				}
				/*
				 * The cost limit, asked about the CHILD rather
				 * than about this object: what a layer costs is
				 * the size of the thing that layer produced, and
				 * a bomb's children are larger than it is. Asking
				 * the parent would let a small archive hand back
				 * a huge one at full depth, which is the case the
				 * limit exists for.
				 */
				if (depth + 1u >
				    depth_allowance(kof_src_buf(w->sc->kids[i]).n))
					continue;   /* said above, before the verdict */
				stack[n].src = kof_src_ref(w->sc->kids[i]);
				stack[n].name = kof_strdup_n(kid, strlen(kid));
				if (!stack[n].name)
					w->out_of_memory = 1;
				stack[n].depth = depth + 1;
				stack[n].from_packer = w->sc->kid_packer &&
						       w->sc->kid_packer[i];
				stack[n].pdepth = pdepth +
					(stack[n].from_packer ? 1u : 0u);
				stack[n].inherit_predict =
					w->sc->kid_family ? w->sc->kid_family[i]
							  : NULL;
				n++;
			}
		}
		kof_scan_kids_reset(w->sc);

		/* Nothing to release by hand: a produced source gives its bytes back
		 * when it is destroyed, so every path that drops one - here, the
		 * child cap, an aborted walk - accounts for it without knowing that
		 * it has to. */
		kof_src_unref(src);
		free(name);

		if (w->aborted || n == 0)
			break;
		n--;
		src = stack[n].src;
		name = stack[n].name;
		depth = stack[n].depth;
		pdepth = stack[n].pdepth;
		from_packer = stack[n].from_packer;
		inherit = stack[n].inherit_predict;
	}

	while (n > 0) {
		n--;
		kof_src_unref(stack[n].src);
		free(stack[n].name);
	}
	free(stack);
}

static void scan_one(struct walk *w, const char *path);

/*
 * THE FILE'S OTHER STREAMS, EACH SCANNED AS A FILE OF ITS OWN.
 *
 * On NTFS a file is a set of named streams and every tool shows one of them.
 * Measured on this machine: a 218KB PE written to `host.txt:hidden.exe` leaves
 * host.txt reporting 29 bytes, and a walk that scans what readdir returns
 * scans those 29 bytes and reports the file clean. The engine could always
 * READ it - naming the stream by hand parsed it correctly as a PE - so what
 * was missing was not a parser, it was anybody ever naming it.
 *
 * SCANNED AS A FILE, NOT AS A CHILD OBJECT. A stream is not something the file
 * contains: it has its own size, its own format and its own verdict, and the
 * only thing it shares with the unnamed stream is a directory entry. So it
 * goes through the same scan_one - cached, unpacked and reported on the same
 * terms as anything else, under a name a person can hand back to the scanner
 * verbatim.
 *
 * IT CALLS scan_one AND NOT scan_file, which is what makes the recursion
 * impossible rather than merely bounded: scan_file is the pair of them and
 * scan_one enumerates nothing, so a stream is never asked for streams of its
 * own. On NTFS that question returns the same list again, so a flag guarding
 * against it would be a flag the correctness depended on.
 */
static void scan_streams(struct walk *w, const char *path)
{
	struct kof_stream_walk sw;
	size_t plen;
	int alias;

	if (w->aborted || w->out_of_memory)
		return;
	if (!kof_streams_open(&sw, path))
		return;

	/*
	 * `path` MAY BE w->path_buf ITSELF, AND path_reserve REALLOCATES IT.
	 *
	 * read_dir builds each entry in w->path_buf and hands that pointer
	 * straight to scan_file, so by the time this runs `path` is very often
	 * the buffer about to be grown. The first version reserved inside the
	 * loop and then did memcpy(w->path_buf, path, plen) - which, on the
	 * one directory deep enough to make the buffer grow, copied from the
	 * block realloc had just freed. It segfaulted on
	 * SysWOW64\WindowsPowerShell and on nothing smaller, which is exactly
	 * how a use-after-free behaves: harmless until the allocator reuses
	 * the page.
	 *
	 * So the aliasing is settled BEFORE anything can move, and the reserve
	 * happens ONCE for the longest suffix the enumeration can produce -
	 * sw.name is a fixed array, so there is a longest. Nothing inside the
	 * loop can reallocate after that.
	 */
	alias = (path == w->path_buf);
	plen = strlen(path);
	if (!path_reserve(w, plen + sizeof sw.name + 1u)) {
		kof_streams_close(&sw);
		return;
	}
	if (!alias)
		memcpy(w->path_buf, path, plen);
	/* When it DID alias, realloc preserved the bytes and they are already
	 * at w->path_buf; `path` is now dangling and is not touched again. */

	while (!w->aborted && !w->out_of_memory && kof_streams_next(&sw)) {
		size_t nl = strlen(sw.name);

		/* Subtraction, so the test cannot be the overflow it guards
		 * against - see the same form throughout this tree. */
		if (plen > w->path_cap || nl + 1u > w->path_cap - plen)
			break;          /* cannot happen; the reserve sized it */
		/*
		 * The suffix is appended verbatim - ":hidden.exe:$DATA" - which
		 * is what the enumeration returned and what CreateFile accepts.
		 * Taking it apart to drop the ":$DATA" would be work with a way
		 * to be wrong and nothing to gain.
		 */
		memcpy(w->path_buf + plen, sw.name, nl + 1u);
		scan_one(w, w->path_buf);
	}
	kof_streams_close(&sw);
}

/*
 * A FILE IS ITS CONTENT AND ITS OTHER STREAMS, and the split is load bearing.
 *
 * scan_one has three early returns - the cache answered, the file would not
 * open, the scan was aborted - and the streams must be enumerated ANYWAY. The
 * cache one is the case that matters: it is keyed on the unnamed stream's size
 * and timestamps, so a file whose content has not changed stays cached while a
 * new alternate stream appears beside it. Enumerating only after a successful
 * scan would make that stream invisible for as long as the cache held, which
 * is exactly the silence this whole feature exists to end.
 */
static void scan_file(struct walk *w, const char *path)
{
	scan_one(w, path);
	scan_streams(w, path);
}

static void scan_one(struct walk *w, const char *path)
{
	struct kof_objsrc *src;
	uint64_t before;
	int err = 0;

	/*
	 * ALREADY ANSWERED - asked here because here is where a file is about
	 * to be opened, and the point of asking is not to open it.
	 *
	 * The engine does not know what answers. It calls out and is told yes
	 * or no; the key, where it is kept and whether it can be trusted are
	 * the caller's, for the reasons set out beside cache_seen in kofeng.h.
	 */
	if (w->opt->should_stop &&
	    w->opt->should_stop(w->opt->stop_user)) {
		/* Asked before the file is opened, so a host that has said
		 * stop does not pay for one more mapping. The walk's own
		 * abort flag carries it out of every enclosing loop. */
		w->aborted = 1;
		return;
	}
	if (w->opt->cache_seen &&
	    w->opt->cache_seen(w->opt->cache_user, path)) {
		w->sc->st.cached++;
		return;
	}

	src = kof_src_file(path, &err);
	if (!src) {
		w->sc->st.unreadable++;
		return;
	}
	before = w->found;
	scan_tree(w, src, path);
	kof_src_unref(src);

	/*
	 * KEPT ONLY WHEN NOTHING WAS FOUND, and that is the whole rule.
	 *
	 * Storing a file that HAD a finding would mean skipping it next time,
	 * and skipping something already known to be bad is the one outcome a
	 * cache must never produce. It has been produced here before: an
	 * earlier version stored clean unconditionally, so a detection wrote
	 * itself down as clean and every later run passed over it in silence.
	 *
	 * So a file with a finding is simply not remembered. It is scanned
	 * again next time and reported in full, which is also what makes the
	 * stored set a set - present or absent, no verdict to go stale.
	 */
	if (w->opt->cache_keep && w->found == before)
		w->opt->cache_keep(w->opt->cache_user, path);
	/*
	 * AND A FINDING IS TOLD TO THE CACHE TOO, which is not the same
	 * statement as not remembering it.
	 *
	 * Not remembering leaves whatever an EARLIER run wrote down. This file
	 * was reached because nothing was consulted or because what was
	 * consulted did not answer for it - and if a set somewhere still calls
	 * it clean, the next run that does trust that set walks past a
	 * detection this one just reported. Saying so is the caller's to act
	 * on; the engine knows no more than the path it just scanned.
	 */
	else if (w->opt->cache_drop && w->found != before)
		w->opt->cache_drop(w->opt->cache_user, path);
}

static void read_dir(struct walk *w, const char *dir, uint32_t depth)
{
	size_t dir_len = strlen(dir);
	struct dirent *de;
	DIR *d;

	d = opendir(dir);
	if (!d) {
		/* Unreadable, or a path the system would not accept. Counted, because a
		 * subtree that silently vanishes reads as a subtree with nothing in it. */
		w->sc->st.unreadable++;
		return;
	}
	while (!w->aborted && !w->out_of_memory && (de = readdir(d)) != NULL) {
		size_t nl, total;
		struct stat sb;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		nl = strlen(de->d_name);
		total = dir_len + 1 + nl + 1;
		if (!path_reserve(w, total))
			break;
		memcpy(w->path_buf, dir, dir_len);
		w->path_buf[dir_len] = '/';
		memcpy(w->path_buf + dir_len + 1, de->d_name, nl + 1);

		/* lstat, not stat: a symlink is not followed unless asked for, so a link
		 * pointing at an ancestor cannot turn this into a loop. */
		if ((w->opt->follow_symlinks ? stat : kof_lstat)(w->path_buf, &sb) != 0) {
			w->sc->st.unreadable++;
			continue;
		}

		if (S_ISDIR(sb.st_mode)) {
			if (!w->opt->recurse_dirs)
				continue;
			if (w->opt->max_depth && depth + 1 > w->opt->max_depth)
				continue;
			push_dir(w, w->path_buf, dir_len + 1 + nl, depth + 1);
		} else if (S_ISREG(sb.st_mode)) {
			if (w->q)
				mtq_put(w, w->path_buf, dir_len + 1 + nl);
			else
				scan_file(w, w->path_buf);
		}
		/* anything else - socket, device, fifo - is not an object */
	}
	closedir(d);
}

/*
 * Scan bytes the caller already has, under a name of their choosing.
 *
 * Same machinery as a file: one source, then scan_tree, which is the part that
 * knows how an object turns into a tree of them. The directory walk above is
 * about finding files; this is about scanning one thing, and the two share
 * everything below that distinction.
 *
 * It exists because a tool that has already scanned a file may want to ask a
 * DIFFERENT question about one object inside it - kofviewer runs the
 * interpreter on a node the reader picked, having built the tree with the
 * static unpackers - and re-scanning the whole file with different options
 * would answer that question about every object instead of the one asked about.
 *
 * The bytes are borrowed, not taken: they must outlive the call.
 */
int kof_scan_bytes(struct kof_scanner *sc, const void *bytes, uint64_t n,
		   const char *name, const struct kof_scan_option *opt,
		   kof_on_object cb, void *user)
{
	static const struct kof_scan_option conservative;
	struct kof_objsrc *src;
	struct walk w;

	if (!sc || !bytes || !n)
		return KOF_ERR_ARG;
	memset(&w, 0, sizeof w);
	w.sc   = sc;
	w.opt  = opt ? opt : &conservative;
	w.cb   = cb;
	w.user = user;

	/*
	 * A window over nothing: kof_src_window needs a parent, and there is no
	 * parent here. kof_src_heap takes ownership of a heap block and this
	 * caller's bytes are not one, so the source is built to borrow - see
	 * kof_src_borrow.
	 */
	src = kof_src_borrow(bytes, n);
	if (!src)
		return KOF_ERR_OPEN;
	scan_tree(&w, src, name ? name : "");
	kof_src_unref(src);
	free(w.path_buf);
	return w.objects ? (int)w.objects : 0;
}

/* ---- the parallel walk ---------------------------------------------------- */

static void mtq_put(struct walk *w, const char *path, size_t len)
{
	struct mtq *q = w->q;
	char *copy = kof_strdup_n(path, len);

	if (!copy) {
		w->out_of_memory = 1;
		return;
	}
	pthread_mutex_lock(&q->lock);
	while (q->n == q->cap && !q->aborted)
		pthread_cond_wait(&q->can_put, &q->lock);
	if (q->aborted) {
		pthread_mutex_unlock(&q->lock);
		free(copy);
		w->aborted = 1;
		return;
	}
	q->slot[q->tail] = copy;
	q->tail = (q->tail + 1u) % q->cap;
	q->n++;
	pthread_cond_signal(&q->can_take);
	pthread_mutex_unlock(&q->lock);
}

/* One path, or NULL when there will be no more. The caller owns what it gets. */
static char *mtq_take(struct mtq *q)
{
	char *p;

	pthread_mutex_lock(&q->lock);
	while (q->n == 0 && !q->closed && !q->aborted)
		pthread_cond_wait(&q->can_take, &q->lock);
	if (q->n == 0 || q->aborted) {
		pthread_mutex_unlock(&q->lock);
		return NULL;
	}
	p = q->slot[q->head];
	q->head = (q->head + 1u) % q->cap;
	q->n--;
	pthread_cond_signal(&q->can_put);
	pthread_mutex_unlock(&q->lock);
	return p;
}

/*
 * What a worker sees. Its own walk - so its own path buffer, its own object
 * count and its own scanner - plus the queue and the lock that serialises the
 * callback.
 */
struct worker {
	struct walk       w;
	struct mtq       *q;
	pthread_mutex_t  *cb_lock;
	kof_on_object     cb;
	void             *user;
	pthread_t         id;
};

/*
 * The callback, under the lock.
 *
 * Serialised rather than left to the caller because the alternative is a
 * callback contract that changes with the number of scanners - every existing
 * caller would have to be audited for thread safety before it could ever pass
 * more than one. The lock is held only for the call itself, and a callback that
 * merely counts or prints is nowhere near the cost of the scan that produced it.
 */
static int worker_cb(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct worker *wk = user;
	int rc;

	pthread_mutex_lock(wk->cb_lock);
	rc = wk->cb ? wk->cb(name, bytes, len, res, wk->user) : 0;
	pthread_mutex_unlock(wk->cb_lock);
	if (rc) {
		pthread_mutex_lock(&wk->q->lock);
		wk->q->aborted = 1;
		pthread_cond_broadcast(&wk->q->can_take);
		pthread_cond_broadcast(&wk->q->can_put);
		pthread_mutex_unlock(&wk->q->lock);
	}
	return rc;
}

static void *worker_main(void *arg)
{
	struct worker *wk = arg;
	char *path;

	while ((path = mtq_take(wk->q)) != NULL) {
		scan_file(&wk->w, path);
		free(path);
		if (wk->w.aborted)
			break;
	}
	return NULL;
}

int kof_scan_walk_mt(struct kof_scanner **scs, unsigned n_sc, const char *path,
		     const struct kof_scan_option *opt, kof_on_object cb,
		     void *user)
{
	struct mtq q;
	struct walk prod;
	struct worker *wk = NULL;
	pthread_mutex_t cb_lock;
	struct stat sb;
	uint64_t total = 0;
	unsigned i, started = 0;
	int rc;

	if (!scs || !n_sc || !scs[0] || !path)
		return KOF_ERR_ARG;
	/*
	 * One scanner is the ordinary walk, and taking that path rather than
	 * running a producer and a single worker keeps the common case free of
	 * threads entirely - including the object ORDER, which a caller that
	 * asked for one scanner has every reason to expect unchanged.
	 */
	if (n_sc == 1)
		return kof_scan_walk(scs[0], path, opt, cb, user);

	if ((opt->follow_symlinks ? stat : kof_lstat)(path, &sb) != 0)
		return KOF_ERR_OPEN;
	/* A single file has nothing to spread. */
	if (!S_ISDIR(sb.st_mode))
		return kof_scan_walk(scs[0], path, opt, cb, user);
	if (!opt->recurse_dirs)
		return KOF_ERR_OPEN;

	memset(&q, 0, sizeof q);
	/* Four slots per worker: enough that a worker starting a small file does
	 * not wait on the producer, small enough that the producer cannot run
	 * away from them. */
	q.cap = (size_t)n_sc * 4u;
	q.slot = calloc(q.cap, sizeof *q.slot);
	if (!q.slot)
		return KOF_ERR_READ;   /* no memory for the queue */
	if (pthread_mutex_init(&q.lock, NULL) != 0 ||
	    pthread_cond_init(&q.can_put, NULL) != 0 ||
	    pthread_cond_init(&q.can_take, NULL) != 0 ||
	    pthread_mutex_init(&cb_lock, NULL) != 0) {
		free(q.slot);
		return KOF_ERR_READ;   /* no memory for the queue */
	}

	wk = calloc(n_sc, sizeof *wk);
	if (!wk) {
		free(q.slot);
		return KOF_ERR_READ;   /* no memory for the queue */
	}
	for (i = 0; i < n_sc; i++) {
		wk[i].q        = &q;
		wk[i].cb_lock  = &cb_lock;
		wk[i].cb       = cb;
		wk[i].user     = user;
		wk[i].w.sc     = scs[i] ? scs[i] : scs[0];
		wk[i].w.opt    = opt;
		wk[i].w.cb     = worker_cb;
		wk[i].w.user   = &wk[i];
		if (pthread_create(&wk[i].id, NULL, worker_main, &wk[i]) != 0)
			break;
		started++;
	}

	/*
	 * The producer runs on this thread, and it is the existing walk with the
	 * queue attached: same directory reading, same symlink policy, same depth
	 * limit, same stack. Nothing about finding files is written twice.
	 */
	memset(&prod, 0, sizeof prod);
	prod.sc  = scs[0];
	prod.opt = opt;
	prod.q   = started ? &q : NULL;
	if (!started) {
		/* No thread could be created: scan on this thread rather than
		 * returning nothing, which is the answer a caller can still use. */
		free(wk);
		pthread_mutex_destroy(&q.lock);
		pthread_cond_destroy(&q.can_put);
		pthread_cond_destroy(&q.can_take);
		pthread_mutex_destroy(&cb_lock);
		free(q.slot);
		return kof_scan_walk(scs[0], path, opt, cb, user);
	}

	{
		char sq[4096];
		size_t n = kof_path_squash(path, sq, sizeof sq);

		if (n)
			push_dir(&prod, sq, n, 0);
	}
	while (!prod.aborted && !prod.out_of_memory && prod.n > 0) {
		struct pending p = prod.stack[--prod.n];
		read_dir(&prod, p.path, p.depth);
		free(p.path);
	}
	while (prod.n > 0)
		free(prod.stack[--prod.n].path);
	free(prod.stack);
	free(prod.path_buf);

	pthread_mutex_lock(&q.lock);
	q.closed = 1;
	pthread_cond_broadcast(&q.can_take);
	pthread_mutex_unlock(&q.lock);

	for (i = 0; i < started; i++) {
		pthread_join(wk[i].id, NULL);
		total += wk[i].w.objects;
	}

	/* Whatever a stopped run left in the ring. */
	while (q.n > 0) {
		free(q.slot[q.head]);
		q.head = (q.head + 1u) % q.cap;
		q.n--;
	}
	free(q.slot);
	free(wk);
	pthread_mutex_destroy(&q.lock);
	pthread_cond_destroy(&q.can_put);
	pthread_cond_destroy(&q.can_take);
	pthread_mutex_destroy(&cb_lock);

	rc = (int)total;
	return rc;
}

int kof_scan_walk(struct kof_scanner *sc, const char *path,
		  const struct kof_scan_option *opt, kof_on_object cb, void *user)
{
	struct walk w;
	struct stat sb;
	int rc;

	memset(&w, 0, sizeof w);
	w.sc   = sc;
	w.opt  = opt;
	w.cb   = cb;
	w.user = user;

	if ((opt->follow_symlinks ? stat : kof_lstat)(path, &sb) != 0)
		return KOF_ERR_OPEN;

	if (!S_ISDIR(sb.st_mode)) {
		/* The single-file case needs it too: this name is what the
		 * callback reports and what a repair is keyed on. */
		char sq[4096];

		if (kof_path_squash(path, sq, sizeof sq))
			scan_file(&w, sq);
		else
			scan_file(&w, path);
		rc = w.objects ? (int)w.objects : KOF_ERR_OPEN;
		free(w.path_buf);
		return rc;
	}

	if (!opt->recurse_dirs)
		return KOF_ERR_OPEN;

	{
		/* Both slashes: the trailing one would put "//" in every child
		 * path, and an internal one makes the file itself unspellable
		 * - see path_squash. */
		char sq[4096];
		size_t n = kof_path_squash(path, sq, sizeof sq);

		if (!n || !push_dir(&w, sq, n, 0))
			goto done;
	}

	/* Depth first, by taking from the end: a directory's children are examined
	 * before its siblings, which keeps the pending set small and the page cache
	 * warm. Breadth first would hold a whole level at once. */
	while (!w.aborted && !w.out_of_memory && w.n > 0) {
		struct pending p = w.stack[--w.n];
		read_dir(&w, p.path, p.depth);
		free(p.path);
	}

done:
	while (w.n > 0)
		free(w.stack[--w.n].path);
	free(w.stack);
	free(w.path_buf);
	/* Running out of heap mid-walk is reported, not fatal: what was scanned before
	 * it is still a result, and the caller can tell the walk was cut short. */
	return (int)w.objects;
}