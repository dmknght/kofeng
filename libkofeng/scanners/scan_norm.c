/*
 * scan_norm.c - the NORMALISE stage: render an object as a view of itself with
 * what does not vary removed, and offer it as a child.
 *
 * Runs last in the object's steps, and only when nothing was opened: a view of a
 * wrapper is a view of noise. Gate, regions, keep map, text transform, library cut,
 * symbol view and publish are the sub-steps, in that order.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include "../../libgenome/genotype/analysis/xref.h"
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


void sx_norm_emit(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		      kof_buf buf)
{
	uint8_t *out, *tmp, *keep, *drop;
	const struct kof_true_all *lib;
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
	if (kof_src_kind_of(sc->cur_src) == KOF_ENT_NORMALIZED)
		return;
	/*
	 * AND NOT A FORM SOMEBODY ELSE ALREADY MADE.
	 *
	 * THE TWO NORMALISERS WERE BLIND TO EACH OTHER. This one marks what it
	 * produces with kof_src_declare_view; the script pass in objctx.c marks
	 * its own with KOF_ENT_NORMALIZED, and each guard tested only its own
	 * mark. So each ran on the other's output and one shell script came
	 * back with four views - 1.norm, 2.NORMALIZED, then 3.NORMALIZED of the
	 * first and 4.norm of the second, each a walk over an object already in
	 * the tree to arrive at bytes already in the tree.
	 *
	 * "A FORM OF A FORM IS THE FORM", as the other guard puts it. Both of
	 * them now say so about both marks.
	 */
	if (sc->cur_src &&
	    kof_src_kind_of(sc->cur_src) == KOF_ENT_NORMALIZED)
		return;
	/*
	 * AND NOT A SCRIPT, BECAUSE A SCRIPT HAS ITS OWN NORMALISER.
	 *
	 * This was widened to KOF_FMT_SCRIPT so that a shell or php file got
	 * its base64 and hex spans decoded, which was the right thing to want
	 * and the wrong place to get it: c_script_unpack already produces a
	 * normalised view of every script, so the object then had TWO - a
	 * `:norm` with the decode and no reformatting, and a `.NORMALIZED`
	 * with the reformatting and no decode. Neither was the object said
	 * plainly and the tree carried both.
	 *
	 * One object, one normaliser, chosen by format. The decode moved to
	 * where the script's own pass ends - see kof_exe_decode's call in
	 * c_script_unpack - so the single view now carries both halves.
	 */
	if (!ctx || (ctx->format != KOF_FMT_ELF &&
		     ctx->format != KOF_FMT_PE))
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
	 * AND NOT AN OBJECT WHOSE CODE IS STILL COMPRESSED.
	 *
	 * The loop in analyze_object already stops this step when the unpack
	 * step PRODUCED something, and says why: "normalising a compressed or
	 * encrypted blob finds no zero runs and no text, because there is none
	 * to find until it has been opened". That reasoning is about the BYTES
	 * and the guard is about the outcome, so it misses the case where the
	 * bytes are exactly that and nothing opened them - a packer no module
	 * here handles. Then the object is compressed, nothing said so, and the
	 * two full-size buffers below get built over it to find the nothing the
	 * comment predicts.
	 *
	 * Measured on an MPRESS packed PE before a module for it existed: 2.7 MB
	 * of LZMA stream, normalised to no effect, at two copies of the object.
	 *
	 * THE SAME 7.5 BITS PER BYTE THE EMULATOR'S GATE USES, and for the same
	 * reason it uses it - see DENSE_EIGHTHS in emu_unpack.c, where over 2678
	 * clean PEs the executable sections fall almost entirely between 6.0 and
	 * 7.0 bits and exactly one file clears 7.5. Compiled code is not this
	 * dense, and the transform has nothing to do to bytes that are.
	 *
	 * CODE AND NOT THE WHOLE OBJECT. A program with a compressed resource
	 * or an appended archive is still a program, and its code is still
	 * worth rendering; what is being asked is whether the EXECUTABLE bytes
	 * have been replaced by a stream. KOF_SCAN_ELF_CODE and KOF_SCAN_PE_CODE
	 * are the same bit, which is what lets one test serve both formats here.
	 *
	 * THE ANSWER IS MEMOISED - c_region_entropy keeps the last few masks it
	 * was asked about - so on an object the emulator's gate or a rule has
	 * already asked about, this costs a lookup rather than a pass.
	 */
	if (ctx->content && ctx->content->region_entropy &&
	    ctx->content->region_entropy(ctx, NORM_CODE_MASK) >=
	    NORM_DENSE_EIGHTHS)
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
	nr = sx_norm_gather(ctx, rgn, KOF_SRC_MAX_REGIONS);
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
	 * FOUND ON THE PARENT, WHERE THE PARSE IS TRUE. kof_true_find works from
	 * markers inside a loadable segment, so it needs segment offsets that
	 * describe the bytes it is reading - which is the case here and is not
	 * the case on a view, whose headers still describe the file before the
	 * padding came out. That is why it is refused there and used here.
	 */
	/*
	 * INHERITED, NOT WORKED OUT AGAIN - see kof_scanner.cur_lib. The gate
	 * that used to be here, refusing the cut on a dynamically linked
	 * object, moved with it: sx_lib_facts asks the marker tier only of a
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
		sx_norm_keep_bits(keep, buf.n, rgn, nr, NORM_KEEP_MASK);
		/* And CODE narrowed to the instructions in it - see
		 * sx_norm_keep_exec. */
		if (ctx->format == KOF_FMT_ELF && ctx->file_header)
			sx_norm_keep_exec(keep, buf.n, kof_elf(ctx), rgn, nr);
		/* And the PE question, which is about the write bit - see
		 * sx_norm_keep_exec_pe. */
		if (ctx->format == KOF_FMT_PE && ctx->file_header)
			sx_norm_keep_exec_pe(keep, buf.n, kof_pe(ctx), rgn, nr);
	}
	if (lib->n) {
		uint32_t a;

		memset(drop, 0, (size_t)((buf.n + 7u) / 8u));
		for (a = 0; a < lib->n; a++) {
			uint64_t e;

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
			sx_bits_set(drop, lib->span[a].off, e);
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
	 * included, which is not something kof_true_find can currently produce -
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
	 * of the object's name - see kobj_label. */
	sc->pend_label_len = (uint32_t)snprintf(sc->pend_label,
						sizeof sc->pend_label, "%s",
						KOF_OBJ_LABEL_NORM);
	sc->pend_fmt = nr ? ctx->format : (uint8_t)KOF_FMT_DECLARED_RAW;
	/*
	 * AND THE LANGUAGE WITH IT, for a view that is declared a format at
	 * all. The decode rewrites the view's own text, so a re-read of it can
	 * come back a different language than the object it is a view OF - a
	 * shell dropper whose payload decodes to PHP reads as PHP, and every
	 * shell rule is then declined on the one object that finally holds the
	 * evidence. See kof_src_declare_lang.
	 */
	if (nr) {
		sc->pend_subtype = ctx->subtype;
		sc->pend_subfam  = ctx->subfamily;
		sc->pend_lang    = 1;
	}
	/*
	 * AND WHAT IT IS, in the enum every consumer already reads.
	 *
	 * KOF_ENT_NORMALIZED is the one carrier: it is both the engine's
	 * own guard against normalising a view twice and
	 * the published fact, the one kof_result.entry_kind carries to a
	 * caller - and without it the viewer saw a child of unknown kind and
	 * had nothing to go on but its label.
	 *
	 * The script normaliser in objctx.c has declared this from the start;
	 * this one did not, and the two produce the same kind of thing.
	 */
	sc->pend_kind = KOF_ENT_NORMALIZED;
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
	 * spends them. See sx_norm_syms.
	 */
	if (!sc->pend_syms)
		sc->pend_syms = malloc(KOF_SYM_MAX_BYTES);
	if (sc->pend_syms)
		sc->n_pend_syms = sx_norm_syms(sc, ctx, sc->pend_syms,
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
