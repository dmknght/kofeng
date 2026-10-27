/*
 * objctx_decomp_buf.c - the codings whose whole output has to be addressable
 * while they decode: LZMA and its MPRESS forms, LZMA2, NRV2, aPLib, ASPack,
 * LZMAT and RAR.
 *
 * WHAT THIS SERVES: the one place a buffered decode is sized, charged, placed
 * (into the sink when the sink is a flat buffer, into a scratch otherwise),
 * run, reported and handed on - and the peek that reads the front of a stream
 * through the same path. Nothing here decides what the output is.
 */


#include "objctx_decomp.h"
#include <stdlib.h>
#include <string.h>

/*
 * The MPRESS bases sit above the plain one and carry the same three parameters,
 * so the arithmetic is shared and only the base differs. Answers 0, 32 or 64:
 * the width of the call filter to undo afterwards, and 0 for "none".
 */
/* And the same question for LZMAT, whose two variants carry no parameters so
 * they are two ids rather than two ranges. */
static unsigned lzmat_cto_bits(uint32_t method)
{
	if (method == KOF_UNP_LZMAT_MPRESS64)
		return 64u;
	if (method == KOF_UNP_LZMAT_MPRESS32)
		return 32u;
	return 0u;
}

static unsigned lzma_cto_bits(uint32_t method)
{
	if (method >= KOF_UNP_LZMA_MPRESS64 &&
	    method <= KOF_UNP_LZMA_MPRESS64 + 224u)
		return 64u;
	if (method >= KOF_UNP_LZMA_MPRESS32 &&
	    method <= KOF_UNP_LZMA_MPRESS32 + 224u)
		return 32u;
	return 0u;
}

/*
 * ASPack, and whether this id carries the call/jmp filter's marker.
 *
 * Returns -1 for anything else, 0 for the plain coding, and mark + 1 for a
 * filtered one - so the caller can tell "no filter" from "a filter whose
 * marker byte is zero", which a bare marker cannot say.
 */
static int aspack_mark_of(uint32_t method)
{
	if (method == KOF_UNP_ASPACK)
		return 0;
	if (method >= KOF_UNP_ASPACK_E8E9 &&
	    method <= KOF_UNP_ASPACK_E8E9 + 0xffu)
		return (int)(method - KOF_UNP_ASPACK_E8E9) + 1;
	return -1;
}

/*
 * The methods oc_unpack_buffered takes: everything whose whole output has to be
 * addressable at once. DEFLATE and HEXTEXT stream instead and are answered
 * before this is asked.
 *
 * A predicate rather than three ifs in a row, each ending in the same call.
 * That is what it was, in both places, and the three differed only in whether
 * NRV2 had filled in a variant and a width - which oc_nrv2_of already says.
 */
int oc_buffered_method(uint32_t method)
{
	/*
	 * LZMA IS A RANGE AND NOT A FLOOR, which is what this said.
	 *
	 * The id carries lc, lp and pb, so the codings are KOF_UNP_LZMA
	 * through KOF_UNP_LZMA + 224 - the same bound kof_unp_method_name
	 * uses, and the same one lzma_props_of enforces one function away.
	 * Written here as `>= KOF_UNP_LZMA` it swallowed everything above:
	 * LZX is 320 and LZX_RESET is 352, and both answered yes.
	 *
	 * What that cost is the REASON. An LZX id handed to kof_unpack_at
	 * reached oc_unpack_buffered, took the LZMA arm, and was refused by
	 * lzma_props_of as KOF_BROKEN_DAMAGED - so a perfectly sound archive
	 * was reported as a damaged one because this build decodes LZX only
	 * through the entry call. oc_broken_of_status draws that distinction on
	 * purpose: a coding the engine lacks is a gap in the engine, damage
	 * is a statement about the file, and the two lead different places.
	 * Bounded, the same id falls out as "a method this engine does not
	 * have" and nothing is said about the file.
	 */
	return method == KOF_UNP_LZMA2 || method == KOF_UNP_LZMA2_BCJ_X86 ||
	       method == KOF_UNP_APLIB || aspack_mark_of(method) >= 0 ||
	       method == KOF_UNP_LZMAT || lzmat_cto_bits(method) != 0u ||
	       method == KOF_UNP_RAR3  || method == KOF_UNP_RAR5 ||
	       (method >= KOF_UNP_LZMA && method <= KOF_UNP_LZMA + 224u) ||
	       lzma_cto_bits(method) != 0u ||
	       (method >= KOF_UNP_NRV2B_8 && method <= KOF_UNP_NRV2E_32);
}

/* NRV2's three codings and three bit widths, as the module ABI numbers them. */
int oc_nrv2_of(uint32_t method, int *variant, int *bits)
{
	static const struct { int v, b; } tab[9] = {
		{ KUNCOAT_NRV2B, 8 }, { KUNCOAT_NRV2B, 16 }, { KUNCOAT_NRV2B, 32 },
		{ KUNCOAT_NRV2D, 8 }, { KUNCOAT_NRV2D, 16 }, { KUNCOAT_NRV2D, 32 },
		{ KUNCOAT_NRV2E, 8 }, { KUNCOAT_NRV2E, 16 }, { KUNCOAT_NRV2E, 32 }
	};

	if (method < KOF_UNP_NRV2B_8 || method > KOF_UNP_NRV2E_32)
		return 0;
	*variant = tab[method - KOF_UNP_NRV2B_8].v;
	*bits    = tab[method - KOF_UNP_NRV2B_8].b;
	return 1;
}

/*
 * The three LZMA parameters, back out of the method id.
 *
 * Refused rather than clamped when they are past what the specification allows:
 * they size an allocation, and one that came out of a file is not a thing to round
 * into range.
 */
static int lzma_props_of(uint32_t method, unsigned *lc, unsigned *lp, unsigned *pb)
{
	uint32_t v, base = KOF_UNP_LZMA;
	unsigned bits = lzma_cto_bits(method);

	if (bits == 64u)
		base = KOF_UNP_LZMA_MPRESS64;
	else if (bits == 32u)
		base = KOF_UNP_LZMA_MPRESS32;
	if (method < base)
		return 0;
	v = method - base;
	if (v > 224u)
		return 0;
	*lc = v % 9u;
	*lp = (v / 9u) % 5u;
	*pb = v / 45u;
	return *lc <= KUNCOAT_LZMA_MAX_LC && *lp <= KUNCOAT_LZMA_MAX_LP &&
	       *pb <= KUNCOAT_LZMA_MAX_PB;
}

/*
 * Decoders that cannot stream, and what they cost.
 *
 * NRV2 places no bound on how far a match may reach back, so the whole of its
 * output has to be addressable until the stream ends - there is no window size
 * that makes it streamable, the buffer IS the window. So this allocates, decodes,
 * and hands the result to the sink.
 *
 * That is TWICE the output alive at the moment of handover: the buffer, plus what
 * the sink has taken from it. Halving the allowance is the honest way to keep the
 * ceiling meaning what it says, and it is why a non-streaming decoder is a worse
 * deal than a streaming one rather than merely a different one.
 *
 * The size comes from what the container declared, clamped to that allowance. A
 * container that overstates gets the clamp; one that understates gets a decode
 * that stops early and an object marked incomplete. Neither is trusted: the
 * declared value sizes a buffer and bounds nothing.
 */
/*
 * `peek_out` turns this from a producer into a reader.
 *
 * When it is set the decoded bytes are copied there and nothing is emitted -
 * which is the whole difference between unpack and unpack_peek. They share this
 * function rather than having one each because a second implementation of the
 * same dispatch is a second thing to get right: the first attempt at peek did
 * have its own, and on one architecture it decoded the same block to different
 * bytes than this did. Two paths that must agree, and no mechanism making them.
 */
/*
 * What one buffered decode carries from step to step.
 *
 * Six things that used to be locals of one function of nearly four hundred
 * lines, and each step below takes the ones it needs by pointer. `want` does not
 * move once the buffer is placed - see buffered_place.
 */
struct bufrun {
	uint64_t want;           /* what the output buffer holds */
	uint8_t *buf;            /* the sink's own bytes, or a charged scratch */
	int      own;            /* 1 when buf is this decode's to free and give back */
	int      capped;         /* a clamp made want smaller than the caller asked */
	const uint8_t *sink_was; /* the sink as it was, when buf points into it */
	size_t   cap_was;
};

/*
 * STEP 1: how much output this decode may produce, and which ceiling said so.
 *
 * Answers 0 when nothing fits - the limit is already recorded - and 1 with
 * r->want and r->capped set.
 */
static int buffered_size(struct kof_scanner *sc, uint64_t out_hint,
			 struct bufrun *r)
{
	uint64_t room, want;
	int capped = 0;

	room = oc_scan_room(sc) / 2u;
	/*
	 * WHICH CEILING IS BINDING, because they mean different things.
	 *
	 * The residency figure is what is LEFT: nothing more fits right now, and
	 * asking again for this object is wasted work - a sticky stop is right.
	 * obj_cap is a per object SIZE POLICY: one entry may not exceed it, and
	 * that says nothing whatever about the entry after it.
	 *
	 * They were one number and one sticky stop, and the cost was whole
	 * archives. Win32.Fearso.c.7z has two content folders; the first claims
	 * 19069533 bytes, over the per object cap, and clamping it stopped the
	 * object - so the second folder, an ordinary 392128 byte executable that
	 * decodes perfectly, was never attempted. Eleven more archives in the
	 * same collection are shaped the same way.
	 */
	if (room == 0) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	{
		int by_policy = room > sc->ledger.obj_cap;

		if (by_policy)
			room = sc->ledger.obj_cap;
		want = out_hint ? out_hint : room;
		if (want > room) {
			want = room;
			/* The tail will not fit and will be dropped. Sticky only
			 * when it was residency that ran out. */
			/* KNOWN DEFECT WP2-D5 (2026-10-24, Inference) [sev M]: buffered_size makes the residency
			 * branch of an oversized claim sticky (oc_scan_broken) where one entry should only be
			 * cut (rule 4); sink read, the branch that fires is not measured. Trigger: a 7z
			 * folder declares an unpack size over the budget. Effect: the folder after the cut
			 * one is not walked (2 of 3). Reproducer: tests/unit/ctr_liars.c 7z/claimUnp (green
			 * until fixed). Fix: oc_entry_cut, and let the module loop go on. */
			if (by_policy) {
				capped = 1;     /* said once the output is in the sink: buffered_cut */
			} else {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			}
		}
	}
	r->want = want;
	r->capped = capped;
	return 1;
}

/* STEP 2: the ratio clamp, settled before anything is taken. */
static void buffered_ratio_clamp(uint32_t method, uint64_t in_len,
				 uint64_t out_hint, struct bufrun *r)
{
	uint64_t want = r->want;
	int capped = r->capped;


	/*
	 * THE RATIO CLAMP, SETTLED BEFORE ANYTHING IS TAKEN.
	 *
	 * It used to sit below, inside each decoder's arm, and assign to `want`
	 * AFTER the buffer had been allocated and charged at the larger size -
	 * so the release at the bottom gave back the CLAMPED figure and the
	 * difference stayed on the residency account for the rest of the scan.
	 * A zip of entries declaring a 600x expansion leaks up to obj_cap minus
	 * a megabyte each; a few hundred of them and the ceiling is exhausted by
	 * memory nothing is holding, after which every later object in the run
	 * produces nothing and is reported as having hit a limit. Precisely the
	 * "limit that tightens itself over a long scan" oc_emit warns about,
	 * arrived at from the other end.
	 *
	 * Settling it here rather than repairing the release also means the
	 * buffer is allocated at the size that will actually be decoded into,
	 * instead of fifteen megabytes for a one megabyte decode.
	 *
	 * Only the codings whose arms applied it: the clamp reads a size the
	 * CONTAINER declared, and LZMA and NRV2 arrive here from formats that
	 * declare none - see expand_limit.
	 */
	if (method == KOF_UNP_RAR3 || method == KOF_UNP_RAR5 ||
	    method == KOF_UNP_LZMA2 || method == KOF_UNP_LZMA2_BCJ_X86) {
		uint64_t lim = expand_limit(in_len, out_hint);

		if (want > lim) {
			want = lim;
			capped = 1;     /* said once the output is in the sink: buffered_cut */
		}
	}
	r->want = want;
	r->capped = capped;
}

/*
 * STEP 3: where the output goes - straight into the sink where there is one,
 * else a scratch buffer charged to the ceiling. Answers 0 when the scratch could
 * not be had (recorded).
 */
static int buffered_place(struct kof_scanner *sc, const uint8_t *in,
			  uint64_t in_len, const uint8_t *peek_out,
			  struct bufrun *r)
{
	uint64_t want = r->want;
	uint8_t *buf = NULL;
	int own;
	const uint8_t *sink_was = NULL;
	size_t cap_was = 0;


	/*
	 * ---- DECODE STRAIGHT INTO THE SINK WHERE THERE IS ONE --------------
	 *
	 * A BUFFERED DECODE WAS COSTING A SECOND COPY OF ITS OWN OUTPUT.
	 *
	 * The output has to be addressable in full while it decodes - that is
	 * what "buffered" means here, and why LZMA, NRV2, aPLib and ASPack are
	 * on this path at all. But when the caller is filling a DECLARED IMAGE
	 * the sink is already a flat buffer of exactly the right size, and this
	 * allocated a second one beside it, decoded into that, and then memcpy'd
	 * the whole thing across.
	 *
	 * Measured on 111.exe, which is VMProtect under MPRESS: the residency
	 * account ran 5.11 MB for the image, then 5.11 for the child, then
	 * FOUR more allocations of about five megabytes each - one per decode -
	 * peaking at 15.31 MB where the two objects alone are 10.21. Half the
	 * peak of an unpack was a copy nobody needed, plus a memcpy of the
	 * whole image per decode.
	 *
	 * WHAT MAKES IT SAFE, and each of these is a refusal rather than an
	 * assumption:
	 *
	 *   - A FIXED, IN-MEMORY SINK. A spilled one has no buffer to write
	 *     into, and a growable one is appended to rather than placed at a
	 *     cursor.
	 *   - ROOM AT THE CURSOR for the whole of `want`, checked exactly as
	 *     oc_emit's fixed arm checks it - against sink_cap, which does not
	 *     move, and never against sink_len, which layout_of_produced
	 *     lowers.
	 *   - NO OVERLAP with the input. The input is the parent object's
	 *     bytes and the sink is the child's own allocation, so they cannot
	 *     alias today; the test is here because "cannot today" is not a
	 *     property this function can check by reading itself.
	 *   - NOT THE PEEK PATH, which copies out to a caller's buffer and
	 *     emits nothing.
	 *
	 * And the sink must not move while the decode is in flight - nothing
	 * resizes it between here and the emit, and the check after the decode
	 * is what says so out loud.
	 */
	own = 1;
	if (!peek_out && sc->sink.fixed && sc->sink.mem &&
	    sc->sink.at <= sc->sink.cap && want <= sc->sink.cap - sc->sink.at) {
		uint8_t *dst = sc->sink.mem + sc->sink.at;

		if (!in || !in_len ||
		    (const uint8_t *)in + in_len <= dst || in >= dst + want) {
			buf = dst;
			own = 0;
			sink_was = sc->sink.mem;
			cap_was = sc->sink.cap;
			sc->st.decode_inplace++;
		}
	}
	if (own) {
		buf = malloc((size_t)want);
		if (!buf) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		sc->st.decode_scratch++;
		/* Charged while it is alive, so a module that unpacks inside an
		 * object that is itself produced cannot exceed the ceiling
		 * between the two of them. Nothing is charged on the path
		 * above: that room was charged once, when oc_image took it.
		 *
		 * `want` DOES NOT MOVE from here to the release at the bottom -
		 * the only assignment to it below is the PE rebuild's, which
		 * releases and recharges around itself. That is what makes the
		 * pair balance. */
		scan_charge(sc, want);
	}
	r->buf = buf;
	r->own = own;
	r->sink_was = sink_was;
	r->cap_was = cap_was;
	return 1;
}

/*
 * STEP 4: run the coding into r->buf. Answers 0 when the method id carries
 * parameters the format does not allow - the buffer is given back and the
 * damage recorded - and 1 with *pst and *pproduced set.
 */
static int buffered_coding(struct kof_scanner *sc, const struct oc_buf_req *q,
			   const struct bufrun *r,
			   enum kuncoat_status *pst, uint64_t *pproduced)
{
	const uint32_t method = q->method;
	const int variant = q->variant, bits = q->bits;
	const uint8_t *in = q->in;
	const uint64_t in_len = q->in_len;
	uint64_t want = r->want, produced = 0;
	uint8_t *buf = r->buf;
	int own = r->own;
	enum kuncoat_status st;

	if (method == KOF_UNP_RAR3 || method == KOF_UNP_RAR5) {
		/*
		 * Working room for the channel delta filter, which writes a
		 * permutation of its input and so cannot work in place. Bounded by
		 * the format rather than by the entry - the filter refuses a block
		 * larger than this - and taken from the same budget as the output,
		 * because a produced object is charged for what producing it costs.
		 *
		 * The two formats bound it differently, so the smaller decoder does
		 * not pay for the larger one's room.
		 */
		uint64_t sn = method == KOF_UNP_RAR3 ? KUNCOAT_RAR3_SCRATCH
						     : KUNCOAT_RAR5_SCRATCH;
		uint8_t *scratch;

		/*
		 * No larger than the output, because a filter cannot cover more of
		 * the entry than the entry holds. The format's bound is four
		 * megabytes and most entries are a fraction of that; taking the
		 * bound every time charged the budget for room nothing would use
		 * and turned ordinary archives into ones that hit a ceiling.
		 */
		if (sn > want)
			sn = want;
		scratch = malloc((size_t)sn);
		if (scratch)
			scan_charge(sc, sn);
		if (method == KOF_UNP_RAR3)
			st = kuncoat_rar3_decode(in, in_len, buf, want, scratch,
					     scratch ? sn : 0u, &produced);
		else
			st = kuncoat_rar5_decode(in, in_len, buf, want, scratch,
					     scratch ? sn : 0u, &produced);
		if (scratch) {
			oc_scan_release(sc, sn);
			free(scratch);
		}
	} else if (method == KOF_UNP_LZMAT || lzmat_cto_bits(method)) {
		unsigned cto = lzmat_cto_bits(method);

		/* Buffered like aPLib and for the same reason: a match
		 * distance has no ceiling and the buffer IS the window. */
		st = kuncoat_lzmat_decode(in, in_len, buf, want, &produced);
		/* And the call target conversion undone over the whole of it,
		 * exactly as the LZMA pair below does it. */
		if (cto && produced)
			kuncoat_mpress_cto_decode(buf, produced, cto);
	} else if (method == KOF_UNP_APLIB) {
		/*
		 * Buffered for the reason NRV2 is: an aPLib match distance has
		 * no ceiling, so the whole output has to stay addressable until
		 * the stream ends and the buffer IS the window.
		 */
		st = kuncoat_aplib_decode(in, in_len, buf, want, &produced);
	} else if (aspack_mark_of(method) >= 0) {
		int mark = aspack_mark_of(method);

		/* Buffered for the same reason again - see aspack.h. */
		st = kuncoat_aspack_decode(in, in_len, buf, want, &produced);
		/*
		 * And the call/jmp filter undone over the whole block, where
		 * the LZMA and BCJ pairs undo theirs and for the same reason:
		 * it rewrites a displacement against the instruction's own
		 * position in the OUTPUT.
		 */
		if (mark > 0 && produced)
			kuncoat_aspack_e8e9_decode(buf, produced,
					       (uint8_t)(mark - 1));
	} else if (method == KOF_UNP_LZMA2 || method == KOF_UNP_LZMA2_BCJ_X86) {
		st = kuncoat_lzma2_decode(in, in_len, buf, want, &produced);
		/*
		 * The transform is undone here, over the whole decoded buffer,
		 * because that is the only place it can be: it rewrites addresses
		 * that are relative to a position in the OUTPUT, so it cannot run
		 * on the compressed bytes and cannot run on a chunk of the output
		 * without knowing where that chunk sits. A buffered decode has the
		 * whole thing in hand and a streaming one never would.
		 */
		if (method == KOF_UNP_LZMA2_BCJ_X86 && produced)
			kuncoat_bcj_x86_decode(buf, produced, 0);
	} else if (method >= KOF_UNP_LZMA) {
		unsigned lc, lp, pb, cto = lzma_cto_bits(method);

		if (!lzma_props_of(method, &lc, &lp, &pb)) {
			/* Only a buffer the engine allocated is the engine's to free
			 * and to give back: on the in-place path `buf` points into the
			 * sink, and nothing was charged. */
			if (own) {
				oc_scan_release(sc, want);
				free(buf);
			}
			oc_scan_broken(sc, KOF_BROKEN_DAMAGED);
			return 0;
		}
		st = kuncoat_lzma_decode(lc, lp, pb, in, in_len, buf, want, &produced);
		/*
		 * Undone here for the reason the BCJ call above is: the
		 * transform rewrites addresses relative to a position in the
		 * output, so it needs the whole output and this is where the
		 * whole output is.
		 *
		 * ON A SHORT DECODE TOO, and deliberately. A stream that
		 * stopped early still yields a real prefix - kuncoat_lzma_decode's
		 * contract says so - and the filter's bound is a length rather
		 * than a structure, so it converts what arrived and leaves the
		 * rest. The alternative is handing back a prefix whose calls
		 * are all wrong, which is the state this exists to end.
		 */
		if (cto && produced)
			kuncoat_mpress_cto_decode(buf, produced, cto);
	} else {
		st = kuncoat_nrv2_decode(variant, bits, in, in_len, buf, want,
				     &produced);
	}
	*pst = st;
	*pproduced = produced;
	return 1;
}

/*
 * STEP 5: what the decoder's answer means for the object. A status other than
 * OK is recorded, as a limit that is not sticky when a clamp sized the buffer.
 */
static void buffered_note(struct kof_scanner *sc, enum kuncoat_status st,
			  uint64_t out_hint, const struct bufrun *r)
{
	uint64_t want = r->want;
	int capped = r->capped;

	/*
	 * STOPPED IS NOT A LIMIT WHEN THE CALLER GOT WHAT IT ASKED FOR.
	 *
	 * KUNCOAT_STOPPED means the output buffer filled. Whether that is a
	 * failure depends entirely on who chose the buffer's size, and until now
	 * this did not ask.
	 *
	 * Several formats carry no end marker in the stream at all - 7z writes
	 * its LZMA that way, and UPX's NRV2 blocks likewise - so the length comes
	 * out of the container and the decode ENDS by filling exactly that many
	 * bytes. Every one of those reported "a limit was reached", on a decode
	 * that had delivered the whole stream. A 1042 byte 7z came back broken
	 * for it, which is what made this visible.
	 *
	 * So: if the buffer was the size the module asked for and it filled,
	 * nothing was refused and there is nothing to report. If it was smaller
	 * than the module asked for, the clamp that made it smaller has already
	 * recorded the limit above - this is not the place that knows about it,
	 * and saying so twice was never what carried the message.
	 */
	if (st == KUNCOAT_STOPPED && out_hint && want == out_hint)
		st = KUNCOAT_OK;
	if (st != KUNCOAT_OK) {
		uint32_t why = oc_broken_of_status(st);

		/* A buffer the ratio clamp or the object cap sized, filled: this
		 * stream was cut short and the next one is unaffected. Said on the
		 * entry by buffered_cut, not sticky. */
		if (!(capped && why == KOF_BROKEN_LIMIT))
			oc_scan_broken(sc, why);
	}
}

/*
 * STEP 6: hand the output on - copied out for a peek, emitted for a produce -
 * and give the buffer back. Answers what the call answers.
 */
static uint64_t buffered_deliver(struct kof_scanner *sc,
				 const struct kof_obj_ctx *ctx,
				 const struct bufrun *r, uint64_t produced,
				 uint8_t *peek_out, uint32_t peek_cap)
{
	uint64_t want = r->want, decoded, at;
	uint8_t *buf = r->buf;
	int own = r->own;
	const uint8_t *sink_was = r->sink_was;
	size_t cap_was = r->cap_was;


	/*
	 * An image becomes a file before anybody sees it.
	 *
	 * Done here rather than after the emit because this is the only place the
	 * whole output is one contiguous buffer: past this point it is in a sink
	 * that may already have spilled to a temporary file. The rebuild is bounded
	 * by what is left under the ceiling for the same reason the decode was.
	 */
	/*
	 * What the DECODER produced, kept before the rebuild changes it.
	 *
	 * This is what the call reports back, and the distinction matters: a module
	 * compares the answer against the length its container declared, and that
	 * length describes the image, not the file the host went on to assemble
	 * from it. Returning the file's size made every rebuilt object look short
	 * and every UPX packed PE was reported as not fully examined.
	 */
	decoded = produced;

	if (peek_out) {
		uint64_t n = produced < (uint64_t)peek_cap ? produced
							  : (uint64_t)peek_cap;

		if (n)
			memcpy(peek_out, buf, (size_t)n);
		oc_scan_release(sc, want);
		free(buf);
		return n;
	}

	/*
	 * KOF_FORM_PE_IMAGE USED TO BE ANSWERED HERE, and is not any more.
	 *
	 * It meant "what I just decompressed is an image, put a file back
	 * together out of it", and the engine did that by hunting for a PE
	 * header inside the output, allocating a SECOND buffer the size of the
	 * whole image, and copying every section into it so that the result
	 * could be parsed back. Two copies of an image to recover a layout that
	 * was written down in the bytes all along.
	 *
	 * A module now asks for the same thing where it can see it happening:
	 * take an image, decompress into it, and call kunp_rcstruct_layout_of_image
	 * - which reads that header and DECLARES the sections. One buffer, and
	 * the module decides when. See upx_pe.c, and `layout_of_produced` in
	 * kofsig.h.
	 */


	/* Whatever was decoded is real output and is worth scanning, whether or not
	 * the stream ended cleanly - the same rule the gzip path follows. */
	if (own) {
		at = oc_emit_all(ctx, buf, produced);
		oc_scan_release(sc, want);
		free(buf);
	} else {
		/*
		 * ALREADY WHERE IT BELONGS. What is left is the bookkeeping
		 * oc_emit's fixed arm does after its memcpy, and it is spelled
		 * out here rather than borrowed, because oc_emit_all would copy
		 * the buffer onto itself.
		 *
		 * The sink is re-read rather than trusted: if anything had
		 * resized it while the decode ran, `buf` would be a pointer
		 * into a freed block and every byte just written would be
		 * lost. Nothing does - but a stale pointer is the failure this
		 * whole path could have, so it is checked instead of assumed.
		 */
		if (sc->sink.mem != sink_was || sc->sink.cap != cap_was) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		sc->sink.at += produced;
		if (sc->sink.at > sc->sink.len)
			sc->sink.len = sc->sink.at;
		at = produced;
	}
	/*
	 * Everything emitted means the decode is what to report; a short emit means
	 * the sink refused and how far it got is the useful number. The two differ
	 * only after a rebuild, where what was emitted is a file assembled from what
	 * was decoded and is a different size by construction.
	 */
	return at == produced ? decoded : at;
}

/*
 * A BUFFER THE OBJECT CAP OR THE RATIO CLAMP SIZED: the entry is cut, and says so on
 * its own child (oc_entry_cut) rather than stopping the walk. Said whether or not the
 * stream would have fitted, as the clamp always did (it cannot know). A peek is no
 * entry - it reads a header for its caller - so it keeps the old non-sticky mark on
 * the object.
 */
static void buffered_cut(struct kof_scanner *sc, const struct bufrun *r, int peek)
{
	if (!r->capped)
		return;
	if (peek)
		oc_scan_capped(sc, KOF_BROKEN_LIMIT);
	else
		oc_entry_cut(sc);
}

uint64_t oc_unpack_buffered(struct kof_scanner *sc,
			    const struct kof_obj_ctx *ctx,
			    const struct oc_buf_req *q)
{
	const uint32_t method = q->method;
	const uint64_t out_hint = q->out_hint;
	const uint8_t *in = q->in;
	const uint64_t in_len = q->in_len;
	uint8_t *peek_out = q->peek_out;
	const uint32_t peek_cap = q->peek_cap;
	struct bufrun r;
	enum kuncoat_status st;
	uint64_t produced;

	if (!buffered_size(sc, out_hint, &r))
		return 0;
	buffered_ratio_clamp(method, in_len, out_hint, &r);
	if (!buffered_place(sc, in, in_len, peek_out, &r)) {
		buffered_cut(sc, &r, peek_out != NULL);
		return 0;
	}
	if (!buffered_coding(sc, q, &r, &st, &produced)) {
		buffered_cut(sc, &r, peek_out != NULL);
		return 0;
	}
	buffered_note(sc, st, out_hint, &r);
	produced = buffered_deliver(sc, ctx, &r, produced, peek_out, peek_cap);
	buffered_cut(sc, &r, peek_out != NULL);
	return produced;
}

/*
 * Decode the front of a stream into the caller's buffer.
 *
 * A read, not a production: nothing reaches a sink, nothing is charged against
 * the object ceiling, and a short or damaged stream is the caller's to judge
 * rather than something recorded against the object. What it is for is a
 * container whose layout is written in a header the container compressed - see
 * `unpack_peek` in kofsig.h.
 *
 * `cap` is the caller's buffer and the only size involved, so nothing a hostile
 * object declares can size anything here. The decoders all take an output
 * bound, and a back reference reaches only bytes already produced, so stopping
 * at `cap` gives the same first `cap` bytes a full decode would.
 */
uint32_t oc_unpack_peek(const struct kof_obj_ctx *ctx, uint32_t method,
			      uint64_t off, uint64_t len, void *out,
			      uint32_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	int variant, bits;
	kof_buf b;

	if (!sc->cur.src || !out || !cap)
		return 0;
	b = kof_src_buf(sc->cur.src);
	len = kof_clip_len(b.n, off, len);
	if (!len)
		return 0;

	/*
	 * Through the same decode as unpack, with the caller's buffer as the
	 * destination. `cap` is also the output bound, which matters more than
	 * it looks: NRV2 has no end marker and stops when the output is full,
	 * so the size it is given is part of the decode rather than a limit
	 * around it. A caller wanting the first N bytes of a block must pass
	 * the block's own declared size, not the size of its buffer.
	 */
	if (!oc_buffered_method(method))
		return 0;
	if (!oc_nrv2_of(method, &variant, &bits))
		variant = bits = 0;
	{
		const struct oc_buf_req q = { method, variant, bits, b.p + off, len,
					      cap, (uint8_t *)out, cap };

		return (uint32_t)oc_unpack_buffered(sc, ctx, &q);
	}
}
