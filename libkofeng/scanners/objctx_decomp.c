/*
 * objctx_decomp.c - the decoders a module asks the engine to run.
 *
 * WHAT THIS SERVES: a container or packer module names a coding and a range;
 * the engine decodes it into the sink, charged to the memory ceiling and bounded
 * by the object's own size (never by what the stream claims). Everything here is
 * a bounded transform from bytes to bytes with a reported outcome: nothing in it
 * decides what the result is, and nothing in it is a verdict.
 *
 * THE OPEN ITEM OF THE AUDIT (DESIGN-objctx.md): the expansion clamp is applied
 * to three codings and not to the cabinet and VBA paths; the bound belongs to
 * the sink, not to the coding.
 */

#define _GNU_SOURCE

#include <kofmod/kofsym.h>
#include <kofmod/heur.h>   /* KOF_ENG_USE_EMU - a module's declaration */
#include "../kofcore/kofplatform.h"
#include "../kofcore/kofdebug.h"   /* kof_write_all - the spill file below */
#include "../analyzers/parsers/binaries/elf/elf_sym.h"
#include <kofmod/kofpathogen.h>
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../analyzers/parsers/binaries/disasm/xref.h"
#include "../disinfect/pzero.h"
#include "../analyzers/normalize/executables.h"
#include "scan.h"
#include <kofmod/elf.h>
#include "../extractors/unpack/emu_unpack.h"
#include "../extractors/unpack/elf_rebuild.h"

#include "../extractors/decomp/ovba.h"
#include "../extractors/decomp/lzma.h"
#include "../extractors/decomp/aplib.h"
#include "../extractors/decomp/aspack.h"
#include "../extractors/decomp/lzmat.h"
#include "../extractors/decomp/bcj.h"
#include "../extractors/decomp/rar3.h"
#include "../extractors/decomp/rar5.h"
#include "../extractors/decomp/bcj2.h"
/* The script folding pass and the lexical table it is driven from - see
 * kof_scan_script_fold below. */
#include "../analyzers/parsers/scripts/script_norm.h"
#include "../analyzers/parsers/scripts/script_parse.h"
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */
#include <kofmod/sevenzip.h>

#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/pathogen/kofdiag.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "objctx_int.h"

/*
 * What the sinks below carry.
 *
 * The sink signature hands back a void *, and what this one needs on the other
 * side is a pointer that is const - the two other sinks in this engine write
 * through theirs, so the typedef cannot be tightened for all of them. Passing
 * the const pointer as void * meant casting the const away and casting it
 * straight back, a promise no compiler can check and the engine's only such
 * cast. A one field carrier keeps the promise in the type instead.
 */
struct sink_carry {
	const struct kof_obj_ctx *ctx;
};

static int inflate_sink(void *user, const uint8_t *p, uint32_t n)
{
	const struct sink_carry *c = user;

	return oc_emit(c->ctx, p, n);
}

/*
 * WHEN A STREAM'S OWN DECLARED EXPANSION SAYS NOT TO BOTHER.
 *
 * The object cap bounds how much one object may hold and says nothing about how it
 * got there, so a stream that expands absurdly is decoded up to that cap like any
 * other. Measured on this collection: 52 objects reach the cap and cost 3.75 of the
 * scan's 9.17 seconds, and the worst is one zip entry declaring 839MB out of a
 * 956KB file - one entry, nothing behind the name but padding.
 *
 * What separates those from real content is not the bytes, which have to be decoded
 * to be seen, but the RATIO THE CONTAINER DECLARES, which is free. Measured over
 * 12787 real zip entries of 4KB or more:
 *
 *     p50 2.8x  p95 6.5x  p99 21.4x  p99.5 29.9x  |  p99.9 654x  max 982x
 *
 * There is a gap and it is wide. Everything a real file does sits under thirty; the
 * padding sits at six hundred and up, and 0.4% of entries are above 32x. So the line
 * goes in the gap - chosen for where the two populations stop overlapping, not for
 * how much time it saves.
 *
 * A stream over the line is decoded to the floor below and no further. Not a
 * detection and not a verdict: the prefix is still scanned and the object is still
 * reported as cut. It costs a bomb its tail and a real file nothing, because a real
 * file is not on that side of the line.
 *
 * Only usable where the container SAYS what it expects. A decoder handed no size -
 * a gzip member, whose length is in a trailer nobody has read yet - gets the object
 * cap and nothing cleverer.
 */
#define KOF_DECLARED_RATIO_MAX 32u
#define KOF_EXPAND_FLOOR (1u << 20)

/*
 * A sink that stops once the expansion bound is reached.
 *
 * Wrapping rather than checking inside oc_emit because the bound depends on the
 * INPUT to one decode, which oc_emit has no way to see - it is handed bytes, not
 * the stream they came from.
 */
struct expand_sink {
	const struct kof_obj_ctx *ctx;
	uint64_t left;
};

static int expand_sink_fn(void *user, const uint8_t *p, uint32_t n)
{
	struct expand_sink *e = user;

	if (n > e->left)
		n = (uint32_t)e->left;
	if (n == 0)
		return 0;              /* the receiver has had enough */
	e->left -= n;
	return oc_emit(e->ctx, p, n);
}

/*
 * What one decode is allowed to produce, given what the container declared.
 *
 * UINT64_MAX means "no opinion" - either nothing was declared, or what was declared
 * is within reason - and the caller then falls back to the object cap.
 */
static uint64_t expand_limit(uint64_t in_len, uint64_t declared)
{
	if (!declared || !in_len)
		return UINT64_MAX;
	if (declared / in_len <= KOF_DECLARED_RATIO_MAX)
		return UINT64_MAX;
	return KOF_EXPAND_FLOOR;
}

/*
 * WHICH OF A STREAMING DECODER'S NON-OK ANSWERS THIS CODING CALLS ORDINARY.
 *
 * They differ by format and the difference is real, so it is a parameter
 * rather than one rule for all of them:
 *
 *   DEFLATE has an end-of-stream marker, so a truncated stream is a truncated
 *   stream and is worth saying.
 *   bzip2, LZW and RunLength end where their input does, so TRUNCATED is the
 *   ordinary ending - though a bzip2 CHECKSUM failure is not, and that arrives
 *   as its own status.
 *   LHA, ARJ and LZX stop when the declared original size has been produced,
 *   so STOPPED is theirs too.
 */
#define STREAM_STRICT   0u
#define STREAM_PARTIAL  1u      /* ... and a stream that simply ran out */
#define STREAM_FILLED   2u      /* ... and one that filled what was asked for */

/*
 * What one streaming decode is worth reporting.
 *
 * Eight callers wrote this out, each with its own spelling of which statuses
 * to tolerate - which is the part that genuinely differs - and all eight with
 * the SAME second clause, which is the part that does not. That clause is the
 * one that matters and the one most easily left out: `left == 0` means the
 * ratio clamp cut the stream, and without it a bomb's prefix is handed on as
 * though it were the whole entry. It was right in all eight, and nothing was
 * making it so.
 */
static void stream_note(struct kof_scanner *sc, enum kof_decomp_status st,
			uint32_t ordinary, const struct expand_sink *snk)
{
	if (st != KOF_DEC_OK &&
	    !(st == KOF_DEC_TRUNCATED && (ordinary & STREAM_PARTIAL)) &&
	    !(st == KOF_DEC_STOPPED && (ordinary & STREAM_FILLED)))
		oc_scan_broken(sc, oc_broken_of_status(st));
	else if (snk->left == 0)
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
}

/*
 * RFC 1950's two byte header, STEPPED OVER WHEN IT IS REALLY THERE.
 *
 * zlib is DEFLATE with a header in front and an Adler-32 behind. The trailer
 * needs nothing - inflate stops at its own end-of-stream marker and never
 * reads it - so only the header has to go, and after it the bytes are exactly
 * what the DEFLATE path already handles.
 *
 * CHECKED, NOT ASSUMED. CM must be 8, the window no larger than 32KB, the two
 * bytes together a multiple of 31 - the check digit RFC 1950 carries for
 * exactly this - and FDICT clear, because a preset dictionary names data this
 * engine does not have and decoding without it produces confident garbage. A
 * stream that fails is raw DEFLATE under a zlib name, which is what a producer
 * that emitted RFC 1951 meant, so it is decoded from its FIRST byte. That is
 * why a caller unsure which of the two it holds can name zlib and be right
 * either way - and why the PDF module, whose /FlateDecode is either in
 * practice, does exactly that.
 *
 * ONE COPY. It was written out twice, once over the object in oc_unpack and
 * once over an intermediate in oc_unpack_chain, and a check digit repeated is a
 * check digit that can be repeated wrong.
 *
 * Answers how many bytes to skip: 2 or 0.
 */
static uint64_t zlib_hdr_len(const uint8_t *p, uint64_t n)
{
	uint32_t cmf, flg;

	if (n <= 2u)
		return 0;
	cmf = p[0];
	flg = p[1];
	return ((cmf & 0x0fu) == 8u && (cmf >> 4) <= 7u &&
		((cmf << 8) + flg) % 31u == 0u && !(flg & 0x20u)) ? 2u : 0u;
}

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
 * The methods unpack_buffered takes: everything whose whole output has to be
 * addressable at once. DEFLATE and HEXTEXT stream instead and are answered
 * before this is asked.
 *
 * A predicate rather than three ifs in a row, each ending in the same call.
 * That is what it was, in both places, and the three differed only in whether
 * NRV2 had filled in a variant and a width - which nrv2_of already says.
 */
static int buffered_method(uint32_t method)
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
	 * reached unpack_buffered, took the LZMA arm, and was refused by
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
static int nrv2_of(uint32_t method, int *variant, int *bits)
{
	static const struct { int v, b; } tab[9] = {
		{ KOF_NRV2B, 8 }, { KOF_NRV2B, 16 }, { KOF_NRV2B, 32 },
		{ KOF_NRV2D, 8 }, { KOF_NRV2D, 16 }, { KOF_NRV2D, 32 },
		{ KOF_NRV2E, 8 }, { KOF_NRV2E, 16 }, { KOF_NRV2E, 32 }
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
	return *lc <= KOF_LZMA_MAX_LC && *lp <= KOF_LZMA_MAX_LP &&
	       *pb <= KOF_LZMA_MAX_PB;
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
static uint64_t unpack_buffered(struct kof_scanner *sc,
				const struct kof_obj_ctx *ctx, uint32_t method,
				int variant, int bits, const uint8_t *in,
				uint64_t in_len, uint64_t out_hint,
				uint8_t *peek_out, uint32_t peek_cap)
{
	uint64_t room, want, produced = 0, decoded, at;
	uint8_t *buf;
	enum kof_decomp_status st;
	int capped = 0;
	/* Whether `buf` is this function's to free - see the note beside the
	 * allocation. */
	int own;
	const uint8_t *sink_was = NULL;
	size_t cap_was = 0;

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
		int by_policy = room > sc->obj_cap;

		if (by_policy)
			room = sc->obj_cap;
		want = out_hint ? out_hint : room;
		if (want > room) {
			want = room;
			/* The tail will not fit and will be dropped. Sticky only
			 * when it was residency that ran out. */
			if (by_policy) {
				capped = 1;
				oc_scan_capped(sc, KOF_BROKEN_LIMIT);
			} else {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			}
		}
	}

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
			capped = 1;
			oc_scan_capped(sc, KOF_BROKEN_LIMIT);
		}
	}

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
	if (!peek_out && sc->sink_fixed && sc->sink_mem &&
	    sc->sink_at <= sc->sink_cap && want <= sc->sink_cap - sc->sink_at) {
		uint8_t *dst = sc->sink_mem + sc->sink_at;

		if (!in || !in_len ||
		    (const uint8_t *)in + in_len <= dst || in >= dst + want) {
			buf = dst;
			own = 0;
			sink_was = sc->sink_mem;
			cap_was = sc->sink_cap;
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
		uint64_t sn = method == KOF_UNP_RAR3 ? KOF_RAR3_SCRATCH
						     : KOF_RAR5_SCRATCH;
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
			st = kof_rar3_decode(in, in_len, buf, want, scratch,
					     scratch ? sn : 0u, &produced);
		else
			st = kof_rar5_decode(in, in_len, buf, want, scratch,
					     scratch ? sn : 0u, &produced);
		if (scratch) {
			oc_scan_release(sc, sn);
			free(scratch);
		}
	} else if (method == KOF_UNP_LZMAT || lzmat_cto_bits(method)) {
		unsigned cto = lzmat_cto_bits(method);

		/* Buffered like aPLib and for the same reason: a match
		 * distance has no ceiling and the buffer IS the window. */
		st = kof_lzmat_decode(in, in_len, buf, want, &produced);
		/* And the call target conversion undone over the whole of it,
		 * exactly as the LZMA pair below does it. */
		if (cto && produced)
			kof_mpress_cto_decode(buf, produced, cto);
	} else if (method == KOF_UNP_APLIB) {
		/*
		 * Buffered for the reason NRV2 is: an aPLib match distance has
		 * no ceiling, so the whole output has to stay addressable until
		 * the stream ends and the buffer IS the window.
		 */
		st = kof_aplib_decode(in, in_len, buf, want, &produced);
	} else if (aspack_mark_of(method) >= 0) {
		int mark = aspack_mark_of(method);

		/* Buffered for the same reason again - see aspack.h. */
		st = kof_aspack_decode(in, in_len, buf, want, &produced);
		/*
		 * And the call/jmp filter undone over the whole block, where
		 * the LZMA and BCJ pairs undo theirs and for the same reason:
		 * it rewrites a displacement against the instruction's own
		 * position in the OUTPUT.
		 */
		if (mark > 0 && produced)
			kof_aspack_e8e9_decode(buf, produced,
					       (uint8_t)(mark - 1));
	} else if (method == KOF_UNP_LZMA2 || method == KOF_UNP_LZMA2_BCJ_X86) {
		st = kof_lzma2_decode(in, in_len, buf, want, &produced);
		/*
		 * The transform is undone here, over the whole decoded buffer,
		 * because that is the only place it can be: it rewrites addresses
		 * that are relative to a position in the OUTPUT, so it cannot run
		 * on the compressed bytes and cannot run on a chunk of the output
		 * without knowing where that chunk sits. A buffered decode has the
		 * whole thing in hand and a streaming one never would.
		 */
		if (method == KOF_UNP_LZMA2_BCJ_X86 && produced)
			kof_bcj_x86_decode(buf, produced, 0);
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
		st = kof_lzma_decode(lc, lp, pb, in, in_len, buf, want, &produced);
		/*
		 * Undone here for the reason the BCJ call above is: the
		 * transform rewrites addresses relative to a position in the
		 * output, so it needs the whole output and this is where the
		 * whole output is.
		 *
		 * ON A SHORT DECODE TOO, and deliberately. A stream that
		 * stopped early still yields a real prefix - kof_lzma_decode's
		 * contract says so - and the filter's bound is a length rather
		 * than a structure, so it converts what arrived and leaves the
		 * rest. The alternative is handing back a prefix whose calls
		 * are all wrong, which is the state this exists to end.
		 */
		if (cto && produced)
			kof_mpress_cto_decode(buf, produced, cto);
	} else {
		st = kof_nrv2_decode(variant, bits, in, in_len, buf, want,
				     &produced);
	}
	/*
	 * STOPPED IS NOT A LIMIT WHEN THE CALLER GOT WHAT IT ASKED FOR.
	 *
	 * KOF_DEC_STOPPED means the output buffer filled. Whether that is a
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
	if (st == KOF_DEC_STOPPED && out_hint && want == out_hint)
		st = KOF_DEC_OK;
	if (st != KOF_DEC_OK) {
		uint32_t why = oc_broken_of_status(st);

		/* A buffer the ratio clamp sized, filled: this stream was cut
		 * short and the next one is unaffected. Recorded, not sticky -
		 * see oc_scan_capped. */
		if (capped && why == KOF_BROKEN_LIMIT)
			oc_scan_capped(sc, why);
		else
			oc_scan_broken(sc, why);
	}

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
		if (sc->sink_mem != sink_was || sc->sink_cap != cap_was) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		sc->sink_at += produced;
		if (sc->sink_at > sc->sink_len)
			sc->sink_len = sc->sink_at;
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

	if (!sc->cur_src || !out || !cap)
		return 0;
	b = kof_src_buf(sc->cur_src);
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
	if (!buffered_method(method))
		return 0;
	if (!nrv2_of(method, &variant, &bits))
		variant = bits = 0;
	return (uint32_t)unpack_buffered(sc, ctx, method, variant, bits,
					 b.p + off, len, cap,
					 (uint8_t *)out, cap);
}

/*
 * RTF's hex text, back to bytes.
 *
 * Its own function because it is an algorithm, not a dispatch: oc_unpack picks a
 * decoder and this decodes, and having the two in one place made oc_unpack a
 * hundred and forty lines that reached eight levels deep - all of the depth
 * being here, in the brace and control-word skipping this format needs.
 *
 * WHAT IT SKIPS AND WHY. \bin and its friends put arbitrary text between the
 * hex digits, and a group in braces can hold a whole document; both would
 * otherwise be read as data. The control word skip is the one that matters:
 * without it "\par" contributes an 'a' to the stream and every byte after it
 * is shifted by half a nibble.
 */
static uint64_t unpack_hextext(const struct kof_obj_ctx *ctx, kof_buf b,
			       uint64_t off, uint64_t len)
{
	uint64_t produced = 0;

	/*
	 * Hex to bytes, streamed through the sink like DEFLATE.
	 *
	 * No output buffer of its own and no size hint needed: two input
	 * characters are one output byte, so the length is known and the
	 * bytes can leave as they are made. Whitespace between digits is
	 * skipped - it is legal in RTF and is used to break a blob up so a
	 * fixed prefix does not match.
	 */
	uint8_t out[512];
	uint32_t n = 0;
	int hi = -1;
	uint64_t i;

	for (i = 0; i < len; i++) {
		uint8_t ch = b.p[off + i];
		int v;

		if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
			continue;
		/*
		 * A nested group is skipped WHOLE, not just its braces.
		 *
		 * Its content is a different destination and is not this
		 * object's data. Skipping only the braces decodes the junk
		 * inside as if it were payload, which on a real document
		 * produced 2875922 bytes against the correct 2875905 - the
		 * right length to look plausible and wrong from the first
		 * byte.
		 */
		if (ch == '{') {
			uint32_t d = 0;

			while (i < len) {
				uint8_t g = b.p[off + i];

				if (g == '\\') {
					i += 2u;
					continue;
				}
				if (g == '{') {
					d++;
				} else if (g == '}') {
					d--;
					if (d == 0)
						break;
				}
				i++;
			}
			continue;
		}
		if (ch == '}')
			continue;
		if (ch == '\\') {
			uint64_t k = i + 1u;
			int alpha = 0;

			/*
			 * A control WORD is letters; a control SYMBOL is
			 * one character that is not. Both have to be
			 * stepped over and the second is the one that
			 * catches a reader out - the ignorable destination
			 * marker is written "\*", so a decoder that skips
			 * only the backslash lands on the asterisk, finds
			 * it is not a hex digit, and stops. Measured on a
			 * real document that ended the decode after zero
			 * bytes of a 2.8MB payload.
			 */
			while (k < len) {
				uint8_t d = b.p[off + k];

				if (!((d >= 'a' && d <= 'z') ||
				      (d >= 'A' && d <= 'Z')))
					break;
				alpha = 1;
				k++;
			}
			if (!alpha) {
				i = k;            /* the symbol itself */
				continue;
			}
			if (k < len && b.p[off + k] == '-')
				k++;
			while (k < len && b.p[off + k] >= '0' &&
			       b.p[off + k] <= '9')
				k++;
			if (k < len && b.p[off + k] == ' ')
				k++;
			i = k - 1u;
			continue;
		}
		if (ch >= '0' && ch <= '9')       v = ch - '0';
		else if ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'f')
			v = (ch | 0x20) - 'a' + 10;
		else
			continue;                 /* skipped, as the parser does */
		if (hi < 0) {
			hi = v;
			continue;
		}
		out[n++] = (uint8_t)((hi << 4) | v);
		hi = -1;
		if (n == sizeof out) {
			if (!oc_emit(ctx, out, n))
				return produced;
			produced += n;
			n = 0;
		}
	}
	if (n && oc_emit(ctx, out, n))
		produced += n;
	return produced;
}

/*
 * ASCII85 as a coding in its own right, not only as a step of a chain.
 *
 * Through a buffer and then one emit, rather than a streaming sink like
 * DEFLATE's: the decode is ONE PASS over input that is already addressable, and
 * the output is at most four fifths of it, so the buffer is bounded by
 * something the OS reported rather than by anything the file claims. That is
 * what makes malloc safe here where it would not be for an expanding coding.
 *
 * THE SAME a85_decode THE CHAIN USES. A second copy of the alphabet, the
 * padding rule and the overflow test would be a second thing that can be wrong
 * in a way the first is not, and only one of them would be under test - the
 * same reasoning kof_src_label's note gives for sanitising in one place.
 *
 * It existed only inside the chain runner before, which meant a stream whose
 * ONLY filter was /ASCII85Decode was named correctly, produced nothing, and
 * said nothing about why. A silent nothing is the one answer this engine must
 * not give, so the refusal paths below all report.
 */
static uint64_t unpack_textcode(const struct kof_obj_ctx *ctx, uint32_t method,
				kof_buf b, uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	enum kof_decomp_status st;
	uint64_t room, got = 0, at;
	uint8_t *buf;

	/*
	 * RunLength goes straight to the sink and never through a buffer,
	 * because its output cannot be sized from its input - see
	 * textcode.h. Answered first so the buffer below is only ever
	 * allocated for a coding that can be bounded.
	 */
	if (method == KOF_UNP_RUNLENGTH) {
		struct expand_sink snk;

		snk.ctx = ctx;
		snk.left = expand_limit(len, 0);
		st = kof_rle_decode(b.p + off, len, expand_sink_fn, &snk, &got);
		stream_note(sc, st, STREAM_PARTIAL, &snk);
		return got;
	}

	room = oc_scan_room(sc);
	if (len > room) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	buf = malloc((size_t)len);
	if (!buf) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	scan_charge(sc, len);

	st = method == KOF_UNP_ASCII85
	   ? kof_a85_decode(b.p + off, len, buf, len, &got)
	   : kof_ahx_decode(b.p + off, len, buf, len, &got);
	if (st != KOF_DEC_OK) {
		/* The container said this WAS the coding, so input that is not
		 * it is the file disagreeing with itself - damage, not a gap in
		 * the engine, and the two lead different places. Whatever
		 * decoded before the disagreement is still emitted below: those
		 * bytes are real, and the same judgement is made about a
		 * damaged archive. */
		oc_scan_broken(sc, oc_broken_of_status(st));
	}
	at = oc_emit_all(ctx, buf, got);
	free(buf);
	oc_scan_release(sc, len);
	return at;
}

uint64_t oc_unpack(const struct kof_obj_ctx *ctx, uint32_t method,
			 uint64_t off, uint64_t len, uint64_t out_hint)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b;
	uint64_t produced = 0;
	int variant, bits;

	if (!sc->cur_src)
		return 0;
	b = kof_src_buf(sc->cur_src);
	/*
	 * Clipped to what the object holds, not refused.
	 *
	 * The length comes from a container's own metadata, and a compressed size
	 * that runs past the end of the file is the ordinary hostile case rather
	 * than an exceptional one - the same reasoning kof_clip_len is written for.
	 * Decoding what is really there and reporting truncation is more useful
	 * than declining to look.
	 */
	len = kof_clip_len(b.n, off, len);
	if (!len)
		return 0;

	/*
	 * ZLIB IS DEFLATE WITH TWO BYTES IN FRONT, so it is answered by moving
	 * the window rather than by a second decoder - see zlib_hdr_len, which
	 * is where the header is checked.
	 */
	if (method == KOF_UNP_ZLIB) {
		uint64_t h = zlib_hdr_len(b.p + off, len);

		off += h;
		len -= h;
		method = KOF_UNP_DEFLATE;
	}

	if (method == KOF_UNP_DEFLATE) {
		if (!sc->inf) {
			sc->inf = malloc(sizeof *sc->inf);
			if (!sc->inf) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
		}
		/*
		 * A truncated or corrupt stream is not an error here.
		 *
		 * Whatever was decoded before the failure is real output and is
		 * the part worth scanning: archives inside malware are routinely
		 * damaged, and discarding a megabyte of decoded payload because
		 * the last block is missing throws away the part that identifies
		 * it. It is recorded as an incomplete examination, not a clean one.
		 */
		{
			struct expand_sink e;
			enum kof_decomp_status st;

			e.ctx = ctx;
			e.left = expand_limit(len, out_hint);
			st = kof_inflate(sc->inf, b.p + off, len, expand_sink_fn,
					 &e, NULL, &produced);
			stream_note(sc, st, STREAM_STRICT, &e);
		}
		return produced;
	}

	if (method == KOF_UNP_HEXTEXT)
		return unpack_hextext(ctx, b, off, len);
	if (method == KOF_UNP_ASCII85 || method == KOF_UNP_ASCIIHEX ||
	    method == KOF_UNP_RUNLENGTH)
		return unpack_textcode(ctx, method, b, off, len);
	if (method == KOF_UNP_LZW) {
		struct expand_sink snk;
		enum kof_decomp_status st;
		uint64_t got = 0;

		if (!sc->lzw) {
			sc->lzw = malloc(sizeof *sc->lzw);
			if (!sc->lzw) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
		}
		snk.ctx = ctx;
		snk.left = expand_limit(len, out_hint);
		st = kof_lzw_decode(sc->lzw, b.p + off, len, expand_sink_fn,
				    &snk, &got);
		/*
		 * Truncation is not an error, for the reason the DEFLATE path
		 * gives: whatever decoded before the stream ran out is real
		 * output and is the part worth scanning.
		 */
		stream_note(sc, st, STREAM_PARTIAL, &snk);
		return got;
	}

	if (method == KOF_UNP_BZIP2) {
		struct expand_sink snk;
		enum kof_decomp_status st;
		uint64_t got = 0;

		if (!sc->bz) {
			sc->bz = malloc(sizeof *sc->bz);
			if (!sc->bz) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
		}
		snk.ctx = ctx;
		snk.left = expand_limit(len, out_hint);
		st = kof_bunzip_decode(sc->bz, b.p + off, len, expand_sink_fn,
				       &snk, &got);
		/*
		 * Truncation is not an error, for the reason the DEFLATE path
		 * gives. A CHECKSUM MISMATCH IS - it is the one thing bzip2
		 * carries that says the bytes came back different from the ones
		 * that went in, and reporting that as a clean decode would hand
		 * a rule content the archive never held.
		 */
		stream_note(sc, st, STREAM_PARTIAL, &snk);
		return got;
	}

	if (method >= KOF_UNP_LZHUF_ARJ && method <= KOF_UNP_LZHUF_LH7) {
		struct expand_sink snk;
		enum kof_decomp_status st;
		uint64_t got = 0;

		/*
		 * OUT_HINT IS NOT A HINT HERE. An LHA or ARJ stream has no end
		 * marker: it stops when the declared original size has been
		 * produced. Without one there is nothing to decode against, so
		 * an entry that does not carry it is refused rather than run
		 * until something goes wrong.
		 */
		if (!out_hint)
			return 0;
		if (!sc->lzh) {
			sc->lzh = malloc(sizeof *sc->lzh);
			if (!sc->lzh) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
		}
		snk.ctx = ctx;
		snk.left = expand_limit(len, out_hint);
		st = kof_lzhuf_decode(sc->lzh,
				      (enum kof_lzhuf_variant)
					      (method - KOF_UNP_LZHUF_ARJ),
				      b.p + off, len, out_hint,
				      expand_sink_fn, &snk, &got);
		/* Truncation is not an error, for the reason the DEFLATE path
		 * gives - and here it is also what a declared size larger than
		 * the stream looks like, which is an archive's claim and not
		 * this engine's failure. */
		stream_note(sc, st, STREAM_PARTIAL | STREAM_FILLED, &snk);
		return got;
	}

	if (!buffered_method(method))
		return 0;              /* a method this engine does not have */
	if (!nrv2_of(method, &variant, &bits))
		variant = bits = 0;
	return unpack_buffered(sc, ctx, method, variant, bits, b.p + off, len,
			       out_hint, NULL, 0);
}

/*
 * Join one entry's chain and decode it, in that order.
 *
 * The joining has to happen first and into a buffer of its own, because every
 * decoder here reads a contiguous input - and an entry's bytes are a chain that is
 * not consecutive 23.6% of the time. The buffer is charged against the residency
 * ceiling while it is alive, on the same account as a decoder's output, so a
 * document full of large streams cannot walk past the limit one stream at a time.
 */
/*
 * Decode one BCJ2 folder: three coded streams and a raw one, merged.
 *
 * Every buffer is charged to the resident budget before it is taken and released
 * whatever happens after, because four allocations on one path is four ways to
 * leak. The output length is the folder's, which the archive states and the ratio
 * cap has already been applied to by the caller that chose to ask.
 */
static uint64_t decode_stream(const struct kof_7z_pack *pk, const uint8_t *in,
			      uint8_t *out, uint64_t cap, uint64_t *got)
{
	uint64_t n = 0;
	enum kof_decomp_status st;

	*got = 0;
	if (pk->coder == KOF_7Z_CODER_LZMA2)
		st = kof_lzma2_decode(in, pk->size, out, cap, &n);
	else if (pk->coder == KOF_7Z_CODER_LZMA)
		st = kof_lzma_decode(pk->lc, pk->lp, pk->pb, in, pk->size,
				     out, cap, &n);
	else
		return 0;              /* a coder this build does not have */
	*got = n;
	return st == KOF_DEC_OK || n ? 1u : 0u;
}

static uint64_t unpack_bcj2(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			    uint32_t index)
{
	const struct kof_7z_info *z = kof_7z(ctx);
	const struct kof_7z_pack *pk[4] = { 0, 0, 0, 0 };
	uint8_t *buf[3] = { 0, 0, 0 };
	uint64_t len[3] = { 0, 0, 0 }, charged = 0, out_len, produced = 0;
	uint8_t *out = NULL;
	kof_buf b;
	uint32_t i;

	if (ctx->format != KOF_FMT_7Z || !z || !z->valid ||
	    index >= z->n_folders)
		return 0;
	out_len = z->folder[index].unpack_size;
	if (!out_len)
		return 0;

	for (i = 0; i < z->n_pack; i++)
		if (z->pack[i].folder == index && z->pack[i].role < 4u)
			pk[z->pack[i].role] = &z->pack[i];
	if (!pk[0] || !pk[1] || !pk[2] || !pk[3])
		return 0;              /* the folder is not the shape BCJ2 needs */

	b = kof_src_buf(sc->cur_src);
	for (i = 0; i < 4u; i++)
		if (kof_clip_len(b.n, pk[i]->off, pk[i]->size) != pk[i]->size)
			return 0;      /* a stream the object does not hold */

	/* The three coded streams, then the output. Charged together so a partial
	 * failure gives the budget back in one place.
	 *
	 * kof_sat_add, not +=: out_len and every out_size here is unclipped -
	 * sevenzip_parse.c reads them as a bare 64-bit varint straight off the
	 * stream, unlike the pack off/size pair checked against the real buffer
	 * a few lines above. Four attacker-chosen values near 2^64/4 each would
	 * otherwise wrap `charged` down to something small enough to slip past
	 * the budget check below while the mallocs further down still see the
	 * real, enormous sizes - the budget invariant this file otherwise
	 * enforces everywhere else, bypassed by exactly the overflow it exists
	 * to rule out. */
	charged = out_len;
	for (i = 0; i < 3u; i++)
		charged = kof_sat_add(charged, pk[i]->out_size);
	if (charged > oc_scan_room(sc)) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	scan_charge(sc, charged);

	/*
	 * A STREAM THAT IS EMPTY IS STILL A STREAM, AND STILL NEEDS A POINTER.
	 *
	 * BCJ2 cuts x86 into four: the code, the call targets, the jump
	 * targets and the range coder. A folder whose code has E8 calls and no
	 * E9 jumps has an EMPTY JUMP CHANNEL, which is an ordinary shape and
	 * not a damaged one.
	 *
	 * This skipped the allocation for such a channel and left the pointer
	 * NULL, and kof_bcj2_decode refuses any NULL pointer outright - it
	 * bounds every read by the channel's LENGTH, so the pointer never
	 * mattered, but the guard does not know that. The decode returned 0,
	 * `produced != out_len` fired, and a sound archive was reported
	 * KOF_BROKEN_DAMAGED with nothing extracted.
	 *
	 * One byte rather than none, because malloc(0) may itself answer NULL
	 * and put us back where we started.
	 */
	for (i = 0; i < 3u; i++) {
		uint64_t want = pk[i]->out_size ? pk[i]->out_size : 1u;

		buf[i] = malloc((size_t)want);
		if (!buf[i])
			goto done;
		if (pk[i]->out_size &&
		    !decode_stream(pk[i], b.p + pk[i]->off, buf[i],
				   pk[i]->out_size, &len[i]))
			goto done;
	}
	out = malloc((size_t)out_len);
	if (!out)
		goto done;

	produced = kof_bcj2_decode(buf[0], len[0], buf[1], len[1],
				   buf[2], len[2],
				   b.p + pk[3]->off, pk[3]->size,
				   out, out_len);
	if (produced != out_len)
		oc_scan_broken(sc, KOF_BROKEN_DAMAGED);
	oc_emit_all(ctx, out, produced);
done:
	free(out);
	for (i = 0; i < 3u; i++)
		free(buf[i]);
	oc_scan_release(sc, charged);
	return produced;
}

/*
 * What one MSZIP decode is producing: a window onto the folder's stream, and
 * the history the next block will need.
 */
struct mszip_out {
	const struct kof_obj_ctx *ctx;
	uint64_t skip, left;      /* of the FILE, inside the folder's stream */
	uint8_t *hist;            /* the last 32KB produced, for the next block */
	uint32_t hist_len;
	uint64_t emitted;
	int stopped;
};

/*
 * THE HISTORY IS KEPT WHATEVER IS EMITTED, and that is the whole subtlety
 * here: the bytes in front of this file belong to other files and are dropped,
 * but the NEXT BLOCK may reference them - so they go into the history even
 * though nothing is done with them. A sink that only remembered what it emitted
 * would decode the second block against a window with holes in it.
 */
static int mszip_sink_fn(void *user, const uint8_t *p, uint32_t n)
{
	struct mszip_out *o = user;
	uint32_t at = 0;

	/* The tail, for the block after this one. */
	if (n >= KOF_INF_WINDOW) {
		memcpy(o->hist, p + (n - KOF_INF_WINDOW), KOF_INF_WINDOW);
		o->hist_len = KOF_INF_WINDOW;
	} else if (n) {
		uint32_t keep = KOF_INF_WINDOW - n;

		if (o->hist_len > keep)
			memmove(o->hist, o->hist + (o->hist_len - keep), keep);
		else
			keep = o->hist_len;
		memcpy(o->hist + keep, p, n);
		o->hist_len = keep + n;
	}

	if (o->skip) {
		uint64_t drop = o->skip < n ? o->skip : n;

		o->skip -= drop;
		at = (uint32_t)drop;
	}
	while (at < n && o->left) {
		uint32_t take = n - at;

		if ((uint64_t)take > o->left)
			take = (uint32_t)o->left;
		if (!oc_emit(o->ctx, p + at, take)) {
			o->stopped = 1;
			return 0;
		}
		o->emitted += take;
		o->left -= take;
		at += take;
	}
	/* Past the file, and the folder still has blocks: keep decoding only
	 * while something is still wanted. */
	return o->left != 0 || o->skip != 0;
}

/*
 * MSZIP: A FOLDER OF DEFLATE BLOCKS THAT SHARE A DICTIONARY, and one file cut
 * out of what they decode to.
 *
 * The ranges resolve_entry hands back are the folder's BLOCKS in order, each
 * "CK" and then a deflate stream. They are not one stream and must not be
 * joined: every block is its own, and every block after the first may reference
 * up to 32KB of the previous one's output. So each is decoded separately with
 * the last block's tail as history - see kof_inflate_seeded, whose note records
 * what decoding them from an empty window produces instead.
 *
 * WHY THE WHOLE FOLDER IS DECODED FOR ONE FILE. A CFFILE names a byte range
 * inside the folder's decoded stream, and a deflate stream cannot be entered
 * part way - so reaching a file at offset N means producing the N bytes in
 * front of it. Those bytes are dropped rather than emitted: they belong to
 * other files, which arrive as their own children with their own names.
 *
 * The cost is one folder decode per file, which is what makes the module's cap
 * on files per folder a real bound rather than tidiness.
 */
static uint64_t unpack_mszip(struct kof_scanner *sc,
			     const struct kof_obj_ctx *ctx, uint32_t index,
			     uint64_t out_hint)
{
	struct kof_range *ext = sc->ext_gather;
	struct mszip_out snk;
	kof_buf b;
	uint32_t n, i;

	if (!ctx->resolve_entry || !oc_can_produce(sc))
		return 0;
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	if (!n)
		return 0;

	b = kof_src_buf(sc->cur_src);
	memset(&snk, 0, sizeof snk);
	snk.ctx = ctx;
	/*
	 * `out_hint` carries where the file starts inside the folder and how
	 * long it is - the two numbers a CFFILE has and a range cannot hold.
	 * Packed rather than added to the entry: the entry is the host's shape
	 * and this is one format's business. See KOF_UNP_MSZIP.
	 */
	snk.skip = out_hint >> 32;
	snk.left = out_hint & 0xffffffffu;
	if (!snk.left)
		return 0;

	snk.hist = malloc(KOF_INF_WINDOW);
	if (!snk.hist) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	scan_charge(sc, KOF_INF_WINDOW);

	if (!sc->inf) {
		sc->inf = malloc(sizeof *sc->inf);
		if (!sc->inf) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			free(snk.hist);
			oc_scan_release(sc, KOF_INF_WINDOW);
			return 0;
		}
	}

	for (i = 0; i < n && snk.left && !snk.stopped; i++) {
		uint64_t off = ext[i].off, len = kof_clip_len(b.n, off, ext[i].len);
		enum kof_decomp_status st;
		uint64_t got = 0;

		/* "CK", which every MSZIP block begins with. A block without it
		 * is not one, and decoding its first two bytes as deflate is
		 * how a wrong answer starts. */
		if (len < 2u || b.p[off] != 'C' || b.p[off + 1u] != 'K') {
			oc_scan_broken(sc, KOF_BROKEN_DAMAGED);
			break;
		}
		/*
		 * `got` is what the FOLDER decoded; what this call answers is
		 * what the FILE got, which is snk.emitted - the bytes in front
		 * of the file belong to other files and are dropped. The two
		 * were both accumulated and only the second was ever read.
		 */
		st = kof_inflate_seeded(sc->inf, snk.hist, snk.hist_len,
					b.p + off + 2u, len - 2u,
					mszip_sink_fn, &snk, NULL, &got);
		if (st != KOF_DEC_OK && st != KOF_DEC_STOPPED) {
			oc_scan_broken(sc, oc_broken_of_status(st));
			break;
		}
	}

	free(snk.hist);
	oc_scan_release(sc, KOF_INF_WINDOW);
	return snk.emitted;
}

/*
 * THE PIECES OF ONE ENTRY, JOINED INTO A BUFFER THE DECODERS CAN READ.
 *
 * Every decoder here takes contiguous input, and an entry's bytes are a chain
 * that is not consecutive 23.6% of the time, so the join is unavoidable. What
 * WAS avoidable is having it twice: unpack_lzx and oc_unpack_entry each carried
 * the same seven steps - total the clipped extents, refuse when the ceiling has
 * no room, allocate, charge, copy - and each had to get the clip right in two
 * separate places, once for the size and once for the copy.
 *
 * Answers the buffer, CHARGED to the residency account, with *total set to its
 * length; the caller frees it and releases *total. NULL means nothing to join,
 * or no room for it - the reason is already recorded either way.
 */
static uint8_t *entry_join(struct kof_scanner *sc, kof_buf b,
			   const struct kof_range *ext, uint32_t n,
			   uint64_t *total)
{
	uint64_t want = 0, at = 0;
	uint8_t *in;
	uint32_t i;

	*total = 0;
	for (i = 0; i < n; i++)
		want += kof_clip_len(b.n, ext[i].off, ext[i].len);
	if (!want)
		return NULL;
	if (want > oc_scan_room(sc)) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return NULL;
	}
	in = malloc((size_t)want);
	if (!in) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return NULL;
	}
	scan_charge(sc, want);
	for (i = 0; i < n; i++) {
		uint64_t len = kof_clip_len(b.n, ext[i].off, ext[i].len);

		if (!len)
			continue;
		memcpy(in + at, b.p + ext[i].off, (size_t)len);
		at += len;
	}
	*total = at;
	return in;
}

/*
 * LZX: ONE FILE OUT OF A STREAM THAT CANNOT BE ENTERED PART WAY.
 *
 * The first range resolve_entry hands back starts at a RESTART POINT - a
 * cabinet folder's first block, a help file's reset interval - because that is
 * the only place an LZX stream can be picked up: its trees are stated as
 * differences from the previous block's and its window is whatever the last
 * 32KB produced.
 *
 * So the file is reached by decoding from there and dropping what comes before,
 * which is what the two halves of `out_hint` say. The dropped bytes are other
 * files; they arrive as their own children with their own names.
 *
 * ONE DECODE PER RANGE, AND THE DECODER IS RESET BETWEEN THEM. A restart is not
 * a place in one stream, it is the start of another: everything the coding
 * carries between blocks begins again there. A file longer than the distance
 * between two restarts therefore arrives as several ranges - see chm.h - and
 * running them together is what a single decode would do. The skip applies to
 * the first range only, because that is the one the file begins in; what a
 * range produces comes off `take` and the rest carry on from where it stopped.
 */
static uint64_t unpack_lzx_reset(struct kof_scanner *sc,
				 const struct kof_obj_ctx *ctx, uint32_t index,
				 uint32_t window_bits, uint64_t out_hint)
{
	struct kof_range *ext = sc->ext_gather;
	struct expand_sink snk;
	enum kof_decomp_status st = KOF_DEC_OK;
	kof_buf b;
	uint64_t skip, take, got = 0;
	uint32_t n, i;

	if (!ctx->resolve_entry || !oc_can_produce(sc))
		return 0;
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	if (!n)
		return 0;

	b = kof_src_buf(sc->cur_src);
	skip = out_hint >> 32;
	take = out_hint & 0xffffffffu;
	if (!take)
		return 0;

	if (!sc->lzx) {
		sc->lzx = malloc(sizeof *sc->lzx);
		if (!sc->lzx) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
	}
	snk.ctx = ctx;
	/*
	 * THE RATIO IS THE FILE'S, SO THE INPUT IN IT IS ALL THE RANGES.
	 *
	 * One sink serves every range - `take` is the whole file's length and
	 * `left` is spent across all of them - so measuring the expansion
	 * against the FIRST range alone divides the input by however many
	 * reset intervals the file spans and multiplies the apparent ratio by
	 * the same number. A file over eight intervals reads as expanding
	 * eight times harder than it does, and an ordinary 5x one crosses a
	 * bound set at 32 and is cut to a megabyte for no reason the file
	 * gave.
	 *
	 * unpack_lzx, which is the same decode with the pieces joined instead
	 * of restarted, already sums them - see its expand_limit(total, take).
	 * These two answered differently about the same question.
	 */
	{
		uint64_t in_all = 0;

		for (i = 0; i < n; i++)
			in_all += kof_clip_len(b.n, ext[i].off, ext[i].len);
		snk.left = expand_limit(in_all, take);
	}

	for (i = 0; i < n && take; i++) {
		uint64_t off = ext[i].off;
		uint64_t len = kof_clip_len(b.n, off, ext[i].len);
		uint64_t part = 0;

		if (!len)
			break;
		st = kof_lzx_decode(sc->lzx, window_bits, b.p + off, len, skip,
				    take, expand_sink_fn, &snk, &part);
		got += part;
		/*
		 * Truncation is not an error, for the reason the DEFLATE path
		 * gives - and on every range but the last it is the ORDINARY
		 * end: the range holds one interval's bytes and the decoder
		 * asks for the next one's, which is not there because the next
		 * range is where they are. UNSUPPORTED is this decoder's way of
		 * saying the stream asked for x86 call translation, which it
		 * does not undo - the bytes are right everywhere except a few
		 * per frame, and saying so is better than either silence or a
		 * refusal.
		 */
		if (st != KOF_DEC_OK && st != KOF_DEC_TRUNCATED &&
		    st != KOF_DEC_STOPPED)
			break;
		if (st == KOF_DEC_STOPPED)
			break;         /* the receiver has had enough */
		if (!part)
			break;         /* no progress: another pass would not
					* make any either */
		take -= part;
		skip = 0;              /* only the first range holds the run-up */
	}

	stream_note(sc, st, STREAM_PARTIAL | STREAM_FILLED, &snk);
	return got;
}

/*
 * LZX WHERE THE PIECES ARE ONE STREAM, which is what a cabinet folder is.
 *
 * A folder is compressed end to end and then cut into CFDATA blocks, each with
 * a header in front of it. The coding knows nothing about that cut - it is not
 * a restart, the trees and the window carry straight across it - so the pieces
 * are joined back into the stream they were and decoded once. That is the whole
 * difference from unpack_lzx_reset, and getting it the wrong way round decodes
 * the first piece and produces refuse from the second.
 *
 * The join costs a copy of the folder's compressed bytes, charged to the
 * resident budget the same way the STORED join is. It is not avoidable: the
 * decoder takes a buffer, and the pieces are not adjacent in the object.
 */
static uint64_t unpack_lzx(struct kof_scanner *sc,
			   const struct kof_obj_ctx *ctx, uint32_t index,
			   uint32_t window_bits, uint64_t out_hint)
{
	struct kof_range *ext = sc->ext_gather;
	struct expand_sink snk;
	enum kof_decomp_status st;
	kof_buf b;
	uint8_t *in;
	uint64_t total = 0, skip, take, got = 0;
	uint32_t n;

	if (!ctx->resolve_entry || !oc_can_produce(sc))
		return 0;
	skip = out_hint >> 32;
	take = out_hint & 0xffffffffu;
	if (!take)
		return 0;
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	if (!n)
		return 0;

	b = kof_src_buf(sc->cur_src);
	if (!sc->lzx) {
		sc->lzx = malloc(sizeof *sc->lzx);
		if (!sc->lzx) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
	}
	in = entry_join(sc, b, ext, n, &total);
	if (!in)
		return 0;

	snk.ctx = ctx;
	snk.left = expand_limit(total, take);
	st = kof_lzx_decode(sc->lzx, window_bits, in, total, skip, take,
			    expand_sink_fn, &snk, &got);
	stream_note(sc, st, STREAM_PARTIAL | STREAM_FILLED, &snk);

	free(in);
	oc_scan_release(sc, total);
	return got;
}

uint64_t oc_unpack_entry(const struct kof_obj_ctx *ctx, uint32_t method,
			       uint32_t index, uint64_t out_hint)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_range *ext = sc->ext_gather;
	kof_buf b;
	uint8_t *in;
	uint64_t total = 0, produced = 0;
	uint32_t n;
	enum kof_decomp_status st;

	if (!oc_can_produce(sc))
		return 0;
	if (method == KOF_UNP_BCJ2)
		return unpack_bcj2(sc, ctx, index);
	if (!ctx->resolve_entry)
		return 0;
	/*
	 * STORED IS A JOIN AND NOT A DECODE, and it is handled below by
	 * skipping the decoder rather than by a path of its own: the ranges are
	 * gathered the same way, charged to the same budget, and emitted
	 * instead of being fed to a coding.
	 *
	 * It exists for the entry that is in several pieces for a reason that
	 * has nothing to do with compression - a cabinet's uncompressed folder
	 * is cut into blocks with a header between them, so every stored file
	 * over 32KB is scattered. Without this those files are the one thing a
	 * scan cannot reach in an archive it otherwise reads completely.
	 */
	if (method == KOF_UNP_MSZIP)
		return unpack_mszip(sc, ctx, index, out_hint);
	if (method > KOF_UNP_LZX_RESET_BASE &&
	    method <= KOF_UNP_LZX_RESET_BASE + KOF_LZX_MAX_BITS)
		return unpack_lzx_reset(sc, ctx, index,
					method -
						(uint32_t)KOF_UNP_LZX_RESET_BASE,
					out_hint);
	if (method > KOF_UNP_LZX_BASE &&
	    method <= KOF_UNP_LZX_BASE + KOF_LZX_MAX_BITS)
		return unpack_lzx(sc, ctx, index,
				  method - (uint32_t)KOF_UNP_LZX_BASE, out_hint);
	if (method != KOF_UNP_OVBA && method != KOF_UNP_STORED)
		return 0;              /* the only codings entries are decoded with */

	b = kof_src_buf(sc->cur_src);
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	in = entry_join(sc, b, ext, n, &total);
	if (!in)
		return 0;

	if (method == KOF_UNP_STORED) {
		/* The joined bytes ARE the object. */
		st = KOF_DEC_OK;
		produced = oc_emit_all(ctx, in, total);
	} else {
		struct sink_carry carry = { ctx };

		st = kof_ovba_decode(in, total, inflate_sink, &carry,
				     &produced);
	}
	if (st != KOF_DEC_OK)
		oc_scan_broken(sc, oc_broken_of_status(st));

	oc_scan_release(sc, total);
	free(in);
	return produced;
}


/* Whether a method's output can be bounded from its input, which is what an
 * INTERMEDIATE step of a chain needs: the buffer for it has to be sized before
 * the decode runs. DEFLATE cannot - that is the whole nature of it - so a Flate
 * anywhere but last has nowhere to put its output and the chain is refused. */
static int bounded_by_input(uint32_t method)
{
	return method == KOF_UNP_ASCII85 || method == KOF_UNP_ASCIIHEX ||
	       method == KOF_UNP_HEXTEXT;
}

/* The entry with this format index, or NULL. Linear because a table is tens of
 * rows and the alternative is an index the parser would have to keep sorted. */
static const struct kof_entry *entry_by_index(const struct kof_obj_ctx *ctx,
					      uint32_t index)
{
	const struct kof_entry *tab = NULL;
	uint32_t n, i;

	if (!ctx->entries)
		return NULL;
	n = ctx->entries(ctx, &tab);
	for (i = 0; tab && i < n; i++)
		if (tab[i].index == index)
			return &tab[i];
	return NULL;
}

/*
 * Run an entry's whole coding chain and hand back one child.
 *
 * THE SHAPE: every step but the last decodes into a buffer, and the last one
 * streams into the sink the way a single decode already does. That split is
 * not an optimisation, it is what makes the memory bounded - an intermediate
 * has to be addressable at once, so it must be a coding whose size is known
 * from its input, while the last step's output is charged to the produced
 * budget as it is written and never has to be held.
 */
uint64_t oc_unpack_chain(const struct kof_obj_ctx *ctx, uint32_t index)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_entry *e = entry_by_index(ctx, index);
	uint8_t *mid = NULL;
	/*
	 * `mid_cap` IS WHAT WAS ALLOCATED; `len` is how much of it is data.
	 *
	 * Two numbers because they differ - ASCII85 fills four fifths of the
	 * buffer it needs - and the budget must be told the ALLOCATION. Charging
	 * the decoded length instead under-charged the resident account by the
	 * difference, which is a budget the host is supposed to be enforcing.
	 */
	uint64_t off, len, mid_cap = 0, produced;
	uint32_t last, i;

	if (!e || !oc_can_produce(sc))
		return 0;
	/*
	 * A step this build cannot express means the chain cannot be run at
	 * all. Reported and not attempted: every step after a missed one
	 * decodes refuse, and handing that on as if it were the file is the one
	 * answer this engine must never give.
	 */
	if (e->flags & KOF_ENT_F_CODED_UNKNOWN) {
		oc_incomplete(ctx, KOF_BROKEN_UNSUPPORTED);
		return 0;
	}
	if (e->flags & KOF_ENT_F_SCATTERED)
		return 0;              /* resolve_entry's case, not this one */
	if (!e->coding[0] || !e->len)
		return 0;              /* stored: the caller windows it */

	for (last = 0; last + 1u < 4u && e->coding[last + 1u]; last++)
		;

	off = e->off;
	len = e->len;
	/*
	 * THE INTERMEDIATE IS CHARGED, SO EVERY WAY OUT HAS TO UNCHARGE IT.
	 *
	 * Three of the exits in this loop freed `mid` and left its charge
	 * standing. They are only reachable from the SECOND step onwards -
	 * on the first there is no intermediate yet - so it takes a chain of
	 * three codings to reach them, which is a shape a container declares
	 * freely and PDF writes in the wild. Each one leaks mid_cap bytes off
	 * the residency ceiling for the rest of the file's tree, and once the
	 * ceiling is gone every remaining entry of that file produces nothing
	 * and the file is reported as having hit a limit it never reached.
	 *
	 * The three correct exits below the loop already pair the two calls.
	 */
	for (i = 0; i < last; i++) {
		uint8_t *next;
		uint64_t got, room;

		if (!bounded_by_input(e->coding[i])) {
			oc_incomplete(ctx, KOF_BROKEN_UNSUPPORTED);
			free(mid);
			oc_scan_release(sc, mid_cap);
			return 0;
		}
		room = oc_scan_room(sc);
		if (len > room) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			free(mid);
			oc_scan_release(sc, mid_cap);
			return 0;
		}
		next = malloc((size_t)len);
		if (!next) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			free(mid);
			oc_scan_release(sc, mid_cap);
			return 0;
		}
		scan_charge(sc, len);

		/*
		 * From the previous intermediate when there is one, and from
		 * the object itself on the first step. `off` is zeroed below
		 * exactly so this stays one expression after that.
		 */
		{
			const uint8_t *p = mid;
			enum kof_decomp_status st;

			if (!p) {
				kof_buf b = kof_src_buf(sc->cur_src);

				p = b.p + off;
			}
			st = e->coding[i] == KOF_UNP_ASCII85
			   ? kof_a85_decode(p, len, next, len, &got)
			   : kof_ahx_decode(p, len, next, len, &got);
			/*
			 * A middle step that disagreed with its own declared
			 * coding stops the chain: the next step would decode
			 * whatever came out of a failure, and that is refuse
			 * presented as the file. Unlike the standalone path,
			 * partial output is NOT kept here - a half-decoded
			 * intermediate is not input for anything.
			 */
			if (st != KOF_DEC_OK)
				got = 0;
		}
		/* The old intermediate is finished with: released, and its
		 * ALLOCATION uncharged rather than its length. */
		free(mid);
		oc_scan_release(sc, mid_cap);
		mid = NULL;
		mid_cap = 0;
		if (!got) {
			free(next);
			oc_scan_release(sc, len);
			oc_incomplete(ctx, KOF_BROKEN_DAMAGED);
			return 0;
		}
		mid = next;
		mid_cap = len;         /* what malloc took, not what it holds */
		off = 0;
		len = got;
	}

	/*
	 * The last step, streamed. With an intermediate in hand it reads from
	 * that; with none it reads the object, which is the ordinary
	 * single-coding case and is why this also replaces a bare
	 * kof_unpack_at for a container that has entries.
	 */
	if (!mid)
		return oc_unpack(ctx, e->coding[last], off, len, e->out_hint);

	/*
	 * INFLATE ONLY, over an intermediate.
	 *
	 * oc_unpack reads the OBJECT, so it cannot be handed a buffer this
	 * function made - and rather than widen it to take either, the one
	 * chain that exists in the wild is served and anything else is
	 * refused out loud. PDF writes /ASCII85Decode in front of a Flate;
	 * a chain ending in something else, over an intermediate, has not
	 * turned up, and inventing a path for it would be code nothing
	 * exercises.
	 */
	if (e->coding[last] != KOF_UNP_ZLIB &&
	    e->coding[last] != KOF_UNP_DEFLATE) {
		oc_incomplete(ctx, KOF_BROKEN_UNSUPPORTED);
		free(mid);
		oc_scan_release(sc, mid_cap);
		return 0;
	}
	{
		struct expand_sink snk;
		enum kof_decomp_status st;
		const uint8_t *p = mid;
		uint64_t n = len;

		if (e->coding[last] == KOF_UNP_ZLIB) {
			uint64_t h = zlib_hdr_len(p, n);

			p += h;
			n -= h;
		}
		if (!sc->inf) {
			sc->inf = malloc(sizeof *sc->inf);
			if (!sc->inf) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				free(mid);
				oc_scan_release(sc, mid_cap);
				return 0;
			}
		}
		snk.ctx = ctx;
		snk.left = expand_limit(n, e->out_hint);
		produced = 0;
		st = kof_inflate(sc->inf, p, n, expand_sink_fn, &snk, NULL,
				 &produced);
		stream_note(sc, st, STREAM_STRICT, &snk);
	}
	free(mid);
	oc_scan_release(sc, mid_cap);
	return produced;
}


