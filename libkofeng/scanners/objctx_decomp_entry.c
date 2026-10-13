/*
 * objctx_decomp_entry.c - a container entry decoded, and an entry's coding
 * chain run to one child.
 *
 * WHAT THIS SERVES: the two calls a container module makes when what it wants
 * is an entry of its own table rather than a byte range: the entry whose
 * pieces are joined and decoded, and the entry whose coding is a chain. The
 * codings themselves are in the units next to it - see objctx_decomp.h.
 */


#include "objctx_decomp.h"
#include <stdlib.h>

/*
 * Join one entry's chain and decode it, in that order.
 *
 * The joining has to happen first and into a buffer of its own, because every
 * decoder here reads a contiguous input - and an entry's bytes are a chain that is
 * not consecutive 23.6% of the time. The buffer is charged against the residency
 * ceiling while it is alive, on the same account as a decoder's output, so a
 * document full of large streams cannot walk past the limit one stream at a time.
 */
uint64_t oc_unpack_entry(const struct kof_obj_ctx *ctx, uint32_t method,
			       uint32_t index, uint64_t out_hint)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_range *ext = sc->cache.ext_gather;
	kof_buf b;
	uint8_t *in;
	uint64_t total = 0, produced = 0;
	uint32_t n;
	enum kuncoat_status st;

	if (!oc_can_produce(sc))
		return 0;
	if (method == KOF_UNP_BCJ2)
		return oc_unpack_bcj2(sc, ctx, index);
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
		return oc_unpack_mszip(sc, ctx, index, out_hint);
	if (method > KOF_UNP_LZX_RESET_BASE &&
	    method <= KOF_UNP_LZX_RESET_BASE + KUNCOAT_LZX_MAX_BITS)
		return oc_unpack_lzx_reset(sc, ctx, index,
					method -
						(uint32_t)KOF_UNP_LZX_RESET_BASE,
					out_hint);
	if (method > KOF_UNP_LZX_BASE &&
	    method <= KOF_UNP_LZX_BASE + KUNCOAT_LZX_MAX_BITS)
		return oc_unpack_lzx(sc, ctx, index,
				  method - (uint32_t)KOF_UNP_LZX_BASE, out_hint);
	if (method != KOF_UNP_OVBA && method != KOF_UNP_STORED)
		return 0;              /* the only codings entries are decoded with */

	b = kof_src_buf(sc->cur.src);
	n = ctx->resolve_entry(ctx, index, ext, KOF_SCAN_MAX_EXTENTS);
	in = oc_entry_join(sc, b, ext, n, &total);
	if (!in)
		return 0;

	if (method == KOF_UNP_STORED) {
		/* The joined bytes ARE the object. */
		st = KUNCOAT_OK;
		produced = oc_emit_all(ctx, in, total);
	} else {
		struct sink_carry carry = { ctx };

		st = kuncoat_ovba_decode(in, total, oc_inflate_sink, &carry,
				     &produced);
	}
	if (st != KUNCOAT_OK)
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
			enum kuncoat_status st;

			if (!p) {
				kof_buf b = kof_src_buf(sc->cur.src);

				p = b.p + off;
			}
			st = e->coding[i] == KOF_UNP_ASCII85
			   ? kuncoat_a85_decode(p, len, next, len, &got)
			   : kuncoat_ahx_decode(p, len, next, len, &got);
			/*
			 * A middle step that disagreed with its own declared
			 * coding stops the chain: the next step would decode
			 * whatever came out of a failure, and that is refuse
			 * presented as the file. Unlike the standalone path,
			 * partial output is NOT kept here - a half-decoded
			 * intermediate is not input for anything.
			 */
			if (st != KUNCOAT_OK)
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
		enum kuncoat_status st;
		const uint8_t *p = mid;
		uint64_t n = len;

		if (e->coding[last] == KOF_UNP_ZLIB) {
			uint64_t h = zlib_hdr_len(p, n);

			p += h;
			n -= h;
		}
		if (!sc->cache.inf) {
			sc->cache.inf = malloc(sizeof *sc->cache.inf);
			if (!sc->cache.inf) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				free(mid);
				oc_scan_release(sc, mid_cap);
				return 0;
			}
		}
		snk.ctx = ctx;
		snk.left = expand_limit(n, e->out_hint);
		{
			struct kuncoat_io io = {
				.in = { p, n }, .sink = oc_expand_sink_fn, .user = &snk,
			};

			st = kuncoat_inflate(sc->cache.inf, &io);
			produced = io.produced;
		}
		oc_stream_note(sc, st, STREAM_STRICT, &snk);
	}
	free(mid);
	oc_scan_release(sc, mid_cap);
	return produced;
}
