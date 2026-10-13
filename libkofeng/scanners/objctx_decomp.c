/*
 * objctx_decomp.c - the decoders a module asks the engine to run: the sinks
 * every one of them writes through, and the dispatch of the streaming codings.
 *
 * WHAT THIS SERVES: a container or packer module names a coding and a range;
 * the engine decodes it into the sink, charged to the memory ceiling and bounded
 * by the object's own size (never by what the stream claims). Everything here is
 * a bounded transform from bytes to bytes with a reported outcome: nothing in it
 * decides what the result is, and nothing in it is a verdict.
 *
 * The other codings are in the units next to it - see objctx_decomp.h.
 *
 * OPEN: the expansion clamp is applied to RAR3, RAR5 and LZMA2 and not to the
 * cabinet and VBA paths; the bound belongs to the sink, not to the coding.
 */

#define _GNU_SOURCE


#include "objctx_decomp.h"
#include <stdlib.h>

int oc_inflate_sink(void *user, const uint8_t *p, uint32_t n)
{
	const struct sink_carry *c = user;

	return oc_emit(c->ctx, p, n);
}

int oc_expand_sink_fn(void *user, const uint8_t *p, uint32_t n)
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
void oc_stream_note(struct kof_scanner *sc, enum kuncoat_status st,
			uint32_t ordinary, const struct expand_sink *snk)
{
	if (st != KUNCOAT_OK &&
	    !(st == KUNCOAT_TRUNCATED && (ordinary & STREAM_PARTIAL)) &&
	    !(st == KUNCOAT_STOPPED && (ordinary & STREAM_FILLED)))
		oc_scan_broken(sc, oc_broken_of_status(st));
	else if (snk->left == 0)
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
}

uint64_t oc_unpack(const struct kof_obj_ctx *ctx, uint32_t method,
			 uint64_t off, uint64_t len, uint64_t out_hint)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b;
	uint64_t produced = 0;
	int variant, bits;

	if (!sc->cur.src)
		return 0;
	b = kof_src_buf(sc->cur.src);
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
		if (!sc->cache.inf) {
			sc->cache.inf = malloc(sizeof *sc->cache.inf);
			if (!sc->cache.inf) {
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
			enum kuncoat_status st;

			struct kuncoat_io io = {
				.in = { b.p + off, len },
				.sink = oc_expand_sink_fn, .user = &e,
			};

			e.ctx = ctx;
			e.left = expand_limit(len, out_hint);
			st = kuncoat_inflate(sc->cache.inf, &io);
			produced = io.produced;
			oc_stream_note(sc, st, STREAM_STRICT, &e);
		}
		return produced;
	}

	if (method == KOF_UNP_HEXTEXT)
		return oc_unpack_hextext(ctx, b, off, len);
	if (method == KOF_UNP_ASCII85 || method == KOF_UNP_ASCIIHEX ||
	    method == KOF_UNP_RUNLENGTH)
		return oc_unpack_textcode(ctx, method, b, off, len);
	if (method == KOF_UNP_LZW) {
		struct expand_sink snk;
		enum kuncoat_status st;
		uint64_t got = 0;

		if (!sc->cache.lzw) {
			sc->cache.lzw = malloc(sizeof *sc->cache.lzw);
			if (!sc->cache.lzw) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
		}
		snk.ctx = ctx;
		snk.left = expand_limit(len, out_hint);
		st = kuncoat_lzw_decode(sc->cache.lzw, b.p + off, len, oc_expand_sink_fn,
				    &snk, &got);
		/*
		 * Truncation is not an error, for the reason the DEFLATE path
		 * gives: whatever decoded before the stream ran out is real
		 * output and is the part worth scanning.
		 */
		oc_stream_note(sc, st, STREAM_PARTIAL, &snk);
		return got;
	}

	if (method == KOF_UNP_BZIP2) {
		struct expand_sink snk;
		enum kuncoat_status st;
		uint64_t got = 0;

		if (!sc->cache.bz) {
			sc->cache.bz = malloc(sizeof *sc->cache.bz);
			if (!sc->cache.bz) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
		}
		snk.ctx = ctx;
		snk.left = expand_limit(len, out_hint);
		st = kuncoat_bunzip_decode(sc->cache.bz, b.p + off, len, oc_expand_sink_fn,
				       &snk, &got);
		/*
		 * Truncation is not an error, for the reason the DEFLATE path
		 * gives. A CHECKSUM MISMATCH IS - it is the one thing bzip2
		 * carries that says the bytes came back different from the ones
		 * that went in, and reporting that as a clean decode would hand
		 * a rule content the archive never held.
		 */
		oc_stream_note(sc, st, STREAM_PARTIAL, &snk);
		return got;
	}

	if (method >= KOF_UNP_LZHUF_ARJ && method <= KOF_UNP_LZHUF_LH7) {
		struct expand_sink snk;
		enum kuncoat_status st;
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
		if (!sc->cache.lzh) {
			sc->cache.lzh = malloc(sizeof *sc->cache.lzh);
			if (!sc->cache.lzh) {
				oc_scan_broken(sc, KOF_BROKEN_LIMIT);
				return 0;
			}
		}
		snk.ctx = ctx;
		snk.left = expand_limit(len, out_hint);
		st = kuncoat_lzhuf_decode(sc->cache.lzh,
				      (enum kuncoat_lzhuf_variant)
					      (method - KOF_UNP_LZHUF_ARJ),
				      b.p + off, len, out_hint,
				      oc_expand_sink_fn, &snk, &got);
		/* Truncation is not an error, for the reason the DEFLATE path
		 * gives - and here it is also what a declared size larger than
		 * the stream looks like, which is an archive's claim and not
		 * this engine's failure. */
		oc_stream_note(sc, st, STREAM_PARTIAL | STREAM_FILLED, &snk);
		return got;
	}

	if (!oc_buffered_method(method))
		return 0;              /* a method this engine does not have */
	if (!oc_nrv2_of(method, &variant, &bits))
		variant = bits = 0;
	{
		const struct oc_buf_req q = { method, variant, bits, b.p + off, len,
					      out_hint, NULL, 0 };

		return oc_unpack_buffered(sc, ctx, &q);
	}
}
