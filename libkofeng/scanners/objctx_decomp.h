/*
 * objctx_decomp.h - what the decoder units of the module-facing context share.
 *
 * objctx_decomp.c was one file of two thousand lines that held the streaming
 * codings, the buffered ones, the text codings, the ciphers, the folder shaped
 * codings of a cabinet or a 7z, and the entry and chain runners. They are split
 * by WHAT KIND OF CODING THEY RUN, and what two of them need is here:
 *
 *   objctx_decomp.c         the sinks and the streaming dispatch (oc_unpack)
 *   objctx_decomp_buf.c     the codings whose whole output must be addressable
 *   objctx_decomp_text.c    hex, ASCII85, ASCIIHex, RunLength
 *   objctx_decomp_folder.c  BCJ2, MSZIP, LZX: one file out of a folder
 *   objctx_decomp_entry.c   a container entry, and its coding chain
 *   objctx_decrypt.c        a cipher a module named
 *
 * The `oc_` functions below are internal to that family, like those of
 * objctx_int.h, and nothing outside scanners/ includes this header. The small
 * pieces that are inline here were `static` in the one file and stay free of a
 * call for the same reason they were.
 */

#ifndef KOF_OBJCTX_DECOMP_H
#define KOF_OBJCTX_DECOMP_H

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

/*
 * What one decode is allowed to produce, given what the container declared.
 *
 * UINT64_MAX means "no opinion" - either nothing was declared, or what was declared
 * is within reason - and the caller then falls back to the object cap.
 */
static inline uint64_t expand_limit(uint64_t in_len, uint64_t declared)
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
static inline uint64_t zlib_hdr_len(const uint8_t *p, uint64_t n)
{
	uint32_t cmf, flg;

	if (n <= 2u)
		return 0;
	cmf = p[0];
	flg = p[1];
	return ((cmf & 0x0fu) == 8u && (cmf >> 4) <= 7u &&
		((cmf << 8) + flg) % 31u == 0u && !(flg & 0x20u)) ? 2u : 0u;
}

/* ---- the sinks and the streaming dispatch (objctx_decomp.c) ---- */
int oc_inflate_sink(void *user, const uint8_t *p, uint32_t n);
int oc_expand_sink_fn(void *user, const uint8_t *p, uint32_t n);
void oc_stream_note(struct kof_scanner *sc, enum kuncoat_status st,
		    uint32_t ordinary, const struct expand_sink *snk);

/* ---- the buffered codings (objctx_decomp_buf.c) ---- */
int oc_buffered_method(uint32_t method);
int oc_nrv2_of(uint32_t method, int *variant, int *bits);
/* One buffered decode asked for: the method (and the NRV2 `variant`/`bits` it
 * carries), the coded bytes, how large the container says the output is
 * (`out_hint`, 0 for no opinion), and - for a peek - the caller's buffer to
 * decode into instead of a scratch one. */
struct oc_buf_req {
	uint32_t method;
	int variant, bits;
	const uint8_t *in;
	uint64_t in_len, out_hint;
	uint8_t *peek_out;
	uint32_t peek_cap;
};
uint64_t oc_unpack_buffered(struct kof_scanner *sc,
			    const struct kof_obj_ctx *ctx,
			    const struct oc_buf_req *q);

/* ---- the text codings (objctx_decomp_text.c) ---- */
uint64_t oc_unpack_hextext(const struct kof_obj_ctx *ctx, kof_buf b,
			   uint64_t off, uint64_t len);
uint64_t oc_unpack_textcode(const struct kof_obj_ctx *ctx, uint32_t method,
			    kof_buf b, uint64_t off, uint64_t len);

/* ---- the folder shaped codings (objctx_decomp_folder.c) ---- */
uint64_t oc_unpack_bcj2(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
			uint32_t index);
uint64_t oc_unpack_mszip(struct kof_scanner *sc,
			 const struct kof_obj_ctx *ctx, uint32_t index,
			 uint64_t out_hint);
uint64_t oc_unpack_lzx_reset(struct kof_scanner *sc,
			     const struct kof_obj_ctx *ctx, uint32_t index,
			     uint32_t window_bits, uint64_t out_hint);
uint64_t oc_unpack_lzx(struct kof_scanner *sc, const struct kof_obj_ctx *ctx,
		       uint32_t index, uint32_t window_bits,
		       uint64_t out_hint);
uint8_t *oc_entry_join(struct kof_scanner *sc, kof_buf b,
		       const struct kof_range *ext, uint32_t n,
		       uint64_t *total);

#endif /* KOF_OBJCTX_DECOMP_H */
