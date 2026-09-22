/*
 * gzip_parse.c - the gzip wrapper, RFC 1952.
 *
 * Ten fixed bytes, then up to three variable fields whose lengths the file states
 * or terminates, then the stream, then eight bytes of trailer. Small enough to
 * hold in the head, which is worth saying because it is the reason the parse is
 * written as a cursor walked forward with every step bounded: there is no second
 * description to cross-check against, so the only defence is that no field is read
 * before the object is known to contain it.
 *
 * Two things here are not obvious from the specification:
 *
 *   - THE STREAM'S LENGTH IS NOT IN THE FILE. gzip has no compressed-size field;
 *     the stream ends where DEFLATE says it ends, which is only knowable by
 *     decoding it. So data_len is an upper bound - everything between the header
 *     and the last eight bytes - and it is used as a bound, never as a fact. The
 *     decoder stops on its own end-of-stream marker well before it.
 *
 *   - THE TRAILER IS AT THE END OF THE MEMBER, NOT THE END OF THE FILE. Members
 *     may be concatenated, and things get appended to gzips. Taking the last eight
 *     bytes as the trailer is therefore a guess, and it is right for the ordinary
 *     single-member file and wrong for the rest. It is recorded as a guess: what
 *     is past the trailer is UNCLAIMED rather than assumed to be nothing, so the
 *     bytes of a second member are still scanned as part of the object.
 */

#include "gzip_parse.h"
#include "../rangelist.h"

#include <string.h>

#define GZIP_FIXED_HDR 10u   /* ID1 ID2 CM FLG MTIME XFL OS */
#define GZIP_TRAILER   8u    /* CRC32 ISIZE */

int kof_gzip_sniff(kof_buf file)
{
	uint8_t id1, id2, cm;

	if (!kof_rd_u8(file, 0, &id1) || !kof_rd_u8(file, 1, &id2) ||
	    !kof_rd_u8(file, 2, &cm))
		return 0;
	return id1 == 0x1f && id2 == 0x8b && cm == KOF_GZIP_DEFLATE;
}

/*
 * Walk a NUL terminated field.
 *
 * Returns the length without the terminator and advances *at past it, or returns
 * KOF_BROKEN when the object ends first - which is the case that matters, because
 * an unterminated name is how a reader that trusts the terminator is walked off
 * the end of the buffer. Bounded by the object, never by a terminator.
 */
#define GZ_NO_END UINT64_MAX

static uint64_t zstring_len(kof_buf f, uint64_t *at)
{
	uint64_t start = *at, i;

	for (i = start; i < f.n; i++) {
		if (f.p[i] == 0) {
			*at = i + 1;
			return i - start;
		}
	}
	*at = f.n;
	return GZ_NO_END;
}

/* ---- regions ----------------------------------------------------------------- */

static uint32_t gzip_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				  struct kof_range *out, uint32_t max_out)
{
	const struct kof_gzip_info *g = (const struct kof_gzip_info *)ctx->file_header;
	struct kof_rlist l;

	if (!g || !g->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);

	/*
	 * The header, minus the name that sits inside it.
	 *
	 * Two extents when a name is present and one when it is not, which is what
	 * keeps HEADER and NAME disjoint. Written as the pieces on either side of
	 * the name rather than as "the header, and also the name": a byte in two
	 * regions is scanned twice and breaks the partition every other region
	 * mask relies on.
	 */
	if (mask & KOF_SCAN_GZIP_HEADER) {
		if (g->name_len || (g->flags & KOF_GZIP_FNAME)) {
			kof_rl_add(&l, ctx->obj_size, 0, g->name_off);
			kof_rl_add(&l, ctx->obj_size, g->name_off + g->name_len,
				   g->data_off - (g->name_off + g->name_len));
		} else {
			kof_rl_add(&l, ctx->obj_size, 0, g->data_off);
		}
	}
	if (mask & KOF_SCAN_GZIP_NAME)
		kof_rl_add(&l, ctx->obj_size, g->name_off, g->name_len);
	if (mask & KOF_SCAN_GZIP_DATA)
		kof_rl_add(&l, ctx->obj_size, g->data_off, g->data_len);
	if (mask & KOF_SCAN_GZIP_TRAILER)
		kof_rl_add(&l, ctx->obj_size, g->trailer_off,
			   g->trailer_off ? GZIP_TRAILER : 0);

	if (mask & KOF_SCAN_GZIP_UNCLAIMED) {
		/* The complement, obtained by asking for everything else - see the
		 * note in pe_parse.c on why the claimants are not listed twice. */
		struct kof_range cv[8];
		struct kof_rlist c;

		kof_rl_init(&c, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		c.n = gzip_resolve_scan(ctx, KOF_SCAN_GZIP_CLAIMED, cv, c.cap);
		kof_rl_complement(&l, &c, ctx->obj_size);
	}
	return kof_rl_normalise(&l);
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_gzip_parse(kof_buf file, struct kof_gzip_info *g, struct kof_obj_ctx *ctx)
{
	uint64_t at = GZIP_FIXED_HDR, end;
	uint8_t cm, flg, xfl, os;
	uint32_t mtime;

	memset(g, 0, sizeof *g);
	g->version = KOF_GZIP_INFO_VERSION;

	/*
	 * THE MAGIC, CHECKED HERE - NOT THE SNIFF, WHICH ALSO CHECKS THE METHOD.
	 *
	 * Calling kof_gzip_sniff cost this collector a bit it declares. The sniff
	 * requires CM to be 8, so by the time the method test below ran, cm was
	 * provably 8 and KOF_GZIP_ANOM_BAD_METHOD could not be set from any call
	 * path at all - a declared anomaly no input could reach.
	 *
	 * The other collectors do not delegate: kof_pe_parse tests the MZ itself
	 * and raises BAD_MZ, kof_elf_parse tests its own magic. A collector
	 * answering a caller that did not sniff first has to say WHY, and "the
	 * recogniser said no" is not a reason it can pass on.
	 *
	 * The engine sniffs before it parses, so nothing it does changes: a file
	 * whose CM is not 8 is still not classified as gzip. What changes is that
	 * a caller who parses one anyway is told which field is wrong.
	 */
	{
		uint8_t id1, id2;

		if (!kof_rd_u8(file, 0, &id1) || !kof_rd_u8(file, 1, &id2) ||
		    id1 != 0x1f || id2 != 0x8b)
			return 0;
	}
	/* The fixed header has to be there in full before any of it is believed:
	 * a three byte file can pass the sniff. */
	if (!kof_rd_u8(file, 2, &cm)  || !kof_rd_u8(file, 3, &flg) ||
	    !kof_rd_u32(file, 4, 0, &mtime) ||
	    !kof_rd_u8(file, 8, &xfl) || !kof_rd_u8(file, 9, &os))
		return 0;

	g->valid  = 1;
	g->method = cm;
	g->flags  = flg;
	g->xfl    = xfl;
	g->os     = os;
	g->mtime  = mtime;

	if (cm != KOF_GZIP_DEFLATE)
		g->anomalies |= KOF_GZIP_ANOM_BAD_METHOD;
	/* Bits 5 to 7 are reserved and RFC 1952 says a reader must not try to
	 * decompress when one is set. Recorded rather than obeyed: what a file with
	 * a reserved bit set is, is a file worth scanning. */
	if (flg & 0xe0u)
		g->anomalies |= KOF_GZIP_ANOM_RESERVED_FLAGS;

	if (flg & KOF_GZIP_FEXTRA) {
		uint16_t xlen;

		if (!kof_rd_u16(file, at, 0, &xlen)) {
			g->anomalies |= KOF_GZIP_ANOM_TRUNCATED_HEADER;
			at = file.n;
		} else {
			at += 2;
			g->extra_off = at;
			/* Clipped, not trusted: XLEN is two bytes the file chose
			 * and may name more than the object holds. */
			g->extra_len = kof_clip_len(file.n, at, xlen);
			if (g->extra_len != xlen)
				g->anomalies |= KOF_GZIP_ANOM_TRUNCATED_HEADER;
			at += g->extra_len;
		}
	}
	if (flg & KOF_GZIP_FNAME) {
		uint64_t n;

		g->name_off = at;
		n = zstring_len(file, &at);
		if (n == GZ_NO_END) {
			g->anomalies |= KOF_GZIP_ANOM_NAME_UNTERMINATED;
			g->name_len = file.n - g->name_off;
		} else {
			g->name_len = n;
		}
	}
	if (flg & KOF_GZIP_FCOMMENT) {
		uint64_t n;

		g->comment_off = at;
		n = zstring_len(file, &at);
		if (n == GZ_NO_END) {
			g->anomalies |= KOF_GZIP_ANOM_COMMENT_UNTERM;
			g->comment_len = file.n - g->comment_off;
		} else {
			g->comment_len = n;
		}
	}
	if (flg & KOF_GZIP_FHCRC) {
		if (at + 2 > file.n) {
			g->anomalies |= KOF_GZIP_ANOM_TRUNCATED_HEADER;
			at = file.n;
		} else {
			at += 2;
		}
	}

	g->data_off = at;

	/*
	 * The trailer, if the object is long enough to have one past the header.
	 *
	 * "Past the header" and not merely "eight bytes long": a header that ran to
	 * the end of the object leaves no room for a stream OR a trailer, and
	 * taking the last eight bytes anyway would put the trailer inside the
	 * header and hand two regions the same bytes.
	 */
	if (file.n >= at + GZIP_TRAILER) {
		g->trailer_off = file.n - GZIP_TRAILER;
		kof_rd_u32(file, g->trailer_off, 0, &g->crc32);
		kof_rd_u32(file, g->trailer_off + 4, 0, &g->isize);
		end = g->trailer_off;
	} else {
		g->anomalies |= KOF_GZIP_ANOM_NO_TRAILER;
		end = file.n;
	}

	g->data_len = end > at ? end - at : 0;
	if (g->data_len == 0)
		g->anomalies |= KOF_GZIP_ANOM_EMPTY_STREAM;

	/*
	 * What the file admits about how much it expands.
	 *
	 * Against the compressed stream, not against the object: a large name or a
	 * large FEXTRA would otherwise make an ordinary file look modest. ISIZE is
	 * modulo 2^32 and is written by whoever built the file, so this can be
	 * evaded by simply declaring something else - it catches what a bomb admits
	 * to, which is a heuristic with a use and not a defence with a hole. The
	 * defence is the host's budget, which never reads this field.
	 */
	if (g->data_len && g->isize / g->data_len >= KOF_GZIP_RATIO_ABSURD)
		g->anomalies |= KOF_GZIP_ANOM_RATIO_ABSURD;

	ctx->format = KOF_FMT_GZIP;
	ctx->obj_size = file.n;
	ctx->file_header = g;
	ctx->resolve_scan = gzip_resolve_scan;
	/* No architecture and no entry point: a container is not code, and leaving
	 * them as the caller set them is what lets arch-targeted modules be ruled
	 * out rather than matched by accident. */
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */


#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_gzip_region_bits[] = { GZIP_REGIONS(X_BIT) };
_Static_assert(sizeof kof_gzip_region_bits / sizeof kof_gzip_region_bits[0] ==
	       KOF_GZIP_REGION_COUNT, "region list and its count disagree");

const char *kof_gzip_region_name(uint32_t bit)
{
	switch (bit) {
	GZIP_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_gzip_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_METHOD", "RESERVED_FLAGS", "TRUNCATED_HEADER",
		"NAME_UNTERMINATED", "COMMENT_UNTERMINATED", "NO_TRAILER",
		"EMPTY_STREAM", "RATIO_ABSURD"
	};


	_Static_assert(sizeof n / sizeof n[0] == KOF_GZIP_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
