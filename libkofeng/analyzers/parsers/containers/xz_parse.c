/*
 * xz_parse.c - walking xz streams from the end, one stream at a time.
 *
 * The order is forced by the format. A block header states its sizes only if it
 * feels like it - two flag bits say whether each is present, and the common
 * encoder writes neither - so a walk forward from the stream header reads the
 * first block header and then has no idea how far to step. The Index at the end
 * lists every block's size and is what makes them findable.
 *
 * So: the twelve byte footer gives the index, the index gives the blocks, and each
 * block header is then read in place for the one thing the index does not carry -
 * which filter chain codes it.
 *
 * AND A FILE IS A CONCATENATION OF STREAMS (what `xz -dc` decodes, in order), with
 * STREAM PADDING between them: zero bytes, a multiple of four (xz format 2.2). The
 * same backward step finds each: the stream's start is its index minus the bytes its
 * blocks occupy minus the twelve of its header, the zero words before that are padding,
 * and the footer of the stream before is what is left. It stops where a stream starts
 * at offset zero. A stream the walk cannot account for is SAID (BAD_FOOTER / NO_INDEX /
 * BAD_HEADER, which the module reads as a damaged object): it used to read only the last
 * stream, so `cat a.xz b.xz` opened b and nothing said a was never looked at.
 *
 * TWO PASSES, NO STORAGE: the first walks back counting the blocks (and so knows the file
 * order's totals); the second walks back again and writes each block straight into the slot
 * its position in the FILE gives it (blocks before this stream + its record number), so the
 * table is in file order with the earliest blocks kept when it fills, which a single pass
 * back from the end cannot do without a buffer of its own. Each pass is bounded by the
 * file's bytes: a stream is at least KOF_XZ_STREAM_MIN of them.
 */

#include <stddef.h>
#include <string.h>

#include "xz_parse.h"
#include "../../../kofcore/runlist.h"

static const uint8_t XZ_MAGIC[KOF_XZ_MAGIC_LEN] = {
	0xfd, '7', 'z', 'X', 'Z', 0x00
};

/* ---- reads -------------------------------------------------------------------- */

/*
 * A multibyte integer, xz's own encoding.
 *
 * Seven bits per byte, low first, the top bit meaning "another follows". Nine
 * bytes is the format's own maximum and the loop is held to it - without that a
 * run of 0x80 bytes walks the whole object one bit at a time.
 *
 * Deliberately NOT the same as the number encoding in 7z, which packs its length
 * into the first byte rather than into a continuation bit. Two containers, two
 * conventions, and reading one with the other yields plausible wrong numbers.
 */
static uint64_t xz_num(kof_buf f, uint64_t *at, int *ok)
{
	uint64_t v = 0;
	uint32_t i;

	*ok = 0;
	for (i = 0; i < 9u; i++) {
		uint8_t b = 0;

		if (!kof_rd_u8(f, *at, &b))
			return 0;
		(*at)++;
		v |= (uint64_t)(b & 0x7fu) << (7u * i);
		if (!(b & 0x80u)) {
			*ok = 1;
			return v;
		}
	}
	return 0;
}

/* Round up to the next multiple of four, saturating rather than wrapping. */
static uint64_t round4(uint64_t v)
{
	uint64_t r = v & 3u;

	return r ? kof_sat_add(v, 4u - r) : v;
}

/*
 * Where the stream's footer is, searching back from the end.
 *
 * Not simply the last twelve bytes, though that is where a lone stream puts it.
 * Three things get in the way and all three are ordinary: the format allows STREAM
 * PADDING of zero bytes after a stream, streams CONCATENATE so a file may hold
 * several, and an xz is routinely glued onto something else. Measured, one file in
 * this collection carries 430 stream headers and 2077 bytes of tail - reading its
 * last twelve bytes as a footer said the stream was broken, which was true of those
 * twelve bytes and false of the file.
 *
 * So the magic is searched for, backwards, at the four byte alignment every stream
 * keeps, within a bounded window. Same shape as the zip parser looking back for an
 * end-of-central-directory record, and bounded for the same reason: an unbounded
 * search is a scan of the whole object for two bytes that occur by chance.
 */
#define XZ_FOOTER_SEARCH (64u << 10)

static uint64_t find_footer(kof_buf f)
{
	uint64_t span = f.n < XZ_FOOTER_SEARCH ? f.n : XZ_FOOTER_SEARCH;
	uint64_t at;

	if (f.n < KOF_XZ_HEADER_LEN + KOF_XZ_FOOTER_LEN)
		return UINT64_MAX;

	/* The last position a footer could start at, aligned down to four. */
	at = (f.n - KOF_XZ_FOOTER_LEN) & ~(uint64_t)3u;
	while (at + KOF_XZ_FOOTER_LEN <= f.n &&
	       at + span >= f.n - KOF_XZ_FOOTER_LEN) {
		if (f.p[at + 10u] == 'Y' && f.p[at + 11u] == 'Z')
			return at;
		if (at < 4u)
			break;
		at -= 4u;
	}
	return UINT64_MAX;
}

/* ---- the walk's own state ----------------------------------------------------- */

struct xw {
	kof_buf f;
	struct kof_xz_info *x;
	struct kof_runs runs;
};

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t xz_cls_bit[KOF_XZ_CLS_COUNT] = {
	KOF_SCAN_XZ_HEADERS,
	KOF_SCAN_XZ_PACKED
};

KOF_RUNS_RESOLVER(xz, struct kof_xz_info, xz_cls_bit, KOF_SCAN_XZ_UNCLAIMED)

/* ---- the block header --------------------------------------------------------- */

/*
 * Read one block header for its filters.
 *
 * Everything else in it - the two optional sizes - is ignored on purpose: the
 * index already said what they are, and the two are allowed to disagree only in
 * a file built to make a reader choose wrong. Taking the index's answer for every
 * block means one source rather than two.
 */
static void block_header(struct xw *s, struct kof_xz_block *bl)
{
	uint64_t at = bl->hdr_off + 2u;
	uint8_t flags = 0;
	uint32_t i, n;
	int ok;

	if (!kof_rd_u8(s->f, bl->hdr_off + 1u, &flags))
		return;
	n = (uint32_t)(flags & 0x03u) + 1u;
	bl->n_filters = n;

	if (flags & 0x40u)
		xz_num(s->f, &at, &ok);         /* compressed size, unused */
	if (flags & 0x80u)
		xz_num(s->f, &at, &ok);         /* uncompressed size, unused */

	for (i = 0; i < n; i++) {
		uint64_t id, psize;

		id = xz_num(s->f, &at, &ok);
		if (!ok)
			return;
		psize = xz_num(s->f, &at, &ok);
		if (!ok || psize > bl->hdr_len)
			return;
		at = kof_sat_add(at, psize);
		/*
		 * Filters are listed in the order they were APPLIED, so the last is
		 * the compressor and anything before it is a transform over the
		 * bytes going in - which has to be undone after the decode.
		 */
		if (i + 1u == n)
			bl->filter = (uint32_t)id;
		else if (i == 0)
			bl->transform = (uint32_t)id;
	}

	if (n > 2u) {
		/* More than one transform is a chain this does not follow. */
		bl->suspicious |= KOF_XZ_BLK_CHAIN;
		s->x->anomalies |= KOF_XZ_ANOM_FILTER_CHAIN;
	}
	if (bl->filter != KOF_XZ_FILTER_LZMA2)
		s->x->anomalies |= KOF_XZ_ANOM_UNKNOWN_FILTER;
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_xz_sniff(kof_buf file)
{
	return kof_in_range(file, 0, KOF_XZ_MAGIC_LEN) &&
	       memcmp(file.p, XZ_MAGIC, KOF_XZ_MAGIC_LEN) == 0;
}

/*
 * ONE STREAM, read from its footer: the index it points at (every record read, not the
 * first KOF_XZ_MAX_BLOCKS), and from the sizes in it where the stream begins.
 *
 * A stream is at least a header, an index of no records (a type byte, a count, padding, a
 * CRC) and a footer: 32 bytes. Nothing here is computed from a count the file states: the
 * records are read until the index's own bytes end, so the work is the index's length.
 */
#define KOF_XZ_STREAM_MIN (KOF_XZ_HEADER_LEN + 8u + KOF_XZ_FOOTER_LEN)

struct xz_stream {
	uint64_t start;       /* the stream header */
	uint64_t foot;        /* the footer */
	uint64_t index_off, index_len;
	uint64_t n_rec;       /* the records the index holds, every one read */
	uint64_t rec_at;      /* where the first record is */
	uint32_t check;       /* the check id of the footer's flags */
};

/*
 * 1 when `foot` is the footer of a stream whose index holds together and whose start is
 * computed; 0 and `*anom` holds what was wrong with it. The stream header at the start is
 * NOT judged here: its absence is a bad header, which still has blocks to open.
 */
static int xz_stream_at(kof_buf f, uint64_t foot, struct xz_stream *st, uint64_t *anom)
{
	uint64_t idx, at, end, n, i, blocks = 0;
	uint8_t b = 0;
	int ok;

	memset(st, 0, sizeof *st);
	st->foot = foot;
	st->check = f.p[foot + 9u] & 0x0fu;
	idx = ((uint64_t)kof_rd32_or0(f, foot + 4u) + 1u) * 4u;
	if (idx > foot) {
		*anom |= KOF_XZ_ANOM_NO_INDEX;
		return 0;
	}
	st->index_off = foot - idx;
	st->index_len = idx;
	at = st->index_off;
	end = foot;
	if (!kof_rd_u8(f, at, &b) || b != 0x00u) {
		*anom |= KOF_XZ_ANOM_NO_INDEX;
		return 0;
	}
	at++;
	n = xz_num(f, &at, &ok);
	if (!ok) {
		*anom |= KOF_XZ_ANOM_NO_INDEX;
		return 0;
	}
	st->rec_at = at;
	/* The records run to the padding and the CRC that close the index: four bytes at the least. */
	for (i = 0; i < n; i++) {
		uint64_t unpadded = xz_num(f, &at, &ok), uncomp;

		if (!ok || at >= end) {
			*anom |= KOF_XZ_ANOM_NO_INDEX;
			return 0;
		}
		uncomp = xz_num(f, &at, &ok);
		if (!ok || at > end) {
			*anom |= KOF_XZ_ANOM_NO_INDEX;
			return 0;
		}
		(void)uncomp;
		blocks = kof_sat_add(blocks, round4(unpadded));
	}
	/* The index is exactly its records, padded to four, and a CRC: what the footer said it is. */
	if (round4(at - st->index_off) + 4u != idx) {
		*anom |= KOF_XZ_ANOM_NO_INDEX;
		return 0;
	}
	if (st->index_off < blocks || st->index_off - blocks < KOF_XZ_HEADER_LEN) {
		*anom |= KOF_XZ_ANOM_NO_INDEX;
		return 0;
	}
	st->start = st->index_off - blocks - KOF_XZ_HEADER_LEN;
	st->n_rec = n;
	return 1;
}

/* A stream's header agrees with its footer: the magic, and the same stream flags. */
static int xz_header_ok(kof_buf f, const struct xz_stream *st)
{
	return kof_in_range(f, st->start, KOF_XZ_HEADER_LEN) &&
	       memcmp(f.p + st->start, XZ_MAGIC, KOF_XZ_MAGIC_LEN) == 0 &&
	       f.p[st->start + 6u] == f.p[st->foot + 8u] &&
	       f.p[st->start + 7u] == f.p[st->foot + 9u];
}

/*
 * A LAST STREAM THAT THE FOUR BYTE ALIGNMENT HID. Every stream starts at a multiple of four
 * when the padding between them is a multiple of four (the format requires it), so find_footer
 * looks only there - and a file whose padding is 2 bytes, `A + 00 00 + B`, has B's footer
 * off the grid: the search landed on A's, opened A, read B as junk glued to the tail and said
 * nothing (`xz -dc` fails on it). So when the tail after the footer found has more in it than
 * zeros, the positions between are searched unaligned for a footer that proves itself: its CRC32
 * (bytes 0..3 over 4..9), then an index that holds together, and a stream header at the start
 * the index's sizes give. Anything that does not prove itself is junk, as before. At most
 * XZ_LATE_TRIES candidates are given the index parse, which is what a CRC32 an author can forge
 * costs the walk: a bound on the work and not on what is found.
 */
#define XZ_LATE_TRIES 16u

static uint64_t xz_late_footer(kof_buf f, uint64_t foot)
{
	uint64_t pos, tail, lo = foot + KOF_XZ_FOOTER_LEN, floor_at;
	uint32_t tries = 0;

	for (tail = lo; tail < f.n && f.p[tail] == 0; tail++)
		;
	if (tail >= f.n || f.n < KOF_XZ_FOOTER_LEN)
		return foot;
	/* within the same window find_footer keeps to, and never into the footer found */
	floor_at = f.n > XZ_FOOTER_SEARCH ? f.n - XZ_FOOTER_SEARCH : 0u;
	for (pos = f.n - KOF_XZ_FOOTER_LEN; pos + 1u > lo && pos >= floor_at; pos--) {
		struct xz_stream st;
		uint64_t anom = 0;

		if ((pos & 3u) == 0 || f.p[pos + 10u] != 'Y' || f.p[pos + 11u] != 'Z')
			continue;
		if (kof_crc32(f.p + pos + 4u, 6u) != kof_rd32_or0(f, pos))
			continue;
		if (++tries > XZ_LATE_TRIES)
			break;
		if (xz_stream_at(f, pos, &st, &anom) && xz_header_ok(f, &st))
			return pos;
	}
	return foot;
}

/*
 * The stream before the one starting at `start`, found backward: the zero words between
 * are stream padding, and what is left must end in a footer. 0 when it does not - the
 * bytes before this stream are not a stream - and `*anom` says BAD_FOOTER.
 */
static int xz_prev_foot(kof_buf f, uint64_t start, uint64_t *foot, uint64_t *anom)
{
	uint64_t p = start;

	while (p >= 4u && kof_rd32_or0(f, p - 4u) == 0u)
		p -= 4u;
	if (p < KOF_XZ_STREAM_MIN || (p & 3u) ||
	    f.p[p - 2u] != 'Y' || f.p[p - 1u] != 'Z') {
		*anom |= KOF_XZ_ANOM_BAD_FOOTER;
		return 0;
	}
	*foot = p - KOF_XZ_FOOTER_LEN;
	return 1;
}

/* ONE BLOCK of a stream, from its index record: where it is, what codes it, and what is wrong. */
static void xz_block(struct xw *s, const struct xz_stream *st, uint64_t block_at,
		     uint64_t unpadded, uint64_t uncomp, struct kof_xz_block *bl, uint64_t *anom)
{
	const uint32_t check_len = kof_xz_check_len(st->check);
	uint64_t hdr_len;
	uint8_t hs = 0;

	if (!kof_rd_u8(s->f, block_at, &hs) || hs == 0) {
		*anom |= KOF_XZ_ANOM_BAD_BLOCK;
		return;
	}
	hdr_len = ((uint64_t)hs + 1u) * 4u;
	if (unpadded <= hdr_len + check_len) {
		*anom |= KOF_XZ_ANOM_BAD_BLOCK;
		return;
	}
	memset(bl, 0, sizeof *bl);
	bl->hdr_off     = block_at;
	bl->hdr_len     = (uint32_t)hdr_len;
	bl->data_off    = block_at + hdr_len;
	bl->comp_size   = unpadded - hdr_len - check_len;
	bl->uncomp_size = uncomp;

	if (!kof_in_range(s->f, bl->hdr_off, hdr_len) ||
	    !kof_in_range(s->f, bl->data_off, bl->comp_size)) {
		bl->suspicious |= KOF_XZ_BLK_PAST_EOF;
		*anom |= KOF_XZ_ANOM_TRUNCATED;
		return;
	}
	if (bl->comp_size && bl->uncomp_size / bl->comp_size >= KOF_XZ_RATIO_ABSURD) {
		bl->suspicious |= KOF_XZ_BLK_RATIO;
		*anom |= KOF_XZ_ANOM_RATIO_ABSURD;
	}
	block_header(s, bl);
	kof_runs_add(&s->runs, s->f.n, bl->hdr_off, hdr_len, KOF_XZ_CLS_HEADERS);
	kof_runs_add(&s->runs, s->f.n, bl->data_off, bl->comp_size, KOF_XZ_CLS_PACKED);
	/* The check sits after the data and is structure, not content. */
	if (check_len)
		kof_runs_add(&s->runs, s->f.n, bl->data_off + bl->comp_size, check_len,
			     KOF_XZ_CLS_HEADERS);
}

/*
 * The records of ONE stream into the slots the file's order gives them. `base` is the number
 * of blocks in the streams before this one, so slot base + i is block i of the FILE; a slot
 * past the table is the table being full (the caller says so from the total) and ends the
 * stream. A record that is bad leaves its slot empty (hdr_len 0) and ends the stream: what
 * follows it cannot be placed. xz_parse compacts the table afterwards.
 */
static void xz_stream_blocks(struct xw *s, const struct xz_stream *st, uint64_t base)
{
	uint64_t at = st->rec_at, block_at = st->start + KOF_XZ_HEADER_LEN, i;
	int ok;

	for (i = 0; i < st->n_rec && base + i < KOF_XZ_MAX_BLOCKS; i++) {
		struct kof_xz_block *bl = &s->x->block[base + i];
		uint64_t unpadded = xz_num(s->f, &at, &ok), uncomp;

		if (!ok)
			return;
		uncomp = xz_num(s->f, &at, &ok);
		if (!ok)
			return;
		xz_block(s, st, block_at, unpadded, uncomp, bl, &s->x->anomalies);
		if (!bl->hdr_len || (bl->suspicious & KOF_XZ_BLK_PAST_EOF))
			return;
		s->x->total_comp = kof_sat_add(s->x->total_comp, bl->comp_size);
		s->x->total_uncomp = kof_sat_add(s->x->total_uncomp, bl->uncomp_size);
		block_at = kof_sat_add(block_at, round4(unpadded));
		if (block_at >= st->index_off)
			return;
	}
}

/*
 * The streams back from the last: calls `fn` for each, in that order, and answers how many
 * there were. The walk is the same for both passes, and every stream it accepts is one
 * whose index held together; where it stops short the anomaly says which way.
 */
static uint32_t xz_walk(struct xw *s, uint64_t foot, uint64_t *anom,
			void (*fn)(struct xw *, const struct xz_stream *, void *), void *arg)
{
	uint32_t n = 0;
	struct xz_stream st;

	for (;;) {
		if (!xz_stream_at(s->f, foot, &st, anom))
			return n;
		n++;
		if (fn)
			fn(s, &st, arg);
		if (st.start == 0)
			return n;
		if (!xz_prev_foot(s->f, st.start, &foot, anom))
			return n;
	}
}

struct xz_count {
	uint64_t total;       /* blocks in every stream the walk accepted */
	uint32_t streams;
};

static void xz_count_fn(struct xw *s, const struct xz_stream *st, void *arg)
{
	struct xz_count *c = arg;

	(void)s;
	c->total = kof_sat_add(c->total, st->n_rec);
	c->streams++;
}

struct xz_place {
	uint64_t after;       /* blocks in the streams later than the one in hand */
	uint64_t total;
	uint32_t left;        /* streams still to place: the second pass ends where the first did */
	int      first;       /* the stream in hand is the last of the file */
};

static void xz_place_fn(struct xw *s, const struct xz_stream *st, void *arg)
{
	struct xz_place *pl = arg;
	uint64_t base;

	/* The first pass's count of streams bounds this one: it must not take a stream the first
	 * did not accept (it cannot differ - the file does not change - but the count is the
	 * contract, so an extra step is refused rather than trusted). */
	if (!pl->left)
		return;
	pl->left--;
	if (pl->first) {
		/* The last stream is the one the info's index and footer fields describe. */
		s->x->index_off = st->index_off;
		s->x->index_len = st->index_len;
		pl->first = 0;
	}
	base = pl->total - pl->after - st->n_rec;
	pl->after += st->n_rec;
	if (!xz_header_ok(s->f, st))
		s->x->anomalies |= KOF_XZ_ANOM_BAD_HEADER;
	if (st->check != KOF_XZ_CHECK_NONE && st->check != KOF_XZ_CHECK_CRC32 &&
	    st->check != KOF_XZ_CHECK_CRC64 && st->check != KOF_XZ_CHECK_SHA256)
		s->x->anomalies |= KOF_XZ_ANOM_BAD_CHECK;
	kof_runs_add(&s->runs, s->f.n, st->start, KOF_XZ_HEADER_LEN, KOF_XZ_CLS_HEADERS);
	kof_runs_add(&s->runs, s->f.n, st->foot, KOF_XZ_FOOTER_LEN, KOF_XZ_CLS_HEADERS);
	kof_runs_add(&s->runs, s->f.n, st->index_off, st->index_len, KOF_XZ_CLS_HEADERS);
	xz_stream_blocks(s, st, base);
}

int kof_xz_parse(kof_buf file, struct kof_xz_info *x, struct kof_obj_ctx *ctx)
{
	struct xw s;
	struct xz_count cnt;
	struct xz_place pl;
	uint64_t foot, held;
	uint32_t i, k;
	uint8_t b = 0;

	/*
	 * THE HEADER ONLY, NOT THE 39008 BYTES OF ARRAYS BEHIND IT - the same
	 * change, for the same reason, as the one at the top of zip_parse.c.
	 *
	 * Smaller here than there, and worth it for the same reason: it is the
	 * per-object cost of every XZ scanned, and it buys nothing. Nothing
	 * reads past a count, every consumer loops on the count, and both
	 * counts are in the header that IS cleared - so a parse that gives up
	 * early reads as "nothing found" rather than as the last file's.
	 *
	 * THE ASSERT IS THE GUARD: the two arrays are the last two members and
	 * this clears everything before them. A field added after them would
	 * silently stop being cleared; adding one breaks the build instead.
	 */
	_Static_assert(offsetof(struct kof_xz_info, run) +
		       sizeof ((struct kof_xz_info *)0)->run +
		       sizeof ((struct kof_xz_info *)0)->block ==
		       sizeof(struct kof_xz_info),
		       "kof_xz_info gained a field after its arrays: the header-only "
		       "clear below would not reach it");
	memset(x, 0, offsetof(struct kof_xz_info, run));
	x->version = KOF_XZ_INFO_VERSION;

	if (!kof_xz_sniff(file))
		return 0;
	x->valid = 1;

	memset(&s, 0, sizeof s);
	memset(&cnt, 0, sizeof cnt);
	memset(&pl, 0, sizeof pl);
	s.f = file;
	s.x = x;
	kof_runs_init(&s.runs, x->run, KOF_XZ_MAX_EXTENTS,
		      KOF_XZ_CLS_COUNT);

	/* ---- the first stream's header: the check is read from it, as it always was ---- */
	if (!kof_in_range(file, 0, KOF_XZ_HEADER_LEN)) {
		x->anomalies |= KOF_XZ_ANOM_BAD_HEADER;
		goto done;
	}
	kof_rd_u8(file, 7, &b);
	x->check = b & 0x0fu;
	x->check_len = kof_xz_check_len(x->check);

	/* ---- the last footer, which is the only way in ---- */
	foot = find_footer(file);
	if (foot == UINT64_MAX) {
		x->anomalies |= KOF_XZ_ANOM_BAD_FOOTER;
		goto done;
	}
	foot = xz_late_footer(file, foot);
	x->footer_off = foot;
	/* Anything after the last footer is not part of any stream: padding, or a file that had
	 * one glued to its end. Worth knowing and no error. */
	if (foot + KOF_XZ_FOOTER_LEN < file.n)
		x->anomalies |= KOF_XZ_ANOM_MULTI_STREAM;

	/* ---- pass one: the streams back to the first, counting their blocks ---- */
	{
		uint64_t anom = 0;

		cnt.streams = xz_walk(&s, foot, &anom, xz_count_fn, &cnt);
		x->anomalies |= anom;
	}
	if (cnt.streams > 1u)
		x->anomalies |= KOF_XZ_ANOM_MULTI_STREAM;
	if (!cnt.streams)
		goto done;
	x->declared_blocks = (uint32_t)(cnt.total > 0xffffffffu ? 0xffffffffu : cnt.total);
	held = cnt.total < KOF_XZ_MAX_BLOCKS ? cnt.total : KOF_XZ_MAX_BLOCKS;
	memset(x->block, 0, (size_t)held * sizeof x->block[0]);

	/* ---- pass two: the same streams, each block into the slot its place in the file gives it ---- */
	pl.total = cnt.total;
	pl.left = cnt.streams;
	pl.first = 1;
	{
		uint64_t anom = 0;

		(void)xz_walk(&s, foot, &anom, xz_place_fn, &pl);
	}

	/* The table, compacted: a slot a bad record left empty has hdr_len 0. */
	for (i = 0, k = 0; i < held; i++)
		if (x->block[i].hdr_len) {
			if (k != i)
				x->block[k] = x->block[i];
			k++;
		}
	if (k < held)
		memset(&x->block[k], 0, (size_t)(held - k) * sizeof x->block[0]);
	x->n_blocks = k;

	if (x->n_blocks < x->declared_blocks)
		x->anomalies |= KOF_XZ_ANOM_BLOCKS_FULL;

done:
	/* After the settle: that is the pass that finds an overlap. */
	kof_runs_settle(&s.runs, x->region_bytes);
	if (s.runs.full)
		x->anomalies |= KOF_XZ_ANOM_EXTENTS_FULL;
	if (s.runs.overlapped)
		x->anomalies |= KOF_XZ_ANOM_OVERLAP;
	x->n_runs = s.runs.n;

	ctx->obj_size     = file.n;
	ctx->format       = KOF_FMT_XZ;
	ctx->file_header  = x;
	ctx->resolve_scan = xz_resolve_scan;
	return 1;
}

/* ---- names -------------------------------------------------------------------- */


#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_xz_region_bits[] = { XZ_REGIONS(X_BIT) };
_Static_assert(sizeof kof_xz_region_bits / sizeof kof_xz_region_bits[0] ==
	       KOF_XZ_REGION_COUNT, "region list and its count disagree");

const char *kof_xz_region_name(uint32_t bit)
{
	switch (bit) {
	XZ_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_xz_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_HEADER", "BAD_FOOTER", "NO_INDEX", "BAD_BLOCK", "TRUNCATED",
		"BLOCKS_FULL", "EXTENTS_FULL", "FILTER_CHAIN", "UNKNOWN_FILTER",
		"BAD_CHECK", "RATIO_ABSURD", "OVERLAP", "MULTI_STREAM"
	};


	_Static_assert(sizeof n / sizeof n[0] == KOF_XZ_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
