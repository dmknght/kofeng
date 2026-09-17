/*
 * bzip2.c - the decoder described in bzip2.h.
 *
 * Written from the format rather than from a library: the stages are the ones
 * every bzip2 implementation has, in the order the header lists them, and the
 * table construction is the canonical Huffman one the specification spells out.
 *
 * WHAT THE DEFENSIVE CHECKS ARE FOR. This decodes archives chosen by whoever is
 * being scanned, so every count that comes out of the stream is bounded before
 * it is used: the number of selectors, the group a selector names, the code
 * length a table declares, the block position a run writes to, and the row the
 * inverse transform starts on. None of them is a "cannot happen" - they are the
 * fields a crafted stream would set, and each one is the difference between a
 * corrupt file reported as corrupt and an index off the end of an array.
 */

#include <string.h>

#include "bzip2.h"

#define BZ_BLOCK_MAGIC_HI 0x314159u   /* 0x314159265359, the 48 bits of pi */
#define BZ_BLOCK_MAGIC_LO 0x265359u
#define BZ_END_MAGIC_HI   0x177245u   /* 0x177245385090, sqrt(pi) */
#define BZ_END_MAGIC_LO   0x385090u

#define BZ_RUNA 0u
#define BZ_RUNB 1u

/* ---- the bit reader ---------------------------------------------------------
 *
 * MOST SIGNIFICANT BIT FIRST, which is the opposite of DEFLATE and is the whole
 * reason this cannot borrow inflate's reader. Everything after the four byte
 * stream header is a bit stream with no alignment of any kind: a block header
 * can start mid-byte, and only the start of a CONCATENATED STREAM is aligned.
 */
struct bz_br {
	const uint8_t *p;
	uint64_t       n, pos;
	uint32_t       buf, cnt;
	int            eof;        /* the input ran out mid-symbol */
};

/* Up to 24 bits at a time, which is every field the format has bar the two
 * magics and the checksums - those are read as two of these. The buffer holds
 * at most 31 bits, so a 24 bit request can always be filled without losing any,
 * and 24 is why the mask below cannot be asked to shift by the word width. */
static uint32_t bz_bits(struct bz_br *br, uint32_t k)
{
	uint32_t v;

	while (br->cnt < k) {
		if (br->pos >= br->n) {
			br->eof = 1;
			return 0;
		}
		br->buf = (br->buf << 8) | br->p[br->pos++];
		br->cnt += 8u;
	}
	v = (br->buf >> (br->cnt - k)) & ((1u << k) - 1u);
	br->cnt -= k;
	return v;
}

static uint32_t bz_bit(struct bz_br *br)
{
	return bz_bits(br, 1u);
}

static uint32_t bz_bits32(struct bz_br *br)
{
	uint32_t hi = bz_bits(br, 16u);

	return (hi << 16) | bz_bits(br, 16u);
}

/* Where the next byte boundary is - the one place alignment matters, because a
 * second stream concatenated onto the first starts on one. */
static void bz_align(struct bz_br *br)
{
	br->cnt -= br->cnt % 8u;
}

static uint64_t bz_byte_pos(const struct bz_br *br)
{
	return br->pos - (br->cnt / 8u);
}

/* ---- the checksum -----------------------------------------------------------
 *
 * CRC-32/BZIP2: the same polynomial as zip's and NOT the same function - this
 * one is most significant bit first with no reflection at either end, so the
 * engine's own crc32 would answer a different number for the same bytes.
 *
 * A BIT AT A TIME AND NO TABLE. A table is eight times faster and costs a
 * kilobyte that has to be built before first use, which on a scanner that runs
 * workers means either a race or a guard on every call. The decode stages above
 * this dominate the time by a wide margin, so the table would buy a few percent
 * of a function that is not the cost - and a lazily built shared table is
 * exactly the kind of thing that is right until the day it is threaded.
 */
static uint32_t bz_crc(uint32_t crc, const uint8_t *p, uint32_t n)
{
	uint32_t i, k;

	for (i = 0; i < n; i++) {
		crc ^= (uint32_t)p[i] << 24;
		for (k = 0; k < 8u; k++)
			crc = (crc & 0x80000000u) ? (crc << 1) ^ 0x04c11db7u
						  : (crc << 1);
	}
	return crc;
}

/* ---- output -----------------------------------------------------------------
 *
 * Buffered, because the sink is a call and the RLE stage produces one byte at a
 * time. `stopped` is not an error: the receiver said it has enough.
 */
struct bz_out {
	kof_bunzip_sink sink;
	void           *user;
	struct kof_bunzip *st;
	uint32_t        n;         /* bytes waiting in st->out */
	uint64_t        total;
	uint32_t        crc;       /* of the current block, as produced */
	int             stopped;
};

static int bz_flush(struct bz_out *o)
{
	if (!o->n)
		return 1;
	o->crc = bz_crc(o->crc, o->st->out, o->n);
	o->total += o->n;
	if (!o->sink(o->user, o->st->out, o->n)) {
		o->n = 0;
		o->stopped = 1;
		return 0;
	}
	o->n = 0;
	return 1;
}

static int bz_put(struct bz_out *o, uint8_t b)
{
	o->st->out[o->n++] = b;
	if (o->n == sizeof o->st->out)
		return bz_flush(o);
	return 1;
}

/* ---- the Huffman tables -----------------------------------------------------
 *
 * The canonical form the specification describes: `limit[l]` is the largest
 * code of length l, `base[l]` turns a code of that length into an index, and
 * `perm` maps the index to a symbol. Decoding is then "read minLen bits, and
 * one more until the value fits inside a limit".
 *
 * Returns zero when the lengths cannot form a code - which is a fact about the
 * stream, not about this build.
 */
static int bz_tables(struct kof_bunzip *st, uint32_t g, uint32_t alpha_size)
{
	int32_t  *limit = st->limit[g], *base = st->base[g], *perm = st->perm[g];
	const uint8_t *len = st->len[g];
	uint32_t min = KOF_BZ_MAX_CODELEN, max = 0, i, j, pp;
	int32_t  vec;

	for (i = 0; i < alpha_size; i++) {
		if (len[i] < min)
			min = len[i];
		if (len[i] > max)
			max = len[i];
	}
	if (min < 1u || max > KOF_BZ_MAX_CODELEN)
		return 0;

	pp = 0;
	for (i = min; i <= max; i++)
		for (j = 0; j < alpha_size; j++)
			if (len[j] == i)
				perm[pp++] = (int32_t)j;

	for (i = 0; i < KOF_BZ_MAX_CODELEN + 2u; i++)
		base[i] = limit[i] = 0;
	for (i = 0; i < alpha_size; i++)
		base[len[i] + 1u]++;
	for (i = 1; i < KOF_BZ_MAX_CODELEN + 2u; i++)
		base[i] += base[i - 1u];

	vec = 0;
	for (i = min; i <= max; i++) {
		vec += base[i + 1u] - base[i];
		limit[i] = vec - 1;
		vec <<= 1;
	}
	for (i = min + 1u; i <= max; i++)
		base[i] = ((limit[i - 1u] + 1) << 1) - base[i];

	st->minlen[g] = (uint8_t)min;
	return 1;
}

/* One symbol from group `g`. Sets `*bad` when the code walks past the longest
 * length the format allows or names a symbol outside the alphabet. */
static uint32_t bz_sym(struct kof_bunzip *st, struct bz_br *br, uint32_t g,
		       uint32_t alpha_size, int *bad)
{
	uint32_t zn = st->minlen[g];
	int32_t  zvec = (int32_t)bz_bits(br, zn), idx;

	while (zn <= KOF_BZ_MAX_CODELEN && zvec > st->limit[g][zn]) {
		zn++;
		zvec = (zvec << 1) | (int32_t)bz_bit(br);
	}
	if (zn > KOF_BZ_MAX_CODELEN) {
		*bad = 1;
		return 0;
	}
	idx = zvec - st->base[g][zn];
	if (idx < 0 || (uint32_t)idx >= alpha_size) {
		*bad = 1;
		return 0;
	}
	return (uint32_t)st->perm[g][idx];
}

/* ---- one block --------------------------------------------------------------
 *
 * The magic has already been read. Everything else about the block is here,
 * including handing its bytes to the sink: a block is the unit the format
 * checksums, so it is the unit this verifies.
 */
static enum kof_decomp_status bz_block(struct kof_bunzip *st, struct bz_br *br,
				       struct bz_out *out, uint32_t block_max,
				       uint32_t *combined)
{
	uint32_t crc_want, orig_ptr, used16, n_in_use = 0, alpha_size;
	uint32_t groups, selectors, i, j, g, sym, nblock = 0;
	uint32_t group_no = 0, group_pos = 0, sel = 0, t_pos;
	uint32_t es = 0, run = 0;
	int      bad = 0;
	uint8_t  pos[KOF_BZ_GROUPS];
	int      rle_run = 0, rle_prev = -1;

	crc_want = bz_bits32(br);
	if (bz_bit(br))
		return KOF_DEC_UNSUPPORTED;     /* randomised - see bzip2.h */
	orig_ptr = bz_bits(br, 24u);

	/* Which byte values the block uses, as sixteen groups of sixteen. */
	used16 = bz_bits(br, 16u);
	for (i = 0; i < 16u; i++) {
		uint32_t u;

		if (!(used16 & (0x8000u >> i)))
			continue;
		u = bz_bits(br, 16u);
		for (j = 0; j < 16u; j++)
			if (u & (0x8000u >> j))
				st->seq_to_unseq[n_in_use++] =
					(uint8_t)(i * 16u + j);
	}
	if (br->eof)
		return KOF_DEC_TRUNCATED;
	if (!n_in_use)
		return KOF_DEC_CORRUPT;
	alpha_size = n_in_use + 2u;

	groups = bz_bits(br, 3u);
	selectors = bz_bits(br, 15u);
	if (groups < 2u || groups > KOF_BZ_GROUPS ||
	    selectors < 1u || selectors > KOF_BZ_MAX_SELECT)
		return br->eof ? KOF_DEC_TRUNCATED : KOF_DEC_CORRUPT;

	/* The selector list, move-to-front coded over the group numbers and
	 * written in unary - so a run of ones longer than the group count is a
	 * stream naming a table that does not exist. */
	for (i = 0; i < KOF_BZ_GROUPS; i++)
		pos[i] = (uint8_t)i;
	for (i = 0; i < selectors; i++) {
		uint32_t k = 0;
		uint8_t  v;

		while (bz_bit(br)) {
			k++;
			if (k >= groups || br->eof)
				return br->eof ? KOF_DEC_TRUNCATED
					       : KOF_DEC_CORRUPT;
		}
		v = pos[k];
		for (j = k; j > 0; j--)
			pos[j] = pos[j - 1u];
		pos[0] = v;
		st->selector[i] = v;
	}

	/* The code lengths, as a delta walk from a five bit start. */
	for (g = 0; g < groups; g++) {
		int32_t curr = (int32_t)bz_bits(br, 5u);

		for (i = 0; i < alpha_size; i++) {
			for (;;) {
				if (curr < 1 || curr > (int32_t)KOF_BZ_MAX_CODELEN)
					return KOF_DEC_CORRUPT;
				if (!bz_bit(br))
					break;
				if (bz_bit(br))
					curr--;
				else
					curr++;
				if (br->eof)
					return KOF_DEC_TRUNCATED;
			}
			st->len[g][i] = (uint8_t)curr;
		}
		if (!bz_tables(st, g, alpha_size))
			return KOF_DEC_CORRUPT;
	}
	if (br->eof)
		return KOF_DEC_TRUNCATED;

	/* The symbols: move-to-front ranks, with runs of the front byte written
	 * in the bijective base two RUNA and RUNB spell. */
	for (i = 0; i < n_in_use; i++)
		st->mtf[i] = (uint8_t)i;
	memset(st->unzftab, 0, sizeof st->unzftab);

	run = 1u;
	es = 0;
	for (;;) {
		if (group_pos == 0u) {
			if (group_no >= selectors)
				return KOF_DEC_CORRUPT;
			sel = st->selector[group_no++];
			group_pos = 50u;
		}
		group_pos--;
		sym = bz_sym(st, br, sel, alpha_size, &bad);
		if (bad)
			return KOF_DEC_CORRUPT;
		if (br->eof)
			return KOF_DEC_TRUNCATED;

		if (sym == BZ_RUNA || sym == BZ_RUNB) {
			es += (sym == BZ_RUNA ? run : 2u * run);
			run <<= 1;
			/* A run longer than the block it is in, or a doubling
			 * that would wrap, is a crafted length and not a long
			 * file. */
			if (es > block_max || !run)
				return KOF_DEC_CORRUPT;
			continue;
		}

		if (es) {
			uint8_t b = st->seq_to_unseq[st->mtf[0]];

			if (es > block_max - nblock)
				return KOF_DEC_CORRUPT;
			st->unzftab[b] += es;
			while (es--)
				st->tt[nblock++] = b;
			es = 0;
			run = 1u;
		}

		if (sym == alpha_size - 1u)
			break;                  /* end of block */

		/* An ordinary symbol is a rank in the move-to-front list. */
		j = sym - 1u;
		if (j >= n_in_use)
			return KOF_DEC_CORRUPT;
		{
			uint8_t v = st->mtf[j];
			uint8_t b;

			memmove(st->mtf + 1, st->mtf, j);
			st->mtf[0] = v;
			b = st->seq_to_unseq[v];
			if (nblock >= block_max)
				return KOF_DEC_CORRUPT;
			st->unzftab[b]++;
			st->tt[nblock++] = b;
		}
	}
	if (!nblock || orig_ptr >= nblock)
		return KOF_DEC_CORRUPT;

	/*
	 * THE INVERSE TRANSFORM, in the array the bytes are already in.
	 *
	 * cftab is where each byte value's run begins once the block is sorted,
	 * which is all the sort that is needed: the sorted column is the
	 * unsorted one counted. The link for position i is written into the top
	 * twenty-four bits of the entry it points at, so the walk is one
	 * indexed read per output byte and needs no second array.
	 */
	st->cftab[0] = 0;
	for (i = 0; i < 256u; i++)
		st->cftab[i + 1u] = st->unzftab[i];
	for (i = 1; i < 257u; i++)
		st->cftab[i] += st->cftab[i - 1u];
	if (st->cftab[256] != nblock)
		return KOF_DEC_CORRUPT;
	for (i = 0; i < nblock; i++) {
		uint32_t ch = st->tt[i] & 0xffu;

		st->tt[st->cftab[ch]] |= (i << 8);
		st->cftab[ch]++;
	}

	out->crc = 0xffffffffu;
	t_pos = st->tt[orig_ptr] >> 8;

	/*
	 * AND THE RUN LENGTH STAGE ON THE WAY OUT. Four equal bytes are
	 * followed by a count of how many MORE of them there are, so the fifth
	 * byte of a run is a length rather than data - which is why this counts
	 * to four and then reads one.
	 */
	for (i = 0; i < nblock; i++) {
		uint8_t b;

		if (t_pos >= nblock)
			return KOF_DEC_CORRUPT;
		t_pos = st->tt[t_pos];
		b = (uint8_t)(t_pos & 0xffu);
		t_pos >>= 8;

		if (rle_run == 4) {
			uint32_t k;

			for (k = 0; k < b; k++)
				if (!bz_put(out, (uint8_t)rle_prev))
					return KOF_DEC_STOPPED;
			rle_run = 0;
			rle_prev = -1;
			continue;
		}
		if ((int)b == rle_prev) {
			rle_run++;
		} else {
			rle_run = 1;
			rle_prev = (int)b;
		}
		if (!bz_put(out, b))
			return KOF_DEC_STOPPED;
	}
	if (!bz_flush(out))
		return KOF_DEC_STOPPED;

	if ((out->crc ^ 0xffffffffu) != crc_want)
		return KOF_DEC_CORRUPT;
	*combined = ((*combined << 1) | (*combined >> 31)) ^ crc_want;
	return KOF_DEC_OK;
}

int kof_bunzip_sniff(const uint8_t *p, uint64_t n)
{
	if (!p || n < 10u)
		return 0;
	if (p[0] != 'B' || p[1] != 'Z' || p[2] != 'h' ||
	    p[3] < '1' || p[3] > '9')
		return 0;
	if (p[4] == 0x31u && p[5] == 0x41u && p[6] == 0x59u &&
	    p[7] == 0x26u && p[8] == 0x53u && p[9] == 0x59u)
		return 1;
	/* An empty stream: the header, then the end marker and nothing between
	 * them. bzip2 writes one for an empty input. */
	return p[4] == 0x17u && p[5] == 0x72u && p[6] == 0x45u &&
	       p[7] == 0x38u && p[8] == 0x50u && p[9] == 0x90u;
}

enum kof_decomp_status kof_bunzip_decode(struct kof_bunzip *st,
					 const uint8_t *in, uint64_t in_len,
					 kof_bunzip_sink sink, void *user,
					 uint64_t *produced)
{
	struct bz_br br;
	struct bz_out out;
	enum kof_decomp_status last = KOF_DEC_OK;
	int streams = 0;

	if (produced)
		*produced = 0;
	if (!st || !in || !sink)
		return KOF_DEC_CORRUPT;

	memset(&br, 0, sizeof br);
	br.p = in;
	br.n = in_len;

	memset(&out, 0, sizeof out);
	out.sink = sink;
	out.user = user;
	out.st = st;

	for (;;) {
		uint32_t block_max, combined = 0, stored;
		uint64_t at = bz_byte_pos(&br);

		/* A stream starts on a byte boundary: the first at offset zero,
		 * a concatenated one wherever the previous ended. */
		if (at + 10u > in_len)
			break;
		if (!kof_bunzip_sniff(in + at, in_len - at))
			break;
		br.pos = at + 4u;
		br.buf = br.cnt = 0;
		block_max = (uint32_t)(in[at + 3u] - '0') * 100000u;
		streams++;

		for (;;) {
			uint32_t hi = bz_bits(&br, 24u);
			uint32_t lo = bz_bits(&br, 24u);

			if (br.eof) {
				last = KOF_DEC_TRUNCATED;
				break;
			}
			if (hi == BZ_END_MAGIC_HI && lo == BZ_END_MAGIC_LO) {
				stored = bz_bits32(&br);
				if (br.eof)
					last = KOF_DEC_TRUNCATED;
				else if (stored != combined)
					last = KOF_DEC_CORRUPT;
				else
					last = KOF_DEC_OK;
				break;
			}
			if (hi != BZ_BLOCK_MAGIC_HI || lo != BZ_BLOCK_MAGIC_LO) {
				last = KOF_DEC_CORRUPT;
				break;
			}
			last = bz_block(st, &br, &out, block_max, &combined);
			if (last != KOF_DEC_OK)
				break;
		}

		if (produced)
			*produced = out.total;
		if (last != KOF_DEC_OK)
			return last;

		/* Whatever follows a complete stream starts at the next byte. */
		bz_align(&br);
	}

	if (produced)
		*produced = out.total;
	if (!streams)
		return KOF_DEC_CORRUPT;        /* not a bzip2 stream at all */
	return last;
}
