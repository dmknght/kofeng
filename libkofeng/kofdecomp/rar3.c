/*
 * rar3.c - RAR 2.9/3.x LZ decoding.
 *
 * THE OUTPUT IS THE WINDOW.
 *
 * RAR keeps a circular dictionary and flushes it as it fills. This decodes into the
 * caller's buffer instead and lets back references reach into what has already been
 * written, which is what inflate.c and lzma.c here do and for the same reason: an
 * entry is decoded whole into a buffer the host has already bounded, so a second
 * copy of the window would be a megabyte of state and a modulo on every byte to
 * arrive at the same bytes. A distance is then valid exactly when it is no larger
 * than the output so far, which is one comparison and is also the security check.
 *
 * THE BIT READER IS BIG ENDIAN AND PEEKS SIXTEEN.
 *
 * Every field in this format is read as "the top N bits of the next sixteen", then
 * the cursor is advanced by N. That is the shape RAR's own reader has, and matching
 * it exactly is the difference between a decoder that works and one that drifts a
 * bit at a time - so the two operations are kept separate here rather than fused
 * into a single read-and-advance that would be tidier and would not be the format.
 */

#include "rar3.h"

#include <string.h>

/* Table sizes, from the format. */
#define NC   299u                 /* literals and lengths */
#define DC    60u                 /* distances */
#define LDC   17u                 /* low bits of large distances */
#define RC    28u                 /* lengths for repeated distances */
#define BC    20u                 /* the table that codes the tables */
#define TABLE_SIZE (NC + DC + RC + LDC)

#define LOW_DIST_REP_COUNT 16u

static const uint32_t LDecode[28] = {
	0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,32,40,48,56,64,80,96,112,128,160,192,224
};
static const uint8_t LBits[28] = {
	0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5
};
static const uint32_t DDecode[60] = {
	0,1,2,3,4,6,8,12,16,24,32,48,64,96,128,192,256,384,512,768,1024,1536,2048,
	3072,4096,6144,8192,12288,16384,24576,32768,49152,65536,98304,131072,196608,
	262144,327680,393216,458752,524288,589824,655360,720896,786432,851968,917504,
	983040,1048576,1310720,1572864,1835008,2097152,2359296,2621440,2883584,
	3145728,3407872,3670016,3932160
};
static const uint8_t DBits[60] = {
	0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,14,14,
	15,15,16,16,16,16,16,16,16,16,16,16,16,16,16,16,18,18,18,18,18,18,18,18,18,
	18,18,18
};
static const uint32_t SDDecode[8] = { 0,4,8,16,32,64,128,192 };
static const uint8_t SDBits[8] = { 2,2,3,4,5,6,6,6 };

/* ---- the bit reader ----------------------------------------------------------- */

struct br {
	const uint8_t *p;
	uint64_t n;
	uint64_t byte;     /* byte cursor */
	uint32_t bit;      /* 0..7 within it */
	int out_of_input;
};

static uint8_t br_at(struct br *b, uint64_t i)
{
	if (i < b->n)
		return b->p[i];
	b->out_of_input = 1;
	return 0;
}

/* The next sixteen bits, most significant first, without advancing. */
static uint32_t br_peek(struct br *b)
{
	uint32_t v = ((uint32_t)br_at(b, b->byte) << 16) |
		     ((uint32_t)br_at(b, b->byte + 1u) << 8) |
		     (uint32_t)br_at(b, b->byte + 2u);

	return (v >> (8u - b->bit)) & 0xffffu;
}

static void br_skip(struct br *b, uint32_t bits)
{
	b->bit += bits;
	b->byte += b->bit >> 3;
	b->bit &= 7u;
}

static uint32_t br_take(struct br *b, uint32_t bits)
{
	uint32_t v = bits ? (br_peek(b) >> (16u - bits)) : 0u;

	br_skip(b, bits);
	return v;
}

static void br_align(struct br *b)
{
	br_skip(b, (8u - b->bit) & 7u);
}

static int br_done(const struct br *b)
{
	return b->byte >= b->n;
}

/* ---- Huffman ------------------------------------------------------------------ */

/*
 * RAR's canonical decoder, kept in its own shape.
 *
 * `len[k]` is the largest sixteen bit field whose code is at most k bits long, so
 * finding a code's length is a walk up that table and nothing else needs to be
 * searched. `pos[k]` is where codes of that length begin in `num`.
 */
struct huff {
	uint32_t len[16];
	uint32_t pos[16];
	uint16_t num[TABLE_SIZE];
	uint32_t max;
};

static void huff_build(struct huff *d, const uint8_t *bits, uint32_t size)
{
	uint32_t count[16], tmp[16], i;
	uint32_t n = 0, m;

	memset(count, 0, sizeof count);
	memset(d->num, 0, sizeof d->num);
	for (i = 0; i < size; i++)
		count[bits[i] & 0x0fu]++;
	count[0] = 0;

	tmp[0] = d->pos[0] = d->len[0] = 0;
	for (i = 1; i < 16u; i++) {
		n = 2u * (n + count[i]);
		m = n << (15u - i);
		if (m > 0xffffu)
			m = 0xffffu;
		d->len[i] = m;
		tmp[i] = d->pos[i] = d->pos[i - 1u] + count[i - 1u];
	}
	for (i = 0; i < size; i++)
		if (bits[i] & 0x0fu) {
			uint32_t l = bits[i] & 0x0fu;

			if (tmp[l] < TABLE_SIZE)
				d->num[tmp[l]++] = (uint16_t)i;
		}
	d->max = size;
}

static uint32_t huff_decode(struct br *b, const struct huff *d)
{
	uint32_t field = br_peek(b) & 0xfffeu;
	uint32_t bits, idx;

	for (bits = 1; bits < 15u; bits++)
		if (field < d->len[bits])
			break;
	br_skip(b, bits);

	idx = d->pos[bits] + ((field - d->len[bits - 1u]) >> (16u - bits));
	if (idx >= d->max)
		idx = 0;
	return d->num[idx];
}

/* ---- the decoder -------------------------------------------------------------- */

struct rar3 {
	struct br b;
	uint8_t *out;
	uint64_t cap, at;

	struct huff LD, DD, LDD, RD, BD;
	uint8_t old_table[TABLE_SIZE];

	uint32_t old_dist[4];
	uint32_t last_dist, last_len;
	uint32_t prev_low_dist, low_dist_rep;
	int tables_read;
	/*
	 * Why the loop stopped, when it stopped for a reason the caller must not
	 * read as success.
	 *
	 * A stream may begin LZ and switch to PPM at any block boundary. Breaking
	 * out and reporting OK hands over a file that is the right shape and the
	 * wrong length, which is the one outcome worse than reporting nothing.
	 */
	int gave_up;
};

static void push_dist(struct rar3 *s, uint32_t d)
{
	s->old_dist[3] = s->old_dist[2];
	s->old_dist[2] = s->old_dist[1];
	s->old_dist[1] = s->old_dist[0];
	s->old_dist[0] = d;
}

/*
 * A back reference, bounded by what has been produced.
 *
 * Byte at a time and deliberately not memmove: RAR, like every LZ77 descendant,
 * allows a distance shorter than the length so that a run repeats itself, and a
 * block move would read the source before the overlap was written.
 */
static int copy_string(struct rar3 *s, uint32_t len, uint32_t dist)
{
	uint64_t src;

	if (dist == 0 || (uint64_t)dist > s->at)
		return 0;
	src = s->at - dist;
	while (len-- > 0) {
		if (s->at >= s->cap)
			return 1;             /* the caller's ceiling, not an error */
		s->out[s->at] = s->out[src++];
		s->at++;
	}
	return 1;
}

/*
 * Read the block header and the four Huffman tables that follow it.
 *
 * Returns 1 for an LZ block ready to decode, 0 for a stream that cannot be read,
 * and -1 for a PPM block - which is well formed and is not decoded here.
 */
static int read_tables(struct rar3 *s)
{
	uint8_t bitlen[BC];
	uint8_t table[TABLE_SIZE];
	uint32_t i, field;

	br_align(&s->b);
	field = br_peek(&s->b);
	if (field & 0x8000u)
		return -1;                    /* PPM */
	/* The second bit says whether the previous tables are the base this one is
	 * a delta against. Cleared, the delta is against zero. */
	if (!(field & 0x4000u))
		memset(s->old_table, 0, sizeof s->old_table);
	br_skip(&s->b, 2u);

	for (i = 0; i < BC; ) {
		uint32_t l = br_take(&s->b, 4u);

		if (l == 15u) {
			uint32_t z = br_take(&s->b, 4u);

			if (z == 0u) {
				bitlen[i++] = 15u;
			} else {
				z += 2u;
				while (z-- > 0u && i < BC)
					bitlen[i++] = 0u;
			}
		} else {
			bitlen[i++] = (uint8_t)l;
		}
		if (s->b.out_of_input)
			return 0;
	}
	huff_build(&s->BD, bitlen, BC);

	for (i = 0; i < TABLE_SIZE; ) {
		uint32_t num = huff_decode(&s->b, &s->BD);

		if (s->b.out_of_input)
			return 0;
		if (num < 16u) {
			table[i] = (uint8_t)((num + s->old_table[i]) & 0x0fu);
			i++;
		} else if (num < 18u) {
			uint32_t n = num == 16u ? br_take(&s->b, 3u) + 3u
						: br_take(&s->b, 7u) + 11u;

			if (i == 0)
				return 0;     /* nothing to repeat */
			while (n-- > 0u && i < TABLE_SIZE) {
				table[i] = table[i - 1u];
				i++;
			}
		} else {
			uint32_t n = num == 18u ? br_take(&s->b, 3u) + 3u
						: br_take(&s->b, 7u) + 11u;

			while (n-- > 0u && i < TABLE_SIZE)
				table[i++] = 0u;
		}
	}
	s->tables_read = 1;

	huff_build(&s->LD, table, NC);
	huff_build(&s->DD, table + NC, DC);
	huff_build(&s->LDD, table + NC + DC, LDC);
	huff_build(&s->RD, table + NC + DC + LDC, RC);
	memcpy(s->old_table, table, sizeof s->old_table);
	return 1;
}

enum kof_decomp_status kof_rar3_decode(const uint8_t *in, uint64_t in_len,
				       uint8_t *out, uint64_t out_cap,
				       uint32_t dict, uint64_t *produced)
{
	/*
	 * On the stack, and it matters that it is.
	 *
	 * This was static, on a guess that the tables were too large to be a local.
	 * They are 5.1KB - the guess was wrong by four times - and a static here
	 * would make the decoder unusable from two threads at once, which is the one
	 * property kofdb.h promises about this engine: the database is immutable and
	 * shared, and everything mutable belongs to the thread that made it.
	 */
	struct rar3 s;
	int t;

	(void)dict;                    /* the output IS the window - see the header */
	if (produced)
		*produced = 0;
	if (!in || !out || out_cap == 0)
		return KOF_DEC_CORRUPT;

	memset(&s, 0, sizeof s);
	s.b.p = in;
	s.b.n = in_len;
	s.out = out;
	s.cap = out_cap;

	t = read_tables(&s);
	if (t < 0) {
		if (produced)
			*produced = 0;
		return KOF_DEC_UNSUPPORTED;
	}
	if (t == 0)
		return KOF_DEC_CORRUPT;

	while (s.at < out_cap) {
		uint32_t num, len, dist, bits;

		if (br_done(&s.b) || s.b.out_of_input)
			break;

		num = huff_decode(&s.b, &s.LD);

		if (num < 256u) {
			s.out[s.at++] = (uint8_t)num;
			continue;
		}
		if (num >= 271u) {
			uint32_t dn;

			num -= 271u;
			if (num >= 28u)
				return KOF_DEC_CORRUPT;
			len = LDecode[num] + 3u;
			bits = LBits[num];
			if (bits)
				len += br_take(&s.b, bits);

			dn = huff_decode(&s.b, &s.DD);
			if (dn >= 60u)
				return KOF_DEC_CORRUPT;
			dist = DDecode[dn] + 1u;
			bits = DBits[dn];
			if (bits) {
				if (dn > 9u) {
					/*
					 * A large distance is split: the high bits
					 * ride here and the low four come from a
					 * table of their own, because the low bits
					 * of consecutive distances repeat and are
					 * worth coding separately.
					 */
					if (bits > 4u)
						dist += br_take(&s.b, bits - 4u) << 4;
					if (s.low_dist_rep > 0u) {
						s.low_dist_rep--;
						dist += s.prev_low_dist;
					} else {
						uint32_t low =
							huff_decode(&s.b, &s.LDD);

						if (low == 16u) {
							s.low_dist_rep =
							    LOW_DIST_REP_COUNT - 1u;
							dist += s.prev_low_dist;
						} else {
							dist += low;
							s.prev_low_dist = low;
						}
					}
				} else {
					dist += br_take(&s.b, bits);
				}
			}
			if (dist >= 0x2000u) {
				len++;
				if (dist >= 0x40000u)
					len++;
			}
			push_dist(&s, dist);
			s.last_len = len;
			s.last_dist = dist;
			if (!copy_string(&s, len, dist))
				return KOF_DEC_CORRUPT;
			continue;
		}
		if (num == 256u) {
			/* End of block: another header follows, unless the stream
			 * ends here. */
			t = read_tables(&s);
			if (t < 0) {
				s.gave_up = 1;        /* PPM from here on */
				break;
			}
			if (t == 0)
				break;
			continue;
		}
		if (num == 257u) {
			/* A filter program. Not run, and not skipped either: what
			 * follows it would be decoded against a window this cannot
			 * reproduce. */
			s.gave_up = 1;
			break;
		}
		if (num == 258u) {
			if (s.last_len &&
			    !copy_string(&s, s.last_len, s.last_dist))
				return KOF_DEC_CORRUPT;
			continue;
		}
		if (num < 263u) {
			uint32_t k = num - 259u, ln;

			dist = s.old_dist[k];
			for (; k > 0u; k--)
				s.old_dist[k] = s.old_dist[k - 1u];
			s.old_dist[0] = dist;

			ln = huff_decode(&s.b, &s.RD);
			if (ln >= 28u)
				return KOF_DEC_CORRUPT;
			len = LDecode[ln] + 2u;
			bits = LBits[ln];
			if (bits)
				len += br_take(&s.b, bits);
			s.last_len = len;
			s.last_dist = dist;
			if (!copy_string(&s, len, dist))
				return KOF_DEC_CORRUPT;
			continue;
		}
		/* 263..270: a short distance with a length of two. */
		{
			uint32_t k = num - 263u;

			if (k >= 8u)
				return KOF_DEC_CORRUPT;
			dist = SDDecode[k] + 1u;
			bits = SDBits[k];
			if (bits)
				dist += br_take(&s.b, bits);
			push_dist(&s, dist);
			s.last_len = 2u;
			s.last_dist = dist;
			if (!copy_string(&s, 2u, dist))
				return KOF_DEC_CORRUPT;
		}
	}

	if (produced)
		*produced = s.at;
	/*
	 * Short output is only OK when the caller's ceiling is what stopped it.
	 * Anything else - a coding this build lacks, an exhausted input - is said
	 * plainly, because the difference decides whether what came back is the
	 * file or a piece of it.
	 */
	if (s.gave_up)
		return KOF_DEC_UNSUPPORTED;
	if (s.at >= out_cap)
		return KOF_DEC_OK;
	return s.b.out_of_input ? KOF_DEC_TRUNCATED : KOF_DEC_UNSUPPORTED;
}
