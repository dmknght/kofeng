/*
 * rar5.c - RAR 5 LZ decoding.
 *
 * THE OUTPUT IS THE WINDOW, as it is in rar3.c and for the same reason: an entry is
 * decoded whole into a buffer the host has already bounded, so a distance is valid
 * exactly when it is no larger than what has been produced. That is one comparison,
 * and it is also the security check.
 *
 * THE BIT READER IS BIG ENDIAN and reads up to thirty two bits at a time. RAR5 needs
 * the wider read: a distance can carry twenty six raw bits where RAR3 never needed
 * more than sixteen, and splitting that across two reads is where a decoder starts
 * drifting a bit at a time.
 */

#include "rar5.h"

#include <string.h>

/* Table sizes, from the format. Larger than RAR3's in every case, and the slot
 * counts are what the arithmetic below is bounded by. */
#define NC   306u                 /* literals and lengths */
#define DC    64u                 /* distances */
#define LDC   16u                 /* low bits of large distances */
#define RC    44u                 /* lengths for repeated distances */
#define BC    20u                 /* the table that codes the tables */
#define TABLE_SIZE (NC + DC + LDC + RC)

/* ---- the bit reader ----------------------------------------------------------- */

struct br {
	const uint8_t *p;
	uint64_t n;
	uint64_t byte;
	uint32_t bit;
	int out_of_input;
};

/*
 * A byte, or zero past the end.
 *
 * Reading past the end is NOT running out of input, and the difference is four
 * bytes of every file. A peek here is thirty two bits wide and needs five bytes to
 * deliver them from an unaligned cursor, so the last symbol of every entry is
 * decoded from a peek that reaches past the last byte - which is fine, because the
 * bits it needs are all before it. Flagging that as exhaustion ended the decode
 * early and produced a file four bytes short of the one in the archive.
 *
 * Exhaustion is what br_skip sees: the CURSOR past the end, not a peek.
 */
static uint8_t br_at(const struct br *b, uint64_t i)
{
	return i < b->n ? b->p[i] : 0u;
}

/* The next thirty two bits, most significant first, without advancing. Five bytes
 * are needed because the cursor is rarely on a byte boundary. */
static uint32_t br_peek32(const struct br *b)
{
	uint64_t v = 0;
	uint32_t i;

	for (i = 0; i < 5u; i++)
		v = (v << 8) | br_at(b, b->byte + i);
	return (uint32_t)((v >> (8u - b->bit)) & 0xffffffffu);
}

static uint32_t br_peek16(const struct br *b)
{
	return br_peek32(b) >> 16;
}

static void br_skip(struct br *b, uint32_t bits)
{
	b->bit += bits;
	b->byte += b->bit >> 3;
	b->bit &= 7u;
	if (b->byte > b->n)
		b->out_of_input = 1;
}

static uint32_t br_take(struct br *b, uint32_t bits)
{
	uint32_t v = bits ? (br_peek32(b) >> (32u - bits)) : 0u;

	br_skip(b, bits);
	return v;
}

static void br_align(struct br *b)
{
	br_skip(b, (8u - b->bit) & 7u);
}

/* Where the cursor is, in bits from the start of the input. */
static uint64_t br_pos(const struct br *b)
{
	return (b->byte << 3) + b->bit;
}

/* ---- Huffman ------------------------------------------------------------------ */

/*
 * The same canonical decoder RAR3 uses, sized for RAR5's tables.
 *
 * `len[k]` is the largest sixteen bit field whose code is at most k bits long, so
 * finding a code's length is a walk up that table; `pos[k]` is where codes of that
 * length begin in `num`.
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
	uint32_t field = br_peek16(b) & 0xfffeu;
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

/* ---- filters ------------------------------------------------------------------ */

/*
 * Named by a three bit field, not by a program.
 *
 * RAR5 dropped the VM: the archiver states which of a fixed set it applied, so there
 * is nothing to identify and no bytecode to refuse. Four of the eight names are ever
 * emitted and all four are implemented; the rest were reserved and never used, and
 * are refused by name.
 */
enum {
	RF_DELTA = 0,
	RF_E8    = 1,
	RF_E8E9  = 2,
	RF_ARM   = 3
};

/* RAR's own bound on what one filter may cover. */
#define FILTER_BLOCK_MAX 0x400000u

/* Enough to follow an archive; reaching it ends the decode rather than dropping a
 * transform and calling what is left the file. */
#define MAX_USES 1024u

struct f_use {
	uint64_t start;
	uint32_t len;
	uint32_t channels;   /* delta only */
	uint8_t  type;
};

static uint32_t rd32le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * The x86 branch transform, undone.
 *
 * Every CALL - and for E8E9 every JMP - whose operand looked like a file offset was
 * turned into an absolute address, because absolute addresses repeat across a binary
 * and relative ones do not.
 *
 * The one difference from RAR3's version is the modulo: RAR5 wraps the file offset
 * at sixteen megabytes, so a block past that point converts against a wrapped offset
 * and a decoder that left the modulo out is correct only for small files.
 */
static void filt_e8(uint8_t *d, uint32_t n, uint32_t file_off, int also_e9)
{
	const uint32_t FILE_SIZE = 0x1000000u;
	uint8_t cmp2 = also_e9 ? 0xe9u : 0xe8u;
	uint32_t cur = 0;

	if (n < 5u)
		return;
	while (cur < n - 4u) {
		uint8_t c = d[cur++];

		if (c != 0xe8u && c != cmp2)
			continue;
		{
			uint32_t off = (cur + file_off) % FILE_SIZE;
			uint32_t addr = rd32le(d + cur);

			if (addr < FILE_SIZE)
				wr32le(d + cur, addr - off);
			else if ((addr & 0x80000000u) &&
				 !((addr + off) & 0x80000000u))
				wr32le(d + cur, addr + FILE_SIZE);
		}
		cur += 4u;
	}
}

/*
 * The ARM branch transform, undone.
 *
 * A 32 bit ARM BL is four bytes with 0xeb on top and a word-counted displacement in
 * the low three, so instructions are stepped four at a time and the offset is in
 * words rather than bytes - which is why the file offset is divided by four here and
 * not in the x86 case.
 */
static void filt_arm(uint8_t *d, uint32_t n, uint32_t file_off)
{
	uint32_t i;

	if (n < 4u)
		return;
	for (i = 0; i + 4u <= n; i += 4u)
		if (d[i + 3u] == 0xebu) {
			uint32_t off = (uint32_t)d[i] |
				       ((uint32_t)d[i + 1u] << 8) |
				       ((uint32_t)d[i + 2u] << 16);

			off -= (file_off + i) / 4u;
			d[i] = (uint8_t)off;
			d[i + 1u] = (uint8_t)(off >> 8);
			d[i + 2u] = (uint8_t)(off >> 16);
		}
}

/*
 * Channel de-interleave, with the running difference undone.
 *
 * Needs working room because the result is a permutation of the input: the source is
 * read in channel-major order and written interleaved, so no byte can be written
 * before the byte it displaces has been read.
 */
static int filt_delta(uint8_t *d, uint32_t n, uint32_t chan,
		      uint8_t *scratch, uint64_t scratch_len)
{
	uint32_t ch, src = 0;

	if (chan == 0u || n == 0u || (uint64_t)n > scratch_len)
		return 0;
	memcpy(scratch, d, n);
	for (ch = 0; ch < chan; ch++) {
		uint8_t prev = 0;
		uint32_t at;

		for (at = ch; at < n; at += chan) {
			prev = (uint8_t)(prev - scratch[src++]);
			d[at] = prev;
		}
	}
	return 1;
}

/* ---- the decoder -------------------------------------------------------------- */

struct rar5 {
	struct br b;
	uint8_t *out;
	uint64_t cap, at;

	struct huff LD, DD, LDD, RD, BD;
	int have_tables;

	uint32_t old_dist[4];
	uint32_t last_len;

	struct f_use use[MAX_USES];
	uint32_t n_uses;

	uint8_t *scratch;
	uint64_t scratch_len;

	/* Why the loop stopped, when it stopped for a reason the caller must not
	 * read as success - a filter this build will not run, or a table it cannot
	 * make sense of. */
	int gave_up;
};

/* One block's header, which says how far the block reaches and whether new tables
 * come with it. */
struct blk {
	uint64_t end_bits;    /* the block's last bit, from the start of the input */
	int last;             /* no block follows this one */
	int tables;           /* tables are present */
};

static void push_dist(struct rar5 *s, uint32_t d)
{
	s->old_dist[3] = s->old_dist[2];
	s->old_dist[2] = s->old_dist[1];
	s->old_dist[1] = s->old_dist[0];
	s->old_dist[0] = d;
}

/*
 * A back reference, bounded by what has been produced.
 *
 * Byte at a time and deliberately not memmove: a distance shorter than the length
 * makes a run repeat itself, and a block move would read the source before the
 * overlap was written.
 */
static int copy_string(struct rar5 *s, uint32_t len, uint32_t dist)
{
	uint64_t src;

	if (dist == 0u || (uint64_t)dist > s->at)
		return 0;
	src = s->at - dist;
	while (len-- > 0u) {
		if (s->at >= s->cap)
			return 1;             /* the caller's ceiling, not an error */
		s->out[s->at++] = s->out[src++];
	}
	return 1;
}

/*
 * Read a block header.
 *
 * The size is stated rather than terminated, and it is checked: the header carries a
 * byte that is the size and the flags folded together, so a header read at the wrong
 * bit offset is caught here instead of becoming a block of noise.
 */
static int read_block_header(struct rar5 *s, struct blk *h)
{
	uint32_t flags, nbytes, saved, i, size = 0, sum;
	uint64_t start;

	br_align(&s->b);
	flags = br_take(&s->b, 8u);
	nbytes = ((flags >> 3) & 3u) + 1u;
	if (nbytes == 4u)
		return 0;
	saved = br_take(&s->b, 8u);
	for (i = 0; i < nbytes; i++)
		size += br_take(&s->b, 8u) << (i * 8u);

	sum = 0x5au ^ flags ^ size ^ (size >> 8) ^ (size >> 16);
	if ((sum & 0xffu) != saved)
		return 0;
	if (s->b.out_of_input)
		return 0;

	start = br_pos(&s->b);
	/* The last byte of a block is only partly used, and by how much is the low
	 * three bits of the flags plus one - so the end is a BIT position and not a
	 * byte one. Rounding it up to the byte reads the next header as data. */
	h->end_bits = start + ((uint64_t)size << 3) - (8u - ((flags & 7u) + 1u));
	h->last = (flags & 0x40u) != 0;
	h->tables = (flags & 0x80u) != 0;
	return 1;
}

/*
 * Read the Huffman tables, when a block says it carries them.
 *
 * Whole, not as a delta against the previous block's - that is RAR3's scheme and
 * carrying it over here produces tables that decode almost correctly.
 */
static int read_tables(struct rar5 *s)
{
	uint8_t bitlen[BC];
	uint8_t table[TABLE_SIZE];
	uint32_t i;

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
			table[i++] = (uint8_t)num;
		} else if (num < 18u) {
			uint32_t n = num == 16u ? br_take(&s->b, 3u) + 3u
						: br_take(&s->b, 7u) + 11u;

			if (i == 0u)
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

	huff_build(&s->LD, table, NC);
	huff_build(&s->DD, table + NC, DC);
	huff_build(&s->LDD, table + NC + DC, LDC);
	huff_build(&s->RD, table + NC + DC + LDC, RC);
	s->have_tables = 1;
	return 1;
}

/*
 * A length, from its slot.
 *
 * Derived rather than looked up: the slot's low bits are the top of the value and
 * its high bits say how many raw bits follow. RAR3 had a table of constants for the
 * same job and RAR5 replaced it with this, which is why the two decoders cannot
 * share the step.
 */
static uint32_t slot_to_len(struct br *b, uint32_t slot)
{
	uint32_t bits, len = 2u;

	if (slot < 8u)
		return len + slot;
	bits = slot / 4u - 1u;
	len += (4u | (slot & 3u)) << bits;
	if (bits > 0u)
		len += br_take(b, bits);
	return len;
}

/* A filter's block start or length: a two bit count of bytes, then the bytes. */
static uint32_t read_filter_data(struct br *b)
{
	uint32_t nbytes = br_take(b, 2u) + 1u, v = 0, i;

	for (i = 0; i < nbytes; i++)
		v += br_take(b, 8u) << (i * 8u);
	return v;
}

static int read_filter(struct rar5 *s)
{
	uint32_t start = read_filter_data(&s->b);
	uint32_t len = read_filter_data(&s->b);
	uint32_t type = br_take(&s->b, 3u);
	uint32_t chan = 0;

	/* Five bits, not eight. The channel count is the only field here whose width
	 * is not a byte multiple, and reading it as one consumed three bits too many
	 * - after which every symbol in the entry decoded as something else. The
	 * entries that carry no filter were unaffected, which is what made it look
	 * like a filter bug rather than a bit width. */
	if (type == RF_DELTA)
		chan = br_take(&s->b, 5u) + 1u;
	if (s->b.out_of_input)
		return 0;
	if (len == 0u || len > FILTER_BLOCK_MAX)
		return 0;
	if (s->n_uses >= MAX_USES)
		return 0;

	switch (type) {
	case RF_E8:
	case RF_E8E9:
	case RF_ARM:
		break;
	case RF_DELTA:
		if (!s->scratch || (uint64_t)len > s->scratch_len)
			return 0;
		break;
	default:
		return 0;             /* a name the format reserved and never used */
	}

	s->use[s->n_uses].start = s->at + start;
	s->use[s->n_uses].len = len;
	s->use[s->n_uses].channels = chan;
	s->use[s->n_uses].type = (uint8_t)type;
	s->n_uses++;
	return 1;
}

/* Run the recorded transforms, once the window will not be read again. In order,
 * because a second filter over one range takes the first one's output as its input. */
static void apply_filters(struct rar5 *s)
{
	uint32_t i;

	for (i = 0; i < s->n_uses; i++) {
		const struct f_use *u = &s->use[i];

		/* A range the decode never reached: its bytes are not there to
		 * transform, and half of one would be worse than none. */
		if (u->start + u->len > s->at)
			continue;

		switch (u->type) {
		case RF_E8:
		case RF_E8E9:
			filt_e8(s->out + u->start, u->len, (uint32_t)u->start,
				u->type == RF_E8E9);
			break;
		case RF_ARM:
			filt_arm(s->out + u->start, u->len, (uint32_t)u->start);
			break;
		default:
			if (!filt_delta(s->out + u->start, u->len, u->channels,
					s->scratch, s->scratch_len))
				s->gave_up = 1;
			break;
		}
	}
}

enum kof_decomp_status kof_rar5_decode(const uint8_t *in, uint64_t in_len,
				       uint8_t *out, uint64_t out_cap,
				       uint8_t *scratch, uint64_t scratch_len,
				       uint64_t *produced)
{
	/* On the stack, for the reason rar3.c gives: a static here would make the
	 * decoder unusable from two threads at once, which is the one property this
	 * engine promises about everything it shares. */
	struct rar5 s;
	struct blk h;
	int corrupt = 0;

	if (produced)
		*produced = 0;
	if (!in || !out || out_cap == 0u)
		return KOF_DEC_CORRUPT;

	memset(&s, 0, sizeof s);
	s.b.p = in;
	s.b.n = in_len;
	s.out = out;
	s.cap = out_cap;
	s.scratch = scratch;
	s.scratch_len = scratch_len;

	if (!read_block_header(&s, &h))
		return KOF_DEC_CORRUPT;
	if (!h.tables || !read_tables(&s))
		return KOF_DEC_CORRUPT;

	while (s.at < out_cap) {
		uint32_t slot, len, dist, bits;

		if (s.b.out_of_input)
			break;

		/*
		 * The block boundary, checked before every symbol.
		 *
		 * There is no end-of-block symbol in RAR5 - the header said how many
		 * bits the block holds, and the next header begins at the bit after
		 * them. A decoder that kept reading would decode the header as data.
		 */
		if (br_pos(&s.b) >= h.end_bits) {
			if (h.last)
				break;
			if (!read_block_header(&s, &h))
				break;
			if (h.tables && !read_tables(&s))
				break;
			if (!s.have_tables)
				break;
			continue;
		}

		slot = huff_decode(&s.b, &s.LD);

		if (slot < 256u) {
			s.out[s.at++] = (uint8_t)slot;
			continue;
		}
		if (slot >= 262u) {
			uint32_t dslot;

			len = slot_to_len(&s.b, slot - 262u);

			dslot = huff_decode(&s.b, &s.DD);
			if (dslot >= DC)
				goto corrupt;
			dist = 1u;
			if (dslot < 4u) {
				bits = 0;
				dist += dslot;
			} else {
				bits = dslot / 2u - 1u;
				dist += (2u | (dslot & 1u)) << bits;
			}
			if (bits > 0u) {
				if (bits >= 4u) {
					/*
					 * A large distance is split: the high
					 * bits ride here and the low four come
					 * from a table of their own, because the
					 * low bits of consecutive distances
					 * repeat and are worth coding separately.
					 */
					if (bits > 4u)
						dist += br_take(&s.b, bits - 4u)
							<< 4;
					dist += huff_decode(&s.b, &s.LDD);
				} else {
					dist += br_take(&s.b, bits);
				}
			}

			if (dist > 0x100u) {
				len++;
				if (dist > 0x2000u) {
					len++;
					if (dist > 0x40000u)
						len++;
				}
			}
			push_dist(&s, dist);
			s.last_len = len;
			if (!copy_string(&s, len, dist))
				goto corrupt;
			continue;
		}
		if (slot == 256u) {
			if (!read_filter(&s)) {
				s.gave_up = 1;
				break;
			}
			continue;
		}
		if (slot == 257u) {
			if (s.last_len &&
			    !copy_string(&s, s.last_len, s.old_dist[0]))
				goto corrupt;
			continue;
		}
		/* 258..261: one of the last four distances, with a length of its own. */
		{
			uint32_t k = slot - 258u, ls;

			dist = s.old_dist[k];
			for (; k > 0u; k--)
				s.old_dist[k] = s.old_dist[k - 1u];
			s.old_dist[0] = dist;

			ls = huff_decode(&s.b, &s.RD);
			if (ls >= RC)
				goto corrupt;
			len = slot_to_len(&s.b, ls);
			s.last_len = len;
			if (!copy_string(&s, len, dist))
				goto corrupt;
		}
	}

	goto done;

	/*
	 * A stream that stopped making sense.
	 *
	 * It joins the exit below rather than returning on the spot, for two
	 * reasons. What came out before it stopped is worth keeping and this
	 * decoder's header promises it - a scanner searches the bytes that arrived,
	 * and returning none of them because the tail was wrong throws away the
	 * part that was right. And if the ceiling was already reached, the whole of
	 * what was asked for is in hand and what the next symbol looked like does
	 * not matter.
	 */
corrupt:
	corrupt = 1;

done:
	apply_filters(&s);
	if (produced)
		*produced = s.at;
	/*
	 * Short output is only OK when the caller's ceiling is what stopped it.
	 * Anything else is said plainly, because the difference decides whether what
	 * came back is the file or a piece of it.
	 */
	if (s.at >= out_cap)
		return KOF_DEC_OK;
	if (corrupt)
		return KOF_DEC_CORRUPT;
	if (s.gave_up)
		return KOF_DEC_UNSUPPORTED;
	return s.b.out_of_input ? KOF_DEC_TRUNCATED : KOF_DEC_CORRUPT;
}
