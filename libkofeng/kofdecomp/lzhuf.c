/*
 * lzhuf.c - LHA's -lh5/6/7 and ARJ's methods 1 to 3, which are one coding.
 *
 * See lzhuf.h for the shape. What follows is the decoder, and the three places
 * it can be got wrong quietly are marked where they are:
 *
 *   - the bit reader is MSB FIRST over a 16 bit window, and it is filled a byte
 *     at a time from a partial byte held beside it. Reading it least
 *     significant first decodes into something, which is the whole problem.
 *   - a code longer than the lookup table is finished by WALKING A TREE built
 *     into the same table's spare entries. The walk has to be bounded: a table
 *     built from lengths that are not a code would otherwise chase indices for
 *     ever.
 *   - ARJ's dictionary is 26624 bytes, WHICH IS NOT A POWER OF TWO.
 *
 * EVERY NUMBER HERE CAME OUT OF THE STREAM. The block count, the three trees'
 * lengths, the run lengths inside them and every symbol are fields somebody
 * else wrote; each is bounded before it is used as an index.
 */

#include <string.h>

#include "lzhuf.h"

#define LH_THRESHOLD 3u
#define LH_CBIT      9u        /* bits in the literal tree's length count */
#define LH_TBIT      5u        /* bits in the pretree's length count */

/* Dictionary, position alphabet and position-length width, per variant - the
 * only three numbers the four variants disagree about. */
static const struct {
	uint32_t dict;
	uint8_t  np;
	uint8_t  pbit;
} lh_var[KOF_LZHUF_VARIANTS] = {
	{ 26624u, 17u, 5u },   /* ARJ 1-3 */
	{  8192u, 14u, 4u },   /* -lh5- */
	{ 32768u, 16u, 5u },   /* -lh6- */
	{ 65536u, 17u, 5u }    /* -lh7- */
};

/* ---- the bit reader ---------------------------------------------------------
 *
 * Sixteen bits, most significant first, topped up from a byte at a time. Past
 * the end it feeds zeroes; whether that MATTERS is decided by `used` rather
 * than by the read - see lzhuf.h. A stream that genuinely runs out mid-symbol
 * is truncated, which the caller is told by the status rather than by a decode
 * that wanders.
 */
static void lh_fill(struct kof_lzhuf *s, uint32_t n)
{
	s->used += n;
	if (s->used > s->in_len * 8u + 16u)
		s->eof = 1;
	while (n > s->bitcount) {
		n -= s->bitcount;
		s->bitbuf = (uint16_t)(((uint32_t)s->bitbuf << s->bitcount) |
				       ((uint32_t)s->sub >> (8u - s->bitcount)));
		s->sub = s->in_pos < s->in_len ? s->in[s->in_pos++] : 0u;
		s->bitcount = 8u;
	}
	s->bitcount = (uint8_t)(s->bitcount - n);
	s->bitbuf = (uint16_t)(((uint32_t)s->bitbuf << n) |
			       ((uint32_t)s->sub >> (8u - n)));
	s->sub = (uint8_t)((uint32_t)s->sub << n);
}

static uint32_t lh_bits(struct kof_lzhuf *s, uint32_t n)
{
	uint32_t v;

	if (!n)
		return 0;
	v = (uint32_t)s->bitbuf >> (16u - n);
	lh_fill(s, n);
	return v;
}

/* ---- the canonical table ------------------------------------------------------
 *
 * Codes up to `tablebits` long are a direct lookup; longer ones end in a tree
 * whose nodes live above `nchar` in the same left/right arrays. That is LHA's
 * own arrangement and it is kept because the two decoders that read these
 * streams are the only things that ever produced them.
 *
 * Returns zero for a set of lengths that is not a code - over or under
 * subscribed - which is a stream that does not match the tree it sent.
 */
static int lh_make_table(struct kof_lzhuf *s, uint32_t nchar,
			 const uint8_t *bitlen, uint32_t tablebits,
			 uint16_t *table)
{
	uint16_t count[17], weight[17], start[18];
	uint32_t i, k, len, ch, jut, avail, nextcode, mask;

	for (i = 0; i <= 16u; i++)
		count[i] = 0;
	for (i = 0; i < nchar; i++) {
		if (bitlen[i] > 16u)
			return 0;
		count[bitlen[i]]++;
	}

	start[1] = 0;
	for (i = 1; i <= 16u; i++)
		start[i + 1u] = (uint16_t)(start[i] +
					   (uint16_t)(count[i] << (16u - i)));
	/* start[17] is the total weight modulo 2^16: a complete code comes to
	 * exactly 2^16 and so wraps to zero. Anything else is not one. */
	if (start[17] != 0)
		return 0;

	jut = 16u - tablebits;
	for (i = 1; i <= tablebits; i++) {
		start[i] = (uint16_t)(start[i] >> jut);
		weight[i] = (uint16_t)(1u << (tablebits - i));
	}
	for (i = tablebits + 1u; i <= 16u; i++)
		weight[i] = (uint16_t)(1u << (16u - i));

	i = (uint32_t)start[tablebits + 1u] >> jut;
	if (i != 0) {
		k = 1u << tablebits;
		while (i != k)
			table[i++] = 0;
	}

	avail = nchar;
	mask = 1u << (15u - tablebits);
	for (ch = 0; ch < nchar; ch++) {
		len = bitlen[ch];
		if (!len)
			continue;
		nextcode = (uint32_t)((uint16_t)(start[len] + weight[len]));
		if (len <= tablebits) {
			for (i = start[len]; i < nextcode; i++) {
				if (i >= (1u << tablebits))
					return 0;
				table[i] = (uint16_t)ch;
			}
		} else {
			/*
			 * The tail of a long code, as a tree. `cur` names where
			 * the next link is: the lookup table itself at first,
			 * then one side of a node.
			 */
			uint16_t *slot = &table[(uint32_t)start[len] >> jut];

			k = start[len];
			i = len - tablebits;
			while (i != 0) {
				if (*slot == 0) {
					if (avail >= 2u * KOF_LZHUF_NC)
						return 0;
					s->left[avail] = 0;
					s->right[avail] = 0;
					*slot = (uint16_t)avail++;
				}
				if (*slot >= 2u * KOF_LZHUF_NC)
					return 0;
				slot = (k & mask) ? &s->right[*slot]
						  : &s->left[*slot];
				k = (uint32_t)(uint16_t)(k << 1);
				i--;
			}
			*slot = (uint16_t)ch;
		}
		start[len] = (uint16_t)nextcode;
	}
	return 1;
}

/* One symbol out of a table built above. `bad` is set when the walk runs past
 * the longest code the format allows, which cannot happen for a code this file
 * built and can for one a hostile stream described. */
static uint32_t lh_sym(struct kof_lzhuf *s, const uint16_t *table,
		       const uint8_t *len, uint32_t n, uint32_t tablebits,
		       int *bad)
{
	uint32_t j = table[(uint32_t)s->bitbuf >> (16u - tablebits)];
	uint32_t mask = 1u << (15u - tablebits);
	uint32_t guard = 0;

	while (j >= n) {
		if (j >= 2u * KOF_LZHUF_NC || !mask || ++guard > 16u) {
			*bad = 1;
			return 0;
		}
		j = (s->bitbuf & mask) ? s->right[j] : s->left[j];
		mask >>= 1;
	}
	lh_fill(s, len[j]);
	return j;
}

/* ---- the three trees ----------------------------------------------------------- */

/*
 * The pretree, and the position tree, which are stated the same way: a count,
 * then that many lengths, each three bits with an escape into a run of ones.
 *
 * `i_special` is the pretree's one irregularity - after the third length a two
 * bit count of zero lengths follows - and is negative for the position tree,
 * which has none.
 */
static int lh_read_pt_len(struct kof_lzhuf *s, uint32_t nn, uint32_t nbit,
			  int i_special)
{
	uint32_t i, c, n;

	n = lh_bits(s, nbit);
	if (n > nn)
		return 0;
	if (n == 0) {
		/* One symbol, no code: every lookup answers it. */
		c = lh_bits(s, nbit);
		if (c >= nn)
			return 0;
		for (i = 0; i < nn; i++)
			s->pt_len[i] = 0;
		for (i = 0; i < 256u; i++)
			s->pt_table[i] = (uint16_t)c;
		return 1;
	}
	i = 0;
	while (i < n) {
		uint32_t mask;

		c = (uint32_t)s->bitbuf >> 13;
		if (c == 7u) {
			mask = 1u << 12;
			while (mask && (mask & s->bitbuf)) {
				mask >>= 1;
				c++;
			}
			if (c > 16u)
				return 0;
		}
		lh_fill(s, c < 7u ? 3u : c - 3u);
		s->pt_len[i++] = (uint8_t)c;
		if (i_special >= 0 && i == (uint32_t)i_special) {
			c = lh_bits(s, 2);
			while (c-- > 0) {
				if (i >= nn)
					return 0;
				s->pt_len[i++] = 0;
			}
		}
		if (s->eof)
			return 0;
	}
	while (i < nn)
		s->pt_len[i++] = 0;
	return lh_make_table(s, nn, s->pt_len, 8u, s->pt_table);
}

/* The literal/length tree, whose lengths are themselves coded with the pretree
 * - which is why that one is read first. */
static int lh_read_c_len(struct kof_lzhuf *s)
{
	uint32_t i, n;
	int bad = 0;

	n = lh_bits(s, LH_CBIT);
	if (n > KOF_LZHUF_NC)
		return 0;
	if (n == 0) {
		uint32_t c = lh_bits(s, LH_CBIT);

		if (c >= KOF_LZHUF_NC)
			return 0;
		for (i = 0; i < KOF_LZHUF_NC; i++)
			s->c_len[i] = 0;
		for (i = 0; i < 4096u; i++)
			s->c_table[i] = (uint16_t)c;
		return 1;
	}
	i = 0;
	while (i < n) {
		uint32_t c = lh_sym(s, s->pt_table, s->pt_len, KOF_LZHUF_NT,
				    8u, &bad);

		if (bad || s->eof)
			return 0;
		if (c <= 2u) {
			/* A run of zero lengths: one, a short count, or a long
			 * one. The three are what make a sparse tree cheap. */
			if (c == 0u)
				c = 1u;
			else if (c == 1u)
				c = lh_bits(s, 4) + 3u;
			else
				c = lh_bits(s, LH_CBIT) + 20u;
			while (c-- > 0) {
				if (i >= KOF_LZHUF_NC)
					return 0;
				s->c_len[i++] = 0;
			}
		} else {
			s->c_len[i++] = (uint8_t)(c - 2u);
		}
	}
	while (i < KOF_LZHUF_NC)
		s->c_len[i++] = 0;
	return lh_make_table(s, KOF_LZHUF_NC, s->c_len, 12u, s->c_table);
}

/* ---- the decode ---------------------------------------------------------------- */

enum kof_decomp_status kof_lzhuf_decode(struct kof_lzhuf *s,
					enum kof_lzhuf_variant var,
					const uint8_t *in, uint64_t in_len,
					uint64_t out_len,
					kof_lzhuf_sink sink, void *user,
					uint64_t *produced)
{
	uint32_t dict, np, pbit, r = 0;
	uint64_t done = 0;
	int status = KOF_DEC_OK, bad = 0;

	if (produced)
		*produced = 0;
	if (!s || !in || !sink)
		return KOF_DEC_CORRUPT;
	if ((unsigned)var >= (unsigned)KOF_LZHUF_VARIANTS)
		return KOF_DEC_UNSUPPORTED;
	if (!out_len)
		return KOF_DEC_OK;

	dict = lh_var[var].dict;
	np   = lh_var[var].np;
	pbit = lh_var[var].pbit;

	memset(s->dict, 0, dict);
	memset(s->c_len, 0, sizeof s->c_len);
	memset(s->pt_len, 0, sizeof s->pt_len);
	memset(s->left, 0, sizeof s->left);
	memset(s->right, 0, sizeof s->right);
	s->in = in;
	s->in_len = in_len;
	s->in_pos = 0;
	s->bitbuf = 0;
	s->sub = 0;
	s->bitcount = 0;
	s->blocksize = 0;
	s->used = 0;
	s->eof = 0;
	lh_fill(s, 16u);

	while (done < out_len) {
		uint32_t c;

		if (s->blocksize == 0) {
			s->blocksize = lh_bits(s, 16);
			if (s->eof) {
				status = KOF_DEC_TRUNCATED;
				break;
			}
			if (!s->blocksize ||
			    !lh_read_pt_len(s, KOF_LZHUF_NT, LH_TBIT, 3) ||
			    !lh_read_c_len(s) ||
			    !lh_read_pt_len(s, np, pbit, -1)) {
				status = s->eof ? KOF_DEC_TRUNCATED
						: KOF_DEC_CORRUPT;
				break;
			}
		}
		s->blocksize--;

		c = lh_sym(s, s->c_table, s->c_len, KOF_LZHUF_NC, 12u, &bad);
		if (bad) {
			status = KOF_DEC_CORRUPT;
			break;
		}
		if (s->eof) {
			status = KOF_DEC_TRUNCATED;
			break;
		}

		if (c <= 255u) {
			s->dict[r++] = (uint8_t)c;
			done++;
			if (r >= dict) {
				if (!sink(user, s->dict, dict)) {
					status = KOF_DEC_STOPPED;
					break;
				}
				r = 0;
			}
			continue;
		}

		{
			/* A match: how long, then how far back. The position
			 * code names a bucket and the bits inside it follow. */
			uint32_t mlen = c - (256u - LH_THRESHOLD);
			uint32_t j = lh_sym(s, s->pt_table, s->pt_len, np, 8u,
					    &bad);
			uint32_t from;

			if (bad) {
				status = KOF_DEC_CORRUPT;
				break;
			}
			if (j != 0) {
				j--;
				if (j >= 16u) {
					status = KOF_DEC_CORRUPT;
					break;
				}
				j = (1u << j) + lh_bits(s, j);
			}
			if (j >= dict) {
				status = KOF_DEC_CORRUPT;
				break;
			}
			from = r >= j + 1u ? r - j - 1u : r + dict - j - 1u;
			while (mlen-- > 0 && done < out_len) {
				s->dict[r++] = s->dict[from++];
				done++;
				if (from >= dict)
					from = 0;
				if (r >= dict) {
					if (!sink(user, s->dict, dict)) {
						status = KOF_DEC_STOPPED;
						break;
					}
					r = 0;
				}
			}
			if (status != KOF_DEC_OK)
				break;
		}
	}

	if (r && status == KOF_DEC_OK && !sink(user, s->dict, r))
		status = KOF_DEC_STOPPED;
	else if (r && status == KOF_DEC_TRUNCATED)
		(void)sink(user, s->dict, r);   /* what was reached is real */
	if (produced)
		*produced = done;
	if (status == KOF_DEC_OK && done < out_len)
		status = KOF_DEC_TRUNCATED;
	return (enum kof_decomp_status)status;
}
