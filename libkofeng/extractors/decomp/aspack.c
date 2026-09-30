/*
 * aspack.c - the ASPack coding. See aspack.h for the format and where it is met.
 *
 * Ported from XVolkolak's xaspack.cpp (MIT); THIRD-PARTY.md says what was taken.
 * Every bound in here is this engine's own: the original runs over an image it
 * owns, and this runs over a caller's buffer with a hostile file behind it.
 */

#include <stdlib.h>
#include <string.h>

#include "aspack.h"


/* 721, 28, 8 and 19 symbols - the four alphabets, largest first. */
#define ASP_A0 721u
#define ASP_A1 28u
#define ASP_A2 8u
#define ASP_A3 19u
#define ASP_LENS 757u          /* A0 + A1 + A2, the code lengths in one run */

struct asp {
	uint32_t bitpos, hash;
	uint32_t init[KOF_ASPACK_OFF_N];

	const uint8_t *in;
	uint64_t n, at;
	uint64_t pad;          /* zero bytes still allowed past the end */
	int      eof;          /* the input ran out, as opposed to being wrong */

	uint32_t d3[4][24], d4[4][24];
	uint32_t size[4];
	uint32_t *starts[4];
	uint8_t  *ends[4];

	uint32_t st0[ASP_A0]; uint8_t en0[0x100];
	uint32_t st1[ASP_A1]; uint8_t en1[0x100];
	uint32_t st2[ASP_A2]; uint8_t en2[0x100];
	uint32_t st3[ASP_A3]; uint8_t en3[0x100];

	int      dict_ok;
	uint8_t  lens[ASP_LENS];       /* the previous block's code lengths */
	uint8_t  a2[ASP_LENS + 1u];    /* this block's, one late - see below */
	uint8_t  a1[ASP_A3];
};

/*
 * Feed the shift register. Past the end of the input it feeds zeroes, for up to
 * KOF_ASPACK_LOOKAHEAD bytes - see the note in aspack.h - and fails after that.
 */
static int asp_fill(struct asp *s)
{
	while (s->bitpos >= 8u) {
		uint32_t b;

		if (s->at < s->n) {
			b = s->in[s->at++];
		} else if (s->pad) {
			s->pad--;
			b = 0;
		} else {
			s->eof = 1;
			return 0;
		}
		s->hash = (s->hash << 8) | b;
		s->bitpos -= 8u;
	}
	return 1;
}

/* `num` is 1 to 7; the caller never asks for more. */
static uint32_t asp_bits(struct asp *s, uint32_t num, int *err)
{
	uint32_t v;

	if (!asp_fill(s)) {
		*err = 1;
		return 0;
	}
	*err = 0;
	v = ((s->hash >> (8u - s->bitpos)) & 0xffffffu) >> (24u - num);
	s->bitpos += num;
	return v & 0xffu;
}

/*
 * One symbol out of alphabet `w`.
 *
 * The code is read most significant bit first out of a 24 bit window. Lengths
 * up to 8 are resolved by a direct table on the top 8 bits; past that the
 * length is found by comparing against the first code of each length, which is
 * what d3 holds, and d4 turns the code back into an index into starts[].
 */
static uint32_t asp_sym(struct asp *s, uint32_t w, int *err)
{
	const uint32_t *d3 = s->d3[w], *d4 = s->d4[w];
	uint32_t ret;
	uint32_t pos;

	*err = 1;
	if (!asp_fill(s))
		return 0;

	ret = (s->hash >> (8u - s->bitpos)) & 0xfffe00u;

	if (ret < d3[8]) {
		if ((ret >> 16) >= 0x100u)
			return 0;
		pos = s->ends[w][ret >> 16];
		if (!pos || pos >= 24u)
			return 0;
	} else if (ret < d3[10]) {
		pos = ret < d3[9] ? 9u : 10u;
	} else if (ret < d3[11]) {
		pos = 11u;
	} else if (ret < d3[12]) {
		pos = 12u;
	} else if (ret < d3[13]) {
		pos = 13u;
	} else if (ret < d3[14]) {
		pos = 14u;
	} else {
		pos = 15u;
	}

	s->bitpos += pos;
	ret = ((ret - d3[pos - 1u]) >> (24u - pos)) + d4[pos];
	if (ret >= s->size[w])
		return 0;
	*err = 0;
	return s->starts[w][ret];
}

/*
 * Turn a run of code lengths into the two lookup tables for alphabet `w`.
 *
 * Canonical Huffman, built from the longest code down, and the check that
 * earns its place is the last one: the codes must fill the space exactly. A
 * table that does not is a stream this decoder would otherwise walk off the end
 * of, and on a hostile file that is the whole attack.
 */
static int asp_build(struct asp *s, const uint8_t *len, uint32_t w)
{
	uint32_t bus[18], dict[18];
	uint32_t *d3 = s->d3[w], *d4 = s->d4[w];
	uint32_t i, counter = 23u, sum = 0, endoff = 0;
	uint32_t n = s->size[w];

	memset(bus, 0, sizeof bus);
	memset(dict, 0, sizeof dict);

	for (i = 0; i < n; i++) {
		if (len[i] > 17u)
			return 0;
		bus[len[i]]++;
	}

	d3[0] = 0;
	d4[0] = 0;
	i = 0;
	while (counter >= 9u) {
		sum += bus[i + 1u] << counter;
		if (sum > 0x1000000u)
			return 0;
		d3[i + 1u] = sum;
		d4[i + 1u] = dict[i + 1u] = bus[i] + d4[i];

		if (counter >= 0x10u) {
			uint32_t old = endoff, rem;

			endoff = d3[i + 1u] >> 0x10;
			if (endoff < old)
				return 0;
			rem = endoff - old;
			if (rem) {
				if (old + rem > 0x100u)
					return 0;
				memset(s->ends[w] + old, (int)(i + 1u), rem);
			}
		}
		i++;
		counter--;
	}
	if (sum != 0x1000000u)
		return 0;

	for (i = 0; i < n; i++) {
		uint32_t l = len[i];

		if (!l)
			continue;
		if (l > 17u || dict[l] >= n)
			return 0;
		s->starts[w][dict[l]] = i;
		dict[l]++;
	}
	return 1;
}

/*
 * Read the three alphabets that describe the block.
 *
 * The code lengths are themselves Huffman coded, by a fourth alphabet whose 19
 * lengths are four bits each - that part is DEFLATE's arrangement exactly. What
 * is not DEFLATE: a length is stored as a DELTA from the same position in the
 * previous block's table, modulo 16, and the first bit of the block says
 * whether that table is carried over or zeroed. So a block cannot be decoded
 * without the one before it, which is why a caller must start at the first.
 *
 * `a2` is filled from index 1 and copied back to `lens` from index 1, because
 * the delta at position i reads `lens[i]` while writing `a2[i + 1]` - the
 * source and the destination are the same run offset by one, and writing in
 * place would read what this loop had just written.
 */
static int asp_dicts(struct asp *s)
{
	uint32_t c, v;
	int oob;

	v = asp_bits(s, 1u, &oob);
	if (oob)
		return 0;
	if (!v)
		memset(s->lens, 0, sizeof s->lens);

	for (c = 0; c < ASP_A3; c++) {
		s->a1[c] = (uint8_t)asp_bits(s, 4u, &oob);
		if (oob)
			return 0;
	}
	if (!asp_build(s, s->a1, 3u))
		return 0;

	c = 0;
	while (c < ASP_LENS) {
		uint32_t ret = asp_sym(s, 3u, &oob);

		if (oob)
			return 0;
		if (ret < 16u) {
			s->a2[1u + c] = (uint8_t)((s->lens[c] + ret) & 0xfu);
			c++;
			continue;
		}
		if (ret == 16u) {
			ret = 3u + asp_bits(s, 2u, &oob);
			if (oob)
				return 0;
			for (; ret && c < ASP_LENS; ret--, c++)
				s->a2[1u + c] = s->a2[c];
			continue;
		}
		if (ret == 17u)
			ret = 3u + asp_bits(s, 3u, &oob);
		else
			ret = 11u + asp_bits(s, 7u, &oob);
		if (oob)
			return 0;
		for (; ret && c < ASP_LENS; ret--, c++)
			s->a2[1u + c] = 0;
	}

	if (!asp_build(s, &s->a2[1], 0u) ||
	    !asp_build(s, &s->a2[1u + ASP_A0], 1u) ||
	    !asp_build(s, &s->a2[1u + ASP_A0 + ASP_A1], 2u))
		return 0;

	/*
	 * WHETHER THE OFFSET ALPHABET IS IN USE. All eight lengths equal to 3
	 * is the flat code the packer writes when it never coded an offset
	 * through that alphabet, and then the low three bits of an offset are
	 * read raw instead. Getting this backwards decodes every match to the
	 * wrong place and nothing else complains.
	 */
	s->dict_ok = 0;
	for (c = 0; c < ASP_A2; c++) {
		if (s->a2[1u + ASP_A0 + ASP_A1 + c] != 3u) {
			s->dict_ok = 1;
			break;
		}
	}

	memcpy(s->lens, &s->a2[1], ASP_LENS);
	return 1;
}

/*
 * The symbol loop.
 *
 *   < 256    a literal
 *   < 720    a match: (sym - 256) >> 3 is the offset class and the low three
 *            bits are the length, with 7 meaning "longer, read an escape"
 *   >= 720   rebuild the alphabets and carry on in the same block
 *
 * `hist` is the four most recent offsets. An offset class below 3 names one of
 * them rather than a distance, and using one moves it to the front - LZMA's
 * arrangement, arrived at independently or borrowed, and the reason a decoder
 * that ignores it produces a file that is almost right.
 */
static int asp_run(struct asp *s, uint64_t size, uint8_t *out, uint64_t *done)
{
	const uint8_t *tab = kof_aspack_tab;
	uint32_t hist[4] = { 0, 0, 0, 0 };
	uint64_t at = 0;
	int oob;

	while (at < size) {
		*done = at;
		uint32_t sym = asp_sym(s, 0u, &oob);
		uint32_t cls, len, use, wide;

		if (oob)
			return 0;
		if (sym < 256u) {
			out[at++] = (uint8_t)sym;
			continue;
		}
		if (sym >= 720u) {
			if (!asp_dicts(s))
				return 0;
			continue;
		}

		cls = (sym - 256u) >> 3;
		len = ((sym - 256u) & 7u) + 2u;
		if (len == 9u) {                   /* the escape: 7 + 2 */
			uint32_t e = asp_sym(s, 1u, &oob);
			uint32_t extra;

			if (oob || e >= 0x56u)
				return 0;
			extra = tab[e + 0x1cu];
			if (!asp_fill(s))
				return 0;
			len += tab[e] +
			       ((((s->hash >> (8u - s->bitpos)) & 0xffffffu) >>
				 (0x18u - extra)));
			s->bitpos += extra;
		}

		use = s->init[cls];
		wide = tab[cls + KOF_ASPACK_OFF_BASE];
		if (!s->dict_ok || wide < 3u) {
			if (!asp_fill(s))
				return 0;
			use += ((s->hash >> (8u - s->bitpos)) & 0xffffffu) >>
			       (24u - wide);
			s->bitpos += wide;
		} else {
			uint32_t low;

			wide -= 3u;
			if (!asp_fill(s))
				return 0;
			use += (((s->hash >> (8u - s->bitpos)) & 0xffffffu) >>
				(24u - wide)) * 8u;
			s->bitpos += wide;
			low = asp_sym(s, 2u, &oob);
			if (oob)
				return 0;
			use += low;
		}

		if (use < 3u) {
			cls = hist[use];
			if (use) {
				hist[use] = hist[0];
				hist[0] = cls;
			}
		} else {
			hist[2] = hist[1];
			hist[1] = hist[0];
			hist[0] = cls = use - 3u;
		}

		cls++;
		if (!cls || (uint64_t)cls > at || (uint64_t)len > size - at)
			return 0;
		while (len--) {
			out[at] = out[at - cls];
			at++;
		}
	}
	*done = at;
	return 1;
}

enum kof_decomp_status kof_aspack_decode(const uint8_t *in, uint64_t in_len,
					 uint8_t *out, uint64_t out_cap,
					 uint64_t *produced)
{
	struct asp *s;
	uint64_t made = 0;
	uint32_t i, j;
	int ok, eof;

	if (produced)
		*produced = 0;
	if (!in || !out || !out_cap || !in_len)
		return KOF_DEC_CORRUPT;

	s = calloc(1, sizeof *s);
	if (!s)
		return KOF_DEC_CORRUPT;

	s->starts[0] = s->st0; s->ends[0] = s->en0; s->size[0] = ASP_A0;
	s->starts[1] = s->st1; s->ends[1] = s->en1; s->size[1] = ASP_A1;
	s->starts[2] = s->st2; s->ends[2] = s->en2; s->size[2] = ASP_A2;
	s->starts[3] = s->st3; s->ends[3] = s->en3; s->size[3] = ASP_A3;

	/* The base distance of each offset class, from the width table. */
	for (i = 0, j = 0; i < KOF_ASPACK_OFF_N; i++) {
		s->init[i] = j;
		j += 1u << kof_aspack_tab[KOF_ASPACK_OFF_BASE + i];
	}

	s->in = in;
	s->n = in_len;
	s->at = 0;
	s->pad = KOF_ASPACK_LOOKAHEAD;
	s->hash = 0x10000u;
	s->bitpos = 0x20u;

	/*
	 * WHAT WAS WRITTEN IS REPORTED WHATEVER HAPPENS, which is the contract
	 * every decoder here keeps and the one that is easy to break: a stream
	 * that fails half way has still filled half the buffer, and a caller
	 * told nothing was produced would hand those bytes on as untouched.
	 * decomp_fuzz checks exactly this - it fills the buffer with a marker
	 * and looks for a write past `produced`.
	 */
	ok = asp_dicts(s) && asp_run(s, out_cap, out, &made);
	eof = s->eof;
	free(s);
	if (produced)
		*produced = made;
	if (ok)
		return KOF_DEC_OK;
	/*
	 * Running out of input is a statement about the file being cut short;
	 * anything else is a statement about the coding. broken_of_status
	 * sends the two different places, so they are told apart here rather
	 * than collapsed into "did not work".
	 */
	return eof ? KOF_DEC_TRUNCATED : KOF_DEC_CORRUPT;
}

/*
 * The call/jmp filter, undone.
 *
 * ASPack rewrote `E8/E9 rel32` as `E8/E9` followed by the absolute target
 * stored big-endian, and marked each one it touched by making the first operand
 * byte a value it chose per file. Turning it back is a rotate and a subtract of
 * the instruction's own position.
 *
 * `k += 4` after a rewrite so a rewritten operand is not scanned for a second
 * marker - the four bytes it left behind can begin with E8 as easily as
 * anything else.
 */
void kof_aspack_e8e9_decode(uint8_t *buf, uint64_t n, uint8_t mark)
{
	uint64_t k = 0;

	if (!buf || n < 7u)
		return;
	while (k < n - 6u) {
		if ((buf[k] == 0xe8u || buf[k] == 0xe9u) &&
		    buf[k + 1u] == mark) {
			uint8_t *w = buf + k + 1u;
			uint32_t t = (uint32_t)w[0] | ((uint32_t)w[1] << 8) |
				     ((uint32_t)w[2] << 16) |
				     ((uint32_t)w[3] << 24);

			t &= 0xffffff00u;
			t = (t << 24) | (t >> 8);     /* rol 24 */
			t -= (uint32_t)k;
			w[0] = (uint8_t)t;
			w[1] = (uint8_t)(t >> 8);
			w[2] = (uint8_t)(t >> 16);
			w[3] = (uint8_t)(t >> 24);
			k += 4u;
		}
		k++;
	}
}
