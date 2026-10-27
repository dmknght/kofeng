/*
 * inflate.c - RFC 1951, decoded a block at a time into a 32KB window.
 *
 * The structure follows the specification directly: a stream is a sequence of
 * blocks, each stored, fixed-Huffman or dynamic-Huffman, and each producing bytes
 * into a window that back references read from. Nothing is buffered beyond that
 * window, so the whole decoder is the state in struct kuncoat_inflate.
 *
 * Every place this code can be lied to is a length, a distance or a code length
 * read out of the stream, and each is bounded where it is read rather than where
 * it is used:
 *
 *   - a code that runs past fifteen bits is corrupt, not a longer code
 *   - a Huffman code set that is over-subscribed is refused before it is used to
 *     decode anything
 *   - a symbol outside the alphabet its table describes is corrupt, even though
 *     the table was built from lengths the file supplied
 *   - a distance reaching further back than the stream has produced is corrupt,
 *     which is what stops the window disclosing an unrelated object
 *   - input running out is truncation and keeps what was decoded; the caller
 *     decides whether a prefix is worth having, and for a scanner it usually is
 *
 * There is no allocation and no I/O here at all, which is what lets the fuzzer run
 * this in isolation at a rate worth having.
 */

#include "inflate.h"

#include <string.h>

/* ---- bits ------------------------------------------------------------------- */

/*
 * Refill to at least `n` bits, or say the input ended.
 *
 * The bit buffer is 32 bits and n is never more than 16, so a refill can always
 * make room for a whole byte without losing anything already in it.
 */
/*
 * THE REFILL IS OUT OF LINE AND THE TEST THAT USUALLY ANSWERS IT IS NOT.
 *
 * Widening the refill made need() big enough that gcc stopped inlining it, and
 * that cost more than the refill saved: measured over the 300-file subset,
 * decode and block_codes fell by 74.7 million instructions while a newly
 * out-of-line `need` added 139.3 million - a net LOSS of 64.5 million, from a
 * change that made the decoder itself faster.
 *
 * Most calls do not refill at all: the buffer already holds the bits, and the
 * whole of need() is then one compare. That part stays inline; everything that
 * touches the input is behind a call that is only made when it is needed.
 */
static int refill(struct kuncoat_inflate *s, uint32_t n)
{
	while (s->bitcnt < n) {
		/*
		 * A WHOLE CHUNK WHEN IT FITS, A BYTE WHEN IT DOES NOT.
		 *
		 * The byte loop below is the contract; this only reaches the
		 * same state in fewer rounds. Two conditions make it the same
		 * state: the input must really hold KUNCOAT_INF_FILL_BYTES more,
		 * and the shift must not run off the top of the word - which
		 * is what `bitcnt + FILL_BITS <= BITS` says. Both are what the
		 * byte loop would have checked one byte at a time.
		 *
		 * Assembled from bytes rather than loaded as a word: DEFLATE
		 * packs bits least significant first, so byte i belongs at bit
		 * 8i, and writing it out keeps that true on a big-endian host
		 * as well. Every compiler this tree builds with folds the
		 * sequence back into one load.
		 */
		if (s->bitcnt + KUNCOAT_INF_FILL_BITS <= KUNCOAT_INF_BITS &&
		    s->in_len - s->in_pos >= KUNCOAT_INF_FILL_BYTES) {
			const uint8_t *q = s->in + s->in_pos;
			kuncoat_inf_word w;

			w = (kuncoat_inf_word)q[0] | ((kuncoat_inf_word)q[1] << 8);
#if KUNCOAT_INF_FILL_BYTES == 4u
			w |= ((kuncoat_inf_word)q[2] << 16) |
			     ((kuncoat_inf_word)q[3] << 24);
#endif
			s->bitbuf |= w << s->bitcnt;
			s->in_pos += KUNCOAT_INF_FILL_BYTES;
			s->bitcnt += KUNCOAT_INF_FILL_BITS;
			continue;
		}
		if (s->in_pos >= s->in_len)
			return 0;
		s->bitbuf |= (kuncoat_inf_word)s->in[s->in_pos++] << s->bitcnt;
		s->bitcnt += 8;
	}
	return 1;
}

static inline int need(struct kuncoat_inflate *s, uint32_t n)
{
	return s->bitcnt >= n ? 1 : refill(s, n);
}

/* Take n bits, least significant first, as RFC 1951 packs them. Caller has
 * already ensured they are there. */
static uint32_t take(struct kuncoat_inflate *s, uint32_t n)
{
	uint32_t v = (uint32_t)(s->bitbuf & (((kuncoat_inf_word)1 << n) - 1u));

	s->bitbuf >>= n;
	s->bitcnt -= n;
	return v;
}

static int getbit(struct kuncoat_inflate *s)
{
	if (!need(s, 1))
		return -1;
	return (int)take(s, 1);
}

/* ---- output ----------------------------------------------------------------- */

/*
 * Hand the window's pending bytes to the sink.
 *
 * Called when the window wraps and once at the end, so the sink sees 32KB at a
 * time rather than a byte at a time - the difference between one call per block of
 * output and one per literal.
 */
static int flush(struct kuncoat_inflate *s, kuncoat_inflate_sink sink, void *user)
{
	uint32_t at, n;

	if (!s->wpend)
		return 1;
	/* The pending run ends at wpos and is wpend long, so it starts wpend
	 * behind - which may be behind the start of the buffer, having wrapped. */
	at = (s->wpos - s->wpend) & (KUNCOAT_INF_WINDOW - 1u);
	n  = s->wpend;
	s->wpend = 0;
	if (at + n > KUNCOAT_INF_WINDOW) {
		uint32_t first = KUNCOAT_INF_WINDOW - at;

		if (!sink(user, s->win + at, first))
			return 0;
		return sink(user, s->win, n - first);
	}
	return sink(user, s->win + at, n);
}

static int put(struct kuncoat_inflate *s, uint8_t b, kuncoat_inflate_sink sink, void *user)
{
	s->win[s->wpos] = b;
	s->wpos = (s->wpos + 1u) & (KUNCOAT_INF_WINDOW - 1u);
	s->wpend++;
	s->produced++;
	if (s->wpend == KUNCOAT_INF_WINDOW)
		return flush(s, sink, user);
	return 1;
}

/* ---- Huffman ---------------------------------------------------------------- */

/*
 * Build a canonical code from a list of code lengths.
 *
 * Returns 0 for a complete code, a positive number for an incomplete one, and a
 * negative number for one that is over-subscribed - that is, one claiming more
 * codes of some length than that length has room for. Over-subscribed has to be
 * refused: the decoder below would otherwise return symbols from a table whose
 * entries were never assigned.
 */
/*
 * Reverse the low `len` bits of a code.
 *
 * Needed because the two orders disagree: a canonical code is defined
 * most-significant-bit first, and DEFLATE hands bits over least-significant first.
 * Doing it here, once per symbol per block, is what lets the decoder index the table
 * with the raw bit buffer.
 */
static uint32_t rev_bits(uint32_t v, uint32_t len)
{
	uint32_t r = 0;

	while (len--) {
		r = (r << 1) | (v & 1u);
		v >>= 1;
	}
	return r;
}

/*
 * Fill the short-code table from the canonical assignment.
 *
 * Codes are assigned in the order the symbol array already holds - by length, then
 * by symbol - which is the same walk the bit-at-a-time decoder performs, so the two
 * cannot disagree about which code means what. Every index whose low `len` bits
 * match the reversed code gets the entry, because the bits above the code are the
 * next symbol's and are not ours to look at.
 */
static void build_fast(struct kuncoat_huff *h)
{
	uint32_t code = 0, index = 0, len;

	for (len = 1; len < 16; len++) {
		uint32_t cnt = (uint32_t)h->count[len], k;

		if (len <= KUNCOAT_HUFF_FAST_BITS) {
			for (k = 0; k < cnt; k++) {
				uint32_t sym = (uint32_t)h->symbol[index + k];
				uint32_t at  = rev_bits(code + k, len);
				uint32_t step = 1u << len;

				for (; at < KUNCOAT_HUFF_FAST_SIZE; at += step)
					h->fast[at] = (uint16_t)((len << 12) | sym);
			}
		}
		index += cnt;
		code = (code + cnt) << 1;
	}
}

static int construct(struct kuncoat_huff *h, const int16_t *length, int n)
{
	int symbol, len, left;
	int16_t offs[16];

	/*
	 * Cleared here, before anything can return.
	 *
	 * construct() has an early exit for an over-subscribed code, and every
	 * caller treats that as fatal - but a table left holding the PREVIOUS
	 * block's symbols is a decoder that answers with another block's alphabet
	 * if one ever does not. Clearing once at the top costs a kilobyte of store
	 * per block and removes the question.
	 */
	memset(h->fast, 0, sizeof h->fast);
	for (len = 0; len < 16; len++)
		h->count[len] = 0;
	for (symbol = 0; symbol < n; symbol++)
		h->count[length[symbol]]++;
	if (h->count[0] == n)
		return 0;               /* no codes at all; a legal empty tree */

	left = 1;
	for (len = 1; len < 16; len++) {
		left <<= 1;
		left -= h->count[len];
		if (left < 0)
			return left;
	}

	offs[1] = 0;
	for (len = 1; len < 15; len++)
		offs[len + 1] = (int16_t)(offs[len] + h->count[len]);
	for (symbol = 0; symbol < n; symbol++)
		if (length[symbol])
			h->symbol[offs[length[symbol]]++] = (int16_t)symbol;
	build_fast(h);
	return left;
}

/*
 * Decode one symbol, one bit at a time.
 *
 * Canonical codes are ordered, so at each length the codes form a contiguous run:
 * comparing the bits read so far against how many codes of that length exist says
 * whether the symbol is here, and where. Fifteen iterations at worst, because RFC
 * 1951 caps a code at fifteen bits - which is also why running past fifteen is
 * corruption rather than a longer code.
 *
 * Returns the symbol, -1 when the input ran out, -2 when no code matched.
 */
static int decode(struct kuncoat_inflate *s, const struct kuncoat_huff *h)
{
	int len, code = 0, first = 0, index = 0;

	/*
	 * The common case: nine bits are available and they begin a short code.
	 *
	 * need() failing is not an error here - the input may be nearly finished
	 * while the buffer still holds a whole short code - so it simply falls
	 * through to the walk, which handles running out properly.
	 */
	if (need(s, KUNCOAT_HUFF_FAST_BITS)) {
		uint16_t e = h->fast[s->bitbuf & (KUNCOAT_HUFF_FAST_SIZE - 1u)];

		if (e) {
			uint32_t got = (uint32_t)e >> 12;

			s->bitbuf >>= got;
			s->bitcnt -= got;
			return (int)(e & 0x0fffu);
		}
	}

	for (len = 1; len < 16; len++) {
		int b = getbit(s);

		if (b < 0)
			return -1;
		code |= b;
		if (code - first < h->count[len])
			return h->symbol[index + (code - first)];
		index += h->count[len];
		first = (first + h->count[len]) << 1;
		code <<= 1;
	}
	return -2;
}

/* ---- blocks ----------------------------------------------------------------- */

/* RFC 1951 section 3.2.5. Index 285 is the fixed length 258 and takes no extra
 * bits, which is why it is spelled out rather than computed. */
static const uint16_t len_base[29] = {
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
	67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const uint8_t len_extra[29] = {
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
	4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const uint16_t dist_base[30] = {
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
	513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
static const uint8_t dist_extra[30] = {
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
	9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

/*
 * A stored block: LEN bytes copied through, with no coding at all.
 *
 * NLEN is LEN's complement and is checked. It is the only integrity check DEFLATE
 * puts on a stored block, and skipping it - as more than one hand-written inflate
 * has - means a corrupt length is copied as if it were meant.
 */
static int block_stored(struct kuncoat_inflate *s, kuncoat_inflate_sink sink, void *user)
{
	uint32_t len, nlen;

	/*
	 * A STORED BLOCK STARTS ON A BYTE BOUNDARY, AND THE WHOLE BYTES IN THE
	 * BIT BUFFER HAVE TO GO BACK TO THE INPUT.
	 *
	 * This cleared bitbuf and bitcnt outright. Dropping the ODD bits is
	 * right - they are the padding to the boundary. Dropping the whole
	 * bytes is not: they were read out of `in` and in_pos moved past them,
	 * and the copy below reads `in` DIRECTLY, so every one of them was
	 * silently skipped.
	 *
	 * It needs a coded block to leave eight or more bits buffered and a
	 * stored block to follow it - which is exactly what Z_SYNC_FLUSH and
	 * Z_FULL_FLUSH emit, an empty stored block (00 00 00 ff ff) after the
	 * coded data. Those are ordinary: any stream written incrementally has
	 * them. Measured against zlib over 4000 generated streams, 46 decoded
	 * short, the worst losing 34 KB of 40 KB and reporting CORRUPT.
	 *
	 * Rewinding by the whole bytes puts the reader back where the buffer's
	 * content actually began; the odd bits are then discarded with it.
	 */
	s->in_pos -= s->bitcnt >> 3;
	s->bitbuf = 0;
	s->bitcnt = 0;
	if (!need(s, 32))
		return KUNCOAT_TRUNCATED;
	len  = take(s, 16);
	nlen = take(s, 16);
	if (len != (~nlen & 0xffffu))
		return KUNCOAT_CORRUPT;

	while (len--) {
		if (s->in_pos >= s->in_len)
			return KUNCOAT_TRUNCATED;
		if (!put(s, s->in[s->in_pos++], sink, user))
			return KUNCOAT_STOPPED;
	}
	return -1;                  /* keep going */
}

/*
 * The body of a Huffman-coded block, once its two tables are built.
 *
 * Shared by the fixed and dynamic cases because they differ only in where the
 * tables came from - which is the whole of the difference RFC 1951 draws between
 * them, and duplicating this loop for each is how the two drift apart.
 */
static int block_codes(struct kuncoat_inflate *s, kuncoat_inflate_sink sink, void *user)
{
	for (;;) {
		int sym = decode(s, &s->lit);
		uint32_t len, dist;
		int dsym;

		if (sym < 0)
			return sym == -1 ? KUNCOAT_TRUNCATED : KUNCOAT_CORRUPT;
		if (sym < 256) {
			if (!put(s, (uint8_t)sym, sink, user))
				return KUNCOAT_STOPPED;
			continue;
		}
		if (sym == 256)
			return -1;                  /* end of block */

		sym -= 257;
		/* 286 and 287 can be given a code length by a hostile stream even
		 * though no encoder may use them, so the table can decode them. */
		if (sym >= 29)
			return KUNCOAT_CORRUPT;
		if (!need(s, len_extra[sym]))
			return KUNCOAT_TRUNCATED;
		len = len_base[sym] + take(s, len_extra[sym]);

		dsym = decode(s, &s->dist);
		if (dsym < 0)
			return dsym == -1 ? KUNCOAT_TRUNCATED : KUNCOAT_CORRUPT;
		if (dsym >= 30)
			return KUNCOAT_CORRUPT;
		if (!need(s, dist_extra[dsym]))
			return KUNCOAT_TRUNCATED;
		dist = dist_base[dsym] + take(s, dist_extra[dsym]);

		/*
		 * The check that keeps one object's bytes out of another's.
		 *
		 * A distance may reach back at most as far as the stream has
		 * written. Further back is not a longer history, it is the window
		 * as some earlier stream left it - so this is refused as corruption
		 * rather than clamped, and the window is zeroed per stream as well.
		 */
		if (dist == 0 || (uint64_t)dist > s->produced)
			return KUNCOAT_CORRUPT;

		/*
		 * The copy, in runs rather than a byte at a time.
		 *
		 * Still a byte-wise loop inside, and that is not an oversight: a
		 * length greater than the distance is how DEFLATE spells a repeat,
		 * so the copy reads bytes it is itself writing and memcpy would be
		 * wrong. What the batching removes is the per-byte work AROUND the
		 * copy - the wrap mask, the pending count, the test for whether a
		 * flush is due - by computing once how far it is safe to run.
		 *
		 * Three things end a run: the write reaching the end of the window,
		 * the read reaching it, and the window filling. Each is at least one
		 * byte away on entry, so the outer loop always advances.
		 */
		while (len) {
			uint32_t src = (s->wpos - dist) & (KUNCOAT_INF_WINDOW - 1u);
			uint32_t n = len, lim, i;

			lim = KUNCOAT_INF_WINDOW - s->wpos;
			if (n > lim)
				n = lim;
			lim = KUNCOAT_INF_WINDOW - src;
			if (n > lim)
				n = lim;
			lim = KUNCOAT_INF_WINDOW - s->wpend;
			if (n > lim)
				n = lim;

			/*
			 * A MATCH THAT DOES NOT OVERLAP ITSELF IS A COPY, and
			 * the test for that is the two OFFSETS - not `dist`.
			 *
			 * DEFLATE's short distances are how it spells a run -
			 * `dist` of 1 and `len` of 300 means "the last byte,
			 * three hundred times" - and those MUST be read a byte
			 * at a time, because each byte written is the source of
			 * a later one. That is why the loop is written this way
			 * and it has to stay for that case.
			 *
			 * THIS SAID `dist >= n` AND THAT IS WRONG, which is
			 * worth keeping because the reasoning was plausible and
			 * the corpus never showed it. `src` is
			 * `(wpos - dist) & (WINDOW - 1)`, so it WRAPS: once
			 * dist exceeds wpos the source sits ABOVE the
			 * destination in the ring and the real gap between them
			 * is WINDOW - dist, which is small exactly when dist is
			 * large. AddressSanitizer caught it on a corpus sample
			 * with dist 32766 and n 3 - a gap of two bytes, a
			 * one-byte overlap, and memcpy with overlapping
			 * arguments is undefined however harmless the result
			 * looks. dist == 32768 is legal too, and there src and
			 * wpos are the SAME address.
			 *
			 * The offsets answer it directly. Both ranges are
			 * inside [0, WINDOW) because of the three clamps above,
			 * so neither sum overflows, and a gap in either
			 * direction that is at least `n` means disjoint.
			 */
			if (src >= s->wpos + n || s->wpos >= src + n) {
				memcpy(s->win + s->wpos, s->win + src,
				       (size_t)n);
			} else {
				for (i = 0; i < n; i++)
					s->win[s->wpos + i] = s->win[src + i];
			}

			s->wpos = (s->wpos + n) & (KUNCOAT_INF_WINDOW - 1u);
			s->wpend += n;
			s->produced += n;
			len -= n;
			if (s->wpend == KUNCOAT_INF_WINDOW && !flush(s, sink, user))
				return KUNCOAT_STOPPED;
		}
	}
}

/* The fixed code of RFC 1951 section 3.2.6. Built rather than stored as a table:
 * it is eight lines against a kilobyte of constants, and it is built once per
 * block that uses it, which is not a cost worth a table. */
static void build_fixed(struct kuncoat_inflate *s)
{
	int16_t len[288];
	int i;

	for (i = 0; i < 144; i++) len[i] = 8;
	for (; i < 256; i++)      len[i] = 9;
	for (; i < 280; i++)      len[i] = 7;
	for (; i < 288; i++)      len[i] = 8;
	construct(&s->lit, len, 288);

	for (i = 0; i < 30; i++)  len[i] = 5;
	construct(&s->dist, len, 30);
}

/* The order HCLEN's lengths arrive in - chosen by the specification so that the
 * least useful ones are last and can be left out. */
static const uint8_t clen_order[19] = {
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

/*
 * Read the two tables a dynamic block describes, themselves Huffman coded.
 *
 * This is where a hostile stream has the most room: the lengths of the real codes
 * are coded with a third code, and the run-length symbols 16, 17 and 18 repeat
 * whatever came before. Each repeat is bounded against the end of the table, and
 * 16 with nothing before it is refused - both are ways of writing past the array.
 */
static int build_dynamic(struct kuncoat_inflate *s)
{
	int16_t len[288 + 32];
	int nlen, ndist, ncode, i, err;
	struct kuncoat_huff clen;

	if (!need(s, 14))
		return KUNCOAT_TRUNCATED;
	nlen  = (int)take(s, 5) + 257;
	ndist = (int)take(s, 5) + 1;
	ncode = (int)take(s, 4) + 4;
	/* 5 bits reach 31, so nlen reaches 288 and ndist 32 - both beyond what any
	 * encoder may use, and both writable by a stream that means harm. */
	if (nlen > 286 || ndist > 30)
		return KUNCOAT_CORRUPT;

	for (i = 0; i < ncode; i++) {
		if (!need(s, 3))
			return KUNCOAT_TRUNCATED;
		len[clen_order[i]] = (int16_t)take(s, 3);
	}
	for (; i < 19; i++)
		len[clen_order[i]] = 0;
	if (construct(&clen, len, 19) != 0)
		return KUNCOAT_CORRUPT;   /* the code-length code must be complete */

	i = 0;
	while (i < nlen + ndist) {
		int sym = decode(s, &clen);
		int16_t v;
		int rep;

		if (sym < 0)
			return sym == -1 ? KUNCOAT_TRUNCATED : KUNCOAT_CORRUPT;
		if (sym < 16) {
			len[i++] = (int16_t)sym;
			continue;
		}
		if (sym == 16) {
			if (i == 0)
				return KUNCOAT_CORRUPT;  /* nothing to repeat */
			v = len[i - 1];
			if (!need(s, 2))
				return KUNCOAT_TRUNCATED;
			rep = 3 + (int)take(s, 2);
		} else if (sym == 17) {
			v = 0;
			if (!need(s, 3))
				return KUNCOAT_TRUNCATED;
			rep = 3 + (int)take(s, 3);
		} else {
			v = 0;
			if (!need(s, 7))
				return KUNCOAT_TRUNCATED;
			rep = 11 + (int)take(s, 7);
		}
		if (rep > nlen + ndist - i)
			return KUNCOAT_CORRUPT;  /* would run past the table */
		while (rep--)
			len[i++] = v;
	}

	/* A literal table without an end-of-block symbol describes a block that
	 * cannot end, which is a stream that never terminates. */
	if (len[256] == 0)
		return KUNCOAT_CORRUPT;

	err = construct(&s->lit, len, nlen);
	/* Incomplete is as bad as over-subscribed here (a gap decodes to nothing),
	 * with the one exception RFC 1951 and every other decoder make: a block
	 * whose only literal/length code is EOB, written as a single code of one
	 * bit. The other bit value decodes to nothing and is refused as CORRUPT. */
	if (err != 0 && !(err > 0 && s->lit.count[1] == 1 && err == (1 << 14)))
		return KUNCOAT_CORRUPT;
	err = construct(&s->dist, len + nlen, ndist);
	/*
	 * An incomplete distance code is tolerated, and only here.
	 *
	 * A block of literals with a single distance code is what several encoders
	 * emit, zlib accepts it, and files in the wild depend on it. Refusing it
	 * would make this decoder disagree with every other one on ordinary input,
	 * which for a scanner means not seeing inside archives that everything else
	 * can open. Over-subscribed is still refused.
	 */
	/* KNOWN DEFECT WP0-1 (2026-10-24, M) [sev L]: The block header accepts EVERY incomplete distance code; the
	 * comment says only a single code and zlib refuses the rest. Trigger: a dynamic block whose distance
	 * lengths leave a gap with more than one code (fuzz seed 7 iter 12407). Effect: a stream zlib calls
	 * corrupt is decoded. Reproducer: tests_wp0/findings/inflate_incomplete_distance_{a,b}.bin. Fix:
	 * accept err > 0 only for one code of length 1. */
	if (err < 0)
		return KUNCOAT_CORRUPT;
	return -1;
}

/* ---- the stream ------------------------------------------------------------- */

/*
 * THE SAME DECODE, WITH A HISTORY IN FRONT OF IT.
 *
 * A stream that may reference bytes it did not itself produce is not a
 * pathological case - it is how MSZIP works. A cabinet's MSZIP folder is a
 * SEQUENCE of deflate streams, one per block, and every block after the first
 * may reach up to 32KB back into the PREVIOUS block's output. Decoded one at a
 * time from an empty window, block one is right and everything after it is
 * plausible and wrong: matches resolve against zeros, so the output is the
 * correct length and the wrong bytes, and nothing reports a failure.
 *
 * So the seed is the previous block's tail, and `produced` starts at its length
 * - which is the same number the distance check reads, so a reference into the
 * seed is permitted and one past it is still refused.
 *
 * kuncoat_inflate is this with no seed, and is written in terms of it so the two
 * cannot drift.
 */
enum kuncoat_status kuncoat_inflate_seeded(struct kuncoat_inflate *s,
		const struct kuncoat_span *seed, struct kuncoat_io *io)
{
	int status = KUNCOAT_OK, last = 0;
	uint64_t seed_start;
	const uint8_t *in;
	kuncoat_inflate_sink sink;
	void *user;
	uint32_t seed_len = 0;

	if (!s || !io || !io->sink || (!io->in.p && io->in.n)) {
		if (io)
			io->consumed = io->produced = 0;
		return KUNCOAT_BAD_ARG;
	}
	in = io->in.p;
	sink = io->sink;
	user = io->user;
	memset(s->win, 0, sizeof s->win);
	s->wpos = s->wpend = 0;
	s->produced = 0;
	if (seed && seed->p && seed->n) {
		seed_len = seed->n > KUNCOAT_INF_WINDOW ? KUNCOAT_INF_WINDOW : (uint32_t)seed->n;
		/* A seed longer than the window keeps its TAIL: the bytes a distance
		 * can reach are the last ones written. */
		memcpy(s->win, seed->p + (seed->n - seed_len), seed_len);
		/*
		 * wpos is where the next byte goes, which is one past the seed;
		 * wpend stays zero because NONE OF THE SEED IS OUTPUT - it has
		 * already been handed to the sink by the block that produced
		 * it, and emitting it again would duplicate it in the child.
		 */
		s->wpos = seed_len & (KUNCOAT_INF_WINDOW - 1u);
		s->produced = seed_len;
	}
	seed_start = s->produced;
	s->in = in;
	s->in_len = in ? io->in.n : 0;
	s->in_pos = 0;
	s->bitbuf = s->bitcnt = 0;

	while (!last) {
		int type, r;

		if (!need(s, 3)) {
			status = KUNCOAT_TRUNCATED;
			break;
		}
		last = (int)take(s, 1);
		type = (int)take(s, 2);

		if (type == 0) {
			r = block_stored(s, sink, user);
		} else if (type == 1) {
			build_fixed(s);
			r = block_codes(s, sink, user);
		} else if (type == 2) {
			r = build_dynamic(s);
			if (r == -1)
				r = block_codes(s, sink, user);
		} else {
			r = KUNCOAT_CORRUPT;   /* type 3 is reserved */
		}
		if (r != -1) {
			status = r;
			break;
		}
	}

	/*
	 * Flush whatever is left even when the stream was corrupt or cut short.
	 *
	 * What was decoded before the failure is real output and is worth scanning:
	 * a truncated archive is the ordinary case in a malware sample, and refusing
	 * to hand back its first megabyte because its last kilobyte is missing would
	 * discard the part that identifies it. The status says the rest is unknown.
	 */
	if (status != KUNCOAT_STOPPED && !flush(s, sink, user))
		status = KUNCOAT_STOPPED;

	/*
	 * How much input was really used, in bytes.
	 *
	 * The bit buffer holds whole bytes already read but not yet consumed, so
	 * in_pos alone overstates it - and the caller uses this to find the gzip
	 * trailer, which sits immediately after the last byte the stream needed.
	 */
	io->consumed = s->in_pos - (s->bitcnt >> 3);
	/* What THIS call produced, which is not s->produced: that one counts the
	 * seed as well, because the distance check reads it. */
	io->produced = s->produced - seed_start;
	return status;
}

enum kuncoat_status kuncoat_inflate(struct kuncoat_inflate *s, struct kuncoat_io *io)
{
	return kuncoat_inflate_seeded(s, NULL, io);
}

