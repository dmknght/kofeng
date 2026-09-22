/*
 * lzx.c - the decoder described in lzx.h.
 *
 * Written from the format. The three things a reader of this file should know
 * before the code makes sense:
 *
 *   1. BITS COME OUT OF 16 BIT LITTLE ENDIAN WORDS, most significant bit first.
 *      So the byte pair 0x34 0x12 is the sixteen bits of 0x1234, read from the
 *      top. Everything else here is ordinary.
 *
 *   2. A BLOCK'S TREES ARE A DIFFERENCE from the previous block's. The lengths
 *      survive between blocks in the state, and a block sends, per symbol, how
 *      far its length moved - which is why `main_len` and its siblings are
 *      cleared once per STREAM and never per block.
 *
 *   3. THE LAST THREE MATCH OFFSETS ARE PART OF THE STATE. Position slots 0, 1
 *      and 2 name them instead of encoding a distance, and using one reorders
 *      them. A decoder that resets them at a block boundary decodes the first
 *      block correctly and drifts afterwards.
 *
 * EVERYTHING THAT COMES OUT OF THE STREAM IS BOUNDED BEFORE IT IS USED: the
 * block size, every code length, every match offset against what the window
 * holds, and every symbol against the tree it came from. A stream that asks for
 * a distance further back than has been produced is refused rather than served
 * from whatever the window happens to hold, which is the same rule inflate.c
 * states for the same reason.
 */

#include <string.h>

#include "lzx.h"

#define LZX_MIN_MATCH     2u
#define LZX_NUM_CHARS   256u
#define LZX_BLOCK_VERBATIM 1u
#define LZX_BLOCK_ALIGNED  2u
#define LZX_BLOCK_UNCOMP   3u
#define LZX_PRIMARY_LENS   7u
#define LZX_FRAME      KOF_LZX_FRAME

/* ---- the bit reader ----------------------------------------------------------
 *
 * Sixteen bits at a time, most significant first - see the note at the top. The
 * buffer holds at most 32 bits, so a request of 17 or more is filled in two
 * steps by the caller (only the 32 bit fields need that).
 */
static void lzx_fill(struct kof_lzx *s)
{
	while (s->bitcnt <= 16u) {
		uint32_t w;

		if (s->in_pos + 2u > s->in_len) {
			/*
			 * Past the end, feed zeroes and COUNT THEM: a stream
			 * that ends mid symbol is truncated, which the caller
			 * is told by the status rather than by a decode that
			 * wanders. Reaching the end is not itself truncation -
			 * see `pad` in lzx.h - so eof is left for whoever
			 * actually takes one of these bits.
			 */
			s->pad += 16u;
			s->bitcnt += 16u;
			continue;
		}
		w = (uint32_t)s->in[s->in_pos] |
		    ((uint32_t)s->in[s->in_pos + 1u] << 8);
		s->in_pos += 2u;
		s->bitbuf |= w << (16u - s->bitcnt);
		s->bitcnt += 16u;
	}
}

/* Whatever was just consumed came off the real bits first, so the pad can
 * never be more than what is left. Where it would be, the difference is bits
 * that were taken FROM the pad - which is the one thing that means truncated. */
static void lzx_took(struct kof_lzx *s)
{
	if (s->pad > s->bitcnt) {
		s->pad = s->bitcnt;
		s->eof = 1;
	}
}

static uint32_t lzx_bits(struct kof_lzx *s, uint32_t n)
{
	uint32_t v;

	if (!n)
		return 0;
	lzx_fill(s);
	if (s->bitcnt - s->pad < n)
		s->eof = 1;
	v = s->bitbuf >> (32u - n);
	s->bitbuf <<= n;
	s->bitcnt -= n;
	lzx_took(s);
	return v;
}

/*
 * THE BITSTREAM IS REALIGNED AT THE END OF EVERY 32KB FRAME, and this is the
 * rule that makes an otherwise correct decoder produce one good frame and
 * rubbish afterwards.
 *
 * LZX is framed: output is counted in 32768 byte frames, and at each boundary
 * the encoder pads to the next 16 bit word before continuing. A decoder that
 * reads straight through is a few bits out from the second frame onward - it
 * keeps decoding, because a bit stream almost always decodes into SOMETHING,
 * and the bytes are wrong from there. Measured on a real help file: correct for
 * 32768 bytes, then wrong, then refused as corrupt 2185 bytes later.
 */
static void lzx_align_frame(struct kof_lzx *s)
{
	uint32_t r = s->bitcnt & 15u;

	if (r) {
		s->bitbuf <<= r;
		s->bitcnt -= r;
		lzx_took(s);
	}
}

static void lzx_skip(struct kof_lzx *s, uint32_t n)
{
	s->bitbuf <<= n;
	s->bitcnt -= n;
	lzx_took(s);
}

/* ---- canonical Huffman ------------------------------------------------------- */

static int lzx_build(struct kof_lzx_huff *h, const uint8_t *len, uint32_t n)
{
	uint32_t i;
	int16_t offs[18];
	int left;

	for (i = 0; i < 18u; i++)
		h->count[i] = 0;
	for (i = 0; i < n; i++)
		h->count[len[i]]++;
	if (h->count[0] == (int16_t)n)
		return 1;              /* an empty tree: legal, never read */

	/* Over-subscribed or incomplete: a set of lengths that is not a code.
	 * Refused here rather than producing symbols nobody encoded. */
	left = 1;
	for (i = 1; i < 18u; i++) {
		left <<= 1;
		left -= h->count[i];
		if (left < 0)
			return 0;
	}

	offs[1] = 0;
	for (i = 1; i < 17u; i++)
		offs[i + 1] = (int16_t)(offs[i] + h->count[i]);
	for (i = 0; i < n; i++)
		if (len[i])
			h->symbol[offs[len[i]]++] = (int16_t)i;
	return 1;
}

/* One symbol, walked a bit at a time. `*bad` is set when the code runs past
 * the longest length the format allows, which is a stream that does not match
 * the tree it sent. */
static uint32_t lzx_sym(struct kof_lzx *s, const struct kof_lzx_huff *h, int *bad)
{
	int32_t code = 0, first = 0, index = 0;
	uint32_t l;

	for (l = 1; l < 17u; l++) {
		code |= (int32_t)lzx_bits(s, 1);
		if (code - first < h->count[l])
			return (uint32_t)h->symbol[index + (code - first)];
		index += h->count[l];
		first = (first + h->count[l]) << 1;
		code <<= 1;
	}
	*bad = 1;
	return 0;
}

/* ---- the position slot tables ------------------------------------------------
 *
 * Built rather than written out: the two tables are defined by a rule - the
 * footer width grows by one every two slots and stops at seventeen, and a
 * slot's base is the sum of every footer before it - and a hand copy of fifty
 * numbers is a hand copy.
 */
static void lzx_slots(uint32_t *base, uint8_t *extra)
{
	uint32_t i, j = 0, at = 0;

	for (i = 0; i < 51u; i += 2u) {
		extra[i] = (uint8_t)j;
		if (i + 1u < 51u)
			extra[i + 1u] = (uint8_t)j;
		if (i != 0 && j < 17u)
			j++;
	}
	for (i = 0; i < 51u; i++) {
		base[i] = at;
		at += 1u << extra[i];
	}
}

/* How many position slots a window of this size has - the table the format
 * fixes, and the one number that cannot be derived from the others. */
static uint32_t lzx_num_slots(uint32_t bits)
{
	switch (bits) {
	case 15: return 30u;
	case 16: return 32u;
	case 17: return 34u;
	case 18: return 36u;
	case 19: return 38u;
	case 20: return 42u;
	default: return 50u;       /* 21 */
	}
}

/* ---- the delta coded lengths -------------------------------------------------
 *
 * A block states its trees as a difference from the previous block's, through a
 * pretree of twenty four-bit lengths. Codes 17, 18 and 19 are runs; anything
 * else is "this length moved by that much, modulo 17".
 */
static int lzx_read_lengths(struct kof_lzx *s, uint8_t *len, uint32_t first,
			    uint32_t last)
{
	uint8_t pre[KOF_LZX_PRETREE_MAX];
	uint32_t i;
	int bad = 0;

	for (i = 0; i < KOF_LZX_PRETREE_MAX; i++)
		pre[i] = (uint8_t)lzx_bits(s, 4);
	if (!lzx_build(&s->pre_h, pre, KOF_LZX_PRETREE_MAX))
		return 0;

	i = first;
	while (i < last) {
		uint32_t sym = lzx_sym(s, &s->pre_h, &bad);
		uint32_t run, k;

		if (bad || s->eof)
			return 0;
		if (sym == 17u) {
			run = lzx_bits(s, 4) + 4u;
			for (k = 0; k < run && i < last; k++)
				len[i++] = 0;
		} else if (sym == 18u) {
			run = lzx_bits(s, 5) + 20u;
			for (k = 0; k < run && i < last; k++)
				len[i++] = 0;
		} else if (sym == 19u) {
			uint32_t sym2;

			run = lzx_bits(s, 1) + 4u;
			sym2 = lzx_sym(s, &s->pre_h, &bad);
			if (bad || sym2 > 16u)
				return 0;
			{
				int v = (int)len[i] - (int)sym2;

				if (v < 0)
					v += 17;
				for (k = 0; k < run && i < last; k++)
					len[i++] = (uint8_t)v;
			}
		} else if (sym <= 16u) {
			int v = (int)len[i] - (int)sym;

			if (v < 0)
				v += 17;
			len[i++] = (uint8_t)v;
		} else {
			return 0;
		}
	}
	return 1;
}

/* ---- output -------------------------------------------------------------------
 *
 * The window is the output: a match copies from it, so nothing can be handed to
 * the sink and forgotten. What leaves the window is a FRAME at a time, because
 * E8 translation works in frames - see lzx_flush.
 */
struct lzx_out {
	kof_lzx_sink sink;
	void    *user;
	uint64_t skip, take;      /* the slice the caller asked for */
	uint64_t seen;            /* decoded so far, before the slice is cut */
	uint64_t given;
	int      stopped;
};

/*
 * E8 TRANSLATION, UNDONE - the transform LZX applies to the OUTPUT and not part
 * of the coding at all.
 *
 * A compressor that was told the stream carries x86 code rewrites the four
 * bytes after every 0xE8 - the call opcode - from a target relative to the
 * instruction into one relative to the start of the file, which makes the same
 * call from different places compress to the same bytes. Undoing it turns them
 * back.
 *
 * WHY IT IS WORTH DOING RATHER THAN REPORTING. A cabinet's LZX folders carry
 * executables and the translation is on in every one of them, so without this a
 * scanner reads code with four bytes wrong at every call site - which is
 * exactly where a byte pattern over code would be looking.
 *
 * THE BOUNDS ARE THE FORMAT'S, and each is load bearing: only the first
 * 2^30 bytes of output are translated, only frames longer than ten bytes are
 * scanned, only the first `n - 10` bytes of a frame are looked at, and a target
 * is rewritten only when it falls inside the declared file size. A decoder that
 * translates outside any of those corrupts bytes a compressor never touched.
 */
static void lzx_e8(uint8_t *d, uint32_t n, uint64_t frame_at, uint32_t fsize)
{
	int64_t curpos = (int64_t)frame_at;
	uint32_t i = 0;

	if (n <= 10u)
		return;
	while (i < n - 10u) {
		int64_t abs_off;

		if (d[i++] != 0xe8u) {
			curpos++;
			continue;
		}
		abs_off = (int32_t)((uint32_t)d[i] |
				    ((uint32_t)d[i + 1u] << 8) |
				    ((uint32_t)d[i + 2u] << 16) |
				    ((uint32_t)d[i + 3u] << 24));
		if (abs_off >= -curpos && abs_off < (int64_t)fsize) {
			uint32_t rel = abs_off >= 0
				     ? (uint32_t)(abs_off - curpos)
				     : (uint32_t)(abs_off + (int64_t)fsize);

			d[i]      = (uint8_t)rel;
			d[i + 1u] = (uint8_t)(rel >> 8);
			d[i + 2u] = (uint8_t)(rel >> 16);
			d[i + 3u] = (uint8_t)(rel >> 24);
		}
		i += 4u;
		curpos += 5;
	}
}

static int lzx_emit(struct lzx_out *o, const uint8_t *p, uint32_t n)
{
	uint32_t at = 0;

	if (o->skip) {
		uint64_t drop = o->skip < n ? o->skip : n;

		o->skip -= drop;
		at = (uint32_t)drop;
	}
	while (at < n && o->take) {
		uint32_t give = n - at;

		if ((uint64_t)give > o->take)
			give = (uint32_t)o->take;
		if (!o->sink(o->user, p + at, give)) {
			o->stopped = 1;
			return 0;
		}
		o->given += give;
		o->take -= give;
		at += give;
	}
	return 1;
}

/*
 * WHAT HAS BEEN DECODED SINCE THE LAST FLUSH, out of the window and on to the
 * sink - a frame at a time, because that is the unit a translated stream is
 * rewritten in.
 *
 * `flushed` counts output, not window positions: the window wraps and the
 * output does not, and the difference between the two is how many bytes are
 * owed. At most one frame is ever owed, since this is called at every boundary.
 */
static int lzx_flush(struct kof_lzx *s, struct lzx_out *o, uint64_t *flushed,
		     int intel, uint32_t fsize)
{
	uint32_t n = (uint32_t)(o->seen - *flushed);
	uint32_t src, k;

	if (!n)
		return 1;
	src = (s->wpos - n) & s->wmask;
	for (k = 0; k < n; k++)
		s->frame[k] = s->win[(src + k) & s->wmask];
	/* Only the first 2^30 bytes of a stream are translated - 32768 frames,
	 * which is what the format bounds it at. */
	if (intel && *flushed < ((uint64_t)LZX_FRAME * 32768u))
		lzx_e8(s->frame, n, *flushed, fsize);
	*flushed = o->seen;
	return lzx_emit(o, s->frame, n);
}

/* ---- the decode --------------------------------------------------------------- */

enum kof_decomp_status kof_lzx_decode(struct kof_lzx *s, uint32_t window_bits,
				      const uint8_t *in, uint64_t in_len,
				      uint64_t skip, uint64_t take,
				      kof_lzx_sink sink, void *user,
				      uint64_t *produced)
{
	uint32_t base[51], slots;
	uint8_t  extra[51];
	struct lzx_out out;
	uint64_t want;
	uint64_t flushed = 0;        /* output already handed on */
	uint32_t fsize = 0;          /* what the header says the file comes to */
	int status = KOF_DEC_OK, bad = 0, intel = 0;

	if (produced)
		*produced = 0;
	if (!s || !in || !sink)
		return KOF_DEC_CORRUPT;
	if (window_bits < KOF_LZX_MIN_BITS || window_bits > KOF_LZX_MAX_BITS)
		return KOF_DEC_UNSUPPORTED;

	memset(s->win, 0, (size_t)1u << window_bits);
	s->wpos = 0;
	s->wmask = (1u << window_bits) - 1u;
	memset(s->main_len, 0, sizeof s->main_len);
	memset(s->len_len, 0, sizeof s->len_len);
	memset(s->align_len, 0, sizeof s->align_len);
	s->r0 = s->r1 = s->r2 = 1;
	s->in = in;
	s->in_len = in_len;
	s->in_pos = 0;
	s->bitbuf = 0;
	s->bitcnt = 0;
	s->pad = 0;
	s->eof = 0;

	lzx_slots(base, extra);
	slots = lzx_num_slots(window_bits);

	memset(&out, 0, sizeof out);
	out.sink = sink;
	out.user = user;
	out.skip = skip;
	out.take = take;
	want = skip + take;

	/*
	 * THE STREAM'S ONE HEADER BIT: whether x86 call targets were rewritten,
	 * and against what length. Read once, before any block.
	 */
	if (lzx_bits(s, 1)) {
		uint32_t hi = lzx_bits(s, 16), lo = lzx_bits(s, 16);

		fsize = (hi << 16) | lo;
		/*
		 * A size of zero means the compressor set the bit and then
		 * translated nothing, which is a real thing for a stream that
		 * turned out to carry no code. Undoing nothing is then exactly
		 * right, and the flag is what says so.
		 */
		intel = fsize != 0;
	}

	while (out.take && status == KOF_DEC_OK) {
		uint32_t btype, bsize, i;

		if (s->eof) {
			status = KOF_DEC_TRUNCATED;
			break;
		}
		btype = lzx_bits(s, 3);
		bsize = lzx_bits(s, 16) << 8;
		bsize |= lzx_bits(s, 8);
		/*
		 * THE END OF THE INPUT, and it is checked here and not only at
		 * the top of the loop: a caller asking for more than the stream
		 * holds arrives with the buffer exactly empty, reads a header
		 * made of the zeroes fed past the end, and would otherwise be
		 * told the stream is CORRUPT rather than that it ran out. That
		 * is the ordinary case for a file cut at a reset interval,
		 * where the next interval's bytes are a separate range.
		 */
		if (s->eof) {
			status = KOF_DEC_TRUNCATED;
			break;
		}
		if (!bsize) {
			status = KOF_DEC_CORRUPT;
			break;
		}

		if (btype == LZX_BLOCK_UNCOMP) {
			/* Byte aligned from here, with the three offsets
			 * restated in the clear. */
			if (s->bitcnt & 15u)
				lzx_skip(s, s->bitcnt & 15u);
			/* The rewind below gives back what the reader ran
			 * ahead by, and zeroes fed past the end were never
			 * taken from the input - so there is nothing to give
			 * back and nothing left to read either. */
			if (s->pad) {
				status = KOF_DEC_TRUNCATED;
				break;
			}
			s->in_pos -= (s->bitcnt >> 3);
			s->bitbuf = s->bitcnt = 0;
			if (s->in_pos + 12u > s->in_len) {
				status = KOF_DEC_TRUNCATED;
				break;
			}
			s->r0 = (uint32_t)s->in[s->in_pos] |
				((uint32_t)s->in[s->in_pos + 1] << 8) |
				((uint32_t)s->in[s->in_pos + 2] << 16) |
				((uint32_t)s->in[s->in_pos + 3] << 24);
			s->r1 = (uint32_t)s->in[s->in_pos + 4] |
				((uint32_t)s->in[s->in_pos + 5] << 8) |
				((uint32_t)s->in[s->in_pos + 6] << 16) |
				((uint32_t)s->in[s->in_pos + 7] << 24);
			s->r2 = (uint32_t)s->in[s->in_pos + 8] |
				((uint32_t)s->in[s->in_pos + 9] << 8) |
				((uint32_t)s->in[s->in_pos + 10] << 16) |
				((uint32_t)s->in[s->in_pos + 11] << 24);
			s->in_pos += 12u;
			if (bsize > s->in_len - s->in_pos) {
				status = KOF_DEC_TRUNCATED;
				bsize = (uint32_t)(s->in_len - s->in_pos);
			}
			/*
			 * INTO THE WINDOW AND OUT AT THE FRAME BOUNDARY, the
			 * same as every other path here - not straight to the
			 * sink. An uncompressed block is still output, so it
			 * is still counted in frames and still translated;
			 * handing it over a byte at a time both emitted it
			 * twice and left the flush owing a whole block.
			 */
			for (i = 0; i < bsize; i++) {
				s->win[s->wpos] = s->in[s->in_pos + i];
				s->wpos = (s->wpos + 1u) & s->wmask;
				out.seen++;
				if (!(out.seen & (LZX_FRAME - 1u))) {
					lzx_align_frame(s);
					if (!lzx_flush(s, &out, &flushed,
						       intel, fsize))
						break;
				}
			}
			s->in_pos += bsize;
			if (bsize & 1u)
				s->in_pos++;      /* padded to a word */
			if (out.stopped)
				break;
			continue;
		}

		if (btype != LZX_BLOCK_VERBATIM && btype != LZX_BLOCK_ALIGNED) {
			status = KOF_DEC_CORRUPT;
			break;
		}

		if (btype == LZX_BLOCK_ALIGNED) {
			for (i = 0; i < KOF_LZX_ALIGN_MAX; i++)
				s->align_len[i] = (uint8_t)lzx_bits(s, 3);
			if (!lzx_build(&s->align_h, s->align_len,
				       KOF_LZX_ALIGN_MAX)) {
				status = KOF_DEC_CORRUPT;
				break;
			}
		}
		/* The main tree arrives in two halves - the literals, then the
		 * match headers - each delta coded against the same table. */
		if (!lzx_read_lengths(s, s->main_len, 0, LZX_NUM_CHARS) ||
		    !lzx_read_lengths(s, s->main_len, LZX_NUM_CHARS,
				      LZX_NUM_CHARS + slots * 8u) ||
		    !lzx_build(&s->main_h, s->main_len,
			       LZX_NUM_CHARS + slots * 8u)) {
			status = KOF_DEC_CORRUPT;
			break;
		}
		if (!lzx_read_lengths(s, s->len_len, 0, KOF_LZX_LEN_MAX) ||
		    !lzx_build(&s->len_h, s->len_len, KOF_LZX_LEN_MAX)) {
			status = KOF_DEC_CORRUPT;
			break;
		}

		for (i = 0; i < bsize && out.take && !out.stopped; ) {
			uint32_t sym = lzx_sym(s, &s->main_h, &bad);
			uint32_t mlen, slot, off;

			if (bad || s->eof) {
				status = s->eof ? KOF_DEC_TRUNCATED
						: KOF_DEC_CORRUPT;
				break;
			}
			if (sym < LZX_NUM_CHARS) {
				uint8_t b = (uint8_t)sym;

				s->win[s->wpos] = b;
				s->wpos = (s->wpos + 1u) & s->wmask;
				out.seen++;
				i++;
				if (!(out.seen & (LZX_FRAME - 1u))) {
					lzx_align_frame(s);
					if (!lzx_flush(s, &out, &flushed,
						       intel, fsize))
						break;
				}
				continue;
			}

			sym -= LZX_NUM_CHARS;
			mlen = sym & (LZX_PRIMARY_LENS);
			slot = sym >> 3;
			if (mlen == LZX_PRIMARY_LENS) {
				uint32_t ex = lzx_sym(s, &s->len_h, &bad);

				if (bad) {
					status = KOF_DEC_CORRUPT;
					break;
				}
				mlen += ex;
			}
			mlen += LZX_MIN_MATCH;

			if (slot > 2u) {
				if (slot >= 51u || slot >= slots) {
					status = KOF_DEC_CORRUPT;
					break;
				}
				if (slot != 3u) {
					uint32_t ex = extra[slot], v = 0, a = 0;

					if (btype == LZX_BLOCK_ALIGNED && ex >= 3u) {
						v = lzx_bits(s, ex - 3u) << 3;
						a = lzx_sym(s, &s->align_h, &bad);
						if (bad) {
							status = KOF_DEC_CORRUPT;
							break;
						}
					} else if (ex) {
						v = lzx_bits(s, ex);
					}
					off = base[slot] - 2u + v + a;
				} else {
					off = 1u;
				}
				s->r2 = s->r1;
				s->r1 = s->r0;
				s->r0 = off;
			} else if (slot == 0u) {
				off = s->r0;
			} else if (slot == 1u) {
				off = s->r1;
				s->r1 = s->r0;
				s->r0 = off;
			} else {
				off = s->r2;
				s->r2 = s->r0;
				s->r0 = off;
			}

			/* A distance further back than the stream has produced
			 * would read the window's previous contents - refused,
			 * for the reason inflate.c gives about the same check. */
			if (!off || (uint64_t)off > out.seen ||
			    off > (s->wmask + 1u)) {
				status = KOF_DEC_CORRUPT;
				break;
			}
			{
				uint32_t src = (s->wpos - off) & s->wmask;
				uint32_t k;

				for (k = 0; k < mlen; k++) {
					uint8_t b = s->win[(src + k) & s->wmask];

					s->win[s->wpos] = b;
					s->wpos = (s->wpos + 1u) & s->wmask;
					out.seen++;
					if (!(out.seen & (LZX_FRAME - 1u))) {
						lzx_align_frame(s);
						if (!lzx_flush(s, &out,
							       &flushed, intel,
							       fsize))
							break;
					}
				}
			}
			i += mlen;
		}
		if (out.stopped)
			break;
	}

	/*
	 * THE LAST PART FRAME. A stream does not end on a frame boundary unless
	 * its length happens to be a multiple of one, so without this the tail
	 * of every file - up to a frame of it - is decoded and never handed
	 * over.
	 */
	if (!out.stopped)
		lzx_flush(s, &out, &flushed, intel, fsize);
	(void)want;
	if (out.stopped && status == KOF_DEC_OK)
		status = KOF_DEC_STOPPED;
	if (produced)
		*produced = out.given;
	return status;
}
