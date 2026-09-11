/*
 * lzw.c - see lzw.h.
 */

#include "lzw.h"

#define LZW_CLEAR 256u
#define LZW_EOD   257u
#define LZW_FIRST 258u          /* the first code the stream can build */

/* How much is handed to the sink at once. Bounded so a receiver that wants to
 * refuse gets the chance often, rather than after a megabyte. */
#define LZW_CHUNK 512u

struct out {
	kof_lzw_sink sink;
	void        *user;
	uint8_t      buf[LZW_CHUNK];
	uint32_t     held;
	uint64_t     total;
	int          stopped;
};

static void put(struct out *o, uint8_t c)
{
	if (o->stopped)
		return;
	o->buf[o->held++] = c;
	if (o->held == LZW_CHUNK) {
		if (!o->sink(o->user, o->buf, o->held))
			o->stopped = 1;
		else
			o->total += o->held;
		o->held = 0;
	}
}

static void flush(struct out *o)
{
	if (o->stopped || !o->held)
		return;
	if (!o->sink(o->user, o->buf, o->held))
		o->stopped = 1;
	else
		o->total += o->held;
	o->held = 0;
}

/*
 * Emit what a code stands for, and return its FIRST byte.
 *
 * The first byte is what the caller needs for the table entry it is about to
 * add, and it falls out of this walk for free: the chain is followed to its
 * root, so the root IS the first byte. Returning it here rather than walking
 * the chain a second time is the whole reason this returns anything.
 *
 * Built in reverse because the chain runs backwards - each entry points at its
 * PREFIX - and then written forwards. The buffer cannot overflow: every entry
 * adds one byte to a shorter one, so no sequence is longer than the table.
 */
static uint8_t emit(struct kof_lzw *st, struct out *o, uint32_t code)
{
	uint32_t n = 0;

	while (code >= LZW_FIRST) {
		st->rev[n++] = st->tail[code];
		code = st->prefix[code];
		if (n >= KOF_LZW_CODES)
			break;          /* a cycle; the guard below is the bound */
	}
	st->rev[n++] = (uint8_t)code;
	while (n)
		put(o, st->rev[--n]);
	return (uint8_t)code;
}

enum kof_decomp_status kof_lzw_decode(struct kof_lzw *st, const uint8_t *in,
				      uint64_t in_len, kof_lzw_sink sink,
				      void *user, uint64_t *produced)
{
	struct out o;
	uint64_t bitpos = 0, nbits = in_len * 8u;
	uint32_t next = LZW_FIRST, width = 9u, prev = KOF_LZW_CODES;
	int ended = 0;

	o.sink = sink;
	o.user = user;
	o.held = 0;
	o.total = 0;
	o.stopped = 0;
	*produced = 0;

	while (bitpos + width <= nbits && !o.stopped) {
		uint32_t code = 0, k;

		/* Most significant bit first, which is what separates this from
		 * the GIF variant - see lzw.h. */
		for (k = 0; k < width; k++) {
			uint64_t at = bitpos + k;

			code = (code << 1) |
			       ((in[at >> 3] >> (7u - (at & 7u))) & 1u);
		}
		bitpos += width;

		if (code == LZW_EOD) {
			ended = 1;
			break;
		}
		if (code == LZW_CLEAR) {
			next = LZW_FIRST;
			width = 9u;
			prev = KOF_LZW_CODES;
			continue;
		}
		/*
		 * A code the stream never built cannot be decoded into
		 * anything. The one exception is the code that is about to be
		 * built - the sequence repeats its own first byte - and that is
		 * handled below rather than refused.
		 */
		if (code > next || (code == next && prev >= KOF_LZW_CODES)) {
			flush(&o);
			*produced = o.total;
			return KOF_DEC_CORRUPT;
		}

		if (code == next) {
			/*
			 * The self-referential case. The entry is not in the
			 * table yet, and what it stands for is the previous
			 * sequence followed by that sequence's first byte -
			 * which is the only thing it CAN be, because the
			 * encoder emitted it immediately after adding it.
			 */
			uint8_t first = emit(st, &o, prev);

			put(&o, first);
			if (next < KOF_LZW_CODES) {
				st->prefix[next] = (uint16_t)prev;
				st->tail[next] = first;
				next++;
			}
		} else {
			uint8_t first = emit(st, &o, code);

			if (prev < KOF_LZW_CODES && next < KOF_LZW_CODES) {
				st->prefix[next] = (uint16_t)prev;
				st->tail[next] = first;
				next++;
			}
		}
		prev = code;

		/*
		 * EARLY CHANGE: the width grows one code before the table
		 * strictly needs it, which is PDF's default and TIFF's
		 * behaviour. See lzw.h on what a stream that disables it does
		 * to this decoder and whose job it is to refuse that.
		 *
		 * At 4095 the table is full and nothing more is added; the
		 * stream is expected to send a clear code. Growing past 12 bits
		 * is not a thing the format allows.
		 */
		if (next + 1u >= (1u << width) && width < 12u)
			width++;
	}
	flush(&o);
	*produced = o.total;
	if (o.stopped)
		return KOF_DEC_STOPPED;
	return ended ? KOF_DEC_OK : KOF_DEC_TRUNCATED;
}
