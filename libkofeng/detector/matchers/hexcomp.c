/*
 * hexcomp.c - compile the hex syntax into the program hexprog.h defines.
 *
 * Build-time code living in the library on purpose. The compiler, the loader's
 * validator and the matcher are three views of one encoding, and an encoding whose
 * producer lives in a different tree from its consumers is an encoding that drifts.
 * Keeping them together is why the unit test can compile a pattern and match it in
 * one process, which is the only way a bug in either half shows up as a wrong
 * answer rather than as a passing test on each side.
 *
 * It costs the product nothing. A static archive links per object file, and nothing
 * in the scan path references this one, so it never reaches a scanner binary.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../../databases/hexprog.h"

/* ============================================================================
 * HEX PATTERNS
 *
 * The YARA hex syntax, parsed here and compiled to the form hexprog.h defines.
 * Doing it at build time is the whole point: the matcher then walks a fixed
 * structure with every bound already checked, and a malformed pattern is a build
 * error naming a line rather than a search that quietly matches nothing.
 * ============================================================================ */

/* One alternative under construction. Masks are only materialised if a wildcard
 * appeared - the unmasked case is a memcmp, and it is nearly all of them. */
struct hx_alt {
	uint32_t len;
	int      masked;
	int      negged;                     /* any "!" byte in this run */
	/*
	 * A 256-VALUE SET, and then `len` is 1 and b[] is the 32-byte bitmap.
	 *
	 * Emitted by the regex front end for a character class - see
	 * KOF_HEX_ALT_CLASS. Exclusive with masked and negged, because the
	 * bitmap already says which values match and a second opinion about
	 * the same byte is a second place for two answers to disagree; a
	 * negated class is folded by inverting the bitmap at parse time.
	 */
	int      klass;
	uint8_t  b[KOF_HEX_MAX_ALT_LEN];
	uint8_t  m[KOF_HEX_MAX_ALT_LEN];
	uint8_t  n[KOF_HEX_MAX_ALT_LEN];     /* 1 where the byte is negated */
};

struct hx_step {
	uint32_t gap_min, gap_max;      /* the gap BEFORE this step */
	uint32_t n_alts;
	struct hx_alt alt[KOF_HEX_MAX_ALTS];
};

/* Static rather than automatic: 8 x 8 x 512 bytes is not a stack frame, and this is
 * a build tool that compiles one pattern at a time. */
static struct hx_step hx_step[KOF_HEX_MAX_STEPS];
static uint32_t       hx_n_steps;

/* The first thing that went wrong, for the caller to print with a file and a line.
 * A sink rather than stderr: this is library code, and a library that prints has
 * decided something the program using it should have decided. */
static char hex_msg[256];

const char *kof_hex_error(void)
{
	return hex_msg;
}

/*
 * SHORT, AND WITH THE NUMBER IN IT.
 *
 * These are read on a build line beside a file and a line number, so what earns
 * its place is the limit that was hit and what to write instead - not a
 * paragraph explaining the design. The reasoning lives in hexprog.h, where
 * somebody who wants it will look.
 */
static int hex_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(hex_msg, sizeof hex_msg, fmt, ap);
	va_end(ap);
	return 0;
}

static int hex_digit(char c, uint8_t *out)
{
	if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0');      return 1; }
	if (c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return 1; }
	if (c >= 'A' && c <= 'F') { *out = (uint8_t)(c - 'A' + 10); return 1; }
	return 0;
}

/*
 * One byte of pattern: "4A", "??", "?A", "A?".
 *
 * A nibble wildcard is a mask like any other; there is no separate representation
 * for it, which is why "?A" and "??" cost the same to match.
 */
static int hex_byte(const char **pp, uint8_t *val, uint8_t *mask, int *neg)
{
	const char *p = *pp;
	uint8_t hi = 0, lo = 0;
	int hi_any = 0, lo_any = 0;

	*neg = 0;

	/*
	 * "!" NEGATES THE BYTE THAT FOLLOWS IT - "!00" is any byte but zero,
	 * "!?0" any byte whose low nibble is not zero. YARA spells this "~";
	 * both are read, because a pattern copied from a YARA rule should not
	 * have to be retyped to be compiled here.
	 */
	if (p[0] == '!' || p[0] == '~') {
		*neg = 1;
		p++;
	}
	if (p[0] == '?')
		hi_any = 1;
	else if (!hex_digit(p[0], &hi))
		return hex_err("expected a hex digit or '?'");
	if (p[1] == '?')
		lo_any = 1;
	else if (!hex_digit(p[1], &lo))
		return hex_err("a hex byte needs two characters");

	*val  = (uint8_t)((hi << 4) | lo);
	*mask = (uint8_t)((hi_any ? 0x00u : 0xf0u) | (lo_any ? 0x00u : 0x0fu));
	/* "!??" is "not any byte", which no byte satisfies - a pattern that can
	 * never match, and a typo rather than an intention. */
	if (*neg && *mask == 0)
		return hex_err("\"!??\" excludes every byte, so nothing can "
			       "match it");
	*pp = p + 2;
	return 1;
}

static int hx_alt_push(struct hx_alt *a, uint8_t v, uint8_t m, int neg)
{
	if (a->len >= KOF_HEX_MAX_ALT_LEN)
		return hex_err("a single run of bytes is too long");
	a->b[a->len] = v;
	a->m[a->len] = m;
	a->n[a->len] = (uint8_t)(neg ? 1 : 0);
	/* A negated byte is a comparison against a mask however wide the mask
	 * is, so it leaves the memcmp path with the masked ones. */
	if (m != 0xff || neg)
		a->masked = 1;
	if (neg)
		a->negged = 1;
	a->len++;
	return 1;
}

static struct hx_step *hx_new_step(uint32_t gap_min, uint32_t gap_max)
{
	struct hx_step *st;

	if (hx_n_steps >= KOF_HEX_MAX_STEPS) {
		hex_err("too many parts: %u at most, and each (..) is one",
			KOF_HEX_MAX_STEPS);
		return NULL;
	}
	st = &hx_step[hx_n_steps++];
	memset(st, 0, sizeof *st);
	st->gap_min = gap_min;
	st->gap_max = gap_max;
	return st;
}

/* "[4]", "[4-6]", "[4-]", "[-]". The open forms are clamped rather than taken as
 * infinite: two parts that may be arbitrarily far apart are two patterns and a
 * kof_find_str_all, not one pattern. */
static int hex_jump(const char **pp, uint32_t *lo, uint32_t *hi)
{
	const char *p = *pp + 1;   /* past '[' */
	unsigned long a = 0, b;
	int have_a = 0;

	while (*p == ' ' || *p == '\t')
		p++;
	while (*p >= '0' && *p <= '9') {
		a = a * 10 + (unsigned long)(*p++ - '0');
		have_a = 1;
		if (a > KOF_HEX_MAX_GAP_TOTAL)
			return hex_err("jump lower bound is too large");
	}
	while (*p == ' ' || *p == '\t')
		p++;

	if (*p == ']') {
		if (!have_a)
			return hex_err("empty jump");
		b = a;                       /* [n] is exactly n */
		p++;
	} else if (*p == '-') {
		p++;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == ']') {
			b = KOF_HEX_GAP_OPEN;    /* [n-] and [-] */
			p++;
		} else {
			b = 0;
			while (*p >= '0' && *p <= '9') {
				b = b * 10 + (unsigned long)(*p++ - '0');
				if (b > KOF_HEX_MAX_GAP_TOTAL)
					return hex_err("jump upper bound is too "
							     "large");
			}
			while (*p == ' ' || *p == '\t')
				p++;
			if (*p != ']')
				return hex_err("unterminated jump");
			p++;
		}
	} else {
		return hex_err("malformed jump");
	}

	if (b < a)
		return hex_err("jump upper bound is below its lower bound");
	*lo = (uint32_t)a;
	*hi = (uint32_t)b;
	*pp = p;
	return 1;
}

/*
 * Parse the whole pattern into steps.
 *
 * Bytes accumulate into the step being built; a jump or an alternation closes it.
 * A leading or trailing jump is refused - it says the pattern may start or end
 * anywhere, which is not a pattern - and so is a jump inside an alternation, which
 * would leave an alternative without a length and the walk without a bound.
 */
static int hex_parse(const char *text)
{
	struct hx_alt cur;
	uint32_t pend_lo = 0, pend_hi = 0;
	uint32_t gap_total = 0;
	int pending = 0;
	const char *p = text;

	hx_n_steps = 0;
	memset(&cur, 0, sizeof cur);

	while (*p) {
		if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\\') {
			p++;
			continue;
		}

		if (*p == '[') {
			uint32_t lo, hi;

			if (cur.len == 0 && hx_n_steps == 0)
				return hex_err("a pattern cannot begin with a "
						     "jump");
			/* Only a gap with nothing between it and the last one is
			 * two in a row; bytes since then have spoken for it. */
			if (cur.len == 0 && pending)
				return hex_err("two jumps in a row");
			if (!hex_jump(&p, &lo, &hi))
				return 0;
			if (cur.len) {
				struct hx_step *st = hx_new_step(pend_lo, pend_hi);
				if (!st)
					return 0;
				st->n_alts = 1;
				st->alt[0] = cur;
				memset(&cur, 0, sizeof cur);
				pending = 0;
			}
			gap_total += hi - lo;
			if (gap_total > KOF_HEX_MAX_GAP_TOTAL)
				return hex_err("jumps span too much: %u bytes "
					       "in total at most",
					       KOF_HEX_MAX_GAP_TOTAL);
			pend_lo = lo;
			pend_hi = hi;
			pending = 1;
			continue;
		}

		if (*p == '(') {
			struct hx_step *st;

			/* Close whatever bytes preceded the group. */
			if (cur.len) {
				st = hx_new_step(pend_lo, pend_hi);
				if (!st)
					return 0;
				st->n_alts = 1;
				st->alt[0] = cur;
				memset(&cur, 0, sizeof cur);
				pend_lo = pend_hi = 0;
				pending = 0;
			}

			st = hx_new_step(pend_lo, pend_hi);
			if (!st)
				return 0;
			pend_lo = pend_hi = 0;
			pending = 0;

			p++;
			for (;;) {
				struct hx_alt *a;

				if (st->n_alts >= KOF_HEX_MAX_ALTS)
					return hex_err("too many alternatives in "
							     "one group");
				a = &st->alt[st->n_alts];
				memset(a, 0, sizeof *a);

				for (;;) {
					uint8_t v, m;
					int neg;

					while (*p == ' ' || *p == '\t' || *p == '\n' ||
					       *p == '\r' || *p == '\\')
						p++;
					if (*p == '|' || *p == ')' || *p == 0)
						break;
					if (*p == '[')
						return hex_err("a jump inside an "
							       "alternative: each "
							       "one needs a "
							       "length");
					if (*p == '(')
						return hex_err("nested alternatives "
								     "are not supported");
					if (!hex_byte(&p, &v, &m, &neg))
						return 0;
					if (!hx_alt_push(a, v, m, neg))
						return 0;
				}
				if (a->len == 0)
					return hex_err("empty alternative");
				/* Counted once, in st->n_alts. A second
				 * counter alongside it was incremented here
				 * and never read - the cap above tests
				 * st->n_alts, and so does everything after
				 * this loop. */
				st->n_alts++;

				if (*p == '|') {
					p++;
					continue;
				}
				if (*p == ')') {
					p++;
					break;
				}
				return hex_err("unterminated alternative group");
			}
			continue;
		}

		if (*p == ')' || *p == '|')
			return hex_err("alternative syntax outside a group");
		if (*p == ']')
			return hex_err("jump syntax outside a jump");

		{
			uint8_t v, m;
			int neg;

			if (!hex_byte(&p, &v, &m, &neg))
				return 0;
			if (!hx_alt_push(&cur, v, m, neg))
				return 0;
		}
	}

	/* Close the tail first: a gap followed by bytes is not a trailing gap, and
	 * checking before the flush called every gapped pattern malformed. */
	if (cur.len) {
		struct hx_step *st = hx_new_step(pend_lo, pend_hi);
		if (!st)
			return 0;
		st->n_alts = 1;
		st->alt[0] = cur;
		pending = 0;
	}
	if (pending)
		return hex_err("a pattern cannot end with a jump");
	if (hx_n_steps == 0)
		return hex_err("empty pattern");
	return 1;
}

/*
 * Where the matcher should search.
 *
 * The longest run of concrete bytes in a step that has exactly one alternative,
 * together with the window of distances between a match's start and that run. One
 * alternative matters: a run inside one branch of a group is not guaranteed to be
 * in the object at all, so searching for it would miss every match that took the
 * other branch.
 *
 * The window is what allows an anchor after a gap or after a group of unequal
 * lengths. It is one position wide - min == max - for the ordinary pattern whose
 * concrete bytes come first, which is the case worth keeping cheap.
 *
 * Returns the run length; 0 means no step qualified, which the caller refuses.
 */
static uint32_t hex_pick_anchor(uint32_t *out_step, uint32_t *out_before_min,
				uint32_t *out_before_max, uint32_t *out_in_alt)
{
	uint32_t i, lo = 0, hi = 0, best = 0;

	*out_step = 0;
	*out_before_min = 0;
	*out_before_max = 0;
	*out_in_alt = 0;

	for (i = 0; i < hx_n_steps; i++) {
		const struct hx_step *st = &hx_step[i];
		uint32_t j, k, run = 0, alt_lo, alt_hi;

		lo += st->gap_min;
		hi += st->gap_max;

		if (st->n_alts == 1 && !st->alt[0].klass) {
			const struct hx_alt *a = &st->alt[0];

			/*
			 * A CLASS IS NOT A KNOWN BYTE, and is refused above
			 * rather than here.
			 *
			 * It names a set of values, so there is nothing for the
			 * search to look for - the same reason a mask and a
			 * negation are refused inside the loop. Tested on the
			 * step because a class alt never fills m[], and this
			 * array is static across compiles: read anyway it would
			 * be answering with whatever the previous pattern left
			 * there, which is a different wrong answer each time.
			 */
			for (j = 0; j < a->len; j++) {
				/* A NEGATED BYTE IS NOT A KNOWN BYTE. Its mask
				 * is 0xff and it names every value but one, so
				 * counting it into the run would have the
				 * matcher search for a byte the pattern
				 * forbids. */
				if (a->m[j] != 0xff || a->n[j]) {
					run = 0;
					continue;
				}
				run++;
				if (run > best) {
					uint32_t at = j + 1 - run;

					best = run;
					*out_step = i;
					*out_before_min = lo + at;
					*out_before_max = hi + at;
					*out_in_alt = at;
				}
			}
		}

		alt_lo = alt_hi = st->alt[0].len;
		for (k = 1; k < st->n_alts; k++) {
			if (st->alt[k].len < alt_lo)
				alt_lo = st->alt[k].len;
			if (st->alt[k].len > alt_hi)
				alt_hi = st->alt[k].len;
		}
		lo += alt_lo;
		hi += alt_hi;
	}
	return best;
}

/* Little endian, like everything else the host writes: the pack is native order by
 * design, so a pattern is too. */
static void put_u16(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * Flatten the parsed steps into the program hexprog.h describes.
 *
 * Header, then the step table, then the alternative table, then the bytes: fixed
 * strides in front so the loader can bounds check them without walking, and one
 * variable area at the end.
 */
static int hex_emit(uint8_t *img, uint32_t cap, struct kof_hex_stat *stat)
{
	uint32_t n_alts = 0, data_len = 0, i, j;
	uint32_t steps_off, alts_off, data_off, total;
	uint32_t min_span = 0, max_span = 0;
	uint32_t anchor_step, anchor_lo, anchor_hi, anchor_in_alt, anchor_len;
	uint32_t wr;

	for (i = 0; i < hx_n_steps; i++) {
		const struct hx_step *st = &hx_step[i];
		uint32_t lo = st->alt[0].len, hi = st->alt[0].len;

		for (j = 0; j < st->n_alts; j++) {
			const struct hx_alt *a = &st->alt[j];
			data_len += a->klass
				  ? 32u
				  : a->len + (a->masked ? a->len : 0) +
				    (a->negged ? a->len : 0);
			if (a->len < lo) lo = a->len;
			if (a->len > hi) hi = a->len;
		}
		n_alts += st->n_alts;
		min_span += st->gap_min + lo;
		max_span += st->gap_max + hi;
	}

	steps_off = (uint32_t)sizeof(struct kof_hex_hdr);
	alts_off  = steps_off + hx_n_steps * (uint32_t)sizeof(struct kof_hex_step);
	data_off  = alts_off + n_alts * (uint32_t)sizeof(struct kof_hex_alt);
	total     = data_off + data_len;

	if (total > cap || total > KOF_HEX_MAX_PROG)
		return hex_err("the compiled pattern is too large");

	anchor_len = hex_pick_anchor(&anchor_step, &anchor_lo, &anchor_hi,
				     &anchor_in_alt);
	if (anchor_len == 0)
		return hex_err("nothing to search for: add a fixed byte outside "
			       "the alternatives");
	if (anchor_hi - anchor_lo > KOF_HEX_MAX_GAP_TOTAL)
		return hex_err("the fixed bytes sit too many distances from the "
			       "start");

	memset(img, 0, total);

	put_u16(img + 0,  hx_n_steps);
	put_u16(img + 2,  n_alts);
	put_u32(img + 4,  min_span);
	put_u32(img + 8,  max_span);
	put_u32(img + 12, anchor_step);
	put_u32(img + 16, anchor_lo);
	put_u32(img + 20, anchor_hi);
	put_u32(img + 24, anchor_in_alt);
	put_u32(img + 28, anchor_len);
	put_u32(img + 32, steps_off);
	put_u32(img + 36, alts_off);
	put_u32(img + 40, data_off);
	put_u32(img + 44, total);

	wr = 0;
	{
		uint32_t alt_i = 0;

		for (i = 0; i < hx_n_steps; i++) {
			const struct hx_step *st = &hx_step[i];
			uint8_t *sp = img + steps_off + i * sizeof(struct kof_hex_step);

			put_u16(sp + 0, st->gap_min);
			put_u16(sp + 2, st->gap_max);
			put_u16(sp + 4, alt_i);
			put_u16(sp + 6, st->n_alts);

			for (j = 0; j < st->n_alts; j++, alt_i++) {
				const struct hx_alt *a = &st->alt[j];
				uint8_t *ap = img + alts_off +
					      alt_i * sizeof(struct kof_hex_alt);

				put_u16(ap + 0, a->len);
				put_u16(ap + 2,
					a->klass ? KOF_HEX_ALT_CLASS :
					((a->masked ? KOF_HEX_ALT_MASKED : 0u) |
					 (a->negged ? KOF_HEX_ALT_NEG : 0u)));
				put_u32(ap + 4, data_off + wr);

				if (a->klass) {
					/* The whole bitmap, one bit per value.
					 * `len` stays 1: it is still one input
					 * byte that is being decided. */
					memcpy(img + data_off + wr, a->b, 32u);
					wr += 32u;
					continue;
				}
				memcpy(img + data_off + wr, a->b, a->len);
				wr += a->len;
				if (a->masked) {
					memcpy(img + data_off + wr, a->m, a->len);
					wr += a->len;
				}
				/* After the masks, because NEG implies MASKED -
				 * see KOF_HEX_ALT_NEG. */
				if (a->negged) {
					memcpy(img + data_off + wr, a->n, a->len);
					wr += a->len;
				}
			}
		}
	}

	stat->len        = total;
	stat->n_steps    = hx_n_steps;
	stat->n_alts     = n_alts;
	stat->min_span   = min_span;
	stat->max_span   = max_span;
	stat->anchor_len = anchor_len;
	return 1;
}

/*
 * Compile hex text into a program.
 *
 * Returns the program length, or 0 with kof_hex_error() set. Not reentrant - the
 * parse state is static - which is what a build tool wants and what nothing else
 * calls: the engine only ever reads programs, never makes them.
 */
uint32_t kof_hex_compile(const char *text, uint8_t *out, uint32_t cap,
			 struct kof_hex_stat *stat)
{
	struct kof_hex_stat local;

	hex_msg[0] = 0;
	if (!stat)
		stat = &local;
	memset(stat, 0, sizeof *stat);
	if (!hex_parse(text))
		return 0;
	if (!hex_emit(out, cap, stat))
		return 0;
	return stat->len;
}


/* ---- regex: a second syntax, the same program ---------------------------- */

/*
 * WHY THIS IS A FRONT END AND NOT AN ENGINE.
 *
 * A regex engine of the ordinary kind backtracks, and backtracking on bytes an
 * attacker chose is how a scanner stops. This compiles to the program above
 * instead, which is walked as a set of positions that only ever moves forward -
 * so the cost of a match is bounded by the pattern and the object, and
 * catastrophic backtracking is not slow here, it is UNREPRESENTABLE.
 *
 * Everything the user asked for falls out of that rather than being bolted on:
 *
 *   `*` and `+` are refused because the program has no unbounded repetition.
 *   A pattern with no concrete run has no anchor, and hex_emit already refuses
 *   one - so "a regex must have something the prefilter can key on" is a
 *   property of the shared back end, not a rule this file has to remember.
 *
 * WHAT IS ACCEPTED, and every refusal names what to write instead:
 *
 *     abc          literal bytes; runs coalesce into one step
 *     .            any byte - joins the run it is in, as a masked byte
 *     [a-z] [^0-9] a class, its own step, a 256-bit set
 *     (ab|cd)      alternatives, one step, up to KOF_HEX_MAX_ALTS of them
 *     .{4,6}       a gap, which is the one variable-length thing there is
 *     X{3}         three copies of X
 *     \. \[ \\ \n \r \t \xNN
 *
 * WHAT IS REFUSED, and why each one is not an omission:
 *
 *     * +          unbounded. The whole point of the walk above is that it
 *                  cannot be made to run long.
 *     X{2,4}       a variable count of something that is not "any byte". The
 *                  program expresses a variable run only as a GAP, and a gap
 *                  does not know what it is skipping. `.{2,4}` is a gap and is
 *                  accepted; `[a-z]{2,4}` is not expressible and is refused
 *                  rather than silently narrowed to {2} or widened to a gap.
 *     X?           optional. An alternative must have a length - see hex_emit -
 *                  so "this or nothing" has nowhere to go.
 *     backreferences, lookaround
 *                  neither is a regular language and neither can be walked
 *                  forward once.
 */

static const char *rx_p;          /* the cursor, so the recursive walk shares it */

/*
 * A GAP BELONGS TO THE STEP THAT FOLLOWS IT, so it is carried rather than
 * placed.
 *
 * The program says "skip between min and max bytes, THEN match this step", and
 * a regex says ".{4,6}" before whatever comes next - the same fact written the
 * other way round. Holding it here until the next step opens is what makes the
 * two agree, and it is also why a run of bytes cannot continue across one: the
 * bytes after a gap are a new step by definition.
 */
static uint32_t rx_gap_lo, rx_gap_hi;
static int      rx_gap_have;

static int rx_fail(const char *why)
{
	snprintf(hex_msg, sizeof hex_msg, "%s", why);
	return 0;
}

/* The current step, opened on demand: a run of bytes grows inside one. */
static struct hx_step *rx_open(void)
{
	if (hx_n_steps >= KOF_HEX_MAX_STEPS) {
		rx_fail("the pattern needs more steps than a program may hold; "
			"shorten it or split it into two markers");
		return NULL;
	}
	{
		struct hx_step *st = &hx_step[hx_n_steps++];

		memset(st, 0, sizeof *st);
		st->n_alts = 1;
		/* Whatever gap was read before this, spent here - see above. */
		if (rx_gap_have) {
			st->gap_min = rx_gap_lo;
			st->gap_max = rx_gap_hi;
			rx_gap_have = 0;
		}
		return st;
	}
}

/* The step a literal run is being appended to, or a fresh one. A run may only
 * continue while the step holds exactly one alternative and no class. */
static struct hx_step *rx_run_step(struct hx_step *cur)
{
	/* A pending gap ends the run: the bytes after it are a new step, or the
	 * gap would be skipped before bytes that were meant to precede it. */
	if (!rx_gap_have && cur && cur->n_alts == 1 && !cur->alt[0].klass &&
	    cur->alt[0].len < KOF_HEX_MAX_ALT_LEN)
		return cur;
	return rx_open();
}

static int rx_put_byte(struct hx_step **cur, uint8_t v, int any)
{
	struct hx_step *st = rx_run_step(*cur);
	struct hx_alt *a;

	if (!st)
		return 0;
	*cur = st;
	a = &st->alt[0];
	a->b[a->len] = any ? 0u : v;
	a->m[a->len] = any ? 0u : 0xffu;
	a->n[a->len] = 0u;
	if (any)
		a->masked = 1;
	a->len++;
	return 1;
}

/* \xNN and the handful of escapes that are worth having. A backslash before
 * anything else is that character, which is how a pattern says "." or "[". */
static int rx_escape(uint8_t *out)
{
	if (!*rx_p)
		return rx_fail("a backslash at the end of the pattern");
	switch (*rx_p) {
	case 'n': rx_p++; *out = '\n'; return 1;
	case 'r': rx_p++; *out = '\r'; return 1;
	case 't': rx_p++; *out = '\t'; return 1;
	case '0': rx_p++; *out = 0;    return 1;
	case 'x': {
		uint8_t h, l;

		rx_p++;
		if (!hex_digit(rx_p[0], &h) || !hex_digit(rx_p[1], &l))
			return rx_fail("\\x must be followed by two hex digits");
		rx_p += 2;
		*out = (uint8_t)((h << 4) | l);
		return 1;
	}
	default:
		*out = (uint8_t)*rx_p++;
		return 1;
	}
}

/*
 * [abc] [a-z] [^0-9] - into a 32-byte bitmap, negation folded by inverting.
 *
 * Fills the CALLER'S bitmap rather than opening a step, because a class may be
 * counted: "[a-z]{3}" is three steps holding the same set, and parsing it once
 * and copying it is the only reading that cannot drift between the copies.
 */
static int rx_class(uint8_t *bits)
{
	int neg = 0, n = 0;

	memset(bits, 0, 32u);
	if (*rx_p == '^') {
		neg = 1;
		rx_p++;
	}
	while (*rx_p && *rx_p != ']') {
		uint8_t lo, hi;

		if (*rx_p == '\\') {
			rx_p++;
			if (!rx_escape(&lo))
				return 0;
		} else {
			lo = (uint8_t)*rx_p++;
		}
		hi = lo;
		/* A "-" before the closing bracket is a literal dash, which is
		 * how every other regex reads it. */
		if (*rx_p == '-' && rx_p[1] && rx_p[1] != ']') {
			rx_p++;
			if (*rx_p == '\\') {
				rx_p++;
				if (!rx_escape(&hi))
					return 0;
			} else {
				hi = (uint8_t)*rx_p++;
			}
			if (hi < lo)
				return rx_fail("a class range runs backwards");
		}
		for (;;) {
			bits[lo >> 3] |= (uint8_t)(1u << (lo & 7u));
			n++;
			if (lo == hi)
				break;
			lo++;
		}
	}
	if (*rx_p != ']')
		return rx_fail("a class was opened and not closed");
	rx_p++;
	if (!n)
		return rx_fail("an empty class matches nothing");
	if (neg) {
		int i;

		for (i = 0; i < 32; i++)
			bits[i] = (uint8_t)~bits[i];
	}
	return 1;
}

/* One step holding one class, which is what a class compiles to. */
static int rx_emit_class(struct hx_step **cur, const uint8_t *bits)
{
	struct hx_step *st = rx_open();

	if (!st)
		return 0;
	st->alt[0].klass = 1;
	st->alt[0].len = 1;
	memcpy(st->alt[0].b, bits, 32u);
	*cur = NULL;          /* a class ends the run it followed */
	return 1;
}

/*
 * A QUANTIFIER, which is where most of the refusing happens.
 *
 * `{n}` repeats; `.{m,n}` is a gap; everything else that varies is refused with
 * a message saying what to write instead. A compiler that narrowed "{2,4}" to
 * "{2}", or widened it to a gap that does not care what it skips, would be
 * answering a question the author did not ask.
 */
static int rx_quant(uint32_t *lo, uint32_t *hi, int *have)
{
	uint32_t a = 0, b;

	*have = 0;
	if (*rx_p == '*' || *rx_p == '+')
		return rx_fail("* and + are unbounded; write a count like {4} "
			       "or a gap like .{0,16}");
	if (*rx_p == '?')
		return rx_fail("? is optional and an alternative must have a "
			       "length; write both forms out, as (ab|a)");
	if (*rx_p != '{')
		return 1;
	rx_p++;
	if (*rx_p < '0' || *rx_p > '9')
		return rx_fail("a count must begin with a digit");
	while (*rx_p >= '0' && *rx_p <= '9') {
		if (a > KOF_HEX_MAX_GAP_TOTAL)
			return rx_fail("a count past what a program may hold");
		a = a * 10u + (uint32_t)(*rx_p++ - '0');
	}
	b = a;
	if (*rx_p == ',') {
		rx_p++;
		if (*rx_p == '}')
			return rx_fail("an open-ended count is unbounded; give "
				       "it an upper bound");
		b = 0;
		while (*rx_p >= '0' && *rx_p <= '9') {
			if (b > KOF_HEX_MAX_GAP_TOTAL)
				return rx_fail("a count past what a program "
					       "may hold");
			b = b * 10u + (uint32_t)(*rx_p++ - '0');
		}
		if (b < a)
			return rx_fail("a count runs backwards");
	}
	if (*rx_p != '}')
		return rx_fail("a count was opened and not closed");
	rx_p++;
	*lo = a;
	*hi = b;
	*have = 1;
	return 1;
}

/*
 * A GROUP: its alternatives become one step's alternatives.
 *
 * Alternatives of LITERAL RUNS only, because a step's alternative IS a run of
 * bytes - it cannot itself hold a class, a gap or another group. The hex syntax
 * states the same restriction ("a gap inside an alternative"); this is that
 * rule reached by the other door.
 */
static int rx_group(struct hx_step **cur)
{
	struct hx_step *st = rx_open();
	uint32_t k = 0;

	if (!st)
		return 0;
	st->n_alts = 0;
	for (;;) {
		struct hx_alt *a;

		if (k >= KOF_HEX_MAX_ALTS)
			return rx_fail("more alternatives than a step may hold");
		a = &st->alt[k];
		memset(a, 0, sizeof *a);
		while (*rx_p && *rx_p != '|' && *rx_p != ')') {
			uint8_t v = 0;

			if (a->len >= KOF_HEX_MAX_ALT_LEN)
				return rx_fail("an alternative longer than a "
					       "program may hold");
			if (*rx_p == '.') {
				rx_p++;
				a->b[a->len] = 0;
				a->m[a->len] = 0;
				a->masked = 1;
			} else if (*rx_p == '[' || *rx_p == '(' ||
				   *rx_p == '{' || *rx_p == '*' ||
				   *rx_p == '+' || *rx_p == '?') {
				return rx_fail("an alternative holds bytes "
					       "only - no class, group or "
					       "count inside one");
			} else {
				if (*rx_p == '\\') {
					rx_p++;
					if (!rx_escape(&v))
						return 0;
				} else {
					v = (uint8_t)*rx_p++;
				}
				a->b[a->len] = v;
				a->m[a->len] = 0xffu;
			}
			a->n[a->len] = 0;
			a->len++;
		}
		if (!a->len)
			return rx_fail("an empty alternative matches nothing");
		k++;
		if (*rx_p == '|') {
			rx_p++;
			continue;
		}
		break;
	}
	if (*rx_p != ')')
		return rx_fail("a group was opened and not closed");
	rx_p++;
	st->n_alts = k;
	*cur = NULL;          /* a group ends the run it followed */
	return 1;
}

/* The body: atoms, each optionally counted. */
static int rx_body(void)
{
	struct hx_step *cur = NULL;

	while (*rx_p) {
		uint32_t lo = 0, hi = 0, times, t;
		int have = 0, any = 0;
		uint8_t v = 0, bits[32];
		enum { A_BYTE, A_CLASS, A_GROUP } kind = A_BYTE;

		if (*rx_p == '[') {
			rx_p++;
			if (!rx_class(bits))
				return 0;
			kind = A_CLASS;
		} else if (*rx_p == '(') {
			rx_p++;
			if (!rx_group(&cur))
				return 0;
			kind = A_GROUP;
		} else if (*rx_p == ')' || *rx_p == '|') {
			return rx_fail("a ) or | outside a group");
		} else if (*rx_p == '.') {
			rx_p++;
			any = 1;
		} else if (*rx_p == '*' || *rx_p == '+' || *rx_p == '?' ||
			   *rx_p == '{') {
			return rx_fail("a count with nothing before it");
		} else if (*rx_p == '\\') {
			rx_p++;
			if (!rx_escape(&v))
				return 0;
		} else {
			v = (uint8_t)*rx_p++;
		}

		if (!rx_quant(&lo, &hi, &have))
			return 0;

		/*
		 * A VARIABLE COUNT IS A GAP, AND ONLY "." CAN BE ONE.
		 *
		 * The program's one variable-length construct skips a number of
		 * bytes without caring what they are, which is exactly what
		 * ".{m,n}" means and exactly what "[a-z]{2,4}" does not. The
		 * second is refused rather than approximated in either
		 * direction.
		 */
		if (have && lo != hi) {
			if (kind != A_BYTE || !any)
				return rx_fail("a variable count applies only "
					       "to '.', which is the gap this "
					       "can express; give anything "
					       "else an exact count");
			if (rx_gap_have)
				return rx_fail("two gaps in a row; write them "
					       "as one");
			rx_gap_lo = lo;
			rx_gap_hi = hi;
			rx_gap_have = 1;
			cur = NULL;
			continue;
		}

		times = have ? lo : 1u;
		if (!times)
			return rx_fail("a count of zero makes the atom "
				       "optional, which cannot be expressed");
		if (kind == A_GROUP && times != 1u)
			return rx_fail("a counted group cannot be expressed; "
				       "write the copies out");
		for (t = 0; t < times; t++) {
			if (kind == A_CLASS) {
				if (!rx_emit_class(&cur, bits))
					return 0;
			} else if (kind == A_BYTE) {
				if (!rx_put_byte(&cur, v, any))
					return 0;
			}
		}
	}
	if (rx_gap_have)
		return rx_fail("the pattern ends with a gap, which matches "
			       "nothing; a trailing .{m,n} says only that the "
			       "object is longer");
	return 1;
}

/*
 * kof_regex_compile - a regex, as the program the matcher already walks.
 *
 * Same output and same guarantees as kof_hex_compile, including the anchor: a
 * pattern with no run of concrete bytes is refused by hex_emit, which is how
 * "a regex must carry something the prefilter can key on" is enforced without
 * this file having to remember it.
 */
uint32_t kof_regex_compile(const char *text, uint8_t *out, uint32_t cap,
			   struct kof_hex_stat *stat)
{
	struct kof_hex_stat local;

	hex_msg[0] = 0;
	if (!stat)
		stat = &local;
	memset(stat, 0, sizeof *stat);
	hx_n_steps = 0;
	rx_gap_have = 0;
	rx_p = text ? text : "";
	if (!*rx_p) {
		rx_fail("an empty pattern");
		return 0;
	}
	if (!rx_body())
		return 0;
	if (!hx_n_steps) {
		rx_fail("the pattern compiled to nothing");
		return 0;
	}
	if (!hex_emit(out, cap, stat))
		return 0;
	return stat->len;
}
