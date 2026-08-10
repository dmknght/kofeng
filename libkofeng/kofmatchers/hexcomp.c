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

#include <stdio.h>
#include <string.h>

#include "hexprog.h"

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
	uint8_t  b[KOF_HEX_MAX_ALT_LEN];
	uint8_t  m[KOF_HEX_MAX_ALT_LEN];
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

static int hex_err(const char *msg)
{
	snprintf(hex_msg, sizeof hex_msg, "%s", msg);
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
static int hex_byte(const char **pp, uint8_t *val, uint8_t *mask)
{
	const char *p = *pp;
	uint8_t hi = 0, lo = 0;
	int hi_any = 0, lo_any = 0;

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
	*pp = p + 2;
	return 1;
}

static int hx_alt_push(struct hx_alt *a, uint8_t v, uint8_t m)
{
	if (a->len >= KOF_HEX_MAX_ALT_LEN)
		return hex_err("a single run of bytes is too long");
	a->b[a->len] = v;
	a->m[a->len] = m;
	if (m != 0xff)
		a->masked = 1;
	a->len++;
	return 1;
}

static struct hx_step *hx_new_step(uint32_t gap_min, uint32_t gap_max)
{
	struct hx_step *st;

	if (hx_n_steps >= KOF_HEX_MAX_STEPS) {
		hex_err("too many parts; a pattern is capped so that matching it "
			      "stays bounded - see KOF_HEX_MAX_STEPS");
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
				return hex_err("the jumps in this pattern span too "
						     "much; matching it would not stay "
						     "bounded");
			pend_lo = lo;
			pend_hi = hi;
			pending = 1;
			continue;
		}

		if (*p == '(') {
			struct hx_step *st;
			uint32_t k;

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
			for (k = 0;; ) {
				struct hx_alt *a;

				if (st->n_alts >= KOF_HEX_MAX_ALTS)
					return hex_err("too many alternatives in "
							     "one group");
				a = &st->alt[st->n_alts];
				memset(a, 0, sizeof *a);

				for (;;) {
					uint8_t v, m;

					while (*p == ' ' || *p == '\t' || *p == '\n' ||
					       *p == '\r' || *p == '\\')
						p++;
					if (*p == '|' || *p == ')' || *p == 0)
						break;
					if (*p == '[')
						return hex_err("a jump inside an "
								     "alternative is not "
								     "supported: an "
								     "alternative has to "
								     "have a length");
					if (*p == '(')
						return hex_err("nested alternatives "
								     "are not supported");
					if (!hex_byte(&p, &v, &m))
						return 0;
					if (!hx_alt_push(a, v, m))
						return 0;
				}
				if (a->len == 0)
					return hex_err("empty alternative");
				st->n_alts++;
				k++;

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

			if (!hex_byte(&p, &v, &m))
				return 0;
			if (!hx_alt_push(&cur, v, m))
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

		if (st->n_alts == 1) {
			const struct hx_alt *a = &st->alt[0];

			for (j = 0; j < a->len; j++) {
				if (a->m[j] != 0xff) {
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
			data_len += a->len + (a->masked ? a->len : 0);
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
		return hex_err("no concrete byte outside an alternative: there is "
			       "nothing to search for. Add a fixed byte, or write "
			       "the alternatives as separate patterns and join them "
			       "with kof_find_str_any");
	if (anchor_hi - anchor_lo > KOF_HEX_MAX_GAP_TOTAL)
		return hex_err("the anchor can sit too many distances from the "
			       "start of a match");

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
				put_u16(ap + 2, a->masked ? KOF_HEX_ALT_MASKED : 0u);
				put_u32(ap + 4, data_off + wr);

				memcpy(img + data_off + wr, a->b, a->len);
				wr += a->len;
				if (a->masked) {
					memcpy(img + data_off + wr, a->m, a->len);
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

