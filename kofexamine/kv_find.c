#define _GNU_SOURCE
#include "kv.h"


/* ---- search --------------------------------------------------------------- */

/*
 * The pattern as bytes.
 *
 * Hex is read two digits at a time and whitespace between them is ignored, so a
 * pattern pasted out of a hex dump works without editing. An odd digit at the
 * end is dropped rather than padded: half a byte is not a byte, and guessing
 * which half would make the search quietly wrong.
 */
static uint32_t find_bytes(const struct view *v, uint8_t *out, uint32_t cap)
{
	uint32_t n = 0;
	const char *p;

	if (!v->find_hex) {
		for (p = v->find; *p && n < cap; p++)
			out[n++] = (uint8_t)*p;
		return n;
	}
	for (p = v->find; *p && n < cap; ) {
		int hi, lo;

		while (*p == ' ' || *p == '\t')
			p++;
		hi = kof_hex_val((uint8_t)(*p));
		if (hi < 0)
			break;
		p++;
		while (*p == ' ' || *p == '\t')
			p++;
		lo = kof_hex_val((uint8_t)(*p));
		if (lo < 0)
			break;
		p++;
		out[n++] = (uint8_t)((hi << 4) | lo);
	}
	return n;
}

/*
 * The next occurrence at or after `from`, as a file offset.
 *
 * Searched over the object's bytes rather than over the region being looked at,
 * because the region is a view and the answer is a place in the file. Which of
 * the two the caller wanted is `find_scope`: within one region the hits outside
 * it are skipped, which is not the same as searching a copy of the region -
 * a pattern lying across two extents of one region is in neither of them, and
 * this reports it where it is rather than inventing a join.
 */
/*
 * ---- A REGULAR EXPRESSION, COMPILED BY THE ENGINE ---------------------------
 *
 * One helper for the two places that offer one - the find dialog and the symbol
 * dialog's filter - because they must mean the same thing by a pattern. Both
 * end up in kof_hex_walk_flags, which is what the matcher itself walks, so a
 * pattern that finds something here finds the same bytes written into a rule.
 *
 * WHAT IT REFUSES, AND WHY THAT IS NOT A BUG HERE. kof_regex_compile rejects a
 * pattern with no concrete run of bytes in it, because a rule's pattern has to
 * give the prefilter something to key on. That is a property of a RULE and not
 * of an interactive search - but the alternative is a second regex
 * implementation, and two of them would be two answers to "what does this
 * pattern mean". The refusal is reported instead: the field goes red and the
 * search does nothing, which is what a half-typed pattern should do.
 */
int rx_compile(const char *text, uint8_t *prog, uint32_t cap,
		      uint32_t *n_out, char *err, size_t err_n)
{
	uint32_t n;

	*n_out = 0;
	if (err && err_n)
		err[0] = 0;
	if (!text || !text[0])
		return 0;
	n = kof_regex_compile(text, prog, cap, 0);
	if (!n) {
		/*
		 * THE REASON, COPIED OUT AT ONCE. kof_hex_error returns the
		 * compiler's own static buffer and the next compile overwrites
		 * it - and there is one on every keystroke.
		 */
		const char *why = kof_hex_error();

		if (err && err_n)
			snprintf(err, err_n, "%s", why && why[0] ? why
				 : "the pattern would not compile");
		return 0;
	}
	*n_out = n;
	return 1;
}

/* Recompile the find dialog's pattern - called wherever the text or the Regex
 * tick changes. */
void find_compile(struct view *v)
{
	v->find_prog_n = 0;
	v->find_rx_bad = 0;
	if (!v->find_regex || !v->find[0])
		return;
	if (!rx_compile(v->find, v->find_prog, (uint32_t)sizeof v->find_prog,
			&v->find_prog_n, v->find_rx_err,
			sizeof v->find_rx_err))
		v->find_rx_bad = 1;
}

static uint64_t find_next(struct view *v, uint64_t from)
{
	uint8_t pat[64];
	uint32_t n = find_bytes(v, pat, sizeof pat);
	/*
	 * WHAT THE PANE IS SHOWING, which on a symbol row is not the file.
	 *
	 * This searched the object's bytes and then dropped any hit that
	 * view_unmap could not place in the region being looked at. A symbol
	 * row has no extents to place anything in, so EVERY hit was dropped
	 * and the search reported "No match" about a marker that is plainly on
	 * the screen - and would have been wrong the other way too, since the
	 * block's layout is ours and its records are nowhere in the file.
	 *
	 * So the search runs over whatever the row is showing. On a symbol row
	 * that makes the answer an offset into the block, which is exactly
	 * what view_map returns there, so everything downstream already agrees.
	 */
	uint64_t bn = 0;
	const uint8_t *bp = view_bytes(v, &bn);
	uint64_t i;

	/*
	 * A REGEX IS A DIFFERENT WALK OVER THE SAME BYTES.
	 *
	 * The engine's, not one written here: kof_hex_walk_flags answers "does
	 * the program match starting exactly at this offset", so the scan is
	 * the loop and the match is the engine's. ICASE is the pattern option
	 * the matcher itself would apply, passed through rather than folded by
	 * hand here.
	 *
	 * A pattern that would not compile finds nothing, and the field says
	 * why - see find_compile.
	 */
	if (v->find_regex) {
		kof_buf d = kof_buf_make(bp, bn);

		if (!v->find_prog_n || !bp)
			return KGENOME_BROKEN;
		for (i = from; i < bn; i++) {
			if (!kof_hex_walk_flags(d, i, v->find_prog,
						v->find_icase
						? (uint8_t)KOF_STR_ICASE : 0u))
				continue;
			if (v->find_scope == 0 &&
			    view_unmap(v, i) == KGENOME_BROKEN)
				continue;
			return i;
		}
		return KGENOME_BROKEN;
	}
	if (!n || !bp || n > bn)
		return KGENOME_BROKEN;
	for (i = from; i + n <= bn; i++) {
		uint32_t k;

		for (k = 0; k < n; k++) {
			uint8_t a = bp[i + k], b = pat[k];

			/* Only for text: a hex pattern names bytes, and two
			 * bytes are equal or they are not. */
			if (v->find_icase && !v->find_hex) {
				if (a >= 'A' && a <= 'Z')
					a = (uint8_t)(a - 'A' + 'a');
				if (b >= 'A' && b <= 'Z')
					b = (uint8_t)(b - 'A' + 'a');
			}
			if (a != b)
				break;
		}
		if (k != n)
			continue;
		/* No exception for a symbol row any more: it has extents like
		 * any other, so a hit outside the half being looked at is
		 * skipped the same way. */
		if (v->find_scope == 0 && view_unmap(v, i) == KGENOME_BROKEN)
			continue;       /* present, but not in this region */
		return i;
	}
	return KGENOME_BROKEN;
}

/*
 * The last occurrence strictly before `before`.
 *
 * Written as a forward scan that keeps the best answer rather than a reverse
 * one: the match test is the same in both directions and only one of them has
 * to be right.
 */
static uint64_t find_prev(struct view *v, uint64_t before)
{
	uint64_t at = 0, best = KGENOME_BROKEN, hit;

	for (;;) {
		hit = find_next(v, at);
		if (hit == KGENOME_BROKEN || hit >= before)
			break;
		best = hit;
		at = hit + 1u;
	}
	return best;
}

/* Run the search, wrapping once at whichever end it reaches. */
void find_run(struct view *v, int back)
{
	uint64_t at;

	if (back) {
		uint64_t before = v->find_at == KGENOME_BROKEN ? 0 : v->find_at;

		at = before ? find_prev(v, before) : KGENOME_BROKEN;
		if (at == KGENOME_BROKEN) {
			uint64_t bn = 0;

			(void)view_bytes(v, &bn);
			at = find_prev(v, bn);                  /* wrap */
		}
	} else {
		uint64_t start = v->find_at == KGENOME_BROKEN ? 0
							  : v->find_at + 1u;

		at = find_next(v, start);
		if (at == KGENOME_BROKEN && start)
			at = find_next(v, 0);           /* wrap */
	}
	if (at == KGENOME_BROKEN) {
		/*
		 * "No match" IS NOT THE ANSWER WHEN THE PATTERN NEVER RAN.
		 *
		 * A regex the compiler refused finds nothing, and saying "No
		 * match" about it blames the file for the pattern. The
		 * compiler's own words are what the reader needs - see
		 * rx_compile, which copies them out before the next keystroke
		 * overwrites them.
		 */
		if (v->find_regex && v->find_rx_bad && v->find_rx_err[0])
			snprintf(v->find_msg, sizeof v->find_msg, "%s",
				 v->find_rx_err);
		else
			snprintf(v->find_msg, sizeof v->find_msg, "No match");
		v->find_i = v->find_n = 0;
		return;
	}
	v->find_msg[0] = 0;
	v->find_at = at;
	/*
	 * Which hit this is, counted rather than tracked.
	 *
	 * Kept as a count over the whole object every time instead of a number
	 * carried between searches: the scope, the case folding and the pattern
	 * can all change between one search and the next, and a carried index
	 * would then be counting something that no longer exists.
	 */
	{
		uint64_t p = 0, h;

		v->find_i = v->find_n = 0;
		for (;;) {
			h = find_next(v, p);
			if (h == KGENOME_BROKEN)
				break;
			v->find_n++;
			if (h == at)
				v->find_i = v->find_n;
			p = h + 1u;
		}
	}
	/* The search ran over whatever the row shows, so the hit is an offset in
	 * that space - view_show alone would fall back to placing it in the
	 * file when the row is a symbol half. */
	/* A SEARCH stays on the row the reader chose - see view_show. */
	view_show_in(v, v->node[v->sel_node].obj, v->node[v->sel_node].sym, at,
		     0);
	{
		uint64_t r = view_unmap(v, at);

		if (r != KGENOME_BROKEN) {
			uint8_t pat[64];
			uint32_t n = find_bytes(v, pat, sizeof pat);

			v->sel_a = r;
			v->sel_b = n ? r + n - 1u : r;
		}
	}
}
