/*
 * psh_value.c - the value of a PowerShell string literal.
 *
 * '...' holds its text, with a pair of single-quote characters (psh.h) for one: 'it''s' is it's. A pair where either
 * is typographic has no value here: which of the two the language keeps is not known to this reader [Unverified],
 * and a value with a guess in it is worse than none.
 * "..." has the backtick for its escape, and the escapes are `0 `a `b `f `n `r `t `v, and any other byte after the
 * backtick is itself (the backtick goes: `" `' `` `$ and `x are ", ', `, $ and x) [Unverified: the language's own
 * description of special characters, as remembered; VS Code's grammar lists the same names plus `e and `u{...}]. The
 * doubled quote is one quote. NO VALUE where the text is not the program's alone:
 *   - a "$" that begins a variable or an expression - $name, ${...}, $(...), $$, $?, $^, $_, $1, $env:x -
 *     because the value is the program's to compute;
 *   - `e and `u{...}, which exist in PowerShell 6 and later and mean "e" and "u" in 5.1 (the same text, two values);
 *   - a backtick before a line break, whose meaning in a string this reader does not know [Unverified].
 * A here-string's value is its body (the lexer put the line break in front of the closer in the closer): verbatim for @'...'@,
 * and for @"..."@ the "..." rules except that a quote is a quote (no doubling) [Unverified: that a doubled quote in
 * a here-string body is two quotes]. A literal that was not closed has no value.
 */

#include "psh.h"

/* Does the byte after a "$" make an interpolation, or at least something this reader cannot decide. */
static int psh_interpolates(uint8_t next)
{
	return kgenome_textual_ident(next) || kof_byte_in_set(next, "({$?^:");
}

/* The byte a backtick and `e stand for: 0 when the escape has no value here. */
static int psh_escape(uint8_t e, uint8_t *v)
{
	if (e == 'e' || e == 'u' || e == '\n' || e == '\r')
		return 0;
	if (!kgenome_textual_pair_get("0\0a\ab\bf\fn\nr\rt\tv\v", e, v))
		*v = e;
	return 1;
}

enum psh_pair { PSH_NOT_QUOTE, PSH_PAIR, PSH_REFUSE };

/* A quote character of the string's class at `i`: a pair of plain ones is one byte `*v`; a lone one or a typographic one has no value. */
static enum psh_pair psh_pair_at(const uint8_t *c, uint32_t cn, uint32_t i, int dbl, uint8_t *v)
{
	uint32_t a = dbl ? kgenome_textual_psh_dq_len(c, cn, i) : kgenome_textual_psh_sq_len(c, cn, i), b;

	if (!a)
		return PSH_NOT_QUOTE;
	b = dbl ? kgenome_textual_psh_dq_len(c, cn, i + a) : kgenome_textual_psh_sq_len(c, cn, i + a);
	if (a != 1u || b != 1u)
		return PSH_REFUSE;
	*v = c[i];
	return PSH_PAIR;
}

int kgenome_textual_psh_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n)
{
	const uint8_t *c = lit + open_len;
	uint32_t cn = len - open_len - close_len, i = 0, w = 0;
	int dbl = (flags & KGENOME_TEXTUAL_F_INTERP) != 0, here = (flags & KGENOME_TEXTUAL_F_HERE) != 0;

	if (flags & KGENOME_TEXTUAL_F_OPEN)
		return 0;
	if (here && !dbl)
		return kgenome_textual_value_verbatim(c, cn, out, n);
	while (i < cn) {
		uint8_t b = c[i], v;
		enum psh_pair r = PSH_NOT_QUOTE;

		if (dbl && b == '`') {
			if (i + 1u >= cn || !psh_escape(c[i + 1u], &v))
				return 0;
			out[w++] = v;
			i += 2u;
			continue;
		}
		if (dbl && b == '$' && i + 1u < cn && psh_interpolates(c[i + 1u]))
			return 0;
		if (!here)
			r = psh_pair_at(c, cn, i, dbl, &v);
		if (r == PSH_REFUSE)
			return 0;
		if (r == PSH_PAIR) {
			out[w++] = v;
			i += 2u;
			continue;
		}
		out[w++] = b;
		i++;
	}
	*n = w;
	return 1;
}
