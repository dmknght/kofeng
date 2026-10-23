/*
 * php_lex.c - the php lexer: where code is, and what is a string, a comment or a tag.
 *
 * WHAT IT DECIDES, and the list is the whole of it: where php starts and stops in a file
 * that may be mostly HTML, where each comment and each string literal begins and ends, and
 * nothing else. A name is code; "eval" is not recognised here, because what a name means
 * is for the passes built on the spans.
 *
 * WHAT IS NOT GUESSED. Each rule below is php's own and was checked against the corpus the
 * lexer was written on (see the note at the foot): a "<?xml" is markup because php with
 * short tags off takes it so; "<<<" with no label after it is a shift; "#[" is an
 * attribute and not a comment. A construct this does not close is delivered as an OPEN
 * span to the end of the input and counted, never silently closed somewhere plausible.
 */

#include <string.h>

#include "php.h"

/* White space as php's tag rule means it: a blank or a line break. */
static int php_ws(uint8_t c)
{
	return kgenome_textual_blank(c) && c != '\v' && c != '\f' ? 1 : c == '\n';
}

/* ---- outside php ---------------------------------------------------------- */

/*
 * Emit the markup up to the next tag that opens php, and the tag. Answers 0 when there is
 * none (the rest is markup) or the sink stopped.
 *
 * "<?php" needs a white space after it (or the end of the file); "<?=" opens by itself; a
 * bare "<?" is a short tag only when white space follows, which is what keeps "<?xml" in
 * the markup. One white space character after "<?php" and a bare "<?" belongs to the tag,
 * as it does to php.
 */
static int enter(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = lx->pos;

	while (i + 1u < n) {
		const uint8_t *q = memchr(p + i, '<', n - 1u - i);
		uint32_t tag, e;

		if (!q)
			break;
		i = (uint32_t)(q - p);
		if (p[i + 1u] != '?') {
			i++;
			continue;
		}
		if (i + 5u <= n && kgenome_textual_ci_eq(p + i + 2u, "php", 3u) && (i + 5u == n || php_ws(p[i + 5u])))
			tag = 5u;
		else if (i + 2u < n && p[i + 2u] == '=')
			tag = 3u;
		else if (i + 2u < n && php_ws(p[i + 2u]))
			tag = 2u;
		else {
			i++;
			continue;
		}
		if (tag != 3u && i + tag < n) {
			e = kgenome_textual_eol_at(p, n, i + tag);
			tag += e ? e : (uint32_t)php_ws(p[i + tag]);
		}
		return kgenome_textual_markup_to(lx, i) &&
		       kgenome_textual_emit(lx, tag, KGENOME_TEXTUAL_TAG, 0, 0, 0);
	}
	kgenome_textual_markup_to(lx, n);
	return 0;
}

/* ---- comments and strings ------------------------------------------------- */

/*
 * "//" and "#". A line comment ends at the line break, or BEFORE a "?>": php leaves the
 * comment there, and the tag is real.
 */
static int line_comment(struct kgenome_textual_lexer *lx, uint32_t i, uint32_t open)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, j = i + open;

	while (j < n && p[j] != '\n' && p[j] != '\r' && !(p[j] == '?' && j + 1u < n && p[j + 1u] == '>'))
		j++;
	return kgenome_textual_span_at(lx, i, j, KGENOME_TEXTUAL_COMMENT, 0, open, 0);
}

/*
 * Past the "{...}" that starts at `j`, in a double quoted string. A "}" in a string inside
 * the braces does not close it - "{$a['}']}" - so strings are skipped as strings. `n` when
 * the braces do not close.
 */
uint32_t kgenome_textual_php_skip_braces(const uint8_t *p, uint32_t n, uint32_t j)
{
	uint32_t depth = 0;

	while (j < n) {
		uint8_t c = p[j];

		if (c == '\'' || c == '"') {
			j = kgenome_textual_skip_quoted(p, n, j);
			if (!j)
				return n;
			continue;
		}
		if (c == '{')
			depth++;
		else if (c == '}' && --depth == 0)
			return j + 1u;
		j++;
	}
	return n;
}

/* ' ... ': a backslash escapes the next byte, which is all php does in it. */
static int single_quoted(struct kgenome_textual_lexer *lx, uint32_t i)
{
	uint32_t j = kgenome_textual_skip_quoted(lx->p, lx->n, i);

	return kgenome_textual_lit(lx, i, j ? j : lx->n, KGENOME_TEXTUAL_STRING, 0, 1u, 1u, j != 0);
}

/* "..." and `...`: interpolation is skipped as one unit, so a quote inside it does not end the string. */
static int double_quoted(struct kgenome_textual_lexer *lx, uint32_t i)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, j = i + 1u;
	uint8_t q = p[i];

	while (j < n) {
		uint8_t c = p[j];

		if (c == '\\') {
			j += 2u;
			continue;
		}
		if (c == q)
			break;
		if (c == '{' && j + 1u < n && p[j + 1u] == '$') {
			j = kgenome_textual_php_skip_braces(p, n, j);
			continue;
		}
		if (c == '$' && j + 1u < n && p[j + 1u] == '{') {
			j = kgenome_textual_php_skip_braces(p, n, j + 1u);
			continue;
		}
		j++;
	}
	return kgenome_textual_lit(lx, i, j < n ? j + 1u : n, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, 1u, 1u, j < n);
}

/* ---- heredoc and nowdoc --------------------------------------------------- */

/*
 * "<<<LABEL", "<<<\"LABEL\"" or "<<<'LABEL'", then a line break. Anything else after "<<<"
 * is not a heredoc - a shift, or a row of angle brackets in a banner - and the caller
 * reads it as code. On success `*body` is where the text starts, `*lab` and `*ll` the label,
 * `*now` whether it is a nowdoc.
 */
static int here_open(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *body, uint32_t *lab,
		     uint32_t *ll, int *now)
{
	uint32_t j = i + 3u, s, e;
	uint8_t q = 0;

	while (j < n && (p[j] == ' ' || p[j] == '\t'))
		j++;
	if (j < n && (p[j] == '\'' || p[j] == '"'))
		q = p[j++];
	if (j >= n || !kgenome_textual_ident(p[j]) || kof_is_digit(p[j]))
		return 0;
	s = j;
	while (j < n && kgenome_textual_ident(p[j]))
		j++;
	if (q) {
		if (j >= n || p[j] != q)
			return 0;
		j++;
	}
	e = kgenome_textual_eol_at(p, n, j);
	if (!e)
		return 0;
	*body = j + e;
	*lab = s;
	*ll = (uint32_t)(q ? j - 1u : j) - s;
	*now = q == '\'';
	return 1;
}

/*
 * The line that closes it: optional white space, the label, and a byte that cannot be part of
 * a name. Since php 7.3 the closer may be indented and may be followed by anything, so that is
 * what is tested. One pass over the lines, so the cost is the length of the text.
 * Answers where the closer ends, or 0.
 */
static uint32_t here_close(const uint8_t *p, uint32_t n, uint32_t body, uint32_t lab, uint32_t ll,
			   uint32_t *ls_out)
{
	uint32_t ls = body;

	for (;;) {
		uint32_t k = ls, e;

		while (k < n && (p[k] == ' ' || p[k] == '\t'))
			k++;
		if (k + ll <= n && memcmp(p + k, p + lab, ll) == 0 && (k + ll == n || !kgenome_textual_ident(p[k + ll]))) {
			*ls_out = ls;
			return k + ll;
		}
		while (ls < n && p[ls] != '\n' && p[ls] != '\r')
			ls++;
		e = kgenome_textual_eol_at(p, n, ls);
		if (!e)
			return 0;
		ls += e;
	}
}

/* Answers 1 when it was one (and delivered), 0 when "<<<" is not a heredoc here, -1 when the sink stopped. */
static int heredoc(struct kgenome_textual_lexer *lx, uint32_t i)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, body, lab, ll, ls, end;
	uint8_t fl;
	int now, ok;

	if (!here_open(p, n, i, &body, &lab, &ll, &now))
		return 0;
	fl = KGENOME_TEXTUAL_F_HERE | (now ? 0u : KGENOME_TEXTUAL_F_INTERP);
	end = here_close(p, n, body, lab, ll, &ls);
	ok = kgenome_textual_lit(lx, i, end ? end : n, KGENOME_TEXTUAL_STRING, fl, body - i, end ? end - ls : 0u, end != 0);
	return ok ? 1 : -1;
}

/* ---- inside php ----------------------------------------------------------- */

/*
 * "__halt_compiler" ( ")" ... ";" : what follows is data the program reads itself, never code
 * and never php. `*end` is where the code of the statement ends; `*tag` is set when it is
 * closed by "?>" and not ";", in which case the tag is still a tag and the data follows it.
 */
static int halt_stmt(const uint8_t *p, uint32_t n, uint32_t j, uint32_t *end, int *tag)
{
	while (j < n && php_ws(p[j]))
		j++;
	if (j >= n || p[j] != '(')
		return 0;
	j++;
	while (j < n && php_ws(p[j]))
		j++;
	if (j >= n || p[j] != ')')
		return 0;
	j++;
	while (j < n && php_ws(p[j]))
		j++;
	if (j < n && p[j] == ';') {
		*end = j + 1u;
		*tag = 0;
		return 1;
	}
	if (j + 1u < n && p[j] == '?' && p[j + 1u] == '>') {
		*end = j;
		*tag = 1;
		return 1;
	}
	return 0;
}

/*
 * Walk php until "?>" or the end. Answers 1 to go back to the markup, 0 when the text is done
 * or the sink stopped. The tag "?>" takes one line break after it, as php does.
 */
static int code(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = lx->pos;
	int halted = 0;
	/*
	 * The last code byte that was not blank was "$": `$__halt_compiler` and `$` comment `__halt_compiler` are a variable's name and no halt, and what
	 * follows is code. Comments and blanks between do not clear it, because the form takes them out: `$` then a comment then the name was a halt
	 * to a lexer that looked at the byte in front, and `$__halt_compiler();` once the form was done - the data after it code.
	 */
	int dollar = 0;

	while (i < n) {
		uint8_t c = p[i];
		int r;

		if (c == '?' && i + 1u < n && p[i + 1u] == '>') {
			uint32_t t = 2u;

			if (!kgenome_textual_code_to(lx, i))
				return 0;
			if (i + 2u < n)
				t += kgenome_textual_eol_at(p, n, i + 2u);
			if (!kgenome_textual_emit(lx, t, KGENOME_TEXTUAL_TAG, KGENOME_TEXTUAL_F_CLOSE, 0, 0))
				return 0;
			if (halted) {
				kgenome_textual_markup_to(lx, n);
				return 0;
			}
			return 1;
		}
		if (c == '/' && i + 1u < n && p[i + 1u] == '/')
			r = line_comment(lx, i, 2u);
		else if (c == '#' && !(i + 1u < n && p[i + 1u] == '['))
			r = line_comment(lx, i, 1u);
		else if (c == '/' && i + 1u < n && p[i + 1u] == '*')
			(void)kgenome_textual_c_comment(lx, n, i, &r);
		else if (c == '\'')
			r = single_quoted(lx, i);
		else if (c == '"' || c == '`')
			r = double_quoted(lx, i);
		else if (c == '<' && i + 2u < n && p[i + 1u] == '<' && p[i + 2u] == '<' &&
			 (r = heredoc(lx, i)) != 0) {
			if (r < 0)
				return 0;
			r = 1;
			dollar = 0;
		} else if (kgenome_textual_ident(c)) {
			uint32_t j = i + 1u, end;
			int tag;

			while (j < n && kgenome_textual_ident(p[j]))
				j++;
			if (j - i == 15u && kgenome_textual_ci_eq(p + i, "__halt_compiler", 15u) && !dollar &&
			    halt_stmt(p, n, j, &end, &tag)) {
				if (tag) {
					halted = 1;
					i = end;
					continue;
				}
				if (!kgenome_textual_code_to(lx, end))
					return 0;
				kgenome_textual_markup_to(lx, n);
				return 0;
			}
			dollar = 0;
			i = j;
			continue;
		} else {
			dollar = c == '$' || (dollar && (c == ' ' || (uint8_t)(c - 9u) < 5u));       /* white space as the form closes it up: \t \n \v \f \r and the blank */
			i++;
			continue;
		}
		if (c == '\'' || c == '"' || c == '`')
			dollar = 0;
		if (!r)
			return 0;
		i = lx->pos;
	}
	kgenome_textual_code_to(lx, n);
	return 0;
}

/*
 * The bytes of a tag that are the tag's own, of a TAG span this lexer delivered: "<?php", "<?=" or "<?" without the one white space php takes after
 * it, and the two bytes of "?>" without the line break after it. The island ends at the closing tag's own bytes, and the span (which the form and the
 * partition tests read as it is) holds the break; this is the row's `tag_own`, kept beside enter() and code() whose tag rules it restates in three tests.
 */
uint32_t kgenome_textual_php_tag_own(const uint8_t *tag, uint32_t len, int close)
{
	if (close)
		return len < 2u ? len : 2u;
	if (len >= 3u && tag[2] == '=')
		return 3u;
	return len >= 5u && kgenome_textual_ci_eq(tag + 2, "php", 3u) ? 5u : 2u;
}

void kgenome_textual_php_lex(struct kgenome_textual_lexer *lx)
{
	/* A fragment is php from its first byte: it has no tag, so it begins where a tag would end. */
	if (lx->fragment && lx->pos < lx->n && !code(lx))
		return;
	while (lx->pos < lx->n)
		if (!enter(lx) || !code(lx))
			return;
}
