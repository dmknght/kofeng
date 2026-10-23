/*
 * textual_vb.c - VBScript, which is not C shaped and is what classic asp is written in (and what wscript and
 * cscript run for a .vbs). One lexer for the standalone file and for the body of an asp island.
 *
 * THE RULES, each with the neighbour it could be taken for. [Inference] marks a rule decided from the
 * language reference and from how other implementations read it, not from running wscript: this tree has no
 * VBScript interpreter (no wscript, no wine, no mono), so nothing here was checked against the real one.
 *
 *  - A LINE ENDS AT "\n", "\r\n" AND AT A LONE "\r" [Inference]. Of the two ways to be wrong, a comment that
 *    stops too late hides code from every pass that reads the spans, and one that stops too early only shows
 *    extra code; a lone CR therefore ends a comment, a string and a statement.
 *  - "'" opens a COMMENT to the end of the line, where in C# and Java it opens a character: read the wrong
 *    way round every comment of an asp file begins a string that never ends. The line break is not in it.
 *    A "_" at the end of a comment is not a continuation: the comment ends with its line.
 *  - "Rem" is a comment WHERE A STATEMENT CAN BEGIN, as a whole word, any case: at the start of a line, after
 *    ":" (so after "::" too: two separators), after Then and after Else on a one-line If, and at the start
 *    of an island. It is not a comment after an expression ("x = 1 Rem y"), after "." ("a.Rem"), inside a
 *    name ("Remark", "Rem_x", "xrem"), or in a string. "Rem:x" and "Rem.x" are comments: the word ends at the
 *    first byte that cannot be in a name, and a comment runs to the end of the LINE, a ":" does not end it.
 *    pygments' VBScriptLexer reads "rem" followed by white space anywhere in a line as a comment, and a "Rem"
 *    that is alone on its line swallows the next line (its \s matches the break): both are its errors
 *    (tests/lib/genome/textual_vbs.c, "oracle", counts the cases on the real files).
 *  - A STRING is "..." with a doubled quote inside it for a quote; there is no escape of any other kind, so a
 *    backslash is a letter. One that is not closed ends at its line, F_OPEN, without the break. "" is an
 *    empty string, """" is one quote, and "a""b" is one string where "a" "b" is two.
 *  - A LINE CONTINUATION is a "_" that is a whole word and the last thing on its line (blanks may follow
 *    it): kgenome_textual_vb_cont. The next line is the same statement, so the lexer does not begin a
 *    statement there - "Rem" after a continuation is a name, as it is after any expression - and
 *    leaves "fresh" as it was before the "_": "a : _" then a line starting "Rem x" is a comment. "foo_" is a
 *    name and "_foo" is not a continuation. A "_" in front of a comment ("_ 'x") is not a continuation:
 *    the reference says it ends the line, and nothing after it is allowed [Inference].
 *  - A DATE LITERAL "#1/1/2000 10:30:00#" is code, skipped as one piece so that the ":" in a time does not
 *    begin a statement. It must close on its line and hold only letters, digits, blanks and "/:.,+-"; a "#"
 *    that does not open one is a byte of code.
 *  - "[name]" is an extended identifier [Inference, as Wine's lexer reads it]: skipped as one piece, so a
 *    quote or an apostrophe inside it opens nothing. It must close on its line; a "[" that does not is a byte.
 *  - A SCRIPT ENCODER BLOCK, "#@~^" ... "^#~@", is one STRING span, not decoded. Evidence: the format is the
 *    one Microsoft's Script Encoder (screnc) writes into a .vbe file, "#@~^" + a six character length and "=="
 *    + the encoded body + a checksum and "==" + "^#~@"; its body is not VBScript and lexed as such would only
 *    produce comments and strings out of encoded bytes. No file of this machine holds one (grep over the
 *    sample trees and the 439 .vbs, .vbe, .wsf, .asp and .bas files found on this machine: 0 hits), so the
 *    markers are from the public description of the format and the body's layout is not used: the block
 *    ends at the FIRST "^#~@" [Unverified]. Not closed in the text (or in an island's window), it is open
 *    to the end of it. The value, [4, len - 4), is what a decoder would read.
 *  - Numbers (&H1F, &O17, 1.5, 1e5), the keywords, "." member access, With blocks, Execute/Eval/ExecuteGlobal,
 *    Chr()/Asc() and "&" concatenation, CreateObject("...") are CODE and STRING like anything else: there is
 *    no lexical rule for them. ":" is a separator only, and there are no labels.
 *
 * What it does not do: curly quotes (U+201C, U+201D) are not string delimiters here [Unverified whether
 * the real scanner takes them as one]. Nothing is decoded and no identifier is looked up beyond Rem, Then
 * and Else. Work is linear in the input: every byte is read a bounded number of times, no allocation and no
 * recursion.
 */

#include "textual_private.h"

uint32_t kgenome_textual_vb_cont(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint32_t j, e;

	if (i >= n || p[i] != '_' || (i && kgenome_textual_ident(p[i - 1u])))
		return 0;
	for (j = i + 1u; j < n && kgenome_textual_hblank(p[j]); j++)
		;
	e = kgenome_textual_eol_at(p, n, j);
	return e ? j + e - i : 0;
}

/* Two bytes of code that closing up would make something else of. Evidence for each is in its comment. */
int kgenome_textual_vb_glue(uint8_t a, uint8_t b)
{
	/* the same operator twice ("& &H10", "- -x"), and two strings: "a" "b" closed up is the one string
	 * a"b with a doubled quote */
	if (kgenome_textual_glue_twice(a, b, "&+-*/\\^=<>\""))
		return 1;
	/* "<>", "<=", ">=", "><", "=>", "=<" are operators; "< >" is not one */
	if ((a == '<' || a == '>' || a == '=') && (b == '<' || b == '>' || b == '='))
		return 1;
	/* a continuation is a "_" after a space: closed up onto a token it is part of that token's name or
	 * of the operator's [Inference] */
	if (b == '_')
		return 1;
	/* "&" then H, O or a digit is the prefix of a hex or octal number: "a & h1" closed up is "a &h1",
	 * the number &H1 [Inference]; and "1 &" is "1&", a Long in VB's spelling */
	if (a == '&' && ((kof_is_digit(b)) || kof_byte_in_set((uint8_t)(b | 0x20u), "ho")))
		return 1;
	if (kof_is_digit(a) && (b == '&' || b == '.'))
		return 1;
	/* "a (1)" and "a(1)" are not the same statement ("Call a (1)", "a (1), 2"): the space is kept
	 * rather than argued about, as is the one before a "#" that opens a date */
	if (b == '(' && (kgenome_textual_ident(a) || a == ')'))
		return 1;
	if ((a == '#' && kgenome_textual_ident(b)) || (b == '#' && kgenome_textual_ident(a)))
		return 1;
	return 0;
}

/* A date literal that starts at `i`: where it ends, or 0 when it is not one. */
static uint32_t vb_date_end(const uint8_t *p, uint32_t end, uint32_t i)
{
	uint32_t j;

	for (j = i + 1u; j < end; j++) {
		uint8_t c = p[j];

		if (c == '#')
			return j > i + 1u ? j + 1u : 0;
		if (!(kof_is_alpha(c) || kof_is_digit(c) || c == ' ' || c == '\t' ||
		      kof_byte_in_set(c, "/:.,+-")))
			return 0;
	}
	return 0;
}

/* An extended identifier that starts at `i`: where it ends, or 0. When there is no "]" before the line ends (or the text does), `*dead` is where the line ends: no
 * "[" of that line before it has a "]" either, so the caller does not ask again (a line of n "[" cost n^2/2 steps: L4 of the lexer audit). An empty "[]" is not that
 * answer - a "[" after it may close - and leaves `*dead` alone. */
static uint32_t vb_bracket_end(const uint8_t *p, uint32_t end, uint32_t i, uint32_t *dead)
{
	uint32_t j;

	for (j = i + 1u; j < end; j++) {
		if (p[j] == ']')
			return j > i + 1u ? j + 1u : 0;
		if (p[j] == '\n' || p[j] == '\r')
			break;
	}
	*dead = j;
	return 0;
}

/* The end of a script encoder block that starts at `i`, and whether it was closed. */
static uint32_t vb_encoded_end(const uint8_t *p, uint32_t end, uint32_t i, int *closed)
{
	uint32_t j = i + 4u;

	*closed = 0;
	while (j < end) {
		const uint8_t *q = memchr(p + j, '^', end - j);

		if (!q)
			break;
		j = (uint32_t)(q - p);
		if (j + 4u <= end && memcmp(p + j, "^#~@", 4u) == 0) {
			*closed = 1;
			return j + 4u;
		}
		j++;
	}
	return end;
}

/* "Rem" at `i`, as a whole word. */
static int vb_rem_at(const uint8_t *p, uint32_t end, uint32_t i)
{
	return i + 3u <= end && kgenome_textual_ci_eq(p + i, "rem", 3u) &&
	       (i + 3u >= end || !kgenome_textual_ident(p[i + 3u]));
}

/* Past the string that opens at `i`: the end, and whether it closed. */
static uint32_t vb_string_end(const uint8_t *p, uint32_t end, uint32_t i, int *closed)
{
	uint32_t j;

	*closed = 0;
	for (j = i + 1u; j < end; j++) {
		if (p[j] == '"') {
			if (j + 1u < end && p[j + 1u] == '"') {
				j++;
				continue;
			}
			*closed = 1;
			return j + 1u;
		}
		if (p[j] == '\n' || p[j] == '\r')
			break;
	}
	return j;
}

/* After a word: does a statement begin (Then, Else)? */
static int vb_opens_statement(const uint8_t *p, uint32_t i, uint32_t j)
{
	return (j - i == 4u && (kgenome_textual_ci_eq(p + i, "then", 4u) || kgenome_textual_ci_eq(p + i, "else", 4u)));
}

int kgenome_textual_vb(struct kgenome_textual_lexer *lx, uint32_t end)
{
	const uint8_t *p = lx->p;
	uint32_t i = lx->pos;
	int fresh = 1, dot = 0, ok = 1;   /* a statement may begin here; the last byte was "." */
	uint32_t br_dead = 0;             /* a "[" before this offset has no "]" on its line (vb_bracket_end) */

	while (i < end && ok) {
		uint8_t c = p[i];
		uint32_t j, e;
		int closed;

		if (c == '\'' || (fresh && vb_rem_at(p, end, i))) {
			j = kgenome_textual_line_end(p, end, i);
			ok = kgenome_textual_span_at(lx, i, j, KGENOME_TEXTUAL_COMMENT, 0, c == '\'' ? 1u : 3u, 0);
			i = j;
		} else if (c == '"') {
			j = vb_string_end(p, end, i, &closed);
			ok = kgenome_textual_lit(lx, i, j, KGENOME_TEXTUAL_STRING, 0, 1u, 1u, closed);
			i = j;
			fresh = dot = 0;
		} else if (c == '#' && i + 4u <= end && memcmp(p + i, "#@~^", 4u) == 0) {
			j = vb_encoded_end(p, end, i, &closed);
			ok = kgenome_textual_lit(lx, i, j, KGENOME_TEXTUAL_STRING, 0, 4u, 4u, closed);
			i = j;
			fresh = dot = 0;
		} else if ((e = kgenome_textual_eol_at(p, end, i)) != 0) {
			fresh = 1;
			dot = 0;
			i += e;
		} else if (c == ':') {
			fresh = 1;
			dot = 0;
			i++;
		} else if (c == '_' && (e = kgenome_textual_vb_cont(p, end, i)) != 0) {
			/* the next line is this one: nothing changes, "fresh" included */
			i += e;
		} else if (kgenome_textual_ident(c)) {
			/* a word, all of it: "rem" inside a name is not looked at */
			for (j = i + 1u; j < end && kgenome_textual_ident(p[j]); j++)
				;
			fresh = !dot && vb_opens_statement(p, i, j);
			dot = 0;
			i = j;
		} else if (c == '#' && (j = vb_date_end(p, end, i)) != 0) {
			fresh = dot = 0;
			i = j;
		} else if (c == '[' && i >= br_dead && (j = vb_bracket_end(p, end, i, &br_dead)) != 0) {
			fresh = dot = 0;
			i = j;
		} else {
			if (!kgenome_textual_hblank(c)) {
				fresh = 0;
				dot = c == '.';
			}
			i++;
		}
	}
	return ok && kgenome_textual_code_to(lx, end);
}
