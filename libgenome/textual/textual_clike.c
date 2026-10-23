/*
 * textual_clike.c - C-shaped code: what js, java, c# and coldfusion's script share, with the three
 * things that differ switched by flags (KGENOME_TEXTUAL_CL_*).
 *
 * WHAT IT DECIDES: the two comments, the quoted strings (a backslash escapes the next byte; one that is
 * not closed ends at the line, which is where every one of these languages ends it), and by flag C#'s
 * verbatim, interpolated and raw strings. A language that reads "/" as a regular expression (js, and
 * jscript in classic asp) is not lexed here: CL_REGEX hands the text to textual_ecma.c, which has the
 * token before, a stack of brackets and the template literals the choice needs. It used to be decided here
 * from the last byte before the "/"; against TypeScript's parser that read 187 of 24699 real .js files
 * wrongly (a "#!" line, a quote or brace in a regular expression inside a template's ${ }, a CRLF after a
 * backslash in a string, ")" of an if, "}" of a block), some of them for thousands of bytes.
 */

#include <string.h>

#include "textual_private.h"

/*
 * The quoted string that starts at `j`: where it ends, and whether it was closed. A backslash escapes the
 * next byte, a line break included; one that is not closed ends AT the line break, which belongs to the
 * code, or at `end`.
 */
static uint32_t str_scan(const uint8_t *p, uint32_t end, uint32_t j, int *closed)
{
	uint8_t q = p[j++];

	*closed = 0;
	while (j < end) {
		if (p[j] == '\\') {
			j += j + 1u < end ? 2u : 1u;
		} else if (p[j] == q) {
			*closed = 1;
			return j + 1u;
		} else if (p[j] == '\n' || p[j] == '\r') {
			return j;
		} else {
			j++;
		}
	}
	return end;
}

/* Past the quoted string that starts at `j`; 0 when it is not closed. */
static uint32_t skip_q(const uint8_t *p, uint32_t end, uint32_t j)
{
	int closed;
	uint32_t e = str_scan(p, end, j, &closed);

	return closed ? e : 0;
}

/*
 * THE WORK OF HOLES THAT DO NOT CLOSE IS BOUNDED BY THE TEXT. Each "{" of an interpolated string asks skip_braces for its "}" and one that never closes walks to the end
 * of the text, so `$"` and n "{ " cost n^2/2 steps (L5 of the lexer audit), and so do n strings that each end with a hole that does not close. The steps of the holes that failed, in ONE lex
 * walk, are charged to `*left`, an allowance of the text's length (and a page): a text whose unclosed holes cost that much has read every byte of itself once for them, and the
 * later "{" of its strings are text, as the failed ones were. Nothing is deleted - the quotes decide where a string ends in either case; what can differ, in a text the compiler
 * refuses, is a quote inside a LATER hole, which ends its string once the allowance is spent.
 */

struct holes {
	uint64_t left;          /* what the holes that do not close may still cost in this walk */
	int      skipped;       /* a hole was read as text because `left` was spent: the walk reports it (kgenome_textual_lex_res.n_bound) */
};

/* Past the "{...}" that starts at `j` inside an interpolated string. 0 when it does not close; the steps of that are taken off `h->left`. */
static uint32_t skip_braces(const uint8_t *p, uint32_t end, uint32_t j, struct holes *h)
{
	uint32_t level = 0, from = j, at = end;

	while (j < end) {
		uint8_t c = p[j];

		if (c == '"' || c == '\'') {
			at = j;
			j = skip_q(p, end, j);
			if (!j)
				break;
			continue;
		}
		if (c == '{')
			level++;
		else if (c == '}' && --level == 0)
			return j + 1u;
		j++;
	}
	if (j)
		at = end;
	h->left = h->left > (uint64_t)(at - from) ? h->left - (at - from) : 0u;
	return 0;
}


/*
 * A C# string whose opening quote is before `j`: verbatim (a doubled quote is a quote, a backslash is
 * a backslash, it runs over lines) and/or interpolated (a "{" opens an expression, "{{" is a brace, and
 * the expression may hold strings). Where it ends, and whether it was closed.
 */
static uint32_t cs_scan(const uint8_t *p, uint32_t end, uint32_t j, int verbatim, int interp, int *closed, struct holes *h)
{
	*closed = 0;
	while (j < end) {
		uint8_t c = p[j];

		if (!verbatim && c == '\\') {
			j += j + 1u < end ? 2u : 1u;
		} else if (c == '"') {
			if (verbatim && j + 1u < end && p[j + 1u] == '"') {
				j += 2u;
				continue;
			}
			*closed = 1;
			return j + 1u;
		} else if (!verbatim && (c == '\n' || c == '\r')) {
			return j;
		} else if (interp && c == '{') {
			uint32_t e = 0;

			if (j + 1u < end && p[j + 1u] == '{')
				e = j + 2u;
			else if (h->left)
				e = skip_braces(p, end, j, h);
			else
				h->skipped = 1;
			j = e ? e : j + 1u;
		} else {
			j++;
		}
	}
	return end;
}

/*
 * C# STRING OPENERS other than a plain "...": at `i`, "$" and "@" in front of a quote run, or a run of three or
 * more quotes. A raw string literal (C# 11) is a run of N >= 3 quotes, the text, and a run of N: a quote
 * or two inside it is text, it has no escape, it may cross lines, and with N "$" in front its holes are N
 * braces wide ("$$\"\"\"{{x}}\"\"\""). "$@" and "@$" are the verbatim interpolated string and "@" with
 * three quotes is a verbatim string that begins with a quote, not a raw one. Evidence for the quote run:
 * under the generic rule `"""a "b" c"""` was an empty string, `"a "` and code, and every byte the raw
 * string held was classed as code.
 */
struct cs_open {
	uint32_t q, nq, dollars;        /* the first quote; the run of quotes there; the "$" bytes in front */
	uint8_t  verbatim, interp, raw;
};

static int cs_open(const uint8_t *p, uint32_t end, uint32_t i, struct cs_open *o, uint32_t *next)
{
	uint32_t j = i, a = 0, after_at = i;

	o->dollars = 0;
	while (j < end && (p[j] == '$' || p[j] == '@')) {
		if (p[j] == '$') {
			o->dollars++;
		} else {
			a++;
			after_at = j + 1u;
		}
		j++;
	}
	/* WHERE THE CALLER LOOKS NEXT WHEN THIS DOES NOT OPEN A STRING. The run of "$" and "@" was read from `i` to `j`, and the byte after `i` used to be asked again
	 * and read the run again: n bytes of "$" cost n^2/2 steps (L21 of the lexer audit). A run that ends in anything but a quote opens nothing from any byte in it. One that
	 * ends in a quote opens a string only from the last two bytes of it (a prefix is "$", "@", "$@" or "@$"), or - when three quotes follow, a raw string - from the byte after
	 * its last "@" (any number of "$" may stand in front of a raw string). */
	*next = j;
	if (j >= end || p[j] != '"')
		return 0;
	o->q = j;
	for (o->nq = 0; j + o->nq < end && p[j + o->nq] == '"'; o->nq++)
		;
	o->raw = !a && o->nq >= 3u;
	o->verbatim = (uint8_t)a;
	o->interp = o->dollars != 0;
	/* "$$" is only the prefix of a raw string; a plain quote with nothing in front is the generic rule's */
	if (a <= 1u && (o->dollars < 2u || o->raw) && (o->dollars || a || o->raw))
		return 1;
	*next = o->nq >= 3u ? after_at : (o->q - i > 2u ? o->q - 2u : i + 1u);
	if (*next <= i)
		*next = i + 1u;
	return 0;
}

/* Past the raw string whose first quote run is [j - nq, j); `nd` is the "$" count. Where it ends; `closed` says if it did. */
static uint32_t raw_scan(const uint8_t *p, uint32_t end, uint32_t j, uint32_t nq, uint32_t nd, int *closed, struct holes *h)
{
	*closed = 0;
	while (j < end) {
		uint32_t r = 0;

		if (p[j] == '"') {
			while (j + r < end && p[j + r] == '"')
				r++;
			if (r >= nq) {
				*closed = 1;
				return j + nq;
			}
			j += r;
		} else if (nd && p[j] == '{') {
			uint32_t e;

			while (j + r < end && p[j + r] == '{')
				r++;
			/* a run wider than the hole is text up to the last nd braces, which open it */
			e = 0;
			if (r >= nd) {
				if (h->left)
					e = skip_braces(p, end, j + r - nd, h);
				else
					h->skipped = 1;
			}
			j = e ? e : j + r;
		} else {
			j++;
		}
	}
	return end;
}

/* Is the byte at `i` the first on its line since `from` (the start of the code being lexed)? */
static int line_start(const uint8_t *p, uint32_t from, uint32_t i)
{
	while (i > from && (p[i - 1u] == ' ' || p[i - 1u] == '\t'))
		i--;
	return i == from || p[i - 1u] == '\n';
}

/*
 * A C# PREPROCESSOR LINE whose rest is TEXT: "#region", "#endregion", "#warning", "#error" (case sensitive, as
 * C# is). The message is not code: "#region User's methods" holds an apostrophe that, read as code, opens
 * a character that never closes (an open string span and a status of OPEN on a file that is fine). The
 * line is CODE here, not a comment: the directive is the language's, and the others (#if, #else,
 * #define, #pragma, #line) are lexed as code with their comments and strings.
 */
static int pp_text(const uint8_t *p, uint32_t end, uint32_t i)
{
	static const char *const w[] = { "region", "endregion", "warning", "error" };
	uint32_t s = i + 1u, e, k;

	while (s < end && (p[s] == ' ' || p[s] == '\t'))
		s++;
	for (e = s; e < end && (uint8_t)(p[e] - 'a') < 26u; e++)
		;
	if (e < end && kgenome_textual_ident(p[e]))
		return 0;
	for (k = 0; k < sizeof w / sizeof w[0]; k++)
		if (strlen(w[k]) == e - s && memcmp(p + s, w[k], e - s) == 0)
			return 1;
	return 0;
}

uint32_t kgenome_textual_c_block_end(const uint8_t *p, uint32_t end, uint32_t i, int *closed)
{
	uint32_t j;

	for (j = i + 2u; j + 1u < end && !(p[j] == '*' && p[j + 1u] == '/'); j++)
		;
	*closed = j + 1u < end;
	return *closed ? j + 2u : end;
}

uint32_t kgenome_textual_c_comment(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t i, int *ok)
{
	uint32_t j;
	int closed = 1;

	/* a CR ends the line as well as an LF: "// c\r\n" is a comment of "// c" (php's, sh's and this tree's other lexers say the
	 * same), and a lone CR ends it in C#, Java and JavaScript */
	if (lx->p[i + 1u] == '/')
		j = kgenome_textual_line_end(lx->p, end, i);
	else
		j = kgenome_textual_c_block_end(lx->p, end, i, &closed);
	*ok = kgenome_textual_lit(lx, i, j, KGENOME_TEXTUAL_COMMENT, 0, 2u, lx->p[i + 1u] == '/' ? 0u : 2u, closed);
	return j;
}

int kgenome_textual_clike(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t flags)
{
	const uint8_t *p = lx->p;
	uint32_t i = lx->pos, start = i;
	int ok = 1;
	struct cs_open cs;
	uint32_t resume;
	struct holes holes = { (uint64_t)(end - i) + 65536u, 0 };     /* what the holes that do not close may cost in this walk (skip_braces) */

	/* js and jscript: their own lexer (above) */
	if (flags & KGENOME_TEXTUAL_CL_REGEX)
		return kgenome_textual_ecma(lx, end, (flags & KGENOME_TEXTUAL_CL_TEMPLATE) ? KGENOME_TEXTUAL_ECMA_TEMPLATE : 0u);
	while (i < end && ok) {
		uint8_t c = p[i];
		uint32_t j, at = i;

		resume = i + 1u;
		if (c == '/' && i + 1u < end && (p[i + 1u] == '/' || p[i + 1u] == '*')) {
			i = kgenome_textual_c_comment(lx, end, i, &ok);
		} else if (c == '#' && (flags & KGENOME_TEXTUAL_CL_VERBATIM) && line_start(p, start, i) &&
			   pp_text(p, end, i)) {
			/* C#: the message of #region and its kind is text, up to the line break, and is left as code */
			for (j = i; j < end && p[j] != '\n'; j++)
				;
			i = j;
		} else if ((flags & KGENOME_TEXTUAL_CL_VERBATIM) && (c == '@' || c == '$' || c == '"') &&
			   cs_open(p, end, i, &cs, &resume)) {
			/* C#: @"..." (a doubled quote), $"..." (braces), the two together, and """...""" (raw) */
			int closed;

			if (cs.raw) {
				j = raw_scan(p, end, cs.q + cs.nq, cs.nq, cs.dollars, &closed, &holes);
				ok = kgenome_textual_lit(lx, at, j, KGENOME_TEXTUAL_STRING, 0, cs.q + cs.nq - i, cs.nq, closed);
			} else {
				j = cs_scan(p, end, cs.q + 1u, cs.verbatim, cs.interp, &closed, &holes);
				ok = kgenome_textual_lit(lx, at, j, KGENOME_TEXTUAL_STRING,
					 (uint8_t)(cs.verbatim ? 0u : KGENOME_TEXTUAL_F_INTERP), cs.q + 1u - i, 1u, closed);
			}
			i = j;
		} else if (c == '"' || c == '\'') {
			int closed;

			j = str_scan(p, end, i, &closed);
			ok = kgenome_textual_lit(lx, i, j, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, 1u, 1u, closed);
			i = j;
		} else {
			i = resume;             /* one byte, or past the run of "$" and "@" that opened nothing (cs_open) */
		}
	}
	lx->n_bound += (uint32_t)(holes.skipped != 0);
	return ok && kgenome_textual_code_to(lx, end);
}
