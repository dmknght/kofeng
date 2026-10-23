/*
 * textual_ecma.c - ECMAScript source: what javascript and jscript are lexed with, in js's own file and
 * in classic asp's <% %> islands (asp's jscript pages call it through the C-shaped entry, textual_clike.c).
 *
 * WHAT IT DECIDES, and the evidence for each (the cases are in tests/lib/genome/textual_js.c, which also says how
 * the lexer was compared with TypeScript 6.0.3's parser and V8 on real files and on generated programs):
 *
 *   LINE TERMINATORS are LF, CR, U+2028 and U+2029 (the spec's four, not LF alone). A "//" comment and
 *   an unclosed quote end at one of them (an unclosed quote at LF or CR only: U+2028/9 are legal inside
 *   a string since ES2019).
 *   COMMENTS: "//", "/ * * /", a leading "#!" line (hashbang, only at byte 0), and with the flag the HTML-like
 *   pair of Annex B, which every engine runs in a classic script: "<!--" anywhere, "-->" only where
 *   nothing but white space and comments stand before it on its line.
 *   STRINGS: ' and "; a backslash escapes the next byte, so "\<CR><LF>" is ONE line continuation (the shared
 *   lexer this replaced ended the string at the LF of it).
 *   TEMPLATES: one STRING span for the whole literal, ${...} included, whatever is inside the
 *   substitutions: it is lexed with the SAME loop as the program (strings, comments, regular
 *   expressions, nested templates, braces), so a "}" or a backtick in a comment, string or regex inside
 *   ${ } closes nothing. No recursion: the open braces and substitutions are a stack of ECMA_NEST bytes.
 *   TAGGED templates are not INTERP (the tag reads the raw text, so the form must not rewrite an escape),
 *   and neither is a template with a substitution (the form cannot tell text from code inside it).
 *   REGULAR EXPRESSIONS are the one choice made from context: see `div_next`. A "/" that begins no
 *   regular expression on its own line was a division after all: a regular expression cannot be unclosed,
 *   so the guess was wrong and the "/" is an operator (a safe fall-back: code, not a string hiding code).
 *   A failed guess reads to the end of its line and consumes nothing, so a line of "[/[/[/..." would read
 *   its own length from every "/" in it (a megabyte of it ran for minutes). The bytes failed guesses read
 *   are counted, and a guess is made only while they are no more than 8 times the bytes lexed plus 64 KiB:
 *   work stays linear, and no program in the corpus comes near it (0 failed guesses in the files that parse).
 *
 * KNOWN LIMITS, each a case in the test marked as such:
 *   - a "/" after the "}" of a function EXPRESSION or after a word that is a name here but a keyword
 *     elsewhere (`of`, `yield`, `await` used as variables) is read as a regular expression; a division by
 *     either is what nothing writes (0 cases in the 25352 real files TypeScript parses);
 *   - a class "[" inside a class in a "v"-flag regular expression, /[[a]/]/v, ends the class early;
 *   - the nesting of braces and of ${ } is tracked ECMA_NEST deep: a template whose substitutions
 *     nest deeper is open from there, and a "}" past that depth reads as a block's.
 *
 * Work is linear (one read of [pos, end), each byte looked at a bounded number of times), nothing is
 * allocated, nothing reads past `end`, and every byte is in exactly one span.
 */

#include <string.h>

#include "textual_private.h"

/* Depth of the open "{" and "(" tracked, and of ${ } inside a template. A DoS bound on stack, not on input: 1 KiB of
 * the lexer's frame. The deepest of 24865 real .js files nests 47 braces, 68 parentheses and 5 substitutions. */
#define ECMA_NEST 512u

/* The token before decides what "/" and "{" are. */
enum ecma_prev {
	P_START,        /* nothing yet: "/" begins a regular expression */
	P_VALUE,        /* a name, number, string, regular expression, "]" or a postfix "++": "/" divides */
	P_KWEXPR,       /* return typeof in ...: an expression follows, so "{" is an object and "/" a regexp */
	P_KWBLOCK,      /* else do try finally: a statement follows, "{" is a block */
	P_RPAREN,       /* ")" of an expression: divides; "{" after it is a block (if/for/function) */
	P_RPAREN_COND,  /* ")" of if/while/for/with: a statement follows, so "/" begins a regexp */
	P_ARROW,        /* "=>": "{" is a body, "/" a regexp */
	P_STMT,         /* ";" "{" and the like: a statement may begin */
	P_COLON,        /* ":" : "{" is a block after a label or case, an object in an expression */
	P_OP,           /* any other operator or opening bracket */
	P_RBRACE_EXPR,  /* "}" that closed an object literal: an operand, so "/" divides */
	P_RBRACE_BLOCK  /* "}" that closed a block: a statement may begin */
};

enum ecma_brace { B_BLOCK, B_EXPR, B_TPL };

struct ecma {
	struct kgenome_textual_lexer *lx;
	const uint8_t *p;
	uint32_t end, flags, i;
	uint32_t t_start;       /* where the outermost template began */
	uint32_t tpl_n;         /* ${ } entered and not left: > 0 is code inside a template */
	uint32_t pdepth, bdepth;
	uint8_t  ptok;          /* enum ecma_prev */
	uint8_t  lt;            /* a line terminator since the last token (true at the start of the text) */
	uint8_t  dot;           /* the last token was "." or "?.": a word now is a property name */
	uint8_t  cond;          /* the last token was if/while/for/with: the "(" that follows is its condition */
	uint8_t  after_for;     /* the last token was "for": "for await (" */
	uint8_t  body;          /* inside the text of a template, not the code of a substitution */
	uint8_t  tagged, subst; /* of the outermost template: a tag in front of it, a ${ } in it */
	uint8_t  lost;          /* a substitution nested past ECMA_NEST: what is left is the template's */
	uint64_t rx_work;       /* bytes read by regular expression guesses that failed (see `slash`) */
	int      ok;
	uint8_t  pstk[ECMA_NEST];
	uint8_t  bstk[ECMA_NEST];
};

/* ---- characters ---------------------------------------------------------------------- */

/*
 * White space or a line terminator at `i`: its length in bytes, 0 when it is neither, and *lt set for a
 * terminator. ASCII's tab VT FF space, the Zs category and the byte order mark (which opens real files:
 * the 3 bytes before a first "/" would otherwise be a name), and LF CR U+2028 U+2029.
 */
static uint32_t ws_len(const uint8_t *p, uint32_t end, uint32_t i, int *lt)
{
	uint8_t c = p[i];

	if (kgenome_textual_hblank(c))
		return 1;
	if (c == '\n' || c == '\r') {
		*lt = 1;
		return 1;
	}
	if (c < 0x80u)
		return 0;
	if (c == 0xC2u && i + 1u < end && p[i + 1u] == 0xA0u)
		return 2;
	if (i + 2u >= end)
		return 0;
	if (c == 0xEFu && p[i + 1u] == 0xBBu && p[i + 2u] == 0xBFu)
		return 3;
	if (c == 0xE2u && p[i + 1u] == 0x80u && (p[i + 2u] == 0xA8u || p[i + 2u] == 0xA9u)) {
		*lt = 1;
		return 3;
	}
	if ((c == 0xE2u && p[i + 1u] == 0x80u && ((p[i + 2u] >= 0x80u && p[i + 2u] <= 0x8Au) || p[i + 2u] == 0xAFu)) ||
	    (c == 0xE2u && p[i + 1u] == 0x81u && p[i + 2u] == 0x9Fu) ||
	    (c == 0xE1u && p[i + 1u] == 0x9Au && p[i + 2u] == 0x80u) ||
	    (c == 0xE3u && p[i + 1u] == 0x80u && p[i + 2u] == 0x80u))
		return 3;
	return 0;
}

/*
 * Does a line terminator (ws_len's `lt`) stand in [from, to) of a block comment: the one thing the ecma lexer asks of a comment's bytes that the
 * C reader (kgenome_textual_c_block_end) does not answer - a comment across lines is a line break for the automatic semicolon. A second walk over
 * the comment, and a cheap one: only the bytes that can begin a terminator are looked at (LF, CR, and the lead bytes of U+2028/2029 from 0xE2),
 * where the loop this replaced was one pass doing both and carried the comment's own copy of the C reader's search.
 */
static int lt_between(const uint8_t *p, uint32_t end, uint32_t from, uint32_t to)
{
	uint32_t j;

	for (j = from; j < to; j++)
		if (p[j] == '\n' || p[j] == '\r' || p[j] >= 0xE2u) {
			int lt = 0;

			if (ws_len(p, end, j, &lt) && lt)
				return 1;
		}
	return 0;
}

/* The end of the line comment that starts at `j`: the first terminator, which is not in it. */
static uint32_t line_end(const uint8_t *p, uint32_t end, uint32_t j)
{
	int lt;

	for (; j < end; j++) {
		lt = 0;
		if ((p[j] == '\n' || p[j] == '\r' || p[j] >= 0xE2u) && ws_len(p, end, j, &lt) && lt)
			break;
	}
	return j;
}

static int name_start(uint8_t c)
{
	return kgenome_textual_ident(c) || c == '$' || c == '\\' || c == '#';
}

/*
 * Past a name that begins at `j`: letters, digits, "_", "$", non-ASCII that is not white space, \uXXXX, \u{...}; a
 * private name's "#" begins one and only there ("a#b" is a name, "#" and a name: the form closes a gap up, so a "#" taken
 * into the name before it would turn the "/" after it into a division - found by the form's check on random text).
 * A "\" that is not an escape ends it.
 */
static uint32_t name_end(const uint8_t *p, uint32_t end, uint32_t j)
{
	int lt;

	if (j < end && p[j] == '#')
		j++;
	while (j < end) {
		uint8_t c = p[j];

		if (c == '\\' && j + 1u < end && p[j + 1u] == 'u') {
			j += 2u;
			if (j < end && p[j] == '{') {
				while (j < end && p[j] != '}' && p[j] != '\n' && p[j] != '\r')
					j++;
				j += j < end && p[j] == '}';
			}
		} else if (kgenome_textual_ident(c) || c == '$') {
			if (c >= 0x80u && ws_len(p, end, j, &lt))
				break;
			j++;
		} else {
			break;
		}
	}
	return j;
}

/* ---- literals ------------------------------------------------------------------------ */

/*
 * The quoted string that starts at `j`: where it ends, and whether it was closed. A backslash escapes
 * the next byte, and "\" CR LF is one escape, so the LF is not a line end here. One not closed ends AT the
 * LF or CR, which belongs to the code.
 */
static uint32_t str_end(const uint8_t *p, uint32_t end, uint32_t j, int *closed)
{
	uint8_t q = p[j++];

	*closed = 0;
	while (j < end) {
		uint8_t c = p[j];

		if (c == '\\') {
			j++;
			if (j < end)
				j += p[j] == '\r' && j + 1u < end && p[j + 1u] == '\n' ? 2u : 1u;
		} else if (c == q) {
			*closed = 1;
			return j + 1u;
		} else if (c == '\n' || c == '\r') {
			return j;
		} else {
			j++;
		}
	}
	return end;
}

/*
 * The regular expression literal that starts at `j`, its flags too: where it ends, or 0 when it does not
 * close on its line. A "/" in a class [...] closes nothing and a backslash escapes the next byte.
 */
static uint32_t regex_end(const uint8_t *p, uint32_t end, uint32_t j, uint32_t *flags_at, uint32_t *stop)
{
	int in_class = 0, lt;

	j++;
	while (j < end) {
		uint8_t c = p[j];

		if (c == '\n' || c == '\r' || (c >= 0xE2u && ws_len(p, end, j, &lt) && lt))
			return *stop = j, 0;
		if (c == '\\') {
			j += 2u;
			if (j <= end && j > 1u && (p[j - 1u] == '\n' || p[j - 1u] == '\r'))
				return *stop = j, 0;
			continue;
		}
		if (c == '[')
			in_class = 1;
		else if (c == ']')
			in_class = 0;
		else if (c == '/' && !in_class) {
			*flags_at = ++j;
			while (j < end && (kgenome_textual_ident(p[j]) || p[j] == '$') && p[j] < 0x80u)
				j++;
			return j;
		}
		j++;
	}
	*stop = end;
	return 0;
}

/* Deliver the code before `at`, then one literal or comment [at, to) - open when `closed` is 0. Inside a ${ } nothing is. */
static int lit(struct ecma *e, uint32_t at, uint32_t to, uint8_t kind, uint8_t flags, uint32_t open,
	       uint32_t close, int closed)
{
	if (e->tpl_n)
		return 1;
	return kgenome_textual_lit(e->lx, at, to, kind, flags, open, close, closed);
}

/* ---- the words that decide what follows --------------------------------------------- */

enum ecma_word { W_PLAIN, W_KWEXPR, W_KWBLOCK, W_COND };

/* A word that is a keyword and says what may follow it. `x.return` is a property: the caller checks. */
static enum ecma_word word_class(const uint8_t *s, uint32_t len)
{
	static const struct { const char *w; uint8_t cls; } kw[] = {
		{ "return", W_KWEXPR }, { "typeof", W_KWEXPR }, { "instanceof", W_KWEXPR }, { "in", W_KWEXPR },
		{ "of", W_KWEXPR }, { "new", W_KWEXPR }, { "delete", W_KWEXPR }, { "void", W_KWEXPR },
		{ "throw", W_KWEXPR }, { "case", W_KWEXPR }, { "yield", W_KWEXPR }, { "await", W_KWEXPR },
		{ "default", W_KWEXPR },
		{ "else", W_KWBLOCK }, { "do", W_KWBLOCK }, { "try", W_KWBLOCK }, { "finally", W_KWBLOCK },
		{ "if", W_COND }, { "while", W_COND }, { "for", W_COND }, { "with", W_COND }
	};
	uint32_t k;

	if (len < 2u || len > 10u)
		return W_PLAIN;
	for (k = 0; k < sizeof kw / sizeof kw[0]; k++)
		if (strlen(kw[k].w) == len && memcmp(kw[k].w, s, len) == 0)
			return (enum ecma_word)kw[k].cls;
	return W_PLAIN;
}

/* Does the token before leave the program expecting an operator - so that "/" divides. */
static int div_next(const struct ecma *e)
{
	return e->ptok == P_VALUE || e->ptok == P_RPAREN || e->ptok == P_RBRACE_EXPR;
}

/* After a token: what the next one is read against. */
static void settle(struct ecma *e, uint8_t ptok, uint32_t len)
{
	e->ptok = ptok;
	e->i += len;
	e->lt = 0;
	e->dot = 0;
	e->cond = 0;
	e->after_for = 0;
}

static void word(struct ecma *e)
{
	uint32_t j = name_end(e->p, e->end, e->i), w, after_for, ptok;
	int is_for;

	if (j == e->i)
		j++;                    /* a backslash that is no escape: a word of one byte */
	w = e->dot ? (uint32_t)W_PLAIN : (uint32_t)word_class(e->p + e->i, j - e->i);
	after_for = e->after_for && j - e->i == 5u && memcmp(e->p + e->i, "await", 5u) == 0;
	ptok = w == W_KWEXPR ? P_KWEXPR : w == W_KWBLOCK ? P_KWBLOCK : w == W_COND ? P_OP : P_VALUE;
	is_for = w == W_COND && j - e->i == 3u && memcmp(e->p + e->i, "for", 3u) == 0;

	settle(e, (uint8_t)ptok, j - e->i);
	e->cond = (uint8_t)(w == W_COND || after_for);
	e->after_for = (uint8_t)is_for;
}

/* Past the digits (and "_" separators, and with `hex` the letters a-f) from `j`. */
static uint32_t digits(const uint8_t *p, uint32_t end, uint32_t j, int hex)
{
	while (j < end && (kof_is_digit(p[j]) || p[j] == '_' || (hex && kof_hex_val(p[j]) >= 0)))
		j++;
	return j;
}

/*
 * A numeric literal, by the grammar: 0x 0b 0o and digits; decimal digits, then "." and digits, then an exponent whose
 * digits are there; a bigint "n". A name right after one is an error in the program, not a part of the number, so the
 * token ends there: "1e" is "1" and "e", and "1 ./a/" and "1./a/" lex alike (the form closes the gap up, so
 * a number that took the "." with it would turn the regular expression after it into a division - found by the
 * form's own check on random text).
 */
static void number(struct ecma *e)
{
	const uint8_t *p = e->p;
	uint32_t j = e->i, end = e->end;

	if (p[j] == '0' && j + 1u < end && ((p[j + 1u] | 0x20u) == 'x' || (p[j + 1u] | 0x20u) == 'b' || (p[j + 1u] | 0x20u) == 'o')) {
		j = digits(p, end, j + 2u, 1);
	} else {
		if (p[j] != '.')
			j = digits(p, end, j, 0);
		if (j < end && p[j] == '.')
			j = digits(p, end, j + 1u, 0);
		if (j < end && (p[j] | 0x20u) == 'e') {
			uint32_t k = j + 1u;

			if (k < end && (p[k] == '+' || p[k] == '-'))
				k++;
			if (k < end && kof_is_digit(p[k]))
				j = digits(p, end, k, 0);
		}
	}
	if (j < end && p[j] == 'n')
		j++;
	settle(e, P_VALUE, j - e->i);
}

/* ---- brackets ------------------------------------------------------------------------ */

static uint8_t brace_top(const struct ecma *e)
{
	return e->bdepth && e->bdepth <= ECMA_NEST ? e->bstk[e->bdepth - 1u] : (uint8_t)B_BLOCK;
}

/* Is the "{" at hand a block or an object literal: from the token before it. */
static int brace_is_block(const struct ecma *e)
{
	if (e->ptok == P_OP || e->ptok == P_KWEXPR)
		return 0;
	if (e->ptok == P_COLON)
		return brace_top(e) == B_BLOCK;
	return 1;
}

static void brace_push(struct ecma *e, uint8_t kind)
{
	if (e->bdepth < ECMA_NEST)
		e->bstk[e->bdepth] = kind;
	else if (kind == B_TPL)
		e->lost = 1;
	e->bdepth++;
}

static void bracket(struct ecma *e, uint8_t c)
{
	uint8_t ptok = P_OP;

	switch (c) {
	case '(':
		if (e->pdepth < ECMA_NEST)
			e->pstk[e->pdepth] = e->cond;
		e->pdepth++;
		break;
	case ')': {
		uint8_t cond = 0;

		if (e->pdepth) {
			e->pdepth--;
			cond = e->pdepth < ECMA_NEST ? e->pstk[e->pdepth] : 0u;
		}
		ptok = cond ? P_RPAREN_COND : P_RPAREN;
		break;
	}
	case '[':
		break;
	case ']':
		ptok = P_VALUE;
		break;
	case '{':
		brace_push(e, brace_is_block(e) ? B_BLOCK : B_EXPR);
		ptok = P_STMT;
		break;
	default: {                      /* "}" */
		uint8_t kind = B_BLOCK;

		if (e->bdepth) {
			e->bdepth--;
			if (e->bdepth < ECMA_NEST)
				kind = e->bstk[e->bdepth];
		}
		if (kind == B_TPL) {
			e->tpl_n--;
			e->body = 1;
			e->i++;
			return;
		}
		ptok = kind == B_EXPR ? P_RBRACE_EXPR : P_RBRACE_BLOCK;
		break;
	}
	}
	settle(e, ptok, 1u);
}

/* ---- templates ----------------------------------------------------------------------- */

/* One step in the TEXT of a template: up to the "${" that enters code, or the backtick that ends it. */
static void tpl_text(struct ecma *e)
{
	const uint8_t *p = e->p;
	uint32_t j = e->i;

	while (j < e->end) {
		if (p[j] == '\\') {
			j += 2u;
		} else if (p[j] == '`') {
			e->i = j + 1u;
			e->body = 0;
			e->ptok = P_VALUE;
			e->lt = 0;
			if (!e->tpl_n) {
				e->ok = lit(e, e->t_start, e->i, KGENOME_TEXTUAL_STRING,
					    (uint8_t)(!e->tagged && !e->subst ? KGENOME_TEXTUAL_F_INTERP : 0u), 1u, 1u, 1);
			}
			return;
		} else if (p[j] == '$' && j + 1u < e->end && p[j + 1u] == '{') {
			if (!e->tpl_n)
				e->subst = 1;
			e->tpl_n++;
			brace_push(e, B_TPL);
			e->i = j + 2u;
			e->body = 0;
			e->ptok = P_OP;
			e->lt = 0;
			if (e->lost)
				e->i = e->end;
			return;
		} else {
			j++;
		}
	}
	e->i = e->end;
}

/* ---- one token of code --------------------------------------------------------------- */

/* "/" at `i`: a comment, a regular expression, or an operator. */
static void slash(struct ecma *e)
{
	const uint8_t *p = e->p;
	uint32_t i = e->i, end = e->end, j = 0, fl = 0, stop = i;
	uint8_t nx = i + 1u < end ? p[i + 1u] : 0u;

	if (nx == '/') {
		j = line_end(p, end, i);
		e->ok = lit(e, i, j, KGENOME_TEXTUAL_COMMENT, 0, 2u, 0, 1);
		e->i = j;
	} else if (nx == '*') {
		int closed;

		/* the reader is the C one (the search starts after the opener, so slash-star-slash is not a whole comment); what is this
		 * lexer's own is whether the comment holds a line terminator, which is read over the bytes it walked (see lt_between) */
		j = kgenome_textual_c_block_end(p, end, i, &closed);
		if (lt_between(p, end, i + 2u, closed ? j - 2u : end - 1u))
			e->lt = 1;
		e->ok = lit(e, i, j, KGENOME_TEXTUAL_COMMENT, 0, 2u, closed ? 2u : 0u, closed);
		e->i = j;
	} else if (!div_next(e) && e->rx_work <= 8u * (uint64_t)i + 65536u && (j = regex_end(p, end, i, &fl, &stop)) != 0) {
		e->ok = lit(e, i, j, KGENOME_TEXTUAL_STRING, 0, 1u, j - fl + 1u, 1);
		e->i = j;
		e->ptok = P_VALUE;
		e->lt = e->dot = e->cond = e->after_for = 0;
	} else {                        /* division, or "/=" */
		e->rx_work += stop - i;
		settle(e, P_OP, nx == '=' ? 2u : 1u);
	}
}

/* The punctuation at `i` that is not a bracket: operators, with the few whose spelling matters to what follows. */
static void punct(struct ecma *e)
{
	const uint8_t *p = e->p;
	uint32_t i = e->i, end = e->end, len = 1;
	uint8_t c = p[i], nx = i + 1u < end ? p[i + 1u] : 0u, ptok = P_OP, dot = 0;

	if (c == ';') {
		ptok = P_STMT;
	} else if (c == ':') {
		ptok = P_COLON;
	} else if (c == '.') {
		len = nx == '.' && i + 2u < end && p[i + 2u] == '.' ? 3u : 1u;
		dot = len == 1u;
	} else if (c == '?' && nx == '.' && !(i + 2u < end && kof_is_digit(p[i + 2u]))) {
		len = 2u;
		dot = 1;
	} else if (c == '<' && nx == '<') {
		len = 2u;       /* "<<" is one token, so the "<" after it cannot begin "<!--": "a <<!-- b" has no comment */
	} else if (c == '=' && nx == '>') {
		len = 2u;
		ptok = P_ARROW;
	} else if ((c == '+' || c == '-') && nx == c) {
		len = 2u;
		/* postfix when an operand stands before it on the same line: then an operator follows */
		ptok = div_next(e) && !e->lt ? P_VALUE : P_OP;
	}
	settle(e, ptok, len);
	e->dot = dot;
}

/* A string, a template, or one of the three HTML-like and hashbang comments begins at `i`. 0 when none does. */
static int literal(struct ecma *e)
{
	const uint8_t *p = e->p;
	uint32_t i = e->i, end = e->end, j;
	uint8_t c = p[i];

	if (c == '"' || c == '\'') {
		int closed;

		j = str_end(p, end, i, &closed);
		e->ok = lit(e, i, j, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, 1u, 1u, closed);
		e->i = j;
		settle(e, P_VALUE, 0);
		return 1;
	}
	if (c == '`' && (e->flags & KGENOME_TEXTUAL_ECMA_TEMPLATE)) {
		if (!e->tpl_n) {
			e->t_start = i;
			e->tagged = (uint8_t)div_next(e);
			e->subst = 0;
		}
		e->body = 1;
		e->i = i + 1u;
		return 1;
	}
	/* "#!" is a comment at byte 0 only; "<!--" anywhere and "-->" at the start of a line (Annex B) */
	if (((e->flags & KGENOME_TEXTUAL_ECMA_HASHBANG) && c == '#' && i == 0 && i + 1u < end && p[1] == '!') ||
	    ((e->flags & KGENOME_TEXTUAL_ECMA_HTML_COMMENT) &&
	     ((c == '<' && i + 3u < end && p[i + 1u] == '!' && p[i + 2u] == '-' && p[i + 3u] == '-') ||
	      (c == '-' && e->lt && i + 2u < end && p[i + 1u] == '-' && p[i + 2u] == '>')))) {
		uint32_t open = c == '#' ? 2u : c == '<' ? 4u : 3u;

		j = line_end(p, end, i);
		e->ok = lit(e, i, j, KGENOME_TEXTUAL_COMMENT, 0, open, 0, 1);
		e->i = j;
		return 1;
	}
	return 0;
}

static void step(struct ecma *e)
{
	const uint8_t *p = e->p;
	uint32_t i = e->i, end = e->end, w;
	uint8_t c = p[i];
	int lt = 0;

	if ((w = ws_len(p, end, i, &lt)) != 0) {
		e->i += w;
		e->lt |= (uint8_t)lt;
	} else if (c == '/') {
		slash(e);
	} else if (literal(e)) {
		return;
	} else if (kof_is_digit(c) || (c == '.' && i + 1u < end && kof_is_digit(p[i + 1u]))) {
		number(e);
	} else if (name_start(c) && !(c == '#' && !(i + 1u < end && name_start(p[i + 1u]) && p[i + 1u] != '#'))) {
		word(e);
	} else if (c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}') {
		bracket(e, c);
	} else {
		punct(e);
	}
}

int kgenome_textual_ecma(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t flags)
{
	struct ecma e = { .lx = lx, .p = lx->p, .end = end, .flags = flags, .i = lx->pos, .lt = 1, .ok = 1,
			  .ptok = P_START };

	while (e.i < end && e.ok) {
		if (e.body)
			tpl_text(&e);
		else
			step(&e);
	}
	if (e.ok && (e.body || e.tpl_n)) {
		/* a template that does not close is open to the end, whatever its substitutions were doing */
		e.tpl_n = 0;
		e.ok = lit(&e, e.t_start, end, KGENOME_TEXTUAL_STRING,
			   (uint8_t)(!e.tagged && !e.subst ? KGENOME_TEXTUAL_F_INTERP : 0u), 1u, 0, 0);
		e.i = end;
	}
	return e.ok && kgenome_textual_code_to(lx, end);
}
