/*
 * psh_lex.c - the PowerShell lexer: where code is, and what is a string, a comment or a here-string.
 *
 * NO PowerShell WAS AVAILABLE WHEN THIS WAS WRITTEN (no pwsh on the machine). Every rule below comes from the
 * language's documentation as remembered and from VS Code's own PowerShell grammar (powershell.tmLanguage.json,
 * a regular-expression grammar: a second source, not the engine), and a rule that rests on memory says
 * [Unverified]. What is checked is that the rules are the ones written here, by known answers and a generator
 * in tests/lib/genome/textual_psh.c, and that the lexer reads the .ps1/.psm1/.psd1 files of the machine
 * without a gap, an overlap or a surprise.
 *
 * WHAT IT DECIDES: the strings - '...', "...", and the here-strings @'...'@ and @"..."@ - and the comments,
 * # to the end of the line and <# ... #> that does not nest. Everything else is code; numbers, operators
 * and type literals ([Convert]::FromBase64String(...)) are not lexed, a digit is a code byte.
 *
 * LINE ENDINGS. "\n", "\r\n" and a lone "\r" all end a line (a comment ends before the break; a here-string
 * opener's line ends at one) [Unverified for the lone CR: from the language's definition of a new line].
 * The row does not say `universal_eol`: that field is python's (the form reads it as "a continuation
 * backslash exists"), so the form reads a lone CR as a blank (psh_lang.c); nothing here depends on it.
 *
 * SINGLE QUOTES. '...' has no escape but the doubled quote: 'it''s' is one string. A quote character is any
 * of ' U+2018 U+2019 U+201A U+201B (psh.h), and a pair of them in a row, whichever two, is the escape. A line
 * break is part of the string. Not closed: it runs to the end of the text and is OPEN.
 *
 * DOUBLE QUOTES. "..." has the BACKTICK as its escape character (`" `n `` `$ - the byte after it is part of
 * the string whatever it is), the doubled quote as a second escape ("a""b"), and interpolation:
 *   - $name and the like are text for the lexer (they hold no quote and no bracket);
 *   - ${any text, with backtick escapes} runs to the first unescaped "}" - quotes and "#" inside it are the name's;
 *   - $( ... ) is a sub-expression, CODE, with strings and comments of its own: "a $("b" + 'c') d" is one string.
 *     It is scanned by the same function that finds strings, so a "..." inside it is a string and not the end
 *     of the outer one, "#" and <# #> are comments in it (a ")" in one is text), ${...} is a name, and parentheses
 *     are counted. It nests PSH_DEPTH levels; past that, or when anything inside it does not close, the OUTER
 *     string is open to the end of the text: the construct is an error in the language and the answer is "not
 *     closed", never a loop and never an unbounded stack.
 *   - "$$", "$?" and "$^" are variables, so "$$(x)" is a variable and the text "(x)", not a sub-expression.
 *   - "@(...)" and "@{...}" do NOT interpolate in a string, and "$(" after a backtick is text.
 * The span is flagged INTERP (the text interpolates and escapes); single quotes are not.
 *
 * HERE-STRINGS. "@'" or '@"' (typographic quotes of the class too) is a here-string only when it is the LAST
 * THING ON ITS LINE (blanks may follow it); the body starts on the next line, and the string ends at the first
 * line that BEGINS with the quote and "@" - column 0, no indentation: "  '@" is body. What follows the closer on
 * its line is code ("'@ | iex"). The span runs from "@'" to the closer's "@": open_len covers the opener's whole
 * line, close_len the two bytes of "'@", and the line break in front of the closer stays in the body (the value
 * hook takes it off, as php's does). F_HERE; INTERP for "@"..."@", whose body interpolates as a "..." string does,
 * so a "$(" in it that never closes opens it to the end. Anything else after "@'" is not a here-string: "@" is a
 * code byte and the quote opens an ordinary string (in the language that is a parse error) [Unverified]. Not
 * closed: to the end, OPEN.
 *
 * COMMENTS. "#" begins a comment where a TOKEN begins, not inside a word: "echo a#b" is the word a#b (so is a path
 * with C# in it), "echo a;#b" and "$x = 1 #c" are comments [Unverified: this is how the tokenizer is remembered,
 * and VS Code's grammar says otherwise - it makes every "#" that is not behind a backtick, a backslash or a "-" a
 * comment]. The rule here: "#" (and "<#") starts a comment at the beginning of the text, after white space or a line
 * break, after any of ; | & ( ) { } , ], right after a string or a comment, and after a VARIABLE NAME ("$x#c": the
 * name ends at the "#"). Anywhere else it is a byte of the word. A comment does not nest: "<# a <# b #> c #>" ends
 * at the first "#>", and the rest is code. A "<#" with no "#>" after it is a comment that runs to the end, OPEN
 * (the form keeps it). A backtick before "#" escapes it: "`#" is not a comment.
 * A "#!" first line is a comment like any other; the row keeps it (keep_hashbang).
 *
 * THE BACKTICK in code escapes the byte after it (a quote, a "#", a line break - the continuation), so that byte
 * begins nothing. "${...}" in code is a variable name that may hold quotes and "#"; if it never closes it is
 * read as two code bytes, and the scan for its "}" is done once (nobrace), so a text of "${" repeated is linear.
 *
 * NOT DONE, and what that costs: the stop-parsing token --% (the rest of the line is not PowerShell's: a quote in
 * it is read as a quote here); the Unicode line separators U+0085/2028/2029 (a comment goes on past them); the
 * dash characters U+2013..2015 (code, so no effect); a file in UTF-16 is read as bytes and is no program here - the
 * caller narrows it first. A UTF-8 BOM is three code bytes and a token boundary: a "#" right after it is a comment
 * (CmdletInterface.ps1 of the PowerShell extension begins that way; the first version read it as a word).
 *
 * LINEAR: every scan, nested or not, either closes and the caller goes on from its end, or fails and the whole
 * text from the construct's start to the end is the answer.
 */

#include "psh.h"

#define PSH_DEPTH 32u           /* nested $( ) in strings: a bound on the stack a text can choose, not a rule of the language */

struct psh_tok {
	uint32_t end, open, close;
	uint8_t  kind, flags;
};

static uint32_t psh_token_at(const uint8_t *p, uint32_t n, uint32_t i, uint32_t bound, uint32_t depth,
			     struct psh_tok *t);

static int psh_var_char(uint8_t c)
{
	return kgenome_textual_ident(c) || c == '?' || c == ':';
}

/*
 * May a "#" at `i` begin a comment. `bound` is where the last string or comment ended: a token has ended there, and a
 * name cannot reach back past it (the high bytes of a typographic quote that closed a string are name bytes, and the "$"
 * in front of them is the string's - found by the generator). The walk back over a name is bounded by the bytes of
 * that name, each of which is walked at most once (a "#" is not a name byte, so the next "#" starts its walk after
 * this one's).
 */
static int psh_comment_ok(const uint8_t *p, uint32_t i, uint32_t bound)
{
	uint8_t c;
	uint32_t k;

	if (i == 0 || i == bound)
		return 1;
	c = p[i - 1u];
	if (kof_is_space_byte(c) || kof_byte_in_set(c, ";|&(){},]"))
		return 1;
	for (k = i; k > bound && psh_var_char(p[k - 1u]); k--)
		;
	return k < i && k > bound && p[k - 1u] == '$';
}

/* Past the "}" that ends the name "${" opens, whose first byte is `j`: a backtick escapes. 0 when none. */
static uint32_t psh_brace_end(const uint8_t *p, uint32_t n, uint32_t j)
{
	while (j < n) {
		if (p[j] == '`')
			j += 2u;
		else if (p[j] == '}')
			return j + 1u;
		else
			j++;
	}
	return 0;
}

/*
 * Past the ")" that ends the sub-expression whose first byte is `j` (after "$("). 0 when it does not close or
 * is nested past PSH_DEPTH. The code in it is read like any: strings and comments by psh_token_at, a backtick
 * escapes, "${" is a name, "(" and ")" are counted.
 */
static uint32_t psh_sub_end(const uint8_t *p, uint32_t n, uint32_t j, uint32_t depth)
{
	uint32_t level = 1, bound = j;
	struct psh_tok t;

	if (depth > PSH_DEPTH)
		return 0;
	while (j < n) {
		uint8_t c = p[j];

		if (c == '`') {
			j += 2u;
			continue;
		}
		if (c == '$' && j + 1u < n && p[j + 1u] == '{') {
			j = psh_brace_end(p, n, j + 2u);
			if (!j)
				return 0;
			continue;
		}
		if (psh_token_at(p, n, j, bound, depth, &t)) {
			if (t.flags & KGENOME_TEXTUAL_F_OPEN)
				return 0;
			j = t.end;
			bound = j;
			continue;
		}
		if (c == '(') {
			level++;
		} else if (c == ')' && --level == 0) {
			return j + 1u;
		}
		j++;
	}
	return 0;
}

/*
 * What interpolates in a "..." string or a "@" here-string body, at `*jp`: a "$(" or "${" that opens something, or
 * "$$", "$?", "$^" (variables, so the byte after them is not an opener). Moves `*jp` past it. Answers 1 when it did,
 * 0 when the byte is not one, and -1 when the construct does not close - the string is then open to the end.
 */
static int psh_interp(const uint8_t *p, uint32_t n, uint32_t *jp, uint32_t depth)
{
	uint32_t j = *jp, e;

	if (p[j] != '$' || j + 1u >= n)
		return 0;
	if (p[j + 1u] == '(' || p[j + 1u] == '{') {
		e = p[j + 1u] == '(' ? psh_sub_end(p, n, j + 2u, depth + 1u) : psh_brace_end(p, n, j + 2u);
		if (!e)
			return -1;
		*jp = e;
		return 1;
	}
	if (kof_byte_in_set(p[j + 1u], "$?^")) {
		*jp = j + 2u;
		return 1;
	}
	return 0;
}

/* The '...' string whose opening quote is at `i`. */
static void psh_sq(const uint8_t *p, uint32_t n, uint32_t i, struct psh_tok *t)
{
	uint32_t j = i + kgenome_textual_psh_sq_len(p, n, i), l;

	t->kind = KGENOME_TEXTUAL_STRING;
	t->flags = 0;
	t->open = j - i;
	t->close = 0;
	while (j < n) {
		l = kgenome_textual_psh_sq_len(p, n, j);
		if (!l) {
			j++;
		} else if (kgenome_textual_psh_sq_len(p, n, j + l)) {
			j += l + kgenome_textual_psh_sq_len(p, n, j + l);          /* the doubled quote */
		} else {
			t->end = j + l;
			t->close = l;
			return;
		}
	}
	t->end = n;
	t->flags = KGENOME_TEXTUAL_F_OPEN;
}

/* The "..." string whose opening quote is at `i`. */
static void psh_dq(const uint8_t *p, uint32_t n, uint32_t i, uint32_t depth, struct psh_tok *t)
{
	uint32_t j = i + kgenome_textual_psh_dq_len(p, n, i), l;
	int r;

	t->kind = KGENOME_TEXTUAL_STRING;
	t->flags = KGENOME_TEXTUAL_F_INTERP;
	t->open = j - i;
	t->close = 0;
	while (j < n) {
		if (p[j] == '`') {
			j += 2u;
			continue;
		}
		l = kgenome_textual_psh_dq_len(p, n, j);
		if (l && kgenome_textual_psh_dq_len(p, n, j + l)) {
			j += l + kgenome_textual_psh_dq_len(p, n, j + l);          /* the doubled quote */
			continue;
		}
		if (l) {
			t->end = j + l;
			t->close = l;
			return;
		}
		r = psh_interp(p, n, &j, depth);
		if (r < 0)
			break;
		j += r == 0;
	}
	t->end = n;
	t->flags |= KGENOME_TEXTUAL_F_OPEN;
}

/*
 * The here-string whose "@" is at `i`: 0 when "@" and the quote are not the last thing on their line. The closer is
 * looked for at the start of every line; a "@"-quoted body skips what interpolates, as a "..." string does, so a "$("
 * whose code holds a line that begins with the closer is not closed by it.
 */
static int psh_here(const uint8_t *p, uint32_t n, uint32_t i, uint32_t depth, struct psh_tok *t)
{
	uint32_t ql = kgenome_textual_psh_sq_len(p, n, i + 1u), j, e, cl, body;
	int dbl = 0, at_line = 1;

	if (!ql) {
		ql = kgenome_textual_psh_dq_len(p, n, i + 1u);
		dbl = 1;
	}
	if (!ql)
		return 0;
	j = i + 1u + ql;
	while (j < n && (p[j] == ' ' || p[j] == '\t'))
		j++;
	e = kgenome_textual_eol_at(p, n, j);
	if (!e)
		return 0;
	j += e;
	body = j;
	t->kind = KGENOME_TEXTUAL_STRING;
	t->flags = (uint8_t)(KGENOME_TEXTUAL_F_HERE | (dbl ? KGENOME_TEXTUAL_F_INTERP : 0u));
	t->open = j - i;
	t->close = 0;
	while (j < n) {
		if (at_line) {
			cl = dbl ? kgenome_textual_psh_dq_len(p, n, j) : kgenome_textual_psh_sq_len(p, n, j);
			if (cl && j + cl < n && p[j + cl] == '@') {
				/* the line break in front of the closer is part of the closer: the value is the body less it, and a
				 * decoded literal written back between open and close keeps its closer at the start of a line */
				uint32_t brk = j == body ? 0u : (j - body >= 2u && p[j - 2u] == '\r' && p[j - 1u] == '\n' ? 2u : 1u);

				t->end = j + cl + 1u;
				t->close = cl + 1u + brk;
				return 1;
			}
		}
		at_line = 0;
		if (dbl && p[j] == '`') {
			j += 2u;
			continue;
		}
		if (dbl) {
			int r = psh_interp(p, n, &j, depth);

			if (r < 0)
				break;
			if (r > 0)
				continue;
		}
		e = kgenome_textual_eol_at(p, n, j);
		at_line = e != 0;
		j += e ? e : 1u;
	}
	t->end = n;
	t->flags |= KGENOME_TEXTUAL_F_OPEN;
	return 1;
}

/* The comment "<#" begins at `i`, up to the first "#>" after it. */
static void psh_block_comment(const uint8_t *p, uint32_t n, uint32_t i, struct psh_tok *t)
{
	uint32_t j = i + 2u;

	t->kind = KGENOME_TEXTUAL_COMMENT;
	t->open = 2u;
	for (; j + 1u < n; j++) {
		const uint8_t *h = memchr(p + j, '#', n - j - 1u);

		if (!h)
			break;
		j = (uint32_t)(h - p);
		if (p[j + 1u] == '>') {
			t->end = j + 2u;
			t->close = 2u;
			t->flags = 0;
			return;
		}
	}
	t->end = n;
	t->close = 0;
	t->flags = KGENOME_TEXTUAL_F_OPEN;
}

/*
 * Does a string or a comment begin at `i`. Answers 1 and fills `t` (`end` is where it ends; an unclosed one ends at
 * `n` with F_OPEN), or 0 when what is there is code. `bound` is where the last one ended (psh_comment_ok).
 */
static uint32_t psh_token_at(const uint8_t *p, uint32_t n, uint32_t i, uint32_t bound, uint32_t depth,
			     struct psh_tok *t)
{
	uint8_t c = p[i];

	if (c == '#' || (c == '<' && i + 1u < n && p[i + 1u] == '#')) {
		if (!psh_comment_ok(p, i, bound))
			return 0;
		if (c == '<') {
			psh_block_comment(p, n, i, t);
		} else {
			uint32_t j = i;

			while (j < n && p[j] != '\n' && p[j] != '\r')
				j++;
			*t = (struct psh_tok){ .end = j, .open = 1u, .kind = KGENOME_TEXTUAL_COMMENT };
		}
		return 1;
	}
	if (kgenome_textual_psh_sq_len(p, n, i)) {
		psh_sq(p, n, i, t);
		return 1;
	}
	if (kgenome_textual_psh_dq_len(p, n, i)) {
		psh_dq(p, n, i, depth, t);
		return 1;
	}
	return c == '@' && psh_here(p, n, i, depth, t);
}

void kgenome_textual_psh_lex(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = 0, bound = 0, nobrace = UINT32_MAX;
	struct psh_tok t;

	/* A byte order mark is not a word: "<EF BB BF># Copyright" is a comment, as most files saved by a Windows editor begin. */
	if (n >= 3u && p[0] == 0xefu && p[1] == 0xbbu && p[2] == 0xbfu)
		bound = 3u;

	while (i < n) {
		uint8_t c = p[i];

		if (c == '`') {
			i = n - i < 2u ? n : i + 2u;
			continue;
		}
		if (c == '$' && i + 1u < n && p[i + 1u] == '{') {
			uint32_t e = i < nobrace ? psh_brace_end(p, n, i + 2u) : 0;

			if (!e)
				nobrace = i;            /* nothing closes it, nor any later one */
			i = e ? e : i + 2u;
			continue;
		}
		if (!psh_token_at(p, n, i, bound, 0, &t)) {
			i++;
			continue;
		}
		if (!kgenome_textual_span_at(lx, i, t.end, t.kind, t.flags, t.open, t.close))
			return;
		i = bound = t.end;
	}
	kgenome_textual_code_to(lx, n);
}
