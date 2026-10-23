/*
 * js_lang.c - the row for javascript and jscript: the ECMAScript lexer (textual_ecma.c), and what the form
 * needs to know about a language where a line break can end a statement and "/" can begin a literal.
 */

#include <kofcore.h>

#include "js.h"

/* The whole text is ECMAScript (textual_ecma.c): template literals, a "#!" first line and the HTML-like comments a classic script runs. */
static const struct kgenome_textual_script_lang whole = {
	.lexer = KGENOME_TEXTUAL_PAGE_ECMA,
	.flags = KGENOME_TEXTUAL_ECMA_TEMPLATE | KGENOME_TEXTUAL_ECMA_HASHBANG | KGENOME_TEXTUAL_ECMA_HTML_COMMENT,
};

static int name_byte(uint8_t c)
{
	return kgenome_textual_ident(c) || c == '$';
}

/*
 * WOULD CLOSING THESE TWO UP MAKE A DIFFERENT TOKEN, which is every pair below and a pair is all the form can ask.
 *   - an operator byte twice: "+ +" "- -" "/ /" "* *" "? ?" "< <" ...;
 *   - "/ *" and "/ i": a comment opens, and a regular expression's flags run on into "in" and "instanceof"
 *     (the only words that may follow a literal: "/a/ in o" is not "/a/in o"). "a / i" keeps its space too,
 *     which is the price of asking about two bytes: "/ b" does not;
 *   - "< !", "! -" and "- >": "<!--" and "-->" are comments (Annex B), "a < !--b" and "a-- > b" are not;
 *   - a digit and ".": "1 .toString()" is not "1.toString()", a syntax error;
 *   - two name bytes, "$" one, and a name before "\": "var ab" is "var" and a name, "varab" is one.
 * KNOWN LIMIT: a name that ends in a braced escape, \u{61}, followed by a name closes up; it takes 3 bytes of
 * look-behind to tell it from "} else", and the forms of 24701 real files all kept their syntax tree.
 */
static int js_glue(uint8_t a, uint8_t b)
{
	return kgenome_textual_glue_twice(a, b, "+-*/%=!<>&|.:?^~") ||
	       (a == '/' && (b == '*' || b == 'i')) ||
	       (a == '<' && b == '!') || (a == '!' && b == '-') || (a == '-' && b == '>') ||
	       (kof_is_digit(a) && b == '.') ||
	       (name_byte(a) && (name_byte(b) || b == '\\'));
}

/* The index of the ")" that closes the "(" at `open` in out[0, n), counting brackets only (a ")" in a string misleads it, and then
 * it is a refusal to join, never a join); `n` when none does. */
static uint32_t paren_close(const uint8_t *out, uint32_t n, uint32_t open)
{
	uint32_t i, depth = 0;

	for (i = open; i < n; i++) {
		if (out[i] == '(')
			depth++;
		else if (out[i] == ')' && --depth == 0)
			return i;
	}
	return n;
}

/* Is the word at out[i..] `w`, as a whole word. */
static int word_at(const uint8_t *out, uint32_t n, uint32_t i, const char *w)
{
	uint32_t l = (uint32_t)strlen(w);

	return i + l <= n && memcmp(out + i, w, l) == 0 && (i + l == n || !name_byte(out[i + l]));
}

/*
 * Does the line that ends in ")" end with the header of a statement or a function: `if(...)`, `} else if(...)`, `for await(...)`,
 * `x=function*f(...)`, `async m(...)`, `get x()`. The ")" must be the one that closes that header's "(": `if(a)f(b)` ends in a
 * call, and a block after a call is a statement of its own. Not method shorthand `m()` (it is not told from a call by its
 * bytes; the cost is that "m()\n{" in a class stays two lines).
 */
static int header_ends_line(const uint8_t *out, uint32_t n)
{
	static const char *const stmt[] = { "if", "for", "while", "switch", "catch", "with" };
	static const char *const method[] = { "static", "async", "get", "set" };
	uint32_t ls = n, p, k, f;

	while (ls && out[ls - 1u] != '\n')
		ls--;
	p = ls;
	while (p < n && out[p] == '}')
		p++;
	if (word_at(out, n, p, "else"))
		for (p += 4u; p < n && out[p] == ' '; )
			p++;
	for (k = 0; k < sizeof stmt / sizeof stmt[0]; k++) {
		uint32_t q = p + (uint32_t)strlen(stmt[k]);

		if (!word_at(out, n, p, stmt[k]))
			continue;
		if (word_at(out, n, q + (q < n && out[q] == ' '), "await"))
			q += 6u;
		while (q < n && out[q] == ' ')
			q++;
		return q < n && out[q] == '(' && paren_close(out, n, q) == n - 1u;
	}
	/* a method begins the line, or follows the "{" or "," of an object literal on it */
	for (k = n; k > p && out[k - 1u] != '{' && out[k - 1u] != ','; k--)
		;
	k = k > p ? k : p;
	for (f = 0; f < sizeof method / sizeof method[0]; f++) {
		uint32_t l = (uint32_t)strlen(method[f]);

		if (word_at(out, n, k, method[f]) && k + l + 1u < n && out[k + l] == ' ' &&
		    (name_byte(out[k + l + 1u]) || out[k + l + 1u] == '*' || out[k + l + 1u] == '['))
			return 1;
	}
	/* the last "function" word on the line, then "*", a name, and a parameter list that ends it */
	for (f = n; f > p; f--) {
		uint32_t q;

		if (f < 8u || !word_at(out, n, f - 8u, "function") || (f - 8u > p && name_byte(out[f - 9u])))
			continue;
		for (q = f; q < n && (out[q] == ' ' || out[q] == '*' || name_byte(out[q])); q++)
			;
		return q < n && out[q] == '(' && paren_close(out, n, q) == n - 1u;
	}
	return 0;
}

/*
 * A "{" alone on a line joins the line above only where a line break there cannot have been a statement's end. A line
 * break is one in javascript: "return\n{a:1}" returns undefined and "return {a:1}" returns the object, "x\n{...}" is a
 * statement and a block where "x {...}" is an error, and so is "f(a)\n{...}" - found by the form's check on 24865 real files, in which
 * `const a = new Array(256)` and a block on the next line stopped compiling. So it joins after the header of an if,
 * for, while, switch, catch, with or function (`header_ends_line`), after "=>", else, do, try, catch and finally, and after
 * a byte that cannot end an operand - an operator, "(", "[", ",", ":", ";", "{". Not after a name, a number, a string,
 * a regular expression, "]", "}", "++", "--", and not after a ")" that ends a call. KNOWN LIMIT: "class A\n{" and "m()\n{"
 * are not joined: a name, and a call.
 */
static int js_join_ok(const uint8_t *out, uint32_t n)
{
	static const char *const word[] = { "else", "do", "try", "catch", "finally" };
	uint32_t k;
	uint8_t c;

	if (!n)
		return 1;
	c = out[n - 1u];
	if (c == ';' || c == '{')
		return 1;
	if (c == ')')
		return header_ends_line(out, n);
	if (name_byte(c)) {
		for (k = 0; k < sizeof word / sizeof word[0]; k++) {
			uint32_t l = (uint32_t)strlen(word[k]);

			if (n >= l && memcmp(out + n - l, word[k], l) == 0 && (n == l || !name_byte(out[n - l - 1u])))
				return 1;
		}
		return 0;
	}
	if ((c == '+' || c == '-') && n >= 2u && out[n - 2u] == c)
		return 0;
	return kof_byte_in_set(c, "=,([:?&|^~!%*<>+-@");
}

/*
 * A block comment that holds a line terminator IS one where a statement may end (ES2025 12.4, MultiLineComment):
 * `return` and a comment across two lines and then `x` returns undefined. The terminators are LF, CR, U+2028, U+2029.
 */
static int js_comment_break(const uint8_t *c, uint32_t len)
{
	uint32_t i;

	if (len < 4u || c[1] != '*')
		return 0;
	for (i = 2u; i < len; i++)
		if (c[i] == '\n' || c[i] == '\r' || (c[i] == 0xE2u && i + 2u < len && c[i + 1u] == 0x80u &&
						    (c[i + 2u] == 0xA8u || c[i + 2u] == 0xA9u)))
			return 1;
	return 0;
}

/* ---- the escapes of a string, written as the byte they stand for --------------------------------- */

/*
 * The escape at s[i], which is a backslash, read with the row the value reads (js_value.c: kgenome_textual_esc_scan; ES2025
 * 12.9.4): its length, and in h->v the code point it spells. Any other escape (a quote, "\n", a line continuation) is a pair
 * that is not written. 0: malformed - a "\x" with fewer than two digits, a "\u" with fewer than four, "\u{}" or past 10FFFF -
 * which no engine reads as written. The guard is the legacy octal one: "\0\x31" is NUL and "1", "\01" is one code unit.
 */
static uint32_t js_at(const struct kgenome_textual_unesc *u, uint32_t i, struct kgenome_textual_unesc_hit *h)
{
	uint8_t c = u->s[i + 1u];
	struct kgenome_textual_esc_at a;
	uint32_t l = kgenome_textual_unesc_scan(u, i, &a);

	h->v = a.v;
	h->write = 1;
	h->guard = (uint8_t)(a.kind == KGENOME_ESC_AT_OCT ? KGENOME_UNESC_OCT : 0u);
	if (!l) {
		h->write = 0;
		return c == 'x' || c == 'u' ? 0u : 2u;
	}
	return a.v > 0x10ffffu ? 0u : l;
}

/*
 * THE STRING WITH ITS ESCAPES AS THE BYTES THEY SPELL: "\x65v\u{61}l" and "eval" are one string, and a script that
 * spells a name the first way does it so that no marker matches it. What is written is decided by what keeps the
 * string's value and a second pass's answer:
 *   - exactly \xHH, \uHHHH and \u{H...} (a hex escape of ONE digit is a syntax error, not "\x4" = "\x04"), and
 *     legacy octal (\101 is "A" in a classic script, as php's); the byte is written only when it is printable ASCII and
 *     not a quote of either kind, the backquote, a backslash, "$" or "{": the string ends at the first, and "$" "{"
 *     could meet in a template;
 *   - a digit 0-7 is not written after a legacy octal escape that was kept: "\0\x31" is NUL and "1", and "\01" is one
 *     code unit (0x01);
 *   - a string with a malformed escape is copied whole: "\x4" followed by a written "1" would become "\x41";
 *   - everything else is copied: a backslash and the byte after it are a pair, so "\\x41" is a backslash and "x41".
 * The span is the whole literal, quotes included, and `open_len` the quote. Never longer than `len`.
 */
static uint32_t js_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out)
{
	struct kgenome_textual_unesc u;

	kgenome_textual_unesc_init(&u, s, len, js_at, &kgenome_textual_js_esc);
	kgenome_textual_unesc_ban(&u, "\\\"'`${");
	return kgenome_textual_unesc_run(&u, open_len, out);
}

/*
 * THE DECODERS A SCRIPT CALLS ON ITS OWN LITERALS - only those the host's decoders read the way javascript does:
 *   atob                 base64 (the host's is the lax one: atob also throws on what is not base64, which is a program
 *                        that does not run);
 *   unescape,            the host's RAW url decoder (rawurldecode's) reads "%XX", leaves a stray "%" and KEEPS "+", as they do;
 *   decodeURIComponent   it does not read "%uXXXX": `payload_ok` keeps a literal with that from it. Verified in
 *                        libuncoat/decoders/codings.c (url_read, KUNCOAT_F_RAW).
 * NOT decodeURI (it leaves the escapes of ; / ? : @ & = + $ , # as they are, and the host decodes them: "%3B" is
 * ";" in a script that hides code), NOT String.fromCharCode (its arguments are numbers, not a literal), NOT
 * Buffer.from("..", "base64") (the literal is the first of two arguments, and without the second the same call is a
 * utf-8 string: the hook cannot say which).
 * Javascript is case sensitive and has no "@" and no leading slash; "$" is a name byte.
 */
static const struct kgenome_textual_decoder_row decoder_row[] = {
	{ "atob",               KGENOME_TEXTUAL_DEC_B64 },
	{ "unescape",           KGENOME_TEXTUAL_DEC_RAWURL },     /* neither turns "+" into a space [Unverified: no node here; the language says so] */
	{ "decodeURIComponent", KGENOME_TEXTUAL_DEC_RAWURL },
};

static const struct kgenome_textual_call_style style = {
	.rows = decoder_row, .n_rows = sizeof decoder_row / sizeof decoder_row[0], .dollar = 1,
	.receiver = 1,
};

/* unescape reads "%uXXXX" (a UTF-16 unit) and the host's url decoder does not: a VALUE (escapes already applied) that has one under that decoder
 * is not offered. decodeURIComponent leaves "%u" as it is, so for it this refuses what could be decoded - a conservative edge, since the row
 * is one decoder for both. "+" is no reason to refuse: both keep it, and so does the decoder the row names. */
static int js_payload_ok(const uint8_t *v, uint32_t len, const uint8_t *chain, uint32_t n_chain)
{
	uint32_t i;

	if (!kgenome_textual_chain_has(chain, n_chain, KGENOME_TEXTUAL_DEC_RAWURL))
		return 1;
	for (i = 0; i + 1u < len; i++)
		if (v[i] == '%' && (v[i + 1u] | 0x20u) == 'u')
			return 0;
	return 1;
}

/* A single quoted string: the backslash and the quote escaped, a control byte as its letter or \xHH (a raw line break does not end up in one). */
static const struct kgenome_textual_quote quote = { .q = '\'', .bs = "\\", .letters = KGENOME_TEXTUAL_JS_CTL, .ctl = 'x' };

const struct kgenome_textual_lang kgenome_textual_lang_js = {
	.name = "js",
	.id = KGENOME_TEXTUAL_LANG_JS,
	.gap_comments = KGENOME_TEXTUAL_GAP_LINE | KGENOME_TEXTUAL_GAP_BLOCK,
	.whole = &whole,
	.glue = js_glue,
	.join_brace = 1,
	.join_ok = js_join_ok,
	.comment_break = js_comment_break,
	.universal_eol = 1,
	.keep_hashbang = 1,
	.unescape_str = js_unescape,
	.calls = &style,
	.payload_ok = js_payload_ok,
	.fn_table = &kgenome_textual_js_fn_table,
	.member_dot = 1,
	.value = kgenome_textual_js_value,
	.concat = '+',
	.quote = &quote,
};
