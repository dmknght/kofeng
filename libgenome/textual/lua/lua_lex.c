/*
 * lua_lex.c - the lua lexer: where code is, and what is a string or a comment.
 *
 * The rules are lua 5.4's lexer (llex.c), checked against the 5.4.7 interpreter of the machine it was written on:
 * luac -p accepts every generated program, the form of each generated program and of each of the 1070 .lua files of the machine
 * compiles to the same listing (luac -l -l, lines and addresses taken out) as the program, and the value of every string literal is
 * the one `load` gives (tests/lib/genome/textual_lua.c says how each is run). [Inference] Lua 5.1 to 5.3 lex alike, except
 * what 5.4 added to strings ("\z" and "\x" are 5.2's, "\u{}" is 5.3's) - not run here, there is no such interpreter.
 *
 * LINE BREAKS. "\n", "\r", "\r\n" and "\n\r" are one break each, and a line comment and an unclosed one-line string end
 * before the break.
 *
 * COMMENTS. "--" runs to the end of the line, unless the bytes after it are a long bracket "[" "="* "[": then it is a
 * long comment that ends at the first "]" "="* "]" with the same number of "=", or at the end of the text when there is
 * none (flagged OPEN). "--[=" with no second "[" is a line comment. A first line that begins "#!" is a comment (the form
 * keeps it) and ENDS AT AN LF ONLY: it is not the lexer's but the loader's (lauxlib.c skipcomment reads to "\n"), and the
 * interpreter on this machine skips the whole of a CR-only file after "#!" - found by running generated programs. Lua skips a
 * first line that begins with "#" for any byte after it; only "#!" is taken here, because the form drops comments and a "#"
 * that is code is lua's length operator, which a text may begin with.
 *
 * STRINGS. '...' and "...", a backslash escaping the next byte; a backslash and a line break (the pair is ONE break) is
 * an escaped break, and "\z" skips all the white space after it, line breaks included, so a string can run over lines
 * that way and no other. A one-line string that is not closed ends at its line. Long strings "[" "="* "[" ... "]" "="* "]"
 * have no escape, so the closer is the first matching one. Both are delivered as STRING with the delimiters counted:
 * a short one is INTERP (the form may write its spelled-out bytes as themselves), a long one is not.
 *
 * NUMBERS ARE LEXED, though they are code, because one thing in them decides where a comment begins: "0xe--1" is the hex
 * number 0xe and a comment, "1e-5" has a sign that is not an operator. llex.c's read_numeral takes a digit or "." and a
 * digit, then loops: an exponent letter (e E; p P after a "0x") with an optional sign, or a hex digit, or ".". So "1..2"
 * is one (malformed) numeral and "a..5" is a name, "..", and 5, which is the order lua tries them in ("." then "." is
 * checked first). A name is read whole, digits in it included, so "x1e--c" is a name and a comment.
 *
 * NOT DECODED: a byte of 0x80 or more is a name byte for the form, as in the other languages. Nothing nests: no
 * depth, no stack, one pass, each byte is looked at once (a closer is searched for from where the opener ended, and a
 * "]" run that is not the closer is skipped as a run).
 */

#include "lua.h"

/* The length of the long bracket opener at `j` ("[" "="* "["), 0 when it is not one; its level is that length minus 2. */
static uint32_t lua_long_open(const uint8_t *p, uint32_t n, uint32_t j)
{
	uint32_t k = j + 1u;

	if (j >= n || p[j] != '[')
		return 0;
	while (k < n && p[k] == '=')
		k++;
	return k < n && p[k] == '[' ? k + 1u - j : 0;
}

/* Past the closer "]" "="*level "]" of a long bracket whose body begins at `j`; `*closed` says whether there was one. */
static uint32_t lua_long_end(const uint8_t *p, uint32_t n, uint32_t j, uint32_t level, int *closed)
{
	*closed = 0;
	while (j < n) {
		uint32_t k = j + 1u;

		if (p[j] != ']') {
			j++;
			continue;
		}
		while (k < n && p[k] == '=')
			k++;
		if (k < n && p[k] == ']' && k - j - 1u == level) {
			*closed = 1;
			return k + 1u;
		}
		j = k;          /* the run is not a closer; the byte that ended it may begin one */
	}
	return n;
}

/*
 * Past the short string whose quote is at `q`: after its closer, or where it stopped being one (its line's break, or `n`).
 * AN UNCLOSED STRING NEVER ENDS ON THE CR OF A BACKSLASH, LF, CR: that CR is left out of it, and is code (a line break) like
 * the next one. The form writes the last CR of an unclosed string as an LF (python's rule, shared), and a backslash, LF, LF
 * is an escaped break and a break, where a backslash, LF, CR is ONE escaped break: the string would end one byte sooner in
 * the form than in the text, and the form of the form would not be itself (found on random text). Only a text that is not
 * a program is read differently.
 */
static uint32_t lua_short_end(const uint8_t *p, uint32_t n, uint32_t q, int *closed)
{
	uint32_t j = q + 1u, nl, lfcr = 0, e = n;

	*closed = 0;
	while (j < n) {
		uint8_t c = p[j];

		if (c == '\\') {
			if (j + 1u < n && p[j + 1u] == 'z') {
				for (j += 2u; j < n && kof_is_space_byte(p[j]); j++)
					;
			} else {
				nl = j + 1u < n ? kgenome_textual_lua_nl(p, n, j + 1u) : 0;
				j += nl ? 1u + nl : 2u;
				lfcr = nl == 2u && p[j - 2u] == '\n' ? j : 0;
			}
		} else if (c == p[q]) {
			*closed = 1;
			return j + 1u;
		} else if (kgenome_textual_eol_byte(c)) {
			e = j;
			break;
		} else {
			j++;
		}
	}
	return e == lfcr && e ? e - 1u : e;
}

/* Past the numeral that starts at `i` (a digit, or "." and a digit): llex.c's read_numeral. */
static uint32_t lua_number_end(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint8_t expo = 'e';
	uint32_t j = i + 1u;

	if (p[i] == '0' && j < n && (p[j] | 0x20u) == 'x') {
		expo = 'p';
		j++;
	}
	while (j < n) {
		if ((p[j] | 0x20u) == expo) {
			j++;
			if (j < n && (p[j] == '-' || p[j] == '+'))
				j++;
		} else if (kof_hex_val(p[j]) >= 0 || p[j] == '.') {
			j++;
		} else {
			break;
		}
	}
	return j;
}

/* The long bracket (`ol` bytes of opener) at `i` as a string or, when `kind` says so, a comment; where it ends, 0 if the sink stopped. */
static uint32_t lua_long(struct kgenome_textual_lexer *lx, uint32_t i, uint32_t at, uint32_t ol, uint8_t kind)
{
	int closed;
	uint32_t e = lua_long_end(lx->p, lx->n, at + ol, ol - 2u, &closed);

	return kgenome_textual_lit(lx, i, e, kind, 0, at - i + ol, ol, closed) ? e : 0u;
}

void kgenome_textual_lua_lex(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = 0, e, ol;
	int closed;

	if (n >= 2u && p[0] == '#' && p[1] == '!') {
		for (e = 2u; e < n && p[e] != '\n'; e++)
			;
		if (!kgenome_textual_span_at(lx, 0, e, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0))
			return;
		i = e;
	}
	while (i < n) {
		uint8_t c = p[i];

		if (c == '-' && i + 1u < n && p[i + 1u] == '-') {
			ol = lua_long_open(p, n, i + 2u);
			if (ol) {
				e = lua_long(lx, i, i + 2u, ol, KGENOME_TEXTUAL_COMMENT);
				if (!e)
					return;
			} else {
				e = kgenome_textual_line_end(p, n, i + 2u);
				if (!kgenome_textual_span_at(lx, i, e, KGENOME_TEXTUAL_COMMENT, 0, 2u, 0))
					return;
			}
			i = e;
		} else if (c == '"' || c == '\'') {
			e = lua_short_end(p, n, i, &closed);
			if (!kgenome_textual_lit(lx, i, e, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, 1u, 1u, closed))
				return;
			i = e;
		} else if (c == '[' && (ol = lua_long_open(p, n, i)) != 0) {
			e = lua_long(lx, i, i, ol, KGENOME_TEXTUAL_STRING);
			if (!e)
				return;
			i = e;
		} else if (kgenome_textual_ident_start(c)) {
			for (i++; i < n && kgenome_textual_ident(p[i]); i++)
				;
		} else if (kof_is_digit(c) || (c == '.' && i + 1u < n && kof_is_digit(p[i + 1u]))) {
			i = lua_number_end(p, n, i);
		} else if (c == '.' && i + 1u < n && p[i + 1u] == '.') {
			i += i + 2u < n && p[i + 2u] == '.' ? 3u : 2u;
		} else {
			i++;
		}
	}
	(void)kgenome_textual_code_to(lx, n);
}
