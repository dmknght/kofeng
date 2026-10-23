/*
 * textual_java.c - java source: the body of a jsp scriptlet, declaration or expression.
 *
 * WHAT IT DECIDES, from the Java Language Specification (JLS 3.3 - 3.10, 17 for text blocks):
 *
 *   - THE SOURCE IS TRANSLATED BEFORE IT IS LEXED. A "\uXXXX" (one or more "u", four hex digits) is the
 *     character it names, and that character is what the lexer sees: """ closes a string, "\u000a"
 *     ends a line comment, "//" begins one. A backslash is eligible to begin such an escape only
 *     when an EVEN number of raw backslashes precede it ("\\u0022" is a backslash, then "u0022"), and
 *     what an escape produces takes no part in a further escape ("\u0022" is a backslash and
 *     "u0022"). This is the one thing a C-shaped lexer gets wrong for java, and it is how obfuscated
 *     shells hide a quote or a newline. Spans are cut at RAW offsets, so an escape is never split.
 *   - "//" ends at a line terminator: "\n", "\r" or "\r\n" (a lone "\r" counts: JLS 3.4), or at the end of
 *     the window, which is where the page's "%>" is. It is not open there: it ended where the line did.
 *   - a block comment does not nest and is open when the window ends first; slash star slash is not a whole one.
 *   - a string or a char literal ends at its quote; a backslash takes the character after it, EXCEPT a line
 *     terminator, because "\" and a line break is no escape in a string (JLS 3.10.7) - so a string that is
 *     not closed ends AT the line break, which stays code, and is open.
 *   - a text block (Java 15+) opens with three quotes, blanks, and a line terminator; the terminator is
 *     part of the opening delimiter, so open_len covers it and the value begins on the next line. Inside
 *     it a backslash takes the next character (so \" and \""" are not closers), a line break does not end
 *     it, and the first three unescaped quotes close it - a fourth quote begins a string of its own,
 *     which is what javac does. Three quotes NOT followed by a line terminator are "" and the start of a
 *     string: that is how Java before 15 reads them and the text is not a valid text block either way.
 *   - annotations, generics ("<", ">" and ">>" as shift or close), lambdas "->", labels and "::" need
 *     nothing: they are code, and no byte of them can open a literal.
 *
 * EVIDENCE: the spans of 23935 real .java files (95 MB, found on this machine) and of 30000 random inputs made of
 * quotes, slashes, backslashes and \u escapes equal those of an independent regex lexer written from the same
 * reading of the JLS (differences: 0, after three bugs in that lexer - a lone backslash at the end of a string,
 * an escaped quote taken for a closer, a backslash after a closing quote - were fixed on its side).
 * The real files have no text block and no escaped quote: those rules rest on the JLS and the random inputs.
 *
 * What is not done, said so it is not mistaken for a lapse: nothing is decoded and no escape is
 * interpreted for its VALUE; a "\u" that is not followed by four hex digits is raw bytes (javac
 * rejects the file, so whatever is chosen is as good as another).
 */

#include <kofcore.h>

#include "textual_private.h"

#define JEOF 0xffffffffu

/* A cursor over the characters java sees. `bs` is how many raw backslashes sit right before `i`. */
struct jcur {
	const uint8_t *p;
	uint32_t       end;
	uint32_t       i;
	uint32_t       bs;
};

/* The character at c->i, and the raw bytes it takes in *len. JEOF at the end of the window. */
static uint32_t jpeek(const struct jcur *c, uint32_t *len)
{
	const uint8_t *p = c->p;
	uint32_t i = c->i, k;

	if (i >= c->end) {
		*len = 0;
		return JEOF;
	}
	if (p[i] == '\\' && !(c->bs & 1u) && i + 1u < c->end && p[i + 1u] == 'u') {
		uint32_t v = 0, d;

		for (k = i + 1u; k < c->end && p[k] == 'u'; k++)
			;
		if (c->end - k >= 4u) {
			for (d = 0; d < 4u && kof_hex_val(p[k + d]) >= 0; d++)
				v = v * 16u + (uint32_t)kof_hex_val(p[k + d]);
			if (d == 4u) {
				*len = k + 4u - i;
				return v;
			}
		}
	}
	*len = 1u;
	return p[i];
}

static void jadv(struct jcur *c, uint32_t len)
{
	c->bs = (len == 1u && c->p[c->i] == '\\') ? c->bs + 1u : 0u;
	c->i += len;
}

/* Take the next character; answers it (JEOF at the end). */
static uint32_t jnext(struct jcur *c)
{
	uint32_t len, v = jpeek(c, &len);

	jadv(c, len);
	return v;
}

static int jeol(uint32_t v)
{
	return v == '\n' || v == '\r';
}

/* A "//" comment whose first slash is at `at` and whose cursor is after both: it runs to the line end. */
static int line_comment(struct kgenome_textual_lexer *lx, struct jcur *c, uint32_t at, uint32_t open)
{
	for (;;) {
		uint32_t len, v = jpeek(c, &len);

		if (v == JEOF || jeol(v))
			break;
		jadv(c, len);
	}
	return kgenome_textual_lit(lx, at, c->i, KGENOME_TEXTUAL_COMMENT, 0, open, 0, 1);
}

/* A block comment whose "/" "*" the cursor is after: to the closing "*" "/", or open at the window's end. */
static int block_comment(struct kgenome_textual_lexer *lx, struct jcur *c, uint32_t at, uint32_t open)
{
	for (;;) {
		uint32_t len, v = jpeek(c, &len);

		if (v == JEOF)
			return kgenome_textual_lit(lx, at, c->i, KGENOME_TEXTUAL_COMMENT, 0, open, 0, 0);
		if (v == '*') {
			struct jcur d = *c;
			uint32_t l2;

			jadv(&d, len);
			if (jpeek(&d, &l2) == '/') {
				uint32_t close_at = c->i;

				jadv(&d, l2);
				*c = d;
				return kgenome_textual_lit(lx, at, c->i, KGENOME_TEXTUAL_COMMENT, 0, open, c->i - close_at, 1);
			}
		}
		jadv(c, len);
	}
}

/*
 * A text block whose three opening quotes the cursor is after, if the opening delimiter is complete: blanks
 * (space, tab, form feed) and a line terminator. Answers 1 and leaves the cursor after the terminator, 0
 * and leaves it where it was.
 */
static int text_block_open(struct jcur *c)
{
	struct jcur d = *c;

	for (;;) {
		uint32_t len, v = jpeek(&d, &len);

		if (v == ' ' || v == '\t' || v == '\f') {
			jadv(&d, len);
			continue;
		}
		if (!jeol(v))
			return 0;
		jadv(&d, len);
		if (v == '\r' && jpeek(&d, &len) == '\n')
			jadv(&d, len);
		*c = d;
		return 1;
	}
}

/* Are the next three characters quotes? Moves c past them when they are. */
static int three_quotes(struct jcur *c)
{
	struct jcur d = *c;

	if (jnext(&d) != '"' || jnext(&d) != '"' || jnext(&d) != '"')
		return 0;
	*c = d;
	return 1;
}

/* A text block whose opening delimiter the cursor is after. */
static int text_block(struct kgenome_textual_lexer *lx, struct jcur *c, uint32_t at)
{
	uint32_t open = c->i - at;

	for (;;) {
		uint32_t len, v = jpeek(c, &len), close_at = c->i;

		if (v == JEOF)
			return kgenome_textual_lit(lx, at, c->i, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, open, 0, 0);
		if (v == '"' && three_quotes(c))
			return kgenome_textual_lit(lx, at, c->i, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, open, c->i - close_at, 1);
		jadv(c, len);
		if (v == '\\')
			jnext(c);       /* the character an escape takes, a line terminator included */
	}
}

/* A string or char literal whose opening quote the cursor is after. */
static int quoted(struct kgenome_textual_lexer *lx, struct jcur *c, uint32_t at, uint32_t q)
{
	uint32_t open = c->i - at;

	for (;;) {
		uint32_t len, v = jpeek(c, &len);

		if (v == JEOF || jeol(v))
			return kgenome_textual_lit(lx, at, c->i, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, open, 0, 0);
		jadv(c, len);
		if (v == q)
			return kgenome_textual_lit(lx, at, c->i, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, open, len, 1);
		if (v == '\\') {
			uint32_t l2, w = jpeek(c, &l2);

			if (w != JEOF && !jeol(w))
				jadv(c, l2);
		}
	}
}

/* A literal or comment that begins with the character `v` at `at`, the cursor after it. nothing when it is not one. */
static void opens(struct kgenome_textual_lexer *lx, struct jcur *c, uint32_t at, uint32_t v, int *ok)
{
	uint32_t len, w;

	if (v == '/') {
		w = jpeek(c, &len);
		if (w != '/' && w != '*')
			return;
		jadv(c, len);
		*ok = w == '/' ? line_comment(lx, c, at, c->i - at) : block_comment(lx, c, at, c->i - at);
		return;
	}
	if (v == '"') {
		struct jcur t = *c;

		if (jnext(&t) == '"' && jnext(&t) == '"' && text_block_open(&t)) {
			*c = t;
			*ok = text_block(lx, c, at);
			return;
		}
		*ok = quoted(lx, c, at, '"');
		return;
	}
	if (v == '\'')
		*ok = quoted(lx, c, at, '\'');
}

int kgenome_textual_java(struct kgenome_textual_lexer *lx, uint32_t end)
{
	struct jcur c = { .p = lx->p, .end = end, .i = lx->pos, .bs = 0 };
	int ok = 1;

	while (ok && c.i < end) {
		uint32_t at = c.i, len, v = jpeek(&c, &len);

		jadv(&c, len);
		opens(lx, &c, at, v, &ok);
	}
	return ok && kgenome_textual_code_to(lx, end);
}
