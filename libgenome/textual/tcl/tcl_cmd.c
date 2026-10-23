/*
 * tcl_cmd.c - the words, the commands and the assignments of tcl (textual.h, "THE WORDS OF A COMMAND LANGUAGE"), as the Tcl manual's twelve rules (Tcl(n)) say.
 *
 * A COMMAND is words separated by blanks, ended by a line break or ";" outside any group. A WORD is one of: a braced word `{..}` (its bytes, nothing substituted but
 * backslash-newline), a double-quoted word `"..."`, or a bare word; the last two substitute `$name`, `${name}`, `[command]` and backslash escapes, and a bare word ends at a blank.
 * Everything a word is made of is one word whatever its value holds: tcl does not split a substitution into more words, which is why no quoting context is told.
 *
 * NOT READ (the sink is told no more): `$name(index)` (an array element), a braced word holding a backslash, anything after a closing brace or quote that is not the end of the word.
 * A braced body is a word like any other here: what is inside it - a proc, an if - is not read (the lexer calls it a string too).
 * [Unverified] against tclsh: none is on this machine; the rules are the manual's, and tcl_esc.c's notes record what tclsh 8.6.16 did for the escapes it reads.
 */

#include <string.h>

#include "tcl.h"

/* After the "}" that closes the "{" at p (a backslash keeps the byte after it from counting), or 0. */
static uint32_t brace_close(const uint8_t *in, uint32_t p, uint32_t limit)
{
	uint32_t i, depth = 0;

	for (i = p; i < limit; i++) {
		if (in[i] == '\\')
			i++;
		else if (in[i] == '{')
			depth++;
		else if (in[i] == '}' && --depth == 0)
			return i + 1u;
	}
	return 0;
}

/* After the "]" that closes the "[" at p: a command, so braces, quotes and nested brackets inside count. */
static uint32_t bracket_close(const uint8_t *in, uint32_t p, uint32_t limit)
{
	uint32_t i, depth = 0;

	for (i = p; i < limit; i++) {
		if (in[i] == '\\') {
			i++;
		} else if (in[i] == '{') {
			uint32_t e = brace_close(in, i, limit);

			if (!e)
				return 0;
			i = e - 1u;
		} else if (in[i] == '"') {
			for (i++; i < limit && in[i] != '"'; i++)
				if (in[i] == '\\')
					i++;
			if (i >= limit)
				return 0;
		} else if (in[i] == '[') {
			depth++;
		} else if (in[i] == ']' && --depth == 0) {
			return i + 1u;
		}
	}
	return 0;
}

/* Is the "$" at i a substitution: a name (letters, digits, "_", "::"), a braced name or an index follows. */
static int subst_at(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint8_t c;

	if (i + 1u >= n)
		return 0;
	c = p[i + 1u];
	return kof_is_word_byte(c) || c == '{' || (c == ':' && i + 3u < n && p[i + 2u] == ':' && kof_is_word_byte(p[i + 3u]));
}

struct st {
	const uint8_t *in;
	uint32_t limit;
	const struct kgenome_textual_word_sink *sk;
	int ok;
};

/* The bytes of in[b..e) as the word's literal run: its value as tcl reads it between substitutions. */
static void run(struct st *s, uint32_t b, uint32_t e, int braced)
{
	uint8_t out[4096 + 8];
	uint32_t w = 0;

	if (e <= b || !s->ok)
		return;
	/* the value of a run is never longer than the run; one past 4 KB is not read (a literal that long is data, and the reader keeps no allocation) */
	if (e - b > 4096u || !kgenome_textual_tcl_text_value(s->in + b, e - b, braced, out, &w))
		s->ok = 0;
	else if (s->sk && w && !s->sk->lit(s->sk->user, out, w))
		s->ok = 0;
}

/* The pieces of the double-quoted or bare word whose content is in[b..e) (a quote ends the word, so only a bare word stops at a blank, found by the caller). */
static void pieces(struct st *s, uint32_t b, uint32_t e)
{
	const uint8_t *in = s->in;
	uint32_t i = b, from = b;

	while (i < e) {
		if (in[i] == '\\') {
			i += 2u;
		} else if (in[i] == '$' && subst_at(in, e, i)) {
			struct kgenome_textual_range name;
			uint32_t r;

			run(s, from, i, 0);
			if (in[i + 1u] == '{') {
				for (r = i + 2u; r < e && in[r] != '}'; r++)
					;
				if (r >= e) {
					s->ok = 0;
					return;
				}
				name = (struct kgenome_textual_range){ i + 2u, r - i - 2u };
				r++;
			} else {
				for (r = i + 1u; r < e && (kof_is_word_byte(in[r]) || (in[r] == ':' && r + 1u < e && in[r + 1u] == ':' && r + 2u < e && kof_is_word_byte(in[r + 2u]))); r++)
					if (in[r] == ':')
						r++;
				name = (struct kgenome_textual_range){ i + 1u, r - i - 1u };
				if (r < e && in[r] == '(')              /* $name(index) */
					s->ok = 0;
			}
			if (s->ok && s->sk && !s->sk->var(s->sk->user, name, 0))
				s->ok = 0;
			i = r;
			from = i;
		} else if (in[i] == '[') {
			uint32_t r = bracket_close(in, i, e);

			if (!r) {
				s->ok = 0;
				return;
			}
			run(s, from, i, 0);
			if (s->ok && s->sk && !s->sk->cmd(s->sk->user, (struct kgenome_textual_range){ i + 1u, r - i - 2u }, 0))
				s->ok = 0;
			i = r;
			from = i;
		} else {
			i++;
		}
	}
	run(s, from, e, 0);
}

/* The extent of the bare word at `p`: to a blank, a line break or ";", brackets and escapes inside it counted. */
static uint32_t bare_end(const uint8_t *in, uint32_t p, uint32_t limit)
{
	uint32_t i;

	for (i = p; i < limit; i++) {
		if (in[i] == '\\') {
			i++;
		} else if (in[i] == '[') {
			uint32_t e = bracket_close(in, i, limit);

			if (!e)
				return 0;
			i = e - 1u;
		} else if (in[i] == '$' && i + 1u < limit && in[i + 1u] == '{') {
			for (i += 2u; i < limit && in[i] != '}'; i++)
				;
			if (i >= limit)
				return 0;
		} else if (kgenome_textual_blank(in[i]) || in[i] == '\n' || in[i] == ';') {
			break;
		}
	}
	return i < limit ? i : limit;
}

/* The end of the word at `from` (0 when a brace, a quote or a bracket does not close), and whether it ends where a word must. */
static uint32_t extent(const uint8_t *in, uint32_t from, uint32_t limit)
{
	uint32_t e;

	if (in[from] == '{')
		return brace_close(in, from, limit);
	if (in[from] == '"') {
		uint32_t i;

		for (i = from + 1u; i < limit && in[i] != '"'; i++) {
			if (in[i] == '\\') {
				i++;
			} else if (in[i] == '[') {
				e = bracket_close(in, i, limit);
				if (!e)
					return 0;
				i = e - 1u;
			}
		}
		return i < limit ? i + 1u : 0u;
	}
	return bare_end(in, from, limit);
}

static uint32_t tcl_word(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, uint32_t ctx, const struct kgenome_textual_word_sink *sk)
{
	struct st s = { in, limit, sk, 1 };
	uint32_t e;

	(void)l;
	(void)ctx;
	if (from >= limit)
		return 0;
	e = extent(in, from, limit);
	if (!e)
		return 0;
	if (in[from] == '{') {
		run(&s, from + 1u, e - 1u, 1);
	} else if (in[from] == '"') {
		pieces(&s, from + 1u, e - 1u);
	} else {
		pieces(&s, from, e);
	}
	/* a closing brace or quote ends the word: anything touching it is an error in tcl */
	if ((in[from] == '{' || in[from] == '"') && e < limit && !(kgenome_textual_blank(in[e]) || in[e] == '\n' || in[e] == ';'))
		s.ok = 0;
	return s.ok ? e : 0u;
}

static int tcl_command(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, struct kgenome_textual_cmd *c)
{
	uint32_t pos = from;

	(void)l;
	memset(c, 0, sizeof *c);
	for (;;) {
		uint8_t ch;

		while (pos < limit && kgenome_textual_blank(in[pos]))
			pos++;
		if (pos + 1u < limit && in[pos] == '\\' && in[pos + 1u] == '\n') {
			pos += 2u;
			continue;
		}
		if (pos >= limit)
			break;
		ch = in[pos];
		if (ch == '#' && !c->n) {               /* a comment, where a command would begin: to the line break, a backslash before it continues it */
			while (pos < limit && in[pos] != '\n') {
				if (in[pos] == '\\' && pos + 1u < limit)      /* a backslash that ends the text escapes nothing: the end is the end (L9: `end` was past it) */
					pos++;
				pos++;
			}
			continue;
		}
		if (ch == '\n' || ch == ';') {
			c->term = ch;
			pos++;
			break;
		}
		{
			uint32_t e = extent(in, pos, limit);

			if (!e || e <= pos) {
				c->open = 1;                    /* a brace, a quote or a bracket that does not close: tcl reads the rest of the text into it, once */
				pos = limit;
				break;
			}
			if (c->n < KGENOME_TEXTUAL_CMD_WORDS)
				c->w[c->n++] = (struct kgenome_textual_range){ pos, e - pos };
			else
				c->many = 1;
			pos = e;
		}
	}
	c->end = pos;
	return 1;
}

static uint32_t tcl_assigns(const uint8_t *in, const struct kgenome_textual_cmd *c, struct kgenome_textual_assign *a, uint32_t max)
{
	uint32_t i;
	int append;

	if (c->n < 3u || !max || c->many)
		return 0;
	append = kgenome_textual_range_is(in, c->w[0], "append");
	if (!append && !kgenome_textual_range_is(in, c->w[0], "set"))
		return 0;
	for (i = 0; i < c->w[1].len; i++)
		if (!kof_is_word_byte(in[c->w[1].off + i]))
			return 0;
	if (!c->w[1].len)
		return 0;
	a[0].name = c->w[1];
	if (append) {                                    /* every word after the name, joined */
		a[0].value = (struct kgenome_textual_range){ c->w[2].off, c->w[c->n - 1u].off + c->w[c->n - 1u].len - c->w[2].off };
		a[0].flags = KGENOME_TEXTUAL_ASSIGN_WORDS;
	} else {
		a[0].value = c->w[2];
		a[0].flags = c->n > 3u ? KGENOME_TEXTUAL_ASSIGN_UNREAD : 0u;     /* `set a b c` is an error */
	}
	return 1;
}

const struct kgenome_textual_cmd_syntax kgenome_textual_tcl_syntax = { tcl_word, tcl_command, tcl_assigns };
