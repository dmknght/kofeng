/*
 * sh_cmd.c - the words, the commands and the assignments of the shell (textual.h, "THE WORDS OF A COMMAND LANGUAGE"): bash's reading of a word, which sh scripts that run under bash
 * share, written as the shell's manual says it.
 *
 * A WORD is bytes against bytes until a blank or one of ; & | ( ) < > ends it (outside quotes): a single-quoted run is its bytes; a double-quoted run is its bytes with the four
 * escapes the shell reads there (\$ \` \" \\ and \ and a line break, which goes) and the expansions; a backslash outside quotes keeps the byte after it; `$name`, `${name}`,
 * `${name<operator>operands}`, `$(command)` and `` `command` `` are expansions. The row's function table spells the operators (shape EXPAND: "//", "#", ":", "^^" ...), so the shell's
 * rules about what each takes are data.
 *
 * WHAT IS REFUSED (the word has no value this can say, and the sink is told no more): a glob character, a brace, a tilde at the front (of an operand too: it is the home directory) - the shell turns the word into other words
 * or a path - `$((`, `$'`, `$"`, a positional or special parameter (`$1 $@ $* $# $? $$ $! $-`), a name no row spells after `${x`, a quote that does not close. A glob character in an
 * OPERAND is a byte of the text (the pattern's own rules are the row's: it refuses a pattern that globs).
 *
 * [Checked against bash 5.3 on this machine, case by case: tests/unit/script_cmds.c.]
 */

#include <string.h>

#include "sh.h"

static int sh_meta(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')' || c == '<' || c == '>';
}

static uint32_t name_run(const uint8_t *in, uint32_t p, uint32_t limit)
{
	uint32_t e = p;

	while (e < limit && kof_is_word_byte(in[e]))
		e++;
	return e;
}

/* ---- where a group ends ---------------------------------------------------------------------------- */

static uint32_t group_end(const uint8_t *in, uint32_t p, uint32_t limit, uint8_t open, uint32_t nest, uint8_t *deep);

/* After the double-quoted run that begins at p (the quote), or 0. `nest` is how many groups are open round it; past KGENOME_TEXTUAL_SH_DEPTH the answer is 0 and `*deep`
 * says it was the bound (what a file nests is not what decides how much stack a scan takes: the two functions call each other once for each level). */
static uint32_t dq_end(const uint8_t *in, uint32_t p, uint32_t limit, uint32_t nest, uint8_t *deep)
{
	uint32_t i;

	if (nest > KGENOME_TEXTUAL_SH_DEPTH) {
		*deep = 1;
		return 0;
	}
	for (i = p + 1u; i < limit; i++) {
		if (in[i] == '\\') {
			i++;
		} else if (in[i] == '$' && i + 1u < limit && (in[i + 1u] == '(' || in[i + 1u] == '{')) {
			uint32_t e = group_end(in, i + 1u, limit, in[i + 1u], nest + 1u, deep);

			if (!e)
				return 0;
			i = e - 1u;
		} else if (in[i] == '`') {
			for (i++; i < limit && in[i] != '`'; i++)
				if (in[i] == '\\')
					i++;
		} else if (in[i] == '"') {
			return i + 1u;
		}
	}
	return 0;
}

/* After the byte that closes the group `open` ("(" or "{") begins at p, quotes and groups inside counted, or 0. A "{" group also reads `$(` as a group of
 * its own (its text is a command); a "(" group needs no such case, its "(" are counted. */
static uint32_t group_end(const uint8_t *in, uint32_t p, uint32_t limit, uint8_t open, uint32_t nest, uint8_t *deep)
{
	const uint8_t close = open == '(' ? ')' : '}';
	uint32_t i, depth = 0;

	if (nest > KGENOME_TEXTUAL_SH_DEPTH) {
		*deep = 1;
		return 0;
	}

	for (i = p; i < limit; i++) {
		if (in[i] == '\\') {
			i++;
		} else if (in[i] == '\'') {
			for (i++; i < limit && in[i] != '\''; i++)
				;
		} else if (in[i] == '"') {
			uint32_t e = dq_end(in, i, limit, nest + 1u, deep);

			if (!e)
				return 0;
			i = e - 1u;
		} else if (open == '{' && in[i] == '$' && i + 1u < limit && in[i + 1u] == '(') {
			uint32_t e = group_end(in, i + 1u, limit, '(', nest + 1u, deep);

			if (!e)
				return 0;
			i = e - 1u;
		} else if (in[i] == open) {
			depth++;
		} else if (in[i] == close && --depth == 0) {
			return i + 1u;
		}
	}
	return 0;
}

/* ---- the sink ---------------------------------------------------------------------------------------- */

static uint32_t word_impl(struct kgenome_textual_wst *s, uint32_t from, uint32_t ctx);

/* The first separator `sep` of in[p..e) that is not inside a quote or a group: its offset, or e. */
static uint32_t find_sep(const uint8_t *in, uint32_t p, uint32_t e, uint8_t sep, uint8_t *deep)
{
	uint32_t i;

	for (i = p; i < e; i++) {
		if (in[i] == '\\') {
			i++;
		} else if (in[i] == '\'') {
			for (i++; i < e && in[i] != '\''; i++)
				;
		} else if (in[i] == '"') {
			uint32_t d = dq_end(in, i, e, 0, deep);

			if (!d)
				return e;
			i = d - 1u;
		} else if (in[i] == '$' && i + 1u < e && (in[i + 1u] == '(' || in[i + 1u] == '{')) {
			uint32_t d = group_end(in, i + 1u, e, in[i + 1u], 0, deep);

			if (!d)
				return e;
			i = d - 1u;
		} else if (in[i] == sep) {
			return i;
		}
	}
	return e;
}

/* `${...}` whose bytes are in[pos .. e) (the "$" at pos, the "}" at e - 1). */
static void braced(struct kgenome_textual_wst *s, uint32_t pos, uint32_t e, int quoted)
{
	const uint8_t *in = s->in;
	uint32_t p = pos + 2u, end = e - 1u, n0, oplen;
	struct kgenome_textual_range name, arg[2];
	struct kgenome_textual_fn f;
	const char *spelled;
	int row, n_arg = 0;

	if (p < end && in[p] == '#' && p + 1u < end && kgenome_textual_name_start(in[p + 1u])) {      /* ${#x}: the length */
		row = kgenome_textual_expand_at(s->l, in, p, end, 1, &oplen);
		n0 = name_run(in, p + oplen, end);
		if (row < 0 || n0 != end) {
			s->ok = 0;
			return;
		}
		name = (struct kgenome_textual_range){ p + oplen, n0 - p - oplen };
		if (s->ok && s->sk && !s->sk->expand(s->sk->user, name, (uint32_t)row, NULL, 0, quoted))
			s->ok = 0;
		return;
	}
	n0 = name_run(in, p, end);
	if (n0 == p || !kgenome_textual_name_start(in[p])) {                    /* ${1}, ${@}, ${!x}: a parameter this does not name */
		s->ok = 0;
		return;
	}
	name = (struct kgenome_textual_range){ p, n0 - p };
	if (n0 == end) {
		if (s->ok && s->sk && !s->sk->var(s->sk->user, name, quoted))
			s->ok = 0;
		return;
	}
	row = kgenome_textual_expand_at(s->l, in, n0, end, 0, &oplen);
	if (row < 0 || !kgenome_textual_fn_row(s->l->id, (uint32_t)row, &spelled, &f)) {
		s->ok = 0;
		return;
	}
	if (f.max_args <= 1u) {                                 /* ${x^^}: no operand */
		if (n0 + oplen != end)
			s->ok = 0;
	} else if (f.max_args == 2u || !f.sep) {                /* one operand, as written */
		arg[0] = (struct kgenome_textual_range){ n0 + oplen, end - n0 - oplen };
		n_arg = 1;
	} else {                                                /* two: the text up to the first separator, and what follows it */
		uint32_t b = n0 + oplen, m = find_sep(in, b, end, f.sep, &s->deep);

		arg[0] = (struct kgenome_textual_range){ b, m - b };
		n_arg = 1;
		if (m < end) {
			arg[1] = (struct kgenome_textual_range){ m + 1u, end - m - 1u };
			n_arg = 2;
		}
	}
	if (s->ok && s->sk && !s->sk->expand(s->sk->user, name, (uint32_t)row, arg, (uint32_t)n_arg, quoted))
		s->ok = 0;
}

/* A "$" at pos: its expansion, and the byte after it in *out; 0 when the text does not close. */
static int dollar(struct kgenome_textual_wst *s, uint32_t pos, uint32_t *out, int quoted)
{
	const uint8_t *in = s->in;
	uint8_t n = pos + 1u < s->limit ? in[pos + 1u] : 0u;
	uint32_t e, r;

	if (n == '(') {
		e = group_end(in, pos + 1u, s->limit, '(', 0, &s->deep);
		if (!e)
			return 0;
		if (pos + 2u < s->limit && in[pos + 2u] == '(') {       /* $((: arithmetic */
			s->ok = 0;
		} else if (s->ok && s->sk && !s->sk->cmd(s->sk->user, (struct kgenome_textual_range){ pos + 2u, e - pos - 3u }, quoted)) {
			s->ok = 0;
		}
		*out = e;
		return 1;
	}
	if (n == '{') {
		e = group_end(in, pos + 1u, s->limit, '{', 0, &s->deep);
		if (!e)
			return 0;
		braced(s, pos, e, quoted);
		*out = e;
		return 1;
	}
	if (kgenome_textual_name_start(n)) {
		r = name_run(in, pos + 1u, s->limit);
		if (s->ok && s->sk && !s->sk->var(s->sk->user, (struct kgenome_textual_range){ pos + 1u, r - pos - 1u }, quoted))
			s->ok = 0;
		*out = r;
		return 1;
	}
	if (!quoted && (n == '\'' || n == '"')) {                       /* $'..' and $"..": not read */
		s->ok = 0;
		if (n == '\'') {
			for (r = pos + 2u; r < s->limit && in[r] != '\''; r++)
				if (in[r] == '\\')
					r++;
			if (r >= s->limit)
				return 0;
			*out = r + 1u;
		} else {
			e = dq_end(in, pos + 1u, s->limit, 0, &s->deep);
			if (!e)
				return 0;
			*out = e;
		}
		return 1;
	}
	if (kof_is_digit(n) || n == '@' || n == '*' || n == '#' || n == '?' || n == '-' || n == '$' || n == '!') {
		s->ok = 0;
		*out = pos + 2u;
		return 1;
	}
	kgenome_textual_wst_lit(s, in + pos, 1);                                    /* a "$" before nothing that expands is a "$" */
	*out = pos + 1u;
	return 1;
}

static int backtick(struct kgenome_textual_wst *s, uint32_t pos, uint32_t *out, int quoted)
{
	const uint8_t *in = s->in;
	uint32_t i;
	int esc = 0;

	for (i = pos + 1u; i < s->limit && in[i] != '`'; i++)
		if (in[i] == '\\') {
			esc = 1;
			i++;
		}
	if (i >= s->limit)
		return 0;
	if (esc)
		s->ok = 0;                                      /* a backslash inside is read by the shell in a way this does not */
	else if (s->ok && s->sk && !s->sk->cmd(s->sk->user, (struct kgenome_textual_range){ pos + 1u, i - pos - 1u }, quoted))
		s->ok = 0;
	*out = i + 1u;
	return 1;
}

static int dq(struct kgenome_textual_wst *s, uint32_t pos, uint32_t *out)
{
	const uint8_t *in = s->in;
	uint32_t i = pos + 1u, run = i;

	while (i < s->limit && in[i] != '"') {
		uint8_t c = in[i];

		if (c == '\\' && i + 1u < s->limit && (in[i + 1u] == '$' || in[i + 1u] == '`' || in[i + 1u] == '"' || in[i + 1u] == '\\' || in[i + 1u] == '\n')) {
			kgenome_textual_wst_lit(s, in + run, i - run);
			if (in[i + 1u] != '\n')
				kgenome_textual_wst_lit(s, in + i + 1u, 1);
			i += 2u;
			run = i;
		} else if (c == '$') {
			uint32_t e;

			kgenome_textual_wst_lit(s, in + run, i - run);
			if (!dollar(s, i, &e, 1))
				return 0;
			i = e;
			run = i;
		} else if (c == '`') {
			uint32_t e;

			kgenome_textual_wst_lit(s, in + run, i - run);
			if (!backtick(s, i, &e, 1))
				return 0;
			i = e;
			run = i;
		} else {
			i++;
		}
	}
	if (i >= s->limit)
		return 0;
	kgenome_textual_wst_lit(s, in + run, i - run);
	*out = i + 1u;
	return 1;
}

/* One word at `from`: its extent (0 when a quote or a group does not close) and, for a sink, its pieces; s->ok is 0 when the word has no value this says. */
static uint32_t word_impl(struct kgenome_textual_wst *s, uint32_t from, uint32_t ctx)
{
	const int word_like = ctx == KGENOME_TEXTUAL_CTX_WORD || ctx == KGENOME_TEXTUAL_CTX_ASSIGN;      /* a word of the command line, or the value of an assignment (a word too) */
	const uint8_t *in = s->in;
	uint32_t pos = from;

	while (pos < s->limit) {
		uint8_t c = in[pos];
		uint32_t e, run;

		if (word_like && sh_meta(c))
			break;
		if (c == '\\') {
			if (pos + 1u >= s->limit) {
				s->ok = 0;
				return 0;
			}
			if (in[pos + 1u] != '\n')
				kgenome_textual_wst_lit(s, in + pos + 1u, 1);
			pos += 2u;
		} else if (c == '\'') {
			for (e = pos + 1u; e < s->limit && in[e] != '\''; e++)
				;
			if (e >= s->limit)
				return 0;
			kgenome_textual_wst_lit(s, in + pos + 1u, e - pos - 1u);
			pos = e + 1u;
		} else if (c == '"') {
			if (!dq(s, pos, &pos))
				return 0;
		} else if (c == '$') {
			if (!dollar(s, pos, &pos, 0))
				return 0;
		} else if (c == '`') {
			if (!backtick(s, pos, &pos, 0))
				return 0;
		} else {
			/* a glob, a brace expansion, a tilde: other words or a path. The tilde is refused in an OPERAND too: the shell expands an unquoted "~" at the front of the operand of
			 * `${x//a/~}`, `${x/a/~}`, `${x#~}`, `${x%~}`, `${x##~}`, `${x%%~}` to $HOME (or the home of the user it names), so the value depends on the machine it runs on and is no
			 * constant (bash 5.3: `x=Banana; echo ${x//a/~}` prints B/home/..n/home/..n/home/..; tests/unit/diag_text_oracle.c). Quoted, escaped or not at the front it is a byte. */
			if ((word_like && (c == '*' || c == '?' || c == '[' || c == '{')) || (c == '~' && pos == from))
				s->ok = 0;
			for (run = pos + 1u; run < s->limit; run++) {
				uint8_t d = in[run];

				if (d == '\\' || d == '\'' || d == '"' || d == '$' || d == '`' || (word_like && (sh_meta(d) || d == '*' || d == '?' || d == '[' || d == '{')))
					break;
			}
			if (ctx == KGENOME_TEXTUAL_CTX_ASSIGN) {
				/* the value of an assignment: a tilde right after an unquoted ":" (or after one that a quote or an expansion in front left at the start of this run) is a tilde-prefix too */
				uint32_t q;

				for (q = pos; q < run; q++)
					if (in[q] == '~' && q > from && in[q - 1u] == ':')
						s->ok = 0;
			}
			kgenome_textual_wst_lit(s, in + pos, run - pos);
			pos = run;
		}
	}
	return pos;
}

static uint32_t sh_word(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, uint32_t ctx, const struct kgenome_textual_word_sink *sk)
{
	struct kgenome_textual_wst s = { l, in, limit, sk, 1, 0 };
	uint32_t e = word_impl(&s, from, ctx);

	return s.ok ? e : 0u;
}

/* ---- commands ------------------------------------------------------------------------------------------ */

/* The extent of the word at `from` for the command reader: a word whose value this does not say still has one. 0 when a quote or a group does not close (`*deep`: when
 * the nesting bound is why). */
static uint32_t extent(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, uint8_t *deep)
{
	struct kgenome_textual_wst s = { l, in, limit, NULL, 1, 0 };
	uint32_t e = word_impl(&s, from, KGENOME_TEXTUAL_CTX_WORD);

	*deep |= s.deep;
	return e;
}

/* The text of a here-document's delimiter word: its quotes and a leading backslash taken off (they only say the body is not expanded). */
static struct kgenome_textual_range delim_of(const uint8_t *in, uint32_t b, uint32_t e)
{
	if (e - b >= 2u && (in[b] == '\'' || in[b] == '"') && in[e - 1u] == in[b])
		return (struct kgenome_textual_range){ b + 1u, e - b - 2u };
	if (e - b >= 2u && in[b] == '\\')
		return (struct kgenome_textual_range){ b + 1u, e - b - 1u };
	return (struct kgenome_textual_range){ b, e - b };
}

/* Past the body of the here-document the command opened: the lines up to the one that is the delimiter (a <<- one may begin with tabs). */
static uint32_t skip_body(const uint8_t *in, uint32_t pos, uint32_t limit, const struct kgenome_textual_cmd *c)
{
	while (pos < limit) {
		uint32_t le = pos, b;

		while (le < limit && in[le] != '\n')
			le++;
		b = pos;
		while (c->hd_dash && b < le && in[b] == '\t')
			b++;
		pos = le < limit ? le + 1u : limit;
		if (le - b == c->hd_delim.len && !memcmp(in + b, in + c->hd_delim.off, c->hd_delim.len))
			return pos;
	}
	return limit;
}

static int sh_command(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, struct kgenome_textual_cmd *c)
{
	uint32_t pos = from;
	struct kgenome_textual_range hd = c->hd_delim;
	uint8_t dash = c->hd_dash;

	memset(c, 0, sizeof *c);
	c->hd_delim = hd;
	c->hd_dash = dash;
	for (;;) {
		uint8_t ch;

		while (pos < limit && (in[pos] == ' ' || in[pos] == '\t'))
			pos++;
		if (pos + 1u < limit && in[pos] == '\\' && in[pos + 1u] == '\n') {
			pos += 2u;
			continue;
		}
		if (pos >= limit)
			break;
		ch = in[pos];
		if (ch == '#') {                        /* a comment: to the line break */
			while (pos < limit && in[pos] != '\n')
				pos++;
			continue;
		}
		if (ch == '\n') {
			c->term = '\n';
			pos++;
			if (c->hd_delim.len)
				pos = skip_body(in, pos, limit, c);
			c->hd_delim.len = 0;
			break;
		}
		if (ch == ';') {
			c->term = ';';
			pos++;
			if (pos < limit && in[pos] == ';')
				pos++;
			break;
		}
		if (ch == '&' || ch == '|') {
			c->term = ch;
			pos++;
			if (pos < limit && in[pos] == ch) {
				c->andor = 1;
				pos++;
			} else if (ch == '|') {
				c->pipe = 1;
			}
			break;
		}
		if (ch == '(' || ch == ')') {
			c->term = ch;
			c->paren += ch == '(' ? 1 : -1;
			pos++;
			break;
		}
		if (ch == '<' || ch == '>') {           /* a redirection: its operator and its target are not arguments */
			int heredoc = ch == '<' && pos + 1u < limit && in[pos + 1u] == '<' && !(pos + 2u < limit && in[pos + 2u] == '<');
			uint32_t b, e, ops = pos;

			if (c->n && c->w[c->n - 1u].off + c->w[c->n - 1u].len == pos) {     /* `2>`: the digits are the descriptor */
				uint32_t k;

				for (k = 0; k < c->w[c->n - 1u].len && kof_is_digit(in[c->w[c->n - 1u].off + k]); k++)
					;
				if (k == c->w[c->n - 1u].len)
					c->n--;
			}
			while (pos < limit && (in[pos] == '<' || in[pos] == '>' || in[pos] == '&' || in[pos] == '|' || in[pos] == '-'))
				pos++;
			c->redirect = 1;
			dash = memchr(in + ops, '-', pos - ops) != NULL;
			while (pos < limit && (in[pos] == ' ' || in[pos] == '\t'))
				pos++;
			b = pos;
			e = extent(l, in, b, limit, &c->deep);
			if (!e) {
				c->open = 1;                    /* the target is the rest of the text */
				pos = limit;
				break;
			}
			if (heredoc) {
				c->hd_delim = delim_of(in, b, e);
				c->hd_dash = dash ? 1u : 0u;
			}
			pos = e > b ? e : b;
			continue;
		}
		{
			uint32_t e = extent(l, in, pos, limit, &c->deep);

			if (!e || e == pos) {
				c->open = 1;                    /* the word is the rest of the text, as the shell reads a quote that does not close: read once, and nothing is left after it */
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

/* ---- assignments ------------------------------------------------------------------------------------------ */

/* Is the word `NAME=` or `NAME+=` (name: letters, digits, "_"): the length of the name and of the operator, or 0. */
static uint32_t assign_head(const uint8_t *in, struct kgenome_textual_range w, uint32_t *oplen)
{
	uint32_t n = 0;

	if (!w.len || !kgenome_textual_name_start(in[w.off]))
		return 0;
	while (n < w.len && kof_is_word_byte(in[w.off + n]))
		n++;
	if (n < w.len && in[w.off + n] == '=')
		*oplen = 1;
	else if (n + 1u < w.len && in[w.off + n] == '+' && in[w.off + n + 1u] == '=')
		*oplen = 2;
	else
		return 0;
	return n;
}

static uint32_t sh_assigns(const uint8_t *in, const struct kgenome_textual_cmd *c, struct kgenome_textual_assign *a, uint32_t max)
{
	static const char *const kw[] = { "export", "readonly", "declare", "typeset", "local" };
	/* words that start a command but are not the command: `while IFS== read ..` assigns IFS for read; after "then", "do",
	 * "else" the assignment is in a branch, so it is read by nobody */
	static const char *const lead[] = { "if", "elif", "while", "until", "!", "time", "then", "do", "else" };
	uint32_t i = 0, n = 0, k, first, lead_n = 0;
	int keyword = 0, branch = 0;
	uint8_t base = 0;

	for (; lead_n < c->n; lead_n++) {
		for (k = 0; k < 9u && !kgenome_textual_range_is(in, c->w[lead_n], lead[k]); k++)
			;
		if (k == 9u)
			break;
		if (k >= 6u || k == 1u)
			branch = 1;
	}
	if (lead_n >= c->n)
		return 0;
	for (k = 0; k < 5u; k++)
		if (kgenome_textual_range_is(in, c->w[lead_n], kw[k])) {
			keyword = 1;
			base = k == 4u ? KGENOME_TEXTUAL_ASSIGN_LOCAL : 0u;
			i = lead_n + 1u;
		}
	if (!keyword)
		i = lead_n;
	while (keyword && i < c->n && c->w[i].len && in[c->w[i].off] == '-')       /* -r, -x, -g: options */
		i++;
	first = i;
	for (; i < c->n && n < max; i++) {
		uint32_t op, nl = assign_head(in, c->w[i], &op);

		if (!nl) {
			if (!keyword)
				break;
			continue;
		}
		a[n].name = (struct kgenome_textual_range){ c->w[i].off, nl };
		a[n].value = (struct kgenome_textual_range){ c->w[i].off + nl + op, c->w[i].len - nl - op };
		a[n].flags = (uint8_t)(base | (op == 2u || branch ? KGENOME_TEXTUAL_ASSIGN_UNREAD : 0u));
		/* `x=(a b)`: the "(" ends the word and the array is the command's term */
		if (c->term == '(' && i + 1u == c->n && !a[n].value.len)
			a[n].flags |= KGENOME_TEXTUAL_ASSIGN_UNREAD;
		n++;
	}
	if (!keyword && n && i < c->n)                  /* `x=1 cmd`: x for cmd alone */
		for (k = 0; k < n; k++)
			a[k].flags |= KGENOME_TEXTUAL_ASSIGN_ENV;
	(void)first;
	return n;
}

/* ---- the value of a literal ------------------------------------------------------------------------------ */

struct vsink {
	uint8_t *out;
	uint32_t w;
};

static int v_lit(void *u, const uint8_t *p, uint32_t n)
{
	struct vsink *v = u;

	memcpy(v->out + v->w, p, n);
	v->w += n;
	return 1;
}

static int v_var(void *u, struct kgenome_textual_range name, int quoted)
{
	(void)u;
	(void)name;
	(void)quoted;
	return 0;
}

static int v_expand(void *u, struct kgenome_textual_range name, uint32_t row, const struct kgenome_textual_range *arg, uint32_t n_arg, int quoted)
{
	(void)u;
	(void)name;
	(void)row;
	(void)arg;
	(void)n_arg;
	(void)quoted;
	return 0;
}

static int v_cmd(void *u, struct kgenome_textual_range inner, int quoted)
{
	(void)u;
	(void)inner;
	(void)quoted;
	return 0;
}

/* The row's `value`: the bytes a quoted run of the shell holds, when nothing in it expands - the same reader as a word's, with a sink that has no variable and no command. */
int kgenome_textual_sh_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags, uint8_t *out, uint32_t *n)
{
	struct vsink v = { out, 0 };
	struct kgenome_textual_word_sink sk = { &v, v_lit, v_var, v_expand, v_cmd };
	struct kgenome_textual_wst s = { &kgenome_textual_lang_sh, lit, len, &sk, 1, 0 };
	uint32_t e;

	if (len < open_len + close_len || !open_len || (flags & (KGENOME_TEXTUAL_F_OPEN | KGENOME_TEXTUAL_F_HERE)))
		return 0;
	e = word_impl(&s, 0, KGENOME_TEXTUAL_CTX_OPERAND);
	if (!s.ok || e != len)
		return 0;
	*n = v.w;
	return 1;
}

const struct kgenome_textual_cmd_syntax kgenome_textual_sh_syntax = { sh_word, sh_command, sh_assigns };
