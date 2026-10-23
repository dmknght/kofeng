/*
 * bat_cmd.c - the words, commands and assignments of batch (textual.h, "THE WORDS OF A COMMAND LANGUAGE"), as cmd.exe reads a batch FILE. [Unverified] against cmd.exe: this machine
 * has none (no wine either); every rule below is the documented behaviour, and each quirk it relies on is named.
 *
 * WHAT cmd.exe DOES, AS RELIED ON HERE:
 *   - A line is read, `%name%` is replaced by the variable's value (and `%%` by `%`) BEFORE the line is parsed: an expansion is a text macro, not a word. `%name:a=b%` replaces every
 *     "a" by "b" ignoring case, `%name:~o,l%` is the characters from o (a negative o counts from the end) for l (a negative l stops that many from the end). In a FILE a name that is
 *     not set expands to nothing; this reader leaves the question to its caller (an unknown name is no constant).
 *   - `set v=text` takes the text to the end of the command, which is the first unquoted & | < >, and keeps its trailing blanks: `set v=a & echo` gives "a ". The name is the text before the first "=",
 *     blanks included (`set v =a` sets "v "). `set "v=text"` ends the text at the closing quote and ignores what follows. The quotes of an unquoted `set v="a b"` are part of the value.
 *   - `^` escapes the next byte and `!name!` is expanded when delayed expansion is on: a word with either is not read. `%1` .. `%9`, `%*` and `%~..` are parameters: not read.
 *   - `rem`, `::` and a label (":name") are not commands. `set /a` and `set /p` write a name this does not read the value of.
 *   - A command inside a block of parentheses has its line expanded when the WHOLE block was read, so what `set` made inside is not in `%v%` in the block: the paren count of each command
 *     is told, and the caller reads nothing in a block.
 */

#include <string.h>

#include "bat.h"

/* The expansion `%...%` at pos (the first %): the byte after the closing %, or 0 when there is none on the line. */
static uint32_t percent(struct kgenome_textual_wst *s, uint32_t pos)
{
	const uint8_t *in = s->in;
	uint32_t q, colon, oplen;
	struct kgenome_textual_range name, arg[2];
	struct kgenome_textual_fn f;
	const char *spelled;
	int row;

	for (q = pos + 1u; q < s->limit && in[q] != '%' && in[q] != '\n'; q++)
		;
	if (q >= s->limit || in[q] != '%' || q == pos + 1u) {
		s->ok = 0;
		return q >= s->limit || in[q] == '\n' ? 0u : q + 1u;
	}
	if (kof_is_digit(in[pos + 1u]) || in[pos + 1u] == '*' || in[pos + 1u] == '~') {          /* %1, %*, %~dp0 */
		s->ok = 0;
		return q + 1u;
	}
	for (colon = pos + 1u; colon < q && in[colon] != ':'; colon++)
		;
	name = (struct kgenome_textual_range){ pos + 1u, colon - pos - 1u };
	if (colon == q) {
		if (s->ok && s->sk && !s->sk->var(s->sk->user, name, 0))
			s->ok = 0;
		return q + 1u;
	}
	row = kgenome_textual_expand_at(s->l, in, colon, q, 0, &oplen);
	if (row < 0 || !kgenome_textual_fn_row(s->l->id, (uint32_t)row, &spelled, &f)) {
		s->ok = 0;
		return q + 1u;
	}
	{
		uint32_t b = colon + oplen, m;

		for (m = b; m < q && in[m] != f.sep; m++)
			;
		arg[0] = (struct kgenome_textual_range){ b, m - b };
		if (f.max_args >= 3u && f.sep && m < q) {
			arg[1] = (struct kgenome_textual_range){ m + 1u, q - m - 1u };
			if (s->ok && s->sk && !s->sk->expand(s->sk->user, name, (uint32_t)row, arg, 2u, 0))
				s->ok = 0;
		} else if (f.max_args == 3u && f.sep && !strcmp(spelled, ":")) {       /* %v:a% : a replacement with no "=" is no expansion */
			s->ok = 0;
		} else if (s->ok && s->sk && !s->sk->expand(s->sk->user, name, (uint32_t)row, arg, 1u, 0)) {
			s->ok = 0;
		}
	}
	return q + 1u;
}

static uint32_t bat_word(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, uint32_t ctx, const struct kgenome_textual_word_sink *sk)
{
	struct kgenome_textual_wst s = { l, in, limit, sk, 1, 0 };
	uint32_t pos = from;
	int inq = 0;

	while (pos < limit) {
		uint8_t c = in[pos];
		uint32_t run;

		if (ctx == KGENOME_TEXTUAL_CTX_WORD && !inq && (kgenome_textual_blank(c) || c == '&' || c == '|' || c == '<' || c == '>' || c == '\n'))
			break;
		if (c == '%') {
			if (pos + 1u < limit && in[pos + 1u] == '%') {
				if (s.ok && sk && !sk->lit(sk->user, (const uint8_t *)"%", 1))
					s.ok = 0;
				pos += 2u;
				continue;
			}
			pos = percent(&s, pos);
			if (!pos)
				return 0;
			continue;
		}
		if (c == '^' || c == '!') {
			s.ok = 0;
			pos += c == '^' ? 2u : 1u;
			continue;
		}
		if (c == '"')
			inq = !inq;
		for (run = pos + 1u; run < limit; run++) {
			uint8_t d = in[run];

			if (d == '%' || d == '^' || d == '!' || d == '"' || (ctx == KGENOME_TEXTUAL_CTX_WORD && !inq && (kgenome_textual_blank(d) || d == '&' || d == '|' || d == '<' || d == '>' || d == '\n')))
				break;
		}
		kgenome_textual_wst_lit(&s, in + pos, run - pos);
		pos = run;
	}
	return s.ok ? pos : 0u;
}

/* The end of the command text that begins at pos: the first unquoted & | or line break (and, for `redirect`, < or >). A caret escapes a byte. */
static uint32_t cmd_end(const uint8_t *in, uint32_t pos, uint32_t limit, int redirect)
{
	int inq = 0;

	for (; pos < limit; pos++) {
		uint8_t c = in[pos];

		if (c == '^' && !inq) {
			pos++;
		} else if (c == '"') {
			inq = !inq;
		} else if (!inq && (c == '&' || c == '|' || c == '\n' || (redirect && (c == '<' || c == '>')))) {
			break;
		}
	}
	return pos < limit ? pos : limit;
}

static int lower_is(const uint8_t *in, struct kgenome_textual_range w, const char *s)
{
	return w.len == strlen(s) && kgenome_textual_ci_eq(in + w.off, s, w.len);
}

static int bat_command(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, struct kgenome_textual_cmd *c)
{
	uint32_t pos = from, t, i;

	(void)l;
	memset(c, 0, sizeof *c);
	while (pos < limit && (kgenome_textual_blank(in[pos]) || in[pos] == '@'))
		pos++;
	if (pos >= limit) {
		c->end = limit;
		return 1;
	}
	if (in[pos] == '\n') {
		c->term = '\n';
		c->end = pos + 1u;
		return 1;
	}
	t = cmd_end(in, pos, limit, 0);
	if (in[pos] == ':' || (t - pos >= 3u && kgenome_textual_ci_eq(in + pos, "rem", 3u) && (t - pos == 3u || kgenome_textual_blank(in[pos + 3u])))) {
		t = pos;                                /* a label, a "::" comment, rem: the line is not a command */
		while (t < limit && in[t] != '\n')
			t++;
		c->term = t < limit ? '\n' : 0u;
		c->end = t < limit ? t + 1u : limit;
		return 1;
	}
	for (i = pos; i < t;) {                         /* the words: blanks apart, a quoted run one piece, a caret keeps the byte after it */
		uint32_t b, inq = 0;

		while (i < t && kgenome_textual_blank(in[i]))
			i++;
		if (i >= t)
			break;
		if (in[i] == '<' || in[i] == '>') {     /* a redirection: its target is not an argument */
			c->redirect = 1;
			while (i < t && (in[i] == '<' || in[i] == '>' || in[i] == '&'))
				i++;
			while (i < t && kgenome_textual_blank(in[i]))
				i++;
			while (i < t && (inq || !(kgenome_textual_blank(in[i]) || in[i] == '<' || in[i] == '>'))) {
				inq ^= in[i] == '"';
				i++;
			}
			continue;
		}
		b = i;
		while (i < t && (inq || !(kgenome_textual_blank(in[i]) || in[i] == '<' || in[i] == '>'))) {
			if (in[i] == '^' && !inq)
				i++;
			else
				inq ^= in[i] == '"';
			i++;
		}
		if (i > t)
			i = t;
		if (c->n < KGENOME_TEXTUAL_CMD_WORDS)
			c->w[c->n++] = (struct kgenome_textual_range){ b, i - b };
		else
			c->many = 1;
	}
	for (i = pos; i < t; i++) {
		if (in[i] == '"') {
			for (i++; i < t && in[i] != '"'; i++)
				;
		} else if (in[i] == '(') {
			c->paren++;
		} else if (in[i] == ')') {
			c->paren--;
		}
	}
	if (c->n) {                                     /* the raw text after the first word, to the end of the command (a redirection ends it): `set` takes it whole */
		uint32_t rs = c->w[0].off + c->w[0].len, re = cmd_end(in, rs, limit, 1);

		while (rs < re && kgenome_textual_blank(in[rs]))
			rs++;
		c->rest = (struct kgenome_textual_range){ rs, re - rs };
	}
	if (t < limit) {
		c->term = in[t];
		c->end = t + 1u;
		if (in[t] == '&' || in[t] == '|') {
			if (c->end < limit && in[c->end] == in[t]) {
				c->andor = 1;
				c->end++;
			} else if (in[t] == '|') {
				c->pipe = 1;
			}
		}
	} else {
		c->end = limit;
	}
	return 1;
}

static uint32_t ident_run(const uint8_t *in, uint32_t b, uint32_t e)
{
	uint32_t i = b;

	while (i < e && kof_is_word_byte(in[i]))
		i++;
	return i;
}

static uint32_t bat_assigns(const uint8_t *in, const struct kgenome_textual_cmd *c, struct kgenome_textual_assign *a, uint32_t max)
{
	uint32_t start, end, n = 0, eq, last;
	uint8_t base = 0;

	if (!c->n)
		return 0;
	if (lower_is(in, c->w[0], "call") && c->n > 1u && lower_is(in, c->w[1], "set")) {
		base = KGENOME_TEXTUAL_ASSIGN_CALL;
		start = c->w[1].off + c->w[1].len;
	} else if (lower_is(in, c->w[0], "set")) {
		start = c->w[0].off + c->w[0].len;
	} else {
		return 0;
	}
	end = c->rest.off + c->rest.len;
	while (start < end && kgenome_textual_blank(in[start]))
		start++;
	if (start >= end)
		return 0;
	if (in[start] == '/') {                         /* set /a, set /p: every name in it is written, and none has a value this reads */
		uint32_t i = start + 2u;

		while (i < end && n < max) {
			uint32_t e;

			while (i < end && !kof_is_word_byte(in[i]))
				i++;
			e = ident_run(in, i, end);
			if (e > i) {
				a[n].name = (struct kgenome_textual_range){ i, e - i };
				a[n].value = (struct kgenome_textual_range){ e, 0 };
				a[n++].flags = (uint8_t)(base | KGENOME_TEXTUAL_ASSIGN_UNREAD);
			}
			i = e > i ? e : i + 1u;
		}
		return n;
	}
	if (in[start] == '"') {                         /* set "v=text": the text ends at the last quote, and nothing after it counts */
		uint32_t q = end, v;

		while (q > start + 1u && in[q - 1u] != '"')
			q--;
		for (eq = start + 1u; eq < q && in[eq] != '='; eq++)
			;
		if (eq >= q || q <= start + 1u || in[q - 1u] != '"')
			return 0;
		last = q - 1u;
		v = eq + 1u;
		a[0].name = (struct kgenome_textual_range){ start + 1u, eq - start - 1u };
		a[0].value = (struct kgenome_textual_range){ v, last > v ? last - v : 0u };
		a[0].flags = (uint8_t)(base | KGENOME_TEXTUAL_ASSIGN_RAW);
		if (memchr(in + v, '"', a[0].value.len))
			a[0].flags |= KGENOME_TEXTUAL_ASSIGN_UNREAD;
		return 1;
	}
	for (eq = start; eq < end && in[eq] != '='; eq++)
		;
	if (eq >= end)
		return 0;
	a[0].name = (struct kgenome_textual_range){ start, eq - start };
	a[0].value = (struct kgenome_textual_range){ eq + 1u, end - eq - 1u };
	a[0].flags = (uint8_t)(base | KGENOME_TEXTUAL_ASSIGN_RAW);
	return 1;
}

const struct kgenome_textual_cmd_syntax kgenome_textual_bat_syntax = { bat_word, bat_command, bat_assigns };
