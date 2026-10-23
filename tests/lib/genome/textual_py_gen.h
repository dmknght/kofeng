#ifndef KGENOME_TEST_TEXTUAL_PY_GEN_H
#define KGENOME_TEST_TEXTUAL_PY_GEN_H

/*
 * textual_py_gen.h - the python program generator of textual_py.c, kept apart so that the test stays under the
 * size of one file and so that a scratch program can include it to write the generated programs to disk for the
 * interpreter to read. Included by textual_py.c only, after textual_check.h and the definition of PY.
 */

/*
 * (b) THE GENERATOR. A program is built from tokens whose class is known when they are written - the generator
 * says "this is a string with a two-byte prefix and a one-byte quote at each end, flagged as escapes" at the
 * moment it writes it - and the expected span list is built beside the text, so what the lexer must answer is
 * not worked out from the text afterwards by a second lexer. What is varied:
 *   - strings: every prefix in every case, ' " ''' """, a raw one, bytes, an f-string; in a body: runs of
 *     plain bytes, the other quote, the string's own quote escaped, escapes of every kind (\n \x4a \101 é
 *     \U0001F600 \N{...}, an unknown one like \d), a backslash and a line break, a line break and one or two
 *     quotes in a triple one, non-ASCII bytes; in an f-string also {{ }}, a backslash in front of a field,
 *     \N{..}, and fields: a name, a number, a call, a subscript, a binary or conditional expression, a lambda
 *     in parentheses, a comprehension, a walrus, a dict, a comment or a continuation inside the field, and a
 *     string of any kind - the f-string's own quote and another f-string included, four deep - then "=", "!r"
 *     and a spec with fields of its own;
 *   - code: statements of every shape python has (decorators, annotations, match, async, lambda, walrus,
 *     comprehensions, slices, star arguments, semicolons, one-line blocks), multi-line brackets with a comment
 *     after each element, implicit concatenation across lines, a keyword touching a string (else"x", 1or"y"),
 *     names that look like prefixes (r, b, rb, f, u) and are not, non-ASCII names, a backslash continuation
 *     and a comment on the line after it, form feeds, blank lines with white space in them;
 *   - the text: indentation of 1 to 8 spaces or tabs, \n or \r\n or \r line endings (inside strings too), a
 *     final line with or without its break.
 * The generator is checked by the interpreter, not trusted: a scratch program includes this file, writes N of its
 * programs to disk and python's compile() reads each, because a generator that wrote text python refuses would
 * be a test of nothing.
 */

#define GEN_MAX 60000u
#define EXP_MAX 8000u

struct sb {
	char     b[8192];
	uint32_t n;
	uint32_t full;          /* an append did not fit: the generator is wrong, and says so */
};

static void sb_cat(struct sb *s, const char *t)
{
	size_t l = strlen(t);

	if (s->n + l < sizeof s->b - 1u) {
		memcpy(s->b + s->n, t, l + 1u);
		s->n += (uint32_t)l;
	} else {
		s->full = 1;
	}
}

struct gen {
	uint64_t s;
	uint8_t  b[GEN_MAX + 64];
	uint32_t n;
	struct kgenome_textual_span x[EXP_MAX];
	uint32_t nx;
	const char *eol;
	const char *ind;                /* one level of indentation */
	uint32_t level;
	uint32_t over;                  /* the program did not fit: a bug of the generator, not a result */
	uint32_t in_def;                /* 0 no, 1 def, 2 async def */
	uint32_t no_walrus;             /* in a class body, where python refuses := in a comprehension */
	uint32_t bare;                  /* the next string has no prefix: a name in front of it would take the prefix's letter */
	uint32_t kind_only;             /* 0 any, 1 not bytes, 2 bytes: adjacent strings are one literal, and python refuses to mix */
	uint32_t no_f;                  /* no f-string: a pattern, a type alias */
	uint32_t ended_comment;         /* the statement's last token is a comment: nothing may follow on its line */
};

static uint32_t rnd(struct gen *g, uint32_t k)
{
	g->s ^= g->s >> 12;
	g->s ^= g->s << 25;
	g->s ^= g->s >> 27;
	return (uint32_t)((g->s * 2685821657736338717ull) >> 33) % k;
}

static int pct(struct gen *g, uint32_t p)
{
	return rnd(g, 100) < p;
}

#define PICK(g, a) (a)[rnd((g), (uint32_t)(sizeof(a) / sizeof((a)[0])))]

static void g_span(struct gen *g, uint8_t kind, const char *t, uint32_t open, uint32_t close, uint8_t flags)
{
	uint32_t len = (uint32_t)strlen(t);

	if (!len)
		return;
	if (g->n + len > GEN_MAX || g->nx + 1u >= EXP_MAX) {
		g->over = 1;
		return;
	}
	if (kind == KGENOME_TEXTUAL_CODE && g->nx && g->x[g->nx - 1u].kind == KGENOME_TEXTUAL_CODE) {
		g->x[g->nx - 1u].len += len;
	} else {
		g->x[g->nx++] = (struct kgenome_textual_span){ .off = g->n, .len = len, .open_len = open,
							      .close_len = close, .kind = kind, .flags = flags };
	}
	memcpy(g->b + g->n, t, len);
	g->n += len;
}

static void code(struct gen *g, const char *t)
{
	g_span(g, KGENOME_TEXTUAL_CODE, t, 0, 0, 0);
	g->ended_comment = 0;
}

static void eol(struct gen *g)
{
	code(g, g->eol);
}

static void indent(struct gen *g, uint32_t level)
{
	uint32_t i;

	for (i = 0; i < level; i++)
		code(g, g->ind);
}

/* A comment: "#" and what follows, not the line break. The text has quotes, braces and backslashes in it. */
static void comment(struct gen *g)
{
	static const char *const text[] = { "# c", "#", "# it's \"x\" '''", "# f\"{", "# \\", "# }} {{ \\N{", "#!/x",
					    "# -*- coding: utf-8 -*-", "# \"\"\" \xc3\xa9", "#\t#", "# r'\\" };

	g_span(g, KGENOME_TEXTUAL_COMMENT, PICK(g, text), 1u, 0, 0);
	g->ended_comment = 1;
}

/* ---- strings ---- */

struct sinfo {
	char     q;
	uint8_t  triple, raw, bytes, fstr, had_field;
};

static void gen_string(struct gen *g, struct sb *o, const struct sinfo *outer, uint32_t depth, uint32_t *open,
		       uint32_t *close, uint32_t *flags, int want_f);

static void gen_field(struct gen *g, struct sb *o, struct sinfo *si, uint32_t depth, int in_spec);

static const char *const fexpr_name[] = { "x", "y1", "_z", "rb", "f", "u", "self", "\xc3\xa9", "os.path", "d" };

/* A string of any kind to put in a field of the f-string `si` (appended to `e`). */
static void field_string(struct gen *g, struct sb *e, const struct sinfo *si, uint32_t depth, int want_f)
{
	struct sb *t = calloc(1, sizeof *t);
	uint32_t o, c, f;

	gen_string(g, t, si, depth + 1u, &o, &c, &f, want_f);
	sb_cat(e, t->b);
	e->full |= t->full;
	free(t);
}

static void gen_fexpr(struct gen *g, struct sb *e, struct sinfo *si, uint32_t depth, int *simple, int *nomod)
{
	uint32_t k = rnd(g, 22);

	*simple = 0;
	if (depth >= 3u && k > 5u)
		k = rnd(g, 3);
	switch (k) {
	case 0: case 1:
		sb_cat(e, PICK(g, fexpr_name));
		*simple = 1;
		break;
	case 2:
		sb_cat(e, PICK(g, ((const char *const[]){ "1", "0x1f", "1_000", "2.5", "1e3", "7j" })));
		*simple = 1;
		break;
	case 3: case 4: case 5:
		field_string(g, e, si, depth, 0);
		break;
	case 6:
		sb_cat(e, "len(");
		field_string(g, e, si, depth, 0);
		sb_cat(e, ")");
		*simple = 1;
		break;
	case 7:
		sb_cat(e, "d[");
		if (pct(g, 40))
			sb_cat(e, "1:2");
		else
			field_string(g, e, si, depth, 0);
		sb_cat(e, "]");
		*simple = 1;
		break;
	case 8:
		sb_cat(e, "(");
		field_string(g, e, si, depth, 0);
		sb_cat(e, pct(g, 50) ? ") + (" : ") if (x) else (");
		field_string(g, e, si, depth, pct(g, 30));
		sb_cat(e, ")");
		break;
	case 9:
		sb_cat(e, "[x, 'a']");
		break;
	case 10:
		sb_cat(e, "(lambda a: a)(1)");
		break;
	case 11:
		sb_cat(e, "[i for i in x if i]");
		break;
	case 12:
		sb_cat(e, g->no_walrus ? "(5)" : "(n := 5)");
		break;
	case 13:
		sb_cat(e, "{1: 2}[1]");
		break;
	case 14:
		sb_cat(e, "x");
		sb_cat(e, PICK(g, ((const char *const[]){ " # c}", " # '\"", " # {x}", " #" })));
		sb_cat(e, g->eol);
		*nomod = 1;
		break;
	case 15:
		sb_cat(e, "x + \\");
		sb_cat(e, g->eol);
		sb_cat(e, " 1");
		*nomod = 1;
		break;
	case 16: case 17:
		field_string(g, e, si, depth, 1);
		break;
	case 18:
		sb_cat(e, "({'k': 1})");
		break;
	case 19:
		sb_cat(e, pct(g, 50) ? "not x" : "-1");
		break;
	case 20: {
		uint32_t saved = g->kind_only;

		g->kind_only = 1u + rnd(g, 2);
		field_string(g, e, si, depth, 0);
		sb_cat(e, " ");
		field_string(g, e, si, depth, 0);
		g->kind_only = saved;
		break;
	}
	default:
		sb_cat(e, "os.path.join(x, d)");
		*simple = 1;
		break;
	}
}

/* The text after a ":" - literal pieces, none with the string's own quote, and fields */
static void gen_spec(struct gen *g, struct sb *o, struct sinfo *si, uint32_t depth)
{
	static const char *const lit[] = { ">10", "<5", "^8", ".2f", "0>8", "%Y-%m-%d", ",", "_", "x", "#x", "e",
					   "%", "+", "" };
	uint32_t i, n = rnd(g, 3) + 1u;

	for (i = 0; i < n; i++) {
		if (depth < 3u && pct(g, 35))
			gen_field(g, o, si, depth + 1u, 1);
		else if (pct(g, 8))
			sb_cat(o, si->q == '"' ? "'>5" : "\"<5");
		else
			sb_cat(o, PICK(g, lit));
	}
}

static void gen_field(struct gen *g, struct sb *o, struct sinfo *si, uint32_t depth, int in_spec)
{
	struct sb *e = calloc(1, sizeof *e);
	int simple = 0, nomod = 0;

	gen_fexpr(g, e, si, depth, &simple, &nomod);
	si->had_field = 1;
	sb_cat(o, "{");
	if (e->b[0] == '{')
		sb_cat(o, " ");
	sb_cat(o, e->b);
	o->full |= e->full;
	free(e);
	if (!nomod) {
		if (simple && !in_spec && pct(g, 15))
			sb_cat(o, pct(g, 50) ? "=" : " = ");
		if (pct(g, 25))
			sb_cat(o, PICK(g, ((const char *const[]){ "!r", "!s", "!a" })));
		if (!in_spec && pct(g, 30)) {
			sb_cat(o, ":");
			gen_spec(g, o, si, depth);
		}
	}
	sb_cat(o, "}");
}

static void gen_body(struct gen *g, struct sb *o, struct sinfo *si, uint32_t depth)
{
	static const char plain[] = "abcxyzABCXYZ019 _-.,;:!?@#$%^&*()[]<>=+/|~`";
	uint32_t items = rnd(g, 8) + (si->triple ? 1u : 0u), i, k, r;
	char one[8];

	for (i = 0; i < items && o->n < 700u - 150u * depth; i++) {
		k = rnd(g, 22);
		switch (k) {
		case 6:
			one[0] = si->q == '"' ? '\'' : '"';
			one[1] = 0;
			sb_cat(o, one);
			break;
		case 7:
			one[0] = '\\';
			one[1] = si->q;
			one[2] = 0;
			sb_cat(o, one);
			break;
		case 8:
			sb_cat(o, PICK(g, ((const char *const[]){ "\\n", "\\t", "\\\\", "\\r", "\\a", "\\0", "\\d", "\\.", "\\/" })));
			break;
		case 9:
			sb_cat(o, PICK(g, ((const char *const[]){ "\\x4a", "\\101", "\\x00", "\\7", "\\x7b", "\\x27" })));
			if (!si->bytes && pct(g, 50))
				sb_cat(o, PICK(g, ((const char *const[]){ "\\u00e9", "\\U0001F600", "\\u0041" })));
			if (!si->bytes && !(si->fstr && si->raw) && pct(g, 30))
				sb_cat(o, "\\N{LATIN SMALL LETTER A}");
			break;
		case 10:
			sb_cat(o, "\\");
			sb_cat(o, g->eol);
			break;
		case 11:
			if (si->triple)
				sb_cat(o, g->eol);
			break;
		case 12:
			if (si->triple) {
				one[0] = si->q;
				one[1] = pct(g, 50) ? si->q : 'z';
				one[2] = one[1] == 'z' ? 0 : 'z';
				one[3] = 0;
				sb_cat(o, one);
			}
			break;
		case 13:
			if (!si->bytes)
				sb_cat(o, PICK(g, ((const char *const[]){ "\xc3\xa9", "\xe6\x97\xa5\xe6\x9c\xac" })));
			break;
		case 14: case 15: case 16: case 17: case 18: case 19:
			if (!si->fstr) {
				sb_cat(o, PICK(g, ((const char *const[]){ "{", "}", "{x}", "{{" })));
			} else if (k == 14) {
				sb_cat(o, "{{");
			} else if (k == 15) {
				sb_cat(o, "}}");
			} else if (k == 19) {
				if (si->raw) {
					sb_cat(o, "\\N{x}");
					si->had_field = 1;
				} else {
					sb_cat(o, "\\N{DIGIT ONE}");
				}
			} else {
				if (k == 18)
					sb_cat(o, "\\");
				gen_field(g, o, si, depth, 0);
			}
			break;
		default:
			r = rnd(g, 5) + 1u;
			while (r--) {
				one[0] = plain[rnd(g, (uint32_t)sizeof plain - 1u)];
				one[1] = 0;
				sb_cat(o, one);
			}
			break;
		}
	}
}

/*
 * One string literal into `o`, with the numbers the lexer must report for it. `want_f`: it is an f-string if
 * the depth allows one. Bytes hold ASCII only. Inside a field of `outer`, a triple string of the same quote as
 * a triple outer one is not written (the closer would be ambiguous to a reader, not to the lexer).
 */
static void gen_string(struct gen *g, struct sb *o, const struct sinfo *outer, uint32_t depth, uint32_t *open,
		       uint32_t *close, uint32_t *flags, int want_f)
{
	static const char *const plain_p[] = { "", "", "", "u", "U" }, *const bytes_p[] = { "b", "B" },
		*const raw_p[] = { "r", "R" }, *const rb_p[] = { "rb", "Rb", "rB", "RB", "br", "bR", "Br", "BR" },
		*const f_p[] = { "f", "F" }, *const rf_p[] = { "rf", "Rf", "rF", "RF", "fr", "fR", "Fr", "FR" };
	struct sinfo si;
	uint32_t k = rnd(g, 100);
	const char *pre;
	char delim[4];
	int fok = depth < 4u;

	memset(&si, 0, sizeof si);
	if (g->bare)
		k = 0;
	else if (want_f && fok && g->kind_only != 2u && !g->no_f)
		k = 60u + rnd(g, 40u);
	else if ((!fok || g->no_f || g->kind_only == 2u) && k >= 60u)
		k = rnd(g, 60u);
	if (g->kind_only == 1u && ((k >= 25u && k < 35u) || (k >= 50u && k < 60u)))
		k = rnd(g, 25u);
	else if (g->kind_only == 2u)
		k = pct(g, 50) ? 25u + rnd(g, 10u) : 50u + rnd(g, 10u);
	if (g->bare)       { pre = ""; }
	else if (k < 25u)  { pre = PICK(g, plain_p); }
	else if (k < 35u)  { pre = PICK(g, bytes_p); si.bytes = 1; }
	else if (k < 50u)  { pre = PICK(g, raw_p); si.raw = 1; }
	else if (k < 60u)  { pre = PICK(g, rb_p); si.raw = si.bytes = 1; }
	else if (k < 85u)  { pre = PICK(g, f_p); si.fstr = 1; }
	else               { pre = PICK(g, rf_p); si.fstr = si.raw = 1; }
	si.q = pct(g, 50) ? '"' : '\'';
	si.triple = (uint8_t)pct(g, 25);
	if (outer && outer->triple && si.triple && si.q == outer->q)
		si.q = si.q == '"' ? '\'' : '"';
	memset(delim, si.q, 3);
	delim[si.triple ? 3 : 1] = 0;
	sb_cat(o, pre);
	sb_cat(o, delim);
	gen_body(g, o, &si, depth);
	sb_cat(o, delim);
	*open = (uint32_t)strlen(pre) + (uint32_t)strlen(delim);
	*close = (uint32_t)strlen(delim);
	*flags = (si.raw || si.had_field) ? 0u : KGENOME_TEXTUAL_F_INTERP;
}

/* A string in the program: the span, with what the lexer must say about it. */
static void gstr(struct gen *g, int want_f)
{
	struct sb *s = calloc(1, sizeof *s);
	uint32_t o, c, f;

	gen_string(g, s, NULL, 0, &o, &c, &f, want_f);
	if (s->full)
		g->over = 1;
	g_span(g, KGENOME_TEXTUAL_STRING, s->b, o, c, (uint8_t)f);
	g->ended_comment = 0;
	free(s);
}

/* ---- code ---- */

static const char *const names[] = { "x", "y", "rb", "f", "b", "u", "r", "br", "fr", "bar", "_", "\xc3\xa9",
				     "\xe5\x8f\x98\xe9\x87\x8f", "self", "os", "d", "n", "t", "ur", "bu" };

static void gen_expr(struct gen *g, uint32_t depth);
static void gen_atom(struct gen *g, uint32_t depth);

/* A keyword and its operand: a string may follow with no space (else"x", or'y'). */
static void kw_then(struct gen *g, const char *kw, uint32_t depth)
{
	code(g, kw);
	if (pct(g, 35)) {
		g->bare = 1;
		gstr(g, 0);
		g->bare = 0;
		return;
	}
	code(g, " ");
	gen_atom(g, depth);
}

static void sep(struct gen *g)
{
	code(g, PICK(g, ((const char *const[]){ ", ", ",", " , ", ",  " })));
}

/* The line break a comment needs after it, and the indentation of the line it starts. */
static void newline(struct gen *g)
{
	eol(g);
	indent(g, g->level + 1u);
}

/* A bracketed list: elements, a comment after some, a line break wherever there is a comment. */
static void gen_items(struct gen *g, const char *open, const char *close, uint32_t depth, int dict)
{
	uint32_t i, n = rnd(g, 4);
	int nl = 0;

	code(g, open);
	for (i = 0; i < n; i++) {
		if (nl || pct(g, 40)) {
			newline(g);
			nl = 0;
		}
		if (dict) {
			gen_atom(g, depth + 1u);
			code(g, pct(g, 50) ? ": " : ":");
		}
		gen_expr(g, depth + 1u);
		if (i + 1u < n || pct(g, 40))
			sep(g);
		if (pct(g, 40)) {
			code(g, " ");
			comment(g);
			nl = 1;
		}
	}
	if (nl || (n && pct(g, 30)))
		newline(g);
	code(g, close);
}

/* An operand: no lambda, no conditional, nothing that cannot stand next to an operator. */
static void gen_atom(struct gen *g, uint32_t depth)
{
	static const char *const nums[] = { "0", "1", "1_000", "0x1f", "0b101", "0o17", "1e-3", "1j", ".5", "1.", "0xB",
					    "10", "3.14" };
	uint32_t k = rnd(g, 22), i, n;

	if (depth >= 3u && k > 5u)
		k = rnd(g, 6);
	switch (k) {
	case 0: case 1:
		code(g, PICK(g, names));
		break;
	case 2:
		code(g, PICK(g, nums));
		break;
	case 3: case 4: case 5: case 6: case 7:
		gstr(g, pct(g, 40));
		break;
	case 8:                                 /* implicit concatenation, on a line or across them */
		code(g, "(");
		g->kind_only = 1u + rnd(g, 2);
		n = rnd(g, 3) + 2u;
		for (i = 0; i < n; i++) {
			if (i) {
				if (pct(g, 50)) {
					code(g, " ");
				} else {
					if (pct(g, 40)) {
						code(g, " ");
						comment(g);
					}
					newline(g);
				}
			}
			gstr(g, pct(g, 30));
		}
		g->kind_only = 0;
		code(g, ")");
		break;
	case 9: case 10:                        /* a call: positional, then keywords, then ** */
		code(g, PICK(g, names));
		code(g, "(");
		n = rnd(g, 3);
		for (i = 0; i < n; i++) {
			if (pct(g, 20))
				code(g, "*");
			gen_expr(g, depth + 1u);
			if (i + 1u < n)
				sep(g);
		}
		if (rnd(g, 3) == 0) {
			if (n)
				sep(g);
			code(g, pct(g, 50) ? "key=" : "key = ");
			gen_expr(g, depth + 1u);
		}
		if (pct(g, 15)) {
			if (n || g->b[g->n - 1u] != '(')
				sep(g);
			code(g, "**");
			gen_atom(g, depth + 1u);
		}
		code(g, ")");
		break;
	case 11:
		gen_items(g, "[", "]", depth, 0);
		break;
	case 12:
		gen_items(g, "(", ")", depth, 0);
		break;
	case 13:
		gen_items(g, "{", "}", depth, (int)rnd(g, 2));
		break;
	case 14:                                /* a comprehension: the element, "for", an iterable, a condition */
		code(g, "[");
		gen_atom(g, depth + 1u);
		code(g, " for i in ");
		code(g, PICK(g, names));
		kw_then(g, " if", depth + 1u);
		code(g, "]");
		break;
	case 15:
		code(g, PICK(g, names));
		code(g, PICK(g, ((const char *const[]){ "[::2]", "[1:]", "[:-1]", "[1:2:3]" })));
		break;
	case 16:
		code(g, PICK(g, names));
		code(g, "[");
		gen_expr(g, depth + 1u);
		code(g, "]");
		break;
	case 17:
		code(g, PICK(g, names));
		code(g, ".");
		code(g, PICK(g, names));
		break;
	case 18:
		code(g, g->no_walrus ? "(" : "(n := ");
		gen_expr(g, depth + 1u);
		code(g, ")");
		break;
	case 19:
		code(g, "(");
		gen_expr(g, depth + 1u);
		code(g, ")");
		break;
	case 20:
		code(g, PICK(g, ((const char *const[]){ "-", "~", "+" })));
		gen_atom(g, depth + 1u);
		break;
	default:
		code(g, PICK(g, names));
		break;
	}
}

static void gen_expr(struct gen *g, uint32_t depth)
{
	static const char *const ops[] = { " + ", "+", " - ", " * ", " // ", " % ", " ** ", " @ ", " << ", " >> ", " & ",
					   " | ", " ^ ", " < ", " == ", " != ", " <= ", ">" };
	static const char *const kws[] = { " or", " and", " in", " is" }, *const kws2[] = { "or", "and", "in", "is" };
	static const char *const nums[] = { "1", "1_000", "10", "3" };
	uint32_t k = rnd(g, 12);

	if (depth >= 3u)
		k = 0;
	switch (k) {
	case 1: case 2: case 3:                 /* an operator between two operands, strings included */
		gen_atom(g, depth + 1u);
		code(g, PICK(g, ops));
		gen_atom(g, depth + 1u);
		break;
	case 4:                                 /* conditional expression; the keyword may touch a string */
		gen_atom(g, depth + 1u);
		code(g, " if ");
		gen_atom(g, depth + 1u);
		kw_then(g, " else", depth + 1u);
		break;
	case 5:                                 /* keyword operators; a string may follow with no space */
		gen_atom(g, depth + 1u);
		kw_then(g, PICK(g, kws), depth + 1u);
		break;
	case 6:                                 /* a number touching a keyword: 1or"x", 1if x else 2 */
		code(g, PICK(g, nums));
		if (pct(g, 50)) {
			kw_then(g, PICK(g, kws2), depth + 1u);
		} else {
			code(g, "if");
			code(g, " ");
			gen_atom(g, depth + 1u);
			kw_then(g, " else", depth + 1u);
		}
		break;
	case 8:                                 /* "not" takes an operand, a string with no space included */
		kw_then(g, "not", depth + 1u);
		break;
	case 7:
		code(g, pct(g, 50) ? "lambda: " : "lambda a, b=");
		if (g->b[g->n - 1u] == '=') {
			gstr(g, 0);
			code(g, ": ");
		}
		gen_expr(g, depth + 1u);
		break;
	default:
		gen_atom(g, depth);
		break;
	}
}

/* ---- statements ---- */

static const char *const targets[] = { "x", "y", "rb", "f", "b", "u", "r", "bar", "_", "\xc3\xa9", "x.y",
				       "a, b", "(a, b)", "[a, b]", "*a, b", "d[1:2]", "" };

static const char *const aug_targets[] = { "x", "y", "rb", "f", "x.y", "_", "" };

/* A target; "" in the table is d[<string>], which has a string in it. */
static void gen_target(struct gen *g, const char *const *table, uint32_t n)
{
	const char *t = table[rnd(g, n)];

	if (*t) {
		code(g, t);
	} else {
		code(g, "d[");
		gstr(g, 0);
		code(g, "]");
	}
}

static void gen_stmt(struct gen *g, uint32_t depth);

/* Blank lines, comment lines at any indentation, and white space on a blank line, before a statement. */
static void line_start(struct gen *g, uint32_t level)
{
	uint32_t n = rnd(g, 3), i;

	for (i = 0; i < n; i++) {
		switch (rnd(g, 4)) {
		case 0:
			eol(g);
			break;
		case 1:
			code(g, PICK(g, ((const char *const[]){ " ", "\t", "  \t", "\f" })));
			eol(g);
			break;
		default:
			indent(g, rnd(g, 4));
			comment(g);
			eol(g);
			break;
		}
	}
	if (level == 0 && pct(g, 8))
		code(g, "\f");
	else
		indent(g, level);
}

static void end_line(struct gen *g)
{
	if (!g->ended_comment && pct(g, 20)) {
		code(g, PICK(g, ((const char *const[]){ " ", "  ", "\t" })));
		comment(g);
	}
	eol(g);
}

/* The statements that take no block, one logical line, without its end. */
static void gen_simple(struct gen *g)
{
	uint32_t k = rnd(g, 22);

	switch (k) {
	case 0: case 1: case 2:
		gen_target(g, targets, (uint32_t)(sizeof targets / sizeof targets[0]));
		code(g, pct(g, 80) ? " = " : "=");
		gen_expr(g, 0);
		break;
	case 3:
		gen_target(g, aug_targets, (uint32_t)(sizeof aug_targets / sizeof aug_targets[0]));
		code(g, PICK(g, ((const char *const[]){ " += ", " -= ", " |= ", " //= ", " <<= ", " @= ", " **= ", " %= " })));
		gen_expr(g, 0);
		break;
	case 4: case 5:
		code(g, "print(");
		gen_expr(g, 0);
		code(g, ")");
		break;
	case 6:
		gen_atom(g, 0);
		break;
	case 7:
		code(g, "assert ");
		gen_expr(g, 0);
		code(g, ", ");
		gstr(g, 0);
		break;
	case 8:
		code(g, "raise ");
		code(g, PICK(g, names));
		code(g, "(");
		gstr(g, 0);
		code(g, pct(g, 50) ? ") from None" : ")");
		break;
	case 9:
		code(g, PICK(g, ((const char *const[]){ "pass", "del x", "del y, z", "x: int" })));
		break;
	case 10:
		code(g, PICK(g, ((const char *const[]){ "import os.path as p", "from . import x", "from .. import y as z",
							"from a import (b, c)", "import a, b" })));
		break;
	case 11:
		code(g, PICK(g, names));
		code(g, ": ");
		gstr(g, 0);
		code(g, " = ");
		gen_expr(g, 0);
		break;
	case 12:
		if (g->in_def) {
			code(g, "return ");
			gen_expr(g, 0);
		} else {
			code(g, "pass");
		}
		break;
	case 13:
		if (g->in_def == 2u) {
			code(g, "await ");
			code(g, PICK(g, names));
			code(g, "()");
		} else if (g->in_def) {
			code(g, "yield ");
			gen_expr(g, 0);
		} else {
			code(g, "...");
		}
		break;
	case 14:                                /* two statements on a line */
		code(g, "a = ");
		gen_expr(g, 1);
		code(g, pct(g, 50) ? "; " : ";");
		code(g, "b = ");
		gen_expr(g, 1);
		if (pct(g, 30))
			code(g, ";");
		break;
	case 15:                                /* a backslash continuation inside an expression */
		code(g, "x = ");
		gen_atom(g, 1);
		code(g, " \\");
		eol(g);
		indent(g, g->level + 1u);
		code(g, "+ 1");
		break;
	case 16:                                /* a comment on the line after a continuation: the statement is complete */
		code(g, "x = ");
		gen_atom(g, 1);
		code(g, " \\");
		eol(g);
		code(g, PICK(g, ((const char *const[]){ "", "  ", "\t" })));
		comment(g);
		break;
	case 17:
		code(g, "assert x, \\");
		eol(g);
		indent(g, g->level + 1u);
		gstr(g, 0);
		break;
	case 18:
		code(g, "type X = ");
		g->no_f = 1;
		gstr(g, 0);
		g->no_f = 0;
		break;
	case 19:
		code(g, "x = ");
		g->kind_only = 1u + rnd(g, 2);
		gstr(g, 0);
		code(g, " \\");
		eol(g);
		code(g, "  ");
		gstr(g, 0);
		g->kind_only = 0;
		break;
	default:
		code(g, "x = ");
		gen_expr(g, 0);
		break;
	}
}

static void gen_block(struct gen *g, uint32_t depth)
{
	uint32_t n = rnd(g, 3) + 1u, i;

	g->level++;
	for (i = 0; i < n; i++)
		gen_stmt(g, depth + 1u);
	g->level--;
}

/* ":" then a block of its own lines, or one simple statement after it */
static void body(struct gen *g, uint32_t depth)
{
	code(g, ":");
	if (depth < 3u && pct(g, 80)) {
		end_line(g);
		gen_block(g, depth);
	} else {
		code(g, " ");
		gen_simple(g);
		end_line(g);
	}
}

static void gen_params(struct gen *g)
{
	switch (rnd(g, 6)) {
	case 0:
		break;
	case 1:
		code(g, "a, b");
		break;
	case 2:
		code(g, "a: ");
		gstr(g, 0);
		code(g, " = ");
		gstr(g, 0);
		break;
	case 3:
		code(g, "*args, **kw");
		break;
	case 4:
		code(g, "a, /, b, *, c=");
		gstr(g, 0);
		break;
	default:
		code(g, "self, x: ");
		gstr(g, 0);
		code(g, " = ");
		gen_expr(g, 1);
		code(g, ", *a: ");
		gstr(g, 0);
		break;
	}
}

/* A def with its decorators, its annotations and a docstring. */
static void gen_def(struct gen *g, uint32_t depth)
{
	uint32_t k = rnd(g, 3), saved = g->in_def, saved_w = g->no_walrus;

	while (pct(g, 25)) {
		code(g, "@");
		gen_atom(g, 2);
		end_line(g);
		line_start(g, g->level);
	}
	if (k == 0) {
		code(g, "async ");
		g->in_def = 2;
	} else {
		g->in_def = 1;
	}
	code(g, "def ");
	code(g, PICK(g, ((const char *const[]){ "f", "g", "rb", "u", "\xc3\xa9", "run" })));
	code(g, "(");
	gen_params(g);
	code(g, ")");
	if (pct(g, 40)) {
		code(g, pct(g, 50) ? " -> " : "->");
		gstr(g, 0);
	}
	code(g, ":");
	end_line(g);
	g->level++;
	if (pct(g, 50)) {
		line_start(g, g->level);
		gstr(g, 0);
		end_line(g);
	}
	g->no_walrus = 0;
	gen_stmt(g, depth + 1u);
	g->no_walrus = saved_w;
	g->level--;
	g->in_def = saved;
}

static void gen_pattern(struct gen *g)
{
	g->no_f = 1;
	switch (rnd(g, 6)) {
	case 0:
		g->kind_only = 1u;
		gstr(g, 0);
		code(g, " | ");
		gstr(g, 0);
		break;
	case 1:
		code(g, "{");
		gstr(g, 0);
		code(g, ": v}");
		break;
	case 2:
		code(g, "[1, *rest]");
		break;
	case 3:
		code(g, "str() as s");
		break;
	case 4:
		gstr(g, 0);
		break;
	default:
		code(g, "1 | 2");
		break;
	}
	g->no_f = g->kind_only = 0;
}

static void gen_match(struct gen *g, uint32_t depth)
{
	uint32_t n = rnd(g, 3) + 1u, i;

	code(g, "match ");
	gen_atom(g, 2);
	code(g, ":");
	end_line(g);
	g->level++;
	for (i = 0; i < n; i++) {
		line_start(g, g->level);
		code(g, "case ");
		gen_pattern(g);
		if (pct(g, 30)) {
			code(g, " if ");
			gen_atom(g, 2);
		}
		body(g, depth + 1u);
	}
	if (pct(g, 30)) {
		line_start(g, g->level);
		code(g, "case _");
		body(g, depth + 1u);
	}
	g->level--;
}

static void gen_stmt(struct gen *g, uint32_t depth)
{
	uint32_t k = depth >= 3u ? 99u : rnd(g, 24), def_state;

	line_start(g, g->level);
	switch (k) {
	case 0: case 1:
		code(g, "if ");
		gen_atom(g, 1);
		body(g, depth);
		if (pct(g, 30)) {
			line_start(g, g->level);
			code(g, "elif ");
			gen_atom(g, 1);
			body(g, depth);
		}
		if (pct(g, 30)) {
			line_start(g, g->level);
			code(g, "else");
			body(g, depth);
		}
		break;
	case 2:
		code(g, "while ");
		gen_atom(g, 1);
		body(g, depth);
		break;
	case 3:
		code(g, "for i in ");
		gen_atom(g, 1);
		body(g, depth);
		break;
	case 4:
		code(g, "try");
		body(g, depth);
		line_start(g, g->level);
		code(g, "except ");
		code(g, PICK(g, names));
		code(g, pct(g, 50) ? " as e" : "");
		body(g, depth);
		if (pct(g, 40)) {
			line_start(g, g->level);
			code(g, "finally");
			body(g, depth);
		}
		break;
	case 5:
		code(g, "with ");
		gen_atom(g, 2);
		code(g, " as x");
		body(g, depth);
		break;
	case 6: case 7: case 8:
		gen_def(g, depth);
		break;
	case 9:
		code(g, "class ");
		code(g, PICK(g, ((const char *const[]){ "A", "B", "rb", "\xc3\xa9" })));
		if (pct(g, 60)) {
			code(g, "(B, metaclass=");
			gen_atom(g, 2);
			code(g, ")");
		}
		code(g, ":");
		end_line(g);
		g->level++;
		g->no_walrus++;
		def_state = g->in_def;
		g->in_def = 0;
		if (pct(g, 60)) {
			line_start(g, g->level);
			gstr(g, 0);
			end_line(g);
		}
		gen_stmt(g, depth + 1u);
		g->in_def = def_state;
		g->no_walrus--;
		g->level--;
		break;
	case 10:
		gen_match(g, depth);
		break;
	default:
		gen_simple(g);
		end_line(g);
		break;
	}
}

/* One program from `seed`: its text in g->b, what the lexer must say about it in g->x. */
static void gen_program(struct gen *g, uint64_t seed)
{
	static const char *const eols[] = { "\n", "\r\n", "\r", "\n" };
	static const char *const inds[] = { " ", "  ", "   ", "    ", "    ", "\t", "        ", "     " };
	uint32_t want;

	g->s = seed * 0x9e3779b97f4a7c15ull + 0x1234567u;
	rnd(g, 2);
	g->n = g->nx = g->level = g->over = g->in_def = g->no_walrus = g->ended_comment = g->bare = g->kind_only = g->no_f = 0;
	g->eol = PICK(g, eols);
	g->ind = PICK(g, inds);
	want = 200u + rnd(g, 5000u);
	if (pct(g, 25)) {
		comment(g);
		eol(g);
	}
	while (g->n < want && !g->over)
		gen_stmt(g, 0);
	if (g->nx && g->x[g->nx - 1u].kind == KGENOME_TEXTUAL_CODE && pct(g, 20)) {
		/* the last line without its break: the last code span loses its final line break */
		uint32_t el = (uint32_t)strlen(g->eol);

		if (g->x[g->nx - 1u].len >= el && !memcmp(g->b + g->n - el, g->eol, el)) {
			g->n -= el;
			if (g->x[g->nx - 1u].len == el)
				g->nx--;
			else
				g->x[g->nx - 1u].len -= el;
		}
	}
}

static void show_text(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		printf(p[i] >= 0x20 && p[i] < 0x7f && p[i] != '\\' ? "%c" : "\\x%02x", p[i]);
}

/* The lexer's spans, kept: what the test compares with the generator's. */
struct got {
	struct kgenome_textual_span s[EXP_MAX];
	uint32_t n;
};

static int keep(void *u, const struct kgenome_textual_span *s)
{
	struct got *r = u;

	if (r->n >= EXP_MAX)
		return 0;
	r->s[r->n++] = *s;
	return 1;
}

/*
 * THE FORM OF A GENERATED PROGRAM keeps every string: read again it has the same strings, in the same order, each
 * with the same delimiters, each byte for byte unless the form was allowed to write an escape as itself (then it is
 * not longer), no comment, and the form of the form is itself. The interpreter's side of the same claim - that the
 * form is the same TOKENS as the program, by tokenize - is a scratch script (see the report), because it needs python.
 */
static int form_agrees(const struct gen *g, const struct got *r)
{
	static uint8_t f1[GEN_MAX * 2u], f2[GEN_MAX * 2u];
	static struct got r2;
	struct kgenome_textual_form_req fq = { .in = g->b, .n = g->n, .lang = PY, .out = f1, .cap = KGENOME_TEXTUAL_FORM_CAP(g->n),
				      .flags = KGENOME_TEXTUAL_KEEP_JOINS };
	struct kgenome_textual_form_res fs;
	struct kgenome_textual_lex_req lq;
	struct kgenome_textual_lex_res ls;
	uint32_t n1, i, j = 0;

	kgenome_textual_form(&fq, &fs);
	n1 = fs.n_out;
	fq = (struct kgenome_textual_form_req){ .in = f1, .n = n1, .lang = PY, .out = f2, .cap = KGENOME_TEXTUAL_FORM_CAP(n1),
						.flags = KGENOME_TEXTUAL_KEEP_JOINS };
	kgenome_textual_form(&fq, &fs);
	if (fs.n_out != n1 || memcmp(f1, f2, n1))
		return 0;
	r2.n = 0;
	lq = (struct kgenome_textual_lex_req){ .in = f1, .n = n1, .lang = PY, .sink = keep, .user = &r2 };
	kgenome_textual_lex(&lq, &ls);
	for (i = 0; i < r->n; i++) {
		const struct kgenome_textual_span *a = &r->s[i], *b;

		if (a->kind != KGENOME_TEXTUAL_STRING)
			continue;
		while (j < r2.n && r2.s[j].kind != KGENOME_TEXTUAL_STRING) {
			if (r2.s[j].kind == KGENOME_TEXTUAL_COMMENT && !(r2.s[j].off == 0 && n1 >= 2u && f1[0] == '#' && f1[1] == '!'))
				return 0;       /* the interpreter line is kept, see keep_hashbang */
			j++;
		}
		if (j >= r2.n)
			return 0;
		b = &r2.s[j++];
		if (a->flags != b->flags || a->open_len != b->open_len || a->close_len != b->close_len ||
		    b->len > a->len || ((a->flags & KGENOME_TEXTUAL_F_INTERP) == 0 && (b->len != a->len ||
		     memcmp(g->b + a->off, f1 + b->off, a->len))))
			return 0;
	}
	for (; j < r2.n; j++)
		if (r2.s[j].kind != KGENOME_TEXTUAL_CODE &&
		    !(r2.s[j].kind == KGENOME_TEXTUAL_COMMENT && r2.s[j].off == 0 && n1 >= 2u && f1[0] == '#' && f1[1] == '!'))
			return 0;
	return 1;
}

/* How many of `count` generated programs the lexer reads as the generator wrote them. */
static uint32_t generated(uint64_t first, uint32_t count)
{
	static struct gen g;
	static struct got r;
	uint32_t i, k, bad = 0;

	for (i = 0; i < count; i++) {
		struct kgenome_textual_lex_req rq;
		struct kgenome_textual_lex_res rs;

		gen_program(&g, first + i);
		r.n = 0;
		rq = (struct kgenome_textual_lex_req){ .in = g.b, .n = g.n, .lang = PY, .sink = keep, .user = &r };
		kgenome_textual_lex(&rq, &rs);
		for (k = 0; k < g.nx && k < r.n; k++)
			if (memcmp(&g.x[k], &r.s[k], sizeof g.x[k]) != 0)
				break;
		if (!g.over && k == g.nx && r.n == g.nx && !form_agrees(&g, &r)) {
			bad++;
			if (bad <= 3u)
				printf("  FAIL the form of generated program %llu loses a string, keeps a comment, or is not its own form\n", (unsigned long long)(first + i));
			continue;
		}
		if (g.over || k != g.nx || r.n != g.nx) {
			bad++;
			if (bad <= 3u) {
				printf("  FAIL generated program %llu (%u bytes): span %u of %u (lexer gave %u)\n",
				       (unsigned long long)(first + i), g.n, k, g.nx, r.n);
				if (k < g.nx)
					printf("    wanted kind %u off %u len %u open %u close %u flags %u: ", g.x[k].kind,
					       g.x[k].off, g.x[k].len, g.x[k].open_len, g.x[k].close_len, g.x[k].flags);
				if (k < g.nx)
					show_text(g.b + g.x[k].off, g.x[k].len < 200u ? g.x[k].len : 200u);
				if (k < r.n)
					printf("\n    got    kind %u off %u len %u open %u close %u flags %u: ", r.s[k].kind,
					       r.s[k].off, r.s[k].len, r.s[k].open_len, r.s[k].close_len, r.s[k].flags);
				if (k < r.n)
					show_text(g.b + r.s[k].off, r.s[k].len < 200u ? r.s[k].len : 200u);
				printf("\n");
			}
		}
	}
	return bad;
}

#ifndef PY_GEN_COUNT
#define PY_GEN_COUNT 6000u
#endif

static void generator(void)
{
	uint32_t bad = generated(1, PY_GEN_COUNT);

	if (bad) {
		printf("  FAIL %u of %u generated programs are not read as written\n", bad, PY_GEN_COUNT);
		fails++;
	}
}

#endif /* KGENOME_TEST_TEXTUAL_PY_GEN_H */
