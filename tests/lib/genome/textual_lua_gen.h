#ifndef KGENOME_TEST_TEXTUAL_LUA_GEN_H
#define KGENOME_TEST_TEXTUAL_LUA_GEN_H

/*
 * textual_lua_gen.h - the lua program generator of textual_lua.c, kept apart so that the test stays under the size of
 * one file and so that a scratch program can include it to write the generated programs to disk for the interpreter
 * to read. Included by textual_lua.c only, after textual_check.h and the definition of LUA.
 *
 * THE GENERATOR builds a program from tokens whose class is known when they are written, and the expected span list is
 * built beside the text, so what the lexer must answer is not worked out from the text afterwards by a second lexer.
 * What is varied:
 *   - short strings, both quotes, with plain runs, the other quote, the own quote escaped, every escape lua 5.4 has
 *     (\n \\ \x4a \65 \0 \u{48} \u{7FFFFFFF}), "\z" with blanks and line breaks after it, a backslash and a line break
 *     of the program's style, "--" and "[[" and "]]" in the text, bytes of 0x80 and above;
 *   - long strings of level 0 to 4 whose body holds "]", "]=", "[[", "--", quotes and line breaks, and never its own closer
 *     (checked on the text: the first closer must be the last bytes);
 *   - comments: "--" lines whose text begins like a long bracket and is not one ("--[", "--[=", "--[=x"), long comments of
 *     level 0 to 4 across lines, the interpreter line; a comment may follow a number with no blank between ("0xe--c");
 *   - code: statements of every shape lua has (local, assignment, call with a string or a table, if, for, while, repeat,
 *     function, do, label), expressions with every binary operator, unary operators, numbers of every spelling (hex
 *     floats, exponents with signs, ".5", "5.", "1e+3"), tables with "[k]=v" fields, names that look like the end of a number
 *     (x1e, e, p, t0x);
 *   - the text: \n, \r\n, \r or \n\r for every line break, strings and comments included; a final line with or without its break.
 * The generator is checked by the interpreter, not trusted: a scratch program includes this file, writes N of its
 * programs to disk and `luac -p` reads each (a scratch script, see the report), because a generator that wrote text
 * lua refuses would be a test of nothing.
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
	uint32_t over;                  /* the program did not fit: a bug of the generator, not a result */
	uint32_t label;                 /* labels are unique in a function */
	uint32_t ended_comment;         /* the last token is a line comment: nothing may follow on its line */
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

/* ---- strings and comments: each is a span with its delimiters counted ---- */

static void level_str(char *dst, uint32_t level, char edge)
{
	uint32_t i;

	dst[0] = edge;
	for (i = 0; i < level; i++)
		dst[1u + i] = '=';
	dst[1u + level] = edge;
	dst[2u + level] = 0;
}

/* A short string body, never containing its own quote unescaped nor a raw line break. */
static void short_body(struct gen *g, struct sb *o, char q)
{
	static const char *const esc[] = { "\\n", "\\\\", "\\t", "\\a", "\\x4a", "\\x00", "\\65", "\\0", "\\255", "\\010",
					   "\\u{48}", "\\u{7FFFFFFF}", "\\u{0}", "\\x7B", "\\v", "\\f", "\\r", "\\b" };
	static const char *const raw[] = { "abc", " ", "--", "--[[", "[[", "]]", "[=[", "#!", "{}", "\xc3\xa9", "\xff", "x1e", "." };
	uint32_t items = rnd(g, 8), i;
	char one[4];

	for (i = 0; i < items && o->n < 600u; i++) {
		switch (rnd(g, 9)) {
		case 0:
			one[0] = q == '"' ? '\'' : '"';
			one[1] = 0;
			sb_cat(o, one);
			break;
		case 1:
			one[0] = '\\';
			one[1] = q;
			one[2] = 0;
			sb_cat(o, one);
			break;
		case 2:
			sb_cat(o, PICK(g, esc));
			break;
		case 3:
			sb_cat(o, "\\");        /* a backslash and a line break of the program's style */
			sb_cat(o, g->eol);
			break;
		case 4:
			sb_cat(o, "\\z");
			sb_cat(o, PICK(g, ((const char *const[]){ "", " ", "  \t", "\n", "\r\n \t", "\n\r", "\r", "\f\v" })));
			break;
		default:
			sb_cat(o, PICK(g, raw));
			break;
		}
	}
}

static void gen_short(struct gen *g)
{
	struct sb *o = calloc(1, sizeof *o);
	char q = pct(g, 50) ? '"' : '\'', qs[2] = { q, 0 };

	sb_cat(o, qs);
	short_body(g, o, q);
	sb_cat(o, qs);
	g_span(g, KGENOME_TEXTUAL_STRING, o->b, 1u, 1u, KGENOME_TEXTUAL_F_INTERP);
	g->ended_comment = 0;
	free(o);
}

/* A long bracket body that does not hold its closer, and in which the first closer is the one appended. */
static void long_body(struct gen *g, struct sb *o, uint32_t level)
{
	static const char *const bit[] = { "abc", "]", "]=", "]==", "]===", "[", "[[", "[=[", "--", "--[[", "\"", "'", "\\", "\\z",
					   " ", "\t", "x]y", "=", "==", "\xc3\xa9", "\\n" };
	char closer[16];
	uint32_t items = rnd(g, 9), i;

	level_str(closer, level, ']');
	if (pct(g, 25))
		sb_cat(o, g->eol);              /* a line break right after the opener is not part of the value */
	for (i = 0; i < items && o->n < 600u; i++) {
		if (pct(g, 20))
			sb_cat(o, g->eol);
		else
			sb_cat(o, PICK(g, bit));
	}
	/* the first closer in body + closer must be the last bytes */
	for (;;) {
		struct sb t = { .n = 0 };
		const char *at;

		sb_cat(&t, o->b);
		sb_cat(&t, closer);
		at = strstr(t.b, closer);
		if (at == t.b + o->n)
			break;
		o->b[--o->n] = 0;       /* drop a byte at a time until it holds: always ends */
	}
}

static void gen_long(struct gen *g, int comment)
{
	struct sb *o = calloc(1, sizeof *o);
	uint32_t level = rnd(g, 5);
	char open[16], close[16];

	level_str(open, level, '[');
	level_str(close, level, ']');
	if (comment)
		sb_cat(o, "--");
	sb_cat(o, open);
	long_body(g, o, level);
	sb_cat(o, close);
	g_span(g, comment ? KGENOME_TEXTUAL_COMMENT : KGENOME_TEXTUAL_STRING, o->b, (comment ? 2u : 0u) + level + 2u,
	       level + 2u, 0);
	g->ended_comment = 0;
	free(o);
}

/* A "--" comment to the end of the line (the break is not in it). Its text may begin like a long bracket and not be one. */
static void gen_line_comment(struct gen *g)
{
	static const char *const text[] = { "", " c", "[", "[=", "[=x", "[==", " [[", "-", "[-", " it's \"x\" '''", "!", "\\",
					    " ]] --", "\xc3\xa9", "[ [", "= [", "[ ]" };
	struct sb *o = calloc(1, sizeof *o);

	sb_cat(o, "--");
	sb_cat(o, PICK(g, text));
	g_span(g, KGENOME_TEXTUAL_COMMENT, o->b, 2u, 0, 0);
	g->ended_comment = 1;
	free(o);
}

/* What lies between two tokens that need a separator: a blank, a break, a comment of either kind (a line one takes the break). */
static void sp(struct gen *g)
{
	/* "-" then "--c" is "---c": a comment that starts at the first dash. The separator after a minus begins with a blank. */
	if (g->n && g->b[g->n - 1u] == '-')
		code(g, " ");
	switch (rnd(g, 10)) {
	case 0:
		code(g, "\t");
		break;
	case 1:
		eol(g);
		break;
	case 2:
		gen_long(g, 1);
		code(g, " ");
		break;
	case 3:
		gen_line_comment(g);
		eol(g);
		break;
	case 4:
		code(g, " ");
		gen_long(g, 1);
		break;
	default:
		code(g, " ");
		break;
	}
}

/* A separator that may be nothing: after "(" or a ",", before ")". */
static void opt(struct gen *g)
{
	if (pct(g, 60))
		sp(g);
}

/* ---- code ---- */

static const char *const names[] = { "x", "y", "e", "p", "x1e", "t0x", "_", "_G", "self", "a_b", "e5", "t.k", "t.u.v" };
static const char *const bins[] = { "+", "-", "*", "/", "//", "%", "^", "..", "==", "~=", "<", "<=", ">", ">=", "and", "or",
				    "&", "|", "~", "<<", ">>" };
static const char *const nums[] = { "0", "10", "3.14", ".5", "5.", "1e10", "1E+5", "3e-2", "0x1F", "0XaB", "0xe", "0xA.8p1",
				    "0x.1p-3", "0x1P+4", "1e5", "0xep1", "7.e1", "08" };

static void gen_expr(struct gen *g, uint32_t depth);

static void gen_number(struct gen *g)
{
	code(g, PICK(g, nums));
}

static void gen_string_any(struct gen *g)
{
	if (pct(g, 55))
		gen_short(g);
	else
		gen_long(g, 0);
}

static void gen_args(struct gen *g, uint32_t depth)
{
	uint32_t i, n = rnd(g, 4);

	code(g, "(");
	opt(g);
	for (i = 0; i < n; i++) {
		if (i) {
			code(g, ",");
			opt(g);
		}
		gen_expr(g, depth + 1u);
	}
	opt(g);
	code(g, ")");
}

static void gen_table(struct gen *g, uint32_t depth)
{
	uint32_t i, n = rnd(g, 5);

	code(g, "{");
	opt(g);
	for (i = 0; i < n; i++) {
		switch (rnd(g, 3)) {
		case 0:
			code(g, "[ ");              /* "[" and a long string is "[[": the opener of one */
			gen_expr(g, depth + 1u);
			code(g, "]=");
			break;
		case 1:
			code(g, PICK(g, ((const char *const[]){ "k=", "e =", "x1e=", "p = " })));
			break;
		default:
			break;
		}
		gen_expr(g, depth + 1u);
		code(g, pct(g, 70) ? "," : ";");
		opt(g);
	}
	code(g, "}");
}

static void gen_atom(struct gen *g, uint32_t depth)
{
	uint32_t k = rnd(g, 16);

	if (depth >= 3u && k > 6u)
		k = rnd(g, 5);
	switch (k) {
	case 0: case 1: case 2:
		gen_number(g);
		break;
	case 3: case 4: case 5:
		gen_string_any(g);
		break;
	case 6:
		code(g, PICK(g, ((const char *const[]){ "nil", "true", "false", "..." })));
		break;
	case 7: case 8:
		code(g, PICK(g, names));
		break;
	case 9: case 10:
		code(g, PICK(g, names));
		gen_args(g, depth);
		break;
	case 11:
		code(g, PICK(g, names));     /* f"x", f[[x]], f{...}: a call whose argument is the literal */
		if (pct(g, 40))
			code(g, " ");
		if (pct(g, 60))
			gen_string_any(g);
		else
			gen_table(g, depth);
		break;
	case 12:
		gen_table(g, depth);
		break;
	case 13:
		code(g, "(");
		opt(g);
		gen_expr(g, depth + 1u);
		opt(g);
		code(g, ")");
		break;
	case 14:
		code(g, "function(a, ...)");
		sp(g);
		code(g, "return");
		sp(g);
		gen_expr(g, depth + 1u);
		sp(g);
		code(g, "end");
		break;
	default:
		code(g, PICK(g, names));
		code(g, "[ ");
		gen_expr(g, depth + 1u);
		code(g, "]");
		break;
	}
}

static void gen_expr(struct gen *g, uint32_t depth)
{
	uint32_t n = 1u + (depth < 3u ? rnd(g, 3) : 0u), i;

	for (i = 0; i < n; i++) {
		if (i) {
			sp(g);
			code(g, PICK(g, bins));
			sp(g);
		}
		if (pct(g, 15)) {
			code(g, PICK(g, ((const char *const[]){ "-", "not", "#", "~" })));
			sp(g);
		}
		gen_atom(g, depth);
	}
}

static void gen_stmt(struct gen *g, uint32_t depth);

static void gen_block(struct gen *g, uint32_t depth)
{
	uint32_t i, n = rnd(g, 3);

	for (i = 0; i < n && depth < 3u; i++)
		gen_stmt(g, depth + 1u);
	if (pct(g, 25)) {
		code(g, "return");
		sp(g);
		gen_expr(g, depth + 1u);
		sp(g);
	}
}

/* A statement ends where the next begins: a line break, or ";", and a line comment has taken its break already. */
static void end_stmt(struct gen *g)
{
	if (g->ended_comment)
		return;
	if (pct(g, 15))
		code(g, ";");
	if (pct(g, 25))
		gen_line_comment(g);
	eol(g);
}

static void gen_stmt(struct gen *g, uint32_t depth)
{
	char buf[32];

	switch (rnd(g, 14)) {
	case 0: case 1:
		code(g, "local ");
		code(g, PICK(g, ((const char *const[]){ "v", "e", "x1e", "p" })));
		sp(g);
		code(g, "=");
		sp(g);
		gen_expr(g, depth);
		break;
	case 2: case 3:
		code(g, PICK(g, names));
		sp(g);
		code(g, "=");
		sp(g);
		gen_expr(g, depth);
		break;
	case 4:
		code(g, "print");
		gen_args(g, depth);
		break;
	case 5:
		code(g, "print");
		if (pct(g, 50))
			code(g, " ");
		gen_string_any(g);
		break;
	case 6:
		code(g, "if ");
		gen_expr(g, depth + 1u);
		sp(g);
		code(g, "then");
		sp(g);
		gen_block(g, depth);
		if (pct(g, 40)) {
			code(g, "elseif ");
			gen_expr(g, depth + 1u);
			sp(g);
			code(g, "then");
			sp(g);
			gen_block(g, depth);
		}
		if (pct(g, 40)) {
			code(g, "else");
			sp(g);
			gen_block(g, depth);
		}
		code(g, "end");
		break;
	case 7:
		code(g, "for i = ");
		gen_expr(g, depth + 1u);
		code(g, ",");
		sp(g);
		gen_expr(g, depth + 1u);
		sp(g);
		code(g, "do");
		sp(g);
		gen_block(g, depth);
		code(g, "end");
		break;
	case 8:
		code(g, "for k, v in pairs(");
		gen_expr(g, depth + 1u);
		code(g, ")");
		sp(g);
		code(g, "do");
		sp(g);
		gen_block(g, depth);
		code(g, "end");
		break;
	case 9:
		code(g, "while ");
		gen_expr(g, depth + 1u);
		sp(g);
		code(g, "do");
		sp(g);
		gen_block(g, depth);
		code(g, "end");
		break;
	case 10:
		code(g, "repeat");
		sp(g);
		gen_block(g, depth);
		code(g, "until ");
		gen_expr(g, depth + 1u);
		break;
	case 11:
		code(g, "local function f(a, ...)");
		sp(g);
		gen_block(g, depth);
		code(g, "end");
		break;
	case 12:
		code(g, "do");
		sp(g);
		gen_block(g, depth);
		code(g, "end");
		break;
	default:
		snprintf(buf, sizeof buf, "::l%u::", g->label++);
		code(g, buf);
		break;
	}
	end_stmt(g);
}

/* One program from `seed`: its text in g->b, what the lexer must say about it in g->x. */
static void gen_program(struct gen *g, uint64_t seed)
{
	static const char *const eols[] = { "\n", "\r\n", "\r", "\n\r", "\n" };
	uint32_t want;

	g->s = seed * 0x9e3779b97f4a7c15ull + 0x1234567u;
	rnd(g, 2);
	g->n = g->nx = g->over = g->ended_comment = g->label = 0;
	g->eol = PICK(g, eols);
	want = 200u + rnd(g, 5000u);
	if (pct(g, 20)) {
		g_span(g, KGENOME_TEXTUAL_COMMENT, "#!/usr/bin/env lua", 1u, 0, 0);
		code(g, "\n");                 /* the interpreter line ends at an LF only, whatever the program's style */
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

static int same_span(const struct kgenome_textual_span *a, const struct kgenome_textual_span *b)
{
	return a->off == b->off && a->len == b->len && a->open_len == b->open_len && a->close_len == b->close_len &&
	       a->kind == b->kind && a->flags == b->flags;
}

static int is_hashbang(const uint8_t *f, uint32_t n, const struct kgenome_textual_span *s)
{
	return s->kind == KGENOME_TEXTUAL_COMMENT && s->off == 0 && n >= 2u && f[0] == '#' && f[1] == '!';
}

/*
 * THE FORM OF A GENERATED PROGRAM keeps every string: read again it has the same strings, in the same order, each
 * with the same delimiters and flags, each byte for byte unless the form was allowed to write an escape as itself (then
 * it is not longer), no comment but the interpreter line, and the form of the form is itself. The interpreter's side of the
 * same claim - that the form is the same PROGRAM as the original, by the listing luac -l gives - is a scratch script.
 */
static int form_agrees(const struct gen *g, const struct got *r)
{
	static uint8_t f1[GEN_MAX * 2u], f2[GEN_MAX * 2u];
	static struct got r2;
	struct kgenome_textual_form_req fq = { .in = g->b, .n = g->n, .lang = LUA, .out = f1, .cap = KGENOME_TEXTUAL_FORM_CAP(g->n) };
	struct kgenome_textual_form_res fs;
	struct kgenome_textual_lex_req lq;
	struct kgenome_textual_lex_res ls;
	uint32_t n1, i, j = 0;

	kgenome_textual_form(&fq, &fs);
	n1 = fs.n_out;
	fq = (struct kgenome_textual_form_req){ .in = f1, .n = n1, .lang = LUA, .out = f2, .cap = KGENOME_TEXTUAL_FORM_CAP(n1) };
	kgenome_textual_form(&fq, &fs);
	if (fs.n_out != n1 || memcmp(f1, f2, n1))
		return 0;
	r2.n = 0;
	lq = (struct kgenome_textual_lex_req){ .in = f1, .n = n1, .lang = LUA, .sink = keep, .user = &r2 };
	kgenome_textual_lex(&lq, &ls);
	for (i = 0; i < r->n; i++) {
		const struct kgenome_textual_span *a = &r->s[i], *b;

		if (a->kind != KGENOME_TEXTUAL_STRING)
			continue;
		while (j < r2.n && r2.s[j].kind != KGENOME_TEXTUAL_STRING) {
			if (r2.s[j].kind == KGENOME_TEXTUAL_COMMENT && !is_hashbang(f1, n1, &r2.s[j]))
				return 0;
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
		if (r2.s[j].kind != KGENOME_TEXTUAL_CODE && !is_hashbang(f1, n1, &r2.s[j]))
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
		rq = (struct kgenome_textual_lex_req){ .in = g.b, .n = g.n, .lang = LUA, .sink = keep, .user = &r };
		kgenome_textual_lex(&rq, &rs);
		for (k = 0; k < g.nx && k < r.n; k++)
			if (!same_span(&g.x[k], &r.s[k]))
				break;
		if (!g.over && k == g.nx && r.n == g.nx && !form_agrees(&g, &r)) {
			bad++;
			if (bad <= 3u)
				printf("  FAIL the form of generated program %llu loses a string, keeps a comment, or is not its own form\n",
				       (unsigned long long)(first + i));
			continue;
		}
		if (g.over || k != g.nx || r.n != g.nx) {
			bad++;
			if (bad <= 3u) {
				printf("  FAIL generated program %llu (%u bytes): span %u of %u (lexer gave %u)\n",
				       (unsigned long long)(first + i), g.n, k, g.nx, r.n);
				if (k < g.nx) {
					printf("    wanted kind %u off %u len %u open %u close %u flags %u: ", g.x[k].kind,
					       g.x[k].off, g.x[k].len, g.x[k].open_len, g.x[k].close_len, g.x[k].flags);
					show_text(g.b + g.x[k].off, g.x[k].len < 200u ? g.x[k].len : 200u);
				}
				if (k < r.n) {
					printf("\n    got    kind %u off %u len %u open %u close %u flags %u: ", r.s[k].kind,
					       r.s[k].off, r.s[k].len, r.s[k].open_len, r.s[k].close_len, r.s[k].flags);
					show_text(g.b + r.s[k].off, r.s[k].len < 200u ? r.s[k].len : 200u);
				}
				printf("\n");
			}
		}
	}
	return bad;
}

#ifndef LUA_GEN_COUNT
#define LUA_GEN_COUNT 6000u
#endif

static void generator(void)
{
	uint32_t bad = generated(1, LUA_GEN_COUNT);

	if (bad) {
		printf("  FAIL %u of %u generated programs are not read as written\n", bad, LUA_GEN_COUNT);
		fails++;
	}
}

#endif /* KGENOME_TEST_TEXTUAL_LUA_GEN_H */
