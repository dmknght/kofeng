#ifndef KGENOME_TEST_TEXTUAL_TCL_GEN_H
#define KGENOME_TEST_TEXTUAL_TCL_GEN_H

/*
 * textual_tcl_gen.h - the tcl program generator of textual_tcl.c, kept apart so that the test stays under the size of
 * one file and so that a scratch program can include it to write the generated programs to disk for tclsh to read. Included by
 * textual_tcl.c only, after textual_check.h and the definition of TCL.
 *
 * THE GENERATOR builds a script from words whose class is known when they are written, and the expected span list is built
 * beside the text. What is varied:
 *   - words: bare ones (names, "$x", "${a b}" - a STRING -, "$a(b c)" - the name code and the index a STRING -, "$::ns::v", an escaped blank or semicolon or brace, a quote or a
 *     brace or a "#" in the middle, "[cmd ...]" with a script of its own); braced ones, nested, with "\{" and "\}", quotes,
 *     brackets, "#" and line breaks in them; double-quoted ones with escapes, "$" substitutions, "\<line break>" and
 *     "[command]" substitutions whose code has quotes and braces of its own;
 *   - the layout: blanks, tabs, VT and FF, "\<line break>" continuations between words, ";" and line breaks between commands,
 *     blank lines, indentation;
 *   - comments: "#" at a command's start - after a line break, after ";" with and without a blank, after a continuation at a
 *     command's start, in a "[" script - with "[", "]", quotes and braces in them, and "\<line break>" continuing them; "#"
 *     in the middle of a command (an argument) is code;
 *   - the text: \n, \r\n or \r for every line break (a file is read with every ending translated), a final line with or without its break.
 * The generator is checked by the interpreter, not trusted: a scratch program includes this file, writes N of its programs to
 * disk and tclsh 8.6 compiles each (a scratch script, see the report), because a generator that wrote text tcl refuses
 * would be a test of nothing.
 */

#define GEN_MAX 60000u
#define EXP_MAX 8000u
#define STAGE_MAX 8192u

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
	/* Inside a double-quoted word the text of a "[command]" is the word's: it is appended here, whatever it holds, and the word
	 * is delivered as one span when it ends. */
	uint32_t staged;
	char     stage[STAGE_MAX];
	uint32_t stage_n;
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
	if (g->staged) {
		if (g->stage_n + len >= STAGE_MAX) {
			g->over = 1;
			return;
		}
		memcpy(g->stage + g->stage_n, t, len + 1u);
		g->stage_n += len;
		return;
	}
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
}

static void eol(struct gen *g)
{
	code(g, g->eol);
}

static void gen_script(struct gen *g, uint32_t depth, int nested);

/* A string of `text` followed by the line break of the program's style where it has a "\n". */
static void with_eol(struct gen *g, struct sb *o, const char *t)
{
	for (; *t; t++) {
		if (*t == '\n') {
			sb_cat(o, g->eol);
		} else {
			char one[2] = { *t, 0 };

			sb_cat(o, one);
		}
	}
}

/* ---- words ---- */

/* A bare word that is plain text: no "]" or ";" that is not escaped, so that it is one in a "[...]" too. */
static const char *const bare_text[] = {
	"abc", "x1", "-opt", "a.b", "$x", "$::ns::v", "$a::b", "$_x9",
	"a\\ b", "a\\;b", "a\\{b", "a\\}b", "\\x41", "\\[x\\]", "a{b", "a}b", "a\\\"b", "a\"b", "#x", "a#b", "$", "$-", "\\$x",
	"a:b", "$a:b", "\xc3\xa9", "0x1F", "a(b", "a)b", "\\\\", "a\\\\b", "}", "'"
};

static void gen_braced(struct gen *g)
{
	static const char *const body[] = {
		"", "a b", "a {b c} d", "a \\{ b", "a \\} b", "\"", "[", "]", "$x [y]", " # c { \n", "a\\\nb", "{{x}}", "\\\\", ";", "a;b", "\n", "#",
		"(", "puts \"a\\\"b\"", "if {$x} { # c } \n", "x \\{ \\} y", "\\\\\n", "$a(b c)", "a\\ b", "\xc3\xa9"
	};
	struct sb *o = calloc(1, sizeof *o);

	sb_cat(o, "{");
	with_eol(g, o, PICK(g, body));
	if (pct(g, 25))
		with_eol(g, o, PICK(g, body));
	/* the pieces together must balance: count the braces that are not escaped */
	{
		int depth = 0;
		uint32_t i;

		for (i = 1; i < o->n; i++) {
			if (o->b[i] == '\\')
				i++;
			else if (o->b[i] == '{')
				depth++;
			else if (o->b[i] == '}')
				depth--;
		}
		if (depth < 0) {
			/* more closers than openers: not a word of this kind; an empty one instead */
			o->n = 1;
			o->b[1] = 0;
		}
		for (; depth > 0; depth--)
			sb_cat(o, "}");
	}
	sb_cat(o, "}");
	g_span(g, KGENOME_TEXTUAL_STRING, o->b, 1u, 1u, 0);
	free(o);
}

static void gen_cmd_subst(struct gen *g, uint32_t depth)
{
	code(g, "[");
	gen_script(g, depth + 1u, 1);
	code(g, "]");
}

/* A double-quoted word. With a "[" in it the span has no INTERP: the code in the brackets is not a string's. */
static void gen_quoted(struct gen *g, uint32_t depth)
{
	static const char *const piece[] = {
		"abc", " ", "$x", "${a b}", "$a(b)", "$a(b c)", "$.", "\\\"", "\\\\", "\\x41", "\\101", "\\u0041", "\\n", "\\$", "\\[", "a;b", "#",
		"{", "}", ")", "\\\n", "]", "$::q", "\xc3\xa9", "\\x", "\\U00110000", "\\777"
	};
	int outer = !g->staged, cmd = 0;
	uint32_t items = rnd(g, 5), i;
	struct sb *o;

	if (outer) {
		g->staged = 1;
		g->stage_n = 0;
		g->stage[0] = 0;
	}
	code(g, "\"");
	for (i = 0; i < items; i++) {
		if (depth < 3u && pct(g, 22)) {
			gen_cmd_subst(g, depth);
			cmd = 1;
		} else {
			o = calloc(1, sizeof *o);
			with_eol(g, o, PICK(g, piece));
			code(g, o->b);
			free(o);
		}
	}
	code(g, "\"");
	if (outer) {
		g->staged = 0;
		g_span(g, KGENOME_TEXTUAL_STRING, g->stage, 1u, 1u, (uint8_t)(cmd ? 0u : KGENOME_TEXTUAL_F_INTERP));
	}
}

/* "${name}": a STRING of its own, delimiters "${" and "}". */
static void gen_brace_name(struct gen *g)
{
	g_span(g, KGENOME_TEXTUAL_STRING, PICK(g, ((const char *const[]){ "${a b}", "${d}", "${ \"q[ }", "${}", "${a\\}", "${::x::y z}" })), 2u, 1u, 0);
}

/* "$name(index)": the name is code and the index, parentheses included, a STRING (INTERP unless a "[" is in it). */
static void gen_index(struct gen *g, uint32_t depth)
{
	static const char *const idx[] = { "i", "a b", "\"x y\"", "$i", "\\)", "a;b", "x\ny", "${q r}", "#", "a  b", "\\x41", "{", "}", "\"" };
	int outer = !g->staged, cmd = 0;
	struct sb *o;

	code(g, PICK(g, ((const char *const[]){ "$arr", "$a::b", "$_x", "$::g" })));
	if (outer) {
		g->staged = 1;
		g->stage_n = 0;
		g->stage[0] = 0;
	}
	code(g, "(");
	if (depth < 3u && pct(g, 25)) {
		gen_cmd_subst(g, depth);
		cmd = 1;
	} else {
		o = calloc(1, sizeof *o);
		with_eol(g, o, PICK(g, idx));
		code(g, o->b);
		free(o);
	}
	code(g, ")");
	if (outer) {
		g->staged = 0;
		g_span(g, KGENOME_TEXTUAL_STRING, g->stage, 1u, 1u, (uint8_t)(cmd ? 0u : KGENOME_TEXTUAL_F_INTERP));
	}
}

static void gen_bare(struct gen *g, uint32_t depth)
{
	switch (rnd(g, 7)) {
	case 0:
		gen_cmd_subst(g, depth);
		break;
	case 1:
		code(g, "pre");
		gen_cmd_subst(g, depth);
		code(g, pct(g, 50) ? "post" : "");
		break;
	case 2:
		gen_index(g, depth);
		break;
	case 3:
		gen_brace_name(g);
		break;
	default:
		code(g, PICK(g, bare_text));
		break;
	}
}

/* A word; `first` is the first of its command (never "#..."). */
static void gen_word(struct gen *g, uint32_t depth, int first)
{
	uint32_t k = rnd(g, 10);

	if (depth >= 3u && k < 4u)
		k = 9;
	if (first && k > 4u && k < 9u)
		k = 0;
	if (k < 3u)
		gen_braced(g);
	else if (k < 5u)
		gen_quoted(g, depth);
	else if (k < 9u)
		gen_bare(g, depth);
	else
		code(g, PICK(g, ((const char *const[]){ "set", "puts", "proc", "if", "foreach", "lappend", "cnt", "expr", "eval", "::ns::f", "a.b" })));
}

/* A gap between two words: blanks, or a continuation (a backslash and a line break, then blanks). */
static void gap(struct gen *g)
{
	switch (rnd(g, 8)) {
	case 0:
		code(g, "\t");
		break;
	case 1:
		code(g, "   ");
		break;
	case 2:
		code(g, " \\");
		eol(g);
		code(g, pct(g, 50) ? "    " : "");
		break;
	case 3:
		code(g, PICK(g, ((const char *const[]){ "\f", "\v", " \f\v " })));
		break;
	default:
		code(g, " ");
		break;
	}
}

/* A comment: "#" and what follows to the line break, which is not in it. A backslash and a line break continue it. */
static void gen_comment(struct gen *g)
{
	static const char *const text[] = { "", " c", " [ ] \" { }", " it's $x [y] ", "\\\\", " a \\\n more [ text", "!", " \\\n \\\n x", "{", " ;puts a" };
	struct sb *o = calloc(1, sizeof *o);

	sb_cat(o, "#");
	with_eol(g, o, PICK(g, text));
	g_span(g, KGENOME_TEXTUAL_COMMENT, o->b, 1u, 0, 0);
	free(o);
}

static void gen_command(struct gen *g, uint32_t depth)
{
	uint32_t i, n = rnd(g, 5);

	gen_word(g, depth, 1);
	for (i = 0; i < n; i++) {
		gap(g);
		gen_word(g, depth, 0);
	}
	if (pct(g, 15))
		code(g, " ");
}

/* The script of a "[...]" or the top: commands, comments at a command's start, separated by line breaks and semicolons. */
static void gen_script(struct gen *g, uint32_t depth, int nested)
{
	uint32_t i, n = 1u + rnd(g, nested ? 2u : 4u);

	if (nested && pct(g, 10))
		code(g, " ");
	for (i = 0; i < n && !g->over; i++) {
		if (pct(g, nested ? 8u : 25u)) {
			if (pct(g, 40))
				code(g, PICK(g, ((const char *const[]){ "  ", "\t", " \\\n" })));
			gen_comment(g);
			eol(g);
		}
		if (pct(g, 10))
			code(g, g->eol);
		gen_command(g, depth);
		if (i + 1u == n)
			break;
		switch (rnd(g, 5)) {
		case 0:
			code(g, ";");
			break;
		case 1:
			code(g, "; ");
			break;
		case 2:
			code(g, ";");
			gen_comment(g);
			eol(g);
			break;
		default:
			eol(g);
			break;
		}
	}
	if (!nested && pct(g, 70)) {
		if (pct(g, 20)) {
			code(g, ";");
			gen_comment(g);
		}
		eol(g);
	}
}

/* One program from `seed`: its text in g->b, what the lexer must say about it in g->x. */
static void gen_program(struct gen *g, uint64_t seed)
{
	static const char *const eols[] = { "\n", "\r\n", "\r", "\n" };
	uint32_t want;

	g->s = seed * 0x9e3779b97f4a7c15ull + 0x1234567u;
	rnd(g, 2);
	g->n = g->nx = g->over = g->staged = g->stage_n = 0;
	g->eol = PICK(g, eols);
	want = 200u + rnd(g, 5000u);
	if (pct(g, 15)) {
		g_span(g, KGENOME_TEXTUAL_COMMENT, "#!/usr/bin/env tclsh", 1u, 0, 0);
		eol(g);
	}
	while (g->n < want && !g->over) {
		gen_script(g, 0, 0);
		if (g->nx && g->x[g->nx - 1u].kind == KGENOME_TEXTUAL_COMMENT)
			eol(g);
		else if (g->n && g->b[g->n - 1u] != '\n' && g->b[g->n - 1u] != '\r')
			eol(g);
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

/* The value of a literal through the API: 1 with the bytes in `out`/`*n`, 0 when it has none. */
static int value_of(const uint8_t *lit, const struct kgenome_textual_span *s, uint8_t *out, uint32_t *n)
{
	struct kgenome_textual_value_req rq = { .lang = TCL, .lit = lit, .len = s->len, .open_len = s->open_len,
						.close_len = s->close_len, .flags = s->flags, .out = out, .cap = s->len };
	struct kgenome_textual_value_res rs;
	int ok = kgenome_textual_value(&rq, &rs) == KGENOME_TEXTUAL_OK;

	*n = rs.n_out;
	return ok;
}

/* Is what a string HOLDS the same in the form as it was: the form may write an escape as its byte, never change a value. */
static int same_value(const uint8_t *in, const struct kgenome_textual_span *a, const uint8_t *f, const struct kgenome_textual_span *b)
{
	static uint8_t va[GEN_MAX], vb[GEN_MAX];
	uint32_t na, nb;
	int ha = value_of(in + a->off, a, va, &na), hb = value_of(f + b->off, b, vb, &nb);

	return ha == hb && (!ha || (na == nb && !memcmp(va, vb, na)));
}

/*
 * THE FORM OF A GENERATED PROGRAM keeps every string: read again it has the same strings in the same order, with the same
 * delimiters and flags, byte for byte unless the form was allowed to write an escape as itself (then it is not longer), no
 * comment but the interpreter line, and the form of the form is itself. The interpreter's side of the same claim - that the
 * form is the same PROGRAM as the original, by its bytecode - is a scratch script.
 */
static int form_agrees(const struct gen *g, const struct got *r)
{
	static uint8_t f1[GEN_MAX * 2u], f2[GEN_MAX * 2u];
	static struct got r2;
	struct kgenome_textual_form_req fq = { .in = g->b, .n = g->n, .lang = TCL, .out = f1, .cap = KGENOME_TEXTUAL_FORM_CAP(g->n) };
	struct kgenome_textual_form_res fs;
	struct kgenome_textual_lex_req lq;
	struct kgenome_textual_lex_res ls;
	uint32_t n1, i, j = 0;

	kgenome_textual_form(&fq, &fs);
	n1 = fs.n_out;
	fq = (struct kgenome_textual_form_req){ .in = f1, .n = n1, .lang = TCL, .out = f2, .cap = KGENOME_TEXTUAL_FORM_CAP(n1) };
	kgenome_textual_form(&fq, &fs);
	if (fs.n_out != n1 || memcmp(f1, f2, n1))
		return 0;
	r2.n = 0;
	lq = (struct kgenome_textual_lex_req){ .in = f1, .n = n1, .lang = TCL, .sink = keep, .user = &r2 };
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
		     memcmp(g->b + a->off, f1 + b->off, a->len))) || !same_value(g->b, a, f1, b))
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
		rq = (struct kgenome_textual_lex_req){ .in = g.b, .n = g.n, .lang = TCL, .sink = keep, .user = &r };
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

#ifndef TCL_GEN_COUNT
#define TCL_GEN_COUNT 6000u
#endif

static void generator(void)
{
	uint32_t bad = generated(1, TCL_GEN_COUNT);

	if (bad) {
		printf("  FAIL %u of %u generated programs are not read as written\n", bad, TCL_GEN_COUNT);
		fails++;
	}
}

#endif /* KGENOME_TEST_TEXTUAL_TCL_GEN_H */
