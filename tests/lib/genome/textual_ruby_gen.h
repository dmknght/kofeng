#ifndef KGENOME_TEST_TEXTUAL_RUBY_GEN_H
#define KGENOME_TEST_TEXTUAL_RUBY_GEN_H

/*
 * textual_ruby_gen.h - the ruby program generator of textual_ruby.c, kept apart so that the test stays under the size of
 * one file and so that a scratch program can include it to write the generated programs to disk for ruby to read.
 * Included by textual_ruby.c only, after textual_check.h and the definition of RB.
 *
 * (b) THE GENERATOR. A program is built from tokens whose class is known when they are written - the generator says
 * "this is a %W literal with an interpolation, flagged as having no escapes to write" at the moment it writes it - and the
 * expected span list is built beside the text, so what the lexer must answer is not worked out from the text afterwards by
 * a second lexer. What is varied:
 *   - literals: '...' "..." `...`; %q %Q %w %W %i %I %r %s %x and the bare %( with the delimiters ( [ { < | ! - # ' and the
 *     paired ones nested; /.../ with every option; a heredoc (<<ID <<-ID <<~ID, the id bare or in "" '' ``) with one, two or
 *     three on a line; a body of plain bytes, the other quotes, escapes of every kind (\n \x4a \101 \u{41} \M-a \\ \<delim>),
 *     a delimiter escaped, a balanced pair of the delimiter, line breaks, non-ASCII bytes; in a literal that interpolates
 *     "#{ code }" to a depth of three with literals of every kind inside, "#@x", "#$x" and "#$1";
 *   - code: the places where a "/", a "%", a "<<", a "?" and a ":" could be read two ways, each written where there is only
 *     one reading - after a number, a literal, a bracket, a name and a space on both sides (a division, a modulo, a shift, a
 *     ternary) and after an operator, a bracket, a comma, a keyword and a method name taking an argument (a pattern, a literal,
 *     a heredoc, a character, a symbol); character literals (?a ?\n ?" ?#); symbols (:a :"a b" :+ :[]=); the global variables
 *     with a quote in their name ($' $" $` $/ $,); labels and string labels; blocks, def, class, if, while;
 *   - comments: "#" after code and alone, "=begin" ... "=end" at column 0, and "__END__" and data after it at the end;
 *   - the text: indentation of tabs and spaces, blank lines, \n or \r\n line endings (inside literals too), a last line
 *     with or without its break.
 * The generator is checked by ruby, not trusted: a scratch program includes this file, writes N of its programs to disk, ruby -c
 * reads each and ripper's string and comment tokens are compared with the spans the generator knew.
 */

#define GEN_MAX 60000u
#define EXP_MAX 8000u

struct gen {
	uint64_t s;
	uint8_t  b[GEN_MAX + 64];
	uint32_t n;
	struct kgenome_textual_span x[EXP_MAX];
	uint32_t nx;
	const char *eol;
	uint32_t over;                  /* the program did not fit: a bug of the generator, not a result */
	uint32_t cap;                   /* inside a literal being written: its pieces are bytes, and one span is made at the end */
	uint32_t nonl;                  /* a heredoc is open on this line: no literal may run onto the next */
	struct { char id[16]; uint8_t raw, indent, interp; } hd[3];
	uint32_t nhd;
	uint32_t level;                 /* indentation of the statement */
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

/* The bytes, as code or as part of the literal being written. */
static void gput(struct gen *g, const char *t)
{
	size_t l = strlen(t);

	if (g->n + l > GEN_MAX) {
		g->over = 1;
		return;
	}
	memcpy(g->b + g->n, t, l);
	g->n += (uint32_t)l;
}

/* The text from `from` to now is code, string or comment, with these delimiters: one span (code joins the one before). */
static void span(struct gen *g, uint32_t from, uint8_t kind, uint32_t open, uint32_t close, uint8_t flags)
{
	if (g->cap || g->n == from)
		return;
	if (g->nx + 1u >= EXP_MAX) {
		g->over = 1;
		return;
	}
	if (kind == KGENOME_TEXTUAL_CODE && g->nx && g->x[g->nx - 1u].kind == KGENOME_TEXTUAL_CODE &&
	    g->x[g->nx - 1u].off + g->x[g->nx - 1u].len == from) {
		g->x[g->nx - 1u].len += g->n - from;
		return;
	}
	g->x[g->nx++] = (struct kgenome_textual_span){ .off = from, .len = g->n - from, .open_len = open, .close_len = close,
						      .kind = kind, .flags = flags };
}

/* Code written now. Between two spans the bytes are code: a gap is filled with it when a literal begins. */
static void code(struct gen *g, const char *t)
{
	uint32_t from = g->n;

	gput(g, t);
	span(g, from, KGENOME_TEXTUAL_CODE, 0, 0, 0);
}

static void eol(struct gen *g)
{
	code(g, g->eol);
}

static void indent(struct gen *g)
{
	uint32_t i;

	for (i = 0; i < g->level; i++)
		code(g, i & 1u ? "\t" : "  ");
}

static void expr(struct gen *g, uint32_t depth);

/* A line break inside a literal, as the text types them; not where a heredoc is waiting for the line. */
static const char *lit_eol(struct gen *g)
{
	return g->nonl ? " " : g->eol;
}

/* What a literal's delimiters are: the opener, the closer, and what it reads. */
struct lit {
	uint8_t o, c;
	uint8_t interp;                 /* "#{" and "#@" are read */
	uint8_t had;                    /* one was written */
	uint8_t re;                     /* a pattern: the body has to be one the regexp compiler takes */
	uint8_t sym;                    /* a symbol's string: no escape may make a byte that is not utf-8 (":\"\\M-a\"" is refused) */
	uint32_t depth;
};

/* Is the byte one of the literal's own delimiters. */
static int is_delim(const struct lit *l, char c)
{
	return (uint8_t)c == l->o || (uint8_t)c == l->c;
}

/* A byte of the text that is not a delimiter: raw, or escaped when it is one. */
static void special(struct gen *g, const struct lit *l, char c)
{
	char t[4] = { 0, 0, 0, 0 };

	if (is_delim(l, c) || (c == '\\')) {
		t[0] = '\\';
		t[1] = c;
	} else {
		t[0] = c;
	}
	gput(g, t);
}

/* "#{ code }", "#@a", "#$1" - only in a literal that reads them. */
static void interpolation(struct gen *g, struct lit *l)
{
	static const char *const var[] = { "#@a ", "#@@b ", "#$c ", "#$1 ", "#$-w ", "#$stdout ", "#@iv_2 " };

	l->had = 1;
	if (pct(g, 30)) {
		gput(g, PICK(g, var));           /* a space after: a name must not run into the text that follows */
		return;
	}
	gput(g, "#{");
	if (pct(g, 15))
		gput(g, lit_eol(g));
	if (l->depth < 3u && pct(g, 80)) {
		uint32_t keep = g->nonl;

		g->nonl = 1;            /* a literal inside it may not run onto a line the heredoc would take */
		/* in a pattern or a symbol the code is an argument: a literal alone would be folded into it when the text is compiled */
		gput(g, l->re || l->sym ? "foo(" : "");
		expr(g, l->depth + 1u);
		gput(g, l->re || l->sym ? ")" : "");
		g->nonl = keep;
	} else {
		gput(g, "x");
	}
	gput(g, pct(g, 10) && !g->nonl ? " # c\n}" : "}");
}

/* May the piece stand in a literal with these delimiters: it holds neither of them, unless it is exactly the balanced pair. */
static const char *fit(const struct lit *l, const char *p)
{
	char pair[3] = { (char)l->o, (char)l->c, 0 };

	if (!strchr(p, (char)l->o) && !strchr(p, (char)l->c))
		return p;
	return l->o != l->c && !strcmp(p, pair) ? p : "q";
}

/* The body of a pattern: pieces that are each a whole regular expression, so that any run of them compiles. */
static void regex_body(struct gen *g, struct lit *l)
{
	static const char *const piece[] = { "abc", "a|b", "[a-z]", "\\d+", "(x)", "\\\\", "\\.", "^", "$", "\\s*", "\xc3\xa9", "\\n", "a?", "[^a]" };
	uint32_t i, k = rnd(g, 8);

	/* a pattern after a name that takes an argument (puts /x/) is a division if it begins with white space */
	gput(g, "q");
	for (i = 0; i < k; i++) {
		uint32_t r = rnd(g, 100);

		if (r < 60) {
			gput(g, fit(l, PICK(g, piece)));
		} else if (r < 75) {
			char t[3] = { '\\', (char)l->o, 0 };

			gput(g, t);              /* the delimiter, escaped */
		} else if (r < 90) {
			interpolation(g, l);
		} else {
			gput(g, lit_eol(g));
		}
	}
	gput(g, "z");
}

/* The content of a literal, up to a dozen pieces; the delimiters are not in it. */
static void body(struct gen *g, struct lit *l, int multiline)
{
	if (l->re) {
		regex_body(g, l);
		return;
	}
	static const char *const plain[] = { "abc", "x y", "foo.bar", "1 2 3", "\xc3\xa9", "a-b", "=", "; ", "!", "%", "*", "&",
					     "~", "^", "_", ",", ".", ":", "?", "\t", "  ", "()", "[]", "{}", "<>", "\\\\", "\\n", "\\x41",
					     "\\101", "\\u{41}", "\\M-a", "\\t", "\\s", "\\e", "\\0" };
	static const char special_byte[] = "\"'`/|!-+$@#{}()[]<>%";
	uint32_t i, k = rnd(g, 12);

	for (i = 0; i < k; i++) {
		uint32_t r = rnd(g, 100);

		if (r < 55) {
			const char *p = fit(l, PICK(g, plain));

			gput(g, l->sym && !strcmp(p, "\\M-a") ? "m" : p);
		} else if (r < 75) {
			char c = special_byte[rnd(g, (uint32_t)sizeof special_byte - 1u)];

			if (c == '#' || (c == '$' || c == '@')) {
				/* not before "{", a name or a "$": no interpolation made by chance */
				gput(g, fit(l, c == '#' ? "# " : c == '$' ? "$ " : "@ "));
			} else {
				special(g, l, c);
			}
		} else if (r < 85 && l->interp) {
			interpolation(g, l);
		} else if (r < 92 && multiline) {
			gput(g, lit_eol(g));
		} else if (l->o != l->c) {
			/* a pair of the delimiter, balanced: it nests */
			char t[4] = { (char)l->o, 'a', (char)l->c, 0 };

			gput(g, t);
		} else {
			gput(g, "z");
		}
	}
	/* a trailing backslash would escape the delimiter */
	if (g->n && g->b[g->n - 1u] == '\\') {
		int odd = 0;
		uint32_t j = g->n;

		while (j && g->b[j - 1u] == '\\') {
			odd = !odd;
			j--;
		}
		if (odd)
			gput(g, "z");
	}
}

/* One literal: the opener text, a body, the closer text; the span is made at the end. */
static void literal(struct gen *g, const char *open, const char *close, struct lit l, uint32_t open_len, uint32_t close_len,
		    uint8_t escapes, int multiline)
{
	uint32_t from = g->n;

	g->cap++;
	gput(g, open);
	body(g, &l, multiline);
	gput(g, close);
	g->cap--;
	span(g, from, KGENOME_TEXTUAL_STRING, open_len, close_len,
	     (uint8_t)(escapes && !l.had ? KGENOME_TEXTUAL_F_INTERP : 0u));
}

/* which: 0 any of the three, 1 '...', 2 "..." (a symbol's quote: ":`" is the method named "`") */
static void lit_quote(struct gen *g, uint32_t depth, uint32_t which)
{
	struct lit l = { .depth = depth, .sym = which != 0 };
	uint32_t r = which == 1u ? 0u : which == 2u ? 5u : rnd(g, 10);

	if (r < 3) {
		l.o = l.c = '\'';
		literal(g, "'", "'", l, 1, 1, 0, 1);
	} else if (r < 8) {
		l.o = l.c = '"';
		l.interp = 1;
		literal(g, "\"", "\"", l, 1, 1, 1, 1);
	} else {
		l.o = l.c = '`';
		l.interp = 1;
		literal(g, "`", "`", l, 1, 1, 1, 1);
	}
}

static void lit_percent(struct gen *g, uint32_t depth)
{
	static const struct { char type, o, c; } d[] = {
		{ 'q', '(', ')' }, { 'Q', '[', ']' }, { 'w', '{', '}' }, { 'W', '<', '>' }, { 'i', '|', '|' }, { 'I', '!', '!' },
		{ 's', '(', ')' }, { 'x', '[', ']' }, { 'r', '{', '}' }, { 0, '(', ')' }, { 'q', '-', '-' }, { 'q', '#', '#' },
		{ 'w', '\'', '\'' }, { 'r', '|', '|' }, { 0, '[', ']' }, { 'Q', '(', ')' }, { 'q', '<', '>' },
	};
	static const char *const opts[] = { "", "i", "mx", "ox" };
	uint32_t k = rnd(g, (uint32_t)(sizeof d / sizeof d[0]));
	struct lit l = { .o = (uint8_t)d[k].o, .c = (uint8_t)d[k].c, .re = d[k].type == 'r', .sym = d[k].type == 'i' || d[k].type == 'I',
			 .depth = depth };
	char open[4] = { '%', d[k].type, d[k].o, 0 }, close[8] = { d[k].c, 0 };
	uint32_t ol = 3, cl = 1;
	int esc = d[k].type == 'Q' || d[k].type == 'x' || d[k].type == 0;

	if (!d[k].type) {
		open[1] = d[k].o;
		open[2] = 0;
		ol = 2;
	}
	l.interp = d[k].type == 'Q' || d[k].type == 'W' || d[k].type == 'I' || d[k].type == 'r' || d[k].type == 'x' || !d[k].type;
	if (d[k].type == 'r') {
		const char *o = opts[rnd(g, 4)];

		strcat(close, o);
		cl += (uint32_t)strlen(o);
	}
	literal(g, open, close, l, ol, cl, (uint8_t)esc, 1);
}

static void lit_regex(struct gen *g, uint32_t depth)
{
	static const char *const opts[] = { "", "i", "mx", "o", "imxo" };
	struct lit l = { .o = '/', .c = '/', .interp = 1, .re = 1, .depth = depth };
	const char *o = PICK(g, opts);
	char close[16] = "/";

	strcat(close, o);
	literal(g, "/", close, l, 1, 1u + (uint32_t)strlen(o), 0, 1);
}

/* A heredoc operator, here; its body is written at the end of the line. */
static void lit_heredoc(struct gen *g)
{
	static const char *const ids[] = { "EOS", "A", "END_X", "TEXT", "B2" };
	static const struct { const char *fmt; uint8_t raw, indent; } form[] = {
		{ "<<%s", 0, 0 }, { "<<-%s", 0, 1 }, { "<<~%s", 0, 1 }, { "<<\"%s\"", 0, 0 }, { "<<'%s'", 1, 0 }, { "<<`%s`", 0, 0 },
		{ "<<-\"%s\"", 0, 1 }, { "<<~'%s'", 1, 1 },
	};
	uint32_t f = rnd(g, (uint32_t)(sizeof form / sizeof form[0]));
	char t[64];

	if (g->nhd >= 3u || g->cap)
		return;
	snprintf(g->hd[g->nhd].id, sizeof g->hd[g->nhd].id, "%s", PICK(g, ids));
	g->hd[g->nhd].raw = form[f].raw;
	g->hd[g->nhd].indent = form[f].indent;
	g->hd[g->nhd].interp = !form[f].raw;
	snprintf(t, sizeof t, form[f].fmt, g->hd[g->nhd].id);
	code(g, t);
	g->nhd++;
	g->nonl = 1;
}

/* The bodies of the heredocs waiting, after the line break that ends the line. */
static void heredoc_bodies(struct gen *g)
{
	uint32_t k, i, lines;

	for (k = 0; k < g->nhd; k++) {
		struct lit l = { .interp = g->hd[k].interp };
		uint32_t from = g->n, tl = (uint32_t)strlen(g->hd[k].id);

		g->cap++;
		g->nonl = 0;
		lines = rnd(g, 4);
		for (i = 0; i < lines; i++) {
			if (pct(g, 40))
				gput(g, g->hd[k].indent ? "  " : "");
			body(g, &l, 0);
			gput(g, "w");
			gput(g, g->eol);
		}
		if (g->hd[k].indent && pct(g, 60)) {
			gput(g, "   ");
			tl += 3u;
		}
		gput(g, g->hd[k].id);
		g->cap--;
		span(g, from, KGENOME_TEXTUAL_STRING, 0, tl,
		     (uint8_t)(KGENOME_TEXTUAL_F_HERE | (g->hd[k].interp && !l.had ? KGENOME_TEXTUAL_F_INTERP : 0u)));
		eol(g);
	}
	g->nhd = 0;
}

/* A symbol, a character literal, a global variable, a number, a name: code. */
static void atom_code(struct gen *g)
{
	static const char *const c[] = { ":foo", ":Bar?", ":+", ":[]=", ":/", ":%", ":<<", ":<=>", "?a", "?\\n", "?\\C-a", "?\"", "?'", "?#",
					 "?(", "?\\u{41}", "$'", "$\"", "$`", "$/", "$,", "$;", "$stdout", "$1", "$0", "@a", "@@b", "7", "0x1f", "1.5",
					 "nil", "true", "self", "FOO", "v1", "v2" };

	code(g, PICK(g, c));
}

static void atom(struct gen *g, uint32_t depth)
{
	uint32_t r = rnd(g, 20);

	if (r < 5) {
		lit_quote(g, depth, 0);
	} else if (r < 8) {
		lit_percent(g, depth);
	} else if (r < 10) {
		lit_regex(g, depth);
	} else if (r < 11) {
		code(g, ":");
		lit_quote(g, depth, pct(g, 50) ? 1u : 2u);
	} else if (r < 12 && !g->cap && !g->nonl) {
		lit_heredoc(g);
	} else {
		atom_code(g);
	}
}

/* The opening of a hash literal and its first key: a name label, a symbol, a string label, a string key. */
static void hash_open(struct gen *g, uint32_t depth)
{
	static const char *const word[] = { "{ a: ", "{ :s => ", "{ if: " };
	uint32_t r = rnd(g, 5);
	uint32_t from;

	(void)depth;
	if (r < 3) {
		code(g, word[r]);
		return;
	}
	code(g, "{ ");
	from = g->n;
	gput(g, r == 3u ? "\"k\"" : "'q'");
	span(g, from, KGENOME_TEXTUAL_STRING, 1, 1, r == 3u ? KGENOME_TEXTUAL_F_INTERP : 0u);
	code(g, r == 3u ? ": " : " => ");
}

/*
 * An expression. The operators are written with a space on both sides where "/" "%" "<<" "?" ":" could be read two ways, and
 * `puts` takes its operand as an argument only where a command call may stand (the top of a statement).
 */
static void expr(struct gen *g, uint32_t depth)
{
	static const char *const op[] = { " + ", " - ", " * ", " / ", " % ", " << ", " == ", " && ", " || ", " =~ ", " <=> " };
	uint32_t r = rnd(g, 100);

	if (depth > 3u || r < 35) {
		atom(g, depth);
	} else if (r < 55) {
		atom(g, depth);
		code(g, PICK(g, op));
		atom(g, depth);
	} else if (r < 63) {
		atom(g, depth);
		code(g, " ? ");
		atom(g, depth);
		code(g, " : ");
		atom(g, depth);
	} else if (r < 71) {
		code(g, "foo(");
		atom(g, depth);
		code(g, ", ");
		expr(g, depth + 1u);
		code(g, ")");
	} else if (r < 77) {
		code(g, "[");
		atom(g, depth);
		code(g, ", ");
		atom(g, depth);
		code(g, "]");
	} else if (r < 83) {
		hash_open(g, depth);
		atom(g, depth);
		code(g, " }");
	} else if (r < 88 && depth == 0) {
		code(g, "puts ");
		atom(g, depth);
	} else if (r < 92) {
		code(g, "(");
		expr(g, depth + 1u);
		code(g, ").size");
	} else {
		code(g, "x.map { |e| ");
		atom(g, depth);
		code(g, " }");
	}
}

static void comment(struct gen *g)
{
	static const char *const t[] = { "# c", "#", "# \"q' `b", "# #{x} %w[ <<A", "#!x", "# \\", "# =begin" };
	uint32_t from = g->n;

	gput(g, PICK(g, t));
	span(g, from, KGENOME_TEXTUAL_COMMENT, 1, 0, 0);
}

/* One statement, one line (and the bodies of the heredocs it opened). */
static void statement(struct gen *g)
{
	static const char *const lhs[] = { "v1 = ", "v2 = ", "@a = ", "$g = ", "X = " };
	static const char *const cmp[] = { "== ", "=~ ", "< ", "% " };
	uint32_t r = rnd(g, 100);

	indent(g);
	if (r < 40) {
		code(g, PICK(g, lhs));
		expr(g, 0);
	} else if (r < 58) {
		expr(g, 0);
	} else if (r < 66) {
		code(g, "if ");
		atom(g, 1);
		code(g, " then ");
		expr(g, 1);
		code(g, " end");
	} else if (r < 74) {
		expr(g, 1);
		code(g, " if v1 ");
		code(g, PICK(g, cmp));
		atom(g, 1);
	} else if (r < 82) {
		code(g, "puts ");
		lit_heredoc(g);
		if (pct(g, 40)) {
			code(g, ", ");
			lit_heredoc(g);
		}
		if (pct(g, 40))
			code(g, ".strip");
	} else if (r < 88) {
		code(g, "def m(a) ");
		lit_regex(g, 1);
		code(g, " end");
	} else if (r < 92) {
		code(g, "return ");
		atom(g, 1);
	} else {
		code(g, "x = ");
		lit_heredoc(g);
	}
	if (pct(g, 25)) {
		code(g, " ");
		comment(g);
	}
	eol(g);
	g->nonl = 0;
	heredoc_bodies(g);
}

/* A whole program: statements, comments, blocks, and at the end perhaps __END__ and data. */
static void program(struct gen *g)
{
	uint32_t i, k = 3u + rnd(g, 14);

	g->eol = pct(g, 30) ? "\r\n" : "\n";
	for (i = 0; i < k && !g->over; i++) {
		uint32_t r = rnd(g, 100);

		g->level = pct(g, 30) ? 1u + rnd(g, 3) : 0u;
		if (r < 8) {
			uint32_t from = g->n;

			gput(g, "=begin");
			if (pct(g, 40))
				gput(g, " note");
			gput(g, g->eol);
			if (pct(g, 60)) {
				gput(g, "x \"y' #{ %w[ <<A");
				gput(g, g->eol);
			}
			gput(g, "=end");
			if (pct(g, 30))
				gput(g, " tail");
			span(g, from, KGENOME_TEXTUAL_COMMENT, 6, 4, 0);
			eol(g);
		} else if (r < 14) {
			g->level = 0;
			indent(g);
			comment(g);
			eol(g);
		} else if (r < 17) {
			eol(g);
		} else {
			statement(g);
		}
	}
	if (pct(g, 25) && !g->over) {
		uint32_t from = g->n, open = 7u + (uint32_t)strlen(g->eol);

		gput(g, "__END__");
		gput(g, g->eol);
		gput(g, pct(g, 50) ? "data \"x' `y #{ %w[ <<A =begin\n" : "");
		span(g, from, KGENOME_TEXTUAL_STRING, open, 0, 0);
	}
}

#endif /* KGENOME_TEST_TEXTUAL_RUBY_GEN_H */
