#ifndef KGENOME_TEST_TEXTUAL_PERL_GEN_H
#define KGENOME_TEST_TEXTUAL_PERL_GEN_H

/*
 * textual_perl_gen.h - the perl program generator of textual_perl.c, kept apart so that the test stays under the
 * size of one file and so that a scratch program can include it to write the generated programs to disk for perl
 * to read. Included by textual_perl.c only, after textual_check.h and the definition of PERL.
 *
 * (b) THE GENERATOR. A program is built from tokens whose class is known when they are written - the generator
 * says "this is a string with a three byte opener and a one byte closer, flagged as interpolating" at the moment
 * it writes it - and the expected span list is built beside the text, so what the lexer must answer is not worked
 * out from the text afterwards by a second lexer. What is varied:
 *   - strings: ' " ` and q qq qw qx qr m with every delimiter perl takes (each bracket pair, which nests, and
 *     / ! | # , ; ' " ~ ^ %), s tr y in both shapes (one delimiter, or brackets with white space and a comment
 *     between the parts, the second part in other brackets), flags; in a body: plain bytes, the delimiter escaped,
 *     a nested pair, a backslash pair, a line break, a "#", an interpolation ($x @a ${x} $h{a} $a[0] @{[ 1 ]}) where
 *     the form interpolates;
 *   - here-documents: <<"A" <<'A' <<A <<~A <<~'A' <<\A, one to three on a line, with code and a comment after the
 *     operators on the line, bodies with "#", quotes and "=pod" in them;
 *   - code: a pattern after an operator or a word and a division after a term, hash keys that are quote words
 *     (s => 1, $h{y}), special variables ($#a $#{$r} $' $" $$ $0), prototypes, blocks and labels, sub names that
 *     are quote words;
 *   - the rest of the text: "#" comments in every place a line may end, pod blocks where a statement begins, an
 *     __END__ or __DATA__ section with bytes of every kind, a format;
 *   - the line endings: "\n" or "\r\n" everywhere, strings and bodies included, a final line with or without its
 *     break.
 * The generator is checked by perl, not trusted: a scratch program includes this file and writes N of its programs to
 * disk; `perl -c` reads each, and `perl -MO=Deparse` reads it again with the text of each span the generator says is
 * a string replaced by a marker (it must come out in the output, and the program must still compile) and each comment
 * replaced by blanks (the output must not change). A generator that wrote text perl refuses, or a string that is
 * not where it was said to be, would be a test of nothing.
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
	uint32_t uniq;                  /* a running number, so that every literal and comment has a text of its own */
};

static uint32_t grnd(struct gen *g, uint32_t k)
{
	g->s ^= g->s >> 12;
	g->s ^= g->s << 25;
	g->s ^= g->s >> 27;
	return (uint32_t)((g->s * 2685821657736338717ull) >> 33) % k;
}

static void gput(struct gen *g, const char *t, uint32_t l)
{
	if (g->n + l > GEN_MAX) {
		g->over = 1;
		return;
	}
	memcpy(g->b + g->n, t, l);
	g->n += l;
}

static void gcat(struct gen *g, const char *t)
{
	gput(g, t, (uint32_t)strlen(t));
}

/* An expected span, [off, n): the generator's own claim. Code next to code is one span, as the lexer delivers it. */
static void gspan(struct gen *g, uint32_t off, uint8_t kind, uint8_t flags, uint32_t open, uint32_t close)
{
	struct kgenome_textual_span *x;

	if (g->over || g->n == off)
		return;
	if (kind == KGENOME_TEXTUAL_CODE && g->nx && g->x[g->nx - 1u].kind == KGENOME_TEXTUAL_CODE) {
		g->x[g->nx - 1u].len += g->n - off;
		return;
	}
	if (g->nx >= EXP_MAX) {
		g->over = 1;
		return;
	}
	x = &g->x[g->nx++];
	x->off = off;
	x->len = g->n - off;
	x->kind = kind;
	x->flags = flags;
	x->open_len = open;
	x->close_len = close;
}

static void gcode(struct gen *g, const char *t)
{
	uint32_t off = g->n;

	gcat(g, t);
	gspan(g, off, KGENOME_TEXTUAL_CODE, 0, 0, 0);
}

/* A line break, in the text's style, as code. */
static void gnl(struct gen *g)
{
	gcode(g, g->eol);
}

/* A comment that ends the line; its text is unique and its line break is the code's. A CRLF text has its CR in it. */
static void gcomment(struct gen *g, const char *lead)
{
	char t[64];
	uint32_t off = g->n;

	snprintf(t, sizeof t, "# %sCMT%u '\"`\\ $x", lead, ++g->uniq);
	gcat(g, t);
	if (g->eol[0] == '\r')
		gcat(g, "\r");
	gspan(g, off, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0);
	gcode(g, "\n");
}

/* A gap that may hold a line break: white space, or a comment and the break after it. */
static void ggap(struct gen *g)
{
	switch (grnd(g, 5)) {
	case 0:
		gcode(g, " ");
		break;
	case 1:
		gcode(g, "\t");
		break;
	case 2:
		gnl(g);
		break;
	case 3:
		gcode(g, " ");
		gcomment(g, "");
		break;
	default:
		break;
	}
}

/* ---- literals ---- */

struct delim {
	const char *open, *close;
};

/* The delimiters perl takes: a bracket pair nests, the rest close on themselves. Not "=" (s=a=b= and "=>" are the form's business), not a word byte. */
static const struct delim delims[] = {
	{ "(", ")" }, { "[", "]" }, { "{", "}" }, { "<", ">" }, { "/", "/" }, { "!", "!" }, { "|", "|" }, { "#", "#" },
	{ ",", "," }, { ";", ";" }, { "'", "'" }, { "\"", "\"" }, { "~", "~" }, { "^", "^" }, { "%", "%" }, { ":", ":" },
};

#define N_DELIMS (sizeof delims / sizeof delims[0])

static int gis_pair(const struct delim *d)
{
	return d->open[0] != d->close[0];
}

/* What the text is read as by perl: bytes only (q, qw, single quotes), interpolated (qq, qx, "..." and the replacement of s///), or a regular expression. */
enum { G_PLAIN, G_INTERP, G_REGEX };

/* One piece of a literal's body that holds no delimiter that is not escaped: plain bytes, the escaped delimiter, a nested pair. */
static void gbody(struct gen *g, const struct delim *d, int kind, uint32_t depth, char *out, uint32_t *w, uint32_t cap)
{
	/* a pattern must be one perl compiles: no metacharacter that needs a partner or an operand, and no "$" or "@" to interpolate */
	static const char *const plain[] = { "abcxyz 019_-+*.,:?%&=~^|!<>()[]{}/@$#'\"`", "abcxyz 019_-+*.,:?%&=~^|!<>()[]{}/#'\"`", "abcxyz 019_,:;!%&=~<>'\"`#" };
	const char *alpha = plain[kind];
	uint32_t k, pieces = 1u + grnd(g, 5), la = (uint32_t)strlen(alpha);

	for (k = 0; k < pieces && *w + 16u < cap; k++) {
		uint32_t r = grnd(g, 10);

		if (r < 5) {
			uint32_t run = 1u + grnd(g, 6);

			while (run-- && *w + 8u < cap) {
				char c = alpha[grnd(g, la)];

				if (c == d->open[0] || c == d->close[0])
					c = 'q';
				out[(*w)++] = c;
			}
		} else if (r == 5) {
			/* perl drops the backslash of an escaped bracket in a pattern, and the group is then unmatched */
			if (kind == G_REGEX && gis_pair(d)) {
				out[(*w)++] = 'q';
				continue;
			}
			out[(*w)++] = '\\';
			out[(*w)++] = d->open[0];
		} else if (r == 6 || (r == 7 && kind == G_REGEX && d->open[0] == '(')) {
			/* (a pattern with "(" for its delimiter does not take a nested group: perl says "Unmatched (" for some, [Unverified] why) */
			if (kind == G_REGEX && d->open[0] == '(') {
				out[(*w)++] = 'q';
				continue;
			}
			out[(*w)++] = '\\';
			out[(*w)++] = '\\';
		} else if (r == 7 && gis_pair(d) && depth < 3u && !(kind == G_REGEX && d->open[0] != '<')) {
			out[(*w)++] = d->open[0];
			out[(*w)++] = 'n';
			gbody(g, d, kind, depth + 1u, out, w, cap);
			out[(*w)++] = d->close[0];
		} else if (r == 8) {
			memcpy(out + *w, g->eol, strlen(g->eol));
			*w += (uint32_t)strlen(g->eol);
		} else if (kind == G_INTERP) {
			static const char *const v[] = { "$x", "@a", "${x}", "$h{a}", "$a[0]", "@{[ 1 ]}", "\\n", "\\t", "\\x41", "\\101" };
			const char *s = v[grnd(g, (uint32_t)(sizeof v / sizeof v[0]))];

			if (!strchr(s, d->open[0]) && !strchr(s, d->close[0])) {
				memcpy(out + *w, s, strlen(s));
				*w += (uint32_t)strlen(s);
				/* perl reads on from a name: "$x{" and "$x[" are subscripts, "$xa" another variable */
				if (s[0] == '$' || s[0] == '@')
					out[(*w)++] = ' ';
			}
		}
	}
}

/* The text between the delimiters, starting with a marker of its own so that the form can be asked to keep it. */
static void gtext(struct gen *g, const struct delim *d, int kind, char *out, uint32_t cap, const char *tag)
{
	uint32_t w = 0;

	w = (uint32_t)snprintf(out, cap, "%s%u", tag, ++g->uniq);
	gbody(g, d, kind, 0, out, &w, cap);
	out[w] = 0;
}

static void gstring(struct gen *g, uint32_t off, uint32_t open, uint32_t close, uint8_t flags)
{
	gspan(g, off, KGENOME_TEXTUAL_STRING, flags, open, close);
}

/* '...' "..." `...` */
static void gquoted(struct gen *g)
{
	static const char q[] = "'\"`";
	char b[512], c = q[grnd(g, 3)], dd[2] = { 0, 0 };
	struct delim d;
	uint32_t off = g->n;

	dd[0] = c;
	d.open = d.close = dd;
	gtext(g, &d, c != '\'' ? G_INTERP : G_PLAIN, b, sizeof b, "STR");
	gput(g, &c, 1);
	gcat(g, b);
	gput(g, &c, 1);
	gstring(g, off, 1u, 1u, (uint8_t)(c == '\'' ? 0u : KGENOME_TEXTUAL_F_INTERP));
}

static const char *const ops1[] = { "q", "qq", "qw", "qx", "qr", "m" };

/* One-part operators and, with a flag, s tr y: the delimiter, its white space and comment in front, and the flags. */
static void gquotelike(struct gen *g, int two)
{
	const struct delim *d = &delims[grnd(g, N_DELIMS)];
	static const char *const ops2[] = { "s", "tr", "y" };
	const char *op = two ? ops2[grnd(g, 3)] : ops1[grnd(g, 6)];
	int is_s = op[0] == 's' && op[1] == 0, interp;
	char b[400], b2[400], pre[80] = "";
	uint32_t off = g->n, open, close = 1;
	const char *flags = "";

	/* qq interpolates with any delimiter, qx with every one but "'" */
	interp = !strcmp(op, "qq") || (!strcmp(op, "qx") && d->open[0] != '\'');
	if (d->open[0] == '#')
		pre[0] = 0;
	else if (grnd(g, 3) == 0)
		snprintf(pre, sizeof pre, grnd(g, 2) ? " " : "\n");
	else if (grnd(g, 6) == 0)
		snprintf(pre, sizeof pre, " # c\n");
	if (g->eol[0] == '\r') {
		/* the break in the gap is typed as the text's */
		char t[80];
		uint32_t i, w = 0;

		for (i = 0; pre[i]; i++) {
			if (pre[i] == '\n')
				t[w++] = '\r';
			t[w++] = pre[i];
		}
		t[w] = 0;
		strcpy(pre, t);
	}
	if (!strcmp(op, "m"))
		flags = grnd(g, 2) ? "i" : "gx";
	if (!strcmp(op, "qr"))
		flags = grnd(g, 2) ? "i" : "x";
	if (is_s)
		flags = grnd(g, 2) ? "g" : "gi";
	if (!strcmp(op, "tr") || !strcmp(op, "y"))
		flags = grnd(g, 2) ? "" : "d";
	if (two && (!strcmp(op, "tr") || !strcmp(op, "y"))) {
		/* a transliteration holds ranges and escapes of its own: plain letters, so that perl accepts it */
		snprintf(b, sizeof b, "abc%u", ++g->uniq % 7u);
		snprintf(b2, sizeof b2, "xyz%u", g->uniq % 7u);
	} else {
		int regex = !strcmp(op, "m") || !strcmp(op, "qr") || is_s;

		gtext(g, d, regex ? G_REGEX : interp ? G_INTERP : G_PLAIN, b, sizeof b, "STR");
	}
	gcat(g, op);
	gcat(g, pre);
	gcat(g, d->open);
	open = g->n - off;
	gcat(g, b);
	if (two) {
		const struct delim *d2 = d;

		gcat(g, d->close);
		if (gis_pair(d)) {
			d2 = &delims[grnd(g, 4)];
			gcat(g, grnd(g, 2) ? " " : "\t");
			if (grnd(g, 3) == 0) {
				gcat(g, "# between");
				gcat(g, "\n");
			}
			gcat(g, d2->open);
		}
		if (strcmp(op, "tr") && strcmp(op, "y"))
			gtext(g, d2, G_INTERP, b2, sizeof b2, "REP");
		gcat(g, b2);
		d = d2;
	}
	gcat(g, d->close);
	/* the flags are in the span after a closer the lexer reads them behind, and are a word of code after any other (flags_end) */
	if (flags[0] && !strchr("/)]}>!|#,:%", d->close[0])) {
		gstring(g, off, open, (uint32_t)strlen(d->close), (uint8_t)(interp ? KGENOME_TEXTUAL_F_INTERP : 0u));
		gcode(g, flags);
		return;
	}
	gcat(g, flags);
	close = (uint32_t)strlen(d->close) + (uint32_t)strlen(flags);
	gstring(g, off, open, close, (uint8_t)(interp ? KGENOME_TEXTUAL_F_INTERP : 0u));
}

/* A statement made of one literal, in whatever shape: the unit most statements are made of. */
static void gliteral(struct gen *g)
{
	uint32_t k = grnd(g, 4);

	if (k == 0)
		gquoted(g);
	else if (k == 1)
		gquotelike(g, 0);
	else
		gquotelike(g, k == 2);
}

/* ---- here-documents ---- */

struct here {
	char     tag[16];
	uint8_t  indent, interp;
};

/* "<<" + "~" + blanks + a quote and the tag, or a bare tag: the quoted tag is a span of its own (a here one), the rest is code. */
static void ghere_op(struct gen *g, struct here *h, int handle)
{
	static const char *const pre[] = { "<<", "<<", "<<", "<<~", "<<~", "<<\\", "<< ", "<<~" };
	static const char qc[] = { '"', '\'', 0, 0, '\'', 0, '"', '"' };
	uint32_t k = grnd(g, 8), off;
	char q;

	/* after the file handle of a print the tag is attached: "print $fh << "A"" is a shift in perl 5.44 */
	if (handle && k == 6)
		k = 0;
	q = qc[k];

	snprintf(h->tag, sizeof h->tag, "TAG%u", ++g->uniq);
	h->indent = (uint8_t)(k == 3 || k == 4 || k == 7);
	h->interp = (uint8_t)!(k == 1 || k == 4 || k == 5);
	gcode(g, pre[k]);
	off = g->n;
	if (q)
		gput(g, &q, 1);
	gcat(g, h->tag);
	if (q)
		gput(g, &q, 1);
	if (q)
		gspan(g, off, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_HERE, 1u, 1u);
	else
		gspan(g, off, KGENOME_TEXTUAL_CODE, 0, 0, 0);
}

/* The body of the heredoc `h`, and its closing line: lines with the things that are not code in them. */
static void ghere_body(struct gen *g, const struct here *h)
{
	uint32_t off = g->n, lines = grnd(g, 4), i, close;
	static const char *const l[] = { "plain text", "# not a comment", "'single' \"double\" `back`", "=pod", "s/a/b/ q{x} <<X", "$x @a ${x}", "", "  indented \\ line" };
	char t[80];

	snprintf(t, sizeof t, "%sHDOC%u", h->indent ? "    " : "", ++g->uniq);
	gcat(g, t);
	gcat(g, g->eol);
	for (i = 0; i < lines; i++) {
		const char *s = l[grnd(g, (uint32_t)(sizeof l / sizeof l[0]))];

		if (h->indent && s[0])
			gcat(g, "    ");
		if (!h->indent || s[0] || grnd(g, 2))
			gcat(g, s);
		gcat(g, g->eol);
	}
	/* the closing line: the tag, indented only for "<<~"; the CR of a CRLF text is not in the span (perl_quote.c: here_body) */
	close = (uint32_t)strlen(h->tag);
	if (h->indent) {
		gcat(g, "  ");
		close += 2u;
	}
	gcat(g, h->tag);
	gspan(g, off, KGENOME_TEXTUAL_STRING, (uint8_t)(KGENOME_TEXTUAL_F_HERE | (h->interp ? KGENOME_TEXTUAL_F_INTERP : 0u)), 0, close);
	gnl(g);
}

/* A statement with one to three here-documents on its line, code and a comment after them, then the bodies. */
static void gheredocs(struct gen *g)
{
	struct here h[3];
	uint32_t n = 1u + grnd(g, 3), i, k = grnd(g, 7);
	static const char *const lead[] = { "print ", "my $v = ", "push @r, ", "foo(", "return ", "print $fh ", "print STDERR " };
	static const char *const tail[] = { ";", ";", ";", ");", ";", ";", ";" };

	gcode(g, lead[k]);
	/* after a handle there is one operator: "print $fh <<A, <<B" prints to $fh, and the second is a list item all the same */
	for (i = 0; i < n; i++) {
		if (i)
			gcode(g, grnd(g, 2) ? ", " : " . ");
		ghere_op(g, &h[i], k >= 5);
	}
	gcode(g, tail[k]);
	if (grnd(g, 2)) {
		gcode(g, " ");
		gcomment(g, "");
	} else {
		gnl(g);
	}
	for (i = 0; i < n; i++)
		ghere_body(g, &h[i]);
}

/* ---- code ---- */

static void gdivision(struct gen *g)
{
	static const char *const t[] = {
		"$z = $a / $b / 2;", "$z = ($a) / $b / 2;", "$z = $h{a} / 2 / 3;", "$z = $a[0] / 2 / 3;", "$z = ff() / 2 / 3;",
		"$z = $i++ / 2 / 3;", "$z = 4 / 2 / 1;", "$z = 1.5 / 2 / 3;", "$z = 0x10 / 2 / 3;", "$z = $#a / 2 / 3;",
		"$z = $x // 1;", "$z //= 2 / 1;", "$z /= 2;", "$z = time / 2 / 3;", "$z = shift // 1;", "$z = $r->{a} / 2 / 3;",
		"$z = @a / 2 / 3;", "$z = length($x) / 2 / 3;", "$z = $x{a}{b} / 2 / 3;", "$z = -$a / 2 / 3;",
	};

	gcode(g, t[grnd(g, (uint32_t)(sizeof t / sizeof t[0]))]);
}

static void gpattern(struct gen *g)
{
	static const char *const a[] = { "if (", "push @r, ", "$z = ", "return ", "my @l = grep ", "my @p = split ", "unless (", "print 1 and ", "$z = $a ? ", "@l = (1, " };
	static const char *const e[] = { ") { 1 }", ";", ";", ";", ", @x;", ", $x;", ") { 1 }", ";", " : 2;", ");" };
	uint32_t k = grnd(g, 10), off, close;
	const struct delim d = { "/", "/" };
	char b[200];
	const char *flags = grnd(g, 2) ? "" : "i";

	gcode(g, a[k]);
	off = g->n;
	gtext(g, &d, G_REGEX, b, sizeof b, "PAT");
	gcat(g, "/");
	gcat(g, b);
	gcat(g, "/");
	gcat(g, flags);
	close = 1u + (uint32_t)strlen(flags);
	gstring(g, off, 1u, close, 0);
	gcode(g, e[k]);
}

static void gbarewords(struct gen *g)
{
	static const char *const t[] = {
		"%h = (s => 1, y => 2, q => 3, m => 4, tr => 5, qw => 6, qq => 7, qx => 8, qr => 9);",
		"$z = $h{s} . $h{y} . $h{ q } . $h{m} . $h{tr};",
		"$z = $o->s . $o->y(1) . $o->m;",
		"sub s { 1 } sub y { 2 } sub m { 3 } sub q { 4 } sub tr { 5 }",
		"package q; package s; package m; package y;",
		"$z = -s $f;", "$z = (-s $f) > 1;", "$z = $s . $y . $m . $q . $tr;", "@z = (@s, @y, %q, &m, *tr);",
		"$z = ${s} . ${ y } . @{q};", "$z = $::s . $Foo::y . $Foo::q::m;", "$z = &s() if 0;",
		"$z = Foo::s() . Foo::y(1);", "$z = __PACKAGE__ . __LINE__;",
	};
	static const char *const w[] = { "s", "y", "q", "m", "tr", "qw", "qq" };

	if (grnd(g, 4) == 0) {
		/* a quote word before "=>", with white space and comments between */
		gcode(g, "%h3 = (");
		gcode(g, w[grnd(g, 7)]);
		ggap(g);
		gcode(g, "=> 1, ");
		gcode(g, w[grnd(g, 7)]);
		gcode(g, "=>2);");
		return;
	}
	gcode(g, t[grnd(g, (uint32_t)(sizeof t / sizeof t[0]))]);
}

static void gspecial(struct gen *g)
{
	static const char *const t[] = {
		"$n = $#a + $#{$r} + $#$r;", "$z = $' . $\" . $` . $\\ . $, . $/ . $; . $.;", "$z = $0 . $$ . $@ . $! . $&;",
		"@z = ($1, $2, $10);", "$z = $^W . ${^TAINT} . $^O;", "@z = (@-, @+, %+, %-, @ARGV, %ENV, $ENV{PATH});",
		"$z = $r->@* . $r->$#* . $r->%*;", "$z = ${$r}[0] . @{$r}[0,1] . ${\\ 1};", "$z = $a[$#a] . $a[-1] . $h{k};",
		"sub f($$) { 1 }", "sub g(\\@\\@) { 1 }", "sub h :lvalue { $z }", "sub i { my ($p, $q) = @_; return $p / $q / 2 }",
		"A: { last A; }", "B: while (0) { next B }", "$z = 1 ? { a => 1 } : { b => 2 };", "$z = { map { $_ => 1 } @a };",
		"$z = do { 1 } / 2 / 1;", "@z = sort { $a <=> $b } @a;", "print STDERR 1 if 0;",
		"*STDOUT = *STDERR;", "$z = \\&f . \\$x . \\@a;", "$z = $x x 3;", "$z = $ x . @ a;", "sub j :prototype($$) { 1 }", "sub k : lvalue { $z }",
	};

	gcode(g, t[grnd(g, (uint32_t)(sizeof t / sizeof t[0]))]);
}

/* pod where a statement can begin: lines with every kind of byte, none of them a line that begins "=cut". */
static void gpod(struct gen *g)
{
	uint32_t off = g->n, i, lines = grnd(g, 4);
	char t[80];
	static const char *const l[] = { "text 'with' \"quotes\"", "# hash", "  code(); s/a/b/;", "=item two", "", "$x @a <<EOF" };

	snprintf(t, sizeof t, "=head%u POD%u", 1u + grnd(g, 4), ++g->uniq);
	gcat(g, t);
	gcat(g, g->eol);
	for (i = 0; i < lines; i++) {
		gcat(g, l[grnd(g, (uint32_t)(sizeof l / sizeof l[0]))]);
		gcat(g, g->eol);
	}
	gcat(g, "=cut");
	if (g->eol[0] == '\r')
		gcat(g, "\r");
	gspan(g, off, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0);
	gcode(g, "\n");
}

static void gformat(struct gen *g)
{
	uint32_t off;

	gcode(g, "format STDOUT =");
	gnl(g);
	off = g->n;
	gcat(g, "@<<<< @>>>> @||||| @###.## 'q' \"q\" # not a comment");
	gcat(g, g->eol);
	gcat(g, "$a, $b, $c, $d");
	gcat(g, g->eol);
	gcat(g, ".");
	gspan(g, off, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_HERE, 0, 1u);
	gnl(g);
}

/* One statement, and the gaps and comments that may stand in it. */
static void gstatement(struct gen *g)
{
	switch (grnd(g, 14)) {
	case 0:
	case 1:
	case 2:
		gcode(g, "push @r, ");
		ggap(g);
		gliteral(g);
		ggap(g);
		gcode(g, ";");
		break;
	case 3:
		gcode(g, "$x =~");
		ggap(g);
		gquotelike(g, 1);
		gcode(g, ";");
		break;
	case 4:
		gheredocs(g);
		return;
	case 5:
		gdivision(g);
		break;
	case 6:
		gpattern(g);
		break;
	case 7:
		gbarewords(g);
		break;
	case 8:
		gspecial(g);
		break;
	case 9:
		gcode(g, "my %h2 = (");
		ggap(g);
		gliteral(g);
		gcode(g, " => ");
		gliteral(g);
		ggap(g);
		gcode(g, ");");
		break;
	case 10:
		if (!g->n || g->b[g->n - 1u] == '\n') {
			gpod(g);
			return;
		}
		gcode(g, "1;");
		break;
	case 11:
		gcode(g, "if ($x) {");
		ggap(g);
		gliteral(g);
		gcode(g, ";");
		ggap(g);
		gcode(g, "}");
		break;
	case 12:
		gcomment(g, "");
		return;
	default:
		if (g->n && g->b[g->n - 1u] == '\n' && grnd(g, 4) == 0) {
			gformat(g);
			return;
		}
		gcode(g, "sub w { return ");
		gliteral(g);
		gcode(g, "; }");
		break;
	}
	if (grnd(g, 3) == 0) {
		gcode(g, " ");
		gcomment(g, "");
	} else {
		gnl(g);
	}
}

static void ggenerate(struct gen *g, uint64_t seed)
{
	uint32_t n, i, tail;

	memset(g, 0, sizeof *g);
	g->s = seed * 2654435761ull + 88172645463325252ull;
	g->eol = grnd(g, 3) == 0 ? "\r\n" : "\n";
	if (grnd(g, 4) == 0) {
		uint32_t off = g->n;

		gcat(g, "#!/usr/bin/perl -w");
		if (g->eol[0] == '\r')
			gcat(g, "\r");
		gspan(g, off, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0);
		gcode(g, "\n");
	}
	n = 1u + grnd(g, 14);
	for (i = 0; i < n; i++)
		gstatement(g);
	/* the end of the text: nothing, a data section, or pod with no =cut */
	tail = grnd(g, 6);
	if (tail == 0 || tail == 1) {
		uint32_t off, k, len = grnd(g, 40);

		gcode(g, tail ? "__DATA__" : "__END__");
		gnl(g);
		off = g->n;
		for (k = 0; k < len; k++) {
			static const char junk[] = "abc 'q' \"d\" # =pod\n\r\\<<EOF`$x\xe9\x01";

			g->b[g->n++] = (uint8_t)junk[grnd(g, (uint32_t)sizeof junk - 1u)];
		}
		gspan(g, off, KGENOME_TEXTUAL_STRING, 0, 0, 0);
	} else if (tail == 2 && g->n && g->b[g->n - 1u] == '\n') {
		uint32_t off = g->n;

		gcat(g, "=head1 TAILPOD");
		gcat(g, g->eol);
		gcat(g, "text 'x' \"y\"");
		gcat(g, g->eol);
		gspan(g, off, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0);
	}
}

/* ---- checking the lexer against the generator ---- */

struct got {
	struct kgenome_textual_span x[EXP_MAX];
	uint32_t n;
};

static int got_sink(void *u, const struct kgenome_textual_span *s)
{
	struct got *r = u;

	if (r->n < EXP_MAX)
		r->x[r->n] = *s;
	r->n++;
	return 1;
}

static int span_same(const struct kgenome_textual_span *a, const struct kgenome_textual_span *b)
{
	return a->off == b->off && a->len == b->len && a->kind == b->kind && a->flags == b->flags &&
	       a->open_len == b->open_len && a->close_len == b->close_len;
}

static void generator(void)
{
	static struct gen g;
	static struct got r;
	uint64_t seed;
	uint32_t bad = 0;

	for (seed = 1; seed <= 6000u && bad < 3u; seed++) {
		struct kgenome_textual_lex_req rq;
		struct kgenome_textual_lex_res rs;
		uint32_t i;

		ggenerate(&g, seed);
		if (g.over)
			continue;
		memset(&r, 0, sizeof r);
		rq = (struct kgenome_textual_lex_req){ .in = g.b, .n = g.n, .lang = PERL, .sink = got_sink, .user = &r };
		kgenome_textual_lex(&rq, &rs);
		if (r.n != g.nx) {
			printf("  FAIL generator seed %llu: %u spans, expected %u\n", (unsigned long long)seed, r.n, g.nx);
			bad++;
			fails++;
			continue;
		}
		for (i = 0; i < g.nx; i++) {
			if (!span_same(&r.x[i], &g.x[i])) {
				printf("  FAIL generator seed %llu, span %u: got kind %u off %u len %u flags %u open %u close %u, wanted kind %u off %u len %u flags %u open %u close %u\n",
				       (unsigned long long)seed, i, r.x[i].kind, r.x[i].off, r.x[i].len, r.x[i].flags, r.x[i].open_len,
				       r.x[i].close_len, g.x[i].kind, g.x[i].off, g.x[i].len, g.x[i].flags, g.x[i].open_len, g.x[i].close_len);
				bad++;
				fails++;
				break;
			}
		}
	}
}

#endif /* KGENOME_TEST_TEXTUAL_PERL_GEN_H */
