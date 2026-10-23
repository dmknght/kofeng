/*
 * textual_php_hostile - the php lexer and the form on text that was written to break them.
 *
 * THREE ATTACKS, and each states what must hold and checks it against the TEXT, not against what the code under test says.
 *
 * BUILT. A generator that knows php's grammar writes a file from parts whose lexing it knows as it writes them - markup (with the
 * look-alikes of a tag: "<?xml", "<?phpx", "<%", "?" and ">" apart), the three open tags, "?>" with each line ending after it, line
 * comments that stop at "?>" and at "\r", block comments that hold "?>" and quotes, attributes ("#[A('x')]" is code and strings, not a comment), single
 * and double quoted strings with every escape and every kind of interpolation, "b" prefixes, backticks, heredocs and nowdocs (quoted
 * labels, an indented closer, body lines that begin with the label's name and are not the closer, a closer followed by
 * ";" "," ")" or text), "__halt_compiler" with its data, and the white space php has (NUL, "\r", "\r\n", "\v", "\f"). The spans the lexer must
 * deliver are written down as each part is, so the check is the whole list - kind, length, flags, delimiters - and not "no crash". Each
 * literal that has a value is written with it, and kgenome_textual_value must give those bytes back; one that interpolates has none.
 * Then the form: it must succeed, stay within its cap, be its own form, and leave every literal's value as it was.
 *
 * CUT. Every prefix of each seed text: a text that ends inside a string, a heredoc, a comment, an escape, an interpolation, a tag, a
 * halt marker, a call. The lexer partitions it, delivers what it could not close as OPEN, and the form of the form is the form.
 *
 * MUTATED. Seed texts - the programs below, and any file named on the command line, which is how a corpus (WordPress) is attacked
 * without a copy of it in the tree - changed at random: bytes flipped, deleted, doubled, replaced by the bytes that mean something
 * to php, a token from the list below spliced in, two texts crossed. Whatever the text is: the spans partition it, the form is within
 * its cap and is its own form, and the work is bounded - an alarm stops a case that runs past ten seconds.
 */

#include "textual_check.h"

#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#endif

static uint64_t rs_ = 0x9e3779b97f4a7c15u;

static uint32_t rnd(void)
{
	rs_ ^= rs_ << 13;
	rs_ ^= rs_ >> 7;
	rs_ ^= rs_ << 17;
	return (uint32_t)(rs_ >> 32);
}

/* a byte that can be in a php name: letters, digits, "_" and every byte from 0x80 (written here from php's rule, not taken from the lib) */
static int is_name(uint8_t c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80u;
}

static uint32_t pick(uint32_t n)
{
	return rnd() % n;
}

/* ---- a growing text and the spans it must lex to --------------------------------------------------------------------------- */

#define MAXT (1u << 16)
#define MAXS 4096u
struct want {
	uint32_t off, len, open, close;
	uint8_t  kind, flags;
	int      has_value;
	uint32_t vlen;
	uint8_t  value[512];
};

struct gen {
	uint8_t     t[MAXT];
	uint32_t    n;
	struct want s[MAXS];
	uint32_t    ns;
	int         in_php;   /* the text is inside php now (a close tag leaves it) */
};

static void gput(struct gen *g, const void *p, uint32_t n)
{
	memcpy(g->t + g->n, p, n);
	g->n += n;
}

static void gstr(struct gen *g, const char *s)
{
	gput(g, s, (uint32_t)strlen(s));
}

/* A span as the lexer must say it. Neighbouring code (or markup) is one span, as the lexer joins it. */
static void gspan(struct gen *g, uint32_t off, uint32_t len, uint8_t kind, uint8_t flags, uint32_t open, uint32_t close)
{
	struct want *w;

	if (!len)
		return;
	if (g->ns && (kind == KGENOME_TEXTUAL_CODE || kind == KGENOME_TEXTUAL_MARKUP) && !flags) {
		w = &g->s[g->ns - 1u];
		if (w->kind == kind && !w->flags && w->off + w->len == off) {
			w->len += len;
			return;
		}
	}
	w = &g->s[g->ns++];
	memset(w, 0, offsetof(struct want, value));
	w->off = off;
	w->len = len;
	w->kind = kind;
	w->flags = flags;
	w->open = open;
	w->close = close;
}

/* text of `kind` appended: `s` as it is typed */
static void gtext(struct gen *g, const char *s, uint8_t kind)
{
	uint32_t off = g->n;

	gstr(g, s);
	gspan(g, off, (uint32_t)strlen(s), kind, 0, 0, 0);
}

static void gbytes(struct gen *g, const uint8_t *p, uint32_t n, uint8_t kind)
{
	uint32_t off = g->n;

	gput(g, p, n);
	gspan(g, off, n, kind, 0, 0, 0);
}

/* white space inside php: what a statement is written with, as code (NUL is a byte php lexes as code too) */
static void gws(struct gen *g)
{
	static const struct { const char *s; uint32_t n; } w[] = {
		{ "", 0 }, { " ", 1 }, { "  ", 2 }, { "\n", 1 }, { "\r\n", 2 }, { "\t", 1 }, { "\r", 1 }, { "\v", 1 }, { "\f", 1 }, { " \n ", 3 }, { "\n\n", 2 },
		{ "\0", 1 }, { "", 0 }, { "", 0 } };
	uint32_t k = pick(sizeof w / sizeof w[0]);

	gbytes(g, (const uint8_t *)w[k].s, w[k].n, KGENOME_TEXTUAL_CODE);
}

/* the last span, which carries a value */
static void gvalue(struct gen *g, const uint8_t *v, uint32_t n, int has)
{
	struct want *w = &g->s[g->ns - 1u];

	w->has_value = has;
	w->vlen = has ? n : 0;
	if (has)
		memcpy(w->value, v, n);
}

/* ---- the parts ------------------------------------------------------------------------------------------------------------- */

static uint32_t gen_val(uint8_t *v, uint32_t max)
{
	static const uint8_t alpha[] = "abxyzAB09 _-.,;:!?<>/*#\\'\"$@{}[]()\n\r\t=&%+|~^`";
	uint32_t n = pick(max + 1u), i;

	for (i = 0; i < n; i++)
		v[i] = pick(10) ? alpha[pick(sizeof alpha - 1u)] : (uint8_t)pick(256);
	return n;
}

/* single quoted: \\ and \' */
static void gsingle(struct gen *g)
{
	uint8_t v[24];
	uint32_t n = gen_val(v, 20), i, off;

	if (pick(6) == 0)
		gtext(g, "b", KGENOME_TEXTUAL_CODE);            /* the binary prefix is a name in front of the literal */
	off = g->n;
	gstr(g, "'");
	for (i = 0; i < n; i++) {
		if (v[i] == '\\' || v[i] == '\'')
			gstr(g, "\\");
		gput(g, v + i, 1);
	}
	gstr(g, "'");
	gspan(g, off, g->n - off, KGENOME_TEXTUAL_STRING, 0, 1, 1);
	gvalue(g, v, n, 1);
}

/*
 * One byte as a double quoted string or a heredoc writes it, into `o`; how many bytes. A "$" is always escaped and so is a "{" before one, so the
 * text never interpolates; a line break is a raw byte or "\n" (not in a heredoc: a line is a line there).
 */
static uint32_t dq_byte(uint8_t c, uint8_t next, char *o, int heredoc)
{
	int hexnext = (next >= '0' && next <= '9') || ((next | 32u) >= 'a' && (next | 32u) <= 'f');
	int octnext = next >= '0' && next <= '7';

	switch (c) {
	case '\\': case '$':
		o[0] = '\\';
		o[1] = (char)c;
		return 2;
	case '"':
		if (!heredoc) {
			o[0] = '\\';
			o[1] = '"';
			return 2;
		}
		o[0] = '"';
		return 1;
	case '\n':
		if (heredoc || pick(2)) {
			memcpy(o, "\\n", 2);
			return 2;
		}
		o[0] = '\n';
		return 1;
	case '\r': memcpy(o, "\\r", 2); return 2;
	case '\t': memcpy(o, "\\t", 2); return 2;
	case 0x0b: memcpy(o, "\\v", 2); return 2;
	case 0x1b: memcpy(o, "\\e", 2); return 2;
	case 0x0c: memcpy(o, "\\f", 2); return 2;
	default:
		break;
	}
	if (c >= 0x20 && c < 0x7f && pick(4)) {
		o[0] = (char)c;
		return 1;
	}
	switch (pick(3)) {
	case 0:
		snprintf(o, 8, "\\x%02x", c);
		return 4;
	case 1:
		if (octnext || c > 077u)
			snprintf(o, 8, "\\%03o", c);
		else
			snprintf(o, 8, "\\%o", c);
		return (uint32_t)strlen(o);
	default:
		if (c < 16u && !hexnext)
			snprintf(o, 8, "\\x%x", c);
		else
			snprintf(o, 8, "\\x%02x", c);
		return (uint32_t)strlen(o);
	}
}

static void gdouble(struct gen *g)
{
	uint8_t v[24];
	uint32_t n = gen_val(v, 20), i, off;
	char o[8];

	if (pick(6) == 0)
		gtext(g, "b", KGENOME_TEXTUAL_CODE);
	off = g->n;
	gstr(g, "\"");
	for (i = 0; i < n; i++) {
		uint32_t k = dq_byte(v[i], i + 1u < n ? v[i + 1u] : 0, o, 0);

		gput(g, o, k);
	}
	gstr(g, "\"");
	gspan(g, off, g->n - off, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, 1, 1);
	gvalue(g, v, n, 1);
}

/* a double quoted string (or a backtick one) that interpolates, in each of php's spellings: no value */
static void ginterp(struct gen *g)
{
	static const char *const body[] = {
		"hi $name!", "${name}s", "{$a['x']}", "{$a[\"}\"]}", "$a[0] $a[x] $a[$i]", "$a->b->c", "{$a->b()}", "x{$a}y", "${a['q']}",
		"\\$a $b", "{$a['}' . '}']}", "$$a", "{$a[\"{\"]}", "a\\\\$b", "{$a['\\'']}" };
	const char *b = body[pick(sizeof body / sizeof body[0])];
	uint32_t off = g->n;
	int bt = pick(5) == 0;

	gstr(g, bt ? "`" : "\"");
	gstr(g, b);
	gstr(g, bt ? "`" : "\"");
	gspan(g, off, g->n - off, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_INTERP, 1, 1);
	gvalue(g, NULL, 0, 0);       /* every body above holds a variable: the text is not a value */
}

static const char *glabel(void)
{
	static const char *const l[] = { "EOT", "X", "_x", "Label9", "END_OF_TEXT", "\xc3\xa9", "A" };

	return l[pick(sizeof l / sizeof l[0])];
}

/*
 * heredoc or nowdoc: the label bare, quoted or (nowdoc) in single quotes, a closer that is indented, text on the lines that is never a name first (a line that
 * began with the label's name and a byte that is not a name would close it), and what follows the closer. The value is the lines with the
 * closer's indentation off each, joined by "\n" with none after the last.
 */
static void ghere(struct gen *g)
{
	const char *lab = glabel();
	int now = pick(3) == 0, q = (int)pick(3), after = (int)pick(5);
	static const char *const inds[] = { "", "", "    ", "\t", "  \t" };
	const char *ind = inds[pick(sizeof inds / sizeof inds[0])];
	uint8_t v[200];
	uint32_t nl = 1u + pick(4), l, off = g->n, k, body_at, closer_at, vn = 0;

	gstr(g, "<<<");
	if (pick(4) == 0)
		gstr(g, pick(2) ? " " : "\t");
	gstr(g, now ? "'" : q == 1 ? "\"" : "");
	gstr(g, lab);
	gstr(g, now ? "'" : q == 1 ? "\"" : "");
	gstr(g, pick(3) ? "\n" : "\r\n");
	body_at = g->n;
	for (l = 0; l < nl; l++) {
		uint8_t line[24];
		uint32_t ln = gen_val(line, 16), i;
		int first_done = 0;

		gstr(g, ind);
		for (i = 0; i < ln; i++) {
			uint8_t c = line[i];
			char o[8];
			uint32_t ok;

			if (c == '\n' || c == '\r')
				c = 'q';
			if (!first_done && c != ' ' && c != '\t') {
				first_done = 1;
				if (is_name(c))
					c = '.';                /* the first byte after the blanks is never a name: the label could begin there */
			}
			if (now) {
				gput(g, &c, 1);
			} else {
				ok = dq_byte(c, i + 1u < ln ? line[i + 1u] : 0, o, 1);
				gput(g, o, ok);
			}
			v[vn++] = c;
		}
		if (l + 1u < nl) {
			gstr(g, "\n");
			v[vn++] = '\n';
		}
	}
	gstr(g, pick(3) ? "\n" : "\r\n");
	closer_at = g->n;
	gstr(g, ind);
	gstr(g, lab);
	k = g->n;
	gspan(g, off, k - off, KGENOME_TEXTUAL_STRING, (uint8_t)(KGENOME_TEXTUAL_F_HERE | (now ? 0u : KGENOME_TEXTUAL_F_INTERP)), body_at - off, k - closer_at);
	gvalue(g, v, vn, 1);
	switch (after) {
	case 0: gtext(g, ";", KGENOME_TEXTUAL_CODE); break;
	case 1: gtext(g, ",", KGENOME_TEXTUAL_CODE); break;
	case 2: gtext(g, ")", KGENOME_TEXTUAL_CODE); break;
	case 3: gtext(g, " + 1;", KGENOME_TEXTUAL_CODE); break;
	default: gtext(g, "\n", KGENOME_TEXTUAL_CODE); break;
	}
}

/* comments; one that stops at "?>" is followed by the tag, which leaves php */
static void gcomment(struct gen *g)
{
	static const char *const inner[] = { " a 'quote", " a \"quote", " <<<EOT", " /* not a block", " {$x", " \\", " ' \" ` ", " #[A]", "", " eval(base64_decode('x'))" };
	uint32_t off = g->n, k = pick(8);
	const char *b = inner[pick(sizeof inner / sizeof inner[0])];
	int slash = (int)pick(2);

	switch (k) {
	case 0: case 1: case 2: case 3:         /* "//" or "#" to the end of the line; the line break is code */
		gstr(g, slash ? "//" : "#");
		gstr(g, b);
		gspan(g, off, g->n - off, KGENOME_TEXTUAL_COMMENT, 0, slash ? 2u : 1u, 0);
		gtext(g, pick(3) ? "\n" : pick(2) ? "\r\n" : "\r", KGENOME_TEXTUAL_CODE);
		break;
	case 4: case 5:                         /* a block comment: holds "?>", "//", quotes and line breaks */
		gstr(g, "/*");
		gstr(g, b);
		gstr(g, pick(2) ? " ?> " : "\n * //\n");
		gstr(g, "*/");
		gspan(g, off, g->n - off, KGENOME_TEXTUAL_COMMENT, 0, 2, 2);
		break;
	case 6: {                               /* a line comment that "?>" ends: the tag is real and php is left */
		uint32_t tag;

		gstr(g, slash ? "//" : "#");
		gstr(g, b);
		gspan(g, off, g->n - off, KGENOME_TEXTUAL_COMMENT, 0, slash ? 2u : 1u, 0);
		tag = g->n;
		gstr(g, "?>");
		if (pick(3) == 0)
			gstr(g, "\r\n");
		else if (pick(2))
			gstr(g, "\n");
		gspan(g, tag, g->n - tag, KGENOME_TEXTUAL_TAG, KGENOME_TEXTUAL_F_CLOSE, 0, 0);
		g->in_php = 0;
		break;
	}
	default:                                /* "#[" is an attribute: code, and the strings in it are strings */
		gtext(g, "#[Route(", KGENOME_TEXTUAL_CODE);
		gsingle(g);
		gtext(g, ", name: ", KGENOME_TEXTUAL_CODE);
		gdouble(g);
		gtext(g, ")]\n", KGENOME_TEXTUAL_CODE);
		break;
	}
}

static void gcode(struct gen *g)
{
	static const char *const c[] = { "$a = 1;", "echo $a;", "function f($x) { return $x + 1; }", "if ($a) { $b = []; } else { $b = [1, 2]; }",
					 "$o->m()->n;", "A::B();", "$x = 5 <=> 6;", "$s = 1 << 2;", "$t = 1 <<= 2;", "namespace A\\B;", "$a ?? $b ?: $c;",
					 "<<<", "<<<<", "<< <EOT", "$h = 1 <<<2;", "x__halt_compiler();", "$__halt_compiler = 1;", "?", "- >" };

	gws(g);
	gtext(g, c[pick(sizeof c / sizeof c[0])], KGENOME_TEXTUAL_CODE);
}

static void gmarkup(struct gen *g)
{
	static const char *const m[] = { "<html>\n<body>", "<?xml version=\"1.0\"?>", "<?phpx", "<?php_", "<%= $x %>", "text ? > text", "<?", "< ?php", "<?ph",
					 "a < b ? c : d", "<p>\xc3\xa9</p>", "x\n\n", "?>" };

	/* a "<?" at the end of what is written is a short tag when white space follows it: something that is not white space comes first */
	if (g->n >= 2u && g->t[g->n - 2u] == '<' && g->t[g->n - 1u] == '?')
		gtext(g, "x", KGENOME_TEXTUAL_MARKUP);
	gtext(g, m[pick(sizeof m / sizeof m[0])], KGENOME_TEXTUAL_MARKUP);
}

static void gopen(struct gen *g)
{
	uint32_t off = g->n;

	switch (pick(7)) {
	case 0: gstr(g, "<?php "); break;
	case 1: gstr(g, "<?php\n"); break;
	case 2: gstr(g, "<?php\r\n"); break;
	case 3: gstr(g, "<?PHP\t"); break;
	case 4: gstr(g, "<?="); break;
	case 5: gstr(g, "<? "); break;
	default: gstr(g, "<?php\r"); break;
	}
	gspan(g, off, g->n - off, KGENOME_TEXTUAL_TAG, 0, 0, 0);
	g->in_php = 1;
	if (g->t[g->n - 1u] == '\r')                   /* "\r" and a "\n" after it are one line break, and the tag's: a byte that is not one comes next */
		gtext(g, " ", KGENOME_TEXTUAL_CODE);
}

static void gclose(struct gen *g)
{
	uint32_t off = g->n;

	gstr(g, "?>");
	switch (pick(4)) {
	case 0: gstr(g, "\n"); break;
	case 1: gstr(g, "\r\n"); break;
	case 2: gstr(g, "\r"); break;
	default: break;
	}
	gspan(g, off, g->n - off, KGENOME_TEXTUAL_TAG, KGENOME_TEXTUAL_F_CLOSE, 0, 0);
	g->in_php = 0;
	if (g->t[g->n - 1u] == '\r')                   /* the same: "?>\r" and "\n" are one line break */
		gtext(g, "z", KGENOME_TEXTUAL_MARKUP);
}

/* __halt_compiler: the data after it is markup to the end, whatever it holds */
static void ghalt(struct gen *g)
{
	uint32_t off, k = pick(3);
	uint8_t data[64];
	uint32_t n = gen_val(data, 60);

	gws(g);
	gtext(g, " ", KGENOME_TEXTUAL_CODE);             /* a name in front of it would be the one name */
	off = g->n;
	gstr(g, pick(2) ? "__halt_compiler" : "__HALT_COMPILER");
	gstr(g, pick(2) ? "(" : " ( ");
	gstr(g, ")");
	if (k == 0) {
		gstr(g, ";");
		gspan(g, off, g->n - off, KGENOME_TEXTUAL_CODE, 0, 0, 0);
		gbytes(g, data, n, KGENOME_TEXTUAL_MARKUP);
		g->in_php = 2;
	} else if (k == 1) {
		gstr(g, " ");
		gspan(g, off, g->n - off, KGENOME_TEXTUAL_CODE, 0, 0, 0);
		gclose(g);
		gtext(g, "<?php ?>", KGENOME_TEXTUAL_MARKUP);    /* markup now: the halted file's tail */
		gbytes(g, data, n, KGENOME_TEXTUAL_MARKUP);
		g->in_php = 2;
	} else {                                                 /* not a halt: no ";" or "?>" after it */
		gstr(g, " + 1");
		gspan(g, off, g->n - off, KGENOME_TEXTUAL_CODE, 0, 0, 0);
	}
}

/* one statement-sized part inside php */
static void gpart(struct gen *g)
{
	switch (pick(14)) {
	case 0: case 1: case 2: gsingle(g); gtext(g, ",", KGENOME_TEXTUAL_CODE); break;
	case 3: case 4: gdouble(g); gtext(g, ",", KGENOME_TEXTUAL_CODE); break;
	case 5: ginterp(g); gtext(g, ";", KGENOME_TEXTUAL_CODE); break;
	case 6: case 7: ghere(g); break;
	case 8: case 9: gcomment(g); break;
	case 10: case 11: gcode(g); break;
	case 12: gws(g); break;
	default: gtext(g, "$f = ", KGENOME_TEXTUAL_CODE); gsingle(g); gtext(g, ";", KGENOME_TEXTUAL_CODE); break;
	}
}

/* a whole file: markup and islands, ending where it ends */
static void gfile(struct gen *g, int tagless)
{
	uint32_t parts = 4u + pick(30), i;

	g->ns = 0;
	g->n = 0;
	g->in_php = tagless;
	for (i = 0; i < parts && g->n < MAXT - 1500u && g->ns < MAXS - 40u && g->in_php != 2; i++) {
		if (!g->in_php) {
			if (g->n && pick(2))
				gmarkup(g);
			gopen(g);
			continue;
		}
		if (pick(14) == 0) {
			gclose(g);
			continue;
		}
		if (pick(40) == 0) {
			ghalt(g);
			continue;
		}
		gpart(g);
	}
}

/* ---- the checks ------------------------------------------------------------------------------------------------------------ */

struct got {
	const uint8_t *in;
	struct want    s[MAXS];
	uint32_t       n;
	int            overflow;
};

static int got_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct got *g = u;

	if (g->n >= MAXS) {
		g->overflow = 1;
		return 0;
	}
	g->s[g->n].off = sp->off;
	g->s[g->n].len = sp->len;
	g->s[g->n].open = sp->open_len;
	g->s[g->n].close = sp->close_len;
	g->s[g->n].kind = sp->kind;
	g->s[g->n].flags = sp->flags;
	g->n++;
	return 1;
}

static void show(const uint8_t *t, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n && i < 600u; i++)
		printf(t[i] >= 0x20 && t[i] < 0x7f && t[i] != '\\' ? "%c" : "\\x%02x", t[i]);
	printf("\n");
}

/* the form of `t`, its cap, and its own form, and the values of its literals unchanged; 0 when all holds */
static int form_holds(const uint8_t *t, uint32_t n, uint32_t flags, const char *why)
{
	static uint8_t o1[MAXT * 2u], o2[MAXT * 2u];
	struct kgenome_textual_form_req rq = { .in = t, .n = n, .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = flags, .out = o1, .cap = KGENOME_TEXTUAL_FORM_CAP(n) };
	struct kgenome_textual_form_res r1, r2;
	enum kgenome_textual_status st = kgenome_textual_form(&rq, &r1);

	if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || r1.n_out > KGENOME_TEXTUAL_FORM_CAP(n)) {
		printf("  FAIL %s: form status %d, %u bytes for %u\n  ", why, (int)st, r1.n_out, n);
		show(t, n);
		return 1;
	}
	rq = (struct kgenome_textual_form_req){ .in = o1, .n = r1.n_out, .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = flags, .out = o2,
						.cap = KGENOME_TEXTUAL_FORM_CAP(r1.n_out) };
	st = kgenome_textual_form(&rq, &r2);
	if (st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) {
		printf("  FAIL %s: the form's form has status %d\n  ", why, (int)st);
		show(t, n);
		return 1;
	}
	if (r2.n_out != r1.n_out || memcmp(o1, o2, r1.n_out)) {
		uint32_t d = 0;

		while (d < r1.n_out && d < r2.n_out && o1[d] == o2[d])
			d++;
		printf("  FAIL %s: the form is not its own form (they differ at byte %u of %u and %u)\n  input  ", why, d, r1.n_out, r2.n_out);
		show(t, n);
		printf("  form   ...");
		show(o1 + (d > 60u ? d - 60u : 0u), r1.n_out - (d > 60u ? d - 60u : 0u) > 140u ? 140u : r1.n_out - (d > 60u ? d - 60u : 0u));
		printf("  again  ...");
		show(o2 + (d > 60u ? d - 60u : 0u), r2.n_out - (d > 60u ? d - 60u : 0u) > 140u ? 140u : r2.n_out - (d > 60u ? d - 60u : 0u));
		return 1;
	}
	return 0;
}

/* the values of the string literals of `t`, in order, that have one: appended to v */
struct vals {
	const uint8_t *in;
	uint8_t  v[MAXT];
	uint32_t n;
	uint32_t count, with;
};

static int vals_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct vals *l = u;

	if (sp->kind == KGENOME_TEXTUAL_STRING && !(sp->flags & KGENOME_TEXTUAL_F_OPEN)) {
		uint8_t *o = l->v + l->n;
		struct kgenome_textual_value_req vq = { .lang = KGENOME_TEXTUAL_LANG_PHP, .lit = l->in + sp->off, .len = sp->len, .open_len = sp->open_len,
							.close_len = sp->close_len, .flags = sp->flags, .out = o, .cap = sp->len };
		struct kgenome_textual_value_res vr;

		l->count++;
		if (l->n + sp->len < MAXT && kgenome_textual_value(&vq, &vr) == KGENOME_TEXTUAL_OK) {
			/* a length prefix: two literals "a","b" are not one "ab" */
			memmove(o + 4, o, vr.n_out);
			memcpy(o, &vr.n_out, 4);
			l->n += 4u + vr.n_out;
			l->with++;
		}
	}
	return 1;
}

static void values_of(const uint8_t *t, uint32_t n, uint32_t flags, struct vals *l)
{
	struct kgenome_textual_lex_req q = { .in = t, .n = n, .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = flags, .sink = vals_sink, .user = l };
	struct kgenome_textual_lex_res r;

	l->n = l->count = l->with = 0;
	l->in = t;
	(void)kgenome_textual_lex(&q, &r);
}

/*
 * THE TEXTS THIS FOUND, each the smallest that shows the defect, with the form it must have now. Every one was a form that was not its own form
 * (or one that changed what a literal or the data after a halt marker held), found by the generated, cut or mutated texts below; they are kept
 * as examples so that none of them depends on a seed, and the comment says what the form would have written.
 */
static void repros(void)
{
	static const struct { const char *in, *want; } r[] = {
		/* a line break written in front of "?>" after "<<<HTML" made a heredoc of the markup that follows */
		{ "<?php\n$html = <<<HTML?>\n<div>\n</div>\nHTML;\n", "<?php\n$html=<<<HTML?>\n<div>\n</div>\nHTML;\n" },
		/* a blank, a comment between "<<<LABEL" and the line break: closed up, it was a heredoc to the end of the text */
		{ "<?php $n = <<<'EOT'\v\nraw\nEOT;\n", "<?php $n=<<<'EOT' \nraw\nEOT;" },
		{ "<?php $n = <<<EOT /* c */\nraw\nEOT;", "<?php $n=<<<EOT \nraw\nEOT;" },
		{ "<?php class A extends B<<<ceptio//n\n{\n}\n", "<?php class A extends B<<<ceptio{\n}" },
		/* an echo inside the argument of another was written a call when the outer one was typed with its bracket, and not when the form opened it */
		{ "<?php echo print 'x'; echo 'y';", "<?php echo(print'x');echo('y');" },
		{ "<?php echo );\necho 'a';", "<?php echo();\necho('a');" },
		/* the two words are what an echo's bracket is looked for after, and both are read: the filter that asks for them ends in "o" or "t" */
		{ "<?php print 'x'; PRINT 'y'; Echo 'z';", "<?php print('x');PRINT('y');Echo('z');" },
		/* the bracket closed inside a halt marker (`__halt_compiler());`), or in front of the data after it */
		{ "<?php echo 'a' __halt_compiler();\ndata ?>", "<?php echo('a'__halt_compiler();\ndata ?>" },
		{ "<?php echo 'a' __halt_compiler() ?>data", "<?php echo('a'__halt_compiler()\n?>data" },
		/* an island that held nothing went, and the markup in front of it became a tag */
		{ "<?php<?php", "<?php<?php" },
		{ "<?ph<?php ?>p x", "<?ph<?php ?>p x" },
		/* "\x4" and then "\101" was written "\x4A": the byte 0x4a, where the string held 0x04 and 0x41 */
		{ "<?php $a = \"\\x4\\101\";", "<?php $a=\"\\x4\\101\";" },
		/* in a heredoc an escape that begins a line was written as its byte: "\x41BC" became the closing label ABC, and a blank became indentation */
		{ "<?php $a = <<<ABC\n\\x41BC\nABC;\n", "<?php $a= <<<ABC\n\\x41BC\nABC;" },
		{ "<?php $a = <<<EOT\n \\x20abc\n EOT;\n", "<?php $a= <<<EOT\n \\x20abc\n EOT;" },
		/* "$ __halt_compiler();" is a variable's name to the form, which closes the blank up, and was a halt to the lexer */
		{ "<?php $  __halt_compiler(); ) ;", "<?php $__halt_compiler(););" },
		{ "<?php $ /* c */ // d\n __halt_compiler(); ) ;", "<?php $\n__halt_compiler(););" },
		/* an echo's bracket was written in front of the data after a halt marker when a bracket of the program was still open at its ";" */
		{ "<?php echo f(__halt_compiler();\ndata", "<?php echo(f(__halt_compiler();\ndata" },
		/* inside `${...}` and `{$...}` the text is the program's, and an escape in it is none: "\x27" written as the quote it spells closed what the lexer
		 * reads there (the string `"${\x27'}"` was one literal, then two), and the form of the form was another text */
		{ "<?php \"${\\x27'}\"\"\"", "<?php \"${\\x27'}\"\"\"" },
		{ "<?php\n\"{$\"\"'\\x27}\" ", "<?php\n\"{$\"\"'\\x27}\" " },
		{ "<?php $a = \"x{$b['\\x27']}y \\x41 ${c}\";", "<?php $a=\"x{$b['\\x27']}y A ${c}\";" },
		/* "$" and a form feed and the name: the form closes them up (a form feed is white space to it), so the halt marker is a variable's name */
		{ "<?php $\f__halt_compiler()?>x<?php echo 1; ?>", "<?php $__halt_compiler()\n?>x<?php echo(1);\n?>" },
		/* "\x" with no digit and then "\x32\x61" was written "\x2a": a star where the string held a backslash, an x, a 2 and an a */
		{ "<?php $a = \"\\x\\x32\\x61\";", "<?php $a=\"\\x\\x32a\";" },
		/* "\1" and then "\62" was written "\12": a line feed where the string held 0x01 and the digit 2 */
		{ "<?php $a = \"\\1\\62\";", "<?php $a=\"\\1\\62\";" },
	};
	uint32_t i;

	for (i = 0; i < sizeof r / sizeof r[0]; i++) {
		static uint8_t in[256], o[1024];
		uint32_t n = 0, k;
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;

		for (k = 0; r[i].in[k]; k++)
			in[n++] = (uint8_t)r[i].in[k];
		rq = (struct kgenome_textual_form_req){ .in = in, .n = n, .lang = KGENOME_TEXTUAL_LANG_PHP, .out = o, .cap = sizeof o };
		(void)kgenome_textual_form(&rq, &rs);
		if (rs.n_out != strlen(r[i].want) || memcmp(o, r[i].want, rs.n_out)) {
			printf("  FAIL repro %u: the form is\n   ", i);
			show(o, rs.n_out);
			printf("   wanted\n   %s\n", r[i].want);
			fails++;
		}
		fails += form_holds(in, n, 0, "repro");
	}
}

/* the value of a heredoc whose closer is indented: the indentation is off every line (php 7.3), in a nowdoc too, before any escape is read */
static void indent_values(void)
{
	static const struct { const char *lit; uint32_t open, close; uint8_t flags; const char *want; } v[] = {
		{ "<<<EOT\n    one\n      two\n    EOT", 7, 7, KGENOME_TEXTUAL_F_HERE | KGENOME_TEXTUAL_F_INTERP, "one\n  two" },
		{ "<<<'EOT'\n\tone\n\t\ttwo\n\tEOT", 9, 4, KGENOME_TEXTUAL_F_HERE, "one\n\ttwo" },
		{ "<<<EOT\r\n  a\\x41\r\n   b\r\n  EOT", 8, 5, KGENOME_TEXTUAL_F_HERE | KGENOME_TEXTUAL_F_INTERP, "aA\r\n b" },
		{ "<<<EOT\n  \\x20a\n  EOT", 7, 5, KGENOME_TEXTUAL_F_HERE | KGENOME_TEXTUAL_F_INTERP, " a" },
		{ "<<<EOT\r  a\r  b\r  EOT", 7, 5, KGENOME_TEXTUAL_F_HERE | KGENOME_TEXTUAL_F_INTERP, "a\rb" },         /* a lone CR is a line break */
		{ "<<<EOT\none\nEOT", 7, 3, KGENOME_TEXTUAL_F_HERE | KGENOME_TEXTUAL_F_INTERP, "one" },
		{ "<<<EOT\n  a\n b\n  EOT", 7, 5, KGENOME_TEXTUAL_F_HERE | KGENOME_TEXTUAL_F_INTERP, "a\nb" },       /* a line with less keeps what it has */
	};
	uint32_t i;

	for (i = 0; i < sizeof v / sizeof v[0]; i++) {
		uint8_t o[64];
		uint32_t len = (uint32_t)strlen(v[i].lit);
		struct kgenome_textual_value_req vq = { .lang = KGENOME_TEXTUAL_LANG_PHP, .lit = (const uint8_t *)v[i].lit, .len = len, .open_len = v[i].open,
							.close_len = v[i].close, .flags = v[i].flags, .out = o, .cap = len };
		struct kgenome_textual_value_res vr;

		if (kgenome_textual_value(&vq, &vr) != KGENOME_TEXTUAL_OK || vr.n_out != strlen(v[i].want) || memcmp(o, v[i].want, vr.n_out)) {
			printf("  FAIL the value of heredoc %u is not the one php gives\n", i);
			fails++;
		}
	}
}

/* a text, lexed, partitioned; 0 when it does */
static int partition_holds(const uint8_t *t, uint32_t n, uint32_t flags, struct got *g)
{
	struct kgenome_textual_lex_req q = { .in = t, .n = n, .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = flags, .sink = got_sink, .user = g };
	struct kgenome_textual_lex_res r;
	uint32_t i, at = 0;

	g->n = 0;
	g->overflow = 0;
	(void)kgenome_textual_lex(&q, &r);
	if (g->overflow)
		return 0;
	for (i = 0; i < g->n; i++) {
		if (g->s[i].off != at || !g->s[i].len || (uint64_t)g->s[i].open + g->s[i].close > g->s[i].len)
			return 1;
		at += g->s[i].len;
	}
	return at != n;
}

static int built_case(uint32_t it, int tagless)
{
	static struct gen g;
	static struct got got;
	static struct vals va, vb;
	static uint8_t fo[MAXT * 2u];
	uint32_t i, bad = 0;
	uint32_t flags = tagless ? KGENOME_TEXTUAL_FRAGMENT : 0u;

	gfile(&g, tagless);
	if (partition_holds(g.t, g.n, flags, &got)) {
		printf("  FAIL built %u: the spans do not partition the text\n  ", it);
		show(g.t, g.n);
		return 1;
	}
	if (got.overflow)
		return 0;
	/* the spans as written down */
	if (got.n != g.ns)
		bad = 1;
	for (i = 0; !bad && i < g.ns; i++)
		if (got.s[i].off != g.s[i].off || got.s[i].len != g.s[i].len || got.s[i].kind != g.s[i].kind || got.s[i].flags != g.s[i].flags ||
		    got.s[i].open != g.s[i].open || got.s[i].close != g.s[i].close)
			bad = 1;
	if (bad) {
		printf("  FAIL built %u: the spans are not the ones the text was written as (%u delivered, %u written)\n", it, got.n, g.ns);
		for (i = 0; i < g.ns && i < got.n; i++)
			if (got.s[i].off != g.s[i].off || got.s[i].len != g.s[i].len || got.s[i].kind != g.s[i].kind || got.s[i].flags != g.s[i].flags ||
			    got.s[i].open != g.s[i].open || got.s[i].close != g.s[i].close) {
				printf("   span %u: delivered kind %u off %u len %u flags %u open %u close %u\n"
				       "           written   kind %u off %u len %u flags %u open %u close %u\n", i,
				       got.s[i].kind, got.s[i].off, got.s[i].len, got.s[i].flags, got.s[i].open, got.s[i].close,
				       g.s[i].kind, g.s[i].off, g.s[i].len, g.s[i].flags, g.s[i].open, g.s[i].close);
				break;
			}
		printf("   text  ");
		show(g.t, g.n);
		return 1;
	}
	/* the values */
	for (i = 0; i < g.ns; i++) {
		if (g.s[i].kind != KGENOME_TEXTUAL_STRING)
			continue;
		{
			uint8_t o[MAXT / 8u];
			struct kgenome_textual_value_req vq = { .lang = KGENOME_TEXTUAL_LANG_PHP, .lit = g.t + g.s[i].off, .len = g.s[i].len, .open_len = g.s[i].open,
								.close_len = g.s[i].close, .flags = g.s[i].flags, .out = o, .cap = g.s[i].len };
			struct kgenome_textual_value_res vr;
			enum kgenome_textual_status st = kgenome_textual_value(&vq, &vr);

			if (g.s[i].has_value ? (st != KGENOME_TEXTUAL_OK || vr.n_out != g.s[i].vlen || memcmp(o, g.s[i].value, vr.n_out)) : st != KGENOME_TEXTUAL_NO_VALUE) {
				printf("  FAIL built %u: the value of span %u (status %d, %u bytes, wanted %s%u)\n   literal ", it, i, (int)st, vr.n_out,
				       g.s[i].has_value ? "" : "none, ", g.s[i].vlen);
				show(g.t + g.s[i].off, g.s[i].len);
				bad = 1;
				break;
			}
		}
	}
	if (bad)
		return 1;
	bad = (uint32_t)form_holds(g.t, g.n, flags, "built");
	if (!bad) {
		/* every literal that had a value has it still, in order, after the form (no join is written in these texts) */
		struct kgenome_textual_form_req rq = { .in = g.t, .n = g.n, .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = flags, .out = fo, .cap = KGENOME_TEXTUAL_FORM_CAP(g.n) };
		struct kgenome_textual_form_res fr;

		(void)kgenome_textual_form(&rq, &fr);
		values_of(g.t, g.n, flags, &va);
		values_of(fo, fr.n_out, flags, &vb);
		if (va.n != vb.n || memcmp(va.v, vb.v, va.n) || va.count != vb.count) {
			printf("  FAIL built %u: the form changed what a literal holds (%u literals, %u with a value; after: %u, %u)\n  input ", it, va.count, va.with,
			       vb.count, vb.with);
			show(g.t, g.n);
			printf("  form  ");
			show(fo, fr.n_out);
			bad = 1;
		}
	}
	return (int)bad;
}

/* every prefix of a text: partition, cap, own form */
static int cut_case(const uint8_t *t, uint32_t n, uint32_t step)
{
	static struct got got;
	uint32_t k, bad = 0;

	for (k = 0; k <= n && !bad; k += step) {
		if (partition_holds(t, k, 0, &got)) {
			printf("  FAIL a prefix of %u bytes does not partition\n  ", k);
			show(t, k);
			bad = 1;
		} else if (form_holds(t, k, 0, "prefix") || form_holds(t, k, KGENOME_TEXTUAL_FRAGMENT, "prefix (fragment)")) {
			bad = 1;
		}
	}
	return (int)bad;
}

/* ---- seeds and mutation ---------------------------------------------------------------------------------------------------- */

static const char *const seeds[] = {
	"<?php\n/**\n * Plugin Name: Example\n */\n\nnamespace Example;\n\nuse Foo\\Bar;\n\nfinal class Box extends Base implements \\Countable {\n"
	"\tprivate array $items = ['a' => 1, \"b\" => 2];\n\n\t#[Override]\n\tpublic function count(): int {\n\t\treturn \\count( $this->items ); // how many\n\t}\n\n"
	"\tpublic function render( string $name ): string {\n\t\t$html = <<<HTML\n\t\t\t<div class=\"box-{$name}\">\n\t\t\t\t{$this->items['a']} and $name\n\t\t\t</div>\n\t\t\tHTML;\n"
	"\t\treturn str_replace( '{name}', esc_html( $name ), $html ) . \"\\n\";\n\t}\n}\n",
	"<!DOCTYPE html>\n<html>\n<head><title><?php echo esc_html( $title ); ?></title></head>\n<body class=\"<?= $cls ?>\">\n<?php if ( $posts ) : ?>\n"
	"\t<?php foreach ( $posts as $p ) : ?>\n\t\t<h2><?php echo $p->post_title; ?></h2>\n\t<?php endforeach; ?>\n<?php else : ?>\n\t<p>None</p>\n<?php endif; ?>\n</body>\n</html>\n",
	"<?php\n$x = base64_decode( 'cGhwaW5mbygpOw==' ); // payload\n$f = 'ev' . 'al'; /* ?> */ $f( $x );\n$n = <<<'EOT'\nraw $text \\n {$not}\nEOT;\n"
	"echo `ls -la`; echo \"a{$b['c']}d ${e} $f[0] $g->h\";\n__halt_compiler();\n<?php binary \x01\x02 ?>\n",
	"<?php\nfunction t() {\n  $s = 'it\\'s';\n  $d = \"say \\\"hi\\\" \\x41\\101\\u{1F600} \\$no\";\n  $b = b'bytes' . b\"more\";\n  return [$s, $d, $b, 1 <=> 2, 3 << 2, 4 ?? 5];\n}\n"
	"# hash comment\n#[Attr('x', y: \"z\")]\nclass K {}\n?>\ntail\n",
};

static const char *const toks[] = {
	"<?php ", "<?php\n", "<?=", "<? ", "?>", "?>\n", "?>\r\n", "<<<EOT\n", "<<<'EOT'\n", "<<<\"EOT\"\n", "\nEOT;\n", "\n  EOT\n", "EOT", "'", "\"", "`", "\\",
	"\\\\", "\\'", "\\\"", "/*", "*/", "//", "#", "#[", "{$", "${", "}", "$", "\\x4", "\\u{", "\\u{1F600}", "\\0", "\\400", "__halt_compiler();", "__halt_compiler()?>",
	"\r", "\r\n", "\n", "\v", "\f", " ", "\t", "b'", "b\"", "<<<", "?", ">", "<", "<?php", "<?", "(", ")", "[", "]", "{", ";", ",", ".", "'\\'", "\"\\\"",
};

#define NTOK ((uint32_t)(sizeof toks / sizeof toks[0]))

static uint32_t mutate(uint8_t *t, uint32_t n, uint32_t max)
{
	uint32_t m = 1u + pick(6), k;

	for (k = 0; k < m; k++) {
		uint32_t at = n ? pick(n + 1u) : 0, len, i;

		switch (pick(8)) {
		case 0:         /* flip a byte */
			if (n)
				t[pick(n)] = (uint8_t)pick(256);
			break;
		case 1:         /* delete a run */
			if (n) {
				at = pick(n);
				len = 1u + pick(8);
				if (at + len > n)
					len = n - at;
				memmove(t + at, t + at + len, n - at - len);
				n -= len;
			}
			break;
		case 2:         /* double a run */
			if (n && n + 40u < max) {
				at = pick(n);
				len = 1u + pick(32);
				if (at + len > n)
					len = n - at;
				memmove(t + at + len, t + at, n - at);
				n += len;
			}
			break;
		case 3: case 4: case 5: {       /* a token php cares about */
			const char *tk = toks[pick(NTOK)];
			uint32_t tl = (uint32_t)strlen(tk);

			if (pick(16) == 0) {            /* a NUL, which a C string cannot hold */
				tk = "";
				tl = 1;
			}
			if (n + tl < max) {
				memmove(t + at + tl, t + at, n - at);
				for (i = 0; i < tl; i++)
					t[at + i] = (uint8_t)tk[i];
				n += tl;
			}
			break;
		}
		case 6:         /* a byte replaced by one that matters */
			if (n)
				t[pick(n)] = (uint8_t)"'\"`\\$<>?#/{}*\n\r"[pick(16)];
			break;
		default:        /* truncate */
			if (n > 4)
				n = 1u + pick(n - 1u);
			break;
		}
	}
	return n;
}

#ifndef _WIN32
static volatile sig_atomic_t in_case;
static void on_alarm(int sig)
{
	(void)sig;
	if (in_case) {
		static const char m[] = "  FAIL a case ran past ten seconds\n";

		(void)!write(1, m, sizeof m - 1u);
		_exit(3);
	}
}
#endif

static uint8_t seedbuf[1u << 20];

static int run_mutations(const uint8_t *seed, uint32_t sn, uint32_t rounds)
{
	static uint8_t t[MAXT];
	static struct got got;
	uint32_t r, bad = 0, n;

	if (sn > MAXT / 2u)
		sn = MAXT / 2u;
	for (r = 0; r < rounds && !bad; r++) {
		memcpy(t, seed, sn);
		n = mutate(t, sn, MAXT - 64u);
#ifndef _WIN32
		in_case = 1;
		alarm(10);
#endif
		if (partition_holds(t, n, 0, &got)) {
			printf("  FAIL a mutated text does not partition\n  ");
			show(t, n);
			bad = 1;
		} else if (form_holds(t, n, 0, "mutated") || form_holds(t, n, KGENOME_TEXTUAL_FRAGMENT, "mutated (fragment)")) {
			bad = 1;
		}
#ifndef _WIN32
		alarm(0);
		in_case = 0;
#endif
	}
	return (int)bad;
}

/* crossing two texts: the head of one and the tail of the other */
static int run_cross(const uint8_t *a, uint32_t an, const uint8_t *b, uint32_t bn, uint32_t rounds)
{
	static uint8_t t[MAXT];
	uint32_t r, bad = 0;

	for (r = 0; r < rounds && !bad; r++) {
		uint32_t ca = an ? pick(an + 1u) : 0, cb = bn ? pick(bn + 1u) : 0, n;

		if (ca > MAXT / 2u)
			ca = MAXT / 2u;
		if (bn - cb > MAXT / 2u)
			cb = bn - MAXT / 2u;
		memcpy(t, a, ca);
		memcpy(t + ca, b + cb, bn - cb);
		n = ca + (bn - cb);
		bad = (uint32_t)(form_holds(t, n, 0, "crossed") || form_holds(t, n, KGENOME_TEXTUAL_FRAGMENT, "crossed (fragment)"));
	}
	return (int)bad;
}

int main(int argc, char **argv)
{
	uint32_t i, it, bad = 0, nseeds = 0, nfiles = 0;
	static uint8_t *files[64];
	static uint32_t flen[64];
	uint32_t built_iter = 40000u, mut_rounds = 2000u;

#ifndef _WIN32
	signal(SIGALRM, on_alarm);
#endif
	/* "--seed N" and "--rounds N" before the files: another walk of the same attacks, and more of them (the defaults are what the build runs) */
	while (argc > 2 && (!strcmp(argv[1], "--seed") || !strcmp(argv[1], "--rounds") || !strcmp(argv[1], "--built"))) {
		unsigned long v = strtoul(argv[2], NULL, 10);

		if (!strcmp(argv[1], "--seed"))
			rs_ = 0x9e3779b97f4a7c15u ^ (v * 0x2545f4914f6cdd1du) ? 0x9e3779b97f4a7c15u ^ (v * 0x2545f4914f6cdd1du) : 1u;
		else if (!strcmp(argv[1], "--rounds"))
			mut_rounds = (uint32_t)v;
		else
			built_iter = (uint32_t)v;
		argc -= 2;
		argv += 2;
	}
	repros();
	indent_values();
	for (it = 0; it < built_iter && bad < 3u; it++)
		bad += (uint32_t)built_case(it, (int)(it & 1u));
	for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++) {
		uint32_t n = (uint32_t)strlen(seeds[i]);

		memcpy(seedbuf, seeds[i], n);
		/* the seed with its NUL: the text is C source, so a NUL is spelt \0 in it and was written as one only in the halt data */
		bad += (uint32_t)cut_case(seedbuf, n, 1u);
		bad += (uint32_t)run_mutations(seedbuf, n, mut_rounds * 10u);
		nseeds++;
	}
	for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
		bad += (uint32_t)run_cross((const uint8_t *)seeds[i], (uint32_t)strlen(seeds[i]), (const uint8_t *)seeds[(i + 1u) % (sizeof seeds / sizeof seeds[0])],
					   (uint32_t)strlen(seeds[(i + 1u) % (sizeof seeds / sizeof seeds[0])]), 200u);
	/* a corpus named on the command line: each file is cut at a stride, mutated, and crossed with the one before it */
	for (i = 1; i < (uint32_t)argc && i < 64u; i++) {
		FILE *f = fopen(argv[i], "rb");
		size_t n;

		if (!f)
			continue;
		n = fread(seedbuf, 1, sizeof seedbuf, f);
		fclose(f);
		if (!n)
			continue;
		files[nfiles] = malloc(n);
		memcpy(files[nfiles], seedbuf, n);
		flen[nfiles] = (uint32_t)n;
		bad += (uint32_t)cut_case(seedbuf, n > MAXT / 2u ? MAXT / 2u : (uint32_t)n, 1u + (uint32_t)n / 400u);
		bad += (uint32_t)run_mutations(seedbuf, (uint32_t)n, mut_rounds);
		if (nfiles)
			bad += (uint32_t)run_cross(files[nfiles - 1u], flen[nfiles - 1u], files[nfiles], flen[nfiles], 20u);
		nfiles++;
		if (bad >= 3u)
			break;
	}
	for (i = 0; i < nfiles; i++)
		free(files[i]);
	fails += (int)bad;
	if (fails) {
		printf("textual_php_hostile: %d failed\n", fails);
		return 1;
	}
	printf("textual_php_hostile: built texts with their spans and values, every prefix, mutated and crossed texts (%u seeds, %u files) - ok\n", nseeds, nfiles);
	return 0;
}
