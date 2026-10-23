#ifndef KGENOME_TEST_TEXTUAL_PSH_GEN_H
#define KGENOME_TEST_TEXTUAL_PSH_GEN_H

/*
 * textual_psh_gen.h - a generator of PowerShell programs whose structure is known as they are written.
 *
 * Every piece is appended together with what it is - code, a string with its delimiters and flags, a comment - so
 * the expected span list exists before the lexer is asked. The programs are valid by construction from the rules of
 * psh_lex.c, NOT by an interpreter's say-so (there is no pwsh here): what the generator checks is that the lexer
 * agrees with those rules in every combination of neighbours, line-ending style and nesting - not that the rules
 * are the language's.
 *
 * What it lays out: code atoms (words, variables, "${name with 'quotes' and #}", numbers with suffixes, splats, type
 * literals, backtick escapes, a "#" inside a word, a path with "C#" in it), separated by blanks, line breaks of one
 * of three styles, a backtick continuation and ";"; '...' strings with doubled quotes and typographic ones; "..."
 * strings with every escape, "$name", "${...}", and $( ) sub-expressions that hold strings, comments and further
 * strings to depth 3; here-strings of both kinds with lines that look like a closer and are not (indented, mid-line,
 * of the other kind); "#" comments and "<# #>" comments with every quote in them. The text may end in something not
 * closed. For a literal whose value is known without running the program (no "$" interpolation) the generator also
 * knows the value.
 */

#include "textual_check.h"

#define G_MAX 65536u
#define G_SPANS 4096u

struct gspan {
	uint32_t off, len, open, close;
	uint8_t  kind, flags;
	int      has_val;
	uint32_t val_off, val_len;      /* in gen.vals */
};

struct gen {
	uint32_t rng;
	const char *eol;                /* the line break of this program */
	int      full;                  /* something did not fit: throw the program away */
	uint32_t n, ns, nv;
	char     buf[G_MAX];
	char     vals[G_MAX];
	struct gspan sp[G_SPANS];
};

/* The piece being built - one literal at a time, so one static serves. */
struct gpiece {
	uint32_t n, vn;
	int      has_val, over;
	char     t[G_MAX];
	char     v[G_MAX];
};

static struct gpiece g_pc;

static uint32_t g_rand(struct gen *g, uint32_t m)
{
	g->rng = g->rng * 1103515245u + 12345u;
	return (g->rng >> 16) % m;
}

static struct gpiece *p_new(void)
{
	memset(&g_pc, 0, offsetof(struct gpiece, t));
	g_pc.has_val = 1;
	return &g_pc;
}

/* Text and its value (NULL: none for this piece, or the same bytes when `val` is the text). */
static void p_put(struct gpiece *p, const char *s, const char *val)
{
	size_t l = strlen(s), lv = val ? strlen(val) : 0;

	if (p->n + l >= sizeof p->t || p->vn + lv >= sizeof p->v) {
		p->over = 1;
		return;
	}
	memcpy(p->t + p->n, s, l);
	p->n += (uint32_t)l;
	if (val) {
		memcpy(p->v + p->vn, val, lv);
		p->vn += (uint32_t)lv;
	}
}

/* Text that makes the value unknown (an interpolation). */
static void p_novalue(struct gpiece *p, const char *s)
{
	p_put(p, s, NULL);
	p->has_val = 0;
}

static void g_span(struct gen *g, uint8_t kind, uint8_t flags, uint32_t open, uint32_t close, const char *t, uint32_t n,
		   const struct gpiece *pc)
{
	struct gspan *s;

	if (g->full || g->n + n >= G_MAX || g->ns + 2u >= G_SPANS || (pc && pc->over)) {
		g->full = 1;
		return;
	}
	if (kind == KGENOME_TEXTUAL_CODE && !flags && g->ns && g->sp[g->ns - 1u].kind == KGENOME_TEXTUAL_CODE &&
	    !g->sp[g->ns - 1u].flags) {
		g->sp[g->ns - 1u].len += n;
	} else {
		s = &g->sp[g->ns++];
		memset(s, 0, sizeof *s);
		s->off = g->n;
		s->len = n;
		s->open = open;
		s->close = close;
		s->kind = kind;
		s->flags = flags;
		if (pc && pc->has_val && kind == KGENOME_TEXTUAL_STRING && !(flags & KGENOME_TEXTUAL_F_OPEN) &&
		    g->nv + pc->vn < G_MAX) {
			s->has_val = 1;
			s->val_off = g->nv;
			s->val_len = pc->vn;
			memcpy(g->vals + g->nv, pc->v, pc->vn);
			g->nv += pc->vn;
		}
	}
	memcpy(g->buf + g->n, t, n);
	g->n += n;
}

static void g_code(struct gen *g, const char *s)
{
	g_span(g, KGENOME_TEXTUAL_CODE, 0, 0, 0, s, (uint32_t)strlen(s), NULL);
}

/* ---- strings ---- */

static const char *const g_sq_q[] = { "'", "\xe2\x80\x98", "\xe2\x80\x99", "\xe2\x80\x9a", "\xe2\x80\x9b" };
static const char *const g_dq_q[] = { "\"", "\xe2\x80\x9c", "\xe2\x80\x9d", "\xe2\x80\x9e" };

/* Bytes that mean nothing to the lexer inside a string or a comment (and are not an escape's). */
static const char *const g_plain[] = { "a", "Z", "x1", " ", "  ", "-", "_", "=", ".", ",", ";", "{", "}", "[", "]", "(", ")",
				       "%", "!", "~", "#", "\\", "@", "<", ">" };

static const char *g_pick(struct gen *g, const char *const *set, uint32_t n)
{
	return set[g_rand(g, n)];
}

static void g_plain_piece(struct gen *g, struct gpiece *p)
{
	const char *s = g_plain[g_rand(g, sizeof g_plain / sizeof g_plain[0])];

	p_put(p, s, s);
}

static void g_sq(struct gen *g, uint32_t pieces, uint8_t extra)
{
	struct gpiece *p = p_new();
	const char *o = g_pick(g, g_sq_q, 5), *c = g_pick(g, g_sq_q, 5);
	uint32_t k, cl = (uint32_t)strlen(c);
	int open = (extra & KGENOME_TEXTUAL_F_OPEN) != 0;

	p_put(p, o, NULL);
	for (k = 0; k < pieces; k++) {
		uint32_t c0 = g_rand(g, 9);

		if (c0 == 0) {
			/* a doubled quote: any two quote characters of the class; the value is a plain quote only when both are */
			const char *a = g_rand(g, 3) ? "'" : g_pick(g, g_sq_q, 5), *b = g_rand(g, 3) ? "'" : g_pick(g, g_sq_q, 5);

			p_put(p, a, NULL);
			p_put(p, b, NULL);
			if (strcmp(a, "'") || strcmp(b, "'"))
				p->has_val = 0;
			else
				p_put(p, "", "'");
		} else if (c0 == 1) {
			p_put(p, "\"", "\"");
		} else if (c0 == 2) {
			p_put(p, "`", "`");
		} else if (c0 == 3) {
			p_put(p, "$(", "$(");
		} else if (c0 == 4) {
			p_put(p, g->eol, g->eol);
		} else if (c0 == 5) {
			p_put(p, "<#", "<#");
		} else {
			g_plain_piece(g, p);
		}
	}
	if (!open)
		p_put(p, c, NULL);
	g_span(g, KGENOME_TEXTUAL_STRING, extra, (uint32_t)strlen(o), open ? 0u : cl, p->t, p->n, p);
}

/* Code inside "$( )": atoms, strings, comments and nested strings, always complete and ending so that ")" is not in a comment. */
static void g_code_in_sub(struct gen *g, struct gpiece *p, uint32_t depth);

static void dq_content(struct gen *g, struct gpiece *p, uint32_t pieces, uint32_t depth)
{
	uint32_t k;

	for (k = 0; k < pieces; k++) {
		uint32_t c = g_rand(g, 18);

		if (c == 0) {
			p_put(p, "`\"", "\"");
		} else if (c == 1) {
			p_put(p, "`n", "\n");
		} else if (c == 2) {
			p_put(p, "``", "`");
		} else if (c == 3) {
			p_put(p, "`$", "$");
		} else if (c == 4) {
			p_put(p, "\"\"", "\"");
		} else if (c == 5) {
			p_put(p, "'", "'");
		} else if (c == 6) {
			p_novalue(p, "$name");
		} else if (c == 7) {
			p_novalue(p, "${a b'\" #}");
		} else if (c == 8) {
			p_novalue(p, "$$");
		} else if (c == 9 && depth < 3u) {
			p_novalue(p, "$(");
			g_code_in_sub(g, p, depth + 1u);
			p_novalue(p, ")");
		} else if (c == 10) {
			p_put(p, "`t`x`'", "\tx'");
		} else if (c == 11) {
			p_put(p, "@(", "@(");
		} else if (c == 12) {
			p_put(p, "$ ", "$ ");
		} else {
			g_plain_piece(g, p);
		}
	}
}

static void g_dq(struct gen *g, uint32_t pieces, uint8_t extra)
{
	struct gpiece *p = p_new();
	const char *o = g_pick(g, g_dq_q, 4), *c = g_pick(g, g_dq_q, 4);
	int open = (extra & KGENOME_TEXTUAL_F_OPEN) != 0;

	p_put(p, o, NULL);
	dq_content(g, p, pieces, 0);
	if (!open)
		p_put(p, c, NULL);
	g_span(g, KGENOME_TEXTUAL_STRING, (uint8_t)(KGENOME_TEXTUAL_F_INTERP | extra), (uint32_t)strlen(o),
	       open ? 0u : (uint32_t)strlen(c), p->t, p->n, p);
}

static void g_code_in_sub(struct gen *g, struct gpiece *p, uint32_t depth)
{
	uint32_t k, items = 1u + g_rand(g, 4);

	for (k = 0; k < items; k++) {
		uint32_t c = g_rand(g, 9);

		p_novalue(p, " ");
		if (c == 0) {
			p_novalue(p, "1 + 2");
		} else if (c == 1) {
			p_novalue(p, "'s)(t'");
		} else if (c == 2) {
			p_novalue(p, "\"d`\"e)\"");
		} else if (c == 3) {
			p_novalue(p, "# c ) ' \" ");
			p_novalue(p, g->eol);
		} else if (c == 4) {
			p_novalue(p, "<# c ) ' \" #>");
		} else if (c == 5) {
			p_novalue(p, "(x)");
		} else if (c == 6) {
			p_novalue(p, "${v)'}");
		} else if (c == 7 && depth < 3u) {
			p_novalue(p, "\"i$(");
			g_code_in_sub(g, p, depth + 1u);
			p_novalue(p, ")j\"");
		} else {
			p_novalue(p, "@'");
			p_novalue(p, g->eol);
			p_novalue(p, "h ) \"@");
			p_novalue(p, g->eol);
			p_novalue(p, "'@");
		}
	}
	p_novalue(p, " ");
}

/* ---- here-strings ---- */

static void g_here(struct gen *g, int dbl, uint8_t extra)
{
	static const char *const sq_close[] = { "'@", "\xe2\x80\x98@", "\xe2\x80\x99@", "\xe2\x80\x9a@", "\xe2\x80\x9b@" };
	static const char *const dq_close[] = { "\"@", "\xe2\x80\x9c@", "\xe2\x80\x9d@", "\xe2\x80\x9e@" };
	struct gpiece *p = p_new();
	const char *o = dbl ? g_pick(g, g_dq_q, 4) : g_pick(g, g_sq_q, 5);
	const char *cl = dbl ? dq_close[g_rand(g, 4)] : sq_close[g_rand(g, 5)];
	const char *wrong = dbl ? "'@" : "\"@";
	uint32_t lines = g_rand(g, 4), k, ol, close_len;
	uint32_t eol_len = (uint32_t)strlen(g->eol);
	int open = (extra & KGENOME_TEXTUAL_F_OPEN) != 0;
	uint8_t fl = (uint8_t)(KGENOME_TEXTUAL_F_HERE | (dbl ? KGENOME_TEXTUAL_F_INTERP : 0u) | extra);

	p_put(p, "@", NULL);
	p_put(p, o, NULL);
	if (g_rand(g, 3) == 0)
		p_put(p, g_rand(g, 2) ? "  " : "\t", NULL);          /* blanks may follow the opener */
	p_put(p, g->eol, NULL);
	ol = p->n;
	for (k = 0; k < lines; k++) {
		uint32_t c = g_rand(g, 8);

		/* a line never BEGINS with a closer of this kind; lines that look like one and are not are the point */
		if (c == 0) {
			p_put(p, "  ", "  ");
			p_put(p, cl, cl);
		} else if (c == 1) {
			p_put(p, "x ", "x ");
			p_put(p, cl, cl);
		} else if (c == 2) {
			p_put(p, wrong, wrong);
		} else if (c == 3) {
			p_put(p, "q'\"#<#", "q'\"#<#");
		} else if (c == 4 && dbl) {
			p_novalue(p, "$x $(1 +");
			p_novalue(p, g->eol);
			p_novalue(p, "2)");
		} else if (c == 5 && dbl) {
			p_put(p, "`\"``", "\"`");
		} else {
			p_put(p, "line", "line");
		}
		p_put(p, g->eol, g->eol);
	}
	/* the value is the body without the line break in front of the closer, which the lexer puts in the closer */
	if (lines)
		p->vn -= eol_len;
	close_len = (uint32_t)strlen(cl) + (lines ? eol_len : 0u);
	if (!open)
		p_put(p, cl, NULL);
	g_span(g, KGENOME_TEXTUAL_STRING, fl, ol, open ? 0u : close_len, p->t, p->n, p);
}

/* ---- comments ---- */

static void g_comment(struct gen *g, int block, int open)
{
	char t[1024];
	uint32_t w = 0, k, pieces = g_rand(g, 8);
	static const char *const bits[] = { "a", " ", "'", "\"", "#", "<#", "@'", "$(", "`", "zQ9", "\xe2\x80\x98", "\xe2\x80\x9c", "{", "}", ")" };

	if (block) {
		memcpy(t, "<#", 2);
		w = 2;
	} else {
		t[w++] = '#';
	}
	for (k = 0; k < pieces; k++) {
		const char *b = bits[g_rand(g, sizeof bits / sizeof bits[0])];

		memcpy(t + w, b, strlen(b));
		w += (uint32_t)strlen(b);
		if (block && g_rand(g, 5) == 0) {
			memcpy(t + w, g->eol, strlen(g->eol));
			w += (uint32_t)strlen(g->eol);
		}
	}
	if (!block) {
		g_span(g, KGENOME_TEXTUAL_COMMENT, 0, 1, 0, t, w, NULL);
	} else if (open) {
		g_span(g, KGENOME_TEXTUAL_COMMENT, KGENOME_TEXTUAL_F_OPEN, 2, 0, t, w, NULL);
	} else {
		/* no byte above is ">" so the first "#>" is the closer, even when a "#" ends the body */
		memcpy(t + w, "#>", 2);
		g_span(g, KGENOME_TEXTUAL_COMMENT, 0, 2, 2, t, w + 2u, NULL);
	}
}

/* ---- the program ---- */

static const char *const g_atoms[] = {
	"Get-Item", "$x", "$env:Path", "$_", "$?", "=", "1KB", "0x1F", "2.5e3", "-eq", "|", "(", ")", "{", "}", "[int]", "@args",
	"&", ".", "@(", "@{", "[Convert]::FromBase64String(", "[System.Text.Encoding]::UTF8.GetString(", "${a b'\" #}", "${x}",
	"`'", "`\"", "`#", "``", "i`ex", "a#b", "C:\\C#\\x", "-f", "-join", "$a.b", "[0]", "..", "%", ",", "!", "-not",
};

static const char *const g_seps[] = { " ", " ", "\t", "  ", "\n", "\n", ";", " ; ", "CONT" };

/* What may stand between two items: blanks, a line break of the program's style, a backtick continuation, ";". */
static void g_sep(struct gen *g)
{
	const char *s = g_seps[g_rand(g, sizeof g_seps / sizeof g_seps[0])];

	if (s[0] == '\n')
		g_code(g, g->eol);
	else if (s[0] == 'C')
		g_code(g, g_rand(g, 2) ? " `\n  " : " `\r\n  ");       /* a continuation: backtick, line break, indentation */
	else
		g_code(g, s);
}

/* One program: items from the classes above and, a quarter of the time, an ending that is not closed. */
static void g_program(struct gen *g, uint32_t seed)
{
	static const char *const eols[] = { "\n", "\r\n", "\r" };
	uint32_t items, k;
	int adj = 0;            /* the last item was a string and nothing follows it yet */

	memset(g, 0, offsetof(struct gen, buf));
	g->rng = seed * 2654435761u + 1u;
	g->eol = eols[seed % 3u];
	if (g_rand(g, 8) == 0) {
		g_code(g, "\xef\xbb\xbf");
		if (g_rand(g, 2)) {
			g_comment(g, 0, 0);     /* a "#" right after the byte order mark is a comment */
			g_code(g, g->eol);
		}
	}
	items = 1u + g_rand(g, 14);
	for (k = 0; k < items && !g->full; k++) {
		uint32_t c = g_rand(g, 12);

		if (c >= 4 && c <= 6) {
			/* two literals side by side would make one ("'a''b'"): a blank between them */
			if (adj)
				g_code(g, " ");
			if (c == 4)
				g_sq(g, g_rand(g, 6), 0);
			else if (c == 5)
				g_dq(g, g_rand(g, 8), 0);
			else
				g_here(g, (int)g_rand(g, 2), 0);
			adj = 1;
			if (g_rand(g, 3)) {
				g_sep(g);
				adj = 0;
			}
			continue;
		}
		adj = 0;
		if (c == 7) {
			g_sep(g);
			g_comment(g, 1, 0);
		} else if (c == 8) {
			g_sep(g);
			g_comment(g, 0, 0);
			g_code(g, g->eol);              /* a line comment ends at its line */
			continue;
		} else if (c == 9) {
			g_code(g, "$x");
			g_comment(g, 0, 0);             /* "$x#c": the name ends at the "#" */
			g_code(g, g->eol);
			continue;
		} else {
			g_code(g, g_atoms[g_rand(g, sizeof g_atoms / sizeof g_atoms[0])]);
		}
		g_sep(g);
	}
	if (g_rand(g, 4) == 0 && !g->full) {
		uint32_t c = g_rand(g, 5);

		g_sep(g);
		if (c == 0)
			g_sq(g, g_rand(g, 4), KGENOME_TEXTUAL_F_OPEN);
		else if (c == 1)
			g_dq(g, g_rand(g, 5), KGENOME_TEXTUAL_F_OPEN);
		else if (c == 2)
			g_here(g, (int)g_rand(g, 2), KGENOME_TEXTUAL_F_OPEN);
		else if (c == 3)
			g_comment(g, 1, 1);
		else
			g_comment(g, 0, 0);
	}
}

#endif /* KGENOME_TEST_TEXTUAL_PSH_GEN_H */
