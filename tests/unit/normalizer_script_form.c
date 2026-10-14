#define _GNU_SOURCE
/*
 * normalizer_script_form - the form pass (kof_script_norm) and the code/data
 * question (kof_lex_is_code_at) against properties that do not depend on how
 * the pass is written.
 *
 * A GENERATED SCRIPT IS BUILT FROM TOKENS, so what each byte IS is known when it
 * is written: code, the body of a string, the body of a comment. The text is
 * then laid out at random - indent, blank lines, comment-only lines, trailing
 * comments, inline block comments, lone braces, runs of spaces, CRLF, strings
 * that span lines - for each language row of the table.
 *
 *   TOKENS KEPT     read back with a lexer of this file (strings, comments,
 *                   words, punctuation), the output has the input's tokens in
 *                   the input's order, minus the comments the pass drops. Every
 *                   string is the SAME BYTES, which is the claim the header opens
 *                   with: inside a literal every byte is a value.
 *   SAFE CLOSING    two tokens the input kept apart that touch in the output are
 *                   not two word bytes and not a byte and itself and not a
 *                   comment opener: closing up never makes a longer token.
 *   NOTHING LEFT    with the flag on, no indent, no blank line, no comment-only
 *                   line survives (read back through the lexer); each flag alone
 *                   does its own work and not the others', on known answers.
 *   SHAPE           never longer than the input, idempotent, the answer 0 when
 *                   the pass declines (a heredoc, no room), NULL and short caps.
 *   CODE OR DATA    kof_lex_is_code_at asked of every byte of the generated
 *                   script: bytes strictly inside a string or a block comment
 *                   are data, bytes strictly outside are code.
 *   HOSTILE         a one-megabyte line, a hundred thousand lines, unterminated
 *                   strings and block comments, guard-page buffers.
 *   KNOWN MISSES    each with its cause.
 */

#include "normalizer_ref.h"
#include <kofmod/script.h>
#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_norm.h"

/* ---- a lexer, from the language table ---------------------------------------------- */

enum { T_WS, T_NL, T_WORD, T_PUNCT, T_STR, T_LCMT, T_BCMT };

struct tok {
	unsigned kind;
	size_t   off, len;
	int      first_on_line;
};

struct toks {
	struct tok *v;
	size_t      n, cap;
};

static int is_w(uint8_t c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int is_b(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

static int at(const uint8_t *p, size_t n, size_t i, const char *t)
{
	size_t l = t ? strlen(t) : 0;

	return l && i + l <= n && !memcmp(p + i, t, l);
}

static void tok_add(struct toks *t, unsigned kind, size_t off, size_t len, int fol)
{
	if (t->n == t->cap) {
		t->cap = t->cap ? 2u * t->cap : 256u;
		t->v = realloc(t->v, t->cap * sizeof *t->v);
	}
	t->v[t->n].kind = kind;
	t->v[t->n].off = off;
	t->v[t->n].len = len;
	t->v[t->n].first_on_line = fol;
	t->n++;
}

/* Does this row's escape rule apply inside a string opened with `q`? */
static int escapes(const struct kof_lex *lx, uint8_t q)
{
	return !lx->no_bs_escape && (q == '"' || lx->sq_escapes);
}

static void lex(const struct kof_lex *lx, const uint8_t *p, size_t n, struct toks *t)
{
	size_t i = 0;
	int fol = 1, k;

	t->n = 0;
	while (i < n) {
		size_t s = i;
		uint8_t c = p[i];
		int done = 0;

		if (c == '\n') {
			tok_add(t, T_NL, i, 1, 0);
			i++;
			fol = 1;
			continue;
		}
		if (at(p, n, i, lx->blk_open)) {
			i += strlen(lx->blk_open);
			while (i < n && !at(p, n, i, lx->blk_close))
				i++;
			i = i < n ? i + strlen(lx->blk_close) : n;
			tok_add(t, T_BCMT, s, i - s, fol);
			fol = 0;
			continue;
		}
		for (k = 0; k < 3 && !done; k++)
			if (at(p, n, i, lx->line_cmt[k])) {
				while (i < n && p[i] != '\n')
					i++;
				tok_add(t, T_LCMT, s, i - s, fol);
				fol = 0;
				done = 1;
			}
		if (done)
			continue;
		for (k = 0; k < 3 && !done; k++)
			if (lx->ml_open[k] && lx->ml_close[k] && at(p, n, i, lx->ml_open[k])) {
				i += strlen(lx->ml_open[k]);
				while (i < n && !at(p, n, i, lx->ml_close[k]))
					i++;
				i = i < n ? i + strlen(lx->ml_close[k]) : n;
				tok_add(t, T_STR, s, i - s, fol);
				fol = 0;
				done = 1;
			}
		if (done)
			continue;
		if (lx->quotes && strchr(lx->quotes, c)) {
			i++;
			while (i < n && p[i] != c) {
				if (p[i] == '\\' && escapes(lx, c) && i + 1u < n)
					i++;
				i++;
			}
			i = i < n ? i + 1u : n;
			tok_add(t, T_STR, s, i - s, fol);
			fol = 0;
			continue;
		}
		if (is_b(c)) {
			while (i < n && is_b(p[i]))
				i++;
			tok_add(t, T_WS, s, i - s, 0);
			continue;
		}
		if (is_w(c)) {
			while (i < n && is_w(p[i]))
				i++;
			tok_add(t, T_WORD, s, i - s, fol);
		} else {
			i++;
			tok_add(t, T_PUNCT, s, 1, fol);
		}
		fol = 0;
	}
}

/* the tokens that mean something: no whitespace, no newline, no comment */
static int significant(const struct toks *t, size_t from, size_t *idx)
{
	size_t i = from;

	while (i < t->n && (t->v[i].kind == T_WS || t->v[i].kind == T_NL || t->v[i].kind == T_LCMT ||
			    t->v[i].kind == T_BCMT))
		i++;
	*idx = i;
	return i < t->n;
}

/* ---- the generator ------------------------------------------------------------------ */

struct gen {
	uint8_t *p;
	size_t   n, cap;
	/* what each byte is, as it was written */
	uint8_t *cls;               /* 0 code, 1 body of a string or block comment, 2 skip */
};

#define C_CODE 0
#define C_BODY 1
#define C_SKIP 2

static void put(struct gen *g, const char *s, size_t l, uint8_t cls)
{
	if (g->n + l + 2u > g->cap) {
		g->cap = (g->n + l + 2u) * 2u;
		g->p = realloc(g->p, g->cap);
		g->cls = realloc(g->cls, g->cap);
	}
	memcpy(g->p + g->n, s, l);
	memset(g->cls + g->n, cls, l);
	g->n += l;
}

static void puts_(struct gen *g, const char *s, uint8_t cls)
{
	put(g, s, strlen(s), cls);
}

static const char *const WORDS[] = { "foo", "bar", "x1", "eval", "echo", "if", "ls", "cat", "var",
				     "$a", "$b", "n", "1", "42", "name", "do", "then", "fi" };
/* punctuation that cannot be, or begin, a comment or a heredoc in any row */
static const char PUNCTS[] = "=+(),;}!&|.*";

static void sp(struct gen *g, struct nrng *r, unsigned allow_zero)
{
	static const char *const w[] = { " ", "  ", "   ", "\t", " \t", "     " };

	if (allow_zero && nr_below(r, 3u) == 0u)
		return;
	puts_(g, w[nr_below(r, sizeof w / sizeof w[0])], C_CODE);
}

/* a string body: the bytes a literal may hold that the pass must not touch */
static void string_body(struct gen *g, const struct kof_lex *lx, uint8_t q, struct nrng *r, int multi)
{
	static const char *const piece[] = { "abc", " ", "   ", "\t", "#", "//", "{", "}", "/*", "*/",
					     ";", "--", "::", "REM x", "'", "  indent  ", "{ }", "<#", "=" };
	unsigned k, np = nr_below(r, 6u);

	for (k = 0; k < np; k++) {
		const char *s = piece[nr_below(r, sizeof piece / sizeof piece[0])];

		/* the quote that closes this string may not appear bare */
		if (strchr(s, q) || (lx->ml_open[0] && at((const uint8_t *)s, strlen(s), 0, lx->ml_open[0])))
			s = "z";
		put(g, s, strlen(s), C_BODY);
		if (escapes(lx, q) && nr_below(r, 6u) == 0u) {
			char e[3] = { '\\', (char)q, 0 };

			put(g, e, 2u, C_BODY);
		}
		if (multi && nr_below(r, 4u) == 0u)
			put(g, "\n", 1u, C_BODY);
	}
}

static void string_tok(struct gen *g, const struct kof_lex *lx, struct nrng *r, int multi)
{
	uint8_t q = (uint8_t)lx->quotes[nr_below(r, (uint32_t)strlen(lx->quotes))];

	/* a body line of a multi-line string that starts with `#` or `//` is text, and
	 * the pass must keep it - generated freely in string_body */
	put(g, (const char *)&q, 1u, C_CODE);
	string_body(g, lx, q, r, multi);
	put(g, (const char *)&q, 1u, C_SKIP);
}

static void code_tok(struct gen *g, const struct kof_lex *lx, struct nrng *r, int multi)
{
	uint32_t k = nr_below(r, 8u);

	/* two quotes that touch can read as a triple quote (python): keep a blank between */
	if (g->n && lx->quotes && strchr(lx->quotes, g->p[g->n - 1u]) && k >= 5u && k < 7u)
		k = 0;

	if (k < 3u) {
		puts_(g, WORDS[nr_below(r, sizeof WORDS / sizeof WORDS[0])], C_CODE);
	} else if (k < 5u) {
		char c = PUNCTS[nr_below(r, sizeof PUNCTS - 1u)];

		put(g, &c, 1u, C_CODE);
	} else if (k < 7u) {
		string_tok(g, lx, r, multi);
	} else {
		puts_(g, WORDS[nr_below(r, sizeof WORDS / sizeof WORDS[0])], C_CODE);
	}
}

/* What a block comment's body is to the question "code or data": data - except
 * where the opener begins with a line-comment opener (Lua's "--[[" begins with
 * "--"), which kof_lex_is_code_at took for a line comment first (edge_cases asks
 * about that one directly), so those bytes are not asked about in the differential. */
static uint8_t block_body(const struct kof_lex *lx)
{
	int k;

	for (k = 0; k < 3; k++)
		if (lx->line_cmt[k] && at((const uint8_t *)lx->blk_open, strlen(lx->blk_open), 0,
					  lx->line_cmt[k]))
			return C_SKIP;
	return C_BODY;
}

/* A literal that names its own end (python's triple quote, lua's long bracket): the
 * pass copies it verbatim, newlines, indents and comment openers inside it included. */
static int ml_literal(struct gen *g, const struct kof_lex *lx, struct nrng *r)
{
	static const char *const piece[] = { "doc text", "\n", "\n\n", "    indented", "# not a comment",
					     "-- nor this", "// nor this", "{", "}", "  ", "\t" };
	int k;
	unsigned i, np = 1u + nr_below(r, 8u);

	for (k = 0; k < 3; k++)
		if (lx->ml_open[k] && lx->ml_close[k])
			break;
	if (k == 3)
		return 0;
	puts_(g, lx->ml_open[k], C_SKIP);
	for (i = 0; i < np; i++) {
		const char *p = piece[nr_below(r, sizeof piece / sizeof piece[0])];

		puts_(g, p, C_BODY);
	}
	puts_(g, lx->ml_close[k], C_SKIP);
	return 1;
}

/* One line of the script, in one of the shapes a script has. */
static void one_line(struct gen *g, const struct kof_lex *lx, struct nrng *r, int multi, int crlf,
		     int blocks)
{
	uint32_t shape = nr_below(r, 14u);
	unsigned k, nt;
	int brace = 0;
	size_t cmt_end = 0;     /* where a line comment's text ended, 0 when the line has none */

	if (nr_below(r, 3u) == 0u)
		sp(g, r, 1);                            /* indent */
	if (shape == 0u) {
		/* blank, maybe with blanks on it */
	} else if (shape == 1u && lx->line_cmt[0]) {
		const char *o = lx->line_cmt[nr_below(r, 3u) && lx->line_cmt[1] ? 1u : 0u];

		puts_(g, o ? o : lx->line_cmt[0], C_SKIP);
		puts_(g, " remark here", C_SKIP);
		cmt_end = g->n;
	} else if (shape == 2u && lx->blk_open && blocks) {
		puts_(g, lx->blk_open, C_SKIP);
		puts_(g, " block remark ", block_body(lx));
		puts_(g, lx->blk_close, C_SKIP);
	} else if (shape == 4u && ml_literal(g, lx, r)) {
		/* a multi-line literal stands where a line would */
	} else if (shape == 3u && !lx->ws_significant) {
		puts_(g, "{", C_CODE);                  /* a lone brace */
		brace = 1;
	} else {
		nt = 1u + nr_below(r, 6u);
		for (k = 0; k < nt; k++) {
			if (k) {
				if (nr_below(r, 2u))
					sp(g, r, 0);
				else
					sp(g, r, 1);
			}
			code_tok(g, lx, r, multi);
			if (lx->blk_open && blocks && nr_below(r, 12u) == 0u) {   /* inline block comment */
				sp(g, r, 1);
				puts_(g, lx->blk_open, C_SKIP);
				puts_(g, " in ", block_body(lx));
				puts_(g, lx->blk_close, C_SKIP);
				sp(g, r, 0);    /* a blank after it, as well as the gap the pass leaves */
			}
		}
		if (lx->line_cmt[0] && nr_below(r, 5u) == 0u) {     /* a trailing comment */
			sp(g, r, 0);
			puts_(g, lx->line_cmt[0], C_SKIP);
			puts_(g, " trailing", C_SKIP);
			cmt_end = g->n;
		}
	}
	/* (a lone brace with a blank or a CR behind it is joined too - edge_cases asks about
	 * it - and the generated corpus leaves them off) */
	if (!brace && nr_below(r, 4u) == 0u)
		sp(g, r, 1);                            /* trailing blanks */
	if (crlf && !brace)
		puts_(g, "\r", C_CODE);
	/* the blanks and the carriage return after a line comment are inside it */
	if (cmt_end)
		memset(g->cls + cmt_end, C_SKIP, g->n - cmt_end);
	puts_(g, "\n", C_CODE);
}

/* quote characters of the generated words must not be able to open anything */
static void generate(struct gen *g, const struct kof_lex *lx, struct nrng *r, unsigned lines,
		     int multi, int crlf, int blocks)
{
	unsigned i;

	g->n = 0;
	for (i = 0; i < lines; i++)
		one_line(g, lx, r, multi, crlf, blocks);
}

/* ---- the properties -------------------------------------------------------------------- */

/* The significant tokens of `a` and `b` are the same bytes in the same order. */
static int same_tokens(const struct kof_lex *lx, const uint8_t *a, size_t an, const uint8_t *b,
		       size_t bn)
{
	static struct toks ta, tb;
	size_t i = 0, j = 0, ia, ib;

	lex(lx, a, an, &ta);
	lex(lx, b, bn, &tb);
	for (;;) {
		int ha = significant(&ta, i, &ia), hb = significant(&tb, j, &ib);

		if (ha != hb)
			return 0;
		if (!ha)
			return 1;
		if (ta.v[ia].kind != tb.v[ib].kind || ta.v[ia].len != tb.v[ib].len ||
		    memcmp(a + ta.v[ia].off, b + tb.v[ib].off, ta.v[ia].len)) {
			if (nr_bad < 3u)
				printf("  first difference: in token %zu kind %u [%.*s] / out token %zu kind %u [%.*s]\n",
				       ia, ta.v[ia].kind, (int)ta.v[ia].len, (const char *)a + ta.v[ia].off, ib,
				       tb.v[ib].kind, (int)tb.v[ib].len, (const char *)b + tb.v[ib].off);
			return 0;
		}
		i = ia + 1u;
		j = ib + 1u;
	}
}

/* Two tokens that touch in `out` but had whitespace (or an inline comment) between
 * them in `in` must not be a pair that closing up would turn into one longer token. */
static int safe_closing(const struct kof_lex *lx, const uint8_t *in, size_t n, const uint8_t *out,
			size_t on)
{
	static struct toks ti, to;
	static size_t si[1u << 16], so[1u << 16];
	size_t mi = 0, mo = 0, k, at_in = 0, at_out = 0;

	lex(lx, in, n, &ti);
	lex(lx, out, on, &to);
	while (mi < sizeof si / sizeof si[0] && significant(&ti, at_in, &si[mi])) {
		at_in = si[mi++] + 1u;
	}
	while (mo < sizeof so / sizeof so[0] && significant(&to, at_out, &so[mo])) {
		at_out = so[mo++] + 1u;
	}
	if (mi != mo || mi >= sizeof si / sizeof si[0])
		return 0;
	for (k = 0; k + 1u < mi; k++) {
		size_t m;
		int sep = 0, nl = 0;
		const struct tok *a = &ti.v[si[k]], *b = &ti.v[si[k + 1u]];

		for (m = si[k] + 1u; m < si[k + 1u]; m++) {
			sep |= ti.v[m].kind == T_WS || ti.v[m].kind == T_BCMT;
			nl |= ti.v[m].kind == T_NL || ti.v[m].kind == T_LCMT;
		}
		if (!sep || nl || so[k + 1u] != so[k] + 1u)
			continue;
		if (a->kind == T_STR || b->kind == T_STR)
			continue;
		{
			uint8_t x = in[a->off + a->len - 1u], y = in[b->off];
			char pair[3] = { (char)x, (char)y, 0 };
			int c;

			if ((is_w(x) && is_w(y)) || x == y)
				return 0;
			for (c = 0; c < 3; c++)
				if (lx->line_cmt[c] && !strcmp(pair, lx->line_cmt[c]))
					return 0;
			if (lx->blk_open && !strcmp(pair, lx->blk_open))
				return 0;
		}
	}
	return 1;
}

static void leading_and_blank(const struct kof_lex *lx, const uint8_t *out, size_t on, int *indent,
			      int *blank, int *cmt_only)
{
	static struct toks t;
	size_t i;
	int line_has = 0, at_start = 1;

	*indent = *blank = *cmt_only = 0;
	lex(lx, out, on, &t);
	for (i = 0; i < t.n; i++) {
		unsigned kind = t.v[i].kind;

		if (kind == T_NL) {
			if (!line_has)
				*blank = 1;
			line_has = 0;
			at_start = 1;
			continue;
		}
		if (kind == T_WS) {
			if (at_start)
				*indent = 1;
			continue;
		}
		if (kind == T_LCMT && !line_has && t.v[i].first_on_line)
			*cmt_only = 1;
		line_has = 1;
		at_start = 0;
	}
}

/* every kind in the table, in the order a build lists them */
static const uint8_t ALL_KINDS[] = {
	KOF_SCRIPT_PHP, KOF_SCRIPT_JS, KOF_SCRIPT_PYTHON, KOF_SCRIPT_PERL, KOF_SCRIPT_RUBY,
	KOF_SCRIPT_SHELL, KOF_SCRIPT_BAT, KOF_SCRIPT_LUA, KOF_SCRIPT_TCL, KOF_SCRIPT_CFM,
	KOF_SCRIPT_PSH, KOF_SCRIPT_ASP, KOF_SCRIPT_VBS, KOF_SCRIPT_ASPX, KOF_SCRIPT_JSP
};

static void table_rows(void)
{
	size_t i;

	for (i = 0; i < sizeof ALL_KINDS; i++) {
		const struct kof_lex *lx = kof_lex_for(ALL_KINDS[i]);

		NCKF(lx != NULL, "kind %u has no row", ALL_KINDS[i]);
		if (!lx)
			continue;
		NCKF(lx->quotes && lx->quotes[0], "kind %u: no quotes", ALL_KINDS[i]);
		NCKF(lx->line_cmt[0] || lx->blk_open, "kind %u: no comment at all", ALL_KINDS[i]);
		NCKF((lx->blk_open != NULL) == (lx->blk_close != NULL), "kind %u: half a block comment",
		     ALL_KINDS[i]);
	}
	NCK(kof_lex_for(KOF_SCRIPT_ANY) == NULL);
	NCK(kof_lex_for(0xff) == NULL);
	/* the two languages that share the "<%" family read "'" differently */
	NCK(kof_lex_for(KOF_SCRIPT_ASP) == kof_lex_for(KOF_SCRIPT_VBS));
	NCK(kof_lex_for(KOF_SCRIPT_ASP) != kof_lex_for(KOF_SCRIPT_ASPX));
	NCK(kof_lex_for(KOF_SCRIPT_ASPX) == kof_lex_for(KOF_SCRIPT_JSP));
	NCK(strchr(kof_lex_for(KOF_SCRIPT_ASP)->quotes, '\'') == NULL);
	NCK(strchr(kof_lex_for(KOF_SCRIPT_ASPX)->quotes, '\'') != NULL);
}

static void generated_scripts(void)
{
	static const uint32_t flagsets[] = { KOF_NORM_ALL, KOF_NORM_SPACE, KOF_NORM_INDENT,
					     KOF_NORM_BLANK, KOF_NORM_COMMENT,
					     KOF_NORM_BRACE | KOF_NORM_SPACE | KOF_NORM_BLANK, 0u };
	static uint8_t out[1u << 16], again[1u << 16];
	struct gen g = { NULL, 0, 0, NULL };
	struct nrng r;
	size_t ki;
	unsigned seed, produced = 0, declined = 0;

	for (ki = 0; ki < sizeof ALL_KINDS; ki++) {
		const struct kof_lex *lx = kof_lex_for(ALL_KINDS[ki]);

		for (seed = 1; seed <= 220u; seed++) {
			uint32_t what = flagsets[seed % (sizeof flagsets / sizeof flagsets[0])];
			int crlf = (seed % 5u) == 0u, multi = (seed % 3u) == 0u;
			/* block comments leave blanks the single flags do not own (see the known
			 * miss on gating), so they are generated only where every flag is on */
			int blocks = what == KOF_NORM_ALL;
			uint32_t w, w2;

			nr_seed(&r, 0x7000u + ALL_KINDS[ki] * 1000u + seed);
			generate(&g, lx, &r, 4u + nr_below(&r, 40u), multi, crlf, blocks);
			if (!g.n)
				continue;
			w = kof_script_norm(lx, g.p, (uint32_t)g.n, out, (uint32_t)g.n, what);
			if (!w) {
				declined++;
				continue;
			}
			produced++;
			NCKF(w <= g.n, "kind %u seed %u: %u bytes from %zu", ALL_KINDS[ki], seed, w, g.n);
			NCKF(same_tokens(lx, g.p, g.n, out, w),
			     "kind %u seed %u what %x: tokens differ\n--- in\n%.*s\n--- out\n%.*s",
			     ALL_KINDS[ki], seed, what, (int)g.n, (char *)g.p, (int)w, (char *)out);
			if ((what & KOF_NORM_SPACE) && !lx->ws_significant)
				NCKF(safe_closing(lx, g.p, g.n, out, w),
				     "kind %u seed %u: a closing-up made a longer token\n--- in\n%.*s\n--- out\n"
				     "%.*s", ALL_KINDS[ki], seed, (int)g.n, (char *)g.p, (int)w,
				     (char *)out);
			{
				int indent, blank, cmt;

				leading_and_blank(lx, out, w, &indent, &blank, &cmt);
				if ((what & KOF_NORM_INDENT) && (!blocks || (what & KOF_NORM_SPACE)))
					NCKF(!indent, "kind %u seed %u: an indent survived\n--- in\n%.*s\n--- out\n%.*s",
					     ALL_KINDS[ki], seed, (int)g.n, (char *)g.p, (int)w, (char *)out);
				if ((what & KOF_NORM_BLANK) && (blocks || !crlf))
					NCKF(!blank, "kind %u seed %u: a blank line survived\n--- in\n%.*s\n--- out\n%.*s",
					     ALL_KINDS[ki], seed, (int)g.n, (char *)g.p, (int)w, (char *)out);
				if (what & KOF_NORM_COMMENT)
					NCKF(!cmt, "kind %u seed %u: a comment line survived\n--- out\n%.*s",
					     ALL_KINDS[ki], seed, (int)w, (char *)out);
			}
			/* the pass is a fixed point: a form of a form is the form */
			w2 = kof_script_norm(lx, out, w, again, w, what);
			NCKF(w2 == 0 || (w2 == w && !memcmp(out, again, w)),
			     "kind %u seed %u what %x: second pass changed it\n--- in\n%.*s\n--- once\n%.*s\n--- twice\n%.*s",
			     ALL_KINDS[ki], seed, what, (int)g.n, (char *)g.p, (int)w, (char *)out, (int)w2, (char *)again);
		}
	}
	NCKF(produced > declined, "generator reach: %u formed, %u declined", produced, declined);
	free(g.p);
	free(g.cls);
}

/* ---- code or data ------------------------------------------------------------------------ */

static void code_or_data(void)
{
	struct gen g = { NULL, 0, 0, NULL };
	struct nrng r;
	size_t ki;
	unsigned seed, checked = 0, data = 0;

	for (ki = 0; ki < sizeof ALL_KINDS; ki++) {
		const struct kof_lex *lx = kof_lex_for(ALL_KINDS[ki]);

		for (seed = 1; seed <= 80u; seed++) {
			size_t i;

			nr_seed(&r, 0x9000u + ALL_KINDS[ki] * 1000u + seed);
			/* a string ends at the newline for this question, so no multi-line strings */
			generate(&g, lx, &r, 3u + nr_below(&r, 12u), 0, 0, !lx->blk_open || block_body(lx) == C_BODY);
			for (i = 0; i < g.n; i++) {
				int got;

				if (g.cls[i] == C_SKIP)
					continue;
				got = kof_lex_is_code_at(lx, g.p, (uint32_t)g.n, (uint32_t)i);
				NCKF(got == (g.cls[i] == C_CODE), "kind %u seed %u offset %zu (%s) said %d\n%.*s",
				     ALL_KINDS[ki], seed, i, g.cls[i] == C_CODE ? "code" : "body", got, (int)g.n,
				     (char *)g.p);
				checked++;
				data += g.cls[i] == C_BODY;
			}
		}
	}
	NCKF(checked > 20000u && data > 2000u, "generator reach: %u bytes asked, %u data", checked, data);
	free(g.p);
	free(g.cls);
}

/* ---- known answers, one flag at a time ---------------------------------------------------------- */

static uint32_t norm_str(uint8_t kind, const char *in, uint32_t what, char *out, uint32_t cap)
{
	return kof_script_norm(kof_lex_for(kind), (const uint8_t *)in, (uint32_t)strlen(in),
			       (uint8_t *)out, cap, what);
}

#define NORMS(kind, in, what, want) do { \
	char o_[512]; \
	uint32_t w_ = norm_str((kind), (in), (what), o_, sizeof o_); \
	NCKF(w_ == strlen(want) && !memcmp(o_, (want), w_), \
	     "norm [%s] what %x: got [%.*s] want [%s]", (in), (what), (int)w_, o_, (want)); \
} while (0)

static void flags_one_at_a_time(void)
{
	/* each flag does its own work and nothing else */
	NORMS(KOF_SCRIPT_PHP, "  $a = 1;\n\n\n// c\n$b  =  2; // t\n{\n",
	      KOF_NORM_INDENT, "$a = 1;\n\n\n// c\n$b  =  2; // t\n{\n");
	NORMS(KOF_SCRIPT_PHP, "  $a = 1;\n\n\n// c\n$b  =  2; // t\n{\n",
	      KOF_NORM_BLANK, "  $a = 1;\n// c\n$b  =  2; // t\n{\n");
	NORMS(KOF_SCRIPT_PHP, "  $a = 1;\n\n\n// c\n$b  =  2; // t\n{\n",
	      KOF_NORM_COMMENT, "  $a = 1;\n\n\n$b  =  2; // t\n{\n");
	NORMS(KOF_SCRIPT_PHP, "$a = 1;\n\n\n// c\n$b  =  2; // t\n{\n",
	      KOF_NORM_SPACE, "$a=1;\n\n\n// c\n$b=2;// t\n{\n");
	NORMS(KOF_SCRIPT_PHP, "if (x)\n{\n  y;\n}\n", KOF_NORM_BRACE, "if (x){\n  y;\n}\n");
	/* shell never joins a brace and never closes up */
	NORMS(KOF_SCRIPT_SHELL, "f()\n{\n  ls   -la   /tmp\n}\n", KOF_NORM_ALL, "f()\n{\nls -la /tmp\n}\n");
	/* a string is data: its spaces, its comment openers and its braces stay */
	NORMS(KOF_SCRIPT_PHP, "$s  =  \"a   #b  //c { d\";\n", KOF_NORM_ALL, "$s=\"a   #b  //c { d\";\n");
	NORMS(KOF_SCRIPT_PHP, "$s='it\\'s  fine'  ;\n", KOF_NORM_ALL, "$s='it\\'s  fine';\n");
	/* two word bytes keep a space; a byte and itself keep one */
	NORMS(KOF_SCRIPT_PHP, "echo   $a ;\n$a +  + $b;\n$c = $a   -   - $b;\nif   x  then\n", KOF_NORM_SPACE,
	      "echo$a;\n$a+ +$b;\n$c=$a- -$b;\nif x then\n");
	/* an inline block comment goes, the code around it joins as closing up allows */
	NORMS(KOF_SCRIPT_PHP, "$a = /* gone */ 1;\n", KOF_NORM_ALL, "$a=1;\n");
	NORMS(KOF_SCRIPT_PHP, "/* one\n  two */\n$a=1;\n", KOF_NORM_ALL, "$a=1;\n");
	/* a brace never joins a line that ends in a comment */
	NORMS(KOF_SCRIPT_PHP, "f() // note\n{\n", KOF_NORM_ALL, "f()// note\n{\n");
	/* CRLF: the trailing carriage return is trailing whitespace */
	NORMS(KOF_SCRIPT_PHP, "$a=1;\r\n$b=2;\r\n", KOF_NORM_ALL, "$a=1;\n$b=2;\n");
	/* python: a triple-quoted literal is copied whole and its indent is data */
	NORMS(KOF_SCRIPT_PYTHON, "x = \"\"\"a\n    b  c\n\n# d\n\"\"\"\ny  =  2\n", KOF_NORM_ALL,
	      "x=\"\"\"a\n    b  c\n\n# d\n\"\"\"\ny=2\n");
	/* lua: a long bracket is declined (whole extent), and the answer is 0 */
	{
		char o[128];

		NCK(norm_str(KOF_SCRIPT_LUA, "x = [[a  b]]\n", KOF_NORM_ALL, o, sizeof o) != 0);
		NCK(norm_str(KOF_SCRIPT_SHELL, "cat <<EOF\n  x\nEOF\n", KOF_NORM_ALL, o, sizeof o) == 0);
		NCK(norm_str(KOF_SCRIPT_PHP, "<<<EOT\n  x\nEOT;\n", KOF_NORM_ALL, o, sizeof o) == 0);
		/* the spellings of a heredoc: indent-stripped, with blanks, with a quoted label */
		NCK(norm_str(KOF_SCRIPT_SHELL, "cat <<-EOF\n  x\nEOF\n", KOF_NORM_ALL, o, sizeof o) == 0);
		NCK(norm_str(KOF_SCRIPT_RUBY, "x = <<~EOT\n  y\nEOT\n", KOF_NORM_ALL, o, sizeof o) == 0);
		NCK(norm_str(KOF_SCRIPT_SHELL, "cat << \"EOF\"\n x\nEOF\n", KOF_NORM_ALL, o, sizeof o) == 0);
		NCK(norm_str(KOF_SCRIPT_PERL, "print <<'EOT';\n  z\nEOT\n", KOF_NORM_ALL, o, sizeof o) == 0);
		/* "<<" with no label is a shift and an ascii banner, not a heredoc */
		NCK(norm_str(KOF_SCRIPT_PHP, "$a = 1 << 2;\n  $b=1;\n", KOF_NORM_ALL, o, sizeof o) != 0);
		NCK(norm_str(KOF_SCRIPT_PHP, "/* <<<<<<<>>>>>>> */\n  $b=1;\n", KOF_NORM_ALL, o, sizeof o) != 0);
	}
	/* a byte that would join its neighbour into a comment opener keeps its space */
	NORMS(KOF_SCRIPT_PHP, "$a = $b / *$c;\n", KOF_NORM_ALL, "$a=$b/ *$c;\n");
	NORMS(KOF_SCRIPT_PSH, "$a -lt < $b;\n", KOF_NORM_ALL, "$a-lt<$b;\n");
	NORMS(KOF_SCRIPT_PSH, "$a = $b < # c\n", KOF_NORM_ALL, "$a=$b< # c\n");
	/* batch and vbs: a backslash is a byte, and "C:\" is a whole string */
	NORMS(KOF_SCRIPT_BAT, "set p=\"C:\\\"\nREM x\n  echo   hi\n", KOF_NORM_ALL,
	      "set p=\"C:\\\"\necho hi\n");
	NORMS(KOF_SCRIPT_VBS, "p = \"C:\\\"  \n' note\nx  =  1\n", KOF_NORM_ALL, "p=\"C:\\\"\nx=1\n");
	/* no row: not touched, and the caller keeps the input */
	{
		char o[64];

		NCK(kof_script_norm(NULL, (const uint8_t *)"a  b\n", 5, (uint8_t *)o, sizeof o, KOF_NORM_ALL) == 0);
		NCK(norm_str(KOF_SCRIPT_ANY, "a  b\n", KOF_NORM_ALL, o, sizeof o) == 0);
	}
}

/* ---- edge cases that were once misses ---------------------------------------------------------- */

static void edge_cases(void)
{
	char o[256];
	uint32_t w;
	const struct kof_lex *php = kof_lex_for(KOF_SCRIPT_PHP);

	/*
	 * KOF_NORM_EOL IS READ. The header lists it first - "CRLF -> LF" - and nothing in the
	 * pass tested the bit: a carriage return went only as trailing whitespace and only with
	 * SPACE asked. Asked alone it now takes the carriage return off every line that ends
	 * outside a literal.
	 */
	w = norm_str(KOF_SCRIPT_PHP, "$a=1;\r\n$b=2;\r\n", KOF_NORM_EOL, o, sizeof o);
	NCKF(w == 12u && !memcmp(o, "$a=1;\n$b=2;\n", 12), "KOF_NORM_EOL alone turns CRLF into LF");
	/* ...and not inside a string or a heredoc, where it is the value */
	w = norm_str(KOF_SCRIPT_PHP, "$a=\"x\r\ny\";\r\n", KOF_NORM_EOL, o, sizeof o);
	NCKF(w == 11u && !memcmp(o, "$a=\"x\r\ny\";\n", 11),
	     "a carriage return inside a string is left alone (%u)", w);
	w = norm_str(KOF_SCRIPT_PHP, "// c\r\n$a=1;\r\n", KOF_NORM_EOL, o, sizeof o);
	NCKF(w == 11u && !memcmp(o, "// c\n$a=1;\n", 11), "the end of a comment line too (%u)", w);

	/*
	 * AN INLINE BLOCK COMMENT TAKEN OUT IS A GAP, NOT NOTHING. The space before the comment
	 * is closed up (its neighbour is the "/" of the opener), the comment is skipped, and with
	 * no blank after it the two words touched: "if", a block comment, "then" became `ifthen`,
	 * and "var", a comment, "x" became `varx` - the very thing the header says closing up must
	 * never do. One space now stands where the comment was when the bytes either side would
	 * make one token.
	 */
	w = norm_str(KOF_SCRIPT_PHP, "if /* c */then\n", KOF_NORM_ALL, o, sizeof o);
	NCKF(w == 8u && !memcmp(o, "if then\n", 8), "removing an inline block comment between two words keeps them apart (%u)", w);
	w = norm_str(KOF_SCRIPT_PHP, "var/* c */x\n", KOF_NORM_ALL, o, sizeof o);
	NCKF(w == 6u && !memcmp(o, "var x\n", 6), "the same with no blank on either side (%u)", w);
	w = norm_str(KOF_SCRIPT_PHP, "a+/* c */+b\n", KOF_NORM_ALL, o, sizeof o);
	NCKF(w == 6u && !memcmp(o, "a+ +b\n", 6), "two operators that would glue stay apart (%u)", w);
	w = norm_str(KOF_SCRIPT_PHP, "a /* c */ (b)\n", KOF_NORM_ALL, o, sizeof o);
	NCKF(w == 5u && !memcmp(o, "a(b)\n", 5), "and a comment that separates nothing leaves no gap (%u)", w);

	/*
	 * THE BRACE JOIN ASKS WHAT IS LEFT AFTER TRAILING WHITESPACE: a lone "{" joins the line
	 * above - "so one marker matches both" styles - and a Windows copy of the same file has
	 * a carriage return after it ("{\r"), as does any brace with a blank behind it. The test
	 * was that the line is exactly one byte long, so the LF copy of an Allman-braced file
	 * formed to `if(x){` and its CRLF copy to `if(x)` and `{` on two lines, a marker written on
	 * one missed the other, and a second pass joined what the first left.
	 */
	{
		char lf[64], crlf[64], blank[64];
		uint32_t wl = norm_str(KOF_SCRIPT_PHP, "if (x)\n{\n  y;\n}\n", KOF_NORM_ALL, lf, sizeof lf);
		uint32_t wc = norm_str(KOF_SCRIPT_PHP, "if (x)\r\n{\r\n  y;\r\n}\r\n", KOF_NORM_ALL, crlf,
				       sizeof crlf);
		uint32_t wb = norm_str(KOF_SCRIPT_PHP, "if (x)\n{ \n  y;\n}\n", KOF_NORM_ALL, blank,
				       sizeof blank);

		NCK(wl == 12u && !memcmp(lf, "if(x){\ny;\n}\n", 12));
		NCKF(wc == wl && !memcmp(lf, crlf, wl),
		     "the form of a CRLF file is the form of its LF copy: a lone brace followed by a carriage return is joined");
		NCKF(wb == wl && !memcmp(lf, blank, wl), "and a brace with a blank behind it");
	}

	/*
	 * INLINE BLOCK COMMENTS ARE DROPPED ONLY WHEN COMMENT IS ASKED. KOF_NORM_COMMENT is "drop
	 * comments"; the walk of a line skipped a block comment wherever it stood, with or without
	 * the flag, so a caller that asked for SPACE alone lost the comments in the middle of its
	 * lines. A comment that is kept is copied with its closer and what stays open across lines
	 * is copied through.
	 */
	w = norm_str(KOF_SCRIPT_PHP, "$a = 1; /* keep me */ $b = 2;\n", KOF_NORM_SPACE, o, sizeof o);
	NCKF(w && memmem(o, w, "keep me", 7) != NULL, "an inline block comment is kept when COMMENT was not asked for");
	w = norm_str(KOF_SCRIPT_PHP, "$a = 1; /* keep\n  me */ $b = 2;\n", KOF_NORM_SPACE, o, sizeof o);
	NCKF(w && memmem(o, w, "keep\n  me */", 12) != NULL, "and one that spans lines");
	w = norm_str(KOF_SCRIPT_PHP, "$a = 1; /* drop me */ $b = 2;\n", KOF_NORM_ALL, o, sizeof o);
	NCKF(w && memmem(o, w, "drop me", 7) == NULL, "and dropped when it was asked for");

	/*
	 * `rem` IS A COMMENT IN CMD WHATEVER ITS CASE, and the row spells it "REM". The compare
	 * was exact, so a lower-case remark line survived the pass and the form of two copies of
	 * one script differed by the case of a comment. It is a keyword: a whole word only, so
	 * `REMOTE=1` is not a comment line.
	 */
	w = norm_str(KOF_SCRIPT_BAT, "echo a\nrem remark\necho b\n", KOF_NORM_ALL, o, sizeof o);
	NCKF(w == 14u && !memcmp(o, "echo a\necho b\n", 14), "a lower-case `rem` line is dropped as a comment (%u)", w);
	w = norm_str(KOF_SCRIPT_BAT, "echo a\nReM remark\nREM\necho b\n", KOF_NORM_ALL, o, sizeof o);
	NCKF(w == 14u && !memcmp(o, "echo a\necho b\n", 14), "in any case, and a bare REM");
	w = norm_str(KOF_SCRIPT_BAT, "echo a\nREMOTE=1\necho b\n", KOF_NORM_ALL, o, sizeof o);
	NCKF(w == 23u && !memcmp(o, "echo a\nREMOTE=1\necho b\n", 23), "REMOTE=1 is not a comment (%u)", w);

	/*
	 * A BYTE INSIDE A COMMENT IS NOT CODE, to kof_lex_is_code_at.
	 *
	 * The function's contract is "outside every string literal and every comment". A block
	 * comment and a string answered 0 for their bodies; a line comment set no state at all - the
	 * memchr that skips to its end left `st` at ST_OUT - so `# <?php` in a python script, or
	 * `// eval(` in a php one, read as code. The sniff asks this to tell a file that IS php
	 * from one that TALKS ABOUT php. Lua's "--[[" is a block comment that begins with its own
	 * line comment, so the block opener is asked first, as the pass does.
	 */
	{
		static const char src[] = "$a = 1; // eval( here\n$b = 2;";
		uint32_t at_eval = (uint32_t)(strstr(src, "eval") - src);

		NCKF(!kof_lex_is_code_at(php, (const uint8_t *)src, (uint32_t)strlen(src), at_eval),
		     "kof_lex_is_code_at reads the body of a line comment as a comment");
		NCKF(kof_lex_is_code_at(php, (const uint8_t *)src, (uint32_t)strlen(src),
					(uint32_t)(strstr(src, "\n") - src)),
		     "and the newline that ends it is not in it");
		NCKF(kof_lex_is_code_at(php, (const uint8_t *)src, (uint32_t)strlen(src),
					(uint32_t)(strstr(src, "$b") - src)),
		     "nor the line after");
	}
	{
		static const char src[] = "x = 1  # <?php here\ny = 2";
		const struct kof_lex *py = kof_lex_for(KOF_SCRIPT_PYTHON);
		uint32_t at_tag = (uint32_t)(strstr(src, "<?php") - src);

		NCKF(!kof_lex_is_code_at(py, (const uint8_t *)src, (uint32_t)strlen(src), at_tag),
		     "a php tag in a python comment is not code to the sniff");
	}
	{
		static const char src[] = "x = 1 --[[ eval( ]] y = 2";
		const struct kof_lex *lua = kof_lex_for(KOF_SCRIPT_LUA);
		uint32_t at_eval = (uint32_t)(strstr(src, "eval") - src);

		NCKF(!kof_lex_is_code_at(lua, (const uint8_t *)src, (uint32_t)strlen(src), at_eval),
		     "kof_lex_is_code_at reads the body of a lua block comment as a comment");
		NCKF(kof_lex_is_code_at(lua, (const uint8_t *)src, (uint32_t)strlen(src),
					(uint32_t)(strstr(src, " y = 2") - src + 1)),
		     "and the code after its close as code");
	}
	/* what it DOES say, so the miss above is not read as the function being inert */
	{
		static const char src[] = "$a = 1; /* eval( */ $b = \"eval(\";";
		const char *p1 = strstr(src, "eval"), *p2 = strstr(p1 + 1, "eval");

		NCK(!kof_lex_is_code_at(php, (const uint8_t *)src, (uint32_t)strlen(src), (uint32_t)(p1 - src)));
		NCK(!kof_lex_is_code_at(php, (const uint8_t *)src, (uint32_t)strlen(src), (uint32_t)(p2 - src)));
		NCK(kof_lex_is_code_at(php, (const uint8_t *)src, (uint32_t)strlen(src), 0));
		NCK(kof_lex_is_code_at(php, (const uint8_t *)src, (uint32_t)strlen(src), (uint32_t)strlen(src)));
		NCK(kof_lex_is_code_at(NULL, (const uint8_t *)src, (uint32_t)strlen(src), 10));
		NCK(kof_lex_is_code_at(php, NULL, 10, 5));
		NCK(kof_lex_is_code_at(php, (const uint8_t *)src, 4, 99));
		/* an unterminated quote ends at the newline: the rest of the file is not a string */
		{
			static const char s2[] = "echo \"abc\n<?php x";

			NCK(kof_lex_is_code_at(php, (const uint8_t *)s2, (uint32_t)strlen(s2),
					       (uint32_t)(strstr(s2, "<?php") - s2)));
		}
	}
}

/* ---- hostile ------------------------------------------------------------------------------------- */

static int group_long(void *arg)
{
	size_t n = 1u << 20, i, lines = 100000u, at;
	uint8_t *in = malloc(n + 16u), *out = malloc(n + 16u);
	const struct kof_lex *php = kof_lex_for(KOF_SCRIPT_PHP);
	uint32_t w;

	(void)arg;
	/* one megabyte on one line: words and spaces, a string in the middle */
	for (i = 0; i < n; i++)
		in[i] = i % 7u == 3u ? ' ' : (uint8_t)('a' + i % 26u);
	in[n / 2] = '"';
	in[n / 2 + 40u] = '"';
	w = kof_script_norm(php, in, (uint32_t)n, out, (uint32_t)n, KOF_NORM_ALL);
	NCK(w > 0 && w <= n);
	NCK(same_tokens(php, in, n, out, w));
	free(in);
	free(out);
	/* a hundred thousand short lines, a third of them blank or comments */
	in = malloc(lines * 16u);
	out = malloc(lines * 16u);
	for (i = 0, at = 0; i < lines; i++) {
		static const char *const l[] = { "  $a = 1;\n", "\n", "// x\n", "  {\n", "f( 1 ,2 );\n" };
		const char *s = l[i % 5u];

		memcpy(in + at, s, strlen(s));
		at += strlen(s);
	}
	w = kof_script_norm(php, in, (uint32_t)at, out, (uint32_t)at, KOF_NORM_ALL);
	NCK(w > 0 && w < at);
	NCK(same_tokens(php, in, at, out, w));
	free(in);
	free(out);
	return (int)nr_bad;
}

static int group_guarded(void *arg)
{
	static const char *const texts[] = {
		"  $a = 1;\r\n\r\n// c\n{\n  /* b */ $b  = \"x  y\" ; // t\n",
		"x = \"\"\"a\n  b\"\"\"\n", "\"unterminated\n  $a = 1;", "/* unterminated\n  $a = 1;",
		"$a = 'x\\", "{", "\n", "  ", "//", "/*", "$a=1;\n\n\n\n", "<<<EOT\nx\n",
	};
	unsigned t, cut;
	int tail;

	(void)arg;
	for (t = 0; t < sizeof texts / sizeof texts[0]; t++) {
		for (tail = 0; tail < 2; tail++) {
			for (cut = 0; cut <= strlen(texts[t]); cut++) {
				struct gbuf in, out;
				uint8_t kind = (uint8_t)(t % 3u == 1u ? KOF_SCRIPT_PYTHON : KOF_SCRIPT_PHP);
				const struct kof_lex *lx = kof_lex_for(kind);
				uint32_t w;

				if (!gb_new(&in, cut, tail) || !gb_new(&out, cut, tail))
					return 99;
				memcpy(in.p, texts[t], cut);
				w = kof_script_norm(lx, in.p, cut, out.p, cut, KOF_NORM_ALL);
				NCK(w <= cut);
				/* the same, on a buffer one byte short: refused, and no write */
				if (cut) {
					struct gbuf small;

					if (!gb_new(&small, cut - 1u, tail))
						return 99;
					NCK(kof_script_norm(lx, in.p, cut, small.p, cut - 1u, KOF_NORM_ALL) == 0);
					gb_free(&small);
				}
				/* fold and is_code_at over the same guarded bytes */
				{
					uint32_t lim = 0, k;

					(void)kof_script_fold_ex(lx, in.p, cut, out.p, cut, &lim);
					for (k = 0; k < cut; k++)
						(void)kof_lex_is_code_at(lx, in.p, cut, k);
				}
				gb_free(&in);
				gb_free(&out);
			}
		}
	}
	return (int)nr_bad;
}

int main(void)
{
	table_rows();
	flags_one_at_a_time();
	generated_scripts();
	code_or_data();
	edge_cases();
	NCK(nr_group("one megabyte and a hundred thousand lines", group_long, NULL) == 0);
	NCK(nr_group("guard pages", group_guarded, NULL) == 0);
	printf("normalizer_script_form: %u checks, %u failed\n", nr_ok + nr_bad,
	       nr_bad);
	return nr_bad != 0;
}
