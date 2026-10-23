/*
 * diag_text_sum_gen - random programs against a MODEL, for the summaries of the TEXT route (diag_text_sum.c) and the scope fixes under them.
 *
 * A program is generated as a tree (functions with parameters, calls, returns, assignments, sinks, nested functions) and RENDERED into seven dialects (php, python, javascript, lua, ruby,
 * vbscript, c# of an aspx page). The expected links are computed from the TREE by a model written here that shares nothing with the lib. The one rule it states is the one the lib
 * documents: a variable holds the producers of every assignment before the use; a call of a function the file defines gives its parameters what its arguments hold and stands for
 * what the function returns - and for the producers of an argument only where no parameter holds it (G3: it said "for its arguments' producers" always, which made a function that
 * ignores an argument pass the argument on); a link whose producer reaches a node only through a parameter or a return is MAY. Everything else - which function a
 * call names, which variable a name is, the order the nodes are made in - is the model's own reading of the language. The lib's graph is compared link for link (from, to, role,
 * MUST or MAY), after the number, the capability and the order of the nodes. A program whose model needs more than the lib keeps (six producers in a variable, four slots, four
 * inputs in a node) is generated again: those are the lib's stated bounds and not what is under test.
 *
 * What the random programs cover: recursion and mutual recursion, a parameter never given a value, fan-in (one function called with different producers), the same names in different
 * functions (shadowing), a function defined after its call, nested functions that hide a same-named outer one (the lexical dialects), vbscript's undeclared names that are global and its
 * `Dim`s that are not, a return written as an assignment to the function's own name, `obj.field = v` where the dialect reads it, and C#'s brace on a line of its own. The literal cases
 * after them name each boundary once, with the links written by hand.
 *
 * usage: diag_text_sum_gen [programs-per-dialect [seed]]   (default 300)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static uint32_t rs = 20261021u;

static uint32_t rnd(void)
{
	rs = rs * 1103515245u + 12345u;
	return rs >> 16;
}

static int chance(int pct)
{
	return (int)(rnd() % 100u) < pct;
}

/* ---- the dialects --------------------------------------------------------------------------------------------------- */

enum kind { K_PHP, K_PY, K_JS, K_LUA, K_RUBY, K_VBS, K_CS };

struct dial {
	const char *name;
	enum kind   k;
	uint32_t    lang;
	const char *src, *mid, *snk;    /* a source (a decode of a literal), a middle node (a decode of an expression) and a sink */
	uint16_t    snk_cap;
	const char *cat;
	int         lexical;            /* functions nest, and see the variables around them (js, python, lua) */
	int         main_fn;            /* the top statements are the body of a method (c#) */
	int         field;              /* `obj.field = v` is read (aspx, vbscript) */
	int         ubd;                /* a name may be read before it was assigned (the languages that do not look the name up outside) */
};

static const struct dial D[] = {
	{ "php",    K_PHP,  KGENOME_TEXTUAL_LANG_PHP,  "base64_decode",            "gzinflate",             "system",        KGENOME_NUCLEO_EXEC_IMAGE, ".",  0, 0, 0, 1 },
	{ "python", K_PY,   KGENOME_TEXTUAL_LANG_PY,   "base64.b64decode",         "zlib.decompress",       "os.system",     KGENOME_NUCLEO_EXEC_IMAGE, "+",  1, 0, 0, 0 },
	{ "js",     K_JS,   KGENOME_TEXTUAL_LANG_JS,   "atob",                     "unescape",              "eval",          KGENOME_NUCLEO_EVAL,       "+",  1, 0, 0, 0 },
	{ "lua",    K_LUA,  KGENOME_TEXTUAL_LANG_LUA,  "base64.dec",               "zlib.inflate",          "os.execute",    KGENOME_NUCLEO_EXEC_IMAGE, "..", 1, 0, 0, 0 },
	{ "ruby",   K_RUBY, KGENOME_TEXTUAL_LANG_RUBY, "Base64.decode64",          "Zlib.inflate",          "system",        KGENOME_NUCLEO_EXEC_IMAGE, "+",  0, 0, 0, 1 },
	{ "vbs",    K_VBS,  KGENOME_TEXTUAL_LANG_VBS,  "StrReverse",               "StrReverse",            "Execute",       KGENOME_NUCLEO_EVAL,       "&",  0, 0, 1, 0 },
	{ "aspx",   K_CS,   KGENOME_TEXTUAL_LANG_ASPX, "Convert.FromBase64String", "HttpUtility.UrlDecode", "Process.Start", KGENOME_NUCLEO_EXEC_IMAGE, "+",  1, 1, 1, 0 },
};

/* ---- the program ---------------------------------------------------------------------------------------------------- */

#define NPOOL 5         /* variable names of a program: few, so that functions share them */
#define NFN   4         /* function names */
#define MAXST 6
#define MAXP  3
#define MAXF  (NFN + 3)
#define MAXN  64

enum { E_LIT, E_VAR, E_SRC, E_MID, E_CALL, E_CAT };

struct ex {
	int        t, var, fname, node, na;     /* var: pool index; fname: pool index of the function called; node: its id, set when rendered */
	struct ex *a[MAXP];
};

enum { S_ASSIGN, S_SINK, S_RET, S_CALL, S_FIELD, S_DEF };

struct stmt {
	int        k, var, fn;                  /* var: the variable assigned; fn: the function an S_DEF writes here */
	struct ex *e;
	int        node;                        /* the sink's node */
};

struct func {
	int         name;                       /* pool index of the function's name, -1 for the top */
	int         np, par[MAXP];
	int         nst;
	struct stmt st[MAXST];
	int         parent;                     /* the function it is written inside, -1 at the top level (0 is the top itself) */
	int         dim[NPOOL];                 /* vbscript: names `Dim`med in it */
	int         placed;                     /* written already (nested ones are written where their S_DEF is) */
};

struct prog {
	struct func f[MAXF];
	int         nf;                         /* f[0] is the top */
	int         order[MAXF + MAXST + 2][2]; /* text order at the top level: {0, fn}: a definition; {1, stmt}: a top statement */
	int         nord;
	struct ex   pool[300];
	int         npool;
	int         nn;                         /* nodes, in the order the text makes them */
	uint16_t    cap[MAXN];
};

static struct ex *new_ex(struct prog *p, int t)
{
	struct ex *e = &p->pool[p->npool++];

	memset(e, 0, sizeof *e);
	e->t = t;
	e->node = -1;
	return e;
}

static struct ex *gen_ex(struct prog *p, int depth, const int *avail, int navail)
{
	int r = (int)(rnd() % 100u), i;
	struct ex *e;

	if (p->npool > 280)
		return new_ex(p, E_LIT);
	if (r < 8)
		return new_ex(p, E_LIT);
	if (r < 38 && navail) {
		e = new_ex(p, E_VAR);
		e->var = avail[rnd() % (unsigned)navail];
		return e;
	}
	if (r < 55 || depth == 0)
		return new_ex(p, E_SRC);
	if (r < 70) {
		e = new_ex(p, E_MID);
		e->na = 1;
		e->a[0] = gen_ex(p, depth - 1, avail, navail);
		return e;
	}
	if (r < 90 && p->nf > 1) {
		e = new_ex(p, E_CALL);
		e->fname = (int)(rnd() % NFN);
		e->na = 1 + (int)(rnd() % 3u);
		for (i = 0; i < e->na; i++)
			e->a[i] = gen_ex(p, depth - 1, avail, navail);
		return e;
	}
	e = new_ex(p, E_CAT);
	e->na = 2;
	e->a[0] = gen_ex(p, depth - 1, avail, navail);
	e->a[1] = gen_ex(p, depth - 1, avail, navail);
	return e;
}

/* The body of function `fn`: statements over the names it has (its parameters, and what it assigned above). */
static void gen_body(struct prog *p, const struct dial *d, int fn)
{
	struct func *f = &p->f[fn];
	int avail[NPOOL], navail = 0, i, ns = fn == 0 ? 2 + (int)(rnd() % 5u) : 1 + (int)(rnd() % 4u);

	for (i = 0; i < f->np; i++)
		avail[navail++] = f->par[i];
	for (i = 0; i < ns && f->nst < MAXST; i++) {
		struct stmt *s = &f->st[f->nst];
		int r = (int)(rnd() % 100u), j, have;

		memset(s, 0, sizeof *s);
		s->node = -1;
		if (r < 38) {
			int rest[NPOOL], nrest = 0;

			s->k = S_ASSIGN;
			s->var = (int)(rnd() % NPOOL);
			/* NOT read inside its own assignment: the walk adds the producers of a right side to the variable as it reads them, so a variable
			 * read in the middle of `v = f(g(v))` already holds what the outer call made (measured on the tree before the summaries: `a = gzinflate(gzinflate(a))` links
			 * the outer decode into the inner one). That is the walk's, not under test here, and the model does not state it. */
			for (j = 0; j < navail; j++)
				if (avail[j] != s->var)
					rest[nrest++] = avail[j];
			s->e = gen_ex(p, 2, rest, nrest);
			for (have = j = 0; j < navail; j++)
				have |= avail[j] == s->var;
			if (!have)
				avail[navail++] = s->var;
		} else if (r < 62) {
			s->k = S_SINK;
			s->e = gen_ex(p, 2, avail, navail);
		} else if (r < 80 && p->nf > 1) {
			s->k = S_CALL;
			s->e = new_ex(p, E_CALL);
			s->e->fname = (int)(rnd() % NFN);
			s->e->na = 1 + (int)(rnd() % 3u);
			for (j = 0; j < s->e->na; j++)
				s->e->a[j] = gen_ex(p, 1, avail, navail);
		} else if (r < 88 && d->field && navail) {
			int rest[NPOOL], nrest = 0;

			s->k = S_FIELD;
			s->var = avail[rnd() % (unsigned)navail];
			for (j = 0; j < navail; j++)
				if (avail[j] != s->var)
					rest[nrest++] = avail[j];
			s->e = gen_ex(p, 1, rest, nrest);
		} else if (fn != 0) {
			s->k = S_RET;
			s->e = gen_ex(p, 2, avail, navail);
		} else {
			s->k = S_SINK;
			s->e = gen_ex(p, 2, avail, navail);
		}
		f->nst++;
		if (s->k == S_RET)
			break;
	}
	if (fn != 0 && f->nst < MAXST && chance(70)) {          /* most functions end by returning something */
		struct stmt *s = &f->st[f->nst++];

		memset(s, 0, sizeof *s);
		s->k = S_RET;
		s->node = -1;
		s->e = gen_ex(p, 2, avail, navail);
	}
	if (d->ubd && fn != 0 && chance(20) && f->nst < MAXST) {  /* a read before any assignment: the name is empty there */
		struct stmt *s = &f->st[f->nst++];

		memset(s, 0, sizeof *s);
		s->k = S_SINK;
		s->node = -1;
		s->e = new_ex(p, E_VAR);
		s->e->var = (int)(rnd() % NPOOL);
	}
	if (d->k == K_VBS)
		for (i = 0; i < NPOOL; i++)
			f->dim[i] = fn != 0 && chance(50);
}

static void gen_prog(struct prog *p, const struct dial *d)
{
	int nfns = 1 + (int)(rnd() % (NFN + 1u)), i, j, tops;

	memset(p, 0, sizeof *p);
	p->nf = 1 + nfns;
	p->f[0].name = -1;
	p->f[0].parent = -1;
	for (i = 1; i < p->nf; i++) {
		struct func *f = &p->f[i];

		f->name = (i - 1) % NFN;
		f->parent = 0;
		f->np = (int)(rnd() % (MAXP + 1u));
		for (j = 0; j < f->np; j++) {
			int again;

			do {
				f->par[j] = (int)(rnd() % NPOOL);
				for (again = 0, tops = 0; tops < j; tops++)
					again |= f->par[tops] == f->par[j];
			} while (again);
		}
		if (d->lexical && i >= 2 && chance(35)) {       /* nested in an earlier function; it may carry the name of one outside */
			f->parent = 1 + (int)(rnd() % (unsigned)(i - 1));
			if (p->f[f->parent].parent != 0)
				f->parent = 0;
			if (chance(50))
				f->name = p->f[1 + (int)(rnd() % (unsigned)(i - 1))].name;
		}
	}
	for (i = 0; i < p->nf; i++)
		gen_body(p, d, i);
	/* a nested function is written inside its parent, at a statement of its own */
	for (i = 1; i < p->nf; i++) {
		struct func *par = &p->f[p->f[i].parent];
		struct stmt def;
		int at;

		if (p->f[i].parent == 0)
			continue;
		if (par->nst >= MAXST) {
			p->f[i].parent = 0;
			continue;
		}
		memset(&def, 0, sizeof def);
		def.k = S_DEF;
		def.fn = i;
		def.node = -1;
		at = (int)(rnd() % (unsigned)(par->nst + 1));
		memmove(&par->st[at + 1], &par->st[at], (size_t)(par->nst - at) * sizeof par->st[0]);
		par->st[at] = def;
		par->nst++;
	}
	/* the order of the text: definitions and top statements shuffled together (a function may come after its call) */
	if (d->main_fn) {
		for (i = 1; i < p->nf; i++)
			if (p->f[i].parent == 0) {
				p->order[p->nord][0] = 0;
				p->order[p->nord++][1] = i;
			}
		p->order[p->nord][0] = 0;
		p->order[p->nord++][1] = 0;             /* the top is a method */
		for (i = p->nord - 1; i > 0; i--) {
			int k = (int)(rnd() % (unsigned)(i + 1)), t0 = p->order[i][1];

			p->order[i][1] = p->order[k][1];
			p->order[k][1] = t0;
		}
	} else {
		for (i = 1; i < p->nf; i++)
			if (p->f[i].parent == 0) {
				p->order[p->nord][0] = 0;
				p->order[p->nord++][1] = i;
			}
		for (i = 0; i < p->f[0].nst; i++) {
			p->order[p->nord][0] = 1;
			p->order[p->nord++][1] = i;
		}
		for (i = p->nord - 1; i > 0; i--) {       /* shuffle the definitions among themselves and among the statements, keeping the statements in order */
			int k = (int)(rnd() % (unsigned)(i + 1));

			if (p->order[i][0] == 0 && p->order[k][0] == 0) {
				int t0 = p->order[i][1];

				p->order[i][1] = p->order[k][1];
				p->order[k][1] = t0;
			}
		}
		for (i = 0; i < p->nord; i++)           /* and move each definition to a random place */
			if (p->order[i][0] == 0 && chance(50)) {
				int to = (int)(rnd() % (unsigned)p->nord), t0[2] = { p->order[i][0], p->order[i][1] };

				if (to != i) {
					memmove(&p->order[i], &p->order[i + 1], (size_t)(p->nord - i - 1) * sizeof p->order[0]);
					memmove(&p->order[to + 1], &p->order[to], (size_t)(p->nord - 1 - to) * sizeof p->order[0]);
					p->order[to][0] = t0[0];
					p->order[to][1] = t0[1];
				}
			}
	}
}

/* ---- the text ------------------------------------------------------------------------------------------------------- */

struct rctx {
	char              *b;
	size_t             n, cap;
	int                ind;
	struct prog       *p;
	const struct dial *d;
	int                declared[MAXF + 1][NPOOL];
};

static void put(struct rctx *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void put(struct rctx *r, const char *fmt, ...)
{
	va_list ap;
	int k;

	va_start(ap, fmt);
	k = vsnprintf(r->b + r->n, r->cap - r->n, fmt, ap);
	va_end(ap);
	if (k > 0 && r->n + (size_t)k < r->cap)
		r->n += (size_t)k;
}

static void nl(struct rctx *r)
{
	int i;

	put(r, "\n");
	for (i = 0; i < r->ind; i++)
		put(r, "    ");
}

static int new_node(struct rctx *r, uint16_t cap)
{
	r->p->cap[r->p->nn] = cap;
	return r->p->nn++;
}

static void vname(struct rctx *r, int v)
{
	static const char *names[NPOOL] = { "Va0", "Vb1", "Vc2", "Vd3", "Ve4" };
	char c[8];

	strcpy(c, names[v]);
	if (r->d->k == K_VBS && chance(40))             /* vbscript does not tell upper and lower case apart */
		c[1] = (char)toupper((unsigned char)c[1]) == c[1] ? (char)tolower((unsigned char)c[1]) : (char)toupper((unsigned char)c[1]);
	put(r, "%s%s", r->d->k == K_PHP ? "$" : "", c);
}

static void fname(struct rctx *r, int n)
{
	static const char *names[NFN] = { "Fa0", "Fb1", "Fc2", "Fd3" };
	char c[8];

	strcpy(c, names[n]);
	if ((r->d->k == K_VBS || r->d->k == K_PHP) && chance(40))      /* function names do not either */
		c[1] = (char)toupper((unsigned char)c[1]) == c[1] ? (char)tolower((unsigned char)c[1]) : (char)toupper((unsigned char)c[1]);
	put(r, "%s", c);
}

static void r_ex(struct rctx *r, struct ex *e)
{
	int i;
	const char *q = r->d->k == K_VBS || r->d->k == K_CS ? "\"" : "'";

	switch (e->t) {
	case E_LIT:
		put(r, "%sk%s", q, q);
		break;
	case E_VAR:
		vname(r, e->var);
		break;
	case E_SRC:
		e->node = new_node(r, KGENOME_NUCLEO_DECODE);
		put(r, "%s(%sQQ%s)", r->d->src, q, q);
		break;
	case E_MID:
		e->node = new_node(r, KGENOME_NUCLEO_DECODE);
		put(r, "%s(", r->d->mid);
		r_ex(r, e->a[0]);
		put(r, ")");
		break;
	case E_CALL:
		fname(r, e->fname);
		put(r, "(");
		for (i = 0; i < e->na; i++) {
			if (i)
				put(r, ", ");
			r_ex(r, e->a[i]);
		}
		put(r, ")");
		break;
	default:
		r_ex(r, e->a[0]);
		put(r, " %s ", r->d->cat);
		r_ex(r, e->a[1]);
		break;
	}
}

static void r_fn(struct rctx *r, int fi);

static const char *semi(const struct dial *d)
{
	return d->k == K_PHP || d->k == K_JS || d->k == K_CS ? ";" : "";
}

static void r_stmt(struct rctx *r, int fi, struct stmt *s)
{
	const struct dial *d = r->d;
	struct func *f = &r->p->f[fi];

	switch (s->k) {
	case S_ASSIGN:
	case S_FIELD:
		if (s->k == S_ASSIGN && !r->declared[fi][s->var]) {
			r->declared[fi][s->var] = 1;
			if (d->k == K_JS)
				put(r, "var ");
			else if (d->k == K_LUA)
				put(r, "local ");
			else if (d->k == K_CS)
				put(r, "string ");
		}
		vname(r, s->var);
		put(r, "%s = ", s->k == S_FIELD ? ".Prop" : "");
		r_ex(r, s->e);
		put(r, "%s", semi(d));
		break;
	case S_SINK:
		s->node = new_node(r, d->snk_cap);
		if (d->k == K_VBS) {
			put(r, "Execute ");
			r_ex(r, s->e);
		} else {
			put(r, "%s(", d->snk);
			r_ex(r, s->e);
			put(r, ")%s", semi(d));
		}
		break;
	case S_RET:
		if (d->k == K_VBS) {
			fname(r, f->name);
			put(r, " = ");
		} else {
			put(r, "return ");
		}
		r_ex(r, s->e);
		put(r, "%s", semi(d));
		break;
	case S_CALL:
		if (d->k == K_VBS)
			put(r, "Call ");
		r_ex(r, s->e);
		put(r, "%s", semi(d));
		break;
	default:
		r_fn(r, s->fn);
		break;
	}
}

static void r_body(struct rctx *r, int fi)
{
	struct func *f = &r->p->f[fi];
	int i;

	for (i = 0; i < f->nst; i++) {
		nl(r);
		r_stmt(r, fi, &f->st[i]);
	}
}

static void r_fn(struct rctx *r, int fi)
{
	const struct dial *d = r->d;
	struct func *f = &r->p->f[fi];
	int i;

	f->placed = 1;
	switch (d->k) {
	case K_PHP:
	case K_JS:
		put(r, "function ");
		fname(r, f->name);
		put(r, "(");
		break;
	case K_PY:
		put(r, "def ");
		fname(r, f->name);
		put(r, "(");
		break;
	case K_LUA:
		put(r, "function ");
		fname(r, f->name);
		put(r, "(");
		break;
	case K_RUBY:
		put(r, "def ");
		fname(r, f->name);
		put(r, "(");
		break;
	case K_VBS:
		put(r, "Function ");
		fname(r, f->name);
		put(r, "(");
		break;
	default:
		if (fi == 0)
			put(r, "void Page_Load(");
		else {
			put(r, "string ");
			fname(r, f->name);
			put(r, "(");
		}
		break;
	}
	for (i = 0; i < f->np; i++) {
		if (i)
			put(r, ", ");
		if (d->k == K_CS)
			put(r, "string ");
		vname(r, f->par[i]);
	}
	put(r, ")");
	switch (d->k) {
	case K_PHP:
	case K_JS:
		put(r, " {");
		break;
	case K_PY:
		put(r, ":");
		break;
	case K_CS:
		put(r, "\n{");              /* the brace on a line of its own */
		break;
	default:
		break;
	}
	r->ind++;
	if (d->k == K_VBS) {
		int any = 0;

		for (i = 0; i < NPOOL; i++)
			if (f->dim[i]) {
				put(r, any++ ? ", " : "\n    Dim ");
				vname(r, i);
			}
	}
	memset(r->declared[fi], 0, sizeof r->declared[fi]);
	for (i = 0; i < f->np; i++)
		r->declared[fi][f->par[i]] = 1;
	r_body(r, fi);
	r->ind--;
	switch (d->k) {
	case K_PHP:
	case K_JS:
	case K_CS:
		nl(r);
		put(r, "}");
		break;
	case K_LUA:
	case K_RUBY:
		nl(r);
		put(r, "end");
		break;
	case K_VBS:
		nl(r);
		put(r, "End Function");
		break;
	default:
		break;
	}
	nl(r);
}

static void render(struct rctx *r, struct prog *p, const struct dial *d, char *buf, size_t cap)
{
	int i;

	memset(r, 0, sizeof *r);
	r->b = buf;
	r->cap = cap;
	r->p = p;
	r->d = d;
	p->nn = 0;
	if (d->k == K_PHP)
		put(r, "<?php\n");
	if (d->k == K_CS)
		put(r, "<%%@ Page Language=\"C#\" %%>\n<script runat=\"server\">\n");
	for (i = 0; i < p->nord; i++) {
		if (p->order[i][0] == 0) {
			r_fn(r, p->order[i][1]);
		} else {
			if (p->order[i][1] == 0 && !d->main_fn)
				memset(r->declared[0], 0, sizeof r->declared[0]);
			r_stmt(r, 0, &p->f[0].st[p->order[i][1]]);
			put(r, "\n");
		}
	}
	if (d->k == K_CS)
		put(r, "</script>\n");
}

/* ---- the model ------------------------------------------------------------------------------------------------------- */

#define SLOT_P(f, k) (1000 + (f) * 4 + (k))
#define SLOT_R(f)    (2000 + (f))

struct pset {
	int n, v[40];
};

static int pset_add(struct pset *s, int v)
{
	int i;

	for (i = 0; i < s->n; i++)
		if (s->v[i] == v)
			return 1;
	if (s->n == 40)
		return 0;
	s->v[s->n++] = v;
	return 1;
}

struct model {
	struct prog       *p;
	const struct dial *d;
	struct pset        defs[MAXF][NPOOL];
	struct pset        edge[3000 - 1000 + MAXF + 1];     /* by slot - 1000: the producers a parameter or a return holds */
	struct { int slot, to, role; } pend[400];
	int                npend;
	unsigned char      link[MAXN][MAXN];                 /* [to][from]: 1 MUST, 2 MAY */
	unsigned char      role[MAXN][MAXN];
	int                bad;                              /* the program needs more than the lib keeps: generate another */
};

/* Which variable table a name is in, for function fn: its own, or - vbscript - the top's when it is neither a parameter nor `Dim`med. */
static int scope_of(const struct model *m, int fn, int var)
{
	int i;

	if (m->d->k != K_VBS || fn == 0)
		return fn;
	for (i = 0; i < m->p->f[fn].np; i++)
		if (m->p->f[fn].par[i] == var)
			return fn;
	return m->p->f[fn].dim[var] ? fn : 0;
}

/* The functions a call of name `name`, written in function `fn`, reaches: all of that name where functions are global; the innermost visible ones where they nest. */
static int resolve(const struct model *m, int fn, int name, int *out)
{
	int g, n = 0, best = -1;

	for (g = 1; g < m->p->nf; g++) {
		int home, vis = 0, depth = 0, c;

		if (m->p->f[g].name != name)
			continue;
		if (!m->d->lexical) {
			out[n++] = g;
			continue;
		}
		home = m->p->f[g].parent;
		for (c = fn; c >= 0; c = m->p->f[c].parent) {
			if (c == home)
				vis = 1;
			if (c == 0)
				break;
		}
		for (c = home; c > 0; c = m->p->f[c].parent)
			depth++;
		if (vis && depth > best) {
			best = depth;
			n = 0;
		}
		if (vis && depth == best)
			out[n++] = g;
	}
	return n;
}

static void add_set(struct model *m, struct pset *to, const struct pset *from)
{
	int i;

	for (i = 0; i < from->n; i++)
		if (!pset_add(to, from->v[i]))
			m->bad = 1;
}

static void link_to(struct model *m, int to, const struct pset *from, int role)
{
	int i;

	for (i = 0; i < from->n; i++) {
		if (from->v[i] == to)           /* a node is not its own input (the lib drops it too) */
			continue;
		if (from->v[i] < 1000) {
			m->link[to][from->v[i]] = 1;
			m->role[to][from->v[i]] = (unsigned char)role;
		} else if (m->npend < 400) {
			m->pend[m->npend].slot = from->v[i];
			m->pend[m->npend].to = to;
			m->pend[m->npend++].role = role;
		} else {
			m->bad = 1;
		}
	}
}

static void m_ex(struct model *m, int fn, const struct ex *e, struct pset *out)
{
	struct pset a[MAXP];
	int i, j, fs[MAXF], nf;

	memset(a, 0, sizeof a);
	switch (e->t) {
	case E_LIT:
		return;
	case E_VAR:
		add_set(m, out, &m->defs[scope_of(m, fn, e->var)][e->var]);
		return;
	case E_SRC:
		pset_add(out, e->node);
		return;
	case E_MID:
		m_ex(m, fn, e->a[0], &a[0]);
		link_to(m, e->node, &a[0], KGENOME_DIAG_ROLE_VALUE);
		pset_add(out, e->node);
		return;
	case E_CAT:
		m_ex(m, fn, e->a[0], out);
		m_ex(m, fn, e->a[1], out);
		return;
	default:
		break;
	}
	for (i = 0; i < e->na; i++)
		m_ex(m, fn, e->a[i], &a[i]);
	nf = resolve(m, fn, e->fname, fs);
	/*
	 * WHAT A CALL STANDS FOR (the rule G3 corrected; the model said every argument's producers, always). A call of a function the text does not define stands for its arguments'
	 * producers: nothing is known about what it does with them. A call of functions the text defines stands for what they RETURN (the return slot of each), and for an argument
	 * only when some function of the name has no parameter that holds it - an argument past the parameters it names may be read some other way (func_get_args), so it is carried
	 * as it always was; an argument every function has a parameter for reaches the result only through the function's own return, and a function that ignores it returns nothing of it.
	 */
	for (i = 0; i < e->na; i++) {
		int held = nf > 0;

		for (j = 0; j < nf; j++)
			if (i >= m->p->f[fs[j]].np)
				held = 0;
		if (!held)
			add_set(m, out, &a[i]);
	}
	for (j = 0; j < nf; j++) {
		for (i = 0; i < e->na && i < m->p->f[fs[j]].np; i++)
			add_set(m, &m->edge[SLOT_P(fs[j], i) - 1000], &a[i]);
		pset_add(out, SLOT_R(fs[j]));
	}
}

static void m_stmt(struct model *m, int fn, const struct stmt *s)
{
	struct pset v;

	memset(&v, 0, sizeof v);
	switch (s->k) {
	case S_ASSIGN:
	case S_FIELD:
		m_ex(m, fn, s->e, &v);
		add_set(m, &m->defs[scope_of(m, fn, s->var)][s->var], &v);
		break;
	case S_SINK:
		m_ex(m, fn, s->e, &v);
		link_to(m, s->node, &v, m->d->snk_cap == KGENOME_NUCLEO_EXEC_IMAGE ? KGENOME_DIAG_ROLE_PATH : KGENOME_DIAG_ROLE_VALUE);
		break;
	case S_RET:
		m_ex(m, fn, s->e, &v);
		add_set(m, &m->edge[SLOT_R(fn) - 1000], &v);
		break;
	case S_CALL:
		m_ex(m, fn, s->e, &v);
		break;
	default:
		break;
	}
}

static void m_fn(struct model *m, int fi)
{
	struct func *f = &m->p->f[fi];
	int i;

	for (i = 0; i < f->np; i++)
		pset_add(&m->defs[fi][f->par[i]], SLOT_P(fi, i));
	for (i = 0; i < f->nst; i++) {
		if (f->st[i].k == S_DEF)
			m_fn(m, f->st[i].fn);
		else
			m_stmt(m, fi, &f->st[i]);
	}
}

/* The reals a slot reaches through the edges, a slot met twice followed once. */
static void closure(const struct model *m, int slot, struct pset *reals, int *seen)
{
	int i;

	if (seen[slot - 1000])
		return;
	seen[slot - 1000] = 1;
	for (i = 0; i < m->edge[slot - 1000].n; i++) {
		int v = m->edge[slot - 1000].v[i];

		if (v >= 1000)
			closure(m, v, reals, seen);
		else
			pset_add(reals, v);
	}
}

static void run_model(struct model *m, struct prog *p, const struct dial *d)
{
	int i, j, k;
	int seen[3000];

	memset(m, 0, sizeof *m);
	m->p = p;
	m->d = d;
	for (i = 0; i < p->nord; i++) {
		if (p->order[i][0] == 0 && p->f[p->order[i][1]].parent <= 0)
			m_fn(m, p->order[i][1]);
		else if (p->order[i][0] == 1)
			m_stmt(m, 0, &p->f[0].st[p->order[i][1]]);
	}
	for (i = 0; i < m->npend; i++) {
		struct pset reals;

		memset(&reals, 0, sizeof reals);
		memset(seen, 0, sizeof seen);
		closure(m, m->pend[i].slot, &reals, seen);
		for (j = 0; j < reals.n; j++)
			if (reals.v[j] != m->pend[i].to && !m->link[m->pend[i].to][reals.v[j]]) {
				m->link[m->pend[i].to][reals.v[j]] = 2;
				m->role[m->pend[i].to][reals.v[j]] = (unsigned char)m->pend[i].role;
			}
	}
	for (i = 0; i < MAXN; i++) {
		for (j = k = 0; j < MAXN; j++)
			k += m->link[i][j] != 0;
		if (k > 4)
			m->bad = 1;
	}
	for (i = 0; i < MAXF; i++)
		for (j = 0; j < NPOOL; j++) {
			int nr = 0, ns = 0;

			for (k = 0; k < m->defs[i][j].n; k++)
				if (m->defs[i][j].v[k] < 1000)
					nr++;
				else
					ns++;
			if (nr > 6 || ns > 4)
				m->bad = 1;
		}
}

/* ---- the comparison ---------------------------------------------------------------------------------------------------- */

static int compare(const struct model *m, const struct prog *p, const struct dial *d, const char *src)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = d->lang };
	struct kgenome_diag_scan *s = kgenome_diag_scan_text(&rq);
	uint32_t i, cnt;
	int ok = 1, k;
	unsigned char seen[MAXN][MAXN];

	memset(seen, 0, sizeof seen);
	if (!s) {
		printf("  no scan\n");
		return 0;
	}
	cnt = kgenome_diag_scan_count(s);
	if (cnt != (uint32_t)p->nn) {
		printf("  %s: %u nodes, the model has %d\n", d->name, cnt, p->nn);
		ok = 0;
	}
	for (i = 0; ok && i < cnt; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		if (h->cap != p->cap[i]) {
			printf("  %s: node %u is %s, the model says %s\n", d->name, i, kgenome_nucleo_cap_name(h->cap), kgenome_nucleo_cap_name(p->cap[i]));
			ok = 0;
		}
		for (k = 0; ok && k < h->n_in; k++) {
			uint16_t from = h->in[k].from;
			int want = from < MAXN ? m->link[i][from] : 0;
			int is_may = h->in[k].how == KGENOME_DIAG_LINK_MAY;

			if (!want || h->in[k].kind != KGENOME_DIAG_KIND_PRODUCED || (want == 2) != is_may || h->in[k].role != m->role[i][from]) {
				printf("  %s: link %u <- %u (role %u, %s) is not what the model has (%d)\n", d->name, i, from, h->in[k].role, is_may ? "may" : "must", want);
				ok = 0;
			} else {
				seen[i][from] = 1;
			}
		}
	}
	for (i = 0; ok && i < (uint32_t)p->nn; i++)
		for (k = 0; k < p->nn; k++)
			if (m->link[i][k] && !seen[i][k]) {
				printf("  %s: the model's link %u <- %u (%s) is missing\n", d->name, i, k, m->link[i][k] == 2 ? "may" : "must");
				ok = 0;
			}
	CK(kgenome_diag_scan_status(s) == KGENOME_OK || !ok, "status");
	kgenome_diag_scan_free(s);
	return ok;
}

/* ---- literal cases ----------------------------------------------------------------------------------------------------- */

/* One written program of a dialect and the links it must have, as "to<-from:m" (must) or ":y" (may), node numbers in the order the names are written. */
struct lit {
	const char *what;
	int         dial;
	const char *src;
	const char *links;
};

static const struct lit L[] = {
	/* php: a parameter reaches the sink in the body; the producer is at the call */
	{ "param", 0, "<?php function run($c) { system($c); } run(base64_decode('x'));", "0<-1:y" },
	/* a call that comes before the definition */
	{ "defined after", 0, "<?php run(base64_decode('x')); function run($c) { system($c); }", "1<-0:y" },
	/* a return: what the function returns reaches the sink at the call */
	{ "return", 0, "<?php function get() { return base64_decode('x'); } system(get());", "1<-0:y" },
	/* a parameter never given a value, and a function never called: no link */
	{ "never called", 0, "<?php function run($c) { system($c); } base64_decode('x');", "" },
	/* fan-in: both call sites reach the one sink (context insensitive) */
	{ "fan-in", 0, "<?php function run($c) { system($c); } run(base64_decode('x')); run(gzinflate('y'));", "0<-1:y 0<-2:y" },
	/* the parameter passed on through a second function */
	{ "passed on", 0, "<?php function a($p) { b($p); } function b($q) { system($q); } a(base64_decode('x'));", "0<-1:y" },
	/* recursion and mutual recursion end */
	{ "recursion", 0, "<?php function r($c, $d) { system($c); r($d, $c); } r(base64_decode('x'), gzinflate('y'));", "0<-1:y 0<-2:y" },
	{ "mutual", 0, "<?php function a($p) { b($p); } function b($q) { system($q); a($q); } a(base64_decode('x'));", "0<-1:y" },
	/* a variable of the same name in another function is another variable */
	{ "shadow", 0, "<?php function f($v) { system($v); } function g() { $v = base64_decode('x'); } f(gzinflate('y'));", "0<-2:y" },
	/* what flows through a call of a function the text defines is what it RETURNS, so it is may (G3: it was must, because the call's result was made of every argument); a call nothing is
	 * known about stands for its arguments and that stays must (the walk's own rule) */
	{ "call result", 0, "<?php function id($a) { return $a; } $v = id(base64_decode('x')); system($v);", "1<-0:y" },
	{ "ignored argument", 0, "<?php function g($a, $b) { return $b; } $v = g(base64_decode('x'), 'k'); system($v);", "" },
	{ "second argument", 0, "<?php function g($a, $b) { return $b; } $v = g('k', base64_decode('x')); system($v);", "1<-0:y" },
	{ "extra argument", 0, "<?php function g($a) { return func_get_args(); } $v = g('k', base64_decode('x')); system($v);", "1<-0" },
	{ "unknown call", 0, "<?php $v = strtolower(base64_decode('x')); system($v);", "1<-0" },
	{ "return only", 0, "<?php function mk() { return base64_decode('x'); } $v = mk(); system($v);", "1<-0:y" },
	/* python: an inner function hides the outer one of its name */
	{ "nested hides", 1, "def Fa0(a):\n    os.system(a)\ndef Fb1(z):\n    def Fa0(b):\n        pass\n    Fa0(base64.b64decode('x'))\nFa0(zlib.decompress('y'))\n", "0<-2:y" },
	/* vbscript: an undeclared name is the global one */
	{ "vbs global", 5, "Function f(a)\n    g = StrReverse(\"x\")\nEnd Function\nCall f(\"k\")\nExecute g\n", "1<-0" },
	{ "vbs dim", 5, "Function f(a)\n    Dim g\n    g = StrReverse(\"x\")\nEnd Function\nCall f(\"k\")\nExecute g\n", "" },
	{ "vbs return", 5, "Function f(a)\n    f = StrReverse(\"x\")\nEnd Function\nExecute f(\"k\")\n", "1<-0:y" },
	/* a member assignment gives the object what it is given and leaves its class alone: `s.Run` stays WScript.Shell.Run (nodes: the decode of the field, the run, the decode of its argument) */
	{ "com class kept", 5, "Set s = CreateObject(\"WScript.Shell\")\ns.Prop = StrReverse(\"x\")\ns.Run(StrReverse(\"y\"))\n", "1<-0 1<-2" },
	/* a pattern is a parameter too: it takes its place (js destructuring) */
	{ "pattern param", 2, "function f({a}, b) { eval(b); } f(atob('x'), atob('y'));", "0<-2:y" },
	/* a variable holding six nodes and a slot keeps its six nodes: the first four are the links the sink keeps */
	{ "slot room", 0, "<?php function g($p) { $v = base64_decode('1'); $v = base64_decode('2'); $v = base64_decode('3'); $v = base64_decode('4'); $v = base64_decode('5'); $v = base64_decode('6'); $v = $p; system($v); } g(gzinflate('x'));", "6<-0 6<-1 6<-2 6<-3" },
	/* an End of another block does not close the function */
	{ "vbs end if", 5, "Function f(a)\n    If a = \"k\" Then\n        g = StrReverse(\"x\")\n    End If\n    Execute a\nEnd Function\nCall f(StrReverse(\"y\"))\n", "1<-2:y" },
	/* the header of a function written as an expression is no call of it: h holds the function, not what it returns */
	{ "header is no call", 2, "var h = function Fz(a) { return atob('y'); }; eval(h);", "" },
	{ "vbs bare name", 5, "Function f()\n    f = StrReverse(\"x\")\nEnd Function\nExecute f\n", "1<-0:y" },
	/* c#: braces on their own lines; a field assignment gives the object what it is given */
	{ "allman", 6, "<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\nstring F(string a)\n{\n    Process.Start(a);\n    return a;\n}\nvoid Page_Load()\n{\n    F(Convert.FromBase64String(\"x\"));\n}\n</script>\n", "0<-1:y" },
	{ "field", 6, "<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\nvoid Page_Load()\n{\n    string p = \"x\";\n    p.Arguments = Convert.FromBase64String(\"x\");\n    Process.Start(p);\n}\n</script>\n", "1<-0" },
};

static int parse_links(const char *s, int to[], int from[], int may[])
{
	int n = 0;

	while (*s) {
		int t, f;
		char c = 0;
		int used = 0;

		while (*s == ' ')
			s++;
		if (!*s)
			break;
		if (sscanf(s, "%d<-%d%n", &t, &f, &used) < 2)
			break;
		s += used;
		if (*s == ':')
			c = s[1], s += 2;
		to[n] = t;
		from[n] = f;
		may[n++] = c == 'y';
	}
	return n;
}

static void literal_cases(void)
{
	size_t i;

	for (i = 0; i < sizeof L / sizeof L[0]; i++) {
		const struct dial *d = &D[L[i].dial];
		struct kgenome_diag_text_req rq = { .base = (const uint8_t *)L[i].src, .size = strlen(L[i].src), .lang = d->lang };
		struct kgenome_diag_scan *s = kgenome_diag_scan_text(&rq);
		int to[16], from[16], may[16], n = parse_links(L[i].links, to, from, may), k, j, have = 0;
		uint32_t h;

		CK(s != NULL, "%s: a scan", L[i].what);
		if (!s)
			continue;
		for (h = 0; h < kgenome_diag_scan_count(s); h++)
			have += kgenome_diag_scan_at(s, h)->n_in;
		CK(have == n, "%s (%s): %d links, wanted %d", L[i].what, d->name, have, n);
		for (k = 0; k < n; k++) {
			const struct kgenome_diag_hit *hit = (uint32_t)to[k] < kgenome_diag_scan_count(s) ? kgenome_diag_scan_at(s, (uint32_t)to[k]) : NULL;
			int found = 0;

			for (j = 0; hit && j < hit->n_in; j++)
				if (hit->in[j].from == from[k] && hit->in[j].kind == KGENOME_DIAG_KIND_PRODUCED &&
				    (hit->in[j].how == KGENOME_DIAG_LINK_MAY) == (may[k] != 0))
					found = 1;
			CK(found, "%s (%s): the link %d <- %d (%s) is not there", L[i].what, d->name, to[k], from[k], may[k] ? "may" : "must");
		}
		kgenome_diag_scan_free(s);
	}
}

int main(int argc, char **argv)
{
	int per = argc > 1 ? atoi(argv[1]) : 300, di, done[8] = { 0 }, skipped = 0, with_links[8] = { 0 }, with_may[8] = { 0 };
	static struct prog p;
	static struct model m;
	static struct rctx r;
	static char buf[16384];

	if (argc > 2)
		rs = (uint32_t)strtoul(argv[2], NULL, 10);
	literal_cases();
	for (di = 0; di < (int)(sizeof D / sizeof D[0]); di++) {
		int tries = 0;

		while (done[di] < per && tries < per * 20) {
			int i, j, nl_ = 0, nm = 0;

			tries++;
			gen_prog(&p, &D[di]);
			render(&r, &p, &D[di], buf, sizeof buf);
			run_model(&m, &p, &D[di]);
			if (m.bad || p.nn > MAXN - 1) {
				skipped++;
				continue;
			}
			done[di]++;
			for (i = 0; i < MAXN; i++)
				for (j = 0; j < MAXN; j++) {
					nl_ += m.link[i][j] != 0;
					nm += m.link[i][j] == 2;
				}
			with_links[di] += nl_ > 0;
			with_may[di] += nm > 0;
			if (!compare(&m, &p, &D[di], buf)) {
				printf("--- %s program %d:\n%s\n", D[di].name, done[di], buf);
				fails++;
				if (fails > 3)
					goto out;
			}
		}
		CK(done[di] == per, "%s: only %d of %d programs fit the bounds", D[di].name, done[di], per);
	}
out:
	for (di = 0; di < (int)(sizeof D / sizeof D[0]); di++)
		printf("%-7s %4d programs, %4d with a link, %4d with a may link\n", D[di].name, done[di], with_links[di], with_may[di]);
	printf("regenerated (outside the lib's bounds): %d\n", skipped);
	printf(fails ? "FAILED: %d\n" : "diag_text_sum_gen: ok\n", fails);
	return fails != 0;
}
