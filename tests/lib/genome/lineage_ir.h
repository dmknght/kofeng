/*
 * lineage_ir.h - the lineage tests' program model: a tiny structured language, a random generator of
 * programs in it, and the ORACLE - a concrete interpreter that runs every behaviour a program can have and
 * writes down which producer's value arrived at which argument of which call.
 *
 * WHY THE ORACLE IS AN INTERPRETER AND NOT ANOTHER DATAFLOW ANALYSIS. A second analysis written by the
 * same hand would share the first one's blind spots and agree with it where both are wrong. The
 * interpreter has no lattice and no join: a value is the number of the call that made it, a variable is
 * a cell, and every `if` and every `while` is explored both ways (a loop up to LG_ITER iterations) by
 * enumerating the sequence of decisions. What the analysis claims MUST is what every execution agrees on;
 * what it claims MAY is what some execution does. Nothing is shared with the engine but the vocabulary (which
 * name is which capability, which argument has which role), which the tests assert first.
 *
 * THE LANGUAGE (everything a generated program does, and what the engine is specified to follow):
 *   expressions   a local, a parameter, a constant, a call of an API (a node), a call of a function of the
 *                 program, a global, a field of the one heap object, an unknown value (an import with no
 *                 capability), a pointer plus an offset, a call through a pointer
 *   statements    local = E, global = E, object.field = E, E, if (unknown) {} else {}, while (unknown) {},
 *                 return E, return F(...) as a tail jump
 * The program's values are the calls that made them. A constant, an unknown and a call through a pointer
 * make a value no call made: OTHER.
 *
 * WHAT THE ORACLE DOES NOT KNOW, ON PURPOSE (and the generator keeps programs inside it): the engine
 * names a heap field by the NODE that made the object, so two objects of one allocation site share their
 * fields; a global written by a callee is not seen by its caller; calls through pointers are not followed.
 * The generator allocates the one object once, in the entry function, before any branch, touches a global
 * from one function only, and never emits a call through a pointer that a function of the program could
 * be the target of. Inside those bounds the oracle is EXACT, and the test compares link for link.
 */
#ifndef KGENOME_TESTS_LINEAGE_IR_H
#define KGENOME_TESTS_LINEAGE_IR_H

#include <stdint.h>
#include <string.h>

#define LG_MAXF     4
#define LG_MAXV     6
#define LG_MAXG     3
#define LG_MAXP     2
#define LG_MAXEX    256
#define LG_MAXST    192
#define LG_MAXBLK   40
#define LG_BLKST    12
#define LG_MAXSITE  56
#define LG_ITER     3       /* iterations of a loop the oracle explores: past the longest chain a generated body carries */
#define LG_DEPTH    2       /* activations of one function at a time the oracle follows (a function that calls itself) */
#define LG_OTHER    63      /* a value no call made and nothing says what it is */
#define LG_CONSTV   61      /* ... or one that is a known constant: nothing to look for, and not an unknown */
#define LG_UNDEF    60      /* what a function that falls off its end returns: the program does not say */
#define LG_BOT      62      /* what a call cut at the recursion bound returns: no value, and no path (nothing it carries is counted) */

enum lg_api { LG_NONE = 0, LG_SOCKET, LG_ACCEPT, LG_MALLOC, LG_CONNECT, LG_LISTEN, LG_BIND, LG_READ, LG_WRITE,
	      LG_NAPI };

/* How many arguments of an API the program supplies (the rest are constants the code generator adds), and which of them carry a role. */
struct lg_apiinfo {
	int nargs;
	int produces;
	int roled;                      /* bit i: argument i has a role */
};

static const struct lg_apiinfo lg_api[LG_NAPI] = {
	{ 0, 0, 0 },
	{ 0, 1, 0 },    /* socket   */
	{ 1, 1, 1 },    /* accept   */
	{ 0, 1, 0 },    /* malloc   */
	{ 1, 0, 1 },    /* connect  */
	{ 1, 0, 1 },    /* listen   */
	{ 1, 0, 1 },    /* bind     */
	{ 2, 0, 3 },    /* read     */
	{ 2, 0, 3 }     /* write    */
};

enum lg_ek { LG_E_VAR, LG_E_PARAM, LG_E_CONST, LG_E_API, LG_E_CALL, LG_E_GLOBAL, LG_E_FIELD, LG_E_UNK, LG_E_ICALL,
	     LG_E_DERIVE,
	     LG_E_BYTE,         /* the low byte written: no longer the value it was */
	     LG_E_STALE,        /* an argument register left as the last call left it: nothing a call may count on */
	     LG_E_ARITH };      /* the value times three: arithmetic, no longer a producer (hand-written programs only) */

struct lg_expr {
	int kind;
	int x;                          /* variable, parameter, global, field, api, callee */
	int arg[2];                     /* expressions; -1 for none */
	int nargs;
	int site;                       /* an API call's number */
};

enum lg_sk { LG_S_ASSIGN, LG_S_GSTORE, LG_S_FSTORE, LG_S_EVAL, LG_S_IF, LG_S_WHILE, LG_S_RET, LG_S_TAIL };

struct lg_stmt {
	int kind;
	int x;                          /* variable, global or field */
	int e;                          /* expression, -1 for none */
	int a, b;                       /* blocks: then/else, or body */
};

struct lg_block {
	int st[LG_BLKST];
	int n;
};

struct lg_fn {
	int nparams;
	int body, dead;                 /* blocks; dead is -1 or code nothing reaches */
	int halts;                      /* the function never returns: its body ends in `ud2` (hand-written programs only) */
};

struct lg_prog {
	struct lg_fn fn[LG_MAXF];
	int nf;
	struct lg_expr ex[LG_MAXEX];
	int nex;
	struct lg_stmt st[LG_MAXST];
	int nst;
	struct lg_block blk[LG_MAXBLK];
	int nblk;
	int nsite;
	int site_api[LG_MAXSITE];       /* the api of each call */
	int g_owner[LG_MAXG];
	int ng;
	int has_obj;                    /* the entry function allocates the one object, in variable 0 */
	int ctl;                        /* if and while statements so far */
	int bad;                        /* the generator ran out of room: discard */
};

/* Which of the language the program may use. */
enum { LG_F_MEM = 1, LG_F_CALL = 2, LG_F_LOOP = 4, LG_F_DEAD = 8, LG_F_ICALL = 16, LG_F_TAIL = 32, LG_F_REC = 64,
       LG_F_DEEP = 128 };   /* a call through a pointer where arguments are being built: an i386 stack that cannot be followed */

struct lg_rng { uint64_t s; };

static LA_UNUSED uint32_t lg_rnd(struct lg_rng *r, uint32_t n)
{
	r->s ^= r->s << 13;
	r->s ^= r->s >> 7;
	r->s ^= r->s << 17;
	return n ? (uint32_t)(r->s % n) : 0u;
}

/* ---- the generator ---- */

static LA_UNUSED int lg_ex(struct lg_prog *p, int kind, int x, int a0, int a1, int nargs)
{
	struct lg_expr *e;

	if (p->nex >= LG_MAXEX) {
		p->bad = 1;
		return 0;
	}
	e = &p->ex[p->nex];
	e->kind = kind;
	e->x = x;
	e->arg[0] = a0;
	e->arg[1] = a1;
	e->nargs = nargs;
	e->site = -1;
	return p->nex++;
}

static LA_UNUSED int lg_st(struct lg_prog *p, int kind, int x, int e, int a, int b)
{
	struct lg_stmt *s;

	if (p->nst >= LG_MAXST) {
		p->bad = 1;
		return 0;
	}
	s = &p->st[p->nst];
	s->kind = kind;
	s->x = x;
	s->e = e;
	s->a = a;
	s->b = b;
	return p->nst++;
}

static LA_UNUSED int lg_newblk(struct lg_prog *p)
{
	if (p->nblk >= LG_MAXBLK) {
		p->bad = 1;
		return 0;
	}
	p->blk[p->nblk].n = 0;
	return p->nblk++;
}

static LA_UNUSED void lg_add(struct lg_prog *p, int blk, int st)
{
	struct lg_block *b = &p->blk[blk];

	if (b->n >= LG_BLKST) {
		p->bad = 1;
		return;
	}
	b->st[b->n++] = st;
}

struct lg_gen {
	struct lg_prog *p;
	struct lg_rng *r;
	unsigned feat;
	int fi;                         /* the function being generated */
	int dead;                       /* inside code nothing reaches: only the safe constructs */
};

static LA_UNUSED int lg_gen_expr(struct lg_gen *g, int depth);

/* An API call expression: its arguments are expressions of their own. */
static LA_UNUSED int lg_gen_api(struct lg_gen *g, int api, int depth)
{
	struct lg_prog *p = g->p;
	int a[2] = { -1, -1 }, i, e;

	for (i = 0; i < lg_api[api].nargs; i++)
		a[i] = lg_rnd(g->r, 16u) == 0 && !g->dead ? lg_ex(p, LG_E_STALE, 0, -1, -1, 0) : lg_gen_expr(g, depth + 1);
	e = lg_ex(p, LG_E_API, api, a[0], a[1], lg_api[api].nargs);
	if (p->nsite >= LG_MAXSITE) {
		p->bad = 1;
		return e;
	}
	p->ex[e].site = p->nsite;
	p->site_api[p->nsite++] = api;
	return e;
}

static LA_UNUSED int lg_gen_expr(struct lg_gen *g, int depth)
{
	struct lg_prog *p = g->p;
	struct lg_rng *r = g->r;
	unsigned k = lg_rnd(r, 100u);

	if (depth >= 2)
		k = lg_rnd(r, 45u);                     /* leaves only */
	if (k < 28u)
		return lg_ex(p, LG_E_VAR, (int)lg_rnd(r, LG_MAXV - 1u) + (p->has_obj && g->fi == 0 ? 1 : 0), -1, -1, 0);
	if (k < 36u && p->fn[g->fi].nparams > 0 && !g->dead)
		return lg_ex(p, LG_E_PARAM, (int)lg_rnd(r, (uint32_t)p->fn[g->fi].nparams), -1, -1, 0);
	if (k < 40u)
		return lg_ex(p, LG_E_CONST, 0, -1, -1, 0);
	if (k < 45u)
		return lg_ex(p, LG_E_UNK, 0, -1, -1, 0);
	if (k < 62u) {
		/* a producer, or - now and then - a consumer used as a value: what it returns is nobody's result */
		static const int cons[] = { LG_CONNECT, LG_LISTEN, LG_BIND, LG_READ, LG_WRITE };
		int api = lg_rnd(r, 8u) == 0 ? cons[lg_rnd(r, sizeof cons / sizeof cons[0])]
			: (int)lg_rnd(r, 3u) == 0 ? LG_MALLOC : (lg_rnd(r, 4u) == 0 ? LG_ACCEPT : LG_SOCKET);

		return lg_gen_api(g, api, depth);
	}
	if (k < 72u && (g->feat & LG_F_CALL) && !g->dead && g->fi + 1 < g->p->nf) {
		int callee = g->fi + 1 + (int)lg_rnd(r, (uint32_t)(g->p->nf - g->fi - 1));
		int a[2] = { -1, -1 }, i;

		for (i = 0; i < p->fn[callee].nparams; i++)
			a[i] = lg_gen_expr(g, depth + 1);
		return lg_ex(p, LG_E_CALL, callee, a[0], a[1], p->fn[callee].nparams);
	}
	if (k < 80u && (g->feat & LG_F_MEM) && !g->dead) {
		int own[LG_MAXG], n = 0, i;

		for (i = 0; i < p->ng; i++)
			if (p->g_owner[i] == g->fi)
				own[n++] = i;
		if (n)
			return lg_ex(p, LG_E_GLOBAL, own[lg_rnd(r, (uint32_t)n)], -1, -1, 0);
		if (p->has_obj && g->fi == 0)
			return lg_ex(p, LG_E_FIELD, (int)lg_rnd(r, 3u), -1, -1, 0);
	}
	if (k < 83u)
		return lg_ex(p, LG_E_BYTE, 0, lg_gen_expr(g, depth + 1), -1, 1);
	if (k < 86u)
		return lg_ex(p, LG_E_DERIVE, 0, lg_gen_expr(g, depth + 1), -1, 1);
	/* A call through a pointer only where nothing is being built for another call: its callee pops an unknown number of
	 * words, and an i386 stack with words pending cannot be followed past it - the engine says the stack pointer is
	 * unknown there (diag_lineage_state.c), which is not what this test is about. */
	if (k < 90u && (g->feat & LG_F_ICALL) && (depth == 0 || (g->feat & LG_F_DEEP)))
		return lg_ex(p, LG_E_ICALL, 0, lg_gen_expr(g, depth + 1), -1, 1);
	return lg_ex(p, LG_E_VAR, (int)lg_rnd(r, LG_MAXV - 1u) + (p->has_obj && g->fi == 0 ? 1 : 0), -1, -1, 0);
}

static LA_UNUSED int lg_gen_consumer(struct lg_gen *g)
{
	static const int cs[] = { LG_CONNECT, LG_LISTEN, LG_BIND, LG_READ, LG_WRITE, LG_READ, LG_CONNECT };

	return lg_gen_api(g, cs[lg_rnd(g->r, sizeof cs / sizeof cs[0])], 0);
}

static LA_UNUSED int lg_gen_block(struct lg_gen *g, int depth, int n, int allow_ret);

static LA_UNUSED int lg_gen_stmt(struct lg_gen *g, int depth, int last)
{
	struct lg_prog *p = g->p;
	struct lg_rng *r = g->r;
	unsigned k = lg_rnd(r, 100u);
	const int var0 = p->has_obj && g->fi == 0 && !g->dead ? 1 : 0;    /* variable 0 is the object */

	if (k < 36u)
		return lg_st(p, LG_S_ASSIGN, (int)lg_rnd(r, LG_MAXV - 1u) + var0, lg_gen_expr(g, 0), 0, 0);
	if (k < 68u)
		return lg_st(p, LG_S_EVAL, 0, lg_gen_consumer(g), 0, 0);
	if (k < 78u && (g->feat & LG_F_MEM) && !g->dead) {
		int own[LG_MAXG], n = 0, i;

		for (i = 0; i < p->ng; i++)
			if (p->g_owner[i] == g->fi)
				own[n++] = i;
		if (n)
			return lg_st(p, LG_S_GSTORE, own[lg_rnd(r, (uint32_t)n)], lg_gen_expr(g, 0), 0, 0);
		if (var0)
			return lg_st(p, LG_S_FSTORE, (int)lg_rnd(r, 3u), lg_gen_expr(g, 0), 0, 0);
	}
	if (k < 86u && p->ctl < 3 && depth < 2) {
		int a, b;
		int cond;

		p->ctl++;
		cond = lg_ex(p, LG_E_UNK, 0, -1, -1, 0);
		a = lg_gen_block(g, depth + 1, 1 + (int)lg_rnd(r, 3u), 0);
		b = lg_rnd(r, 2u) ? lg_gen_block(g, depth + 1, 1 + (int)lg_rnd(r, 2u), 0) : -1;
		return lg_st(p, LG_S_IF, 0, cond, a, b);
	}
	if (k < 91u && p->ctl < 3 && depth < 2 && (g->feat & LG_F_LOOP)) {
		int a;
		int cond;

		p->ctl++;
		cond = lg_ex(p, LG_E_UNK, 0, -1, -1, 0);
		a = lg_gen_block(g, depth + 1, 1 + (int)lg_rnd(r, 3u), 0);
		return lg_st(p, LG_S_WHILE, 0, cond, a, -1);
	}
	if (last && !g->dead && k < 97u)
		return lg_st(p, LG_S_RET, 0, lg_gen_expr(g, 0), 0, 0);
	return lg_st(p, LG_S_EVAL, 0, lg_gen_expr(g, 0), 0, 0);
}

static LA_UNUSED int lg_gen_block(struct lg_gen *g, int depth, int n, int allow_ret)
{
	int blk = lg_newblk(g->p), i;

	for (i = 0; i < n && !g->p->bad; i++)
		lg_add(g->p, blk, lg_gen_stmt(g, depth, allow_ret && i + 1 == n));
	return blk;
}

/* Generate a program. `feat` is what the language may use. */
static LA_UNUSED void lg_generate(struct lg_prog *p, struct lg_rng *r, unsigned feat)
{
	struct lg_gen g;
	int i, j;

	memset(p, 0, sizeof *p);
	g.p = p;
	g.r = r;
	g.feat = feat;
	g.dead = 0;
	p->nf = (feat & LG_F_CALL) ? 1 + (int)lg_rnd(r, 3u) : 1;
	/* the entry function takes parameters too: nothing proves what its caller - the loader - passes */
	for (i = 0; i < p->nf; i++)
		p->fn[i].nparams = (int)lg_rnd(r, LG_MAXP + 1u);
	if (feat & LG_F_MEM) {
		p->ng = 1 + (int)lg_rnd(r, 2u);
		for (i = 0; i < p->ng; i++)
			p->g_owner[i] = (int)lg_rnd(r, (uint32_t)p->nf);
		p->has_obj = (int)lg_rnd(r, 2u);
	}
	for (i = 0; i < p->nf && !p->bad; i++) {
		int body;

		g.fi = i;
		g.dead = 0;
		body = lg_newblk(p);
		if (i == 0 && p->has_obj) {
			/* the one object, allocated once, before any branch, into variable 0 */
			int e = lg_gen_api(&g, LG_MALLOC, 0);

			lg_add(p, body, lg_st(p, LG_S_ASSIGN, 0, e, 0, 0));
			/* and its fields filled at once, so reading one back says which one it was */
			for (j = 0; j < 3 && (feat & LG_F_MEM); j++)
				lg_add(p, body, lg_st(p, LG_S_FSTORE, j, lg_gen_expr(&g, 1), 0, 0));
		}
		if (i == 0)
			for (j = 1; j < p->nf; j++) {
				/* every other function is called, in live code, from the entry */
				int a[2] = { -1, -1 }, q;

				for (q = 0; q < p->fn[j].nparams; q++)
					a[q] = lg_gen_expr(&g, 1);
				lg_add(p, body, lg_st(p, LG_S_EVAL, 0, lg_ex(p, LG_E_CALL, j, a[0], a[1], p->fn[j].nparams), 0, 0));
			}
		{
			int n = 2 + (int)lg_rnd(r, 4u), k;

			for (k = 0; k < n && !p->bad; k++)
				lg_add(p, body, lg_gen_stmt(&g, 0, k + 1 == n));
		}
		p->fn[i].body = body;
		p->fn[i].dead = -1;
		if ((feat & LG_F_DEAD) && lg_rnd(r, 2u)) {
			g.dead = 1;
			p->fn[i].dead = lg_gen_block(&g, 0, 2 + (int)lg_rnd(r, 3u), 0);
			g.dead = 0;
		}
		/* a function of the program may be tail-called with nothing left to do */
		if ((feat & LG_F_TAIL) && i + 1 < p->nf && lg_rnd(r, 3u) == 0 && p->blk[body].n < LG_BLKST - 1 &&
		    p->st[p->blk[body].st[p->blk[body].n - 1]].kind != LG_S_RET) {
			int callee = i + 1 + (int)lg_rnd(r, (uint32_t)(p->nf - i - 1)), a[2] = { -1, -1 }, q;

			for (q = 0; q < p->fn[callee].nparams; q++)
				a[q] = lg_gen_expr(&g, 1);
			lg_add(p, body, lg_st(p, LG_S_TAIL, 0, lg_ex(p, LG_E_CALL, callee, a[0], a[1], p->fn[callee].nparams), 0, 0));
		}
	}
	if (feat & LG_F_REC) {
		/* a function that calls itself, guarded: if (unknown) f(params...) - added where it cannot end a block early */
		int f = (int)lg_rnd(r, (uint32_t)p->nf), a[2] = { -1, -1 }, q, then, cond;

		g.fi = f;
		/* (not the entry function when it holds the object: that is allocated before any branch) */
		if ((f || !p->has_obj) && p->blk[p->fn[f].body].n < LG_BLKST - 1) {
			for (q = 0; q < p->fn[f].nparams; q++)
				a[q] = lg_ex(p, LG_E_PARAM, q, -1, -1, 0);
			then = lg_newblk(p);
			/* a call whose result is dropped, or one that is the function's own result */
			lg_add(p, then, lg_st(p, lg_rnd(r, 2u) ? LG_S_EVAL : LG_S_RET, 0,
					      lg_ex(p, LG_E_CALL, f, a[0], a[1], p->fn[f].nparams), 0, 0));
			cond = lg_ex(p, LG_E_UNK, 0, -1, -1, 0);
			/* before the final statements, so it is live whatever follows */
			{
				struct lg_block *b = &p->blk[p->fn[f].body];

				memmove(&b->st[1], &b->st[0], (size_t)b->n * sizeof b->st[0]);
				b->st[0] = lg_st(p, LG_S_IF, 0, cond, then, -1);
				b->n++;
			}
		}
	}
}

/* ---- the oracle: every behaviour of the program ---- */

struct lg_oracle {
	const struct lg_prog *p;
	uint64_t obs[LG_MAXSITE][3];    /* the values that arrived at an argument: a bit for each producing call, LG_OTHER for none */
	uint8_t  unc[LG_MAXSITE][3];    /* some of them arrived through code nothing reaches */
	int      summ, mem, seed;
	/* the walk of the decisions */
	uint8_t  dec[512], arity[512];
	int      nd, di;
	int      act[LG_MAXF], seeded, cut;
	long     runs;
};

static LA_UNUSED int lg_choose(struct lg_oracle *o, int arity)
{
	int v;

	if (o->di < o->nd) {
		v = o->dec[o->di];
	} else {
		if (o->nd >= (int)sizeof o->dec) {
			o->cut = 1;
			return 0;
		}
		o->dec[o->nd] = 0;
		o->arity[o->nd++] = (uint8_t)arity;
		v = 0;
	}
	o->di++;
	return v;
}

static LA_UNUSED int lg_next_path(struct lg_oracle *o)
{
	while (o->nd > 0 && o->dec[o->nd - 1] + 1 >= o->arity[o->nd - 1])
		o->nd--;
	if (!o->nd)
		return 0;
	o->dec[o->nd - 1]++;
	return 1;
}

/*
 * ONE ACTIVATION of a function. A global and a field of the object are followed INSIDE a function body and nowhere else
 * (a callee's write is not seen by its caller, a caller's earlier invocation is not seen by the next): each activation
 * has its own copy of them, unknown at the entry. That is what the engine is specified to do, so it is what the oracle
 * means by them - the generator keeps a global to one function so the specification is all there is to disagree on.
 */
struct lg_act {
	int fi;
	int par[LG_MAXP];
	int loc[LG_MAXV];
	int gl[LG_MAXG], fld[3];
	int ret, returned;
};

static LA_UNUSED void lg_act_init(struct lg_act *a, int fi)
{
	int i;

	memset(a, 0, sizeof *a);
	a->fi = fi;
	for (i = 0; i < LG_MAXP; i++)
		a->par[i] = LG_OTHER;
	for (i = 0; i < LG_MAXV; i++)
		a->loc[i] = LG_OTHER;
	for (i = 0; i < LG_MAXG; i++)
		a->gl[i] = LG_OTHER;
	for (i = 0; i < 3; i++)
		a->fld[i] = LG_OTHER;
	a->ret = LG_UNDEF;
}

static LA_UNUSED int lg_eval(struct lg_oracle *o, struct lg_act *a, int e);
static LA_UNUSED void lg_block_run(struct lg_oracle *o, struct lg_act *a, int blk);

static LA_UNUSED int lg_run_fn(struct lg_oracle *o, int fi, const int *par)
{
	struct lg_act a;
	int i;

	lg_act_init(&a, fi);
	for (i = 0; i < LG_MAXP && par; i++)
		a.par[i] = par[i];
	lg_block_run(o, &a, o->p->fn[fi].body);
	return a.ret;
}

static LA_UNUSED int lg_eval(struct lg_oracle *o, struct lg_act *a, int e)
{
	const struct lg_expr *x;
	int v[2] = { LG_OTHER, LG_OTHER }, i;

	if (e < 0)
		return LG_OTHER;
	x = &o->p->ex[e];
	switch (x->kind) {
	case LG_E_VAR:
		return a->loc[x->x];
	case LG_E_PARAM:
		return a->par[x->x];
	case LG_E_CONST:
		return LG_CONSTV;
	case LG_E_UNK:
	case LG_E_STALE:
		return LG_OTHER;
	case LG_E_BYTE:
	case LG_E_ARITH:
		(void)lg_eval(o, a, x->arg[0]);
		return LG_OTHER;
	case LG_E_GLOBAL:
		return o->mem ? a->gl[x->x] : LG_OTHER;
	case LG_E_FIELD:
		return o->mem ? a->fld[x->x] : LG_OTHER;
	case LG_E_DERIVE:
		return lg_eval(o, a, x->arg[0]);
	case LG_E_ICALL:
		(void)lg_eval(o, a, x->arg[0]);
		return LG_OTHER;
	case LG_E_API:
		for (i = 0; i < x->nargs; i++) {
			v[i] = lg_eval(o, a, x->arg[i]);
			if ((lg_api[x->x].roled & (1 << i)) && v[i] != LG_BOT) {
				o->obs[x->site][i] |= 1ull << v[i];
				if (o->seeded)
					o->unc[x->site][i] = 1;
			}
		}
		return lg_api[x->x].produces ? x->site : LG_OTHER;
	case LG_E_CALL: {
		int par[LG_MAXP] = { LG_OTHER, LG_OTHER };

		for (i = 0; i < x->nargs; i++)
			par[i] = lg_eval(o, a, x->arg[i]);
		/* a function that calls itself is followed two activations deep: what a third could add is what the second
		 * did, and its result is discarded by the shape the generator gives recursion (a guarded call as a statement) */
		if (!o->summ)
			return LG_OTHER;
		if (o->act[x->x] >= LG_DEPTH)
			return LG_BOT;
		o->act[x->x]++;
		i = lg_run_fn(o, x->x, par);
		o->act[x->x]--;
		if (o->p->fn[x->x].halts) {     /* the program does not come back from it: nothing after the call happens */
			a->returned = 1;
			a->ret = LG_BOT;
			return LG_BOT;
		}
		return i;
	}
	default:
		return LG_OTHER;
	}
}

static LA_UNUSED void lg_block_run(struct lg_oracle *o, struct lg_act *a, int blk)
{
	const struct lg_block *b = &o->p->blk[blk];
	int i;

	for (i = 0; i < b->n && !a->returned; i++) {
		const struct lg_stmt *s = &o->p->st[b->st[i]];

		switch (s->kind) {
		case LG_S_ASSIGN:
			a->loc[s->x] = lg_eval(o, a, s->e);
			break;
		case LG_S_GSTORE:
			{
				int v = lg_eval(o, a, s->e);

				if (o->mem)
					a->gl[s->x] = v;
			}
			break;
		case LG_S_FSTORE:
			{
				int v = lg_eval(o, a, s->e);

				if (o->mem)
					a->fld[s->x] = v;
			}
			break;
		case LG_S_EVAL:
			(void)lg_eval(o, a, s->e);
			break;
		case LG_S_IF:
			if (lg_choose(o, 2))
				lg_block_run(o, a, s->a);
			else if (s->b >= 0)
				lg_block_run(o, a, s->b);
			break;
		case LG_S_WHILE: {
			int it;

			for (it = 0; it < LG_ITER && !a->returned && lg_choose(o, 2); it++)
				lg_block_run(o, a, s->a);
			break;
		}
		case LG_S_RET:
		case LG_S_TAIL:
			a->ret = lg_eval(o, a, s->e);
			a->returned = 1;
			break;
		default:
			break;
		}
	}
}

/* Every behaviour of one root: the function (with its parameters unknown), or a region nothing reaches. */
static LA_UNUSED void lg_explore(struct lg_oracle *o, int fi, int dead_region)
{
	o->nd = 0;
	o->cut = 0;
	do {
		o->di = 0;
		memset(o->act, 0, sizeof o->act);
		o->act[fi] = 1;
		o->seeded = dead_region;
		if (dead_region) {
			struct lg_act a;

			lg_act_init(&a, fi);
			lg_block_run(o, &a, o->p->fn[fi].dead);
		} else {
			(void)lg_run_fn(o, fi, NULL);
		}
		o->runs++;
	} while (lg_next_path(o) && o->runs < 400000);
}

/* The oracle of a program under a set of stages. */
static LA_UNUSED void lg_oracle(struct lg_oracle *o, const struct lg_prog *p, int summ, int mem, int seed)
{
	int i;

	memset(o, 0, sizeof *o);
	o->p = p;
	o->summ = summ;
	o->mem = mem;
	o->seed = seed;
	if (summ) {
		lg_explore(o, 0, 0);            /* every other function is called from the entry, in live code */
	} else {
		for (i = 0; i < p->nf; i++)
			lg_explore(o, i, 0);    /* each function on its own, with parameters nothing proves */
	}
	if (seed)
		for (i = 0; i < p->nf; i++)
			if (p->fn[i].dead >= 0)
				lg_explore(o, i, 1);
}

#endif /* KGENOME_TESTS_LINEAGE_IR_H */
