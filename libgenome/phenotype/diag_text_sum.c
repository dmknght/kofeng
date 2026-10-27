/*
 * diag_text_sum.c - THE FUNCTIONS A SCRIPT DEFINES, and what flows through them: parameter summaries and the return flow of the TEXT route.
 *
 * WHY. The walk follows a value from the node that made it to the call that takes it, through nesting and assignment, in textual order. A user
 * function cut that: `function run($c) { system($c); }` called as `run($_POST['x'])` has the request in one place and the command in another, and the
 * only link between them is the call. Measured (the corpora of the TEXT route, 2026-10-21, before this file): the four classic-asp/aspx shells whose
 * command goes through a function (asp 015_newaspcmd, aspx 009_aspx_bypass_av, 019_cmdasp, 075_cmdasp) had both nodes and no link, and a python
 * wrapper `def run(cmd): subprocess.call(cmd, shell=True)` fed by urlopen had a fetch and a process start and no link.
 *
 * WHAT IT IS. A SUMMARY, not an inlining and not a second walk. A function's parameter, read inside its body, holds a PLACEHOLDER PRODUCER (a slot at
 * or above KGENOME_DTX_PSEUDO, one per parameter): it flows wherever the parameter's value does, through variables and into the arguments of calls, like
 * a node. A call of a function the file defines records, for each argument, the producers that flowed into it (an EDGE slot <- producer); a `return`
 * records the producers of its expression the same way into the function's RETURN slot, and the call, once its bracket closes, produces that slot where
 * it stands. A link whose producer is a slot is kept (PENDING) until the walk has read the whole file - a function may be defined after its call - and then
 * made from every producer the slot reaches through the edges, following a slot given to another function's call (a parameter passed on) and a slot
 * returned through another call. A producer reached twice is followed once, so recursion and mutual recursion end.
 *
 * WHAT A CALL STANDS FOR. A call of a function the text defines stands for what the function RETURNS - the return slot, flowing where the call stands once its bracket closes -
 * and not for the arguments a parameter holds: `function g($a, $b) { return $b; }` makes `g($_GET[0], 'x')` carry nothing of the request (G3; the call's result was made of every
 * argument, the rule for a call nothing is known about). An argument no parameter holds (past the list, a pattern, a function with no list: php's func_get_args() reads it some way
 * the summary does not follow) is carried as before: dropping it would delete evidence for a reading this file cannot rule out. What this costs, and is said: a link through a
 * function whose parameter reaches the return is now the context-insensitive union of every caller's argument (MAY), where it was this call's own argument; a node keeps four inputs,
 * so which four of the union survive is the order the resolution makes them in.
 *
 * WHAT IT MEANS, AND WHAT IT DOES NOT. The summary is CONTEXT INSENSITIVE: a function called with A at one call and with B at another gives the producers of
 * both to every link its parameter feeds, and no control flow is read (a literal overwrite does not kill a producer: measured, killing one without a
 * CFG lost 331 php links of which 18 of 24 read were real). So a link made here is a MAY link - true for at least one call, not shown for all - and is
 * marked KGENOME_DIAG_LINK_MAY in `how`; a link the walk makes by nesting or assignment stays PROVEN. Nothing here makes a node: a callee that only a
 * summary could name (a parameter called as `$f(...)`) has no node, because the nodes are made while the walk reads.
 *
 * NOT READ, and said where it is not: a function called through a member (`$o->run($x)`, `self.run(x)`), by a value (`$f($x)` where $f is not a constant
 * name), or with `call_user_func`; a parameter named by `@_` (perl: the row has no parameter list, so only the return flow applies); the arguments past
 * the ones a function names (python `*args`); a function a program builds at run time.
 *
 * COST. Nothing is allocated for a text without a function that has a name or a parameter. The function table is by scope id, the names are hashed, the
 * edges and the pending links are sets keyed by value (a repeat is not stored), and the resolution is bounded by the text's size and reports
 * KGENOME_TRUNCATED when it stops: a bound on cost that says so (rule 4).
 */

#include <stdlib.h>
#include <string.h>

#include <kofcmp.h>
#include "diag_text_walk.h"

struct sum_fn {
	uint32_t name_tok;      /* the token of its name, 0 for a function that has none (an anonymous one that nothing names) */
	uint32_t same;          /* the next function of the same name, 0 none */
	uint32_t p0, np;        /* its parameters: pool[p0 .. p0 + np) */
	uint32_t lo, hi;        /* the tokens its parameter list occupies (a parameter is declared by one of them), lo > hi when it has none */
	uint32_t depth;         /* the functions it is written inside */
};

struct sum_edge {
	uint32_t pseudo, def, next;
};

struct sum_pend {
	uint32_t pseudo, to, role;
};

struct kgenome_dtx_sum {
	struct sum_fn   *fn;            /* by scope id (the function a token is in is `scope[token]`): [0] is the top of the file and has none. It grows with the functions found: a
					 * text counts every "{" a possible function (a method is `name(...) {`), and almost none is one */
	uint32_t         nfn;           /* the highest id of a function found: ids 1..nfn all are */
	uint32_t         cfn;           /* ids allocated */
	uint8_t          first[32];     /* the bytes a function's name begins with, and the lengths names have: a call of any other is told by two tests, without the hash */
	uint8_t          minlen, maxlen;
	uint32_t        *pool;          /* the name token of every parameter of every function, 0 for one the walk gives no value (a pattern) */
	uint32_t         np, cpool;
	uint32_t        *nh;            /* name -> first function of the name (open addressing, its id; the others of the name follow by `same`) */
	uint32_t         nhcap, nnamed;
	struct sum_edge *e;
	uint32_t         ne, ce;
	struct sum_pend *pp;
	uint32_t         npp, cpp;
	uint64_t        *set;           /* edges and pending links already kept: a repeat is not stored */
	uint32_t         setcap, nset;
};

/* ---- the tables -------------------------------------------------------------------------------------------- */

static int charge(struct kgenome_dtx *x, uint64_t n)
{
	return kgenome_dtx_charge(x, n);
}

int kgenome_dtx_grow(struct kgenome_dtx *x, void **p, uint32_t *cap, uint32_t need, size_t elem)
{
	uint32_t nc = *cap ? *cap : 32u;
	void *nv;

	if (need <= *cap)
		return 1;
	while (nc < need)
		nc *= 2u;
	if (!charge(x, (uint64_t)(nc - *cap) * elem))
		return 0;
	nv = realloc(*p, (size_t)nc * elem);
	if (!nv) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		return 0;
	}
	*p = nv;
	*cap = nc;
	return 1;
}

int kgenome_dtx_sum_new(struct kgenome_dtx *x)
{
	struct kgenome_dtx_sum *s;

	if (!charge(x, sizeof *s))
		return 0;
	s = calloc(1, sizeof *s);
	if (!s) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		return 0;
	}
	s->minlen = 255u;
	x->sum = s;
	return 1;
}

void kgenome_dtx_sum_free(struct kgenome_dtx *x)
{
	struct kgenome_dtx_sum *s = x->sum;

	if (!s)
		return;
	if (x->lay)
		x->lay->work.edges += s->ne;
	free(s->fn);
	free(s->pool);
	free(s->nh);
	free(s->e);
	free(s->pp);
	free(s->set);
	free(s);
	x->sum = NULL;
}

static uint32_t set_hash(void *ctx, const void *slot)
{
	(void)ctx;
	return kof_hash64_slot(*(const uint64_t *)slot);
}

/* A set of 64-bit keys (never 0): 1 when `k` was new. The tables above and the pending links stay small because a repeat is dropped here. */
static int set_add(struct kgenome_dtx *x, struct kgenome_dtx_sum *s, uint64_t k)
{
	uint32_t i;

	if (!kgenome_dtx_oa_grow(x, (void **)&s->set, &s->setcap, s->nset, 256u, sizeof *s->set, set_hash))
		return 0;
	for (i = kof_hash64_slot(k) & (s->setcap - 1u); s->set[i]; i = kgenome_oatab_next(i, s->setcap), x->probes++)
		if (s->set[i] == k)
			return 0;
	s->set[i] = k;
	s->nset++;
	return 1;
}

#define KEY_EDGE(p, d)     ((1ull << 63) | ((uint64_t)(p) << 32) | (uint32_t)(d))
#define KEY_PEND(p, t, r)  (((uint64_t)(p) << 24) | ((uint64_t)(t) << 8) | (uint64_t)(r))

/* ---- names ------------------------------------------------------------------------------------------------- */

static int name_same(const struct kgenome_dtx *x, uint32_t tok, const uint8_t *p, uint32_t n)
{
	return x->t[tok].len == n && kgenome_dtx_name_eq(x->in + x->t[tok].off, p, n, x->lang->fold);
}

/* The first function of the name p/n (the rest by `same`), 0 for none. */
static uint32_t name_find(struct kgenome_dtx *x, const uint8_t *p, uint32_t n)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t i;

	if (!s || !s->nhcap || n < s->minlen || n > s->maxlen)
		return 0;
	{
		uint8_t c = p[0];

		if (x->lang->fold)
			c = kof_lower_byte(c);
		if (!(s->first[c >> 3] >> (c & 7u) & 1u))
			return 0;
	}
	for (i = kgenome_dtx_name_hash(x->seed, p, n, x->lang->fold) & (s->nhcap - 1u); s->nh[i]; i = kgenome_oatab_next(i, s->nhcap), x->probes++)
		if (name_same(x, s->fn[s->nh[i]].name_tok, p, n))
			return s->nh[i];
	return 0;
}

/* The hash of the function a slot of `nh` holds, by its name in the text. */
static uint32_t nh_hash(void *ctx, const void *slot)
{
	const struct kgenome_dtx *x = ctx;
	const struct sum_fn *g = &x->sum->fn[*(const uint32_t *)slot];

	return kgenome_dtx_name_hash(x->seed, x->in + x->t[g->name_tok].off, x->t[g->name_tok].len, x->lang->fold);
}

static int name_insert(struct kgenome_dtx *x, uint32_t id)
{
	struct kgenome_dtx_sum *s = x->sum;
	struct sum_fn *f = &s->fn[id];
	const uint8_t *p = x->in + x->t[f->name_tok].off;
	uint32_t n = x->t[f->name_tok].len, i;

	if (!kgenome_dtx_oa_grow(x, (void **)&s->nh, &s->nhcap, s->nnamed, 64u, sizeof *s->nh, nh_hash))
		return 0;
	for (i = kgenome_dtx_name_hash(x->seed, p, n, x->lang->fold) & (s->nhcap - 1u); s->nh[i]; i = kgenome_oatab_next(i, s->nhcap), x->probes++) {
		uint32_t first = s->nh[i];

		if (name_same(x, s->fn[first].name_tok, p, n)) {      /* a second function of the name: it joins the chain */
			f->same = s->fn[first].same;
			s->fn[first].same = id;
			return 1;
		}
	}
	s->nh[i] = id;
	s->nnamed++;
	{
		uint8_t c = p[0];

		if (x->lang->fold)
			c = kof_lower_byte(c);
		s->first[c >> 3] = (uint8_t)(s->first[c >> 3] | 1u << (c & 7u));
		if (n < s->minlen)
			s->minlen = (uint8_t)(n > 255u ? 255u : n);
		if (n > s->maxlen)
			s->maxlen = (uint8_t)(n > 255u ? 255u : n);
	}
	return 1;
}

/* ---- the functions the scope pass found ----------------------------------------------------------------------- */

static int is_name_tok(const struct kgenome_dtx *x, uint32_t i)
{
	return i < x->nt && (x->t[i].k == 'I' || x->t[i].k == 'V') && x->t[i].len && !kof_is_digit(x->in[x->t[i].off]);
}

/*
 * THE NAME A FUNCTION IS CALLED BY. `function NAME(`, `def NAME(`, `Function NAME(` and a method written `NAME(...) {` have it in front of the parameter list
 * (a name that is a member - `function M.run(a)` of lua - is a method of something and is called through it, so it has none). A function with no list takes the word
 * after its keyword (perl's `sub name {`). A function written as an expression is called by the name it is assigned to where the language keeps variables and
 * functions in one space (js `const run = (c) => ..`, `var f = function (a) ..`, lua): not php, whose `$f = function` is a variable called through `$f(`.
 */
static uint32_t fn_name(const struct kgenome_dtx *x, uint32_t kw, uint32_t par, uint32_t from)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t start = from ? from : kw, nt = 0;

	if (!from && par && par >= 1u && par - 1u != kw)
		nt = par - 1u;
	else if (!from && !par && kw + 1u < x->nt && x->t[kw].k == 'I' && ((l->fn_kw && kgenome_dtx_is_word(x, kw, l->fn_kw)) || (l->fn_kw2 && kgenome_dtx_is_word(x, kw, l->fn_kw2))))
		nt = kw + 1u;
	if (nt) {
		if (!is_name_tok(x, nt) || kgenome_dtx_member(x, nt))
			return 0;
		return nt;
	}
	/* anonymous: named by the variable it is assigned to */
	if (!l->sigil && start >= 2u && kgenome_dtx_is_p(x, start - 1u, '=') && !kgenome_dtx_is_p(x, start - 2u, '=') && is_name_tok(x, start - 2u) &&
	    !kgenome_dtx_member(x, start - 2u))
		return start - 2u;
	return 0;
}

static int pool_put(struct kgenome_dtx *x, struct kgenome_dtx_sum *s, uint32_t tok)
{
	if (!kgenome_dtx_grow(x, (void **)&s->pool, &s->cpool, s->np + 1u, sizeof *s->pool))
		return 0;
	s->pool[s->np++] = tok;
	return 1;
}

/*
 * THE PARAMETERS of the list whose "(" is `par` (or the one name of an arrow `a => ..`, token `from`): one per top-level comma, named by the last name in its segment that is
 * not after a default value (`=`) or a type word the language puts after the name (`As`); a bracket inside a segment is skipped (a default value, a destructuring pattern, an array
 * type) and so are the commas inside the `<...>` of a generic type where the language writes typed declarations. A segment that has no such name (a pattern) still occupies its place,
 * with token 0: the arguments are matched by position and a skipped one would shift every later one.
 */
static int params(struct kgenome_dtx *x, struct kgenome_dtx_sum *s, struct sum_fn *f, uint32_t par, uint32_t from)
{
	uint32_t end, k, name = 0, angle = 0;
	int have = 0, stop = 0, any = 0;

	f->p0 = s->np;
	f->lo = 1u;
	f->hi = 0u;
	if (!par) {
		if (from && is_name_tok(x, from) && x->t[from].k == 'V') {
			f->np = 1;
			f->lo = f->hi = from;
			return pool_put(x, s, from);
		}
		return 1;
	}
	end = (uint32_t)x->match[par];
	f->lo = par + 1u;
	f->hi = end;
	for (k = par + 1u; k <= end; k++) {
		int boundary = k == end || (kgenome_dtx_is_p(x, k, ',') && !angle);

		if (boundary) {
			if (have || any) {
				if (!pool_put(x, s, have ? name : 0u))
					return 0;
				f->np++;
			}
			have = 0;
			any = 0;
			stop = 0;
			name = 0;
			continue;
		}
		any = 1;
		if ((kgenome_dtx_is_p(x, k, '(') || kgenome_dtx_is_p(x, k, '[') || kgenome_dtx_is_p(x, k, '{')) && x->match[k] > 0) {
			k = (uint32_t)x->match[k];
			continue;
		}
		if (x->lang->typed_decl && kgenome_dtx_is_p(x, k, '<'))
			angle++;
		else if (x->lang->typed_decl && kgenome_dtx_is_p(x, k, '>') && angle)
			angle--;
		if (stop)
			continue;
		if (kgenome_dtx_is_p(x, k, '=') || (x->t[k].k == 'I' && kgenome_dtx_is_word(x, k, "as"))) {
			stop = 1;
			continue;
		}
		if (x->t[k].k == 'V' || (x->t[k].k == 'I' && is_name_tok(x, k))) {
			name = k;
			have = x->t[k].k == 'V';           /* a word that is no variable (a type) is not the name: `string $c`, `String c` */
		}
	}
	return 1;
}

int kgenome_dtx_sum_fn(struct kgenome_dtx *x, uint32_t id, uint32_t kw, uint32_t par, uint32_t from, uint32_t depth)
{
	struct kgenome_dtx_sum *s = x->sum;
	struct sum_fn *f;

	if (id >= s->cfn) {
		uint32_t old = s->cfn;

		if (!kgenome_dtx_grow(x, (void **)&s->fn, &s->cfn, id + 1u, sizeof *s->fn))
			return 0;
		memset(s->fn + old, 0, (size_t)(s->cfn - old) * sizeof *s->fn);
	}
	f = &s->fn[id];
	f->name_tok = fn_name(x, kw, par, from);
	f->depth = depth;
	if (!params(x, s, f, par, from))
		return 0;
	if (id > s->nfn)
		s->nfn = id;
	return f->name_tok ? name_insert(x, id) : 1;
}

/* ---- what the walk asks ------------------------------------------------------------------------------------------ */

uint32_t kgenome_dtx_sum_param(const struct kgenome_dtx *x, uint32_t tok)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t id, k;

	if (!s)
		return 0;
	id = x->scope[tok];
	if (!id || id > s->nfn || tok < s->fn[id].lo || tok > s->fn[id].hi)       /* a token outside the list of the function it is in is no declaration */
		return 0;
	for (k = 0; k < s->fn[id].np; k++)
		if (s->pool[s->fn[id].p0 + k] == tok)
			return KGENOME_DTX_PSEUDO + s->fn[id].p0 + k;
	return 0;
}

/* Is a function written in scope `from` visible at a call written in scope `cs`: the call is in it or inside it. */
static int visible(struct kgenome_dtx *x, uint32_t home, uint32_t cs)
{
	uint32_t n = 0;

	for (;;) {
		if (cs == home)
			return 1;
		if (!cs || !x->sparent)
			return 0;
		if (++n > 4096u) {              /* functions nested deeper than the walk up to the one a call sees: the call is not matched to it, and it is said */
			kgenome_dtx_cut(x);
			return 0;
		}
		cs = x->sparent[cs];
	}
}

/* The innermost depth among the visible functions of a chain: a function written nearer the call hides a same-named one outside (the languages that nest them); 0 where the row
 * says functions are not lexical (php's are global whatever they are written in). */
static uint32_t best_depth(struct kgenome_dtx *x, uint32_t head, uint32_t cs)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t f, best = 0;

	if (!x->lang->lexical)
		return 0;
	for (f = head; f; f = s->fn[f].same)
		if (visible(x, x->sparent ? x->sparent[f] : 0u, cs) && s->fn[f].depth + 1u > best)
			best = s->fn[f].depth + 1u;
	return best;
}

static int takes(struct kgenome_dtx *x, uint32_t f, uint32_t cs, uint32_t best)
{
	if (!x->lang->lexical)
		return 1;
	return visible(x, x->sparent ? x->sparent[f] : 0u, cs) && x->sum->fn[f].depth + 1u == best;
}

/*
 * The functions a variable that holds a constant name calls: `$f = 'run'; $f($x)` (the row says a variable holding a string is called by it, `string_call`). The value is the
 * evaluator's, so a name the program built (`'ru' . 'n'`) is the same name. Not a class (`new $c(`) and not a member (`$o->$f(`).
 */
static uint32_t callee_by_value(struct kgenome_dtx *x, uint32_t nt)
{
	struct kgenome_dtx_val val;
	struct kgenome_dtx_var *v;
	uint32_t used, head = 0;
	int built = 0;

	if (!x->lang->string_call || x->t[nt].k != 'V' || kgenome_dtx_member(x, nt) || (nt >= 1u && x->t[nt - 1u].k == 'I' && kgenome_dtx_is_word(x, nt - 1u, "new")))
		return 0;
	v = kgenome_dtx_var_for(x, nt, &used, 0);
	if (!v || v->unknown || !kgenome_dtx_eval_var(x, v, &val, &built))
		return 0;
	if (val.n && val.n < KGENOME_DTX_NAME)
		head = name_find(x, val.p, val.n);
	kgenome_dtx_val_free(&val);
	return head;
}

uint32_t kgenome_dtx_sum_callee(struct kgenome_dtx *x, uint32_t open)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t nt, f, head;

	if (!s || !open)
		return 0;
	nt = open - 1u;
	if (x->t[nt].k == 'V')
		return s->nnamed ? callee_by_value(x, nt) : 0u;
	if (x->t[nt].k != 'I')
		return 0;
	head = name_find(x, x->in + x->t[nt].off, x->t[nt].len);       /* the length and the first byte say no for almost every call, before anything else is asked */
	if (!head || !is_name_tok(x, nt) || kgenome_dtx_member(x, nt))
		return 0;
	for (f = head; f; f = s->fn[f].same)
		if (s->fn[f].name_tok == nt)
			return 0;               /* the definition's own header, not a call of it */
	if (x->lang->lexical && kgenome_dtx_declared(x, x->scope[open], x->in + x->t[nt].off, x->t[nt].len))
		return 0;               /* a parameter holding a function: a call of a value */
	return head;
}

/*
 * A NAME READ ON ITS OWN THAT IS A FUNCTION THE TEXT DEFINES, in a language whose functions are also variables of their own name (vbscript: `http.Open method, FullUrl, False`
 * calls FullUrl with no argument and no bracket): the first of its name. The old reading - a function that assigns its own name made a global variable of that name - gave this read
 * the value the function assigned, and the links through it must stay (measured: the asp proxy shells lost the request -> http-connect links when functions got a scope).
 * 0 for the header of the definition itself, for a name a parameter or a `Dim` made a variable of the function, and for a member.
 */
uint32_t kgenome_dtx_sum_bare_callee(struct kgenome_dtx *x, uint32_t tok)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t head, f;

	if (!s || !s->nnamed || kgenome_dtx_member(x, tok))
		return 0;
	head = name_find(x, x->in + x->t[tok].off, x->t[tok].len);
	for (f = head; f; f = s->fn[f].same)
		if (s->fn[f].name_tok == tok)
			return 0;
	if (head && x->scope[tok] && kgenome_dtx_declared(x, x->scope[tok], x->in + x->t[tok].off, x->t[tok].len))
		return 0;
	return head;
}

/* Is the variable token `i` the name of the function it is written in (vbscript returns a value by assigning it). */
int kgenome_dtx_sum_own_name(const struct kgenome_dtx *x, uint32_t i)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t id = x->scope[i];

	return s && id && id <= s->nfn && s->fn[id].name_tok && name_same(x, s->fn[id].name_tok, x->in + x->t[i].off, x->t[i].len);
}

/*
 * HOW MANY EDGES (and pending links) THE SUMMARIES MAY KEEP, as a function of the text: a few for every token and a floor. A call of a name that F functions of the text share gives
 * the arguments of every call to every one of them, so F definitions and C calls are F*C edges (G11: 600 and 600 were 360000 edges for 46 KB, and 4000 and 4000 ran the ledger out),
 * which is a product of two counts the file chooses. A text whose relations need more than this says so (TRUNCATED) and the edges past it are not kept; the links already made stay.
 * [Measured over 3604 script files (s3, dx_malc, wpcheck, smp, 600 of dx_benfarm, 150 of each language list), the unfixed code: at most 0.025 edges a byte (adminer-4.8.1: 7974 for 317 KB); the
 * bound is 8 a token and 4096, which for text that averages three bytes a token is above two a byte.]
 */
#define SUM_EDGES_PER_TOKEN 8u
#define SUM_EDGES_FLOOR     4096u

static int room_for(struct kgenome_dtx *x, uint32_t have)
{
	if (have < SUM_EDGES_FLOOR + SUM_EDGES_PER_TOKEN * x->nt)
		return 1;
	kgenome_dtx_cut(x);
	return 0;
}

static void edge_add(struct kgenome_dtx *x, uint32_t pseudo, uint32_t def)
{
	struct kgenome_dtx_sum *s = x->sum;

	if (!room_for(x, s->ne) || !set_add(x, s, KEY_EDGE(pseudo, def)) || !kgenome_dtx_grow(x, (void **)&s->e, &s->ce, s->ne + 1u, sizeof *s->e))
		return;
	s->e[s->ne].pseudo = pseudo;
	s->e[s->ne].def = def;
	s->e[s->ne++].next = 0;
}

void kgenome_dtx_sum_arg(struct kgenome_dtx *x, uint32_t head, uint32_t cs, uint32_t arg, int32_t node, const struct kgenome_dtx_var *v)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t f, best = best_depth(x, head, cs);

	for (f = head; f; f = s->fn[f].same) {
		uint32_t pseudo, k;

		if (arg >= s->fn[f].np || !s->pool[s->fn[f].p0 + arg] || !takes(x, f, cs, best))
			continue;
		pseudo = KGENOME_DTX_PSEUDO + s->fn[f].p0 + arg;
		if (node >= 0)
			edge_add(x, pseudo, (uint32_t)node);
		for (k = 0; v && k < kgenome_dtx_var_nprod(v); k++)
			edge_add(x, pseudo, kgenome_dtx_var_prod(v, k));
	}
}

/*
 * IS ARGUMENT `arg` OF THIS CALL HELD BY A PARAMETER of every function it can reach: then what flows into it reaches the call's result only through the function's own return (the
 * slot the call stands for once its bracket closes), and not as the call's own operand. `function g($a, $b) { return $b; } system(g($_GET[0], 'x'))` passes nothing to system: the
 * summary says $a is read and not returned (G3: the call's result was made of ALL its arguments, the rule for a call nothing is known about).
 *
 * Not bound, and so carried as before: an argument past the parameters the function names (php's func_get_args(), js's `arguments`, python's *args are read some way the summary does
 * not follow, and the argument may reach the result by it: dropping the link would delete evidence for a reading this file cannot rule out), a parameter that is a pattern, a function
 * with no parameter list (perl's `@_`). Where any function of the name has no parameter for it, none is assumed.
 */
int kgenome_dtx_sum_bound(struct kgenome_dtx *x, uint32_t head, uint32_t cs, uint32_t arg)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t f, best = best_depth(x, head, cs);
	int any = 0;

	for (f = head; f; f = s->fn[f].same) {
		if (!takes(x, f, cs, best))
			continue;
		any = 1;
		if (arg >= s->fn[f].np || !s->pool[s->fn[f].p0 + arg])
			return 0;
	}
	return any;
}

uint32_t kgenome_dtx_sum_ret_slot(const struct kgenome_dtx *x, uint32_t fn)
{
	return KGENOME_DTX_PSEUDO + x->sum->np + fn;
}

void kgenome_dtx_sum_ret(struct kgenome_dtx *x, uint32_t fn, int32_t node, const struct kgenome_dtx_var *v)
{
	uint32_t slot = kgenome_dtx_sum_ret_slot(x, fn), k;

	if (node >= 0)
		edge_add(x, slot, (uint32_t)node);
	for (k = 0; v && k < kgenome_dtx_var_nprod(v); k++)
		edge_add(x, slot, kgenome_dtx_var_prod(v, k));
}

/* The call whose chain starts at `head`, written in scope `cs`, has closed: what its functions return is the value of the call. */
void kgenome_dtx_sum_call_value(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t head, uint32_t cs)
{
	const struct kgenome_dtx_sum *s = x->sum;
	uint32_t f, best = best_depth(x, head, cs);

	for (f = head; f; f = s->fn[f].same)
		if (takes(x, f, cs, best))
			kgenome_dtx_flow(x, w, (int32_t)kgenome_dtx_sum_ret_slot(x, f), NULL);
}

void kgenome_dtx_sum_pend(struct kgenome_dtx *x, uint32_t pseudo, uint32_t to, uint8_t role)
{
	struct kgenome_dtx_sum *s = x->sum;

	if (!room_for(x, s->npp) || !set_add(x, s, KEY_PEND(pseudo, to, role)) || !kgenome_dtx_grow(x, (void **)&s->pp, &s->cpp, s->npp + 1u, sizeof *s->pp))
		return;
	s->pp[s->npp].pseudo = pseudo;
	s->pp[s->npp].to = to;
	s->pp[s->npp++].role = role;
}

/* ---- resolution ----------------------------------------------------------------------------------------------------- */

/* A link made from a summary: it is true for at least one call, and `how` says so. A link that was already there (made by the walk, PROVEN) stays what it was. */
static void note_may(struct kgenome_dtx *x, uint32_t to, uint32_t from, uint8_t role)
{
	struct kgenome_diag_hit *h = kgenome_diag_hit_of(x->s, to);
	uint8_t n;

	if (!h || from == to)
		return;
	n = h->n_in;
	kgenome_diag_note_in(x->s, h, (uint16_t)from, role, KGENOME_DIAG_KIND_PRODUCED);
	if (h->n_in > n)
		h->in[n].how = KGENOME_DIAG_LINK_MAY;
}

static int pend_before(const void *a, const void *b)
{
	const struct sum_pend *p = a, *q = b;

	return p->pseudo != q->pseudo ? (p->pseudo < q->pseudo ? -1 : 1) : 0;
}

/*
 * Every pending link, made. They are grouped by the slot they came from, so the producers a slot reaches are found ONCE for all the links it feeds: a depth-first walk over the
 * edges, a slot met twice not followed again, the nodes it reaches collected. The work (edges followed and links offered) is bounded by the text; one that runs out is reported.
 */
/* KNOWN DEFECT G3-GEL4Y (2026-10-24, R) [sev M]: kgenome_dtx_sum_resolve links a call result only through the callee's return slot (G3, strict) and a node keeps four inputs, so which four of a context-insensitive union survive is the resolution order.
 * Trigger: php/053_gel4y.php L133 `$loc=$p."/".nhx($_GET[n])` -> L134 unlink($loc): nhx() has many callers whose arguments fill the four inputs first. Effect: the expected MAY link request -> file-delete is lost.
 * Reproducer: tests/data/diag_text_expect.tsv row for 053_gel4y.php L133 (run by diag_text_relations). Fix: call-site-sensitive resolution, or order the MAY inputs nearest-first (new link power, later). */
void kgenome_dtx_sum_resolve(struct kgenome_dtx *x)
{
	struct kgenome_dtx_sum *s = x->sum;
	uint32_t slots, i, g, *head = NULL, *seen = NULL, *stk = NULL, *reals = NULL, *rseen = NULL, gen = 0, nstk, nreal;
	uint64_t work = 0, cap;

	if (!s || !s->npp)
		return;
	slots = s->np + s->nfn + 1u;
	cap = 4096u + 64ull * x->nt;
	if (!charge(x, (uint64_t)slots * 2u * sizeof *head + (uint64_t)(s->ne + 1u) * sizeof *stk + (uint64_t)(x->s->n_hit + 1u) * 2u * sizeof *reals))
		return;
	head = calloc(slots, sizeof *head);
	seen = calloc(slots, sizeof *seen);
	stk = malloc(((size_t)s->ne + 1u) * sizeof *stk);
	reals = malloc(((size_t)x->s->n_hit + 1u) * sizeof *reals);
	rseen = calloc((size_t)x->s->n_hit + 1u, sizeof *rseen);
	if (!head || !seen || !stk || !reals || !rseen) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		goto out;
	}
	for (i = 0; i < s->ne; i++) {                   /* the edges of a slot, as a list (the 0 of head is "none": an edge is its index + 1) */
		uint32_t k = s->e[i].pseudo - KGENOME_DTX_PSEUDO;

		s->e[i].next = head[k];
		head[k] = i + 1u;
	}
	qsort(s->pp, s->npp, sizeof *s->pp, pend_before);
	for (g = 0; g < s->npp;) {
		uint32_t gend = g, root = s->pp[g].pseudo, j, n;

		while (gend < s->npp && s->pp[gend].pseudo == root)
			gend++;
		gen++;
		nstk = 0;
		nreal = 0;
		stk[nstk++] = root - KGENOME_DTX_PSEUDO;
		seen[root - KGENOME_DTX_PSEUDO] = gen;
		while (nstk) {
			uint32_t k = stk[--nstk], e;

			for (e = head[k]; e; e = s->e[e - 1u].next) {
				uint32_t d = s->e[e - 1u].def;

				if (++work > cap)
					goto cut;
				if (d >= KGENOME_DTX_PSEUDO) {
					uint32_t kk = d - KGENOME_DTX_PSEUDO;

					if (kk < slots && seen[kk] != gen) {
						seen[kk] = gen;
						stk[nstk++] = kk;
					}
				} else if (d < x->s->n_hit && rseen[d] != gen) {
					rseen[d] = gen;
					reals[nreal++] = d;
				}
			}
		}
		qsort(reals, nreal, sizeof *reals, kof_cmp_u32);   /* textual order: the same links whichever way the edges were found */
		for (j = g; j < gend; j++) {
			for (n = 0; n < nreal; n++) {
				if (++work > cap)
					goto cut;
				note_may(x, s->pp[j].to, reals[n], (uint8_t)s->pp[j].role);
			}
		}
		g = gend;
	}
	goto out;
cut:
	kgenome_diag_note(x->s, KGENOME_TRUNCATED);      /* the work bound: the links made so far are kept and the answer says it is partial */
out:
	free(head);
	free(seen);
	free(stk);
	free(reals);
	free(rseen);
}
