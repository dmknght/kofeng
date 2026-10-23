/*
 * diag_text_vars.c - THE VARIABLES OF THE TEXT ROUTE: the table the walk keeps, what a name is in the scope a token is in, and the producers a variable holds.
 *
 * A variable keeps where its value is written and who produced it, not the value (see struct kgenome_dtx_var): the evaluator makes a value when something asks. The table holds
 * pointers to variables that never move (the walk keeps one across the statements that follow); a name is looked up by the scope it is in, and the scope's aliases (`global`,
 * `use`, the parameters and the `Dim`s a function declares) say which scope's variable it is. Moved out of diag_text.c, whole, when the walk reached the file-size ceiling.
 */

#include <stdlib.h>

#include "diag_text_walk.h"

/* ---- variables ------------------------------------------------------------ */

/*
 * THE TABLE HOLDS POINTERS, and a variable never moves once it is made: the walk keeps a variable across the statements that follow (`w->av`,
 * the variable a call writes), and the table grows while it does - an array of the structs themselves was freed under the one being assigned
 * (a use after free, found on a minified js of 90 KB whose second assignment made the table grow).
 */
#define VAR_CHUNK 128u

struct kgenome_dtx_vchunk {
	struct kgenome_dtx_vchunk *next;
	uint32_t                   n;
	struct kgenome_dtx_var     v[VAR_CHUNK];
};

static struct kgenome_dtx_var *var_new(struct kgenome_dtx *x)
{
	struct kgenome_dtx_vchunk *c = x->vchunk;

	if (!c || c->n == VAR_CHUNK) {
		if (!kgenome_dtx_charge(x, sizeof *c))
			return NULL;
		c = calloc(1, sizeof *c);
		if (!c) {
			kgenome_diag_note(x->s, KGENOME_NOMEM);
			x->oom = 1;
			return NULL;
		}
		c->next = x->vchunk;
		x->vchunk = c;
	}
	return &c->v[c->n++];
}

static uint32_t var_hash(void *ctx, const void *slot)
{
	(void)ctx;
	return (*(struct kgenome_dtx_var *const *)slot)->hash;
}

static struct kgenome_dtx_var *var_find(struct kgenome_dtx *x, const uint8_t *p, uint32_t n, uint32_t scope, int make)
{
	uint32_t h = kgenome_dtx_name_hash(x->seed, p, n, x->lang->fold_vars) ^ (scope * 0x9e3779b1u), i;
	struct kgenome_dtx_var *v;

	if (make && !kgenome_dtx_oa_grow(x, (void **)&x->vt, &x->vcap, x->vn, 256u, sizeof *x->vt, var_hash))
		return NULL;
	if (!x->vcap)
		return NULL;
	for (i = h & (x->vcap - 1u); x->vt[i]; i = kgenome_oatab_next(i, x->vcap), x->probes++)
		if (x->vt[i]->hash == h && x->vt[i]->scope == scope && x->vt[i]->len == n && kgenome_dtx_name_eq(x->vt[i]->name, p, n, x->lang->fold_vars))
			return x->vt[i];
	if (!make)
		return NULL;
	v = var_new(x);
	if (!v)
		return NULL;
	v->name = p;
	v->len = n;
	v->hash = h;
	v->scope = scope;
	x->vt[i] = v;
	x->vn++;
	return v;
}

void kgenome_dtx_var_def(struct kgenome_dtx_var *v, uint32_t node)
{
	uint8_t i;

	if (node >= KGENOME_DTX_PSEUDO) {            /* a slot of a summary: its own list, so that it moves no node out of `def` */
		for (i = 0; i < v->n_pdef; i++)
			if (v->pdef[i] == node)
				return;
		if (v->n_pdef == KGENOME_DTX_PDEFS) {
			v->lost = 1;
			memmove(v->pdef, v->pdef + 1, (KGENOME_DTX_PDEFS - 1u) * sizeof v->pdef[0]);
			v->n_pdef--;
		}
		v->pdef[v->n_pdef++] = node;
		return;
	}
	for (i = 0; i < v->n_def; i++)
		if (v->def[i] == node)
			return;
	if (v->n_def == KGENOME_DTX_DEFS) {              /* the latest producers are the ones a use sees */
		v->lost = 1;
		memmove(v->def, v->def + 1, (KGENOME_DTX_DEFS - 1u) * sizeof v->def[0]);
		v->n_def--;
	}
	v->def[v->n_def++] = (uint16_t)node;
}

int kgenome_dtx_seg_add(struct kgenome_dtx *x, struct kgenome_dtx_var *v, uint32_t rs, uint32_t re)
{
	struct kgenome_dtx_seg *g;

	if (!kgenome_dtx_grow(x, (void **)&x->seg, &x->csegs, x->nsegs + 1u, sizeof *x->seg)) {
		v->unknown = 1;                 /* a right side it could not keep: not a value the program holds (the refusal is said by what refused) */
		return 0;
	}
	g = &x->seg[x->nsegs++];
	g->rs = rs;
	g->re = re;
	g->next = 0;
	if (v->seg_tail)
		x->seg[v->seg_tail - 1u].next = x->nsegs;
	else
		v->seg_head = x->nsegs;
	v->seg_tail = x->nsegs;
	v->nseg++;
	return 1;
}

void kgenome_dtx_seg_clear(struct kgenome_dtx_var *v)
{
	v->nseg = 0;
	v->seg_head = 0;
	v->seg_tail = 0;
}

uint32_t kgenome_dtx_var_key(const struct kgenome_dtx *x, uint32_t i, const uint8_t **name, uint32_t *len)
{
	const struct kgenome_dtx_tok *t = &x->t[i];

	/* a bare-variable language reads a name that is no call as a variable too: the callee `f` of `f(x)` is the variable f (data-call) */
	if (t->k != 'V' && !(t->k == 'I' && !x->lang->sigil && t->len && !kof_is_digit(x->in[t->off])))
		return 0;
	/* $GLOBALS['name'] is the global variable $name: the same variable under another spelling */
	if (x->lang->dyn_var && t->len == 7u && memcmp(x->in + t->off, "GLOBALS", 7u) == 0 && kgenome_dtx_is_p(x, i + 1u, '[') && i + 3u < x->nt &&
	    x->t[i + 2u].k == 'S' && kgenome_dtx_is_p(x, i + 3u, ']') && x->t[i + 2u].len > (uint32_t)x->t[i + 2u].open + x->t[i + 2u].close &&
	    !memchr(x->in + x->t[i + 2u].off + x->t[i + 2u].open, '\\', x->t[i + 2u].len - x->t[i + 2u].open - x->t[i + 2u].close)) {
		*name = x->in + x->t[i + 2u].off + x->t[i + 2u].open;
		*len = x->t[i + 2u].len - x->t[i + 2u].open - x->t[i + 2u].close;
		return 4u;
	}
	*name = x->in + t->off;
	*len = t->len;
	return 1u;
}

/* ---- the aliases ------------------------------------------------------------------ */

static uint32_t alias_hash_of(const struct kgenome_dtx *x, uint32_t scope, const uint8_t *nm, uint32_t nl)
{
	return kgenome_dtx_name_hash(x->seed, nm, nl, x->lang->fold_vars) ^ (scope * 0x9e3779b1u);
}

static uint32_t alias_slot_hash(void *ctx, const void *slot)
{
	const struct kgenome_dtx *x = ctx;

	return x->al[*(const uint32_t *)slot - 1u].hash;
}

/* The slot of the key (scope, name): the one that holds its newest alias, or the empty one it would go in. */
static uint32_t alias_slot(struct kgenome_dtx *x, uint32_t h, uint32_t scope, const uint8_t *nm, uint32_t nl)
{
	uint32_t i;

	for (i = h & (x->altcap - 1u); x->alt[i]; i = kgenome_oatab_next(i, x->altcap), x->probes++) {
		const struct kgenome_dtx_alias *a = &x->al[x->alt[i] - 1u];

		if (a->hash == h && a->scope == scope && a->len == nl && kgenome_dtx_name_eq(a->name, nm, nl, x->lang->fold_vars))
			break;
	}
	return i;
}

int kgenome_dtx_alias_add(struct kgenome_dtx *x, uint32_t scope, uint32_t tok, uint32_t target)
{
	struct kgenome_dtx_alias *a;
	const uint8_t *nm = x->in + x->t[tok].off;
	uint32_t nl = x->t[tok].len, h = alias_hash_of(x, scope, nm, nl), i;

	if (x->nal == x->cal) {
		uint32_t nc = x->cal ? x->cal * 2u : 32u;
		struct kgenome_dtx_alias *nv;

		if (!kgenome_dtx_charge(x, (uint64_t)(nc - x->cal) * sizeof *nv))
			return 0;
		nv = realloc(x->al, (size_t)nc * sizeof *nv);
		if (!nv) {
			kgenome_diag_note(x->s, KGENOME_NOMEM);
			x->oom = 1;
			return 0;
		}
		x->al = nv;
		x->cal = nc;
	}
	if (!kgenome_dtx_oa_grow(x, (void **)&x->alt, &x->altcap, x->nalt, 64u, sizeof *x->alt, alias_slot_hash))
		return 0;
	a = &x->al[x->nal];
	a->name = nm;
	a->len = nl;
	a->target = target;
	a->scope = scope;
	a->hash = h;
	i = alias_slot(x, h, scope, nm, nl);
	a->same = x->alt[i];                    /* the older alias of this key, or 0 when it is the first */
	x->nalt += x->alt[i] == 0;
	x->alt[i] = ++x->nal;
	return 1;
}

/* The newest alias of `name` written in scope `sc` that satisfies `self` (target == sc: a name the scope declared for itself) or any when `self` is 0: its index + 1, 0 none. */
static uint32_t alias_find(struct kgenome_dtx *x, uint32_t sc, const uint8_t *nm, uint32_t nl, int self)
{
	uint32_t a, i;

	if (!sc || !x->altcap)
		return 0;
	i = alias_slot(x, alias_hash_of(x, sc, nm, nl), sc, nm, nl);
	for (a = x->alt[i]; a; a = x->al[a - 1u].same)
		if (!self || x->al[a - 1u].target == sc)
			return a;
	return 0;
}

/* Is `name` a parameter of scope `sc`: a name the scope declared for itself (an alias to itself, which nothing else makes). */
int kgenome_dtx_declared(struct kgenome_dtx *x, uint32_t sc, const uint8_t *nm, uint32_t nl)
{
	return alias_find(x, sc, nm, nl, 1) != 0;
}

struct kgenome_dtx_var *kgenome_dtx_var_for(struct kgenome_dtx *x, uint32_t tok, uint32_t *used, int make)
{
	const uint8_t *nm;
	uint32_t nl, sc, a;
	int declared = 0;
	struct kgenome_dtx_var *v = NULL;

	*used = kgenome_dtx_var_key(x, tok, &nm, &nl);
	if (!*used)
		return NULL;
	sc = *used == 4u ? 0u : x->scope[tok];          /* $GLOBALS['a'] is the top level's, from wherever it is written */
	a = alias_find(x, sc, nm, nl, 0);
	if (a) {
		sc = x->al[a - 1u].target;
		declared = 1;
	}
	/* vbscript: a name that is neither a parameter nor `Dim`med in the function is the top level's - read or assigned - and not one of the function's own */
	if (sc && !declared && x->lang->global_default)
		sc = 0;
	/* a language whose functions see the variables around them (js, python, lua, java, perl): a name read and never assigned here is the enclosing
	 * scope's - unless it is a parameter of this function or of one between (declared_in), which is another variable that happens to be
	 * spelt the same: minified js reuses `t` and `e` in every function, and each is its own. An assignment (`make`) is a variable of this
	 * scope, as python's is and js's `var`. */
	while (!make && x->lang->lexical && sc && !(v = var_find(x, nm, nl, sc, 0)) && !kgenome_dtx_declared(x, sc, nm, nl))
		sc = x->sparent[sc];
	if (v)
		return v;
	return var_find(x, nm, nl, sc, make);
}

/* The variables, given back: the table and the chunks that hold them (the route's close). */
void kgenome_dtx_vars_free(struct kgenome_dtx *x)
{
	free(x->vt);
	free(x->seg);
	x->seg = NULL;
	x->nsegs = x->csegs = 0;
	while (x->vchunk) {
		struct kgenome_dtx_vchunk *c = x->vchunk;

		x->vchunk = c->next;
		free(c);
	}
	x->vt = NULL;
}
