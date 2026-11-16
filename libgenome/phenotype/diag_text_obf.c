/*
 * diag_text_obf.c - HOW HIDDEN WHAT A SCRIPT DOES IS (EXPERIMENTAL, owner 2026-11-13): the measure of struct kgenome_diag_text_obf_rec (diag_scan.h).
 *
 * WHY HERE. The measure reads nothing of its own: the tokens, the variables with their scopes and the constant evaluator are the TEXT route's, and k(e) is
 * the evaluator's own count of the transforms it applied (struct kgenome_dtx.obf_ops). A second resolver would be a second answer to "what does this
 * name come to" (rule 2), and the token-level prototype that had one (exp_obflm/hlc.py) merged a minifier's reused names across scopes and called
 * WordPress's .min.js obfuscated. It runs nothing: it is a static reading, run when the walk is over and every assignment is known.
 *
 * WHAT IS AN EFFECT, per token (the rows of the language decide what a call and a member are):
 *   - a name called, `f(...)`: its identity is written, k = 0 - unless the language calls a variable by its name (data_call) and `f` is one, or the name
 *     is a row that RUNS code (eval, create_function, new Function: KGENOME_NUCLEO_EVAL / _CREATE), whose identity is the code it is handed
 *     (eval's first argument, the last one of the others);
 *   - a variable called, `$f(...)`, `$GLOBALS['f'](...)`: its value, when that is a constant; and when it names a row that runs code, the code as well;
 *   - a subscript called, `$a[3](...)`, `o[k](...)`: the element of the array literal, or the key.
 * A definition (`function f(`, a method written `name(...) {`), a control word (`if (`) and a call of a call (`f()()`) are not effects.
 *
 * ONE RECORD PER PLACE (owner 2026-11-14): the file gives one record per island of the CALLER's table (kgenome_diag_text_req.obf_isl: the engine hands its
 * parse's, kof_script_info.island - the islands are the engine's, and the measure finds none of its own) and one TEXT record for what no island holds (the
 * whole file when the caller names none); each layer of code the program computes is a record of its own. An effect and a node belong to the record whose
 * bytes hold their token.
 *
 * NOT YET, each with the reason: a code argument the walk already evaluated (layer_of_call) is evaluated again here - the count is not kept by the walk (measured cost: none yet);
 * the argument a code row runs is the first or the last, not the row's own `val` (callsem is the walk's static table).
 */

#include <math.h>
#include <stdlib.h>

#include "diag_text_eval_private.h"
#include <textual/textual.h>

/* Words that take a bracket and are no call, in every language the route reads (a row's own keywords and control words are asked as well). */
static const char *const not_calls[] = { "if", "elseif", "else", "while", "for", "foreach", "switch", "catch", "return", "array", "list", "isset", "empty",
					 "unset", "function", "fn", "match", "declare", "use", "typeof", "do", "with", "elif", "until", "unless", "and", "or",
					 "not", "in", "sub", "def", "class", NULL };

uint32_t kgenome_diag_text_obf_milli(const struct kgenome_diag_text_obf_rec *r)
{
	return r && r->n_eff ? (uint32_t)(r->bits_milli / r->n_eff) : 0u;
}

uint32_t kgenome_diag_text_obf_value(const struct kgenome_diag_text_obf_set *s)
{
	uint32_t i, best = 0;

	for (i = 0; s && i < s->n; i++) {
		uint32_t m = kgenome_diag_text_obf_milli(&s->v[i]);

		if (m > best)
			best = m;
	}
	return best;
}

static int not_call(const struct kgenome_dtx *x, uint32_t i)
{
	const uint8_t *p = x->in + x->t[i].off;
	uint32_t n = x->t[i].len;
	const struct kgenome_dtx_lang *l = x->lang;

	return kgenome_dtx_word_in(not_calls, p, n, 1) || kgenome_dtx_word_in(l->keywords, p, n, l->fold) || kgenome_dtx_word_in(l->ctl_words, p, n, l->fold);
}

/* `function f(`, `sub f {`, a method written `name(...) {`: token `i` names what is defined. */
static int defines(const struct kgenome_dtx *x, uint32_t i)
{
	const struct kgenome_dtx_lang *l = x->lang;

	if (i && x->t[i - 1u].k == 'I' && ((l->fn_kw && kgenome_dtx_is_word(x, i - 1u, l->fn_kw)) || (l->fn_kw2 && kgenome_dtx_is_word(x, i - 1u, l->fn_kw2))))
		return 1;
	if (l->shape && x->match[i + 1u] > 0 && kgenome_dtx_is_p(x, (uint32_t)x->match[i + 1u] + 1u, '{'))
		return 1;
	return 0;
}

/* What one evaluation came to: KIND_* and its k. */
enum { OBF_LIT, OBF_BOUND, OBF_BUILT, OBF_REFUSED, OBF_DYN };

struct obf_k {
	int kind;
	uint32_t k;
};

static void ev_begin(struct kgenome_dtx *x)
{
	x->obf_ops = 0;
	x->obf_refused = 0;
}

/* The answer of an evaluation that just ran: built (k = transforms), bound (none), refused (the steps it took and the one it could not: a lower bound), dynamic. */
static struct obf_k ev_end(const struct kgenome_dtx *x, int ok)
{
	struct obf_k r;

	if (ok) {
		r.k = x->obf_ops;
		r.kind = r.k ? OBF_BUILT : OBF_BOUND;
	} else if (x->obf_refused) {
		r.k = x->obf_ops + 1u;
		r.kind = OBF_REFUSED;
	} else {
		r.k = 0;
		r.kind = OBF_DYN;
	}
	return r;
}

/* The code a row that runs code is handed, at the call whose "(" is `open`: eval's first argument, the last one of create_function and new Function. */
static struct obf_k code_arg(struct kgenome_dtx *x, uint32_t open, uint16_t cap)
{
	struct obf_k r = { OBF_LIT, 0 };
	struct kgenome_dtx_val v;
	uint32_t rs, re, a = 0, n = 0;
	int built, ok;

	if (cap == KGENOME_NUCLEO_CREATE)
		while (kgenome_dtx_arg_range(x, open, n, &rs, &re))
			n++;
	if (n)
		a = n - 1u;
	if (!kgenome_dtx_arg_range(x, open, a, &rs, &re))
		return r;
	if (re == rs + 1u && x->t[rs].k == 'S')
		return r;                       /* the code is written where it is run */
	ev_begin(x);
	ok = kgenome_dtx_eval_range(x, rs, re, &v, &built);
	r = ev_end(x, ok);
	if (ok)
		kgenome_dtx_val_free(&v);
	return r;
}

/* The row a constant callee names, KGENOME_NUCLEO_NONE when it is no name or no row. */
static uint16_t val_cap(struct kgenome_dtx *x, const struct kgenome_dtx_val *v)
{
	if (!v->n || !kgenome_textual_name_ok(v->p, v->n))
		return KGENOME_NUCLEO_NONE;
	return kgenome_dtx_cap(x, v->p, v->n, NULL);
}

static int runs_code(uint16_t cap)
{
	return cap == KGENOME_NUCLEO_EVAL || cap == KGENOME_NUCLEO_CREATE;
}

/* A callee held by variable `v`, called at the "(" `open`: its value's transforms, and the code's when the value names a row that runs code. */
static struct obf_k var_callee(struct kgenome_dtx *x, const struct kgenome_dtx_var *v, uint32_t open)
{
	struct kgenome_dtx_val val;
	struct obf_k r;
	int built, ok;

	if (!v)
		return (struct obf_k){ OBF_DYN, 0 };
	ev_begin(x);
	ok = kgenome_dtx_eval_var(x, v, &val, &built);
	r = ev_end(x, ok);
	if (ok) {
		uint16_t cap = val_cap(x, &val);

		kgenome_dtx_val_free(&val);
		if (runs_code(cap)) {
			struct obf_k c = code_arg(x, open, cap);

			r.k += c.k;
			if (c.kind == OBF_REFUSED || (c.kind == OBF_BUILT && r.kind == OBF_BOUND))
				r.kind = c.kind;
			if (r.k && r.kind == OBF_BOUND)
				r.kind = OBF_BUILT;
		}
	}
	return r;
}

/* A subscript called, `]` at token `rb` and its "(" after it. */
static struct obf_k sub_callee(struct kgenome_dtx *x, uint32_t rb)
{
	struct kgenome_dtx_val val;
	int32_t lb = x->match[rb];
	int built, ok;
	struct obf_k r;

	if (lb <= 0)
		return (struct obf_k){ OBF_DYN, 0 };
	ev_begin(x);
	if (x->t[lb - 1].k == 'V' && x->lang->sigil)
		ok = kgenome_dtx_eval_element(x, (uint32_t)lb, &val, &built);
	else {
		x->obf_key = 1;
		ok = (uint32_t)lb + 1u < rb && kgenome_dtx_eval_range(x, (uint32_t)lb + 1u, rb, &val, &built);
		x->obf_key = 0;
	}
	r = ev_end(x, ok);
	if (ok)
		kgenome_dtx_val_free(&val);
	return r;
}

static void tally(struct kgenome_diag_text_obf_rec *rec, struct obf_k r)
{
	rec->n_eff++;
	switch (r.kind) {
	case OBF_BUILT:
		rec->n_built++;
		break;
	case OBF_BOUND:
		rec->n_bound++;
		break;
	case OBF_REFUSED:
		rec->n_refused++;
		break;
	case OBF_DYN:
		rec->n_dynamic++;
		return;                 /* dispatch: not hidden, k = 0 */
	default:
		return;
	}
	if (r.k > rec->k_max)
		rec->k_max = r.k;
	if (r.k)
		rec->bits_milli += (uint64_t)(log2(1.0 + (double)r.k) * 1000.0 + 0.5);
}

/* The records of one text: the islands `v[0..n_isl)` sorted by `at`, none overlapping (the caller's table, checked by take_islands), and after them
 * `out`, the TEXT record for what no island holds (made on first use; the whole text when the language has no islands). */
struct obf_places {
	struct kgenome_diag_text_obf_rec *v;
	uint32_t n, cap, n_isl;
	int32_t out;
	int nomem;
};

static struct kgenome_diag_text_obf_rec *place_add(struct obf_places *P, uint64_t at, uint64_t len, uint8_t kind, uint32_t layer)
{
	struct kgenome_diag_text_obf_rec *r;

	if (P->n == P->cap) {
		uint32_t nc = P->cap ? P->cap * 2u : 8u;
		void *nv = realloc(P->v, (size_t)nc * sizeof *P->v);

		if (!nv) {
			P->nomem = 1;
			return NULL;
		}
		P->v = nv;
		P->cap = nc;
	}
	r = &P->v[P->n++];
	memset(r, 0, sizeof *r);
	r->at = at;
	r->len = len;
	r->kind = kind;
	r->layer = layer;
	return r;
}

/* The caller's islands, each one ISLAND record: a place out of order, overlapping the one before, empty or reaching past the text is not taken, and the
 * answer says so (0: the set is TRUNCATED; its effects are the TEXT record's, never dropped). -1: no memory. */
static int take_islands(const struct kgenome_dtx *x, struct obf_places *P)
{
	uint64_t end = 0;
	uint32_t i;
	int all = 1;

	for (i = 0; i < x->n_obf_isl; i++) {
		const struct kgenome_diag_text_place *q = &x->obf_isl[i];

		if (!q->len || q->off < end || q->off > x->n_in || q->len > x->n_in - q->off) {
			all = 0;
			continue;
		}
		if (!place_add(P, q->off, q->len, KGENOME_DIAG_TEXT_OBF_ISLAND, 0u))
			return -1;
		end = q->off + q->len;
	}
	return all;
}

/* The record that holds file offset `off`. */
static struct kgenome_diag_text_obf_rec *place_of(const struct kgenome_dtx *x, struct obf_places *P, uint64_t off)
{
	uint32_t lo = 0, hi = P->n_isl;

	if (x->layer)
		return P->n ? &P->v[0] : NULL;
	while (lo < hi) {               /* the first record that starts after `off` */
		uint32_t m = lo + (hi - lo) / 2u;

		if (P->v[m].at <= off)
			lo = m + 1u;
		else
			hi = m;
	}
	if (lo && off < P->v[lo - 1u].at + P->v[lo - 1u].len && P->v[lo - 1u].kind == KGENOME_DIAG_TEXT_OBF_ISLAND)
		return &P->v[lo - 1u];
	if (P->out < 0) {
		struct kgenome_diag_text_obf_rec *r = place_add(P, 0u, x->n_in, KGENOME_DIAG_TEXT_OBF_TEXT, 0u);

		if (!r)
			return NULL;
		P->out = (int32_t)(r - P->v);
	}
	return &P->v[P->out];
}

/* Add `cap` to the record's ascending list of distinct capabilities. */
static void cap_add(struct obf_places *P, struct kgenome_diag_text_obf_rec *r, uint16_t cap)
{
	uint32_t i = 0;
	uint16_t *nv;

	if (cap == KGENOME_NUCLEO_NONE)
		return;
	while (i < r->n_cap && r->cap[i] < cap)
		i++;
	if (i < r->n_cap && r->cap[i] == cap)
		return;
	nv = realloc(r->cap, (size_t)(r->n_cap + 1u) * sizeof *nv);
	if (!nv) {
		P->nomem = 1;
		return;
	}
	r->cap = nv;
	memmove(&r->cap[i + 1u], &r->cap[i], (size_t)(r->n_cap - i) * sizeof *nv);
	r->cap[i] = cap;
	r->n_cap++;
}

void kgenome_dtx_obf_node(struct kgenome_dtx *x, uint32_t tok, uint16_t cap)
{
	if (tok >= x->nt || cap == KGENOME_NUCLEO_NONE)
		return;
	if (x->obf_nn == x->obf_ncap) {
		uint32_t nc = x->obf_ncap ? x->obf_ncap * 2u : 32u;
		void *nv = realloc(x->obf_nd, (size_t)nc * sizeof *x->obf_nd);

		if (!nv) {
			x->obf_nomem = 1;
			return;
		}
		x->obf_nd = nv;
		x->obf_ncap = nc;
	}
	x->obf_nd[x->obf_nn].off = x->t[tok].off;
	x->obf_nd[x->obf_nn].cap = cap;
	x->obf_nn++;
}

static void measure(struct kgenome_dtx *x, struct obf_places *P)
{
	uint32_t i;
	struct kgenome_diag_text_obf_rec *rec;

	for (i = 0; i + 1u < x->nt; i++) {
		if (!(rec = place_of(x, P, x->t[i].off)))
			return;
		const struct kgenome_dtx_tok *t = &x->t[i];

		if (t->k == 'V' && x->lang->sigil) {
			uint32_t used = 0;
			struct kgenome_dtx_var *v = kgenome_dtx_var_for(x, i, &used, 0);

			if (!used)
				used = 1;
			if (!kgenome_dtx_is_p(x, i + used, '('))
				continue;
			tally(rec, var_callee(x, v, i + used));
			i += used - 1u;         /* `$GLOBALS['f'](` is one effect, not a subscript call as well */
			continue;
		}
		if (t->k == 'I' && kgenome_dtx_is_p(x, i + 1u, '(')) {
			uint16_t cap;

			if (not_call(x, i) || defines(x, i))
				continue;
			if (kgenome_dtx_member(x, i)) {
				tally(rec, (struct obf_k){ OBF_LIT, 0 });
				continue;
			}
			if (x->lang->data_call) {
				uint32_t used;
				struct kgenome_dtx_var *v = kgenome_dtx_var_for(x, i, &used, 0);

				if (v) {
					tally(rec, var_callee(x, v, i + 1u));
					continue;
				}
			}
			cap = kgenome_dtx_cap(x, x->in + t->off, t->len, NULL);
			tally(rec, runs_code(cap) ? code_arg(x, i + 1u, cap) : (struct obf_k){ OBF_LIT, 0 });
			continue;
		}
		if (kgenome_dtx_is_p(x, i, ']') && kgenome_dtx_is_p(x, i + 1u, '('))
			tally(rec, sub_callee(x, i));
	}
}

/*
 * The walk is over: this text's record, appended to x->obf. The measure evaluates with an allowance of its own and leaves the scan as the walk left it - its
 * status, its count of cut evaluations, the evaluator's mode - so that asking for it changes no other answer of the route; a bound it hits is the record's
 * (the set's status), not the scan's.
 */
void kgenome_dtx_obf(struct kgenome_dtx *x)
{
	struct kgenome_diag_text_obf_set *s = x->obf;
	struct obf_places P = { .out = -1 };
	enum kgenome_status st0 = x->s->status;
	uint32_t cut0 = x->s->eval_cut, steps0 = x->steps, i;
	uint8_t strict0 = x->strict;

	if (x->layer)
		(void)place_add(&P, x->layer_at, x->n_in, KGENOME_DIAG_TEXT_OBF_LAYER, x->layer);
	else {
		if (!take_islands(x, &P))
			s->status = kgenome_status_merge(s->status, KGENOME_TRUNCATED);
		P.n_isl = P.n;
		if (!P.n && !P.nomem)
			P.out = place_add(&P, 0u, x->n_in, KGENOME_DIAG_TEXT_OBF_TEXT, 0u) ? 0 : -1;
	}
	x->strict = 0;
	x->steps = 0;
	if (P.n)
		measure(x, &P);
	for (i = 0; i < x->obf_nn && !P.nomem; i++) {
		struct kgenome_diag_text_obf_rec *r = place_of(x, &P, x->obf_nd[i].off);

		if (r)
			cap_add(&P, r, x->obf_nd[i].cap);
	}
	if (x->s->status != st0)
		s->status = kgenome_status_merge(s->status, x->s->status);
	x->s->status = st0;
	x->s->eval_cut = cut0;
	x->steps = steps0;
	x->strict = strict0;
	if (P.nomem || x->obf_nomem)
		s->status = kgenome_status_merge(s->status, KGENOME_NOMEM);
	/* the file's records go FIRST: its layers were walked, and appended, while the file was */
	if (P.n && !kgenome_dtx_grow(x, (void **)&s->v, &s->cap, s->n + P.n, sizeof *s->v)) {
		s->status = KGENOME_OVER_BUDGET;
		for (i = 0; i < P.n; i++)
			free(P.v[i].cap);
	} else if (P.n) {
		uint32_t at = x->layer ? s->n : 0u;

		memmove(&s->v[at + P.n], &s->v[at], (size_t)(s->n - at) * sizeof *s->v);
		memcpy(&s->v[at], P.v, (size_t)P.n * sizeof *P.v);
		s->n += P.n;
	}
	free(P.v);
}

void kgenome_diag_text_obf(const struct kgenome_diag_text_req *rq)
{
	if (!rq || !rq->obf)
		return;
	memset(rq->obf, 0, sizeof *rq->obf);
	kgenome_diag_scan_free(kgenome_diag_scan_text(rq));
}

void kgenome_diag_text_obf_free(struct kgenome_diag_text_obf_set *s)
{
	uint32_t i;

	if (!s)
		return;
	for (i = 0; i < s->n; i++)
		free(s->v[i].cap);
	free(s->v);
	memset(s, 0, sizeof *s);
}
