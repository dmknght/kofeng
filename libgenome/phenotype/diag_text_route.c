/*
 * diag_text_route.c - the TEXT route's entry: one text lexed into tokens, the tables made out of them, the walk run over them, and the three ways it is
 * asked for - the scan of a script (kgenome_diag_run_text), the names it calls (kgenome_diag_text_names) and the constants it computes (on_const).
 * The walk itself is diag_text.c's, whatever the language; the language is the profile row the request's `lang` finds (diag_text_lang.c).
 */

#include <stdlib.h>

#include "diag_text_eval_private.h"
#include "diag_text_names.h"
#include <textual/textual.h>

/* ---- the route ------------------------------------------------------------ */

static int kgenome_dtx_open(struct kgenome_dtx *x, const struct kgenome_dtx_lang *lang, struct kgenome_diag_scan *s, const uint8_t *base,
			    uint64_t size, uint32_t flags)
{
	struct kgenome_textual_lex_req q = { base, (uint32_t)size, lang->id, flags, kgenome_dtx_sink, x };
	struct kgenome_textual_lex_res lr;

	memset(x, 0, sizeof *x);
	x->lang = lang;
	x->stages = kgenome_dtx_stages(lang->id);
	x->ret_len = lang->ret_kw ? (uint8_t)strlen(lang->ret_kw) : 0u;
	x->s = s;
	x->in = base;
	x->n_in = (uint32_t)size;
	x->seed = kgenome_oatab_seed(base, size, (uintptr_t)x ^ (uintptr_t)s);
	kgenome_dtx_prefilters(x);
	kgenome_dtx_ev_ops_open(x);
	if (!base || !size || size > 0xffffffffu)
		return 0;
	(void)kgenome_textual_lex(&q, &lr);
	return !x->oom && x->nt != 0;
}

/* The bracket each bracket token pairs with, and -1 for every other token: one pass with a stack of the open ones. */
static int kgenome_dtx_pair(struct kgenome_dtx *x)
{
	uint32_t *stk, sn = 0, i;

	if (!kgenome_dtx_charge(x, (uint64_t)x->nt * sizeof *x->match))
		return 0;
	x->match = malloc((size_t)x->nt * sizeof *x->match);
	stk = malloc((size_t)x->nt * sizeof *stk);
	if (!x->match || !stk) {
		free(stk);
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		return 0;
	}
	for (i = 0; i < x->nt; i++)
		x->match[i] = -1;
	for (i = 0; i < x->nt; i++) {
		if (x->t[i].k != 'P')
			continue;
		switch (x->in[x->t[i].off]) {
		case '(':
		case '[':
		case '{':
			stk[sn++] = i;
			break;
		case ')':
		case ']':
		case '}':
			if (sn) {
				uint32_t o = stk[--sn];

				x->match[o] = (int32_t)i;
				x->match[i] = (int32_t)o;
			}
			break;
		default:
			break;
		}
	}
	free(stk);
	return 1;
}

static void kgenome_dtx_close(struct kgenome_dtx *x)
{
	if (x->lay) {
		x->lay->work.probes += x->probes;
		x->lay->work.steps += x->steps;
		x->lay->work.listed += x->listed;
	}
	free(x->t);
	free(x->site);
	free(x->match);
	free(x->capc);
	free(x->dstk);
	kgenome_dtx_vars_free(x);
	free(x->scope);
	free(x->al);
	free(x->alt);
	free(x->sparent);
	free(x->cand);
	kgenome_dtx_sum_free(x);
	kgenome_dtx_ident_free(x);
	kgenome_dtx_cv_free(x->cv);
}

/* Does right side `a` come before `b`: by where it begins, the longest first where two begin together. */
static int cand_before(const struct kgenome_dtx *x, const struct kgenome_dtx_cand *a, const struct kgenome_dtx_cand *b)
{
	if (x->t[a->rs].off != x->t[b->rs].off)
		return x->t[a->rs].off < x->t[b->rs].off;
	return a->re > b->re;
}

/* A shell sort: in place, no allocation, and no qsort_r (not every platform this builds on has one). */
static void cand_sort(const struct kgenome_dtx *x)
{
	uint32_t gap, i, j;

	for (gap = x->ncand / 2u; gap; gap /= 2u)
		for (i = gap; i < x->ncand; i++) {
			struct kgenome_dtx_cand t = x->cand[i];

			for (j = i; j >= gap && cand_before(x, &t, &x->cand[j - gap]); j -= gap)
				x->cand[j] = x->cand[j - gap];
			x->cand[j] = t;
		}
}

/*
 * THE CONSTANTS, TOLD: the right sides collected by the walk that the evaluator follows to a text, outermost first and none inside another.
 * One that called a decoder is left to the decode hook - what a decoder makes is shown by it, with the call kept and renamed - and is not
 * told here as well.
 */
static void report_consts(struct kgenome_dtx *x)
{
	uint32_t i, last_end = 0;
	int any = 0;

	if (!x->ncand)
		return;
	cand_sort(x);
	x->strict = x->lang->typed;
	for (i = 0; i < x->ncand; i++) {
		const struct kgenome_dtx_cand *c = &x->cand[i];
		/* a variable token begins after its "$", which is part of the expression's bytes - where the language has one: a bare name has nothing in front of
		 * it, and the byte there is the "=" (javascript's `var a=b+c` came out `var a'..'`) */
		uint32_t off = x->t[c->rs].off - (x->t[c->rs].k == 'V' && x->lang->sigil ? 1u : 0u), end = x->t[c->re - 1u].off + x->t[c->re - 1u].len;
		struct kgenome_dtx_val v;
		int built;

		if (any && off < last_end)
			continue;       /* inside one already taken */
		x->saw_decoder = 0;
		if (!kgenome_dtx_eval_range(x, c->rs, c->re, &v, &built))
			continue;
		if (built && !x->saw_decoder && (v.str == 1u || (!v.str && !x->lang->typed))) {
			x->on_const(x->const_user, off, end - off, v.p, v.n);
			any = 1;
			last_end = end;
		}
		kgenome_dtx_val_free(&v);
	}
}

/*
 * THE HEADS OF CALLS, TOLD: `$l('', $c)` where `$l` is a variable with ONE producer - assigned once, never appended to - that the evaluator follows to a constant,
 * and that constant is a plain name. The view says what is called, `create_function('', $c)`, and a marker on the name finds it. Only where the variable was
 * written in the call's own scope's reach by one assignment: a name that two statements give is whichever the program had run last, which nothing here
 * knows, so it is left. A member (`$o->$f(`, `A::$f(`) is not a call of the function the variable names.
 */
static void report_heads(struct kgenome_dtx *x)
{
	uint32_t i;

	x->strict = 1;
	for (i = 0; i + 1u < x->nt; i++) {
		struct kgenome_dtx_val v;
		struct kgenome_dtx_var *var;
		uint32_t used;
		int built;

		if (x->t[i].k != 'V' || !kgenome_dtx_is_p(x, i + 1u, '(') || x->t[i].off + x->t[i].len != x->t[i + 1u].off)
			continue;
		if (i && x->t[i - 1u].k == 'P' && (x->in[x->t[i - 1u].off] == '>' || x->in[x->t[i - 1u].off] == ':'))
			continue;
		var = kgenome_dtx_var_for(x, i, &used, 0);
		if (!var || used != 1u || var->unknown || var->nseg != 1u || var->n_set != 1u || var->n_app)
			continue;
		x->saw_decoder = 0;
		if (!kgenome_dtx_eval_var(x, var, &v, &built))
			continue;
		if (kgenome_textual_name_ok(v.p, v.n))
			x->on_head(x->const_user, x->t[i].off - 1u, x->t[i].len + 1u, v.p, v.n);
		kgenome_dtx_val_free(&v);
	}
}

/*
 * ONE LEXED TEXT, WALKED: the file (layer 0), or a layer of code it computes. `hooks` carries the callbacks (the names told, the engine's
 * string functions), which a layer inherits; `lay` is the allowance shared by every layer of the scan.
 */
void kgenome_dtx_run_one(struct kgenome_diag_scan *s, const uint8_t *base, uint64_t size, uint32_t flags, const struct kgenome_dtx *hooks,
		    struct kgenome_dtx_layers *lay, uint32_t layer, uint64_t layer_at)
{
	struct kgenome_dtx x;
	uint32_t i;

	if (!kgenome_dtx_open(&x, hooks->lang, s, base, size, flags))
		goto out;
	x.on_node = hooks->on_node;
	x.user = hooks->user;
	x.apply = hooks->apply;
	x.apply_user = hooks->apply_user;
	x.lay = lay;
	x.on_const = hooks->on_const;
	x.on_head = hooks->on_head;
	x.const_user = hooks->const_user;
	x.step_cap = 200000u + 16u * x.nt;      /* the work the evaluator may spend grows with the text it reads */
	x.extract_src = -1;
	x.named_node = -1;
	x.layer = layer;
	x.layer_at = layer_at;
	if (!kgenome_dtx_charge(&x, (uint64_t)x.nt * sizeof *x.site))
		goto out;
	x.site = malloc((size_t)x.nt * sizeof *x.site);
	if (!x.site) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	for (i = 0; i < x.nt; i++)
		x.site[i] = -1;
	if (kgenome_dtx_pair(&x) && kgenome_dtx_scopes(&x)) {
		kgenome_dtx_walk(&x);
		if (x.on_const && !x.layer && x.lang->cmd_vals) {
			kgenome_dtx_cmd_consts(&x);          /* no expression is read: a value is a word */
		} else if (x.on_const && !x.layer) {
			kgenome_dtx_ev_floating_cands(&x);
			report_consts(&x);
		}
		if (x.on_head && x.lang->string_call && !x.layer)
			report_heads(&x);
	}
out:
	kgenome_dtx_close(&x);
}

void kgenome_diag_run_text(struct kgenome_diag_scan *s, const struct kgenome_diag_text_req *rq)
{
	struct kgenome_dtx h = { 0 };
	struct kgenome_dtx_layers lay = { .room = 32u * rq->size + 65536u };

	h.lang = kgenome_dtx_lang_find(rq->lang);
	if (!h.lang)            /* a language with no row: no nodes (the engine asks kgenome_diag_text_serves first) */
		return;
	h.on_node = rq->on_node;
	h.user = rq->user;
	h.apply = rq->apply;
	h.apply_user = rq->apply_user;
	h.on_const = rq->on_const;
	h.on_head = rq->on_head;
	h.const_user = rq->const_user;
	kgenome_dtx_run_one(s, rq->base, rq->size, 0, &h, &lay, 0, 0);
	if (rq->work)
		*rq->work = lay.work;
}

/* A name's id counts over the tables laid end to end (nucleo), so a language late in the order has ids past the first thousand: each name is told once
 * whatever table it is in. 8192 holds every row of every table with room; an id past it is told each time it is met, which repeats a name and never loses one. */
#define NAMES_IDS 8192u

struct kgenome_diag_text_names_acc {
	void (*fn)(void *user, const char *name, uint32_t len);
	void *user;
	const struct kgenome_dtx_lang *lang;
	uint8_t seen[NAMES_IDS / 8u];
};

void kgenome_diag_text_names_node(void *user, const char *name)
{
	struct kgenome_diag_text_names_acc *a = user;
	uint16_t id = kgenome_dtx_name_row(a->lang, name, NULL, NULL);
	const char *spelled = kgenome_nucleo_name_of(id);

	if (!spelled)
		return;
	if (id < NAMES_IDS) {
		if (a->seen[id >> 3] & (1u << (id & 7u)))
			return;
		a->seen[id >> 3] |= (uint8_t)(1u << (id & 7u));
	}
	a->fn(a->user, spelled, (uint32_t)strlen(spelled));
}

struct kgenome_diag_text_names_acc *kgenome_diag_text_names_new(uint32_t lang, void (*fn)(void *user, const char *name, uint32_t len), void *user)
{
	struct kgenome_diag_text_names_acc *a;
	const struct kgenome_dtx_lang *l = kgenome_dtx_lang_find(lang);

	if (!fn || !l)
		return NULL;
	a = calloc(1, sizeof *a);
	if (!a)
		return NULL;
	a->fn = fn;
	a->user = user;
	a->lang = l;
	return a;
}

void kgenome_diag_text_names_free(struct kgenome_diag_text_names_acc *acc)
{
	free(acc);
}

void kgenome_diag_text_names(const uint8_t *base, uint64_t size, uint32_t lang, kgenome_textual_apply_fn apply,
			     void (*fn)(void *user, const char *name, uint32_t len), void *user)
{
	struct kgenome_diag_text_names_acc *acc = kgenome_diag_text_names_new(lang, fn, user);
	struct kgenome_diag_text_req rq = { .base = base, .size = size, .lang = lang,
					    .on_node = kgenome_diag_text_names_node, .user = acc, .apply = apply };
	struct kgenome_diag_scan *s;

	if (!acc)
		return;
	s = kgenome_diag_scan_text(&rq);
	kgenome_diag_scan_free(s);
	kgenome_diag_text_names_free(acc);
}
