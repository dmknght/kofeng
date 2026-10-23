/*
 * diag_text_eval_ops.c - what a program writes AROUND a value to change it, read by the constant evaluator: a method (`"abc".replace("a", "b")`), an operator
 * (powershell's `'abc' -replace 'a', 'b'`, python's `"ab" * 3`), a suffix (python's `[::-1]`), a cast (powershell's `[char]65`), a static call (`[string]::Join(...)`),
 * and the lists the join and the split work on.
 *
 * ONE TABLE. php's `str_replace('a', 'b', 'abc')`, python's `'abc'.replace('a', 'b')` and powershell's `'abc' -replace 'a', 'b'` are the same operation on the same
 * three strings, and the table (textual.h, enum kgenome_textual_shape) has ONE row for each, with the SAME op: the row says how the language writes it and what the
 * language does that the op does not (the bytes its pattern may not hold, whether an empty search is an error, whether the cut counts from 1). Reading a spelling
 * is this file's; running the row is kgenome_textual_fn_run's, through the engine's hook, as for php. There is no second implementation of replace, trim or case here.
 *
 * WHAT IS REFUSED IS LEFT AS WRITTEN. Anything the row does not say is exact - a regular expression, a locale's case, a negative index the language reads
 * differently, a receiver that is not a string of the program - makes the whole expression not constant: the answer is "no value", never a guess.
 *
 * A LIST is a value only inside one term (struct kgenome_dtx_list): a list literal or a split makes one, a join uses it, and a list that is still one at the end of an
 * expression is not a constant. Nothing here keeps one between statements.
 */

#include <stdlib.h>
#include <string.h>

#include "diag_text_eval_private.h"
#include <kofstrlist.h>
#include <textual/textual.h>

/* ---- lists ---------------------------------------------------------------- */

void kgenome_dtx_ev_list_free(struct kgenome_dtx_list *l)
{
	free(l->p);
	memset(l, 0, sizeof *l);
}

int kgenome_dtx_ev_list_add(struct kgenome_dtx *x, struct kgenome_dtx_list *l, const uint8_t *p, uint32_t n)
{
	uint64_t at = l->n;

	if (kof_strlist_size(n) > (uint64_t)KGENOME_DTX_EV_VMAX - l->n) {
		kgenome_dtx_ev_cut(x);
		return 0;
	}
	if (l->n + kof_strlist_size(n) > l->cap) {
		uint32_t nc = l->cap ? l->cap * 2u : 64u;
		uint8_t *np;

		while (nc < l->n + kof_strlist_size(n))
			nc *= 2u;
		np = realloc(l->p, nc);
		if (!np) {
			kgenome_diag_note(x->s, KGENOME_NOMEM);
			return 0;
		}
		l->p = np;
		l->cap = nc;
	}
	kof_strlist_put(l->p, &at, p, n);
	l->n = (uint32_t)at;
	l->on = 1;
	return 1;
}

/* ---- the rows of a text's language, by shape --------------------------------- */

#define SHAPE_BIT(s) (1u << (s))

void kgenome_dtx_ev_ops_open(struct kgenome_dtx *x)
{
	const char *name;
	struct kgenome_textual_fn f;
	uint32_t k;

	x->shapes = kgenome_textual_fn_shapes(x->lang->id);
	if (!(x->shapes & (SHAPE_BIT(KGENOME_TEXTUAL_SHAPE_OP) | SHAPE_BIT(KGENOME_TEXTUAL_SHAPE_CAST) | SHAPE_BIT(KGENOME_TEXTUAL_SHAPE_SUFFIX))))
		return;
	for (k = 0; kgenome_textual_fn_row(x->lang->id, k, &name, &f); k++) {
		if (f.shape == KGENOME_TEXTUAL_SHAPE_OP && x->n_ops < sizeof x->op_row)
			x->op_row[x->n_ops++] = (uint8_t)k;
		else if (f.shape == KGENOME_TEXTUAL_SHAPE_CAST && x->n_casts < sizeof x->cast_row)
			x->cast_row[x->n_casts++] = (uint8_t)k;
		else if (f.shape == KGENOME_TEXTUAL_SHAPE_SUFFIX && x->n_sufs < sizeof x->suf_row)
			x->suf_row[x->n_sufs++] = (uint8_t)k;
	}
}

/*
 * HOW MANY TOKENS the spelling `w` takes at token `i`, 0 when the text there is not it: the bytes are the same (the language's case where it folds names) and the
 * tokens are laid end to end over exactly those bytes with nothing between them - `-replace` is a name token and `[::-1]` is six, and `- replace` is neither.
 */
static uint32_t spelled(const struct kgenome_dtx *x, uint32_t i, uint32_t end, const char *w)
{
	uint32_t n = (uint32_t)strlen(w), off, pos, j, k;

	if (i >= end)
		return 0;
	off = x->t[i].off;
	if (n > x->n_in - off)
		return 0;
	for (k = 0; k < n; k++) {
		uint8_t c = x->in[off + k];

		if ((x->lang->fold ? kof_lower_byte(c) : c) != (uint8_t)w[k])
			return 0;
	}
	for (j = i, pos = off; pos < off + n; j++) {
		if (j >= end || x->t[j].off != pos || x->t[j].k == 'T' || !x->t[j].len)
			return 0;
		pos += x->t[j].len;
	}
	return pos == off + n ? j - i : 0;
}

/* The row of shape `shape` the table's index list names, at position `k` of that list; its name too. */
static int row_at(const struct kgenome_dtx *x, const uint8_t *idx, uint32_t k, const char **name, struct kgenome_textual_fn *f)
{
	return kgenome_textual_fn_row(x->lang->id, idx[k], name, f);
}

uint32_t kgenome_dtx_ev_static_callee(const struct kgenome_dtx *x, uint32_t i, uint32_t end, uint32_t *noff, uint32_t *nlen)
{
	const struct kgenome_dtx_tok *t = x->t;
	uint32_t m;

	/* `[type]::name(`: the tokens are "[", the type, "]", ":", ":", the name, "(" laid end to end */
	if (!x->shapes || i + 6u >= end || !kgenome_dtx_is_p(x, i, '[') || (t[i + 1u].k != 'I' && t[i + 1u].k != 'V') || !kgenome_dtx_is_p(x, i + 2u, ']') ||
	    !kgenome_dtx_is_p(x, i + 3u, ':') || !kgenome_dtx_is_p(x, i + 4u, ':') || t[i + 5u].k != 'I' || !kgenome_dtx_is_p(x, i + 6u, '('))
		return 0;
	if (t[i + 1u].off != t[i].off + 1u || t[i + 2u].off != t[i + 1u].off + t[i + 1u].len || t[i + 3u].off != t[i + 2u].off + 1u ||
	    t[i + 4u].off != t[i + 3u].off + 1u || t[i + 5u].off != t[i + 4u].off + 1u || t[i + 6u].off != t[i + 5u].off + t[i + 5u].len)
		return 0;
	m = (uint32_t)x->match[i + 6u];
	if (x->match[i + 6u] <= 0 || m >= end)
		return 0;
	*noff = t[i].off;
	*nlen = t[i + 5u].off + t[i + 5u].len - t[i].off;
	return i + 6u;
}

/* ---- arguments ---------------------------------------------------------------- */

int kgenome_dtx_ev_args(struct kgenome_dtx_ev *e, uint32_t open, struct kgenome_dtx_val *a, uint32_t first, int listarg, struct kgenome_dtx_list *lst)
{
	struct kgenome_dtx *x = e->x;
	uint32_t close = (uint32_t)x->match[open], j = open + 1u, n = first;
	int ok = 1;

	x->in_call++;
	x->list_ok = (uint8_t)(x->list_ok + (listarg != 0));
	while (ok && j < close) {
		int b = 0;

		if (n == KGENOME_DTX_EV_ARGS) {         /* more arguments than a call is run with (the stack of the recursion is what bounds it): said, the name is not followed */
			kgenome_dtx_ev_cut(x);
			ok = 0;
			break;
		}
		ok = kgenome_dtx_ev_expr(e, &j, close, &a[n++], &b, listarg ? lst : NULL);
		/* a list is the last argument: it is not one a function of strings takes beside others, and the slot it came in holds nothing */
		if (ok && lst && lst->on && j < close)
			ok = 0;
		if (ok && j < close)
			ok = kgenome_dtx_is_p(x, j, ',') && ++j <= close;
	}
	x->in_call--;
	x->list_ok = (uint8_t)(x->list_ok - (listarg != 0));
	return ok ? (int)n : -1;
}

/* ---- running a row --------------------------------------------------------------- */

/*
 * A JOIN, as the op wants it: the list as the subject and the separator as the one parameter. The language writes it three ways, and this only puts the pieces in the op's order:
 * the list is the receiver (`list.join(sep)`, `list -join sep`), the separator is the receiver and the list the argument (python's `sep.join(list)`, php's implode), or the
 * separator comes first and the elements after it (perl's join, [string]::Join), which are collected into a list here. Nothing about a string is decided here.
 */
static int ev_join_row(struct kgenome_dtx_ev *e, const struct kgenome_textual_fn *f, struct kgenome_dtx_val *a, uint32_t n, const struct kgenome_dtx_list *lin, struct kgenome_dtx_val *res)
{
	struct kgenome_dtx_list tmp = { 0 };
	struct kgenome_dtx_val args[2] = { { 0 }, { 0 } };
	const struct kgenome_dtx_val *sep = NULL;
	uint32_t k, n2 = 1;
	int ok = 0;

	if (f->flags & KGENOME_TEXTUAL_FN_LIST_RECV) {
		if (!lin || !lin->on)
			return 0;
		args[0].p = lin->p;
		args[0].n = lin->n;
		sep = n >= 2u ? &a[1] : NULL;
	} else if (f->list & KGENOME_TEXTUAL_LIST_VARIADIC) {
		sep = &a[0];
		if (lin && lin->on) {
			if (n != 2u)
				return 0;
			args[0].p = lin->p;
			args[0].n = lin->n;
		} else {
			for (k = 1; k < n; k++)
				if (!kgenome_dtx_ev_list_add(e->x, &tmp, a[k].p, a[k].n) || (e->x->lang->typed && a[k].str != 1u))
					goto out;
			tmp.on = 1;
			args[0].p = tmp.p;
			args[0].n = tmp.n;
		}
	} else {
		if (!lin || !lin->on)
			return 0;
		args[0].p = lin->p;
		args[0].n = lin->n;
		sep = n >= 2u ? &a[0] : NULL;
	}
	if (sep) {
		if (e->x->lang->typed && sep->str != 1u)
			goto out;
		args[1].p = sep->p;
		args[1].n = sep->n;
		n2 = 2;
	}
	ok = kgenome_dtx_ev_run_row(e, f, args, n2, res);
out:
	kgenome_dtx_ev_list_free(&tmp);
	return ok;
}

int kgenome_dtx_ev_apply(struct kgenome_dtx_ev *e, const struct kgenome_textual_fn *f, struct kgenome_dtx_val *a, uint32_t n, const struct kgenome_dtx_list *lin, struct kgenome_dtx_val *res,
	     struct kgenome_dtx_list *lout)
{
	uint32_t k;

	if (f->op == KGENOME_TEXTUAL_DEC_JOIN)
		return ev_join_row(e, f, a, n, lin, res);
	if (n > KGENOME_DTX_EV_ARGS || n < f->min_args || n > f->max_args)
		return 0;
	if (f->shape != KGENOME_TEXTUAL_SHAPE_CALL && e->x->lang->typed) {
		/* a typed language does not turn a number into the string a function wants, or the other way round (python's "ab" * "3" and "a".replace(1, "x") are errors);
		 * the arguments the row calls bytes are strings of the program, the ones it calls numbers are numbers */
		for (k = 0; k < 2u; k++) {
			uint8_t idx = f->param[k];

			if (idx == KGENOME_TEXTUAL_FN_NONE || idx >= n)
				continue;
			if ((f->numeric >> k & 1u) ? ((f->flags & KGENOME_TEXTUAL_FN_NUMTYPED) && a[idx].str) : !a[idx].str)
				return 0;
		}
	}
	if (!kgenome_dtx_ev_run_row(e, f, a, n, res))
		return 0;
	if (f->op == KGENOME_TEXTUAL_DEC_SPLIT) {
		/* the answer is the op's list: it is kept as the list (its buffer is moved, not copied) */
		kgenome_dtx_ev_list_free(lout);
		lout->p = res->p;
		lout->n = res->n;
		lout->cap = res->cap;
		lout->on = 1;
		memset(res, 0, sizeof *res);
	}
	return 1;
}

/* ---- a method or a suffix: what follows a value ---------------------------------- */

/* The `open` of a method written without its brackets (the row says NOPAREN: ruby's `"abc".reverse`). */
#define NO_OPEN 0xffffffffu

/* Is the text at token `i` `.name(` of a METHOD row (or `.name` of one that may have no brackets): the row, and the token of its "(" (NO_OPEN for none). */
static int method_at(const struct kgenome_dtx *x, uint32_t i, uint32_t end, struct kgenome_textual_fn *f, uint32_t *open)
{
	const struct kgenome_dtx_tok *d, *nm;

	if (i + 1u >= end || !kgenome_dtx_is_p(x, i, '.'))
		return 0;
	d = &x->t[i];
	nm = &x->t[i + 1u];
	if ((nm->k != 'I' && nm->k != 'V') || nm->off != d->off + 1u)
		return 0;
	/* ruby's `upcase!` and `empty?` are other methods, and the one that changes its receiver gives nil when nothing changed: the name is ended by the "!" or "?" */
	if (nm->off + nm->len < x->n_in && (x->in[nm->off + nm->len] == '!' || x->in[nm->off + nm->len] == '?'))
		return 0;
	if (!kgenome_textual_fn_find(x->lang->id, x->in + d->off, 1u + nm->len, f) || f->shape != KGENOME_TEXTUAL_SHAPE_METHOD)
		return 0;
	if (i + 2u < end && kgenome_dtx_is_p(x, i + 2u, '(') && x->t[i + 2u].off == nm->off + nm->len) {
		if (x->match[i + 2u] <= 0 || (uint32_t)x->match[i + 2u] >= end)
			return 0;
		*open = i + 2u;
		return 1;
	}
	if (!(f->flags & KGENOME_TEXTUAL_FN_NOPAREN))
		return 0;
	*open = NO_OPEN;
	return 1;
}

/* The suffix spelt at token `i`: its row and how many tokens it is, 0 for none. */
static uint32_t suffix_at(const struct kgenome_dtx *x, uint32_t i, uint32_t end, struct kgenome_textual_fn *f)
{
	uint32_t k, n;
	const char *name;

	for (k = 0; k < x->n_sufs; k++)
		if (row_at(x, x->suf_row, k, &name, f) && (n = spelled(x, i, end, name)) != 0)
			return n;
	return 0;
}

/* The receiver of a postfix row, out[base..], as a value of its own that a call may keep; a list receiver is `L`. 0 when the language needs a string and it is not one. */
static int receiver(struct kgenome_dtx *x, const struct kgenome_dtx_val *out, uint32_t base, struct kgenome_dtx_list *L, struct kgenome_dtx_val *a0)
{
	if (L->on)
		return 1;
	if (x->lang->typed && out->str != 1u)          /* a string of the program: not a number, not a character (powershell's [char]65 is no string) */
		return 0;
	if (!kgenome_dtx_ev_val_put(x, a0, out->p + base, out->n - base))
		return 0;
	a0->str = 1;
	return 1;
}

/* The answer of a postfix, in the place of the receiver and what was written after it: a string where the receiver's text was, or the list in L. */
static int answer(struct kgenome_dtx *x, struct kgenome_dtx_val *out, uint32_t base, int *built, struct kgenome_dtx_list *L, struct kgenome_dtx_val *res, struct kgenome_dtx_list *lres)
{
	if (lres->on) {
		kgenome_dtx_ev_list_free(L);
		*L = *lres;
		memset(lres, 0, sizeof *lres);
		out->n = base;
		out->str = 0;
	} else {
		kgenome_dtx_ev_list_free(L);
		out->n = base;
		if (!kgenome_dtx_ev_val_put(x, out, res->p, res->n))
			return 0;
		out->str = 1;
	}
	*built = 1;
	return 1;
}

static int postfix_one(struct kgenome_dtx_ev *e, const struct kgenome_textual_fn *f, uint32_t open, uint32_t suffix_tokens, struct kgenome_dtx_val *out, const struct kgenome_dtx_at *at,
		       struct kgenome_dtx_list *L)
{
	struct kgenome_dtx *x = e->x;
	uint32_t *i = at->i, base = at->base;
	int *built = at->built;
	struct kgenome_dtx_val a[KGENOME_DTX_EV_ARGS], res = { 0 };
	struct kgenome_dtx_list lst = { 0 }, lres = { 0 };
	const struct kgenome_dtx_list *lin;
	uint32_t k;
	int n = 1, ok = 0;

	memset(a, 0, sizeof a);
	if (!receiver(x, out, base, L, &a[0]))
		goto out;
	if (suffix_tokens == 0 && open != NO_OPEN) {
		n = kgenome_dtx_ev_args(e, open, a, 1, f->op == KGENOME_TEXTUAL_DEC_JOIN && !(f->flags & KGENOME_TEXTUAL_FN_LIST_RECV), &lst);
		if (n <= 0)
			goto out;
	}
	/* a list that is the receiver is read by a join and by nothing else; a string receiver by everything but a join of a list */
	if (L->on && !(f->op == KGENOME_TEXTUAL_DEC_JOIN && (f->flags & KGENOME_TEXTUAL_FN_LIST_RECV)))
		goto out;
	lin = (f->flags & KGENOME_TEXTUAL_FN_LIST_RECV) ? L : &lst;
	ok = kgenome_dtx_ev_apply(e, f, a, (uint32_t)n, lin, &res, &lres) && answer(e->x, out, base, built, L, &res, &lres);
	if (ok)
		*i = suffix_tokens ? *i + suffix_tokens : open == NO_OPEN ? *i + 2u : (uint32_t)x->match[open] + 1u;
out:
	for (k = 0; k < KGENOME_DTX_EV_ARGS; k++)
		kgenome_dtx_val_free(&a[k]);
	kgenome_dtx_val_free(&res);
	kgenome_dtx_ev_list_free(&lst);
	kgenome_dtx_ev_list_free(&lres);
	return ok;
}

int kgenome_dtx_ev_postfix(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, uint32_t base, int *built, struct kgenome_dtx_list *L)
{
	const struct kgenome_dtx *x = e->x;
	struct kgenome_textual_fn f;
	struct kgenome_dtx_at at = { i, end, 0, base, built };
	uint32_t open, n;

	while (*i < end) {
		if ((x->shapes & SHAPE_BIT(KGENOME_TEXTUAL_SHAPE_METHOD)) && method_at(x, *i, end, &f, &open)) {
			if (!postfix_one(e, &f, open, 0, out, &at, L))
				return 0;
		} else if (x->n_sufs && (n = suffix_at(x, *i, end, &f)) != 0) {
			if (!postfix_one(e, &f, 0, n, out, &at, L))
				return 0;
		} else {
			break;
		}
	}
	return 1;
}

/* ---- an operator: what stands between two values ---------------------------------- */

/* The row of an operator of this precedence spelt at token `i`, and how many tokens it is; 0 for none. */
static uint32_t operator_at(const struct kgenome_dtx *x, uint32_t i, uint32_t end, uint8_t prec, struct kgenome_textual_fn *f)
{
	uint32_t k, n;
	const char *name;

	for (k = 0; k < x->n_ops; k++)
		if (row_at(x, x->op_row, k, &name, f) && f->prec == prec && (n = spelled(x, i, end, name)) != 0)
			return n;
	return 0;
}

static void vals_free(struct kgenome_dtx_val *a, uint32_t n)
{
	uint32_t k;

	for (k = 0; k < n; k++)
		kgenome_dtx_val_free(&a[k]);
}

/*
 * THE RIGHT SIDE of an operator at token *i, into a[1..]: how many values (the left is a[0]), -1 for one that is not constant. A tighter operator takes one term; a looser one
 * takes what binds tighter than it - the joins of terms - and, where the row says it takes a LIST (`-replace 'a', 'b'`), the comma list of terms, which binds tighter than the
 * join in the language and so cannot be followed by one (`'a','b' + 'c'` is an array sum: not constant).
 */
static int right_side(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, const struct kgenome_textual_fn *f, struct kgenome_dtx_val *a)
{
	struct kgenome_dtx *x = e->x;
	uint32_t j = *i, n = 1;
	int b = 0;

	if (f->prec) {
		if (!kgenome_dtx_ev_term(e, &j, end, &a[n++], &b, NULL))
			return -1;
	} else if (f->list & KGENOME_TEXTUAL_LIST_RIGHT) {
		if (!kgenome_dtx_ev_term(e, &j, end, &a[n++], &b, NULL))
			return -1;
		if (kgenome_dtx_is_p(x, j, ',')) {
			while (kgenome_dtx_is_p(x, j, ',') && n < (uint32_t)f->max_args) {
				j++;
				if (n == KGENOME_DTX_EV_ARGS) {
					kgenome_dtx_ev_cut(x);
					return -1;
				}
				if (!kgenome_dtx_ev_term(e, &j, end, &a[n++], &b, NULL))
					return -1;
			}
			if (kgenome_dtx_is_p(x, j, ','))                /* more than the row takes; a join after the list is left over and fails the expression */
				return -1;
		} else if (kgenome_dtx_ev_join(x, j)) {              /* one value that is a join: read it again as the expression it is */
			kgenome_dtx_val_free(&a[1]);
			n = 1;
			j = *i;
			if (!kgenome_dtx_ev_join_level(e, &j, end, &a[n++], &b, NULL) || kgenome_dtx_is_p(x, j, ','))
				return -1;
		}
	} else {
		if (!kgenome_dtx_ev_join_level(e, &j, end, &a[n++], &b, NULL) || kgenome_dtx_is_p(x, j, ','))
			return -1;
	}
	*i = j;
	return (int)n;
}

static int ops_run(struct kgenome_dtx_ev *e, const struct kgenome_dtx_at *at, struct kgenome_dtx_val *out, uint8_t prec, struct kgenome_dtx_list *L)
{
	struct kgenome_dtx *x = e->x;
	uint32_t *i = at->i, end = at->end, from = at->from, base = at->base;
	int *built = at->built;
	struct kgenome_textual_fn f;
	uint32_t ntok;

	while (*i < end && (ntok = operator_at(x, *i, end, prec, &f)) != 0) {
		struct kgenome_dtx_val a[KGENOME_DTX_EV_ARGS], res = { 0 };
		struct kgenome_dtx_list lres = { 0 };
		uint32_t j = *i + ntok;
		int n, ok = 0;

		memset(a, 0, sizeof a);
		/* a tighter operator's left side is a term as written: a bracket in front of perl's x makes it list repetition, which is not one string */
		if ((f.flags & KGENOME_TEXTUAL_FN_NOGROUP) && kgenome_dtx_is_p(x, from, '('))
			goto out;
		if (!receiver(x, out, base, L, &a[0]))
			goto out;
		if (L->on && !(f.op == KGENOME_TEXTUAL_DEC_JOIN && (f.flags & KGENOME_TEXTUAL_FN_LIST_RECV)))
			goto out;
		n = right_side(e, &j, end, &f, a);
		if (n < 0)
			goto out;
		ok = kgenome_dtx_ev_apply(e, &f, a, (uint32_t)n, L, &res, &lres) && answer(e->x, out, base, built, L, &res, &lres);
		if (ok)
			*i = j;
out:
		vals_free(a, KGENOME_DTX_EV_ARGS);
		kgenome_dtx_val_free(&res);
		kgenome_dtx_ev_list_free(&lres);
		if (!ok)
			return 0;
	}
	return 1;
}

int kgenome_dtx_ev_ops(struct kgenome_dtx_ev *e, const struct kgenome_dtx_at *at, struct kgenome_dtx_val *out, uint8_t prec, struct kgenome_dtx_list *L)
{
	struct kgenome_dtx_list local = { 0 };
	int ok = ops_run(e, at, out, prec, L ? L : &local);

	/* a caller that takes no list gets none: an operator that ended in one (a split nobody joined) is not a constant */
	if (!L && local.on)
		ok = 0;
	kgenome_dtx_ev_list_free(&local);
	return ok;
}

/* ---- a list literal, a cast ------------------------------------------------------- */

/* Does the bracket at token `open`, closing at `close`, hold a comma of its own (not one inside a bracket within it)? */
static int has_comma(const struct kgenome_dtx *x, uint32_t open, uint32_t close)
{
	uint32_t j;

	for (j = open + 1u; j < close; j++) {
		if (kgenome_dtx_is_p(x, j, ','))
			return 1;
		if (x->match[j] > (int32_t)j && x->t[j].k == 'P' && (x->in[x->t[j].off] == '(' || x->in[x->t[j].off] == '[' || x->in[x->t[j].off] == '{'))
			j = (uint32_t)x->match[j];
	}
	return 0;
}

/* Does what follows the bracket that closes a list take a list: a method (".join(") or an operator that binds looser than the join. */
static int list_consumer_follows(const struct kgenome_dtx *x, uint32_t at, uint32_t end)
{
	struct kgenome_textual_fn f;

	return kgenome_dtx_is_p(x, at, '.') || (x->n_ops && operator_at(x, at, end, 0, &f) != 0);
}

int kgenome_dtx_ev_list_primary(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_list *L)
{
	struct kgenome_dtx *x = e->x;
	struct kgenome_dtx_list tmp = { 0 };
	uint32_t open, close, j;
	int ok = 1;

	open = *i;
	if (x->lang->list_call && x->t[open].k == 'I' && kgenome_dtx_is_word(x, open, x->lang->list_call) && kgenome_dtx_is_p(x, open + 1u, '('))
		open++;                                         /* `array(a, b)`: the name, then the bracket the elements are in */
	else if (!kgenome_dtx_is_p(x, open, '[') && !kgenome_dtx_is_p(x, open, '(') && !kgenome_dtx_is_p(x, open, '@'))
		return 0;
	else if (kgenome_dtx_is_p(x, open, '['))
		open = x->lang->list_bracket ? open : 0u;
	else if (kgenome_dtx_is_p(x, open, '@'))                /* `@(a, b)`: the "@" and the bracket touch */
		open = x->lang->list_at && kgenome_dtx_is_p(x, open + 1u, '(') && x->t[open + 1u].off == x->t[open].off + 1u ? open + 1u : 0u;
	else
		open = x->lang->list_paren && x->match[open] > 0 && (uint32_t)x->match[open] < end && has_comma(x, open, (uint32_t)x->match[open]) ? open : 0u;
	if (!open || x->match[open] <= 0 || (uint32_t)x->match[open] >= end)
		return 0;
	close = (uint32_t)x->match[open];
	/* the elements are read only where something takes the list: a join's argument, a join's operand, or what follows is a method or a looser operator (`[a, b].join(..)`,
	 * `('a','b') -join ..`). A table of a thousand strings that is only assigned is not parsed for them - and is no value either way. */
	if (!x->list_ok && !list_consumer_follows(x, close + 1u, end))
		return 0;
	/* a list is empty or its elements are strings of the program (or characters, which a join writes as the strings they are), one expression each */
	for (j = open + 1u; ok && j < close; ) {
		struct kgenome_dtx_val v = { 0 };
		int b = 0;

		ok = kgenome_dtx_ev_expr(e, &j, close, &v, &b, NULL) && (!x->lang->typed || v.str) && kgenome_dtx_ev_list_add(x, &tmp, v.p, v.n);
		kgenome_dtx_val_free(&v);
		if (ok && j < close)
			ok = kgenome_dtx_is_p(x, j, ',') && ++j <= close;
	}
	if (!ok) {
		kgenome_dtx_ev_list_free(&tmp);
		return -1;
	}
	tmp.on = 1;
	kgenome_dtx_ev_list_free(L);
	*L = tmp;
	*i = close + 1u;
	return 1;
}

int kgenome_dtx_ev_cast(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L)
{
	struct kgenome_dtx *x = e->x;
	struct kgenome_textual_fn f;
	const char *name;
	uint32_t k, n = 0, j;

	for (k = 0; k < x->n_casts && !n; k++)
		if (row_at(x, x->cast_row, k, &name, &f))
			n = spelled(x, *i, end, name);
	if (!n)
		return 0;
	j = *i + n;
	{
		struct kgenome_dtx_val a[1] = { { 0 } }, opnd = { 0 }, res = { 0 };
		struct kgenome_dtx_list lst = { 0 }, lres = { 0 };
		int b = 0, ok;

		/* the operand is one term; a join takes a list or a string (a string is a list of one) */
		x->list_ok = (uint8_t)(x->list_ok + (f.op == KGENOME_TEXTUAL_DEC_JOIN));
		ok = kgenome_dtx_ev_term(e, &j, end, &opnd, &b, f.op == KGENOME_TEXTUAL_DEC_JOIN ? &lst : NULL);
		x->list_ok = (uint8_t)(x->list_ok - (f.op == KGENOME_TEXTUAL_DEC_JOIN));
		if (ok && f.op == KGENOME_TEXTUAL_DEC_JOIN && !lst.on)
			ok = opnd.str == 1u && kgenome_dtx_ev_list_add(x, &lst, opnd.p, opnd.n);
		else if (ok)
			ok = kgenome_dtx_ev_val_put(x, &a[0], opnd.p, opnd.n);
		a[0].str = opnd.str;
		ok = ok && kgenome_dtx_ev_apply(e, &f, a, 1u, &lst, &res, &lres) && !lres.on;
		if (ok) {
			ok = kgenome_dtx_ev_val_put(x, out, res.p, res.n);
			out->str = f.op == KGENOME_TEXTUAL_DEC_CHR ? 2u : 1u;      /* [char]65 is a character, which is not a string (see kgenome_dtx_ev_join_level) */
			*i = j;
		}
		kgenome_dtx_val_free(&a[0]);
		kgenome_dtx_val_free(&opnd);
		kgenome_dtx_val_free(&res);
		kgenome_dtx_ev_list_free(&lst);
		kgenome_dtx_ev_list_free(&lres);
		(void)built;
		(void)L;
		return ok ? 1 : -1;
	}
}

/*
 * THE LITERALS THAT ARE CHANGED WHERE THEY STAND: `"a-b".replace("-", "")` written as an argument, a condition, a statement - anywhere an assignment's right side is not. The
 * evaluator is asked for the right sides of assignments (report_consts); a method or a suffix on a LITERAL is a value wherever it is, and php's str_replace is rewritten
 * wherever it stands too (the form's call stage), so the same is done here: each string literal followed by what a method or a suffix reads is an expression of its own,
 * [literal, end of what follows it), kept with the right sides and evaluated with them. It starts at the literal because a method binds tighter than any operator on its left: it is
 * the literal's, whatever is written in front of it. An operator is not looked for here (it binds looser than the join, and the literal may be the right side of another expression).
 * The extent is what the evaluator itself reads: kgenome_dtx_ev_term, and only a result that went past the literal is kept.
 */
void kgenome_dtx_ev_floating_cands(struct kgenome_dtx *x)
{
	struct kgenome_dtx_ev e = { x };
	uint32_t i;

	if (!(x->shapes & (SHAPE_BIT(KGENOME_TEXTUAL_SHAPE_METHOD) | SHAPE_BIT(KGENOME_TEXTUAL_SHAPE_SUFFIX))))
		return;
	for (i = 0; i + 1u < x->nt; i++) {
		struct kgenome_dtx_val v = { 0 };
		uint32_t first = i, k;
		int built = 0, ok;

		if (x->t[i].k != 'S' || !(kgenome_dtx_is_p(x, i + 1u, '.') || (x->n_sufs && kgenome_dtx_is_p(x, i + 1u, '['))))
			continue;
		/* literals side by side are one literal (python): the candidate starts at the first of them, not at the one the method touches */
		while (x->lang->adjacent && first > 0 && x->t[first - 1u].k == 'S')
			first--;
		k = first;
		ok = kgenome_dtx_ev_term(&e, &k, x->nt, &v, &built, NULL) && k > i + 1u;
		kgenome_dtx_val_free(&v);
		if (ok) {
			kgenome_dtx_cand_add(x, first, k);
			i = k - 1u;
		}
	}
}
