/*
 * diag_text_eval.c - the constant evaluator of the TEXT route: a name a script builds, read out of the program.
 *
 * The classic way to hide a function is to build its name where it is used, so no marker finds it:
 *
 *     $f = str_replace('k', '', 'ckrekatek_fuknkkction');       $f('', $code);
 *     $GLOBALS['a'] = 'bas' . 'e64_de' . 'code';                 $GLOBALS['a']($x);
 *     $n = strrev('edoced_46esab');                              $n($x);
 *     $c = chr(115) . chr(121) . 'stem';                         $c($_GET['c']);
 *     $fc = array('base64_decode', 'gzinflate');                 $fc[0]($x);
 *
 * Nothing runs. What is followed is the text of the program: a name is whatever the assignments to it give, evaluated over
 * the constants the program holds with the few pure string functions this is done with. A value that depends on a request,
 * a file or a call this does not know is "not constant", and the answer is no name - never a guess.
 *
 * BOUNDED, because the program chooses how much there is to follow: a chain of variables is cut at KGENOME_DTX_EV_DEPTH (a variable that is its own right side
 * is a cycle, and no cut), the work at `step_cap` tokens for the whole scan, a value at KGENOME_DTX_EV_VMAX bytes, a call at KGENOME_DTX_EV_ARGS arguments, the
 * expressions inside one another at KGENOME_DTX_EV_NEST. Past any of them the answer is "not constant" AND the scan says it was cut (kgenome_dtx_ev_cut: KGENOME_TRUNCATED
 * and `eval_cut`) - it said nothing for all of them but the nesting, and a name behind nine aliases was lost without a word.
 * The buffers are transient (a few at a time, at most KGENOME_DTX_EV_DEPTH deep), so they are bounded by those numbers and not charged
 * to the ledger one by one.
 */


#include "diag_text_eval_private.h"
#include <textual/textual.h>

/* KGENOME_DTX_EV_NEST: expressions inside one another in the recursion (a bracket, a call's argument): kgenome_dtx_ev_term and kgenome_dtx_ev_expr recurse on the C stack, one pair of frames (about 400
 * bytes) a level, so a file that opens 100000 `str_replace(` chose to overflow it (measured: a segmentation fault at 20000 levels, in the tree this was
 * found in). 256 levels is 100 KB, and past the generators measured (the deepest nests five). Past it the expression is not constant, and the scan says
 * it was cut (KGENOME_TRUNCATED), as every bound of the lib does. */

void kgenome_dtx_val_free(struct kgenome_dtx_val *v)
{
	free(v->p);
	v->p = NULL;
	v->n = v->cap = 0;
}

/*
 * Room for `n` more bytes at the end of `v`, without changing what it holds. 0 when that is past KGENOME_DTX_EV_VMAX or memory. `exact` allocates
 * what is asked (the answer of a call is written in place and its size is known); otherwise the capacity doubles, which is what a value
 * built from pieces needs.
 */
void kgenome_dtx_ev_cut_at(struct kgenome_dtx *x, const char *file, int line)
{
	kgenome_dtx_cut_at(x, file, line);
	if (x->s->eval_cut != UINT32_MAX)
		x->s->eval_cut++;
}

int kgenome_dtx_ev_val_room(struct kgenome_dtx *x, struct kgenome_dtx_val *v, uint32_t n, int exact)
{
	uint8_t *np;
	uint32_t nc;

	if (n > KGENOME_DTX_EV_VMAX - v->n) {
		kgenome_dtx_ev_cut(x);
		return 0;
	}
	if (v->n + n <= v->cap)
		return 1;
	nc = v->n + n;
	if (!exact) {
		nc = v->cap ? v->cap * 2u : 64u;
		while (nc < v->n + n)
			nc *= 2u;
	}
	np = realloc(v->p, nc);
	if (!np) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		return 0;
	}
	v->p = np;
	v->cap = nc;
	return 1;
}

int kgenome_dtx_ev_val_put(struct kgenome_dtx *x, struct kgenome_dtx_val *v, const uint8_t *p, uint32_t n)
{
	if (!kgenome_dtx_ev_val_room(x, v, n, 0))
		return 0;
	if (n)
		memcpy(v->p + v->n, p, n);
	v->n += n;
	return 1;
}

/* The value of a literal as the language of the text reads it (escapes applied); a literal that needs the program to run has none. */
static int ev_literal(struct kgenome_dtx_ev *e, uint32_t i, struct kgenome_dtx_val *out)
{
	const struct kgenome_dtx_tok *t = &e->x->t[i];
	struct kgenome_textual_value_req rq = { .lang = e->x->lang->lit_lang ? e->x->lang->lit_lang : e->x->lang->id, .lit = e->x->in + t->off, .len = t->len,
						.open_len = t->open, .close_len = t->close, .flags = t->fl };
	struct kgenome_textual_value_res rs;
	uint32_t room;

	if (t->len < (uint32_t)t->open + t->close || (t->fl & KGENOME_TEXTUAL_F_OPEN))
		return 0;
	room = t->len - t->open - t->close;
	if (room > KGENOME_DTX_EV_VMAX - out->n) {
		kgenome_dtx_ev_cut(e->x);
		return 0;
	}
	{
		uint8_t *tmp = malloc(room ? room : 1u);
		int ok;

		if (!tmp) {
			kgenome_diag_note(e->x->s, KGENOME_NOMEM);
			return 0;
		}
		rq.out = tmp;
		rq.cap = room;
		ok = kgenome_textual_value(&rq, &rs) == KGENOME_TEXTUAL_OK && kgenome_dtx_ev_val_put(e->x, out, tmp, rs.n_out);
		free(tmp);
		return ok;
	}
}

/* ---- the pure functions ---------------------------------------------------- */

static int is_name(const struct kgenome_dtx *x, uint32_t i, const char *w)
{
	size_t n = strlen(w), k;

	if (x->t[i].len != n)
		return 0;
	for (k = 0; k < n; k++)
		if (kof_lower_byte(x->in[x->t[i].off + k]) != w[k])
			return 0;
	return 1;
}

/*
 * A ROW OF THE LANGUAGE'S TABLE, RUN over a[0..n): which argument is which, the numbers and chr are kgenome_textual_fn_run's - the form that writes a call on literals as its
 * value asks the same - and what the op does is the hook's (x->apply, the engine's). Every shape of row comes here: a call by name, a method (its receiver is a[0]), an operator
 * (its left side is). The answer is appended to `o`. 0 for one the row or the hook refuses (a user function never gets here: the caller found no row).
 */
int kgenome_dtx_ev_run_row(struct kgenome_dtx_ev *e, const struct kgenome_textual_fn *f, const struct kgenome_dtx_val *a, uint32_t n, struct kgenome_dtx_val *o)
{
	const struct kgenome_dtx *x = e->x;
	struct kgenome_textual_arg args[KGENOME_DTX_EV_ARGS];
	uint32_t got = 0, k;

	if (n > KGENOME_DTX_EV_ARGS)
		return 0;
	if (f->form == KGENOME_TEXTUAL_FN_FORM_NEVER)
		e->x->saw_decoder = 1;
	for (k = 0; k < n; k++) {
		args[k].p = a[k].p;
		args[k].n = a[k].n;
	}
	/*
	 * ROOM FOR THE ANSWER: twice the subject and a page first, because most of these functions do not grow what they are given and a
	 * megabyte per call would be paid thousands of times over for a name; and if the hook says it did not fit, all that is left. A
	 * value is bounded by KGENOME_DTX_EV_VMAX, and one the bound refuses is "not constant" - the one answer this evaluator has for what it
	 * cannot follow.
	 */
	{
		uint32_t left = KGENOME_DTX_EV_VMAX - o->n, first = left;
		int ok;

		if (f->subject < n && left > 4096u && a[f->subject].n <= (left - 4096u) / 2u)
			first = 2u * a[f->subject].n + 4096u;
		ok = kgenome_dtx_ev_val_room(e->x, o, first, 1) && kgenome_textual_fn_run(f, args, n, x->apply, x->apply_user, o->p + o->n, first, &got);
		if (!ok && first < left)
			ok = kgenome_dtx_ev_val_room(e->x, o, left, 1) && kgenome_textual_fn_run(f, args, n, x->apply, x->apply_user, o->p + o->n, left, &got);
		if (!ok)
			return 0;
	}
	o->n += got;
	return 1;
}

/*
 * THE CALL AT TOKEN `i`: the token of its "(" and the bytes of its name, or 0. A name is one token (`chr(65)`), or - where the language writes the function with
 * its receiver (`String.fromCharCode(...)`, `string.char(...)`) - names joined by "." with nothing between them, taken whole: the table's row is that spelling. A
 * A name that is a MEMBER of something else (`obj.chr(65)`) is that object's method and not the builtin, and needs no guard here: an expression begins at
 * `obj`, and the dotted name `obj.chr` is no row of the table (the form's call stage, which meets `chr` on its own, has the guard: member_dot).
 */
static uint32_t ev_callee(const struct kgenome_dtx *x, uint32_t i, uint32_t end, uint32_t *noff, uint32_t *nlen)
{
	const struct kgenome_dtx_tok *t = &x->t[i];
	uint32_t j = i;

	if (t->k == 'P')
		return kgenome_dtx_ev_static_callee(x, i, end, noff, nlen);
	if (t->k != 'I' && t->k != 'V')
		return 0;
	while (j + 2u < end && kgenome_dtx_is_p(x, j + 1u, '.') && x->t[j + 1u].off == x->t[j].off + x->t[j].len && x->t[j + 2u].k == 'I' &&
	       x->t[j + 2u].off == x->t[j + 1u].off + 1u)
		j += 2u;
	/* the receiver of a dotted name is a bare name, which a language without a sigil reads as a variable ('V'): only a run of names, never a variable called. With a
	 * sigil a 'V' is a variable and its "." is a join (`$a.str_replace(...)`): not a dotted name. */
	if (t->k == 'V' && x->lang->sigil)
		return 0;
	if ((t->k == 'V' && j == i) || !kgenome_dtx_is_p(x, j + 1u, '(') || x->match[j + 1u] <= 0 || (uint32_t)x->match[j + 1u] >= end)
		return 0;
	*noff = t->off;
	*nlen = x->t[j].off + x->t[j].len - t->off;
	return j + 1u;
}

/* Do the tokens before `i` spell a join operator of the language (lua's two dots)? */
static int ev_join_before(const struct kgenome_dtx *x, uint32_t i)
{
	const char *const *c = x->lang->concat;
	uint32_t k;

	for (k = 0; c && c[k]; k++) {
		uint32_t n = (uint32_t)strlen(c[k]), j;

		if (i < n)
			continue;
		for (j = 0; j < n && kgenome_dtx_is_p(x, i - n + j, c[k][j]); j++)
			;
		if (j == n)
			return 1;
	}
	return 0;
}

/*
 * IS THE CALL READ AS ONE VALUE: one that answers several (lua's gsub: the text and how many it changed) gives the enclosing call all of them where it is the last argument,
 * and an assignment of several variables the second to the second variable. It is one value where a bracket holds it alone - `(string.gsub(s, a, b))` - or where it is an
 * operand of a join, either side, which takes the first of it. The call begins at token `start` and its ")" is `close`.
 */
static int ev_single_value(const struct kgenome_dtx *x, uint32_t start, uint32_t close)
{
	if (x->in_call)
		return 0;
	if (start && kgenome_dtx_is_p(x, start - 1u, '(') && kgenome_dtx_is_p(x, close + 1u, ')'))
		return 1;
	return kgenome_dtx_ev_join(x, close + 1u) != 0 || ev_join_before(x, start);
}

/*
 * A CALL OF A NAME, at the token whose "(" is `open`: the arguments are evaluated (and counted against the bounds whether or not the name is a row: they are read the same way
 * for a function of the program, which refuses afterwards), the row is found, and run. A join's last argument may be a list. 1 with the answer appended to `out` (or a list in
 * `L`); 0 for a name that is no row of the table, any argument that is not constant, a refusal.
 */
static int ev_call_named(struct kgenome_dtx_ev *e, uint32_t start, uint32_t open, uint32_t noff, uint32_t nlen, struct kgenome_dtx_val *out, struct kgenome_dtx_list *L)
{
	struct kgenome_dtx *x = e->x;
	struct kgenome_textual_fn f;
	struct kgenome_dtx_val a[KGENOME_DTX_EV_ARGS];
	struct kgenome_dtx_list lst = { 0 }, lres = { 0 };
	struct kgenome_dtx_val res = { 0 };
	uint32_t close = (uint32_t)x->match[open], k;
	int n, found, ok = 0;

	memset(a, 0, sizeof a);
	found = kgenome_textual_fn_find(x->lang->id, x->in + noff, nlen, &f) && f.shape == KGENOME_TEXTUAL_SHAPE_CALL;
	n = kgenome_dtx_ev_args(e, open, a, 0, found && f.op == KGENOME_TEXTUAL_DEC_JOIN, &lst);
	if (n <= 0 || !found)
		goto out;
	/* an answer of more than one value is one value only where the call is bracketed or an operand of a join */
	if ((f.flags & KGENOME_TEXTUAL_FN_MULTI) && !ev_single_value(x, start, close))
		goto out;
	ok = kgenome_dtx_ev_apply(e, &f, a, (uint32_t)n, &lst, &res, &lres);
	if (ok && lres.on) {
		ok = L != NULL;
		if (ok) {
			kgenome_dtx_ev_list_free(L);
			*L = lres;
			memset(&lres, 0, sizeof lres);
		}
	} else if (ok) {
		ok = kgenome_dtx_ev_val_put(x, out, res.p, res.n);
		out->str = 1;
	}
out:
	for (k = 0; k < KGENOME_DTX_EV_ARGS; k++)
		kgenome_dtx_val_free(&a[k]);
	kgenome_dtx_val_free(&res);
	kgenome_dtx_ev_list_free(&lst);
	kgenome_dtx_ev_list_free(&lres);
	return ok;
}

/* One value: a literal, a number, a variable, a bracketed expression, a list, a cast, or a call of one of the pure functions. */
static int ev_primary(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L)
{
	struct kgenome_dtx *x = e->x;
	const struct kgenome_dtx_tok *t;
	uint32_t open, noff, nlen;
	int r;

	if (*i >= end)
		return 0;
	if (++x->steps > x->step_cap) {          /* the work the evaluator may spend on this text is spent: what is not read from here on is said (G8), not silently "not constant" */
		kgenome_dtx_ev_cut(x);
		return 0;
	}
	t = &x->t[*i];
	if (t->k == 'S') {
		(*i)++;
		/* a typed language's string is a plain one: a prefix (python's b"", r"", f"", c#'s @"", lua's [[ ]]) is a bytes or a raw or a verbatim literal, which
		 * is not written back as a plain one */
		out->str = !x->lang->typed || t->open == 1u;
		if (!ev_literal(e, *i - 1u, out))
			return 0;
		/* TWO LITERALS SIDE BY SIDE ARE ONE where the language reads them so (python's "a" "b"): they are joined when the program is read, before anything that follows
		 * applies, so `"a" "b".upper()` is "AB" and `"Ab" "".replace("A", "z")` is "zb" - a method is the whole literal's, and a join of the pieces in the join level would
		 * have given it to the last piece alone (found by the interpreter differential, tests/unit/diag_text_oracle.c and diag_text_ops.c) */
		while (x->lang->adjacent && *i < end && x->t[*i].k == 'S') {
			uint8_t piece = !x->lang->typed || x->t[*i].open == 1u;

			(*i)++;
			if (!ev_literal(e, *i - 1u, out))
				return 0;
			out->str = (uint8_t)(out->str | piece);
			*built = 1;
		}
		return 1;
	}
	if (t->k == 'P' && x->in[t->off] == '-' && *i + 1u < end && x->t[*i + 1u].k == 'I' && x->t[*i + 1u].len &&
	    kof_is_digit(x->in[x->t[*i + 1u].off])) {                        /* a negative number: "-" then digits */
		static const uint8_t minus = '-';

		*i += 2u;
		return kgenome_dtx_ev_val_put(x, out, &minus, 1) && kgenome_dtx_ev_val_put(x, out, x->in + x->t[*i - 1u].off, x->t[*i - 1u].len);
	}
	if (t->k == 'I' && t->len && kof_is_digit(x->in[t->off])) {          /* a number */
		uint32_t len = t->len;

		(*i)++;
		/* 2.58 is one number: the walk's tokens are `2` `.` `58`, and read as php's join they were the string '258' */
		if (*i + 1u < end && x->t[*i].k == 'P' && x->in[x->t[*i].off] == '.' && x->t[*i].off == t->off + t->len &&
		    x->t[*i + 1u].k == 'I' && x->t[*i + 1u].off == x->t[*i].off + 1u && kof_is_digit(x->in[x->t[*i + 1u].off])) {
			len = x->t[*i + 1u].off + x->t[*i + 1u].len - t->off;
			*i += 2u;
		}
		return kgenome_dtx_ev_val_put(x, out, x->in + t->off, len);
	}
	if (x->shapes && (r = kgenome_dtx_ev_list_primary(e, i, end, L)) != 0)
		return r > 0;
	if (x->shapes && (r = kgenome_dtx_ev_cast(e, i, end, out, built, L)) != 0) {
		if (r > 0)
			*built = 1;
		return r > 0;
	}
	if (t->k == 'P' && x->in[t->off] == '(') {
		uint32_t close = x->match[*i] > 0 ? (uint32_t)x->match[*i] : end, j = *i + 1u;
		uint8_t in_call = x->in_call;
		int b0 = *built, ok;

		/* a bracket takes the first value of what it holds: a call inside it is one value (lua's `(string.gsub(s, a, b))`) */
		x->in_call = 0;
		ok = close < end && kgenome_dtx_ev_expr(e, &j, close, out, built, NULL) && j == close;
		x->in_call = in_call;
		if (!ok)
			return 0;
		*i = close + 1u;
		*built = x->lang->typed ? b0 | *built : 1;      /* brackets alone build nothing in a typed language: `(b"x")` is the literal it holds */
		return 1;
	}
	if ((t->k == 'I' || t->k == 'V' || t->k == 'P') && (open = ev_callee(x, *i, end, &noff, &nlen)) != 0) {
		uint32_t close = (uint32_t)x->match[open];

		if (!ev_call_named(e, *i, open, noff, nlen, out, L))
			return 0;
		*i = close + 1u;
		*built = 1;
		return 1;
	}
	if (t->k == 'V') {
		uint32_t used;
		struct kgenome_dtx_var *v = kgenome_dtx_var_for(x, *i, &used, 0);

		struct kgenome_dtx_val tmp;
		int ok, b2;

		/* The variable is evaluated into a value of its own and appended: kgenome_dtx_eval_var starts its answer from nothing, and
		 * handing it `out` - which already holds what came before the "." - threw that away (a join of eight variables was its last). */
		if (!v || (x->strict && (v->scope || v->n_set != 1u || v->n_app)) || !kgenome_dtx_eval_var(x, v, &tmp, &b2))
			return 0;
		ok = kgenome_dtx_ev_val_put(x, out, tmp.p, tmp.n);
		out->str |= tmp.str;
		kgenome_dtx_val_free(&tmp);
		if (!ok)
			return 0;
		*i += used;
		*built = 1;
		return 1;
	}
	return 0;
}

/* A value is a term: a primary, then what is written after it (`.replace(a, b)`, `[::-1]`). A list the term ends as is handed to `L`; with none, a list is not a value. */
int kgenome_dtx_ev_term(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L)
{
	struct kgenome_dtx_list pl = { 0 };
	uint32_t base = out->n;
	int ok, islist;

	ok = ev_primary(e, i, end, out, built, &pl) && (!e->x->shapes || kgenome_dtx_ev_postfix(e, i, end, out, base, built, &pl));
	islist = pl.on;
	if (ok && islist && L) {
		kgenome_dtx_ev_list_free(L);
		*L = pl;
		return 1;
	}
	kgenome_dtx_ev_list_free(&pl);
	return ok && !islist;
}

/* How many tokens the operator that joins two strings is, at token `i`: the row's (php ".", lua "..", js "+"), 0 when it is none. */
uint32_t kgenome_dtx_ev_join(const struct kgenome_dtx *x, uint32_t i)
{
	const char *const *c = x->lang->concat;
	uint32_t k;

	for (k = 0; c && c[k]; k++) {
		uint32_t n = (uint32_t)strlen(c[k]), j;

		for (j = 0; j < n && kgenome_dtx_is_p(x, i + j, c[k][j]); j++)
			;
		if (j == n)
			return n;
	}
	return 0;
}

/* Is the join at token `i` a "+": the one operator that adds numbers as well as joins strings. */
static int ev_is_plus(const struct kgenome_dtx *x, uint32_t i)
{
	return kgenome_dtx_is_p(x, i, '+') && !kgenome_dtx_is_p(x, i + 1u, '+') && !kgenome_dtx_is_p(x, i + 1u, '=');
}

/* An operand of a join: a term and the operators that bind tighter than the join (python's `*`). */
static int ev_operand(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L)
{
	uint32_t base = out->n, from = *i;

	if (!kgenome_dtx_ev_term(e, i, end, out, built, L))
		return 0;
	if (L && L->on)                 /* a list is not an operand of anything here but a list operator's */
		return 1;
	if (e->x->n_ops) {
		struct kgenome_dtx_at at = { i, end, from, base, built };

		return kgenome_dtx_ev_ops(e, &at, out, 1, L);
	}
	return 1;
}

/* The joins of terms: `a . b . c`. (Two literals side by side are one literal and are read by ev_primary: what follows them is the whole's.) */
int kgenome_dtx_ev_join_level(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L)
{
	uint32_t jn;
	uint8_t before = out->str, acc;
	int joined = 0;

	out->str = 0;
	if (!ev_operand(e, i, end, out, built, L))
		return 0;
	if (L && L->on) {
		out->str = before;
		return !(*i < end && kgenome_dtx_ev_join(e->x, *i));
	}
	acc = out->str;
	while (*i < end && (jn = kgenome_dtx_ev_join(e->x, *i)) != 0) {
		int plus = jn && e->x->lang->typed && ev_is_plus(e->x, *i);

		*i += jn;
		*built = 1;
		out->str = 0;
		if (!ev_operand(e, i, end, out, built, NULL))
			return 0;
		/* "+" joins two STRINGS, in every language that has one; with a number on either side it is a sum (vbscript's "4" + 5 is 9, powershell's 5 + "4" is 9)
		 * or a join (javascript's "4" + 5 is "45") according to the language, and the evaluator does not know which: not constant. A CHARACTER (powershell's
		 * `[char]65`, a value of 2) is no string: `"a" + [char]66` is a string, and `[char]65 + [char]66` is a sum - so it may be the right side of a join and
		 * never its left. */
		if (plus && !((acc & 1u) && out->str))
			return 0;
		acc = (uint8_t)((acc | out->str | (jn && !plus)) & 1u);
		joined = 1;
	}
	out->str = (uint8_t)(before | (joined ? acc & 1u : acc));
	return 1;
}

/*
 * An expression: the join of terms, and the operators that bind looser than it (powershell's -replace: `'a' + 'b' -replace 'a', 'c'` replaces in the joined value). A list
 * the join level ends with is the left side of such an operator (`('a', 'b') -join ''`), so it is held here even for a caller that takes none; one that is left at the end is
 * handed to `L`, or is not a value.
 */
int kgenome_dtx_ev_expr(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L)
{
	struct kgenome_dtx_list local = { 0 };
	struct kgenome_dtx_list *lp = L ? L : &local;
	uint32_t base = out->n, from = *i;
	int ok;

	if (e->x->ev_nest >= KGENOME_DTX_EV_NEST) {
		kgenome_dtx_ev_cut(e->x);
		return 0;
	}
	e->x->ev_nest++;
	{
		struct kgenome_dtx_at at = { i, end, from, base, built };

		ok = kgenome_dtx_ev_join_level(e, i, end, out, built, lp) && (!e->x->n_ops || kgenome_dtx_ev_ops(e, &at, out, 0, lp));
	}
	e->x->ev_nest--;
	if (!L && local.on)
		ok = 0;
	kgenome_dtx_ev_list_free(&local);
	return ok;
}

int kgenome_dtx_eval_range(struct kgenome_dtx *x, uint32_t rs, uint32_t re, struct kgenome_dtx_val *out, int *built)
{
	struct kgenome_dtx_ev e = { x };
	uint32_t i = rs;

	memset(out, 0, sizeof *out);
	*built = 0;
	if (rs >= re || !kgenome_dtx_ev_expr(&e, &i, re, out, built, NULL) || i != re) {
		kgenome_dtx_val_free(out);
		return 0;
	}
	return 1;
}

int kgenome_dtx_eval_var(struct kgenome_dtx *x, const struct kgenome_dtx_var *v, struct kgenome_dtx_val *out, int *built)
{
	struct kgenome_dtx_ev e = { x };
	const struct kgenome_dtx_seg *g;
	uint32_t s = 0;

	memset(out, 0, sizeof *out);
	*built = 0;
	if (v->unknown || !v->nseg)
		return 0;
	/* a variable that is evaluated while it is being evaluated ($a = $a . 'x') has no constant value: that is the program's, and no bound that fired */
	for (s = 0; s < (uint32_t)x->ev_depth; s++)
		if (x->ev_stack[s] == v)
			return 0;
	/* a chain of variables deeper than the bound is a bound that fired (G5: it was "not constant", and a name behind nine aliases was lost without a word) */
	if (x->ev_depth >= KGENOME_DTX_EV_DEPTH) {
		kgenome_dtx_ev_cut(x);
		return 0;
	}
	x->ev_stack[x->ev_depth++] = v;
	s = 0;
	for (g = kgenome_dtx_seg_next(x, v, NULL); g; g = kgenome_dtx_seg_next(x, v, g), s++) {
		uint32_t i = g->rs;

		if (!kgenome_dtx_ev_expr(&e, &i, g->re, out, built, NULL) || i != g->re) {
			kgenome_dtx_val_free(out);
			x->ev_depth--;
			return 0;
		}
		if (s)
			*built = 1;
	}
	x->ev_depth--;
	return 1;
}

/*
 * ELEMENT `n` OF AN ARRAY LITERAL: array(a, b, c) or [a, b, c]. The elements are the stretches between the commas of its own
 * bracket (the brackets nested in an element are skipped by their partners), and the one asked for is evaluated.
 */
int kgenome_dtx_eval_element(struct kgenome_dtx *x, uint32_t lb, struct kgenome_dtx_val *out, int *built)
{
	struct kgenome_dtx_ev e = { x };
	struct kgenome_dtx_val idx;
	struct kgenome_textual_arg ia;
	uint32_t nl, rb, j, rs, ro, n = 0;
	long want;
	struct kgenome_dtx_var *v;
	const struct kgenome_dtx_seg *g0;
	int ok;

	memset(out, 0, sizeof *out);
	*built = 0;
	if (lb == 0 || x->match[lb] <= 0 || x->t[lb - 1u].k != 'V')
		return 0;
	v = kgenome_dtx_var_for(x, lb - 1u, &nl, 0);
	if (!v || v->unknown || v->nseg != 1u)
		return 0;
	rb = (uint32_t)x->match[lb];
	memset(&idx, 0, sizeof idx);
	j = lb + 1u;
	ok = kgenome_dtx_ev_expr(&e, &j, rb, &idx, built, NULL) && j == rb;
	if (ok) {
		ia.p = idx.p;
		ia.n = idx.n;
		ok = kgenome_textual_arg_num(&ia, &want) && want >= 0;
	}
	kgenome_dtx_val_free(&idx);
	if (!ok)
		return 0;
	/* the right side must be exactly the array literal */
	g0 = kgenome_dtx_seg_next(x, v, NULL);
	if (!g0)
		return 0;
	rs = g0->rs;
	ro = g0->re;
	if (rs >= ro)
		return 0;
	if (x->t[rs].k == 'I' && kgenome_dtx_is_p(x, rs + 1u, '(') && x->t[rs].len == 5u && is_name(x, rs, "array"))
		rs++;
	else if (!kgenome_dtx_is_p(x, rs, '['))
		return 0;
	if (x->match[rs] <= 0 || (uint32_t)x->match[rs] + 1u != ro)
		return 0;
	{
		uint32_t close = (uint32_t)x->match[rs], i = rs + 1u, from = i;

		for (; i <= close; i++) {
			if (i == close || (kgenome_dtx_is_p(x, i, ',') && 1)) {
				if (n == (uint32_t)want) {
					uint32_t k = from;

					if (!kgenome_dtx_ev_expr(&e, &k, i, out, built, NULL) || k != i) {
						kgenome_dtx_val_free(out);
						return 0;
					}
					*built = 1;     /* the name is picked out of an array by an index: it is not written where it is called */
					return 1;
				}
				n++;
				from = i + 1u;
			} else if (x->match[i] > (int32_t)i && x->t[i].k == 'P' &&
				   (x->in[x->t[i].off] == '(' || x->in[x->t[i].off] == '[' || x->in[x->t[i].off] == '{')) {
				i = (uint32_t)x->match[i];
			}
		}
	}
	return 0;
}
