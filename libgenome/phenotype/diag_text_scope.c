/*
 * diag_text_scope.c - which function a token is in, for the variables of the TEXT route.
 *
 * A VARIABLE BELONGS TO THE FUNCTION IT IS WRITTEN IN. `$body` in one method and `$body` in another are two variables, and a
 * table keyed by the spelling alone made a request value in one reach the eval of the other (WordPress: a file's contents in
 * one method of PHPMailer reached a call_user_func three methods away). One pass over the tokens gives each its scope:
 * a function's header (its parameters and `use` list) and its body are one scope, a nested function is another, and the top of
 * the file is 0. `global $a` makes `$a` the top level's variable inside that function and `use ($a)` the enclosing scope's;
 * `$GLOBALS['a']` is always the top level's.
 *
 * NO CONTROL FLOW IS READ and none is needed: a scope is the extent of a body the language delimits, and HOW it delimits it is the row's
 * `blocks`: a brace pair the lexer already matched (php, js, perl; java and c# by the shape `name(...) {`), the lines more indented than the
 * `def` (python), or the `end` that matches, counting the words that open a block (lua, ruby). One pass, one stack, whichever the language.
 */

#include <stdlib.h>

#include "diag_text_walk.h"

/* How far an arrow function's expression body is looked for the end of: `(a)=>(a)=>(a)=>...` has each body run to the end of the text, so the scan is the
 * bound. A body longer than this has its scope end here (what the corpus's longest body is was not measured). */
#define ARROW_SCAN 4096u
#define SCOPE_NONE 0xffffffffu

/* A function's extent: the token its header ends at (`hdr`, the scope's first tokens run to it), the last token of its body (`close`), and
 * the token of its `use (...)` list, when there is one. */
struct extent {
	uint32_t hdr, close, use;
	uint32_t par;           /* the "(" of the parameter list, 0 when there is none: its names are the function's own (lexical languages) */
	uint32_t from;          /* the first token that belongs to the scope, when it is before the keyword (an arrow function's parameters), else 0 */
	uint32_t head;          /* the same for a function with no keyword (`name(...) {`): its parameter list is before the "{" the scope is found at, and is the function's own, else 0 */
};

/* The `{` that begins the body of the function whose keyword is token `i`, or 0: `function &name(...) use (...) : type {`. */
static uint32_t function_body(const struct kgenome_dtx *x, uint32_t i, uint32_t *par, uint32_t *use)
{
	uint32_t j = i + 1u, k;

	while (j < x->nt && j < i + 4u && !kgenome_dtx_is_p(x, j, '(') && !(x->lang->fn_noparen && kgenome_dtx_is_p(x, j, '{')))
		j++;
	if (x->lang->fn_noparen && kgenome_dtx_is_p(x, j, '{')) {
		*par = 0;
		*use = 0;
		return x->match[j] > 0 ? j : 0;
	}
	if (!kgenome_dtx_is_p(x, j, '(') || x->match[j] <= 0)
		return 0;
	*par = j;
	*use = 0;
	j = (uint32_t)x->match[j] + 1u;
	if (x->lang->use_kw && j + 1u < x->nt && x->t[j].k == 'I' && kgenome_dtx_is_word(x, j, x->lang->use_kw) && kgenome_dtx_is_p(x, j + 1u, '(') &&
	    x->match[j + 1u] > 0) {
		*use = j + 1u;
		j = (uint32_t)x->match[j + 1u] + 1u;
	}
	for (k = 0; k < 8u && j < x->nt && !kgenome_dtx_is_p(x, j, '{') && !kgenome_dtx_is_p(x, j, ';'); k++)
		j++;                    /* a return type */
	return j < x->nt && kgenome_dtx_is_p(x, j, '{') && x->match[j] > 0 ? j : 0;
}

/* Where the line holding byte `off` begins. Asked for the tokens of a text in order, so it remembers the last answer and reads only the bytes since: on
 * one long line (minified code, 50 000 names after a `global`) every token read back to the line's start, which was the whole route. */
static uint32_t line_start(struct kgenome_dtx *x, uint32_t off)
{
	uint32_t b = off;

	if (x->lsa <= off) {
		while (b > x->lsa && !kgenome_dtx_eol(x->in, x->n_in, b - 1u))
			b--;
		if (b == x->lsa)
			b = x->lss;
	} else {
		while (b > 0 && !kgenome_dtx_eol(x->in, x->n_in, b - 1u))
			b--;
	}
	x->lsa = off;
	x->lss = b;
	return b;
}

/* The line a token is on begins with it: the column of its first byte (a tab is eight), or -1 when something else comes first. */
static int32_t line_first_col(struct kgenome_dtx *x, uint32_t i)
{
	uint32_t b = line_start(x, x->t[i].off), col = 0;

	for (; b < x->t[i].off; b++) {
		if (x->in[b] == ' ')
			col++;
		else if (x->in[b] == '\t')
			col = (col / 8u + 1u) * 8u;
		else
			return -1;
	}
	return (int32_t)col;
}

/* The column the line holding token `i` is indented to, whatever comes first on it (`async def`, `@decorator`). */
static uint32_t line_indent(struct kgenome_dtx *x, uint32_t i)
{
	uint32_t b = line_start(x, x->t[i].off), col = 0;

	for (; b < x->n_in && (x->in[b] == ' ' || x->in[b] == '\t'); b++)
		col = x->in[b] == ' ' ? col + 1u : (col / 8u + 1u) * 8u;
	return col;
}

/*
 * BLK_INDENT: every `def` and the lines under it, matched in ONE pass with a stack of the defs still open and kept in `match` (as block_pass does for
 * `end`): a line that begins a token at or left of a def's own indentation closes it. A def inside a def inside a def, a thousand deep, was a scan
 * to the end of the text for each (4 s on 1 MB); this is one.
 */
static int indent_pass(struct kgenome_dtx *x)
{
	const char *fn_kw = x->lang->fn_kw;
	struct { uint32_t tok, ind; } *stk;
	uint32_t sn = 0, k;

	if (!kgenome_dtx_charge(x, ((uint64_t)x->nt + 1u) * sizeof *stk))
		return 0;
	stk = malloc(((size_t)x->nt + 1u) * sizeof *stk);
	if (!stk) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		return 0;
	}
	for (k = 0; k < x->nt; k++) {
		int32_t col;

		if (x->t[k].k == 'T')
			continue;
		col = line_first_col(x, k);
		while (col >= 0 && sn && (uint32_t)col <= stk[sn - 1u].ind) {
			x->match[stk[sn - 1u].tok] = (int32_t)k - 1;
			sn--;
		}
		if (fn_kw && x->t[k].k == 'I' && kgenome_dtx_is_word(x, k, fn_kw)) {
			stk[sn].tok = k;
			stk[sn++].ind = line_indent(x, k);
		}
	}
	while (sn)
		x->match[stk[--sn].tok] = (int32_t)x->nt - 1;
	free(stk);
	return 1;
}

/* BLK_INDENT: `def name(...) -> t:`, and the extent indent_pass found. */
static int indent_extent(const struct kgenome_dtx *x, uint32_t i, struct extent *e)
{
	uint32_t j = i + 1u, k;

	while (j < x->nt && j < i + 4u && !kgenome_dtx_is_p(x, j, '('))
		j++;
	if (!kgenome_dtx_is_p(x, j, '(') || x->match[j] <= 0)
		return 0;
	e->par = j;
	j = (uint32_t)x->match[j] + 1u;
	for (k = 0; k < 8u && j < x->nt && !kgenome_dtx_is_p(x, j, ':'); k++)
		j++;                    /* a return annotation */
	if (!kgenome_dtx_is_p(x, j, ':') || x->match[i] <= (int32_t)j)
		return 0;
	e->hdr = j;
	e->use = 0;
	e->from = 0;
	e->close = (uint32_t)x->match[i];
	return 1;
}

/*
 * BLK_END: the words of the row that open a block and the one that closes it, matched in ONE pass with a stack and kept in `match` (a word
 * has no bracket to pair, so the slot is free): a function is looked up in constant time, and a file of ten thousand `def` with no `end`
 * costs one pass, not ten thousand.
 */
static int block_pass(struct kgenome_dtx *x)
{
	const struct kgenome_dtx_lang *l = x->lang;
	const char *const close_[] = { l->blk_close, NULL };
	uint32_t *stk, sn = 0, i;

	if (!kgenome_dtx_charge(x, ((uint64_t)x->nt + 1u) * sizeof *stk))
		return 0;
	stk = malloc(((size_t)x->nt + 1u) * sizeof *stk);
	if (!stk) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		return 0;
	}
	for (i = 0; i < x->nt; i++) {
		const struct kgenome_dtx_tok *t = &x->t[i];

		if ((t->k != 'I' && t->k != 'V') || kgenome_dtx_member(x, i))
			continue;
		if (kgenome_dtx_word_in(l->blk_open, x->in + t->off, t->len, l->fold) &&
		    (!kgenome_dtx_word_in(l->blk_open_first, x->in + t->off, t->len, l->fold) ||
		     line_first_col(x, i) >= 0 || (i && kgenome_dtx_is_term(x, i - 1u))))
			stk[sn++] = i;
		else if (l->blk_close && sn && kgenome_dtx_word_in(close_, x->in + t->off, t->len, l->fold)) {
			uint32_t o = stk[--sn];

			x->match[o] = (int32_t)i;
			x->match[i] = (int32_t)o;
		}
	}
	free(stk);
	return 1;
}

/* BLK_END: from the function word to its `end`; the parameters are the bracket that follows the name (lua `function f(a)`, ruby `def f(a)`). */
static int end_extent(const struct kgenome_dtx *x, uint32_t i, struct extent *e)
{
	uint32_t j = i + 1u;

	if (x->match[i] <= 0)
		return 0;
	while (j < x->nt && j < i + 4u && !kgenome_dtx_is_p(x, j, '(') && x->t[j].k != 'T')
		j++;
	e->par = kgenome_dtx_is_p(x, j, '(') && x->match[j] > 0 ? j : 0u;
	e->hdr = e->par ? (uint32_t)x->match[e->par] : i;
	e->use = 0;
	e->from = 0;
	e->close = (uint32_t)x->match[i];
	return 1;
}

/*
 * BLK_PAIR: `Function` and `Sub` up to the `End Function` / `End Sub` that names the same word, matched in ONE pass and kept in `match` as block_pass keeps its pairs. The opener is
 * not a function when `End` or `Exit` stands in front of it (`End Function`, `Exit Sub`), and a word with no `End` after it (a jscript `function` in an asp page) pairs with nothing and is
 * no scope. A function does not nest in the languages that have this form, so the last opener of each word is the one an `End` of that word closes.
 */
static int is_fn_open(const struct kgenome_dtx *x, uint32_t i)
{
	const struct kgenome_dtx_lang *l = x->lang;

	if (x->t[i].k != 'I' || kgenome_dtx_member(x, i))
		return 0;
	if (!((l->fn_kw && kgenome_dtx_is_word(x, i, l->fn_kw)) || (l->fn_kw2 && kgenome_dtx_is_word(x, i, l->fn_kw2))))
		return 0;
	return !(i && x->t[i - 1u].k == 'I' && (kgenome_dtx_is_word(x, i - 1u, "end") || kgenome_dtx_is_word(x, i - 1u, "exit")));
}

static void pair_pass(struct kgenome_dtx *x)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t open1 = 0, open2 = 0, i;
	int have1 = 0, have2 = 0;

	for (i = 0; i < x->nt; i++) {
		if (is_fn_open(x, i)) {
			if (l->fn_kw && kgenome_dtx_is_word(x, i, l->fn_kw))
				open1 = i, have1 = 1;
			else
				open2 = i, have2 = 1;
		} else if (i + 1u < x->nt && x->t[i].k == 'I' && kgenome_dtx_is_word(x, i, "end") && x->t[i + 1u].k == 'I') {
			if (have1 && l->fn_kw && kgenome_dtx_is_word(x, i + 1u, l->fn_kw)) {
				x->match[open1] = (int32_t)(i + 1u);
				have1 = 0;
			} else if (have2 && l->fn_kw2 && kgenome_dtx_is_word(x, i + 1u, l->fn_kw2)) {
				x->match[open2] = (int32_t)(i + 1u);
				have2 = 0;
			}
		}
	}
}

/* BLK_PAIR: `Function name(params)` / `Sub name`, up to the `End` pair_pass found. */
static int pair_extent(const struct kgenome_dtx *x, uint32_t i, struct extent *e)
{
	uint32_t j = i + 1u;

	if (!is_fn_open(x, i) || x->match[i] <= 0 || j >= x->nt || !(x->t[j].k == 'I' || x->t[j].k == 'V'))
		return 0;
	e->par = kgenome_dtx_is_p(x, j + 1u, '(') && x->match[j + 1u] > 0 ? j + 1u : 0u;
	e->hdr = e->par ? (uint32_t)x->match[e->par] : j;
	e->use = 0;
	e->from = 0;
	e->close = (uint32_t)x->match[i];
	return 1;
}

/* BLK_BRACE: the function word `i`, as php, js and perl write it. */
static int brace_extent(const struct kgenome_dtx *x, uint32_t i, struct extent *e)
{
	uint32_t par, use, b = function_body(x, i, &par, &use);

	if (!b)
		return 0;
	e->hdr = b;
	e->use = use;
	e->par = par;
	e->from = 0;
	e->close = (uint32_t)x->match[b];
	return 1;
}

/*
 * `name(...) {`: the `{` at token `b` begins a function whose keyword the language does not write (java and c# methods, js class methods).
 * A word of the row's `ctl_words` before the bracket - if, for, while, catch - is a statement and not a function. Up to four tokens may
 * stand between the ")" and the "{" (`throws X`).
 */
static int shape_extent(const struct kgenome_dtx *x, uint32_t b, struct extent *e)
{
	uint32_t j = b, k;

	if (x->match[b] <= 0 || b < 2u)
		return 0;
	/* a line break between the ")" and the "{" is the Allman style (`void Run(string c)` and the brace on the next line): the lexer's 'T' stands there, and a language that
	 * writes `name(...) {` writes it that way as often as the other (measured: the three .aspx shells whose methods are written so had no function scope) */
	if (j >= 1u && x->t[j - 1u].k == 'T')
		j--;
	for (k = 0; k < 5u && j > 1u && !kgenome_dtx_is_p(x, j - 1u, ')'); k++) {
		if (x->t[j - 1u].k != 'I' && x->t[j - 1u].k != 'V')
			return 0;
		j--;
	}
	if (j < 2u || !kgenome_dtx_is_p(x, j - 1u, ')') || x->match[j - 1u] < 1)
		return 0;
	k = (uint32_t)x->match[j - 1u] - 1u;
	if (x->t[k].k != 'I' || kgenome_dtx_word_in(x->lang->ctl_words, x->in + x->t[k].off, x->t[k].len, x->lang->fold))
		return 0;
	e->hdr = b;
	e->use = 0;
	e->par = (uint32_t)x->match[j - 1u];
	e->from = 0;
	e->head = e->par;
	e->close = (uint32_t)x->match[b];
	return 1;
}

/* Do the tokens from `i` spell the arrow the row names (`=>`, `->`). */
static int arrow_at(const struct kgenome_dtx *x, uint32_t i)
{
	const char *a = x->lang->arrow;
	uint32_t k;

	if (!a || !kgenome_dtx_is_p(x, i, a[0]))
		return 0;
	for (k = 0; a[k]; k++)
		if (!kgenome_dtx_is_p(x, i + k, a[k]))
			return 0;
	return 1;
}

/*
 * AN ARROW FUNCTION, `(a, b) => body` and `a => { ... }`: a scope of its own, whose parameters are written BEFORE the arrow and whose body is a
 * block or an expression. An expression ends where the bracket it is inside closes, or at a comma, a ";" or a line's end at its own level.
 * Without this, minified js - nothing but arrows - has one scope for the whole file and `t` is one variable.
 */
static int arrow_extent(struct kgenome_dtx *x, uint32_t i, struct extent *e)
{
	uint32_t an = (uint32_t)strlen(x->lang->arrow), b = i + an, k;

	if (i >= 1u && kgenome_dtx_is_p(x, i - 1u, ')') && x->match[i - 1u] > 0) {
		e->par = (uint32_t)x->match[i - 1u];
		e->from = e->par;
	} else if (i >= 1u && (x->t[i - 1u].k == 'V' || x->t[i - 1u].k == 'I')) {
		e->par = 0;
		e->from = i - 1u;
	} else {
		return 0;
	}
	e->use = 0;
	e->hdr = b - 1u;
	if (kgenome_dtx_is_p(x, b, '{') && x->match[b] > 0) {
		e->hdr = b;
		e->close = (uint32_t)x->match[b];
		return 1;
	}
	for (k = b; k < x->nt && k < b + ARROW_SCAN; k++) {
		if (x->t[k].k == 'T' || kgenome_dtx_is_p(x, k, ';') || kgenome_dtx_is_p(x, k, ',') || kgenome_dtx_is_p(x, k, ')') ||
		    kgenome_dtx_is_p(x, k, ']') || kgenome_dtx_is_p(x, k, '}'))
			break;
		if ((kgenome_dtx_is_p(x, k, '(') || kgenome_dtx_is_p(x, k, '[') || kgenome_dtx_is_p(x, k, '{')) && x->match[k] > 0)
			k = (uint32_t)x->match[k];
	}
	if (k >= b + ARROW_SCAN && k < x->nt)           /* the body ran past what is looked at: its scope ends here, and what follows is read as the enclosing scope's (said) */
		kgenome_dtx_cut(x);
	e->close = k - 1u;
	return k > b;
}

/* The names in a function's parameter list are its own: a name declared in the scope that is the scope's alias to itself (nothing else makes one). */
static int declare_params(struct kgenome_dtx *x, uint32_t id, const struct extent *e)
{
	uint32_t k, end;

	if (e->par) {
		end = (uint32_t)x->match[e->par];
		for (k = e->par + 1u; k < end; k++) {
			if (x->t[k].k == 'V' && !kgenome_dtx_alias_add(x, id, k, id))
				return 0;
			if ((kgenome_dtx_is_p(x, k, '(') || kgenome_dtx_is_p(x, k, '[') || kgenome_dtx_is_p(x, k, '{')) && x->match[k] > 0)
				k = (uint32_t)x->match[k];         /* a default value is not a parameter */
		}
	} else if (e->from && x->t[e->from].k != 'P' && x->t[e->from].k != 'S') {
		return kgenome_dtx_alias_add(x, id, e->from, id);
	}
	return 1;
}

/* Is the "{" at token `i` the body of one of the keyword functions opened a moment ago. */
static int body_of(const uint32_t *bodies, uint32_t n, uint32_t i)
{
	uint32_t k;

	for (k = 0; k < 4u && k < n; k++)
		if (bodies[k] == i)
			return 1;
	return 0;
}

int kgenome_dtx_scopes(struct kgenome_dtx *x)
{
	const struct kgenome_dtx_lang *l = x->lang;
	struct { uint32_t close, id; } *stk = NULL;
	uint32_t sp = 0, nsc = 0, i, k, nfn = 0;
	uint32_t gl_end = 0, gl_scope = 0, dm_end = 0, dm_scope = 0;       /* the end of the `global` and of the `Dim` statement whose names were taken last, and the scope they were taken for */
	const char *fn_kw = l->fn_kw, *fn_kw2 = l->fn_kw2, *local_kw = l->local_kw;     /* what the rows say is read once: this loop is per token */
	const int pair = l->blocks == KGENOME_DTX_BLK_PAIR, shape = l->shape != 0;
	uint32_t bodies[4] = { 0, 0, 0, 0 }, nbody = 0;       /* the "{" of the keyword functions just opened: a `name(...) {` that is one of them is the same function, not another */
	int want_parent;

	for (i = 0; i < x->nt; i++)
		nfn += (fn_kw && x->t[i].k == 'I' && kgenome_dtx_is_word(x, i, fn_kw)) || (fn_kw2 && x->t[i].k == 'I' && kgenome_dtx_is_word(x, i, fn_kw2)) ||
		       (shape && kgenome_dtx_is_p(x, i, '{')) || arrow_at(x, i);
	/* the stack of the functions still open holds at most one entry per function (no bound but the text's: the 64 it had merged the scope of the 65th nested function into the 64th's) */
	if (!kgenome_dtx_charge(x, (uint64_t)x->nt * sizeof *x->scope + (uint64_t)(nfn + 1u) * (sizeof *x->sparent + sizeof *stk)))
		return 0;
	stk = malloc(((size_t)nfn + 1u) * sizeof *stk);
	x->scope = malloc((size_t)x->nt * sizeof *x->scope);
	/* the scope each function is written in: a language whose functions see the variables around them reads it, and so does a call that looks for the function it names (diag_text_sum.c: only
	 * where the row says functions are lexical; php's are global whatever they are written in) */
	want_parent = l->lexical;
	x->sparent = want_parent ? calloc((size_t)nfn + 1u, sizeof *x->sparent) : NULL;
	if (!stk || !x->scope || (want_parent && !x->sparent)) {
		free(stk);
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		return 0;
	}
	for (i = 0; i < x->nt; i++)
		x->scope[i] = SCOPE_NONE;
	if ((l->blocks == KGENOME_DTX_BLK_END && !block_pass(x)) || (l->blocks == KGENOME_DTX_BLK_INDENT && !indent_pass(x))) {
		free(stk);
		return 0;
	}
	if (l->blocks == KGENOME_DTX_BLK_PAIR)
		pair_pass(x);
	if (nfn && (x->stages & KGENOME_DTX_ST_SUM) && !kgenome_dtx_sum_new(x)) {
		free(stk);
		return 0;
	}
	for (i = 0; i < x->nt && !x->oom; i++) {
		struct extent e = { 0, 0, 0, 0, 0, 0 };
		uint32_t outer;
		int fn = 0;

		while (sp && i > stk[sp - 1u].close)
			sp--;
		outer = sp ? stk[sp - 1u].id : 0u;
		if (x->scope[i] == SCOPE_NONE)
			x->scope[i] = outer;
		if (pair)
			fn = pair_extent(x, i, &e);
		else if (fn_kw && x->t[i].k == 'I' && kgenome_dtx_is_word(x, i, fn_kw))
			fn = l->blocks == KGENOME_DTX_BLK_INDENT ? indent_extent(x, i, &e)
			   : l->blocks == KGENOME_DTX_BLK_END ? end_extent(x, i, &e) : brace_extent(x, i, &e);
		else if (arrow_at(x, i))
			fn = arrow_extent(x, i, &e);
		else if (shape && kgenome_dtx_is_p(x, i, '{') && !body_of(bodies, nbody, i))
			fn = shape_extent(x, i, &e);
		if (fn && nsc < nfn) {
			uint32_t id = ++nsc;

			if (x->sparent)
				x->sparent[id] = x->scope[i];
			for (k = e.from ? e.from : e.head ? e.head : i + 1u; k <= e.hdr; k++)
				if (e.from || e.head || x->scope[k] == SCOPE_NONE)
					x->scope[k] = id;
			if ((l->lexical || l->global_default) && !declare_params(x, id, &e)) {
				free(stk);
				return 0;
			}
			if (x->sum && !kgenome_dtx_sum_fn(x, id, i, e.par, e.from, sp)) {
				free(stk);
				return 0;
			}
			if (shape && fn_kw && e.hdr < x->nt && kgenome_dtx_is_p(x, e.hdr, '{'))   /* js: `function f(a) {` is a keyword function AND looks like `f(a) {`: one scope, not two */
				bodies[nbody++ & 3u] = e.hdr;
			if (e.use)              /* the variables a closure takes are its enclosing scope's */
				for (k = e.use; k < (uint32_t)x->match[e.use]; k++)
					if (x->t[k].k == 'V' && !kgenome_dtx_alias_add(x, id, k, x->scope[i])) {
						free(stk);
						return 0;
					}
			stk[sp].close = e.close;
			stk[sp++].id = id;
		} else if (local_kw && x->t[i].k == 'I' && x->scope[i] != 0 && kgenome_dtx_is_word(x, i, local_kw)) {
			/* `Dim a, b`: the function's own variables (an array's size, `a(5)`, is skipped: a number is no name). Every name of the statement, whatever its length (G7: a window of 64 tokens
			 * left the 33rd name the top level's). A `Dim` met inside a statement already taken adds nothing: its names were. */
			if (i >= dm_end || x->scope[i] != dm_scope) {
				uint32_t last = sp && stk[sp - 1u].close < x->nt ? stk[sp - 1u].close : x->nt - 1u;     /* a statement ends with the function it is in: the scan is the function's, not the text's */

				for (k = i + 1u; k <= last && !kgenome_dtx_is_term(x, k); k++, x->listed++) {
					if ((kgenome_dtx_is_p(x, k, '(') || kgenome_dtx_is_p(x, k, '[')) && x->match[k] > 0)
						k = (uint32_t)x->match[k];
					else if (x->t[k].k == 'V' && !kgenome_dtx_alias_add(x, x->scope[i], k, x->scope[i])) {
						free(stk);
						return 0;
					}
				}
				dm_end = k;
				dm_scope = x->scope[i];
			}
		} else if (l->global_kw && x->t[i].k == 'I' && kgenome_dtx_is_word(x, i, l->global_kw) && x->scope[i] != 0) {
			/* `global a, b`: every name of the statement is the top level's (the same, and the same once) */
			if (i >= gl_end || x->scope[i] != gl_scope) {
				/* the list is variables and commas: the first token that is neither ends it, so a `global` costs its own names and a text of a million of them is one scan */
				for (k = i + 1u; k < x->nt && !kgenome_dtx_is_term(x, k) && (x->t[k].k == 'V' || kgenome_dtx_is_p(x, k, ',')); k++, x->listed++)
					if (x->t[k].k == 'V' && !kgenome_dtx_alias_add(x, x->scope[i], k, 0)) {
						free(stk);
						return 0;
					}
				gl_end = k;
				gl_scope = x->scope[i];
			}
		}
	}
	free(stk);
	x->nscope = nsc;
	return 1;
}
