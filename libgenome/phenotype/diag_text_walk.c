/*
 * diag_text_walk.c - THE CALLS THE WALK MAKES AND THE WALK ITSELF: what a call is (the name a variable's callee evaluates to, a function the text defines, a request that is read in
 * a body, a literal that is code), where its arguments go (the layers of code a script computes), the node a call makes and the frame its arguments are read in, a token of a
 * language that qualifies its names, and the loop over the tokens (kgenome_dtx_walk_range, kgenome_dtx_walk).
 *
 * Moved out of diag_text.c whole, with no change of what it does, when that file reached the size ceiling (1499 of 1500 lines): the split is at the line where the file
 * stops being the tokenizer and the links (diag_text.c: the lexer's spans into tokens, a link, the flow of a value into a frame, an assignment, a frame) and becomes the walk
 * that uses them. It reads four things of the first part, and they are the only ones that cross: kgenome_dtx_cap_of, kgenome_dtx_prod_cap, kgenome_dtx_link_role and
 * kgenome_dtx_end_assign (diag_text_walk.h). Every graph the route made before the move is the graph it makes now (tests/lib/genome/diag_text_scan_same.c and the node and link
 * dump of the 3607 script files of the corpora, byte for byte).
 */

#include <stdlib.h>

#include "diag_text_walk.h"
#include <textual/textual.h>

/* The name a variable's callee evaluates to, as the table's capability: 0 when it is not constant or not a name the table has. */
static uint16_t callee_cap(struct kgenome_dtx *x, const struct kgenome_dtx_val *val, char *nb, size_t nbn)
{
	if (!val->n || val->n >= nbn)
		return KGENOME_NUCLEO_NONE;
	memcpy(nb, val->p, val->n);
	nb[val->n] = 0;
	return kgenome_dtx_cap(x, val->p, val->n, NULL);
}

/*
 * A READ OF THE REQUEST'S OWN BODY. `file_get_contents('php://input')` opens no file: what it returns is what the sender posted, the
 * same value `$_POST` holds, and a shell that takes its payload from there (haha.php: `preg_match(.., file_get_contents('php://input'),
 * $m)` then `eval(gzuncompress(base64_decode($m[1])))`) has the request as its source. The first argument is the stream's name, and a
 * name the program builds is not read (the literal is).
 */
static int reads_request_body(const struct kgenome_dtx *x, uint32_t i)
{
	const char *w = x->lang->body_stream;
	const struct kgenome_dtx_tok *a;
	uint32_t n, k;

	if (!w || i + 2u >= x->nt || x->t[i + 2u].k != 'S')
		return 0;
	a = &x->t[i + 2u];
	if (a->len < (uint32_t)a->open + a->close)
		return 0;
	n = a->len - a->open - a->close;
	if (n != strlen(w))
		return 0;
	for (k = 0; k < n; k++)
		if (kof_lower_byte(x->in[a->off + a->open + k]) != w[k])
			return 0;
	return 1;
}

/* The row of the call whose name is `name` (as the table spells it, or as written: the language's fold decides), when it has one. */
static const struct kgenome_dtx_callsem *callsem_named(const struct kgenome_dtx *x, const char *name, uint32_t n)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t k, j;
	/* the first byte rejects almost every row before the length of its name is read (callgrind, 71 php files: 78 k lookups at 650 Ir, 50 M of a 1.5 G scan) */
	uint8_t c0 = n ? (l->fold ? kof_lower_byte((uint8_t)name[0]) : (uint8_t)name[0]) : 0u;

	/* BOTH SIDES are folded where the language folds: the table spells `CInt`, `Len`, `int.Parse` as the language does, and a name read from the text is lower-cased - one side
	 * folded made every row of vbscript's table (twelve, all capitalised) and aspx's three unable to match, so `CInt(Request("x"))` kept the request a number would not carry (S2-4) */
	for (k = 0; k < l->n_callsem; k++) {
		const char *w = l->callsem[k].name;

		if ((l->fold ? kof_lower_byte((uint8_t)w[0]) : (uint8_t)w[0]) != c0 || strlen(w) != n)
			continue;
		for (j = 0; j < n && kgenome_dtx_name_eq((const uint8_t *)name + j, (const uint8_t *)w + j, 1u, l->fold); j++)
			;
		if (j == n)
			return &l->callsem[k];
	}
	return NULL;
}

/* The node `n` was made by a name a value spelled (`b`, as the table spells it): its bracket is read by that name's row. */
static void note_named(struct kgenome_dtx *x, int32_t n, const char *b)
{
	x->named_node = n;
	x->named_cs = n >= 0 ? callsem_named(x, b, (uint32_t)strlen(b)) : NULL;
}

/* The row of the call whose "(" is token `i`, when the name before it has one. */
static const struct kgenome_dtx_callsem *callsem_of(struct kgenome_dtx *x, uint32_t i)
{
	char b[KGENOME_DTX_NAME];
	uint32_t n;

	if (!i || x->t[i - 1u].k != 'I')
		return NULL;
	n = x->lang->chain ? kgenome_dtx_chain_name(x, i - 1u, b, sizeof b, NULL) : 0u;
	if (!x->lang->chain) {
		if (x->t[i - 1u].len >= sizeof b)
			return NULL;
		memcpy(b, x->in + x->t[i - 1u].off, x->t[i - 1u].len);
		n = x->t[i - 1u].len;
	}
	return n ? callsem_named(x, b, n) : NULL;
}

/* The argument a call acts on, by the table's spelling of its name (a name the program built has no token to read it from). */
static uint32_t val_arg_named(const struct kgenome_dtx *x, const char *name)
{
	const struct kgenome_dtx_callsem *cs = callsem_named(x, name, (uint32_t)strlen(name));

	return cs ? cs->val : 0u;
}

/* A numeric cast, "(int)" and its kin, whose "(" is token `i`: the next value is a number, whatever it was. */
static int is_numeric_cast(const struct kgenome_dtx *x, uint32_t i)
{
	return i + 2u < x->nt && (x->t[i + 1u].k == 'I' || (!x->lang->sigil && x->t[i + 1u].k == 'V')) && kgenome_dtx_is_p(x, i + 2u, ')') &&
	       kgenome_dtx_word_in(x->lang->num_casts, x->in + x->t[i + 1u].off, x->t[i + 1u].len, x->lang->fold);
}

/*
 * A SUBSCRIPT: the "[" that follows a variable, a "]" or a property (`$a[...]`, `$a[0][...]`, `$this->items[...]`). What is inside
 * SELECTS an element of what is in front of it, and is not that element's value: `$handlers[$_GET['k']]` is a registry lookup, and
 * the request chose which entry, not what is in it. `[` after anything else begins an array literal, whose elements ARE its value.
 */
static uint8_t sub_bracket(const struct kgenome_dtx *x, uint32_t i)
{
	if (!i)
		return 0;
	if (x->t[i - 1u].k == 'V' || kgenome_dtx_is_p(x, i - 1u, ']'))
		return 1;
	return x->t[i - 1u].k == 'I' && kgenome_dtx_member(x, i - 1u);
}

/* ---- code the script computes ---------------------------------------------- */

/*
 * hoho.php hides its payload one step further than a decode: the text is JOINED out of eight variables, str_replace takes the marker
 * out of it, and `create_function('', $text)` makes a function of it that is then called. Nothing is encoded and no decoder is in the
 * file, but the program is not in the file either - it is a value the program computes. When the evaluator can follow that value to a
 * constant and it is the argument a node RUNS (eval's text, create_function's body), the text is lexed as code (a fragment: it has no
 * tag) and walked in this same scan, so the request it reads, the decodes it makes and the eval it ends in are nodes and links like any
 * other. Its nodes are told to be where the call that ran it is, in the file.
 *
 * BOUNDED BY THE SCAN, not by what the file says: sixteen layers deep, and the code of all the layers of one scan may not exceed thirty-two
 * times the file and sixty-four kilobytes (the allowance the engine gives what a script decodes). A layer past the depth is reported
 * (TRUNCATED) and one past the allowance is (OVER_BUDGET), and neither is analysed; it is never cut silently (G14: the depth was).
 */
#define LAYER_DEPTH 16u


/* The tokens of argument `val` of the call whose "(" is token `open`, as [*rs, *re). 0 when the call has no such argument. */
int kgenome_dtx_arg_range(const struct kgenome_dtx *x, uint32_t open, uint32_t val, uint32_t *rs, uint32_t *re)
{
	uint32_t close, j, arg = 0, from;

	if (open >= x->nt || x->match[open] <= 0)
		return 0;
	close = (uint32_t)x->match[open];
	from = open + 1u;
	for (j = from; j < close; j++) {
		char c;

		if (x->t[j].k != 'P')
			continue;
		c = (char)x->in[x->t[j].off];
		if ((c == '(' || c == '[' || c == '{') && x->match[j] > (int32_t)j) {
			j = (uint32_t)x->match[j];
		} else if (c == ',') {
			if (arg == val)
				break;
			arg++;
			from = j + 1u;
		}
	}
	if (arg != val || from >= j)
		return 0;
	*rs = from;
	*re = j;
	return 1;
}

/* The call whose "(" is token `open` runs its argument `val`: if that is a constant the evaluator can follow, it is code to walk. */
static void layer_of_call(struct kgenome_dtx *x, uint32_t open, uint32_t val)
{
	struct kgenome_dtx_val v;
	uint32_t rs, re;
	int built;

	if (!x->lay || !kgenome_dtx_arg_range(x, open, val, &rs, &re) || !kgenome_dtx_eval_range(x, rs, re, &v, &built))
		return;
	if (x->layer >= LAYER_DEPTH) {          /* a text this call runs, past the layers followed: not analysed, and said (it was dropped without a word) */
		if (v.n)
			kgenome_diag_note(x->s, KGENOME_TRUNCATED);
		kgenome_dtx_val_free(&v);
		return;
	}
	if (v.n && v.n <= x->lay->room) {
		x->lay->room -= v.n;
		kgenome_dtx_run_one(x->s, v.p, v.n, KGENOME_TEXTUAL_FRAGMENT, x, x->lay, x->layer + 1u, x->layer ? x->layer_at : x->t[open].off);
	} else if (v.n) {
		kgenome_diag_note(x->s, KGENOME_OVER_BUDGET);
	}
	kgenome_dtx_val_free(&v);
}

/*
 * AN ASSIGNMENT TO A VARIABLE WHOSE NAME IS A VALUE, `$$k = ...` and `${expr} = ...`: the token index where its right side begins, or 0.
 * (The "$" is token `i`; a "$" in front of a name is the variable-variable, and a "$" in front of a brace is the same with the name written
 * as an expression.)
 */
static uint32_t dyn_assign(const struct kgenome_dtx *x, uint32_t i)
{
	uint32_t j;

	if (i + 2u < x->nt && x->t[i + 1u].k == 'V')
		j = i + 2u;
	else if (i + 1u < x->nt && kgenome_dtx_is_p(x, i + 1u, '{') && x->match[i + 1u] > 0)
		j = (uint32_t)x->match[i + 1u] + 1u;
	else
		return 0;
	return kgenome_dtx_is_p(x, j, '=') && !kgenome_dtx_is_p(x, j + 1u, '=') ? j + 1u : 0u;
}

/* `new` is the token before token `i`. */
static int after_new(const struct kgenome_dtx *x, uint32_t i)
{
	return i && x->t[i - 1u].k == 'I' && kgenome_dtx_is_word(x, i - 1u, "new");
}

/*
 * THE NODE A VARIABLE'S VALUE MAKES WHEN IT NAMES WHAT IS RUN OR LOADED, at token `tok`. `by_name` is a call (a node of data-call) and
 * otherwise a class (data-load): the value is the callee,
 * and when the program wrote it out of constants (a literal, a join, str_replace over a scrambled one, $GLOBALS['f']) it is the table's
 * own name for what it is - a node of that name, BUILT when it was made. Otherwise, and for a class (which is not a name the table
 * has), the value is whatever its producers say: the sender, a decode, a function create_function made. Each of those is a link into
 * the node as the TARGET of the call or the load. -1 when nothing makes a node: a value the program wrote, or one nothing we follow
 * produced.
 */
int32_t kgenome_dtx_target_node(struct kgenome_dtx *x, const struct kgenome_dtx_var *v, uint32_t tok, uint32_t open, int by_name)
{
	int32_t n = -1;
	uint8_t k;

	if (v->lost)
		kgenome_dtx_cut(x);             /* the callee is read from the producers the variable still holds */
	if (by_name) {
		struct kgenome_dtx_val val;
		int built = 0;

		if (kgenome_dtx_eval_var(x, v, &val, &built)) {
			char b[64];
			uint16_t c = callee_cap(x, &val, b, sizeof b);

			if (c != KGENOME_NUCLEO_NONE) {
				n = kgenome_dtx_add_node(x, tok, c, b, built ? KGENOME_NUCLEO_F_BUILT : 0);
				note_named(x, n, b);
				if (n >= 0 && (c == KGENOME_NUCLEO_EVAL || c == KGENOME_NUCLEO_CREATE))
					layer_of_call(x, open, val_arg_named(x, b));       /* a name the program built, and the text it hands that name */
			}
			kgenome_dtx_val_free(&val);
		}
	}
	if (n >= 0)
		return n;               /* a name the program wrote out of constants: that is the node, whatever else flowed into it */
	for (k = 0; k < v->n_def; k++) {
		uint16_t dc = kgenome_dtx_prod_cap(x, v->def[k]);

		/* what reaches the name: the sender, a decode, or a function create_function made, which is called through its handle */
		if (dc == KGENOME_NUCLEO_REQUEST || dc == KGENOME_NUCLEO_DECODE || dc == KGENOME_NUCLEO_CREATE) {
			if (n < 0)
				n = by_name ? kgenome_dtx_add_node(x, tok, KGENOME_NUCLEO_DYNCALL, KGENOME_NUCLEO_DYNAMIC_NAME, 0)
					    : kgenome_dtx_add_node(x, tok, KGENOME_NUCLEO_DYNLOAD, KGENOME_NUCLEO_DYNLOAD_NAME, 0);
			kgenome_dtx_link_role(x, (int32_t)v->def[k], n, KGENOME_DIAG_ROLE_TARGET);
		}
	}
	return n;
}

/* A statement ends: a ";", or the 'T' a line break or the end of an island made. The calls it held without a bracket end with it. */
void kgenome_dtx_end_stmt(struct kgenome_dtx *x, struct kgenome_dtx_walk *w)
{
	w->drop_next = 0;
	while (w->nf && !w->ovf && w->fr[w->nf - 1u].stmt)
		kgenome_dtx_pop_frame(x, w);
	if (w->asg && w->nf <= w->a_nf)
		kgenome_dtx_end_assign(x, w);
	if (w->ret_fn && w->nf <= w->ret_nf)
		w->ret_fn = 0;
	if (x->lang->cmd)
		kgenome_dtx_cmd_reset(x, w);
}

/* A closing bracket: the calls without a bracket that were begun inside it end first. */
void kgenome_dtx_close_frame(struct kgenome_dtx *x, struct kgenome_dtx_walk *w)
{
	while (w->nf && !w->ovf && w->fr[w->nf - 1u].stmt)
		kgenome_dtx_pop_frame(x, w);
	kgenome_dtx_pop_frame(x, w);
}

/* The "[" at token `lb` subscripts the language's own table of globals (`window[n]`, `globals()[n]`, `_G[n]`): what is called is the value inside. */
static int scope_root(const struct kgenome_dtx *x, uint32_t lb)
{
	uint32_t k = lb - 1u;

	if (!x->lang->scope_objs)
		return 0;
	if (kgenome_dtx_is_p(x, k, ')') && k >= 2u && kgenome_dtx_is_p(x, k - 1u, '('))
		k -= 2u;
	return x->t[k].k != 'S' && x->t[k].k != 'P' && kgenome_dtx_word_in(x->lang->scope_objs, x->in + x->t[k].off, x->t[k].len, x->lang->fold);
}

/*
 * A CALL BY A VALUE ON THE GLOBALS: `window[n](...)`, `globals()[n](...)`, `_G[n](...)` - the callee is what is inside the brackets, so it is read as
 * `$f(...)` is: a name the program wrote out of constants is that name's node, and what the sender or a decode produced is a call of a value
 * (data-call). Without the form the language has no way to call what it does not name but this, and a shell written that way would be invisible.
 */
static int32_t scope_call(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t open, uint32_t lb)
{
	uint32_t rb = (uint32_t)x->match[lb], k, used;
	struct kgenome_dtx_val val;
	int built = 0;
	int32_t n = -1;

	if (rb == lb + 2u && x->t[lb + 1u].k == 'V') {
		struct kgenome_dtx_var *v = kgenome_dtx_var_for(x, lb + 1u, &used, 0);

		n = v ? kgenome_dtx_target_node(x, v, lb + 1u, open, 1) : -1;
	} else if (kgenome_dtx_eval_range(x, lb + 1u, rb, &val, &built)) {
		char b[KGENOME_DTX_NAME];
		uint16_t cap = callee_cap(x, &val, b, sizeof b);

		if (cap != KGENOME_NUCLEO_NONE) {
			n = kgenome_dtx_add_node(x, open, cap, b, built ? KGENOME_NUCLEO_F_BUILT : 0);
			note_named(x, n, b);
		}
		kgenome_dtx_val_free(&val);
	} else {
		/* an expression the program does not evaluate: what the sender or a decode produced into any part of it (a request node in it, or a
		 * variable the request was put in) is the name called */
		for (k = lb + 1u; k < rb; k++) {
			const struct kgenome_dtx_var *v = x->t[k].k == 'V' ? kgenome_dtx_var_for(x, k, &used, 0) : NULL;
			uint32_t d;

			if (v && v->lost)
				kgenome_dtx_cut(x);

			for (d = 0; d <= (v ? v->n_def : 0u); d++) {
				int32_t s = d ? (int32_t)v->def[d - 1u] : x->site[k];
				uint16_t sc = s >= 0 ? kgenome_dtx_prod_cap(x, (uint32_t)s) : KGENOME_NUCLEO_NONE;

				if (sc == KGENOME_NUCLEO_REQUEST || sc == KGENOME_NUCLEO_DECODE) {
					if (n < 0)
						n = kgenome_dtx_add_node(x, open, KGENOME_NUCLEO_DYNCALL, KGENOME_NUCLEO_DYNAMIC_NAME, 0);
					kgenome_dtx_link_role(x, s, n, KGENOME_DIAG_ROLE_TARGET);
				}
			}
		}
	}
	if (n >= 0)
		kgenome_dtx_flow(x, w, n, NULL);
	return n;
}

/*
 * THE RESULT OF A CALL, CALLED: `new Function(code)()`, `loadstring(code)()` - the "(" at token `i` follows the ")" of a call that made a function out of
 * text (or whose callee a decode or the request made), so what is called is that call's result: a data-call whose target is the node. The two-step
 * form `f = create_function(..); f()` is the same through a variable and is read by target_node; this is the form with no variable to hold it.
 * Only for the languages whose row has `chain` and `data_call` (php's `f()()` is left as it was; vb's `Request.QueryString(k)(j)` is an index).
 */
static int32_t result_call(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	uint32_t f;
	int32_t s, n;
	uint16_t sc;

	if (!i || !kgenome_dtx_is_p(x, i - 1u, ')') || x->match[i - 1u] < 1)
		return -1;
	f = (uint32_t)x->match[i - 1u] - 1u;
	s = x->t[f].k == 'I' ? x->site[f] : -1;
	sc = s >= 0 ? x->s->hit[s].cap : KGENOME_NUCLEO_NONE;
	if (sc != KGENOME_NUCLEO_CREATE && sc != KGENOME_NUCLEO_DECODE && sc != KGENOME_NUCLEO_REQUEST)
		return -1;
	n = kgenome_dtx_add_node(x, i, KGENOME_NUCLEO_DYNCALL, KGENOME_NUCLEO_DYNAMIC_NAME, 0);
	kgenome_dtx_link_role(x, s, n, KGENOME_DIAG_ROLE_TARGET);
	kgenome_dtx_flow(x, w, n, NULL);
	return n;
}

/* A call whose first argument is not one literal: the module or the object it names is a value (`__import__(x)`). No argument is none. */
static int arg0_not_literal(const struct kgenome_dtx *x, uint32_t open)
{
	uint32_t rs, re;

	return kgenome_dtx_arg_range(x, open, 0, &rs, &re) && !(re == rs + 1u && x->t[rs].k == 'S');
}

/* The node of the call whose name token is `at`, named `b` (`len` bytes), of capability `cap` - made at token `at`, the call's "(" being `at + 1`. */
int32_t kgenome_dtx_call_node(struct kgenome_dtx *x, uint32_t at, uint16_t cap, const char *b, uint32_t len, uint16_t flags)
{
	const struct kgenome_dtx_callsem *cs;
	int32_t n;

	if (cap == KGENOME_NUCLEO_DYNLOAD && kgenome_dtx_word_in(x->lang->load_names, (const uint8_t *)b, len, x->lang->fold) &&
	    arg0_not_literal(x, at + 1u))
		n = kgenome_dtx_add_node(x, at, cap, KGENOME_NUCLEO_DYNLOAD_NAME, flags);   /* a module named by a value: the row no program can write */
	else
		n = kgenome_dtx_add_node(x, at, cap, b, flags);
	if (n >= 0 && (cap == KGENOME_NUCLEO_EVAL || cap == KGENOME_NUCLEO_CREATE)) {
		cs = callsem_named(x, b, len);
		layer_of_call(x, at + 1u, cs ? cs->val : 0u);
	}
	x->site[at] = n;
	return n;
}

/*
 * THE OBJECT A METHOD IS CALLED ON is an argument of it: `f.delete()` after `f = new File($_GET['p'])` deletes what the request named, and the
 * value `f` holds is what flows into the call. The variable at the root of the call's chain, when it has producers, links into the node as the
 * call's first argument.
 */
void kgenome_dtx_receiver_into(struct kgenome_dtx *x, uint32_t i, int32_t n)
{
	char b[KGENOME_DTX_NAME];
	struct kgenome_dtx_var *v;
	uint32_t root = i, used, k;

	if (n < 0 || !kgenome_dtx_member(x, i) || !kgenome_dtx_chain_name(x, i, b, sizeof b, &root) || x->t[root].k != 'V')
		return;
	v = kgenome_dtx_var_for(x, root, &used, 0);
	if (v && v->lost)
		kgenome_dtx_cut(x);
	for (k = 0; v && k < kgenome_dtx_var_nprod(v); k++)
		kgenome_dtx_link(x, (int32_t)kgenome_dtx_var_prod(v, k), n, 0);
}

/*
 * A TOKEN OF A LANGUAGE THAT QUALIFIES ITS NAMES (row `chain`), read as a call or as the request: 1 when it was, 0 for a token that is read as any
 * other (a variable that is no request). A name in front of a bracket is the call whose qualified name diag_text_chain.c gives; a member that
 * begins a request ("request.args", `$ENV{QUERY_STRING}`) is a node of its own; a member name, a keyword and a number are nothing here - the chain
 * that begins before them has been read.
 *
 * `new X(a).m(b)` is ONE act of the class X ("ProcessBuilder.start" in the table): the node is made where the constructor is, so that what is given
 * to the constructor links into it, and the later `.m(` is told it is that node's.
 */
static int chain_tok(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t *ip, int32_t *pend)
{
	uint32_t i = *ip, len, fin, off = 0;
	const struct kgenome_dtx_tok *t = &x->t[i];
	char b[KGENOME_DTX_NAME];
	uint16_t cap;
	int32_t n;
	struct kgenome_dtx_chain_res cr = { 0 };

	if (t->k != 'I' && t->k != 'V')
		return 0;
	if (x->lang->req_obj && kgenome_dtx_req_obj(x, w, i, pend))     /* `Request["x"]`, `Request("x")` */
		return 1;
	if (t->k == 'V' || !kgenome_dtx_is_p(x, i + 1u, '(')) {
		int32_t e;

		if (kgenome_dtx_member(x, i))
			return kgenome_dtx_member_tok(x, w, i);
		e = !x->lang->bare_members && (t->k == 'V' || kgenome_dtx_join_after(x, i + 1u)) ? kgenome_dtx_request_end(x, i, b, sizeof b) : -1;
		if (e < 0)
			return t->k == 'I';
		n = kgenome_dtx_add_node(x, i, KGENOME_NUCLEO_REQUEST, b, 0);
		x->site[i] = n;
		x->site[e] = n;                  /* `request.args[0](x)`: the token before the "[" is the member's last */
		kgenome_dtx_flow(x, w, n, NULL);
		return 1;
	}
	if (x->site[i] >= 0) {                  /* the call a constructor in front began (below) */
		*pend = x->site[i];
		return 1;
	}
	fin = kgenome_dtx_member(x, i) ? 0u : kgenome_dtx_ctor_final(x, i);
	if (fin && (len = kgenome_dtx_chain_full(x, fin, b, sizeof b, &cr, 0)) != 0 &&
	    (cap = kgenome_dtx_chain_cap(x, &cr, b, len, &off)) != KGENOME_NUCLEO_NONE) {
		n = kgenome_dtx_call_node(x, fin, cap, b + off, len - off, cr.flags);
		x->site[i] = n;
		kgenome_dtx_flow(x, w, n, NULL);
		*pend = n;
		return 1;
	}
	len = kgenome_dtx_chain_full(x, i, b, sizeof b, &cr, 0);
	cap = len ? kgenome_dtx_chain_cap(x, &cr, b, len, &off) : KGENOME_NUCLEO_NONE;
	/* a module loader the table has no row for, called with a value (`require(req.query.m)`): the row no program can write, "(load)" */
	if (cap == KGENOME_NUCLEO_NONE && len && kgenome_dtx_word_in(x->lang->load_names, (const uint8_t *)b, len, x->lang->fold) && arg0_not_literal(x, i + 1u))
		cap = KGENOME_NUCLEO_DYNLOAD;
	if (cap == KGENOME_NUCLEO_NONE) {
		/* `f(x)` where f is a variable: the callee is whatever the program put in it (data-call) */
		struct kgenome_dtx_var *v = NULL;
		uint32_t used;

		if (x->lang->data_call && len == t->len && !kgenome_dtx_member(x, i))
			v = kgenome_dtx_var_for(x, i, &used, 0);
		n = v ? kgenome_dtx_target_node(x, v, i, i + 1u, 1) : -1;
		if (n >= 0) {
			x->site[i] = n;
			kgenome_dtx_flow(x, w, n, NULL);
		}
		*pend = n;
		return 1;
	}
	n = kgenome_dtx_call_node(x, i, cap, b + off, len - off, cr.flags);
	kgenome_dtx_flow(x, w, n, NULL);
	kgenome_dtx_receiver_into(x, i, n);
	*pend = n;
	return 1;
}

/*
 * `obj.field = v`, the "=" read from token `at` (the one after the variable): the token of that "=" when the variable is followed by one or more `.member` and an assignment (not
 * `==`), else 0. A row that qualifies names writes an object's inputs one member at a time (`psi.FileName = ..; psi.Arguments = ..; Process.Start(psi)`), and what the walk does with
 * the right side is give it to the object (the stage KGENOME_DTX_ST_FIELD): the object's own value - what class it is - is left as it was (`a_member`).
 */
static uint32_t field_target(const struct kgenome_dtx *x, uint32_t at)
{
	uint32_t m = at, jl, depth = 0;

	while ((jl = kgenome_dtx_join_after(x, m)) != 0 && m + jl < x->nt && (x->t[m + jl].k == 'I' || x->t[m + jl].k == 'V') && depth < 8u) {
		m += jl + 1u;
		depth++;
	}
	if (!depth || !kgenome_dtx_is_p(x, m, '=') || kgenome_dtx_is_p(x, m + 1u, '='))
		return 0;
	return m;
}

/* The tokens [from, to) walked: the file, or the tokens a string holds that run as code (a command it is, a substitution). */
void kgenome_dtx_walk_range(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t from, uint32_t to)
{
	uint32_t i;
	int32_t pend = -1;
	const struct kgenome_dtx_lang *l = x->lang;
	const uint8_t cmd = l->cmd;     /* the loop is the hot one: what the row says is read once */

	for (i = from; i < to && !x->s->halt && !x->oom; i++) {
		const struct kgenome_dtx_tok *t = &x->t[i];

		w->cur = i;
		if (t->k == 'P') {
			char c = (char)x->in[t->off];

			if (cmd && kgenome_dtx_cmd_punct(x, w, i))
				continue;                       /* a ")" that closes nothing: a case pattern's */
			if (l->dyn_var && c == '$' && dyn_assign(x, i)) {
				/* $$k = ... or ${expr} = ...: the name is a value, and the value is what the right side holds */
				if (w->asg)
					kgenome_dtx_end_assign(x, w);
				memset(&x->vdyn, 0, sizeof x->vdyn);
				w->asg = 1;
				w->av = &x->vdyn;
				w->a_nf = w->nf;
				w->a_nsf = w->nsf;
				w->a_rs = dyn_assign(x, i);
				w->a_append = 0;
				i = w->a_rs - 1u;
				continue;
			}
			if (c == '(' && pend < 0 && is_numeric_cast(x, i)) {
				w->drop_next = 1;       /* the operand that follows is a number */
				i += 2u;
				continue;
			}
			if (c == '(') {
				/* a call through an array read: $_POST[0](...) is whatever the sender chose; $fc[3](...) is the element
				 * of an array the program wrote, a name when the elements are constants */
				if (pend < 0 && l->chain && l->data_call)
					pend = result_call(x, w, i);
				if (pend < 0 && i >= 2u && x->match[i - 1u] > 0 && kgenome_dtx_is_p(x, i - 1u, ']')) {
					uint32_t lb = (uint32_t)x->match[i - 1u];

					if (lb > 0 && (x->t[lb - 1u].k == 'V' || (l->chain && x->t[lb - 1u].k == 'I')) && x->site[lb - 1u] >= 0 &&
					    x->s->hit[x->site[lb - 1u]].cap == KGENOME_NUCLEO_REQUEST) {
						pend = kgenome_dtx_add_node(x, i, KGENOME_NUCLEO_DYNCALL, KGENOME_NUCLEO_DYNAMIC_NAME, 0);
						kgenome_dtx_link_role(x, x->site[lb - 1u], pend, KGENOME_DIAG_ROLE_TARGET);
						kgenome_dtx_flow(x, w, pend, NULL);
					} else if (lb > 0 && scope_root(x, lb)) {
						pend = scope_call(x, w, i, lb);
					} else if (lb > 0) {
						struct kgenome_dtx_val val;
						int built = 0;

						if (kgenome_dtx_eval_element(x, lb, &val, &built)) {
							char b[64];
							uint16_t cap = callee_cap(x, &val, b, sizeof b);

							if (cap != KGENOME_NUCLEO_NONE) {
								pend = kgenome_dtx_add_node(x, i, cap, b, built ? KGENOME_NUCLEO_F_BUILT : 0);
								note_named(x, pend, b);
								kgenome_dtx_flow(x, w, pend, NULL);
							}
							kgenome_dtx_val_free(&val);
						}
					}
				}
				{
					const struct kgenome_dtx_callsem *cs = callsem_of(x, i);

					if (!cs && pend >= 0 && pend == x->named_node)
						cs = x->named_cs;       /* a call a value named is read by the row of the name it came to */
					kgenome_dtx_push_frame(w, pend, 0, cs, cs && (cs->flags & KGENOME_DTX_CS_CLEAN) && pend < 0);
					if (!w->ovf) {
						w->fr[w->nf - 1u].paren = 1;
						if (pend < 0 && x->sum) {       /* a call of a function the text defines: its arguments are what the parameters hold */
							w->fr[w->nf - 1u].ufn = kgenome_dtx_sum_callee(x, i);
							w->fr[w->nf - 1u].uscope = x->scope[i];
							w->nufn += w->fr[w->nf - 1u].ufn != 0u;
						}
					}
				}
				pend = -1;
			} else if (c == '[' || c == '{') {
				kgenome_dtx_push_frame(w, -1, 0, NULL, sub_bracket(x, i));
			} else if (c == ')' || c == ']' || c == '}') {
				kgenome_dtx_close_frame(x, w);
				if (cmd)
					kgenome_dtx_cmd_flush(x, w);
			} else if (c == ',') {
				w->drop_next = 0;
				if (w->nf && !w->ovf)
					w->fr[w->nf - 1u].arg++;
			} else if (c == ';' || (l->sep && c == (char)l->sep)) {
				kgenome_dtx_end_stmt(x, w);
			}
			continue;
		}
		if (t->k == 'T') {
			kgenome_dtx_end_stmt(x, w);
			continue;
		}
		if (t->k == 'S') {
			w->drop_next = 0;
			if (cmd)
				(void)kgenome_dtx_cmd_word(x, w, i);
			continue;
		}
		if (t->k > 'Z') {                       /* the kinds a row that reads statements and strings makes (lower case): a tag's name, a command string, a block */
			if (t->k == 'g')
				kgenome_dtx_tag(x, w, i);
			else
				i = kgenome_dtx_block(x, w, i);
			continue;
		}
		if (x->sum && t->len == x->ret_len && t->k == 'I' && x->scope[i] && kgenome_dtx_is_word(x, i, l->ret_kw) && !kgenome_dtx_member(x, i)) {
			w->ret_fn = x->scope[i];        /* what flows into the expression that follows, outside the arguments of a node, is what the function returns */
			w->ret_nf = w->nf;
			continue;
		}
		if (l->stmt_lead && t->k == 'I' && !kgenome_dtx_member(x, i) &&
		    kgenome_dtx_word_in(l->stmt_lead, x->in + t->off, t->len, l->fold)) {
			kgenome_dtx_end_stmt(x, w);             /* `Then` and `Else` begin a statement, and end the one before */
			continue;
		}
		if (cmd && kgenome_dtx_cmd_word(x, w, i)) {
			if (w->cmd_next > i)
				i = w->cmd_next - 1u;   /* the operands of a condition are skipped */
			continue;
		}
		if (t->k == 'I' && l->stmt_words && kgenome_dtx_word_in(l->stmt_words, x->in + t->off, t->len, l->fold) && kgenome_dtx_stmt_tok(x, w, i))
			continue;
		if (l->chain && chain_tok(x, w, &i, &pend))
			continue;
		if (t->k == 'I') {
			uint16_t cap;

			if (kgenome_dtx_is_p(x, i + 1u, '(') && (cap = kgenome_dtx_cap_of(x, i)) != KGENOME_NUCLEO_NONE) {
				char nb[64];
				int32_t n;

				if (cap == KGENOME_NUCLEO_FILE_OPEN && reads_request_body(x, i))
					cap = KGENOME_NUCLEO_REQUEST;
				n = kgenome_dtx_add_node(x, i, cap, kgenome_dtx_tok_name(x, i, nb, sizeof nb), 0);
				if (n >= 0 && (cap == KGENOME_NUCLEO_EVAL || cap == KGENOME_NUCLEO_CREATE)) {
					const struct kgenome_dtx_callsem *cs = callsem_of(x, i + 1u);

					layer_of_call(x, i + 1u, cs ? cs->val : 0u);
				}
				x->site[i] = n;
				kgenome_dtx_flow(x, w, n, NULL);
				pend = n;
			}
			continue;
		}
		/* a variable: a request value is a node of its own; any other is read through the producers it was given */
		{
			const uint8_t *vname;
			uint32_t vlen, used = kgenome_dtx_var_key(x, i, &vname, &vlen);
			struct kgenome_dtx_var *v = NULL, xt;
			uint16_t cap = KGENOME_NUCLEO_NONE;
			char nb[KGENOME_DTX_NAME];
			const char *spelt;

			if (!used)
				continue;
			if (x->sum) {
				uint32_t slot = kgenome_dtx_sum_param(x, i);

				if (slot) {
					/* the declaration of a parameter: what the function is called with is what it holds from here on */
					v = kgenome_dtx_var_for(x, i, &used, 1);
					if (v)
						kgenome_dtx_var_def(v, slot);
					i += used - 1u;
					continue;
				}
			}
			if (vlen < sizeof nb) {
				memcpy(nb, vname, vlen);
				nb[vlen] = 0;
				cap = kgenome_dtx_cap(x, vname, vlen, &spelt);
				/* a function's name is not case sensitive and a variable's is: "$_get" is not the request, "$_GET" is */
				if (cap != KGENOME_NUCLEO_NONE && l->fold && (!spelt || strlen(spelt) != vlen || memcmp(spelt, vname, vlen) != 0))
					cap = KGENOME_NUCLEO_NONE;
			}
			if (cap == KGENOME_NUCLEO_REQUEST && !(l->bare_members && kgenome_dtx_join_after(x, i + used))) {
				int32_t n = kgenome_dtx_add_node(x, i, cap, nb, 0);

				x->site[i] = n;
				kgenome_dtx_flow(x, w, n, NULL);
				i += used - 1u;
				continue;
			}
			/* `obj.field = v`: the object is given what v holds (it is the one unit an object is: its members have no variables of their own here) */
			if (x->stages & KGENOME_DTX_ST_FIELD) {
				uint32_t m = field_target(x, i + used);

				if (m) {
					v = kgenome_dtx_var_for(x, i, &used, 1);
					if (v) {
						if (w->asg)
							kgenome_dtx_end_assign(x, w);
						w->asg = 1;
						w->av = v;
						w->a_nf = w->nf;
						w->a_nsf = w->nsf;
						w->a_scope = x->scope[i];
						w->a_rs = m + 1u;
						w->a_append = 1;
						w->a_member = 1;
						i = m;
						continue;
					}
				}
			}
			/* $v = ...   and   $v .= ...   begin an assignment (not ==); a keyword argument `f(v=1)` is not one */
			{
				uint32_t alen = kgenome_dtx_append_len(x, i + used);
				int plain = kgenome_dtx_is_p(x, i + used, '=') && !kgenome_dtx_is_p(x, i + used + 1u, '=');

				if (plain && x->sum && l->ret_name && kgenome_dtx_sum_own_name(x, i)) {
					/* vbscript: `getOutput = x` inside Function getOutput is the function's return */
					w->ret_fn = x->scope[i];
					w->ret_nf = w->nf;
					i += used;
					continue;
				}

				if (plain && kgenome_dtx_names_arg(x, w)) {
					i += used - 1u;
					continue;
				}
				if (plain || alen) {
					int app = alen != 0;

					v = kgenome_dtx_var_for(x, i, &used, 1);
					if (!v)
						continue;
					if (w->asg)
						kgenome_dtx_end_assign(x, w);
					w->asg = 1;
					w->av = v;
					w->a_nf = w->nf;
					w->a_nsf = w->nsf;
					w->a_scope = x->scope[i];
					w->a_rs = i + used + (app ? alen : 1u);
					w->a_append = app;
					i += used - 1u + (app ? alen : 1u);
					continue;
				}
			}
			/* the variable a call writes: it is not read here, it is given what the call took from its other arguments */
			if (w->nf && !w->ovf && w->fr[w->nf - 1u].op && w->fr[w->nf - 1u].arg == w->fr[w->nf - 1u].op->dst) {
				w->fr[w->nf - 1u].dstv = kgenome_dtx_var_for(x, i, &used, 1);
				if (w->fr[w->nf - 1u].dstv && w->fr[w->nf - 1u].dstv->n_set < 255u)
					w->fr[w->nf - 1u].dstv->n_set++;        /* a call writes it: an assignment the evaluator cannot read */
				i += used - 1u;
				continue;
			}
			if (x->sum && l->ret_name) {
				uint32_t head = kgenome_dtx_sum_bare_callee(x, i);

				if (head)               /* a function called by its name alone: what it returns is the value here */
					kgenome_dtx_sum_call_value(x, w, head, x->scope[i]);
			}
			v = kgenome_dtx_var_for(x, i, &used, 0);
			if (x->extract_src >= 0 && x->scope[i] == x->extract_scope) {
				/* the request was poured into this scope's variables: this one may hold it, whatever else it was given, and is no constant */
				xt = v ? *v : (struct kgenome_dtx_var){ 0 };
				xt.unknown = 1;
				kgenome_dtx_var_def(&xt, (uint32_t)x->extract_src);
				v = &xt;
			}
			if (!l->dyn_var) {
				/* no value is a name that is called, or a class that is built, at a "$" */
			} else if (kgenome_dtx_is_p(x, i + used, '(') && !after_new(x, i)) {
				/* $f(...): the name is what the program built into $f - a literal, a join, str_replace over a scrambled one,
				 * $GLOBALS['f'] - or the callee is something the sender or a decode made. Either is a call of whatever it
				 * says, and a node because of that */
				int32_t n = v ? kgenome_dtx_target_node(x, v, i, i + used, 1) : -1;

				if (n >= 0) {
					x->site[i] = n;
					kgenome_dtx_flow(x, w, n, NULL);
					pend = n;
					i += used - 1u;
					continue;
				}
			} else if (v && (after_new(x, i) || (kgenome_dtx_is_p(x, i + used, ':') && kgenome_dtx_is_p(x, i + used + 1u, ':')))) {
				/* new $cls, $cls::f(): the CLASS is a value. The "(" that may follow is the constructor's or the method's, whose
				 * arguments are data for it, so the node is not the call's: no frame names it */
				int32_t n = kgenome_dtx_target_node(x, v, i, 0, 0);

				if (n >= 0) {
					x->site[i] = n;
					kgenome_dtx_flow(x, w, n, NULL);
					i += used - 1u;
					continue;
				}
			}
			if (v)
				kgenome_dtx_flow(x, w, -1, v);
			i += used - 1u;
		}
	}
}

void kgenome_dtx_walk(struct kgenome_dtx *x)
{
	struct kgenome_dtx_walk *w = calloc(1, sizeof *w);

	if (!w) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		return;
	}
	w->x = x;
	w->cmd_pos = 1;
	kgenome_dtx_walk_range(x, w, 0, x->nt);
	w->cur = x->nt;
	if (w->asg)
		kgenome_dtx_end_assign(x, w);
	if (x->sum)
		kgenome_dtx_sum_resolve(x);
	if (x->ident)
		kgenome_dtx_ident(x);
	free(w->fr);
	free(w->sfi);
	free(w);
}
