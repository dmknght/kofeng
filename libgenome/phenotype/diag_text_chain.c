/*
 * diag_text_chain.c - how a language that qualifies its names writes a call: `os.system(c)`, `Runtime.getRuntime().exec(c)`,
 * `IO::Socket::INET->new(...)`, `request.args.get('c')`.
 *
 * A table of names (nucleo_names_<lang>.c) spells a qualified name with "." whatever the language writes between the pieces, and a call on
 * the result of a factory without the factory. This is the one place that reads the tokens that way, for the walk (which asks the name of
 * a call, and whether a member is the request) and for the scopes (which ask whether a token is a member). A language with no `chain` in its
 * row (php) never gets here: its call is the one name in front of its bracket.
 *
 * WHAT IT CANNOT NAME is left unnamed, not guessed: a call on a value (`f(x).m()`, `a[0].m()`, `"s".join()`), a chain longer than
 * MAX_PIECES or MAX_STEPS (said: kgenome_dtx_cut), a name that would not fit. An unnamed call is not looked up, and so is no node.
 */

#include <string.h>

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

#define MAX_PIECES 16u
#define MAX_STEPS  64u          /* links of a chain looked back over, calls that are dropped included: a longer chain has no name (a bound on the work, not on what is found) */
#define ALIAS_DEPTH 3u

/* Is the list of pieces of a name full: more than a name is read from has no name and so is no node, and the scan says it (it was a silent "no name"). */
static int piece_full(struct kgenome_dtx *x, uint32_t np)
{
	if (np < MAX_PIECES)
		return 0;
	kgenome_dtx_cut(x);
	return 1;
}

/* How many tokens the join `js` is, when the tokens from `at` spell it (each of its bytes a punctuation token of its own), else 0. */
static uint32_t join_spells(const struct kgenome_dtx *x, uint32_t at, const char *js)
{
	uint32_t k;

	for (k = 0; js[k]; k++)
		if (!kgenome_dtx_is_p(x, at + k, js[k]))
			return 0;
	return k;
}

uint32_t kgenome_dtx_join_after(const struct kgenome_dtx *x, uint32_t i)
{
	const char *const *j = x->lang->joins;
	uint32_t best = 0, k;

	if (i >= x->nt || x->t[i].k != 'P')
		return 0;

	for (k = 0; j && j[k]; k++) {
		uint32_t n = join_spells(x, i, j[k]);

		if (n > best)
			best = n;
	}
	return best;
}

uint32_t kgenome_dtx_join_before(const struct kgenome_dtx *x, uint32_t i)
{
	const char *const *j = x->lang->joins;
	uint32_t best = 0, k;

	if (!i || x->t[i - 1u].k != 'P')       /* every name of the text asks, and most have no punctuation in front */
		return 0;
	{
		uint8_t c = x->in[x->t[i - 1u].off];

		if (!(x->jlast[c >> 3] >> (c & 7u) & 1u))      /* ... and what there is, is rarely a join's last byte */
			return 0;
	}

	for (k = 0; j && j[k]; k++) {
		uint32_t n = (uint32_t)strlen(j[k]);

		/* the join's last byte is the token in front: most punctuation in front of a name is none of them */
		if (n > best && i >= n && (uint8_t)j[k][n - 1u] == x->in[x->t[i - 1u].off] && join_spells(x, i - n, j[k]))
			best = n;
	}
	/* a single byte that is the second of a pair is no join: lua's `a .. b` is a concatenation, js's `...x` a spread */
	if (best == 1u && i >= 2u && x->t[i - 2u].k == 'P' && x->t[i - 2u].len == 1u && x->in[x->t[i - 2u].off] == x->in[x->t[i - 1u].off])
		return 0;
	return best;
}

uint32_t kgenome_dtx_append_len(const struct kgenome_dtx *x, uint32_t i)
{
	const char *a = x->lang->append;
	uint32_t n;

	if (!a)
		return 0;
	n = (uint32_t)strlen(a);
	return join_spells(x, i, a) && !kgenome_dtx_is_p(x, i + n, '=') ? n : 0u;
}

int kgenome_dtx_member(const struct kgenome_dtx *x, uint32_t i)
{
	return kgenome_dtx_join_before(x, i) != 0;
}

struct piece {
	const uint8_t *p;
	uint32_t       n;
};

/* Is the name at token `f` what `new` constructs: `new X(`, and `new a.b.X(` whose first piece `new` precedes. */
static int new_before(const struct kgenome_dtx *x, uint32_t f)
{
	uint32_t jl;

	while ((jl = kgenome_dtx_join_before(x, f)) != 0 && f > jl && x->t[f - jl - 1u].k != 'P')
		f -= jl + 1u;
	return f >= 1u && x->t[f - 1u].k != 'S' && x->t[f - 1u].k != 'P' && kgenome_dtx_is_word(x, f - 1u, "new");
}

/* The class of the object a variable holds, as the table spells it: `s = socket.socket()` is "socket.socket", `cp = require('child_process')` is
 * "child_process", `p = new Process()` is "Process", `o = CreateObject("WScript.Shell")` is "WScript.Shell" (a table of another target: `r->target`). Only for a
 * variable assigned once in the way it is read (the producers of the latest assignment: a single right side), and only a call or a require - anything else says
 * nothing of what the object is. */
static uint32_t class_of_var(struct kgenome_dtx *x, uint32_t tok, char *b, uint32_t cap, uint32_t depth, struct kgenome_dtx_chain_res *r)
{
	const struct kgenome_dtx_var *v;
	const struct kgenome_dtx_seg *g0;
	uint32_t used, rs, re, f, n;
	struct kgenome_dtx_chain_res in = { 0 };

	if (depth >= ALIAS_DEPTH || (x->lang->sigil && !x->lang->n_classfns))
		return 0;
	v = kgenome_dtx_var_for(x, tok, &used, 0);
	if (!v || v->unknown || v->nseg != 1u)
		return 0;
	g0 = kgenome_dtx_seg_next(x, v, NULL);
	if (!g0)
		return 0;
	rs = g0->rs;
	re = g0->re;
	if (re <= rs || re > x->nt)
		return 0;
	/* `File f = ...`: the type written in front of the variable is its class, whatever made the value (java, c#: `var` says nothing) */
	if (x->lang->typed_decl && rs >= 3u && (x->t[rs - 3u].k == 'V' || x->t[rs - 3u].k == 'I') && kgenome_dtx_is_p(x, rs - 1u, '=') &&
	    x->t[rs - 2u].len == x->t[tok].len && !memcmp(x->in + x->t[rs - 2u].off, x->in + x->t[tok].off, x->t[tok].len) &&
	    !kgenome_dtx_is_word(x, rs - 3u, "var")) {
		n = x->t[rs - 3u].len;
		if (n >= cap || kgenome_dtx_member(x, rs - 3u) || kgenome_dtx_word_in(x->lang->keywords, x->in + x->t[rs - 3u].off, n, x->lang->fold))
			return 0;
		memcpy(b, x->in + x->t[rs - 3u].off, n);
		return n;
	}
	if (re - rs < 2u)
		return 0;
	/* `o = New-Object -ComObject X`: a command that makes an object */
	if ((n = kgenome_dtx_class_command(x, rs, re, b, cap, r)) != 0)
		return n;
	if (re - rs == 4u && x->lang->module_fn && x->t[rs].k != 'S' && kgenome_dtx_is_word(x, rs, x->lang->module_fn) && kgenome_dtx_is_p(x, rs + 1u, '(') &&
	    x->t[rs + 2u].k == 'S' && kgenome_dtx_is_p(x, rs + 3u, ')')) {
		const struct kgenome_dtx_tok *s = &x->t[rs + 2u];

		n = s->len > (uint32_t)s->open + s->close ? s->len - s->open - s->close : 0u;
		if (!n || n >= cap || (s->fl & KGENOME_TEXTUAL_F_OPEN))
			return 0;
		memcpy(b, x->in + s->off + s->open, n);
		return n;
	}
	if (!kgenome_dtx_is_p(x, re - 1u, ')') || x->match[re - 1u] < 1 || (uint32_t)x->match[re - 1u] - 1u < rs)
		return 0;
	f = (uint32_t)x->match[re - 1u] - 1u;
	if (x->t[f].k != 'I')
		return 0;
	n = kgenome_dtx_chain_full(x, f, b, cap, &in, depth + 1u);
	if (!n || !(in.root == rs || (in.root == rs + 1u && x->t[rs].k != 'S' && kgenome_dtx_is_word(x, rs, "new"))))
		return 0;
	/* `Set o = CreateObject("X")`: the class is what the call names, not the call */
	{
		char cls[KGENOME_DTX_NAME];
		uint32_t cn = kgenome_dtx_class_call(x, b, n, f + 1u, cls, sizeof cls, r);

		if (cn) {
			memcpy(b, cls, cn + 1u);
			return cn;
		}
	}
	return n;
}

/* The root of a chain is the object made by a call or a command, written where it is used: `CreateObject("X").Run`, `(New-Object Net.WebClient).Download(..)`. The
 * piece to begin the name with (its length, 0 when the token before the member is no such thing) and the token the chain's root is. */
static uint32_t class_root(struct kgenome_dtx *x, uint32_t k, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r, uint32_t depth, uint32_t *root)
{
	uint32_t f, n;
	char callee[KGENOME_DTX_NAME];
	struct kgenome_dtx_chain_res in = { 0 };

	if (!x->lang->n_classfns || depth >= ALIAS_DEPTH || !kgenome_dtx_is_p(x, k, ')') || x->match[k] < 1)
		return 0;
	if ((n = kgenome_dtx_class_group(x, (uint32_t)x->match[k], b, cap, r)) != 0) {
		*root = (uint32_t)x->match[k];
		return n;
	}
	f = (uint32_t)x->match[k] - 1u;
	if (x->match[k] < 2 || x->t[f].k != 'I' || !kgenome_dtx_may_make_object(x, f))
		return 0;
	n = kgenome_dtx_chain_full(x, f, callee, sizeof callee, &in, depth + 1u);
	if (!n || !(n = kgenome_dtx_class_call(x, callee, n, f + 1u, b, cap, r)))
		return 0;
	*root = in.root;
	return n;
}

uint32_t kgenome_dtx_chain_full(struct kgenome_dtx *x, uint32_t i, char *b, uint32_t cap, struct kgenome_dtx_chain_res *res, uint32_t depth)
{
	struct piece pc[MAX_PIECES];
	uint32_t np = 0, j = i, k, n = 0, r;
	char cls[KGENOME_DTX_NAME], rb[KGENOME_DTX_NAME];
	uint32_t cn = 0;
	int rooted = 0;
	uint32_t steps = 0;
	struct kgenome_dtx_chain_res out = { 0 };

	pc[np++] = (struct piece){ x->in + x->t[i].off, x->t[i].len };
	for (; !rooted;) {
		uint32_t jl = kgenome_dtx_join_before(x, j);
		const struct kgenome_dtx_tok *t;

		if (!jl)
			break;
		if (++steps > MAX_STEPS) {
			kgenome_dtx_cut(x);     /* a chain longer than the look-back bound has no name and so is no node: said (the bound is on the work: a hundred thousand calls in a row would make each read all the ones before it) */
			return 0;
		}
		if (j < jl + 1u)
			return 0;
		k = j - jl - 1u;
		t = &x->t[k];
		if (t->k == 'I' || t->k == 'V') {
			if (piece_full(x, np))
				return 0;
			pc[np++] = (struct piece){ x->in + t->off, t->len };
			j = k;
		} else if (kgenome_dtx_is_p(x, k, ']') && x->lang->type_lit) {
			uint32_t tn;
			const uint8_t *tp = kgenome_dtx_type_lit(x, k, &tn);

			if (!tp || piece_full(x, np))
				return 0;
			pc[np++] = (struct piece){ tp, tn };    /* `[Convert]::FromBase64String`: the type is the receiver */
			j = (uint32_t)x->match[k];
			rooted = 1;
		} else if (kgenome_dtx_is_p(x, k, ')') && x->match[k] > 0) {
			uint32_t f = (uint32_t)x->match[k] - 1u, rt = 0, rn = class_root(x, k, rb, sizeof rb, &out, depth, &rt);

			if (rn) {
				if (piece_full(x, np))
					return 0;
				pc[np++] = (struct piece){ (const uint8_t *)rb, rn };    /* `CreateObject("X").Run`: the class is the receiver */
				rooted = 1;
				j = rt;
				continue;
			}
			if (x->t[f].k != 'I')
				return 0;
			if (x->lang->module_fn && kgenome_dtx_is_word(x, f, x->lang->module_fn) && k == f + 3u && x->t[f + 2u].k == 'S') {
				const struct kgenome_dtx_tok *s = &x->t[f + 2u];   /* `require('m').f`: the module is the root */
				uint32_t sl = s->len > (uint32_t)s->open + s->close ? s->len - s->open - s->close : 0u;

				if (!sl || (s->fl & KGENOME_TEXTUAL_F_OPEN) || piece_full(x, np))
					return 0;
				pc[np++] = (struct piece){ x->in + s->off + s->open, sl };
				rooted = 1;
			} else if (new_before(x, f)) {
				if (piece_full(x, np))
					return 0;
				pc[np++] = (struct piece){ x->in + x->t[f].off, x->t[f].len };   /* `new X(...).m()`: the class is the receiver */
			} else if (!kgenome_dtx_join_before(x, f)) {
				return 0;               /* `f(x).m()`: a value no name is given to */
			}
			j = f;
		} else {
			return 0;
		}
	}
	out.root = j;
	if (x->t[j].k == 'V')
		cn = class_of_var(x, j, cls, sizeof cls, depth, &out);
	for (r = np; r > 0; r--) {
		const struct piece *p = &pc[r - 1u];
		const uint8_t *src = p->p;
		uint32_t len = p->n;

		if (r == np && cn) {
			src = (const uint8_t *)cls;
			len = cn;
		}
		if (n + len + 1u >= cap)
			return 0;
		if (n)
			b[n++] = '.';
		memcpy(b + n, src, len);
		n += len;
	}
	b[n] = 0;
	if (res)
		*res = out;
	return n;
}

uint32_t kgenome_dtx_chain_name(struct kgenome_dtx *x, uint32_t i, char *b, uint32_t cap, uint32_t *root)
{
	struct kgenome_dtx_chain_res r = { 0 };
	uint32_t n = kgenome_dtx_chain_full(x, i, b, cap, &r, 0);

	if (root)
		*root = r.root;
	return n;
}

/* Append ".piece" (or the piece, for the first) to the name being built: 0 when it would not fit. */
static int add_piece(char *b, uint32_t *n, uint32_t cap, const uint8_t *p, uint32_t len)
{
	if (*n + len + 1u >= cap)
		return 0;
	if (*n)
		b[(*n)++] = '.';
	memcpy(b + *n, p, len);
	*n += len;
	return 1;
}

int32_t kgenome_dtx_request_end(struct kgenome_dtx *x, uint32_t i, char *b, uint32_t cap)
{
	uint32_t n = 0, p = i;
	const struct kgenome_dtx_tok *t = &x->t[i];

	if ((t->k != 'V' && t->k != 'I') || kgenome_dtx_member(x, i) || !add_piece(b, &n, cap, x->in + t->off, t->len))
		return -1;
	for (;;) {
		uint32_t jl;

		if ((b[n] = 0, kgenome_dtx_cap(x, (const uint8_t *)b, n, NULL)) == KGENOME_NUCLEO_REQUEST && !kgenome_dtx_is_p(x, p + 1u, '('))
			return (int32_t)p;
		if (x->lang->hash_key && kgenome_dtx_is_p(x, p + 1u, '{') && p + 3u < x->nt && x->match[p + 1u] == (int32_t)(p + 3u) &&
		    (x->t[p + 2u].k == 'I' || x->t[p + 2u].k == 'S')) {
			const struct kgenome_dtx_tok *k = &x->t[p + 2u];
			uint32_t o = k->k == 'S' ? k->open : 0u, c = k->k == 'S' ? k->close : 0u;

			if (k->len < o + c || !add_piece(b, &n, cap, x->in + k->off + o, k->len - o - c))
				return -1;
			p += 3u;
			continue;
		}
		jl = kgenome_dtx_join_after(x, p + 1u);
		if (!jl || p + jl + 1u >= x->nt || x->t[p + jl + 1u].k != 'I')
			return -1;
		p += jl + 1u;
		if (!add_piece(b, &n, cap, x->in + x->t[p].off, x->t[p].len))
			return -1;
	}
}

uint32_t kgenome_dtx_ctor_final(const struct kgenome_dtx *x, uint32_t i)
{
	uint32_t j;

	if (!i || x->t[i - 1u].k == 'S' || !kgenome_dtx_is_word(x, i - 1u, "new") || !kgenome_dtx_is_p(x, i + 1u, '(') || x->match[i + 1u] < 1)
		return 0;
	j = (uint32_t)x->match[i + 1u] + 1u;
	for (;;) {
		uint32_t jl = kgenome_dtx_join_after(x, j), f, c;

		if (!jl || j + jl + 1u >= x->nt || x->t[j + jl].k != 'I' || !kgenome_dtx_is_p(x, j + jl + 1u, '(') || x->match[j + jl + 1u] < 1)
			return 0;
		f = j + jl;
		c = (uint32_t)x->match[f + 1u] + 1u;
		if (!kgenome_dtx_join_after(x, c))
			return f;
		j = c;
	}
}

uint16_t kgenome_dtx_chain_cap(struct kgenome_dtx *x, const struct kgenome_dtx_chain_res *r, const char *b, uint32_t len, uint32_t *off)
{
	uint32_t o = 0;
	unsigned target = r->target;
	int drop = target && target != x->lang->target ? r->drop : x->lang->ns_drop;

	for (;;) {
		uint16_t cap = kgenome_dtx_cap_in(x, target, (const uint8_t *)b + o, len - o);
		const char *dot;

		if (cap != KGENOME_NUCLEO_NONE) {
			*off = o;
			return cap;
		}
		dot = drop ? memchr(b + o, '.', len - o) : NULL;
		if (!dot)
			return KGENOME_NUCLEO_NONE;
		o = (uint32_t)(dot - b) + 1u;
	}
}
