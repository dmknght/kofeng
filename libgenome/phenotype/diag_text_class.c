/*
 * diag_text_class.c - the class of an object that a call makes out of a name written in the program: COM (`CreateObject("WScript.Shell")`, `new ActiveXObject(..)`,
 * `Server.CreateObject(..)`, powershell's `New-Object -ComObject ..`), a .NET type (`New-Object Net.WebClient`), a java object of cfml (`createObject("java", ..)`).
 *
 * WHY IT IS READ HERE AND NOT LOOKED UP BY NAME. A program that uses COM does almost nothing itself: what it asks of the system is the member it calls on an object
 * (`o.Run cmd`), and the identity of that call is the class of the object, not the variable's name. The tables write COM once, in the VBS table, as "ProgID.Member"
 * (nucleo.h), so a language that reaches a COM object (js, powershell, asp) gets the class from the call that made the object - one literal, read by the evaluator so
 * that a class the program JOINED out of pieces is read as well, and told BUILT - and looks the member up in that table (`kgenome_dtx_classfn.target`). The rows of
 * calls that make an object are the language's (diag_text_lang_<name>.c): data, one row per call.
 *
 * WHAT IT DOES NOT READ: an object a function returns, one that is passed on through another variable (`p = o`), a class chosen by a value. Those have no class here, and a
 * member called on them is not looked up - never guessed.
 */

#include <string.h>

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static int same_word(const struct kgenome_dtx *x, const char *w, const char *p, uint32_t n)
{
	uint32_t k;

	if (strlen(w) != n)
		return 0;
	for (k = 0; k < n; k++)
		if ((x->lang->fold ? kof_lower_byte((uint8_t)p[k]) : (uint8_t)p[k]) != (x->lang->fold ? kof_lower_byte((uint8_t)w[k]) : (uint8_t)w[k]))
			return 0;
	return 1;
}

const struct kgenome_dtx_classfn *kgenome_dtx_classfn_named(const struct kgenome_dtx *x, const char *name, uint32_t n, int bare)
{
	uint32_t k;

	for (k = 0; k < x->lang->n_classfns; k++)
		if (!x->lang->classfns[k].bare == !bare && same_word(x, x->lang->classfns[k].name, name, n))
			return &x->lang->classfns[k];
	return NULL;
}

/* Could the call whose name is the token `f` make an object of a class: its name is the last piece of a row's. Asked of every call in a chain before the chain of the call is read, so it
 * is the cheap test that keeps a chain of a hundred thousand calls linear. */
int kgenome_dtx_may_make_object(const struct kgenome_dtx *x, uint32_t f)
{
	uint32_t k;

	for (k = 0; k < x->lang->n_classfns; k++) {
		const char *nm = x->lang->classfns[k].name, *dot = strrchr(nm, '.');

		if (!x->lang->classfns[k].bare && same_word(x, dot ? dot + 1 : nm, (const char *)x->in + x->t[f].off, x->t[f].len))
			return 1;
	}
	return 0;
}

/* "MSXML2.XMLHTTP.6.0" is "MSXML2.XMLHTTP": the table's row has no version number, whichever the program asks for. */
static uint32_t drop_versions(const char *b, uint32_t n)
{
	for (;;) {
		uint32_t k = n;

		while (k && kof_is_digit((uint8_t)b[k - 1u]))
			k--;
		if (k == n || k < 2u || b[k - 1u] != '.')
			return n;
		n = k - 1u;
	}
}

/* The text a name token or a string token holds, in `b`: 0 when it does not fit or is no such token. */
static uint32_t word_text(const struct kgenome_dtx *x, uint32_t i, char *b, uint32_t cap)
{
	const struct kgenome_dtx_tok *t = &x->t[i];
	uint32_t o = t->k == 'S' ? t->open : 0u, c = t->k == 'S' ? t->close : 0u, n;

	if ((t->k != 'I' && t->k != 'S' && t->k != 'V') || t->len < o + c || (t->k == 'S' && (t->fl & KGENOME_TEXTUAL_F_OPEN)))
		return 0;
	n = t->len - o - c;
	if (!n || n >= cap)
		return 0;
	memcpy(b, x->in + t->off + o, n);
	return n;
}

static uint32_t finish(const struct kgenome_dtx_classfn *cf, char *b, uint32_t n, unsigned target, uint16_t flags, struct kgenome_dtx_chain_res *r)
{
	if (cf->versions)
		n = drop_versions(b, n);
	b[n] = 0;
	r->target = target;
	r->drop = cf->ns_drop;
	r->flags = (uint16_t)(r->flags | flags);
	return n;
}

/* The class one row of `classfns` reads out of the call whose "(" is token `open`: written in `b`, its length, 0 when the call is not of that row's kind. */
static uint32_t class_by_row(struct kgenome_dtx *x, const struct kgenome_dtx_classfn *cf, uint32_t open, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r)
{
	struct kgenome_dtx_val v;
	uint32_t rs, re, n;
	int built = 0;

	if (cf->type) {                         /* the argument that says what kind of object it is: createObject("java", ..) */
		if (!kgenome_dtx_arg_range(x, open, cf->type - 1u, &rs, &re) || !kgenome_dtx_eval_range(x, rs, re, &v, &built))
			return 0;
		n = cf->type_word && v.n == strlen(cf->type_word) && same_word(x, cf->type_word, (const char *)v.p, v.n);
		kgenome_dtx_val_free(&v);
		if (!n)
			return 0;
		built = 0;
	}
	if (!kgenome_dtx_arg_range(x, open, cf->arg, &rs, &re) || !kgenome_dtx_eval_range(x, rs, re, &v, &built))
		return 0;
	n = v.n;
	if (n && n < cap)
		memcpy(b, v.p, n);
	else
		n = 0;
	kgenome_dtx_val_free(&v);
	return n ? finish(cf, b, n, cf->target, built ? KGENOME_NUCLEO_F_BUILT : 0u, r) : 0u;
}

uint32_t kgenome_dtx_class_call(struct kgenome_dtx *x, const char *callee, uint32_t clen, uint32_t open, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r)
{
	uint32_t k, n;

	for (k = 0; k < x->lang->n_classfns; k++) {
		const struct kgenome_dtx_classfn *cf = &x->lang->classfns[k];

		if (!cf->bare && same_word(x, cf->name, callee, clen) && (n = class_by_row(x, cf, open, b, cap, r)) != 0)
			return n;
	}
	return 0;
}

/* The class a command makes: tokens [from, to) begin with its name; the options (words that begin with the row's option byte) are skipped, and the first word after them is the class. */
uint32_t kgenome_dtx_class_command(struct kgenome_dtx *x, uint32_t from, uint32_t to, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r)
{
	const struct kgenome_dtx_classfn *cf;
	uint32_t k, n = 0;
	unsigned target = 0;

	if (from >= to || x->t[from].k != 'I')
		return 0;
	cf = kgenome_dtx_classfn_named(x, (const char *)x->in + x->t[from].off, x->t[from].len, 1);
	if (!cf)
		return 0;
	for (k = from + 1u; k < to && k < from + 8u; k++) {
		if (x->t[k].k == 'I' && x->in[x->t[k].off] == '-') {
			if (cf->flag && same_word(x, cf->flag, (const char *)x->in + x->t[k].off, x->t[k].len))
				target = cf->target;
			continue;
		}
		n = word_text(x, k, b, cap);
		break;
	}
	return n ? finish(cf, b, n, target, 0, r) : 0u;
}

/* The `(` at token `o` groups a command that makes an object, `(New-Object Net.WebClient).DownloadString(..)`: its class, 0 when it does not. */
uint32_t kgenome_dtx_class_group(struct kgenome_dtx *x, uint32_t o, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r)
{
	if (!x->lang->n_classfns || o + 1u >= x->nt || x->match[o] < 1)
		return 0;
	return kgenome_dtx_class_command(x, o + 1u, (uint32_t)x->match[o], b, cap, r);
}

/* A type written in square brackets, `[Net.WebClient]` or `[System.Convert]`, whose "]" is token `k`: the dotted name inside, as one piece. NULL when it is no such literal
 * (a subscript has a name in front of its "["). */
const uint8_t *kgenome_dtx_type_lit(const struct kgenome_dtx *x, uint32_t k, uint32_t *n)
{
	uint32_t o, j;

	if (!x->lang->type_lit || !kgenome_dtx_is_p(x, k, ']') || x->match[k] < 0)
		return NULL;
	o = (uint32_t)x->match[k];
	if (o + 1u >= k || (o && (x->t[o - 1u].k == 'I' || x->t[o - 1u].k == 'V' || x->t[o - 1u].k == 'S' || kgenome_dtx_is_p(x, o - 1u, ')') ||
				  kgenome_dtx_is_p(x, o - 1u, ']'))))
		return NULL;
	for (j = o + 1u; j < k; j++) {
		int name = x->t[j].k == 'I', dot = kgenome_dtx_is_p(x, j, '.');

		if (!(name || dot) || (name && (j - o) % 2u == 0u) || (dot && (j - o) % 2u == 1u))
			return NULL;            /* names and dots, alternating, and nothing else */
	}
	if ((k - o) % 2u)               /* the last token inside is a name */
		return NULL;
	*n = x->t[k - 1u].off + x->t[k - 1u].len - x->t[o + 1u].off;
	return x->in + x->t[o + 1u].off;
}
