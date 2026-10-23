/*
 * textual_fn.c - which function a call names: kgenome_textual_fn_find, over the table of a language row.
 *
 * What a function DOES is the engine's (the hook of kgenome_textual_apply_fn); what it is CALLED, and which of its
 * arguments is the value and which are parameters, is the language's, and is data in the row.
 */

#include <string.h>

#include <kofbytes.h>
#include <kofcore.h>

#include "textual_lang.h"

int kgenome_textual_fn_find(uint32_t lang, const uint8_t *name, uint32_t len, struct kgenome_textual_fn *out)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);
	uint32_t i, k;

	if (!l || !l->fn_table)
		return 0;
	for (i = 0; i < l->fn_table->n; i++) {
		const char *w = l->fn_table->rows[i].name;

		if (strlen(w) != len)
			continue;
		for (k = 0; k < len; k++)
			if ((l->fn_fold ? kof_lower_byte(name[k]) : name[k]) != (uint8_t)w[k])
				break;
		if (k == len) {
			*out = l->fn_table->rows[i].fn;
			return 1;
		}
	}
	return 0;
}

uint32_t kgenome_textual_fn_shapes(uint32_t lang)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);
	uint32_t i, m = 0;

	if (!l || !l->fn_table)
		return 0;
	for (i = 0; i < l->fn_table->n; i++)
		m |= 1u << l->fn_table->rows[i].fn.shape;
	return m;
}

int kgenome_textual_fn_row(uint32_t lang, uint32_t k, const char **name, struct kgenome_textual_fn *out)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);

	if (!l || !l->fn_table || k >= l->fn_table->n)
		return 0;
	*name = l->fn_table->rows[k].name;
	*out = l->fn_table->rows[k].fn;
	return 1;
}

int kgenome_textual_arg_num(const struct kgenome_textual_arg *a, long *n)
{
	uint32_t i = 0;
	int neg = 0;
	long v = 0;

	if (i < a->n && (a->p[i] == '-' || a->p[i] == '+'))
		neg = a->p[i++] == '-';
	if (i >= a->n)
		return 0;
	for (; i < a->n; i++) {
		if (a->p[i] < '0' || a->p[i] > '9' || v > 100000000L)
			return 0;
		v = v * 10 + (a->p[i] - '0');
	}
	*n = neg ? -v : v;
	return 1;
}

/* One argument as the parameter the table says it is: bytes, or a number. */
/* tcl's `end`, `end-N`, `end+N`: the index of the last character of a subject `len` long, moved by N. 1 and the index, 0 when it is none of those. */
static int end_word(const struct kgenome_textual_arg *a, uint32_t len, long *v)
{
	struct kgenome_textual_arg d;
	long n;

	if (a->n < 3u || memcmp(a->p, "end", 3u))
		return 0;
	if (a->n == 3u) {
		*v = (long)len - 1;
		return 1;
	}
	if ((a->p[3] != '-' && a->p[3] != '+') || a->n < 5u)
		return 0;
	d.p = a->p + 4;
	d.n = a->n - 4u;
	if (d.p[0] == '-' || d.p[0] == '+' || !kgenome_textual_arg_num(&d, &n))
		return 0;
	*v = (long)len - 1 + (a->p[3] == '-' ? -n : n);
	return 1;
}

static int fn_param(const struct kgenome_textual_fn *f, uint32_t k, const struct kgenome_textual_arg *a,
		    struct kgenome_textual_call *c, uint32_t len)
{
	long v;
	struct kgenome_textual_arg t;
	int signed_ok = 0;

	if (f->numeric >> k & 1u) {
		if (k == 0 && (f->flags & KGENOME_TEXTUAL_FN_BASHSLICE)) {      /* `${x: -3}`: the blank is what makes the sign an offset's */
			t = *a;
			while (t.n && t.p[0] == ' ') {
				t.p++;
				t.n--;
				signed_ok = 1;
			}
			a = &t;
		}
		if (!((f->flags & KGENOME_TEXTUAL_FN_ENDWORD) && end_word(a, len, &v)) && !kgenome_textual_arg_num(a, &v))
			return 0;
		if ((f->flags & KGENOME_TEXTUAL_FN_PLAINNUM) && (!a->n || ((a->p[0] < '0' || a->p[0] > '9') && !(signed_ok && a->p[0] == '-'))))
			return 0;
		if ((f->flags & KGENOME_TEXTUAL_FN_NONNEG) && v < 0 && !signed_ok)
			return 0;
		if (k == 0 && (f->flags & KGENOME_TEXTUAL_FN_BASE1)) {     /* counted from 1: 0 and below are an error, and the op counts from 0 */
			if (v < 1)
				return 0;
			v--;
		}
		*(k ? &c->k2 : &c->k1) = (int32_t)v;
		return 1;
	}
	*(k ? &c->s2 : &c->s1) = a->p;
	*(k ? &c->n2 : &c->n1) = a->n;
	return 1;
}

/* One character of the flavour `chr` for the number `v`, at out[*w]: 1, or 0 when the language refuses the number (or `cap` is short). */
static int chr_put(uint8_t chr, long v, uint8_t *out, uint32_t cap, uint32_t *w)
{
	uint32_t cp, n;
	uint8_t tmp[8];

	switch (chr) {
	case KGENOME_TEXTUAL_CHR_PHP:
		cp = (uint32_t)(v & 0xff);
		break;
	case KGENOME_TEXTUAL_CHR_BYTE:
		if (v < 0 || v > 255)
			return 0;
		cp = (uint32_t)v;
		break;
	case KGENOME_TEXTUAL_CHR_ASCII:
		if (v < 0 || v > 127)
			return 0;
		cp = (uint32_t)v;
		break;
	case KGENOME_TEXTUAL_CHR_UTF16:
		cp = (uint32_t)(v & 0xffff);
		break;
	case KGENOME_TEXTUAL_CHR_UCS2:
		if (v < 0 || v > 0xffff)
			return 0;
		cp = (uint32_t)v;
		break;
	default:        /* KGENOME_TEXTUAL_CHR_UTF8 */
		if (v < 0 || v > 0x10ffff)
			return 0;
		cp = (uint32_t)v;
		break;
	}
	if (chr >= KGENOME_TEXTUAL_CHR_UTF8 && cp >= 0x80u) {
		if (cp >= 0xd800u && cp <= 0xdfffu)
			return 0;
		n = kgenome_textual_utf8_put(tmp, cp);
	} else {
		tmp[0] = (uint8_t)cp;
		n = 1;
	}
	if (n > cap - *w)
		return 0;
	memcpy(out + *w, tmp, n);
	*w += n;
	return 1;
}

/*
 * The rules a row states about its arguments, which are not the op's: the bytes a parameter may not hold, an empty search, a byte of the list twice, one-byte and ASCII subjects.
 * Each is a refusal (kofcore/kofbytes.h answers the byte questions: this lib does not run string algorithms, kuncoat does). 1 when the call may be run.
 */
static int args_ok(const struct kgenome_textual_fn *f, const struct kgenome_textual_arg *a, uint32_t n_args)
{
	const struct kgenome_textual_arg *s = &a[f->subject];
	uint32_t k;

	/* the language's own case folding is Unicode's, and a character of a str is more than a byte above 0x7f: only ASCII is the op's */
	if ((f->flags & (KGENOME_TEXTUAL_FN_ASCII | KGENOME_TEXTUAL_FN_ICASE)) && !kof_bytes_ascii(s->p, s->n))
		return 0;
	if ((f->flags & KGENOME_TEXTUAL_FN_ONECHAR) && (s->n != 1u || !kof_bytes_ascii(s->p, s->n)))
		return 0;
	if (kof_bytes_has_any(s->p, s->n, f->bad[0]))
		return 0;
	if ((f->flags & KGENOME_TEXTUAL_FN_NODASH) && !(f->flags & KGENOME_TEXTUAL_FN_STDIN) && s->n && s->p[0] == '-')
		return 0;
	for (k = 0; k < 2u; k++) {
		if (f->param[k] == KGENOME_TEXTUAL_FN_NONE || f->param[k] >= n_args || (f->numeric >> k & 1u))
			continue;
		if (kof_bytes_has_any(a[f->param[k]].p, a[f->param[k]].n, f->bad[1u + k]))
			return 0;
		if ((f->flags & KGENOME_TEXTUAL_FN_NODASH) && a[f->param[k]].n && a[f->param[k]].p[0] == '-')
			return 0;
		if (k == 0 && (f->flags & KGENOME_TEXTUAL_FN_NOEMPTY) && !a[f->param[0]].n)
			return 0;
		if (k == 0 && (f->flags & KGENOME_TEXTUAL_FN_UNIQUE) && kof_bytes_has_twice(a[f->param[0]].p, a[f->param[0]].n))
			return 0;
		if (k == 0 && (f->flags & KGENOME_TEXTUAL_FN_ONESEP) && a[f->param[0]].n != 1u)
			return 0;
	}
	return 1;
}

/*
 * THE NUMBERS OF A CUT, as the op reads them (a start, and a length or to the end), from what the language's function was given. The ops are php's substr and
 * count from the start; the languages differ in how they say where the cut ends (a length, an end index exclusive or inclusive, how many bytes of the end to keep),
 * what a start past the end does and whether a number below 0 is allowed - the row says which (the flags), and this is the one place that turns it into the op's
 * numbers, so every language's slice is read the same way. `len` is the subject's length. 0: the language raises an error for these numbers.
 */
static int cut_numbers(const struct kgenome_textual_fn *f, uint32_t len, struct kgenome_textual_call *c)
{
	int64_t st = c->k1, cnt = c->k2;

	if ((f->flags & KGENOME_TEXTUAL_FN_BASHSLICE) && st < 0) {      /* from the end; before the start there is nothing */
		st += (int64_t)len;
		if (st < 0) {
			c->k1 = (int32_t)len;
			c->k2 = 0;
			c->to_end = 1;
			return 1;
		}
		c->k1 = (int32_t)st;
		return 1;
	}
	if (f->flags & KGENOME_TEXTUAL_FN_FROMEND) {
		cnt = c->k2;
		c->k1 = (int32_t)(cnt >= (int64_t)len ? 0 : (int64_t)len - cnt);
		c->k2 = 0;
		c->to_end = 1;
		return 1;
	}
	if (f->flags & KGENOME_TEXTUAL_FN_ENDIDX) {
		if (!c->to_end) {
			if ((f->flags & KGENOME_TEXTUAL_FN_SWAP) && st > cnt) {
				int64_t t = st;

				st = cnt;
				cnt = t;
			}
			if (f->flags & KGENOME_TEXTUAL_FN_INCL)      /* the end is the last character wanted */
				cnt++;
			cnt -= st;
			if (cnt < 0)
				cnt = 0;
			c->k1 = (int32_t)st;
			c->k2 = (int32_t)(cnt > 0x7fffffffLL ? 0x7fffffffLL : cnt);
		}
		return 1;
	}
	if (f->flags & KGENOME_TEXTUAL_FN_STRICT) {
		if (st > (int64_t)len || (!c->to_end && (cnt < 0 || st + cnt > (int64_t)len)))
			return 0;
	}
	return 1;
}

int kgenome_textual_fn_run(const struct kgenome_textual_fn *f, const struct kgenome_textual_arg *a, uint32_t n_args,
			   kgenome_textual_apply_fn apply, void *apply_user, uint8_t *out, uint32_t cap, uint32_t *n_out)
{
	struct kgenome_textual_call c;
	uint32_t k;
	long v;

	*n_out = 0;
	if (n_args < f->min_args || n_args > f->max_args)
		return 0;
	if (f->op == KGENOME_TEXTUAL_DEC_CHR) {
		/* a character from a number, as the language's own function makes it (enum kgenome_textual_chr); with more than one argument each is one more */
		uint32_t w = 0;

		for (k = f->param[0]; k < (f->max_args > 1u ? n_args : f->param[0] + 1u); k++)
			if (!kgenome_textual_arg_num(&a[k], &v) || !chr_put(f->chr, v, out, cap, &w))
				return 0;
		*n_out = w;
		return 1;
	}
	if (!apply || !args_ok(f, a, n_args))
		return 0;
	memset(&c, 0, sizeof c);
	c.op = f->op;
	for (k = 0; k < 2u; k++) {
		if (f->param[k] == KGENOME_TEXTUAL_FN_NONE)
			continue;
		if (f->param[k] >= n_args) {            /* an optional parameter the call left out: substr's length */
			c.to_end = 1;
			continue;
		}
		if (!fn_param(f, k, &a[f->param[k]], &c, a[f->subject].n))
			return 0;
	}
	if (f->op == KGENOME_TEXTUAL_DEC_SLICE && !cut_numbers(f, a[f->subject].n, &c))
		return 0;
	if (f->op == KGENOME_TEXTUAL_DEC_REPEAT && c.k1 < 0)    /* an error where the row says NONNEG (refused above), nothing at all elsewhere */
		c.k1 = 0;
	if (f->list & KGENOME_TEXTUAL_LIST_DROP_TRAILING)
		c.flags |= KGENOME_TEXTUAL_CALL_DROPTRAIL;
	if (f->flags & KGENOME_TEXTUAL_FN_FIRST)
		c.flags |= KGENOME_TEXTUAL_CALL_FIRST;
	if (f->flags & KGENOME_TEXTUAL_FN_ICASE)
		c.flags |= KGENOME_TEXTUAL_CALL_ICASE;
	c.flags |= f->opflags;
	if ((f->flags & KGENOME_TEXTUAL_FN_SETARG) && f->param[0] < n_args) {       /* tcl's string trim s chars: the set is the parameter, which is already s1 */
		c.flags |= KGENOME_TEXTUAL_CALL_SET;
	} else if (f->set) {
		c.flags |= KGENOME_TEXTUAL_CALL_SET;
		c.s1 = (const uint8_t *)f->set;
		c.n1 = (uint32_t)strlen(f->set);
	}
	return apply(apply_user, &c, a[f->subject].p, a[f->subject].n, out, cap, n_out);
}
