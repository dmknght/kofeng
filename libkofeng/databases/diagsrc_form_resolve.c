/*
 * diagsrc_form_resolve.c - the detection form of a diagnose source, resolved: the names turned into indices, the markers
 * compiled, the expression read into a tree, every rule checked in one place for both callers (the builder and the
 * editor). Split from diagsrc_form.c (which reads and writes the declarations); see that file for the spelling.
 */

#include "../kofcore/kofdebug.h"
#include "diagsrc_int.h"
#include "pack/diagform.h"
#include "pack/hexprog.h"
#include "pack/dbcore.h"

#include <celllysis/mutation_window.h>
#include <celllysis/mutation.h>

/* ---- resolving -------------------------------------------------------------- */

struct rname {
	char     name[KOF_DSRC_NAME_LEN];
	uint32_t v;                         /* a range's mask, a string's or a block's index, a matcher's number */
	int      used;
	unsigned line;
};

struct rtab {
	struct rname e[KOF_FORM_MAX_MATCH + 1u];
	unsigned     n, cap;
};

static struct rname *rfind(struct rtab *t, const char *name, size_t n)
{
	unsigned i;

	for (i = 0; i < t->n; i++)
		if (strlen(t->e[i].name) == n && !memcmp(t->e[i].name, name, n))
			return &t->e[i];
	return NULL;
}

/* Claim a name in a namespace: NULL (said) when it is taken or the table is full. */
static struct rname *radd(struct rtab *t, const struct kof_dsrc_item *it, const char *what, int line, int *errs,
			  const struct kof_dsrc_report *r)
{
	struct rname *e;
	char msg[96];

	if (rfind(t, it->s1, strlen(it->s1))) {
		snprintf(msg, sizeof msg, "a %s with this name is already declared", what);
		kof_dsrc_say_err(r, errs, line, msg);
		return NULL;
	}
	if (t->n >= t->cap) {
		snprintf(msg, sizeof msg, "more declared %ss than a diagnose may have", what);
		kof_dsrc_say_err(r, errs, line, msg);
		return NULL;
	}
	e = &t->e[t->n++];
	memset(e, 0, sizeof *e);
	memcpy(e->name, it->s1, strlen(it->s1) + 1u);
	e->line = it->line;
	return e;
}

/* The expression parser: || over && over ! over a name or a parenthesis. A tree built into f->node. */
struct xp {
	const char *p;
	struct kof_form *f;
	struct rtab *match;
	const char *err;
	int depth;
};

static void xp_ws(struct xp *x)
{
	while (*x->p == ' ' || *x->p == '\t')
		x->p++;
}

static int xp_node(struct xp *x, uint8_t op, uint8_t a, uint8_t b)
{
	struct kof_form_node *n;

	if (x->f->n_node >= KOF_FORM_MAX_NODE) {
		x->err = "the expression is over the bound on its parts";
		return -1;
	}
	n = &x->f->node[x->f->n_node];
	n->op = op;
	n->a = a;
	n->b = b;
	return x->f->n_node++;
}

static int xp_or(struct xp *x);

static int xp_atom(struct xp *x)
{
	xp_ws(x);
	if (x->depth > 40) {
		x->err = "the expression is nested too deep";
		return -1;
	}
	if (*x->p == '!') {
		int a;

		x->p++;
		x->depth++;
		a = xp_atom(x);
		x->depth--;
		return a < 0 ? -1 : xp_node(x, KOF_FORM_OP_NOT, (uint8_t)a, 0);
	}
	if (*x->p == '(') {
		int a;

		x->p++;
		x->depth++;
		a = xp_or(x);
		x->depth--;
		if (a < 0)
			return -1;
		xp_ws(x);
		if (*x->p != ')') {
			x->err = "a parenthesis of the expression is not closed";
			return -1;
		}
		x->p++;
		return a;
	}
	{
		const char *s = x->p;
		struct rname *m;

		while ((*x->p >= 'a' && *x->p <= 'z') || (*x->p >= 'A' && *x->p <= 'Z') || (*x->p >= '0' && *x->p <= '9') ||
		       *x->p == '_')
			x->p++;
		if (x->p == s) {
			x->err = "the expression wants a matcher name, ! or a parenthesis here";
			return -1;
		}
		m = rfind(x->match, s, (size_t)(x->p - s));
		if (!m) {
			x->err = "the expression names a matcher that is not declared";
			return -1;
		}
		m->used = 1;
		return xp_node(x, KOF_FORM_OP_LEAF, (uint8_t)m->v, 0);
	}
}

static int xp_and(struct xp *x)
{
	int a = xp_atom(x);

	while (a >= 0) {
		int b;

		xp_ws(x);
		if (x->p[0] != '&' || x->p[1] != '&')
			break;
		x->p += 2;
		b = xp_atom(x);
		if (b < 0)
			return -1;
		a = xp_node(x, KOF_FORM_OP_AND, (uint8_t)a, (uint8_t)b);
	}
	return a;
}

static int xp_or(struct xp *x)
{
	int a = xp_and(x);

	while (a >= 0) {
		int b;

		xp_ws(x);
		if (x->p[0] != '|' || x->p[1] != '|')
			break;
		x->p += 2;
		b = xp_and(x);
		if (b < 0)
			return -1;
		a = xp_node(x, KOF_FORM_OP_OR, (uint8_t)a, (uint8_t)b);
	}
	return a;
}

/* The names of a comma joined list, one at a time: the next name's span, or 0 at the end. */
static int next_name(const char **p, const char **s, size_t *n)
{
	const char *q = *p;

	while (*q == ',' || *q == ' ')
		q++;
	if (!*q)
		return 0;
	*s = q;
	while (*q && *q != ',' && *q != ' ')
		q++;
	*n = (size_t)(q - *s);
	*p = q;
	return 1;
}

#define RERR(ln, msg) kof_dsrc_say_err(r, &errs, (int)(ln), (msg))

/* The form of a source, or NULL when it has none; errors are counted in *nerr and reported. */
struct kof_form *kof_dsrc_form_resolve(const struct kof_dsrc *d, const struct kof_dsrc_report *r, int *nerr, int *has)
{
	struct kof_form *f;
	struct rtab *rng, *str, *blk, *mat;
	const struct kof_dsrc_item *expr = NULL;
	uint32_t q, last = d->lines;
	int errs = 0, any = 0;
	const char *why;
	char msg[160];

	for (q = 0; q < d->n; q++)
		any |= d->item[q].kind >= KDS_RANGE;
	*has = any;
	if (!any)
		return NULL;
	f = kof_form_new();
	rng = calloc(4, sizeof *rng);
	if (!f || !rng) {
		free(f);
		free(rng);
		RERR(0, "out of memory");
		*nerr += errs;
		return NULL;
	}
	str = rng + 1;
	blk = rng + 2;
	mat = rng + 3;
	rng->cap = KOF_FORM_MAX_STR;           /* a range is named by a matcher: as many as there are strings, at most */
	str->cap = KOF_FORM_MAX_STR;
	blk->cap = KOF_FORM_MAX_BLOCK;
	mat->cap = KOF_FORM_MAX_MATCH;

	/* Pass one: the things that are named - ranges, markers, blocks. Order-free for the matchers that follow. */
	for (q = 0; q < d->n; q++) {
		const struct kof_dsrc_item *it = &d->item[q];
		struct rname *e;
		int ln = (int)it->line;

		switch (it->kind) {
		case KDS_RANGE:
			if ((e = radd(rng, it, "range", ln, &errs, r))) {
				e->v = (uint32_t)it->v;
			}
			break;
		case KDS_STR: {
			uint8_t prog[KOF_HEX_MAX_PROG], lit[2u * KOF_DSRC_LIT_MAX];
			const uint8_t *bytes = prog;
			uint32_t n = 0;
			uint8_t kind = KOF_STR_LITERAL, flags;
			int idx;

			if (!(e = radd(str, it, "string", ln, &errs, r)))
				break;
			flags = (uint8_t)(((it->b & KDS_OPT_ICASE) ? KOF_STR_ICASE : 0u) |
					  ((it->b & KDS_OPT_FULLWORD) ? KOF_STR_FULLWORD : 0u) |
					  ((it->b & KDS_OPT_TOKEN) ? KOF_STR_TOKEN : 0u));
			if (it->a == KDS_STR_PLAIN || it->a == KDS_STR_WIDE) {
				if (!it->n1 || it->n1 > KOF_DSRC_LIT_MAX) {
					RERR(ln, "a pattern literal is from one to 512 bytes");
					break;
				}
				if (it->a == KDS_STR_WIDE) {
					const char *wmsg = NULL;
					long w = kof_dsrc_widen((const uint8_t *)it->t1, it->n1, lit, sizeof lit, &wmsg);

					if (w < 0 || w > (long)KOF_STR_MAX_LEN) {
						RERR(ln, w < 0 ? wmsg : "wide pattern too long once widened");
						break;
					}
					n = (uint32_t)w;
					flags |= KOF_STR_WIDE;
				} else {
					memcpy(lit, it->t1, it->n1);
					n = it->n1;
				}
				bytes = lit;
			} else {
				struct kof_hex_stat st;

				kind = KOF_STR_HEX;
				n = it->a == KDS_STR_REGEX ? kof_regex_compile(it->t1, prog, sizeof prog, &st)
							   : kof_hex_compile(it->t1, prog, sizeof prog, &st);
				if (!n) {
					RERR(ln, kof_hex_error());
					break;
				}
				if (st.anchor_len < 4u) {
					snprintf(msg, sizeof msg, "line %d: the marker %s has an anchor under four bytes: the presence "
						 "set cannot rule an object out, so it is searched on every object of its format",
						 ln, it->s1);
					kof_dsrc_say_warn(r, msg);
				}
			}
			idx = kof_form_add_str(f, kind, flags, bytes, n);
			if (idx < 0) {
				RERR(ln, "a marker does not fit the form (too many, too long, or over the size of a record)");
				break;
			}
			e->v = (uint32_t)idx;
			break;
		}
		case KDS_BLOCK: {
			uint32_t h[KOF_FORM_HASH_MAX], k, nh = it->n2 / 4u;
			int idx;

			if (!(e = radd(blk, it, "block", ln, &errs, r)))
				break;
			if (nh < kgenome_mutation_block_min((uint32_t)it->v)) {
				RERR(ln, "too few hashes to score a block with; widen it");
				break;
			}
			if (nh > KOF_FORM_HASH_MAX) {
				RERR(ln, "more hashes than a block may carry");
				break;
			}
			for (k = 0; k < nh; k++)
				memcpy(&h[k], it->t2 + 4u * k, 4u);
			idx = kof_form_add_block(f, (uint32_t)it->v, (uint8_t)it->b, h, nh);
			if (idx < 0) {
				RERR(ln, "a block does not fit the form (too many, or over the size of a record)");
				break;
			}
			e->v = (uint32_t)idx;
			break;
		}
		default:
			break;
		}
	}
	/* Pass two: the matchers, which name them. */
	for (q = 0; q < d->n; q++) {
		const struct kof_dsrc_item *it = &d->item[q];
		struct rname *e;
		struct kof_form_match *m;
		const char *p, *s;
		size_t n;
		int ln = (int)it->line;

		if (it->kind != KDS_FIND && it->kind != KDS_SIMILAR)
			continue;
		/* (radd holds the bound: the table of matchers is KOF_FORM_MAX_MATCH long and f->n_match never passes it.) */
		if (!(e = radd(mat, it, "matcher", ln, &errs, r)))
			continue;
		e->v = f->n_match;
		m = &f->match[f->n_match];
		memset(m, 0, sizeof *m);
		p = it->t1 ? it->t1 : "";
		if (it->kind == KDS_FIND) {
			int ok = 1;

			m->kind = KOF_FORM_M_FIND;
			m->rule = (uint8_t)it->a;
			if (it->a == KOF_FORM_R_AT) {
				m->anchor = (uint8_t)it->b;
				m->at = (int64_t)it->v;
				if (it->s2[0]) {
					RERR(ln, "a KOF_FIND_AT matcher compares at one place and names no range");
					ok = 0;
				}
			} else {
				struct rname *rg = rfind(rng, it->s2, strlen(it->s2));

				if (!rg) {
					RERR(ln, "the matcher names a range that is not declared (KOF_TARGET_RANGE)");
					ok = 0;
				} else {
					rg->used = 1;
					m->mask = rg->v;
				}
				if (it->a == KOF_FORM_R_MULTI)
					m->thresh = (uint8_t)it->b;
			}
			while (next_name(&p, &s, &n)) {
				struct rname *sn = rfind(str, s, n);
				uint8_t k;

				if (!sn) {
					RERR(ln, "the matcher names a string that is not declared");
					ok = 0;
					continue;
				}
				for (k = 0; k < m->n; k++)
					if (m->arg[k] == sn->v) {
						RERR(ln, "a string is listed twice in one matcher: it would be counted twice");
						ok = 0;
						break;
					}
				if (m->n >= KOF_FORM_MAX_ARG) {
					RERR(ln, "a matcher lists from one to sixteen markers");
					ok = 0;
					break;
				}
				sn->used = 1;
				m->arg[m->n++] = (uint8_t)sn->v;
			}
			if (ok && it->a == KOF_FORM_R_AT && m->n != 1u) {
				RERR(ln, "a KOF_FIND_AT matcher compares ONE marker at its place");
				ok = 0;
			}
			if (ok && it->a == KOF_FORM_R_MULTI && (m->thresh < 1u || m->thresh > m->n)) {
				RERR(ln, "KOF_FIND_MULTI(n) cannot ask for more markers than the matcher lists");
				ok = 0;
			}
			if (!ok) {
				mat->n--;           /* a matcher that did not resolve is not in the tree */
				continue;
			}
		} else {
			int ok = 1;

			m->kind = KOF_FORM_M_SIM;
			m->thresh = (uint8_t)it->a;
			while (next_name(&p, &s, &n)) {
				struct rname *bn = rfind(blk, s, n);
				uint8_t k;

				if (!bn) {
					RERR(ln, "the matcher names a block that is not declared");
					ok = 0;
					continue;
				}
				for (k = 0; k < m->n; k++)
					if (m->arg[k] == bn->v) {
						RERR(ln, "a block is listed twice in one matcher");
						ok = 0;
						break;
					}
				if (m->n >= KOF_FORM_MAX_ARG) {
					RERR(ln, "a matcher lists from one to sixteen blocks");
					ok = 0;
					break;
				}
				bn->used = 1;
				m->arg[m->n++] = (uint8_t)bn->v;
			}
			if (!ok) {
				mat->n--;
				continue;
			}
			f->n_sim++;
		}
		f->n_match++;
	}
	/* Pass three: the expression. */
	for (q = 0; q < d->n; q++)
		if (d->item[q].kind == KDS_EXPR) {
			if (expr)
				RERR(d->item[q].line, "a diagnose has one KOF_DIAG_EXPR");
			expr = &d->item[q];
		}
	if (!f->n_match) {
		if (!errs)
			RERR(last, "a form needs a matcher (KOF_DIAG_FIND or KOF_DIAG_SIMILAR)");
	} else if (expr) {
		struct xp x;
		int root;

		x.p = expr->t1 ? expr->t1 : "";
		x.f = f;
		x.match = mat;
		x.err = NULL;
		x.depth = 0;
		root = xp_or(&x);
		if (root >= 0) {
			xp_ws(&x);
			if (*x.p) {
				x.err = "the expression has something after its end (the operators are && || and !)";
				root = -1;
			}
		}
		if (root < 0) {
			RERR(expr->line, x.err ? x.err : "the expression does not read");
		} else if ((uint32_t)root != (uint32_t)f->n_node - 1u) {
			RERR(expr->line, "the expression does not read");
		}
	} else {
		/* No expression: every matcher, and: what the editor writes for a condition that names them all. */
		uint32_t i;
		int acc = -1;
		struct xp x;

		x.p = "";
		x.f = f;
		x.match = mat;
		x.err = NULL;
		x.depth = 0;
		for (i = 0; i < f->n_match; i++) {
			int leaf = xp_node(&x, KOF_FORM_OP_LEAF, (uint8_t)i, 0);

			mat->e[i].used = 1;
			acc = acc < 0 ? leaf : xp_node(&x, KOF_FORM_OP_AND, (uint8_t)acc, (uint8_t)leaf);
			if (acc < 0)
				break;
		}
		if (acc < 0)
			RERR(last, x.err ? x.err : "the matchers do not fit an expression");
	}
	/* What nothing uses is said: a marker, a block or a range no matcher names, a matcher no expression names. */
	for (q = 0; q < rng->n; q++)
		if (!rng->e[q].used) {
			snprintf(msg, sizeof msg, "line %u: the range %s is used by no matcher", rng->e[q].line, rng->e[q].name);
			kof_dsrc_say_warn(r, msg);
		}
	for (q = 0; q < str->n; q++)
		if (!str->e[q].used) {
			snprintf(msg, sizeof msg, "line %u: the string %s is used by no matcher", str->e[q].line, str->e[q].name);
			kof_dsrc_say_warn(r, msg);
		}
	for (q = 0; q < blk->n; q++)
		if (!blk->e[q].used) {
			snprintf(msg, sizeof msg, "line %u: the block %s is used by no matcher", blk->e[q].line, blk->e[q].name);
			kof_dsrc_say_warn(r, msg);
		}
	for (q = 0; q < mat->n; q++)
		if (!mat->e[q].used) {
			snprintf(msg, sizeof msg, "line %u: the matcher %s is used by no expression", mat->e[q].line,
				 mat->e[q].name);
			kof_dsrc_say_warn(r, msg);
		}
	/* The one check the loader ends with, asked here: a source the builder accepts is a record the loader reads. */
	if (!errs && (why = kof_form_check(f)) != NULL)
		RERR(last, why);
	if (!errs && !kof_form_wire_size(f))
		RERR(last, "the form is over the size of a record");
	free(rng);
	*nerr += errs;
	KOF_TRACE("[src] form resolved: %u string(s), %u block(s) (%u hash(es)), %u matcher(s) (%u similarity), %u node(s), %d error(s)\n",
		  (unsigned)f->n_str, (unsigned)f->n_block, (unsigned)f->n_hash, (unsigned)f->n_match, (unsigned)f->n_sim,
		  (unsigned)f->n_node, errs);
	if (errs) {
		kof_form_free(f);
		return NULL;
	}
	return f;
}
