/*
 * fntab_merge.c - the entry list of the function table, and THE ONE PLACE TWO SOURCES MEET (fntab.h).
 *
 * Rank of an entry, highest first: SYMTAB 5, PDATA 4, DYNSYM or COFF 3, FDE or an import stub (end = its own instruction) 2, an entry whose end no source established (the walk's, the entry point's) 1.
 * A FRAGMENT (a chained unwind entry of a PE x64: the cold part of another function) takes part as an exact body - so the walk cannot start a function inside it - and leaves
 * the table at the end, counted in set->n_extra: the function it belongs to keeps its own extent.
 * An exact body (end from a symbol size or an unwind length) is authoritative: a start of a lower rank inside it is not a function of its
 * own, and where two exact sources give one start with different ends the better rank stands and the entry says so (flag DISAGREE,
 * set->n_disagree) - a disagreement is recorded, never hidden. The rule inside ONE source is the one this table always had: one function per
 * start (the longer extent stands) and no label inside another body; two bodies that overlap without one holding the other are both kept.
 */
#include <stdlib.h>
#include <string.h>

#include <kofcore.h>
#include <kgenome_budget.h>
#include "fntab_private.h"

int kgenome_fntab_list_add(struct kgenome_fntab_list *l, const struct kgenome_func *f)
{
	if (l->n >= KGENOME_FNTAB_MAX) {
		l->partial |= KGENOME_FNTAB_P_CAP;      /* a bound of cost, said */
		return 0;
	}
	if (l->n == l->cap) {
		uint32_t nc = kgenome_grow_cap(l->cap, 256u);
		struct kgenome_func *nv = nc ? realloc(l->v, (size_t)nc * sizeof *nv) : NULL;

		if (!nv) {
			l->status = KGENOME_NOMEM;
			return 0;
		}
		l->v = nv;
		l->cap = nc;
	}
	l->v[l->n++] = *f;
	return 1;
}

void kgenome_fntab_list_free(struct kgenome_fntab_list *l)
{
	if (!l)
		return;
	free(l->v);
	memset(l, 0, sizeof *l);
}

static unsigned rank(const struct kgenome_func *f)
{
	if (!kgenome_fntab_exact(f))
		return 1u;
	if (f->source & KGENOME_FN_S_SYMTAB)
		return 5u;
	if (f->source & KGENOME_FN_S_PDATA)
		return 4u;
	if (f->source & (KGENOME_FN_S_DYNSYM | KGENOME_FN_S_COFF))      /* a PE has no .dynsym and an ELF no COFF table: one rung */
		return 3u;
	return 2u;
}

static int cmp(const void *a, const void *b)
{
	const struct kgenome_func *x = a, *y = b;
	unsigned rx = rank(x), ry = rank(y);

	if (x->off != y->off)
		return x->off < y->off ? -1 : 1;
	if (rx != ry)
		return rx < ry ? 1 : -1;
	if (x->len != y->len)
		return x->len < y->len ? 1 : -1;
	/* the rest of the key: two entries of one start, rank and length that differ only in what named them must not come out in the order they went in (qsort is not stable) */
	if (x->source != y->source)
		return x->source > y->source ? -1 : 1;
	if (x->end_source != y->end_source)
		return x->end_source < y->end_source ? -1 : 1;
	return x->value < y->value ? -1 : x->value > y->value;
}

void kgenome_fntab_merge(struct kgenome_fntab_list *l, uint32_t check_only, struct kgenome_func_set *out)
{
	struct kgenome_func *v = l->v;
	uint32_t n = l->n, i, k = 0;
	int pa = -1;                    /* the last kept exact entry */
	uint64_t auth_end = 0;          /* the furthest end of the exact entries kept */

	out->status = l->status;
	out->partial = l->partial;
	if (!n) {
		l->v = NULL;
		l->n = l->cap = 0;
		free(v);
		return;
	}
	qsort(v, n, sizeof *v, cmp);
	for (i = 0; i < n; i++) {
		struct kgenome_func *e = &v[i];
		int chk;

		/* A START is a check only when EVERY source that named it is: the union over the entries of the start, not the first of them (which one comes first is the sort's business) */
		if (k && v[k - 1u].off == e->off) {
			chk = 0;                                         /* (not read: the entry joins the one kept before it) */
		} else {
			uint32_t j;
			uint32_t all = 0;

			for (j = i; j < n && v[j].off == e->off; j++)
				all |= v[j].source;
			chk = !(all & ~check_only);
		}

		/* the same start as the entry kept before: one function, the sources add up */
		if (k && v[k - 1u].off == e->off) {
			struct kgenome_func *kp = &v[k - 1u];

			kp->source |= e->source;
			if (kgenome_fntab_exact(kp) && kgenome_fntab_exact(e) && kp->len != e->len && rank(kp) != rank(e)) {
				kp->flags |= KGENOME_FN_F_DISAGREE;
				out->n_disagree++;
			} else if (kgenome_fntab_exact(kp) && kgenome_fntab_exact(e) && kp->len != e->len) {
				out->n_extra++;       /* the same source, the shorter extent: an alias, as it always was */
			}
			continue;
		}
		if (kgenome_fntab_exact(e)) {
			if (pa >= 0) {
				const struct kgenome_func *p = &v[pa];
				const uint64_t pend = p->off + p->len;

				if (e->off < pend) {
					if (e->off + e->len <= pend) {           /* a label inside the body of the one before */
						if (!(p->source & e->source))
							out->n_extra++;
						continue;
					}
					if (rank(e) < rank(p)) {                 /* overlaps a better source's body */
						out->n_disagree++;
						continue;
					}
					/* two bodies of one rank that overlap and neither holds the other: both are kept (as this table always did) and the overlap is SAID */
					if (rank(e) == rank(p) && (p->source & e->source & KGENOME_FN_S_PDATA)) {
						v[pa].flags |= KGENOME_FN_F_DISAGREE;
						e->flags |= KGENOME_FN_F_DISAGREE;
						out->n_disagree++;
					}
				}
			}
			if (chk) {
				/* only a check: counted; a start outside every body is what the symbols lack */
				out->n_extra++;
				if (e->off >= auth_end)
					out->partial |= KGENOME_FNTAB_P_SYMTAB;
				continue;
			}
		} else {
			if (e->off < auth_end || chk) {                  /* inside an exact body: not a function of its own */
				out->n_extra++;
				continue;
			}
		}
		v[k] = *e;
		if (kgenome_fntab_exact(&v[k])) {
			pa = (int)k;
			if (v[k].off + v[k].len > auth_end)
				auth_end = v[k].off + v[k].len;
		}
		k++;
	}
	l->v = NULL;
	l->n = l->cap = 0;
	/* the fragments did their work as masks above: they are not functions */
	{
		uint32_t j, m = 0;

		for (j = 0; j < k; j++) {
			if (v[j].kind == KGENOME_FN_FRAGMENT) {
				out->n_extra++;
				continue;
			}
			v[m++] = v[j];
		}
		k = m;
	}
	if (!k) {
		free(v);
		return;
	}
	/* A symbol of size 0 was closed by the symbol strategy at the next SYMBOL of its own table: a start another source names inside that body ends it there (FNTAB-COV-1). */
	for (i = 0; i + 1u < k; i++)
		if ((v[i].flags & KGENOME_FN_F_SIZE0) && v[i].len && v[i + 1u].off < v[i].off + v[i].len)
			v[i].len = v[i + 1u].off - v[i].off;
	out->v = v;
	out->n = k;
}
