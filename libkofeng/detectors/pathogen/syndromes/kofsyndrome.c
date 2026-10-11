#include "kofsyndrome.h"
#include "../../../kofcore/kofmod/kofsig.h"   /* kof_maltype */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert((uint32_t)KOF_MALTYPE_COUNT <= 32u,
	       "a type is a bit of a 32 bit mask here; widen the masks before adding the 33rd");

/*
 * A disease is a number in this set, in sorted order of its text, and a
 * syndrome is a bitset over those numbers. The query is a bitset too, so both
 * relations are word operations: Q <= T is (Q & ~T) == 0, T <= Q is
 * (T & ~Q) == 0.
 */
struct kof_synd_set {
	uint32_t   n_dis;
	char     **dis;         /* sorted, distinct */
	uint32_t   n_w;         /* words in one bitset */
	uint32_t   n;           /* exemplars kept */
	uint32_t  *type;        /* type mask of each */
	uint32_t  *sure;        /* types this exemplar's syndrome alone proves */
	uint64_t  *bits;        /* n x n_w */
};

static char *dup_str(const char *a)
{
	size_t n = strlen(a) + 1u;
	char *o = malloc(n);

	if (o)
		memcpy(o, a, n);
	return o;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static uint32_t dis_id(const struct kof_synd_set *s, const char *a)
{
	uint32_t lo = 0, hi = s->n_dis;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;
		int c = strcmp(a, s->dis[mid]);

		if (!c)
			return mid;
		if (c < 0)
			hi = mid;
		else
			lo = mid + 1u;
	}
	return UINT32_MAX;
}

static int subset(const uint64_t *a, const uint64_t *b, uint32_t n_w)
{
	uint32_t i;

	for (i = 0; i < n_w; i++)
		if (a[i] & ~b[i])
			return 0;
	return 1;
}

void kof_synd_free(struct kof_synd_set *s)
{
	uint32_t i;

	if (!s)
		return;
	for (i = 0; i < s->n_dis; i++)
		free(s->dis[i]);
	free(s->dis);
	free(s->type);
	free(s->sure);
	free(s->bits);
	free(s);
}

uint32_t kof_synd_count(const struct kof_synd_set *s)
{
	return s ? s->n : 0;
}

struct kof_synd_set *kof_synd_build(const struct kof_synd_in *in, uint32_t n)
{
	struct kof_synd_set *s = calloc(1, sizeof *s);
	char **all = NULL;
	uint32_t i, j, k, n_all = 0, kept = 0;

	if (!s)
		return NULL;
	for (i = 0; i < n; i++)
		n_all += in[i].n_dis;
	if (n_all) {
		all = malloc((size_t)n_all * sizeof *all);
		if (!all)
			goto fail;
	}
	/* The diseases, once each. */
	n_all = 0;
	for (i = 0; i < n; i++)
		for (j = 0; j < in[i].n_dis; j++) {
			all[n_all] = dup_str(in[i].dis[j]);
			if (!all[n_all])
				goto fail_all;
			n_all++;
		}
	if (n_all) {
		qsort(all, n_all, sizeof *all, cmp_str);
		s->dis = all;
		for (i = 0; i < n_all; i++) {
			if (s->n_dis && !strcmp(s->dis[s->n_dis - 1u], all[i])) {
				free(all[i]);
				continue;
			}
			s->dis[s->n_dis++] = all[i];
		}
	}
	all = NULL;
	s->n_w = (s->n_dis + 63u) / 64u;
	if (!s->n_w)
		s->n_w = 1u;
	s->type = calloc(n ? n : 1u, sizeof *s->type);
	s->sure = calloc(n ? n : 1u, sizeof *s->sure);
	s->bits = calloc((size_t)(n ? n : 1u) * s->n_w, sizeof *s->bits);
	if (!s->type || !s->sure || !s->bits)
		goto fail;
	for (i = 0; i < n; i++) {
		uint64_t *w = s->bits + (size_t)kept * s->n_w;

		if (!in[i].n_dis)
			continue;       /* shows nothing */
		for (j = 0; j < in[i].n_dis; j++) {
			uint32_t id = dis_id(s, in[i].dis[j]);

			w[id / 64u] |= 1ull << (id % 64u);
		}
		s->type[kept++] = in[i].type_mask;
	}
	s->n = kept;
	/*
	 * WHAT AN EXEMPLAR'S SYNDROME PROVES: the types that EVERY exemplar showing
	 * at least that syndrome has. Decided here, once, because it depends on the
	 * exemplars and not on the query.
	 */
	for (i = 0; i < s->n; i++) {
		uint32_t m = s->type[i];

		for (k = 0; k < s->n; k++)
			if (subset(s->bits + (size_t)i * s->n_w,
				   s->bits + (size_t)k * s->n_w, s->n_w))
				m &= s->type[k];
		s->sure[i] = m;
	}
	return s;
fail_all:
	for (i = 0; i < n_all; i++)
		free(all[i]);
	free(all);
fail:
	kof_synd_free(s);
	return NULL;
}

int kof_synd_infer(const struct kof_synd_set *s, const char *const *dis,
		   uint32_t n, struct kof_synd_result *r)
{
	uint64_t *q;
	uint32_t i, compat = 0, proven = 0;

	memset(r, 0, sizeof *r);
	if (!s || !n)
		return 0;
	q = calloc(s->n_w, sizeof *q);
	if (!q)
		return 0;
	for (i = 0; i < n; i++) {
		uint32_t id = dis_id(s, dis[i]);

		r->n_query++;
		if (id == UINT32_MAX)
			r->n_unknown++;
		else if (!(q[id / 64u] & (1ull << (id % 64u))))
			q[id / 64u] |= 1ull << (id % 64u);
		else
			r->n_query--;           /* a duplicate is one */
	}
	/*
	 * A behaviour no exemplar carries is not covered by any syndrome, so
	 * nothing is compatible - and nothing can be proven by a syndrome that
	 * does not contain it either, but that is a statement about the syndrome
	 * and is still decided below.
	 */
	for (i = 0; i < s->n; i++) {
		const uint64_t *t = s->bits + (size_t)i * s->n_w;

		if (!r->n_unknown && subset(q, t, s->n_w)) {
			compat |= s->type[i];
			r->n_compat++;
		}
		if (subset(t, q, s->n_w))
			proven |= s->sure[i];
	}
	r->guaranteed = proven;
	r->possible = compat & ~proven;
	free(q);
	return 1;
}

static size_t put(char *out, size_t cap, size_t at, const char *s)
{
	size_t l = strlen(s);

	if (at < cap) {
		size_t room = cap - at - 1u;

		memcpy(out + at, s, l < room ? l : room);
	}
	return at + l;
}

/*
 * THE NAMING IS HARD-CODED HERE FOR NOW - see the note on the declaration. When
 * it moves into the bases, this function stops spelling anything: it reads the
 * researcher's declarations (which family word, which suffix, how two types
 * join, what an undecided set is called) and applies them, the way a verdict's
 * KOF_TARGET_NAME is applied. What is decided here and should stay decided in
 * the engine is WHICH case applies - proven, one left, several left, nothing -
 * not how each is written.
 */
size_t kof_synd_name(const struct kof_synd_result *r, char *out, size_t cap)
{
	size_t at = 0;
	uint32_t t, n = 0;
	const uint32_t mask = r->guaranteed ? r->guaranteed : r->possible;

	for (t = 0; t < (uint32_t)KOF_MALTYPE_COUNT; t++)
		n += (mask >> t) & 1u;
	if (!n) {
		at = put(out, cap, at, "Malware:Unresolved");
	} else if (r->guaranteed) {
		uint32_t seen = 0;

		for (t = 0; t < (uint32_t)KOF_MALTYPE_COUNT; t++)
			if ((mask >> t) & 1u) {
				if (seen++)
					at = put(out, cap, at, "+");
				at = put(out, cap, at, kof_maltype_name(t));
			}
		at = put(out, cap, at, ":Agent");
	} else if (n == 1u) {
		for (t = 0; t < (uint32_t)KOF_MALTYPE_COUNT; t++)
			if ((mask >> t) & 1u)
				at = put(out, cap, at, kof_maltype_name(t));
		at = put(out, cap, at, ":Agent.Predict");
	} else {
		uint32_t seen = 0;

		at = put(out, cap, at, "Ambiguous(");
		for (t = 0; t < (uint32_t)KOF_MALTYPE_COUNT; t++)
			if ((mask >> t) & 1u) {
				if (seen++)
					at = put(out, cap, at, ",");
				at = put(out, cap, at, kof_maltype_name(t));
			}
		at = put(out, cap, at, ")");
	}
	if (cap)
		out[at < cap ? at : cap - 1u] = 0;
	return at;
}
