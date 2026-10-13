#include "kofsyndrome.h"
#include "../../kofcore/kofmod/kofsig.h"   /* kof_maltype */
#include "../../kofcore/kofcmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert((uint32_t)KOF_MALTYPE_COUNT <= 32u,
	       "a type is a bit of a 32 bit mask here; widen the masks before adding the 33rd");

/*
 * A disease is its id, and a syndrome is a bitset over the ids this set knows,
 * numbered in ascending order of id. The query is a bitset too, so both
 * relations are word operations: Q <= T is (Q & ~T) == 0, T <= Q is
 * (T & ~Q) == 0.
 */
struct kof_synd_set {
	uint32_t   n_dis;
	uint32_t  *dis;         /* ascending, distinct */
	uint32_t   n_w;         /* words in one bitset */
	uint32_t   n;           /* exemplars kept */
	uint32_t  *type;        /* type mask of each */
	uint32_t  *sure;        /* types this exemplar's syndrome alone proves */
	uint64_t  *bits;        /* n x n_w */
	/* The same exemplars as ids, ascending, for kof_synd_get: `ex_n[i]` of them
	 * from `ex_ids + ex_first[i]`. */
	uint32_t  *ex_ids;
	uint32_t  *ex_first;
	uint32_t  *ex_n;
};

static uint32_t dis_index(const struct kof_synd_set *s, uint32_t id)
{
	uint32_t lo = 0, hi = s->n_dis;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (s->dis[mid] == id)
			return mid;
		if (id < s->dis[mid])
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
	if (!s)
		return;
	free(s->dis);
	free(s->type);
	free(s->sure);
	free(s->bits);
	free(s->ex_ids);
	free(s->ex_first);
	free(s->ex_n);
	free(s);
}

uint32_t kof_synd_count(const struct kof_synd_set *s)
{
	return s ? s->n : 0;
}

/* The most ids the exemplars can hold between them: what the id array is sized by. */
static uint32_t n_all_ids(const struct kof_synd_in *in, uint32_t n)
{
	uint32_t i, t = 0;

	for (i = 0; i < n; i++)
		t += in[i].n_dis;
	return t;
}

int kof_synd_get(const struct kof_synd_set *s, uint32_t i, uint32_t *type_mask,
		 uint32_t *n_dis, const uint32_t **dis)
{
	if (!s || i >= s->n)
		return 0;
	*type_mask = s->type[i];
	*n_dis = s->ex_n[i];
	*dis = s->ex_ids + s->ex_first[i];
	return 1;
}

struct kof_synd_set *kof_synd_build(const struct kof_synd_in *in, uint32_t n)
{
	struct kof_synd_set *s = calloc(1, sizeof *s);
	uint32_t i, j, k, n_all = 0, kept = 0;

	if (!s)
		return NULL;
	for (i = 0; i < n; i++)
		n_all += in[i].n_dis;
	if (n_all) {
		/* The ids, once each. */
		s->dis = malloc((size_t)n_all * sizeof *s->dis);
		if (!s->dis)
			goto fail;
		n_all = 0;
		for (i = 0; i < n; i++)
			for (j = 0; j < in[i].n_dis; j++)
				s->dis[n_all++] = in[i].dis[j];
		qsort(s->dis, n_all, sizeof *s->dis, kof_cmp_u32);
		for (i = 0; i < n_all; i++)
			if (!s->n_dis || s->dis[s->n_dis - 1u] != s->dis[i])
				s->dis[s->n_dis++] = s->dis[i];
	}
	s->n_w = (s->n_dis + 63u) / 64u;
	if (!s->n_w)
		s->n_w = 1u;
	s->type = calloc(n ? n : 1u, sizeof *s->type);
	s->sure = calloc(n ? n : 1u, sizeof *s->sure);
	s->bits = calloc((size_t)(n ? n : 1u) * s->n_w, sizeof *s->bits);
	s->ex_first = calloc(n ? n : 1u, sizeof *s->ex_first);
	s->ex_n = calloc(n ? n : 1u, sizeof *s->ex_n);
	s->ex_ids = malloc(((size_t)n_all_ids(in, n) + 1u) * sizeof *s->ex_ids);
	if (!s->type || !s->sure || !s->bits || !s->ex_first || !s->ex_n || !s->ex_ids)
		goto fail;
	for (i = 0; i < n; i++) {
		uint64_t *w = s->bits + (size_t)kept * s->n_w;

		if (!in[i].n_dis)
			continue;       /* shows nothing */
		for (j = 0; j < in[i].n_dis; j++) {
			uint32_t id = dis_index(s, in[i].dis[j]);

			w[id / 64u] |= 1ull << (id % 64u);
		}
		s->type[kept++] = in[i].type_mask;
	}
	s->n = kept;
	/* The ids of each, ascending, from the bitsets: duplicates in the input are
	 * one disease here, as they are in the matching. */
	{
		uint32_t at = 0;

		for (i = 0; i < s->n; i++) {
			const uint64_t *w = s->bits + (size_t)i * s->n_w;

			s->ex_first[i] = at;
			for (j = 0; j < s->n_dis; j++)
				if ((w[j / 64u] >> (j % 64u)) & 1u)
					s->ex_ids[at++] = s->dis[j];
			s->ex_n[i] = at - s->ex_first[i];
		}
	}
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
fail:
	kof_synd_free(s);
	return NULL;
}

int kof_synd_infer(const struct kof_synd_set *s, const uint32_t *dis,
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
		uint32_t id = dis_index(s, dis[i]), j;

		/* A duplicate is one, whether or not the set knows the disease: an
		 * unverified behaviour asked about twice is still one behaviour. */
		for (j = 0; j < i; j++)
			if (dis[j] == dis[i])
				break;
		if (j < i)
			continue;
		r->n_query++;
		if (id == UINT32_MAX)
			r->n_unknown++;
		else
			q[id / 64u] |= 1ull << (id % 64u);
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
