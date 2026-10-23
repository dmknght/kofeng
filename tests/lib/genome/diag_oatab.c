/*
 * genome / diag_oatab - the one open-addressing table of the diagnose family (libgenome/phenotype/diag_oatab.h) against a REFERENCE written here.
 *
 * What is under test is not "a table works" but the three things four copies used to agree on and one function now owns:
 *   when it grows      kgenome_oatab_want: at or under half full it stays, past it doubles, an empty table gets `first`;
 *   where an entry goes the rehash moves occupied slots in SLOT ORDER, each to the first empty slot from its home - so two entries with the same home keep the order
 *                      they had, which decides what a lookup finds first. The reference rehash below is written separately and the two tables are compared byte for byte, with
 *                      a hash that collides on purpose (everything in one chain, and 16 keys to a home);
 *   memory refused     the table and its capacity are as they were, and its entries still found.
 * The entry sizes are 4, 8 and 24 bytes with the non-zero byte NOT first, so "occupied" cannot be read from one field.
 *
 * usage: diag_oatab   (seeded, fixed)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_oatab.h>

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint32_t rs = 7u;

static uint32_t rnd(void)
{
	rs = rs * 1103515245u + 12345u;
	return rs >> 8;
}

/* ---- an entry: a key (never 0) and padding in front of it, so the first byte of a slot is zero for an occupied slot too ---- */
struct ent {
	uint8_t  pad[8];
	uint32_t key;
	uint32_t val;
	uint32_t more[2];
};

/* the three hashes: spread, 16 keys to a home, and one home for all */
static uint32_t h_spread(void *ctx, const void *s) { (void)ctx; return ((const struct ent *)s)->key * 2654435761u; }
static uint32_t h_clump(void *ctx, const void *s) { (void)ctx; return ((const struct ent *)s)->key >> 4; }
static uint32_t h_one(void *ctx, const void *s) { (void)ctx; (void)s; return 0; }

static kgenome_oatab_hash_fn const hashes[3] = { h_spread, h_clump, h_one };

struct tab {
	struct ent *t;
	uint32_t cap, n;
};

static struct ent *find(const struct tab *tb, kgenome_oatab_hash_fn h, uint32_t key)
{
	uint32_t i;
	struct ent probe = { .key = key };

	if (!tb->cap)
		return NULL;
	for (i = h(NULL, &probe) & (tb->cap - 1u); tb->t[i].key; i = kgenome_oatab_next(i, tb->cap))
		if (tb->t[i].key == key)
			return &tb->t[i];
	return NULL;
}

static int is_pow2(uint32_t v)
{
	return v && !(v & (v - 1u));
}

/* the reference rehash: a plain loop over the old slots in order into a zeroed table */
static struct ent *ref_rehash(const struct tab *tb, kgenome_oatab_hash_fn h, uint32_t nc)
{
	struct ent *nv = calloc(nc, sizeof *nv);
	uint32_t k, m;

	for (k = 0; k < tb->cap; k++) {
		if (!tb->t[k].key)
			continue;
		for (m = h(NULL, &tb->t[k]) & (nc - 1u); nv[m].key; m = (m + 1u) & (nc - 1u))
			;
		nv[m] = tb->t[k];
	}
	return nv;
}

static void want_table(void)
{
	/* an empty table takes `first`; half full stays; one past half doubles; the answer does not depend on `first` once there are slots */
	CK(kgenome_oatab_want(0, 0, 64) == 64u);
	CK(kgenome_oatab_want(0, 0, 256) == 256u);
	CK(kgenome_oatab_want(0, 64, 256) == 0u);
	CK(kgenome_oatab_want(31, 64, 256) == 0u);      /* 32 entries of 64: exactly half */
	CK(kgenome_oatab_want(32, 64, 256) == 128u);    /* the 33rd passes it */
	CK(kgenome_oatab_want(63, 64, 256) == 128u);
	CK(kgenome_oatab_want(127, 256, 64) == 0u);
	CK(kgenome_oatab_want(128, 256, 64) == 512u);
	CK(kgenome_oatab_want(0, 2, 64) == 0u);         /* 1 of 2 */
	CK(kgenome_oatab_want(1, 2, 64) == 4u);
	CK(kgenome_oatab_next(0, 8) == 1u);
	CK(kgenome_oatab_next(7, 8) == 0u);             /* wraps */
	CK(kgenome_oatab_next(3, 4) == 0u);
}

/* grow one entry at a time, as a caller does: the same table as the reference at every growth, every key still found, at most half full */
static void grow_vs_reference(int which, uint32_t first, uint32_t nkeys)
{
	struct tab tb = { NULL, 0, 0 };
	kgenome_oatab_hash_fn h = hashes[which];
	uint32_t k, grown = 0;
	uint32_t *keys = malloc(nkeys * sizeof *keys);

	for (k = 0; k < nkeys; k++) {
		uint32_t key = 1u + (rnd() % (nkeys * 4u)), j, nc;
		struct ent *e;

		keys[k] = key;
		nc = kgenome_oatab_want(tb.n, tb.cap, first);
		if (nc) {
			struct ent *ref = ref_rehash(&tb, h, nc);

			CK(is_pow2(nc));
			CK(nc >= tb.cap);
			CK(kgenome_oatab_rehash((void **)&tb.t, &tb.cap, nc, sizeof *tb.t, h, NULL, NULL));
			CK(tb.cap == nc);
			CK(memcmp(ref, tb.t, (size_t)nc * sizeof *ref) == 0);   /* the order of the entries in the new table is the reference's */
			free(ref);
			grown++;
		}
		CK(tb.cap && tb.n * 2u <= tb.cap);
		if (find(&tb, h, key)) {
			continue;       /* a repeat: not stored */
		}
		{
			uint32_t i;
			struct ent probe = { .key = key };

			for (i = h(NULL, &probe) & (tb.cap - 1u); tb.t[i].key; i = kgenome_oatab_next(i, tb.cap))
				;
			e = &tb.t[i];
			memset(e, 0, sizeof *e);
			e->key = key;
			e->val = key * 3u;
			e->more[1] = 0xabu;
			tb.n++;
		}
		for (j = 0; j <= k; j += 1u + k / 40u) {         /* a sample of the earlier keys still found with their value */
			struct ent *f = find(&tb, h, keys[j]);

			CK(f && f->val == keys[j] * 3u && f->more[1] == 0xabu);
		}
	}
	for (k = 0; k < nkeys; k++) {
		struct ent *f = find(&tb, h, keys[k]);

		CK(f && f->val == keys[k] * 3u);
	}
	CK(grown >= 2u || nkeys < 8u);
	free(tb.t);
	free(keys);
}

/* the entry sizes of the four tables: a pointer, a 64-bit key, a 24-byte struct - occupied is read from any byte */
static void sizes(void)
{
	uint32_t cap = 0, i;
	uint64_t *t64 = NULL;
	void **tp = NULL;
	uint32_t pcap = 0;
	int dummy[4];

	for (i = 1; i <= 100; i++) {
		uint32_t nc = kgenome_oatab_want(i - 1u, cap, 4u), j;
		uint64_t key = (uint64_t)i << 40;     /* the non-zero byte is the last */

		if (nc)
			CK(kgenome_oatab_rehash((void **)&t64, &cap, nc, sizeof *t64, h_one, NULL, NULL));
		for (j = 0; t64[j]; j = kgenome_oatab_next(j, cap))
			;
		t64[j] = key;
	}
	{
		uint32_t n = 0;

		for (i = 0; i < cap; i++)
			n += t64[i] != 0;
		CK(n == 100u);
	}
	for (i = 0; i < 40; i++) {
		uint32_t nc = kgenome_oatab_want(i, pcap, 4u), j;

		if (nc)
			CK(kgenome_oatab_rehash((void **)&tp, &pcap, nc, sizeof *tp, h_one, NULL, NULL));
		for (j = 0; tp[j]; j = kgenome_oatab_next(j, pcap))
			;
		tp[j] = &dummy[i & 3u];
	}
	{
		uint32_t n = 0;

		for (i = 0; i < pcap; i++)
			n += tp[i] != NULL;
		CK(n == 40u);
	}
	free(t64);
	free(tp);
}

/* memory refused: calloc of nc * elem overflows size_t, so no table is made and the old one stays whole */
static void refused(void)
{
	struct tab tb = { NULL, 0, 0 };
	kgenome_oatab_hash_fn h = h_spread;
	uint32_t k;
	struct ent *before;

	for (k = 1; k <= 20; k++) {
		uint32_t nc = kgenome_oatab_want(tb.n, tb.cap, 8u);

		if (nc)
			CK(kgenome_oatab_rehash((void **)&tb.t, &tb.cap, nc, sizeof *tb.t, h, NULL, NULL));
		{
			uint32_t i;
			struct ent probe = { .key = k };

			for (i = h(NULL, &probe) & (tb.cap - 1u); tb.t[i].key; i = kgenome_oatab_next(i, tb.cap))
				;
			tb.t[i].key = k;
			tb.n++;
		}
	}
	before = malloc((size_t)tb.cap * sizeof *before);
	memcpy(before, tb.t, (size_t)tb.cap * sizeof *before);
	{
		uint32_t cap0 = tb.cap;
		struct ent *t0 = tb.t;

		CK(!kgenome_oatab_rehash((void **)&tb.t, &tb.cap, 0x80000000u, (size_t)1 << 40, h, NULL, NULL));
		CK(tb.t == t0);
		CK(tb.cap == cap0);
		CK(memcmp(before, tb.t, (size_t)cap0 * sizeof *before) == 0);
	}
	for (k = 1; k <= 20; k++)
		CK(find(&tb, h, k) != NULL);
	free(before);
	free(tb.t);
}

int main(void)
{
	int w;
	uint32_t first;

	want_table();
	for (w = 0; w < 3; w++)
		for (first = 4; first <= 256; first *= 8)
			grow_vs_reference(w, first, w == 2 ? 300u : 2000u);
	sizes();
	refused();
	printf("genome diag_oatab: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
