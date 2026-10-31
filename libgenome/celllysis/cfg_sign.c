/*
 * cfg_sign.c - a signature of a function's SHAPE: labels, one Weisfeiler-Lehman round, a multiset, a 64-bit
 * canonical hash and a bottom-32 sketch of the multiset.
 *
 * THE LABEL of a reachable block is (in-degree, out-degree, terminator class FALL/COND/JUMP/EXIT) and nothing
 * else - no callee, no jump value, no name, no instruction. That is the measured winner among 100+ candidates
 * (cfg_decision.md): richer labels (instruction classes, size buckets, call counts, syscalls, loops,
 * dominators) lost recall to build differences or bought nothing; WL0 (no round) made 1491 clean matches a
 * reference function at 0.5, WL2 and deeper fall back to exact matching.
 *
 * ONE WL ROUND: a block's new label is the hash of its label and of the COMMUTATIVE sums of the labels of its
 * successors and of its predecessors, so it does not depend on the order edges are listed in or on the layout.
 *
 * THE MULTISET of final labels becomes a SET by pairing each label with its k-th occurrence, so the Jaccard of
 * the sets is the multiset Jaccard and a bottom-k sample of the set is a min-hash sketch. The elements are
 * the high 32 bits of mix(label, k); the sketch keeps the 32 smallest DISTINCT ones.
 *
 * NO SORT. The survey's harness sorted the labels twice (1.65 us of 4.0 us a function, M). Neither is needed:
 *   - the canonical hash is a SUM of a mix of each label (a multiset hash: commutative), folded with the block
 *     and edge counts. A sum of independent 64-bit mixes can collide only like a random 64-bit value, and the
 *     canonical hash is a similarity index key, not a defence;
 *   - k is the running count of equal labels, from a small hash table (open addressing, sized to the blocks),
 *     and the bottom-32 is kept as a MAX-HEAP of the 32 smallest distinct elements held in the sketch's own key[]
 *     (no allocation): an element enters only when it is smaller than the root (after the first few blocks that is
 *     rare), replaces it and sifts down; the heap is sorted once when the pass ends. The earlier form kept a sorted
 *     window and moved up to 31 slots for every entry; the keys are the same bit for bit (tests/lib/genome/cfg_sketch.c
 *     runs the earlier form as an oracle) so no pack and no threshold moved.
 * Everything is linear in the blocks.
 *
 * IMPROVE cfg-cost-1 (owner, 2026-10-31): the cost of this pass is accepted for now, because it runs after a decode that is paid anyway and it
 * widens what is computed per function (a richer label such as the call factor of the wl1call experiment costs about 41 ns of 412 ns here, agent-reported).
 * To be optimised later; measure first (callgrind Ir of the whole signing, decode excluded), do not guess.
 *
 * IMPROVE cfg-small-1 (owner, 2026-11-01): the floor of 12 reachable blocks is removed, so a function of any size with a reachable block is
 * signed. Functions of up to 4 blocks are not separable by shape alone (measured earlier, agent-reported): many different small functions share one
 * sketch, and a function of 5 to 11 blocks has fewer than 12 keys. Where to look when that matters: a richer label (the call factor of the
 * wl1call experiment, cfg-cost-1 above), the callee sketch (`ckey`), or the user's own threshold on the block; not here.
 *
 * KNOWN LIMIT, from the survey and not repeated as a claim: WL1 does not separate graphs that a deeper
 * refinement would (the regular-graph collisions); tests/lib/genome/cfg_sign.c lists the ones found over every
 * graph of up to five blocks.
 */
#include <string.h>

#include "cfg_private.h"

/* the largest label arrays of one call: 4 per block (current, next, predecessor sum, successor sum) */
#define WORK_PER_BLOCK (4u * sizeof(uint64_t))

static uint32_t pow2_at_least(uint32_t n)
{
	uint32_t p = 16u;

	while (p < n && p < 0x80000000u)
		p <<= 1;
	return p;
}

static uint64_t init_label(const struct kgenome_cfg_block *b)
{
	uint64_t h = kgenome_cfg_mix(kgenome_cfg_mix(7u, b->in_deg), b->out_deg);

	return kgenome_cfg_mix(h, b->term);     /* FALL 0, COND 1, JUMP 2, EXIT 3: the four classes of the survey */
}

/* One round over the reachable blocks: cur -> cur. */
static void wl_round(const struct kgenome_cfg *g, uint64_t *cur, uint64_t *nxt, uint64_t *sp, uint64_t *ss)
{
	const uint32_t n = g->n_all;
	uint32_t i;

	memset(sp, 0, (size_t)n * sizeof *sp);
	memset(ss, 0, (size_t)n * sizeof *ss);
	for (i = 0; i < n; i++) {
		const struct kgenome_cfg_block *b = &g->b[i];
		unsigned e;

		if (!b->reach)
			continue;
		for (e = 0; e < 2u; e++) {
			const uint32_t s = b->succ[e];

			if (s == KGENOME_CFG_NONE)
				continue;
			ss[i] += kgenome_cfg_mix(cur[s], 2u);
			sp[s] += kgenome_cfg_mix(cur[i], 1u);
		}
	}
	for (i = 0; i < n; i++)
		if (g->b[i].reach)
			nxt[i] = kgenome_cfg_mix(kgenome_cfg_mix(cur[i], sp[i]), ss[i]);
}

/*
 * THE BOTTOM-32 FORM. While a sketch is being made key[0..m) is a max-heap of the 32 smallest elements seen, duplicates counted (unordered
 * until it holds 32, then heapified); sketch_close sorts it ascending, which is what the pack and the compare read. An element enters only
 * when the heap is not full or it is below the root, so a rejected element costs one compare.
 *
 * EXACT, NOT APPROXIMATE. The heap is the 32 smallest of the MULTISET of elements. When those 32 are pairwise different they are also the 32
 * smallest DISTINCT values (a distinct value below the largest held would have a place among them), which is the sketch. When two are equal
 * (two labels whose 32-bit keys collide: about n^2 / 2^33 for n elements, so rare, but not impossible and a test builds one) the heap may hold fewer
 * distinct values than it should, sketch_close says so and the sketch is made again with `strict`, which refuses an element already
 * held by a branch-free scan of at most 32 words (done only for an element that would enter). The common pass has no such scan: with it, a sketch of 40 random
 * elements took 628 ns against 418 ns (tests/lib/genome/cfg_sketch.c --bench, agent-reported).
 */
static void heap_down(uint32_t *key, uint32_t n, uint32_t p)
{
	for (;;) {
		uint32_t c = 2u * p + 1u, big = p, t;

		if (c < n && key[c] > key[big])
			big = c;
		if (c + 1u < n && key[c + 1u] > key[big])
			big = c + 1u;
		if (big == p)
			return;
		t = key[p];
		key[p] = key[big];
		key[big] = t;
		p = big;
	}
}

static int sketch_has(const uint32_t *key, uint32_t m, uint32_t e)
{
	uint32_t i, d = 0;

	for (i = 0; i < m; i++)
		d |= (uint32_t)(key[i] == e);
	return (int)d;
}

static void sketch_add(uint32_t *key, uint32_t *m, uint32_t e, int strict)
{
	if (*m < KGENOME_CFG_KEYS) {
		if (strict && sketch_has(key, *m, e))
			return;
		key[(*m)++] = e;
		if (*m == KGENOME_CFG_KEYS) {
			uint32_t k;

			for (k = KGENOME_CFG_KEYS / 2u; k-- > 0;)
				heap_down(key, KGENOME_CFG_KEYS, k);
		}
		return;
	}
	if (e >= key[0] || (strict && sketch_has(key, KGENOME_CFG_KEYS, e)))
		return;
	key[0] = e;
	heap_down(key, KGENOME_CFG_KEYS, 0);
}

/* End of a pass: sort ascending, the order every reader of a sketch expects. Returns 1 when the elements are pairwise different (the sketch is final). */
static int sketch_close(uint32_t *key, uint32_t m)
{
	uint32_t i, j, dup = 0;

	for (i = 1; i < m; i++) {
		const uint32_t x = key[i];

		for (j = i; j && key[j - 1u] > x; j--)
			key[j] = key[j - 1u];
		key[j] = x;
	}
	for (i = 1; i < m; i++)
		dup |= (uint32_t)(key[i] == key[i - 1u]);
	return !dup;
}

/* The element of the k-th occurrence of `lab` in a multiset: count in a small open-addressing table (count 0 = free), keep the bottom 32. */
struct occ {
	uint64_t *lab;
	uint32_t *cnt;
	uint32_t mask;         /* table size - 1 */
};

static void occ_add(struct occ *t, uint64_t lab, uint32_t *key, uint32_t *m)
{
	uint32_t slot = (uint32_t)(lab ^ (lab >> 32)) & t->mask, run;

	while (t->cnt[slot] && t->lab[slot] != lab)
		slot = (slot + 1u) & t->mask;
	if (!t->cnt[slot])
		t->lab[slot] = lab;
	run = t->cnt[slot]++;
	sketch_add(key, m, kgenome_cfg_key(lab, run), 0);
}

/*
 * End of a multiset's pass. When the sketch came out with two equal elements (see THE BOTTOM-32 FORM) it is made again from the TABLE, which holds every
 * distinct label with its count, so it holds every element of the multiset (label, 0..count-1) whatever order they arrived in; the sketch is a set function,
 * so the order does not matter, and this time an element already held is refused.
 */
static void occ_close(const struct occ *t, uint32_t *key, uint32_t *m)
{
	uint32_t slot, run;

	if (sketch_close(key, *m))
		return;
	memset(key, 0, KGENOME_CFG_KEYS * sizeof *key);
	*m = 0;
	for (slot = 0; slot <= t->mask; slot++)
		for (run = 0; run < t->cnt[slot]; run++)
			sketch_add(key, m, kgenome_cfg_key(t->lab[slot], run), 1);
	sketch_close(key, *m);
}

/* The structural part: labels, WL rounds, canonical hash, sketch. `mem` has 4 label arrays of n_all and the table. */
static void sign_struct(const struct kgenome_cfg_sign_req *r, uint8_t *mem, uint32_t cap, struct kgenome_cfg_sign *out)
{
	const struct kgenome_cfg *g = r->g;
	uint64_t *cur = (uint64_t *)(void *)mem, *nxt = cur + g->n_all, *sp = nxt + g->n_all, *ss = sp + g->n_all, sum = 0;
	struct occ t;
	uint32_t i, rounds = r->rounds ? r->rounds : 1u;

	t.lab = ss + g->n_all;
	t.cnt = (uint32_t *)(void *)(t.lab + cap);
	t.mask = cap - 1u;
	memset(t.cnt, 0, (size_t)cap * sizeof *t.cnt);
	for (i = 0; i < g->n_all; i++)
		if (g->b[i].reach)
			cur[i] = init_label(&g->b[i]);
	for (; rounds; rounds--) {
		uint64_t *tmp;

		wl_round(g, cur, nxt, sp, ss);
		tmp = cur;
		cur = nxt;
		nxt = tmp;
	}
	for (i = 0; i < g->n_all; i++) {
		if (!g->b[i].reach)
			continue;
		sum += kgenome_cfg_mix(cur[i], 0x4d554c5449534554ull);
		occ_add(&t, cur[i], out->key, &out->n_key);
	}
	occ_close(&t, out->key, &out->n_key);
	out->canon = kgenome_cfg_mix(kgenome_cfg_mix(kgenome_cfg_mix(0x5151u, g->n_blk), g->n_edge), sum);
	if (r->label)
		for (i = 0; i < g->n_all; i++)
			r->label[i] = g->b[i].reach ? cur[i] : 0u;
}

/* The callee part: the resolved identities of the reachable calls, each with its kind, as a multiset of (kind+identity, k-th occurrence). */
static void sign_callees(const struct kgenome_cfg *g, uint8_t *mem, uint32_t cap, uint32_t n_res, struct kgenome_cfg_sign *out)
{
	struct occ t;
	uint64_t sum = 0;
	uint32_t i;

	t.lab = (uint64_t *)(void *)mem;
	t.cnt = (uint32_t *)(void *)(t.lab + cap);
	t.mask = cap - 1u;
	memset(t.cnt, 0, (size_t)cap * sizeof *t.cnt);
	for (i = 0; i < g->n_call; i++) {
		const uint64_t id = kgenome_cfg_mix(g->call[i].id, g->call[i].kind);

		if (!g->call[i].id)
			continue;       /* unresolved: no element, never a match */
		sum += kgenome_cfg_mix(id, 0x43414c4c454553ull);
		occ_add(&t, id, out->ckey, &out->n_ckey);
	}
	occ_close(&t, out->ckey, &out->n_ckey);
	out->n_cid = n_res;
	out->ccanon = kgenome_cfg_mix(kgenome_cfg_mix(0xca11u, n_res), sum);
}

enum kgenome_status kgenome_cfg_sign(const struct kgenome_cfg_sign_req *r, struct kgenome_cfg_sign *out)
{
	const struct kgenome_cfg *g;
	size_t bytes_s = 0, bytes_c = 0, bytes;
	uint32_t cap_s = 0, cap_c = 0, n_res = 0, i;
	unsigned policy;
	uint8_t *mem;

	memset(out, 0, sizeof *out);
	if (!r || !r->g || r->rounds > KGENOME_CFG_ROUNDS_MAX || r->policy > KGENOME_CFG_P_BOTH) {
		out->status = KGENOME_BAD_INPUT;
		return out->status;
	}
	g = r->g;
	policy = r->policy ? r->policy : KGENOME_CFG_P_STRUCT;
	out->status = g->status;
	out->n_blk = g->n_blk;
	if (r->label && g->n_all)
		memset(r->label, 0, (size_t)g->n_all * sizeof *r->label);
	if (policy & KGENOME_CFG_P_CALLEES)
		for (i = 0; i < g->n_call; i++)
			n_res += g->call[i].id != 0;
	if ((policy & KGENOME_CFG_P_STRUCT) && g->n_blk) {
		cap_s = pow2_at_least(g->n_blk > 0x3fffffffu ? 0x3fffffffu : g->n_blk * 2u);
		bytes_s = (size_t)g->n_all * WORK_PER_BLOCK + (size_t)cap_s * (sizeof(uint64_t) + sizeof(uint32_t));
	}
	if (n_res) {
		cap_c = pow2_at_least(n_res > 0x3fffffffu ? 0x3fffffffu : n_res * 2u);
		bytes_c = (size_t)cap_c * (sizeof(uint64_t) + sizeof(uint32_t));
	}
	bytes = bytes_s + bytes_c;
	if (!bytes)
		return out->status;
	if (kgenome_cfg_over(r->budget, bytes)) {
		out->n_blk = 0;
		out->status = kgenome_status_merge(out->status, KGENOME_OVER_BUDGET);
		return out->status;
	}
	mem = kgenome_cfg_alloc(&r->mem, bytes);
	if (!mem) {
		out->n_blk = 0;
		out->status = kgenome_status_merge(out->status, KGENOME_NOMEM);
		return out->status;
	}
	if (bytes_s)
		sign_struct(r, mem, cap_s, out);
	if (bytes_c)
		sign_callees(g, mem + bytes_s, cap_c, n_res, out);
	kgenome_cfg_release(&r->mem, mem, bytes);
	return out->status;
}

void kgenome_cfg_keys_sign(struct kgenome_cfg_sign *out, const uint32_t *key, uint32_t n)
{
	uint32_t i, m = 0;

	memset(out, 0, sizeof *out);
	if (!key)
		return;
	for (i = 0; i < n; i++)
		sketch_add(out->key, &m, key[i], 0);    /* the 32 smallest distinct: the sketch's own rule, in one place */
	if (!sketch_close(out->key, m)) {
		memset(out->key, 0, sizeof out->key);   /* equal elements: again, refusing a repeat */
		m = 0;
		for (i = 0; i < n; i++)
			sketch_add(out->key, &m, key[i], 1);
		sketch_close(out->key, m);
	}
	out->n_key = m;
}

/*
 * The merge has no data-dependent branch: an exhausted side reads as 0xffffffff, which is never LESS than anything, so the other side
 * advances; and a hit needs both sides to be real (0xffffffff is also a legal element, and an exhausted side must not match it). The compares
 * of a real pair are not predictable: 130 ns -> 76 ns a call over 4096 random pairs (tests/lib/genome/cfg_sketch.c --bench, agent-reported),
 * with MORE instructions (callgrind: 692 -> 1003 Ir a call). Time, not Ir, is the measure here.
 */
static void overlap_keys(const uint32_t *a, uint32_t na, const uint32_t *b, uint32_t nb, uint32_t *hit_o, uint32_t *taken_o)
{
	uint32_t i = 0, j = 0, taken = 0, hit = 0;

	*hit_o = *taken_o = 0;
	if (!na || !nb)
		return;
	while (taken < KGENOME_CFG_KEYS && (i < na || j < nb)) {
		const uint32_t ra = i < na, rb = j < nb;
		const uint32_t x = ra ? a[i] : 0xffffffffu, y = rb ? b[j] : 0xffffffffu;

		hit += (uint32_t)(x == y) & ra & rb;
		i += (uint32_t)(x <= y);
		j += (uint32_t)(y <= x);
		taken++;
	}
	*hit_o = hit;
	*taken_o = taken;
}

static uint32_t pct_keys(const uint32_t *a, uint32_t na, const uint32_t *b, uint32_t nb)
{
	uint32_t hit, taken;

	overlap_keys(a, na, b, nb, &hit, &taken);
	return taken ? hit * 100u / taken : 0u;
}

void kgenome_cfg_overlap(const struct kgenome_cfg_sign *a, const struct kgenome_cfg_sign *b, uint32_t *hit, uint32_t *taken)
{
	overlap_keys(a->key, a->n_key, b->key, b->n_key, hit, taken);
}

uint32_t kgenome_cfg_pct(const struct kgenome_cfg_sign *a, const struct kgenome_cfg_sign *b)
{
	return pct_keys(a->key, a->n_key, b->key, b->n_key);
}

uint32_t kgenome_cfg_pct_callee(const struct kgenome_cfg_sign *a, const struct kgenome_cfg_sign *b)
{
	return pct_keys(a->ckey, a->n_ckey, b->ckey, b->n_ckey);
}
