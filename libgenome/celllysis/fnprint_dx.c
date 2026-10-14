/*
 * fnprint_dx.c - the decision state of the window stream: a diagnose is MET or IMPOSSIBLE, a cluster
 * is MET or IMPOSSIBLE, and work stops only for what can no longer change.
 *
 * WHY NOT "RETIRE AT THE FIRST HIT". The detections that decide a diagnose read SEVERAL pieces of
 * evidence together, and a block reaching its percent is one piece. Retiring the family at that
 * hit froze the credit of every other block of the family (measured: 9,302 blocks that reach 70% in a
 * full run became 128 in a run that retires at the first), which is the input a cluster needs. Here a
 * diagnose is dropped when its answer is known - `need` blocks are at their percent, or the blocks that
 * are not cannot get there - and not before; the state is kept so that the consumer reads the answer
 * and not a credit that stopped growing.
 *
 * THE BOUND. Credit only rises, one slot at a time, and a window credits the slots of a block that
 * hold its value: at most `dup` of them (the multiplicity of the most repeated value in the block). So
 * with `rem` windows still to come, a block at `c` credited slots of `n` can reach at most
 * c + min(n - c, rem x dup). If that is below the count its diagnose asks of it, the block is out; a
 * diagnose with fewer blocks left than it needs is IMPOSSIBLE. The bound is sound for any object and
 * any database (a hostile one with repeated hashes included, through `dup`), and it is the whole of
 * what the interrupt may claim: it is weak until `rem` is small (the unseen hashes of a block are
 * at most 128), which is why a clean object is decided at its end and not before.
 *
 * MEMORY. The index (dxdb) is read-only and shared; each context holds one byte or word per diagnose,
 * block and cluster. begin() resets them: O(blocks + diagnoses) per object, charged to the object.
 */
#include "fnprint.h"
#include "fnprint_private.h"

#include <stdlib.h>
#include <string.h>

struct kgenome_fnprint_dxrun {
	const struct kgenome_fnprint_dxdb *x;
	uint8_t  *dst;                  /* [n_dx] enum kgenome_fnprint_dstate */
	uint32_t *met;                  /* [n_dx] listed blocks at their percent */
	uint32_t *want;                 /* [n_dx] undecided clusters that list it */
	uint32_t *unw;                  /* [n_blk] listings of the block whose diagnose stopped wanting it (0 untouched) */
	uint32_t *touch;                /* [n_blk] the blocks with unw != 0 or dropped: the only ones begin() has to reset */
	uint32_t  n_touch;
	uint8_t  *bdead;                /* [n_blk] */
	uint8_t  *cst;                  /* [n_cl] */
	uint32_t *cmet, *cimp;          /* [n_cl] */
	uint32_t  n_open;
	uint64_t  swept;                /* windows left at the last sweep: a sweep within 8 of it decides nothing new worth its cost */
	uint64_t  bytes;
};

static uint32_t need_hashes(uint32_t pct, uint32_t n)
{
	return (uint32_t)(((uint64_t)(pct ? pct : 70u) * n + 99u) / 100u);
}

static void *dx_alloc(struct kgenome_ledger *led, uint64_t n, uint64_t *sum)
{
	void *p;

	if (!n)
		n = 1;
	if (led && !kgenome_ledger_charge(led, n))
		return NULL;
	p = calloc(1, (size_t)n);
	if (!p) {
		if (led)
			kgenome_ledger_release(led, n);
		return NULL;
	}
	*sum += n;
	return p;
}

/* ---- the index ---------------------------------------------------------------------- */

static int dx_validate(struct kgenome_fnprint_dxdb *x, const struct kgenome_fnprint_dxdesc *s, uint32_t n_blk)
{
	uint32_t i;
	uint64_t j;

	if (s->n_dx && !s->dx)
		return 0;
	if (s->n_ref && !s->ref)
		return 0;
	if (s->n_cl && (!s->cl || (s->n_mem && !s->mem)))
		return 0;
	if (s->n_ref >= 0xfffffff0ull || s->n_mem >= 0xfffffff0ull)
		return 0;
	for (i = 0; i < s->n_dx; i++)
		if (s->dx[i].first > s->n_ref || s->dx[i].n > s->n_ref - s->dx[i].first)
			return 0;
	for (j = 0; j < s->n_ref; j++)
		if (s->ref[j] >= n_blk)
			return 0;
	if (s->cl)
		for (i = 0; i < s->n_cl; i++) {
			uint32_t m;

			if (s->cl[i].first > s->n_mem || s->cl[i].n > s->n_mem - s->cl[i].first)
				return 0;
			for (m = 0; m < s->cl[i].n; m++)
				if (s->mem[s->cl[i].first + m] >= s->n_dx)
					return 0;
		}
	(void)x;
	return 1;
}

static void dup_of(const struct kgenome_fnprint_wdb *d, uint8_t *dup)
{
	uint32_t b, i, j;

	for (b = 0; b < d->n_blk; b++) {
		const uint32_t *h = d->pool + d->blk[b].first;
		uint32_t n = d->blk[b].n, best = 1;

		if (n > 1u)
			for (i = 0; i < n; i++) {
				uint32_t m = 1;

				for (j = i + 1u; j < n; j++)
					m += h[j] == h[i];
				if (m > best)
					best = m;
			}
		dup[b] = (uint8_t)best;
	}
}

int kgenome_fnprint_dxdb_build(struct kgenome_fnprint_dxdb *x, const struct kgenome_fnprint_wdb *d,
			       const struct kgenome_fnprint_dxdesc *desc, struct kgenome_ledger *led)
{
	const struct kgenome_fnprint_dxdesc *s = desc;
	uint32_t b, i;
	uint64_t j, sum = 0, n_list = 0, n_mlist = 0;
	uint32_t *cursor = NULL;

	memset(x, 0, sizeof *x);
	x->led = led;
	x->db = d;
	if (!d || !desc || !dx_validate(x, s, d->n_blk)) {
		x->status = KGENOME_BAD_INPUT;
		return 0;
	}
	x->desc = *s;
	if (!s->cl) {                           /* every diagnose is a consumer on its own */
		x->own_cl = dx_alloc(led, (uint64_t)s->n_dx * sizeof *x->own_cl, &x->bytes);
		x->own_mem = dx_alloc(led, (uint64_t)s->n_dx * 4u, &x->bytes);
		if (!x->own_cl || !x->own_mem)
			goto over;
		for (i = 0; i < s->n_dx; i++) {
			x->own_cl[i].first = i; x->own_cl[i].n = 1; x->own_cl[i].k = 1;
			x->own_mem[i] = i;
		}
		x->desc.cl = x->own_cl; x->desc.n_cl = s->n_dx;
		x->desc.mem = x->own_mem; x->desc.n_mem = s->n_dx;
		s = &x->desc;
	}
	/* Diagnoses may overlap in ref[] and clusters in mem[]: the index is sized by the LISTINGS, not by the arrays. */
	for (i = 0; i < s->n_dx; i++)
		n_list += s->dx[i].n;
	for (j = 0; j < s->n_cl; j++)
		n_mlist += s->cl[j].n;
	if (n_list >= 0xfffffff0ull || n_mlist >= 0xfffffff0ull) {
		x->status = KGENOME_TRUNCATED;
		kgenome_fnprint_dxdb_free(x);
		x->status = KGENOME_TRUNCATED;
		return 0;
	}
	x->rv_first = dx_alloc(led, ((uint64_t)d->n_blk + 1u) * 4u, &x->bytes);
	x->rv_dx = dx_alloc(led, n_list * 4u, &x->bytes);
	x->need_min = dx_alloc(led, (uint64_t)d->n_blk * 4u, &x->bytes);
	x->dup = dx_alloc(led, d->n_blk, &x->bytes);
	x->dxc_first = dx_alloc(led, ((uint64_t)s->n_dx + 1u) * 4u, &x->bytes);
	x->dxc_cl = dx_alloc(led, n_mlist * 4u, &x->bytes);
	cursor = dx_alloc(led, ((uint64_t)(d->n_blk > s->n_dx ? d->n_blk : s->n_dx) + 1u) * 4u, &sum);
	if (!x->rv_first || !x->rv_dx || !x->need_min || !x->dup || !x->dxc_first || !x->dxc_cl || !cursor)
		goto over;
	/* block -> diagnoses: counting sort over the listings */
	for (i = 0; i < s->n_dx; i++)
		for (j = 0; j < s->dx[i].n; j++)
			x->rv_first[s->ref[s->dx[i].first + j] + 1u]++;
	for (b = 0; b < d->n_blk; b++)
		x->rv_first[b + 1u] += x->rv_first[b];
	memcpy(cursor, x->rv_first, (size_t)d->n_blk * 4u);
	for (i = 0; i < s->n_dx; i++)
		for (j = 0; j < s->dx[i].n; j++)
			x->rv_dx[cursor[s->ref[s->dx[i].first + j]]++] = i;
	for (b = 0; b < d->n_blk; b++)
		x->need_min[b] = 0xffffffffu;
	for (i = 0; i < s->n_dx; i++)
		for (j = 0; j < s->dx[i].n; j++) {
			uint32_t bb = s->ref[s->dx[i].first + j], nh = need_hashes(s->dx[i].pct, d->blk[bb].n);

			if (nh < x->need_min[bb])
				x->need_min[bb] = nh;
			if (nh > x->trigger)
				x->trigger = nh;
		}
	/* diagnose -> clusters */
	for (j = 0; j < s->n_cl; j++) {
		uint32_t m;

		for (m = 0; m < s->cl[j].n; m++)
			x->dxc_first[s->mem[s->cl[j].first + m] + 1u]++;
	}
	for (i = 0; i < s->n_dx; i++)
		x->dxc_first[i + 1u] += x->dxc_first[i];
	memcpy(cursor, x->dxc_first, (size_t)s->n_dx * 4u);
	for (j = 0; j < s->n_cl; j++) {
		uint32_t m;

		for (m = 0; m < s->cl[j].n; m++)
			x->dxc_cl[cursor[s->mem[s->cl[j].first + m]]++] = (uint32_t)j;
	}
	dup_of(d, x->dup);
	free(cursor);
	if (led)
		kgenome_ledger_release(led, ((uint64_t)(d->n_blk > s->n_dx ? d->n_blk : s->n_dx) + 1u) * 4u);
	return 1;
over:
	if (cursor) {
		free(cursor);
		if (led)
			kgenome_ledger_release(led, ((uint64_t)(d->n_blk > s->n_dx ? d->n_blk : s->n_dx) + 1u) * 4u);
	}
	{
		struct kgenome_ledger *l = x->led;

		kgenome_fnprint_dxdb_free(x);
		x->led = l;
		x->status = KGENOME_OVER_BUDGET;
	}
	return 0;
}

void kgenome_fnprint_dxdb_free(struct kgenome_fnprint_dxdb *x)
{
	if (!x)
		return;
	if (x->led)
		kgenome_ledger_release(x->led, x->bytes);
	free(x->own_cl); free(x->own_mem); free(x->rv_first); free(x->rv_dx); free(x->need_min); free(x->dup);
	free(x->dxc_first); free(x->dxc_cl);
	memset(x, 0, sizeof *x);
}

/* ---- the state of one context --------------------------------------------------------- */

int kgenome_fnprint_dx_attach(struct kgenome_fnprint_wctx *c, const struct kgenome_fnprint_dxdb *x)
{
	struct kgenome_fnprint_dxrun *r;
	const struct kgenome_fnprint_dxdesc *s;
	uint64_t sum = 0;

	if (!c || !c->db || !x || x->db != c->db || x->status != KGENOME_OK)
		return 0;
	kgenome_fnprint_dx_detach(c);
	s = &x->desc;
	r = dx_alloc(c->led, sizeof *r, &sum);
	if (!r)
		goto over;
	r->x = x;
	r->dst = dx_alloc(c->led, s->n_dx, &sum);
	r->met = dx_alloc(c->led, (uint64_t)s->n_dx * 4u, &sum);
	r->want = dx_alloc(c->led, (uint64_t)s->n_dx * 4u, &sum);
	r->unw = dx_alloc(c->led, (uint64_t)c->db->n_blk * 4u, &sum);
	r->touch = dx_alloc(c->led, (uint64_t)c->db->n_blk * 4u, &sum);
	r->bdead = dx_alloc(c->led, c->db->n_blk, &sum);
	r->cst = dx_alloc(c->led, s->n_cl, &sum);
	r->cmet = dx_alloc(c->led, (uint64_t)s->n_cl * 4u, &sum);
	r->cimp = dx_alloc(c->led, (uint64_t)s->n_cl * 4u, &sum);
	if (!r->dst || !r->met || !r->want || !r->unw || !r->touch || !r->bdead || !r->cst || !r->cmet || !r->cimp)
		goto over;
	r->bytes = sum;
	c->dxr = r;
	c->bdead = r->bdead;
	c->dx_need_min = x->need_min;
	c->bytes += sum;
	return 1;
over:
	if (r) {
		free(r->dst); free(r->met); free(r->want); free(r->unw); free(r->touch); free(r->bdead); free(r->cst); free(r->cmet); free(r->cimp);
		free(r);
	}
	if (c->led)
		kgenome_ledger_release(c->led, sum);
	c->status = kgenome_status_merge(c->status, KGENOME_OVER_BUDGET);
	return 0;
}

void kgenome_fnprint_dx_detach(struct kgenome_fnprint_wctx *c)
{
	struct kgenome_fnprint_dxrun *r = c ? c->dxr : NULL;

	if (!r)
		return;
	if (c->led)
		kgenome_ledger_release(c->led, r->bytes);
	c->bytes -= r->bytes;
	free(r->dst); free(r->met); free(r->want); free(r->unw); free(r->touch); free(r->bdead); free(r->cst); free(r->cmet); free(r->cimp);
	free(r);
	c->dxr = NULL;
	c->bdead = NULL;
	c->dx_need_min = NULL;
	c->n_bdead = 0;
}

/* d leaves UNDECIDED: the blocks it listed lose one wanting listing; one nobody wants is dropped. */
static void unwant(struct kgenome_fnprint_wctx *c, uint32_t d)
{
	struct kgenome_fnprint_dxrun *r = c->dxr;
	const struct kgenome_fnprint_dxdesc *s = &r->x->desc;
	uint32_t j;

	/*
	 * DROPPING A BLOCK ONLY PAYS WHEN THE LOOKUPS IT SAVES ARE MANY: it costs a visit to every listing and a
	 * walk over the pairs, and a pair that is skipped as dead is almost as cheap to skip as to credit. It pays
	 * where the filter can be rebuilt without those keys, which needs many windows still to come. With fewer
	 * left (and `rem` only falls) nothing is dropped: the credit of a decided diagnose simply keeps growing,
	 * which is the better information and the cheaper pass. Measured in fnprint_sel_eval.md.
	 */
	if (c->rem < 16u * c->db->n_pair)
		return;
	for (j = 0; j < s->dx[d].n; j++) {
		uint32_t b = s->ref[s->dx[d].first + j];

		if (!r->unw[b])
			r->touch[r->n_touch++] = b;
		if (++r->unw[b] == r->x->rv_first[b + 1u] - r->x->rv_first[b])
			kgenome_fnprint_wctx_kill_block(c, b);
	}
}

static void cl_set(struct kgenome_fnprint_wctx *c, uint32_t cl, uint8_t st)
{
	struct kgenome_fnprint_dxrun *r = c->dxr;
	const struct kgenome_fnprint_dxdesc *s = &r->x->desc;
	uint32_t m;

	r->cst[cl] = st;
	r->n_open--;
	for (m = 0; m < s->cl[cl].n; m++) {
		uint32_t d = s->mem[s->cl[cl].first + m];

		if (r->want[d] && --r->want[d] == 0 && r->dst[d] == KGENOME_FNP_D_UNDECIDED) {
			r->dst[d] = KGENOME_FNP_D_RELEASED;
			unwant(c, d);
		}
	}
}

static void cl_eval(struct kgenome_fnprint_wctx *c, uint32_t cl)
{
	struct kgenome_fnprint_dxrun *r = c->dxr;
	const struct kgenome_fnprint_cl *q = &r->x->desc.cl[cl];

	if (r->cst[cl] != KGENOME_FNP_D_UNDECIDED)
		return;
	if (r->cmet[cl] >= q->k)
		cl_set(c, cl, KGENOME_FNP_D_MET);
	else if (q->k > q->n || r->cimp[cl] > q->n - q->k)
		cl_set(c, cl, KGENOME_FNP_D_IMPOSSIBLE);
}

static void dx_decide(struct kgenome_fnprint_wctx *c, uint32_t d, uint8_t st)
{
	struct kgenome_fnprint_dxrun *r = c->dxr;
	const struct kgenome_fnprint_dxdb *x = r->x;
	uint32_t i;

	if (r->dst[d] != KGENOME_FNP_D_UNDECIDED)
		return;
	r->dst[d] = st;
	unwant(c, d);
	for (i = x->dxc_first[d]; i < x->dxc_first[d + 1u]; i++) {
		uint32_t cl = x->dxc_cl[i];

		if (st == KGENOME_FNP_D_MET)
			r->cmet[cl]++;
		else
			r->cimp[cl]++;
		cl_eval(c, cl);
	}
}

void kgenome_fnprint_dx_begin(struct kgenome_fnprint_wctx *c)
{
	struct kgenome_fnprint_dxrun *r = c->dxr;
	const struct kgenome_fnprint_dxdb *x = r->x;
	const struct kgenome_fnprint_dxdesc *s = &x->desc;
	uint32_t i, b;

	memset(r->dst, 0, s->n_dx);
	memset(r->met, 0, (size_t)s->n_dx * 4u);
	for (b = 0; b < r->n_touch; b++) {              /* what the last object touched: O(touched), not O(blocks) */
		r->bdead[r->touch[b]] = 0;
		r->unw[r->touch[b]] = 0;
	}
	r->n_touch = 0;
	memset(r->cst, 0, s->n_cl);
	memset(r->cmet, 0, (size_t)s->n_cl * 4u);
	memset(r->cimp, 0, (size_t)s->n_cl * 4u);
	for (i = 0; i < s->n_dx; i++)
		r->want[i] = x->dxc_first[i + 1u] - x->dxc_first[i];
	r->n_open = s->n_cl;
	r->swept = UINT64_MAX;
	/* what holds before any window: no blocks asked, more blocks asked than listed, k of zero, k above n */
	for (i = 0; i < s->n_dx; i++) {
		if (s->dx[i].need == 0)
			dx_decide(c, i, KGENOME_FNP_D_MET);
		else if (s->dx[i].need > s->dx[i].n)
			dx_decide(c, i, KGENOME_FNP_D_IMPOSSIBLE);
	}
	for (i = 0; i < s->n_cl; i++)
		if (r->cst[i] == KGENOME_FNP_D_UNDECIDED) {
			if (s->cl[i].k == 0)
				cl_set(c, i, KGENOME_FNP_D_MET);
			else if (s->cl[i].k > s->cl[i].n)
				cl_set(c, i, KGENOME_FNP_D_IMPOSSIBLE);
		}
	for (i = 0; i < s->n_dx; i++)
		if (r->want[i] == 0 && r->dst[i] == KGENOME_FNP_D_UNDECIDED) {
			r->dst[i] = KGENOME_FNP_D_RELEASED;
			unwant(c, i);
		}
	if (r->n_open == 0)
		c->stop = 1;
}

void kgenome_fnprint_dx_credit(struct kgenome_fnprint_wctx *c, uint32_t b, uint32_t cnt)
{
	struct kgenome_fnprint_dxrun *r = c->dxr;
	const struct kgenome_fnprint_dxdb *x = r->x;
	uint32_t i, n;

	if (cnt < x->need_min[b])
		return;
	n = c->db->blk[b].n;
	for (i = x->rv_first[b]; i < x->rv_first[b + 1u]; i++) {
		uint32_t d = x->rv_dx[i];
		const struct kgenome_fnprint_dx *q = &x->desc.dx[d];

		if (r->dst[d] != KGENOME_FNP_D_UNDECIDED || cnt != need_hashes(q->pct, n))
			continue;
		if (++r->met[d] >= q->need)
			dx_decide(c, d, KGENOME_FNP_D_MET);
	}
	if (r->n_open == 0)
		c->stop = 1;
}

void kgenome_fnprint_dx_remain(struct kgenome_fnprint_wctx *c, uint64_t rem)
{
	struct kgenome_fnprint_dxrun *r = c ? c->dxr : NULL;
	const struct kgenome_fnprint_dxdb *x;
	const struct kgenome_fnprint_dxdesc *s;
	uint32_t d;

	if (!r)
		return;
	c->rem = rem;
	if (r->n_open == 0)
		return;
	x = r->x;
	if (rem == 0) {                         /* nothing left: no block can gain, so what is not MET never will be */
		for (d = 0; d < x->desc.n_dx; d++)
			if (r->dst[d] == KGENOME_FNP_D_UNDECIDED)
				dx_decide(c, d, KGENOME_FNP_D_IMPOSSIBLE);
		if (r->n_open == 0)
			c->stop = 1;
		return;
	}
	if (rem > x->trigger || r->swept - rem < 8u)
		return;
	r->swept = rem;
	s = &x->desc;
	for (d = 0; d < s->n_dx; d++) {
		uint64_t alive = 0;
		uint32_t j;

		if (r->dst[d] != KGENOME_FNP_D_UNDECIDED)
			continue;
		for (j = 0; j < s->dx[d].n; j++) {
			uint32_t b = s->ref[s->dx[d].first + j], n = c->db->blk[b].n, cnt = kgenome_fnprint_wctx_count(c, b);
			uint32_t nh = need_hashes(s->dx[d].pct, n);
			uint64_t gain;

			if (cnt >= nh)
				continue;               /* counted in met[] */
			gain = n - cnt;
			if (rem * x->dup[b] < gain)
				gain = rem * x->dup[b];
			alive += (uint64_t)cnt + gain >= nh;
		}
		if (r->met[d] + alive < s->dx[d].need)
			dx_decide(c, d, KGENOME_FNP_D_IMPOSSIBLE);
	}
	if (r->n_open == 0)
		c->stop = 1;
}

enum kgenome_fnprint_dstate kgenome_fnprint_dx_state(const struct kgenome_fnprint_wctx *c, uint32_t dx)
{
	return c && c->dxr && dx < c->dxr->x->desc.n_dx ? (enum kgenome_fnprint_dstate)c->dxr->dst[dx] : KGENOME_FNP_D_UNDECIDED;
}

enum kgenome_fnprint_dstate kgenome_fnprint_dx_cluster(const struct kgenome_fnprint_wctx *c, uint32_t cl)
{
	return c && c->dxr && cl < c->dxr->x->desc.n_cl ? (enum kgenome_fnprint_dstate)c->dxr->cst[cl] : KGENOME_FNP_D_UNDECIDED;
}

uint32_t kgenome_fnprint_dx_open(const struct kgenome_fnprint_wctx *c)
{
	return c && c->dxr ? c->dxr->n_open : 0;
}

/* ---- the reference answer, from final counts ------------------------------------------- */

static int dx_full_one(const struct kgenome_fnprint_dxdb *x, const struct kgenome_fnprint_wctx *c, uint32_t d)
{
	const struct kgenome_fnprint_dxdesc *s = &x->desc;
	uint32_t j, met = 0;

	for (j = 0; j < s->dx[d].n; j++) {
		uint32_t b = s->ref[s->dx[d].first + j];

		met += kgenome_fnprint_wctx_count(c, b) >= need_hashes(s->dx[d].pct, c->db->blk[b].n);
	}
	return met >= s->dx[d].need;
}

int kgenome_fnprint_dx_full(const struct kgenome_fnprint_dxdb *x, const struct kgenome_fnprint_wctx *c, uint32_t cl)
{
	const struct kgenome_fnprint_cl *q;
	uint32_t m, held = 0;

	if (!x || !c || cl >= x->desc.n_cl)
		return 0;
	q = &x->desc.cl[cl];
	for (m = 0; m < q->n; m++)
		held += dx_full_one(x, c, x->desc.mem[q->first + m]) ? 1u : 0u;
	return held >= q->k;
}
