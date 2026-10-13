/*
 * fnprint_stream - the walk is streaming: each function is analysed, selected and
 * credited at once and forgotten, and the answer is EXACTLY the one a
 * collect-everything-then-match implementation gives; and what it holds does
 * not grow with the number of functions.
 *
 *   differential   hand-built objects of random shape (static with a frontier,
 *                  dynamic, gaps of random size and filler, a node list); every
 *                  pick mode; the credits of every block of a database cut from
 *                  the object itself, streaming against the reference that
 *                  collects the records, builds the unit list in the test (its own
 *                  run-merge), and credits after. Equal for every block, exactly.
 *   fingerprints   the streaming match of a reference against an object equals the
 *                  merge of two sorted signatures.
 *   memory         ledger peak of the streaming walk over 1k, 10k and 100k
 *                  functions is the same constant; the collecting variant's grows
 *                  with the count.
 */
#include "fnprint_db.h"
#include "known_miss.h"

struct unit { uint64_t off, len; uint32_t side; };

struct ulist { struct unit *v; uint32_t n, cap; };

static void upush(struct ulist *l, uint64_t off, uint64_t len, uint32_t side)
{
	if (l->n == l->cap) {
		l->cap = l->cap ? l->cap * 2u : 64u;
		l->v = realloc(l->v, (size_t)l->cap * sizeof *l->v);
	}
	l->v[l->n].off = off; l->v[l->n].len = len; l->v[l->n].side = side;
	l->n++;
}

/* The reference: the units a pick makes from COLLECTED records, written out again here. */
static void ref_units(const struct kgenome_fnprint_set *s, uint32_t pick, uint64_t lo, uint64_t hi, struct ulist *out)
{
	uint32_t i, open = 0, side = 0;
	uint64_t rlo = 0, rhi = 0, prev_end = 0, gap = 32;
	int have = 0, sided = (pick & KGENOME_FNP_PICK_SIDED) != 0;

#define PIECE(L, H, SD) do { \
		uint64_t l_ = (L), h_ = (H); uint32_t sd_ = (SD); \
		if (h_ > l_) { \
			if (open && side == sd_ && l_ <= rhi + gap && l_ + gap >= rlo) { \
				if (l_ < rlo) \
					rlo = l_; \
				if (h_ > rhi) \
					rhi = h_; \
			} else { \
				if (open) upush(out, rlo, rhi - rlo, side); \
				open = 1; rlo = l_; rhi = h_; side = sd_; \
			} \
		} \
	} while (0)
	for (i = 0; i < s->n; i++) {
		const struct kgenome_fnprint_fn *f = &s->fn[i];
		int bad = (f->reason & KGENOME_FNP_R_BAD) != 0, take;

		if (sided && !bad && f->off >= prev_end) {
			uint64_t from = have ? prev_end : lo;

			if (from < lo)
				from = lo;
			PIECE(from, f->off, KGENOME_MUTATION_SIDE_USER);
		}
		if (bad)
			take = 0;
		else if (sided)
			take = 1;
		else if (pick & KGENOME_FNP_PICK_DIAG)
			take = (f->reason & KGENOME_FNP_R_DIAG) && f->cls != KGENOME_FNP_LIB;
		else
			take = (f->cls == KGENOME_FNP_AUTHOR && (pick & KGENOME_FNP_PICK_AUTHOR)) ||
			       (f->cls == KGENOME_FNP_UNKNOWN && (pick & KGENOME_FNP_PICK_UNKNOWN));
		if (take)
			PIECE(f->off, f->off + f->len, sided && f->cls == KGENOME_FNP_LIB ? KGENOME_MUTATION_SIDE_LIB
											  : KGENOME_MUTATION_SIDE_USER);
		if (!bad) {
			if (!have || f->off + f->len > prev_end)
				prev_end = f->off + f->len;
			have = 1;
		}
	}
	if (sided) {
		uint64_t from = have ? prev_end : lo;

		if (from < lo)
			from = lo;
		PIECE(from, hi, KGENOME_MUTATION_SIDE_USER);
	}
	if (open)
		upush(out, rlo, rhi - rlo, side);
#undef PIECE
}

static uint32_t rnd(struct hk_rng *r, uint32_t lo, uint32_t hi)
{
	return lo + hk_below(r, hi - lo + 1u);
}

/* A random static or dynamic object, and the entry offset (KGENOME_BROKEN when dynamic). */
static uint64_t random_obj(struct fk_obj *o, struct hk_rng *r, enum kgenome_fnprint_link *link)
{
	uint64_t e = KGENOME_BROKEN, m = 0;
	uint32_t na = rnd(r, 3, 14), nl = rnd(r, 6, 40), nw = rnd(r, 0, 5), i, gapmax = rnd(r, 0, 90);
	int stat = (int)hk_below(r, 3) != 0;
	uint32_t seed = (uint32_t)hk_next(r) & 0xffffu;
	static const struct fk_var V = { 0x111, 0x222, 0x33445566u };
	static const uint8_t fillers[3] = { 0x00, 0xcc, 0x90 };

	fk_init(o);
	*link = stat ? KGENOME_FNP_LINK_STATIC : KGENOME_FNP_LINK_DYNAMIC;
	if (stat)
		e = fk_entry(o, 0);
	for (i = 0; i < na; i++) {
		uint64_t at = fk_func(o, seed + i, rnd(r, 12, 60), &V);

		if (!i)
			m = at;
		fk_fill(o, fillers[hk_below(r, 3)], hk_below(r, gapmax + 1u));
	}
	for (i = 0; i < nw; i++) {
		fk_wrapper(o, 1 + i);
		fk_fill(o, 0xcc, hk_below(r, 8));
	}
	for (i = 0; i < nl; i++) {
		fk_func(o, seed + 5000 + i, rnd(r, 10, 50), &V);
		fk_fill(o, fillers[hk_below(r, 3)], hk_below(r, gapmax + 1u));
	}
	if (stat) {
		int32_t d = (int32_t)((int64_t)m - (int64_t)(e + 7));

		memcpy(o->b + e + 3, &d, 4);
	}
	return e;
}

static int cmp64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

static void t_differential(void)
{
	struct hk_rng r = { 0x5eed1234abcdull };
	uint32_t it, mode;
	static const uint32_t picks[5] = { KGENOME_FNP_PICK_AUTHOR, KGENOME_FNP_PICK_AUTHOR | KGENOME_FNP_PICK_UNKNOWN,
					   KGENOME_FNP_PICK_SIDED, KGENOME_FNP_PICK_DIAG, KGENOME_FNP_PICK_SIDED | KGENOME_FNP_PICK_DIAG };
	uint32_t compared = 0, nonzero = 0;

	for (it = 0; it < 60; it++) {
		struct fk_obj o;
		enum kgenome_fnprint_link link;
		uint64_t e = random_obj(&o, &r, &link), nodes[24];
		uint32_t nn = 0, k;
		struct fd_db d;

		memset(&d, 0, sizeof d);
		for (k = 0; k < 8; k++) {
			const struct kgenome_func *f = &o.v[hk_below(&r, o.nf)];

			fd_block(&d, o.b, f->off, f->len, hk_below(&r, 4) == 0 ? KGENOME_MUTATION_SIDE_LIB : KGENOME_MUTATION_SIDE_USER);
		}
		fd_build(&d);
		if (!d.set) {
			fk_free(&o);
			continue;
		}
		for (k = 0; k < 24; k++)
			if (hk_below(&r, 3) == 0)
				nodes[nn++] = o.v[hk_below(&r, o.nf)].off + hk_below(&r, 4);
		qsort(nodes, nn, sizeof nodes[0], cmp64);
		for (mode = 0; mode < 5; mode++) {
			struct kof_mutation_ctx cs, cr;
			struct kgenome_fnprint_stat st, st2;
			struct kgenome_fnprint_req rq;
			struct kgenome_func_set fs;
			struct kgenome_fnprint_set s;
			struct ulist ul = { 0 };
			struct fd_feed f2;
			uint32_t b;

			kof_mutation_ctx_init(&cs, d.set); kof_mutation_ctx_init(&cr, d.set);
			kof_mutation_begin(&cs); kof_mutation_begin(&cr);
			/* streaming: credited the moment each unit is complete */
			fd_credit(&o, link, e, picks[mode], nodes, nn, &cs, NULL, &st);
			/* reference: collect the records (same walk, no units), build the list, credit afterwards */
			fk_req(&rq, &o, link, &st2, &fs);
			rq.entry_off = e; rq.hint.node_at = nodes; rq.hint.n_node = nn;
			kgenome_fnprint_collect(&rq, &s);
			ref_units(&s, picks[mode], 0, o.n, &ul);
			f2.c = &cr; f2.c2 = NULL; f2.p = o.b; f2.n_units = 0; f2.bytes = 0;
			for (k = 0; k < ul.n; k++)
				fd_unit(&f2, ul.v[k].off, ul.v[k].len, ul.v[k].side, NULL);
			CK(f2.n_units == st.n_units);
			CK(f2.bytes == st.unit_bytes);
			for (b = 0; b < d.n_blk; b++) {
				CK(kof_mutation_pct(&cs, b) == kof_mutation_pct(&cr, b));
				CK(kof_mutation_matched(&cs, b) == kof_mutation_matched(&cr, b));
				compared++;
				nonzero += kof_mutation_pct(&cs, b) > 0;
			}
			free(ul.v);
			kgenome_fnprint_set_free(&s, NULL);
			kof_mutation_ctx_done(&cs); kof_mutation_ctx_done(&cr);
		}
		fd_free(&d);
		fk_free(&o);
	}
	CK(compared > 1500 && nonzero > 300);       /* the comparison had something to compare */
}

/* Streaming match of a reference equals the merge of two collected signatures. */
static void t_match_differential(void)
{
	struct hk_rng r = { 0xfeed5eedull };
	uint32_t it;
	uint32_t agree = 0, some = 0;

	for (it = 0; it < 30; it++) {
		struct fk_obj a, b;
		enum kgenome_fnprint_link la, lb;
		uint64_t ea = random_obj(&a, &r, &la), eb;
		struct kgenome_fnprint_req ra, rb;
		struct kgenome_fnprint_stat sa, sb;
		struct kgenome_func_set fa, fb;
		struct kgenome_fnprint_set s, t;
		struct kgenome_fnprint_ref ra_ref, rb_ref;
		struct kgenome_fnprint_match m;
		uint64_t w = 0;
		uint32_t i = 0, j = 0;

		/* b: a's functions with half of them replaced by others, so the two overlap partly */
		eb = random_obj(&b, &r, &lb);
		if (hk_below(&r, 2)) {
			fk_free(&b);
			fk_init(&b);
			for (i = 0; i < a.nf; i += 2)
				fk_func(&b, 7000 + i, 20, &(struct fk_var){ 1, 2, 3 });
			for (i = 1; i < a.nf; i += 2)
				fk_raw(&b, a.b + a.v[i].off, a.v[i].len), fk_mark(&b, b.n - a.v[i].len, a.v[i].len);
			eb = KGENOME_BROKEN;
			lb = KGENOME_FNP_LINK_DYNAMIC;
			la = KGENOME_FNP_LINK_DYNAMIC;
			ea = KGENOME_BROKEN;
		}
		fk_req(&ra, &a, la, &sa, &fa); ra.entry_off = ea;
		fk_req(&rb, &b, lb, &sb, &fb); rb.entry_off = eb;
		kgenome_fnprint_collect(&ra, &s);
		kgenome_fnprint_collect(&rb, &t);
		kgenome_fnprint_ref_build(&s, &ra_ref);
		kgenome_fnprint_ref_build(&t, &rb_ref);
		/* the reference arrangement: two sorted signatures merged */
		i = j = 0;
		while (i < ra_ref.n && j < rb_ref.n) {
			if (ra_ref.e[i].fp == rb_ref.e[j].fp) { w += ra_ref.e[i].weight; i++; j++; }
			else if (ra_ref.e[i].fp < rb_ref.e[j].fp) i++;
			else j++;
		}
		/* the streaming arrangement: b's functions looked up one at a time in a's table */
		memset(&m, 0, sizeof m);
		kgenome_fnprint_match_init(&m, &ra_ref, NULL);
		rb.visit = kgenome_fnprint_match_visit; rb.user = &m;
		kgenome_fnprint_walk(&rb);
		CK(m.strong_w == w);
		agree += m.strong_w == w;
		some += w > 0;
		kgenome_fnprint_match_done(&m);
		kgenome_fnprint_ref_free(&ra_ref); kgenome_fnprint_ref_free(&rb_ref);
		kgenome_fnprint_set_free(&s, NULL); kgenome_fnprint_set_free(&t, NULL);
		fk_free(&a); fk_free(&b);
	}
	CK(agree == 30 && some >= 10);
}

static void many(struct fk_obj *o, uint32_t n)
{
	static const struct fk_var V = { 5, 6, 7 };
	uint32_t i;

	fk_init(o);
	for (i = 0; i < n; i++) {
		fk_func(o, 20 + (i % 97), 14, &V);                 /* 97 distinct bodies, repeated */
		fk_fill(o, i % 3 ? 0xcc : 0x90, 1 + i % 4);
	}
}

static void t_memory_does_not_grow(void)
{
	static const uint32_t sizes[3] = { 1000, 10000, 100000 };
	uint64_t stream_peak[3], collect_peak[3];
	uint32_t i;

	for (i = 0; i < 3; i++) {
		struct fk_obj o;
		struct kgenome_fnprint_req rq;
		struct kgenome_fnprint_stat st;
		struct kgenome_func_set fs;
		struct kgenome_ledger led;
		struct kgenome_fnprint_set s;
		struct fd_feed f;

		many(&o, sizes[i]);
		/* streaming, units on, credit at once into a counter that is the caller's (a database of one block) */
		{
			struct fd_db d;
			struct kof_mutation_ctx c;

			memset(&d, 0, sizeof d);
			fd_block(&d, o.b, o.v[0].off, o.v[0].len, KGENOME_MUTATION_SIDE_USER);
			fd_build(&d);
			kof_mutation_ctx_init(&c, d.set);
			kof_mutation_begin(&c);
			fk_req(&rq, &o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
			kgenome_ledger_init(&led, 0);
			rq.led = &led;
			f.c = &c; f.c2 = NULL; f.p = o.b; f.n_units = 0; f.bytes = 0;
			rq.units.fn = fd_unit; rq.units.user = &f; rq.units.pick = KGENOME_FNP_PICK_SIDED;
			rq.units.hi = o.n; rq.units.gap = 1;                 /* small gap: many units */
			kgenome_fnprint_walk(&rq);
			CK(st.status == KGENOME_OK && st.n_visited == sizes[i]);
			CK(kof_mutation_pct(&c, 0) == 100);
			stream_peak[i] = led.peak;
			CK(led.used == 0);                                   /* all given back */
			kof_mutation_ctx_done(&c);
			fd_free(&d);
		}
		/* collecting */
		fk_req(&rq, &o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
		kgenome_ledger_init(&led, 0);
		rq.led = &led;
		kgenome_fnprint_collect(&rq, &s);
		collect_peak[i] = led.peak;
		CK(s.n == sizes[i]);
		kgenome_fnprint_set_free(&s, &led);
		CK(led.used == 0);
		fk_free(&o);
	}
	CK(stream_peak[0] == stream_peak[1] && stream_peak[1] == stream_peak[2]);
	CK(stream_peak[0] > 0 && stream_peak[0] < 4096);
	CK(collect_peak[2] > 50 * collect_peak[0]);               /* 100x the functions, at least 50x the memory */
	CK(collect_peak[2] > 1000 * stream_peak[2]);
}

int main(void)
{
	t_differential();
	t_match_differential();
	t_memory_does_not_grow();
	printf("fnprint_stream: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
