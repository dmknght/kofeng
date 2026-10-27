/*
 * diag/fnprint_bytes - the byte-level half of the function print (celllysis/fnprint.h): the library window table, the relocation mask,
 * the data statistics, the byte-level call-graph sketch, the runs of non-library windows and the sketch block of a unit. Every one takes
 * bytes and a ledger and answers with a status or a count, which is what a fuzz row needs. (The request-shaped half - the walk, the set,
 * the reference, the matcher, the window database and its context, the decision-complete passes - needs a function table and an image
 * and stays on the exempt list; fnprint has no caller on the scan path and its fate is the owner's, STATUS.md open item 4.)
 *
 * The input is [sel_bits][ledger selector][bytes]. Held:
 *   TABLE     a table made of the bytes holds EVERY sampled window of them (the vote over the same bytes has n_hit == n_sampled) unless the ledger
 *             refused (status not ok and n_refused counted: never silent); put(v) answers 1 exactly when v is sampled and held; has(v) is 0 for a
 *             value that is not sampled; vote counts nest (n_hit <= n_sampled <= n_win)
 *   MASK      the mask changes no length, the in-place and the out-of-place answers are the same bytes and the same count, and at most n / 4
 *             fields are masked (masking twice is NOT masking once, and the row counts it in the digest instead of asserting it)
 *   STAT      zero + ascii + hi <= n and the counts add over a split of the bytes
 *   SKETCH    starts ascending, edges ascending by origin, reached[] a 0/1 per start counted by n_reached, find(off) the stretch that holds off
 *             and UINT32_MAX outside, and the ledger back to zero after the free (no allocation outlives the sketch)
 *   RUNS      the callbacks are in order and inside the bytes, the count returned is the callbacks seen, a run holds at least min_win windows
 *   SKETCH-BLOCK  wsketch is ascending, distinct, at most k, and none of its values is in the library table
 */
#include "diag_seed.h"

#include <celllysis/fnprint.h>

static void seeds(struct fz_corpus *c)
{
	static struct ds_code code;
	uint8_t b[DS_CODE_MAX + 2u];
	unsigned i;

	for (i = 0; i < DS_NPROG; i++) {
		ds_prog(&code, i);
		b[0] = (uint8_t)(i % 5u);
		b[1] = (uint8_t)(i % 3u);
		memcpy(b + 2, code.b, code.n);
		/* a call-rich body: the call and lea shapes the sketch looks for */
		fz_corpus_add(c, "code", b, code.n + 2u);
	}
	{
		uint8_t t[600];
		unsigned k;

		t[0] = 0; t[1] = 0;
		for (k = 0; k < 598u; k++)
			t[2 + k] = (uint8_t)(k % 7u == 0 ? 0xe8 : (k * 13u + 5u));
		fz_corpus_add(c, "calls", t, sizeof t);
	}
}

struct runs_acc {
	struct fz_ctx *c;
	uint64_t       n, last_end, seen;
	uint32_t       min_win;
};

static int run_cb(void *u, uint64_t off, uint64_t len, uint32_t n_win)
{
	struct runs_acc *a = (struct runs_acc *)u;

	a->seen++;
	fz_step(&a->c->steps, 1);
	FZ_CHECK(a->c, off >= a->last_end || a->seen == 1u, "runs out of order");
	FZ_CHECK(a->c, off <= a->n && len <= a->n - off, "a run outside the bytes");
	FZ_CHECK(a->c, n_win >= a->min_win, "a run with fewer non-library windows than the floor");
	a->last_end = off;
	return 0;
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kgenome_ledger led;
	struct kgenome_fnprint_libtab t;
	struct kgenome_fnprint_libvote v;
	struct kgenome_fnprint_bstat st, sa, sb;
	struct kgenome_fnprint_bsketch g;
	uint8_t *m1, *m2;
	uint64_t f1, f2, i;
	uint32_t sel, out[16], k;
	const uint8_t *p;
	size_t pn;

	if (n < 3)
		return 1;
	sel = in[0] % 5u;
	p = in + 2;
	pn = n - 2u;
	kgenome_ledger_init(&led, in[1] % 3u == 0 ? 4096u + 64u * (uint64_t)pn : 0u);
	/* the table */
	memset(&t, 0, sizeof t);
	if (kgenome_fnprint_libtab_init(&t, sel, &led)) {
		kgenome_fnprint_libtab_add(&t, p, pn);
		FZ_CHECK(c, (unsigned)t.status <= (unsigned)KGENOME_NOMEM, "libtab status outside the enum");
		FZ_CHECK(c, t.n <= t.cap || !t.cap, "more values than slots");
		FZ_CHECK(c, t.n <= t.n_seen, "more values held than windows offered");
		memset(&v, 0, sizeof v);
		kgenome_fnprint_libvote(&t, p, pn, &v);
		FZ_CHECK(c, v.n_hit <= v.n_sampled && v.n_sampled <= v.n_win, "the vote counts do not nest");
		if (t.status == KGENOME_OK && !t.n_refused)
			FZ_CHECK(c, v.n_hit == v.n_sampled, "a table made of the bytes does not hold every sampled window of them");
		else
			FZ_CHECK(c, t.status != KGENOME_OK, "values were refused and the status says ok");
		for (k = 0; k < 24u; k++) {
			uint32_t val = (uint32_t)fz_below(c->rng, 1u << 20) * 2654435761u;
			int put = kgenome_fnprint_libtab_put(&t, val), has = kgenome_fnprint_libtab_has(&t, val), samp = kgenome_fnprint_libtab_sampled(&t, val);

			FZ_CHECK(c, !put || (samp && has), "put answered 1 for a value that is not sampled or not held");
			FZ_CHECK(c, samp || !has, "has answered 1 for a value the table does not sample");
		}
		/* wsketch: none of the values is in the table */
		{
			uint32_t got = kgenome_fnprint_wsketch(p, pn, &t, out, 16);

			FZ_CHECK(c, got <= 16u, "wsketch answered more than k");
			for (k = 0; k < got; k++) {
				FZ_CHECK(c, k == 0 || out[k - 1u] < out[k], "wsketch is not ascending and distinct");
				FZ_CHECK(c, !kgenome_fnprint_libtab_has(&t, out[k]), "wsketch holds a value of the library table");
			}
			fz_digest(c, got);
		}
		{
			struct runs_acc a;
			uint32_t dropped = 0, got, gap = (uint32_t)fz_below(c->rng, 8), min_win = 1u + (uint32_t)fz_below(c->rng, 6);

			a.c = c; a.n = pn; a.last_end = 0; a.seen = 0; a.min_win = min_win;
			got = kgenome_fnprint_runs(p, pn, &t, gap, min_win, run_cb, &a, &dropped);
			FZ_CHECK(c, got == a.seen, "kgenome_fnprint_runs returned a count other than the callbacks seen");
			fz_digest(c, got + ((uint64_t)dropped << 20));
		}
		fz_digest(c, t.n + ((uint64_t)v.n_hit << 24));
		kgenome_fnprint_libtab_free(&t);
		FZ_CHECK(c, led.used == 0, "the library table left bytes on the ledger after its free");
	}
	/* the relocation mask */
	m1 = (uint8_t *)malloc(pn ? pn : 1u);
	m2 = (uint8_t *)malloc(pn ? pn : 1u);
	if (m1 && m2) {
		uint64_t slack = fz_below(c->rng, 4) ? 0u : fz_below(c->rng, 4096);

		memcpy(m2, p, pn);
		f1 = kgenome_fnprint_relmask(p, pn, m1, slack);
		f2 = kgenome_fnprint_relmask(m2, pn, m2, slack);
		FZ_CHECK(c, f1 == f2 && !memcmp(m1, m2, pn), "the in-place mask and the out-of-place mask differ");
		FZ_CHECK(c, f1 <= pn / 4u + 1u, "more masked fields than four bytes each");
		for (i = 0; i < pn; i++)
			if (m1[i] != p[i])
				break;
		FZ_CHECK(c, f1 > 0 || i == pn, "bytes changed and no field was counted");
		{
			uint8_t *m3 = (uint8_t *)malloc(pn ? pn : 1u);

			if (m3) {
				uint64_t f3 = kgenome_fnprint_relmask(m1, pn, m3, slack);

				/* masking is NOT idempotent (measured: about one input in a thousand): a mask zeroes a field and a second look finds a field
				 * the first one skipped. fnprint.h does not promise it - every side of a comparison is masked once - so it is counted, not asserted. */
				fz_digest(c, memcmp(m1, m3, pn) != 0 ? 0x1d0u : 0u);
				(void)f3;
				free(m3);
			}
		}
		fz_digest(c, f1);
	}
	free(m1);
	free(m2);
	/* the statistics */
	kgenome_fnprint_bstat(p, (uint32_t)pn, &st);
	FZ_CHECK(c, st.n == pn && (uint64_t)st.zero + st.ascii + st.hi <= pn, "bstat counts do not fit the bytes");
	if (pn >= 2u) {
		uint32_t h = (uint32_t)(pn / 2u);

		kgenome_fnprint_bstat(p, h, &sa);
		kgenome_fnprint_bstat(p + h, (uint32_t)pn - h, &sb);
		FZ_CHECK(c, sa.zero + sb.zero == st.zero && sa.ascii + sb.ascii == st.ascii && sa.hi + sb.hi == st.hi, "bstat counts do not add over a split");
	}
	fz_digest(c, (uint64_t)kgenome_fnprint_bstat_is_data(&st));
	/* the sketch */
	memset(&g, 0, sizeof g);
	{
		uint64_t root = fz_below(c->rng, pn + 1u);

		kgenome_fnprint_bsketch_build(&g, p, 0, pn, (int64_t)0x400000, root + 0x400000u, &led);
		FZ_CHECK(c, (unsigned)g.status <= (unsigned)KGENOME_NOMEM, "bsketch status outside the enum");
		for (i = 1; i < g.n_start; i++)
			FZ_CHECK(c, g.start[i - 1u] < g.start[i], "bsketch starts are not strictly ascending");
		for (i = 1; i < g.n_edge; i++)
			FZ_CHECK(c, g.from[i - 1u] <= g.from[i], "bsketch edges are not ascending by origin");
		/* F14: when the allocation of the reached flags is refused the sketch keeps its starts and edges, status NOMEM, and `reached` NULL with
		 * n_start non-zero (fnprint_bsketch.c, the end of kgenome_fnprint_bsketch_build): a reader that trusts "reached[] per start" faults. The
		 * row reads the flags only of a sketch that has them. */
		if (g.reached) {
			uint32_t r = 0;

			for (i = 0; i < g.n_start; i++) {
				FZ_CHECK(c, g.reached[i] <= 1u, "a reached flag that is not 0 or 1");
				r += g.reached[i];
			}
			FZ_CHECK(c, g.n_start ? r == g.n_reached : g.n_reached == 0, "n_reached is not the number of reached stretches");
		}
		for (i = 0; g.reached && i < g.n_start && i < 64u; i++)
			FZ_CHECK(c, kgenome_fnprint_bsketch_find(&g, g.start[i]) == (uint32_t)i, "find did not answer the stretch that starts there");
		FZ_CHECK(c, g.reached || !g.n_start || g.status == KGENOME_NOMEM, "the sketch has starts, no reached flags and does not say NOMEM");
		FZ_CHECK(c, kgenome_fnprint_bsketch_find(&g, UINT64_MAX) == UINT32_MAX || g.n_start, "find answered a stretch for an offset past the text");
		fz_digest(c, g.n_start + ((uint64_t)g.n_edge << 20) + ((uint64_t)g.n_reached << 40));
		kgenome_fnprint_bsketch_free(&g);
		FZ_CHECK(c, led.used == 0, "the sketch left bytes on the ledger after its free");
		{
			uint64_t mn = kgenome_fnprint_bsketch_main(p, pn, fz_below(c->rng, pn + 1u), (int64_t)0, 0, pn);

			FZ_CHECK(c, mn == KGENOME_BROKEN || mn < pn + 0x100000000ull, "bsketch_main answered an address that is not BROKEN and not a place");
			fz_digest(c, mn == KGENOME_BROKEN);
		}
	}
	return 0;
}

FZ_ADAPTER(fnprint_bytes, .name = "kgenome/diag_fnprint_bytes",
	   .covers = "kgenome_fnprint_libtab_init kgenome_fnprint_libtab_free kgenome_fnprint_libtab_add kgenome_fnprint_libtab_put "
		     "kgenome_fnprint_libtab_sampled kgenome_fnprint_libtab_has kgenome_fnprint_libvote kgenome_fnprint_relmask "
		     "kgenome_fnprint_bstat kgenome_fnprint_bstat_is_data kgenome_fnprint_bsketch_build kgenome_fnprint_bsketch_free "
		     "kgenome_fnprint_bsketch_find kgenome_fnprint_bsketch_main kgenome_fnprint_runs kgenome_fnprint_wsketch",
	   .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000, .steps_base = 1000000u, .steps_per_byte = 64, .shape = FZ_REQ, .seeds = seeds, .run = run);
