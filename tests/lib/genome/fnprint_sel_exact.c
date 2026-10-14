/*
 * fnprint_sel_exact - the selection policies that claim to be EXACT (FLAT, DUP, ORDER) change nothing:
 * the count of EVERY block is the full computation's (which is stronger than "the decision is the same"),
 * on random objects and databases, over many seeds. The policies that are not exact (TINY, SAMPLE) are
 * held to what they do claim: never more credit than the full computation, and the credit lost is
 * bounded by the windows they say they left unread.
 *
 * The objects are built to hurt: junk functions, padding functions (flat, and padding with a few real
 * windows in it), one function repeated hundreds of times, empty and shorter-than-a-window extents,
 * a block whose windows are spread over two functions so that its credit is a UNION (a duplicate of
 * either must not matter), and credit at 22 and 23 of 32 hashes either side of the 70% line.
 */
#include "fnprint_sel_kit.h"
#include "../../unit/known_miss.h"

static void make_object(struct sk_obj *o, const struct sk_db *db, struct hk_rng *g, uint32_t flavour)
{
	uint32_t f, copies, i, nj;

	memset(o, 0, sizeof *o);
	for (f = 0; f < SK_NF; f++) {
		uint32_t pick = hk_below(g, 100u);

		if (pick >= 40u)
			continue;
		copies = pick < 4u ? 20u + hk_below(g, 200u) : pick < 10u ? 2u + hk_below(g, 3u) : 1u;
		for (i = 0; i < copies; i++)
			sk_add(o, db->body[f], db->len[f]);
		if (hk_below(g, 5u) == 0) {                                  /* padding between functions */
			sk_add_fill(o, 0x90, 1u + hk_below(g, 40u));
			sk_add_fill(o, 0x00, 1u + hk_below(g, 40u));
		}
	}
	nj = flavour ? 40u : 10u;
	for (i = 0; i < nj; i++) {
		switch (hk_below(g, 6u)) {
		case 0: sk_add_fill(o, 0xcc, hk_below(g, 300u)); break;       /* flat, any length incl. empty / < 8 */
		case 1: sk_add(o, db->body[0], 0); break;                      /* an empty extent */
		case 2: sk_add_random(o, g, hk_below(g, 200u)); break;
		case 3: {                                                      /* padding with a few real windows in it */
			uint8_t buf[300];
			uint32_t j;

			memset(buf, 0x90, sizeof buf);
			for (j = 0; j < 12u; j++)
				buf[100u + j] = (uint8_t)hk_next(g);
			sk_add(o, buf, sizeof buf);
			break;
		}
		case 4: sk_add_random(o, g, 40u + hk_below(g, 900u)); break;
		default: sk_add(o, o->p + (o->n_fn ? o->fn[hk_below(g, o->n_fn)].off : 0), o->n_fn ? o->fn[hk_below(g, o->n_fn)].len & 0x3f : 0); break;
		}
	}
}

static uint32_t differs(const uint32_t *a, const uint32_t *b, uint32_t n)
{
	uint32_t i, d = 0;

	for (i = 0; i < n; i++)
		d += a[i] != b[i];
	return d;
}

static void t_exact_random(void)
{
	uint64_t seed;
	uint32_t bad = 0, removed = 0, objs = 0, win_full = 0, win_sel = 0;

	for (seed = 1; seed <= 25u * hk_scale(); seed++) {
		struct sk_db *db = malloc(sizeof *db);
		struct kgenome_fnprint_wctx c;
		struct hk_rng g = { seed * 13u + 1u };
		uint32_t round;

		CK(sk_db_make(db, seed, NULL));
		CK(kgenome_fnprint_wctx_init(&c, &db->d, NULL));
		for (round = 0; round < 4u; round++) {
			struct sk_obj o;
			struct kof_range *out;
			uint32_t full[SK_NF], sel[SK_NF], pol;
			static const uint32_t pols[] = { KGENOME_FNP_SEL_FLAT, KGENOME_FNP_SEL_DUP, KGENOME_FNP_SEL_ORDER,
				KGENOME_FNP_SEL_FLAT | KGENOME_FNP_SEL_DUP | KGENOME_FNP_SEL_ORDER };
			struct kgenome_fnprint_wpass_stat st0, st1;
			struct kgenome_fnprint_sel_stat ss;

			make_object(&o, db, &g, round & 1u);
			out = malloc((o.n_fn + 1u) * sizeof *out);
			sk_roll(db, &c, &o, o.fn, o.n_fn, full, &st0);
			for (pol = 0; pol < sizeof pols / sizeof *pols; pol++) {
				sk_plan(db, &o, pols[pol], 8, 0, out, NULL, NULL, &ss);
				bad += ss.status != KGENOME_OK;
				/* every extent is either returned, removed by a named policy, or counted bad */
				bad += ss.n_in != ss.n_out + ss.n_flat + ss.n_dup + ss.n_tiny + ss.n_sample + ss.n_lib + ss.n_bad;
				sk_roll(db, &c, &o, out, ss.n_out, sel, &st1);
				bad += differs(full, sel, db->n_blk);
				removed += ss.n_in - ss.n_out;
				win_full += (uint32_t)st0.n_win_rolled; win_sel += (uint32_t)st1.n_win_rolled;
				objs++;
			}
			free(out);
			sk_obj_free(&o);
		}
		kgenome_fnprint_wctx_done(&c);
		sk_db_free(db);
		free(db);
	}
	CK(bad == 0);
	CK(removed > 0 && win_sel < win_full);                       /* they do remove something: the test is not vacuous */
	printf("  SEL-EXACT runs=%u removed_extents=%u windows %u -> %u\n", objs, removed, win_full, win_sel);
}

/* FLAT removes a function of one repeated byte and one shorter than a window, and nothing else. */
static void t_flat_exactness(void)
{
	struct sk_obj o;
	struct kof_range out[8];
	struct kgenome_fnprint_sel_stat ss;
	uint8_t pad[200], mixed[200];
	struct hk_rng g = { 5 };
	uint32_t j;

	memset(&o, 0, sizeof o);
	memset(pad, 0x90, sizeof pad);
	memcpy(mixed, pad, sizeof mixed);
	for (j = 0; j < 8; j++)
		mixed[100u + j] = (uint8_t)(0x11u * (j + 1u));              /* eight different bytes inside padding */
	sk_add(&o, pad, 200);                                           /* flat */
	sk_add(&o, pad, 7);                                             /* shorter than a window */
	sk_add(&o, pad, 0);                                             /* empty */
	sk_add(&o, mixed, 200);                                         /* NOT flat: windows around the eight bytes */
	sk_add_random(&o, &g, 100);
	pad[199] = 0x91;
	sk_add(&o, pad, 200);                                           /* one byte differs at the very end: the last window is not flat */
	sk_plan(NULL, &o, KGENOME_FNP_SEL_FLAT, 8, 0, out, NULL, NULL, &ss);
	CK(ss.status == KGENOME_OK && ss.n_flat == 3u && ss.n_out == 3u);
	CK(out[0].off == o.fn[3].off && out[1].off == o.fn[4].off && out[2].off == o.fn[5].off);
	sk_obj_free(&o);
}

/* DUP verifies bytes: equal length, one byte apart, both kept; true copies removed, first kept. */
static void t_dup_verified(void)
{
	struct sk_obj o;
	struct kof_range out[600];
	uint32_t idx[600], i;
	struct kgenome_fnprint_sel_stat ss;
	uint8_t a[300], b[300];
	struct hk_rng g = { 9 };

	memset(&o, 0, sizeof o);
	for (i = 0; i < 300; i++)
		a[i] = (uint8_t)hk_next(&g);
	memcpy(b, a, 300);
	b[299] ^= 1u;
	sk_add(&o, a, 300);
	sk_add(&o, b, 300);                                             /* differs in the last byte */
	for (i = 0; i < 500; i++)
		sk_add(&o, a, 300);                                     /* five hundred copies */
	sk_add(&o, b, 300);
	sk_plan(NULL, &o, KGENOME_FNP_SEL_DUP, 8, 0, out, idx, NULL, &ss);
	CK(ss.n_out == 2u && ss.n_dup == 501u && idx[0] == 0 && idx[1] == 1);
	CK(ss.bytes_hashed == 503u * 48u && ss.n_dup_cap == 0);
	sk_obj_free(&o);
}

/* ORDER puts the function that holds a rare key first, and never drops one. */
static void t_order(void)
{
	struct sk_db *db = malloc(sizeof *db);
	struct sk_obj o;
	struct kof_range out[16];
	uint32_t idx[16], i;
	struct kgenome_fnprint_sel_stat ss;
	struct hk_rng g = { 3 };

	CK(sk_db_make(db, 77, NULL));
	memset(&o, 0, sizeof o);
	for (i = 0; i < 5; i++)
		sk_add_random(&o, &g, 400);
	sk_add(&o, db->body[3], db->len[3]);                            /* a block's own function, last */
	sk_plan(db, &o, KGENOME_FNP_SEL_ORDER, 64, 0, out, idx, NULL, &ss);
	CK(ss.n_out == 6u && idx[0] == 5u);
	for (i = 1; i < 6; i++)
		CK(idx[i] == i - 1u);                                   /* the rest in address order */
	sk_obj_free(&o);
	sk_db_free(db);
	free(db);
}

/* Not exact: TINY and SAMPLE never add credit, and what they lose is bounded by the windows they say they skipped. */
static void t_inexact_bounds(void)
{
	uint64_t seed;
	uint32_t bad = 0, lost_total = 0, runs = 0;

	for (seed = 1; seed <= 20u * hk_scale(); seed++) {
		struct sk_db *db = malloc(sizeof *db);
		struct kgenome_fnprint_wctx c;
		struct hk_rng g = { seed * 31u };
		struct sk_obj o;
		struct kof_range *out = NULL;
		uint32_t full[SK_NF], sel[SK_NF], b, pol;
		struct kgenome_fnprint_wpass_stat st;
		struct kgenome_fnprint_sel_stat ss;

		CK(sk_db_make(db, seed + 500u, NULL));
		CK(kgenome_fnprint_wctx_init(&c, &db->d, NULL));
		make_object(&o, db, &g, 1);
		out = malloc((o.n_fn + 1u) * sizeof *out);
		sk_roll(db, &c, &o, o.fn, o.n_fn, full, &st);
		for (pol = 0; pol < 4u; pol++) {
			uint32_t pols = pol < 2u ? KGENOME_FNP_SEL_TINY : KGENOME_FNP_SEL_SAMPLE, skipped;

			sk_plan(db, &o, pols, pol == 2u ? 4u : 16u, pol == 0u ? 64u : 256u, out, NULL, NULL, &ss);
			sk_roll(db, &c, &o, out, ss.n_out, sel, &st);
			skipped = (uint32_t)(ss.win_in - ss.win_out);
			for (b = 0; b < db->n_blk; b++) {
				bad += sel[b] > full[b];                           /* never more */
				bad += full[b] - (sel[b] < full[b] ? sel[b] : full[b]) > skipped;   /* the loss is within the windows left unread */
				lost_total += full[b] - (sel[b] < full[b] ? sel[b] : full[b]);
			}
			runs++;
		}
		free(out);
		sk_obj_free(&o);
		kgenome_fnprint_wctx_done(&c);
		sk_db_free(db);
		free(db);
	}
	CK(bad == 0);
	printf("  SEL-INEXACT runs=%u credit_slots_lost=%u\n", runs, lost_total);
}

/*
 * The limit of a sample, which no tuning removes: a function that holds a whole block between two
 * probes loses it. FLAT/DUP/ORDER do not have this (above).
 */
static void t_sample_limit(void)
{
	struct sk_db *db = malloc(sizeof *db);
	struct kof_range out[4];
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_stat st;
	struct kgenome_fnprint_sel_stat ss;
	uint32_t full[SK_NF], sel[SK_NF];
	struct hk_rng g = { 11 };
	uint8_t *fn;
	uint32_t len, i, j, b = 0, lost = 0, tried = 0;

	CK(sk_db_make(db, 123, NULL));
	CK(kgenome_fnprint_wctx_init(&c, &db->d, NULL));
	/* a long function of random bytes with one block's body in the middle, probes at k = 2 (the two ends) */
	len = 20000;
	fn = malloc(len);
	for (i = 0; i < len; i++)
		fn[i] = (uint8_t)hk_next(&g);
	for (b = 0; b < db->n_blk && tried < 8u; b++) {
		struct sk_obj o;

		memcpy(fn + 9000, db->body[b], db->len[b]);
		memset(&o, 0, sizeof o);
		sk_add(&o, fn, len);
		sk_roll(db, &c, &o, o.fn, o.n_fn, full, &st);
		sk_plan(db, &o, KGENOME_FNP_SEL_SAMPLE, 2, 0, out, NULL, NULL, &ss);
		sk_roll(db, &c, &o, out, ss.n_out, sel, &st);
		for (j = 0; j < db->n_blk; j++)
			lost += sel[j] < full[j];
		tried++;
		sk_obj_free(&o);
	}
	free(fn);
	KM_CHECK(lost == 0, "a sampled prefilter keeps a function that holds a block between its probes",
		 "SAMPLE_MISSES_UNSAMPLED_WINDOWS");
	kgenome_fnprint_wctx_done(&c);
	sk_db_free(db);
	free(db);
}

int main(void)
{
	t_exact_random();
	t_flat_exactness();
	t_dup_verified();
	t_order();
	t_inexact_bounds();
	t_sample_limit();
	printf("fnprint_sel_exact: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
