/*
 * api_engine_ranges.c - <range.h>, <rangelist.h> and <runlist.h>: the three
 * tables every parser uses to say which bytes of an object are which.
 *
 * What a region table promises is a PARTITION: bytes are claimed once, a
 * claim past the end of the object is clipped (and says so), a table that is
 * full says it is full instead of dropping silently. These are asserted
 * differentially against a one-byte-per-cell model over small objects, with a
 * fixed-seed generator, so an off-by-one at an interval edge cannot hide the
 * way it can behind a handful of hand-picked cases.
 *
 * The 2^64 end is exercised by hand: an offset or a length that would wrap an
 * interval end must be clipped to nothing, not wrapped into a small range.
 */

#include "hostile_engine.h"

#include "../../libkofeng/kofcore/rangelist.h"
#include "../../libkofeng/kofcore/runlist.h"
#include <kofmod/kofsig.h>

#define MODEL 96u    /* the object size used by the differential cases */

/* ---- struct layout ------------------------------------------------------------ */

static void t_layout(void)
{
	struct kof_range r = { 3, 4 };
	struct kof_run u;

	CK(r.off == 3 && r.len == 4 && sizeof r == 16, "kof_range is two u64");
	memset(&u, 0, sizeof u);
	u.off = 1;
	u.len = 2;
	{
		struct kof_range head;

		memcpy(&head, &u, sizeof head);
		CK(sizeof u == 24 && head.off == 1 && head.len == 2,
		   "a kof_run begins with a kof_range and is 24 bytes");
	}
}

/* ---- rangelist: the model -------------------------------------------------------- */

static void model_mark(uint8_t *m, uint64_t off, uint64_t len)
{
	uint64_t i;

	for (i = off; i < off + len && i < MODEL; i++)
		m[i] = 1;
}

static void rl_to_model(const struct kof_rlist *l, uint8_t *m)
{
	uint32_t i;

	memset(m, 0, MODEL);
	for (i = 0; i < l->n; i++)
		model_mark(m, l->v[i].off, l->v[i].len);
}

static void t_rl_basic(void)
{
	struct kof_range buf[4];
	struct kof_rlist l;

	kof_rl_init(&l, buf, 4);
	CK(l.n == 0 && l.cap == 4 && !l.packed && !l.overflow && l.v == buf, "init");
	kof_rl_add(&l, 100, 10, 0);
	kof_rl_add(&l, 100, 100, 5);
	kof_rl_add(&l, 100, 200, 5);
	kof_rl_add(&l, 100, UINT64_MAX, 5);
	CK(l.n == 0 && !l.overflow, "empty, at-the-end and past-the-end adds record nothing");
	kof_rl_add(&l, 100, 95, 50);
	CK(l.n == 1 && l.v[0].off == 95 && l.v[0].len == 5, "a range running past the end is clipped");
	kof_rl_add(&l, 100, 10, UINT64_MAX);
	CK(l.n == 2 && l.v[1].len == 90, "a length of 2^64-1 is clipped to the object, not wrapped");
	kof_rl_add(&l, 100, 1, 1);
	kof_rl_add(&l, 100, 3, 1);
	CK(l.n == 4 && !l.overflow, "cap reached exactly: no overflow yet");
	kof_rl_add(&l, 100, 5, 1);
	CK(l.n == 4 && l.overflow, "one more sets overflow and keeps n at cap");
	CK(kof_rl_normalise(&l) == 3 && l.v[0].off == 1 && l.v[1].off == 3 &&
	   l.v[2].off == 10 && l.v[2].len == 90, "normalise sorts and merges overlaps");
	CK(l.packed == 0, "packed is cap-reached after merging: 3 < 4");

	/* A full list after merging says packed. */
	kof_rl_init(&l, buf, 2);
	kof_rl_add(&l, 100, 0, 1);
	kof_rl_add(&l, 100, 10, 1);
	CK(kof_rl_normalise(&l) == 2 && l.packed == 1, "w >= cap is packed");

	/* kof_rl_before is by offset only. */
	{
		struct kof_range a = { 1, 100 }, b = { 2, 1 };

		CK(kof_rl_before(&a, &b) && !kof_rl_before(&b, &a) && !kof_rl_before(&a, &a),
		   "rl_before is a strict order on off");
	}

	/* Adjacent ranges merge (off <= end), ranges with a one byte gap do not. */
	kof_rl_init(&l, buf, 4);
	kof_rl_add(&l, 100, 0, 5);
	kof_rl_add(&l, 100, 5, 5);
	kof_rl_add(&l, 100, 11, 5);
	CK(kof_rl_normalise(&l) == 2 && l.v[0].len == 10 && l.v[1].off == 11,
	   "touching merge, gap of one stays");

	/* Zero capacity: every add overflows, nothing is written. */
	kof_rl_init(&l, NULL, 0);
	kof_rl_add(&l, 100, 0, 5);
	CK(l.n == 0 && l.overflow, "cap 0 never dereferences the buffer");
}

static void t_rl_finish(void)
{
	struct kof_range buf[3];
	struct kof_rlist l;
	uint32_t n;

	kof_rl_init(&l, buf, 3);
	kof_rl_add(&l, 100, 40, 10);
	kof_rl_add(&l, 100, 10, 5);
	CK(kof_rl_finish(&l) == 2, "no overflow: the merged count");

	/*
	 * An overflowed list is padded to its capacity with empty ranges at the end
	 * of what it holds, so a consumer that trusts n == cap knows it is looking at
	 * a TRUNCATED list (rule 4: a cap must not look like a complete answer).
	 */
	kof_rl_init(&l, buf, 3);
	kof_rl_add(&l, 100, 10, 1);
	kof_rl_add(&l, 100, 20, 1);
	kof_rl_add(&l, 100, 30, 1);
	kof_rl_add(&l, 100, 40, 1);
	CK(l.overflow, "four ranges into three");
	n = kof_rl_finish(&l);
	CK(n == 3, "an overflowed list reports cap");
	kof_rl_init(&l, buf, 3);
	kof_rl_add(&l, 100, 10, 1);
	kof_rl_add(&l, 100, 20, 1);
	kof_rl_add(&l, 100, 30, 1);
	kof_rl_add(&l, 100, 40, 1);
	kof_rl_add(&l, 100, 50, 1);
	n = kof_rl_finish(&l);
	CK(n == 3 && l.v[2].len == 1, "full after merge, overflowed: stays cap");
	kof_rl_init(&l, buf, 3);
	kof_rl_add(&l, 100, 10, 1);
	kof_rl_add(&l, 100, 11, 1);
	kof_rl_add(&l, 100, 12, 1);
	kof_rl_add(&l, 100, 13, 1);
	n = kof_rl_finish(&l);
	CK(l.overflow && n == 3 && l.v[0].len == 3 && l.v[1].len == 0 && l.v[2].len == 0 &&
	   l.v[1].off == 13, "overflow pads with empty ranges at the end of the data");
}

static void t_rl_model(void)
{
	static struct kof_range a[64], b[64], c[64];
	struct kof_rlist la, lb, lc;
	uint8_t ma[MODEL], mb[MODEL], mc[MODEL];
	uint32_t round, i;

	he_seed(777);
	for (round = 0; round < 400; round++) {
		uint32_t k = 1u + he_below(10);
		uint8_t want[MODEL], got[MODEL], inv[MODEL];

		kof_rl_init(&la, a, 64);
		memset(want, 0, sizeof want);
		for (i = 0; i < k; i++) {
			uint64_t off = he_below(MODEL + 20), len = he_below(30);

			kof_rl_add(&la, MODEL, off, len);
			if (off < MODEL)
				model_mark(want, off, len > MODEL - off ? MODEL - off : len);
		}
		kof_rl_normalise(&la);
		rl_to_model(&la, got);
		CK(memcmp(want, got, MODEL) == 0, "normalise preserves the union (round %u)", round);
		for (i = 1; i < la.n; i++)
			CK(la.v[i].off > la.v[i - 1].off + la.v[i - 1].len,
			   "normalised ranges are sorted with gaps (round %u)", round);

		/* complement */
		kof_rl_init(&lb, b, 64);
		kof_rl_complement(&lb, &la, MODEL);
		rl_to_model(&lb, mb);
		for (i = 0; i < MODEL; i++)
			inv[i] = !want[i];
		CK(memcmp(inv, mb, MODEL) == 0, "complement is the cover of what is unclaimed (round %u)", round);

		/* subtract the complement-of-complement pieces: la - lb == la, la - la == empty */
		kof_rl_init(&lc, c, 64);
		for (i = 0; i < la.n; i++)
			kof_rl_add(&lc, MODEL, la.v[i].off, la.v[i].len);
		kof_rl_subtract(&lc, lb.v, lb.n);
		rl_to_model(&lc, mc);
		CK(memcmp(mc, want, MODEL) == 0, "subtracting the complement changes nothing (round %u)", round);
		kof_rl_subtract(&lc, la.v, la.n);
		rl_to_model(&lc, mc);
		memset(ma, 0, sizeof ma);
		CK(memcmp(mc, ma, MODEL) == 0 && lc.n == 0, "subtracting everything empties (round %u)", round);

		/* subtract a random cut and compare with the model */
		{
			struct kof_range cut = { he_below(MODEL), he_below(40) };

			kof_rl_init(&lc, c, 64);
			for (i = 0; i < la.n; i++)
				kof_rl_add(&lc, MODEL, la.v[i].off, la.v[i].len);
			kof_rl_subtract(&lc, &cut, 1);
			rl_to_model(&lc, mc);
			memcpy(ma, want, MODEL);
			for (i = 0; i < MODEL; i++)
				if (i >= cut.off && i < cut.off + cut.len)
					ma[i] = 0;
			CK(memcmp(mc, ma, MODEL) == 0 && !lc.overflow,
			   "subtract a cut (round %u)", round);
		}
	}
}

static void t_rl_subtract_edges(void)
{
	struct kof_range buf[2], cut;
	struct kof_rlist l;

	kof_rl_init(&l, buf, 2);
	kof_rl_add(&l, 100, 10, 80);
	cut.off = 40;
	cut.len = 10;
	kof_rl_subtract(&l, &cut, 1);
	CK(l.n == 2 && l.v[0].len == 30 && l.v[1].off == 50 && l.v[1].len == 40, "a hole splits in two");
	kof_rl_init(&l, buf, 1);
	kof_rl_add(&l, 100, 10, 80);
	kof_rl_subtract(&l, &cut, 1);
	CK(l.overflow && l.n == 1 && l.v[0].len == 30,
	   "a split with no room says overflow and keeps the lower half");
	kof_rl_init(&l, buf, 2);
	kof_rl_add(&l, 100, 10, 80);
	cut.off = 0;
	cut.len = 0;
	kof_rl_subtract(&l, &cut, 1);
	CK(l.n == 1 && l.v[0].len == 80, "a zero length cut is nothing");
	kof_rl_subtract(&l, NULL, 0);
	CK(l.n == 1, "no cuts");
}

static void t_claim_order(void)
{
	struct kof_claim a, b;

	memset(&a, 0, sizeof a);
	memset(&b, 0, sizeof b);
	a.off = 5; a.rank = 1;
	b.off = 5; b.rank = 2;
	CK(kof_claim_before(&a, &b) && !kof_claim_before(&b, &a) && !kof_claim_before(&a, &a), "claims order by offset, then by rank");
	b.off = 4;
	CK(kof_claim_before(&b, &a) && !kof_claim_before(&a, &b), "a lower offset wins whatever the rank");
}

static void t_claims(void)
{
	struct kof_claim c[5];
	uint8_t owner[MODEL];
	uint32_t round, i;

	memset(c, 0, sizeof c);
	c[0].off = 10; c[0].len = 20; c[0].rank = 1; c[0].tag = 100;
	c[1].off = 10; c[1].len = 5;  c[1].rank = 0; c[1].tag = 101;
	c[2].off = 90; c[2].len = 50; c[2].rank = 0; c[2].tag = 102;
	c[3].off = 200; c[3].len = 5; c[3].rank = 0; c[3].tag = 103;
	c[4].off = 20; c[4].len = UINT64_MAX; c[4].rank = 0; c[4].tag = 104;
	kof_rl_settle(c, 5, 100);
	/* sorted by off, then rank: 10/r0(101), 10/r1(100), 20(104), 90(102), 200(103) */
	CK(c[0].tag == 101 && c[0].got_off == 10 && c[0].got_len == 5, "lower rank wins a tie on offset");
	CK(c[1].tag == 100 && c[1].got_off == 15 && c[1].got_len == 15, "the loser keeps only what is left");
	CK(c[2].tag == 104 && c[2].got_off == 30 && c[2].got_len == 70,
	   "a claim of 2^64-1 bytes is clipped to the object, after the earlier claims");
	CK(c[3].tag == 102 && c[3].got_len == 0 && c[3].got_off == 0,
	   "a claim wholly inside an earlier grant gets nothing");
	CK(c[4].tag == 103 && c[4].got_len == 0 && c[4].got_off == 0, "a claim past the end gets nothing");

	he_seed(31337);
	for (round = 0; round < 300; round++) {
		struct kof_claim q[8];
		uint32_t n = 1u + he_below(8);
		uint32_t seen_end = 0;

		for (i = 0; i < n; i++) {
			q[i].off = he_below(MODEL + 10);
			q[i].len = he_below(40);
			q[i].rank = he_below(3);
			q[i].tag = i;
			q[i].got_off = q[i].got_len = 0xdead;
		}
		kof_rl_settle(q, n, MODEL);
		memset(owner, 0xff, sizeof owner);
		for (i = 0; i < n; i++) {
			uint64_t b;

			if (i)
				CK(q[i].off > q[i - 1].off || (q[i].off == q[i - 1].off && q[i].rank >= q[i - 1].rank),
				   "settled claims come back sorted");
			if (q[i].got_len == 0) {
				CK(q[i].got_off == 0, "an empty grant has offset 0");
				continue;
			}
			CK(q[i].got_off >= q[i].off && q[i].got_off + q[i].got_len <= q[i].off + q[i].len &&
			   q[i].got_off + q[i].got_len <= MODEL, "a grant lies inside the declared claim and the object");
			for (b = q[i].got_off; b < q[i].got_off + q[i].got_len; b++) {
				CK(owner[b] == 0xff, "no byte is granted twice (byte %u)", (unsigned)b);
				owner[b] = (uint8_t)i;
			}
			CK(q[i].got_off >= seen_end, "grants advance");
			seen_end = (uint32_t)(q[i].got_off + q[i].got_len);
		}
	}
	kof_rl_settle(NULL, 0, 100);
	CK(1, "settling nothing");
}

/* ---- runlist ------------------------------------------------------------------- */

static void t_runs_basic(void)
{
	struct kof_run buf[4];
	struct kof_runs l;
	uint64_t bytes[KOF_RUNS_MAX_CLS];

	kof_runs_init(&l, buf, 4, 3);
	CK(l.n == 0 && l.cap == 4 && l.ncls == 3 && !l.full && !l.clipped && !l.overlapped, "init");
	kof_runs_init(&l, buf, 4, 99);
	CK(l.ncls == KOF_RUNS_MAX_CLS, "ncls is capped at KOF_RUNS_MAX_CLS");
	kof_runs_init(&l, buf, 4, 3);

	kof_runs_add(&l, 100, 0, 10, 0);
	kof_runs_add(&l, 100, 10, 10, 0);
	CK(l.n == 1 && l.v[0].len == 20, "an adjacent run of the same class extends the last");
	kof_runs_add(&l, 100, 20, 10, 1);
	kof_runs_add(&l, 100, 30, 10, 0);
	CK(l.n == 3, "a different class in between breaks the extension");
	kof_runs_add(&l, 100, 40, 0, 0);
	CK(l.n == 3 && !l.clipped, "a zero length add is not a clip");
	kof_runs_add(&l, 100, 95, 10, 2);
	CK(l.n == 4 && l.v[3].len == 5 && l.clipped, "a run past the end is clipped and says so");
	kof_runs_add(&l, 100, 100, 5, 2);
	kof_runs_add(&l, 100, 1000, 5, 2);
	kof_runs_add(&l, 100, UINT64_MAX, UINT64_MAX, 2);
	CK(l.n == 4 && !l.full, "runs at or past the end record nothing");
	kof_runs_add(&l, 100, 60, 5, 1);
	CK(l.full && l.n == 4, "a fifth run into four sets full");

	kof_runs_settle(&l, bytes);
	CK(bytes[0] == 30 && bytes[1] == 10 && bytes[2] == 5, "settle totals per class");
	CK(!l.overlapped, "no overlap");

	/* Overlap: the earlier offset wins, the loser is trimmed, and it is said. */
	kof_runs_init(&l, buf, 4, 2);
	kof_runs_add(&l, 100, 10, 20, 0);
	kof_runs_add(&l, 100, 20, 20, 1);
	kof_runs_settle(&l, bytes);
	CK(l.overlapped && l.n == 2 && l.v[1].off == 30 && l.v[1].len == 10 &&
	   bytes[0] == 20 && bytes[1] == 10, "overlap trims the later run");
	kof_runs_init(&l, buf, 4, 2);
	kof_runs_add(&l, 100, 10, 20, 0);
	kof_runs_add(&l, 100, 12, 5, 1);
	kof_runs_settle(&l, bytes);
	CK(l.overlapped && l.n == 1 && bytes[1] == 0, "a run swallowed by an earlier one is dropped and said");

	{
		struct kof_run a = { 5, 1, 1, 0 }, b = { 5, 1, 0, 0 }, c = { 6, 1, 0, 0 };

		CK(kof_run_before(&b, &a) && !kof_run_before(&a, &b) && kof_run_before(&a, &c) &&
		   !kof_run_before(&a, &a), "run_before is by offset then class");
	}
}

/*
 * A class number the list was not made for. The init clamps ncls to
 * KOF_RUNS_MAX_CLS (the callers' per-class totals are that size), and a run of a
 * class past it is not recorded - and says so with `full`, the flag every parser
 * turns into its limit anomaly. It used to return with no flag at all.
 */
static void t_runs_class_overflow(void)
{
	struct kof_run buf[4];
	struct kof_runs l;

	kof_runs_init(&l, buf, 4, 16);
	kof_runs_add(&l, 100, 0, 10, 14);
	CK(l.n == 1 || l.full || l.clipped || l.overlapped,
	   "a run of class 14 asked for in a 16-class list is kept or flagged");
	CK(l.n == 0 && l.full, "it is flagged as not kept (full), and the table does not pretend");
	kof_runs_add(&l, 100, 10, 10, 11);
	CK(l.n == 1 && l.v[0].cls == 11, "the last class the list carries is kept");
	kof_runs_init(&l, buf, 4, 3);
	kof_runs_add(&l, 100, 0, 10, 3);
	CK(l.n == 0 && l.full, "a class past a small list's own count is flagged too");
	kof_runs_init(&l, buf, 4, 3);
	kof_runs_add(&l, 100, 0, 10, 2);
	CK(l.n == 1 && !l.full, "a class inside it is not");
}

static void runs_model(const struct kof_runs *l, uint8_t *m)
{
	uint32_t i;
	uint64_t b;

	memset(m, 0xff, MODEL);
	for (i = 0; i < l->n; i++)
		for (b = l->v[i].off; b < l->v[i].off + l->v[i].len && b < MODEL; b++)
			m[b] = (uint8_t)l->v[i].cls;
}

static void t_runs_model(void)
{
	static struct kof_run buf[64];
	struct kof_runs l;
	uint32_t round, i;
	uint64_t bytes[KOF_RUNS_MAX_CLS], tot;

	he_seed(4242);
	for (round = 0; round < 400; round++) {
		struct { uint64_t off, len; uint32_t cls; } in[10];
		uint32_t n = 1u + he_below(10);
		uint8_t want[MODEL], got[MODEL];
		uint8_t pos[MODEL];

		kof_runs_init(&l, buf, 64, 4);
		for (i = 0; i < n; i++) {
			in[i].off = he_below(MODEL + 8);
			in[i].len = he_below(25);
			in[i].cls = he_below(4);
			kof_runs_add(&l, MODEL, in[i].off, in[i].len, in[i].cls);
		}
		/* model: the runs as recorded (clipped), first in (off, cls) order owns a byte */
		{
			uint32_t nr = l.n, a, b2;
			struct kof_run tmp[64];

			memcpy(tmp, l.v, nr * sizeof tmp[0]);
			for (a = 0; a < nr; a++)
				for (b2 = a + 1; b2 < nr; b2++)
					if (kof_run_before(&tmp[b2], &tmp[a])) {
						struct kof_run t = tmp[a];

						tmp[a] = tmp[b2];
						tmp[b2] = t;
					}
			memset(want, 0xff, sizeof want);
			memset(pos, 0, sizeof pos);
			for (a = 0; a < nr; a++) {
				uint64_t x;

				for (x = tmp[a].off; x < tmp[a].off + tmp[a].len && x < MODEL; x++)
					if (!pos[x]) {
						pos[x] = 1;
						want[x] = (uint8_t)tmp[a].cls;
					}
			}
		}
		kof_runs_settle(&l, bytes);
		runs_model(&l, got);
		CK(memcmp(want, got, MODEL) == 0, "settle assigns each byte to the first run (round %u)", round);
		tot = 0;
		for (i = 0; i < 4; i++)
			tot += bytes[i];
		{
			uint64_t covered = 0, b;

			for (b = 0; b < MODEL; b++)
				covered += got[b] != 0xff;
			CK(tot == covered, "class totals add up to the covered bytes (round %u)", round);
		}
		for (i = 1; i < l.n; i++)
			CK(l.v[i].off >= l.v[i - 1].off + l.v[i - 1].len, "settled runs do not overlap (round %u)", round);
	}
}

static void t_runs_resolve(void)
{
	static const uint32_t cls_bit[3] = { 0x1, 0x2, 0x4 };
	struct kof_run v[3] = { { 10, 10, 0, 0 }, { 30, 10, 1, 0 }, { 40, 20, 0, 0 } };
	struct kof_range out[8];
	uint32_t n;

	n = kof_runs_resolve(v, 3, 0x1, cls_bit, 0, 100, out, 8);
	CK(n == 2 && out[0].off == 10 && out[1].off == 40 && out[1].len == 20, "class 0 runs");
	n = kof_runs_resolve(v, 3, 0x3, cls_bit, 0, 100, out, 8);
	CK(n == 2 && out[0].off == 10 && out[1].off == 30 && out[1].len == 30,
	   "two classes, adjacent runs merged");
	n = kof_runs_resolve(v, 3, 0x8, cls_bit, 0x8, 100, out, 8);
	CK(n == 3 && out[0].off == 0 && out[0].len == 10 && out[1].off == 20 && out[1].len == 10 &&
	   out[2].off == 60 && out[2].len == 40, "the unclaimed bit resolves to the gaps");
	n = kof_runs_resolve(v, 3, 0xf, cls_bit, 0x8, 100, out, 8);
	CK(n == 1 && out[0].off == 0 && out[0].len == 100, "everything is the whole object");
	n = kof_runs_resolve(v, 3, 0x8, cls_bit, 0, 100, out, 8);
	CK(n == 0, "an unclaimed bit the format does not define resolves to nothing");
	n = kof_runs_resolve(v, 3, 0xf, cls_bit, 0x8, 100, out, 2);
	CK(n == 2, "output smaller than the answer: reports cap, padded");
	n = kof_runs_resolve(v, 0, 0x8, cls_bit, 0x8, 100, out, 8);
	CK(n == 1 && out[0].len == 100, "no runs: the whole object is unclaimed");
	n = kof_runs_resolve(v, 0, 0x8, cls_bit, 0x8, 0, out, 8);
	CK(n == 0, "an empty object has no unclaimed bytes");
}

/* The macro a parser instantiates, with a view type of the test's own. */
struct tview {
	uint32_t valid;
	uint32_t n_runs;
	struct kof_run run[4];
};

static const uint32_t tview_cls_bit[2] = { 0x10, 0x20 };

KOF_RUNS_RESOLVER(tv, struct tview, tview_cls_bit, 0x40)

static void t_resolver_macro(void)
{
	struct kof_obj_ctx ctx;
	struct tview v;
	struct kof_range out[4];

	memset(&ctx, 0, sizeof ctx);
	memset(&v, 0, sizeof v);
	v.valid = 1;
	v.n_runs = 2;
	v.run[0].off = 4; v.run[0].len = 4; v.run[0].cls = 0;
	v.run[1].off = 12; v.run[1].len = 4; v.run[1].cls = 1;
	ctx.file_header = &v;
	ctx.obj_size = 32;
	CK(tv_resolve_scan(&ctx, 0x10, out, 4) == 1 && out[0].off == 4, "the resolver reads the view");
	CK(tv_resolve_scan(&ctx, 0x40, out, 4) == 3 && out[2].off == 16 && out[2].len == 16,
	   "and answers the unclaimed bit");
	CK(tv_resolve_scan(&ctx, 0x10, NULL, 4) == 0, "no output buffer");
	CK(tv_resolve_scan(&ctx, 0x10, out, 0) == 0, "no room");
	v.valid = 0;
	CK(tv_resolve_scan(&ctx, 0x10, out, 4) == 0, "an invalid view resolves to nothing");
	ctx.file_header = NULL;
	CK(tv_resolve_scan(&ctx, 0x10, out, 4) == 0, "a NULL view");
}

int main(void)
{
	t_layout();
	t_rl_basic();
	t_rl_finish();
	t_rl_model();
	t_rl_subtract_edges();
	t_claim_order();
	t_claims();
	t_runs_basic();
	t_runs_class_overflow();
	t_runs_model();
	t_runs_resolve();
	t_resolver_macro();
	printf("api_engine_ranges: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
