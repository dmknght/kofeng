/*
 * cov_fnprint_api - the five functions of fnprint.h that nothing else in the suite calls:
 *
 *   kgenome_fnprint_relmask      the relocation mask: which bytes of an instruction stream are zeroed
 *   kgenome_fnprint_libtab_put   one window value into the known-library table, and what a full ledger does
 *   kgenome_fnprint_runs         the runs of bytes whose windows are not library, with gap and floor
 *   kgenome_fnprint_sorted       "ascending by offset", O(1) memory
 *   kgenome_fnprint_match_any_pm the containment with weak hits at half
 *
 * Each is asserted on bytes and numbers that are written out here: a call whose target is inside the
 * object is masked and one that is not stays, a negative displacement needs the slack, a field is
 * consumed so the next opcode starts after it; the table keeps what it holds and says when it could
 * not (rule 4: a limit that fires is reported, never silent); the run starts and ends where the
 * windows say (the window length is KGENOME_MUTATION_NG), a gap longer than the island joins two
 * runs, a floor drops the short ones and counts them.
 */

#define FK_LEGACY_RULES 1
#include "fnprint_kit.h"

#include <celllysis/mutation_window.h>

/* ---- relmask ------------------------------------------------------------------------------- */

static void le32(uint8_t *p, int32_t v)
{
	memcpy(p, &v, 4);
}

static void t_relmask(void)
{
	uint8_t b[64], o[64];
	uint64_t n;

	/* call rel32 whose target (the end of the instruction + disp) is inside the object */
	memset(b, 0x90, sizeof b);
	b[2] = 0xe8;
	le32(b + 3, 1);                           /* 7 + 1 = 8 inside 16 */
	n = kgenome_fnprint_relmask(b, 16, o, 0);
	CK(n == 1);
	CK(!memcmp(o, b, 3) && !memcmp(o + 3, "\0\0\0\0", 4) && !memcmp(o + 7, b + 7, 9));
	CK(b[3] == 1);                              /* out != p: the input is untouched */

	/* jmp rel32 whose target is far outside: not a field of this object */
	memset(b, 0x90, sizeof b);
	b[0] = 0xe9;
	le32(b + 1, 0x1000);
	CK(kgenome_fnprint_relmask(b, 16, o, 0) == 0 && !memcmp(o, b, 16));
	/* ... and just past the end: held back by slack 0, taken by slack 4 */
	le32(b + 1, 16 - 5 + 4);                  /* target = n + 4 */
	CK(kgenome_fnprint_relmask(b, 16, o, 0) == 0);
	CK(kgenome_fnprint_relmask(b, 16, o, 4) == 1 && !memcmp(o + 1, "\0\0\0\0", 4));
	/* a negative displacement: before the start by 3 needs slack 3 */
	le32(b + 1, -8);                          /* target = 5 - 8 = -3 */
	CK(kgenome_fnprint_relmask(b, 16, o, 2) == 0);
	CK(kgenome_fnprint_relmask(b, 16, o, 3) == 1);

	/* jcc rel32 (0F 8x) */
	memset(b, 0x90, sizeof b);
	b[4] = 0x0f; b[5] = 0x85;
	le32(b + 6, 2);
	CK(kgenome_fnprint_relmask(b, 24, o, 0) == 1 && !memcmp(o + 6, "\0\0\0\0", 4) && o[4] == 0x0f && o[5] == 0x85);

	/* the RIP-relative forms: mov r64, [rip+d] (48 8B 05), lea (48 8D 3D), and the 0F xx ones */
	memset(b, 0x90, sizeof b);
	b[1] = 0x48; b[2] = 0x8b; b[3] = 0x05;     /* 8B with modrm 05: the opcode is b[2] */
	le32(b + 4, 4);
	CK(kgenome_fnprint_relmask(b, 24, o, 0) == 1 && !memcmp(o + 4, "\0\0\0\0", 4));
	memset(b, 0x90, sizeof b);
	b[0] = 0x48; b[1] = 0x8d; b[2] = 0x3d;
	le32(b + 3, 0x10);
	CK(kgenome_fnprint_relmask(b, 40, o, 0) == 1 && !memcmp(o + 3, "\0\0\0\0", 4));
	memset(b, 0x90, sizeof b);
	b[2] = 0x0f; b[3] = 0xb6; b[4] = 0x05;     /* movzx r32, byte [rip+d] */
	le32(b + 5, 3);
	CK(kgenome_fnprint_relmask(b, 24, o, 0) == 1 && !memcmp(o + 5, "\0\0\0\0", 4));
	/* a modrm that is not RIP-relative (mod 00, rm 011) is not a field */
	memset(b, 0x90, sizeof b);
	b[2] = 0x8b; b[3] = 0x03;
	le32(b + 4, 2);
	CK(kgenome_fnprint_relmask(b, 24, o, 0) == 0);

	/* two calls one after the other, both masked */
	memset(b, 0x90, sizeof b);
	b[0] = 0xe8; le32(b + 1, 0x10);
	b[5] = 0xe8; le32(b + 6, 0x8);
	CK(kgenome_fnprint_relmask(b, 32, o, 0) == 2);

	/* in place: out == p */
	memcpy(o, b, 32);
	CK(kgenome_fnprint_relmask(o, 32, o, 0) == 2 && !memcmp(o + 1, "\0\0\0\0", 4) && !memcmp(o + 6, "\0\0\0\0", 4));

	/* too short to hold an instruction with a field: nothing, and the output is a copy */
	memset(b, 0xe8, sizeof b);
	CK(kgenome_fnprint_relmask(b, 4, o, 0) == 0 && !memcmp(o, b, 4));
	CK(kgenome_fnprint_relmask(b, 0, o, 0) == 0);

	/* the same function at two link addresses masks to the same bytes: the point of it */
	{
		uint8_t f1[40], f2[40], m1[40], m2[40];
		uint64_t k;

		memset(f1, 0x90, sizeof f1);
		f1[3] = 0xe8; le32(f1 + 4, 0x0c);
		f1[20] = 0x48; f1[21] = 0x8d; f1[22] = 0x05; le32(f1 + 23, -0x10);
		memcpy(f2, f1, sizeof f1);
		le32(f2 + 4, 0x0a);                    /* the linker chose another place for both */
		le32(f2 + 23, -0x14);
		CK(memcmp(f1, f2, sizeof f1) != 0);
		k = kgenome_fnprint_relmask(f1, sizeof f1, m1, 0) + kgenome_fnprint_relmask(f2, sizeof f2, m2, 0);
		CK(k == 4 && !memcmp(m1, m2, sizeof m1));
	}
}

/* ---- the library table ------------------------------------------------------------------------ */

static void t_libtab_put(void)
{
	struct kgenome_fnprint_libtab t;
	struct kgenome_ledger led;
	uint32_t i, held = 0, refused_seen = 0;

	CK(kgenome_fnprint_libtab_init(&t, 0, NULL));
	CK(kgenome_fnprint_libtab_put(&t, 0) == 1);            /* value 0 is stored as 1 and is still found */
	CK(kgenome_fnprint_libtab_has(&t, 0) == 1);
	CK(kgenome_fnprint_libtab_put(&t, 0xdeadbeefu) == 1);
	CK(kgenome_fnprint_libtab_put(&t, 7u) == 1);
	CK(kgenome_fnprint_libtab_put(&t, 7u) == 1);            /* a repeat is held, not refused */
	CK(t.n == 3 && t.n_seen == 4 && t.n_refused == 0 && t.status == KGENOME_OK);
	CK(kgenome_fnprint_libtab_has(&t, 7u) && kgenome_fnprint_libtab_has(&t, 0xdeadbeefu));
	CK(!kgenome_fnprint_libtab_has(&t, 8u) && !kgenome_fnprint_libtab_has(&t, 1u));
	CK(kgenome_fnprint_libtab_put(NULL, 1u) == 0);
	kgenome_fnprint_libtab_free(&t);
	CK(t.cap == 0 && t.slot == NULL && t.n == 0);

	/* sampling: with sel_bits 4 only a value whose low 4 bits are zero is kept, and the table says so */
	CK(kgenome_fnprint_libtab_init(&t, 4, NULL));
	CK(kgenome_fnprint_libtab_put(&t, 0x30u) == 1);
	CK(kgenome_fnprint_libtab_put(&t, 0x31u) == 0);
	CK(kgenome_fnprint_libtab_sampled(&t, 0x30u) && !kgenome_fnprint_libtab_sampled(&t, 0x31u));
	CK(kgenome_fnprint_libtab_has(&t, 0x30u) && !kgenome_fnprint_libtab_has(&t, 0x31u));
	CK(t.n == 1 && t.n_seen == 1);                           /* an unsampled value is not even counted as seen */
	kgenome_fnprint_libtab_free(&t);
	CK(kgenome_fnprint_libtab_init(&t, 99, NULL) && t.sel_bits == 24);   /* clamped */
	kgenome_fnprint_libtab_free(&t);

	/* a ledger that cannot hold the first table: every put is refused, counted and the status says so */
	kgenome_ledger_init(&led, 1000);
	CK(kgenome_fnprint_libtab_init(&t, 0, &led));
	CK(kgenome_fnprint_libtab_put(&t, 5u) == 0);
	CK(t.n == 0 && t.n_refused == 1 && t.status == KGENOME_OVER_BUDGET);
	CK(!kgenome_fnprint_libtab_has(&t, 5u));
	kgenome_fnprint_libtab_free(&t);

	/* a ledger that holds the first 4096 slots and not the second: the table fills to nine tenths of
	 * the first and then refuses, and everything it accepted is still found (rule 4: a cap that fires
	 * is told, and what is already held is not thrown away) */
	kgenome_ledger_init(&led, 4096u * 4u);
	CK(kgenome_fnprint_libtab_init(&t, 0, &led));
	for (i = 1; i <= 5000; i++) {
		uint32_t v = i * 2654435761u;
		int r = kgenome_fnprint_libtab_put(&t, v);

		if (r)
			held++;
		else
			refused_seen++;
	}
	CK(held > 3000 && held <= 3687);                         /* 9/10 of 4096 */
	CK(refused_seen == 5000 - held);
	CK(t.n == held && t.n_refused == refused_seen && t.status == KGENOME_OVER_BUDGET);
	CK(led.used == 4096u * 4u);
	{
		uint32_t found = 0;

		for (i = 1; i <= 5000; i++)
			found += (uint32_t)kgenome_fnprint_libtab_has(&t, i * 2654435761u);
		CK(found >= held);                                /* nothing accepted was lost (a miss may collide) */
	}
	kgenome_fnprint_libtab_free(&t);
	CK(led.used == 0);                                       /* and the charge is given back */
}

/* ---- runs --------------------------------------------------------------------------------------- */

struct runlog {
	uint32_t n;
	uint64_t off[8], len[8];
	uint32_t win[8];
	int      stop_after;
};

static int run_cb(void *u, uint64_t off, uint64_t len, uint32_t n_win)
{
	struct runlog *l = u;

	if (l->n < 8) {
		l->off[l->n] = off;
		l->len[l->n] = len;
		l->win[l->n] = n_win;
	}
	l->n++;
	return l->stop_after && l->n >= (uint32_t)l->stop_after;
}

static void rnd(uint8_t *p, size_t n, uint64_t seed)
{
	struct hk_rng r = { seed };
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)hk_next(&r);
}

static void t_runs(void)
{
	enum { NG = KGENOME_MUTATION_NG };
	static uint8_t lib[400], a1[100], a2[100], blob[1100];
	struct kgenome_fnprint_libtab t;
	struct runlog l;
	uint32_t dropped = 99, offered, win0;
	size_t at = 0;

	rnd(lib, sizeof lib, 0x1111);
	rnd(a1, sizeof a1, 0x2222);
	rnd(a2, sizeof a2, 0x3333);
	CK(kgenome_fnprint_libtab_init(&t, 0, NULL));
	kgenome_fnprint_libtab_add(&t, lib, sizeof lib);

	/* library, author code, library: ONE run, from the first window that touches author bytes to the
	 * last, and the table makes no difference to what is outside it */
	memcpy(blob, lib, 400); at = 400;
	memcpy(blob + at, a1, 100); at += 100;
	memcpy(blob + at, lib, 400); at += 400;
	memset(&l, 0, sizeof l);
	offered = kgenome_fnprint_runs(blob, at, &t, 4, 8, run_cb, &l, &dropped);
	CK(offered == 1 && l.n == 1 && dropped == 0);
	CK(l.off[0] == 400 - (NG - 1));
	CK(l.len[0] == 100 + 2 * (NG - 1));
	CK(l.win[0] == l.len[0] - NG + 1);
	win0 = l.win[0];

	/* the floor: a run of fewer windows than min_win is not offered, and is counted */
	memset(&l, 0, sizeof l);
	offered = kgenome_fnprint_runs(blob, at, &t, 4, win0 + 1, run_cb, &l, &dropped);
	CK(offered == 0 && l.n == 0 && dropped == 1);
	/* ... and exactly at the floor it is */
	{
		uint32_t w = (uint32_t)(100 + 2 * (NG - 1) - NG + 1);

		memset(&l, 0, sizeof l);
		offered = kgenome_fnprint_runs(blob, at, &t, 4, w, run_cb, &l, &dropped);
		CK(offered == 1 && dropped == 0 && l.win[0] == w);
	}

	/* two stretches of author code with a library island between them: a gap shorter than the island's windows
	 * closes the first run, a longer one joins them */
	at = 0;
	memcpy(blob, lib, 400); at = 400;
	memcpy(blob + at, a1, 100); at += 100;
	memcpy(blob + at, lib + 100, 40); at += 40;           /* an island: 33 library windows */
	memcpy(blob + at, a2, 100); at += 100;
	memcpy(blob + at, lib, 400); at += 400;
	memset(&l, 0, sizeof l);
	offered = kgenome_fnprint_runs(blob, at, &t, 4, 8, run_cb, &l, &dropped);
	CK(offered == 2 && l.n == 2);
	CK(l.off[0] == 400 - (NG - 1) && l.len[0] == 100 + 2 * (NG - 1));
	CK(l.off[1] == 540 - (NG - 1) && l.len[1] == 100 + 2 * (NG - 1));
	memset(&l, 0, sizeof l);
	offered = kgenome_fnprint_runs(blob, at, &t, 64, 8, run_cb, &l, &dropped);
	CK(offered == 1 && l.n == 1 && l.off[0] == 400 - (NG - 1));
	CK(l.len[0] == 240 + 2 * (NG - 1));
	/* the callback may stop the walk: after the first run, the second is not offered */
	memset(&l, 0, sizeof l);
	l.stop_after = 1;
	offered = kgenome_fnprint_runs(blob, at, &t, 4, 8, run_cb, &l, &dropped);
	CK(offered == 1 && l.n == 1);

	/* no table: every window is not library, so the whole object is one run */
	memset(&l, 0, sizeof l);
	offered = kgenome_fnprint_runs(blob, at, NULL, 4, 8, run_cb, &l, &dropped);
	CK(offered == 1 && l.off[0] == 0 && l.len[0] == at);

	/* arguments: no bytes, no callback, a flat object (no window is evidence) */
	dropped = 77;
	CK(kgenome_fnprint_runs(NULL, 10, &t, 4, 8, run_cb, &l, &dropped) == 0 && dropped == 0);
	CK(kgenome_fnprint_runs(blob, at, &t, 4, 8, NULL, &l, &dropped) == 0);
	CK(kgenome_fnprint_runs(blob, at, &t, 4, 8, run_cb, &l, NULL) <= 2);
	memset(blob, 0, 300);
	memset(&l, 0, sizeof l);
	CK(kgenome_fnprint_runs(blob, 300, NULL, 4, 1, run_cb, &l, &dropped) == 0 && l.n == 0);
	kgenome_fnprint_libtab_free(&t);
}

/* ---- sorted -------------------------------------------------------------------------------------- */

static void t_sorted(void)
{
	struct kgenome_func v[4];
	struct kgenome_func_set s;

	memset(v, 0, sizeof v);
	memset(&s, 0, sizeof s);
	CK(kgenome_fnprint_sorted(NULL) == 1);                 /* nothing is in order */
	CK(kgenome_fnprint_sorted(&s) == 1);                   /* an empty set */
	v[0].off = 10;
	s.v = v; s.n = 1;
	CK(kgenome_fnprint_sorted(&s) == 1);
	v[1].off = 10; v[2].off = 20; v[3].off = 30;
	s.n = 4;
	CK(kgenome_fnprint_sorted(&s) == 1);                   /* equal offsets are in order */
	v[2].off = 9;
	CK(kgenome_fnprint_sorted(&s) == 0);                   /* one descent anywhere */
	v[2].off = 20; v[3].off = 19;
	CK(kgenome_fnprint_sorted(&s) == 0);                   /* ... including the last pair */
	s.n = 3;
	CK(kgenome_fnprint_sorted(&s) == 1);                   /* only the first n are read */
}

/* ---- any_pm -------------------------------------------------------------------------------------- */

static struct fk_var V = { 0x100, 0x200, 0x30405060u };

static uint64_t prog(struct fk_obj *o, uint32_t aseed, uint32_t na, uint32_t lseed, uint32_t nl)
{
	uint64_t e, m, at[64], site[64];
	uint32_t i;

	fk_init(o);
	e = fk_entry(o, 0);
	m = fk_stub(o, na < 64 ? na : 64, site);
	for (i = 0; i < na && i < 64; i++)
		at[i] = fk_func(o, aseed + i, 30 + (i % 10), &V);
	for (i = 0; i < na && i < 64; i++)
		fk_call_to(o, site[i], at[i]);
	for (i = 0; i < 4; i++)
		fk_wrapper(o, 1 + i);
	for (i = 0; i < nl; i++)
		fk_func(o, lseed + i, 25 + (i % 12), &V);
	{
		int32_t d = (int32_t)((int64_t)m - (int64_t)(e + 7));

		memcpy(o->b + e + 3, &d, 4);
	}
	return e;
}

static void t_any_pm(void)
{
	struct kgenome_fnprint_ref ref;
	struct kgenome_fnprint_match m;

	/* the numbers, by hand: strong 300 and weak 400 of 1000 -> strong 300 per mille, any (600 + 400) / 2 = 500 */
	memset(&ref, 0, sizeof ref);
	memset(&m, 0, sizeof m);
	ref.total_w = 1000;
	m.ref = &ref;
	m.strong_w = 300;
	m.weak_w = 400;
	CK(kgenome_fnprint_match_strong_pm(&m) == 300);
	CK(kgenome_fnprint_match_any_pm(&m) == 500);
	m.strong_w = 1000;
	m.weak_w = 0;
	CK(kgenome_fnprint_match_any_pm(&m) == 1000 && kgenome_fnprint_match_strong_pm(&m) == 1000);
	m.strong_w = 0;
	m.weak_w = 1000;
	CK(kgenome_fnprint_match_any_pm(&m) == 500 && kgenome_fnprint_match_strong_pm(&m) == 0);
	/* nothing to contain: zero, not a division by zero */
	ref.total_w = 0;
	CK(kgenome_fnprint_match_any_pm(&m) == 0 && kgenome_fnprint_match_strong_pm(&m) == 0);
	CK(kgenome_fnprint_match_any_pm(NULL) == 0);
	m.ref = NULL;
	CK(kgenome_fnprint_match_any_pm(&m) == 0);

	/* on real objects: a program contains itself fully, and the weak figure never falls below the strong */
	{
		struct fk_obj a, b;
		uint64_t ea, eb;
		struct kgenome_fnprint_req ra, rb;
		struct kgenome_fnprint_stat sa, sb;
		struct kgenome_func_set fa, fb;
		struct kgenome_fnprint_set s;
		struct kgenome_fnprint_match mm;
		uint32_t strong, any;
		int k;

		ea = prog(&a, 1000, 12, 5000, 40);
		eb = prog(&b, 1000, 12, 5000, 40);
		for (k = 0; k < 2; k++) {
			fk_req(&ra, &a, KGENOME_FNP_LINK_STATIC, &sa, &fa);
			ra.entry_off = ea;
			fk_req(&rb, k ? &b : &a, KGENOME_FNP_LINK_STATIC, &sb, &fb);
			rb.entry_off = k ? eb : ea;
			memset(&s, 0, sizeof s);
			kgenome_fnprint_collect(&ra, &s);
			kgenome_fnprint_ref_build(&s, &ref);
			kgenome_fnprint_set_free(&s, NULL);
			memset(&mm, 0, sizeof mm);
			CK(kgenome_fnprint_match_init(&mm, &ref, NULL));
			rb.visit = kgenome_fnprint_match_visit;
			rb.user = &mm;
			kgenome_fnprint_walk(&rb);
			strong = kgenome_fnprint_match_strong_pm(&mm);
			any = kgenome_fnprint_match_any_pm(&mm);
			CK(ref.total_w > 0);
			CK(strong == 1000 && any == 1000);
			CK(any == (uint32_t)((mm.strong_w * 2u + mm.weak_w) * 500u / ref.total_w));
			kgenome_fnprint_match_done(&mm);
			kgenome_fnprint_ref_free(&ref);
		}
		fk_free(&a);
		fk_free(&b);
	}
}

int main(void)
{
	t_relmask();
	t_libtab_put();
	t_runs();
	t_sorted();
	t_any_pm();
	if (hk_fails) {
		printf("cov_fnprint_api: FAILED (%d)\n", hk_fails);
		return 1;
	}
	printf("cov_fnprint_api: ok\n");
	return 0;
}
