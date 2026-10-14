/*
 * fnprint_danger - what an adversary, a bad function set or a plain accident can
 * do to the similarity, and what the prototype does about it.
 *
 * The core reason this exists: two unrelated programs that share only a
 * statically linked libc must NOT score as similar. The first test builds
 * exactly that and holds both readings - the naive one (every function counts)
 * says similar, the relevance-weighted one says not.
 *
 * What cannot be fixed without a redesign is KM_CHECK with its cause in the cap
 * string: junk interleaved in the REFERENCE's author block dilutes it; a program
 * with no frontier and no main (a Go-like runtime) cannot separate its library
 * without a fingerprint table; a few raw-syscall helpers of the author's own
 * latch the frontier early.
 */
#define FK_LEGACY_RULES 1
#include "fnprint_kit.h"
#include "../../unit/known_miss.h"

static struct fk_var V = { 0x100, 0x200, 0x30405060u };

/*
 * A static program: entry, `na` author functions (seeds aseed..), the library
 * block - `nw` syscall wrappers, then `nl` functions (seeds lseed..). Returns the
 * entry offset; main is the first author function.
 */
static uint64_t prog(struct fk_obj *o, uint32_t aseed, uint32_t na, uint32_t lseed, uint32_t nl, uint32_t nw)
{
	uint64_t e, m, at[64], site[64];
	uint32_t i;

	fk_init(o);
	e = fk_entry(o, 0);
	m = fk_stub(o, na < 64 ? na : 64, site);       /* main: calls every author function, so the program reaches its code */
	for (i = 0; i < na && i < 64; i++)
		at[i] = fk_func(o, aseed + i, 30 + (i % 10), &V);
	for (i = 0; i < na && i < 64; i++)
		fk_call_to(o, site[i], at[i]);
	for (i = 0; i < nw; i++)
		fk_wrapper(o, 1 + i);
	for (i = 0; i < nl; i++)
		fk_func(o, lseed + i, 25 + (i % 12), &V);
	{
		int32_t d = (int32_t)((int64_t)m - (int64_t)(e + 7));

		memcpy(o->b + e + 3, &d, 4);
	}
	return e;
}

static void req_of(struct kgenome_fnprint_req *rq, const struct fk_obj *o, uint64_t entry,
		   struct kgenome_fnprint_stat *st, struct kgenome_func_set *fs)
{
	fk_req(rq, o, KGENOME_FNP_LINK_STATIC, st, fs);
	rq->entry_off = entry;
}

/* Containment of a's reference in object b, in per mille. naive: every function counts at full weight. */
static uint32_t contain(const struct fk_obj *a, uint64_t ea, const struct fk_obj *b, uint64_t eb, int naive,
			struct kgenome_fnprint_match *mout)
{
	struct kgenome_fnprint_req ra, rb;
	struct kgenome_fnprint_stat sa, sb;
	struct kgenome_func_set fa, fb;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_ref ref;
	struct kgenome_fnprint_match m;
	uint32_t pm;

	req_of(&ra, a, ea, &sa, &fa);
	req_of(&rb, b, eb, &sb, &fb);
	if (naive) {
		ra.opt.w_lib = ra.opt.w_unknown = 100;
		rb.opt.w_lib = rb.opt.w_unknown = 100;
	}
	kgenome_fnprint_collect(&ra, &s);
	kgenome_fnprint_ref_build(&s, &ref);
	kgenome_fnprint_set_free(&s, NULL);
	memset(&m, 0, sizeof m);
	kgenome_fnprint_match_init(&m, &ref, NULL);
	rb.visit = kgenome_fnprint_match_visit;
	rb.user = &m;
	kgenome_fnprint_walk(&rb);
	pm = kgenome_fnprint_match_strong_pm(&m);
	if (mout)
		*mout = m;
	else
		kgenome_fnprint_match_done(&m);
	kgenome_fnprint_ref_free(&ref);
	return pm;
}

static void t_libc_only_sharing(void)
{
	struct fk_obj a, b, c;
	uint64_t ea = prog(&a, 1000, 12, 5000, 60, 4);
	uint64_t eb = prog(&b, 2000, 12, 5000, 60, 4);       /* other author code, the same library */
	uint64_t ec = prog(&c, 1000, 12, 7000, 60, 4);       /* the same author code, another library build */

	CK(contain(&a, ea, &b, eb, 1, NULL) > 500);          /* the naive reading: "similar" */
	CK(contain(&a, ea, &b, eb, 0, NULL) < 100);          /* the relevance reading: not */
	CK(contain(&a, ea, &c, ec, 0, NULL) >= 900);         /* and the same author code under another libc still is */
	CK(contain(&a, ea, &a, ea, 0, NULL) == 1000);
	fk_free(&a); fk_free(&b); fk_free(&c);
}

/* Junk added to the OBJECT - after the frontier and among the author code - does not move the containment of the reference. */
static void t_junk_in_object(void)
{
	struct fk_obj a, b;
	uint64_t ea = prog(&a, 1000, 12, 5000, 40, 4), eb;
	uint32_t i, j;
	uint8_t *keep;

	/* b: the same author functions, then 400 junk functions among them, then the library */
	fk_init(&b);
	eb = fk_entry(&b, 0);
	{
		uint64_t site[12], m = fk_stub(&b, 12, site);
		int32_t d = (int32_t)((int64_t)m - (int64_t)(eb + 7));

		memcpy(b.b + eb + 3, &d, 4);
		for (i = 0; i < 12; i++) {
			fk_call_to(&b, site[i], fk_func(&b, 1000 + i, 30 + (i % 10), &V));
			for (j = 0; j < 33; j++)
				fk_func(&b, 90000 + i * 33 + j, 12, &V);
		}
	}
	for (i = 0; i < 4; i++)
		fk_wrapper(&b, 1 + i);
	for (i = 0; i < 40; i++)
		fk_func(&b, 5000 + i, 25 + (i % 12), &V);
	keep = b.b;
	(void)keep;
	CK(contain(&a, ea, &b, eb, 0, NULL) >= 990);
	fk_free(&a); fk_free(&b);
}

/*
 * Junk in the REFERENCE, interleaved in the author block, is weighed as author
 * code: it dilutes a reference that is otherwise contained in the object.
 */
static void t_junk_in_reference(void)
{
	struct fk_obj a, b;
	uint64_t ea, eb = prog(&b, 1000, 12, 5000, 40, 4);
	uint32_t i, j;

	fk_init(&a);
	ea = fk_entry(&a, 0);
	{
		uint64_t site[12], m = fk_stub(&a, 12, site);
		int32_t d = (int32_t)((int64_t)m - (int64_t)(ea + 7));

		memcpy(a.b + ea + 3, &d, 4);
		for (i = 0; i < 12; i++) {
			fk_call_to(&a, site[i], fk_func(&a, 1000 + i, 30 + (i % 10), &V));
			for (j = 0; j < 40; j++)
				fk_func(&a, 70000 + i * 40 + j, 30, &V);       /* between two reached functions: the program's, by position */
		}
	}
	for (i = 0; i < 4; i++)
		fk_wrapper(&a, 1 + i);
	for (i = 0; i < 40; i++)
		fk_func(&a, 5000 + i, 25 + (i % 12), &V);
	KM_CHECK(contain(&a, ea, &b, eb, 0, NULL) >= 800,
		 "a reference padded with junk functions inside its author block is still contained in the clean object",
		 "JUNK_IN_REFERENCE_WEIGHS_AS_AUTHOR");
	fk_free(&a); fk_free(&b);
}

/* The same stub repeated thousands of times is one entry of the reference, counted once. */
static void t_repeated_stubs(void)
{
	struct fk_obj a, b;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_ref ref;
	uint32_t i;

	fk_init(&a);
	for (i = 0; i < 5000; i++)
		fk_func(&a, 4242, 14, &V);                   /* the same seed: identical bytes, 5000 positions */
	fk_func(&a, 4243, 30, &V);
	fk_req(&rq, &a, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	kgenome_fnprint_collect(&rq, &s);
	kgenome_fnprint_ref_build(&s, &ref);
	CK(s.n == 5001 && ref.n == 2);
	CK(ref.e[0].mult == 5000 || ref.e[1].mult == 5000);
	CK(ref.total_w < 100);                               /* two functions' weight, not 5001 */
	kgenome_fnprint_ref_free(&ref);
	kgenome_fnprint_set_free(&s, NULL);
	/* a reference of one stub is fully contained in an object that has it once, and in one that has it 5000 times */
	fk_init(&b);
	fk_func(&b, 4242, 14, &V);
	fk_req(&rq, &b, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	kgenome_fnprint_collect(&rq, &s);
	kgenome_fnprint_ref_build(&s, &ref);
	{
		struct kgenome_fnprint_match m;
		struct kgenome_fnprint_req ro;
		struct kgenome_fnprint_stat so;
		struct kgenome_func_set fo;

		fk_req(&ro, &a, KGENOME_FNP_LINK_DYNAMIC, &so, &fo);
		memset(&m, 0, sizeof m);
		kgenome_fnprint_match_init(&m, &ref, NULL);
		ro.visit = kgenome_fnprint_match_visit; ro.user = &m;
		kgenome_fnprint_walk(&ro);
		CK(kgenome_fnprint_match_strong_pm(&m) == 1000);
		kgenome_fnprint_match_done(&m);
	}
	kgenome_fnprint_ref_free(&ref);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&a); fk_free(&b);
}

/* Bogus extents are flagged and counted, never read past the object, never dropped without a number. */
static void t_bogus_extents(void)
{
	struct fk_obj o;
	struct kgenome_func v[9];
	struct kgenome_func_set fs;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_fnprint_set s;
	struct hk_gb g;
	uint8_t *p;
	uint64_t at;

	fk_init(&o);
	at = fk_func(&o, 1, 40, &V);
	fk_func(&o, 2, 40, &V);
	memset(v, 0, sizeof v);
	v[0].off = at;               v[0].len = 0;                      /* zero length */
	v[1].off = o.n + 100;        v[1].len = 16;                     /* starts past the end */
	v[2].off = 8;                v[2].len = UINT64_MAX;             /* the end overflows */
	v[3].off = UINT64_MAX - 3;   v[3].len = 8;                      /* off + len wraps */
	v[4].off = o.n - 4;          v[4].len = 64;                     /* runs off the end */
	v[5].off = 0;                v[5].len = o.n;                    /* the whole object: huge, overlaps the next */
	v[6].off = 10;               v[6].len = 30;                     /* inside it */
	v[7].off = 20;               v[7].len = 30;                     /* overlaps the one before */
	v[8].off = at;               v[8].len = 40;                     /* a plausible one */
	gb_init(&g, o.n + 64);
	p = gb_put(&g, o.b, o.n);                                       /* the last byte is the last before a guard page */
	fs.v = v; fs.n = 9; fs.status = KGENOME_OK;
	memset(&rq, 0, sizeof rq);
	rq.p = p; rq.n = o.n; rq.arch = KGENOME_ARCH_X86_64; rq.funcs = &fs;
	rq.entry_off = KGENOME_BROKEN; rq.link = KGENOME_FNP_LINK_DYNAMIC; rq.stat = &st;
	rq.opt.huge_len = o.n / 2;
	kgenome_fnprint_collect(&rq, &s);
	CK(s.n == 9 && st.n_visited == 9 && st.n_skipped == 0);       /* all nine are in the answer */
	CK(st.n_bad == 5);                                            /* zero, past the end, overflow x2, runs off */
	CK(st.n_huge >= 1);
	CK(st.n_overlap >= 2);
	CK(s.fn[0].reason & KGENOME_FNP_R_BAD && s.fn[0].weight == 0 && s.fn[0].cls == KGENOME_FNP_UNKNOWN);
	CK(st.status == KGENOME_TRUNCATED);                           /* the set was not in address order */
	kgenome_fnprint_set_free(&s, NULL);
	gb_free(&g);
	fk_free(&o);
}

/* A count that is larger than the file: a million entries over a few bytes. */
static void t_counts_larger_than_file(void)
{
	struct kgenome_func_set fs;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	uint8_t code[16] = { 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3 };
	uint32_t n = 1000000u, i;
	double t0 = hk_now();

	fs.v = malloc((size_t)n * sizeof *fs.v);
	for (i = 0; i < n; i++) {
		fs.v[i].off = 0; fs.v[i].len = 4096; fs.v[i].value = 0; fs.v[i].shndx = 0;      /* every one runs past the end */
	}
	fs.n = n; fs.status = KGENOME_OK;
	memset(&rq, 0, sizeof rq);
	rq.p = code; rq.n = sizeof code; rq.arch = KGENOME_ARCH_X86_64; rq.funcs = &fs;
	rq.entry_off = KGENOME_BROKEN; rq.link = KGENOME_FNP_LINK_DYNAMIC; rq.stat = &st;
	kgenome_fnprint_walk(&rq);
	CK(st.n_funcs == n && st.n_visited == n && st.n_bad == n);
	CK(hk_now() - t0 < 4.0);
	free(fs.v);
}

/* Nothing hostile at the door: NULL, empty, truncated, every length of a small object. */
static void t_hostile_inputs(void)
{
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs = { NULL, 0, KGENOME_OK };
	struct fk_obj o;
	struct hk_gb g;
	uint64_t n;

	kgenome_fnprint_walk(NULL);
	memset(&rq, 0, sizeof rq);
	kgenome_fnprint_walk(&rq);                                    /* no stat: nothing to write, no crash */
	rq.stat = &st;
	kgenome_fnprint_walk(&rq);
	CK(st.status == KGENOME_BAD_INPUT);
	rq.p = (const uint8_t *)"\x55"; rq.n = 0; rq.funcs = &fs;
	kgenome_fnprint_walk(&rq);
	CK(st.status == KGENOME_BAD_INPUT);                           /* zero size */
	rq.n = 1; rq.funcs = NULL;
	kgenome_fnprint_walk(&rq);
	CK(st.status == KGENOME_BAD_INPUT);
	fs.n = 5; fs.v = NULL; rq.funcs = &fs;
	kgenome_fnprint_walk(&rq);
	CK(st.status == KGENOME_BAD_INPUT);                           /* a count and no array */
	CK(kgenome_fnprint_equal(NULL, NULL, NULL, NULL) == 0);
	fk_init(&o);
	fk_func(&o, 9, 30, &V);
	fk_func(&o, 10, 30, &V);
	gb_init(&g, o.n + 64);
	for (n = 0; n <= o.n; n++) {                                  /* every truncation: the extent says more than the bytes */
		struct kgenome_func_set f2;
		struct kgenome_fnprint_set s;
		uint8_t *p = gb_put(&g, o.b, n);

		f2.v = o.v; f2.n = o.nf; f2.status = KGENOME_OK;
		memset(&rq, 0, sizeof rq);
		rq.p = p; rq.n = n; rq.arch = KGENOME_ARCH_X86_64; rq.funcs = &f2;
		rq.entry_off = KGENOME_BROKEN; rq.link = KGENOME_FNP_LINK_STATIC; rq.stat = &st;
		kgenome_fnprint_collect(&rq, &s);
		kgenome_fnprint_set_free(&s, NULL);
		if (n)
			CK(st.n_visited == 2);
	}
	gb_free(&g);
	fk_free(&o);
}

/* A weak-fingerprint flood: the candidates examined per function are bounded, and the bound is reported. */
static void t_weak_flood_bounded(void)
{
	struct fk_obj a, b;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;
	struct kgenome_fnprint_ref ref;
	struct kgenome_fnprint_match m;
	uint32_t i;
	/* a reference of 3000 functions that share one opcode sequence and differ in two small immediates, matched by 3000 of another set */
	fk_init(&a); fk_init(&b);
	for (i = 0; i < 3000; i++) {
		uint8_t c[13] = { 0x83, 0xc0, 0, 0x83, 0xc0, 0, 0x83, 0xc0, 1, 0x83, 0xc0, 1, 0xc3 };

		c[2] = (uint8_t)(i & 0x7f); c[5] = (uint8_t)((i >> 7) & 0x7f);
		fk_mark(&a, a.n, 13); fk_raw(&a, c, 13);
	}
	for (i = 0; i < 3000; i++) {
		uint8_t c[13] = { 0x83, 0xc0, 0, 0x83, 0xc0, 0, 0x83, 0xc0, 1, 0x83, 0xc0, 1, 0xc3 };

		c[2] = (uint8_t)(0x7f - (i & 0x7f)); c[5] = (uint8_t)(0x7f - ((i >> 7) & 0x7f));
		fk_mark(&b, b.n, 13); fk_raw(&b, c, 13);
	}
	fk_req(&rq, &a, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	rq.opt.tiny_insn = 2;
	kgenome_fnprint_collect(&rq, &s);
	kgenome_fnprint_ref_build(&s, &ref);
	{
		struct kgenome_fnprint_req rb;
		struct kgenome_fnprint_stat sb;
		struct kgenome_func_set fb;
		double t0 = hk_now();

		fk_req(&rb, &b, KGENOME_FNP_LINK_DYNAMIC, &sb, &fb);
		rb.opt.tiny_insn = 2;
		memset(&m, 0, sizeof m);
		kgenome_fnprint_match_init(&m, &ref, NULL);
		rb.visit = kgenome_fnprint_match_visit; rb.user = &m;
		kgenome_fnprint_walk(&rb);
		CK(hk_now() - t0 < 3.0);
	}
	CK(m.n_capped > 0 && m.status == KGENOME_TRUNCATED);        /* a bound that fired says so */
	kgenome_fnprint_match_done(&m);
	kgenome_fnprint_ref_free(&ref);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&a); fk_free(&b);
}

/* A 64-bit hash can collide: the exact verification rejects a forged equal fingerprint and counts it. */
static void t_collision_verified(void)
{
	struct fk_obj a, b;
	struct kgenome_fnprint_req ra, rb;
	struct kgenome_fnprint_stat sa, sb;
	struct kgenome_func_set fa, fb;
	struct kgenome_fnprint_set s, t;
	struct kgenome_fnprint_ref ref;
	struct kgenome_fnprint_match m;

	fk_init(&a); fk_init(&b);
	fk_func(&a, 31, 40, &V);
	fk_func(&b, 32, 40, &V);                             /* a different function */
	fk_req(&ra, &a, KGENOME_FNP_LINK_DYNAMIC, &sa, &fa);
	fk_req(&rb, &b, KGENOME_FNP_LINK_DYNAMIC, &sb, &fb);
	kgenome_fnprint_collect(&ra, &s);
	kgenome_fnprint_collect(&rb, &t);
	kgenome_fnprint_ref_build(&s, &ref);
	CK(ref.n == 1 && ref.e[0].fp != t.fn[0].fp);
	CK(kgenome_fnprint_equal(&ra, &s.fn[0], &rb, &t.fn[0]) == 0);
	CK(kgenome_fnprint_equal(&ra, &s.fn[0], &ra, &s.fn[0]) == 1);
	ref.e[0].fp = t.fn[0].fp;                            /* the forged collision: b's fingerprint on a's entry */
	ref.e[0].fw = 0;
	memset(&m, 0, sizeof m);
	m.verify_ref = &ra; m.verify_obj = &rb;
	kgenome_fnprint_match_init(&m, &ref, NULL);
	kgenome_fnprint_match_feed(&m, &t.fn[0]);
	CK(m.n_collision == 1 && m.n_strong == 0);
	kgenome_fnprint_match_done(&m);
	/* without verification the forged equality is believed */
	memset(&m, 0, sizeof m);
	kgenome_fnprint_match_init(&m, &ref, NULL);
	kgenome_fnprint_match_feed(&m, &t.fn[0]);
	CK(m.n_strong == 1);
	kgenome_fnprint_match_done(&m);
	kgenome_fnprint_ref_free(&ref);
	kgenome_fnprint_set_free(&s, NULL); kgenome_fnprint_set_free(&t, NULL);
	fk_free(&a); fk_free(&b);
}

/*
 * A program with no main and no frontier (a Go-like runtime around a tiny author
 * part): the walk cannot separate the library, so everything is UNKNOWN and two
 * such programs that share only the runtime score alike - until a table of
 * known-library fingerprints is handed over.
 */
static void t_runtime_without_main(void)
{
	struct fk_obj a, b;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;
	uint64_t *lib;
	uint32_t i, nl = 0;
	uint32_t pm;

	fk_init(&a); fk_init(&b);
	for (i = 0; i < 400; i++) {                  /* the runtime: 400 functions both share */
		fk_func(&a, 6000 + i, 30, &V);
		fk_func(&b, 6000 + i, 30, &V);
	}
	for (i = 0; i < 5; i++) {                    /* the author part: 5 functions, different */
		fk_func(&a, 100 + i, 30, &V);
		fk_func(&b, 200 + i, 30, &V);
	}
	{
		struct kgenome_fnprint_req ra, rb;
		struct kgenome_fnprint_stat sa, sb;
		struct kgenome_func_set fa, fb;
		struct kgenome_fnprint_ref ref;
		struct kgenome_fnprint_match m;

		fk_req(&ra, &a, KGENOME_FNP_LINK_STATIC, &sa, &fa);
		fk_req(&rb, &b, KGENOME_FNP_LINK_STATIC, &sb, &fb);
		kgenome_fnprint_collect(&ra, &s);
		CK(sa.n_unknown == 405 && sa.n_author == 0);          /* the walk says it cannot tell */
		kgenome_fnprint_ref_build(&s, &ref);
		memset(&m, 0, sizeof m);
		kgenome_fnprint_match_init(&m, &ref, NULL);
		rb.visit = kgenome_fnprint_match_visit; rb.user = &m;
		kgenome_fnprint_walk(&rb);
		pm = kgenome_fnprint_match_strong_pm(&m);
		KM_CHECK(pm < 300, "two programs sharing only a runtime, no main and no frontier, do not score as similar",
			 "NO_MAIN_NO_FRONTIER_LIBRARY_NOT_SEPARABLE");
		kgenome_fnprint_match_done(&m);
		/* the table of known-library fingerprints is the answer to it */
		lib = malloc(405 * sizeof *lib);
		for (i = 0; i < 400; i++) {
			/* the runtime's own fingerprints, as a library database would hold them */
			uint32_t k;

			for (k = 0; k < s.n; k++)
				if (s.fn[k].off == a.v[i].off)
					lib[nl++] = s.fn[k].fp;
		}
		{
			uint32_t x, y;

			for (x = 0; x < nl; x++)
				for (y = x + 1; y < nl; y++)
					if (lib[y] < lib[x]) { uint64_t t = lib[x]; lib[x] = lib[y]; lib[y] = t; }
		}
		kgenome_fnprint_set_free(&s, NULL);
		kgenome_fnprint_ref_free(&ref);
		ra.hint.lib_fp = lib; ra.hint.n_lib_fp = nl;
		rb.hint.lib_fp = lib; rb.hint.n_lib_fp = nl;
		kgenome_fnprint_collect(&ra, &s);
		CK(sa.n_lib == 400 && sa.n_unknown == 5);
		kgenome_fnprint_ref_build(&s, &ref);
		memset(&m, 0, sizeof m);
		kgenome_fnprint_match_init(&m, &ref, NULL);
		rb.visit = kgenome_fnprint_match_visit; rb.user = &m;
		kgenome_fnprint_walk(&rb);
		CK(kgenome_fnprint_match_strong_pm(&m) == 0);
		kgenome_fnprint_match_done(&m);
		kgenome_fnprint_ref_free(&ref);
		kgenome_fnprint_set_free(&s, NULL);
		free(lib);
	}
	(void)rq; (void)st; (void)fs;
	fk_free(&a); fk_free(&b);
}

/* The frontier is a layout assumption: three raw-syscall helpers of the AUTHOR's own latch it, and the author code after them is called library. */
static void t_author_syscall_helpers(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;
	uint64_t e, m;
	uint32_t i;

	fk_init(&o);
	e = fk_entry(&o, 0);
	m = fk_func(&o, 1, 40, &V);
	for (i = 0; i < 3; i++)
		fk_wrapper(&o, 1 + i);                   /* the author's own inline syscall helpers */
	for (i = 0; i < 10; i++)
		fk_func(&o, 50 + i, 40, &V);             /* the rest of the author's code */
	{ int32_t d = (int32_t)((int64_t)m - (int64_t)(e + 7)); memcpy(o.b + e + 3, &d, 4); }
	fk_req(&rq, &o, KGENOME_FNP_LINK_STATIC, &st, &fs);
	rq.entry_off = e;
	kgenome_fnprint_collect(&rq, &s);
	KM_CHECK(s.fn[5].cls == KGENOME_FNP_AUTHOR,
		 "author code placed after the author's own syscall helpers is still author code",
		 "FRONTIER_IS_A_LAYOUT_ASSUMPTION");
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

int main(void)
{
	t_libc_only_sharing();
	t_junk_in_object();
	t_junk_in_reference();
	t_repeated_stubs();
	t_bogus_extents();
	t_counts_larger_than_file();
	t_hostile_inputs();
	t_weak_flood_bounded();
	t_collision_verified();
	t_runtime_without_main();
	t_author_syscall_helpers();
	printf("fnprint_danger: %s (known-miss %u)\n", hk_fails ? "FAIL" : "ok", km_known());
	return hk_fails != 0 || km_failed();
}
