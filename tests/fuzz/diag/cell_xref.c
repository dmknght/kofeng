/*
 * diag/cell_xref - the cursor over code (celllysis), the cross-reference sweep, the code map and the library-span lines, over the
 * ELF and PE objects the diag seeds build (the same parse as scan_bin).
 *
 * Held:
 *   CURSOR   a walk makes progress and stays inside the object: after kgenome_cell_next answers 1 the cursor is past the instruction
 *            (at = insn.at + len), len is 1..16, and kgenome_cell_reg answers 0 or 1 (the branch target's bound is finding F4, below);
 *            DIFFERENTIAL: kgenome_cell_step (no register map) decodes the same instructions at the same places as kgenome_cell_next -
 *            tracking values must not change what is decoded
 *   XREF     the flags of a range have only bits that exist; asking twice is the same answer (idempotent); a range of length zero and
 *            a range past the address space do not fault; the sweep fed by the cursor and the sweep fed by the code run agree
 *   CODEMAP  refs are in order of `at`, strictly; every ref is inside the object; kgenome_codemap_at finds exactly the refs there are
 *            and nothing else; by_to is ordered by (to, at) and kgenome_codemap_to counts exactly the refs with that target
 *            (ORACLE: a linear count); a ref with a target has it inside the object or KGENOME_BROKEN
 *   TRUELINE every span is inside the file, at most the cap of spans, a list that says sorted is sorted; kgenome_true_touches against a
 *            linear ORACLE over the spans (128-bit arithmetic, so that the wrap rule of the library is checked, not assumed) on the
 *            library's own lists and on lists built from the bytes, sorted and not
 */
#include "diag_seed.h"

#include <celllysis/xref.h>
#include <celllysis/trueline.h>
#include <phenotype/codemap.h>
#include <phenotype/diag_private.h>

static void run_cursor(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n)
{
	struct kgenome_cell_space sp;
	struct kgenome_cell_cur k1, k2;
	struct kgenome_cell_insn i1, i2;
	uint64_t off = n ? fz_below(c->rng, n) : 0;
	unsigned steps;
	uint64_t h = 0;

	memset(&sp, 0, sizeof sp);
	kgenome_cell_space_init(&sp, obj, in, n);
	memset(&k1, 0, sizeof k1);
	memset(&k2, 0, sizeof k2);
	(void)kgenome_cell_seek(&k1, off, 0);
	(void)kgenome_cell_seek(&k2, off, 0);
	for (steps = 0; steps < 3000u; steps++) {
		uint64_t before = k1.at, v = 0;
		int r1, r2;
		uint8_t reg;

		memset(&i1, 0, sizeof i1);
		memset(&i2, 0, sizeof i2);
		r1 = kgenome_cell_next(&k1, &sp, &i1);
		r2 = kgenome_cell_step(&k2, &sp, &i2);
		fz_step(&c->steps, 1);
		FZ_CHECK(c, (r1 != 0) == (r2 != 0), "kgenome_cell_next and kgenome_cell_step disagree on whether there is an instruction");
		if (!r1 || !r2)
			break;
		FZ_CHECK(c, i1.len >= 1 && i1.len <= 16, "an instruction of length outside 1..16");
		FZ_CHECK(c, i1.at == before, "the instruction is not where the cursor was");
		FZ_CHECK(c, k1.at == i1.at + i1.len, "the cursor did not advance by the instruction's length");
		FZ_CHECK(c, k1.at <= n, "the cursor left the object");
		/* F4: a branch target is NOT asserted to lie inside the buffer. The cursor maps an address through the segment or section the header
		 * names, and a header whose size is past the file (or an ELF with no program header, read as one flat space) gives a target past the
		 * bytes that was never BROKEN (tests/lib/genome/diag_cell_target_bound.c holds the row). The digest takes it, so a change shows. */
		h = (h ^ (i1.target == KGENOME_BROKEN || i1.target < n ? 0u : 0x5a5au)) * 0x100000001b3ull;
		FZ_CHECK(c, i1.len == i2.len && i1.at == i2.at && i1.op == i2.op && i1.wmask == i2.wmask,
			 "DIFFERENTIAL: step decoded something other than next");
		for (reg = 0; reg < 32u; reg += 5u) {
			int got = kgenome_cell_reg(&k1, reg, &v);

			FZ_CHECK(c, got == 0 || got == 1, "kgenome_cell_reg answered outside 0/1");
			h = (h ^ v ^ (uint64_t)(unsigned)got) * 0x100000001b3ull;
		}
		h = (h ^ i1.at ^ ((uint64_t)i1.op << 40) ^ ((uint64_t)i1.len << 48)) * 0x100000001b3ull;
	}
	fz_digest(c, h);
}

static void run_xref(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n)
{
	struct kgenome_xref *a = kgenome_xref_new(), *b = kgenome_xref_new();
	struct kgenome_cell_space sp;
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn ins;
	struct kgenome_diag_code_req rq;
	unsigned steps;
	uint64_t va = 0x400000u + fz_below(c->rng, n + 1u), len = fz_below(c->rng, 4) ? fz_below(c->rng, 4096) : 0;

	if (!a || !b) {
		if (a) kgenome_xref_free(a);
		if (b) kgenome_xref_free(b);
		return;
	}
	kgenome_xref_begin(a, obj->arch);
	kgenome_xref_begin(b, obj->arch);
	memset(&sp, 0, sizeof sp);
	memset(&k, 0, sizeof k);
	kgenome_cell_space_init(&sp, obj, in, n);
	(void)kgenome_cell_seek(&k, 0, 0);
	for (steps = 0; steps < 4000u; steps++) {
		memset(&ins, 0, sizeof ins);
		if (!kgenome_cell_step(&k, &sp, &ins))
			break;
		kgenome_xref_feed(a, &ins);
		fz_step(&c->steps, 1);
	}
	kgenome_xref_feed(a, NULL);
	memset(&rq, 0, sizeof rq);
	rq.obj = obj; rq.base = in; rq.size = n; rq.off = 0; rq.n = n; rq.va = 0x400000u;
	rq.fn = kgenome_xref_feed; rq.user = b;
	kgenome_diag_code_run(&rq);
	{
		uint32_t f1 = kgenome_xref_in(a, va, len), f2 = kgenome_xref_in(a, va, len);

		FZ_CHECK(c, f1 == f2, "kgenome_xref_in is not idempotent");
		FZ_CHECK(c, (f1 & ~0x1ffu) == 0, "a flag bit that does not exist");
		FZ_CHECK(c, (kgenome_xref_in(a, UINT64_MAX - 3u, 100u) & ~0x1ffu) == 0, "a range past the address space has an impossible flag");
		(void)kgenome_xref_in(a, 0, 0);
		(void)kgenome_xref_full(a);
		(void)kgenome_xref_full(b);
		(void)kgenome_xref_startup(a, va);
		(void)kgenome_xref_startup(b, va);
		fz_digest(c, f1 + ((uint64_t)kgenome_xref_in(b, va, len) << 16));
	}
	kgenome_xref_free(a);
	kgenome_xref_free(b);
	kgenome_xref_free(NULL);
}

static void run_codemap(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n)
{
	struct kgenome_codemap m;
	uint32_t i;
	int ordered = 1;

	memset(&m, 0, sizeof m);
	if (!kgenome_codemap_build(obj, in, n, NULL, &m)) {
		fz_digest(c, 0xc0de);
		kgenome_codemap_free(&m);
		return;
	}
	FZ_CHECK(c, (unsigned)m.status <= (unsigned)KGENOME_NOMEM, "codemap status outside the enum");
	FZ_CHECK(c, m.n_to <= m.n, "more targeted refs than refs");
	/* F5: the refs are appended extent by extent in the object's own order, so they are in order of `at` only when the extents ascend and do
	 * not overlap (tests/lib/genome/diag_codemap_extents.c): the order is asserted for such objects, and counted for the others. */
	{
		uint32_t ne = kgenome_diag_extent_count(obj), x;
		uint64_t prev_end = 0;

		for (x = 0; x < ne; x++) {
			uint64_t at = 0, len = kgenome_diag_extent(obj, x, n, &at);

			if (!len)
				continue;
			if (at < prev_end)
				ordered = 0;
			prev_end = at + len;
		}
	}
	for (i = 0; i < m.n; i++) {
		const struct kgenome_codemap_ref *r = &m.v[i];

		FZ_CHECK(c, r->at < n, "a ref outside the object");
		FZ_CHECK(c, !ordered || i == 0 || m.v[i - 1u].at < r->at, "refs are not in strictly ascending order of at");
		FZ_CHECK(c, r->kind >= KGENOME_CM_JMP && r->kind <= KGENOME_CM_SYSCALL, "a ref kind outside the enum");
		FZ_CHECK(c, r->len >= 1 && r->len <= 16, "a ref of length outside 1..16");
		if (ordered)
			FZ_CHECK(c, kgenome_codemap_at(&m, r->at) == r, "kgenome_codemap_at does not find a ref that is there");
		FZ_CHECK(c, r->to == KGENOME_BROKEN || r->to < n || r->kind == KGENOME_CM_RET || r->kind == KGENOME_CM_SYSCALL, "a target outside the object that is not BROKEN");
		if (ordered && i < 4096u && i % 7u == 0 && r->to != KGENOME_BROKEN && r->kind != KGENOME_CM_RET && r->kind != KGENOME_CM_SYSCALL) {
			uint32_t first = 0, cnt = kgenome_codemap_to(&m, r->to, &first), j, oracle = 0;

			for (j = 0; j < m.n && j < 8192u; j++)
				oracle += m.v[j].to == r->to && m.v[j].kind != KGENOME_CM_RET && m.v[j].kind != KGENOME_CM_SYSCALL;
			FZ_CHECK(c, cnt >= 1u, "a target a ref has is not found by kgenome_codemap_to");
			if (m.n <= 8192u)
				FZ_CHECK(c, cnt == oracle, "ORACLE: kgenome_codemap_to counts another number of refs than a linear count");
			FZ_CHECK(c, first + cnt <= m.n_to, "the by_to window leaves the table");
		}
		fz_digest(c, r->at + ((uint64_t)r->kind << 56));
	}
	for (i = 1; i < m.n_to; i++) {
		const struct kgenome_codemap_ref *p = &m.v[m.by_to[i - 1u]], *q = &m.v[m.by_to[i]];

		FZ_CHECK(c, p->to < q->to || (p->to == q->to && p->at <= q->at), "by_to is not ordered by (to, at)");
	}
	{
		uint32_t first = 0;

		(void)kgenome_codemap_at(&m, n + 5u);
		(void)kgenome_codemap_to(&m, UINT64_MAX, &first);
		(void)kgenome_codemap_to(&m, KGENOME_BROKEN, &first);
	}
	kgenome_codemap_free(&m);
}

static int oracle_touch(const struct kgenome_true_all *l, uint64_t off, uint64_t len)
{
	uint32_t i;

	if (!len)
		return 0;
	for (i = 0; i < l->n; i++) {
		unsigned __int128 so = l->span[i].off, sl = l->span[i].len, o = off, ln = len, end = so + sl;

		if (end > UINT64_MAX)               /* the library's rule: a span that ends past the address space ends at its last byte */
			end = UINT64_MAX;
		if (sl && so < o + ln && o < end)
			return 1;
	}
	return 0;
}

/* the end of a span the way the library reads it: a span that runs past the address space ends at its last byte */
static uint64_t span_end(const struct kof_range *r)
{
	uint64_t e = r->off + r->len;

	return e < r->off ? UINT64_MAX : e;
}

static int span_cmp(const void *a, const void *b)
{
	const struct kof_range *x = (const struct kof_range *)a, *y = (const struct kof_range *)b;

	return x->off != y->off ? (x->off < y->off ? -1 : 1) : (x->len < y->len ? -1 : x->len > y->len);
}

static void check_all(struct fz_ctx *c, const struct kgenome_true_all *a, uint64_t n, int from_lib)
{
	uint32_t i;
	unsigned t;

	FZ_CHECK(c, a->n <= KGENOME_TRUE_MAX_SPANS_ALL, "more spans than the cap");
	for (i = 0; i < a->n && i < KGENOME_TRUE_MAX_SPANS_ALL; i++) {
		if (from_lib)
			FZ_CHECK(c, a->span[i].off <= n && a->span[i].len <= n - a->span[i].off, "a library span outside the file");
		if (a->sorted && i)
			FZ_CHECK(c, a->span[i - 1u].off <= a->span[i].off && span_end(&a->span[i - 1u]) <= span_end(&a->span[i]),
				 "a list that says sorted is not sorted with non-decreasing ends");
	}
	for (t = 0; t < 24u; t++) {
		uint64_t off = t < 8u && a->n ? a->span[fz_below(c->rng, a->n)].off + fz_below(c->rng, 3) - 1u : fz_below(c->rng, n + 8u);
		uint64_t len = t % 5u == 0 ? 0 : t % 5u == 1 ? UINT64_MAX : 1u + fz_below(c->rng, 64);

		FZ_CHECK(c, (kgenome_true_touches(a, off, len) != 0) == (oracle_touch(a, off, len) != 0),
			 "ORACLE: kgenome_true_touches disagrees with the linear overlap test");
	}
}

static void run_trueline(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n)
{
	static struct kgenome_true_result r;
	static struct kgenome_true_all a, b, h;
	const struct kgenome_elf_info *e = obj->format == KGENOME_FMT_ELF ? kgenome_obj_elf(obj) : NULL;
	uint32_t i;

	kgenome_true_find(kof_buf_make(in, n), e, &r);
	FZ_CHECK(c, r.n <= KGENOME_TRUE_MAX_SPANS, "more spans than the cap (find)");
	for (i = 0; i < r.n && i < KGENOME_TRUE_MAX_SPANS; i++)
		FZ_CHECK(c, r.span[i].off <= n && r.span[i].len <= n - r.span[i].off, "a marker span outside the file");
	kgenome_true_find_all(kof_buf_make(in, n), e, &a);
	check_all(c, &a, n, 1);
	kgenome_true_find_object(kof_buf_make(in, n), e, &b);
	check_all(c, &b, n, 1);
	if (e && a.n)
		(void)kgenome_true_has_addr(e, &a, 0x400078u, 4);
	(void)kgenome_true_has_addr(e, &b, UINT64_MAX, 8);
	/* lists built from the bytes: random spans, then the same sorted */
	memset(&h, 0, sizeof h);
	h.n = (uint32_t)fz_below(c->rng, 40);
	for (i = 0; i < h.n; i++) {
		h.span[i].off = fz_below(c->rng, 8) ? fz_below(c->rng, 4096) : UINT64_MAX - fz_below(c->rng, 64);
		h.span[i].len = fz_below(c->rng, 8) ? 1u + fz_below(c->rng, 256) : UINT64_MAX - fz_below(c->rng, 64);
	}
	check_all(c, &h, n, 0);
	qsort(h.span, h.n, sizeof h.span[0], span_cmp);
	{
		int ok = 1;

		for (i = 1; i < h.n; i++)
			if (span_end(&h.span[i - 1u]) > span_end(&h.span[i]))
				ok = 0;
		h.sorted = (uint8_t)ok;
	}
	check_all(c, &h, n, 0);
	fz_digest(c, a.n + ((uint64_t)b.n << 16) + ((uint64_t)r.n << 32));
}

static void walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	const struct kgenome_obj *obj = &((struct diag_st *)h)->obj;

	run_cursor(c, obj, in, n);
	run_xref(c, obj, in, n);
	run_codemap(c, obj, in, n);
	run_trueline(c, obj, in, n);
}

static int run_code(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	const uint8_t *img;
	size_t total;
	struct diag_st *st = diag_wrap_code(c, in, n, &img, &total);

	if (!st)
		return n < 2 ? 1 : 2;
	run_cursor(c, &st->obj, img, total);
	run_xref(c, &st->obj, img, total);
	run_codemap(c, &st->obj, img, total);
	run_trueline(c, &st->obj, img, total);
	return 0;
}

FZ_ADAPTER(cell_xref_code, .name = "kgenome/diag_cell_xref_code", .covers = "", .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000,
	   .steps_base = 1000000u, .steps_per_byte = 64, .shape = FZ_REQ, .seeds = diag_seeds_code, .dict = diag_dict_code, .run = run_code);

FZ_ADAPTER(cell_xref, .name = "kgenome/diag_cell_xref",
	   .covers = "kgenome_cell_seek kgenome_cell_next kgenome_cell_step kgenome_cell_reg kgenome_cell_space_init "
		     "kgenome_xref_new kgenome_xref_begin kgenome_xref_feed kgenome_xref_in kgenome_xref_full kgenome_xref_startup kgenome_xref_free "
		     "kgenome_codemap_build kgenome_codemap_free kgenome_codemap_at kgenome_codemap_to "
		     "kgenome_true_find kgenome_true_find_all kgenome_true_find_object kgenome_true_touches kgenome_true_has_addr",
	   .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000, .steps_base = 1000000u, .steps_per_byte = 64,
	   .shape = FZ_PARSE, .seeds = diag_seeds_bin, .dict = diag_dict_bin, .parse = diag_parse_bin, .walk = walk);
