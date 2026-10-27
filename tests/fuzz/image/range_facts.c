/*
 * image/range_facts - kgenome_range_xref_build, kgenome_range_facts and kgenome_xref_refs on corrupt ELF and PE objects.
 *
 * Seeds are the ELF (64 and 32 bit, executable and relocatable) and PE (PE32, PE32+) objects of tests/lib/genome/hk.h. The walk
 * builds the reference map once, then asks about ranges drawn from the iteration's seed: the whole object, each section or
 * segment, a few random ones and hostile ones (offset past the end, a length that wraps, size zero), with and without the map
 * and with a tight budget.
 * Held: the status is in the enum; BAD_INPUT only for a range outside the file; `analysed` is at most the bound and at most the
 * bytes the file holds; the percentages and the entropy are in range (decode 0..100, entropy 0..800) and the shape is one of
 * the six; counts are zero when `refs_known` is 0; the same question twice gives one answer; the map is NULL exactly when the
 * status says there is none.
 */
#include <kgenome.h>

#include "../../lib/genome/hk.h"
#include "../../lib/fuzz_drv.h"

static void seeds(struct fz_corpus *c)
{
	static struct hk_elf e[3];
	static struct hk_pe p[2];

	hk_elf(&e[0], 1, 0, 0);
	fz_corpus_add(c, "elf64", e[0].b, e[0].n);
	hk_elf(&e[1], 0, 0, 0);
	fz_corpus_add(c, "elf32", e[1].b, e[1].n);
	hk_elf(&e[2], 1, 0, 1);
	fz_corpus_add(c, "elf64rel", e[2].b, e[2].n);
	hk_pe(&p[0], 0);
	fz_corpus_add(c, "pe32", p[0].b, p[0].n);
	hk_pe(&p[1], 1);
	fz_corpus_add(c, "pe32plus", p[1].b, p[1].n);
}

struct st {
	struct kgenome_elf_info e;
	struct kgenome_pe_info  p;
	struct kgenome_obj      obj;
};

static struct st state;

static void *parse(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	kof_buf f = kof_buf_make(in, n);

	memset(&state, 0, sizeof state);
	if (kgenome_elf_image_parse(f, &state.e, &state.obj))
		return &state;
	memset(&state, 0, sizeof state);
	if (kgenome_pe_image_parse(f, &state.p, &state.obj))
		return &state;
	fz_digest(c, 0xdead);
	return NULL;
}

static uint64_t next(uint64_t *s)
{
	*s = *s * 6364136223846793005ull + 1442695040888963407ull;
	return *s ^ (*s >> 29);
}

static void ask(struct fz_ctx *c, struct kgenome_obj *obj, kof_buf f, struct kgenome_xref *map, enum kgenome_status xs,
		uint64_t off, uint64_t size, uint64_t va, const struct kgenome_budget *b)
{
	struct kgenome_range_req rq;
	struct kgenome_range_facts a, z;
	enum kgenome_status st, st2;

	memset(&rq, 0, sizeof rq);
	rq.obj = obj;
	rq.file = f;
	rq.off = off;
	rq.size = size;
	rq.va = va;
	rq.xref = map;
	rq.xref_status = xs;
	rq.budget = b;
	st = kgenome_range_facts(&rq, &a);
	st2 = kgenome_range_facts(&rq, &z);
	FZ_CHECK(c, (unsigned)st <= (unsigned)KGENOME_NOMEM && st == st2 && !memcmp(&a, &z, sizeof a), "facts: an unstable answer");
	if (off >= f.n || !size) {
		FZ_CHECK(c, st == KGENOME_BAD_INPUT && a.analysed == 0, "facts: a range outside the file was analysed");
		return;
	}
	FZ_CHECK(c, st != KGENOME_BAD_INPUT, "facts: BAD_INPUT for a range inside the file");
	FZ_CHECK(c, a.analysed <= f.n - off && a.analysed <= size, "facts: more bytes analysed than the range holds");
	FZ_CHECK(c, a.analysed <= (b && b->max_steps ? b->max_steps : KGENOME_RANGE_BYTES), "facts: more bytes than the bound");
	FZ_CHECK(c, a.decode_pct <= 100u && a.entropy_centi <= 800u, "facts: a percentage or entropy out of range");
	FZ_CHECK(c, a.shape >= KGENOME_RANGE_EMPTY && a.shape <= KGENOME_RANGE_MIXED, "facts: a shape of no kind");
	FZ_CHECK(c, a.decodes || (a.decode_pct == 0 && !a.syscall), "facts: a decode result without a decoder");
	FZ_CHECK(c, map || (!a.refs_known && !a.refs.call && !a.refs.jump && !a.refs.read && !a.refs.write && !a.refs.arg),
		 "facts: references without a map");
	fz_digest(c, a.analysed ^ ((uint64_t)a.decode_pct << 40) ^ ((uint64_t)a.entropy_centi << 48) ^ ((uint64_t)a.shape << 60) ^
		     a.refs.call ^ a.refs_ptr);
}

static void walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct st *s = (struct st *)h;
	kof_buf f = kof_buf_make(in, n);
	struct kgenome_xref *map = NULL;
	struct kgenome_budget tight;
	enum kgenome_status xs;
	uint64_t seed = c->seed * 6364136223846793005ull + 17u, base = s->obj.format == KGENOME_FMT_PE ? s->p.image_base : 0;
	unsigned i;

	xs = kgenome_range_xref_build(&s->obj, f, NULL, &map);
	FZ_CHECK(c, (unsigned)xs <= (unsigned)KGENOME_NOMEM, "xref build: status outside the enum");
	FZ_CHECK(c, (map != NULL) == (xs == KGENOME_OK || xs == KGENOME_TRUNCATED || xs == KGENOME_OVER_BUDGET),
		 "xref build: the map and the status disagree");
	memset(&tight, 0, sizeof tight);
	tight.max_steps = 1u + (uint32_t)(next(&seed) % 64u);
	if (xs != KGENOME_NOMEM) {
		struct kgenome_xref *m2 = NULL;
		enum kgenome_status x2 = kgenome_range_xref_build(&s->obj, f, &tight, &m2);

		FZ_CHECK(c, (unsigned)x2 <= (unsigned)KGENOME_NOMEM, "xref build with a budget: status outside the enum");
		kgenome_xref_free(m2);
	}
	ask(c, &s->obj, f, map, xs, 0, n, base, NULL);
	ask(c, &s->obj, f, NULL, KGENOME_OK, 0, n, base, NULL);
	ask(c, &s->obj, f, map, xs, 0, n, base, &tight);
	for (i = 0; i < 6; i++) {
		uint64_t r = next(&seed), off = r % (n + 8u), size = (r >> 20) % 300u, va = base + (r >> 32) % 0x20000u;

		fz_step(&c->steps, 1);
		if (i == 4)
			size = ~0ull - (r >> 50);          /* wraps */
		if (i == 5)
			off = ~0ull;
		ask(c, &s->obj, f, map, xs, off, size, va, NULL);
	}
	if (map) {
		struct kgenome_xref_refs z;

		kgenome_xref_refs(map, 0, 10, &z);             /* address 0 names nothing */
		FZ_CHECK(c, !z.call && !z.read && !z.write && !z.jump && !z.arg, "refs of address zero");
		kgenome_xref_refs(map, ~0ull - 3u, ~0ull, &z); /* a wrapping range: must not read outside */
	}
	kgenome_xref_free(map);
}

FZ_ADAPTER(range_facts, .name = "kgenome/range_facts",
	   .covers = "kgenome_range_xref_build kgenome_range_facts kgenome_xref_refs",
	   .shape = FZ_PARSE, .seeds = seeds, .parse = parse, .walk = walk);
