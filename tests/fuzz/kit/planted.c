/*
 * kit/planted - the kit's own self-test: adapters with a defect planted on purpose, which the harness must catch, and good
 * adapters (the seams, the limits) it must not. `fuzz_kit --selftest` runs the planted rows and fails when one is MISSED.
 * A planted defect fires only at iteration 1, so a run costs one dead child.
 *   plant_overread   reads the byte after the exact-size input: the guard page faults (every build)
 *   plant_overwrite  writes the byte after the exact-size output buffer (every build)
 *   plant_heap       a heap overflow of one byte: only AddressSanitizer sees it (registered only in an ASAN build)
 *   plant_alloc      allocates without end: the allocation cap must answer and be reported
 *   plant_cpu        a loop that never checks its step counter: the counter bound must be reported
 *   plant_hang       a loop that never ends: the backstop must kill it and attribute it
 *   plant_sink       ignores the refusal of its sink: "called again after it refused"
 *   plant_leak       forgets to free: the net allocation after the call must be reported
 *   plant_nondet     a result that depends on a counter outside the input: determinism must fail
 * With -DFZ_MUTANT_SINK_NEVER_REFUSES or -DFZ_MUTANT_NO_STEPS the DRIVER is broken instead (fuzz_drv.c), and the self-test must
 * fail: that is the proof that the sink-refusal path and the work counter are what catch plant_sink and plant_cpu.
 */
#include "../../lib/fuzz_drv.h"

#define PLANT_AT 1u

static void seeds(struct fz_corpus *c)
{
	uint8_t b[256];
	size_t i;

	for (i = 0; i < sizeof b; i++)
		b[i] = (uint8_t)(i * 7u + 3u);
	fz_corpus_add(c, "a", b, sizeof b);
	fz_corpus_add(c, "b", b, 64);
	fz_corpus_add(c, "c", b, 200);
}

static int overread(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	volatile uint8_t x = c->iter == PLANT_AT ? in[n] : 0;

	fz_digest(c, x);
	return 0;
}
FZ_ADAPTER(plant_overread, .name = "kit/plant_overread", .shape = FZ_REQ, .flags = FZ_PLANTED, .expect = "crash", .seeds = seeds, .run = overread);

static int overwrite(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	(void)in; (void)n;
	if (c->iter == PLANT_AT)
		*(volatile uint8_t *)(c->out + c->cap) = 1;
	return 0;
}
FZ_ADAPTER(plant_overwrite, .name = "kit/plant_overwrite", .shape = FZ_BYTES, .flags = FZ_PLANTED, .expect = "crash", .seeds = seeds, .run = overwrite);

#if FZ_ASAN
static int heap(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint8_t *p = (uint8_t *)malloc(n + 8u);

	(void)in;
	if (p) {
		memset(p, 1, n + 8u + (c->iter == PLANT_AT));   /* one byte past the block: ASAN's memset check */
		fz_digest(c, p[0]);
		free(p);
	}
	return 0;
}
FZ_ADAPTER(plant_heap, .name = "kit/plant_heap", .shape = FZ_REQ, .flags = FZ_PLANTED, .expect = "crash", .seeds = seeds, .run = heap);
#endif

static int alloc_inf(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	void *p;

	(void)in; (void)n;
	if (c->iter != PLANT_AT)
		return 0;
	while ((p = malloc(1u << 20)) != NULL)
		memset(p, 1, 16);        /* never freed */
	return 0;
}
FZ_ADAPTER(plant_alloc, .name = "kit/plant_alloc", .shape = FZ_REQ, .flags = FZ_PLANTED | FZ_NO_FAILK, .expect = "allocation cap", .seeds = seeds, .run = alloc_inf);

static int cpu_loop(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t i;

	(void)in; (void)n;
	if (c->iter != PLANT_AT)
		return 0;
	for (i = 0; i < 20000000u; i++)
		fz_step(&c->steps, 1);   /* counted, never checked: a loop that cannot stop itself */
	return 0;
}
FZ_ADAPTER(plant_cpu, .name = "kit/plant_cpu", .shape = FZ_REQ, .flags = FZ_PLANTED | FZ_NO_FAILK, .expect = "work bound", .seeds = seeds, .run = cpu_loop);

static int hang(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	(void)in; (void)n;
	if (c->iter == PLANT_AT)
		for (;;)
			__asm__ volatile ("");
	return 0;
}
FZ_ADAPTER(plant_hang, .name = "kit/plant_hang", .shape = FZ_REQ, .flags = FZ_PLANTED | FZ_NO_FAILK, .expect = "hang", .backstop_s = 1, .seeds = seeds, .run = hang);

/* The refusal path: the good form stops, the planted form keeps pushing. */
static int sink_good(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	size_t at = 0;

	while (at < n) {
		uint32_t l = n - at < 8 ? (uint32_t)(n - at) : 8u;

		if (!c->sink_fn(c->sink_user, in + at, l))
			break;
		at += l;
	}
	fz_digest(c, at);
	return 0;
}
FZ_ADAPTER(sink_good, .name = "kit/sink_good", .shape = FZ_BYTES, .seeds = seeds, .run = sink_good);

static int sink_bad(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	size_t at = 0;
	unsigned refusals = 0;

	while (at < n) {
		uint32_t l = n - at < 8 ? (uint32_t)(n - at) : 8u;

		refusals += !c->sink_fn(c->sink_user, in + at, l);   /* the answer is ignored: the plant */
		at += l;
	}
	fz_digest(c, refusals);
	return 0;
}
FZ_ADAPTER(plant_sink, .name = "kit/plant_sink", .shape = FZ_BYTES, .flags = FZ_PLANTED, .expect = "called again", .seeds = seeds, .run = sink_bad);

static int leak(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	void *p = malloc(n + 100u);

	(void)in;
	fz_digest(c, p != NULL);
	if (c->iter == PLANT_AT)
		return 0;                 /* the plant: not freed */
	free(p);
	return 0;
}
FZ_ADAPTER(plant_leak, .name = "kit/plant_leak", .shape = FZ_REQ, .flags = FZ_PLANTED | FZ_NO_FAILK, .expect = "leak", .seeds = seeds, .run = leak);

static int nondet(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static unsigned calls;

	(void)in; (void)n;
	fz_digest(c, c->iter == PLANT_AT ? ++calls : 0);
	return 0;
}
FZ_ADAPTER(plant_nondet, .name = "kit/plant_nondet", .shape = FZ_REQ, .flags = FZ_PLANTED | FZ_NO_FAILK, .expect = "nondeterministic", .seeds = seeds, .run = nondet);
