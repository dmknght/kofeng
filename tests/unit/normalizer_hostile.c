#define _GNU_SOURCE
/*
 * normalizer_hostile - the normaliser against input chosen to hurt it.
 *
 * EVERY GROUP RUNS IN A FORKED CHILD. A product that reads or writes past a
 * buffer must not take the suite down with it and must not be invisible: the
 * child dies on a signal, the parent says which group and counts a failure.
 * The buffers of the first group are mmap'd with a PROT_NONE page on both sides
 * (normalizer_ref.h, gbuf), so a single byte beyond either end is that signal -
 * input, output, spans, keep and drop maps, marks and mark answers are each
 * their own guarded buffer, exactly as long as the contract says.
 *
 *   SWEEP        every cut of generated objects (so every run is truncated at
 *                every byte, ends on the last byte, odd lengths, a payload one
 *                byte short of its anchor), through every entry point, at both
 *                alignments of the guard page, equal to the reference
 *   BIG          a one-megabyte base64 run, hex run and percent run; a million
 *                tiny runs of each; percent-of-percent
 *   BUDGET       nested percent layers 1..64 reach the work budget and say so
 *                (limit field), and never leave an object half decoded with
 *                limit zero; honest base64 layering to 40 deep is read to the
 *                bottom
 *   ALLOCATION   a table that cannot grow is reported (TABLE), not dropped -
 *                with the address space capped; skipped under the sanitiser,
 *                which cannot run capped
 *   THREADS      separate buffers on separate threads give the single-thread
 *                answer: the passes keep no writable global
 *   ARGUMENTS    NULL, zero length, offsets that do not fit in 32 or 64 bits
 */

#include <pthread.h>
#include <sys/resource.h>

#include "normalizer_ref.h"
#include "known_miss.h"

#if defined(__SANITIZE_ADDRESS__)
#define UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UNDER_ASAN 1
#endif
#endif
#ifndef UNDER_ASAN
#define UNDER_ASAN 0
#endif

/* ---- the sweep ------------------------------------------------------------ */

#define SMALL 4096u

/* Every buffer an entry point reads or writes, each guarded and each exactly as
 * long as its argument says. */
struct sweep {
	struct gbuf in, out, spans, keep, drop, marks, mout, dst;
};

static uint8_t ref_in[SMALL], ref_out[SMALL], ref_dec[SMALL];
static uint64_t ref_mout[16];

static void sweep_free(struct sweep *s)
{
	gb_free(&s->in);
	gb_free(&s->out);
	gb_free(&s->spans);
	gb_free(&s->keep);
	gb_free(&s->drop);
	gb_free(&s->marks);
	gb_free(&s->mout);
	gb_free(&s->dst);
}

static int sweep_alloc(struct sweep *s, size_t n, uint32_t nm, size_t span_cap, int tail)
{
	size_t mapn = (n + 7u) / 8u;

	memset(s, 0, sizeof *s);
	return gb_new(&s->in, n, tail) && gb_new(&s->out, n, tail) &&
	       gb_new(&s->spans, span_cap * sizeof(struct kof_exe_norm_span), tail) &&
	       gb_new(&s->keep, mapn, tail) && gb_new(&s->drop, mapn, tail) &&
	       gb_new(&s->marks, nm * sizeof(uint64_t), tail) &&
	       gb_new(&s->mout, nm * sizeof(uint64_t), tail) &&
	       gb_new(&s->dst, nm * sizeof(uint64_t), tail);
}

/* decode in place and every single pass, on the guarded input */
static int sweep_decode(struct sweep *s, const uint8_t *src, size_t n)
{
	struct kof_exe_decode_res d;
	struct nr_dec rr;
	int ch;

	memcpy(s->in.p, src, n);
	memcpy(ref_dec, src, n);
	ch = kof_exe_decode_ex(s->in.p, n, &d);
	nr_decode(ref_dec, n, &rr);
	if (n && memcmp(s->in.p, ref_dec, n))
		return 1;
	if ((ch != 0) != (rr.changed != 0) || d.rounds != rr.rounds || d.limit != rr.limit ||
	    d.scanned != rr.scanned || d.dropped != rr.dropped)
		return 2;
	memcpy(s->in.p, src, n);
	memcpy(ref_dec, src, n);
	if ((kof_exe_unb64(s->in.p, n) != 0) != (nr_unb64(ref_dec, n, 0, n, NULL) != 0))
		return 3;
	if (n && memcmp(s->in.p, ref_dec, n))
		return 3;
	memcpy(s->in.p, src, n);
	memcpy(ref_dec, src, n);
	if ((kof_exe_unhex(s->in.p, n) != 0) != (nr_unhex(ref_dec, n, 0, n, NULL) != 0))
		return 4;
	if (n && memcmp(s->in.p, ref_dec, n))
		return 4;
	return 0;
}

/* narrowing, the plain transform with a span table of a stated size, the masked
 * transform with guarded maps and marks, and the boundary table. */
static int sweep_norm(struct sweep *s, const uint8_t *src, size_t n, uint32_t nm,
		      size_t span_cap, struct nrng *r)
{
	uint64_t *marks = (uint64_t *)(void *)s->marks.p;
	uint64_t *mout = (uint64_t *)(void *)s->mout.p;
	uint64_t *dst = (uint64_t *)(void *)s->dst.p;
	struct kof_exe_norm_span *spans = (struct kof_exe_norm_span *)(void *)s->spans.p;
	uint32_t ops = 1u + nr_below(r, 3u), ns = 77, k;
	size_t i, mapn = (n + 7u) / 8u;
	uint64_t got;
	struct nr_req rq;
	struct nr_out ro;

	memcpy(s->in.p, src, n);
	{
		int changed = nr_unwide(src, n, ref_out);

		if ((kof_exe_unwide(s->in.p, n, s->out.p) != 0) != (changed != 0))
			return 1;
		if (n && memcmp(s->out.p, ref_out, n))
			return 1;
	}
	for (k = 0; k < nm; k++)
		marks[k] = k ? marks[k - 1u] + nr_below(r, (uint32_t)n / 4u + 2u)
			     : nr_below(r, (uint32_t)n + 2u);
	for (i = 0; i < mapn; i++) {
		s->keep.p[i] = nr_below(r, 4u) ? 0u : (uint8_t)nr_next(r);
		s->drop.p[i] = nr_below(r, 5u) ? 0u : (uint8_t)nr_next(r);
	}
	rq.in = src; rq.n = n; rq.keep = NULL; rq.drop = NULL; rq.ops = ops;
	rq.mark = NULL; rq.n_mark = 0;
	ro.out = ref_out; ro.mark_out = ref_mout;
	/* the plain transform, with `span_cap` entries and not one more */
	got = kof_exe_norm(s->in.p, n, ops, s->out.p, n, spans, (uint32_t)span_cap, &ns);
	(void)nr_norm(&rq, &ro);
	if (ro.n_span <= span_cap) {
		if (got != ro.len || (got && memcmp(s->out.p, ref_out, got)))
			return 2;
		if (got && ns != ro.n_span)
			return 3;
	} else if (got != 0 || ns != 0) {
		return 4;                       /* the spans did not fit: no view, no count */
	}
	free(ro.span);
	/* the masked transform: maps and marks exactly as long as stated */
	{
		const struct kof_exe_norm_req m = { s->in.p, n, s->keep.p, s->drop.p, ops, marks, nm };
		struct kof_exe_norm_res rs = { s->out.p, n, mout, 0 };

		for (k = 1; k < nm; k++)
			if (marks[k] < marks[k - 1u])
				marks[k] = marks[k - 1u];
		got = kof_exe_norm_masked(&m, &rs);
		rq.keep = s->keep.p; rq.drop = s->drop.p; rq.mark = marks; rq.n_mark = nm;
		ro.out = ref_out; ro.mark_out = ref_mout;
		(void)nr_norm(&rq, &ro);
		if (got != ro.len || rs.fired != ro.fired || (got && memcmp(s->out.p, ref_out, got)))
			return 5;
		if (n && nm && memcmp(mout, ref_mout, nm * sizeof *mout))
			return 6;
		free(ro.span);
	}
	/* the replay: the same answers for the same places (an empty object has no
	 * walk to replay - see the known miss in normalizer_transform.c) */
	kof_exe_norm_map(s->in.p, n, ops, marks, dst, nm);
	rq.keep = NULL; rq.drop = NULL;
	ro.out = ref_out; ro.mark_out = ref_mout;
	(void)nr_norm(&rq, &ro);
	if (n && nm && memcmp(dst, ref_mout, nm * sizeof *dst))
		return 7;
	free(ro.span);
	return 0;
}

static int sweep_one(const uint8_t *src, size_t n, int tail, struct nrng *r)
{
	struct sweep s;
	uint32_t nm = nr_below(r, 9u);
	size_t span_cap = n ? nr_below(r, (uint32_t)n + 2u) : 0u;
	int rc;

	if (!sweep_alloc(&s, n, nm, span_cap, tail)) {
		sweep_free(&s);
		return 99;
	}
	rc = sweep_decode(&s, src, n);
	if (!rc)
		rc = 10 * sweep_norm(&s, src, n, nm, span_cap, r);
	sweep_free(&s);
	return rc;
}

/* a generated object of one of three kinds, so the cuts land on every shape */
static size_t sweep_object(struct nrng *r, uint8_t *b, unsigned kind)
{
	size_t i, n;

	switch (kind % 3u) {
	case 0:
		return nr_mix(r, b, 480u);
	case 1:
		n = 40u + nr_below(r, 200u);
		for (i = 0; i < n; i++)
			b[i] = (uint8_t)"0123456789abcdefABCDEF%+=&\n \"'|(base64 -d"[nr_below(r, 41u)];
		return n;
	default:
		n = 40u + nr_below(r, 200u);
		for (i = 0; i < n; i++)
			b[i] = nr_below(r, 3u) ? 0u : (uint8_t)(nr_below(r, 2u) ? 0x20u + nr_below(r, 0x5f)
									  : nr_next(r));
		return n;
	}
}

static int group_sweep(void *arg)
{
	struct nrng r;
	unsigned seed, runs = 0;

	(void)arg;
	for (seed = 1; seed <= 36u; seed++) {
		size_t n, cut;

		nr_seed(&r, 0xa000u + seed);
		n = sweep_object(&r, ref_in, seed);
		for (cut = 0; cut <= n; cut++) {
			int tail;

			/* every cut of the short objects, a spread of cuts of the long */
			if (n > 160u && cut > 40u && nr_below(&r, 6u))
				continue;
			for (tail = 0; tail < 2; tail++) {
				int rc = sweep_one(ref_in, cut, tail, &r);

				NCKF(rc == 0, "seed %u cut %zu of %zu tail %d: step %d", seed, cut, n, tail,
				     rc);
				runs++;
			}
		}
	}
	NCKF(runs > 4000u, "sweep ran %u cuts", runs);
	return (int)nr_bad;
}

/* ---- big objects ------------------------------------------------------------ */

static uint8_t *big_alloc(size_t n)
{
	uint8_t *p = malloc(n);

	if (!p) {
		printf("  cannot allocate %zu bytes\n", n);
		exit(2);
	}
	return p;
}

static void big_pattern(uint8_t *b, size_t n, unsigned salt)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)(0x20u + (i * 7u + salt + (i >> 9)) % 0x5fu);
}

/* a megabyte of payload as one run in each of the three encodings */
static int group_megabyte_runs(void *arg)
{
	const size_t PL = 768u * 1024u;
	uint8_t *plain = big_alloc(PL), *obj, *want;
	char *enc = (char *)big_alloc(2u * PL + 64u);
	size_t el, n;
	struct kof_exe_decode_res d;

	(void)arg;
	big_pattern(plain, PL, 3u);
	/* base64: 1 MiB of characters (768 KiB of payload) in front of the decoder */
	el = nr_b64_enc(plain, PL, enc, 1, 0, 0);
	obj = big_alloc(el + 64u);
	want = big_alloc(el + 64u);
	n = 0;
	memcpy(obj, "echo ", 5u);
	memcpy(obj + 5u, enc, el);
	memcpy(obj + 5u + el, " | base64 -d\n", 13u);
	n = 5u + el + 13u;
	memcpy(want, obj, n);
	memcpy(want + 5u, plain, PL);
	memset(want + 5u + PL, 0, el - PL);
	NCK(el >= (1u << 20));
	NCK(kof_exe_unb64(obj, n) == 1 && !memcmp(obj, want, n));
	free(obj);
	free(want);
	/* hex: 2 * 768 KiB digits, the printable payload decodes whole */
	el = nr_hex_enc(plain, PL, enc, 0);
	obj = big_alloc(el + 8u);
	want = big_alloc(el + 8u);
	obj[0] = ' ';
	memcpy(obj + 1u, enc, el);
	obj[1u + el] = '\n';
	n = el + 2u;
	memcpy(want, obj, n);
	memcpy(want + 1u, plain, PL);
	memset(want + 1u + PL, 0, el - PL);
	NCK(kof_exe_unhex(obj, n) == 1 && !memcmp(obj, want, n));
	free(obj);
	free(want);
	/* percent: every byte that is not alphanumeric as %XX, with '+' for blanks */
	el = nr_pct_enc(plain, PL, enc, 1);
	obj = big_alloc(el + 16u);
	memcpy(obj, "q=", 2u);
	memcpy(obj + 2u, enc, el);
	obj[2u + el] = '&';
	n = el + 3u;
	{
		struct nr_dec rr;

		want = big_alloc(n);
		memcpy(want, obj, n);
		nr_decode(want, n, &rr);
		NCK(kof_exe_decode_ex(obj, n, &d) == (rr.changed != 0));
		NCK(!memcmp(obj, want, n) && d.limit == rr.limit && d.rounds == rr.rounds);
		free(want);
	}
	free(obj);
	/* percent of percent in one megabyte: "%25" * 340k decodes to "%%%..." and
	 * the second round refuses a doubled percent, so one round and no limit */
	{
		size_t k, m = 360u * 1024u;

		obj = big_alloc(3u * m + 4u);
		memcpy(obj, "q=", 2u);
		for (k = 0; k < m; k++)
			memcpy(obj + 2u + 3u * k, "%25", 3u);
		obj[2u + 3u * m] = '&';
		NCK(kof_exe_decode_ex(obj, 3u * m + 3u, &d) == 1);
		NCK(d.limit == 0 && d.rounds == 2u);
		NCK(obj[2] == '%' && obj[2u + m - 1u] == '%' && obj[2u + m] == '&' && obj[3u + m] == 0);
		free(obj);
	}
	free(plain);
	free(enc);
	return (int)nr_bad;
}

/* millions of small runs, one table entry each */
static size_t tiny_object(unsigned kind, size_t runs, uint8_t *b, size_t *unit_n, uint8_t *unit_out)
{
	static const char plain16[] = "ABCDEFGHIJKLMNOP";
	char enc[64];
	size_t el, o = 0, k, un;
	uint8_t unit[128], out_unit[128];

	switch (kind) {
	case 0:                                 /* echo <b64> | base64 -d */
		el = nr_b64_enc((const uint8_t *)plain16, 16u, enc, 1, 0, 0);
		un = 0;
		memcpy(unit, "echo ", 5u);
		memcpy(unit + 5u, enc, el);
		memcpy(unit + 5u + el, " | base64 -d\n", 13u);
		un = 5u + el + 13u;
		memcpy(out_unit, unit, un);
		memcpy(out_unit + 5u, plain16, 16u);
		memset(out_unit + 21u, 0, el - 16u);
		break;
	case 1:                                 /* a 24-digit run per line */
		el = nr_hex_enc((const uint8_t *)plain16, 12u, enc, 0);
		unit[0] = ' ';
		memcpy(unit + 1u, enc, el);
		unit[1u + el] = '\n';
		un = el + 2u;
		memcpy(out_unit, unit, un);
		memcpy(out_unit + 1u, plain16, 12u);
		memset(out_unit + 13u, 0, el - 12u);
		break;
	default:                                /* four escapes per run */
		/* a newline between runs: '&' and '=' are body bytes and would join them */
		memcpy(unit, "x=a%2Fb%2Fc%2Fd%2F\n", 19u);
		un = 19u;
		memcpy(out_unit, "x=a/b/c/d/", 10u);
		memset(out_unit + 10u, 0, 8u);
		out_unit[18] = '\n';
		break;
	}
	for (k = 0; k < runs; k++) {
		memcpy(b + o, unit, un);
		o += un;
	}
	*unit_n = un;
	memcpy(unit_out, out_unit, un);
	return o;
}

static int group_tiny_runs(void *arg)
{
	size_t runs = UNDER_ASAN ? 150000u : 1000000u, unit_n = 0, n, k;
	unsigned kind;
	uint8_t *b, uo[128];
	struct kof_exe_decode_res d;

	(void)arg;
	for (kind = 0; kind < 3u; kind++) {
		b = big_alloc(runs * 64u);
		n = tiny_object(kind, runs, b, &unit_n, uo);
		NCK(kof_exe_decode_ex(b, n, &d) == 1);
		NCKF(d.limit == 0, "kind %u: limit %u", kind, d.limit);
		/* every run was read: the object is the decoded unit, repeated */
		for (k = 0; k < runs; k += runs / 50u + 1u)
			NCKF(!memcmp(b + k * unit_n, uo, unit_n), "kind %u run %zu", kind, k);
		NCKF(!memcmp(b + (runs - 1u) * unit_n, uo, unit_n), "kind %u last run", kind);
		free(b);
	}
	return (int)nr_bad;
}

/* ---- the budget ---------------------------------------------------------------- */

/* the slashes of `S` encoded `layers` times: each layer turns '/' into "%2F" and
 * '%' into "%25", so a slash costs 2 more characters per layer and each decode
 * round peels one layer and gives back two of them. */
static size_t pct_nest(const char *s, unsigned layers, uint8_t *out, size_t cap)
{
	static uint8_t a[1u << 22], b[1u << 22];
	size_t n = strlen(s), i;
	unsigned k;

	memcpy(a, s, n);
	for (k = 0; k < layers; k++) {
		size_t o = 0;

		for (i = 0; i < n; i++) {
			if (a[i] == '/' || a[i] == '%') {
				b[o++] = '%';
				b[o++] = '2';
				b[o++] = a[i] == '/' ? 'F' : '5';
			} else {
				b[o++] = a[i];
			}
		}
		memcpy(a, b, o);
		n = o;
	}
	if (n + 8u > cap)
		return 0;
	memcpy(out, "x=", 2u);
	memcpy(out + 2u, a, n);
	out[2u + n] = '&';
	return n + 3u;
}

static int group_budget_pct_layers(void *arg)
{
	static const char S[] = "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/";
	static uint8_t obj[1u << 22], ref[1u << 22], plain[128];
	unsigned layers, first_limit = 0;
	size_t pn = pct_nest(S, 0, plain, sizeof plain);

	(void)arg;
	for (layers = 1; layers <= 64u; layers++) {
		size_t n = pct_nest(S, layers, obj, sizeof obj);
		struct kof_exe_decode_res d;
		struct nr_dec rr;
		int full;

		memcpy(ref, obj, n);
		nr_decode(ref, n, &rr);
		(void)kof_exe_decode_ex(obj, n, &d);
		NCKF(!memcmp(obj, ref, n) && d.limit == rr.limit && d.rounds == rr.rounds &&
		     d.dropped == rr.dropped && d.scanned == rr.scanned, "layers %u vs reference",
		     layers);
		/* decoded to the bottom: the plain text is where the run began (the '&'
		 * is a body byte, so it moves up with the text) */
		full = !memcmp(obj, plain, pn);
		/* NEVER SILENT: an object left with layers on it says the budget fired */
		NCKF(full || (d.limit & KOF_EXE_DEC_WORK), "layers %u: half decoded, limit %x",
		     layers, d.limit);
		NCKF(!(d.limit & KOF_EXE_DEC_WORK) || d.dropped > 0, "layers %u: limit without a count",
		     layers);
		/* and the work stays inside eight times the object */
		NCKF(d.scanned <= 8u * n, "layers %u: scanned %llu of %zu", layers,
		     (unsigned long long)d.scanned, n);
		if ((d.limit & KOF_EXE_DEC_WORK) && !first_limit)
			first_limit = layers;
		/* a limit is permanent in the sense that matters: more layers do not clear it */
		if (first_limit && layers > first_limit)
			NCKF(d.limit & KOF_EXE_DEC_WORK, "layers %u: limit went away", layers);
	}
	NCKF(first_limit >= 8u && first_limit <= 40u, "the budget first fires at %u layers",
	     first_limit);
	printf("  percent nest: the work budget first fires at %u layers\n", first_limit);
	return (int)nr_bad;
}

/* one megabyte of nested percent: bounded, and says so */
static int group_budget_big(void *arg)
{
	const size_t M = 1u << 20;
	uint8_t *obj = big_alloc(24u * M), *tmp = big_alloc(24u * M);
	size_t n, i, o;
	unsigned layers;
	struct kof_exe_decode_res d;

	(void)arg;
	/* 100k slashes, 20 layers deep: 100k * 41 bytes */
	n = 100000u;
	for (i = 0; i < n; i++)
		obj[i] = i % 2u ? 'a' : '/';
	for (layers = 0; layers < 20u; layers++) {
		for (i = 0, o = 0; i < n; i++) {
			if (obj[i] == '/' || obj[i] == '%') {
				tmp[o++] = '%';
				tmp[o++] = '2';
				tmp[o++] = obj[i] == '/' ? 'F' : '5';
			} else {
				tmp[o++] = obj[i];
			}
		}
		memcpy(obj, tmp, o);
		n = o;
	}
	memmove(obj + 2, obj, n);
	memcpy(obj, "x=", 2u);
	obj[n + 2u] = '&';
	n += 3u;
	(void)kof_exe_decode_ex(obj, n, &d);
	NCKF(d.limit & KOF_EXE_DEC_WORK, "a 100000-slash, 20-layer object: limit %x", d.limit);
	NCK(d.scanned <= 8u * n);
	NCK(d.dropped > 0);
	free(obj);
	free(tmp);
	return (int)nr_bad;
}

/* honest layering - base64 inside base64 - is read to the bottom and costs less
 * than the budget however deep it is, up to a megabyte of text. */
static int group_budget_honest(void *arg)
{
	static uint8_t a[1u << 22], b[1u << 22];
	size_t n = 13u;
	unsigned depth;

	(void)arg;
	memcpy(a, "wget http://x", n);
	for (depth = 1; depth <= 40u; depth++) {
		struct kof_exe_decode_res d;
		static char enc[1u << 21];
		size_t el = nr_b64_enc(a, n, enc, 1, 0, 0), o = 0;

		memcpy(b, "echo ", 5u);
		o = 5u;
		memcpy(b + o, enc, el);
		o += el;
		memcpy(b + o, " | base64 -d\n", 13u);
		o += 13u;
		memcpy(a, b, o);
		n = o;
		if (n > (1u << 20))
			break;
		memcpy(b, a, n);
		NCKF(kof_exe_decode_ex(b, n, &d) == 1 && d.limit == 0 && d.rounds == depth + 1u,
		     "depth %u: limit %x rounds %u", depth, d.limit, d.rounds);
		NCKF(memmem(b, n, "wget http://x", 13u) != NULL, "depth %u: not decoded to the bottom",
		     depth);
		NCKF(d.scanned < 4u * n + 4096u, "depth %u: scanned %llu of %zu", depth,
		     (unsigned long long)d.scanned, n);
	}
	NCKF(depth > 25u, "honest layering reached depth %u", depth);
	return (int)nr_bad;
}

/* ---- allocation failure -------------------------------------------------------------- */

static long vm_bytes(void)
{
	long pages = 0, rss = 0;
	FILE *f = fopen("/proc/self/statm", "r");

	if (f) {
		if (fscanf(f, "%ld %ld", &pages, &rss) != 2)
			pages = 0;
		fclose(f);
	}
	return pages * sysconf(_SC_PAGESIZE);
}

/* A million runs need a table of a million entries. With the address space held
 * to a few megabytes above what the object itself takes, the table cannot grow:
 * the pass must say so (TABLE) - the layers under what it could not remember were
 * not looked for, and a caller that ignored the field would never know. */
static int group_table_cannot_grow(void *arg)
{
	size_t runs = 300000u, unit_n = 0, n, k;
	uint8_t *b = big_alloc(runs * 80u), uo[128], *c, *plain_copy;
	struct kof_exe_decode_res d, d2;
	struct rlimit rl;
	long base;

	(void)arg;
	n = tiny_object(0, runs, b, &unit_n, uo);
	c = big_alloc(n);
	plain_copy = big_alloc(n);
	memcpy(c, b, n);
	memcpy(plain_copy, b, n);
	/* the uncapped answer, for comparison */
	(void)kof_exe_decode_ex(c, n, &d2);
	NCK(d2.limit == 0);
	base = vm_bytes();
	rl.rlim_cur = rl.rlim_max = (rlim_t)(base + (1L << 20));
	if (setrlimit(RLIMIT_AS, &rl)) {
		printf("  cannot cap the address space: group skipped\n");
		return 0;
	}
	(void)kof_exe_decode_ex(b, n, &d);
	NCKF(d.limit & KOF_EXE_DEC_TABLE, "no table limit with the address space capped (%x)",
	     d.limit);
	/* the first round still decoded every run: only what was UNDER them is lost,
	 * and the round count shows round two was cut short */
	for (k = 0; k < runs; k += 997u)
		NCKF(!memcmp(b + k * unit_n, uo, unit_n), "run %zu decoded", k);
	NCK(d.rounds <= d2.rounds);
	free(plain_copy);
	free(c);
	return (int)nr_bad;
}

/* ---- threads --------------------------------------------------------------------------- */

struct tjob {
	unsigned seed;
	uint8_t  out[6000];
	size_t   n;
	uint64_t norm_len;
	unsigned rounds;
};

static void *thread_main(void *p)
{
	struct tjob *j = p;
	struct nrng r;
	uint8_t obj[6000], v[6000];
	struct kof_exe_decode_res d;
	unsigned rep;

	for (rep = 0; rep < 30u; rep++) {
		nr_seed(&r, j->seed);
		j->n = nr_mix(&r, obj, 5000u);
		(void)kof_exe_decode_ex(obj, j->n, &d);
		j->norm_len = kof_exe_norm(obj, j->n, 3u, v, j->n, NULL, 0, NULL);
		j->rounds = d.rounds;
		memcpy(j->out, obj, j->n);
	}
	return NULL;
}

static int group_threads(void *arg)
{
	pthread_t t[8];
	static struct tjob job[8], one[8];
	unsigned k;

	(void)arg;
	for (k = 0; k < 8u; k++) {
		job[k].seed = 100u + k % 4u;                 /* pairs of threads on one object */
		one[k].seed = job[k].seed;
		thread_main(&one[k]);
	}
	for (k = 0; k < 8u; k++)
		if (pthread_create(&t[k], NULL, thread_main, &job[k]))
			return 1;
	for (k = 0; k < 8u; k++)
		pthread_join(t[k], NULL);
	for (k = 0; k < 8u; k++) {
		NCKF(job[k].n == one[k].n && !memcmp(job[k].out, one[k].out, job[k].n) &&
		     job[k].norm_len == one[k].norm_len && job[k].rounds == one[k].rounds,
		     "thread %u differs from the single-thread answer", k);
		/* threads on the same seed agree with each other */
		if (k >= 4u)
			NCK(!memcmp(job[k].out, job[k - 4u].out, job[k].n));
	}
	return (int)nr_bad;
}

/* ---- arguments --------------------------------------------------------------------------- */

static int group_arguments(void *arg)
{
	struct gbuf e, o;
	uint64_t src[8], dst[8];
	struct kof_exe_decode_res d;
	struct kof_exe_norm_span sp[2];
	uint32_t ns = 9;
	uint64_t s1;
	const uint64_t BIG32 = 1ull << 32;

	(void)arg;
	/* zero length at a guard boundary: nothing may be read or written */
	NCK(gb_new(&e, 0, 1) && gb_new(&o, 0, 1));
	NCK(kof_exe_decode(e.p, 0) == 0 && kof_exe_unb64(e.p, 0) == 0 && kof_exe_unhex(e.p, 0) == 0);
	NCK(kof_exe_decode_ex(e.p, 0, &d) == 0 && d.rounds == 0 && d.scanned == 0);
	NCK(kof_exe_unwide(e.p, 0, o.p) == 0);
	NCK(kof_exe_norm(e.p, 0, 3u, o.p, 0, sp, 2u, &ns) == 0 && ns == 0);
	{
		const struct kof_exe_norm_req rq = { e.p, 0, NULL, NULL, 3u, NULL, 0 };
		struct kof_exe_norm_res rs = { o.p, 0, NULL, 9u };

		NCK(kof_exe_norm_masked(&rq, &rs) == 0 && rs.fired == 0);
	}
	kof_exe_norm_map(e.p, 0, 3u, src, dst, 0);
	gb_free(&e);
	gb_free(&o);
	/* offsets that fit in neither 32 nor 64 bits of a real object: every place
	 * past the end answers the end of the view, whatever its magnitude */
	{
		uint8_t in[100];
		uint64_t places[8] = { 0, 99, 100, 101, BIG32 - 1u, BIG32, 1ull << 63, ~0ull };
		uint64_t view[8], outlen;
		const struct kof_exe_norm_req rq = { in, 100, NULL, NULL, KOF_EXE_NORM_NULLRUN,
						     places, 8 };
		uint8_t o2[100];
		struct kof_exe_norm_res rs = { o2, 100, view, 0 };
		uint32_t i;

		memset(in, 'a', 100);
		memset(in + 20, 0, 40);                  /* 20..59: collapses to two */
		outlen = kof_exe_norm_masked(&rq, &rs);
		NCK(outlen == 62u);
		NCK(view[0] == 0 && view[1] == 61u);
		for (i = 2; i < 8u; i++)
			NCKF(view[i] == 62u, "place %u -> %llu", i, (unsigned long long)view[i]);
		kof_exe_norm_map(in, 100, KOF_EXE_NORM_NULLRUN, places, dst, 8);
		NCK(!memcmp(dst, view, sizeof dst));
		/* marks that equal the sentinel the walk uses for "no more" */
		places[6] = ~0ull - 1u;
		places[7] = ~0ull;
		(void)kof_exe_norm_masked(&rq, &rs);
		NCK(view[6] == 62u && view[7] == 62u);
		/* unsorted marks break the contract but must not break memory */
		places[0] = 90; places[1] = 5; places[2] = 70; places[3] = 1; places[4] = 99;
		places[5] = 0; places[6] = 50; places[7] = 2;
		(void)kof_exe_norm_masked(&rq, &rs);
		/* duplicates are fine and answer alike */
		for (i = 0; i < 8u; i++)
			places[i] = i < 4u ? 30u : 61u;
		(void)kof_exe_norm_masked(&rq, &rs);
		NCK(view[0] == view[3] && view[4] == view[7] && view[4] >= view[0]);
		kof_exe_norm_map(in, 100, KOF_EXE_NORM_NULLRUN, places, dst, 8);
		NCK(!memcmp(dst, view, sizeof dst));
	}
	/* the span lookup at the far end of both spaces: no wrap, and a miss is 0 */
	memset(sp, 0, sizeof sp);
	sp[0].kind = KOF_EXE_NORM_COPY;
	sp[0].src_off = ~0ull - 50u; sp[0].src_len = 50u;
	sp[0].dst_off = BIG32; sp[0].dst_len = 50u;
	NCK(kof_exe_norm_src_of(sp, 1, BIG32 + 49u, &s1) && s1 == ~0ull - 1u);
	NCK(!kof_exe_norm_src_of(sp, 1, BIG32 - 1u, &s1) && !kof_exe_norm_src_of(sp, 1, BIG32 + 50u, &s1));
	return (int)nr_bad;
}

/* The harness itself: one byte past either end of a guarded buffer is a signal. If
 * these did not die, every "no fault" above would say nothing. */
static int bite(int tail, int past)
{
	struct gbuf g;
	volatile uint8_t x;

	signal(SIGSEGV, SIG_DFL);                /* no sanitiser report for the expected one */
	signal(SIGBUS, SIG_DFL);
	if (!gb_new(&g, 100, tail))
		return 1;
	x = past ? g.p[100] : g.p[-1];
	(void)x;
	return 0;
}

static int group_bite_end(void *arg)   { (void)arg; return bite(1, 1); }
static int group_bite_start(void *arg) { (void)arg; return bite(0, 0); }
static int group_bite_inside(void *arg)
{
	struct gbuf g;

	(void)arg;
	if (!gb_new(&g, 100, 1))
		return 1;
	memset(g.p, 1, 100);                      /* every byte in range is writable */
	return g.p[0] == 1 && g.p[99] == 1 ? 0 : 1;
}

static void harness_bites(void)
{
	int rc;

	nr_quiet = 1;
	rc = nr_group("one past the end", group_bite_end, NULL);
	NCKF(rc == 128 + SIGSEGV, "a read one past the end gave %d", rc);
	rc = nr_group("one before the start", group_bite_start, NULL);
	NCKF(rc == 128 + SIGSEGV, "a read one before the start gave %d", rc);
	nr_quiet = 0;
	NCK(nr_group("inside", group_bite_inside, NULL) == 0);
}

int main(void)
{
	struct { const char *name; nr_group_fn fn; int skip_asan; } g[] = {
		{ "guard-page sweep", group_sweep, 0 },
		{ "megabyte runs", group_megabyte_runs, 0 },
		{ "a million tiny runs", group_tiny_runs, 0 },
		{ "percent layers vs the budget", group_budget_pct_layers, 0 },
		{ "a big nested object", group_budget_big, 0 },
		{ "honest layering to the bottom", group_budget_honest, 0 },
		{ "a table that cannot grow", group_table_cannot_grow, 1 },
		{ "threads", group_threads, 0 },
		{ "arguments and far offsets", group_arguments, 0 },
	};
	unsigned i;

	harness_bites();
	for (i = 0; i < sizeof g / sizeof g[0]; i++) {
		int rc;

		if (g[i].skip_asan && UNDER_ASAN) {
			printf("  group '%s' skipped: the sanitiser cannot run with the address space capped\n",
			       g[i].name);
			continue;
		}
		rc = nr_group(g[i].name, g[i].fn, NULL);
		NCKF(rc == 0, "group '%s' returned %d", g[i].name, rc);
	}
	printf("normalizer_hostile: %u checks, %u failed, %u known miss(es)\n", nr_ok + nr_bad,
	       nr_bad, km_known());
	return nr_bad != 0 || km_failed();
}
