/*
 * fuzz_drv.c - the driver of the fuzz binaries: the allocation wrap, the adapter registry, the per-shape drivers and main().
 * Linked ONLY by the fuzz binaries (mk/fuzz.mk), which pass -Wl,--wrap=malloc,calloc,realloc,free,posix_memalign,mmap.
 * See fuzz_kit.h for the kit and fuzz_drv.h for how a row is written.
 *
 * One adapter runs in ONE forked child for all its iterations (fork per RUN, not per call: the PoC did 2 M
 * iterations a second in-process under ASAN+UBSAN). The child writes each case into the mailbox first, so a crash,
 * a hang or an RSS kill is attributed to adapter + iteration + seed, the input is saved, and the parent starts a
 * new child at iteration + 1.
 */
#include "fuzz_drv.h"

#include <malloc.h>

/* ---- the allocation wrap -------------------------------------------------------------------------------- */

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
int __real_posix_memalign(void **pp, size_t al, size_t n);
void *__real_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);
void __wrap_free(void *p);
int __wrap_posix_memalign(void **pp, size_t al, size_t n);
void *__wrap_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);

static struct {
	int                 armed;
	volatile char       lock;
	struct fz_alloc_cfg cfg;
	uint64_t            calls, bytes, refused, peak;
	int64_t             live;
	int                 hit;
} al;

static void al_lock(void)
{
	while (__atomic_test_and_set(&al.lock, __ATOMIC_ACQUIRE))
		;
}

static void al_unlock(void)
{
	__atomic_clear(&al.lock, __ATOMIC_RELEASE);
}

/* 1 when the call may go on. The bytes of a call the caps refuse are not charged. */
static int al_charge_ex(size_t n, int live_too)
{
	int ok = 1;

	if (!__atomic_load_n(&al.armed, __ATOMIC_RELAXED))
		return 1;
	al_lock();
	if (al.armed) {
		al.calls++;
		if (al.cfg.fail_k && al.calls == al.cfg.fail_k) {
			al.refused++;
			ok = 0;
		} else if ((al.cfg.max_calls && al.calls > al.cfg.max_calls) || n > al.cfg.call_cap || al.bytes + n > al.cfg.total_cap) {
			al.refused++;
			al.hit = 1;
			ok = 0;
		} else {
			al.bytes += n;
			if (live_too) {
				al.live += (int64_t)n;
				if (al.live > 0 && (uint64_t)al.live > al.peak)
					al.peak = (uint64_t)al.live;
			}
		}
	}
	al_unlock();
	return ok;
}

static int al_charge(size_t n)
{
	return al_charge_ex(n, 1);
}

static void al_release(void *p)
{
	if (p && __atomic_load_n(&al.armed, __ATOMIC_RELAXED)) {
		size_t u = malloc_usable_size(p);

		al_lock();
		al.live -= (int64_t)u;
		al_unlock();
	}
}

void *__wrap_malloc(size_t n)
{
	return al_charge(n) ? __real_malloc(n) : NULL;
}

void *__wrap_calloc(size_t a, size_t b)
{
	if (b && a > SIZE_MAX / b)
		return NULL;
	return al_charge(a * b) ? __real_calloc(a, b) : NULL;
}

void *__wrap_realloc(void *p, size_t n)
{
	void *q;

	if (!al_charge(n))
		return NULL;
	if (p && n)
		al_release(p);
	q = __real_realloc(p, n);
	return q;
}

void __wrap_free(void *p)
{
	al_release(p);
	__real_free(p);
}

int __wrap_posix_memalign(void **pp, size_t al_, size_t n)
{
	return al_charge(n) ? __real_posix_memalign(pp, al_, n) : ENOMEM;
}

void *__wrap_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	/* an anonymous mapping is capped (total, per call, k-th) but not counted as live: munmap is not wrapped */
	if ((flags & MAP_ANONYMOUS) && !al_charge_ex(len, 0)) {
		errno = ENOMEM;
		return MAP_FAILED;
	}
	return __real_mmap(addr, len, prot, flags, fd, off);
}

void fz_alloc_arm(const struct fz_alloc_cfg *cfg)
{
	al_lock();
	al.cfg = *cfg;
	al.calls = al.bytes = al.refused = al.peak = 0;
	al.live = 0;
	al.hit = 0;
	al.armed = 1;
	al_unlock();
}

void fz_alloc_disarm(struct fz_alloc_stats *out)
{
	al_lock();
	al.armed = 0;
	if (out) {
		out->calls = al.calls;
		out->bytes = al.bytes;
		out->peak_live = al.peak;
		out->refused = al.refused;
		out->net = al.live;
		out->hit = al.hit;
	}
	al_unlock();
}

#if FZ_ASAN
/* The sanitised run's own ceilings (the plan measured each of them): a huge request is refused, not fatal, and a runaway
 * resident size is stopped. In the CHILD the watcher thread does not survive fork, so fz_isolate also polls the RSS. */
const char *__asan_default_options(void);
const char *__asan_default_options(void)
{
	return "detect_leaks=1:abort_on_error=0:allocator_may_return_null=1:max_allocation_size_mb=256:hard_rss_limit_mb=2048";
}
#endif

/* ---- the registry ---------------------------------------------------------------------------------------- */

#define FZ_MAX_ADAPTERS 256u
static const struct fz_adapter *registry[FZ_MAX_ADAPTERS];
static size_t n_registry;

void fz_register(const struct fz_adapter *ad)
{
	if (n_registry < FZ_MAX_ADAPTERS)
		registry[n_registry++] = ad;
	else {
		fprintf(stderr, "fuzz: more than %u adapters\n", FZ_MAX_ADAPTERS);
		abort();
	}
}

static int cmp_adapter(const void *a, const void *b)
{
	return strcmp((*(const struct fz_adapter *const *)a)->name, (*(const struct fz_adapter *const *)b)->name);
}

/* ---- one run of one adapter ------------------------------------------------------------------------------- */

#define WORK_CAP (1u << 20)
#define OUT_CAP (1u << 20)
#define FZ_CANARY 64u
#define NHIST 16u

struct fz_shared {
	uint64_t digest, done, cap_hits, failk_runs, hist[NHIST];
	char     why[120];
};

struct fz_run {
	const struct fz_opts    *o;
	const struct fz_adapter *ad;
	unsigned                 idx, start, end;
	struct fz_shared        *sh;
};

static void save_input(const struct fz_opts *o, const char *name, unsigned iter, const uint8_t *in, size_t n)
{
	char path[512], flat[80];
	size_t i;
	FILE *f;

	snprintf(flat, sizeof flat, "%s", name);
	for (i = 0; flat[i]; i++)
		if (flat[i] == '/')
			flat[i] = '_';
	(void)mkdir(o->out, 0755);
	snprintf(path, sizeof path, "%s/%s_%u.bin", o->out, flat, iter);
	f = fopen(path, "wb");
	if (f) {
		if (n)
			(void)fwrite(in, 1, n, f);
		fclose(f);
		printf("  input saved: %s (%zu bytes)\n", path, n);
	}
}

/* The sink the driver gives FZ_BYTES: a receiver with an exact capacity (it refuses what would not fit), a quota, and the
 * rule that it is not called again once it said no. It copies what it accepts into the guard buffer. */
static int drv_sink(void *user, const uint8_t *p, uint32_t n)
{
	struct fz_ctx *c = (struct fz_ctx *)user;
	uint64_t at = c->sink.total;

	fz_step(&c->steps, 1);
	if (c->refused)
		c->after_refusal++;
#ifdef FZ_MUTANT_SINK_NEVER_REFUSES
	if (c->sink.total + n > c->cap)
		return 1;                       /* the mutant: the receiver accepts everything and keeps nothing */
#else
	if (c->sink.total + n > c->cap) {
		c->refused = 1;
		c->sink.refused_calls++;
		return 0;
	}
#endif
	if (!fz_sink_fn(&c->sink, p, n)) {
		c->refused = 1;
		return 0;
	}
	if (n)
		memcpy(c->out + at, p, n);
	return 1;
}

struct fz_gbs {
	struct fz_gb in, out;
};

static void ctx_init(struct fz_ctx *c, struct fz_rng *rng, uint64_t seed, unsigned iter, const struct fz_adapter *ad, size_t n, size_t cap)
{
	memset(c, 0, sizeof *c);
	c->rng = rng;
	c->seed = seed;
	c->iter = iter;
	c->steps.cap = (ad->steps_base ? ad->steps_base : 1000000u) + (ad->steps_per_byte ? ad->steps_per_byte : 64u) * n;
	c->cap = cap;
	c->sink_fn = drv_sink;
	c->sink_user = c;
}

/* One call of the adapter on `in`, under the allocation caps. Returns the status the adapter answered. */
static int call_shape(const struct fz_adapter *ad, struct fz_ctx *c, struct fz_gbs *g, const uint8_t *in, size_t n, uint64_t quota)
{
	int st = 0;
	size_t i;

	switch (ad->shape) {
	case FZ_BYTES:
		c->out = fz_gb_end(&g->out, c->cap);
		memset(c->out - FZ_CANARY, 0xA5, FZ_CANARY);
		memset(c->out, 0xCC, c->cap);
	#ifdef FZ_MUTANT_SINK_NEVER_REFUSES
	(void)quota;
#else
		c->sink.refuse_at = quota;
#endif
		st = ad->run(c, in, n);
		for (i = 1; i <= FZ_CANARY; i++)
			if (c->out[-(ptrdiff_t)i] != 0xA5) {
				FZ_CHECK(c, 0, "wrote before the output buffer");
				break;
			}
		FZ_CHECK(c, c->sink.total <= c->cap, "sink accepted more than its capacity");
		if (!(ad->flags & FZ_POST_REFUSAL))
			FZ_CHECK(c, c->after_refusal == 0, "sink called again after it refused");
		break;
	case FZ_REQ:
		st = ad->run(c, in, n);
		break;
	case FZ_PARSE: {
		void *h = ad->parse(c, in, n);

		if (h) {
			ad->walk(c, h, in, n);
			if (ad->drop)
				ad->drop(h);
		}
		st = h ? 1 : 0;
		break;
	}
	case FZ_SEQ: {
		void *h = ad->open(c, in, n);
		unsigned k, nops = (unsigned)(n / 10u);

		if (nops > 256u)
			nops = 256u;
		for (k = 0; h && k < nops && ad->n_kinds; k++) {
			const uint8_t *r = in + 10u * k;

			st = ad->op(c, h, r[0] % ad->n_kinds, fz_get(r + 1, 4, 0), fz_get(r + 5, 4, 0));
			if (!fz_step(&c->steps, 1))
				break;
		}
		if (h && ad->close)
			ad->close(h);
		break;
	}
	case FZ_TWO: {
		uint64_t need = ad->size(c, in, n), wrote;

		if (need > OUT_CAP)
			break;
		c->cap = (size_t)need;
		c->out = fz_gb_end(&g->out, c->cap);
		memset(c->out - FZ_CANARY, 0xA5, FZ_CANARY);
		memset(c->out, 0xCC, c->cap);
		wrote = ad->write(c, in, n, c->out, need);
		FZ_CHECK(c, wrote == need, "write produced a different size than size() said");
		for (i = 1; i <= FZ_CANARY; i++)
			if (c->out[-(ptrdiff_t)i] != 0xA5) {
				FZ_CHECK(c, 0, "wrote before the output buffer");
				break;
			}
		if (need) {
			c->cap = (size_t)need - 1u;
			c->out = fz_gb_end(&g->out, c->cap);
			memset(c->out, 0xCC, c->cap);
			wrote = ad->write(c, in, n, c->out, need - 1u);
			FZ_CHECK(c, wrote <= need - 1u, "write with a short buffer claims more than it was given");
		}
		fz_digest(c, need);
		break;
	}
	}
	return st;
}

/* call_shape between arm and disarm; leak, cap and step bounds checked here. */
static int call_armed(const struct fz_adapter *ad, struct fz_ctx *c, struct fz_gbs *g, const uint8_t *in, size_t n, uint64_t fail_k, uint64_t quota,
		      struct fz_alloc_stats *as, struct fz_shared *sh)
{
	struct fz_alloc_cfg cfg;
	int st;

	cfg.total_cap = 64u << 20;
	cfg.call_cap = 32u << 20;
	cfg.max_calls = 1u << 20;
	cfg.fail_k = fail_k;
	c->failk = fail_k != 0;
	FZ_WORK_BEGIN();
	fz_alloc_arm(&cfg);
	st = call_shape(ad, c, g, in, n, quota);
	fz_alloc_disarm(as);
	(void)FZ_WORK_END();
	if (as->hit) {
		sh->cap_hits++;
		if (!(ad->flags & FZ_MAY_HIT_CAP))
			FZ_CHECK(c, 0, "allocation cap reached (a size taken from the input without a bound)");
	}
#ifndef FZ_MUTANT_NO_LEAK_CHECK
	if (as->net > 0 && !(ad->flags & FZ_KEEPS_STATE))
#else
	if (0)
#endif
		FZ_CHECK(c, 0, "leak: bytes allocated by the call were not freed");
#ifndef FZ_MUTANT_NO_STEPS
	FZ_CHECK(c, c->steps.used <= c->steps.cap, "work bound exceeded (steps over base + per_byte * n)");
#endif
	return st;
}

static size_t pick_cap(struct fz_rng *r, size_t n)
{
	switch (fz_below(r, 5)) {
	case 0: return 0;
	case 1: return 1u + (size_t)fz_below(r, 63);
	case 2: return (size_t)fz_below(r, 4096);
	default: {
		size_t c = 4096u + (size_t)fz_below(r, n * 16u + 4096u);

		return c > OUT_CAP ? OUT_CAP : c;
	}
	}
}

static int run_child(void *arg)
{
	struct fz_run *R = (struct fz_run *)arg;
	const struct fz_adapter *ad = R->ad;
	const struct fz_opts *o = R->o;
	struct fz_corpus corp;
	struct fz_gbs g;
	uint8_t *work = (uint8_t *)malloc(WORK_CAP);
	size_t nbuiltin, i;
	unsigned it, viol = 0;
	uint64_t digest = R->sh->digest;

	if (ad->flags & FZ_PLANTED) {            /* a planted crash makes the sanitiser print a report: it is expected, not shown */
		int nul = open("/dev/null", O_WRONLY);

		if (nul >= 0)
			(void)dup2(nul, 2);
	}
	memset(&corp, 0, sizeof corp);
	if (ad->seeds)
		ad->seeds(&corp);
	nbuiltin = corp.n;
	for (i = 0; i < o->n_corpus; i++)
		fz_corpus_load_dir(&corp, o->corpus[i], 64, 65536);
	if (!corp.n)
		fz_corpus_add(&corp, "empty", "", 0);
	if (!work || !fz_gb_init(&g.in, WORK_CAP, 1, 0) || !fz_gb_init(&g.out, OUT_CAP, 1, FZ_CANARY)) {
		fprintf(stderr, "fuzz: cannot make the buffers\n");
		return 2;
	}
	for (it = R->start; it < R->end; it++) {
		struct fz_rng rng, snap;
		struct fz_ctx c, c2;
		struct fz_alloc_stats as, as2;
		struct fz_mut mu;
		const struct fz_seed *sd;
		uint64_t seed = fz_mix(o->seed, it), quota;
		size_t n, cap;
		uint8_t *in;
		int st;

		fz_rng_seed(&rng, seed);
		if (it < nbuiltin) {
			sd = &corp.v[it];
		} else if (nbuiltin && corp.n > nbuiltin && fz_below(&rng, 4) != 0) {
			sd = &corp.v[fz_below(&rng, nbuiltin)];
		} else
			sd = &corp.v[fz_below(&rng, corp.n)];
		n = sd->n < WORK_CAP ? sd->n : WORK_CAP;
		memcpy(work, sd->p, n);
		if (it >= nbuiltin) {
			mu.rng = &rng;
			mu.map = sd->map;
			mu.splice = &corp;
			mu.dict = ad->dict;
			n = fz_mutate(&mu, work, n, WORK_CAP);
		}
		cap = pick_cap(&rng, n);
		quota = cap > 1 && fz_below(&rng, 4) == 0 ? 1u + fz_below(&rng, cap) : 0;
		in = fz_gb_put(&g.in, work, n);
		fz_mail_case(ad->name, R->idx, it, seed, work, n);

		snap = rng;
		ctx_init(&c, &rng, seed, it, ad, n, cap);
		st = call_armed(ad, &c, &g, in, n, 0, quota, &as, R->sh);
		R->sh->hist[(unsigned)st & (NHIST - 1u)]++;
#ifdef FZ_MUTANT_NO_DETERMINISM
		if (0) {
#else
		if (!(ad->flags & FZ_NONDET)) {
#endif
			rng = snap;
			ctx_init(&c2, &rng, seed, it, ad, n, cap);
			(void)call_armed(ad, &c2, &g, in, n, 0, quota, &as2, R->sh);
			FZ_CHECK(&c, c2.digest == c.digest, "nondeterministic: two calls on one input gave different digests");
		}
		digest = (digest ^ c.digest) * 0x100000001b3ull;
		if (!(ad->flags & FZ_NO_FAILK) && as.calls && it % 8u == 3u) {
			struct fz_ctx c3;
			struct fz_alloc_stats as3;
			uint64_t k = 1u + (seed >> 9) % (as.calls < 64u ? as.calls : 64u);

			rng = snap;
			ctx_init(&c3, &rng, seed, it, ad, n, cap);
			(void)call_armed(ad, &c3, &g, in, n, k, quota, &as3, R->sh);
			R->sh->failk_runs++;
			c.fails += c3.fails;
			if (!c.why)
				c.why = c3.why;
		}
		if (c.fails) {
			viol++;
			if (!R->sh->why[0] && c.why)
				snprintf(R->sh->why, sizeof R->sh->why, "%s", c.why);
			if (viol <= 8) {
				printf("  FAIL %s iter %u seed %llu: %s\n", ad->name, it, (unsigned long long)seed, c.why ? c.why : "check failed");
				save_input(o, ad->name, it, work, n);
			}
		}
		R->sh->done++;
	}
	R->sh->digest = digest;
	fflush(NULL);
	fz_gb_free(&g.in);
	fz_gb_free(&g.out);
	fz_corpus_free(&corp);
	free(work);
	return viol ? 77 : 0;
}

struct fz_verdict {
	unsigned violations, crashes, hangs, rss;
	char     seen[160];
};

/* All iterations of one adapter; a dead child is attributed and the run goes on after the case that killed it. */
static void run_adapter(const struct fz_opts *o, const struct fz_adapter *ad, unsigned idx, struct fz_verdict *vd)
{
	struct fz_shared *sh = (struct fz_shared *)mmap(NULL, sizeof *sh, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	struct fz_run R;
	unsigned first = o->has_only ? o->only : 0u, last = o->has_only ? o->only + 1u : o->iters * o->scale;
	unsigned crashes = 0, secs = ad->backstop_s ? ad->backstop_s : 60u;
	struct fz_lim lim;
	unsigned i;

	memset(vd, 0, sizeof *vd);
	if (sh == (struct fz_shared *)MAP_FAILED)
		return;
	memset(sh, 0, sizeof *sh);
	sh->digest = 0xcbf29ce484222325ull;
	memset(&lim, 0, sizeof lim);
	lim.cpu_s = secs + 5u;
	lim.rss_mb = 2048;
	R.o = o;
	R.ad = ad;
	R.idx = idx;
	R.sh = sh;
	R.start = first;
	R.end = last;
	fz_mail_share();
	while (R.start < last) {
		struct fz_iso iso;
		int rc = 0;

		fz_mail_share();
		if (o->inline_run)
			iso.kind = FZ_EXITED, iso.code = run_child(&R), iso.sig = 0;
		else
			rc = fz_isolate(run_child, &R, secs, &lim, &iso);
		if (rc < 0) {
			printf("  fork failed\n");
			vd->crashes++;
			break;
		}
		if (iso.kind == FZ_EXITED && iso.code == 0)
			break;
		if (iso.kind == FZ_EXITED && iso.code == 77) {
			vd->violations++;
			break;
		}
		{
			unsigned at = fz_mb->iter;
			const char *what = iso.kind == FZ_TIMEOUT ? "HANG" : iso.kind == FZ_RSS_KILL ? "RSS-KILL" : iso.kind == FZ_SIGNALED ? "CRASH" : "EXIT";

			printf("  %s %s iter %u seed %llu (%s %d; case input %u bytes)\n", what, ad->name, at, (unsigned long long)fz_mb->seed,
			       iso.kind == FZ_EXITED ? "exit" : "signal", iso.kind == FZ_EXITED ? iso.code : iso.sig, (unsigned)fz_mb->in_n);
			save_input(o, ad->name, at, fz_mb->in, fz_mb->in_kept);
			if (iso.kind == FZ_TIMEOUT)
				vd->hangs++;
			else if (iso.kind == FZ_RSS_KILL)
				vd->rss++;
			else
				vd->crashes++;
			if (at < R.start)
				at = R.start;
			R.start = at + 1u;
			if (++crashes >= 10u) {
				printf("  too many deaths, adapter abandoned\n");
				break;
			}
		}
	}
	printf("adapter %s: iters %llu digest %016llx status", ad->name, (unsigned long long)sh->done, (unsigned long long)sh->digest);
	for (i = 0; i < NHIST; i++)
		if (sh->hist[i])
			printf(" %u:%llu", i, (unsigned long long)sh->hist[i]);
	printf(" cap-hits %llu failk-runs %llu viol %u crash %u hang %u rss %u\n", (unsigned long long)sh->cap_hits, (unsigned long long)sh->failk_runs,
	       vd->violations, vd->crashes, vd->hangs, vd->rss);
	snprintf(vd->seen, sizeof vd->seen, "%s%s%s%s", vd->crashes ? "crash " : "", vd->hangs ? "hang " : "", vd->rss ? "rss " : "", sh->why);
	munmap(sh, sizeof *sh);
}

int main(int argc, char **argv)
{
	struct fz_opts o;
	size_t n = n_registry, i, bad = 0, ran = 0;
	const struct fz_adapter **v = (const struct fz_adapter **)malloc((n ? n : 1u) * sizeof *v);
	struct timespec t0, t1;

	fz_opts_init(&o);
	fz_args(&o, argc, argv);
	if (!v)
		return 2;
	for (i = 0; i < n; i++)
		v[i] = registry[i];
	qsort(v, n, sizeof *v, cmp_adapter);
	if (o.list) {
		for (i = 0; i < n; i++)
			printf("%s\tshape %d\t%s\n", v[i]->name, (int)v[i]->shape, v[i]->covers ? v[i]->covers : "");
		return 0;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < n; i++) {
		struct fz_verdict vd;
		int planted = (v[i]->flags & FZ_PLANTED) != 0;

		if (o.adapter && strncmp(v[i]->name, o.adapter, strlen(o.adapter)))
			continue;
		if (planted && !o.planted && !o.selftest)
			continue;
		if (o.selftest && !planted && !o.adapter)
			continue;
		ran++;
		run_adapter(&o, v[i], (unsigned)i, &vd);
		if (o.selftest && planted) {
			int caught = (vd.violations || vd.crashes || vd.hangs || vd.rss) && (!v[i]->expect || strstr(vd.seen, v[i]->expect));

			printf("selftest %s: %s (expected '%s', saw '%s')\n", v[i]->name, caught ? "CAUGHT" : "MISSED", v[i]->expect ? v[i]->expect : "",
			       vd.seen);
			bad += !caught;
		} else if (vd.violations || vd.crashes || vd.hangs || vd.rss)
			bad++;
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	fprintf(stderr, "fuzz: %zu adapter(s), %zu failing, %.1fs\n", ran, bad, (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9);
	free(v);
	if (!ran) {
		fprintf(stderr, "fuzz: no adapter matched\n");
		return o.nomatch_ok ? 0 : 2;
	}
	return bad ? 1 : 0;
}
