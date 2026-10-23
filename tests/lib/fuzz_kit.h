/*
 * fuzz_kit.h - the shared kit of every hostile-input test and fuzz adapter.
 *
 * Header only: every helper is static (FZ_UNUSED), so a test that does not use one pays nothing. The two
 * older harnesses are thin users of it: tests/lib/genome/hk.h and tests/lib/uncoat/hostile_common.h.
 * The allocation wrap, the adapter registry and main() are in tests/lib/fuzz_drv.c (linked only by
 * the fuzz binaries, built by mk/fuzz.mk).
 *
 * WHAT IS HERE
 *   options      fz_args:  --seed N  --iters N  --only I  --scale N  --adapter NAME  --inline  --out DIR
 *                --corpus DIR (repeatable). There is no getenv; a replay is `--seed S --only I`.
 *   rng          fz_rng (xorshift 13/7/17, the stream hk.h always used), fz_rng_star (the stream
 *                hostile_common.h always used), fz_mix(seed, iter): the per-iteration seed.
 *   guard bufs   fz_gb: the data END-ALIGNED to a PROT_NONE page, optionally with a PROT_NONE page in front
 *                (fz_gb_start puts it flush against the front: an under-read faults). Exact size every call.
 *   isolation    fz_isolate: fork, alarm, optional rlimits, and a shared MAILBOX (fz_mb) that holds the
 *                adapter, iteration, seed and the INPUT of the running case, so the parent can say which
 *                case killed the child and write the input to a file. fz_at(a, b) is the free-form pair.
 *   mutators     fz_mutate: bit flip, byte set, interesting values (LE/BE, 1/2/4/8 bytes), +-1..35,
 *                truncate (random and at every field boundary), zero/0xff runs, insert / delete /
 *                duplicate / swap blocks, splice of another seed, field-map corruption (LEN, COUNT,
 *                OFFSET, RVA: 0, 1, n-1, n, n+1, 2^31, 2^32-1, 2^64-1, huge counts, an offset to the
 *                end, before the start, onto another field), duplicate / reorder records, dictionary
 *                tokens. Plain blind mutation of a compressed stream is 99% CORRUPT (measured in the
 *                plan's PoC), so a seed brings a field map (struct fz_map) for what it knows.
 *   corpus       fz_corpus: seeds from memory (builders) or from a directory of fixtures.
 *   limits       COUNTERS, not the clock. Allocation: tests/lib/fuzz_drv.c wraps malloc, calloc,
 *                realloc, free, posix_memalign and mmap at LINK time (-Wl,--wrap=..., see mk/fuzz.mk):
 *                a cap on total and per-call bytes, a call cap, and "fail the k-th allocation" (the OOM
 *                paths). It works under AddressSanitizer: the wrap sits in front of ASAN's malloc
 *                (measured in the PoC, and by the kit's own self-test). Work: struct fz_steps and, when
 *                the TU defines FZ_USE_WORK, tests/lib/work_count.h (basic blocks). Process:
 *                fz_lim (RLIMIT_CPU, _FSIZE, _NOFILE, _NPROC, _AS), applied only in the child and _AS
 *                not under ASAN (the shadow reservation cannot start under it; the sanitised run uses
 *                ASAN_OPTIONS hard_rss_limit_mb / max_allocation_size_mb, and the parent polls the child's
 *                RSS because ASAN's watcher thread does not survive fork). The wall clock is only the
 *                backstop of a hang and is never an assertion.
 *   fault seams  fz_sink (a receiver that counts, reads every byte, refuses after a quota or at the k-th
 *                call), fz_read_fn (shaped like kof_src_read_io.read: short reads, EIO after N bytes),
 *                fz_wr_fn / fz_wr_open (shaped like kof_spill_io: ENOSPC after N bytes, no file).
 *
 * HOW A CASE IS PLACED: the case input is copied into a guard buffer of exactly its size; whatever reads
 * one byte beyond it faults without a sanitiser, so the release build is checked too.
 */
#ifndef KOF_TESTS_FUZZ_KIT_H
#define KOF_TESTS_FUZZ_KIT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The rng, the receiver, the guard buffer (heap memory on a host without mmap), the mixer of corpora and mutators and the
 * mailbox's "where am I" are portable: tests/lib/uncoat/hostile_common.h uses them on Windows too. Everything that forks,
 * maps, limits or reads a directory is POSIX only. */
#ifndef _WIN32
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__GNUC__)
#define FZ_UNUSED __attribute__((unused))
#else
#define FZ_UNUSED
#endif

#if defined(__SANITIZE_ADDRESS__)
#define FZ_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FZ_ASAN 1
#endif
#endif
#ifndef FZ_ASAN
#define FZ_ASAN 0
#endif

/* ---- options ------------------------------------------------------------------------------------- */

#define FZ_CORPUS_DIRS 8u

struct fz_opts {
	uint64_t    seed;        /* --seed */
	unsigned    iters;       /* --iters */
	unsigned    only;        /* --only I */
	int         has_only;
	unsigned    scale;       /* --scale */
	int         inline_run;  /* --inline: no fork, a debugger sees the crash */
	int         list;
	int         selftest;    /* --selftest: planted adapters must FAIL, the others pass */
	int         planted;     /* --planted: run the planted adapters too */
	int         nomatch_ok;  /* --nomatch-ok: an --adapter that matches nothing here is not an error (make fuzz ONLY=) */
	const char *adapter;     /* --adapter NAME (prefix match) */
	const char *out;         /* --out DIR: where a failing input is saved */
	const char *corpus[FZ_CORPUS_DIRS];
	unsigned    n_corpus;
};

static void fz_opts_init(struct fz_opts *o) FZ_UNUSED;
static void fz_opts_init(struct fz_opts *o)
{
	memset(o, 0, sizeof *o);
	o->seed = 1;
	o->iters = 200;
	o->scale = 1;
	o->out = "build/kof_fuzz";
}

/* "--name value" and "--name=value" both. Returns the value or NULL. */
static const char *fz_optval(int argc, char **argv, int *i, const char *name) FZ_UNUSED;
static const char *fz_optval(int argc, char **argv, int *i, const char *name)
{
	size_t l = strlen(name);

	if (strncmp(argv[*i], name, l))
		return NULL;
	if (argv[*i][l] == '=')
		return argv[*i] + l + 1;
	if (argv[*i][l] == 0 && *i + 1 < argc)
		return argv[++*i];
	return NULL;
}

static uint64_t fz_num(const char *s, uint64_t dflt) FZ_UNUSED;
static uint64_t fz_num(const char *s, uint64_t dflt)
{
	char *e;
	unsigned long long v;

	if (!s || !*s)
		return dflt;
	v = strtoull(s, &e, 0);
	return *e ? dflt : (uint64_t)v;
}

static void fz_args(struct fz_opts *o, int argc, char **argv) FZ_UNUSED;
static void fz_args(struct fz_opts *o, int argc, char **argv)
{
	int i;
	const char *v;

	for (i = 1; i < argc; i++) {
		if ((v = fz_optval(argc, argv, &i, "--seed")))
			o->seed = fz_num(v, 1);
		else if ((v = fz_optval(argc, argv, &i, "--iters")))
			o->iters = (unsigned)fz_num(v, 200);
		else if ((v = fz_optval(argc, argv, &i, "--only"))) {
			o->only = (unsigned)fz_num(v, 0);
			o->has_only = 1;
		} else if ((v = fz_optval(argc, argv, &i, "--scale"))) {
			uint64_t s = fz_num(v, 1);

			o->scale = s > 0 && s < 100000 ? (unsigned)s : 1u;
		} else if ((v = fz_optval(argc, argv, &i, "--adapter")))
			o->adapter = v;
		else if ((v = fz_optval(argc, argv, &i, "--out")))
			o->out = v;
		else if ((v = fz_optval(argc, argv, &i, "--corpus"))) {
			if (o->n_corpus < FZ_CORPUS_DIRS)
				o->corpus[o->n_corpus++] = v;
		} else if (!strcmp(argv[i], "--inline"))
			o->inline_run = 1;
		else if (!strcmp(argv[i], "--list"))
			o->list = 1;
		else if (!strcmp(argv[i], "--selftest"))
			o->selftest = 1;
		else if (!strcmp(argv[i], "--planted"))
			o->planted = 1;
		else if (!strcmp(argv[i], "--nomatch-ok"))
			o->nomatch_ok = 1;
	}
}

/* ---- the generators -------------------------------------------------------------------------------- */

struct fz_rng { uint64_t s; };

/* xorshift 13/7/17: the stream hk.h has always used (hk_next is this). */
static inline uint64_t fz_rng_next(struct fz_rng *r) FZ_UNUSED;
static inline uint64_t fz_rng_next(struct fz_rng *r)
{
	r->s ^= r->s << 13;
	r->s ^= r->s >> 7;
	r->s ^= r->s << 17;
	return r->s;
}

/* xorshift 12/25/27 with the multiplier: the stream hostile_common.h has always used (hv_rng is this). */
static inline uint64_t fz_rng_star(uint64_t *s) FZ_UNUSED;
static inline uint64_t fz_rng_star(uint64_t *s)
{
	uint64_t x = *s;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*s = x;
	return x * 0x2545F4914F6CDD1Dull;
}

/* The seed of iteration `iter` of a campaign of `seed`: splitmix64 over both, so "--seed S --only I" replays one case. */
static inline uint64_t fz_mix(uint64_t seed, uint64_t iter) FZ_UNUSED;
static inline uint64_t fz_mix(uint64_t seed, uint64_t iter)
{
	uint64_t z = seed + 0x9e3779b97f4a7c15ull * (iter + 1u);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	return z ^ (z >> 31);
}

static inline void fz_rng_seed(struct fz_rng *r, uint64_t seed) FZ_UNUSED;
static inline void fz_rng_seed(struct fz_rng *r, uint64_t seed)
{
	r->s = seed ? seed : 0x9e3779b97f4a7c15ull;
}

static inline uint64_t fz_below(struct fz_rng *r, uint64_t n) FZ_UNUSED;
static inline uint64_t fz_below(struct fz_rng *r, uint64_t n)
{
	return n ? fz_rng_next(r) % n : 0u;
}

static inline int fz_chance(struct fz_rng *r, unsigned one_in) FZ_UNUSED;
static inline int fz_chance(struct fz_rng *r, unsigned one_in)
{
	return one_in ? fz_rng_next(r) % one_in == 0u : 0;
}

/* ---- guard buffers --------------------------------------------------------------------------------- */

/* [ front page ][ data pages: room for cap + canary bytes ][ PROT_NONE page ]
 * The front page is PROT_NONE when front_guard is set (a read before the data faults), writable otherwise. */
struct fz_gb {
	uint8_t *map;
	size_t   len, page, dlen, cap, canary;
	uint8_t *data;
};

static int fz_gb_init(struct fz_gb *g, size_t cap, int front_guard, size_t canary) FZ_UNUSED;
static int fz_gb_init(struct fz_gb *g, size_t cap, int front_guard, size_t canary)
{
#ifdef _WIN32
	size_t pg = 4096u;
#else
	size_t pg = (size_t)sysconf(_SC_PAGESIZE);
#endif

	memset(g, 0, sizeof *g);
	g->page = pg;
	g->cap = cap;
	g->canary = canary;
	g->dlen = (cap + canary + pg - 1u) / pg * pg;
	g->len = g->dlen + 2u * pg;
#ifdef _WIN32
	(void)front_guard;
	g->map = (uint8_t *)malloc(g->len);        /* no guard pages: the checks that need a fault are weaker here */
	if (!g->map)
		return 0;
	g->data = g->map + pg;
	return 1;
#else
	g->map = (uint8_t *)mmap(NULL, g->len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (g->map == (uint8_t *)MAP_FAILED) {
		g->map = NULL;
		return 0;
	}
	g->data = g->map + pg;
	if (mprotect(g->data + g->dlen, pg, PROT_NONE) || (front_guard && mprotect(g->map, pg, PROT_NONE))) {
		munmap(g->map, g->len);
		g->map = NULL;
		return 0;
	}
	return 1;
#endif
}

static void fz_gb_free(struct fz_gb *g) FZ_UNUSED;
static void fz_gb_free(struct fz_gb *g)
{
	if (g->map) {
#ifdef _WIN32
		free(g->map);
#else
		munmap(g->map, g->len);
#endif
	}
	g->map = NULL;
}

/* The `n` bytes that END at the guard page: byte n is the first byte of a PROT_NONE page. NULL when n does not fit. */
static uint8_t *fz_gb_end(const struct fz_gb *g, size_t n) FZ_UNUSED;
static uint8_t *fz_gb_end(const struct fz_gb *g, size_t n)
{
	return n + g->canary > g->dlen ? NULL : g->data + g->dlen - n;
}

/* The `n` bytes that START at the first data byte (flush against the front page when front_guard was set). */
static uint8_t *fz_gb_start(const struct fz_gb *g, size_t n) FZ_UNUSED;
static uint8_t *fz_gb_start(const struct fz_gb *g, size_t n)
{
	return n > g->dlen ? NULL : g->data;
}

/* An exact-size copy of src[0..n) that ends at the guard page; n == 0 gives the guard page's own address. */
static uint8_t *fz_gb_put(const struct fz_gb *g, const void *src, size_t n) FZ_UNUSED;
static uint8_t *fz_gb_put(const struct fz_gb *g, const void *src, size_t n)
{
	uint8_t *p = fz_gb_end(g, n);

	if (p && n && src)
		memmove(p, src, n);
	return p;
}

/* ---- the mailbox and the isolated run ---------------------------------------------------------------- */

#define FZ_MAIL_IN (256u * 1024u)

/* In shared memory: the child writes, the parent reads after the child is dead. */
struct fz_mail {
	volatile uint64_t a, b;                 /* fz_at(): free-form "where am I" */
	volatile uint64_t seed;                 /* per-iteration seed of the running case */
	volatile uint32_t iter;
	volatile uint32_t adapter;              /* index into the registry */
	volatile uint32_t in_n;                 /* bytes of the input, whatever FZ_MAIL_IN kept */
	volatile uint32_t in_kept;
	volatile uint32_t violations;           /* checks that failed in the child, which went on */
	char              name[64];
	uint8_t           in[FZ_MAIL_IN];
};

static struct fz_mail fz_mb_local;
static struct fz_mail *fz_mb FZ_UNUSED = &fz_mb_local;

#ifndef _WIN32
static void fz_mail_share(void) FZ_UNUSED;
static void fz_mail_share(void)
{
	if (fz_mb == &fz_mb_local) {
		void *m = mmap(NULL, sizeof *fz_mb, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		if (m != MAP_FAILED)
			fz_mb = (struct fz_mail *)m;
	}
	fz_mb->a = fz_mb->b = 0;
}
#endif

static inline void fz_at(uint64_t a, uint64_t b) FZ_UNUSED;
static inline void fz_at(uint64_t a, uint64_t b)
{
	fz_mb->a = a;
	fz_mb->b = b;
}

/* Record the case that is about to run: adapter name and index, iteration, seed, and the input itself. */
static void fz_mail_case(const char *name, unsigned adapter, unsigned iter, uint64_t seed, const uint8_t *in, size_t n) FZ_UNUSED;
static void fz_mail_case(const char *name, unsigned adapter, unsigned iter, uint64_t seed, const uint8_t *in, size_t n)
{
	size_t k = n < FZ_MAIL_IN ? n : FZ_MAIL_IN;

	fz_mb->adapter = adapter;
	fz_mb->iter = iter;
	fz_mb->seed = seed;
	fz_mb->in_n = (uint32_t)n;
	fz_mb->in_kept = (uint32_t)k;
	if (k)
		memcpy(fz_mb->in, in, k);
	if (name) {
		strncpy(fz_mb->name, name, sizeof fz_mb->name - 1u);
		fz_mb->name[sizeof fz_mb->name - 1u] = 0;
	}
}

#ifndef _WIN32
/* Limits of ONE isolated child. 0 = leave alone. */
struct fz_lim {
	unsigned cpu_s;         /* RLIMIT_CPU */
	uint64_t fsize;         /* RLIMIT_FSIZE (SIGXFSZ is ignored so a write fails with EFBIG) */
	unsigned nofile;        /* RLIMIT_NOFILE */
	unsigned nproc;         /* RLIMIT_NPROC (not honoured for root) */
	uint64_t as;            /* RLIMIT_AS: ignored under ASAN */
	unsigned rss_mb;        /* the PARENT polls /proc/<child>/statm and kills over this */
};

/* soft == hard, except CPU: soft+1 so the process gets SIGXCPU (classified as a timeout) and not an unexplained SIGKILL. */
static void fz_setrl(int what, uint64_t v) FZ_UNUSED;
static void fz_setrl(int what, uint64_t v)
{
	struct rlimit r;

	r.rlim_cur = (rlim_t)v;
	r.rlim_max = (rlim_t)v + (what == RLIMIT_CPU ? 1u : 0u);
	(void)setrlimit(what, &r);
}

static void fz_lim_apply(const struct fz_lim *l) FZ_UNUSED;
static void fz_lim_apply(const struct fz_lim *l)
{
	if (!l)
		return;
	if (l->cpu_s)
		fz_setrl(RLIMIT_CPU, l->cpu_s);
	if (l->fsize) {
		signal(SIGXFSZ, SIG_IGN);
		fz_setrl(RLIMIT_FSIZE, l->fsize);
	}
	if (l->nofile)
		fz_setrl(RLIMIT_NOFILE, l->nofile);
	if (l->nproc)
		fz_setrl(RLIMIT_NPROC, l->nproc);
	if (l->as && !FZ_ASAN)
		fz_setrl(RLIMIT_AS, l->as);
}

enum fz_kind { FZ_EXITED = 0, FZ_SIGNALED, FZ_TIMEOUT, FZ_RSS_KILL };

struct fz_iso {
	enum fz_kind kind;
	int          code;     /* exit status when FZ_EXITED */
	int          sig;      /* the signal when FZ_SIGNALED / FZ_TIMEOUT */
};

/* The child's own resident size in MiB from /proc/<pid>/statm; 0 when it cannot be read. */
static unsigned fz_rss_mb(pid_t pid) FZ_UNUSED;
static unsigned fz_rss_mb(pid_t pid)
{
	char path[64];
	unsigned long total = 0, res = 0;
	FILE *f;

	snprintf(path, sizeof path, "/proc/%d/statm", (int)pid);
	f = fopen(path, "r");
	if (!f)
		return 0;
	if (fscanf(f, "%lu %lu", &total, &res) != 2)
		res = 0;
	fclose(f);
	return (unsigned)(res * (unsigned long)sysconf(_SC_PAGESIZE) >> 20);
}

/* Run fn(arg) in a child; its return value is its exit status (0 = pass). The alarm is the HANG backstop. When `hook`
 * is set it runs in the child before fn (the limits, a reset of the test's counters). */
static int fz_isolate(int (*fn)(void *), void *arg, unsigned secs, const struct fz_lim *lim, struct fz_iso *r) FZ_UNUSED;
static int fz_isolate(int (*fn)(void *), void *arg, unsigned secs, const struct fz_lim *lim, struct fz_iso *r)
{
	int st = 0;
	pid_t pid;

	memset(r, 0, sizeof *r);
	fflush(NULL);
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int rc;

		signal(SIGALRM, SIG_DFL);
		if (secs)
			alarm(secs);
		fz_lim_apply(lim);
		rc = fn(arg);
		fflush(NULL);
		_exit(rc);
	}
	if (lim && lim->rss_mb) {
		for (;;) {
			pid_t w = waitpid(pid, &st, WNOHANG);
			struct timespec ts = {0, 5 * 1000 * 1000};

			if (w == pid)
				break;
			if (w < 0)
				return -1;
			if (fz_rss_mb(pid) > lim->rss_mb) {
				kill(pid, SIGKILL);
				(void)waitpid(pid, &st, 0);
				r->kind = FZ_RSS_KILL;
				r->sig = SIGKILL;
				return 0;
			}
			nanosleep(&ts, NULL);
		}
	} else if (waitpid(pid, &st, 0) < 0)
		return -1;
	if (WIFSIGNALED(st)) {
		r->sig = WTERMSIG(st);
		r->kind = r->sig == SIGALRM || r->sig == SIGXCPU ? FZ_TIMEOUT : FZ_SIGNALED;
	} else
		r->code = WEXITSTATUS(st);
	return 0;
}

#endif /* !_WIN32 */

/* ---- the counters of work --------------------------------------------------------------------------- */

/* A bound on steps an adapter counts itself (loop turns, sink calls, bytes visited). fz_step answers 0 once over. */
struct fz_steps {
	uint64_t used, cap;
};

static inline int fz_step(struct fz_steps *s, uint64_t n) FZ_UNUSED;
static inline int fz_step(struct fz_steps *s, uint64_t n)
{
	s->used += n;
	return s->used <= s->cap;
}

/* Basic blocks, when the TU is built with -fsanitize-coverage=trace-pc and defines FZ_USE_WORK (work_count.h). */
#ifdef FZ_USE_WORK
#include "work_count.h"
#define FZ_WORK_BEGIN() WORK_BEGIN()
#define FZ_WORK_END() work_end()
#else
#define FZ_WORK_BEGIN() ((void)0)
#define FZ_WORK_END() ((uint64_t)0)
#endif

/* ---- the allocation caps (implemented in fuzz_drv.c, behind --wrap) ------------------------------------ */

struct fz_alloc_cfg {
	uint64_t total_cap;     /* bytes asked in all, while armed; over it the call returns NULL */
	uint64_t call_cap;      /* bytes of ONE call */
	uint64_t max_calls;     /* calls while armed; 0 = no cap */
	uint64_t fail_k;        /* the k-th call (1-based) returns NULL; 0 = off */
};

struct fz_alloc_stats {
	uint64_t calls, bytes, peak_live, refused;
	int64_t  net;           /* bytes allocated minus bytes freed while armed: > 0 after a call that frees all = a leak */
	int      hit;           /* any call was refused by a cap (not by fail_k) */
};

void fz_alloc_arm(const struct fz_alloc_cfg *cfg);
void fz_alloc_disarm(struct fz_alloc_stats *out);

/* ---- fault seams ------------------------------------------------------------------------------------- */

/* A receiver of decoded bytes: counts, reads every byte (a wild pointer faults), refuses after a quota, or at the k-th
 * call. The fields are the ones hostile_common.h's hv_sink always had. */
struct fz_sink {
	uint64_t total;         /* bytes accepted */
	uint64_t calls;
	uint64_t cap;           /* the most the caller asked for; 0 = no statement */
	uint64_t refuse_at;     /* refuse once this many have been accepted; 0 = never */
	uint64_t refused_calls; /* calls that came after the refusal */
	int      over;          /* accepted more than `cap` */
	int      zero_call;     /* a call with n == 0 */
	uint32_t sum;           /* every byte was read */
	uint8_t *keep;          /* copy of the first keep_cap bytes, or NULL */
	size_t   keep_cap;
	uint64_t fail_call;     /* refuse the call with this number (1-based); 0 = never */
};

static inline int fz_sink_fn(void *user, const uint8_t *p, uint32_t n) FZ_UNUSED;
static inline int fz_sink_fn(void *user, const uint8_t *p, uint32_t n)
{
	struct fz_sink *s = (struct fz_sink *)user;
	uint32_t i;

	s->calls++;
	if ((s->refuse_at && s->total >= s->refuse_at) || (s->fail_call && s->calls == s->fail_call)) {
		s->refused_calls++;
		return 0;
	}
	if (!n)
		s->zero_call = 1;
	for (i = 0; i < n; i++)
		s->sum += p[i];
	if (s->keep && s->total < s->keep_cap) {
		size_t room = s->keep_cap - (size_t)s->total;

		memcpy(s->keep + s->total, p, n < room ? n : room);
	}
	s->total += n;
	if (s->cap && s->total > s->cap)
		s->over = 1;
	return 1;
}

#ifndef _WIN32
/* A read(2) that goes wrong on a schedule; the shape of struct kof_src_read_io.read. */
struct fz_read_plan {
	uint64_t fail_after;    /* -1 with errno from this many bytes on; 0 = never */
	uint32_t short_max;     /* a read returns at most this many bytes; 0 = no limit */
	int      err;           /* errno of the failure (EIO when 0) */
	uint64_t calls, bytes;
};

static int64_t fz_read_fn(void *user, int fd, void *buf, uint64_t n) FZ_UNUSED;
static int64_t fz_read_fn(void *user, int fd, void *buf, uint64_t n)
{
	struct fz_read_plan *p = (struct fz_read_plan *)user;
	ssize_t r;

	p->calls++;
	if (p->fail_after && p->bytes >= p->fail_after) {
		errno = p->err ? p->err : EIO;
		return -1;
	}
	if (p->short_max && n > p->short_max)
		n = p->short_max;
	if (p->fail_after && p->bytes + n > p->fail_after)
		n = p->fail_after - p->bytes;
	r = read(fd, buf, (size_t)n);
	if (r > 0)
		p->bytes += (uint64_t)r;
	return (int64_t)r;
}

/* A spill file that fills up; the shape of struct kof_spill_io (open / write). fz_wr_open hands out a real unnamed
 * file in `dir` (or answers -1 when the plan says no file may be made). */
struct fz_wr_plan {
	uint64_t fail_after;    /* write answers 0 once this many bytes were written; 0 = never */
	int      no_file;       /* open answers -1 */
	uint64_t bytes, writes, opens;
};

static int fz_wr_open(void *user, const char *dir) FZ_UNUSED;
static int fz_wr_open(void *user, const char *dir)
{
	struct fz_wr_plan *p = (struct fz_wr_plan *)user;
	int fd;

	p->opens++;
	if (p->no_file)
		return -1;
#ifdef O_TMPFILE
	fd = open(dir && *dir ? dir : ".", O_RDWR | O_TMPFILE, 0600);
#else
	(void)dir;
	fd = -1;                    /* no O_TMPFILE without _GNU_SOURCE: the fuzz builds define it */
#endif
	return fd;
}

static int fz_wr_fn(void *user, int fd, const void *buf, uint64_t n) FZ_UNUSED;
static int fz_wr_fn(void *user, int fd, const void *buf, uint64_t n)
{
	struct fz_wr_plan *p = (struct fz_wr_plan *)user;

	p->writes++;
	if (p->fail_after && p->bytes + n > p->fail_after)
		return 0;
	p->bytes += n;
	return write(fd, buf, (size_t)n) == (ssize_t)n;
}

/* fd exhaustion: open /dev/null until only `spare` descriptors can still be made; the count to close with fz_fds_free. */
static int fz_fds_eat(int *fds, int cap, unsigned spare) FZ_UNUSED;
static int fz_fds_eat(int *fds, int cap, unsigned spare)
{
	struct rlimit r;
	int n = 0;

	if (getrlimit(RLIMIT_NOFILE, &r))
		return 0;
	while (n < cap) {
		int fd = open("/dev/null", O_RDONLY);

		if (fd < 0)
			break;
		if ((unsigned)fd + spare >= (unsigned)r.rlim_cur) {
			close(fd);
			break;
		}
		fds[n++] = fd;
	}
	return n;
}

static void fz_fds_free(const int *fds, int n) FZ_UNUSED;
static void fz_fds_free(const int *fds, int n)
{
	while (n-- > 0)
		close(fds[n]);
}

#endif /* !_WIN32 */

/* ---- the corpus ---------------------------------------------------------------------------------------- */

/* A field of a seed the mutators know about: where it is, how wide, which endianness, what it means. */
enum fz_fkind { FZ_LEN = 0, FZ_COUNT, FZ_OFFSET, FZ_RVA };

struct fz_field {
	uint32_t off;
	uint8_t  size;      /* 1, 2, 4 or 8 */
	uint8_t  be;
	uint8_t  kind;      /* enum fz_fkind */
};

/* What a builder knows about its seed: fields, and one array of fixed-size records (rec_n == 0: none). */
struct fz_map {
	const struct fz_field *f;
	unsigned               n;
	uint32_t               rec_off, rec_size, rec_n;
};

struct fz_seed {
	const char          *name;
	uint8_t             *p;
	size_t               n;
	const struct fz_map *map;   /* borrowed, static; may be NULL */
};

struct fz_corpus {
	struct fz_seed *v;
	size_t          n, cap;
};

static struct fz_seed *fz_corpus_add_map(struct fz_corpus *c, const char *name, const void *p, size_t n, const struct fz_map *m) FZ_UNUSED;
static struct fz_seed *fz_corpus_add_map(struct fz_corpus *c, const char *name, const void *p, size_t n, const struct fz_map *m)
{
	struct fz_seed *s;
	uint8_t *copy;

	if (c->n == c->cap) {
		size_t nc = c->cap ? c->cap * 2u : 16u;
		struct fz_seed *nv = (struct fz_seed *)realloc(c->v, nc * sizeof *nv);

		if (!nv)
			return NULL;
		c->v = nv;
		c->cap = nc;
	}
	copy = (uint8_t *)malloc(n ? n : 1u);
	if (!copy)
		return NULL;
	if (n)
		memcpy(copy, p, n);
	s = &c->v[c->n++];
	s->name = name;
	s->p = copy;
	s->n = n;
	s->map = m;
	return s;
}

static struct fz_seed *fz_corpus_add(struct fz_corpus *c, const char *name, const void *p, size_t n) FZ_UNUSED;
static struct fz_seed *fz_corpus_add(struct fz_corpus *c, const char *name, const void *p, size_t n)
{
	return fz_corpus_add_map(c, name, p, n, NULL);
}

#ifndef _WIN32
static int fz_cmp_name(const void *a, const void *b) FZ_UNUSED;
static int fz_cmp_name(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Every regular file of `dir` up to max_size bytes, in name order (so the corpus is the same on every run). Returns how many. */
static size_t fz_corpus_load_dir(struct fz_corpus *c, const char *dir, size_t max_files, size_t max_size) FZ_UNUSED;
static size_t fz_corpus_load_dir(struct fz_corpus *c, const char *dir, size_t max_files, size_t max_size)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char **names = NULL;
	size_t nn = 0, cap = 0, i, added = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		if (nn == cap) {
			char **t = (char **)realloc(names, (cap = cap ? cap * 2u : 64u) * sizeof *names);

			if (!t)
				break;
			names = t;
		}
		{
			size_t l = strlen(e->d_name) + 1u;          /* not strdup: a test may include this header without _GNU_SOURCE */

			names[nn] = (char *)malloc(l);
			if (names[nn]) {
				memcpy(names[nn], e->d_name, l);
				nn++;
			}
		}
	}
	closedir(d);
	if (nn)
		qsort(names, nn, sizeof *names, fz_cmp_name);
	for (i = 0; i < nn && added < max_files; i++) {
		char path[1024];
		struct stat sb;
		FILE *f;
		uint8_t *buf;

		snprintf(path, sizeof path, "%s/%s", dir, names[i]);
		if (stat(path, &sb) || !S_ISREG(sb.st_mode) || (uint64_t)sb.st_size > max_size)
			continue;
		f = fopen(path, "rb");
		if (!f)
			continue;
		buf = (uint8_t *)malloc((size_t)sb.st_size + 1u);
		if (buf && fread(buf, 1, (size_t)sb.st_size, f) == (size_t)sb.st_size) {
			if (fz_corpus_add(c, "file", buf, (size_t)sb.st_size))
				added++;
		}
		free(buf);
		fclose(f);
	}
	for (i = 0; i < nn; i++)
		free(names[i]);
	free(names);
	return added;
}

#endif /* !_WIN32 */

static void fz_corpus_free(struct fz_corpus *c) FZ_UNUSED;
static void fz_corpus_free(struct fz_corpus *c)
{
	size_t i;

	for (i = 0; i < c->n; i++)
		free(c->v[i].p);
	free(c->v);
	memset(c, 0, sizeof *c);
}

/* ---- the mutators ---------------------------------------------------------------------------------------- */

struct fz_mut {
	struct fz_rng          *rng;
	const struct fz_map    *map;       /* of the seed being mutated; may be NULL */
	const struct fz_corpus *splice;    /* another seed to take a block from; may be NULL */
	const char *const      *dict;      /* tokens (magic, API names, keywords); NULL-terminated; may be NULL */
};

static const uint64_t fz_interesting[] = {
	0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffffu, 0x80000000u, 0xffffffffu,
	0x7fffffffffffffffull, 0x8000000000000000ull, 0xffffffffffffffffull
};
#define FZ_N_INTERESTING (sizeof fz_interesting / sizeof fz_interesting[0])

static void fz_put(uint8_t *p, uint64_t v, unsigned size, int be) FZ_UNUSED;
static void fz_put(uint8_t *p, uint64_t v, unsigned size, int be)
{
	unsigned i;

	for (i = 0; i < size; i++)
		p[be ? size - 1u - i : i] = (uint8_t)(v >> (8u * i));
}

static uint64_t fz_get(const uint8_t *p, unsigned size, int be) FZ_UNUSED;
static uint64_t fz_get(const uint8_t *p, unsigned size, int be)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < size; i++)
		v |= (uint64_t)p[be ? size - 1u - i : i] << (8u * i);
	return v;
}

/* A value for a field: its own boundaries, the buffer's, or a huge count. */
static uint64_t fz_field_value(struct fz_rng *r, const struct fz_field *f, uint64_t cur, size_t n) FZ_UNUSED;
static uint64_t fz_field_value(struct fz_rng *r, const struct fz_field *f, uint64_t cur, size_t n)
{
	switch (fz_below(r, 12)) {
	case 0: return 0;
	case 1: return 1;
	case 2: return n ? n - 1u : 0;
	case 3: return n;
	case 4: return n + 1u;
	case 5: return 0x80000000u;
	case 6: return 0xffffffffu;
	case 7: return 0xffffffffffffffffull;
	case 8: return f->kind == FZ_COUNT ? 0x00ffffffu + fz_below(r, 0x100) : cur + 1u;
	case 9: return cur ? cur - 1u : 0xffffffffffffffffull;
	case 10: return cur * 2u + 1u;
	default: return fz_interesting[fz_below(r, FZ_N_INTERESTING)];
	}
}

/* An offset-kind value: to the end, before the start, one past, onto the field's own place or another field's. */
static uint64_t fz_offset_value(struct fz_rng *r, const struct fz_map *m, unsigned self, size_t n) FZ_UNUSED;
static uint64_t fz_offset_value(struct fz_rng *r, const struct fz_map *m, unsigned self, size_t n)
{
	switch (fz_below(r, 6)) {
	case 0: return n;
	case 1: return n ? n - 1u : 0;
	case 2: return 0;
	case 3: return 0xffffffffu - fz_below(r, 64);       /* "before the start" once added to a base */
	case 4: return m->f[self].off + fz_below(r, 4);     /* onto itself */
	default: return m->n ? m->f[fz_below(r, m->n)].off : n / 2u;   /* overlap another field */
	}
}

/* One structure-aware mutation of b[0..n), growing it up to cap. Returns the new length. */
static size_t fz_mutate_once(struct fz_mut *m, uint8_t *b, size_t n, size_t cap) FZ_UNUSED;
static size_t fz_mutate_once(struct fz_mut *m, uint8_t *b, size_t n, size_t cap)
{
	struct fz_rng *r = m->rng;
	unsigned op = (unsigned)fz_below(r, 17);
	size_t o, l, o2;

	switch (op) {
	case 0:                                                     /* bit flip */
		if (n)
			b[fz_below(r, n)] ^= (uint8_t)(1u << fz_below(r, 8));
		break;
	case 1:                                                     /* byte set */
		if (n)
			b[fz_below(r, n)] = (uint8_t)fz_rng_next(r);
		break;
	case 2: {                                                   /* interesting value, 1/2/4/8 bytes, LE or BE */
		static const unsigned sz[] = {1, 2, 4, 8};
		unsigned w = sz[fz_below(r, 4)];

		if (n >= w)
			fz_put(b + fz_below(r, n - w + 1u), fz_interesting[fz_below(r, FZ_N_INTERESTING)], w, (int)fz_below(r, 2));
		break;
	}
	case 3: {                                                   /* +-1..35 on a 1/2/4 byte value */
		static const unsigned sz[] = {1, 2, 4};
		unsigned w = sz[fz_below(r, 3)];

		if (n >= w) {
			size_t at = fz_below(r, n - w + 1u);
			int be = (int)fz_below(r, 2);
			uint64_t v = fz_get(b + at, w, be), d = 1u + fz_below(r, 35);

			fz_put(b + at, fz_below(r, 2) ? v + d : v - d, w, be);
		}
		break;
	}
	case 4:                                                     /* truncate at random */
		n = n ? (size_t)fz_below(r, n) : 0;
		break;
	case 5:                                                     /* truncate at a field boundary */
		if (m->map && m->map->n) {
			const struct fz_field *f = &m->map->f[fz_below(r, m->map->n)];
			size_t at = f->off + (fz_below(r, 2) ? f->size : 0u);

			if (at < n)
				n = at;
		} else
			n = n ? (size_t)fz_below(r, n) : 0;
		break;
	case 6:                                                     /* extend with a zero or 0xff run */
		l = 1u + (size_t)fz_below(r, 4096);
		if (l > cap - n)
			l = cap - n;
		memset(b + n, fz_below(r, 2) ? 0xff : 0, l);
		n += l;
		break;
	case 7:                                                     /* insert a copy of a block of this buffer */
		if (n) {
			o = fz_below(r, n);
			l = 1u + (size_t)fz_below(r, 64);
			o2 = fz_below(r, n);
			if (l > n - o2)
				l = n - o2;
			if (l <= cap - n) {
				memmove(b + o + l, b + o, n - o);
				memmove(b + o, b + (o2 >= o ? o2 + l : o2), l);
				n += l;
			}
		}
		break;
	case 8:                                                     /* delete a block */
		if (n) {
			o = fz_below(r, n);
			l = 1u + (size_t)fz_below(r, 64);
			if (l > n - o)
				l = n - o;
			memmove(b + o, b + o + l, n - o - l);
			n -= l;
		}
		break;
	case 9:                                                     /* duplicate a block over another place */
		if (n >= 4) {
			l = 1u + (size_t)fz_below(r, n / 2u);
			o = fz_below(r, n - l + 1u);
			o2 = fz_below(r, n - l + 1u);
			memmove(b + o2, b + o, l);
		}
		break;
	case 10:                                                    /* swap two blocks */
		if (n >= 8) {
			uint8_t t[64];

			l = 1u + (size_t)fz_below(r, n / 2u < sizeof t ? n / 2u : sizeof t);
			o = fz_below(r, n - l + 1u);
			o2 = fz_below(r, n - l + 1u);
			if ((o2 >= o + l || o >= o2 + l)) {
				memcpy(t, b + o, l);
				memmove(b + o, b + o2, l);
				memcpy(b + o2, t, l);
			}
		}
		break;
	case 11:                                                    /* splice a block of another seed */
		if (m->splice && m->splice->n) {
			const struct fz_seed *s = &m->splice->v[fz_below(r, m->splice->n)];

			if (s->n) {
				l = 1u + (size_t)fz_below(r, s->n < 256 ? s->n : 256);
				o2 = fz_below(r, s->n - l + 1u);
				o = n ? fz_below(r, n + 1u) : 0;
				if (l <= cap - n) {
					memmove(b + o + l, b + o, n - o);
					memcpy(b + o, s->p + o2, l);
					n += l;
				}
			}
		}
		break;
	case 12: case 13:                                           /* field corruption */
		if (m->map && m->map->n) {
			unsigned i = (unsigned)fz_below(r, m->map->n);
			const struct fz_field *f = &m->map->f[i];

			if ((size_t)f->off + f->size <= n) {
				uint64_t cur = fz_get(b + f->off, f->size, f->be);
				uint64_t v = f->kind == FZ_OFFSET || f->kind == FZ_RVA ? fz_offset_value(r, m->map, i, n) : fz_field_value(r, f, cur, n);

				fz_put(b + f->off, v, f->size, f->be);
			}
		} else if (n >= 4)
			fz_put(b + fz_below(r, n - 3u), fz_interesting[fz_below(r, FZ_N_INTERESTING)], 4, 0);
		break;
	case 14:                                                    /* duplicate or reorder records */
		if (m->map && m->map->rec_n > 1 && m->map->rec_size && (uint64_t)m->map->rec_off + (uint64_t)m->map->rec_size * m->map->rec_n <= n) {
			uint32_t a = (uint32_t)fz_below(r, m->map->rec_n), c = (uint32_t)fz_below(r, m->map->rec_n);
			uint8_t *pa = b + m->map->rec_off + (size_t)a * m->map->rec_size, *pc = b + m->map->rec_off + (size_t)c * m->map->rec_size;

			if (a != c) {
				if (fz_below(r, 2)) {
					memmove(pc, pa, m->map->rec_size);          /* duplicate */
				} else {
					uint8_t t[256];
					size_t k = m->map->rec_size < sizeof t ? m->map->rec_size : sizeof t;

					memcpy(t, pa, k);                           /* reorder (swap) */
					memmove(pa, pc, k);
					memcpy(pc, t, k);
				}
			}
		}
		break;
	case 15:                                                    /* a dictionary token */
		if (m->dict && m->dict[0]) {
			unsigned nd = 0;
			const char *t;

			while (m->dict[nd])
				nd++;
			t = m->dict[fz_below(r, nd)];
			l = strlen(t);
			if (l && l <= n)
				memcpy(b + fz_below(r, n - l + 1u), t, l);
			else if (l && l <= cap - n) {
				memcpy(b + n, t, l);
				n += l;
			}
		}
		break;
	default:                                                    /* overwrite a run with one byte */
		if (n) {
			o = fz_below(r, n);
			l = 1u + (size_t)fz_below(r, 32);
			if (l > n - o)
				l = n - o;
			memset(b + o, fz_below(r, 2) ? 0xff : 0, l);
		}
		break;
	}
	return n;
}

/* 1..4 mutations, structure-aware when the seed brought a map. */
static size_t fz_mutate(struct fz_mut *m, uint8_t *b, size_t n, size_t cap) FZ_UNUSED;
static size_t fz_mutate(struct fz_mut *m, uint8_t *b, size_t n, size_t cap)
{
	unsigned k = 1u + (unsigned)fz_below(m->rng, 4);

	while (k--)
		n = fz_mutate_once(m, b, n, cap);
	return n;
}

#endif /* KOF_TESTS_FUZZ_KIT_H */
