/*
 * hostile_common.h - the harness the hostile_*.c and api_*.c tests of libuncoat share.
 *
 * A decoder of untrusted bytes fails in ways a return code cannot show: a read one
 * byte past the input, a write one byte past the output, a loop that never ends, a
 * table sized by a number out of the file. So the harness gives each case what
 * makes those failures LOUD instead of silent:
 *
 *   GUARD BUFFERS    mmap'd, the data END-ALIGNED to a page whose neighbours are
 *                    PROT_NONE. An input of n bytes sits so that byte n is the first
 *                    byte of a PROT_NONE page: reading it faults. The same for an
 *                    output of `cap` bytes: writing byte `cap` faults. This does not
 *                    need a sanitizer, so it also checks the release build.
 *   ISOLATION        a case that can crash or hang runs in a forked child with an
 *                    alarm, and the parent reports WHICH case (two numbers the child
 *                    keeps in shared memory) instead of dying with it. A crash is a
 *                    finding, and the runner has to survive to say so.
 *   A SINK           that counts what it is handed, reads every byte of it (a wild
 *                    pointer faults), and can refuse after a quota.
 *   A PRNG           fixed seeds only: every failure is reproducible from its number.
 *
 * Nothing here reads or writes a file. A test that needs bzip2 or xz to make its
 * input runs the tool through pipes (hv_tool) and SKIPS, visibly, when it is not
 * there. On a host without fork and mmap (Windows) the guard buffers are plain heap
 * memory and a case runs in-process: the checks that need a fault are weaker there
 * and everything else is the same.
 */

#ifndef HOSTILE_COMMON_H
#define HOSTILE_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <uncoat.h>
#include "../../unit/known_miss.h"

/* Built with AddressSanitizer? (gcc defines the macro, clang answers __has_feature.) */
#if defined(__SANITIZE_ADDRESS__)
#define HV_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HV_ASAN 1
#endif
#endif

/* ---- checks ------------------------------------------------------------------- */

static int hv_fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		hv_fails++; \
	} \
} while (0)

/* A check that says what it was about when it fails (a case number, a length). */
#define CKF(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s  --  ", __FILE__, __LINE__, #cond); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		hv_fails++; \
	} \
} while (0)

/* A status this build can return: the closed set of status.h. */
static inline int hv_status_ok(enum kuncoat_status st)
{
	return (unsigned)st <= (unsigned)KUNCOAT_BAD_ARG;
}

/* ---- the generator ------------------------------------------------------------ */

static inline uint64_t hv_rng(uint64_t *s)
{
	uint64_t x = *s;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*s = x;
	return x * 0x2545F4914F6CDD1Dull;
}

static inline uint32_t hv_rng32(uint64_t *s)
{
	return (uint32_t)(hv_rng(s) >> 32);
}

/* ---- guard buffers ------------------------------------------------------------ */

#define HV_CANARY_BYTES 64u

struct hv_gb {
	uint8_t *map;       /* the whole mapping */
	size_t   maplen;
	uint8_t *data;      /* first usable byte (page aligned) */
	size_t   dlen;      /* usable bytes (whole pages) */
};

static inline size_t hv_pagesz(void)
{
#ifdef _WIN32
	return 4096u;
#else
	return (size_t)sysconf(_SC_PAGESIZE);
#endif
}

/* Room for up to `cap` bytes with the END of the usable pages flush against a
 * PROT_NONE page (and one before it). Returns 0 on failure. */
static inline int hv_gb_init(struct hv_gb *g, size_t cap)
{
	size_t pg = hv_pagesz();
	size_t need = cap + HV_CANARY_BYTES;

	g->dlen = (need + pg - 1u) / pg * pg;
	g->maplen = g->dlen + 2u * pg;
#ifdef _WIN32
	g->map = malloc(g->maplen);
	if (!g->map)
		return 0;
	g->data = g->map + pg;
#else
	g->map = mmap(NULL, g->maplen, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (g->map == MAP_FAILED) {
		g->map = NULL;
		return 0;
	}
	g->data = g->map + pg;
	if (mprotect(g->map, pg, PROT_NONE) || mprotect(g->data + g->dlen, pg, PROT_NONE)) {
		munmap(g->map, g->maplen);
		g->map = NULL;
		return 0;
	}
#endif
	return 1;
}

static inline void hv_gb_free(struct hv_gb *g)
{
	if (!g->map)
		return;
#ifdef _WIN32
	free(g->map);
#else
	munmap(g->map, g->maplen);
#endif
	g->map = NULL;
}

/* The `len` bytes that END at the guard page. */
static inline uint8_t *hv_gb_at(const struct hv_gb *g, size_t len)
{
	if (len + HV_CANARY_BYTES > g->dlen) {
		printf("  TEST BUG: a guard buffer of %zu bytes was asked for %zu\n", g->dlen - HV_CANARY_BYTES, len);
		abort();
	}
	return g->data + g->dlen - len;
}

/* An input of exactly `len` bytes copied from `src`, a read past it faults. */
static inline const uint8_t *hv_in(const struct hv_gb *g, const uint8_t *src, size_t len)
{
	uint8_t *p = hv_gb_at(g, len);

	if (len)
		memcpy(p, src, len);
	return p;
}

/* An output of exactly `cap` bytes filled with 0xCC and a canary before it. */
static inline uint8_t *hv_out(const struct hv_gb *g, size_t cap)
{
	uint8_t *p = hv_gb_at(g, cap);

	memset(p - HV_CANARY_BYTES, 0xA5, HV_CANARY_BYTES);
	memset(p, 0xCC, cap);
	return p;
}

/* Nothing wrote BEFORE the output. */
static inline int hv_out_canary_ok(const uint8_t *out)
{
	unsigned i;

	for (i = 1; i <= HV_CANARY_BYTES; i++)
		if (out[-(ptrdiff_t)i] != 0xA5)
			return 0;
	return 1;
}

/* Wall clock in seconds. */
static inline double hv_wall(void)
{
#ifdef _WIN32
	return (double)clock() / (double)CLOCKS_PER_SEC;
#else
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
}

/* ---- isolation ---------------------------------------------------------------- */

struct hv_prog {
	volatile uint64_t a, b;
};

static struct hv_prog *hv_prog_p;
static struct hv_prog hv_prog_local;

/* Say which case is running: shown by the parent if the child dies in it. */
static inline void hv_at(uint64_t a, uint64_t b)
{
	if (!hv_prog_p)
		hv_prog_p = &hv_prog_local;
	hv_prog_p->a = a;
	hv_prog_p->b = b;
}

enum { HV_OK = 0, HV_FAILED = 1, HV_CRASHED = 2, HV_HUNG = 3 };

/*
 * Run fn(arg) in a child with `secs` to finish. fn returns non-zero for a failed
 * check. Returns HV_OK, HV_FAILED (checks failed, already printed), HV_CRASHED (a
 * signal, or a sanitizer's exit) or HV_HUNG (the alarm). A crash or a hang prints
 * `name` and the case numbers the child last announced with hv_at.
 */
static inline int hv_isolate(const char *name, int (*fn)(void *), void *arg, unsigned secs)
{
#ifdef _WIN32
	(void)secs;
	(void)name;
	return fn(arg) || hv_fails || km_failed() ? HV_FAILED : HV_OK;
#else
	pid_t pid;
	int status = 0;

	if (!hv_prog_p || hv_prog_p == &hv_prog_local) {
		void *m = mmap(NULL, sizeof *hv_prog_p, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		hv_prog_p = m == MAP_FAILED ? &hv_prog_local : m;
	}
	hv_prog_p->a = hv_prog_p->b = 0;
	fflush(stdout);
	pid = fork();
	if (pid < 0) {
		printf("  FAIL %s: fork failed\n", name);
		return HV_FAILED;
	}
	if (pid == 0) {
		int r;

		alarm(secs);
		hv_fails = 0;
		r = fn(arg);
		fflush(stdout);
		_exit(r || hv_fails || km_failed() ? 77 : 0);
	}
	if (waitpid(pid, &status, 0) < 0) {
		printf("  FAIL %s: waitpid failed\n", name);
		return HV_FAILED;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return HV_OK;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 77)
		return HV_FAILED;
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
		printf("  HANG %s after %us (case %llu, %llu)\n", name, secs,
		       (unsigned long long)hv_prog_p->a, (unsigned long long)hv_prog_p->b);
		return HV_HUNG;
	}
	printf("  CRASH %s: %s %d (case %llu, %llu)\n", name,
	       WIFSIGNALED(status) ? "signal" : "exit", WIFSIGNALED(status) ?
	       WTERMSIG(status) : WEXITSTATUS(status),
	       (unsigned long long)hv_prog_p->a, (unsigned long long)hv_prog_p->b);
	return HV_CRASHED;
#endif
}

/* Wrap a void test function as an isolated group: HV_GROUP(f) defines hv_grp_f. */
#define HV_GROUP(f) \
	static int hv_grp_##f(void *a) \
	{ \
		(void)a; \
		f(); \
		return hv_fails != 0; \
	}

/* A case that must come out clean: HV_OK, or the test fails with the reason. A group
 * that takes more than half a second says how long, so a slow one is seen. */
static inline void hv_expect_clean(const char *name, int (*fn)(void *), void *arg, unsigned secs)
{
	double t0 = hv_wall(), el;
	int r = hv_isolate(name, fn, arg, secs);

	el = hv_wall() - t0;
	if (el > 0.5)
		printf("  (%s: %.2fs)\n", name, el);

	CKF(r == HV_OK, "%s -> %s", name, r == HV_FAILED ? "checks failed" :
	    r == HV_CRASHED ? "crashed" : "hung");
}

/* ---- the receiver ------------------------------------------------------------- */

struct hv_sink {
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
};

static inline int hv_sink_fn(void *user, const uint8_t *p, uint32_t n)
{
	struct hv_sink *s = user;
	uint32_t i;

	s->calls++;
	if (s->refuse_at && s->total >= s->refuse_at) {
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

/* ---- tools: produce real streams without a file ------------------------------- */

/*
 * Run `argv` with `in` on its stdin and return its stdout, malloc'd, or NULL when
 * the tool is not there or fails. Pipes only: no file is created. The input is fed
 * by a second child so a tool that writes before it has read everything cannot
 * deadlock the pair.
 */
static inline uint8_t *hv_tool(const char *const *argv, const uint8_t *in, size_t n,
			       size_t *outn)
{
#ifdef _WIN32
	(void)argv; (void)in; (void)n;
	*outn = 0;
	return NULL;
#else
	int pin[2], pout[2], st1 = 0, st2 = 0, nul;
	pid_t tool, feeder;
	uint8_t *buf = NULL;
	size_t len = 0, cap = 0;

	*outn = 0;
	if (pipe(pin))
		return NULL;
	if (pipe(pout)) {
		close(pin[0]);
		close(pin[1]);
		return NULL;
	}
	fflush(stdout);
	tool = fork();
	if (tool == 0) {
		nul = open("/dev/null", O_WRONLY);
		dup2(pin[0], 0);
		dup2(pout[1], 1);
		if (nul >= 0)
			dup2(nul, 2);
		close(pin[0]); close(pin[1]); close(pout[0]); close(pout[1]);
		execvp(argv[0], (char *const *)(uintptr_t)argv);
		_exit(127);
	}
	feeder = tool < 0 ? -1 : fork();
	if (feeder == 0) {
		size_t off = 0;

		signal(SIGPIPE, SIG_DFL);
		close(pin[0]); close(pout[0]); close(pout[1]);
		while (off < n) {
			ssize_t w = write(pin[1], in + off, n - off);

			if (w <= 0)
				_exit(1);
			off += (size_t)w;
		}
		_exit(0);
	}
	close(pin[0]);
	close(pin[1]);
	close(pout[1]);
	for (;;) {
		ssize_t r;

		if (len + 65536u > cap) {
			uint8_t *q = realloc(buf, cap = cap * 2u + 131072u);

			if (!q) {
				free(buf);
				buf = NULL;
				break;
			}
			buf = q;
		}
		r = read(pout[0], buf + len, cap - len);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
		len += (size_t)r;
	}
	close(pout[0]);
	if (tool > 0)
		waitpid(tool, &st1, 0);
	if (feeder > 0)
		waitpid(feeder, &st2, 0);
	if (!buf || tool < 0 || !WIFEXITED(st1) || WEXITSTATUS(st1) != 0 || !len) {
		free(buf);
		return NULL;
	}
	*outn = len;
	return buf;
#endif
}

/* ---- small shared helpers ------------------------------------------------------- */

/* A deterministic body of `n` bytes that compresses a little: words, runs, noise. */
static inline void hv_body(uint8_t *p, size_t n, uint64_t seed)
{
	static const char *const words[] = {
		"kernel", "socket", "connect", "payload", "stage", "loader", "decode",
		"CreateProcess", "VirtualAlloc", "/bin/sh", "http://", "0123456789"
	};
	uint64_t st = seed | 1u;
	size_t i = 0;

	while (i < n) {
		uint32_t r = hv_rng32(&st) % 8u;

		if (r < 5) {
			const char *w = words[hv_rng32(&st) % 12u];
			size_t l = strlen(w);

			while (l-- && i < n)
				p[i++] = (uint8_t)*w++;
		} else if (r < 7) {
			uint8_t c = (uint8_t)hv_rng32(&st);
			uint32_t run = 3u + hv_rng32(&st) % 40u;

			while (run-- && i < n)
				p[i++] = c;
		} else {
			uint32_t k = 1u + hv_rng32(&st) % 12u;

			while (k-- && i < n)
				p[i++] = (uint8_t)hv_rng32(&st);
		}
	}
}

/* Final line of a test: 0 when nothing failed and no marker is stale. */
static inline int hv_done(const char *name)
{
	if (hv_fails || km_failed()) {
		printf("%s: %d check(s) failed%s\n", name, hv_fails,
		       km_failed() ? ", a KNOWN-MISS marker is stale" : "");
		return 1;
	}
	printf("%s: ok\n", name);
	return 0;
}

#endif /* HOSTILE_COMMON_H */
