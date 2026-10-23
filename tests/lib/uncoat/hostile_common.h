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
#include "../fuzz_kit.h"

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

/* The kit's generator (fuzz_kit.h), the stream this harness has always used. */
static inline uint64_t hv_rng(uint64_t *s)
{
	return fz_rng_star(s);
}

static inline uint32_t hv_rng32(uint64_t *s)
{
	return (uint32_t)(hv_rng(s) >> 32);
}

/* ---- guard buffers ------------------------------------------------------------ */

#define HV_CANARY_BYTES 64u

/* The kit's guard buffer with a PROT_NONE page in front as well as behind and a canary margin (fuzz_kit.h). */
struct hv_gb {
	struct fz_gb g;
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
	return fz_gb_init(&g->g, cap, 1, HV_CANARY_BYTES);
}

static inline void hv_gb_free(struct hv_gb *g)
{
	fz_gb_free(&g->g);
}

/* The `len` bytes that END at the guard page. */
static inline uint8_t *hv_gb_at(const struct hv_gb *g, size_t len)
{
	uint8_t *p = fz_gb_end(&g->g, len);

	if (!p) {
		printf("  TEST BUG: a guard buffer of %zu bytes was asked for %zu\n", g->g.dlen - HV_CANARY_BYTES, len);
		abort();
	}
	return p;
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

/* Say which case is running: shown by the parent if the child dies in it (the kit's mailbox). */
static inline void hv_at(uint64_t a, uint64_t b)
{
	fz_at(a, b);
}

/* A test reads which case it was in as hv_prog_p->a / ->b: that is the kit's mailbox. */
#define hv_prog_p fz_mb

enum { HV_OK = 0, HV_FAILED = 1, HV_CRASHED = 2, HV_HUNG = 3 };

struct hv_iso_arg {
	int (*fn)(void *);
	void *arg;
};

static inline int hv_iso_child(void *a)
{
	struct hv_iso_arg *x = (struct hv_iso_arg *)a;
	int r;

	hv_fails = 0;
	r = x->fn(x->arg);
	return r || hv_fails || km_failed() ? 77 : 0;
}

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
	struct hv_iso_arg x = { fn, arg };
	struct fz_iso iso;

	fz_mail_share();
	if (fz_isolate(hv_iso_child, &x, secs, NULL, &iso) < 0) {
		printf("  FAIL %s: fork failed\n", name);
		return HV_FAILED;
	}
	if (iso.kind == FZ_EXITED && iso.code == 0)
		return HV_OK;
	if (iso.kind == FZ_EXITED && iso.code == 77)
		return HV_FAILED;
	if (iso.kind == FZ_TIMEOUT) {
		printf("  HANG %s after %us (case %llu, %llu)\n", name, secs,
		       (unsigned long long)fz_mb->a, (unsigned long long)fz_mb->b);
		return HV_HUNG;
	}
	printf("  CRASH %s: %s %d (case %llu, %llu)\n", name,
	       iso.kind == FZ_SIGNALED ? "signal" : "exit", iso.kind == FZ_SIGNALED ? iso.sig : iso.code,
	       (unsigned long long)fz_mb->a, (unsigned long long)fz_mb->b);
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

/* The kit's receiver (fuzz_kit.h): `struct hv_sink` IS `struct fz_sink`, with the same fields. */
#define hv_sink fz_sink

static inline int hv_sink_fn(void *user, const uint8_t *p, uint32_t n)
{
	return fz_sink_fn(user, p, n);
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
