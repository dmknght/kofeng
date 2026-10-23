/*
 * hostile_engine.h - what the api_engine_* and hostile_engine_* tests share.
 *
 * Three things only, each of which a second copy would let drift:
 *
 *   GUARD BUFFERS   an input that ENDS on a PROT_NONE page (and, for the empty
 *                   case, IS one), so a parser that reads one byte past the length
 *                   it was given faults instead of reading whatever heap followed.
 *                   A heap buffer of the same size would only show the over-read
 *                   under AddressSanitizer; this shows it in the plain build too.
 *
 *   CHILDREN        a hostile group runs in a forked child with an alarm, so a
 *                   product crash or a hang is a RESULT of the group (signal or
 *                   timeout, reported by name) and not the end of the test binary.
 *
 *   A GENERATOR     a fixed-seed PRNG, so every run draws the same hostile bytes.
 *
 * Header-only and static, like seeds.h: the tests are separate binaries.
 */

#ifndef KOFENG_TEST_HOSTILE_ENGINE_H
#define KOFENG_TEST_HOSTILE_ENGINE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>

#include "../../libkofeng/kofeng.h"
#include "notes.h"

/*
 * UNDER A SANITISER A CRASH IS AN EXIT CODE, NOT A SIGNAL. AddressSanitizer reports and then
 * calls exit(1), which a forked child would hand its parent as "exited with 1" - the
 * parent could not tell a product fault from a test that returned 1. abort_on_error turns
 * the report into SIGABRT, which is what he_child reports as a crash. (The reports still
 * print, and are expected from the children the tests mark as known defects.)
 */
#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
const char *__asan_default_options(void);
const char *__asan_default_options(void)
{
	return "abort_on_error=1:detect_leaks=1";
}

const char *__ubsan_default_options(void);
const char *__ubsan_default_options(void)
{
	return "abort_on_error=1:print_stacktrace=1";
}
#endif

/* ---- checks ------------------------------------------------------------------- */

static unsigned he_fails, he_checks;

#define CK(cond, ...) do { \
	he_checks++; \
	if (!(cond)) { \
		printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		he_fails++; \
	} \
} while (0)

/* ---- generator ---------------------------------------------------------------- */

static uint64_t he_rng = 0x9e3779b97f4a7c15ull;

static inline void he_seed(uint64_t s)
{
	he_rng = s ? s : 1u;
}

static inline uint64_t he_next(void)
{
	uint64_t x = he_rng;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	he_rng = x;
	return x * 0x2545f4914f6cdd1dull;
}

static inline uint32_t he_below(uint32_t n)
{
	return n ? (uint32_t)(he_next() % n) : 0u;
}

/* ---- guard buffers ------------------------------------------------------------ */

struct he_guard {
	uint8_t *map;       /* the whole mapping */
	size_t   map_n;
	uint8_t *p;         /* the bytes: p + n is the first byte of a PROT_NONE page */
	size_t   n;
};

static inline size_t he_page(void)
{
	long v = sysconf(_SC_PAGESIZE);

	return v > 0 ? (size_t)v : 4096u;
}

/*
 * Copy `src` (n bytes, n may be 0) so that its last byte is the last byte before
 * an inaccessible page. src NULL leaves the bytes zero. Returns 0 on failure.
 */
static inline int he_guard_make2(struct he_guard *g, const void *src, size_t n, int front)
{
	size_t pg = he_page();
	size_t body = ((n + pg - 1u) / pg) * pg;

	memset(g, 0, sizeof *g);
	g->map_n = body + 2u * pg;
	g->map = mmap(NULL, g->map_n, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (g->map == MAP_FAILED) {
		g->map = NULL;
		return 0;
	}
	if (mprotect(g->map, pg, PROT_NONE) != 0 ||
	    mprotect(g->map + pg + body, pg, PROT_NONE) != 0) {
		munmap(g->map, g->map_n);
		g->map = NULL;
		return 0;
	}
	g->n = n;
	/* front: the bytes START a page (an under-read faults); otherwise they END one. */
	g->p = front ? g->map + pg : g->map + pg + body - n;
	if (src && n)
		memcpy(g->p, src, n);
	return 1;
}

static inline int he_guard_make(struct he_guard *g, const void *src, size_t n)
{
	return he_guard_make2(g, src, n, 0);
}

static inline void he_guard_free(struct he_guard *g)
{
	if (g->map)
		munmap(g->map, g->map_n);
	memset(g, 0, sizeof *g);
}

/* ---- children ----------------------------------------------------------------- */

struct he_status {
	int exited;    /* 1 when the child returned normally */
	int code;      /* its exit code, when exited */
	int sig;       /* the signal that ended it, otherwise (SIGALRM = a hang) */
};

/*
 * Run fn(arg) in a child with an alarm. The child's own stdout is flushed before
 * _exit, and the parent's before the fork, so nothing prints twice.
 */
static inline struct he_status he_child(int (*fn)(void *), void *arg, unsigned secs)
{
	struct he_status st = { 0, 0, 0 };
	pid_t pid;
	int ws = 0;

	fflush(stdout);
	fflush(stderr);
	pid = fork();
	if (pid < 0) {
		st.sig = -1;
		return st;
	}
	if (pid == 0) {
		int rc;

		signal(SIGALRM, SIG_DFL);
		alarm(secs);
		rc = fn(arg);
		fflush(stdout);
		_exit(rc & 0xff);
	}
	if (waitpid(pid, &ws, 0) < 0) {
		st.sig = -1;
		return st;
	}
	if (WIFEXITED(ws)) {
		st.exited = 1;
		st.code = WEXITSTATUS(ws);
	} else if (WIFSIGNALED(ws)) {
		st.sig = WTERMSIG(ws);
	}
	return st;
}

static inline int he_ok(struct he_status s)
{
	return s.exited && s.code == 0;
}

static inline const char *he_how(struct he_status s)
{
	static char buf[64];

	if (s.exited && s.code == 0)
		return "ok";
	if (s.exited) {
		snprintf(buf, sizeof buf, "exit %d", s.code);
		return buf;
	}
	if (s.sig == SIGALRM)
		return "HANG (alarm)";
	snprintf(buf, sizeof buf, "signal %d", s.sig);
	return buf;
}

/* ---- scratch trees ---------------------------------------------------------------- */

/* Remove `path` and everything under it. lstat, so a symlink is unlinked and never
 * followed out of the tree; the caller passes the one directory the test made. */
static inline void he_rmtree(const char *path)
{
	struct stat sb;
	DIR *d;
	struct dirent *de;
	char p[1024];

	if (lstat(path, &sb) != 0)
		return;
	if (!S_ISDIR(sb.st_mode)) {
		unlink(path);
		return;
	}
	d = opendir(path);
	if (d) {
		while ((de = readdir(d)) != NULL) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			if ((size_t)snprintf(p, sizeof p, "%s/%s", path, de->d_name) >= sizeof p)
				continue;
			he_rmtree(p);
		}
		closedir(d);
	}
	rmdir(path);
}

/* ---- the engine --------------------------------------------------------------- */

#define HE_DB "build/release/databases"

struct he_tally {
	uint64_t objects, bytes, findings, max_name, max_depth;
	uint64_t max_obj;
	uint64_t child_bytes;      /* bytes of every object below the root */
	uint64_t broken;           /* objects reported with a broken reason */
	uint64_t broken_limit;     /* ... of which KOF_BROKEN_LIMIT */
	uint64_t unexamined;       /* objects no module ran on */
};

static inline int he_on_object(const char *name, const void *bytes, uint64_t len,
			const struct kof_result *res, void *user)
{
	struct he_tally *t = (struct he_tally *)user;
	uint64_t nl = name ? (uint64_t)strlen(name) : 0u;
	uint64_t d = name ? kobj_depth(name) : 0u;

	(void)bytes;
	if (!t)
		return 0;
	t->objects++;
	t->bytes += len;
	{
		struct note_list got;

		notes_here(&got);
		t->findings += got.n;
	}
	if (nl > t->max_name)
		t->max_name = nl;
	if (d > t->max_depth)
		t->max_depth = d;
	if (len > t->max_obj)
		t->max_obj = len;
	if (d > 0)
		t->child_bytes += len;
	if (res && res->broken) {
		t->broken++;
		if (res->broken == KOF_BROKEN_LIMIT)
			t->broken_limit++;
	}
	if (res && !res->examined)
		t->unexamined++;
	return 0;
}

/* A descending scan with the budgets of a small test: the ceilings are what a
 * hostile object is measured against, so they are set, not left at zero. */
static inline struct kof_scan_option he_opt(void)
{
	struct kof_scan_option o;

	memset(&o, 0, sizeof o);
	o.heur_level = 1;
	o.recurse_dirs = 1;
	o.max_resident_bytes = 256ull << 20;
	o.max_produced_bytes = 64ull << 20;
	o.max_object_bytes = 64ull << 20;
	return o;
}

/* ---- little-endian writers for the test-local object builders ------------------ */

struct he_w {
	uint8_t *p;
	size_t   n, cap;
	int      oom;
};

static inline void he_put(struct he_w *w, const void *s, size_t n)
{
	if (w->oom)
		return;
	if (w->n + n > w->cap) {
		size_t nc = w->cap ? w->cap : 256u;
		uint8_t *q;

		while (nc < w->n + n)
			nc *= 2u;
		q = realloc(w->p, nc);
		if (!q) {
			w->oom = 1;
			return;
		}
		w->p = q;
		w->cap = nc;
	}
	if (n)
		memcpy(w->p + w->n, s, n);
	w->n += n;
}

static inline void he_u8(struct he_w *w, uint32_t v)
{
	uint8_t b = (uint8_t)v;

	he_put(w, &b, 1);
}

static inline void he_u16(struct he_w *w, uint32_t v)
{
	he_u8(w, v);
	he_u8(w, v >> 8);
}

static inline void he_u32(struct he_w *w, uint32_t v)
{
	he_u16(w, v);
	he_u16(w, v >> 16);
}

static inline void he_u64(struct he_w *w, uint64_t v)
{
	he_u32(w, (uint32_t)v);
	he_u32(w, (uint32_t)(v >> 32));
}

static inline void he_zero(struct he_w *w, size_t n)
{
	while (n--)
		he_u8(w, 0);
}

static inline void he_str(struct he_w *w, const char *s)
{
	he_put(w, s, strlen(s));
}

static inline void he_free(struct he_w *w)
{
	free(w->p);
	memset(w, 0, sizeof *w);
}

/* ---- object writers (valid objects, built in memory) ---------------------------- */

struct he_member {
	const char *name;
	const void *data;
	uint32_t    len;
};

static inline uint32_t he_crc32(const void *p, uint64_t n)
{
	uint32_t c = 0xffffffffu;
	const uint8_t *b = (const uint8_t *)p;
	uint64_t i;
	unsigned k;

	for (i = 0; i < n; i++) {
		c ^= b[i];
		for (k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
	}
	return ~c;
}

/* A zip of stored members: local headers, central directory, end record. */
static inline void he_zip(struct he_w *w, const struct he_member *m, uint32_t n)
{
	uint32_t i, cd_off, cd_n;
	uint32_t *lho = calloc(n ? n : 1u, sizeof *lho);

	if (!lho) {
		w->oom = 1;
		return;
	}
	for (i = 0; i < n; i++) {
		size_t nl = strlen(m[i].name);

		lho[i] = (uint32_t)w->n;
		he_u32(w, 0x04034b50u);
		he_u16(w, 20);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u16(w, 0x21);
		he_u32(w, he_crc32(m[i].data, m[i].len));
		he_u32(w, m[i].len);
		he_u32(w, m[i].len);
		he_u16(w, (uint32_t)nl);
		he_u16(w, 0);
		he_put(w, m[i].name, nl);
		he_put(w, m[i].data, m[i].len);
	}
	cd_off = (uint32_t)w->n;
	for (i = 0; i < n; i++) {
		size_t nl = strlen(m[i].name);

		he_u32(w, 0x02014b50u);
		he_u16(w, 20);
		he_u16(w, 20);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u16(w, 0x21);
		he_u32(w, he_crc32(m[i].data, m[i].len));
		he_u32(w, m[i].len);
		he_u32(w, m[i].len);
		he_u16(w, (uint32_t)nl);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u32(w, 0);
		he_u32(w, lho[i]);
		he_put(w, m[i].name, nl);
	}
	cd_n = (uint32_t)w->n - cd_off;
	he_u32(w, 0x06054b50u);
	he_u16(w, 0);
	he_u16(w, 0);
	he_u16(w, n);
	he_u16(w, n);
	he_u32(w, cd_n);
	he_u32(w, cd_off);
	he_u16(w, 0);
	free(lho);
}

/* A gzip member holding stored deflate blocks. */
static inline void he_gzip(struct he_w *w, const void *d, uint32_t n)
{
	const uint8_t *p = (const uint8_t *)d;
	uint32_t off = 0;

	he_u8(w, 0x1f);
	he_u8(w, 0x8b);
	he_u8(w, 8);
	he_u8(w, 0);
	he_u32(w, 0);
	he_u8(w, 0);
	he_u8(w, 3);
	do {
		uint32_t k = n - off > 65535u ? 65535u : n - off;
		int last = off + k == n;

		he_u8(w, last ? 1u : 0u);
		he_u16(w, k);
		he_u16(w, ~k & 0xffffu);
		he_put(w, p + off, k);
		off += k;
	} while (off < n);
	he_u32(w, he_crc32(d, n));
	he_u32(w, n);
}

/* A ustar archive. */
static inline void he_tar(struct he_w *w, const struct he_member *m, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		uint8_t h[512];
		unsigned sum = 0, k;
		size_t pad;

		memset(h, 0, sizeof h);
		strncpy((char *)h, m[i].name, 99);
		memcpy(h + 100, "0000644", 7);
		memcpy(h + 108, "0000000", 7);
		memcpy(h + 116, "0000000", 7);
		snprintf((char *)h + 124, 12, "%011o", m[i].len);
		memcpy(h + 136, "00000000000", 11);
		h[156] = '0';
		memcpy(h + 257, "ustar", 5);
		memcpy(h + 263, "00", 2);
		memset(h + 148, ' ', 8);
		for (k = 0; k < 512; k++)
			sum += h[k];
		snprintf((char *)h + 148, 8, "%06o", sum);
		h[154] = 0;
		h[155] = ' ';
		he_put(w, h, sizeof h);
		he_put(w, m[i].data, m[i].len);
		pad = (512u - (m[i].len & 511u)) & 511u;
		he_zero(w, pad);
	}
	he_zero(w, 1024);
}

/* A fixed-Huffman deflate stream that inflates to 1 + 258*k bytes of `c` (c < 144):
 * one literal and k maximal matches at distance 1 - about 160:1, and the whole of
 * what a bomb needs, since a bomb needs no nesting and a depth limit never sees it. */
struct he_bits {
	struct he_w *w;
	uint32_t     acc;
	unsigned     n;
};

static inline void he_bits_put(struct he_bits *b, uint32_t v, unsigned n)
{
	b->acc |= v << b->n;
	b->n += n;
	while (b->n >= 8) {
		he_u8(b->w, b->acc & 0xffu);
		b->acc >>= 8;
		b->n -= 8;
	}
}

static inline void he_bits_code(struct he_bits *b, uint32_t code, unsigned n)
{
	uint32_t r = 0, i;

	for (i = 0; i < n; i++)
		r |= ((code >> i) & 1u) << (n - 1u - i);
	he_bits_put(b, r, n);
}

static inline void he_deflate_run(struct he_w *w, uint8_t c, uint64_t k)
{
	struct he_bits b = { w, 0, 0 };
	uint64_t i;

	he_bits_put(&b, 1, 1);
	he_bits_put(&b, 1, 2);
	he_bits_code(&b, 0x30u + c, 8);
	for (i = 0; i < k; i++) {
		he_bits_code(&b, 0xc5, 8);
		he_bits_code(&b, 0, 5);
	}
	he_bits_code(&b, 0, 7);
	if (b.n)
		he_u8(w, b.acc & 0xffu);
}

/* ---- scanning ------------------------------------------------------------------- */

static inline int he_scan(kof_scanner *sc, const void *p, uint64_t n, const char *name,
			  const struct kof_scan_option *o, struct he_tally *t)
{
	memset(t, 0, sizeof *t);
	return kscan_bytes(sc, p, n, name, o, he_on_object, t);
}

#endif /* KOFENG_TEST_HOSTILE_ENGINE_H */
