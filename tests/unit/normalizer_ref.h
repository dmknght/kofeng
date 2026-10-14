/*
 * normalizer_ref.h - what the normaliser tests compare the product AGAINST.
 *
 * Everything here is written from the contract in executables.h and from the
 * rules the product's comments state, one byte at a time and with no shortcut:
 * no memchr skip, no word-wide zero count, no cached bound. A reference that
 * shared the product's optimisations would agree with them for the wrong
 * reason, so each of these is the slow obvious reading, and the tests ask the
 * product to equal it on thousands of generated objects.
 *
 *   - the check counters and a deterministic generator;
 *   - guard-page buffers (mmap, PROT_NONE on both sides) and a forked group
 *     runner, so an over-read or over-write is a signal the test can report;
 *   - encoders (base64, hex, percent) that do not use the product's decoders;
 *   - the reference transform (zero collapse, narrowing, keep and drop maps,
 *     mark carry) and the reference decode passes with the layer loop;
 *   - the generator of objects that mix plain bytes with encoded runs.
 *
 * Includes only the normaliser's own header, so every test that uses it links
 * the engine archive and nothing else is assumed.
 */

#ifndef KOFENG_TESTS_NORMALIZER_REF_H
#define KOFENG_TESTS_NORMALIZER_REF_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "../../libkofeng/analyzers/normalize/executables.h"

#define NR_UNUSED __attribute__((unused))

/* ---- checks ----------------------------------------------------------------- */

static unsigned nr_ok NR_UNUSED, nr_bad NR_UNUSED;

#define NCK(cond) do { \
	if (cond) { \
		nr_ok++; \
	} else { \
		nr_bad++; \
		if (nr_bad <= 40u) \
			printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

/* A check that says WHAT it was about when it fails: the loops run thousands of
 * seeds and "cond" alone would not say which. */
#define NCKF(cond, ...) do { \
	if (cond) { \
		nr_ok++; \
	} else { \
		nr_bad++; \
		if (nr_bad <= 40u) { \
			printf("  FAIL %s:%d  %s  [", __FILE__, __LINE__, #cond); \
			printf(__VA_ARGS__); \
			printf("]\n"); \
		} \
	} \
} while (0)

/* ---- the generator ------------------------------------------------------------ */

struct nrng {
	uint64_t s;
};

static inline uint64_t nr_next(struct nrng *r) NR_UNUSED;
static inline uint64_t nr_next(struct nrng *r)
{
	r->s ^= r->s >> 12;
	r->s ^= r->s << 25;
	r->s ^= r->s >> 27;
	return r->s * 2685821657736338717ull;
}

static inline uint32_t nr_below(struct nrng *r, uint32_t n) NR_UNUSED;
static inline uint32_t nr_below(struct nrng *r, uint32_t n)
{
	return n ? (uint32_t)(nr_next(r) >> 33) % n : 0u;
}

static inline void nr_seed(struct nrng *r, uint64_t seed) NR_UNUSED;
static inline void nr_seed(struct nrng *r, uint64_t seed)
{
	r->s = seed * 0x9e3779b97f4a7c15ull + 0x1234567ull;
	if (!r->s)
		r->s = 1;
	(void)nr_next(r);
}

/* ---- guard-page buffers ---------------------------------------------------------- */

/*
 * `n` usable bytes with a PROT_NONE page on each side. `tail` puts the bytes
 * flush against the page AFTER (an over-read or over-write at the end faults);
 * otherwise they sit flush against the page BEFORE (an under-run faults). For
 * n == 0 the pointer is the boundary itself, so any access faults.
 */
struct gbuf {
	uint8_t *base;
	size_t   total;
	uint8_t *p;
	size_t   n;
};

static int gb_new(struct gbuf *g, size_t n, int tail) NR_UNUSED;
static int gb_new(struct gbuf *g, size_t n, int tail)
{
	size_t pg = (size_t)sysconf(_SC_PAGESIZE);
	size_t body = (n + pg - 1u) / pg * pg;
	uint8_t *m;

	if (!body)
		body = pg;
	g->total = body + 2u * pg;
	m = mmap(NULL, g->total, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED)
		return 0;
	if (mprotect(m, pg, PROT_NONE) || mprotect(m + pg + body, pg, PROT_NONE)) {
		munmap(m, g->total);
		return 0;
	}
	g->base = m;
	g->n = n;
	g->p = tail ? m + pg + body - n : m + pg;
	return 1;
}

static void gb_free(struct gbuf *g) NR_UNUSED;
static void gb_free(struct gbuf *g)
{
	if (g->base)
		munmap(g->base, g->total);
	memset(g, 0, sizeof *g);
}

/* ---- forked groups ----------------------------------------------------------------- */

typedef int (*nr_group_fn)(void *);

/* A coverage build (gcc --coverage, with -DNR_COVERAGE) writes its counters at exit,
 * and a forked group leaves by _exit; this is the one call that writes them first.
 * An ordinary build defines nothing and the call is not there. */
#ifdef NR_COVERAGE
extern void __gcov_dump(void);
#define NR_FLUSH_COUNTERS() __gcov_dump()
#else
#define NR_FLUSH_COUNTERS() ((void)0)
#endif

/* set around a group that is EXPECTED to die, so the report stays quiet */
static int nr_quiet NR_UNUSED;

/*
 * Run `fn` in a child. 0 when it returned 0; what it returned (at most 100) when
 * it returned something else - a failure count, or a code the caller chose; 128 + signal when it died (an over-read of a guard page is SIGSEGV or,
 * under the sanitiser, an abort). The child is bounded by an alarm, so a hang is
 * a signal too and not a stuck suite.
 */
static int nr_group(const char *name, nr_group_fn fn, void *arg) NR_UNUSED;
static int nr_group(const char *name, nr_group_fn fn, void *arg)
{
	pid_t pid;
	int st = 0;

	fflush(stdout);
	pid = fork();
	if (pid < 0)
		return 255;
	if (!pid) {
		int rc;

		alarm(60);
		nr_ok = nr_bad = 0;     /* this child's own count */
		rc = fn(arg);
		fflush(stdout);
		NR_FLUSH_COUNTERS();
		_exit(rc ? (rc > 100 ? 100 : rc) : (nr_bad ? 1 : 0));
	}
	if (waitpid(pid, &st, 0) < 0)
		return 255;
	if (WIFSIGNALED(st)) {
		if (!nr_quiet)
			printf("  group '%s' died on signal %d\n", name, WTERMSIG(st));
		return 128 + WTERMSIG(st);
	}
	return WIFEXITED(st) ? WEXITSTATUS(st) : 255;
}

/* ---- encoders (independent of the product's decoders) ---------------------------------- */

static const char NR_B64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char NR_B64URL[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Base64 of `in`; `pad` appends '='; `wrap` > 0 breaks the line every `wrap`
 * characters with "\n"; `urlsafe` swaps the last two digits. Returns length. */
static size_t nr_b64_enc(const uint8_t *in, size_t n, char *out, int pad,
			 unsigned wrap, int urlsafe) NR_UNUSED;
static size_t nr_b64_enc(const uint8_t *in, size_t n, char *out, int pad,
			 unsigned wrap, int urlsafe)
{
	const char *al = urlsafe ? NR_B64URL : NR_B64;
	size_t i, o = 0, col = 0;

	for (i = 0; i < n; i += 3u) {
		size_t k = n - i < 3u ? n - i : 3u;
		uint32_t v = (uint32_t)in[i] << 16;
		char q[4];
		size_t j, want = k + 1u;

		if (k > 1u)
			v |= (uint32_t)in[i + 1u] << 8;
		if (k > 2u)
			v |= in[i + 2u];
		q[0] = al[(v >> 18) & 63u];
		q[1] = al[(v >> 12) & 63u];
		q[2] = al[(v >> 6) & 63u];
		q[3] = al[v & 63u];
		for (j = 0; j < 4u; j++) {
			if (j >= want) {
				if (!pad)
					continue;
				q[j] = '=';
			}
			if (wrap && col == wrap) {
				out[o++] = '\n';
				col = 0;
			}
			out[o++] = q[j];
			col++;
		}
	}
	return o;
}

static size_t nr_hex_enc(const uint8_t *in, size_t n, char *out, int upper) NR_UNUSED;
static size_t nr_hex_enc(const uint8_t *in, size_t n, char *out, int upper)
{
	const char *d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2u * i] = d[in[i] >> 4];
		out[2u * i + 1u] = d[in[i] & 15u];
	}
	return 2u * n;
}

/* Percent-encode every byte that is not a letter or a digit; ' ' as '+' when
 * `plus`. Returns length. */
static size_t nr_pct_enc(const uint8_t *in, size_t n, char *out, int plus) NR_UNUSED;
static size_t nr_pct_enc(const uint8_t *in, size_t n, char *out, int plus)
{
	const char *d = "0123456789ABCDEF";
	size_t i, o = 0;

	for (i = 0; i < n; i++) {
		uint8_t c = in[i];

		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
		    (c >= 'a' && c <= 'z')) {
			out[o++] = (char)c;
		} else if (c == ' ' && plus) {
			out[o++] = '+';
		} else {
			out[o++] = '%';
			out[o++] = d[c >> 4];
			out[o++] = d[c & 15u];
		}
	}
	return o;
}

/* ---- the reference transform ---------------------------------------------------------------- */

static int nr_wide_char(uint8_t lo, uint8_t hi)
{
	return hi == 0 && lo >= 0x20 && lo <= 0x7e;
}

/* UTF-16LE ASCII characters starting at i, never reading at or past `lim`. */
static uint64_t nr_wide_run(const uint8_t *p, uint64_t lim, uint64_t i)
{
	uint64_t k = 0;

	while (i + 2u * k + 1u < lim && nr_wide_char(p[i + 2u * k], p[i + 2u * k + 1u]))
		k++;
	return k;
}

static uint64_t nr_zero_run(const uint8_t *p, uint64_t lim, uint64_t i)
{
	uint64_t k = 0;

	while (i + k < lim && !p[i + k])
		k++;
	return k;
}

static int nr_bit(const uint8_t *map, uint64_t i)
{
	return map && (map[i >> 3] >> (i & 7u)) & 1u;
}

static void nr_bit_set(uint8_t *map, uint64_t from, uint64_t to) NR_UNUSED;
static void nr_bit_set(uint8_t *map, uint64_t from, uint64_t to)
{
	uint64_t i;

	for (i = from; i < to; i++)
		map[i >> 3] |= (uint8_t)(1u << (i & 7u));
}

/* kof_exe_unwide, from its header: a run of eight or more printable-and-zero
 * pairs is packed to the left of its own place and the vacated half is zeroed.
 * Writes n bytes into `o` (a copy first); returns whether anything moved. */
static int nr_unwide(const uint8_t *p, uint64_t n, uint8_t *o) NR_UNUSED;
static int nr_unwide(const uint8_t *p, uint64_t n, uint8_t *o)
{
	uint64_t i = 0;
	int changed = 0;

	memcpy(o, p, n);
	while (i + 1u < n) {
		uint64_t k = nr_wide_run(p, n, i), j;

		if (k < KOF_EXE_NORM_WIDE_MIN) {
			i++;
			continue;
		}
		for (j = 0; j < k; j++)
			o[i + j] = p[i + 2u * j];
		memset(o + i + k, 0, k);
		i += 2u * k;
		changed = 1;
	}
	return changed;
}

/* One output piece, as the reference sees it. */
struct nr_span {
	uint64_t src_off, src_len, dst_off, dst_len;
	uint8_t  kind;
};

struct nr_req {
	const uint8_t  *in;
	uint64_t        n;
	const uint8_t  *keep, *drop;    /* bitmaps or NULL */
	uint32_t        ops;
	const uint64_t *mark;
	uint32_t        n_mark;
};

struct nr_out {
	uint8_t        *out;        /* n bytes, the caller's */
	uint64_t       *mark_out;   /* n_mark answers, the caller's */
	uint64_t        len;        /* the return value of the transform */
	uint32_t        fired;
	struct nr_span *span;
	uint32_t        n_span;
};

/*
 * THE TRANSFORM, FROM ITS CONTRACT.
 *
 * Byte by byte: a dropped byte is removed; a kept byte is copied; a free byte
 * starts a wide run (checked first) or a zero run, each bounded by the next
 * kept or dropped byte, else it is copied. A mark is answered when the walk
 * first stands at or past it. Returns the output length, or 0 when nothing was
 * rewritten (and then the output is not meaningful, as in the product).
 */
static uint64_t nr_norm(const struct nr_req *rq, struct nr_out *ro) NR_UNUSED;
static uint64_t nr_norm(const struct nr_req *rq, struct nr_out *ro)
{
	const uint8_t *in = rq->in, *keep = rq->keep, *drop = rq->drop;
	const uint64_t n = rq->n, *mark = rq->mark;
	const uint32_t ops = rq->ops, nm = rq->n_mark;
	uint8_t *out = ro->out;
	uint64_t *mark_out = ro->mark_out;
	uint64_t *lim_at = malloc((n + 1u) * sizeof *lim_at);
	uint64_t i, o = 0;
	uint32_t q = 0, did = 0, cap_sp = 64u;
	int changed = 0;
	uint64_t at;

	ro->n_span = 0;
	ro->span = malloc(cap_sp * sizeof *ro->span);
	/* the next kept or dropped byte at or after each position */
	lim_at[n] = n;
	for (at = n; at-- > 0;)
		lim_at[at] = (nr_bit(keep, at) || nr_bit(drop, at)) ? at : lim_at[at + 1u];
	for (i = 0; i < n;) {
		uint64_t k, lim;
		struct nr_span s;

		while (q < nm && mark[q] <= i)
			mark_out[q++] = o;
		s.kind = KOF_EXE_NORM_COPY;
		s.src_off = i;
		s.dst_off = o;
		if (nr_bit(drop, i)) {
			i++;
			did |= KOF_EXE_NORM_CUTLIB;
			changed = 1;
			continue;
		}
		if (nr_bit(keep, i)) {
			s.src_len = s.dst_len = 1u;
			out[o++] = in[i++];
		} else {
			lim = lim_at[i];
			if ((ops & KOF_EXE_NORM_UNWIDE) &&
			    (k = nr_wide_run(in, lim, i)) >= KOF_EXE_NORM_WIDE_MIN) {
				uint64_t j;

				for (j = 0; j < k; j++)
					out[o + j] = in[i + 2u * j];
				s.kind = KOF_EXE_NORM_UNWIDENED;
				s.src_len = 2u * k;
				s.dst_len = k;
				i += 2u * k;
				o += k;
				did |= KOF_EXE_NORM_UNWIDE;
				changed = 1;
			} else if ((ops & KOF_EXE_NORM_NULLRUN) &&
				   (k = nr_zero_run(in, lim, i)) >= KOF_EXE_NORM_NULL_MIN) {
				out[o] = out[o + 1u] = 0;
				s.kind = KOF_EXE_NORM_NULLS;
				s.src_len = k;
				s.dst_len = 2u;
				i += k;
				o += 2u;
				did |= KOF_EXE_NORM_NULLRUN;
				changed = 1;
			} else {
				s.src_len = s.dst_len = 1u;
				out[o++] = in[i++];
			}
		}
		if (ro->n_span && s.kind == KOF_EXE_NORM_COPY &&
		    ro->span[ro->n_span - 1u].kind == KOF_EXE_NORM_COPY &&
		    ro->span[ro->n_span - 1u].src_off + ro->span[ro->n_span - 1u].src_len == s.src_off &&
		    ro->span[ro->n_span - 1u].dst_off + ro->span[ro->n_span - 1u].dst_len == s.dst_off) {
			ro->span[ro->n_span - 1u].src_len += s.src_len;
			ro->span[ro->n_span - 1u].dst_len += s.dst_len;
			continue;
		}
		if (ro->n_span == cap_sp) {
			cap_sp *= 2u;
			ro->span = realloc(ro->span, cap_sp * sizeof *ro->span);
		}
		ro->span[ro->n_span++] = s;
	}
	while (q < nm)
		mark_out[q++] = o;
	free(lim_at);
	ro->fired = did;
	ro->len = changed ? o : 0u;
	return ro->len;
}

/* ---- the reference decode passes ---------------------------------------------------------------- */

struct nr_note {
	uint64_t off, len;
};

struct nr_notes {
	struct nr_note *v;
	uint32_t        n, cap;
};

static void nr_note_add(struct nr_notes *t, uint64_t off, uint64_t len)
{
	if (!t)
		return;
	if (t->n == t->cap) {
		t->cap = t->cap ? 2u * t->cap : 64u;
		t->v = realloc(t->v, t->cap * sizeof *t->v);
	}
	t->v[t->n].off = off;
	t->v[t->n].len = len;
	t->n++;
}

/*
 * What a write notes for the next round: the stretch, and past the zero fill behind it (to
 * `src_end`, not walked) the token after it up to the next hard delimiter plus 24 bytes of room
 * for the separators and the decoder's name an anchored pass needs past a token. A NUL
 * the fill leaves is a legal delimiter, so the token behind it can be readable now.
 */
static void nr_note_run(struct nr_notes *t, const uint8_t *p, uint64_t n, uint64_t off,
			uint64_t out_n, uint64_t src_end)
{
	uint64_t e = src_end;

	nr_note_add(t, off, out_n);
	while (e < n && p[e] != 0 && p[e] != ' ' && p[e] != '\t' && p[e] != '\n' && p[e] != '\r')
		e++;
	e = e + 24u < n ? e + 24u : n;
	if (e > src_end)
		nr_note_add(t, src_end, e - src_end);
}

static int nr_hexv(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int nr_b64v(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

/* A byte a payload's run may hold: the alphabet, padding, line breaks. */
static int nr_b64_run_char(uint8_t c)
{
	return nr_b64v(c) >= 0 || c == '=' || c == '\n' || c == '\r';
}

/* Is the decoder named at i; its length, or 0. */
static uint32_t nr_b64_anchor(const uint8_t *p, uint64_t n, uint64_t i)
{
	if (n - i < 9u)
		return 0;
	if (memcmp(p + i, "base64 -", 8u))
		return 0;
	if (n - i >= 15u && !memcmp(p + i + 7u, "--decode", 8u))
		return 15u;
	return (p[i + 8u] == 'd' || p[i + 8u] == 'D') ? 9u : 0u;
}

/* Lax base64 of in[0..n): every byte that is not an alphabet digit is skipped. */
static uint64_t nr_b64_lax(const uint8_t *in, uint64_t n, uint8_t *out)
{
	uint32_t acc = 0, have = 0;
	uint64_t i, w = 0;

	for (i = 0; i < n; i++) {
		int v = nr_b64v(in[i]);

		if (v < 0)
			continue;
		acc = (acc << 6) | (uint32_t)v;
		have += 6u;
		if (have >= 8u) {
			have -= 8u;
			out[w++] = (uint8_t)(acc >> have);
		}
	}
	return w;
}

static int nr_unb64(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		    struct nr_notes *nt)
{
	uint64_t i;
	int changed = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;
	for (i = from; i + 8u < to; i++) {
		uint64_t run_end = i, run_beg, j, got;
		int piped = 0;
		uint8_t before, *tmp;

		if (!nr_b64_anchor(p, n, i))
			continue;
		for (j = 0; j < 8u && run_end > 0; j++) {
			uint8_t c = p[run_end - 1u];

			if (c == '|' || c == '<' || c == '>')
				piped = 1;
			else if (c != ' ' && c != '\t' && c != ')' && c != '"' && c != '\'')
				break;
			run_end--;
		}
		if (!piped)
			continue;
		run_beg = run_end;
		while (run_beg > 0 && nr_b64_run_char(p[run_beg - 1u]))
			run_beg--;
		for (j = run_beg; j + 1u < run_end; j++)
			if (p[j] == '=' && p[j + 1u] != '=')
				run_beg = j + 1u;
		if (run_end - run_beg < 16u)
			continue;
		before = run_beg ? p[run_beg - 1u] : 0;
		if (before != 0 && before != ' ' && before != '\t' && before != '"' &&
		    before != '\'' && before != '(' && before != '=' && before != '\n')
			continue;
		tmp = malloc(run_end - run_beg);
		got = nr_b64_lax(p + run_beg, run_end - run_beg, tmp);
		if (got) {
			memcpy(p + run_beg, tmp, got);
			memset(p + run_beg + got, 0, run_end - run_beg - got);
			nr_note_run(nt, p, n, run_beg, got, run_end);
			changed = 1;
		}
		free(tmp);
	}
	return changed;
}

/* What a decoded byte may be for a run to count as text. */
static int nr_text(int c)
{
	return (c >= 0x20 && c <= 0x7e) || c == 9 || c == 10 || c == 13;
}

/* The bytes that may precede a payload. */
static int nr_delim(uint8_t c)
{
	return c == 0 || strchr(" \t\"'(=\n\r,;:>|{[", c) != NULL;
}

static int nr_has_letter(const uint8_t *p, uint64_t beg, uint64_t end)
{
	uint64_t j;

	for (j = beg; j < end; j++)
		if (nr_hexv(p[j]) > 9)
			return 1;
	return 0;
}

static void nr_hex_decode(uint8_t *p, uint64_t n, uint64_t beg, uint64_t end,
			  struct nr_notes *nt)
{
	uint64_t j, w = 0;
	uint64_t len = end - beg;

	for (j = beg; j < end; j += 2u)
		p[beg + w++] = (uint8_t)((nr_hexv(p[j]) << 4) | nr_hexv(p[j + 1u]));
	memset(p + beg + w, 0, len - w);
	nr_note_run(nt, p, n, beg, w, end);
}

static int nr_unhex(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		    struct nr_notes *nt)
{
	uint64_t i = from;
	int changed = 0;
	struct { uint64_t beg, end; } *pend = NULL;
	uint32_t n_pend = 0, cap_pend = 0, n_lett = 0, k;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;
	while (i < to) {
		uint64_t beg, end, j;
		int text = 1, even;

		if (nr_hexv(p[i]) < 0) {
			i++;
			continue;
		}
		beg = i;
		while (i < to && nr_hexv(p[i]) >= 0)
			i++;
		end = i;
		even = ((end - beg) & 1u) == 0;
		if (!even)
			end--;
		if (end - beg < 24u) {
			if (!even || end - beg < 8u || beg == 0 || end >= n)
				continue;
			if ((p[beg - 1u] != '\'' && p[beg - 1u] != '"') || p[end] != p[beg - 1u])
				continue;
			for (j = beg; j < end && text; j += 2u)
				text = nr_text((nr_hexv(p[j]) << 4) | nr_hexv(p[j + 1u]));
			if (!text)
				continue;
			if (n_pend == cap_pend) {
				cap_pend = cap_pend ? 2u * cap_pend : 64u;
				pend = realloc(pend, cap_pend * sizeof *pend);
			}
			pend[n_pend].beg = beg;
			pend[n_pend].end = end;
			n_pend++;
			if (nr_has_letter(p, beg, end))
				n_lett++;
			continue;
		}
		if (!nr_delim(beg ? p[beg - 1u] : 0))
			continue;
		for (j = beg; j < end && text; j += 2u)
			text = nr_text((nr_hexv(p[j]) << 4) | nr_hexv(p[j + 1u]));
		if (!text)
			continue;
		nr_hex_decode(p, n, beg, end, nt);
		changed = 1;
	}
	if (n_lett >= 4u)
		for (k = 0; k < n_pend; k++) {
			nr_hex_decode(p, n, pend[k].beg, pend[k].end, nt);
			changed = 1;
		}
	free(pend);
	return changed;
}

/* The bytes a percent-encoded run may be made of: the 85 the product's table
 * holds, spelled as the characters they are. */
static int nr_pct_body(uint8_t c)
{
	return c && strchr("!#$%&'()*+,-./0123456789:;=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			   "[]_~abcdefghijklmnopqrstuvwxyz", c) != NULL;
}

static int nr_unpct(uint8_t *p, uint64_t n, uint64_t from, uint64_t to,
		    struct nr_notes *nt)
{
	uint64_t i = from;
	int changed = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;
	while (i < to) {
		uint64_t beg, end, j, w;
		uint32_t esc = 0;
		int text = 1;

		if (!nr_pct_body(p[i])) {
			i++;
			continue;
		}
		beg = i;
		while (i < to && nr_pct_body(p[i]))
			i++;
		end = i;
		if (end - beg < 8u || !nr_delim(beg ? p[beg - 1u] : 0))
			continue;
		for (j = beg; j < end && text; j++) {
			if (p[j] != '%')
				continue;
			if (j + 1u < end && p[j + 1u] == '%') {
				text = 0;
				break;
			}
			if (j + 2u >= end || nr_hexv(p[j + 1u]) < 0 || nr_hexv(p[j + 2u]) < 0)
				continue;
			esc++;
			text = nr_text((nr_hexv(p[j + 1u]) << 4) | nr_hexv(p[j + 2u]));
			j += 2u;
		}
		if (!text || esc < 4u)
			continue;
		w = 0;
		for (j = beg; j < end; j++) {
			if (p[j] == '%' && j + 2u < end && nr_hexv(p[j + 1u]) >= 0 &&
			    nr_hexv(p[j + 2u]) >= 0) {
				p[beg + w++] = (uint8_t)((nr_hexv(p[j + 1u]) << 4) | nr_hexv(p[j + 2u]));
				j += 2u;
			} else {
				p[beg + w++] = p[j] == '+' ? (uint8_t)' ' : p[j];
			}
		}
		memset(p + beg + w, 0, end - beg - w);
		nr_note_run(nt, p, n, beg, w, end);
		changed = 1;
	}
	return changed;
}

/*
 * THE LAYER LOOP, with the same budget the header states: round zero is the
 * whole object, each round walks only what the one before wrote, and the bytes
 * walked over rounds after the first may not pass eight times the object.
 */
struct nr_dec {
	int      changed;
	uint32_t limit, rounds;
	uint64_t scanned, dropped;
};

static void nr_decode(uint8_t *p, uint64_t n, struct nr_dec *r) NR_UNUSED;
static void nr_decode(uint8_t *p, uint64_t n, struct nr_dec *r)
{
	struct nr_notes cur, nxt, tmp;
	uint64_t work = 8u * n, spent = n;
	uint32_t k;

	memset(r, 0, sizeof *r);
	memset(&cur, 0, sizeof cur);
	memset(&nxt, 0, sizeof nxt);
	if (!p || !n)
		return;
	nr_note_add(&cur, 0, n);
	while (cur.n) {
		nxt.n = 0;
		r->rounds++;
		for (k = 0; k < cur.n; k++) {
			uint64_t a = cur.v[k].off, b = a + cur.v[k].len;

			if (!cur.v[k].len)
				continue;
			if (r->rounds > 1u) {
				if (cur.v[k].len > work - spent) {
					r->limit |= KOF_EXE_DEC_WORK;
					r->dropped += cur.n - k;
					break;
				}
				spent += cur.v[k].len;
			}
			r->changed |= nr_unb64(p, n, a, b, &nxt);
			r->changed |= nr_unhex(p, n, a, b, &nxt);
			r->changed |= nr_unpct(p, n, a, b, &nxt);
		}
		if (r->limit & KOF_EXE_DEC_WORK)
			break;
		tmp = cur;
		cur = nxt;
		nxt = tmp;
	}
	r->scanned = spent;
	free(cur.v);
	free(nxt.v);
}

/* ---- objects that mix plain bytes with encoded runs ----------------------------------------------- */

static size_t nr_put(uint8_t *b, size_t at, size_t cap, const void *p, size_t n) NR_UNUSED;
static size_t nr_put(uint8_t *b, size_t at, size_t cap, const void *p, size_t n)
{
	if (at + n > cap)
		n = cap > at ? cap - at : 0u;
	memcpy(b + at, p, n);
	return at + n;
}

/* A printable command of `n` bytes, built from words a rule would name. */
static size_t nr_cmd(struct nrng *r, char *out, size_t n) NR_UNUSED;
static size_t nr_cmd(struct nrng *r, char *out, size_t n)
{
	static const char *w[] = { "wget", "http://", "10.0.0.", "chmod", "777", "/tmp/x",
				   "sh", "-c", "curl", "|", "echo", "rm", "-rf", ";", "cd" };
	size_t o = 0;

	while (o < n) {
		const char *s = w[nr_below(r, sizeof w / sizeof w[0])];
		size_t l = strlen(s);

		if (o + l + 1u > n)
			break;
		memcpy(out + o, s, l);
		o += l;
		out[o++] = ' ';
	}
	while (o < n)
		out[o++] = (char)('a' + nr_below(r, 26));
	return o;
}

/*
 * One object of up to `cap` bytes: plain bytes of several flavours, runs of
 * zeros of every length near the threshold, UTF-16 text, `echo ... | base64
 * -d`, bare and quoted hex, percent-encoded forms - and sometimes a payload
 * that is itself one of those, so layering is exercised. Returns the length.
 */
static size_t nr_mix(struct nrng *r, uint8_t *b, size_t cap) NR_UNUSED;
static size_t nr_mix(struct nrng *r, uint8_t *b, size_t cap)
{
	size_t at = 0;
	char cmd[96], enc[400], enc2[900];

	while (at + 200u < cap) {
		uint32_t kind = nr_below(r, 12u);
		size_t k, l, l2;

		switch (kind) {
		case 0:
		case 1:
			k = 1u + nr_below(r, 60u);
			while (k-- && at < cap)
				b[at++] = (uint8_t)nr_next(r);
			break;
		case 2:
			k = 1u + nr_below(r, 30u);
			while (k-- && at < cap)
				b[at++] = (uint8_t)(0x20u + nr_below(r, 0x5f));
			break;
		case 3:                         /* zeros near the threshold */
			k = nr_below(r, 4u) ? 5u + nr_below(r, 8u) : nr_below(r, 200u);
			while (k-- && at < cap)
				b[at++] = 0;
			break;
		case 4:                         /* UTF-16LE text */
			k = 4u + nr_below(r, 24u);
			while (k-- && at + 1u < cap) {
				b[at++] = (uint8_t)(0x20u + nr_below(r, 0x5f));
				b[at++] = 0;
			}
			break;
		case 5:
		case 6:                         /* echo <b64> | base64 -d */
			l = nr_cmd(r, cmd, 12u + nr_below(r, 60u));
			l2 = nr_b64_enc((const uint8_t *)cmd, l, enc, (int)nr_below(r, 2u),
					nr_below(r, 4u) ? 0u : 20u, 0);
			{
				const char *e = nr_below(r, 2u) ? "echo \"" : "echo ";
				const char *t = nr_below(r, 3u) ? " | base64 -d\n" : "\"|base64 --decode\n";

				at = nr_put(b, at, cap, e, strlen(e));
				at = nr_put(b, at, cap, enc, l2);
				at = nr_put(b, at, cap, t, strlen(t));
			}
			break;
		case 7:                         /* bare hex after a delimiter */
			l = nr_cmd(r, cmd, 12u + nr_below(r, 40u));
			l2 = nr_hex_enc((const uint8_t *)cmd, l, enc, (int)nr_below(r, 2u));
			{
				const char *d = nr_below(r, 2u) ? " " : "\"";

				at = nr_put(b, at, cap, d, 1u);
			}
			at = nr_put(b, at, cap, enc, l2);
			at = nr_put(b, at, cap, "\n", 1u);
			break;
		case 8:                         /* a quoted table of hex literals */
			k = 2u + nr_below(r, 6u);
			while (k--) {
				l = nr_cmd(r, cmd, 4u + nr_below(r, 8u));
				l2 = nr_hex_enc((const uint8_t *)cmd, l, enc, 0);
				at = nr_put(b, at, cap, nr_below(r, 4u) ? "'" : "\"", 1u);
				at = nr_put(b, at, cap, enc, l2);
				at = nr_put(b, at, cap, b[at - l2 - 1u] == '\'' ? "'," : "\",", 2u);
			}
			break;
		case 9:                         /* a percent-encoded form body */
			l = nr_cmd(r, cmd, 12u + nr_below(r, 40u));
			l2 = nr_pct_enc((const uint8_t *)cmd, l, enc, 1);
			at = nr_put(b, at, cap, "Cmd=", 4u);
			at = nr_put(b, at, cap, enc, l2);
			at = nr_put(b, at, cap, "&x=1\n", 5u);
			break;
		case 10:                        /* layered: hex of base64 of a command */
			l = nr_cmd(r, cmd, 12u + nr_below(r, 24u));
			l2 = nr_b64_enc((const uint8_t *)cmd, l, enc, 1, 0u, 0);
			l = 0;
			memcpy(enc2, "echo ", 5u);
			memcpy(enc2 + 5u, enc, l2);
			memcpy(enc2 + 5u + l2, " | base64 -d\n", 13u);
			l = 5u + l2 + 13u;
			l2 = nr_hex_enc((const uint8_t *)enc2, l, enc, 0);
			at = nr_put(b, at, cap, " ", 1u);
			at = nr_put(b, at, cap, enc, l2);
			at = nr_put(b, at, cap, "\n", 1u);
			break;
		default:                        /* decoy: runs that look like payloads */
			k = 8u + nr_below(r, 40u);
			while (k-- && at < cap)
				b[at++] = (uint8_t)"0123456789abcdefABCDEF%+="[nr_below(r, 25u)];
			break;
		}
	}
	return at;
}

#endif /* KOFENG_TESTS_NORMALIZER_REF_H */
