/*
 * limits_children - how many members of a container the engine opens, against what the
 * container holds. The expectation is the plain one: a zip with N entries, a PDF with M
 * objects each carrying a stream, becomes N / M child objects and the top object is not
 * `Limit reached`.
 *
 *   zip   N in {2040, 2100, 4096, 5000, 20000} stored members      CHECKED: every member opened
 *   pdf   M in {4000, 4200, 5000, 20000} objects, each a stream     CHECKED: every stream opened
 *   big   one stored member, and one deflated member, of 17 MB and of 40 MB
 *   deep  a stored zip inside a stored zip, D levels, a marker at the bottom
 *
 * The zip and pdf cases were WARNs while the views were fixed arrays (4096 entries; 4096
 * objects and 1024 streams) and the extents a region resolves into were 4096: 2100 members
 * were enough to lose all of them, and a PDF lost every stream past the cap. Both views are now
 * tables the size of the file and the extent buffer grows against the ledger, so they are checks:
 * the top object is not broken and EVERY member is a child. The big and deep cases are still
 * measurements: where the engine falls short of them it prints a WARN with the numbers (the
 * children, the broken reason, the seconds) and the run stays green - silent_loss_scan.c pins
 * that a shortfall is REPORTED, this file measures HOW FAR the engine is from opening everything.
 *
 * A WARN is not a defect list: it is the output. Every case stays under five seconds.
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../libkofeng/kofeng.h"
#include "known_miss.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define MARKER "KOFMARK!"

static kof_engine  *eng;
static kof_scanner *sc;

struct seen {
	unsigned objs;       /* every object the callback saw, the top one too */
	unsigned marker;     /* children whose bytes are the marker            */
	unsigned top_broken; /* the top object's kof_result.broken             */
	unsigned any_broken; /* the first non-zero reason on any object        */
	uint64_t biggest;    /* the largest child's length                     */
	double   secs;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	if (!s->objs)
		s->top_broken = res->broken;
	else if (len > s->biggest)
		s->biggest = len;
	s->objs++;
	if (bytes && len == 8u && memcmp(bytes, MARKER, 8) == 0)
		s->marker++;
	if (res->broken && !s->any_broken)
		s->any_broken = res->broken;
	return 0;
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void scan2(const uint8_t *b, uint64_t n, const char *name, struct seen *s, int host_defaults)
{
	struct kof_scan_option opt;
	double t0 = now();

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	if (!host_defaults) {
		opt.max_produced_bytes = 256u << 20;
		opt.max_resident_bytes = 512u << 20;
		opt.max_object_bytes = 64u << 20;
	}
	(void)kscan_bytes(sc, b, n, name, &opt, on_object, s);
	s->secs = now() - t0;
}

static void scan(const uint8_t *b, uint64_t n, const char *name, struct seen *s)
{
	scan2(b, n, name, s, 0);
}

static const char *why(unsigned b)
{
	static const char *const w[] = { "none", "LIMIT", "UNSUPPORTED", "DAMAGED" };

	return b < 4u ? w[b] : b == KOF_BROKEN_ENCRYPTED ? "ENCRYPTED" : "other";
}

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void body8(uint8_t *b, unsigned i, unsigned n)
{
	char t[16];

	if (i + 1u == n) {
		memcpy(b, MARKER, 8);
		return;
	}
	snprintf(t, sizeof t, "KOF%04u", i % 10000u);
	memcpy(b, t, 8);
}

/* ---- zip -------------------------------------------------------------------- */

/* n stored members of `dl` bytes: the last is the marker (dl == 8) or `payload`. */
static uint8_t *zip_of2(unsigned n, const uint8_t *payload, size_t pl, size_t usize, unsigned method,
			size_t *len)
{
	size_t cap = (size_t)n * 160u + 64u + pl, at = 0, cd, lo = 0, i;
	uint8_t *f = calloc(1, cap);
	char name[16];

	if (!f)
		return NULL;
	for (i = 0; i < n; i++) {
		unsigned nl = (unsigned)snprintf(name, sizeof name, "e%05u", (unsigned)i);
		size_t dl = payload ? pl : 8u;

		le32(f + at, 0x04034b50u);
		le16(f + at + 4, 10);
		le16(f + at + 8, method);
		le32(f + at + 18, (uint32_t)dl);
		le32(f + at + 22, (uint32_t)(payload ? usize : dl));
		le16(f + at + 26, nl);
		memcpy(f + at + 30, name, nl);
		if (payload)
			memcpy(f + at + 30 + nl, payload, pl);
		else
			body8(f + at + 30 + nl, (unsigned)i, n);
		at += 30u + nl + dl;
	}
	cd = at;
	for (i = 0; i < n; i++) {
		unsigned nl = (unsigned)snprintf(name, sizeof name, "e%05u", (unsigned)i);
		size_t dl = payload ? pl : 8u;

		le32(f + at, 0x02014b50u);
		le16(f + at + 4, 20);
		le16(f + at + 6, 10);
		le16(f + at + 10, method);
		le32(f + at + 20, (uint32_t)dl);
		le32(f + at + 24, (uint32_t)(payload ? usize : dl));
		le16(f + at + 28, nl);
		le32(f + at + 42, (uint32_t)lo);
		memcpy(f + at + 46, name, nl);
		at += 46u + nl;
		lo += 30u + nl + dl;
	}
	le32(f + at, 0x06054b50u);
	le16(f + at + 8, n > 0xffffu ? 0xffffu : n);
	le16(f + at + 10, n > 0xffffu ? 0xffffu : n);
	le32(f + at + 12, (uint32_t)(at - cd));
	le32(f + at + 16, (uint32_t)cd);
	at += 22u;
	*len = at;
	return f;
}

static uint8_t *zip_of(unsigned n, const uint8_t *payload, size_t pl, size_t *len)
{
	return zip_of2(n, payload, pl, pl, 0, len);
}

static void case_zip(unsigned n)
{
	size_t len;
	uint8_t *f = zip_of(n, NULL, 0, &len);
	struct seen s;
	unsigned kids;

	CK(f != NULL);
	if (!f)
		return;
	scan(f, len, "wide.zip", &s);
	kids = s.objs ? s.objs - 1u : 0;
	printf("  zip %u entries: %u children, marker %u, top broken=%s, %.2fs\n", n, kids, s.marker,
	       why(s.top_broken), s.secs);
	CK(s.secs < 5.0);
	CK(kids == n && !s.top_broken && s.marker == 1u);   /* every member, the last one the marker, not broken */
	free(f);
}

/* ---- pdf -------------------------------------------------------------------- */

static uint8_t *pdf_of(unsigned n, size_t *len)
{
	uint8_t *f = calloc((size_t)n + 4u, 96u);
	size_t at = 0;
	unsigned i;

	if (!f)
		return NULL;
	at += (size_t)sprintf((char *)f, "%%PDF-1.4\n");
	for (i = 1; i <= n; i++) {
		at += (size_t)sprintf((char *)f + at, "%u 0 obj\n<< /Length 8 >>\nstream\n", i);
		body8(f + at, i - 1u, n);
		at += 8;
		at += (size_t)sprintf((char *)f + at, "\nendstream\nendobj\n");
	}
	at += (size_t)sprintf((char *)f + at,
			      "trailer\n<< /Size %u /Root 1 0 R >>\nstartxref\n0\n%%%%EOF\n", n + 1u);
	*len = at;
	return f;
}

static void case_pdf(unsigned m)
{
	size_t len;
	uint8_t *f = pdf_of(m, &len);
	struct seen s;
	unsigned kids;

	CK(f != NULL);
	if (!f)
		return;
	scan(f, len, "wide.pdf", &s);
	kids = s.objs ? s.objs - 1u : 0;
	printf("  pdf %u objects: %u children, marker %u, top broken=%s, %.2fs\n", m, kids, s.marker,
	       why(s.top_broken), s.secs);
	CK(s.secs < 5.0);
	CK(kids == m && !s.top_broken && s.marker == 1u);
	free(f);
}

/* ---- one big member ------------------------------------------------------------ */

static void case_big(size_t mb)
{
	size_t pl = mb << 20, len, i;
	uint8_t *p = malloc(pl), *f;
	struct seen s;

	CK(p != NULL);
	if (!p)
		return;
	for (i = 0; i < pl; i++)
		p[i] = (uint8_t)((i * 2654435761u) >> 13);   /* not compressible, not a format */
	memcpy(p + pl - 8, MARKER, 8);
	f = zip_of(1, p, pl, &len);
	free(p);
	CK(f != NULL);
	if (!f)
		return;
	scan2(f, len, "big.zip", &s, 1);
	printf("  zip with one %zu MB stored member: %u children, biggest child %llu, top broken=%s, %.2fs\n", mb,
	       s.objs ? s.objs - 1u : 0, (unsigned long long)s.biggest, why(s.top_broken), s.secs);
	CK(s.secs < 5.0);
	KM_WARN(s.objs == 2u && s.biggest == pl && !s.any_broken,
		"zip with one %zu MB stored member: %u child(ren), biggest child %llu of %zu bytes, broken=%s - "
		"the member's bytes are %s (what is lost: every rule and parser on that member)",
		mb, s.objs ? s.objs - 1u : 0u, (unsigned long long)s.biggest, pl, why(s.any_broken),
		s.biggest ? "cut" : "not scanned");
	free(f);
}

/*
 * The same member DEFLATED (stored blocks of a deflate stream: a real decoder run, no
 * compressor needed). A stored member is a window into its parent and costs nothing; a
 * deflated one is produced bytes, and max_object_bytes (16 MB when the host sets none)
 * bounds it.
 */
static void case_big_deflated(size_t mb)
{
	size_t pl = mb << 20, dl = 0, len, i, at = 0, left;
	uint8_t *raw = malloc(pl), *z, *f;
	struct seen s;

	CK(raw != NULL);
	if (!raw)
		return;
	for (i = 0; i < pl; i++)
		raw[i] = (uint8_t)((i * 2654435761u) >> 13);
	memcpy(raw + pl - 8, MARKER, 8);
	z = malloc(pl + (pl / 65535u + 2u) * 5u);
	CK(z != NULL);
	if (!z) {
		free(raw);
		return;
	}
	for (left = pl; left;) {
		size_t b = left > 65535u ? 65535u : left;

		z[at++] = left == b ? 1u : 0u;
		le16(z + at, (unsigned)b);
		le16(z + at + 2, (unsigned)(~b & 0xffffu));
		at += 4;
		memcpy(z + at, raw + (pl - left), b);
		at += b;
		left -= b;
	}
	dl = at;
	free(raw);
	f = zip_of2(1, z, dl, pl, 8, &len);
	free(z);
	CK(f != NULL);
	if (!f)
		return;
	scan2(f, len, "bigdef.zip", &s, 1);
	printf("  zip with one %zu MB deflated member (host limits): %u child(ren), biggest child %llu, top broken=%s, "
	       "%.2fs\n", mb, s.objs ? s.objs - 1u : 0, (unsigned long long)s.biggest, why(s.any_broken), s.secs);
	CK(s.secs < 5.0);
	CK(s.biggest == pl || s.any_broken);
	KM_WARN(s.biggest == pl && !s.any_broken,
		"zip with one %zu MB deflated member under the default limits: biggest child %llu of %zu bytes, "
		"broken=%s - what is lost: the member's bytes past the cut (a rule or parser on the tail never sees them)",
		mb, (unsigned long long)s.biggest, pl, why(s.any_broken));
	free(f);
}

/* ---- a zip in a zip in a zip ----------------------------------------------------- */

static void case_deep(unsigned depth)
{
	uint8_t *cur, *nx;
	size_t cl, nl, d;
	struct seen s;

	cur = zip_of(1, (const uint8_t *)MARKER, 8, &cl);       /* level 1: the marker, one member */
	for (d = 1; cur && d < depth; d++) {
		nx = zip_of(1, cur, cl, &nl);
		free(cur);
		cur = nx;
		cl = nl;
	}
	CK(cur != NULL);
	if (!cur)
		return;
	scan(cur, cl, "deep.zip", &s);
	printf("  zip nested %u deep: %u objects, marker %u, any broken=%s, %.2fs\n", depth, s.objs, s.marker,
	       why(s.any_broken), s.secs);
	CK(s.secs < 5.0);
	CK(s.marker == 1u || s.any_broken);
	KM_WARN(s.marker == 1u,
		"zip nested %u deep: the marker at the bottom is %s (%u objects seen, broken=%s) - "
		"what is lost: everything below the level where the walk stopped",
		depth, s.marker ? "opened" : "NOT reached", s.objs, why(s.any_broken));
	free(cur);
}

int main(int argc, char **argv)
{
	static const unsigned zn[] = { 2040, 2100, 4096, 5000, 20000 };
	static const unsigned pm[] = { 4000, 4200, 5000, 20000 };
	static const unsigned dp[] = { 16, 40, 64, 65, 100, 1000 };
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	unsigned i;

	eng = keng_open(db);
	if (!eng) {
		printf("limits_children: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = kscan_new(eng);
	if (!sc)
		return 1;
	for (i = 0; i < sizeof zn / sizeof zn[0]; i++)
		case_zip(zn[i]);
	for (i = 0; i < sizeof pm / sizeof pm[0]; i++)
		case_pdf(pm[i]);
	case_big(17);
	case_big(40);
	case_big_deflated(17);
	case_big_deflated(40);
	for (i = 0; i < sizeof dp / sizeof dp[0]; i++)
		case_deep(dp[i]);
	kscan_free(sc);
	keng_close(eng);
	km_summary();
	return fails != 0 || km_failed();
}
