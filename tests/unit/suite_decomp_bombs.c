/*
 * suite_decomp_bombs - decompression bombs and deep codings through the WHOLE engine (kscan_bytes, the real unpacker modules, the real
 * budgets), counted and not timed: what the tree produced, how high the resident bytes got, whether the cut was SAID.
 *
 * hostile_engine_archives.c has the zip and gzip bombs, the overlap bomb and the nesting of containers; this file adds the codings
 * it has not got: a dense deflate bomb in a gzip (258 bytes from one byte back, a hundred and seventy to one), bzip2 and xz bombs
 * made by the tools (tens of megabytes of zeros in tens of bytes; skipped visibly when the tool is not there), gzip inside gzip a hundred
 * deep, three different codings one inside the next, and a gzip whose ISIZE lies both ways.
 *
 *   BOMB     max_object_bytes 2 MiB, max_produced_bytes 4 MiB: the child is CUT at the object cap (its bytes are the plain
 *            text's beginning, stamped LIMIT) and limit_hits moves; the tree produces at most the produced budget; the peak
 *            resident bytes stay under 24 MiB (the decoder's own state included); and the scan ends: the wall clock is a
 *            backstop of 20 s (the counters are the assertion)
 *   NEST     gzip in gzip, 100 layers: the layers opened never pass the allowance for the depth (depth_allowance: 64 for something
 *            small), the cut is SAID (LIMIT on an object, or limit_hits), and the bytes produced are the layers', not a multiple
 *   CHAIN    gzip of bzip2 of xz of a text: the text is a child at depth 3, whole
 *   LIES     ISIZE says 4 GiB - 1 for a 1 KiB member and 1 for a 1 MiB one: the child is the member's real bytes either way (a
 *            declared size is a hint and never a bound or a fact)
 *
 * Needs the built database, run from the repository root after make.
 */
#define _GNU_SOURCE

#include "../lib/uncoat/hostile_common.h"
#undef CK
#include "hostile_engine.h"
#include "decomp_fixtures.h"

#include <time.h>

#define DB "build/release/databases"
#define MIB (1u << 20)

struct seen {
	uint64_t objects, child_bytes, max_child, broken_limit, limit_hits_after;
	uint32_t max_depth;
	int      cut_child_prefix_ok;    /* every child's first bytes are 'a' (the bombs' plain text) */
	uint64_t whole_children;         /* children whose length is exactly `want_len` */
	uint64_t want_len;
};

static int cb(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;
	uint32_t d = kobj_depth(name);

	s->objects++;
	if (d > s->max_depth)
		s->max_depth = d;
	if (d > 0) {
		s->child_bytes += len;
		if (len > s->max_child)
			s->max_child = len;
		if (s->want_len && len == s->want_len)
			s->whole_children++;
		if (bytes && len && ((const uint8_t *)bytes)[0] != 'a')
			s->cut_child_prefix_ok = 0;
	}
	if (res->broken == KOF_BROKEN_LIMIT)
		s->broken_limit++;
	return 0;
}

static kof_engine *eng;
static kof_scanner *sc;

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static struct seen scan(const struct he_w *w, const char *root, uint64_t obj_cap, uint64_t produced, double *secs)
{
	struct kof_scan_option o;
	struct seen s;
	double t0 = now_s();

	memset(&s, 0, sizeof s);
	s.cut_child_prefix_ok = 1;
	memset(&o, 0, sizeof o);
	o.heur_level = 1;
	o.emu_forbidden = 1;
	o.max_object_depth = 0;
	o.max_object_bytes = obj_cap;
	o.max_produced_bytes = produced;
	o.max_resident_bytes = 256u << 20;
	(void)kscan_bytes(sc, w->p, w->n, root, &o, cb, &s);
	*secs = now_s() - t0;
	return s;
}

static void bomb_row(const char *what, const struct he_w *w, const char *root, uint64_t input_n)
{
	uint64_t hits0 = kscan_stats(sc)->limit_hits;
	double secs;
	struct seen s = scan(w, root, 2u * MIB, 4u * MIB, &secs);

	CK(s.max_child <= 2u * MIB, "%s: a child of %llu bytes under a 2 MiB object cap", what, (unsigned long long)s.max_child);
	CK(s.child_bytes <= 4u * MIB, "%s: the tree produced %llu bytes under a 4 MiB budget", what, (unsigned long long)s.child_bytes);
	CK(s.child_bytes > 0, "%s: no child at all (the bomb should open and be cut)", what);
	CK(kscan_stats(sc)->limit_hits > hits0 || s.broken_limit, "%s: the cut is not said (limit_hits +%llu, %llu objects broken LIMIT)", what,
	   (unsigned long long)(kscan_stats(sc)->limit_hits - hits0), (unsigned long long)s.broken_limit);
	CK(kscan_stats(sc)->peak_resident <= 24u * MIB, "%s: peak resident %llu bytes", what, (unsigned long long)kscan_stats(sc)->peak_resident);
	CK(s.cut_child_prefix_ok, "%s: the child is not the beginning of the plain text", what);
	CK(secs < 20.0, "%s: took %.1f s", what, secs);
	printf("  (%s: %llu bytes of file -> child %llu bytes, %.2f s, peak %llu)\n", what, (unsigned long long)input_n, (unsigned long long)s.max_child, secs,
	       (unsigned long long)kscan_stats(sc)->peak_resident);
}

static uint8_t zeros[1u << 20];

static int tool_zeros(struct he_w *w, const char *const *argv, size_t mib)
{
	/* the tool is fed `mib` MiB of 'a': one run per call would need a pipe of that size in memory, so a buffer is built and handed over */
	uint8_t *big = (uint8_t *)malloc(mib * MIB);
	size_t out = 0;
	uint8_t *z;

	if (!big)
		return 0;
	memset(big, 'a', mib * MIB);
	z = hv_tool(argv, big, mib * MIB, &out);
	free(big);
	if (!z)
		return 0;
	he_put(w, z, out);
	free(z);
	return 1;
}

static void bombs(void)
{
	struct he_w w = { 0 };
	static const char *const bz[] = { "bzip2", "-9", "-c", NULL };
	static const char *const xz[] = { "xz", "-9", "-c", "--format=xz", NULL };

	(void)zeros;
	CK(b_gzip_bomb(&w, 100000), "the gzip bomb did not fit");
	bomb_row("gzip, 258 from one byte back", &w, "bomb.gz", w.n);
	w.n = 0;
	if (tool_zeros(&w, bz, 48)) {
		bomb_row("bzip2, 48 MiB of one byte", &w, "bomb.bz2", w.n);
	} else {
		printf("  SKIP bzip2 bomb: no bzip2 tool\n");
	}
	w.n = 0;
	if (tool_zeros(&w, xz, 192)) {
		bomb_row("xz, 192 MiB of one byte", &w, "bomb.xz", w.n);
	} else {
		printf("  SKIP xz bomb: no xz tool\n");
	}
	free(w.p);
}

/* gzip(gzip(...(payload))) `depth` layers, each of stored blocks. */
static int nest_gz(struct he_w *out, const uint8_t *payload, size_t n, unsigned depth)
{
	struct he_w a = { 0 }, b = { 0 };
	unsigned i;

	he_put(&a, payload, n);
	for (i = 0; i < depth; i++) {
		b.n = 0;
		if (!b_gzip(&b, a.p, a.n))
			return 0;
		a.n = 0;
		he_put(&a, b.p, b.n);
	}
	he_put(out, a.p, a.n);
	free(a.p);
	free(b.p);
	return 1;
}

static void nest(void)
{
	struct he_w w = { 0 };
	static const uint8_t text[] = "aaaa payload that is gzip all the way down, deep inside";
	double secs;
	struct seen s;
	uint64_t hits0 = kscan_stats(sc)->limit_hits;

	CK(nest_gz(&w, text, sizeof text - 1u, 100), "nest builder");
	s = scan(&w, "nest.gz", 16u * MIB, 64u * MIB, &secs);
	CK(s.max_depth <= 64, "100 gzip layers: depth %u reached (the allowance for something small is 64)", s.max_depth);
	CK(s.max_depth >= 8, "100 gzip layers: only depth %u opened", s.max_depth);
	CK(kscan_stats(sc)->limit_hits > hits0 || s.broken_limit, "100 gzip layers: the cut at the allowance is not said");
	CK(s.child_bytes < 100u * (sizeof text + 64u * 100u), "100 gzip layers: %llu bytes produced (a layer is ~ 20 bytes bigger than the next)", (unsigned long long)s.child_bytes);
	CK(secs < 10.0, "100 gzip layers took %.1f s", secs);
	/* 10 layers: all of them open and the innermost is the text */
	w.n = 0;
	CK(nest_gz(&w, text, sizeof text - 1u, 10), "nest builder");
	{
		struct seen t;

		memset(&t, 0, sizeof t);
		t.want_len = sizeof text - 1u;
		t = scan(&w, "nest10.gz", 16u * MIB, 64u * MIB, &secs);
		CK(t.max_depth == 10, "10 gzip layers: depth %u reached", t.max_depth);
	}
	free(w.p);
}

static void lies(void)
{
	static uint8_t pay[MIB], mem[MIB + 4096];
	struct he_w w = { 0 };
	struct seen s;
	double secs;
	size_t n;
	unsigned i;

	for (i = 0; i < sizeof pay; i++)
		pay[i] = (uint8_t)('b' + (i * 5u + (i >> 7)) % 20u);
	/* a 1 KiB member that says it is 4 GiB - 1 */
	CK(b_gzip(&w, pay, 1024), "builder");
	w.p[w.n - 4] = w.p[w.n - 3] = w.p[w.n - 2] = w.p[w.n - 1] = 0xff;
	memset(&s, 0, sizeof s);
	s.want_len = 1024;
	s = scan(&w, "lie_big.gz", 16u * MIB, 64u * MIB, &secs);
	CK(s.max_child <= 1024u && s.child_bytes <= 1024u, "ISIZE 4 GiB - 1 on 1 KiB: the child is %llu bytes (the member holds 1024)", (unsigned long long)s.child_bytes);
	/* a 1 MiB member that says it is 1 byte */
	w.n = 0;
	CK(b_gzip(&w, pay, sizeof pay), "builder");
	w.p[w.n - 4] = 1; w.p[w.n - 3] = w.p[w.n - 2] = w.p[w.n - 1] = 0;
	s = scan(&w, "lie_small.gz", 16u * MIB, 64u * MIB, &secs);
	CK(s.max_child == sizeof pay, "ISIZE 1 on 1 MiB: the child is %llu bytes (the member holds %zu)", (unsigned long long)s.max_child, sizeof pay);
	free(w.p);
	(void)mem; (void)n;
}

static void chain(void)
{
	static const char *const bz[] = { "bzip2", "-9", "-c", NULL };
	static const char *const xz[] = { "xz", "-6", "-c", "--format=xz", NULL };
	static uint8_t text[8192];
	struct he_w a = { 0 }, b = { 0 }, c = { 0 };
	struct seen s;
	double secs;
	size_t i, n;
	uint8_t *z;

	for (i = 0; i < sizeof text; i++)
		text[i] = (uint8_t)('a' + (i * 3u + (i >> 5)) % 20u);
	z = hv_tool(xz, text, sizeof text, &n);
	if (!z) {
		printf("  SKIP chain: no xz tool\n");
		return;
	}
	he_put(&a, z, n);
	free(z);
	z = hv_tool(bz, a.p, a.n, &n);
	if (!z) {
		printf("  SKIP chain: no bzip2 tool\n");
		free(a.p);
		return;
	}
	he_put(&b, z, n);
	free(z);
	CK(b_gzip(&c, b.p, b.n), "builder");
	memset(&s, 0, sizeof s);
	s = scan(&c, "chain.gz", 16u * MIB, 64u * MIB, &secs);
	{
		/* the text is the third child down: gzip -> bzip2 -> xz -> text */
		struct seen t;

		memset(&t, 0, sizeof t);
		t.want_len = sizeof text;
		{
			struct kof_scan_option o;

			memset(&o, 0, sizeof o);
			o.heur_level = 1;
			o.emu_forbidden = 1;
			o.max_object_bytes = 16u * MIB;
			o.max_produced_bytes = 64u * MIB;
			o.max_resident_bytes = 256u << 20;
			t.cut_child_prefix_ok = 1;
			(void)kscan_bytes(sc, c.p, c.n, "chain.gz", &o, cb, &t);
		}
		CK(t.max_depth == 3 && t.whole_children >= 1, "gzip of bzip2 of xz of a text: depth %u, %llu whole text children", t.max_depth, (unsigned long long)t.whole_children);
	}
	free(a.p);
	free(b.p);
	free(c.p);
}

static int run_all(void *arg)
{
	(void)arg;
	eng = keng_open(DB);
	sc = eng ? kscan_new(eng) : NULL;
	if (!sc) {
		printf("suite_decomp_bombs: no database (run from the repository root after make): nothing tested\n");
		return 1;
	}
	bombs();
	nest();
	lies();
	chain();
	kscan_free(sc);
	keng_close(eng);
	return he_fails ? 1 : 0;
}

int main(void)
{
	struct he_status st = he_child(run_all, NULL, 280);

	if (!st.exited || st.code) {
		printf("suite_decomp_bombs: FAILED (exited %d code %d signal %d)\n", st.exited, st.code, st.sig);
		return 1;
	}
	printf("suite_decomp_bombs: ok\n");
	return 0;
}
