/*
 * hostile_engine_archives.c - containers built to make the engine over-produce,
 * over-recurse, lose its place or lie about a name, scanned through the whole
 * engine (kscan_bytes on a guard-page buffer, the real unpackers, the real
 * budgets).
 *
 * The parser fuzzers stop at the view. This is the next layer: what the engine
 * DOES with a believable hostile container. Each case is a forked child with an
 * alarm and, outside a sanitiser, an address-space ceiling, so a hang, a crash or
 * an unbounded allocation is a named result and not the end of the test.
 *
 * What a case asserts is the budget contract in kofoption.h: bytes produced below
 * the root never pass max_produced_bytes, an object count past the children
 * ceiling is REPORTED (a broken reason on some object) and not silently
 * dropped, nesting is cut at the layer allowance and says so, and a name a
 * member chose cannot forge the "//" that separates an object from its parent.
 */

#include "hostile_engine.h"
#include "hostile_engine_seeds.h"

#include <sys/resource.h>
#include <time.h>

#include "../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/gzip_parse.h"
#include <kofmod/kofsig.h>
#include <kofmod/zip.h>

#define MB (1024ull * 1024ull)

#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
#define UNDER_ASAN 1
#else
#define UNDER_ASAN 0
#endif

/* ---- a zip writer with room for lies --------------------------------------------- */

struct zent {
	const char *name;
	uint32_t    name_len;     /* 0: strlen(name) */
	uint16_t    method;
	const void *data;
	uint32_t    clen;
	uint32_t    csize_claim;  /* what the headers say, written when claim_set */
	uint32_t    usize;
	int         claim_set;
	int         share;        /* 1-based: no local header of its own, point at that entry's */
	const void *extra;        /* a central-directory extra field */
	uint32_t    extra_len;
};

static void zip_ex(struct he_w *w, const struct zent *e, uint32_t n)
{
	uint32_t i, cd_off, cd_n;
	uint32_t *lho = calloc(n ? n : 1u, sizeof *lho);

	if (!lho) {
		w->oom = 1;
		return;
	}
	for (i = 0; i < n; i++) {
		uint32_t nl = e[i].name_len ? e[i].name_len : (uint32_t)strlen(e[i].name);
		uint32_t cs = e[i].claim_set ? e[i].csize_claim : e[i].clen;

		if (e[i].share) {
			lho[i] = lho[e[i].share - 1];
			continue;
		}
		lho[i] = (uint32_t)w->n;
		he_u32(w, 0x04034b50u);
		he_u16(w, 20);
		he_u16(w, 0);
		he_u16(w, e[i].method);
		he_u16(w, 0);
		he_u16(w, 0x21);
		he_u32(w, 0);
		he_u32(w, cs);
		he_u32(w, e[i].usize);
		he_u16(w, (uint16_t)nl);
		he_u16(w, 0);
		he_put(w, e[i].name, nl);
		he_put(w, e[i].data, e[i].clen);
	}
	cd_off = (uint32_t)w->n;
	for (i = 0; i < n; i++) {
		uint32_t nl = e[i].name_len ? e[i].name_len : (uint32_t)strlen(e[i].name);
		uint32_t cs = e[i].claim_set ? e[i].csize_claim : e[i].clen;

		he_u32(w, 0x02014b50u);
		he_u16(w, 20);
		he_u16(w, 20);
		he_u16(w, 0);
		he_u16(w, e[i].method);
		he_u16(w, 0);
		he_u16(w, 0x21);
		he_u32(w, 0);
		he_u32(w, cs);
		he_u32(w, e[i].usize);
		he_u16(w, (uint16_t)nl);
		he_u16(w, (uint16_t)e[i].extra_len);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u16(w, 0);
		he_u32(w, 0);
		he_u32(w, lho[i]);
		he_put(w, e[i].name, nl);
		he_put(w, e[i].extra, e[i].extra_len);
	}
	cd_n = (uint32_t)w->n - cd_off;
	he_u32(w, 0x06054b50u);
	he_u16(w, 0);
	he_u16(w, 0);
	he_u16(w, n > 0xffffu ? 0xffffu : n);
	he_u16(w, n > 0xffffu ? 0xffffu : n);
	he_u32(w, cd_n);
	he_u32(w, cd_off);
	he_u16(w, 0);
	free(lho);
}

/* ---- the harness of one case ---------------------------------------------------------- */

struct run {
	struct he_tally t;
	int      rc;
	double   secs;
	uint64_t limit_hits, peak;
	uint64_t distinct, names;
	uint64_t names_invalid;
};

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

struct nameset {
	uint64_t h[4096];
	uint64_t distinct, total;
	struct he_tally *t;
};

static struct nameset ns;

/* What each object came back with, in the order the walk reported it: the cases that
 * assert on ONE member (it was cut, it was opened, it carries its own Limit). */
struct oseen {
	char     name[128];
	uint32_t broken;
	uint64_t len;
};

#define OSEEN_MAX 512u
static struct oseen os[OSEEN_MAX];
static unsigned os_n;

static const struct oseen *os_find(const char *tail)
{
	unsigned i;
	size_t tl = strlen(tail);

	for (i = 0; i < os_n; i++) {
		size_t nl = strlen(os[i].name);

		if (nl >= tl && !strcmp(os[i].name + nl - tl, tail))
			return &os[i];
	}
	return NULL;
}

static int on_obj(const char *name, const void *bytes, uint64_t len,
		  const struct kof_result *res, void *user)
{
	uint64_t h = 1469598103934665603ull, i;
	uint64_t slot;

	he_on_object(name, bytes, len, res, user);
	if (os_n < OSEEN_MAX) {
		snprintf(os[os_n].name, sizeof os[os_n].name, "%s", name);
		os[os_n].broken = res ? res->broken : 0u;
		os[os_n].len = len;
		os_n++;
	}
	for (i = 0; name[i]; i++)
		h = (h ^ (uint8_t)name[i]) * 1099511628211ull;
	h |= 1u;
	ns.total++;
	for (slot = h & 4095u; ns.h[slot]; slot = (slot + 1u) & 4095u)
		if (ns.h[slot] == h)
			return 0;
	if (ns.distinct < 2048u) {
		ns.h[slot] = h;
		ns.distinct++;
	}
	return 0;
}

/* One scan of `bytes`, copied under a guard page. */
static int scan_guarded(const struct he_w *w, const struct kof_scan_option *opt,
			const char *root, struct run *r)
{
	kof_engine *e = keng_open(HE_DB);
	kof_scanner *sc = e ? kscan_new(e) : NULL;
	struct he_guard g;
	double t0;

	memset(r, 0, sizeof *r);
	memset(&ns, 0, sizeof ns);
	os_n = 0;
	if (!sc || !he_guard_make(&g, w->p, w->n)) {
		kscan_free(sc);
		keng_close(e);
		return -1;
	}
	t0 = now();
	r->rc = kscan_bytes(sc, g.p, g.n, root, opt, on_obj, &r->t);
	r->secs = now() - t0;
	r->limit_hits = kscan_stats(sc)->limit_hits;
	r->peak = kscan_stats(sc)->peak_resident;
	r->names_invalid = kscan_stats(sc)->names_invalid;
	r->distinct = ns.distinct;
	r->names = ns.total;
	he_guard_free(&g);
	kscan_free(sc);
	keng_close(e);
	return 0;
}

static void limit_memory(void)
{
#if !UNDER_ASAN
	struct rlimit rl;

	rl.rlim_cur = rl.rlim_max = 3ull << 30;
	setrlimit(RLIMIT_AS, &rl);
#endif
}

struct kase {
	const char *name;
	int (*body)(void);
};

static int run_kase(void *arg)
{
	const struct kase *k = (const struct kase *)arg;

	limit_memory();
	return k->body();
}

static struct kof_scan_option opt_small(void)
{
	struct kof_scan_option o = he_opt();

	o.max_resident_bytes = 128ull * MB;
	o.max_produced_bytes = 64ull * MB;
	o.max_object_bytes = 32ull * MB;
	return o;
}

#define NEED(cond, ...) do { if (!(cond)) { printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); bad |= 1; } } while (0)

/* ---- cases ------------------------------------------------------------------------------ */

/* One member inflates to 200 MB. The tree may yield 64 MB; the rest must be said. */
static int kase_bomb_zip(void)
{
	struct he_w d = { 0 }, z = { 0 };
	struct zent e;
	struct kof_scan_option o = opt_small();
	struct run r;
	int bad = 0;

	he_deflate_run(&d, 'A', 775000);
	memset(&e, 0, sizeof e);
	e.name = "bomb";
	e.method = 8;
	e.data = d.p;
	e.clen = (uint32_t)d.n;
	e.usize = (uint32_t)(1u + 258u * 775000u);
	zip_ex(&z, &e, 1);
	if (scan_guarded(&z, &o, "bomb.zip", &r))
		return 9;
	printf("  bomb.zip %zu bytes -> rc %d objects %llu child_bytes %llu broken %llu (limit %llu) %.2fs peak %llu\n",
	       z.n, r.rc, (unsigned long long)r.t.objects, (unsigned long long)r.t.child_bytes,
	       (unsigned long long)r.t.broken, (unsigned long long)r.t.broken_limit, r.secs,
	       (unsigned long long)r.peak);
	NEED(r.t.child_bytes <= o.max_produced_bytes, "produced %llu bytes past max_produced_bytes %llu",
	     (unsigned long long)r.t.child_bytes, (unsigned long long)o.max_produced_bytes);
	NEED(r.t.child_bytes >= 200ull * MB || r.t.broken > 0 || r.limit_hits > 0,
	     "the bomb was cut short and nothing says so");
	NEED(r.peak <= o.max_resident_bytes + 4ull * MB, "peak resident %llu past max_resident_bytes",
	     (unsigned long long)r.peak);
	he_free(&d);
	he_free(&z);
	return bad;
}

/* The same through gzip, whose header carries no size to refuse early. */
static int kase_bomb_gzip(void)
{
	struct he_w d = { 0 }, g = { 0 };
	struct kof_scan_option o = opt_small();
	struct run r;
	int bad = 0;
	uint64_t k = 775000;

	he_deflate_run(&d, 'A', k);
	he_u8(&g, 0x1f);
	he_u8(&g, 0x8b);
	he_u8(&g, 8);
	he_u8(&g, 0);
	he_u32(&g, 0);
	he_u8(&g, 0);
	he_u8(&g, 3);
	he_put(&g, d.p, d.n);
	he_u32(&g, 0);
	he_u32(&g, (uint32_t)(1u + 258u * k));
	if (scan_guarded(&g, &o, "bomb.gz", &r))
		return 9;
	printf("  bomb.gz %zu bytes -> rc %d objects %llu child_bytes %llu broken %llu %.2fs\n", g.n, r.rc,
	       (unsigned long long)r.t.objects, (unsigned long long)r.t.child_bytes,
	       (unsigned long long)r.t.broken, r.secs);
	NEED(r.t.child_bytes <= o.max_produced_bytes, "produced %llu bytes past the budget",
	     (unsigned long long)r.t.child_bytes);
	NEED(r.t.child_bytes >= 200ull * MB || r.t.broken > 0 || r.limit_hits > 0,
	     "the bomb was cut short and nothing says so");
	he_free(&d);
	he_free(&g);
	return bad;
}

/* The overlapping bomb: one local header, thousands of central entries aimed at it. */
static int kase_bomb_overlap(void)
{
	struct he_w d = { 0 }, z = { 0 };
	struct zent *e = calloc(3000, sizeof *e);
	struct kof_scan_option o = opt_small();
	struct run r;
	uint32_t i;
	int bad = 0;
	static char names[3000][12];

	if (!e)
		return 9;
	he_deflate_run(&d, 'A', 3000);
	for (i = 0; i < 3000; i++) {
		snprintf(names[i], sizeof names[i], "n%u", i);
		e[i].name = names[i];
		e[i].method = 8;
		e[i].data = d.p;
		e[i].clen = (uint32_t)d.n;
		e[i].usize = (uint32_t)(1u + 258u * 3000u);
		e[i].share = i ? 1 : 0;
	}
	zip_ex(&z, e, 3000);
	if (scan_guarded(&z, &o, "overlap.zip", &r))
		return 9;
	printf("  overlap.zip %zu bytes (3000 entries x %u bytes) -> rc %d objects %llu child_bytes %llu broken %llu %.2fs\n",
	       z.n, 1u + 258u * 3000u, r.rc, (unsigned long long)r.t.objects,
	       (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken, r.secs);
	NEED(r.t.child_bytes <= o.max_produced_bytes, "overlapping entries produced %llu bytes past the budget",
	     (unsigned long long)r.t.child_bytes);
	NEED(r.t.child_bytes >= 3000ull * (1u + 258u * 3000u) || r.t.broken > 0 || r.limit_hits > 0,
	     "the overlap was cut short and nothing says so");
	free(e);
	he_free(&d);
	he_free(&z);
	return bad;
}

/* Sizes in the headers that no allocation may be sized from. */
static int kase_claims(void)
{
	static const struct { uint32_t cs, us; } c[] = {
		{ 0xffffffffu, 0xffffffffu }, { 0, 0xffffffffu }, { 0xffffffffu, 0 }, { 0x7fffffffu, 0x7fffffffu },
		{ 0x80000000u, 0x80000000u }, { 1, 0x40000000u }, { 0xfffffff0u, 8 }
	};
	struct kof_scan_option o = opt_small();
	unsigned i, m;
	int bad = 0;

	for (m = 0; m < 3; m++)
		for (i = 0; i < sizeof c / sizeof c[0]; i++) {
			struct he_w z = { 0 };
			struct zent e;
			struct run r;
			static const uint8_t body[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };

			memset(&e, 0, sizeof e);
			e.name = "claim";
			e.method = m == 0 ? 0 : (m == 1 ? 8 : 12);
			e.data = body;
			e.clen = 16;
			e.csize_claim = c[i].cs;
			e.claim_set = 1;
			e.usize = c[i].us;
			zip_ex(&z, &e, 1);
			if (scan_guarded(&z, &o, "claim.zip", &r))
				return 9;
			NEED(r.t.child_bytes <= 16ull * MB, "method %u claim %u/%u produced %llu bytes", m, i,
			     (unsigned)c[i].us, (unsigned long long)r.t.child_bytes);
			NEED(r.secs < 2.0, "method %u claim %u took %.1fs", m, i, r.secs);
			he_free(&z);
		}
	return bad;
}

/* zip64 sizes of 2^63 and 2^64-1 in the central directory's extra field. */
static int kase_zip64(void)
{
	static const uint64_t big[] = { 0x8000000000000000ull, 0xffffffffffffffffull, 0x7fffffffffffffffull,
					0x100000000ull, 0xfffffffffull };
	struct kof_scan_option o = opt_small();
	unsigned i;
	int bad = 0;

	for (i = 0; i < sizeof big / sizeof big[0]; i++) {
		struct he_w z = { 0 }, ex = { 0 };
		struct zent e;
		struct run r;
		static const uint8_t body[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };

		he_u16(&ex, 1);
		he_u16(&ex, 16);
		he_u64(&ex, big[i]);
		he_u64(&ex, big[i]);
		memset(&e, 0, sizeof e);
		e.name = "z64";
		e.method = 0;
		e.data = body;
		e.clen = 16;
		e.claim_set = 1;
		e.csize_claim = 0xffffffffu;
		e.usize = 0xffffffffu;
		e.extra = ex.p;
		e.extra_len = (uint32_t)ex.n;
		zip_ex(&z, &e, 1);
		if (scan_guarded(&z, &o, "z64.zip", &r))
			return 9;
		NEED(r.t.child_bytes <= 16ull * MB, "zip64 size %llx produced %llu bytes",
		     (unsigned long long)big[i], (unsigned long long)r.t.child_bytes);
		NEED(r.secs < 2.0, "zip64 size took %.1fs", r.secs);
		he_free(&z);
		he_free(&ex);
	}
	return bad;
}

/* Member names that try to be something else. Each in its own zip with an honest
 * second member, so one refusal cannot hide what the others would show. */
static int kase_names(void)
{
	static const char nul_name[] = { 'a', 0, 'b' };
	static const struct { const char *name; uint32_t len; int slip; } nm[] = {
		{ "../../etc/passwd", 0, 1 }, { "/abs/path", 0, 0 }, { "C:\\windows\\x", 0, 0 },
		{ "a//b//c", 0, 0 }, { "//", 0, 0 }, { "x//0:evil", 0, 0 }, { "a\nb", 0, 0 },
		{ nul_name, 3, 0 }, { "..", 0, 0 }, { ".", 0, 0 }, { "a/", 0, 0 }, { "\xff\xfe\xfd", 0, 0 },
		{ "0:0:0:0", 0, 0 }, { "..\\..\\x", 0, 1 }
	};
	struct kof_scan_option o = opt_small();
	static const uint8_t body[32] = "kofeng names test body 0123456";
	unsigned i, n = sizeof nm / sizeof nm[0];
	int bad = 0;

	for (i = 0; i < n; i++) {
		struct zent e[2];
		struct he_w z = { 0 };
		struct run r;

		memset(e, 0, sizeof e);
		e[0].name = nm[i].name;
		e[0].name_len = nm[i].len;
		e[0].data = body;
		e[0].clen = sizeof body;
		e[0].usize = sizeof body;
		e[1] = e[0];
		e[1].name = "fine.bin";
		e[1].name_len = 0;
		zip_ex(&z, e, 2);
		if (scan_guarded(&z, &o, "names.zip", &r))
			return 9;
		NEED(r.t.max_depth <= 1, "member name %u forged the object separator: depth %llu", i,
		     (unsigned long long)r.t.max_depth);
		NEED(r.t.max_name < 64, "member name %u: object name of %llu bytes", i,
		     (unsigned long long)r.t.max_name);
		if (!nm[i].slip)
			NEED(r.t.objects == 3, "member name %u: %llu objects of 3", i,
			     (unsigned long long)r.t.objects);
		he_free(&z);
	}

	/* the same names through tar */
	for (i = 0; i < n; i++) {
		struct he_member m[2];
		struct he_w t = { 0 };
		struct run r;

		m[0].name = nm[i].name;
		m[0].data = body;
		m[0].len = sizeof body;
		m[1].name = "fine.bin";
		m[1].data = body;
		m[1].len = sizeof body;
		he_tar(&t, m, 2);
		if (scan_guarded(&t, &o, "names.tar", &r))
			return 9;
		NEED(r.t.max_depth <= 1, "tar member name %u forged the object separator: depth %llu", i,
		     (unsigned long long)r.t.max_depth);
		he_free(&t);
	}
	return bad;
}

/*
 * A name that merely contains dots. "../" as a SUBSTRING of an entry name would call
 * "Loading.../a.txt" or "x/.../y" a traversal without leaving any directory.
 * entryname.h's kof_name_escapes judges names by whole path segments, and that is the
 * one answer the engine holds to the question: the zip parse publishes it as
 * KOF_ZIP_ANOM_TRAVERSAL on the view.
 */
static int kase_slip_dots(void)
{
	static const uint8_t body[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };
	struct kof_scan_option o = opt_small();
	int bad = 0;

	(void)o;

	/*
	 * THE ENGINE'S OWN ANSWER: the zip parse judges every name with kof_name_escapes (whole path segments, a
	 * leading separator, a drive letter) and publishes it as KOF_ZIP_ANOM_TRAVERSAL on the view. A name that only
	 * contains dots is clear here, and every real escape is set.
	 */
	{
		static const char *clear[] = { "Loading.../a.txt", "x/.../y", "weird../dir/file", "a..b/c", "...", "dots../",
					       "..config", "a/..b", "..a/b" };
		static const char *escapes[] = { "../real", "a/../b", "..\\real", "a\\..\\b", "/abs/path", "\\abs", "C:x", "dir/.." };
		unsigned k;

		for (k = 0; k < sizeof clear / sizeof clear[0] + sizeof escapes / sizeof escapes[0]; k++) {
			int want = k >= sizeof clear / sizeof clear[0];
			const char *nm = want ? escapes[k - sizeof clear / sizeof clear[0]] : clear[k];
			struct zent e;
			struct he_w z = { 0 };
			struct kof_zip_info *zi = calloc(1, sizeof *zi);
			struct kof_obj_ctx ctx;

			if (!zi)
				return 9;
			memset(&e, 0, sizeof e);
			memset(&ctx, 0, sizeof ctx);
			e.name = nm;
			e.data = body;
			e.clen = sizeof body;
			e.usize = sizeof body;
			zip_ex(&z, &e, 1);
			if (!kof_zip_parse(kof_buf_make(z.p, z.n), zi, &ctx))
				return 9;
			NEED(!!(zi->anomalies & KOF_ZIP_ANOM_TRAVERSAL) == want, "'%s': the parse says traversal=%d, expected %d", nm,
			     !!(zi->anomalies & KOF_ZIP_ANOM_TRAVERSAL), want);
			kof_zip_release(zi);
			free(zi);
			he_free(&z);
		}
	}
	return bad;
}

/* The same name, a thousand times: every one is an object, none replaces another. */
static int kase_duplicates(void)
{
	struct kof_scan_option o = opt_small();
	struct zent *e = calloc(1000, sizeof *e);
	struct he_w z = { 0 };
	struct run r;
	static const uint8_t body[8] = "dupdupd";
	unsigned i;
	int bad = 0;

	if (!e)
		return 9;
	for (i = 0; i < 1000; i++) {
		e[i].name = "same";
		e[i].data = body;
		e[i].clen = sizeof body;
		e[i].usize = sizeof body;
	}
	zip_ex(&z, e, 1000);
	if (scan_guarded(&z, &o, "dup.zip", &r))
		return 9;
	printf("  dup.zip -> rc %d objects %llu distinct names %llu\n", r.rc, (unsigned long long)r.t.objects,
	       (unsigned long long)r.distinct);
	NEED(r.t.objects == 1001 || r.t.broken > 0, "1000 duplicate members gave %llu objects and no reason",
	     (unsigned long long)r.t.objects);
	NEED(r.distinct == r.names, "two objects share a name (%llu distinct of %llu)",
	     (unsigned long long)r.distinct, (unsigned long long)r.names);
	free(e);
	he_free(&z);
	return bad;
}

/* An archive in an archive, a hundred times over. */
static int kase_nest_stored(void)
{
	struct kof_scan_option o = opt_small();
	struct he_w cur = { 0 };
	struct run r;
	unsigned i;
	int bad = 0;
	static const uint8_t body[200] = "innermost";

	he_put(&cur, body, sizeof body);
	for (i = 0; i < 100; i++) {
		struct he_w nx = { 0 };
		struct he_member m;

		m.name = "in";
		m.data = cur.p;
		m.len = (uint32_t)cur.n;
		he_zip(&nx, &m, 1);
		he_free(&cur);
		cur = nx;
	}
	if (scan_guarded(&cur, &o, "nest.zip", &r))
		return 9;
	printf("  nest.zip x100 -> objects %llu max_depth %llu broken %llu\n", (unsigned long long)r.t.objects,
	       (unsigned long long)r.t.max_depth, (unsigned long long)r.t.broken);
	NEED(r.t.max_depth <= 64, "nesting went %llu deep", (unsigned long long)r.t.max_depth);
	NEED(r.t.broken > 0, "the layers past the allowance are not said to be unexamined");
	he_free(&cur);
	return bad;
}

/* The caller's depth limit is honoured exactly. */
static int kase_nest_limit(void)
{
	struct kof_scan_option o = opt_small();
	struct he_w cur = { 0 };
	struct run r;
	unsigned i, lim;
	int bad = 0;
	static const uint8_t body[200] = "innermost";

	he_put(&cur, body, sizeof body);
	for (i = 0; i < 12; i++) {
		struct he_w nx = { 0 };
		struct he_member m;

		m.name = "in";
		m.data = cur.p;
		m.len = (uint32_t)cur.n;
		he_zip(&nx, &m, 1);
		he_free(&cur);
		cur = nx;
	}
	for (lim = 1; lim <= 5; lim++) {
		o.max_object_depth = lim;
		if (scan_guarded(&cur, &o, "nest.zip", &r))
			return 9;
		NEED(r.t.max_depth <= lim, "max_object_depth %u: reached depth %llu", lim,
		     (unsigned long long)r.t.max_depth);
		NEED(r.t.objects == lim + 1u, "max_object_depth %u: %llu objects", lim,
		     (unsigned long long)r.t.objects);
	}
	he_free(&cur);
	return bad;
}

/* Long member names, nested: the names the host is handed must stay distinct. */
static int kase_nest_names(void)
{
	struct kof_scan_option o = opt_small();
	struct he_w cur = { 0 };
	struct run r;
	unsigned i;
	int bad = 0;
	char nm[260];
	static const uint8_t body[64] = "innermost";

	memset(nm, 'n', 250);
	nm[250] = 0;
	he_put(&cur, body, sizeof body);
	for (i = 0; i < 10; i++) {
		struct he_w nx = { 0 };
		struct he_member m;

		nm[0] = (char)('a' + i);
		m.name = nm;
		m.data = cur.p;
		m.len = (uint32_t)cur.n;
		he_zip(&nx, &m, 1);
		he_free(&cur);
		cur = nx;
	}
	if (scan_guarded(&cur, &o, "nest.zip", &r))
		return 9;
	printf("  nest names -> objects %llu distinct %llu max_name %llu\n", (unsigned long long)r.t.objects,
	       (unsigned long long)r.distinct, (unsigned long long)r.t.max_name);
	NEED(r.distinct == r.names, "%llu objects were reported under %llu distinct names",
	     (unsigned long long)r.names, (unsigned long long)r.distinct);
	he_free(&cur);
	return bad;
}

/* A GNU @LongLink member: the long name in its own 'L' entry, then the real entry under a
 * name cut to 99 bytes, as GNU tar writes it. */
static void tar_gnu_long(struct he_w *w, const char *name, size_t nlen, const void *data, uint32_t len)
{
	uint8_t h[512];
	unsigned sum, k;
	size_t pad, i;

	for (i = 0; i < 2; i++) {
		uint32_t sz = i == 0 ? (uint32_t)nlen + 1u : len;

		memset(h, 0, sizeof h);
		if (i == 0)
			memcpy(h, "././@LongLink", 13);
		else
			memcpy(h, name, nlen < 99 ? nlen : 99);
		memcpy(h + 100, "0000644", 7);
		snprintf((char *)h + 124, 12, "%011o", sz);
		h[156] = i == 0 ? 'L' : '0';
		memcpy(h + 257, "ustar", 5);
		memcpy(h + 263, "00", 2);
		memset(h + 148, ' ', 8);
		for (sum = 0, k = 0; k < 512; k++)
			sum += h[k];
		snprintf((char *)h + 148, 8, "%06o", sum);
		h[154] = 0;
		h[155] = ' ';
		he_put(w, h, sizeof h);
		if (i == 0) {
			he_put(w, name, nlen);
			he_zero(w, 1);
			pad = (512u - ((uint32_t)(nlen + 1u) & 511u)) & 511u;
		} else {
			he_put(w, data, len);
			pad = (512u - (len & 511u)) & 511u;
		}
		he_zero(w, pad);
	}
}

/*
 * NAMES ARE KEPT WHOLE up to what each format's standard allows. A member name is the
 * parent's name and then "//<index>:<label>", and was composed into 512 bytes and cut there,
 * so a deep parent path or a long label made two members one name; the label itself was held
 * to 95 bytes. Checked on the three widths that matter: a zip field at its 16-bit limit, a zip
 * under a root path of 3000 bytes with two members of ONE name (only the index tells them
 * apart), and a GNU long name of 3000 bytes (past ustar's 100+155, inside PATH_MAX).
 */
static int kase_long_names(void)
{
	struct kof_scan_option o = opt_small();
	static const uint8_t body[32] = "kofeng long names test body 012";
	struct he_w w = { 0 };
	struct run r;
	struct zent e[2];
	char *big = malloc(70000), *root = malloc(3200);
	int bad = 0;

	if (!big || !root)
		return 9;
	memset(big, 'z', 70000);
	memset(root, 'r', 3000);
	root[3000] = 0;

	memset(e, 0, sizeof e);
	e[0].name = big;
	e[0].name_len = 65535;
	e[0].data = body;
	e[0].clen = e[0].usize = sizeof body;
	zip_ex(&w, e, 1);
	if (scan_guarded(&w, &o, "wide.zip", &r))
		return 9;
	NEED(r.t.objects == 2 && r.t.max_name >= 65535u + strlen("wide.zip//0:"),
	     "a zip name of 65535 bytes: %llu objects, longest object name %llu", (unsigned long long)r.t.objects,
	     (unsigned long long)r.t.max_name);
	NEED(r.t.broken == 0 && r.names_invalid == 0, "a zip name at its field's limit is valid (%llu broken)",
	     (unsigned long long)r.t.broken);
	he_free(&w);

	memset(e, 0, sizeof e);
	e[0].name = "same";
	e[0].data = body;
	e[0].clen = e[0].usize = sizeof body;
	e[1] = e[0];
	zip_ex(&w, e, 2);
	if (scan_guarded(&w, &o, root, &r))
		return 9;
	NEED(r.t.objects == 3 && r.distinct == r.names, "two members of one name under a 3000 byte root: %llu objects, %llu distinct names of %llu",
	     (unsigned long long)r.t.objects, (unsigned long long)r.distinct, (unsigned long long)r.names);
	NEED(r.t.max_name == 3000u + strlen("//1:same"), "the whole parent name survives: longest %llu", (unsigned long long)r.t.max_name);
	he_free(&w);

	tar_gnu_long(&w, big, 3000, body, sizeof body);
	he_zero(&w, 1024);
	if (scan_guarded(&w, &o, "gnu.tar", &r))
		return 9;
	NEED(r.t.max_name >= 3000u + strlen("gnu.tar//0:") && r.names_invalid == 0 && r.t.broken == 0,
	     "a GNU long name of 3000 bytes is kept whole: longest %llu, %llu invalid", (unsigned long long)r.t.max_name,
	     (unsigned long long)r.names_invalid);
	he_free(&w);
	free(big);
	free(root);
	return bad;
}

/*
 * A NAME PAST ITS STANDARD IS INVALID, NOT CUT. A GNU long name of 5000 bytes is longer than
 * any path the system stores (PATH_MAX 4096): the member is opened - its bytes are evidence -
 * without a name, its object is reported damaged and kof_stats.names_invalid counts it. It was
 * cut at 400 bytes in the parser, so it looked like a different, valid name.
 */
static int kase_name_invalid(void)
{
	struct kof_scan_option o = opt_small();
	static const uint8_t body[32] = "kofeng invalid name test body 0";
	struct he_w w = { 0 };
	struct run r;
	char *big = malloc(6000);
	int bad = 0;

	if (!big)
		return 9;
	memset(big, 'q', 6000);
	tar_gnu_long(&w, big, 5000, body, sizeof body);
	he_zero(&w, 1024);
	if (scan_guarded(&w, &o, "bad.tar", &r))
		return 9;
	NEED(r.names_invalid == 1, "one invalid name counted: %llu", (unsigned long long)r.names_invalid);
	NEED(r.t.broken >= 1, "the member whose name is invalid is reported broken: %llu", (unsigned long long)r.t.broken);
	NEED(r.t.objects == 2 && r.t.max_name == strlen("bad.tar//0"), "the member is opened without a name: %llu objects, longest %llu",
	     (unsigned long long)r.t.objects, (unsigned long long)r.t.max_name);
	he_free(&w);
	free(big);
	return bad;
}

/* Twenty thousand gzip members, one after another: gzip -dc writes them as ONE stream, so the engine yields one child
 * holding all of them, and says nothing is wrong because nothing is. */
static int kase_gzip_members(void)
{
	struct kof_scan_option o = opt_small();
	struct he_w g = { 0 };
	struct run r;
	unsigned i;
	int bad = 0;

	for (i = 0; i < 20000; i++)
		he_gzip(&g, "x", 1);
	if (scan_guarded(&g, &o, "multi.gz", &r))
		return 9;
	printf("  multi.gz x20000 -> rc %d objects %llu child_bytes %llu broken %llu %.2fs\n", r.rc,
	       (unsigned long long)r.t.objects, (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken, r.secs);
	NEED(r.secs < 5.0, "took %.1fs", r.secs);
	NEED(r.t.child_bytes == 20000u, "the members' output is %llu bytes, not the 20000 they hold",
	     (unsigned long long)r.t.child_bytes);
	NEED(r.t.broken == 0, "a well formed multi-member file is reported broken (%llu)", (unsigned long long)r.t.broken);
	he_free(&g);
	return bad;
}

/* One gzip made of the given members and a tail, scanned; fills `r`. */
static int gz_scan(const char *name, const uint8_t *tail, size_t tail_n, size_t cut, struct run *r)
{
	struct kof_scan_option o = opt_small();
	struct he_w g = { 0 };
	uint8_t a[100], b[200];
	int rc;

	memset(a, 'a', sizeof a);
	memset(b, 'b', sizeof b);
	he_gzip(&g, a, sizeof a);
	he_gzip(&g, b, sizeof b);
	g.n -= cut;                      /* cut bytes off the second member's end */
	if (tail_n)
		he_put(&g, tail, tail_n);
	rc = scan_guarded(&g, &o, name, r);
	he_free(&g);
	return rc;
}

/*
 * What follows the first member of a gzip file. Each case is two members of 100 and 200 bytes and then:
 *   nothing        both are decoded (300 bytes in one child), nothing is broken
 *   a cut trailer  the second member's output is kept and the object says it is damaged
 *   blanks         zero padding is tolerated as gzip does and is not an incident
 *   junk           decoded up to it, then reported: appended bytes are a fact about the file
 *   a bare header  a member header with no stream behind it is damaged
 */
static int kase_gzip_concat(void)
{
	static const uint8_t junk[] = "this is not a gzip member, it is whatever was appended";
	static const uint8_t zeros[64];
	static const uint8_t bare[] = { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3 };
	struct run r;
	int bad = 0;

	/* The header walk the host uses to find a later member: where the stream starts, and what a cut header looks like. */
	{
		static const uint8_t named[] = { 0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3, 'a', 'b', 0, 3, 0 };
		static const uint8_t cut[] = { 0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3, 'a', 'b' };
		static const uint8_t no[] = "not gzip at all";
		struct kof_gzip_info gi;

		NEED(kof_gzip_header(kof_buf_make(named, sizeof named), &gi) && gi.valid && gi.data_off == 13u && gi.name_len == 2u,
		     "a named member starts its stream at %llu", (unsigned long long)gi.data_off);
		NEED(kof_gzip_header(kof_buf_make(cut, sizeof cut), &gi) && gi.data_off == sizeof cut &&
			     (gi.anomalies & KOF_GZIP_ANOM_NAME_UNTERMINATED),
		     "a name that never ends leaves no room for a stream and says so");
		NEED(!kof_gzip_header(kof_buf_make(no, sizeof no - 1u), &gi) && !gi.valid, "bytes that are not a member are refused");
	}
	if (gz_scan("c0.gz", NULL, 0, 0, &r))
		return 9;
	NEED(r.t.child_bytes == 300u && r.t.broken == 0, "two members: %llu child bytes, %llu broken (want 300, 0)",
	     (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken);
	if (gz_scan("c1.gz", NULL, 0, 3, &r))
		return 9;
	NEED(r.t.child_bytes == 300u && r.t.broken >= 1u, "a cut trailer: %llu child bytes, %llu broken (want 300, >=1)",
	     (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken);
	if (gz_scan("c2.gz", zeros, sizeof zeros, 0, &r))
		return 9;
	NEED(r.t.child_bytes == 300u && r.t.broken == 0, "zero padding: %llu child bytes, %llu broken (want 300, 0)",
	     (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken);
	if (gz_scan("c3.gz", junk, sizeof junk, 0, &r))
		return 9;
	NEED(r.t.child_bytes == 300u && r.t.broken >= 1u, "trailing junk: %llu child bytes, %llu broken (want 300, >=1)",
	     (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken);
	if (gz_scan("c4.gz", bare, sizeof bare, 0, &r))
		return 9;
	NEED(r.t.child_bytes == 300u && r.t.broken >= 1u, "a header with no stream: %llu child bytes, %llu broken (want 300, >=1)",
	     (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken);
	return bad;
}

/* Several members that each expand a long way: the budget bounds the SUM and says so. */
static int kase_gzip_member_bomb(void)
{
	struct he_w d = { 0 }, g = { 0 };
	struct kof_scan_option o = opt_small();
	struct run r;
	unsigned m;
	int bad = 0;

	he_deflate_run(&d, 'A', 100000);
	for (m = 0; m < 8; m++) {
		he_u8(&g, 0x1f);
		he_u8(&g, 0x8b);
		he_u8(&g, 8);
		he_u8(&g, 0);
		he_u32(&g, 0);
		he_u8(&g, 0);
		he_u8(&g, 3);
		he_put(&g, d.p, d.n);
		he_u32(&g, 0);
		he_u32(&g, (uint32_t)(1u + 258u * 100000u));
	}
	if (scan_guarded(&g, &o, "bombs.gz", &r))
		return 9;
	printf("  bombs.gz %zu bytes x8 members -> objects %llu child_bytes %llu broken %llu (limit %llu) %.2fs\n", g.n,
	       (unsigned long long)r.t.objects, (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken,
	       (unsigned long long)r.t.broken_limit, r.secs);
	NEED(r.t.child_bytes <= o.max_produced_bytes, "produced %llu bytes past the budget", (unsigned long long)r.t.child_bytes);
	NEED(r.t.broken_limit > 0 || r.limit_hits > 0, "members past the budget were dropped and nothing says so");
	he_free(&d);
	he_free(&g);
	return bad;
}

/* A hundred thousand empty tar members. */
static int kase_tar_many(void)
{
	struct kof_scan_option o = opt_small();
	struct he_w t = { 0 };
	struct run r;
	unsigned i;
	int bad = 0;
	struct he_member m;
	char name[16];

	m.name = name;
	m.data = "";
	m.len = 0;
	for (i = 0; i < 100000; i++) {
		struct he_w one = { 0 };

		snprintf(name, sizeof name, "f%u", i);
		he_tar(&one, &m, 1);
		he_put(&t, one.p, one.n - 1024u);
		he_free(&one);
	}
	he_zero(&t, 1024);
	if (scan_guarded(&t, &o, "many.tar", &r))
		return 9;
	printf("  many.tar x100000 -> rc %d objects %llu broken %llu %.2fs\n", r.rc,
	       (unsigned long long)r.t.objects, (unsigned long long)r.t.broken, r.secs);
	NEED(r.secs < 10.0, "took %.1fs", r.secs);
	/* The members are EMPTY, so none is a child (tar.c opens a member with content); what matters is that
	 * the walk reaches the end of all hundred thousand - the entry table was 2048 rows and said so at
	 * the 2049th (ENTRIES_FULL, Limit), and is the size of the archive now - so nothing is reported. */
	NEED(r.t.objects == 1 && r.t.broken == 0, "%llu objects, broken %llu: empty members make no child and no report",
	     (unsigned long long)r.t.objects, (unsigned long long)r.t.broken);
	he_free(&t);
	return bad;
}

/* An end-of-central-directory signature at every position of 256KB of tail. */
static int kase_fake_eocd(void)
{
	struct kof_scan_option o = opt_small();
	struct he_w z = { 0 };
	struct run r;
	unsigned i;
	int bad = 0;

	he_u32(&z, 0x04034b50u);
	he_zero(&z, 26);
	for (i = 0; i < 65536u; i++)
		he_u32(&z, 0x06054b50u);
	if (scan_guarded(&z, &o, "fake.zip", &r))
		return 9;
	printf("  fake EOCD x65536 -> rc %d objects %llu %.2fs\n", r.rc, (unsigned long long)r.t.objects, r.secs);
	NEED(r.secs < 3.0, "took %.1fs", r.secs);
	he_free(&z);
	return bad;
}

/* A central directory that claims 65535 entries and holds none. */
static int kase_cd_count(void)
{
	struct kof_scan_option o = opt_small();
	struct he_w z = { 0 };
	struct run r;
	int bad = 0;

	he_u32(&z, 0x06054b50u);
	he_u16(&z, 0);
	he_u16(&z, 0);
	he_u16(&z, 0xffff);
	he_u16(&z, 0xffff);
	he_u32(&z, 0xffffffffu);
	he_u32(&z, 0);
	he_u16(&z, 0);
	if (scan_guarded(&z, &o, "count.zip", &r))
		return 9;
	NEED(r.secs < 2.0, "took %.1fs", r.secs);
	NEED(r.t.objects < 70000, "%llu objects out of 22 bytes", (unsigned long long)r.t.objects);
	he_free(&z);
	return bad;
}

/* Local-header offsets that point into the directory itself, at the end record, and at 0. */
static int kase_self_reference(void)
{
	struct kof_scan_option o = opt_small();
	int bad = 0;
	unsigned v;

	for (v = 0; v < 5; v++) {
		struct he_w z = { 0 };
		struct zent e[4];
		struct run r;
		static const uint8_t body[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };
		uint32_t cd_off, eocd, i;

		memset(e, 0, sizeof e);
		for (i = 0; i < 4; i++) {
			e[i].name = "self";
			e[i].data = body;
			e[i].clen = 16;
			e[i].usize = 16;
		}
		zip_ex(&z, e, 4);
		eocd = (uint32_t)z.n - 22u;
		cd_off = z.p[eocd + 16] | (uint32_t)z.p[eocd + 17] << 8 | (uint32_t)z.p[eocd + 18] << 16 |
			 (uint32_t)z.p[eocd + 19] << 24;
		for (i = 0; i < 4; i++) {
			uint8_t *lh = z.p + cd_off + i * (46u + 4u) + 42u;
			uint32_t to = v == 0 ? cd_off : v == 1 ? eocd : v == 2 ? 0u : v == 3 ? (uint32_t)z.n - 1u
										: 0xffffffffu;

			lh[0] = (uint8_t)to;
			lh[1] = (uint8_t)(to >> 8);
			lh[2] = (uint8_t)(to >> 16);
			lh[3] = (uint8_t)(to >> 24);
		}
		if (scan_guarded(&z, &o, "self.zip", &r))
			return 9;
		NEED(r.secs < 2.0, "variant %u took %.1fs", v, r.secs);
		NEED(r.t.child_bytes <= 16u * 8u, "variant %u: %llu bytes from 4 entries of 16", v,
		     (unsigned long long)r.t.child_bytes);
		he_free(&z);
	}
	return bad;
}

/* ---- structures that point at themselves ---------------------------------------------------------------- */

static const struct field *field_named(const struct field *f, unsigned n, const char *name)
{
	unsigned i;

	for (i = 0; i < n; i++)
		if (!strcmp(f[i].name, name))
			return &f[i];
	return NULL;
}

static int scan_cycle(uint8_t *b, size_t n, const char *name, double limit, struct run *r)
{
	struct he_w w;
	struct kof_scan_option o = opt_small();

	w.p = b;
	w.n = n;
	w.cap = n;
	w.oom = 0;
	if (scan_guarded(&w, &o, name, r))
		return 9;
	return r->secs < limit ? 0 : 1;
}

/* A compound file whose sector chains, directory tree and index loop on themselves. */
static int kase_ole_cycles(void)
{
	static const char *const sets[][3] = {
		{ "fat[*]", "0", NULL },                       /* every sector's successor is sector 0 */
		{ "dir[*].left", "0", NULL },                  /* every sibling pointer is the root */
		{ "dir[*].child", "0", "dir[*].right" },       /* the root is everyone's child */
		{ "difat_start", "0", "n_difat" },             /* the extra index chain starts at 0 and claims 2^32-1 sectors */
		{ "mfat_start", "0", "n_mfat" },               /* the small-block chain likewise */
		{ "dir_start", "0", NULL },                    /* the directory begins at the header's own sector */
		{ "sector_shift", "31", NULL },                /* 2 GiB sectors */
		{ "dir[*].start", "0", "dir[*].size" }         /* every stream starts at 0 and is as large as it can be */
	};
	uint8_t *b = calloc(1, SEED_MAX);
	size_t i, n;
	int bad = 0;

	if (!b)
		return 9;
	for (i = 0; i < sizeof sets / sizeof sets[0]; i++) {
		struct run r;
		const struct field *f1, *f2;
		unsigned nf = (unsigned)(sizeof f_docole / sizeof f_docole[0]);

		n = (size_t)seed_docole(b);
		f1 = field_named(f_docole, nf, sets[i][0]);
		f2 = sets[i][2] ? field_named(f_docole, nf, sets[i][2]) : NULL;
		if (!f1)
			continue;
		poke(b, n, f1, strtoull(sets[i][1], NULL, 10));
		if (f2)
			poke(b, n, f2, 0xffffffffffffffffull);
		if (scan_cycle(b, n, "cycle.doc", 3.0, &r)) {
			printf("  FAIL: %s took %.1fs\n", sets[i][0], r.secs);
			bad = 1;
		}
		if (r.t.child_bytes > 64ull * MB) {
			printf("  FAIL: %s produced %llu bytes\n", sets[i][0], (unsigned long long)r.t.child_bytes);
			bad = 1;
		}
	}
	free(b);
	return bad;
}

/* PDFs whose cross reference sections, object streams and filter chains loop. */
static int kase_pdf_loops(void)
{
	struct he_w w = { 0 };
	struct run r;
	unsigned v;
	int bad = 0;
	size_t xref_at;

	for (v = 0; v < 6; v++) {
		he_free(&w);
		he_str(&w, "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n");
		xref_at = w.n;
		switch (v) {
		case 0:        /* a trailer whose /Prev is its own section */
			he_str(&w, "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R /Prev ");
			{
				char num[24];

				snprintf(num, sizeof num, "%zu", xref_at);
				he_str(&w, num);
			}
			he_str(&w, " >>\nstartxref\n");
			{
				char num[24];

				snprintf(num, sizeof num, "%zu", xref_at);
				he_str(&w, num);
			}
			he_str(&w, "\n%%EOF\n");
			break;
		case 1:        /* startxref pointing at 0 and at the end of the file */
			he_str(&w, "startxref\n0\n%%EOF\nstartxref\n99999999999999999999\n%%EOF\n");
			break;
		case 2:        /* an object stream that extends itself and lists its own number */
			he_str(&w, "2 0 obj\n<< /Type /ObjStm /N 100000 /First 8 /Extends 2 0 R /Length 16 >>\nstream\n2 0 2 0 2 0 2 0\nendstream\nendobj\n");
			break;
		case 3: {      /* a filter chain fifty thousand long */
			unsigned k;

			he_str(&w, "2 0 obj\n<< /Length 4 /Filter [");
			for (k = 0; k < 50000; k++)
				he_str(&w, "/ASCIIHexDecode ");
			he_str(&w, "] >>\nstream\n4142>\nendstream\nendobj\n");
			break;
		}
		case 4:        /* a reference chain: object N is a reference to N+1, ten thousand of them */
			{
				unsigned k;
				char line[48];

				for (k = 2; k < 10002; k++) {
					snprintf(line, sizeof line, "%u 0 obj %u 0 R endobj\n", k, k + 1);
					he_str(&w, line);
				}
			}
			he_str(&w, "trailer << /Root 2 0 R >>\n");
			break;
		default: {     /* an object that refers to itself, in a dictionary, an array and a stream length */
			he_str(&w, "2 0 obj\n<< /Length 2 0 R /Kids [2 0 R 2 0 R] /Parent 2 0 R /Filter /FlateDecode >>\nstream\nxx\nendstream\nendobj\n");
			break;
		}
		}
		{
			struct kof_scan_option o = opt_small();

			scan_guarded(&w, &o, "loop.pdf", &r);
		}
		if (r.secs > 3.0) {
			printf("  FAIL: pdf variant %u took %.1fs\n", v, r.secs);
			bad = 1;
		}
	}
	he_free(&w);
	return bad;
}

/* A cabinet that claims 65535 folders and files whose folder numbers are nowhere. */
static int kase_cab_cycles(void)
{
	struct he_w w = { 0 };
	unsigned v;
	int bad = 0;

	for (v = 0; v < 4; v++) {
		struct run r;

		he_free(&w);
		hs_cab(&w);
		switch (v) {
		case 0:        /* cFolders at 26, cFiles at 28 */
			w.p[26] = 0xff; w.p[27] = 0xff; w.p[28] = 0xff; w.p[29] = 0xff;
			break;
		case 1:        /* every file in folder 0xfffe */
			{
				size_t at = 36 + 16 + 8;
				unsigned k;

				for (k = 0; k < 3 && at + 16 < w.n; k++) {
					w.p[at + 8] = 0xfe; w.p[at + 9] = 0xff;
					at += 16 + 10;
				}
			}
			break;
		case 2:        /* the files section starts inside the header, and cbCabinet is 2^32-1 */
			w.p[16] = 4; w.p[17] = 0; w.p[18] = 0; w.p[19] = 0;
			w.p[8] = 0xff; w.p[9] = 0xff; w.p[10] = 0xff; w.p[11] = 0xff;
			break;
		default:       /* both folders' data begin at the folder table itself */
			w.p[36] = 36; w.p[37] = 0; w.p[38] = 0; w.p[39] = 0;
			w.p[44] = 36; w.p[45] = 0; w.p[46] = 0; w.p[47] = 0;
			break;
		}
		{
			struct kof_scan_option o = opt_small();

			scan_guarded(&w, &o, "cycle.cab", &r);
		}
		if (r.secs > 3.0 || r.t.child_bytes > 64ull * MB) {
			printf("  FAIL: cab variant %u: %.1fs, %llu bytes\n", v, r.secs, (unsigned long long)r.t.child_bytes);
			bad = 1;
		}
	}
	he_free(&w);
	return bad;
}


/* ---- an entry that outgrows its OWN bound is cut and the walk goes on ------------------------- */

/* One object cap of 1 MiB, so an entry of a few MiB meets it without a long test. */
static struct kof_scan_option opt_cap1m(void)
{
	struct kof_scan_option o = he_opt();

	o.max_resident_bytes = 128ull * MB;
	o.max_produced_bytes = 64ull * MB;
	o.max_object_bytes = 1ull * MB;
	return o;
}

static void put_gz_member(struct he_w *g, const struct he_w *d)
{
	he_u8(g, 0x1f);
	he_u8(g, 0x8b);
	he_u8(g, 8);
	he_u8(g, 0);
	he_u32(g, 0);
	he_u8(g, 0);
	he_u8(g, 3);
	he_put(g, d->p, d->n);
	he_u32(g, 0);
	he_u32(g, 0);
}

/*
 * A deflated member over the object cap, and another declared to expand past the ratio,
 * between ordinary members. Each of the two is CUT: the bytes decoded so far are its
 * object, and it says Limit itself. The entries before and after are all opened and the
 * parent is not told to stop - it was, by one sticky LIMIT on the root, and an 84 MB archive
 * with one 91 MB member came back with 6 objects (the rest of its 5750 entries lost).
 */
static int kase_cut_zip(void)
{
	static const uint8_t body[16] = "stored-entry-bd";
	static const char *const names[] = { "first", "huge", "mid", "ratio", "small", "last" };
	struct he_w big = { 0 }, tiny = { 0 }, z = { 0 };
	struct zent e[6];
	struct kof_scan_option o = opt_cap1m();
	struct run r;
	unsigned i;
	int bad = 0;

	he_deflate_run(&big, 'A', 10000);      /* 2.58 MB out */
	he_deflate_run(&tiny, 'B', 10);
	memset(e, 0, sizeof e);
	for (i = 0; i < 6; i++)
		e[i].name = names[i];
	e[0].data = body; e[0].clen = e[0].usize = sizeof body;
	/* declared at 8x its compressed size: no ratio clamp, so the OBJECT CAP is what cuts it */
	e[1].method = 8; e[1].data = big.p; e[1].clen = (uint32_t)big.n; e[1].usize = (uint32_t)(big.n * 8u);
	e[2].data = body; e[2].clen = e[2].usize = sizeof body;
	/* declared at the size it really has: 2.58 MB over a few KB, which the RATIO clamp cuts at 1 MiB */
	e[3].method = 8; e[3].data = big.p; e[3].clen = (uint32_t)big.n; e[3].usize = (uint32_t)(1u + 258u * 10000u);
	e[4].method = 8; e[4].data = tiny.p; e[4].clen = (uint32_t)tiny.n; e[4].usize = 1u + 258u * 10u;
	e[5].data = body; e[5].clen = e[5].usize = sizeof body;
	zip_ex(&z, e, 6);
	if (scan_guarded(&z, &o, "cut.zip", &r))
		return 9;
	printf("  cut.zip -> objects %llu broken %llu (limit %llu) limit_hits %llu\n", (unsigned long long)r.t.objects,
	       (unsigned long long)r.t.broken, (unsigned long long)r.t.broken_limit, (unsigned long long)r.limit_hits);
	NEED(r.t.objects == 7, "root and all six entries are opened, got %llu objects", (unsigned long long)r.t.objects);
	for (i = 0; i < 6; i++)
		NEED(os_find(names[i]) != NULL, "entry %s was lost", names[i]);
	for (i = 1; i < 4; i += 2) {
		const struct oseen *m = os_find(names[i]);

		NEED(m && m->broken == KOF_BROKEN_LIMIT, "%s: cut at its bound and not saying Limit itself", names[i]);
		NEED(m && m->len > 0 && m->len <= 1ull * MB, "%s: the bytes before the cut are its object (%llu)", names[i],
		     m ? (unsigned long long)m->len : 0ull);
	}
	NEED(os_find("first") && !os_find("first")->broken && os_find("mid") && !os_find("mid")->broken &&
	     os_find("small") && !os_find("small")->broken && os_find("last") && !os_find("last")->broken,
	     "an entry that did not meet a bound is reported broken");
	NEED(os_n && !os[0].broken, "the archive itself stopped: a cut member is the member's report (broken %u)",
	     os_n ? os[0].broken : 0u);
	NEED(r.limit_hits >= 2, "the two cuts are not counted (%llu)", (unsigned long long)r.limit_hits);
	he_free(&big);
	he_free(&tiny);
	he_free(&z);
	return bad;
}

/* The same shape one layer down: the cut is inside an archive that is itself a member. */
static int kase_cut_nested(void)
{
	static const uint8_t body[16] = "stored-entry-bd";
	struct he_w big = { 0 }, in = { 0 }, out = { 0 };
	struct zent e[3], o2[3];
	struct kof_scan_option o = opt_cap1m();
	struct run r;
	int bad = 0;

	he_deflate_run(&big, 'A', 10000);
	memset(e, 0, sizeof e);
	e[0].name = "p"; e[0].data = body; e[0].clen = e[0].usize = sizeof body;
	e[1].name = "big"; e[1].method = 8; e[1].data = big.p; e[1].clen = (uint32_t)big.n; e[1].usize = (uint32_t)(big.n * 8u);
	e[2].name = "q"; e[2].data = body; e[2].clen = e[2].usize = sizeof body;
	zip_ex(&in, e, 3);
	memset(o2, 0, sizeof o2);
	o2[0].name = "a"; o2[0].data = body; o2[0].clen = o2[0].usize = sizeof body;
	o2[1].name = "inner.zip"; o2[1].data = in.p; o2[1].clen = o2[1].usize = (uint32_t)in.n;
	o2[2].name = "z"; o2[2].data = body; o2[2].clen = o2[2].usize = sizeof body;
	zip_ex(&out, o2, 3);
	if (scan_guarded(&out, &o, "nest-cut.zip", &r))
		return 9;
	printf("  nest-cut.zip -> objects %llu broken %llu\n", (unsigned long long)r.t.objects, (unsigned long long)r.t.broken);
	NEED(os_find("p") && os_find("q") && os_find("z") && os_find("a"), "an entry after the cut layer was lost");
	NEED(os_find("big") && os_find("big")->broken == KOF_BROKEN_LIMIT, "the cut member does not say Limit");
	NEED(os_find("inner.zip") && !os_find("inner.zip")->broken, "the archive around the cut member is reported broken");
	he_free(&big);
	he_free(&in);
	he_free(&out);
	return bad;
}

/* A gzip file is ONE stream: a member that outgrows the object cap cuts that object, and says so. */
static int kase_cut_gzip(void)
{
	struct he_w d1 = { 0 }, d2 = { 0 }, g = { 0 };
	struct kof_scan_option o = opt_cap1m();
	struct run r;
	int bad = 0;

	he_deflate_run(&d1, 'A', 10);
	he_deflate_run(&d2, 'B', 10000);
	put_gz_member(&g, &d1);
	put_gz_member(&g, &d2);
	put_gz_member(&g, &d1);
	if (scan_guarded(&g, &o, "cut.gz", &r))
		return 9;
	printf("  cut.gz -> objects %llu broken %llu limit_hits %llu\n", (unsigned long long)r.t.objects,
	       (unsigned long long)r.t.broken, (unsigned long long)r.limit_hits);
	NEED(r.t.objects == 2, "the gzip's object was not made (%llu objects)", (unsigned long long)r.t.objects);
	NEED(os_n == 2 && os[1].broken == KOF_BROKEN_LIMIT && os[1].len > 0 && os[1].len <= 1ull * MB,
	     "the cut stream does not say Limit itself (broken %u, %llu bytes)", os_n > 1 ? os[1].broken : 0u,
	     os_n > 1 ? (unsigned long long)os[1].len : 0ull);
	NEED(os_n && !os[0].broken, "the gzip file itself is reported stopped");
	NEED(r.limit_hits >= 1, "the cut is not counted");
	he_free(&d1);
	he_free(&d2);
	he_free(&g);
	return bad;
}

/*
 * The same through a BUFFERED coding (xz: LZMA2 into a buffer sized before the decode). 4 MiB
 * of zeros in two 2 MiB blocks and a small third; the object cap is 1 MiB, so each of the first two
 * is cut and carries Limit itself, and the third is opened whole. The archive is not told to stop,
 * and before this the cut was said on the PARENT (which then ended the other modules' turn).
 * Generated with: xz -T1 --block-size=2MiB --check=crc32 (4 MiB of zero bytes, then
 * "TAIL-MARKER-" x 100); 900 bytes.
 */
static int kase_cut_xz(void)
{
	static const uint8_t xz[] = {
	0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36,
	0x02, 0x00, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3,
	0xff, 0xff, 0x11, 0x01, 0x6c, 0x5d, 0x00, 0x00, 0x6f, 0xfd, 0xff, 0xff,
	0xa3, 0xb7, 0xff, 0x47, 0x3e, 0x48, 0x15, 0x72, 0x39, 0x61, 0x51, 0xb8,
	0x92, 0x28, 0xe6, 0xa3, 0x86, 0x07, 0xf9, 0xee, 0xe4, 0x1e, 0x82, 0xd3,
	0x2f, 0xc5, 0x3a, 0x3c, 0x01, 0x4b, 0xb1, 0x7e, 0xc9, 0x8a, 0x8a, 0x4d,
	0x2f, 0xa3, 0x0d, 0xd9, 0x7f, 0xa6, 0xe3, 0x8c, 0x23, 0x11, 0x53, 0xe0,
	0x59, 0x18, 0xc5, 0x75, 0x8a, 0xe2, 0x77, 0xf8, 0xb6, 0x94, 0x7f, 0x0c,
	0x6a, 0xc0, 0xde, 0x74, 0x49, 0x64, 0xe2, 0xe9, 0x5c, 0x53, 0xb2, 0x04,
	0xd8, 0xf7, 0x44, 0x0c, 0xab, 0x5f, 0x0d, 0x6d, 0x46, 0xe9, 0xe5, 0xc3,
	0x76, 0x88, 0xb7, 0x96, 0x57, 0xac, 0xb6, 0x4d, 0xe1, 0x69, 0x1d, 0x6f,
	0xfb, 0x4b, 0x88, 0x10, 0x6c, 0x42, 0xcb, 0x88, 0x3f, 0x5c, 0x00, 0x8f,
	0xd0, 0x4e, 0xaf, 0x26, 0x28, 0x94, 0x71, 0x1f, 0x3d, 0x8f, 0x24, 0xe1,
	0x70, 0x9e, 0xa7, 0x23, 0x5f, 0xec, 0x28, 0xcb, 0x85, 0xd1, 0x95, 0x98,
	0x8a, 0x7e, 0x2a, 0x91, 0xf2, 0x27, 0x75, 0xf7, 0x19, 0xc0, 0x06, 0x98,
	0x4d, 0x98, 0xfd, 0xd8, 0xaf, 0xd5, 0x90, 0x0f, 0xc4, 0x25, 0x53, 0xf8,
	0xf5, 0x91, 0x36, 0x31, 0x05, 0xa5, 0xb0, 0xee, 0x6f, 0xc1, 0x70, 0x4d,
	0x47, 0x0c, 0xd1, 0x91, 0x11, 0xaa, 0xad, 0x60, 0x1d, 0xba, 0xce, 0xb1,
	0x27, 0x18, 0x5c, 0x59, 0x86, 0xe9, 0x66, 0x52, 0x58, 0xbe, 0xe9, 0x76,
	0xac, 0x59, 0xe4, 0xe5, 0x5b, 0x05, 0x08, 0xf9, 0xc7, 0xda, 0xad, 0xfc,
	0xfb, 0x52, 0x2b, 0x74, 0xcd, 0x1e, 0x5b, 0x20, 0x42, 0xf9, 0xdd, 0x53,
	0x3d, 0xf8, 0x29, 0x64, 0x09, 0x3b, 0x80, 0xcb, 0x2a, 0x6c, 0xdf, 0xb5,
	0x3b, 0xf0, 0xc4, 0xbd, 0x2e, 0x5f, 0xaa, 0x0f, 0x3e, 0x4b, 0x66, 0x42,
	0x90, 0x13, 0x0e, 0xff, 0x10, 0x93, 0xf8, 0x71, 0x78, 0x59, 0xf8, 0x0b,
	0xcd, 0xff, 0x95, 0x28, 0x46, 0x0f, 0xa9, 0xfc, 0x7c, 0xde, 0xfb, 0x9a,
	0x30, 0x2e, 0x56, 0xc0, 0x8f, 0x85, 0xf3, 0x83, 0x81, 0xc0, 0x65, 0xc4,
	0x25, 0x53, 0xf8, 0xf5, 0x91, 0x36, 0x31, 0x05, 0xa5, 0xb0, 0xee, 0x6f,
	0xc1, 0x70, 0x4d, 0x47, 0x0c, 0xd1, 0x91, 0x11, 0xaa, 0xad, 0x60, 0x1d,
	0xba, 0xce, 0xb1, 0x27, 0x18, 0x5c, 0x59, 0x86, 0xe9, 0x66, 0x52, 0x58,
	0xbe, 0xe9, 0x76, 0xac, 0x59, 0xe4, 0xe5, 0x5b, 0x05, 0x08, 0xf9, 0xc7,
	0xda, 0xad, 0xfc, 0xfb, 0x52, 0x2b, 0x74, 0xcd, 0x1e, 0x5b, 0x20, 0x42,
	0xf9, 0xdd, 0x53, 0x3d, 0xf8, 0x29, 0x64, 0x09, 0x3b, 0x80, 0xcb, 0x2a,
	0x6c, 0xdf, 0xb5, 0x3b, 0xf0, 0xc4, 0xbc, 0x48, 0x27, 0xe6, 0x58, 0x80,
	0x00, 0xed, 0x00, 0x05, 0x00, 0x1c, 0xa6, 0x24, 0xf1, 0x00, 0x00, 0x00,
	0x7e, 0x87, 0x89, 0x8d, 0x02, 0x00, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00,
	0x74, 0x2f, 0xe5, 0xa3, 0xff, 0xff, 0x11, 0x01, 0x6c, 0x5d, 0x00, 0x00,
	0x6f, 0xfd, 0xff, 0xff, 0xa3, 0xb7, 0xff, 0x47, 0x3e, 0x48, 0x15, 0x72,
	0x39, 0x61, 0x51, 0xb8, 0x92, 0x28, 0xe6, 0xa3, 0x86, 0x07, 0xf9, 0xee,
	0xe4, 0x1e, 0x82, 0xd3, 0x2f, 0xc5, 0x3a, 0x3c, 0x01, 0x4b, 0xb1, 0x7e,
	0xc9, 0x8a, 0x8a, 0x4d, 0x2f, 0xa3, 0x0d, 0xd9, 0x7f, 0xa6, 0xe3, 0x8c,
	0x23, 0x11, 0x53, 0xe0, 0x59, 0x18, 0xc5, 0x75, 0x8a, 0xe2, 0x77, 0xf8,
	0xb6, 0x94, 0x7f, 0x0c, 0x6a, 0xc0, 0xde, 0x74, 0x49, 0x64, 0xe2, 0xe9,
	0x5c, 0x53, 0xb2, 0x04, 0xd8, 0xf7, 0x44, 0x0c, 0xab, 0x5f, 0x0d, 0x6d,
	0x46, 0xe9, 0xe5, 0xc3, 0x76, 0x88, 0xb7, 0x96, 0x57, 0xac, 0xb6, 0x4d,
	0xe1, 0x69, 0x1d, 0x6f, 0xfb, 0x4b, 0x88, 0x10, 0x6c, 0x42, 0xcb, 0x88,
	0x3f, 0x5c, 0x00, 0x8f, 0xd0, 0x4e, 0xaf, 0x26, 0x28, 0x94, 0x71, 0x1f,
	0x3d, 0x8f, 0x24, 0xe1, 0x70, 0x9e, 0xa7, 0x23, 0x5f, 0xec, 0x28, 0xcb,
	0x85, 0xd1, 0x95, 0x98, 0x8a, 0x7e, 0x2a, 0x91, 0xf2, 0x27, 0x75, 0xf7,
	0x19, 0xc0, 0x06, 0x98, 0x4d, 0x98, 0xfd, 0xd8, 0xaf, 0xd5, 0x90, 0x0f,
	0xc4, 0x25, 0x53, 0xf8, 0xf5, 0x91, 0x36, 0x31, 0x05, 0xa5, 0xb0, 0xee,
	0x6f, 0xc1, 0x70, 0x4d, 0x47, 0x0c, 0xd1, 0x91, 0x11, 0xaa, 0xad, 0x60,
	0x1d, 0xba, 0xce, 0xb1, 0x27, 0x18, 0x5c, 0x59, 0x86, 0xe9, 0x66, 0x52,
	0x58, 0xbe, 0xe9, 0x76, 0xac, 0x59, 0xe4, 0xe5, 0x5b, 0x05, 0x08, 0xf9,
	0xc7, 0xda, 0xad, 0xfc, 0xfb, 0x52, 0x2b, 0x74, 0xcd, 0x1e, 0x5b, 0x20,
	0x42, 0xf9, 0xdd, 0x53, 0x3d, 0xf8, 0x29, 0x64, 0x09, 0x3b, 0x80, 0xcb,
	0x2a, 0x6c, 0xdf, 0xb5, 0x3b, 0xf0, 0xc4, 0xbd, 0x2e, 0x5f, 0xaa, 0x0f,
	0x3e, 0x4b, 0x66, 0x42, 0x90, 0x13, 0x0e, 0xff, 0x10, 0x93, 0xf8, 0x71,
	0x78, 0x59, 0xf8, 0x0b, 0xcd, 0xff, 0x95, 0x28, 0x46, 0x0f, 0xa9, 0xfc,
	0x7c, 0xde, 0xfb, 0x9a, 0x30, 0x2e, 0x56, 0xc0, 0x8f, 0x85, 0xf3, 0x83,
	0x81, 0xc0, 0x65, 0xc4, 0x25, 0x53, 0xf8, 0xf5, 0x91, 0x36, 0x31, 0x05,
	0xa5, 0xb0, 0xee, 0x6f, 0xc1, 0x70, 0x4d, 0x47, 0x0c, 0xd1, 0x91, 0x11,
	0xaa, 0xad, 0x60, 0x1d, 0xba, 0xce, 0xb1, 0x27, 0x18, 0x5c, 0x59, 0x86,
	0xe9, 0x66, 0x52, 0x58, 0xbe, 0xe9, 0x76, 0xac, 0x59, 0xe4, 0xe5, 0x5b,
	0x05, 0x08, 0xf9, 0xc7, 0xda, 0xad, 0xfc, 0xfb, 0x52, 0x2b, 0x74, 0xcd,
	0x1e, 0x5b, 0x20, 0x42, 0xf9, 0xdd, 0x53, 0x3d, 0xf8, 0x29, 0x64, 0x09,
	0x3b, 0x80, 0xcb, 0x2a, 0x6c, 0xdf, 0xb5, 0x3b, 0xf0, 0xc4, 0xbc, 0x48,
	0x27, 0xe6, 0x58, 0x80, 0x00, 0xed, 0x00, 0x05, 0x00, 0x1c, 0xa6, 0x24,
	0xf1, 0x00, 0x00, 0x00, 0x7e, 0x87, 0x89, 0x8d, 0x02, 0x00, 0x21, 0x01,
	0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3, 0xe0, 0x04, 0xaf, 0x00,
	0x1a, 0x5d, 0x00, 0x2a, 0x10, 0x45, 0x51, 0x10, 0x98, 0x54, 0xfe, 0x62,
	0x65, 0xb1, 0x0a, 0xcc, 0x64, 0xea, 0x1b, 0xd1, 0x87, 0xbe, 0x13, 0x1a,
	0x5c, 0xec, 0xad, 0x5f, 0x00, 0x00, 0x00, 0x00, 0x49, 0x7a, 0xd4, 0x9a,
	0x00, 0x03, 0x8f, 0x03, 0x80, 0x80, 0x80, 0x01, 0x8f, 0x03, 0x80, 0x80,
	0x80, 0x01, 0x32, 0xb0, 0x09, 0x00, 0x00, 0x00, 0xe9, 0xdf, 0x42, 0x31,
	0x86, 0x00, 0x08, 0x96, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a
	};
	struct he_w w = { 0 };
	struct kof_scan_option o = opt_cap1m();
	struct run r;
	int bad = 0;

	he_put(&w, xz, sizeof xz);
	if (scan_guarded(&w, &o, "cut.xz", &r))
		return 9;
	printf("  cut.xz -> objects %llu broken %llu limit_hits %llu\n", (unsigned long long)r.t.objects,
	       (unsigned long long)r.t.broken, (unsigned long long)r.limit_hits);
	NEED(r.t.objects == 4, "root and three blocks, got %llu objects", (unsigned long long)r.t.objects);
	NEED(os_n == 4 && !os[0].broken, "the archive says it stopped (broken %u)", os_n ? os[0].broken : 0u);
	NEED(os_n == 4 && os[1].broken == KOF_BROKEN_LIMIT && os[2].broken == KOF_BROKEN_LIMIT && !os[3].broken,
	     "the two cut blocks say Limit themselves and the last does not (%u %u %u)", os_n > 1 ? os[1].broken : 0u,
	     os_n > 2 ? os[2].broken : 0u, os_n > 3 ? os[3].broken : 0u);
	NEED(os_n == 4 && os[3].len == 1200u, "the small block is whole (%llu bytes)", os_n > 3 ? (unsigned long long)os[3].len : 0ull);
	he_free(&w);
	return bad;
}

/*
 * What still ends the walk: the TREE's budget. 200 members each cut at 1 MiB would be 200
 * MiB; the produced-bytes budget (64 MiB) stops the walk, the archive says Limit, and no
 * more than the budget is produced. Both halves asserted: a cut member does not stop the
 * walk, and a tree that has spent its budget does.
 */
static int kase_cut_budget(void)
{
	struct he_w big = { 0 }, z = { 0 };
	struct zent *e = calloc(200, sizeof *e);
	struct kof_scan_option o = opt_cap1m();
	struct run r;
	static char nm[200][8];
	unsigned i;
	int bad = 0;

	if (!e)
		return 9;
	he_deflate_run(&big, 'A', 10000);
	for (i = 0; i < 200; i++) {
		snprintf(nm[i], sizeof nm[i], "m%u", i);
		e[i].name = nm[i];
		e[i].method = 8;
		e[i].data = big.p;
		e[i].clen = (uint32_t)big.n;
		e[i].usize = (uint32_t)(big.n * 8u);
	}
	zip_ex(&z, e, 200);
	if (scan_guarded(&z, &o, "cutmany.zip", &r))
		return 9;
	printf("  cutmany.zip %zu bytes -> objects %llu child_bytes %llu broken %llu (limit %llu)\n", z.n,
	       (unsigned long long)r.t.objects, (unsigned long long)r.t.child_bytes, (unsigned long long)r.t.broken,
	       (unsigned long long)r.t.broken_limit);
	NEED(r.t.child_bytes <= o.max_produced_bytes, "produced %llu bytes past the budget", (unsigned long long)r.t.child_bytes);
	NEED(r.t.objects > 20, "a cut member ended the walk (%llu objects)", (unsigned long long)r.t.objects);
	NEED(r.t.objects < 200, "the budget did not stop the walk (%llu objects)", (unsigned long long)r.t.objects);
	NEED(os_n && os[0].broken == KOF_BROKEN_LIMIT, "the archive that ran out of budget does not say so (broken %u)",
	     os_n ? os[0].broken : 0u);
	free(e);
	he_free(&big);
	he_free(&z);
	return bad;
}

/*
 * THE WINDOW ALLOWANCE refuses a bomb and nothing else. Stored members share bytes with
 * nothing in a well-formed archive, but real ones list a member twice (a tool that appends
 * and does not replace) and an archive built by a script may list it four times: the sum
 * of the windows is then four times the archive and every one is a real member. It was
 * refused after the second (twice the archive, in zip.c).
 */
static int kase_window_duplicates(void)
{
	static uint8_t body[5][100000];
	struct he_w z = { 0 };
	struct zent e[20];
	struct kof_scan_option o = opt_small();
	struct run r;
	static char nm[20][8];
	unsigned i;
	int bad = 0;

	memset(e, 0, sizeof e);
	for (i = 0; i < 5; i++)
		memset(body[i], 'a' + (int)i, sizeof body[i]);
	for (i = 0; i < 20; i++) {
		snprintf(nm[i], sizeof nm[i], "d%u", i);
		e[i].name = nm[i];
		e[i].data = body[i % 5];
		e[i].clen = e[i].usize = sizeof body[0];
		e[i].share = i >= 5 ? (int)(i % 5) + 1 : 0;      /* 15 records point at the first five */
	}
	zip_ex(&z, e, 20);
	if (scan_guarded(&z, &o, "dups.zip", &r))
		return 9;
	printf("  dups.zip %zu bytes, 20 records over 5 blobs -> objects %llu broken %llu\n", z.n,
	       (unsigned long long)r.t.objects, (unsigned long long)r.t.broken);
	NEED(r.t.objects == 21 && r.t.broken == 0,
	     "records that share a blob are real members: %llu objects, %llu broken", (unsigned long long)r.t.objects,
	     (unsigned long long)r.t.broken);
	he_free(&z);
	return bad;
}

/* ---- the runner ----------------------------------------------------------------------------------- */

static const struct kase cases[] = {
	{ "zip bomb (200MB from 1.2MB)", kase_bomb_zip },
	{ "gzip bomb", kase_bomb_gzip },
	{ "overlapping zip bomb", kase_bomb_overlap },
	{ "huge size claims", kase_claims },
	{ "zip64 sizes at 2^63/2^64", kase_zip64 },
	{ "hostile member names", kase_names },
	{ "names that only contain dots", kase_slip_dots },
	{ "1000 duplicate names", kase_duplicates },
	{ "nested 100 deep", kase_nest_stored },
	{ "max_object_depth honoured", kase_nest_limit },
	{ "nested long names", kase_nest_names },
	{ "names kept whole to their standard's width", kase_long_names },
	{ "a name past its standard is invalid", kase_name_invalid },
	{ "20000 gzip members", kase_gzip_members },
	{ "gzip members, trailers and junk", kase_gzip_concat },
	{ "gzip members that each expand", kase_gzip_member_bomb },
	{ "100000 tar members", kase_tar_many },
	{ "65536 fake end records", kase_fake_eocd },
	{ "central directory count 65535", kase_cd_count },
	{ "self referencing offsets", kase_self_reference },
	{ "compound file cycles", kase_ole_cycles },
	{ "pdf loops", kase_pdf_loops },
	{ "cabinet cycles", kase_cab_cycles },
	{ "an entry past its own bound is cut, the walk goes on", kase_cut_zip, NULL, NULL },
	{ "the same, one archive deep", kase_cut_nested, NULL, NULL },
	{ "a gzip member past the object cap", kase_cut_gzip, NULL, NULL },
	{ "a buffered coding (xz) past the object cap", kase_cut_xz, NULL, NULL },
	{ "cut members still end at the tree's budget", kase_cut_budget, NULL, NULL },
	{ "records that share a blob are not a window bomb", kase_window_duplicates, NULL, NULL }
};

int main(void)
{
	unsigned i;
	struct stat sb;

	if (stat(HE_DB, &sb) != 0) {
		printf("hostile_engine_archives: no database - nothing tested\n");
		return 0;
	}
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		struct he_status st = he_child(run_kase, (void *)(uintptr_t)&cases[i], 40);

		printf("%s: %s\n", cases[i].name, he_how(st));
		CK(he_ok(st), "%s: %s", cases[i].name, he_how(st));
	}
	printf("hostile_engine_archives: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
