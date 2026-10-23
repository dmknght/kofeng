/*
 * api_engine_scan.c - the public API of kofeng.h, one contract at a time:
 * keng_open/close, kdb_* introspection, keng_version, kscan_new/free/stats,
 * kscan_bytes, kscan_path and the options and callbacks that steer them.
 *
 * Two databases are used and each for what it is good at. The engine's own
 * unpackers (build/release/databases) open containers, so a zip or gzip yields
 * children there. The test signature set (build/test/databases-sigs) carries a
 * detector that fires on a literal in any object - "GCC: (GNU)" in 64 bytes or
 * more - which is the smallest thing a scan can be asked to find.
 *
 * What is asserted is what a host depends on: the return value says how many
 * objects were scanned or which KOF_ERR_* it was, a NULL or empty argument is
 * refused rather than dereferenced, the callback sees the right name, bytes and
 * length in the right order, a cache hook is told what the header says it is
 * told, and every counter in kof_stats moves for the thing it counts.
 *
 * Scratch files go under build/test and are removed.
 */

#include "hostile_engine.h"
#include "known_miss.h"
#include "notes.h"
#pragma push_macro("CK")
#undef CK
#include "caps_fix.h"
#undef CK
#pragma pop_macro("CK")

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DB_REL  "build/release/databases"
#define DB_SIGS "build/test/databases-sigs"
#define MARK    "GCC: (GNU)"

static kof_engine *eng_rel, *eng_sigs;
static char tmp[300];

static void mkobj(uint8_t *b, size_t n, int marked)
{
	memset(b, 'A', n);
	if (marked && n >= 64)
		memcpy(b + 10, MARK, strlen(MARK));
}

static int put_file(const char *leaf, const void *p, size_t n)
{
	char path[600];
	FILE *f;

	snprintf(path, sizeof path, "%s/%s", tmp, leaf);
	f = fopen(path, "wb");
	if (!f)
		return 0;
	if (n)
		fwrite(p, 1, n, f);
	fclose(f);
	return 1;
}

static void tpath(char *out, size_t cap, const char *leaf)
{
	snprintf(out, cap, "%s/%s", tmp, leaf);
}

/* ---- engine handles ------------------------------------------------------------- */

static void t_open(void)
{
	kof_engine *a, *b, *c;
	struct kof_db_version v;
	char empty[600];

	CK(keng_open(NULL) == NULL, "a NULL path is refused");
	CK(keng_open("") == NULL, "an empty path is refused");
	CK(keng_open("build/test/definitely-not-a-database") == NULL, "a missing path");
	CK(keng_open("Makefile") == NULL, "a file that is not a pack");
	tpath(empty, sizeof empty, "emptydb");
	mkdir(empty, 0700);
	CK(keng_open(empty) == NULL, "a directory with no packs");
	keng_close(NULL);
	CK(1, "closing NULL is a no-op");

	a = keng_open(DB_REL);
	b = keng_open(DB_REL);
	c = keng_open(DB_SIGS);
	CK(a && b && c, "three opens, two of them of the same database");
	if (!a || !b || !c) {
		keng_close(a);
		keng_close(b);
		keng_close(c);
		return;
	}
	CK(a != b, "each open is its own engine");
	CK(kdb_records(a) == kdb_records(b) && kdb_unpackers(a) == kdb_unpackers(b) &&
	   kdb_diagnoses(a) == kdb_diagnoses(b),
	   "two opens of one database count the same");
	CK(kdb_unpackers(a) > 0 && kdb_unpackers(c) > 0, "unpackers are counted");
	CK(kdb_records(c) > 0, "the test set holds detections");
	CK(kdb_stamp(a) != 0 && kdb_stamp(a) == kdb_stamp(b), "the stamp is stable across opens");
	CK(kdb_stamp(a) != kdb_stamp(c), "and differs between databases");
	CK(kdb_stamp(NULL) == 0, "no engine, no stamp");
	CK(kdb_records(NULL) == 0 && kdb_unpackers(NULL) == 0 &&
	   kdb_diagnoses(NULL) == 0 && kdb_diag_full(NULL) == 0 && kdb_diag_collisions(NULL) == 0 &&
	   kdb_diag_refused(NULL) == 0 && kdb_diag_packs_refused(NULL) == 0, "a NULL engine counts zero everywhere");
	CK(kdb_diag_full(a) == 0 && kdb_diag_collisions(a) == 0 && kdb_diag_refused(a) == 0 &&
	   kdb_diag_packs_refused(a) == 0, "a healthy database refuses nothing");
	CK(kdb_diag_full(c) == 0 && kdb_diag_collisions(c) == 0 && kdb_diag_refused(c) == 0 &&
	   kdb_diag_packs_refused(c) == 0, "and neither does the test set");

	memset(&v, 0xaa, sizeof v);
	CK(kdb_version(a, &v) == 1 && v.major != 0xaaaa && v.build != 0, "kdb_version fills in");
	CK(kdb_version(a, NULL) == 0, "no output structure");
	CK(kdb_version(NULL, &v) == 0 && v.major == 0 && v.minor == 0 && v.build == 0 && v.machine == 0,
	   "no engine: zero-filled and 0");

	{
		uint64_t bytes = 123;
		uint32_t chain = 123;
		int rc = kmatch_tables(a, &bytes, &chain);

		CK(rc == 0 || rc == -1, "kmatch_tables answers 0 or -1");
		if (rc == 0)
			CK(bytes > 0, "tables occupy memory");
		else
			CK(bytes == 0 && chain == 0, "no tables: zero-filled");
		CK(kmatch_tables(a, NULL, NULL) == rc, "both outputs are optional");
		bytes = 7;
		chain = 7;
		CK(kmatch_tables(NULL, &bytes, &chain) == -1 && bytes == 0 && chain == 0,
		   "a NULL engine is -1 and zero-filled");
	}
	keng_close(a);
	CK(kdb_unpackers(b) > 0, "closing one engine leaves the other");
	keng_close(b);
	keng_close(c);
	rmdir(empty);
}

static void t_version(void)
{
	struct kof_version v;

	memset(&v, 0xaa, sizeof v);
	keng_version(&v);
	/* The build stamp is the UTC hour the LIBRARY was compiled in; this file is compiled
	 * in the hour it is built, so the two differ whenever a build crosses an hour (the
	 * archive is not rebuilt for a test). What can be checked is that it is a stamp. */
	CK(v.major == KOFENG_MAJOR && v.minor == KOFENG_MINOR && v.build >= 2026010100u && v.build <= KOFENG_BUILD + 100000u,
	   "keng_version reports its major and minor and a YYYYMMDDHH build stamp");
	keng_version(NULL);
	CK(1, "NULL out is ignored");
}

static void t_names(void)
{
	uint32_t r;
	const char *seen[KOF_BROKEN_COUNT];

	for (r = 0; r < KOF_BROKEN_COUNT; r++) {
		seen[r] = kverdict_broken_name(r);
		CK(seen[r] && seen[r][0], "reason %u has a name", r);
	}
	CK(strcmp(kverdict_broken_name(KOF_BROKEN_NONE), "Unknown") == 0,
	   "none is not a reason: it reads Unknown");
	for (r = 1; r < KOF_BROKEN_COUNT; r++) {
		uint32_t q;

		for (q = r + 1; q < KOF_BROKEN_COUNT; q++)
			CK(strcmp(seen[r], seen[q]) != 0, "reasons %u and %u read differently", r, q);
	}
	CK(strcmp(kverdict_broken_name(KOF_BROKEN_COUNT), "Unknown") == 0 &&
	   strcmp(kverdict_broken_name(0xffffffffu), "Unknown") == 0, "a value from outside is Unknown");
	CK(kverdict_fact_id("version") == kverdict_fact_id("UPX.ELF.version"), "fact id by field");
}

/* ---- the scanner ----------------------------------------------------------------- */

static void t_scanner(void)
{
	kof_scanner *sc, *sc2;
	const struct kof_stats *st;
	static const struct kof_stats zero;

	CK(kscan_new(NULL) == NULL, "no engine, no scanner");
	kscan_free(NULL);
	CK(1, "freeing NULL is a no-op");
	CK(kscan_stats(NULL) == NULL, "stats of NULL");
	kscan_on_debug(NULL, NULL, NULL);
	CK(1, "debug hook on NULL is ignored");
	sc = kscan_new(eng_rel);
	sc2 = kscan_new(eng_rel);
	CK(sc && sc2 && sc != sc2, "two scanners from one engine");
	if (!sc || !sc2) {
		kscan_free(sc);
		kscan_free(sc2);
		return;
	}
	st = kscan_stats(sc);
	CK(st && memcmp(st, &zero, sizeof zero) == 0, "a new scanner has zero counters");
	CK(kscan_stats(sc) == kscan_stats(sc), "the stats pointer is stable");
	kscan_on_debug(sc, NULL, NULL);
	kscan_free(sc);
	CK(kscan_stats(sc2) && kscan_stats(sc2)->objects == 0, "freeing one leaves the other");
	kscan_free(sc2);
}

/* ---- kscan_bytes ------------------------------------------------------------------ */

/* What the test modules said while an object was scanned - see notes.h. */
static struct note_list pend;

struct rec {
	char     name[8][300];
	uint64_t len[8];
	const void *ptr[8];
	uint32_t n_find[8];
	uint32_t examined[8];
	unsigned n;
	int      ret;           /* what the callback returns */
	int      calls_after_abort;
};

static int on_rec(const char *name, const void *bytes, uint64_t len,
		  const struct kof_result *res, void *user)
{
	struct rec *r = (struct rec *)user;
	struct note_list got;

	notes_take(&pend, &got);
	if (r->n < 8) {
		snprintf(r->name[r->n], sizeof r->name[0], "%s", name ? name : "(null)");
		r->len[r->n] = len;
		r->ptr[r->n] = bytes;
		r->n_find[r->n] = res ? got.n : 99u;
		r->examined[r->n] = res ? res->examined : 99u;
	}
	r->n++;
	if (r->ret)
		r->calls_after_abort++;
	return r->ret;
}

static void t_bytes(void)
{
	kof_scanner *sc = kscan_new(eng_sigs);
	static uint8_t buf[300];
	struct kof_scan_option o;
	struct rec r;
	int rc;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	kscan_on_debug(sc, notes_on, &pend);
	mkobj(buf, sizeof buf, 1);
	memset(&o, 0, sizeof o);

	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_bytes(sc, buf, sizeof buf, "obj.bin", &o, on_rec, &r);
	CK(rc == 1 && r.n == 1, "one object scanned, one callback");
	CK(strcmp(r.name[0], "obj.bin") == 0, "the caller's name is what is reported");
	CK(r.ptr[0] == buf && r.len[0] == sizeof buf, "the bytes are the caller's own, borrowed, with their length");
	CK(r.n_find[0] == 1 && r.examined[0] > 0, "the marker is found and modules ran");

	mkobj(buf, sizeof buf, 0);
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_bytes(sc, buf, sizeof buf, "clean.bin", &o, on_rec, &r);
	CK(rc == 1 && r.n == 1 && r.n_find[0] == 0, "an object with no findings is still reported");

	CK(kscan_bytes(sc, buf, 0, "x", &o, on_rec, &r) == KOF_ERR_ARG, "zero length is KOF_ERR_ARG");
	CK(kscan_bytes(sc, NULL, 10, "x", &o, on_rec, &r) == KOF_ERR_ARG, "NULL bytes is KOF_ERR_ARG");
	CK(kscan_bytes(NULL, buf, sizeof buf, "x", &o, on_rec, &r) == KOF_ERR_ARG, "NULL scanner is KOF_ERR_ARG");

	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_bytes(sc, buf, sizeof buf, NULL, NULL, on_rec, &r);
	CK(rc == 1 && r.n == 1 && r.name[0][0] == 0, "NULL name reports an empty name, NULL option is the zero option");
	CK(kscan_bytes(sc, buf, sizeof buf, "x", &o, NULL, NULL) == 1, "a NULL callback still scans and counts");

	/* A single byte, and an object just under the smallest the detector looks at. */
	CK(kscan_bytes(sc, buf, 1, "one", &o, NULL, NULL) == 1, "a one byte object");
	CK(kscan_bytes(sc, buf, 63, "short", &o, NULL, NULL) == 1, "63 bytes");

	/* The scanner is reusable after the refusals above. */
	mkobj(buf, sizeof buf, 1);
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	CK(kscan_bytes(sc, buf, sizeof buf, "again", &o, on_rec, &r) == 1 && r.n_find[0] == 1,
	   "the scanner works after refused calls");
	kscan_free(sc);
}

static void t_callback_abort(void)
{
	kof_scanner *sc = kscan_new(eng_rel);
	struct he_w z = { 0 };
	static uint8_t body[600];
	struct he_member m[3];
	struct kof_scan_option o = he_opt();
	struct rec r;
	int rc;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	mkobj(body, sizeof body, 0);
	m[0].name = "a"; m[0].data = body; m[0].len = 100;
	m[1].name = "b"; m[1].data = body; m[1].len = 200;
	m[2].name = "c"; m[2].data = body; m[2].len = 300;
	he_zip(&z, m, 3);

	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_bytes(sc, z.p, z.n, "z.zip", &o, on_rec, &r);
	CK(rc == 4 && r.n == 4, "a three member zip is four objects (rc %d, callbacks %u)", rc, r.n);
	CK(strcmp(r.name[0], "z.zip") == 0, "the container is reported before its members");
	CK(strncmp(r.name[1], "z.zip//0:", 9) == 0 && strstr(r.name[1], "a") &&
	   strncmp(r.name[2], "z.zip//1:", 9) == 0 && strncmp(r.name[3], "z.zip//2:", 9) == 0,
	   "members follow in order, named parent//index:label (%s)", r.name[1]);
	CK(r.len[1] == 100 && r.len[2] == 200 && r.len[3] == 300, "member lengths are the entries' sizes");
	CK(r.ptr[1] != NULL && r.ptr[1] != r.ptr[2], "each member has its own bytes");

	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	r.ret = 1;
	rc = kscan_bytes(sc, z.p, z.n, "z.zip", &o, on_rec, &r);
	CK(r.n == 1 && r.calls_after_abort == 1, "a non-zero return abandons the walk: no callback after it");
	CK(rc == 1, "the object already scanned is still counted (rc %d)", rc);

	/* heur_off: look, do not open. */
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	o.heur_off = 1;
	rc = kscan_bytes(sc, z.p, z.n, "z.zip", &o, on_rec, &r);
	CK(rc == 1 && r.n == 1, "heur_off scans the container and does not descend (rc %d)", rc);
	o.heur_off = 0;

	/* max_object_depth 1: the members, not their members. */
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	o.max_object_depth = 1;
	rc = kscan_bytes(sc, z.p, z.n, "z.zip", &o, on_rec, &r);
	CK(rc == 4, "depth 1 still opens the members of the zip (rc %d)", rc);
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	o.max_object_depth = 0;
	{
		/* children cap */
		o.max_children = 2;
		rc = kscan_bytes(sc, z.p, z.n, "z.zip", &o, on_rec, &r);
		CK(rc <= 3, "max_children 2 opens at most two members (rc %d)", rc);
		o.max_children = 0;
	}
	he_free(&z);
	kscan_free(sc);
}

/* ---- kscan_path -------------------------------------------------------------------- */

static void t_path(void)
{
	kof_scanner *sc = kscan_new(eng_sigs);
	if (sc)
		kscan_on_debug(sc, notes_on, &pend);
	static uint8_t buf[300];
	struct kof_scan_option o;
	struct rec r;
	char p[600], d[600], sub[320], lnk[600];
	const struct kof_stats *st;
	uint64_t before;
	int rc;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	memset(&o, 0, sizeof o);
	st = kscan_stats(sc);
	mkobj(buf, sizeof buf, 1);
	put_file("one.bin", buf, sizeof buf);
	tpath(p, sizeof p, "one.bin");

	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_path(sc, p, &o, on_rec, &r);
	CK(rc == 1 && r.n == 1 && strcmp(r.name[0], p) == 0 && r.len[0] == sizeof buf && r.n_find[0] == 1,
	   "a file is one object under its own path");
	CK(st->objects == 1 && st->object_bytes == sizeof buf, "stats: objects and bytes");

	rc = kscan_path(sc, p, NULL, on_rec, &r);
	CK(rc == 1, "a NULL option is the zero option");
	CK(kscan_path(NULL, p, &o, on_rec, &r) == KOF_ERR_ARG, "NULL scanner");
	CK(kscan_path(sc, NULL, &o, on_rec, &r) == KOF_ERR_ARG, "NULL path");
	CK(kscan_path(sc, "", &o, on_rec, &r) == KOF_ERR_OPEN, "empty path");
	CK(kscan_path(sc, "build/test/definitely-missing", &o, on_rec, &r) == KOF_ERR_OPEN, "missing path");
	CK(kscan_path(sc, p, &o, NULL, NULL) == 1, "a NULL callback");

	/* A directory is refused unless the caller asked to descend: zero is conservative. */
	CK(kscan_path(sc, tmp, &o, on_rec, &r) == KOF_ERR_OPEN, "a directory without recurse_dirs is refused");

	put_file("empty.bin", "", 0);
	tpath(d, sizeof d, "empty.bin");
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	CK(kscan_path(sc, d, &o, on_rec, &r) == 1 && r.len[0] == 0 && r.n_find[0] == 0,
	   "a zero length file is one empty object");

	before = st->unreadable;
	CK(kscan_path(sc, "/dev/null", &o, on_rec, &r) == KOF_ERR_OPEN, "a device is not an object");
	CK(st->unreadable == before + 1, "and it is counted as unreadable");

	/* A tree. */
	tpath(sub, sizeof sub, "tree");
	mkdir(sub, 0700);
	snprintf(d, sizeof d, "%s/a", sub);
	mkdir(d, 0700);
	snprintf(d, sizeof d, "%s/a/b", sub);
	mkdir(d, 0700);
	snprintf(d, sizeof d, "%s/top.bin", sub);
	{
		FILE *f = fopen(d, "wb");

		if (f) {
			fwrite(buf, 1, sizeof buf, f);
			fclose(f);
		}
	}
	snprintf(d, sizeof d, "%s/a/mid.bin", sub);
	{
		FILE *f = fopen(d, "wb");

		if (f) {
			fwrite(buf, 1, 100, f);
			fclose(f);
		}
	}
	snprintf(d, sizeof d, "%s/a/b/deep.bin", sub);
	{
		FILE *f = fopen(d, "wb");

		if (f) {
			fwrite(buf, 1, 50, f);
			fclose(f);
		}
	}
	o.recurse_dirs = 1;
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_path(sc, sub, &o, on_rec, &r);
	CK(rc == 3 && r.n == 3, "a tree of three files is three objects (rc %d)", rc);
	o.max_depth = 1;
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_path(sc, sub, &o, on_rec, &r);
	CK(rc == 2, "max_depth 1 reaches a/ and not a/b/ (rc %d)", rc);
	o.max_depth = 0;

	/* Trailing and doubled separators are squashed; the names are single-slashed. */
	snprintf(d, sizeof d, "%s//", sub);
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_path(sc, d, &o, on_rec, &r);
	CK(rc == 3, "a directory given with a trailing // (rc %d)", rc);
	{
		unsigned i;
		int dbl = 0;

		for (i = 0; i < r.n && i < 8; i++)
			if (strstr(r.name[i] + 1, "//"))
				dbl = 1;
		CK(!dbl, "no object name carries '//' (it is the object separator)");
	}

	/* A symlink to a directory and to a file. */
	snprintf(lnk, sizeof lnk, "%s/link", sub);
	snprintf(d, sizeof d, "%s/a", sub);
	if (symlink("a", lnk) == 0) {
		memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
		rc = kscan_path(sc, sub, &o, on_rec, &r);
		CK(rc == 3, "a symlink to a directory is not followed (rc %d)", rc);
		/* follow_symlinks is deprecated and ignored: the engine never follows a link. */
		o.follow_symlinks = 1;
		memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
		rc = kscan_path(sc, sub, &o, on_rec, &r);
		CK(rc == 3, "and it is not followed when asked either (rc %d)", rc);
		o.follow_symlinks = 0;
		unlink(lnk);
	}
	kscan_free(sc);
}

/* ---- the cache hooks ----------------------------------------------------------------- */

struct cache {
	unsigned seen, keep, drop;
	char last_seen[300], last_keep[300], last_drop[300];
	int answer;   /* what seen returns */
};

static int c_seen(void *u, const char *path)
{
	struct cache *c = (struct cache *)u;

	c->seen++;
	snprintf(c->last_seen, sizeof c->last_seen, "%s", path);
	return c->answer;
}

static void c_keep(void *u, const char *path)
{
	struct cache *c = (struct cache *)u;

	c->keep++;
	snprintf(c->last_keep, sizeof c->last_keep, "%s", path);
}

static void c_drop(void *u, const char *path)
{
	struct cache *c = (struct cache *)u;

	c->drop++;
	snprintf(c->last_drop, sizeof c->last_drop, "%s", path);
}

static int stop_flag;
static unsigned stop_calls;

static int stop_after(void *u)
{
	unsigned n = *(unsigned *)u;

	stop_calls++;
	return stop_calls > n;
}

static void t_cache(void)
{
	kof_scanner *sc = kscan_new(eng_sigs);
	static uint8_t buf[300], kmod[4096];
	struct kof_scan_option o;
	struct cache c;
	struct rec r;
	char clean[600], dirty[600];
	int rc;
	uint64_t cached;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	mkobj(buf, sizeof buf, 0);
	put_file("clean.bin", buf, sizeof buf);
	/* a file with a verdict: a kernel module the fixture diagnose kmod_give_root names */
	put_file("dirty.bin", kmod, (size_t)cf_kmod(kmod, sizeof kmod, 0, 0));
	tpath(clean, sizeof clean, "clean.bin");
	tpath(dirty, sizeof dirty, "dirty.bin");
	memset(&o, 0, sizeof o);
	o.cache_seen = c_seen;
	o.cache_keep = c_keep;
	o.cache_drop = c_drop;
	o.cache_user = &c;

	memset(&c, 0, sizeof c);
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	rc = kscan_path(sc, clean, &o, on_rec, &r);
	CK(rc == 1 && c.seen == 1 && c.keep == 1 && c.drop == 0 && strcmp(c.last_keep, clean) == 0,
	   "a clean file: asked, scanned, then kept (rc %d)", rc);

	memset(&c, 0, sizeof c);
	rc = kscan_path(sc, dirty, &o, on_rec, &r);
	CK(rc == 1 && c.seen == 1 && c.keep == 0 && c.drop == 1 && strcmp(c.last_drop, dirty) == 0,
	   "a file with a verdict is never kept and is dropped");

	memset(&c, 0, sizeof c);
	c.answer = 1;
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	cached = kscan_stats(sc)->cached;
	rc = kscan_path(sc, clean, &o, on_rec, &r);
	CK(r.n == 0 && c.keep == 0 && c.drop == 0, "a file the cache already answered is not opened or reported");
	CK(kscan_stats(sc)->cached == cached + 1, "and is counted in stats.cached");
	CK(rc == KOF_ERR_OPEN, "with no object scanned the answer is KOF_ERR_OPEN (rc %d)", rc);

	/* Hooks are optional one by one. */
	memset(&c, 0, sizeof c);
	o.cache_keep = NULL;
	o.cache_drop = NULL;
	CK(kscan_path(sc, clean, &o, NULL, NULL) == 1 && c.keep == 0, "keep and drop may be NULL");
	o.cache_seen = NULL;
	o.cache_keep = c_keep;
	o.cache_drop = c_drop;
	memset(&c, 0, sizeof c);
	CK(kscan_path(sc, clean, &o, NULL, NULL) == 1 && c.keep == 1, "seen may be NULL");

	/* kscan_bytes has no identity to cache under: the hooks are not called. */
	memset(&c, 0, sizeof c);
	o.cache_seen = c_seen;
	CK(kscan_bytes(sc, buf, sizeof buf, "x", &o, NULL, NULL) == 1 &&
	   c.seen == 0 && c.keep == 0 && c.drop == 0, "kscan_bytes never consults the cache");

	/* should_stop: asked before the file is opened, and a stopped scan is never kept. */
	{
		unsigned limit = 0;

		memset(&o, 0, sizeof o);
		memset(&c, 0, sizeof c);
		o.cache_keep = c_keep;
		o.cache_drop = c_drop;
		o.cache_user = &c;
		o.should_stop = stop_after;
		o.stop_user = &limit;
		stop_calls = 0;
		stop_flag = 0;
		rc = kscan_path(sc, clean, &o, NULL, NULL);
		CK(rc == KOF_ERR_OPEN && c.keep == 0 && stop_calls >= 1,
		   "a host that has said stop pays for no further file (rc %d)", rc);

		limit = 1;
		stop_calls = 0;
		memset(&c, 0, sizeof c);
		rc = kscan_path(sc, clean, &o, NULL, NULL);
		CK(c.keep == 0, "a stop that arrives during the scan is not remembered as clean (rc %d, calls %u)",
		   rc, stop_calls);
		limit = 1000000;
		stop_calls = 0;
		memset(&c, 0, sizeof c);
		rc = kscan_path(sc, clean, &o, NULL, NULL);
		CK(rc == 1 && c.keep == 1 && stop_calls > 0, "should_stop is asked inside an object, and a no changes nothing");
	}
	kscan_free(sc);
}

/* ---- events and the verdict callback -------------------------------------------------- */

struct evrec {
	unsigned n;
	char object[300], verdict[300];
};

static void on_event(const char *object, const char *verdict, const struct kof_finding *f, void *u)
{
	struct evrec *e = (struct evrec *)u;

	e->n++;
	snprintf(e->object, sizeof e->object, "%s", object);
	snprintf(e->verdict, sizeof e->verdict, "%s", verdict);
	(void)f;
}

static void t_events(void)
{
	kof_scanner *sc = kscan_new(eng_sigs);
	static uint8_t buf[300];
	struct kof_scan_option o;
	struct evrec e;
	struct rec r;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	mkobj(buf, sizeof buf, 1);
	memset(&o, 0, sizeof o);
	memset(&e, 0, sizeof e);
	memset(&r, 0, sizeof r);
	memset(&pend, 0, sizeof pend);
	o.on_event_detected = on_event;
	o.event_user = &e;
	CK(kscan_bytes(sc, buf, sizeof buf, "ev.bin", &o, on_rec, &r) == 1, "scan");
	CK(r.n == 1, "the object callback fires");
	/* This detector declares no disease, so its finding is evidence and makes no verdict:
	 * the event channel delivers verdicts only (tests/unit/verdict_delivery.c has the
	 * object that does carry a disease, and the event it makes). */
	CK(e.n == 0, "a finding that is only evidence is not delivered as an event");
	kscan_free(sc);
}

/* ---- stats -------------------------------------------------------------------------------- */

static void t_stats(void)
{
	kof_scanner *sc = kscan_new(eng_rel);
	static uint8_t buf[500];
	struct kof_scan_option o = he_opt();
	const struct kof_stats *st;
	struct he_tally t;
	struct he_w z = { 0 };
	struct he_member m[1];
	uint64_t o0, b0;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	st = kscan_stats(sc);
	mkobj(buf, sizeof buf, 0);
	he_scan(sc, buf, sizeof buf, "a", &o, &t);
	CK(st->objects == 1 && st->object_bytes == sizeof buf, "objects and object_bytes");
	CK(st->considered >= st->ran, "a module is considered before it can run");
	o0 = st->objects;
	b0 = st->object_bytes;
	he_scan(sc, buf, sizeof buf, "b", &o, &t);
	CK(st->objects == o0 + 1 && st->object_bytes == b0 + sizeof buf, "counters accumulate over scans");

	m[0].name = "inner";
	m[0].data = buf;
	m[0].len = sizeof buf;
	he_zip(&z, m, 1);
	o0 = st->objects;
	b0 = st->object_bytes;
	he_scan(sc, z.p, z.n, "c.zip", &o, &t);
	CK(st->objects == o0 + 2, "a produced child is an object in the counters");
	CK(st->object_bytes == b0 + z.n + sizeof buf, "and its bytes");
	he_free(&z);
	kscan_free(sc);
}

/* ---- scanner reuse and several scanners one engine --------------------------------------- */

static void t_reuse(void)
{
	kof_scanner *a = kscan_new(eng_rel), *b = kscan_new(eng_rel);
	static uint8_t buf[400];
	struct kof_scan_option o = he_opt();
	struct he_tally t1, t2;
	unsigned i;
	int rc1, rc2;

	if (!a || !b) {
		CK(0, "scanners");
		kscan_free(a);
		kscan_free(b);
		return;
	}
	mkobj(buf, sizeof buf, 1);
	for (i = 0; i < 50; i++) {
		struct he_w g = { 0 };

		he_gzip(&g, buf, (uint32_t)(sizeof buf - (i % 7)));
		rc1 = he_scan(a, g.p, g.n, "g", &o, &t1);
		rc2 = he_scan(b, g.p, g.n, "g", &o, &t2);
		CK(rc1 == rc2 && t1.objects == t2.objects && t1.bytes == t2.bytes && t1.findings == t2.findings,
		   "two scanners agree on the same input (iteration %u)", i);
		he_free(&g);
	}
	CK(kscan_stats(a)->objects == kscan_stats(b)->objects, "and count the same");
	/* A refused call between two good ones changes nothing. */
	CK(kscan_bytes(a, buf, 0, "x", &o, NULL, NULL) == KOF_ERR_ARG, "refused");
	rc1 = he_scan(a, buf, sizeof buf, "after", &o, &t1);
	rc2 = he_scan(b, buf, sizeof buf, "after", &o, &t2);
	CK(rc1 == rc2 && t1.findings == t2.findings, "the scanner that was refused is unchanged");
	kscan_free(a);
	kscan_free(b);
}

/* ---- the debug hook ------------------------------------------------------------------------- */

static void on_dbg(uint32_t fact, const char *what, uint64_t value, void *user)
{
	unsigned *n = (unsigned *)user;

	(void)fact;
	(void)what;
	(void)value;
	(*n)++;
}

static void t_debug_hook(void)
{
	kof_scanner *sc = kscan_new(eng_rel);
	static uint8_t buf[400];
	struct kof_scan_option o = he_opt();
	struct he_tally t;
	unsigned n = 0;
	struct he_w z = { 0 };
	struct he_member m[1];

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	mkobj(buf, sizeof buf, 0);
	m[0].name = "x";
	m[0].data = buf;
	m[0].len = sizeof buf;
	he_zip(&z, m, 1);
	kscan_on_debug(sc, on_dbg, &n);
	he_scan(sc, z.p, z.n, "d.zip", &o, &t);
	CK(1, "a scan with the hook set completes (it fired %u times: notes are the modules' to give)", n);
	kscan_on_debug(sc, NULL, NULL);
	n = 0;
	he_scan(sc, z.p, z.n, "d.zip", &o, &t);
	CK(n == 0, "a cleared hook is never called");
	he_free(&z);
	kscan_free(sc);
}

int main(void)
{
	struct stat sb;

	if (stat(DB_REL, &sb) != 0 || stat(DB_SIGS, &sb) != 0) {
		printf("api_engine_scan: databases missing (make test-sigs) - nothing tested\n");
		return 0;
	}
	snprintf(tmp, sizeof tmp, "build/test/api_engine_scan_%d", (int)getpid());
	if (mkdir(tmp, 0700) != 0) {
		printf("api_engine_scan: no build/test directory - nothing tested\n");
		return 0;
	}
	eng_rel = keng_open(DB_REL);
	eng_sigs = keng_open(DB_SIGS);
	if (!eng_rel || !eng_sigs) {
		printf("api_engine_scan: databases did not load\n");
		return 1;
	}
	t_open();
	t_version();
	t_names();
	t_scanner();
	t_bytes();
	t_callback_abort();
	t_path();
	t_cache();
	t_events();
	t_stats();
	t_reuse();
	t_debug_hook();
	keng_close(eng_rel);
	keng_close(eng_sigs);
	he_rmtree(tmp);
	printf("api_engine_scan: %u checks, %u failed, %u known-miss\n",
	       he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
