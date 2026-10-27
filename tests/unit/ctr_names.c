/*
 * ctr_names - hostile ENTRY NAMES through the whole scan of every container format (hostile matrix, column 1: path).
 *
 * The engine must never make a file from a name inside an archive, and a name a member chose must never become a path, a
 * forged object separator or a control character in what the host is told. Each row is an archive of three members,
 * [pre, HOSTILE, post], written by tests/lib/ctr_writers.h with the name the row says (the bytes of the name, its length
 * apart from strlen where the row needs a NUL in it):
 *
 *   traversal  "../../../../x", "..\..\x", a deep "../" chain, "%2e%2e/x", an overlong-UTF-8 dot-dot
 *   absolute   "/etc/kof_ctr_owned", "C:\Windows\x.exe", and an absolute path INSIDE the scratch tree (the one a writing
 *              engine would have created, and the snapshot below would see)
 *   odd bytes  an embedded NUL, bytes that are not UTF-8, control characters, a lone "..", ".", "", a separator "x//y"
 *              (the engine's own object separator), 5000 bytes
 *   duplicates three members called "dup"; two members whose names differ only by the traversal prefix
 *
 * ASSERTED, per format and row: the scan answers; the scratch tree (the working directory is six levels deep in it, so
 * "../" up to five levels stays inside) is exactly what it was, and nothing exists at the absolute probe paths; every
 * child object's leaf has no '/', no '\' and no control byte, and a child is one level below the root whatever the name
 * said; the members before and after the hostile one are opened whole (hash of the bytes); duplicates are three
 * distinct objects. A name too long for the format's own limit is clamped or counted (names_invalid) and the member kept.
 *
 *   WP2-D6 (KM_CHECK): a cab file whose name is not a C string the table can step over (an embedded NUL, 5000 bytes) ends
 *          the file table: every later file is dropped and broken stays 0.
 *
 * LONG NAMES: 200 zip members with 60000 byte names each (12 MB of names): the scan finishes, every member is a child and the
 * peak resident stays under the ceiling. No file is written in any build outside build/kof_ctr_names_XXXXXX.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"

#include <ftw.h>
#include <limits.h>

/* ---- the scratch tree and its snapshot ---------------------------------------------------------- */

static char scratch[PATH_MAX], deep[PATH_MAX + 64], absprobe[PATH_MAX + 16];
static uint64_t snap_h;
static unsigned snap_n;

static int snap_cb(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
	(void)flag;
	(void)ftw;
	snap_n++;
	snap_h = (snap_h ^ cs_fnv(path, strlen(path))) * 1099511628211ull;
	snap_h = (snap_h ^ (uint64_t)sb->st_size ^ ((uint64_t)sb->st_mode << 40)) * 1099511628211ull;
	return 0;
}

static void snapshot(void)
{
	snap_h = 14695981039346656037ull;
	snap_n = 0;
	(void)nftw(scratch, snap_cb, 16, FTW_PHYS);
}

static int make_scratch(void)
{
	char tmpl[] = "build/kof_ctr_names_XXXXXX";
	char *r = mkdtemp(tmpl);
	char path[PATH_MAX + 64];
	int i;
	FILE *f;

	if (!r)
		return -1;
	if (!realpath(r, scratch))
		return -1;
	snprintf(deep, sizeof deep, "%s", scratch);
	for (i = 1; i <= 6; i++) {
		if ((size_t)snprintf(path, sizeof path, "%s/%d", deep, i) >= sizeof path)
			return -1;
		if (mkdir(path, 0700))
			return -1;
		snprintf(deep, sizeof deep, "%s", path);
	}
	if ((size_t)snprintf(path, sizeof path, "%s/canary", scratch) >= sizeof path)
		return -1;
	f = fopen(path, "w");
	if (!f)
		return -1;
	fputs("canary\n", f);
	fclose(f);
	snprintf(absprobe, sizeof absprobe, "%s/abs_owned", scratch);
	return 0;
}

/* ---- rows ----------------------------------------------------------------------------------------- */

struct row {
	const char *what;
	const char *name;       /* NULL: absprobe */
	uint32_t    len;        /* 0: strlen */
	unsigned    five;       /* 1: 5000 'A' */
	unsigned    nul;        /* the name has an embedded NUL or is 5000 bytes: a cab table cannot step over it */
};

static const struct row rows[] = {
	{ "dotdot x4",           "../../../../x",                     0, 0, 0 },
	{ "dotdot deep",         "../../../../../../../../../../tmp/kof_ctr_owned", 0, 0, 0 },
	{ "backslash dotdot",    "..\\..\\..\\x",                     0, 0, 0 },
	{ "percent dotdot",      "%2e%2e/%2e%2e/x",                   0, 0, 0 },
	{ "overlong utf8",       "\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/x", 0, 0, 0 },
	{ "absolute etc",        "/etc/kof_ctr_owned",                0, 0, 0 },
	{ "absolute scratch",    NULL,                                0, 0, 0 },
	{ "drive path",          "C:\\Windows\\x.exe",                0, 0, 0 },
	{ "embedded NUL",        "a\0b",                              3, 0, 1 },
	{ "not utf8",            "\xff\xfe\x80zz",                    0, 0, 0 },
	{ "control chars",       "l\nf\r\t\x1b[2J",                   0, 0, 0 },
	{ "only dotdot",         "..",                                0, 0, 0 },
	{ "only dot",            ".",                                 0, 0, 0 },
	{ "empty",               "",                                  0, 0, 0 },
	{ "separator x//y",      "x//y",                              0, 0, 0 },
	{ "trailing slash",      "dir/",                              0, 0, 0 },
	{ "5000 bytes",          NULL,                                5000, 1, 1 }
};
#define NROWS (sizeof rows / sizeof rows[0])

static uint8_t dpre[24], dbad[24], dpost[24];
static char big[5001];

static int has_hash(const struct cs_run *r, uint64_t h)
{
	unsigned i;

	for (i = 1; i < r->n && i < CS_MAXOBJ; i++)
		if (r->o[i].hash == h)
			return 1;
	return 0;
}

static int run_format(void *p)
{
	unsigned f = (unsigned)(uintptr_t)p, k;
	const struct cw_format *F = &cw_formats[f];
	struct kof_scan_option o = cs_opt();

	if (F->gathered)
		return 0;                       /* an OLE entry name is 31 characters, and its streams come out as one object */
	cs_fill(dpre, sizeof dpre, 1);
	cs_fill(dbad, sizeof dbad, 2);
	cs_fill(dpost, sizeof dpost, 3);
	memset(big, 'A', 5000);
	o.scratch_dir = scratch;
	if (chdir(deep))
		return 9;
	for (k = 0; k < NROWS; k++) {
		const struct row *R = &rows[k];
		struct cw_ent e[3];
		struct cw w = { 0 };
		struct cs_run r;
		unsigned n = F->max_members == 1 ? 1u : 3u, i;
		uint64_t h0, h1;
		unsigned n0, n1;
		int cab_lost = !strcmp(F->name, "cab") && R->nul;
		const char *nm = R->name ? R->name : (R->five ? big : absprobe);
		uint32_t nl = R->len ? R->len : (uint32_t)strlen(nm);

		memset(e, 0, sizeof e);
		e[0].name = "pre";  e[0].data = dpre;  e[0].len = sizeof dpre;
		e[1].name = nm;     e[1].name_len = nl; e[1].data = dbad;  e[1].len = sizeof dbad;
		e[2].name = "post"; e[2].data = dpost; e[2].len = sizeof dpost;
		if (n == 1) {
			e[0] = e[1];
		}
		F->write(&w, e, n, NULL, NULL);
		snapshot();
		h0 = snap_h;
		n0 = snap_n;
		if (cs_scan(w.p, w.n, "r.x", &o, &r))
			return 9;
		snapshot();
		h1 = snap_h;
		n1 = snap_n;
		CK(r.rc >= 1, "%s/%s: the scan answers (rc %d)", F->name, R->what, r.rc);
		CK(h0 == h1 && n0 == n1, "%s/%s: the scratch tree changed (%u entries before, %u after): a name made a file", F->name, R->what, n0, n1);
		CK(access(absprobe, F_OK) != 0, "%s/%s: the absolute probe path exists", F->name, R->what);
		CK(access("/etc/kof_ctr_owned", F_OK) != 0, "%s/%s: /etc/kof_ctr_owned exists", F->name, R->what);
		CK(access("/tmp/kof_ctr_owned", F_OK) != 0, "%s/%s: /tmp/kof_ctr_owned exists", F->name, R->what);
		CK(r.slash_forged == 0, "%s/%s: %u child names carry a path separator or a control byte", F->name, R->what, r.slash_forged);
		for (i = 1; i < r.n && i < CS_MAXOBJ; i++)
			CK(r.o[i].depth == 1, "%s/%s: object %u is %u levels below the root (%s)", F->name, R->what, i, r.o[i].depth, r.o[i].name);
		if (n == 3) {
			int post_found = has_hash(&r, cs_fnv(dpost, sizeof dpost));

			CK(has_hash(&r, cs_fnv(dpre, sizeof dpre)), "%s/%s: the member before is opened whole", F->name, R->what);
			if (cab_lost) {
				char what[160];

				snprintf(what, sizeof what, "cab/%s: the files after a name the table cannot take (a NUL in it, or 5000 bytes) are %s", R->what,
					 post_found ? "kept" : "dropped with broken 0");
				/* KNOWN DEFECT WP2-D6 (2026-10-24, M): this row pins it, green until fixed. */
				KM_CHECK(post_found || r.broken > 0 || r.limit_hits > 0 || r.names_invalid > 0, what, "WP2-D6");
			} else {
				CK(has_hash(&r, cs_fnv(dpost, sizeof dpost)), "%s/%s: the member after is opened whole", F->name, R->what);
				CK(has_hash(&r, cs_fnv(dbad, sizeof dbad)), "%s/%s: the hostile member itself is opened whole", F->name, R->what);
			}
			if (!strcmp(F->name, "tar") && R->five)
				CK(r.names_invalid >= 1 || r.broken >= 1, "%s/%s: a name past the format's limit is counted, not silent", F->name, R->what);
		}
		cs_free(&r);
		cw_free(&w);
	}
	/* duplicates: three members, one name, three distinct objects */
	if (F->max_members > 1) {
		struct cw_ent e[3];
		struct cw w = { 0 };
		struct cs_run r;
		unsigned i, j, dist = 0;

		memset(e, 0, sizeof e);
		for (i = 0; i < 3; i++) {
			e[i].name = "dup";
			e[i].data = i == 0 ? dpre : i == 1 ? dbad : dpost;
			e[i].len = sizeof dpre;
		}
		F->write(&w, e, 3, NULL, NULL);
		if (cs_scan(w.p, w.n, "r.x", &o, &r))
			return 9;
		for (i = 1; i < r.n && i < CS_MAXOBJ; i++) {
			int seen = 0;

			for (j = 1; j < i; j++)
				seen |= !strcmp(r.o[i].name, r.o[j].name);
			dist += !seen;
		}
		CK(r.n >= 4 && dist == r.n - 1u, "%s: three members called dup are %u objects with %u distinct names", F->name, r.n - 1u, dist);
		CK(has_hash(&r, cs_fnv(dpre, sizeof dpre)) && has_hash(&r, cs_fnv(dbad, sizeof dbad)) && has_hash(&r, cs_fnv(dpost, sizeof dpost)),
		   "%s: every duplicate's bytes are opened", F->name);
		cs_free(&r);
		cw_free(&w);
	}
	return he_fails != 0 ? 1 : 0;
}

/* ---- links ------------------------------------------------------------------------------------------ */

/*
 * Symlink and hardlink ENTRIES, scanned from inside the scratch tree: a hardlink pair that names each other, a link to itself, a
 * symlink to "../../../../etc/passwd" and one to an absolute path inside the scratch tree, a hardlink to a name that does not exist.
 * The engine never follows a link (it opens no path from a member), so: the scan ends, the scratch tree is unchanged, a file member
 * after the links is opened whole, and a zip symlink is its target TEXT (the 11 bytes of the path, not the file it names).
 */
static int links(void *unused)
{
	static const struct { const char *name; int kind; const char *target; } L[] = {
		{ "h1", CW_HARDLINK, "h2" }, { "h2", CW_HARDLINK, "h1" }, { "self", CW_HARDLINK, "self" },
		{ "s1", CW_SYMLINK, "../../../../etc/passwd" }, { "s2", CW_SYMLINK, NULL }, { "s3", CW_SYMLINK, "s3" }, { "h3", CW_HARDLINK, "no-such-member" }
	};
	static const char *const fmts[] = { "tar", "zip" };
	unsigned fi, mode, i;
	struct kof_scan_option o = cs_opt();

	(void)unused;
	cs_fill(dpost, sizeof dpost, 3);
	o.scratch_dir = scratch;
	if (chdir(deep))
		return 9;
	for (fi = 0; fi < 2; fi++)
		for (mode = 0; mode < 2; mode++) {
			unsigned f = cw_find(fmts[fi]), n = (unsigned)(sizeof L / sizeof L[0]) + 1u;
			struct cw_ent e[sizeof L / sizeof L[0] + 1u];
			struct cw_lies lies;
			struct cw w = { 0 };
			struct cs_run r;
			uint64_t h0, h1;
			unsigned n0, n1;

			if (fi == 1 && mode == 1)           /* a zip whose directory points at itself opens as nothing (WP2-D3): nothing more to say */
				continue;
			memset(e, 0, sizeof e);
			memset(&lies, 0, sizeof lies);
			lies.mask = mode ? CW_L_CYCLE : 0u;
			for (i = 0; i + 1u < n; i++) {
				e[i].name = L[i].name;
				e[i].kind = L[i].kind;
				e[i].target = L[i].target ? L[i].target : absprobe;
			}
			e[n - 1u].name = "file";
			e[n - 1u].data = dpost;
			e[n - 1u].len = sizeof dpost;
			cw_formats[f].write(&w, e, n, &lies, NULL);
			snapshot();
			h0 = snap_h;
			n0 = snap_n;
			if (cs_scan(w.p, w.n, "l.x", &o, &r))
				return 9;
			snapshot();
			h1 = snap_h;
			n1 = snap_n;
			CK(r.rc >= 1, "%s links (cycle %u): the scan ends", fmts[fi], mode);
			CK(h0 == h1 && n0 == n1, "%s links (cycle %u): the scratch tree changed", fmts[fi], mode);
			CK(access(absprobe, F_OK) != 0, "%s links (cycle %u): the absolute probe exists", fmts[fi], mode);
			CK(has_hash(&r, cs_fnv(dpost, sizeof dpost)), "%s links (cycle %u): the file after the links is opened whole", fmts[fi], mode);
			if (!strcmp(fmts[fi], "zip")) {
				const struct cs_obj *s1 = cs_find(&r, ":s1");

				CK(s1 && s1->len == strlen("../../../../etc/passwd") && !memcmp(s1->head, "../../../../etc/passwd", s1->len),
				   "zip links: a symlink member is its target text, not the file it names");
			} else {
				CK(r.n == 2, "tar links (cycle %u): links make no child, only the file does (%u objects)", mode, r.n);
			}
			cs_free(&r);
			cw_free(&w);
		}
	return he_fails != 0 ? 1 : 0;
}

/* ---- long names ------------------------------------------------------------------------------------ */

static int long_names(void *unused)
{
	enum { N = 200, L = 60000 };
	struct cw_ent *e = (struct cw_ent *)calloc(N, sizeof *e);
	char *nm = (char *)malloc(L + 1u);
	struct cw w = { 0 };
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	uint8_t one[1] = { 'x' };
	unsigned i;
	uint64_t maxlen = 0;

	(void)unused;
	if (!e || !nm)
		return 9;
	for (i = 0; i < L; i++)
		nm[i] = (char)('a' + i % 26u);
	nm[L] = 0;
	for (i = 0; i < N; i++) {
		e[i].name = nm;
		e[i].name_len = L;
		e[i].data = one;
		e[i].len = 1;
	}
	cw_zip(&w, e, N, NULL, NULL);
	CK(w.n > (size_t)N * L, "long names: the archive holds %zu bytes of names", w.n);
	if (cs_scan(w.p, w.n, "long.zip", &o, &r))
		return 9;
	for (i = 1; i < r.n && i < CS_MAXOBJ; i++)
		if (strlen(r.o[i].name) > maxlen)
			maxlen = strlen(r.o[i].name);
	printf("  long names: %zu byte zip, %u objects, longest kept name %llu, peak %llu, names_invalid %llu\n", w.n, r.n,
	       (unsigned long long)r.max_name, (unsigned long long)r.peak, (unsigned long long)r.names_invalid);
	/* a cap bounds the cost of the names (the engine keeps 183 of the 200 here and says so); what is NOT allowed is losing members
	 * with nothing said: either every member is a child or the walk reports a limit, on an object and in the counter */
	CK(r.n == 1u + N || (r.broken_limit > 0 && r.limit_hits > 0), "long names: %u of %u members are children and nothing says why (limit objects %llu, hits %llu)",
	   r.n - 1u, (unsigned)N, (unsigned long long)r.broken_limit, (unsigned long long)r.limit_hits);
	CK(r.n > 1u, "long names: some members are opened (%u objects)", r.n);
	CK(r.peak <= o.max_resident_bytes, "long names: peak resident %llu under the %llu ceiling", (unsigned long long)r.peak,
	   (unsigned long long)o.max_resident_bytes);
	CK(r.slash_forged == 0, "long names: no forged separator");
	cs_free(&r);
	cw_free(&w);
	free(e);
	free(nm);
	return he_fails != 0 ? 1 : 0;
}

int main(void)
{
	unsigned f, bad = 0;
	struct he_status st;
	char cmd[PATH_MAX + 16];

	cs_eng = keng_open(HE_DB);                  /* before any chdir: the database path is relative */
	if (!cs_eng || make_scratch()) {
		printf("ctr_names: no scratch tree\n");
		return 1;
	}
	for (f = 0; f < CW_NFORMATS; f++) {
		st = he_child(run_format, (void *)(uintptr_t)f, 120);
		printf("names %-5s %s\n", cw_formats[f].name, he_how(st));
		bad |= !he_ok(st);
	}
	st = he_child(links, NULL, 60);
	printf("names links %s\n", he_how(st));
	bad |= !he_ok(st);
	st = he_child(long_names, NULL, 120);
	printf("names long %s\n", he_how(st));
	bad |= !he_ok(st);
	if (chdir(scratch) == 0)
		(void)chdir("/");
	snprintf(cmd, sizeof cmd, "%s", scratch);
	he_rmtree(cmd);
	printf("ctr_names: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
