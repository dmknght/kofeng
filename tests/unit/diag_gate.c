/*
 * diag_gate - THE ANALYSIS RUNS WHEN SOMETHING READS IT, AND ONLY THEN.
 *
 * Four properties, each pinned with the product counters (kof_prod_ran: how many
 * times the object's diagnose analysis, function table and decode walk were built)
 * and with the bit a diagnose leaves when it matched:
 *
 *   1. A diagnose that only a verdict reads - it declares a disease, no rule names
 *      it - is analysed by a plain scan, and the verdict it makes is there.
 *   2. A diagnose NOTHING reads (no rule, no disease) is not run by a plain scan:
 *      an object only it could be answered on costs no analysis at all. The caller
 *      asks for every diagnose with kof_scan_option.report_diag, and that runs it.
 *   3. An object no gate is open on - no diagnose can be answered on it - builds
 *      no analysis, no function table and no walk, whatever its name.
 *   4. An object that looks like nothing (no symbols, no sections, a harmless
 *      name) but carries the evidence is still analysed when a reader exists: the
 *      gate rests on the loaded database and on the file's structure, not on a
 *      name the file chose.
 *
 * Database: build/test/databases-sigs. kmod_give_root declares a disease and no
 * rule reads it; rwx_exec is read by a rule and declares a disease; kmod_commit_only
 * is read by nothing and declares nothing - see tests/sigs/diagnoses.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "caps_fix.h"
#include "notes.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/scanners/scan.h"

static kof_engine  *eng;
static kof_scanner *sc;

static uint8_t img[1u << 18];
static uint8_t code[1u << 12];

struct got {
	unsigned n_obj;
	uint8_t  runs[KOF_PROD_COUNT];
	unsigned all[KOF_PROD_COUNT];  /* summed over the object and what it produced */
	char     verdict[112];
	uint32_t n_diag;               /* res->n_diag, the report */
	uint32_t n_find;               /* the notes the test modules made on the object */
	int      hit_root, hit_commit, hit_rwx;
};

static int slot_of(const char *name)
{
	uint32_t i;

	for (i = 0; i < eng->n_diag; i++)
		if (eng->diag[i].name && !strcmp(eng->diag[i].name, name))
			return (int)i;
	return -1;
}

static int hit(const char *name)
{
	int i = slot_of(name);

	return i >= 0 && ((sc->diag.hit[(unsigned)i >> 3] >> ((unsigned)i & 7u)) & 1u);
}

/* What the test modules said while the object was scanned - see notes.h. */
static struct note_list pend;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct got *g = user;
	struct note_list got;
	unsigned p;

	(void)name; (void)bytes; (void)len;
	notes_take(&pend, &got);
	for (p = 0; p < KOF_PROD_COUNT; p++)
		g->all[p] += sc->obj.prod_runs[p];
	if (g->n_obj++)
		return 0;                       /* the top-level object only below */
	memcpy(g->runs, sc->obj.prod_runs, sizeof g->runs);
	g->n_diag = res->n_diag;
	g->n_find = got.n;
	if (res->has_verdict)
		snprintf(g->verdict, sizeof g->verdict, "%s", res->verdict.name);
	g->hit_root = hit("kmod_give_root");
	g->hit_commit = hit("kmod_commit_only");
	g->hit_rwx = hit("rwx_exec");
	return 0;
}

static struct got scan(const uint8_t *b, uint64_t n, const char *name, int report)
{
	struct kof_scan_option opt;
	struct got g;

	memset(&opt, 0, sizeof opt);
	memset(&g, 0, sizeof g);
	memset(&pend, 0, sizeof pend);
	opt.report_diag = report;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	kscan_bytes(sc, b, n, name, &opt, on_object, &g);
	return g;
}

/* "prepare_creds" is spelled with its last letter changed, so the module no
 * longer imports it: same length, same file, one import fewer. */
static void rename_import(uint8_t *b, uint64_t n, const char *from, const char *to)
{
	uint64_t i, l = strlen(from);

	for (i = 0; i + l <= n; i++)
		if (!memcmp(b + i, from, l)) {
			memcpy(b + i, to, l);
			return;
		}
}

static void verdict_only(void)
{
	uint64_t len = cf_kmod(img, sizeof img, 4, 0);
	struct got a = scan(img, len, "x", 0);

	/* 1. read by a verdict only: analysed, and the verdict is made of its disease */
	CK(a.n_obj >= 1u);
	CK(a.runs[KOF_PROD_DIAG] == 1u);
	CK(a.hit_root == 1);
	CK(strstr(a.verdict, "Rootkit") != NULL);
	/* 2a. read by nothing: not matched, though its gate is open on this module */
	CK(a.hit_commit == 0);
	/* the plain scan carries no report */
	CK(a.n_diag == 0u);
}

static void report_asks_for_all(void)
{
	uint64_t len = cf_kmod(img, sizeof img, 4, 0);
	struct got a = scan(img, len, "x", 1);

	/* 2b. the caller asked for every diagnose: the unread one runs too */
	CK(a.hit_root == 1);
	CK(a.hit_commit == 1);
	CK(a.n_diag == eng->n_diag);
	/* and asking changes no verdict */
	CK(strstr(a.verdict, "Rootkit") != NULL);
}

/* A copy of the test database without the pack that holds `skip`, in a directory
 * of this test's own, so a diagnose can be taken out and the others left. */
static const char *tmpdb = "build/test/diag_gate_db";

static int copy_file(const char *from, const char *to)
{
	static char buf[1u << 16];
	FILE *a = fopen(from, "rb"), *o;
	size_t n;
	int ok = 1;

	if (!a)
		return 0;
	o = fopen(to, "wb");
	if (!o) {
		fclose(a);
		return 0;
	}
	while ((n = fread(buf, 1, sizeof buf, a)) > 0)
		if (fwrite(buf, 1, n, o) != n)
			ok = 0;
	fclose(a);
	return fclose(o) == 0 && ok;
}

/* `skip` is a list of name prefixes, each a pack left out. */
static int make_tmpdb(const char *src, const char *const *skip)
{
	DIR *d = opendir(src);
	struct dirent *e;
	char from[700], to[700];
	unsigned q;
	int left_out;

	if (!d)
		return 0;
	(void)mkdir(tmpdb, 0755);
	while ((e = readdir(d)) != NULL) {
		left_out = e->d_name[0] == '.';
		for (q = 0; skip[q] && !left_out; q++)
			left_out = !strncmp(e->d_name, skip[q], strlen(skip[q]));
		if (left_out)
			continue;
		snprintf(from, sizeof from, "%s/%s", src, e->d_name);
		snprintf(to, sizeof to, "%s/%s", tmpdb, e->d_name);
		if (!copy_file(from, to)) {
			closedir(d);
			return 0;
		}
	}
	closedir(d);
	return 1;
}

static void drop_tmpdb(void)
{
	DIR *d = opendir(tmpdb);
	struct dirent *e;
	char to[700];

	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(to, sizeof to, "%s/%s", tmpdb, e->d_name);
		(void)unlink(to);
	}
	closedir(d);
	(void)rmdir(tmpdb);
}

/* No rule reads anything that a module of this shape could be answered on, and the
 * only diagnose whose gate is open is the one nothing reads: a plain scan builds
 * no analysis and no walk; the report asks for it and gets it. */
static void only_unread_is_answerable(const char *db)
{
	struct got p, r;
	uint64_t len;

	if (!make_tmpdb(db, (const char *const[]){ "diag-rwx", NULL })) {
		printf("diag_gate: cannot make %s\n", tmpdb);
		fails++;
		return;
	}
	kscan_free(sc);            /* the scanner reads the engine's ledger when it goes: it goes first */
	keng_close(eng);
	eng = keng_open(tmpdb);
	sc = eng ? kscan_new(eng) : NULL;
	if (sc)
		kscan_on_debug(sc, notes_on, &pend);
	CK(eng && sc);
	if (!eng || !sc)
		return;
	len = cf_kmod(img, sizeof img, 4, 0);
	/* give_root's import is gone; commit_creds, which only the unread one wants,
	 * stays */
	rename_import(img, len, "prepare_creds", "prepare_credz");
	p = scan(img, len, "x", 0);
	CK(p.runs[KOF_PROD_DIAG] == 0u);        /* nothing read can be answered: nothing run */
	CK(p.runs[KOF_PROD_WALK] == 0u);        /* (the function table is not asserted: this
						 * database has block rules, which read it) */
	CK(p.hit_commit == 0 && p.hit_root == 0);
	/* the fixture's own pattern detector declares no disease, so it is evidence and not a
	 * verdict: nothing was read, so there is none */
	CK(p.verdict[0] == 0);
	r = scan(img, len, "x", 1);
	CK(r.runs[KOF_PROD_DIAG] == 1u);        /* the report is the asker */
	CK(r.hit_commit == 1);
	CK(strstr(r.verdict, "commit") == NULL);   /* a diagnose with no disease names nothing */
	/* nothing carried over: a plain scan again is as before */
	p = scan(img, len, "x", 0);
	CK(p.runs[KOF_PROD_DIAG] == 0u && p.hit_commit == 0 && p.n_diag == 0u);
	/* and the evidence in place: both imports present, the disease-only reader
	 * runs the analysis and its verdict is there */
	len = cf_kmod(img, sizeof img, 4, 0);
	p = scan(img, len, "x", 0);
	CK(p.runs[KOF_PROD_DIAG] == 1u && p.hit_root == 1 && p.hit_commit == 0);
	CK(strstr(p.verdict, "Rootkit") != NULL);
	/* neither import: no gate open, and the report has nothing to run either */
	len = cf_kmod(img, sizeof img, 4, 0);
	rename_import(img, len, "prepare_creds", "prepare_credz");
	rename_import(img, len, "commit_creds", "commit_credz");
	r = scan(img, len, "driver.ko", 1);
	CK(r.runs[KOF_PROD_DIAG] == 0u && r.runs[KOF_PROD_WALK] == 0u);
	drop_tmpdb();
}

/* An x86-64 ELF with an overlay of 8 KB of zeros and a UTF-16 string behind its one
 * segment: it has a normalised view, and (the shape of view_equiv.c's first row)
 * the view is a child of its own. */
static uint64_t elf_with_view(uint8_t *b, uint64_t cap)
{
	const char *w = "Permission denied Connection refused";
	unsigned n = cf_stager64(code, 0), i;
	uint64_t len = cf_elf64(b, cap, code, n);

	memset(b + len, 0, 8192);
	len += 8192;
	for (i = 0; w[i]; i++) {
		b[len++] = (uint8_t)w[i];
		b[len++] = 0;
	}
	return len;
}

/*
 * A VIEW'S FUNCTIONS ARE CARRIED OVER ONLY WHEN A BLOCK RULE WILL READ THEM. The
 * carry-over asks for the parent's functions, which for an object nothing else
 * analysed is a decode of all its code; no diagnose is served on a view (it
 * adopts the parent's) and no module reads a function table. A database with block
 * rules (this test's) still gets the table; one without (the shipped one) does
 * not pay for it. Both databases here carry no diagnose, so nothing else asks.
 */
static void view_functions(const char *db, const char *shipped)
{
	struct got a, b;
	uint64_t len = elf_with_view(img, sizeof img);
	kof_engine *e0 = eng, *e2 = NULL;
	kof_scanner *s0 = sc, *s2 = NULL;
	int k;

	for (k = 0; k < 2; k++) {
		if (make_tmpdb(k ? shipped : db, (const char *const[]){ "diag-", NULL })) {
			e2 = keng_open(tmpdb);
			s2 = e2 ? kscan_new(e2) : NULL;
		}
		if (!e2 || !s2) {
			printf("diag_gate: cannot open the %s database, view case skipped\n",
			       k ? "shipped" : "test");
			drop_tmpdb();
			continue;
		}
		eng = e2;
		sc = s2;
		if (!k) {
			a = scan(img, len, "stub.bin", 0);
			CK(a.n_obj >= 2u);                      /* the parent and its view */
			CK(a.all[KOF_PROD_FUNCS] >= 1u);        /* a block rule may read it */
		} else {
			b = scan(img, len, "stub.bin", 0);
			CK(b.n_obj >= 2u);
			CK(b.all[KOF_PROD_FUNCS] == 0u && b.all[KOF_PROD_WALK] == 0u);
			CK(b.all[KOF_PROD_DIAG] == 0u);
		}
		kscan_free(s2);
		keng_close(e2);
		e2 = NULL;
		s2 = NULL;
		drop_tmpdb();
	}
	eng = e0;
	sc = s0;
}

/*
 * NO RULE ASKS AT ALL - every signature pack is left out, and the pack of the
 * diagnoses that no import gates (rwx_exec is open on any ELF) - and a diagnose that
 * declares a disease is still analysed, because the verdict reads it: the stage
 * that infers the verdict asks for the analysis when such a diagnose is
 * answerable on the object (kof_scan_diag_feeds_verdict), and not otherwise.
 */
static void verdict_asks(const char *db)
{
	struct got p;
	uint64_t len;
	kof_engine *e0 = eng;
	kof_scanner *s0 = sc;

	if (!make_tmpdb(db, (const char *const[]){ "sigs-", "diag-rwx", NULL })) {
		printf("diag_gate: cannot make %s\n", tmpdb);
		fails++;
		return;
	}
	eng = keng_open(tmpdb);
	sc = eng ? kscan_new(eng) : NULL;
	if (sc)
		kscan_on_debug(sc, notes_on, &pend);
	CK(eng && sc);
	if (eng && sc) {
		len = cf_kmod(img, sizeof img, 4, 0);
		p = scan(img, len, "x", 0);
		CK(p.runs[KOF_PROD_DIAG] == 1u && p.hit_root == 1 && p.hit_commit == 0);
		CK(strstr(p.verdict, "Rootkit") != NULL);
		/* answerable on nothing here: the verdict stage asks for nothing */
		rename_import(img, len, "prepare_creds", "prepare_credz");
		p = scan(img, len, "x", 0);
		CK(p.runs[KOF_PROD_DIAG] == 0u && p.verdict[0] == 0);
		/* a text object has no route at all */
		memset(img, 'a', 4096);
		p = scan(img, 4096, "y", 0);
		CK(p.runs[KOF_PROD_DIAG] == 0u);
		kscan_free(sc);
		keng_close(eng);
	}
	eng = e0;
	sc = s0;
	drop_tmpdb();
}

/*
 * THE RULE THAT READS A DIAGNOSE (the expensive one) is the LAST of the detect stage:
 *   - the loader marks the module a diagnose names as its reader (reads_diag) and
 *     sorts it after every other module of its format, so the cheap detectors have
 *     reported before the analysis is asked for;
 *   - no finding ends the stage: of two detectors that both fire, both report, because
 *     what they found is evidence and the verdict is read off every disease.
 */
static struct got scan_with(const uint8_t *b, uint64_t n)
{
	struct kof_scan_option opt;
	struct got g;

	memset(&opt, 0, sizeof opt);
	memset(&g, 0, sizeof g);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	kscan_bytes(sc, b, n, "x", &opt, on_object, &g);
	return g;
}

static void reader_order(void)
{
	uint32_t i, seen_reader = 0, bad = 0;
	struct got b;
	static uint8_t blob[512];

	/* the mark and the order, in the walk of ELF (the format's list merged with the generic one) */
	{
		struct kof_mod_walk w;
		uint32_t mi;

		CK(eng->mod_by_target != NULL);
		kof_mod_walk_begin(&w, eng, KOF_FMT_ELF);
		while (kof_mod_walk_next(&w, &mi)) {
			const struct kof_module *m = &eng->mods[mi];

			if (m->reads_diag)
				seen_reader++;
			else if (seen_reader)
				bad++;                  /* a module that reads none, after one that does */
		}
	}
	CK(seen_reader >= 1u);
	CK(bad == 0u);
	for (i = 0; i < eng->n_mods; i++)       /* only modules a diagnose names */
		if (eng->mods[i].reads_diag)
			CK(eng->mods[i].n_str == 0u);

	/* two detectors that both match: the layer fixture's word and the any-format
	 * fixture's comment string, in a blob of no format */
	memset(blob, 'a', sizeof blob);
	memcpy(blob + 16, "CONVICT", 7);
	memcpy(blob + 64, "GCC: (GNU)", 10);
	b = scan_with(blob, sizeof blob);
	CK(b.n_find >= 2u);                     /* both say so: nothing ends the stage */
}

static void closed_gate(void)
{
	static uint8_t blob[8192];
	unsigned i;
	struct got a, b;

	/* a text object: no route for any diagnose, whatever the database holds */
	for (i = 0; i < sizeof blob; i++)
		blob[i] = (uint8_t)(0x20u + (i % 90u));
	a = scan(blob, sizeof blob, "notes.txt", 0);
	CK(a.runs[KOF_PROD_DIAG] == 0u && a.runs[KOF_PROD_WALK] == 0u &&
	   a.runs[KOF_PROD_FUNCS] == 0u && a.runs[KOF_PROD_APIHASH] == 0u);
	b = scan(blob, sizeof blob, "notes.txt", 1);
	CK(b.runs[KOF_PROD_DIAG] == 0u);        /* the report has no route to run either */
}

static void evidence_under_a_harmless_name(void)
{
	/* stripped static stager, no symbols, no section table, a harmless name: the
	 * file structure (a static x86-64 ELF) and a rule that reads rwx_exec open the
	 * gate - and the analysis finds the evidence. */
	uint64_t len;
	unsigned n = cf_stager64(code, 0);
	struct got a, b;

	len = cf_elf64(img, sizeof img, code, n);
	a = scan(img, len, "README.txt", 0);
	b = scan(img, len, "/usr/lib/libc.so.6", 0);
	CK(a.runs[KOF_PROD_DIAG] == 1u && b.runs[KOF_PROD_DIAG] == 1u);
	CK(a.hit_rwx == 1 && b.hit_rwx == 1);
	CK(strstr(a.verdict, "Dropper") != NULL);
	CK(!strcmp(a.verdict, b.verdict));
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";

	eng = keng_open(db);
	if (!eng) {
		printf("diag_gate: cannot open %s\n", db);
		return 2;
	}
	sc = kscan_new(eng);
	if (sc)
		kscan_on_debug(sc, notes_on, &pend);
	if (!sc || slot_of("kmod_commit_only") < 0 || slot_of("kmod_give_root") < 0 ||
	    slot_of("rwx_exec") < 0) {
		printf("diag_gate: the database lacks the fixtures\n");
		return 2;
	}
	verdict_only();
	report_asks_for_all();
	closed_gate();
	reader_order();
	evidence_under_a_harmless_name();
	only_unread_is_answerable(db);
	verdict_asks(db);
	view_functions(db, "build/release/databases");
	kscan_free(sc);
	keng_close(eng);
	printf("diag_gate: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
