/*
 * api_edges - every branch of the public API files (kofeng.c, kofdetect.c, verdictor/verdict.c): the NULL arguments, the cap boundaries and the engine
 * states that no other test reaches (owner 2026-10-29: tests must take EVERY BRANCH of the code they cover).
 *
 * WHY THE OLD TESTS LEFT THEM: (a) the line was never executed - gcov (make cov-report, mk/tests_cov.mk) showed kofeng.c at 74.8 % of its branches and
 * keng_catalog_load_bases at 0 %: every caller of the API passes a valid engine and a valid out pointer, so the `e ? ... : 0` arm of 30 accessors, the cap
 * 0 / 1 / exact / one short of kdb_*_name and kdb_diagnose_form_expr, and the multi-pack arms of kdb_version / kdb_stamp ran in no test. The answer for a
 * missing argument is part of the API's promise (a host passes NULL after a failed open); (c) the tests that did call these checked "no crash".
 *
 *   NULL        every accessor with a NULL engine and every out pointer NULL: the documented answer, never a crash
 *   CAPS        kdb_family_name / variant / tag with cap 0, 1, exact fit and one short; kdb_diagnose_form_expr the same, and what it RETURNS (the whole length)
 *   MEMORY      keng_set_memory_cap: 0 restores the default, below the least that works and below what is held are refused and change nothing
 *   VERSION     kdb_version names the OLDEST pack's build; kdb_stamp is independent of the order of the packs and moves when a pack moves
 *   COMPOSE     kof_verdict_name over every length of family and reason around the name's size, against an oracle written here; kof_verdict_make's lead,
 *               reason and trace; kof_verdict_make_cat; kof_object_label; kverdict_target
 *   EXPLAIN     kscan_explain arguments, kdet_run_* past the end, kdet_info / kdet_diag over a result written by hand
 *   FILEMAP     fold / find / at over a map grown past both of its tables
 *
 * usage: api_edges
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "form_pack.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/kofcore/kofbudget.h"

static int failures;
#define CK(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

static char root[256];
static const char *dbdir = "build/test/databases-sigs";

#define NFORMS 5u

/* a database of the engine's test packs, the names, and NFORMS similarity diagnoses; `leaf` of a pack may be given a build of its own */
static void make_db(const char *dir, int with_forms)
{
	uint8_t *rec[NFORMS];
	size_t rl[NFORMS], k;

	kof_mkdir(dir, 0700);
	(void)copy_pack("build/release/databases", "names.kdig", dir);
	if (!with_forms)
		return;
	for (k = 0; k < NFORMS; k++) {
		char name[16];

		rec[k] = malloc(70000);
		snprintf(name, sizeof name, "f%zu", k);
		rl[k] = form_record(rec[k], name, (uint32_t)k, 1u + (uint32_t)k % 3u);
	}
	write_kdig(dir, "diag-a.kdig", rec, rl, NFORMS);
	for (k = 0; k < NFORMS; k++)
		free(rec[k]);
}

/* one pack copied under a new name with its header's build changed (the build is outside the checksum: KOF_PACK_CRC_FROM) */
static void copy_with_build(const char *leaf, const char *as, const char *to_dir, uint32_t build)
{
	char a[700], b[700];
	size_t n = 0;
	uint8_t *p;

	snprintf(a, sizeof a, "%s/%s", dbdir, leaf);
	snprintf(b, sizeof b, "%s/%s", to_dir, as);
	p = read_file(a, &n);
	if (!p) {
		CK(0, "cannot read %s", a);
		return;
	}
	if (build) {
		struct kof_pack_hdr h;

		memcpy(&h, p, sizeof h);
		h.build = build;
		memcpy(p, &h, sizeof h);
	}
	CK(write_file(b, p, n), "cannot write %s", b);
	free(p);
}

/* ---- NULL ---------------------------------------------------------------------------------------------- */

static void null_matrix(void)
{
	struct keng_catalog_info ci;
	struct kdb_diag_form f;
	struct kof_db_version v;
	uint64_t b = 99, m = 99;
	uint32_t keys = 99;
	char out[16];
	int why = -1;
	struct kof_version ver;

	memset(&ci, 0xAB, sizeof ci);
	keng_catalog_info(NULL, &ci);
	CK(ci.flags == 0 && ci.families == 0 && ci.variants == 0 && ci.tags == 0 && ci.files_refused == 0 && ci.bytes == 0, "info of no engine is not all zero");
	keng_catalog_info(NULL, NULL);
	CK(keng_catalog_load(NULL, "a", "b") == KENG_CAT_NOMEM, "catalog_load(NULL engine) is not NOMEM");
	CK(kdb_unpackers(NULL) == 0 && kdb_diagnoses(NULL) == 0, "counts of no engine");
	CK(kdb_diagnose_name(NULL, 1) == NULL && kdb_diagnose_disease(NULL, 1) == 0 && kdb_diagnose_family(NULL, 1) == 0, "diagnose accessors of no engine");
	CK(kdb_diagnose_variant(NULL, 1) == 0 && kdb_diagnose_tag(NULL, 1) == 0 && kdb_diagnose_type(NULL, 1) == -1, "diagnose accessors of no engine (2)");
	CK(kdb_diagnose_form(NULL, 1, &f) == 0 && kdb_diagnose_form(NULL, 1, NULL) == 0, "form of no engine");
	out[0] = 'x';
	CK(kdb_diagnose_form_expr(NULL, 1, out, sizeof out) == 0 && out[0] == 0, "form_expr of no engine must empty the buffer");
	CK(kdb_diagnose_form_expr(NULL, 1, NULL, 0) == 0 && kdb_diagnose_form_expr(NULL, 1, out, 0) == 0, "form_expr of no engine, no room");
	CK(kdb_disease_name(NULL, 1) == NULL && kdb_disease_type(NULL, 1) == -1, "disease accessors of no engine");
	CK(kdb_diag_full(NULL) == 0 && kdb_diag_collisions(NULL) == 0 && kdb_diag_refused(NULL) == 0 && kdb_diag_packs_refused(NULL) == 0, "diag counters of no engine");
	CK(kdb_mutation_status(NULL, &b, &keys) == 0 && b == 0 && keys == 0, "mutation status of no engine must zero its outputs");
	CK(kdb_mutation_status(NULL, NULL, NULL) == 0, "mutation status, no outputs");
	CK(kdb_pattern_status(NULL, &b, &m) == 0 && b == 0 && m == 0, "pattern status of no engine");
	CK(kdb_pattern_status(NULL, NULL, NULL) == 0, "pattern status, no outputs");
	b = 99;
	CK(kmatch_tables(NULL, &b, &keys) == -1 && b == 0 && keys == 0, "kmatch_tables of no engine");
	CK(kmatch_tables(NULL, NULL, NULL) == -1, "kmatch_tables, no outputs");
	CK(keng_memory_cap(NULL) == 0 && keng_memory_db(NULL) == 0 && keng_memory_peak(NULL) == 0 && keng_set_memory_cap(NULL, 1ull << 30) == 0, "memory of no engine");
	CK(kdb_stamp(NULL) == 0, "stamp of no engine");
	memset(&v, 0xAB, sizeof v);
	CK(kdb_version(NULL, &v) == 0 && v.major == 0 && v.minor == 0 && v.build == 0 && v.machine == 0, "version of no engine is not zeroed");
	CK(kdb_version(NULL, NULL) == 0, "version, no out");
	keng_version(NULL);
	keng_version(&ver);
	CK(ver.build != 0, "keng_version has no build");
	CK(kscan_new(NULL) == NULL, "kscan_new(NULL)");
	CK(kscan_new_ex(NULL, &why) == NULL && why == KSCAN_NEW_NO_ENGINE, "kscan_new_ex(NULL) says %d", why);
	CK(kscan_new_ex(NULL, NULL) == NULL, "kscan_new_ex(NULL, NULL)");
	CK(!strcmp(kscan_new_why_str(KSCAN_NEW_OK), "made") && strstr(kscan_new_why_str(KSCAN_NEW_NO_ENGINE), "no engine") &&
	   strstr(kscan_new_why_str(KSCAN_NEW_BUDGET), "budget") && strstr(kscan_new_why_str(KSCAN_NEW_NOMEM), "memory") &&
	   !strcmp(kscan_new_why_str(77), "unknown") && !strcmp(kscan_new_why_str(-1), "unknown"), "kscan_new_why_str words");
	kscan_on_debug(NULL, NULL, NULL);
	CK(kscan_stats(NULL) == NULL, "kscan_stats(NULL)");
	kscan_free(NULL);
	kscan_trim(NULL, 0);
	CK(kscan_path(NULL, "x", NULL, NULL, NULL) == KOF_ERR_ARG, "kscan_path(NULL scanner)");
	CK(kscan_path_mt(NULL, 2u, "x", NULL, NULL, NULL) == KOF_ERR_ARG, "kscan_path_mt(NULL scanners)");
	CK(kscan_explain(NULL, "x", 1u, "n", NULL) == NULL, "explain(NULL scanner)");
	{
		kof_scanner *none[1] = { NULL };

		CK(kscan_path_mt(none, 0u, "x", NULL, NULL, NULL) == KOF_ERR_ARG, "kscan_path_mt with no scanner count");
		CK(kscan_path_mt(none, 1u, NULL, NULL, NULL, NULL) == KOF_ERR_ARG, "kscan_path_mt with no path");
		CK(kscan_path(none[0], "x", NULL, NULL, NULL) == KOF_ERR_ARG, "kscan_path with a NULL scanner and a path");
	}
	CK(keng_open(NULL) == NULL, "keng_open(NULL)");
	keng_close(NULL);
	CK(kdet_run_count(NULL) == 0 && kdet_run_at(NULL, 0) == NULL && kdet_run_find(NULL, "a") == NULL && kdet_run_verdict(NULL) == NULL && kdet_run_status(NULL) == 0, "run accessors of no run");
	kdet_run_free(NULL);
	CK(!strcmp(kverdict_broken_name(KOF_BROKEN_LIMIT), "Limit reached") && !strcmp(kverdict_broken_name(KOF_BROKEN_UNSUPPORTED), "Unsupported by this build") &&
	   !strcmp(kverdict_broken_name(KOF_BROKEN_DAMAGED), "Damaged object") && !strcmp(kverdict_broken_name(KOF_BROKEN_ENCRYPTED), "Encrypted content") &&
	   !strcmp(kverdict_broken_name(0), "Unknown") && !strcmp(kverdict_broken_name(0x7777), "Unknown"), "kverdict_broken_name words");
	CK(kverdict_fact_id("version") == kverdict_fact_id("version") && kverdict_fact_id("version") != kverdict_fact_id("versio"), "fact id");
	/* the name calls of a NULL engine spell the id in hex and answer 0, whatever the cap */
	out[0] = 'x';
	CK(kdb_family_name(NULL, 0x1234567800000000ull, out, 0) == 0 && out[0] == 'x', "cap 0 writes nothing");
	CK(kdb_family_name(NULL, 0x1234567800000000ull, out, sizeof out) == 0 && !strcmp(out, "12345678"), "hex word of an id: %s", out);
	CK(kdb_variant_name(NULL, 0x1234567800000000ull, out, sizeof out) == 0 && !strcmp(out, "12345678"), "variant hex");
	CK(kdb_tag_name(NULL, 0x1234567800000000ull, out, sizeof out) == 0 && !strcmp(out, "12345678"), "tag hex");
	CK(kdb_variant_name(NULL, 1, out, 0) == 0 && kdb_tag_name(NULL, 1, out, 0) == 0, "variant/tag cap 0");
}

/* ---- the engine's states ------------------------------------------------------------------------------ */

/* The ids of the diagnoses are hashes of their names (kof_diag_id32_), so they are read where the engine lists them: the report of a scan. */
static void collect_ids(kof_engine *e, uint32_t *ids, uint32_t want)
{
	kof_scanner *sc = kscan_new(e);
	uint8_t obj[BLK];
	kdet_run *run;
	uint32_t i, n = 0;

	make_bytes(obj, seed_of(77u, 0u));
	run = sc ? kscan_explain(sc, obj, BLK, "ids", NULL) : NULL;
	if (run && kdet_run_at(run, 0))
		for (i = 0; i < kdet_run_at(run, 0)->res.n_diag && n < want; i++)
			ids[n++] = kdet_run_at(run, 0)->res.diag[i].id;
	CK(n == want, "found %u of %u diagnose ids", n, want);
	while (n < want)
		ids[n++] = 0;
	kdet_run_free(run);
	kscan_free(sc);
}

static void engine_edges(void)
{
	char dir[400], dir2[400];
	kof_engine *e;
	uint32_t ids[NFORMS], i;
	struct kdb_diag_form f;
	char buf[400], tiny[2];
	size_t full;
	struct kof_db_version v;
	uint64_t st1, st2, st3;

	snprintf(dir, sizeof dir, "%s/db1", root);
	make_db(dir, 1);
	copy_with_build("sigs-any.ksig", "a.ksig", dir, 0u);
	copy_with_build("sigs-elf.ksig", "b.ksig", dir, 2026010101u);
	copy_with_build("sigs-pe.ksig", "c.ksig", dir, 2025010101u);
	e = keng_open(dir);
	CK(e != NULL, "the test database does not open");
	if (!e)
		return;
	collect_ids(e, ids, NFORMS);
	CK(kdb_diagnoses(e) == NFORMS, "%u diagnoses", kdb_diagnoses(e));

	/* an id the engine does not hold */
	CK(kdb_diagnose_name(e, 0xFFFFFFF0u) == NULL && kdb_diagnose_disease(e, 0xFFFFFFF0u) == 0 && kdb_diagnose_family(e, 0xFFFFFFF0u) == 0 &&
	   kdb_diagnose_variant(e, 0xFFFFFFF0u) == 0 && kdb_diagnose_tag(e, 0xFFFFFFF0u) == 0 && kdb_diagnose_type(e, 0xFFFFFFF0u) == -1 &&
	   kdb_diagnose_form(e, 0xFFFFFFF0u, &f) == 0, "accessors of an id that is not held");
	buf[0] = 'x';
	CK(kdb_diagnose_form_expr(e, 0xFFFFFFF0u, buf, sizeof buf) == 0 && buf[0] == 0, "expr of an id not held empties the buffer");
	CK(kdb_diagnose_form_expr(e, 0xFFFFFFF0u, NULL, 0) == 0, "expr of an id not held, no buffer");
	CK(kdb_disease_name(e, 0xFFFFFFF0u) == NULL && kdb_disease_type(e, 0xFFFFFFF0u) == -1, "a disease that is not held");

	/* a form diagnose: the form, no catalog facts (the test pack carries no META: type -1) */
	CK(kdb_diagnose_form(e, ids[0], &f) == 1 && f.blocks >= 1u && f.matchers >= 1u && f.similarity == 1, "the form of %s", kdb_diagnose_name(e, ids[0]));
	CK(kdb_diagnose_form(e, ids[0], NULL) == 1, "form with no out");
	CK(kdb_diagnose_type(e, ids[0]) == -1 && kdb_diagnose_family(e, ids[0]) == 0, "a diagnose with no catalog facts has no type");
	/* the expression text: the whole length is returned whatever the buffer, the buffer is always terminated */
	full = kdb_diagnose_form_expr(e, ids[1], buf, sizeof buf);
	CK(full > 0 && full < sizeof buf && strlen(buf) == full, "expr length %zu", full);
	/* no buffer or no room: nothing is written and nothing crashes. What it ANSWERS then is 0, while kofeng.h says "the length it wanted": reported to the
	 * coordinator as D-API-2 (comment against code), not pinned here until the owner says which of the two is right. */
	buf[0] = 'q';
	(void)kdb_diagnose_form_expr(e, ids[1], NULL, 0);
	(void)kdb_diagnose_form_expr(e, ids[1], buf, 0);
	CK(buf[0] == 'q', "expr with cap 0 wrote into the buffer");
	CK(kdb_diagnose_form_expr(e, ids[1], buf, sizeof buf) == full, "expr, again");
	for (i = 1; i <= full + 2u; i++) {
		char *b2 = malloc(i + 4u);
		size_t r;

		memset(b2, 'Z', i + 4u);
		r = kdb_diagnose_form_expr(e, ids[1], b2, i);
		CK(r == full, "expr into %u bytes returned %zu, not %zu", i, r, full);
		CK(b2[i + 0] == 'Z' && b2[i + 3] == 'Z', "expr into %u bytes wrote past its end", i);
		CK(memchr(b2, 0, i) != NULL, "expr into %u bytes is not terminated", i);
		CK(strncmp(b2, buf, i - 1u < full ? i - 1u : full) == 0, "expr into %u bytes is not a prefix of the whole", i);
		free(b2);
	}
	tiny[0] = 'x';
	(void)kdb_diagnose_form_expr(e, ids[1], tiny, 1);
	CK(tiny[0] == 0, "expr into one byte is the empty string");

	/* version: the OLDEST build of the three packs; the stamp is a function of the set */
	CK(kdb_version(e, &v) == 1 && v.build == 2025010101u, "kdb_version build %u, the oldest is 2025010101", v.build);
	CK(kdb_version(e, NULL) == 0, "kdb_version(e, NULL)");
	st1 = kdb_stamp(e);
	CK(st1 != 0, "stamp of a loaded engine is zero");
	keng_close(e);
	snprintf(dir2, sizeof dir2, "%s/db2", root);
	make_db(dir2, 1);
	copy_with_build("sigs-pe.ksig", "x1.ksig", dir2, 2025010101u);      /* the same three packs under other names, so a directory walk meets them in another order */
	copy_with_build("sigs-any.ksig", "x2.ksig", dir2, 0u);
	copy_with_build("sigs-elf.ksig", "x3.ksig", dir2, 2026010101u);
	e = keng_open(dir2);
	CK(e != NULL, "second directory");
	if (e) {
		st2 = kdb_stamp(e);
		CK(st1 == st2, "the stamp depends on the order of the packs (%llx vs %llx)", (unsigned long long)st1, (unsigned long long)st2);
		keng_close(e);
	}
	copy_with_build("sigs-elf.ksig", "x3.ksig", dir2, 2026010102u);    /* one pack's build moves */
	e = keng_open(dir2);
	if (e) {
		st3 = kdb_stamp(e);
		CK(st3 != st1 && st3 != 0, "the stamp did not move when a pack's build moved");
		keng_close(e);
	}
	{
		char d3[400];

		snprintf(d3, sizeof d3, "%s/db3", root);
		make_db(d3, 1);                                         /* diagnoses and names only: no .ksig, so no pack header to stamp */
		e = keng_open(d3);
		if (e) {
			CK(kdb_stamp(e) == 0, "the stamp of an engine with no ksig pack is %llx", (unsigned long long)kdb_stamp(e));
			CK(kdb_version(e, &v) == 0 && v.build == 0, "kdb_version with no pack");
			CK(kmatch_tables(e, NULL, NULL) == -1, "no pattern table in a database of diagnoses");
			keng_close(e);
		} else {
			printf("  note: a directory of diagnoses alone does not open (db3)\n");
		}
	}
}

/* ---- memory cap and catalog ------------------------------------------------------------------------------ */

static void memory_and_catalog(void)
{
	char dir[400], path[500];
	kof_engine *e;
	struct keng_catalog_info ci;
	uint64_t used;
	uint32_t fl;

	snprintf(dir, sizeof dir, "%s/db1", root);
	e = keng_open(dir);
	if (!e) {
		CK(0, "no engine for the memory rows");
		return;
	}
	CK(keng_memory_cap(e) == KOF_ENGINE_MEM_CAP, "default cap");
	CK(keng_set_memory_cap(e, 1ull << 30) == 1 && keng_memory_cap(e) == (1ull << 30), "a valid cap is taken");
	CK(keng_set_memory_cap(e, 0) == 1 && keng_memory_cap(e) == KOF_ENGINE_MEM_CAP, "zero restores the default");
	CK(keng_set_memory_cap(e, KOF_ENGINE_MEM_MIN - 1u) == 0 && keng_memory_cap(e) == KOF_ENGINE_MEM_CAP, "below the least that works is refused and changes nothing");
	CK(keng_set_memory_cap(e, KOF_ENGINE_MEM_MIN) == 1 && keng_memory_cap(e) == KOF_ENGINE_MEM_MIN, "exactly the least that works is taken");
	CK(keng_set_memory_cap(e, 0) == 1, "back to default");
	{
		kof_scanner *many[8];
		unsigned n = 0, k;

		used = atomic_load(&e->budget->used);
		while (n < 8u && used <= KOF_ENGINE_MEM_MIN + 1u && (many[n] = kscan_new(e)) != NULL) {
			n++;
			used = atomic_load(&e->budget->used);
		}
		CK(n >= 1u, "no scanner could be made");
		CK(used > KOF_ENGINE_MEM_MIN, "%u scanners and the database hold only %llu bytes, under the least cap: the arm below what is held cannot be taken", n, (unsigned long long)used);
		CK(keng_set_memory_cap(e, used - 1u) == 0, "a cap below what is held is refused");
		CK(keng_memory_cap(e) == KOF_ENGINE_MEM_CAP, "...and changes nothing");
		CK(keng_set_memory_cap(e, used) == 1 && keng_memory_cap(e) == used, "a cap equal to what is held is taken");
		CK(keng_set_memory_cap(e, 0) == 1, "back to default");
		for (k = 0; k < n; k++)
			kscan_free(many[k]);
	}
	CK(keng_memory_peak(e) >= keng_memory_db(e), "peak below the database");

	/* the catalog: a directory that does not exist is an empty catalog; bases NULL / "" load nothing; a path too long is UNREADABLE */
	CK(keng_catalog_load(e, "build/does-not-exist-a", "build/does-not-exist-b") == 0, "missing catalog directories are an empty catalog");
	CK(keng_catalog_load(e, NULL, "") == 0 && keng_catalog_load(e, "", NULL) == 0, "NULL and empty directories are empty halves");
	CK(keng_catalog_load_bases(e, NULL) == 0 && keng_catalog_load_bases(e, "") == 0, "no bases loads nothing");
	CK(keng_catalog_load_bases(e, "build/does-not-exist") == 0, "missing bases");
	{
		char *big = malloc(5000u);

		memset(big, 'a', 4999u);
		big[4999] = 0;
		fl = keng_catalog_load_bases(e, big);
		CK((fl & KENG_CAT_UNREADABLE) != 0, "a bases path that does not fit is UNREADABLE, got %x", fl);
		keng_catalog_info(e, &ci);
		CK(ci.families == 0 && ci.variants == 0 && ci.tags == 0, "...and loaded nothing");
		free(big);
	}
	snprintf(path, sizeof path, "%s", "bases");
	fl = keng_catalog_load_bases(e, path);
	keng_catalog_info(e, &ci);
	CK(ci.flags == fl, "info flags %x are the load's %x", ci.flags, fl);
	CK(ci.families > 0 || ci.tags > 0 || ci.variants > 0 || fl != 0, "bases/ holds a catalog and nothing says it was not read");
	keng_close(e);
}

/* ---- composing a name -------------------------------------------------------------------------------------- */

static void fill(char *s, size_t n, char c)
{
	memset(s, c, n);
	s[n] = 0;
}

/* The oracle: the name kof_verdict_name must make, written from the contract in verdict.c and not from its code. */
static size_t expect_name(char *out, size_t cap, const struct kof_finding *f, const char *family, const char *reason, int *cut)
{
	char tgt[32], full[1024];
	const char *word = kof_verdict_word(f->verdict);
	size_t rest, total = sizeof f->name - 1u, room, fl = strlen(family), at;

	kverdict_target(tgt, sizeof tgt, f->fmt, f->arch);
	rest = strlen(word) + 1u + (tgt[0] ? strlen(tgt) + 1u : 0u) + strlen(kof_maltype_name(f->type)) + 1u +
	       (f->engine != (uint8_t)KOF_ENGINE_NONE ? 1u + strlen(kof_engine_name(f->engine)) : 0u) + (reason && reason[0] ? 1u + strlen(reason) : 0u);
	room = rest < total ? total - rest : 0u;
	at = (size_t)snprintf(full, sizeof full, "%s#", word);
	if (tgt[0])
		at += (size_t)snprintf(full + at, sizeof full - at, "%s/", tgt);
	at += (size_t)snprintf(full + at, sizeof full - at, "%s:", kof_maltype_name(f->type));
	if (room && fl > room) {
		memcpy(full + at, family, room);
		at += room;
		full[at] = 0;
	} else {
		at += (size_t)snprintf(full + at, sizeof full - at, "%s", family);
	}
	if (f->engine != (uint8_t)KOF_ENGINE_NONE)
		at += (size_t)snprintf(full + at, sizeof full - at, "!%s", kof_engine_name(f->engine));
	if (reason && reason[0])
		at += (size_t)snprintf(full + at, sizeof full - at, "?%s", reason);
	*cut = (room && fl > room) || at > total;
	if (at > total)
		at = total;
	if (at >= cap)
		at = cap - 1u;
	memcpy(out, full, at);
	out[at] = 0;
	return at;
}

static void compose_names(void)
{
	static const uint8_t fmts[] = { KOF_FMT_UNKNOWN, KOF_FMT_ELF, KOF_FMT_PE, KOF_FMT_SCRIPT };
	static const uint8_t engines[] = { (uint8_t)KOF_ENGINE_NONE, (uint8_t)KOF_ENGINE_DIAGNOSE };
	unsigned checked = 0, cut_seen = 0, fmt_i, eng_i, fl_, rl_;
	char fam[400], rea[400], want[sizeof ((struct kof_finding *)0)->name];

	for (fmt_i = 0; fmt_i < sizeof fmts; fmt_i++)
		for (eng_i = 0; eng_i < 2u; eng_i++)
			for (fl_ = 0; fl_ <= 300u; fl_ += (fl_ < 140u ? 1u : 7u))
				for (rl_ = 0; rl_ <= 300u; rl_ += (rl_ < 140u ? 1u : 11u)) {
					struct kof_finding f;
					int cut = 0;
					size_t n;
					const char *family, *reason;

					memset(&f, 0x55, sizeof f);
					f.verdict = (uint8_t)KOF_VERDICT_INFECTED;
					f.fmt = fmts[fmt_i];
					f.arch = fmt_i % 2u ? (uint8_t)KGENOME_ARCH_ANY : (uint8_t)1;
					f.engine = engines[eng_i];
					f.type = (uint8_t)(fl_ % 5u);
					fill(fam, fl_, 'f');
					fill(rea, rl_, 'r');
					family = fam;
					reason = rl_ ? rea : (fl_ & 1u ? NULL : "");
					kof_verdict_name(&f, family, reason);
					n = expect_name(want, sizeof want, &f, family, reason, &cut);
					checked++;
					cut_seen += (unsigned)cut;
					CK(strlen(f.name) == n && !strcmp(f.name, want), "fmt %u eng %u family %u reason %u: name\n    got  %s\n    want %s", fmt_i, eng_i, fl_, rl_, f.name, want);
					CK(!!f.name_cut == !!cut, "fmt %u eng %u family %u reason %u: name_cut %d, expected %d", fmt_i, eng_i, fl_, rl_, f.name_cut, cut);
					CK(f.family.at + f.family.n <= strlen(f.name) && f.maltype.at + f.maltype.n <= strlen(f.name) && f.reason.at + f.reason.n <= strlen(f.name),
					   "a span lies outside the name");
					if (failures > 20)
						return;
				}
	CK(cut_seen > 100u && cut_seen < checked, "the sweep cut %u of %u names: it does not cross the boundary both ways", cut_seen, checked);
	kof_verdict_name(NULL, "a", "b");           /* NULL finding: nothing */
	{
		struct kof_finding f;

		memset(&f, 0, sizeof f);
		f.verdict = (uint8_t)KOF_VERDICT_INFECTED;
		f.type = (uint8_t)KOF_MALTYPE_COUNT;
		kof_verdict_name(&f, NULL, NULL);       /* a NULL family is an empty one; a type nobody names reads "Malware" */
		CK(strstr(f.name, "Malware:") != NULL, "type out of range does not read Malware: %s", f.name);
	}
	printf("  %u names composed, %u cut, every one equal to the oracle\n", checked, cut_seen);
}

static void compose_verdicts(void)
{
	struct kof_finding f;
	struct kof_verdict_in in;
	struct kof_verdict_disease d[4];
	uint32_t diag[200], i;
	char label[16];
	struct kof_verdict_cat cat;

	/* the lead: more parts, then the lower type, then the lower id; in every order of the input */
	d[0] = (struct kof_verdict_disease){ 10, 3, "a/b" };
	d[1] = (struct kof_verdict_disease){ 11, 1, "x" };
	d[2] = (struct kof_verdict_disease){ 12, 2, "a/b" };
	d[3] = (struct kof_verdict_disease){ 9, 2, "a/b" };
	for (i = 0; i < 24u; i++) {
		static const unsigned perm[24][4] = {
			{0,1,2,3},{0,1,3,2},{0,2,1,3},{0,2,3,1},{0,3,1,2},{0,3,2,1},{1,0,2,3},{1,0,3,2},{1,2,0,3},{1,2,3,0},{1,3,0,2},{1,3,2,0},
			{2,0,1,3},{2,0,3,1},{2,1,0,3},{2,1,3,0},{2,3,0,1},{2,3,1,0},{3,0,1,2},{3,0,2,1},{3,1,0,2},{3,1,2,0},{3,2,0,1},{3,2,1,0} };
		struct kof_verdict_disease p[4];

		for (unsigned j = 0; j < 4u; j++)
			p[j] = d[perm[i][j]];
		memset(&in, 0, sizeof in);
		in.dis = p;
		in.n_dis = 4;
		kof_verdict_make(&in, &f);
		CK(f.type == 2 && strstr(f.name, ":a.b") != NULL, "permutation %u: lead is %s", i, f.name);
		CK(f.disease[0] == p[0].id && f.disease_total == 4u && f.n_disease == 4u, "permutation %u: the trace keeps the order of the input", i);
		CK(f.engine == (uint8_t)KOF_ENGINE_NONE, "no diagnose: engine none");
	}
	/* the other types are the reason; a disease with no name is "unnamed" and typed by its own type; a type out of range is Malware and not a reason */
	d[0] = (struct kof_verdict_disease){ 1, 1, NULL };
	d[1] = (struct kof_verdict_disease){ 2, 3, "" };
	d[2] = (struct kof_verdict_disease){ 3, 200, "q" };
	memset(&in, 0, sizeof in);
	in.dis = d;
	in.n_dis = 3;
	kof_verdict_make(&in, &f);
	CK(strstr(f.name, "unnamed") != NULL || strstr(f.name, ":q") != NULL, "name %s", f.name);
	kof_verdict_make(&(struct kof_verdict_in){ 0 }, &f);
	CK(strstr(f.name, "unnamed") != NULL && f.type == (uint8_t)KOF_MALTYPE_COUNT, "no diseases at all reads unnamed Malware: %s", f.name);
	/* one disease whose name is empty: "unnamed", typed by its own type */
	{
		struct kof_verdict_disease one = { 5, 2, "" };

		memset(&in, 0, sizeof in);
		in.dis = &one;
		in.n_dis = 1;
		kof_verdict_make(&in, &f);
		CK(f.type == 2 && strstr(f.name, ":unnamed") != NULL, "an empty behaviour name reads unnamed: %s", f.name);
	}
	/* every type at once: the reason is cut where its buffer ends and the name is still terminated */
	{
		struct kof_verdict_disease all[KOF_MALTYPE_COUNT + 1u];

		for (i = 0; i < (uint32_t)KOF_MALTYPE_COUNT; i++)
			all[i] = (struct kof_verdict_disease){ i + 1u, (uint8_t)i, "b" };
		memset(&in, 0, sizeof in);
		in.dis = all;
		in.n_dis = KOF_MALTYPE_COUNT;
		kof_verdict_make(&in, &f);
		CK(strchr(f.name, '?') != NULL && strlen(f.name) < sizeof f.name, "a name with every other type: %s", f.name);
	}
	/* the trace is bounded with its true total beside it */
	for (i = 0; i < 200u; i++)
		diag[i] = 1000u + i;
	memset(&in, 0, sizeof in);
	in.dis = d;
	in.n_dis = 1;
	in.diag = diag;
	in.n_diag = 200;
	kof_verdict_make(&in, &f);
	CK(f.diag_total == 200u && f.n_diag == KOF_VERDICT_TRACE && f.diag[KOF_VERDICT_TRACE - 1u] == 1000u + KOF_VERDICT_TRACE - 1u, "trace bounded: %u of %u", f.n_diag, f.diag_total);
	CK(f.engine == (uint8_t)KOF_ENGINE_DIAGNOSE && strstr(f.name, "!Diagnose") != NULL, "a verdict made of diagnoses says so: %s", f.name);

	/* the catalog verdict: the tag level and the variant level, a type out of range, other types excluding the lead's own */
	memset(&cat, 0, sizeof cat);
	cat.level = KOF_VCAT_TAG;
	cat.type = 1;
	cat.tag_id = 0x5d1c0e7900000000ull;
	cat.other_types = (1u << 1) | (1u << 2);
	memset(&in, 0, sizeof in);
	in.fmt = KOF_FMT_ELF;
	kof_verdict_make_cat(&in, &cat, NULL, &f);
	CK(strstr(f.name, "T5d1c0e79") != NULL && strstr(f.name, "?") != NULL && f.type == 1, "tag level: %s", f.name);
	cat.level = KOF_VCAT_VARIANT;
	cat.family_id = 0x8f3a51c200000000ull;
	cat.variant_id = 0x2c61b7e000000000ull;
	cat.type = (uint8_t)(KOF_MALTYPE_COUNT + 3u);
	cat.other_types = 0;
	kof_verdict_make_cat(&in, &cat, NULL, &f);
	CK(strstr(f.name, "F8f3a51c2.V2c61b7e0") != NULL && f.type == (uint8_t)KOF_MALTYPE_COUNT && strchr(f.name, '?') == NULL, "variant level: %s", f.name);

	/* what to call an object, and its target */
	kof_object_label(0, "UPX", KOF_FMT_ELF, 0, label, sizeof label);
	CK(!strcmp(label, "UPX"), "packer first");
	kof_object_label(KOF_ENT_NORMALIZED, "", KOF_FMT_ELF, 0, label, sizeof label);
	CK(!strcmp(label, "Norm"), "normalised view");
	kof_object_label(0, NULL, KOF_FMT_SCRIPT, 1, label, sizeof label);
	CK(strcmp(label, "Norm") != 0 && label[0], "script language");
	kof_object_label(0, "Longer-than-two", KOF_FMT_PE, 0, label, 4u);
	CK(strlen(label) == 3u && !strncmp(label, "Lon", 3), "label cut to its buffer");
	kof_object_label(0, NULL, KOF_FMT_PE, 0, NULL, 4u);
	kof_object_label(0, NULL, KOF_FMT_PE, 0, label, 0u);
	{
		char t[32];

		kverdict_target(t, sizeof t, KOF_FMT_UNKNOWN, 1);
		CK(strchr(t, '-') == NULL, "an unknown format has no arch: %s", t);
		kverdict_target(t, sizeof t, KOF_FMT_ELF, (uint8_t)KGENOME_ARCH_ANY);
		CK(strchr(t, '-') == NULL, "no arch to name: %s", t);
		kverdict_target(t, sizeof t, KOF_FMT_ELF, 1);
		CK(strchr(t, '-') != NULL, "format and arch: %s", t);
	}
}

/* ---- kdet_* over a result written by hand --------------------------------------------------------------- */

static void detect_edges(void)
{
	char dir[400];
	kof_engine *e;
	struct kof_result r;
	struct kdet_info inf;
	struct kdet_diag dg;
	uint32_t ids[NFORMS];
	uint8_t obj[BLK];
	kof_scanner *sc;
	kdet_run *run;
	struct kof_scan_option base;

	snprintf(dir, sizeof dir, "%s/db1", root);
	e = keng_open(dir);
	if (!e) {
		CK(0, "no engine for kdet");
		return;
	}
	collect_ids(e, ids, NFORMS);
	memset(&r, 0, sizeof r);
	kdet_info(e, NULL, &inf);
	CK(inf.has_verdict == 0 && inf.verdict == NULL, "no result, no verdict");
	kdet_info(e, &r, &inf);
	CK(inf.has_verdict == 0, "a result with no verdict");
	r.has_verdict = 1;
	r.verdict_incomplete = 1;
	snprintf(r.verdict.name, sizeof r.verdict.name, "Infected#X");
	r.verdict.n_diag = 2;
	r.verdict.diag_total = 9;
	r.verdict.diag[0] = ids[0];
	r.verdict.diag[1] = 0xFFFFFFF0u;
	kdet_info(e, &r, &inf);
	CK(inf.has_verdict == 1 && inf.incomplete == 1 && !strcmp(inf.verdict, "Infected#X") && inf.n_diag == 2u && inf.diag_total == 9u && inf.level == 0, "verdict without a catalog level");
	r.cat.level = KOF_VCAT_VARIANT;
	r.cat.cover = 7;
	r.cat.jaccard = 8;
	r.cat.n_groups = 3;
	r.cat.n_fired = 2;
	r.cat.cut = 1;
	r.cat.family_id = 0x1111111100000000ull;
	kdet_info(e, &r, &inf);
	CK(inf.level == KOF_VCAT_VARIANT && inf.cover == 7u && inf.jaccard == 8u && inf.groups == 3u && inf.fired == 2u && inf.cut == 1 && !strcmp(inf.family, "11111111"), "catalog level fields");
	CK(kdet_diag(e, &r, 0, &dg) == 1 && dg.name && dg.kind == KDET_KIND_FORM && dg.has_form && dg.expr[0], "diag 0 is a held form diagnose");
	CK(kdet_diag(e, &r, 1, &dg) == 1 && dg.name == NULL && dg.kind == 0 && !dg.has_form, "diag 1 is listed by the verdict and not held");
	CK(kdet_diag(e, &r, 2, &dg) == 0 && dg.id == 0, "an index past the list answers 0 and clears the out");
	CK(kdet_diag(e, NULL, 0, &dg) == 0, "no result");
	r.has_verdict = 0;
	CK(kdet_diag(e, &r, 0, &dg) == 0, "no verdict, no diagnoses");
	CK(kdet_diag_of(e, 0xFFFFFFF0u, &dg) == 0 && dg.name == NULL, "an id not held");
	CK(kdet_diag_of(e, ids[2], &dg) == 1 && dg.has_form && dg.form.blocks >= 1u && dg.has_catalog == 0, "a held id");

	/* explain: arguments */
	sc = kscan_new(e);
	make_bytes(obj, seed_of(1u, 0u));
	CK(kscan_explain(sc, NULL, BLK, "n", NULL) == NULL && kscan_explain(sc, obj, BLK, NULL, NULL) == NULL, "explain refuses missing bytes or a missing name");
	memset(&base, 0, sizeof base);
	base.max_object_bytes = 64u << 20;
	run = kscan_explain(sc, obj, BLK, "root", &base);
	CK(run != NULL && kdet_run_count(run) >= 1u && kdet_run_status(run) == 0, "explain with a base option");
	if (run) {
		const struct kdet_object *o = kdet_run_at(run, 0);

		CK(o && !strcmp(o->name, "root") && o->res.n_diag == NFORMS, "the report holds one row per diagnose: %u", o ? o->res.n_diag : 0u);
		CK(kdet_run_at(run, kdet_run_count(run)) == NULL && kdet_run_at(run, 0xFFFFFFFFu) == NULL, "kdet_run_at past the end");
		CK(kdet_run_find(run, "root") == o && kdet_run_find(run, "nope") == NULL && kdet_run_find(run, NULL) == NULL, "kdet_run_find");
		kdet_run_free(run);
	}
	/* a scan that fails outright is said in the run's status: a zero-byte object, and a name too long for the walk */
	run = kscan_explain(sc, obj, 0u, "empty", NULL);
	CK(run != NULL, "explaining nothing still answers a run");
	if (run) {
		CK(kdet_run_count(run) > 0u || (kdet_run_status(run) & KDET_RUN_SCAN_ERR) != 0u, "a scan that delivered nothing and failed says so in the status (%u)", kdet_run_status(run));
		kdet_run_free(run);
	}
	kscan_free(sc);
	keng_close(e);
}

/* ---- the whole test database: pattern tables, graph diagnoses, an object with many children -------------------------------------- */

static void whole_db_edges(void)
{
	kof_engine *e = keng_open(dbdir);
	kof_scanner *sc;
	kdet_run *run;
	uint8_t obj[BLK];
	uint64_t bytes = 0;
	uint32_t chain = 0, i;
	struct kdet_diag dg;
	int graph_seen = 0;
	char cmd[2048], tarp[500], dir[500], dbu[500];
	kof_engine *eu;
	kof_scanner *su;
	uint8_t *tb;
	size_t tn = 0;

	if (!e) {
		CK(0, "the whole test database does not open");
		return;
	}
	/* a database with pattern markers: kmatch_tables answers 0 and fills what it was given, and takes NULL outputs */
	CK(kmatch_tables(e, &bytes, &chain) == 0 && bytes > 0u, "kmatch_tables of a database with markers: bytes %llu", (unsigned long long)bytes);
	CK(kmatch_tables(e, NULL, &chain) == 0 && kmatch_tables(e, &bytes, NULL) == 0 && kmatch_tables(e, NULL, NULL) == 0, "kmatch_tables with some outputs missing");
	/* a graph diagnose (no form): kdet_diag_of says so */
	sc = kscan_new(e);
	make_bytes(obj, seed_of(5u, 0u));
	run = kscan_explain(sc, obj, BLK, "g", NULL);
	if (run && kdet_run_at(run, 0))
		for (i = 0; i < kdet_run_at(run, 0)->res.n_diag; i++)
			if (!kdet_run_at(run, 0)->res.diag[i].form) {
				CK(kdet_diag_of(e, kdet_run_at(run, 0)->res.diag[i].id, &dg) == 1 && dg.kind == KDET_KIND_GRAPH && !dg.has_form, "a graph diagnose is KDET_KIND_GRAPH");
				graph_seen = 1;
				break;
			}
	CK(graph_seen, "the whole test database holds no graph diagnose to ask about");
	kdet_run_free(run);
	/* an object with 20 children: the run's tables grow past their first 16 */
	snprintf(dir, sizeof dir, "%s/many", root);
	kof_mkdir(dir, 0700);
	for (i = 0; i < 20u; i++) {
		char f[600];

		snprintf(f, sizeof f, "%s/m%02u.txt", dir, i);
		(void)write_file(f, "hello world\n", 12u);
	}
	snprintf(tarp, sizeof tarp, "%s/many.tar", root);
	snprintf(cmd, sizeof cmd, "tar -C %s -cf %s .", dir, tarp);
	CK(system(cmd) == 0, "tar of 20 files");
	tb = read_file(tarp, &tn);
	/* the release unpackers open a tar */
	snprintf(dbu, sizeof dbu, "%s/dbu", root);
	kof_mkdir(dbu, 0700);
	{
		static const char *const unp[] = { "unpack-archive.ksig", "unpack-raw.ksig", "unpack-raw-x7.ksig" };

		for (i = 0; i < 3u; i++)
			CK(copy_pack("build/release/databases", unp[i], dbu), "copy %s", unp[i]);
	}
	eu = keng_open(dbu);
	su = eu ? kscan_new(eu) : NULL;
	run = tb && su ? kscan_explain(su, tb, tn, "many.tar", NULL) : NULL;
	CK(run && kdet_run_count(run) >= 17u, "explain of a tar of 20 files returned %u objects", run ? kdet_run_count(run) : 0u);
	if (run)
		for (i = 0; i < kdet_run_count(run); i++)
			CK(kdet_run_find(run, kdet_run_at(run, i)->name) == kdet_run_at(run, i), "object %u is not found by its name", i);
	kdet_run_free(run);
	kscan_free(su);
	keng_close(eu);
	free(tb);
	/* a path with no options is the conservative walk: a file is scanned, a directory is not descended */
	{
		kof_scanner *mt[1];
		int rc;

		mt[0] = sc;
		rc = kscan_path_mt(mt, 1u, tarp, NULL, NULL, NULL);
		CK(rc >= 1, "kscan_path_mt with no options on a file: %d", rc);
	}
	kscan_free(sc);
	keng_close(e);
}

/* ---- the file map ---------------------------------------------------------------------------------------- */

static void filemap_edges(void)
{
	kverdict_filemap *m = kverdict_filemap_new();
	struct kof_result res;
	struct kverdict_file *f;
	char name[64];
	unsigned i;

	CK(m != NULL, "new");
	CK(kverdict_filemap_count(NULL) == 0 && kverdict_filemap_at(NULL, 0) == NULL && kverdict_filemap_files(NULL) == 0 && kverdict_filemap_find(NULL, "a", 1) == NULL, "NULL map");
	CK(kverdict_filemap_find(m, "a", 1) == NULL, "find in an empty map (no index yet)");
	kverdict_filemap_free(NULL);
	memset(&res, 0, sizeof res);
	res.examined = 1;
	CK(kverdict_filemap_fold(NULL, "a", &res, 1) == NULL && kverdict_filemap_fold(m, NULL, &res, 1) == NULL && kverdict_filemap_fold(m, "a", NULL, 1) == NULL, "fold refuses missing arguments");
	CK(kverdict_filemap_fold(m, "clean.bin", &res, 0) == NULL, "a clean examined object keeps no entry");
	CK(kverdict_filemap_files(m) == 1u && kverdict_filemap_count(m) == 0u, "...but is counted as a file");
	CK((f = kverdict_filemap_fold(m, "kept.bin", &res, 1)) != NULL && !strcmp(f->file, "kept.bin") && f->examined == 1, "keep_clean makes an entry");
	res.examined = 0;
	CK((f = kverdict_filemap_fold(m, "unexamined.bin", &res, 0)) != NULL && f->examined == 0, "an object no module was eligible for is not clean");
	res.examined = 1;
	res.broken = KOF_BROKEN_ENCRYPTED;
	CK((f = kverdict_filemap_fold(m, "pw.zip//1:m", &res, 0)) != NULL && !strcmp(f->file, "pw.zip") && f->broken == KOF_BROKEN_ENCRYPTED, "a member rolls up into its file");
	res.broken = KOF_BROKEN_LIMIT;
	CK((f = kverdict_filemap_fold(m, "pw.zip//2:m", &res, 0)) != NULL && f->broken == KOF_BROKEN_ENCRYPTED, "the FIRST broken reason is kept");
	CK(kverdict_filemap_files(m) == 3u, "members are not counted as files: %llu", (unsigned long long)kverdict_filemap_files(m));
	/* a verdict: the first one of a file's tree names it; a later one does not replace it; the name is bounded by the array it lives in */
	memset(&res, 0, sizeof res);
	res.has_verdict = 1;
	res.examined = 1;
	memset(res.verdict.name, 'v', sizeof res.verdict.name);       /* NOT terminated: a finding handed in from elsewhere */
	CK((f = kverdict_filemap_fold(m, "bad.exe", &res, 0)) != NULL && f->has_verdict && strlen(f->name) < sizeof f->name, "an unterminated verdict name is bounded");
	snprintf(res.verdict.name, sizeof res.verdict.name, "Infected#Other");
	CK((f = kverdict_filemap_fold(m, "bad.exe//1:x", &res, 0)) != NULL && f->name[0] == 'v', "the first verdict of the tree stays");
	/* growth past both tables (index 256, entries 128) and every entry findable and in first-seen order */
	for (i = 0; i < 1500u; i++) {
		memset(&res, 0, sizeof res);
		res.broken = KOF_BROKEN_DAMAGED;
		snprintf(name, sizeof name, "many/%u.bin", i);
		CK(kverdict_filemap_fold(m, name, &res, 0) != NULL, "fold %u", i);
	}
	for (i = 0; i < 1500u; i++) {
		snprintf(name, sizeof name, "many/%u.bin", i);
		f = kverdict_filemap_find(m, name, strlen(name));
		CK(f != NULL && !strcmp(f->file, name) && f->broken == KOF_BROKEN_DAMAGED, "find %u", i);
		if (failures > 10)
			break;
	}
	CK(kverdict_filemap_of_file(m, "many/7.bin") == kverdict_filemap_find(m, "many/7.bin", 10) && kverdict_filemap_of_file(m, "many/7.bin") != NULL, "of_file: a top-level name");
	CK(kverdict_filemap_of_file(m, "bad.exe//1:x") == NULL && kverdict_filemap_of_file(m, NULL) == NULL && kverdict_filemap_of_file(NULL, "bad.exe") == NULL
	   && kverdict_filemap_of_file(m, "nothing.bin") == NULL, "of_file: a child, NULL name, NULL map, an unknown file");
	CK(kverdict_filemap_find(m, "many/1.bi", 9) == NULL && kverdict_filemap_find(m, "many/1.binx", 11) == NULL, "a prefix and an extension are not the file");
	CK(kverdict_filemap_count(m) == 1504u, "count %zu", kverdict_filemap_count(m));
	CK(!strcmp(kverdict_filemap_at(m, 0)->file, "kept.bin") && !strcmp(kverdict_filemap_at(m, 1)->file, "unexamined.bin"), "first-seen order");
	CK(kverdict_filemap_at(m, kverdict_filemap_count(m)) == NULL, "at past the end");
	kverdict_filemap_free(m);
}

int main(void)
{
	if (access(dbdir, X_OK) != 0) {
		printf("api_edges: %s is not built\n", dbdir);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_apiedges_XXXXXX");
	if (!mkdtemp(root)) {
		printf("api_edges: cannot make a scratch directory\n");
		return 2;
	}
	null_matrix();
	engine_edges();
	memory_and_catalog();
	compose_names();
	compose_verdicts();
	detect_edges();
	whole_db_edges();
	filemap_edges();
	if (!failures)
		rm_all(root);
	if (failures) {
		printf("api_edges: %d FAIL\n", failures);
		return 1;
	}
	printf("api_edges: ok\n");
	return 0;
}
