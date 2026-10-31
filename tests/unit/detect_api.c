/*
 * detect_api - the pull API of the detection (kofeng.h, kdet_*): what the verdict is made of, and why each diagnose matched.
 *
 * The chain under test: ksigbuilder builds a pack of detection forms (strings and a similarity block, with diseases so the
 * verdict reads them); the engine scans a sample twice - a plain scan (the callback carries the verdict and no report) and
 * kscan_explain (the same scan with the report, asked for) - and the API must answer from the same pipeline.
 *
 * WHAT IS PINNED
 *   no push     a plain scan delivers no report (n_diag 0): nothing is computed for a question nobody asked
 *   same answer the verdict kscan_explain returns for the object is the plain scan's, byte for byte
 *   facts       kdet_info / kdet_diag name the verdict and each matched diagnose (name, id, disease, form, expression)
 *   why         a string matcher records how many markers were found, a similarity matcher the percentage against what was
 *               demanded, a matcher the expression's short circuit never asked says NOT_ASKED, a miss says NO
 *   two diagnoses  both are listed, each with its own matchers
 *   no match    a clean sample: no verdict, kdet_info empty, every matcher NO / NOT_ASKED
 *   absent      an object the scan did not report is NULL; NULL and empty arguments answer NULL / 0
 *
 * Why the old tests missed it: (a) the API did not exist (kdet_* undefined: RED by not linking on the old tree).
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/databases/pack/diagform.h"
#include "../../libkofeng/databases/pack/hexprog.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include <kofmod/kofdiagtree.h>
#include <celllysis/mutation.h>
#include <kofmod/kofsig.h>
#include <stdatomic.h>
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/scanners/scan.h"

static int failures;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";
static const char *builder = "build/release/bin/ksigbuilder";

#define OKF(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

static int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static uint8_t *read_file(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
	long L;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	L = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = malloc((size_t)L + 1u);
	if (b && fread(b, 1, (size_t)L, f) != (size_t)L) {
		free(b);
		b = NULL;
	}
	fclose(f);
	if (b)
		*n = (size_t)L;
	return b;
}


static int copy_pack(const char *from_dir, const char *leaf, const char *to_dir)
{
	char a[700], b[700];
	size_t n = 0;
	uint8_t *p;
	int r;

	snprintf(a, sizeof a, "%s/%s", from_dir, leaf);
	snprintf(b, sizeof b, "%s/%s", to_dir, leaf);
	p = read_file(a, &n);
	r = p && n && write_file(b, p, n);
	free(p);
	return r;
}

/* ---- a database of diagnoses, built by the real builder -------------------------- */

struct scene {
	char base[400], art[400], db[400], err[400];
};

static void scene_new_with(struct scene *s, const char *tag, const char *pack)
{
	char d[500];

	snprintf(s->base, sizeof s->base, "%s/%s_base", root, tag);
	snprintf(s->art, sizeof s->art, "%s/%s_art", root, tag);
	snprintf(s->db, sizeof s->db, "%s/%s_db", root, tag);
	snprintf(s->err, sizeof s->err, "%s/%s_err.txt", root, tag);
	kof_mkdir(s->base, 0700);
	kof_mkdir(s->art, 0700);
	kof_mkdir(s->db, 0700);
	snprintf(d, sizeof d, "%s/diagnoses", s->base);
	kof_mkdir(d, 0700);
	(void)copy_pack(dbdir, pack, s->db);
}

static void scene_new(struct scene *s, const char *tag)
{
	scene_new_with(s, tag, "sigs-any.ksig");
}

/* One diagnose source: <name>.c in the base's diagnoses directory. */
static void scene_src(struct scene *s, const char *name, const char *text)
{
	char p[700];

	snprintf(p, sizeof p, "%s/diagnoses/%s.c", s->base, name);
	(void)write_file(p, text, strlen(text));
}

/* The tree build. 0: built. */
static int scene_build(struct scene *s)
{
	char cmd[2400];

	snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --basedir '%s' >/dev/null 2>'%s'", builder, s->base, s->art, s->db,
		 s->base, s->err);
	return system(cmd);
}




#define BLK 2048u

static void make_bytes(uint8_t *b, uint32_t seed)
{
	uint32_t i;

	for (i = 0; i < BLK; i++) {
		seed ^= seed << 13;
		seed ^= seed >> 17;
		seed ^= seed << 5;
		b[i] = (uint8_t)seed;
	}
}

static size_t block_text(char *out, size_t cap, const char *name, uint32_t seed)
{
	uint8_t b[BLK];
	uint32_t h[KOF_MUTATION_MAX_HASH], n, i;
	size_t at;

	make_bytes(b, seed);
	n = kgenome_mutation_minhash(b, BLK, h);
	at = (size_t)snprintf(out, cap, "KOF_MUTATION_BLOCK(%s, KOF_SCAN_ALL", name);
	for (i = 0; i < n; i++)
		at += (size_t)snprintf(out + at, cap - at, ", 0x%08xu", (unsigned)h[i]);
	at += (size_t)snprintf(out + at, cap - at, ");\n");
	return at;
}

static const char *const strs =
	"KOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
	"KOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
	"KOF_DEFINE_STR(beta, \"beta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
	"KOF_DEFINE_STR(zeta, \"zeta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n";

struct take {
	int n_report;               /* res->n_diag of the object */
	int has_verdict;
	char verdict[240];
};

static int plain_cb(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct take *t = user;

	(void)name; (void)bytes; (void)len;
	if (res->n_diag)
		t->n_report++;
	if (res->has_verdict && !t->has_verdict) {
		t->has_verdict = 1;
		snprintf(t->verdict, sizeof t->verdict, "%s", res->verdict.name);
	}
	return 0;
}

static const struct kof_diag_report *rep_of(const struct kdet_object *o, const char *name)
{
	uint32_t i;

	for (i = 0; o && i < o->res.n_diag; i++)
		if (o->res.diag[i].name && !strcmp(o->res.diag[i].name, name))
			return &o->res.diag[i];
	return NULL;
}

static void run_all(void)
{
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	uint8_t sample[BLK + 32], clean[BLK];
	char text[8000];
	size_t at;
	struct take plain;
	struct kof_scan_option opt;
	kdet_run *run;
	const struct kdet_object *o;
	const struct kof_diag_report *r;
	struct kdet_info in;
	struct kdet_diag d;

	scene_new(&sc, "det");
	scene_src(&sc, "d_str", "KOF_DIAG_NAME(d_str);\nKOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, \"strings/a\");\n"
		  "KOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\nKOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DEFINE_STR(beta, \"beta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DIAG_FIND(m0, KOF_FIND_ALL, whole, alpha, beta);\n");
	/* a miss, and a matcher the short circuit never asks: zeta is absent, so m1 (alpha) is not needed */
	scene_src(&sc, "d_short", "KOF_DIAG_NAME(d_short);\nKOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, \"strings/b\");\n"
		  "KOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\nKOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DEFINE_STR(zeta, \"zeta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, zeta);\nKOF_DIAG_FIND(m1, KOF_FIND_ANY, whole, alpha);\n"
		  "KOF_DIAG_EXPR(m0 && m1);\n");
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(d_sim);\nKOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, \"blocks/a\");\n");
	at += block_text(text + at, sizeof text - at, "ba", 0xA11CE5u);
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 60, ba);\n");
	scene_src(&sc, "d_sim", text);
	/* a marker AT an offset: the matcher's answer is the place, so it lists no part */
	scene_src(&sc, "d_at", "KOF_DIAG_NAME(d_at);\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\nKOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, 2048), alpha);\n");
	/* two matchers of ten markers each, one present: twenty parts, sixteen listed, the true count said */
	{
		char big[3000];
		size_t bo = 0;
		int q;

		bo += (size_t)snprintf(big + bo, sizeof big - bo, "KOF_DIAG_NAME(d_many);\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
				      "KOF_DEFINE_STR(a0, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n");
		for (q = 1; q < 10; q++)
			bo += (size_t)snprintf(big + bo, sizeof big - bo, "KOF_DEFINE_STR(a%d, \"zz%d\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n", q, q);
		for (q = 0; q < 2; q++) {
			int k;

			bo += (size_t)snprintf(big + bo, sizeof big - bo, "KOF_DIAG_FIND(m%d, KOF_FIND_ANY, whole, a0", q);
			for (k = 1; k < 10; k++)
				bo += (size_t)snprintf(big + bo, sizeof big - bo, ", a%d", k);
			bo += (size_t)snprintf(big + bo, sizeof big - bo, ");\n");
		}
		scene_src(&sc, "d_many", big);
	}
	OKF(scene_build(&sc) == 0, "the sources build");
	(void)strs;
	eng = keng_open(sc.db);
	if (!eng) {
		OKF(0, "the database does not open");
		return;
	}
	OKF(kdb_diagnoses(eng) == 5u, "five diagnoses loaded (%u)", kdb_diagnoses(eng));
	scn = kscan_new(eng);
	make_bytes(sample, 0xA11CE5u);
	memcpy(sample + BLK, "alpha beta ", 11);
	make_bytes(clean, 0x5EED5u);
	memset(&opt, 0, sizeof opt);

	/* PLAIN SCAN: a verdict and no report. */
	memset(&plain, 0, sizeof plain);
	kscan_bytes(scn, sample, sizeof sample, "sample", &opt, plain_cb, &plain);
	OKF(plain.has_verdict, "the plain scan has a verdict");
	OKF(plain.n_report == 0, "a plain scan pushes no report (%d objects carried one)", plain.n_report);

	/* THE PULL: the same scan with the report. */
	run = kscan_explain(scn, sample, sizeof sample, "sample", NULL);
	OKF(run && kdet_run_count(run) >= 1u, "the run holds the object");
	OKF(run && kdet_run_status(run) == 0u, "the run is complete");
	o = kdet_run_find(run, "sample");
	OKF(o != NULL, "the root object is in the run");
	if (o) {
		OKF(o->res.has_verdict && !strcmp(o->res.verdict.name, plain.verdict), "same verdict as the plain scan: '%s' vs '%s'",
		    o->res.verdict.name, plain.verdict);
		kdet_info(eng, &o->res, &in);
		OKF(in.has_verdict && in.verdict && !strcmp(in.verdict, plain.verdict), "kdet_info names the verdict");
		OKF(in.n_diag == 2u, "two diagnoses matched, the verdict lists them (%u)", (unsigned)in.n_diag);
		OKF(kdet_diag(eng, &o->res, 0, &d) && d.name && d.has_form && d.expr[0] && d.disease, "kdet_diag: name, form, expression, disease");
		OKF(!kdet_diag(eng, &o->res, 9, &d) && d.name == NULL, "kdet_diag past the list answers 0 and clears the row");
		OKF(o->res.n_diag == 5u, "the report holds all five diagnoses (%u)", (unsigned)o->res.n_diag);
		r = rep_of(o, "d_str");
		OKF(r && r->state == KOF_DIAG_ST_MATCH && r->form && r->n_match_total == 1u, "d_str matched, one matcher");
		OKF(r && r->match[0].kind == KDET_M_FIND && r->match[0].result == KDET_M_YES && r->match[0].n == 2u && r->match[0].found == 2u,
		    "d_str: 2 of 2 markers found");
		/* THE THIRD LEVEL: the markers and blocks of a matched form, and where they are */
		if (r) {
			char t[240];

			OKF(r->n_part == 2u && r->n_part_total == 2u, "d_str lists its two markers (%u/%u)", (unsigned)r->n_part, (unsigned)r->n_part_total);
			OKF(r->part[0].kind == KDET_P_MARKER && r->part[0].hit && r->part[0].place && r->part[0].off == BLK && r->part[0].plen == 5u && r->part[0].n == 5u,
			    "marker alpha: found at %llu (%u bytes)", (unsigned long long)r->part[0].off, (unsigned)r->part[0].n);
			OKF(r->part[1].kind == KDET_P_MARKER && r->part[1].hit && r->part[1].place && r->part[1].off == BLK + 6u && r->part[1].plen == 4u,
			    "marker beta: found at %llu", (unsigned long long)r->part[1].off);
			OKF(r->part[0].id != r->part[1].id, "the two markers have their own index");
			OKF(kdet_part_text(&r->part[0], t, sizeof t) == 1 && strstr(t, "marker") && strstr(t, "found at 0x800 (5 bytes)"), "marker words: '%s'", t);
		}
		r = rep_of(o, "d_at");
		OKF(r && r->state == KOF_DIAG_ST_MATCH && r->n_part == 0u && r->n_part_total == 0u, "an AT marker matched and lists no part (%u)", r ? (unsigned)r->n_part : 99u);
		r = rep_of(o, "d_many");
		OKF(r && r->state == KOF_DIAG_ST_MATCH && r->n_part == KOF_DIAG_REPORT_PARTS && r->n_part_total == 20u,
		    "twenty markers: sixteen listed, the count says twenty (%u/%u)", r ? (unsigned)r->n_part : 0u, r ? (unsigned)r->n_part_total : 0u);
		OKF(r && r->part[0].hit && !r->part[1].hit && !r->part[1].place, "the present marker is hit and the absent one is not");
		r = rep_of(o, "d_short");
		OKF(r && r->n_part == 0u && r->n_part_total == 0u, "a form that did not match lists no parts (%u)", r ? (unsigned)r->n_part : 99u);
		OKF(r && r->state == KOF_DIAG_ST_SEEN && r->n_match_total == 2u, "d_short did not match");
		OKF(r && r->match[0].result == KDET_M_NO && r->match[0].found == 0, "d_short: zeta not found");
		OKF(r && r->match[1].result == KDET_M_NOT_ASKED, "d_short: the matcher the short circuit skipped is NOT_ASKED (%d)", r ? r->match[1].result : -1);
		r = rep_of(o, "d_sim");
		OKF(r && r->state == KOF_DIAG_ST_MATCH, "d_sim matched");
		OKF(r && r->n_part == 1u && r->part[0].kind == KDET_P_BLOCK && r->part[0].hit && r->part[0].n >= 1u && r->part[0].matched == r->part[0].n &&
		    r->part[0].pct >= 60u, "d_sim lists its block: holds %u of %u hashes", r ? (unsigned)r->part[0].matched : 0u, r ? (unsigned)r->part[0].n : 0u);
		OKF(r && r->part[0].place && r->part[0].off < BLK && r->part[0].plen >= 1u && r->part[0].place_hits >= 1u,
		    "d_sim's block has a place inside the object (%llu +%llu holds %u)", r ? (unsigned long long)r->part[0].off : 0ull,
		    r ? (unsigned long long)r->part[0].plen : 0ull, r ? (unsigned)r->part[0].place_hits : 0u);
		if (r) {
			char t[240];

			OKF(kdet_part_text(&r->part[0], t, sizeof t) == 1 && strstr(t, "block ") && strstr(t, " yes: holds ") && strstr(t, "place 0 +"), "block words: '%s'", t);
			OKF(kdet_part_text(NULL, t, sizeof t) == 0 && t[0] == 0 && kdet_part_text(&r->part[0], NULL, 5) == 0, "NULL part / no room");
		}
		OKF(r && r->match[0].kind == KDET_M_SIMILAR && r->match[0].result == KDET_M_YES && r->match[0].need == 60u && r->match[0].pct >= 60u,
		    "d_sim: %u%% against 60%% demanded", r ? (unsigned)r->match[0].pct : 0u);
		/* The block, found by its hash among the matched diagnoses; the matcher's demanded percentage; the objects that decide. */
		if (r) {
			const struct kof_diag_report *from = NULL;
			const struct kof_diag_part *bp = kdet_block_part(o->res.diag, o->res.n_diag, r->part[0].unit_id, &from);
			uint32_t nd = 0;

			OKF(bp == &r->part[0] && from == r, "kdet_block_part finds d_sim's unit by the unit's own id (%08x, the diagnose's block is %08x)", (unsigned)r->part[0].unit_id, (unsigned)r->part[0].id);
			OKF(kdet_part_need(from, bp) == 60u, "kdet_part_need: 60 demanded (%u)", kdet_part_need(from, bp));
			OKF(kdet_block_part(o->res.diag, o->res.n_diag, r->part[0].unit_id ^ 1u, NULL) == NULL, "no unit of another id");
			OKF(kdet_block_part(NULL, 0, r->part[0].unit_id, &from) == NULL && kdet_part_need(NULL, bp) == 0 && kdet_part_need(from, NULL) == 0,
			    "NULL report, NULL part");
			OKF(kdet_run_decided(run, o, &nd) == o->res.diag && nd == o->res.n_diag, "kdet_run_decided: the object's own matched diagnoses");
			OKF(kdet_run_decided(run, NULL, &nd) == NULL && nd == 0u, "no object, no diagnoses");
		}
	}
	OKF(kdet_run_verdict(run) != NULL && kdet_run_verdict(run)->res.has_verdict && kdet_run_verdict(run) == kdet_run_find(run, "sample"),
	    "kdet_run_verdict is the first object with a verdict (here the root)");
	OKF(kdet_run_verdict(NULL) == NULL, "no run, no verdict object");
	OKF(kdet_run_find(run, "no such object") == NULL, "an object the scan did not report is NULL");
	OKF(kdet_run_at(run, 99999u) == NULL, "kdet_run_at past the end is NULL");
	kdet_run_free(run);

	/* A NEAR MATCH: the unit holds most of the block's hashes but not all, so its own id is not the block's hash - and it is still found,
	 * by the unit's id, which is what the viewer's block rows carry. (A join by the block's hash finds only the 100% case.) */
	{
		uint8_t near_[sizeof sample];
		uint32_t q;
		struct kdet_run *run2;
		const struct kdet_object *o2;
		const struct kof_diag_report *r2;

		memcpy(near_, sample, sizeof near_);
		for (q = 5; q < BLK; q += 100u)
			near_[q] ^= 0x5au;
		run2 = kscan_explain(scn, near_, sizeof near_, "near", NULL);
		o2 = kdet_run_find(run2, "near");
		r2 = o2 ? rep_of(o2, "d_sim") : NULL;
		OKF(r2 && r2->state == KOF_DIAG_ST_MATCH && r2->n_part == 1u && r2->part[0].hit && r2->part[0].place && r2->part[0].pct < 100u,
		    "the altered unit still matches d_sim, below 100%% (%u%%)", r2 ? (unsigned)r2->part[0].pct : 0u);
		OKF(o2 && o2->res.has_verdict, "a unit at or above the threshold and below 100%% gives the object its verdict");
		if (r2 && r2->n_part == 1u) {
			const struct kof_diag_report *from2 = NULL;
			uint32_t uid = r2->part[0].unit_id;

			OKF(uid != 0u && uid != r2->part[0].id, "its own id (%08x) is not the diagnose's block hash (%08x)", (unsigned)uid, (unsigned)r2->part[0].id);
			OKF(kdet_block_part(o2->res.diag, o2->res.n_diag, uid, &from2) == &r2->part[0] && from2 == r2, "found by the unit's id");
			OKF(kdet_block_part(o2->res.diag, o2->res.n_diag, r2->part[0].id, NULL) == NULL, "and not by the diagnose's block hash");
		}
		kdet_run_free(run2);
	}

	/* NO MATCH */
	run = kscan_explain(scn, clean, sizeof clean, "clean", NULL);
	o = kdet_run_find(run, "clean");
	OKF(o && !o->res.has_verdict, "a clean sample has no verdict");
	if (o) {
		kdet_info(eng, &o->res, &in);
		OKF(!in.has_verdict && !in.verdict && in.n_diag == 0, "kdet_info of a clean object is empty");
		r = rep_of(o, "d_str");
		OKF(r && r->state != KOF_DIAG_ST_MATCH && r->match[0].result == KDET_M_NO && r->match[0].found == 0, "d_str: no marker found");
		r = rep_of(o, "d_sim");
		OKF(r && r->state != KOF_DIAG_ST_MATCH && r->match[0].result == KDET_M_NO && r->match[0].pct < 60u, "d_sim: %u%% is short of 60%%",
		    r ? (unsigned)r->match[0].pct : 0u);
	}
	kdet_run_free(run);

	/* THE MATCHER'S WORDS, one spelling for every tool (kdet_matcher_text) */
	{
		struct kof_diag_match mm;
		char t[120], tiny[1];

		memset(&mm, 0, sizeof mm);
		mm.kind = KDET_M_SIMILAR; mm.result = KDET_M_YES; mm.n = 2; mm.pct = 83; mm.need = 70;
		OKF(kdet_matcher_text(&mm, t, sizeof t) == KDET_M_YES && !strcmp(t, "similarity 83% of the 2 block(s), 70% demanded"), "similarity words: '%s'", t);
		mm.kind = KDET_M_FIND; mm.result = KDET_M_NO; mm.n = 3; mm.found = 1; mm.mask = 0x10;
		OKF(kdet_matcher_text(&mm, t, sizeof t) == KDET_M_NO && !strcmp(t, "1 of 3 marker(s) found, regions 0x10"), "find words: '%s'", t);
		mm.result = KDET_M_NOT_ASKED;
		OKF(kdet_matcher_text(&mm, t, sizeof t) == KDET_M_NOT_ASKED && strstr(t, "not asked"), "not asked words: '%s'", t);
		OKF(kdet_matcher_text(NULL, t, sizeof t) == KDET_M_NOT_ASKED && t[0] == 0, "NULL matcher: empty text");
		OKF(kdet_matcher_text(&mm, NULL, 5) == KDET_M_NOT_ASKED && kdet_matcher_text(&mm, tiny, 0) == KDET_M_NOT_ASKED, "no room: no write, no crash");
		OKF(kdet_matcher_text(&mm, tiny, sizeof tiny) == KDET_M_NOT_ASKED && tiny[0] == 0, "one byte of room is a NUL");
	}

	/* THE REPORT'S TABLES ARE CHARGED TO THE ENGINE'S BUDGET and given back; a budget that refuses them gives an empty, flagged run. */
	{
		uint64_t used0, used1, cap0;
		kdet_run *r2;

		kscan_free(scn);
		scn = kscan_new(eng);
		used0 = atomic_load(&eng->budget->used);
		r2 = kscan_explain(scn, sample, sizeof sample, "sample", NULL);
		used1 = atomic_load(&eng->budget->used);
		OKF(used1 > used0 && used1 - used0 == 5u * (sizeof(struct kof_diag_report) + sizeof(struct kof_diag_match) * KOF_DIAG_REPORT_MATCH),
		    "the explain tables are charged to the ledger: %llu bytes for 5 diagnoses", (unsigned long long)(used1 - used0));
		kdet_run_free(r2);
		r2 = kscan_explain(scn, sample, sizeof sample, "sample", NULL);
		OKF(atomic_load(&eng->budget->used) == used1, "a second explain on the same scanner charges nothing again");
		kdet_run_free(r2);
		kscan_free(scn);
		OKF(atomic_load(&eng->budget->used) == eng->budget->db, "freeing the scanner gives everything back, the tables included (%llu held, database %llu)", (unsigned long long)atomic_load(&eng->budget->used), (unsigned long long)eng->budget->db);
		scn = kscan_new(eng);
		used0 = atomic_load(&eng->budget->used);
		cap0 = eng->budget->cap;
		eng->budget->cap = used0 + 16u;               /* the scanner is paid for; the report's tables are not affordable */
		r2 = kscan_explain(scn, sample, sizeof sample, "sample", NULL);
		OKF(r2 && (kdet_run_status(r2) & KDET_RUN_NOMEM) && kdet_run_count(r2) == 0u, "refused tables: an empty run flagged NOMEM (status %u, %u objects)",
		    r2 ? (unsigned)kdet_run_status(r2) : 99u, (unsigned)kdet_run_count(r2));
		OKF(atomic_load(&eng->budget->used) == used0, "refused tables charge nothing");
		kdet_run_free(r2);
		OKF(kof_scan_set_explain(NULL, 1) == 0 && kof_scan_set_explain(scn, 0) == 1, "set_explain: NULL scanner refused, off always answers");
		eng->budget->cap = cap0;
		r2 = kscan_explain(scn, sample, sizeof sample, "sample", NULL);
		OKF(r2 && kdet_run_status(r2) == 0u && kdet_run_find(r2, "sample"), "with the room back the same scanner explains");
		kdet_run_free(r2);
	}

	/* ARGUMENTS */
	OKF(kscan_explain(NULL, sample, sizeof sample, "x", NULL) == NULL, "no scanner: NULL");
	OKF(kscan_explain(scn, NULL, 0, "x", NULL) == NULL, "no bytes: NULL");
	OKF(kscan_explain(scn, sample, sizeof sample, NULL, NULL) == NULL, "no name: NULL");
	OKF(kdet_run_count(NULL) == 0 && kdet_run_at(NULL, 0) == NULL && kdet_run_find(NULL, "x") == NULL && kdet_run_status(NULL) == 0,
	    "a NULL run answers nothing");
	kdet_run_free(NULL);
	kdet_info(eng, NULL, &in);
	OKF(!in.has_verdict, "kdet_info of NULL is empty");
	kscan_free(scn);
	keng_close(eng);
}

int main(void)
{
	if (access(builder, X_OK) != 0) {
		printf("detect_api: %s is not built\n", builder);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_detect_api_XXXXXX");
	if (!mkdtemp(root)) {
		printf("detect_api: cannot make a scratch directory\n");
		return 2;
	}
	run_all();
	if (!failures) {
		char cmd[400];

		snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
		(void)system(cmd);
	}
	if (failures) {
		printf("detect_api: %d FAIL\n", failures);
		return 1;
	}
	printf("detect_api: ok\n");
	return 0;
}
