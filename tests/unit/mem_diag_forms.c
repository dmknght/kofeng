/*
 * mem_diag_forms - the memory of the diagnose -> verdict pipeline, attacked (audit_mem, 2026-10-29).
 *
 * WHAT IS ATTACKED, and why the old tests (diag_form_engine, verdict_catalog) could not see it: (b) they load a handful of
 * forms of one block, so the engine's tables of form blocks (dblk, dpool) never grow past their first allocation, no block
 * number is ever far from zero, and "no leak" was never measured - they check answers, not what stays allocated.
 *
 *   growth     700 forms of 1 to 32 blocks of 128 hashes in two packs, with a duplicate name (the loader takes its blocks
 *              back) and a record that is refused, between them: dblk and dpool double several times. Every form is then
 *              asked with the bytes of each of its own blocks and must be the ONLY one that matches - a wrong blk_base
 *              (a block number off by one after a growth, a collision or a refusal) is a wrong or a missing match.
 *   cap        4100 forms in two packs: 4096 load, the rest is said to be cut (KOF_DB_MAX_DIAG), and the last loaded one
 *              still matches its own block.
 *   retained   after the load no form holds its hash array: the engine's own copy (dpool) is the one the set reads, so the
 *              form's copy is dead weight of n_hash * 4 bytes a diagnose for the engine's whole life.
 *   reuse      the same engine scanned 300 times, the engine opened and closed 30 times, the catalog loaded 30 times:
 *              the heap in use does not move after the first round (a leak of a byte per object shows).
 *
 * Under `make unit-asan` LeakSanitizer adds what the numbers cannot see (a block lost on a failure path).
 */

#define _GNU_SOURCE

#include <malloc.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "form_pack.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/databases/pack/diagform.h"
#include "../../libkofeng/databases/pack/dbtables.h"
#include <celllysis/mutation.h>
#include <kofmod/kofsig.h>
#include "../../libkofeng/scanners/scan.h"

extern size_t __sanitizer_get_current_allocated_bytes(void) __attribute__((weak));

static int failures;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";

#define OKF(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

static int kdb_full_check(const kof_engine *e)
{
	return kdb_diag_full(e) == 1;
}

static unsigned long long heap_now(void)
{
	if (__sanitizer_get_current_allocated_bytes)
		return (unsigned long long)__sanitizer_get_current_allocated_bytes();
	return (unsigned long long)mallinfo2().uordblks;
}

/* ---- scanning ------------------------------------------------------------------------ */

struct seen {
	uint8_t *hit;       /* hit[k] = form k answered MATCH over the objects of the scan */
	uint32_t n_hit, cap;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;
	uint32_t i;

	(void)name; (void)bytes; (void)len;
	if (!res)
		return 0;
	for (i = 0; i < res->n_diag; i++) {
		unsigned k;

		if (res->diag[i].state != KOF_DIAG_ST_MATCH)
			continue;
		if (sscanf(res->diag[i].name, "f%u", &k) == 1 && k < s->cap && !s->hit[k]) {
			s->hit[k] = 1;
			s->n_hit++;
		}
	}
	return 0;
}

static void scan(kof_scanner *sc, const void *p, size_t n, struct seen *s)
{
	struct kof_scan_option opt;

	memset(&opt, 0, sizeof opt);
	(void)kof_scan_set_explain(sc, 1);
	memset(s->hit, 0, s->cap);
	s->n_hit = 0;
	kscan_bytes(sc, p, n, "sample", &opt, on_object, s);
}

/* ---- growth: every form answers for its own blocks and for nobody else's --------------- */

#define N_FORMS 700u

static uint32_t nb_of(uint32_t k)
{
	return k % 7u == 0u ? 32u : 1u + k % 5u;
}

static void growth(void)
{
	char db[400];
	uint8_t *rec_a[400], *rec_b[400];
	size_t rl_a[400], rl_b[400], na = 0, nb = 0;
	uint32_t k;
	kof_engine *eng;
	kof_scanner *sc;
	struct seen s;
	uint8_t blk[BLK];
	uint32_t wrong = 0, missed = 0, total_blocks = 0;
	char name[32];

	snprintf(db, sizeof db, "%s/growth_db", root);
	kof_mkdir(db, 0700);
	(void)copy_pack(dbdir, "sigs-any.ksig", db);
	for (k = 0; k < N_FORMS; k++) {
		uint8_t *r = malloc(70000);

		snprintf(name, sizeof name, "f%u", k);
		total_blocks += nb_of(k);
		if (k < 350u) {
			rl_a[na] = form_record(r, name, k, nb_of(k));
			rec_a[na++] = r;
		} else {
			rl_b[nb] = form_record(r, name, k, nb_of(k));
			rec_b[nb++] = r;
		}
		if (k == 349u) {
			/* a record of the first pack whose name is taken by an earlier one: the loader takes its blocks back */
			uint8_t *d = malloc(70000);

			rl_a[na] = form_record(d, "f5", 9000u, 32u);
			rec_a[na++] = d;
		}
		if (k == 400u) {
			/* a record that is refused (a cut stream), between the good ones */
			uint8_t *bad = malloc(70000);

			rl_b[nb] = form_record(bad, "bad_cut", 9001u, 3u);
			rl_b[nb] -= 9u;
			rec_b[nb++] = bad;
		}
	}
	write_kdig(db, "diag-a.kdig", rec_a, rl_a, na);
	write_kdig(db, "diag-b.kdig", rec_b, rl_b, nb);
	for (k = 0; k < na; k++)
		free(rec_a[k]);
	for (k = 0; k < nb; k++)
		free(rec_b[k]);

	eng = keng_open(db);
	if (!eng) {
		OKF(0, "the growth database does not open");
		return;
	}
	OKF(kdb_diagnoses(eng) == N_FORMS, "%u forms loaded, want %u (the duplicate and the cut record are refused)", (unsigned)kdb_diagnoses(eng),
	    N_FORMS);
	sc = kscan_new(eng);
	s.cap = N_FORMS;
	s.hit = calloc(1, s.cap);
	if (!sc || !s.hit) {
		OKF(0, "no scanner");
		keng_close(eng);
		return;
	}
	for (k = 0; k < N_FORMS; k++) {
		uint32_t j, nbk = nb_of(k);

		for (j = 0; j < nbk; j += (nbk > 4u ? nbk - 1u : 1u)) {      /* the first and the last block of a big form, every one of a small */
			make_bytes(blk, seed_of(k, j));
			scan(sc, blk, BLK, &s);
			if (!s.hit[k]) {
				missed++;
				if (missed <= 8u)
					printf("  form %u block %u of %u: not matched (%u matched)\n", (unsigned)k, (unsigned)j, (unsigned)nbk, s.n_hit);
			}
			if (s.n_hit != (s.hit[k] ? 1u : 0u)) {
				wrong++;
				if (wrong <= 8u) {
					uint32_t q;

					for (q = 0; q < N_FORMS; q++)
						if (s.hit[q])
							printf("  form %u block %u: matched form %u\n", (unsigned)k, (unsigned)j, (unsigned)q);
				}
			}
		}
	}
	OKF(missed == 0, "%u forms did not match the bytes of their own block (a block number off after a growth)", missed);
	OKF(wrong == 0, "%u scans matched a form that does not own the block", wrong);
	/* the refused duplicate's own bytes match nobody: its blocks were taken back, not left in the set */
	make_bytes(blk, seed_of(9000u, 3u));
	scan(sc, blk, BLK, &s);
	OKF(s.n_hit == 0u, "the blocks of a refused duplicate still score (%u forms matched)", s.n_hit);
	make_bytes(blk, seed_of(9001u, 1u));
	scan(sc, blk, BLK, &s);
	OKF(s.n_hit == 0u, "the blocks of a refused record still score (%u forms matched)", s.n_hit);
	printf("  growth: %u forms, %u blocks in the set\n", (unsigned)N_FORMS, (unsigned)total_blocks);
	free(s.hit);
	kscan_free(sc);
	keng_close(eng);
}

/* ---- cap: past KOF_DB_MAX_DIAG the rest is cut and what was kept still answers ---------- */

#define N_CAP 4100u

static void cap_pack(const char *db, const char *leaf, uint32_t first, uint32_t n)
{
	uint8_t **rec = calloc(n, sizeof *rec);
	size_t *rl = calloc(n, sizeof *rl);
	uint32_t k;
	char name[32];

	for (k = 0; k < n; k++) {
		rec[k] = malloc(30000);
		snprintf(name, sizeof name, "f%u", first + k);
		rl[k] = form_record(rec[k], name, first + k, 1u);
	}
	write_kdig(db, leaf, rec, rl, n);
	for (k = 0; k < n; k++)
		free(rec[k]);
	free(rec);
	free(rl);
}

static void cap(void)
{
	char db[400];
	kof_engine *eng;
	kof_scanner *sc;
	struct seen s;
	uint8_t blk[BLK];

	snprintf(db, sizeof db, "%s/cap_db", root);
	kof_mkdir(db, 0700);
	(void)copy_pack(dbdir, "sigs-any.ksig", db);
	cap_pack(db, "diag-a.kdig", 0u, N_CAP / 2u);
	cap_pack(db, "diag-b.kdig", N_CAP / 2u, N_CAP / 2u);
	{
		/* what the loader says on stderr while the pack is read, kept in a file */
		char errp[500];
		int keep = dup(2), fd;
		size_t en = 0;
		uint8_t *et;

		snprintf(errp, sizeof errp, "%s/cap_stderr.txt", root);
		fd = open(errp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		fflush(stderr);
		if (fd >= 0 && keep >= 0)
			dup2(fd, 2);
		eng = keng_open(db);
		fflush(stderr);
		if (keep >= 0) {
			dup2(keep, 2);
			close(keep);
		}
		if (fd >= 0)
			close(fd);
		et = read_file(errp, &en);
		OKF(et && memmem(et, en, "KOF_DB_MAX_DIAG", 15u), "the cap was hit and the loader said nothing on stderr (%zu bytes of it)", en);
		free(et);
	}
	if (!eng) {
		OKF(0, "the cap database does not open");
		return;
	}
	OKF(kdb_full_check(eng), "kdb_diag_full does not say the bound was hit");
	OKF(kdb_diagnoses(eng) == KOF_DB_MAX_DIAG, "%u forms loaded, want the bound %u", (unsigned)kdb_diagnoses(eng), (unsigned)KOF_DB_MAX_DIAG);
	sc = kscan_new(eng);
	s.cap = N_CAP;
	s.hit = calloc(1, s.cap);
	if (!sc || !s.hit) {
		OKF(0, "no scanner");
		keng_close(eng);
		return;
	}
	make_bytes(blk, seed_of(KOF_DB_MAX_DIAG - 1u, 0u));
	scan(sc, blk, BLK, &s);
	OKF(s.n_hit == 1u && s.hit[KOF_DB_MAX_DIAG - 1u], "the last form that fits does not match its block (%u matched)", s.n_hit);
	make_bytes(blk, seed_of(KOF_DB_MAX_DIAG + 3u, 0u));
	scan(sc, blk, BLK, &s);
	OKF(s.n_hit == 0u, "a form past the bound matches (%u)", s.n_hit);
	free(s.hit);
	kscan_free(sc);
	keng_close(eng);
}

/* ---- retained: the form's own copy of the hashes is not kept ---------------------------- */

static void retained(void)
{
	char db[400];
	kof_engine *eng;
	uint32_t i, held = 0, bytes = 0;

	snprintf(db, sizeof db, "%s/growth_db", root);
	eng = keng_open(db);
	if (!eng) {
		OKF(0, "the retained database does not open");
		return;
	}
	for (i = 0; i < eng->n_diag; i++)
		if (eng->diag[i].form && eng->diag[i].form->hash) {
			held++;
			bytes += eng->diag[i].form->n_hash * 4u;
		}
	OKF(held == 0u, "%u forms keep their hashes after the load (%u bytes of a second copy the engine never reads)", held, bytes);
	keng_close(eng);
}

/* ---- reuse: what is allocated after a round is what is allocated after the next -------- */

static void reuse(void)
{
	char db[400];
	kof_engine *eng;
	kof_scanner *sc;
	struct seen s;
	uint8_t blk[BLK];
	unsigned long long h0, h1, h2;
	uint32_t i;

	snprintf(db, sizeof db, "%s/growth_db", root);
	s.cap = N_FORMS;
	s.hit = calloc(1, s.cap);
	/* one engine, many objects of one scanner */
	eng = keng_open(db);
	sc = eng ? kscan_new(eng) : NULL;
	if (!sc) {
		OKF(0, "no scanner");
		return;
	}
	make_bytes(blk, seed_of(10u, 0u));
	for (i = 0; i < 20u; i++)
		scan(sc, blk, BLK, &s);
	h0 = heap_now();
	for (i = 0; i < 300u; i++)
		scan(sc, blk, BLK, &s);
	h1 = heap_now();
	OKF(h1 <= h0 + 4096u, "300 more scans of the same object grew the heap by %llu bytes", h1 - h0);
	OKF(s.n_hit == 1u, "the object still matches its form after 320 scans");
	kscan_free(sc);
	keng_close(eng);
	/* open, scan, close: the whole engine given back every time */
	for (i = 0; i < 3u; i++) {
		eng = keng_open(db);
		sc = eng ? kscan_new(eng) : NULL;
		if (sc)
			scan(sc, blk, BLK, &s);
		kscan_free(sc);
		keng_close(eng);
	}
	h0 = heap_now();
	for (i = 0; i < 30u; i++) {
		eng = keng_open(db);
		sc = eng ? kscan_new(eng) : NULL;
		if (sc)
			scan(sc, blk, BLK, &s);
		kscan_free(sc);
		keng_close(eng);
	}
	h1 = heap_now();
	OKF(h1 <= h0 + 4096u, "30 opens and closes of the engine left %llu bytes behind", h1 - h0);
	/* the catalog loaded again and again on one engine */
	eng = keng_open(db);
	/* The allocator's per-size caches (tcache) count as in use in mallinfo2 and fill over the first loads: measured 1408, 6928, 11152, 13968 bytes after
	 * loads 1, 2, 5, 10 and 13968 still after 400 (valgrind: no block left). The count is taken after they are full, so only a per-load growth shows. */
	for (i = 0; i < 16u; i++)
		(void)keng_catalog_load(eng, "bases/pathogens", "bases/syndromes");
	h0 = heap_now();
	for (i = 0; i < 30u; i++)
		(void)keng_catalog_load(eng, "bases/pathogens", "bases/syndromes");
	h2 = heap_now();
	OKF(h2 <= h0 + 4096u, "30 catalog loads grew the heap by %llu bytes", h2 - h0);
	(void)keng_catalog_load(eng, NULL, NULL);
	keng_close(eng);
	free(s.hit);
}

/* ---- regions: a diagnose that is dropped names no region ------------------------------------ */

static uint32_t scan_mask_of(const char *db, int with_dup)
{
	uint8_t *rec[2];
	size_t rl[2];
	uint32_t m;
	kof_engine *eng;

	rec[0] = malloc(70000);
	rec[1] = malloc(70000);
	rl[0] = form_record_in(rec[0], "r_first", 1u, 1u, KGENOME_SCAN_ELF_DATA);
	rl[1] = form_record_in(rec[1], "r_first", 2u, 1u, KGENOME_SCAN_ELF_CODE);     /* the same name: this one is not kept */
	write_kdig(db, "diag-a.kdig", rec, rl, with_dup ? 2u : 1u);
	free(rec[0]);
	free(rec[1]);
	eng = keng_open(db);
	m = eng ? eng->scan_mask : 0xffffffffu;
	if (eng)
		keng_close(eng);
	return m;
}

static void regions(void)
{
	char db1[400], db2[400];
	uint32_t alone, dup;

	snprintf(db1, sizeof db1, "%s/regions1_db", root);
	snprintf(db2, sizeof db2, "%s/regions2_db", root);
	kof_mkdir(db1, 0700);
	kof_mkdir(db2, 0700);
	(void)copy_pack(dbdir, "sigs-any.ksig", db1);
	(void)copy_pack(dbdir, "sigs-any.ksig", db2);
	alone = scan_mask_of(db1, 0);
	dup = scan_mask_of(db2, 1);
	OKF((alone & KGENOME_SCAN_ELF_CODE) == 0u, "the fixture pack already names the ELF code (%x): the case below proves nothing", (unsigned)alone);
	OKF((alone & KGENOME_SCAN_ELF_DATA) != 0u, "a kept form's region is in the scan mask (%x)", (unsigned)alone);
	OKF(dup == alone, "a dropped duplicate widened the scan mask from %x to %x (every object then resolves a region nobody reads)", (unsigned)alone,
	    (unsigned)dup);
}

/* ---- work once: each product is built once for an object, and the counters say so ------------ */

static void work_once(void)
{
	char db[400];
	kof_engine *eng;
	kof_scanner *sc;
	struct seen s;
	uint8_t blk[BLK];
	struct kof_stats a, b;
	uint32_t i, matchers = 0;

	snprintf(db, sizeof db, "%s/growth_db", root);
	s.cap = N_FORMS;
	s.hit = calloc(1, s.cap);
	eng = keng_open(db);
	sc = eng ? kscan_new(eng) : NULL;
	if (!sc) {
		OKF(0, "no scanner");
		return;
	}
	for (i = 0; i < eng->n_diag; i++)
		matchers += eng->diag[i].form ? eng->diag[i].form->n_match : 0u;
	for (i = 0; i < 5u; i++) {
		a = *kscan_stats(sc);
		make_bytes(blk, seed_of(40u + i, 0u));
		scan(sc, blk, BLK, &s);
		b = *kscan_stats(sc);
		OKF(b.objects - a.objects >= 1u, "the object was not counted");
		OKF(b.work_feeds - a.work_feeds <= b.objects - a.objects, "the similarity feed ran %llu times for %llu object(s)",
		    (unsigned long long)(b.work_feeds - a.work_feeds), (unsigned long long)(b.objects - a.objects));
		OKF(b.work_form_asks - a.work_form_asks <= (uint64_t)eng->n_form * (b.objects - a.objects),
		    "%llu form expressions were evaluated for %u forms and %llu object(s)", (unsigned long long)(b.work_form_asks - a.work_form_asks),
		    (unsigned)eng->n_form, (unsigned long long)(b.objects - a.objects));
		OKF(b.work_form_matchers - a.work_form_matchers <= (uint64_t)matchers * (b.objects - a.objects),
		    "%llu matchers were answered for %u matchers and %llu object(s)", (unsigned long long)(b.work_form_matchers - a.work_form_matchers),
		    (unsigned)matchers, (unsigned long long)(b.objects - a.objects));
		OKF(b.work_verdicts - a.work_verdicts == b.objects - a.objects, "the verdict was built %llu times for %llu object(s)",
		    (unsigned long long)(b.work_verdicts - a.work_verdicts), (unsigned long long)(b.objects - a.objects));
		OKF(b.work_catalogs - a.work_catalogs <= b.objects - a.objects, "the catalog verdict was built %llu times for %llu object(s)",
		    (unsigned long long)(b.work_catalogs - a.work_catalogs), (unsigned long long)(b.objects - a.objects));
	}
	free(s.hit);
	kscan_free(sc);
	keng_close(eng);
}

/* ---- the ledger: what a scan charged it gave back ------------------------------------------ */

static void ledger(void)
{
	char db[400];
	kof_engine *eng;
	kof_scanner *sc;
	struct seen s;
	uint8_t blk[BLK];
	uint64_t used0, used1;
	uint32_t i;

	snprintf(db, sizeof db, "%s/growth_db", root);
	s.cap = N_FORMS;
	s.hit = calloc(1, s.cap);
	eng = keng_open(db);
	if (!eng || !eng->budget) {
		OKF(0, "no engine");
		return;
	}
	used0 = atomic_load(&eng->budget->used);
	OKF(used0 == eng->budget->db, "after the open the ledger holds %llu, the database %llu", (unsigned long long)used0,
	    (unsigned long long)eng->budget->db);
	OKF(keng_catalog_load(eng, "bases/pathogens", "bases/syndromes") == 0u, "the catalog loads");
	used1 = atomic_load(&eng->budget->used);
	OKF(used1 > used0 && used1 == eng->budget->db, "the catalog is charged to the ledger and to the database count (%llu, %llu, %llu)",
	    (unsigned long long)used0, (unsigned long long)used1, (unsigned long long)eng->budget->db);
	sc = kscan_new(eng);
	if (!sc) {
		OKF(0, "no scanner");
		return;
	}
	used0 = atomic_load(&eng->budget->used);
	/* The report's tables (one report and one matcher record per diagnose) are charged to the ledger when the report is first asked for, once. */
	OKF(kof_scan_set_explain(sc, 1) == 1, "the report tables are made");
	used1 = atomic_load(&eng->budget->used);
	OKF(used1 - used0 == (uint64_t)N_FORMS * (sizeof(struct kof_diag_report) + sizeof(struct kof_diag_match) * KOF_DIAG_REPORT_MATCH),
	    "the report tables are charged to the ledger: %llu bytes for %u diagnoses", (unsigned long long)(used1 - used0), (unsigned)N_FORMS);
	OKF(kof_scan_set_explain(sc, 1) == 1 && atomic_load(&eng->budget->used) == used1, "asking again charges nothing");
	used0 = used1;
	for (i = 0; i < 20u; i++) {
		make_bytes(blk, seed_of(i * 7u, 0u));
		scan(sc, blk, BLK, &s);
	}
	kscan_trim(sc, 0u);
	used1 = atomic_load(&eng->budget->used);
	OKF(used1 == used0, "after 20 objects and a trim the ledger holds %llu, with the scanner idle it held %llu", (unsigned long long)used1,
	    (unsigned long long)used0);
	kscan_free(sc);
	used1 = atomic_load(&eng->budget->used);
	OKF(used1 == eng->budget->db, "with no scanner the ledger holds %llu, the database %llu", (unsigned long long)used1,
	    (unsigned long long)eng->budget->db);
	OKF(keng_catalog_load(eng, NULL, NULL) == 0u, "the catalog is dropped");
	used1 = atomic_load(&eng->budget->used);
	OKF(used1 == eng->budget->db && eng->budget->db < used0, "after dropping the catalog %llu is held, the database %llu", (unsigned long long)used1,
	    (unsigned long long)eng->budget->db);
	free(s.hit);
	keng_close(eng);
}

int main(void)
{
	if (access(dbdir, X_OK) != 0) {
		printf("mem_diag_forms: %s is not built\n", dbdir);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_memforms_XXXXXX");
	if (!mkdtemp(root)) {
		printf("mem_diag_forms: cannot make a scratch directory\n");
		return 2;
	}
	growth();
	cap();
	retained();
	regions();
	work_once();
	ledger();
	reuse();
	if (!failures)
		rm_all(root);
	if (failures) {
		printf("mem_diag_forms: %d FAIL\n", failures);
		return 1;
	}
	printf("mem_diag_forms: ok\n");
	return 0;
}
