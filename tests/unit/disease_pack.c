/*
 * disease_pack - the disease a diagnose record carries, the table that names it, a matched
 * diagnose's disease reaching the object's verdict, and a pack an older build wrote
 * that this one no longer reads.
 *
 * The same properties diag_pack pins for a diagnose pack: a record that does not add
 * up is refused, and a file the loader will not read is said (kdb_diag_packs_refused)
 * and never taken for an absent one.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/analyzers/diseases/kofdisease.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "caps_fix.h"

static int failures;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		failures++;
}

static void put32_le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}


static int write_file(const char *dir, const char *leaf, const void *p, size_t n)
{
	char path[640];
	FILE *f;

	snprintf(path, sizeof path, "%s/%s", dir, leaf);
	f = fopen(path, "wb");
	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static int copy_good_pack(const char *dir)
{
	char src[640];
	FILE *f;
	static uint8_t buf[1u << 20];
	size_t n;

	snprintf(src, sizeof src, "%s/sigs-any.ksig", dbdir);
	f = fopen(src, "rb");
	if (!f)
		return 0;
	n = fread(buf, 1, sizeof buf, f);
	fclose(f);
	return n > 0 && write_file(dir, "sigs-any.ksig", buf, n);
}

static void rm_all(const char *dir)
{
	char cmd[700];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
	(void)system(cmd);
}


/* An engine over a directory holding the good signature pack and `leaf` as `bytes`. */
static struct kof_engine *open_with(const char *tag, char *dir, size_t cap,
				    const char *leaf, const uint8_t *pk, size_t n)
{
	snprintf(dir, cap, "%s/%s", root, tag);
	if (kof_mkdir(dir, 0700) != 0 || !copy_good_pack(dir))
		return NULL;
	if (pk && !write_file(dir, leaf, pk, n))
		return NULL;
	return kof_db_load(dir);
}

/* ---- a file an older build wrote ----------------------------------------- */

static void retired(void)
{
	static const uint8_t old_pack[16] = { 'K', 'S', 'Y', 'N', 1 };
	char dir[640];
	struct kof_engine *e;

	e = open_with("plain", dir, sizeof dir, NULL, NULL, 0);
	ok("a directory without it loads and refuses nothing",
	   e != NULL && kdb_diag_packs_refused(e) == 0u);
	if (e)
		kof_db_free(e);
	rm_all(dir);

	e = open_with("old", dir, sizeof dir, "syndromes.kdig", old_pack, sizeof old_pack);
	ok("a directory that holds it still loads", e != NULL);
	ok("and says that a file was not read, instead of treating it as absent",
	   e != NULL && kdb_diag_packs_refused(e) == 1u);
	if (e)
		kof_db_free(e);
	rm_all(dir);
}


/* ---- the disease in a diagnose record ----------------------------------- */

static size_t drec(uint8_t *b, uint32_t id, unsigned type, unsigned len_byte)
{
	static const char *const nm = "DIAG_X";
	size_t at = 0, nl = strlen(nm);
	uint16_t cap = (uint16_t)KGENOME_NUCLEO_NET_OPEN;

	b[at++] = 1; b[at++] = 0;
	b[at++] = KOF_DIAG_ANALYSIS_SYSCALL;
	b[at++] = (uint8_t)nl;
	memcpy(b + at, nm, nl); at += nl;
	b[at++] = (uint8_t)cap; b[at++] = (uint8_t)(cap >> 8);
	b[at++] = 0; b[at++] = 0;
	b[at++] = KOF_DIAG_NO_PARENT;
	b[at++] = 0; b[at++] = 0; b[at++] = 0;
	b[at++] = 0;                            /* the legacy name count */
	b[at++] = KDIG_SEC_DISEASE;
	b[at++] = (uint8_t)len_byte;
	put32_le(b + at, id); at += 4;
	b[at++] = (uint8_t)type;
	return at;
}

static void disease(void)
{
	uint8_t b[128];
	struct kof_diag d;
	struct kof_diag_node node[2];
	char name[KOF_DB_DIAG_NAME], needs[sizeof b + 1u];   /* a store never needs more than the record */
	const struct kof_diag_store st = { node, name, needs, sizeof name, sizeof needs, 2 };
	const uint32_t id = kof_disease_id("cnc/recv-syscall");
	size_t at;

	at = drec(b, id, KOF_MALTYPE_BOTNET, 5);
	memset(&d, 0, sizeof d);
	ok("a record with a disease loads",
	   kof_diag_load(kof_buf_make(b, at), &d, &st) == 1);
	ok("and carries its id and its type",
	   d.disease == id && d.disease_type == KOF_MALTYPE_BOTNET);
	memset(&d, 0, sizeof d);
	ok("a record without one has none",
	   kof_diag_load(kof_buf_make(b, at - 7u), &d, &st) == 1 && d.disease == 0);
	/* a section that is not an id and a type refuses the record whole */
	at = drec(b, id, KOF_MALTYPE_BOTNET, 4);
	ok("a length that is not five refuses the record",
	   kof_diag_load(kof_buf_make(b, at), &d, &st) == 0);
	at = drec(b, id, KOF_MALTYPE_COUNT, 5);
	ok("a type that is no maltype refuses the record",
	   kof_diag_load(kof_buf_make(b, at), &d, &st) == 0);
	at = drec(b, 0, KOF_MALTYPE_BOTNET, 5);
	ok("the id zero, which means no disease, refuses the record",
	   kof_diag_load(kof_buf_make(b, at), &d, &st) == 0);
}


/* ---- the database the build makes from tests/sigs ------------------------- */

/*
 * The whole path, once: sources through the builder, the diagnose pack that
 * carries ids, the table of names, and what the engine makes of them. Nothing here
 * is written by hand, so what is checked is the build.
 */
static void database(void)
{
	struct kof_engine *e = kof_db_load(dbdir);
	const struct kof_disease_ent *d;
	uint32_t id = kof_disease_id("kernel/giveroot"), i;
	int carried = 0;

	ok("the engine loads the database the build made", e != NULL);
	if (!e)
		return;
	ok("and refuses none of its files", kdb_diag_packs_refused(e) == 0u);
	d = kof_db_disease(e, id);
	ok("a disease id is turned back into its name and its type",
	   d && !strcmp(d->name, "kernel/giveroot") && d->type == KOF_MALTYPE_ROOTKIT);
	ok("an id nobody carries is not named", kof_db_disease(e, kof_disease_id("no/such")) == NULL);
	for (i = 0; i < e->n_diag; i++)
		if (e->diag[i].disease == id)
			carried = e->diag[i].disease_type == KOF_MALTYPE_ROOTKIT;
	ok("the diagnose carries the id and the type it declared", carried);
	{
		uint32_t prev = 0, k, n = kof_db_disease_count(e);
		int ascending = n > 0;

		for (k = 0; k < n; k++) {
			const struct kof_disease_ent *x = kof_db_disease_at(e, k);

			if (!x || x->id <= prev)
				ascending = 0;
			else
				prev = x->id;
		}
		ok("the names can be listed, ascending by id", ascending);
		ok("and a list ends where it ends", kof_db_disease_at(e, n) == NULL);
	}
	kof_db_free(e);
}

/* ---- a diagnose that matched: its disease is the object's ------------------- */

static int g_has;
static char g_name[224];
static uint32_t g_dis;

static int on_obj(const char *name, const void *bytes, uint64_t len,
		  const struct kof_result *res, void *user)
{
	(void)name; (void)bytes; (void)len; (void)user;
	g_has = res->has_verdict;
	g_dis = res->has_verdict ? res->verdict.n_disease : 0u;
	snprintf(g_name, sizeof g_name, "%s", res->has_verdict ? res->verdict.name : "");
	return 0;
}

static void detector(void)
{
	kof_engine *eng = keng_open(dbdir);
	kof_scanner *sc;
	struct kof_scan_option opt;
	static uint8_t hit[4096];
	uint8_t miss[256];
	uint64_t hit_n;

	ok("the engine opens the database", eng != NULL);
	if (!eng)
		return;
	sc = kscan_new(eng);
	hit_n = cf_kmod(hit, sizeof hit, 0, 0);     /* what the fixture diagnose kmod_give_root names */
	memset(miss, 'x', sizeof miss);
	memset(&opt, 0, sizeof opt);

	g_has = 0;
	kscan_bytes(sc, hit, hit_n, "hit", &opt, on_obj, NULL);
	ok("an object a diagnose matched carries that diagnose's disease",
	   g_has == 1 && g_dis == 1u);
	ok("and its verdict is named from it", strstr(g_name, "Rootkit:kernel.giveroot") != NULL);

	g_has = 0;
	kscan_bytes(sc, miss, sizeof miss, "miss", &opt, on_obj, NULL);
	ok("an object nothing matched has no verdict and no disease", g_has == 0);

	/* the next object does not inherit the last one's disease */
	g_has = 0;
	kscan_bytes(sc, hit, hit_n, "hit2", &opt, on_obj, NULL);
	kscan_bytes(sc, miss, sizeof miss, "miss2", &opt, on_obj, NULL);
	ok("a disease belongs to the object it was found on", g_has == 0);
	kscan_free(sc);
	keng_close(eng);
}

int main(int argc, char **argv)
{
	if (argc > 1)
		dbdir = argv[1];
	snprintf(root, sizeof root, "build/test/diseasepack_%d", (int)getpid());
	if (kof_mkdir(root, 0700) != 0) {
		printf("disease_pack: cannot make a work directory\n");
		return 1;
	}
	printf("disease_pack:\n");
	retired();
	disease();
	database();
	detector();
	rm_all(root);
	if (failures) {
		printf("disease_pack: %d failure(s)\n", failures);
		return 1;
	}
	printf("disease_pack: a diagnose carries its disease, the table names it, a matched "
	       "diagnose's disease makes the verdict, a file of an older build is said - ok\n");
	return 0;
}
