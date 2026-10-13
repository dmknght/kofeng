/*
 * caps_db - limits of the DATABASE the engine loads: how many diagnoses, and
 * how many nodes one diagnose may have. Evidence just INSIDE and just OUTSIDE.
 *
 * WHAT THIS CATCHES:
 *
 *   KOF_DB_MAX_DIAG             was 256: the 257th diagnose of a database was
 *                               not loaded, and a rule asking for it by name
 *                               (kof_diag(x)) was never true, with no error.
 *                               The tables are now allocated for what the
 *                               packs carry (300 load); the bound is 4096,
 *                               against a hostile pack, and a database over
 *                               it is reported - e->diag_full, read through
 *                               kdb_diag_full.
 *   KOF_DB_MAX_DIAG_NODE (32)   a diagnose with 33 nodes is refused as "not
 *                               one this build can read": a message on
 *                               stderr and a detection that never exists.
 *   KOF_DIAG_PACKS_MAX (64)     EXTRA, same family: the 65th diag-*.kdig file
 *                               of a directory is not opened.
 *   KOF_DIAG_ID (was 16 bits)   EXTRA, same family: two diagnose NAMES that
 *                               hash to one 16-bit id loaded only the first.
 *                               With 256 names the chance of such a pair was
 *                               about 40%. The id is the full 32-bit hash now
 *                               (the diag32, diag_share32 and diag_str32 slots,
 *                               appended to the module ABI), so a 16-bit pair
 *                               loads whole; a real 32-bit collision is still
 *                               COUNTED (kdb_diag_collisions) and ksigbuilder
 *                               refuses to build such a pack.
 *
 * Same method as diag_pack.c: the pack is written byte by byte, the engine
 * loads the directory, the test reads what survived.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "known_miss.h"
#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofdiagtree.h"

static int fails;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* One diagnose of `n_node` nodes: a head and n-1 children of it. */
static size_t rec(uint8_t *b, const char *name, unsigned n_node)
{
	size_t nl = strlen(name), at = 0;
	unsigned i;

	b[at++] = (uint8_t)n_node; b[at++] = 0;
	b[at++] = KOF_DIAG_ANALYSIS_SYSCALL;
	b[at++] = (uint8_t)nl;
	memcpy(b + at, name, nl); at += nl;
	for (i = 0; i < n_node; i++) {
		uint16_t cap = (uint16_t)(i ? KGENOME_NUCLEO_MEM_READ : KGENOME_NUCLEO_NET_OPEN);

		b[at++] = (uint8_t)cap; b[at++] = (uint8_t)(cap >> 8);
		b[at++] = 0; b[at++] = 0;               /* flags            */
		b[at++] = i ? 0 : KOF_DIAG_NO_PARENT;   /* parent           */
		b[at++] = 0;                            /* role             */
		b[at++] = 0;                            /* bits             */
		b[at++] = 0;                            /* attribute length */
	}
	return at;
}

/*
 * `n` names with DISTINCT 16-bit ids, so that what is measured is the count
 * limit and not the id collision (which is measured by itself below). Names
 * are dg_<k> for the k that do not collide with an earlier one.
 */
static char names_v[4200][12];
static void unique_names(unsigned n, unsigned first)
{
	static unsigned char used[65536];
	unsigned i = 0, k = first;

	memset(used, 0, sizeof used);
	while (i < n) {
		uint16_t id;

		snprintf(names_v[i], sizeof names_v[i], "dg_%04u", k++);
		id = kof_diag_id_(names_v[i]);
		if (used[id])
			continue;
		used[id] = 1;
		i++;
	}
}


static uint8_t *pack_n(size_t *len, unsigned n, unsigned n_node)
{
	unique_names(n, 0);
	uint8_t *b = calloc(1, 8u + (size_t)n * (8u + 16u + 8u * 40u));
	size_t at = 8u + (size_t)n * 8u;
	unsigned i;

	memcpy(b, "KDGP", 4);
	b[4] = 1;
	b[6] = (uint8_t)n; b[7] = (uint8_t)(n >> 8);
	for (i = 0; i < n; i++) {
		size_t l = rec(b + at, names_v[i], n_node);

		put32(b + 8u + i * 8u, (uint32_t)at);
		put32(b + 12u + i * 8u, (uint32_t)l);
		at += l;
	}
	*len = at;
	return b;
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

/* Load a directory holding one pack of `n` diagnoses of `n_node` nodes. */
static struct kof_engine *load(const char *tag, unsigned n, unsigned n_node)
{
	char dir[640];
	size_t len;
	uint8_t *pk = pack_n(&len, n, n_node);
	struct kof_engine *e = NULL;

	snprintf(dir, sizeof dir, "%s/%s", root, tag);
	if (kof_mkdir(dir, 0700) == 0 && copy_good_pack(dir) &&
	    write_file(dir, "diag-x.kdig", pk, len))
		e = kof_db_load(dir);
	free(pk);
	rm_all(dir);
	return e;
}

static int has(const struct kof_engine *e, const char *name)
{
	uint32_t i;

	for (i = 0; i < e->n_diag; i++)
		if (!strcmp(e->diag[i].name, name))
			return 1;
	return 0;
}

/* The k-th name of the search: ten letters from an LCG seeded by k. */
static void rand_name(char out[16], unsigned k)
{
	uint32_t x = k * 2654435761u + 12345u;
	unsigned i;

	for (i = 0; i < 10u; i++) {
		x = x * 1664525u + 1013904223u;
		out[i] = (char)('a' + (x >> 24) % 26u);
	}
	out[10] = 0;
}

static int idk_cmp(const void *x, const void *y)
{
	const uint32_t *p = x, *q = y;

	return *p < *q ? -1 : *p > *q;
}

/* A directory holding the good pack and one diagnose pack of exactly the two
 * named diagnoses, loaded. NULL when it could not be built. */
static char collide_dir[640];

static kof_engine *load_pair(const char *a, const char *b)
{
	uint8_t *pk = calloc(1, 512), *two = calloc(1, 256);
	size_t l1, l2;
	char *dir = collide_dir;
	kof_engine *e = NULL;

	if (!pk || !two)
		goto out;
	l1 = rec(two, a, 1);
	l2 = rec(two + l1, b, 1);
	memcpy(pk, "KDGP", 4); pk[4] = 1; pk[6] = 2;
	put32(pk + 8, 24); put32(pk + 12, (uint32_t)l1);
	put32(pk + 16, (uint32_t)(24 + l1)); put32(pk + 20, (uint32_t)l2);
	memcpy(pk + 24, two, l1 + l2);
	snprintf(collide_dir, sizeof collide_dir, "%s/collide", root);
	if (kof_mkdir(dir, 0700) == 0 && copy_good_pack(dir) &&
	    write_file(dir, "diag-x.kdig", pk, 24 + l1 + l2))
		e = kof_db_load(dir);
out:
	free(pk);
	free(two);
	return e;
}


int main(int argc, char **argv)
{
	struct kof_engine *e;

	if (argc > 1)
		dbdir = argv[1];
	snprintf(root, sizeof root, "build/test/capsdb_%d", (int)getpid());
	if (kof_mkdir(root, 0700) != 0) {
		printf("caps db: cannot make a work directory\n");
		return 1;
	}

	/* the 256th diagnose is the last that fits */
	e = load("n256", 256, 1);
	CK(e && e->n_diag == 256u && !kdb_diag_full(e) && has(e, names_v[255]));
	if (e)
		kof_db_free(e);

	/* 300 diagnoses: all loaded, nothing marked - the table is allocated for
	 * what the packs carry, not for a constant. */
	e = load("n300", 300, 1);
	CK(e != NULL);
	CK(e && e->n_diag == 300u && has(e, names_v[299]));
	CK(e && e->diag_full == 0 && kdb_diag_full(e) == 0);
	if (e)
		kof_db_free(e);

	/* past the bound against a hostile pack: the first 4096 load and the
	 * engine SAYS it did not take them all. */
	e = load("n4097", KOF_DB_MAX_DIAG + 1u, 1);
	CK(e != NULL);
	CK(e && e->n_diag == KOF_DB_MAX_DIAG && has(e, names_v[KOF_DB_MAX_DIAG - 1u]));
	CK(e && !has(e, names_v[KOF_DB_MAX_DIAG]));
	CK(e && kdb_diag_full(e) == 1);
	if (e)
		kof_db_free(e);

	/* nodes: 32 are read, 33 are not */
	e = load("node32", 1, KOF_DB_MAX_DIAG_NODE);
	CK(e && e->n_diag == 1u);
	if (e)
		kof_db_free(e);
	e = load("node33", 1, KOF_DB_MAX_DIAG_NODE + 1u);
	CK(e != NULL);
	KM_CHECK(e && e->n_diag == 1u,
		 "a diagnose of 33 nodes is loaded", "KOF_DB_MAX_DIAG_NODE");
	if (e)
		kof_db_free(e);

	/* 64 pack files fit, the 65th is not read */
	{
		char dir[640];
		unsigned i;

		for (i = 0; i < 2; i++) {
			unsigned n_pack = i ? 65u : 64u, k;

			snprintf(dir, sizeof dir, "%s/packs%u", root, n_pack);
			CK(kof_mkdir(dir, 0700) == 0 && copy_good_pack(dir));
			unique_names(n_pack, 0);
			for (k = 0; k < n_pack; k++) {
				uint8_t one[64], file[128];
				char leaf[32];
				size_t rl = rec(one, names_v[k], 1), at = 16;

				memcpy(file, "KDGP", 4); file[4] = 1; file[5] = 0;
				file[6] = 1; file[7] = 0;
				put32(file + 8, 16); put32(file + 12, (uint32_t)rl);
				memcpy(file + at, one, rl);
				snprintf(leaf, sizeof leaf, "diag-%03u.kdig", k);
				CK(write_file(dir, leaf, file, at + rl));
			}
			e = kof_db_load(dir);
			CK(e != NULL);
			if (!i)
				CK(e && e->n_diag == 64u);
			else
				KM_CHECK(e && e->n_diag == 65u,
					 "all 65 diagnose packs of a directory are read",
					 "KOF_DIAG_PACKS_MAX");
			if (e)
				kof_db_free(e);
			rm_all(dir);
		}
	}

	/*
	 * TWO NAMES, ONE 16-BIT ID: the pair that the old fold could not tell apart.
	 * The id is the full 32-bit hash now, so both load, each answers by its own id,
	 * and nothing is counted as lost.
	 */
	{
		static char a[16], b[16];
		static int16_t seen[65536];
		unsigned k, found = 0;

		memset(seen, -1, sizeof seen);
		for (k = 0; k < 70000u && !found; k++) {
			uint16_t id;

			snprintf(b, sizeof b, "col_%05u", k);
			id = kof_diag_id_(b);
			if (seen[id] >= 0) {
				snprintf(a, sizeof a, "col_%05d", seen[id]);
				found = 1;
			} else {
				seen[id] = (int16_t)k;
			}
		}
		CK(found && kof_diag_id_(a) == kof_diag_id_(b) && strcmp(a, b));
		CK(kof_diag_id32_(a) != kof_diag_id32_(b));
		e = load_pair(a, b);
		CK(e && has(e, a) && has(e, b) && e->n_diag == 2u);
		CK(e && kdb_diag_collisions(e) == 0u);
		if (e)
			kof_db_free(e);
		rm_all(collide_dir);
	}

	/*
	 * TWO NAMES, ONE 32-BIT ID: a real collision of the full hash, found by the
	 * birthday search (about 77000 names for an even chance, 400000 for
	 * certainty). The loader keeps the first, COUNTS the second and the build
	 * refuses such a pack - the loss is never silent, only a million times rarer.
	 */
	{
		struct idk { uint32_t id; uint32_t k; };
		/* names of a pseudo-random 10 letters each, from a fixed seed: the same
		 * search every run, and not names that differ in one digit, whose hashes
		 * a multiplicative hash spreads too evenly to collide */
		static char a[16], b[16];
		const unsigned N = 600000u;
		struct idk *t = malloc(N * sizeof *t);
		unsigned k, found = 0;

		CK(t != NULL);
		for (k = 0; t && k < N; k++) {
			char nm[16];

			rand_name(nm, k);
			t[k].id = kof_diag_id32_(nm);
			t[k].k = k;
		}
		if (t) {
			qsort(t, N, sizeof *t, idk_cmp);
			for (k = 1; k < N && !found; k++)
				if (t[k].id == t[k - 1u].id) {
					rand_name(a, t[k - 1u].k);
					rand_name(b, t[k].k);
					found = 1;
				}
		}
		free(t);
		CK(found && strcmp(a, b) && kof_diag_id32_(a) == kof_diag_id32_(b));
		e = found ? load_pair(a, b) : NULL;
		CK(e && has(e, a) && !has(e, b));
		CK(e && kdb_diag_collisions(e) == 1u);     /* the loss is counted */
		if (e)
			kof_db_free(e);
		rm_all(collide_dir);
	}

	rm_all(root);
	printf("caps db: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
