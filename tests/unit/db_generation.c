/*
 * db_generation - a published pack is replaced, never rewritten: an engine that
 * mapped the old generation keeps working, and an engine opened afterwards sees
 * the new one.
 *
 * WHY. The engine maps every pack read-only and reads it in place
 * (kof_map_file_ro). Truncating or rewriting the SAME file under a running
 * scanner makes its next page touch a SIGBUS. The builder therefore writes a
 * pack to a temporary beside it and renames over the final name
 * (kof_write_file_atomic): the old inode stays alive for the mapper, and the
 * name points at the complete new file. This test does what a build or an
 * update does while a scanner is running - on the engine's own test database,
 * copied to a scratch directory so the shared one is never touched.
 *
 * It does NOT make the unsupported thing happen (an in-place truncate of a
 * mapped pack): that is a genuine crash by design and nothing here swallows it.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/kofeng.h"

static unsigned checks, failures;
#define CK(c, ...) do { checks++; if (!(c)) { failures++; \
	printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); \
	printf("\n"); } } while (0)

static const char *src_db = "build/test/databases-sigs";
static const char *gen_db = "build/test/gen_db";

static uint8_t *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	struct stat st;
	uint8_t *b;

	if (!f)
		return NULL;
	if (fstat(fileno(f), &st) != 0 || st.st_size < 0) {
		fclose(f);
		return NULL;
	}
	b = malloc((size_t)st.st_size ? (size_t)st.st_size : 1u);
	if (b && fread(b, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
		free(b);
		b = NULL;
	}
	fclose(f);
	*n = (size_t)st.st_size;
	return b;
}

/* One layer of the test cipher: "LAYA", four clear bytes, the rest XOR 0x5a.
 * The unpacker that opens it (tests/sigs/layer_a_00.c) is a module in some pack,
 * so a scan returning two objects proves that pack is still readable. */
static size_t layer_sample(uint8_t *out)
{
	size_t i;

	memcpy(out, "LAYAZZZZ", 8);
	for (i = 0; i < 64u; i++)
		out[8 + i] = (uint8_t)(((i * 37u + 11u) | 0x80u) ^ 0x5au);
	return 72u;
}

static int count_cb(const char *name, const void *b, uint64_t n,
		    const struct kof_result *r, void *user)
{
	(void)name; (void)b; (void)n; (void)r;
	(*(unsigned *)user)++;
	return 0;
}

static int objects_of(kof_engine *e)
{
	kof_scanner *sc = kscan_new(e);
	struct kof_scan_option opt;
	uint8_t buf[80];
	unsigned n = 0;
	int rc;

	if (!sc)
		return -1;
	memset(&opt, 0, sizeof opt);
	opt.heur_level = 2;
	rc = kscan_bytes(sc, buf, layer_sample(buf), "gen//sample", &opt,
			 count_cb, &n);
	kscan_free(sc);
	return rc < 0 ? -1 : (int)n;
}

static int is_pack(const char *nm)
{
	size_t l = strlen(nm);

	return (l > 5u && !strcmp(nm + l - 5u, ".ksig")) ||
	       (l > 5u && !strcmp(nm + l - 5u, ".kdig"));
}

/* Apply `fn` to every pack file of the scratch generation. */
static unsigned each_pack(int (*fn)(const char *path, void *u), void *u)
{
	DIR *d = opendir(gen_db);
	struct dirent *de;
	unsigned n = 0;

	while (d && (de = readdir(d)) != NULL) {
		char p[600];

		if (!is_pack(de->d_name))
			continue;
		snprintf(p, sizeof p, "%s/%s", gen_db, de->d_name);
		if (fn(p, u))
			n++;
	}
	if (d)
		closedir(d);
	return n;
}

static int count_tmp(void)
{
	DIR *d = opendir(gen_db);
	struct dirent *de;
	int n = 0;

	while (d && (de = readdir(d)) != NULL)
		n += strstr(de->d_name, ".tmp") != NULL;
	if (d)
		closedir(d);
	return n;
}

/* Replace each pack with same-length garbage: the worst "new generation". */
static int garble(const char *path, void *u)
{
	size_t n;
	uint8_t *b = slurp(path, &n);
	int ok;

	(void)u;
	if (!b)
		return 0;
	memset(b, 0xab, n);
	ok = kof_write_file_atomic(path, b, n);
	free(b);
	return ok;
}

int main(int argc, char **argv)
{
	kof_engine *a, *b, *c;
	struct stat st, st2;
	char first[600] = "", missing[700];
	unsigned n_packs, rec_a, unp_a;
	DIR *d;
	struct dirent *de;
	uint8_t one[4] = { 1, 2, 3, 4 };

	if (argc > 1)
		src_db = argv[1];
	mkdir(gen_db, 0700);

	/* generation 1: a copy of the test database, every file via the atomic writer */
	{
		DIR *s = opendir(src_db);
		unsigned n = 0;

		if (!s) {
			printf("db generation: cannot open %s\n", src_db);
			return 2;
		}
		while ((de = readdir(s)) != NULL) {
			char p[600], q[600];
			size_t l;
			uint8_t *buf;

			if (!is_pack(de->d_name))
				continue;
			snprintf(p, sizeof p, "%s/%s", src_db, de->d_name);
			snprintf(q, sizeof q, "%s/%s", gen_db, de->d_name);
			buf = slurp(p, &l);
			CK(buf && kof_write_file_atomic(q, buf, l), "generation 1: %s", de->d_name);
			free(buf);
			if (!first[0])
				snprintf(first, sizeof first, "%s", q);
			n++;
		}
		closedir(s);
		CK(n > 5u, "the test database has packs (%u)", n);
	}
	CK(count_tmp() == 0, "no temporary is left after a successful write");

	a = keng_open(gen_db);
	if (!a) {
		printf("db generation: cannot open %s\n", gen_db);
		return 2;
	}
	rec_a = kdb_records(a);
	unp_a = kdb_unpackers(a);
	CK(objects_of(a) == 2, "baseline: the layer opens (%d objects)", objects_of(a));

	/* generation 2 published over the mapped one: every pack replaced */
	CK(first[0] && stat(first, &st) == 0, "pack present");
	n_packs = each_pack(garble, NULL);
	CK(n_packs > 5u, "every pack was replaced (%u)", n_packs);
	CK(stat(first, &st2) == 0 && st2.st_ino != st.st_ino,
	   "the name now points at a NEW inode (the old one stays for its mappers)");
	CK(count_tmp() == 0, "no temporary left after replacing");

	/* the engine that mapped generation 1 is undisturbed */
	CK(kdb_records(a) == rec_a && kdb_unpackers(a) == unp_a, "old engine: counts unchanged");
	CK(objects_of(a) == 2, "old engine: still scans against the old pack (%d)", objects_of(a));
	CK(objects_of(a) == 2, "old engine: and again");

	/* an engine opened now sees generation 2 (garbage): refused, not half loaded */
	b = keng_open(gen_db);
	CK(b == NULL || (kdb_records(b) == 0 && kdb_unpackers(b) == 0),
	   "new engine does not load the damaged generation");
	if (b)
		keng_close(b);
	CK(objects_of(a) == 2, "old engine unaffected by the new open");

	/* generation 3: the good packs again; a new engine sees them, the first one is still alive */
	{
		DIR *s = opendir(src_db);

		while (s && (de = readdir(s)) != NULL) {
			char p[600], q[600];
			size_t l;
			uint8_t *buf;

			if (!is_pack(de->d_name))
				continue;
			snprintf(p, sizeof p, "%s/%s", src_db, de->d_name);
			snprintf(q, sizeof q, "%s/%s", gen_db, de->d_name);
			buf = slurp(p, &l);
			CK(buf && kof_write_file_atomic(q, buf, l), "generation 3: %s", de->d_name);
			free(buf);
		}
		if (s)
			closedir(s);
	}
	c = keng_open(gen_db);
	CK(c != NULL, "new engine opens generation 3");
	if (c) {
		CK(kdb_records(c) == rec_a && kdb_unpackers(c) == unp_a, "generation 3 is the full database");
		CK(objects_of(c) == 2, "generation 3 scans");
	}
	CK(objects_of(a) == 2, "the generation-1 engine is STILL scanning (3 generations alive)");
	if (c)
		keng_close(c);
	keng_close(a);

	/* the failure paths: nothing changes, nothing is left behind */
	snprintf(missing, sizeof missing, "%s/no-such-dir/x.ksig", gen_db);
	CK(!kof_write_file_atomic(missing, one, sizeof one), "a directory that does not exist is refused");
	snprintf(missing, sizeof missing, "%s/adir.ksig", gen_db);
	mkdir(missing, 0700);
	CK(!kof_write_file_atomic(missing, one, sizeof one), "renaming over a directory is refused");
	CK(count_tmp() == 0, "failures remove their temporary");
	rmdir(missing);
	CK(!kof_write_file_atomic(NULL, one, 4) && !kof_write_file_atomic("", one, 4) &&
	   !kof_write_file_atomic(first, NULL, 4), "bad arguments");
	/* an empty file is a valid write */
	snprintf(missing, sizeof missing, "%s/empty.bin", gen_db);
	CK(kof_write_file_atomic(missing, NULL, 0) && stat(missing, &st) == 0 && st.st_size == 0,
	   "an empty file");
	remove(missing);

	d = opendir(gen_db);
	while (d && (de = readdir(d)) != NULL) {
		char p[600];

		if (de->d_name[0] == '.')
			continue;
		snprintf(p, sizeof p, "%s/%s", gen_db, de->d_name);
		remove(p);
	}
	if (d)
		closedir(d);
	rmdir(gen_db);

	printf("db generation: %u checks, %u failed\n", checks, failures);
	return failures ? 1 : 0;
}
