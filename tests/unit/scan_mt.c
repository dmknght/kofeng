/*
 * scan_mt - the parallel walk finds the same objects as the serial one.
 *
 * A scan that runs on eight threads and reports something different from the
 * same scan on one is worse than a slow scan, and the difference would be
 * invisible in ordinary use: the counts are large, the order is expected to
 * change, and a handful of missed files reads as a handful of clean files. So
 * the assertion is not "it is fast" but "it is the SAME", and it is made on the
 * set of object names rather than on a count - a count matches while two files
 * swap places, and a set does not.
 *
 *
 * WHAT IS ASSERTED
 *
 *   SAME SET     Every name the serial walk produced, the parallel walk
 *                produced, and nothing else. This is what catches a work queue
 *                that drops an item under contention or hands one out twice.
 *
 *   SAME VERDICT Each name comes back with the same level. A worker whose
 *                scanner state leaked into another's would show up here rather
 *                than as a crash.
 *
 *   ONE SCANNER  n_sc of 1 goes through the serial path. Asserted because it is
 *                the promise the header makes to every existing caller, and
 *                because it is one line in the implementation to break.
 *
 *   ABORT        A callback that returns non-zero stops the parallel walk, and
 *                stops it having reported fewer objects than the tree holds.
 *                An abort that only sets a flag the producer never reads is a
 *                scan that cannot be interrupted.
 *
 * The tree is built in a temporary directory: a handful of small ELFs, enough
 * files that eight workers actually contend for them.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../libkofeng/kofeng.h"

#define FILES     64u
#define SUBDIRS    4u
#define MAX_SEEN 512u

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

struct seen {
	char     name[MAX_SEEN][256];
	uint32_t level[MAX_SEEN];
	uint32_t n;
	uint32_t stop_after;      /* 0 = never abort */
	uint32_t overflow;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)bytes; (void)len;
	if (s->n < MAX_SEEN) {
		snprintf(s->name[s->n], sizeof s->name[0], "%s", name);
		s->level[s->n] = res ? res->n : 0u;   /* how many findings, as the verdict */
		s->n++;
	} else {
		s->overflow = 1;
	}
	return (s->stop_after && s->n >= s->stop_after) ? 1 : 0;
}

/*
 * The same set, allowing for repeats: every name is matched against an unused
 * slot on the other side, so two files with one name still have to appear twice
 * in both.
 */
static int same_set(const struct seen *a, const struct seen *b)
{
	static uint8_t used[MAX_SEEN];
	uint32_t i;

	if (a->n != b->n)
		return 0;
	memset(used, 0, sizeof used);
	for (i = 0; i < a->n; i++) {
		uint32_t j;
		int hit = -1;

		for (j = 0; j < b->n; j++) {
			if (used[j] || strcmp(a->name[i], b->name[j]) != 0)
				continue;
			hit = (int)j;
			break;
		}
		if (hit < 0)
			return 0;
		if (a->level[i] != b->level[hit])
			return 0;
		used[hit] = 1;
	}
	return 1;
}

/* A small ELF64 whose body is `tag` repeated, so the files differ. */
static void write_elf(const char *path, uint8_t tag)
{
	static uint8_t f[4096];
	const uint64_t base = 0x400000, off = 0x1000;
	uint8_t *ph = f + 64;
	unsigned i;
	FILE *fp;

	memset(f, 0, sizeof f);
	memcpy(f, "\177ELF\2\1\1", 7);
	f[0x10] = 2;
	f[0x12] = 0x3e;
	f[0x14] = 1;
	for (i = 0; i < 8; i++)
		f[0x18 + i] = (uint8_t)((base + off) >> (i * 8));
	f[0x20] = 64;
	f[0x34] = 64;
	f[0x36] = 56;
	f[0x38] = 1;
	ph[0] = 1;
	ph[4] = 5;
	for (i = 0; i < 8; i++) {
		ph[0x10 + i] = (uint8_t)(base >> (i * 8));
		ph[0x18 + i] = (uint8_t)(base >> (i * 8));
		ph[0x20 + i] = (uint8_t)(sizeof f >> (i * 8));
		ph[0x28 + i] = (uint8_t)(sizeof f >> (i * 8));
	}
	memset(f + off, tag, sizeof f - off);
	fp = fopen(path, "wb");
	if (!fp)
		return;
	fwrite(f, 1, sizeof f, fp);
	fclose(fp);
}

static void build_tree(const char *root)
{
	char path[512];
	unsigned i;

	mkdir(root, 0700);
	for (i = 0; i < SUBDIRS; i++) {
		snprintf(path, sizeof path, "%s/d%u", root, i);
		mkdir(path, 0700);
	}
	for (i = 0; i < FILES; i++) {
		snprintf(path, sizeof path, "%s/d%u/f%03u.bin",
			 root, i % SUBDIRS, i);
		write_elf(path, (uint8_t)(0x40u + (i & 0x3fu)));
	}
}

static void drop_tree(const char *root)
{
	char path[512];
	unsigned i;

	for (i = 0; i < FILES; i++) {
		snprintf(path, sizeof path, "%s/d%u/f%03u.bin",
			 root, i % SUBDIRS, i);
		remove(path);
	}
	for (i = 0; i < SUBDIRS; i++) {
		snprintf(path, sizeof path, "%s/d%u", root, i);
		rmdir(path);
	}
	rmdir(root);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	const char *root = "build/test/scan_mt.d";
	static struct seen one, many, capped;
	struct kof_scan_option opt;
	kof_engine *eng;
	kof_scanner *scs[8];
	unsigned i, n_sc = 8;
	int rc1, rc8;

	build_tree(root);

	eng = kof_engine_open(db);
	if (!eng) {
		printf("scan mt: cannot open %s\n", db);
		drop_tree(root);
		return 2;
	}
	for (i = 0; i < n_sc; i++) {
		scs[i] = kof_scanner_new(eng);
		if (!scs[i]) {
			printf("scan mt: out of memory\n");
			kof_engine_close(eng);
			drop_tree(root);
			return 2;
		}
	}

	memset(&opt, 0, sizeof opt);
	opt.recurse_dirs = 1;

	rc1 = kof_scan_path(scs[0], root, &opt, on_object, &one);
	rc8 = kof_scan_path_mt(scs, n_sc, root, &opt, on_object, &many);

	printf("  1 luồng  -> %u object (rc=%d)\n", one.n, rc1);
	printf("  %u luồng -> %u object (rc=%d)\n", n_sc, many.n, rc8);
	if (one.overflow || many.overflow)
		fail("the test's own buffer overflowed - raise MAX_SEEN");
	if (one.n == 0)
		fail("the serial walk found nothing, so nothing is being compared");
	if (!same_set(&one, &many))
		fail("the parallel walk did not produce the same objects");
	if (rc1 != rc8)
		fail("the two walks reported different object counts");

	/*
	 * One scanner: the header promises this is the serial walk, order and
	 * all. Asserted on the ORDER, because that is what the promise is about
	 * and it is the only thing that distinguishes the two paths here.
	 */
	{
		static struct seen solo;
		int ordered = 1;

		kof_scan_path_mt(scs, 1, root, &opt, on_object, &solo);
		if (solo.n != one.n) {
			ordered = 0;
		} else {
			for (i = 0; i < solo.n; i++)
				if (strcmp(solo.name[i], one.name[i]) != 0) {
					ordered = 0;
					break;
				}
		}
		printf("  1 scanner qua API song song -> %u object, %s thứ tự\n",
		       solo.n, ordered ? "giữ nguyên" : "ĐỔI");
		if (!ordered)
			fail("n_sc of 1 did not behave as the serial walk");
	}

	/* Abort: the callback stops after a few objects and the walk has to end. */
	capped.stop_after = 4;
	kof_scan_path_mt(scs, n_sc, root, &opt, on_object, &capped);
	printf("  callback dừng sau 4 -> %u object\n", capped.n);
	if (capped.n >= one.n)
		fail("an aborting callback did not stop the parallel walk");

	for (i = 0; i < n_sc; i++)
		kof_scanner_free(scs[i]);
	kof_engine_close(eng);
	drop_tree(root);
	printf("scan mt: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
