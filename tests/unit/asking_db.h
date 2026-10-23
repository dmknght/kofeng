/*
 * asking_db.h - a database that holds what the product ships and the diagnoses that ASK.
 *
 * Needs <dirent.h>, <stdio.h>, <stdlib.h>, <string.h>, <sys/stat.h>, <unistd.h>; a test
 * includes this after them.
 */

#ifndef KOFENG_TESTS_ASKING_DB_H
#define KOFENG_TESTS_ASKING_DB_H

#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Remove `path` and everything under it. lstat, so a symlink is unlinked and never
 * followed out of the tree; the caller passes the one directory the test made. */
static inline void ad_rmtree(const char *path)
{
	struct stat sb;
	DIR *d;
	struct dirent *de;
	char p[1024];

	if (lstat(path, &sb) != 0)
		return;
	if (!S_ISDIR(sb.st_mode)) {
		unlink(path);
		return;
	}
	d = opendir(path);
	if (d) {
		while ((de = readdir(d)) != NULL) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			if ((size_t)snprintf(p, sizeof p, "%s/%s", path, de->d_name) >= sizeof p)
				continue;
			ad_rmtree(p);
		}
		closedir(d);
	}
	rmdir(path);
}

/*
 * A DATABASE THAT HOLDS WHAT THE PRODUCT SHIPS AND A DIAGNOSE THAT ASKS.
 *
 * The product ships unpackers and no diagnoses, so on the shipped database nothing asks
 * the engine to interpret an object: the asks come from a diagnose's own declaration (a
 * file attribute, an import). A test of what the interpreter COSTS - its ledger, its
 * ceiling, its count - needs something to ask, and the fixtures that do are the diagnoses
 * of tests/shape (build/test/databases-shape), the shape every synthetic stager of the
 * suite has. This makes one directory with both: the release packs and those, copied, in
 * a directory of this process's own, removed when it exits. NULL when either source is
 * missing.
 */
static char ad_dir[160];
static char ad_dir_script[160];
static int  ad_exit_set;

static void ad_gone(void)
{
	if (ad_dir[0])
		ad_rmtree(ad_dir);
	if (ad_dir_script[0])
		ad_rmtree(ad_dir_script);
}

static inline int ad_copy_file(const char *from, const char *to)
{
	FILE *f = fopen(from, "rb"), *o;
	char buf[8192];
	size_t n;
	int ok = 1;

	if (!f)
		return 0;
	o = fopen(to, "wb");
	if (!o) {
		fclose(f);
		return 0;
	}
	while ((n = fread(buf, 1, sizeof buf, f)) > 0)
		if (fwrite(buf, 1, n, o) != n)
			ok = 0;
	fclose(f);
	return fclose(o) == 0 && ok;
}

static inline void ad_copy_packs(const char *srcdir, const char *dstdir, const char *ext)
{
	DIR *d = opendir(srcdir);
	struct dirent *de;

	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name), e = strlen(ext);
		char a[512], b[512];

		if (l <= e || strcmp(de->d_name + l - e, ext) != 0)
			continue;
		snprintf(a, sizeof a, "%s/%s", srcdir, de->d_name);
		snprintf(b, sizeof b, "%s/%s", dstdir, de->d_name);
		(void)ad_copy_file(a, b);
	}
	closedir(d);
}

static inline const char *ad_db_asking(void)
{
	struct stat sb;

	if (ad_dir[0])
		return ad_dir;
	if (stat("build/release/databases", &sb) != 0 || stat("build/test/databases-shape", &sb) != 0)
		return NULL;
	snprintf(ad_dir, sizeof ad_dir, "build/test/db-asking-%d", (int)getpid());
	if (mkdir(ad_dir, 0700) != 0) {
		ad_dir[0] = 0;
		return NULL;
	}
	ad_copy_packs("build/release/databases", ad_dir, ".ksig");
	ad_copy_packs("build/test/databases-shape", ad_dir, ".kdig");
	if (!ad_exit_set) {
		ad_exit_set = 1;
		atexit(ad_gone);
	}
	return ad_dir;
}

/*
 * THE PRODUCT'S PACKS AND ONE DETECTOR THAT TARGETS SCRIPTS.
 *
 * Whether a script a container carries is opened as a child depends on whether anything
 * in the database would look inside one (the format-wanted gate), and the product ships
 * no detector now. A test of what the engine does with a document's carried scripts needs
 * one, and tests/sigs has it. Made like ad_db_asking, in a directory of this process's own.
 */
static inline const char *ad_db_script(void)
{
	struct stat sb;
	char pack[300];

	if (ad_dir_script[0])
		return ad_dir_script;
	if (stat("build/release/databases", &sb) != 0 ||
	    stat("build/test/databases-sigs/sigs-script.ksig", &sb) != 0)
		return NULL;
	snprintf(ad_dir_script, sizeof ad_dir_script, "build/test/db-script-%d", (int)getpid());
	if (mkdir(ad_dir_script, 0700) != 0) {
		ad_dir_script[0] = 0;
		return NULL;
	}
	ad_copy_packs("build/release/databases", ad_dir_script, ".ksig");
	snprintf(pack, sizeof pack, "%s/sigs-script.ksig", ad_dir_script);
	(void)ad_copy_file("build/test/databases-sigs/sigs-script.ksig", pack);
	if (!ad_exit_set) {
		ad_exit_set = 1;
		atexit(ad_gone);
	}
	return ad_dir_script;
}

#endif /* KOFENG_TESTS_ASKING_DB_H */
