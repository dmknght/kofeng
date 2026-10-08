/*
 * diag_pack - what the loader does with a diagnose pack, and with one that is wrong.
 *
 * A diag-<kind>.kdig is a table of (offset, length) followed by records, and every
 * number in it is read out of a file in a directory somebody assembled: it can be
 * truncated by a full disk, left over from an older build, written by another
 * tool, or simply not a pack. The properties under test are the ones the loader's
 * comment claims:
 *
 *   a header that does not add up refuses the WHOLE pack - no record in it can be
 *   trusted to start where the table says;
 *
 *   a RECORD that does not parse, or whose table entry points outside the file, is
 *   skipped and its siblings still load - one bad diagnose must not take the
 *   others with it, and must not be believed either;
 *
 *   a damaged pack never takes the signature packs beside it down.
 *
 * Every case that damages something names which check it is aimed at. A record
 * that the loader would also refuse for a second reason proves nothing about the
 * first.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofpathogen.h"

static int failures;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		failures++;
}

/* ---- records and packs, spelled out byte by byte ------------------------ */

static size_t rec(uint8_t *b, const char *name)
{
	size_t nl = strlen(name), at = 0;
	uint16_t cap = (uint16_t)KOF_NUCLEO_NET_OPEN;

	b[at++] = 1; b[at++] = 0;                 /* one node          */
	b[at++] = KOF_DIAG_ANALYSIS_SYSCALL;
	b[at++] = (uint8_t)nl;
	memcpy(b + at, name, nl); at += nl;
	b[at++] = (uint8_t)cap; b[at++] = (uint8_t)(cap >> 8);
	b[at++] = 0; b[at++] = 0;                 /* flags             */
	b[at++] = KOF_DIAG_NO_PARENT;
	b[at++] = 0;                              /* role              */
	b[at++] = 0;                              /* bits              */
	b[at++] = 0;                              /* attribute length  */
	return at;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* A pack of `n` named records. Returns its length. */
static size_t pack(uint8_t *b, const char *const *names, unsigned n)
{
	size_t at = 8u + (size_t)n * 8u;
	unsigned i;

	memcpy(b, "KDGP", 4);
	b[4] = 1; b[5] = 0;
	b[6] = (uint8_t)n; b[7] = (uint8_t)(n >> 8);
	for (i = 0; i < n; i++) {
		size_t l = rec(b + at, names[i]);

		put32(b + 8u + i * 8u, (uint32_t)at);
		put32(b + 12u + i * 8u, (uint32_t)l);
		at += l;
	}
	return at;
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

/* A case: a directory with the good signature pack and these diagnose packs. */
struct file { const char *leaf; const uint8_t *b; size_t n; };

static struct kof_engine *open_case(const char *tag, char *dir, size_t cap,
				    const struct file *fs, unsigned n_fs)
{
	unsigned i;

	snprintf(dir, cap, "%s/%s", root, tag);
	if (kof_mkdir(dir, 0700) != 0 || !copy_good_pack(dir))
		return NULL;
	for (i = 0; i < n_fs; i++)
		if (!write_file(dir, fs[i].leaf, fs[i].b, fs[i].n))
			return NULL;
	return kof_db_load(dir);
}

static int has(const struct kof_engine *e, const char *name)
{
	uint32_t i;

	for (i = 0; i < e->n_diag; i++)
		if (!strcmp(e->diag[i].name, name))
			return 1;
	return 0;
}

/* Runs one case and reports how many diagnoses survived. -1: the engine did
 * not load at all, which none of these cases may cause. */
static int run(const char *tag, const struct file *fs, unsigned n_fs,
	       const char *want_a, const char *want_b)
{
	char dir[640];
	struct kof_engine *e = open_case(tag, dir, sizeof dir, fs, n_fs);
	int n;

	if (!e) {
		rm_all(dir);
		return -1;
	}
	n = (int)e->n_diag;
	if (want_a && !has(e, want_a))
		n = -2;
	if (want_b && !has(e, want_b))
		n = -2;
	kof_db_free(e);
	rm_all(dir);
	return n;
}

int main(int argc, char **argv)
{
	static uint8_t good[256], bad[256], big[8];
	static const char *const two[] = { "aa", "bb" };
	static const char *const one_b[] = { "bb" };
	size_t gl, i;
	int n;

	if (argc > 1)
		dbdir = argv[1];
	snprintf(root, sizeof root, "build/test/diagpack_%d", (int)getpid());
	if (kof_mkdir(root, 0700) != 0) {
		printf("diag_pack: cannot make a work directory\n");
		return 1;
	}
	printf("diag_pack:\n");

	gl = pack(good, two, 2);
	{ struct file f[] = { { "diag-x.kdig", good, gl } };
	  n = run("good", f, 1, "aa", "bb");
	  ok("a good pack loads both of its diagnoses", n == 2); }

	/* ---- a header that does not add up refuses the whole pack ---------- */
	memcpy(bad, good, gl); memcpy(bad, "KDGX", 4);
	{ struct file f[] = { { "diag-x.kdig", bad, gl } };
	  n = run("magic", f, 1, NULL, NULL);
	  ok("a wrong magic loads nothing and the engine still loads", n == 0); }

	memcpy(bad, good, gl); bad[4] = 2;
	{ struct file f[] = { { "diag-x.kdig", bad, gl } };
	  n = run("version", f, 1, NULL, NULL);
	  ok("a version this build does not know loads nothing", n == 0); }

	{ struct file f[] = { { "diag-x.kdig", good, 8 } };
	  n = run("table_cut", f, 1, NULL, NULL);
	  ok("a table longer than the file loads nothing", n == 0); }

	{ struct file f[] = { { "diag-x.kdig", good, 7 } };
	  n = run("under_header", f, 1, NULL, NULL);
	  ok("a file shorter than its own header loads nothing", n == 0); }

	{ struct file f[] = { { "diag-x.kdig", good, 0 } };
	  n = run("empty", f, 1, NULL, NULL);
	  ok("an empty file loads nothing", n == 0); }

	memcpy(bad, good, gl); bad[6] = 0xff; bad[7] = 0xff;
	{ struct file f[] = { { "diag-x.kdig", bad, gl } };
	  n = run("count_huge", f, 1, NULL, NULL);
	  ok("a count of 65535 against a short file loads nothing", n == 0); }

	/* ---- a record that is wrong is skipped, its sibling is not -------- */
	memcpy(bad, good, gl); put32(bad + 8, (uint32_t)gl + 100u);
	{ struct file f[] = { { "diag-x.kdig", bad, gl } };
	  n = run("off_past", f, 1, "bb", NULL);
	  ok("an offset past the end skips that record, the next loads", n == 1); }

	memcpy(bad, good, gl); put32(bad + 12, 0x7fffffffu);
	{ struct file f[] = { { "diag-x.kdig", bad, gl } };
	  n = run("len_past", f, 1, "bb", NULL);
	  ok("a length past the end skips that record, the next loads", n == 1); }

	memcpy(bad, good, gl); put32(bad + 8, 0xffffffffu); put32(bad + 12, 0xffffffffu);
	{ struct file f[] = { { "diag-x.kdig", bad, gl } };
	  n = run("wrap", f, 1, "bb", NULL);
	  ok("offset and length that would wrap are not believed", n == 1); }

	memcpy(bad, good, gl); put32(bad + 12, 0);
	{ struct file f[] = { { "diag-x.kdig", bad, gl } };
	  n = run("zero_len", f, 1, "bb", NULL);
	  ok("a zero length record is skipped", n == 1); }

	memcpy(bad, good, gl);
	{ uint32_t off = (uint32_t)(bad[8] | (bad[9] << 8));
	  for (i = 0; i < 12; i++) bad[off + i] = 0;          /* the first record, zeroed */
	}
	{ struct file f[] = { { "diag-x.kdig", bad, gl } };
	  n = run("garbage", f, 1, "bb", NULL);
	  ok("a record of zeros does not parse and is skipped", n == 1); }

	/* ---- the directory ------------------------------------------------ */
	gl = pack(bad, one_b, 1);
	{ uint8_t a1[128]; static const char *const aa[] = { "aa" };
	  size_t l1 = pack(a1, aa, 1);
	  struct file f[] = { { "diag-a.kdig", a1, l1 }, { "diag-b.kdig", bad, gl } };
	  n = run("two_packs", f, 2, "aa", "bb");
	  ok("two packs in one directory both load", n == 2); }

	{ struct file f[] = { { "diag-a.kdig", bad, gl }, { "diag-b.kdig", bad, gl } };
	  n = run("same_name", f, 2, "bb", NULL);
	  ok("the same diagnose in two packs is loaded once", n == 1); }

	{ static const char junk[] = "this is an older build's diagnose, one file";
	  struct file f[] = { { "diag-old.kdig", (const uint8_t *)junk, sizeof junk },
			      { "diag-new.kdig", good, 0 } };
	  gl = pack(good, two, 2);
	  f[1].n = gl;
	  n = run("stale_beside_good", f, 2, "aa", "bb");
	  ok("a stale file in the old format does not stop the good pack", n == 2); }

	{ struct file f[] = { { "diag-x.kdig", good, gl }, { "unrelated.txt", (const uint8_t *)"x", 1 } };
	  n = run("unrelated", f, 2, "aa", "bb");
	  ok("a file that is not a diagnose pack by name is not read", n == 2); }

	/* ---- the size ceiling -------------------------------------------- */
	{
		char dir[640];
		struct kof_engine *e;
		FILE *fp;
		static uint8_t zeros[1u << 16];
		size_t w;

		snprintf(dir, sizeof dir, "%s/huge", root);
		if (kof_mkdir(dir, 0700) == 0 && copy_good_pack(dir)) {
			char path[700];

			memcpy(big, "KDGP\x01\x00\x00\x00", 8);
			snprintf(path, sizeof path, "%s/diag-big.kdig", dir);
			fp = fopen(path, "wb");
			if (fp) {
				fwrite(big, 1, 8, fp);
				for (w = 0; w < (5u << 20) / sizeof zeros; w++)
					fwrite(zeros, 1, sizeof zeros, fp);
				fclose(fp);
			}
			e = kof_db_load(dir);
			ok("a pack over the size ceiling is refused, the engine loads",
			   e && e->n_diag == 0);
			if (e)
				kof_db_free(e);
		} else {
			ok("cannot set up the oversize case", 0);
		}
		rm_all(dir);
	}

	rm_all(root);
	printf("diag_pack: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
