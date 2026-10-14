/*
 * xz_multistream - an xz file of several streams opens every stream's blocks, in order, and a
 * stream the walk cannot account for is said.
 *
 * FOUND BY the differential of tests/unit/hunt_bz2_empty_first.c (finding H6): the parser found the
 * footer from the END of the file, so `cat a.xz b.xz` opened b's blocks only and the object said
 * "Damaged" about a valid file. xz_parse.c now walks the streams back from the last (footer, index,
 * the start the index's sizes give, the zero words of stream padding, the footer before), and the
 * module opens the blocks of all of them in file order, as `xz -dc` decodes them.
 *
 * THE DIFFERENTIAL, generated here and not stored: streams are made by the xz tool from data this
 * test makes (so what the engine must produce is known without trusting any decoder), joined with
 * stream padding, written under build/ and decoded by `xz -dc` and by Python's lzma module; the
 * engine's direct children, concatenated in order, must equal the data. Python's lzma reads stream
 * padding wrongly (it stops at the first padded stream and says nothing: measured here, 4 zero
 * bytes between two streams returns the first stream's data only) so it is a reference for the
 * unpadded files and its answer on the padded ones is printed, not asserted; `xz -dc` is the
 * reference for all.
 *
 * Needs the xz tool and the built database, run from the repository root; python3 is optional.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../libkofeng/kofeng.h"

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

struct buf {
	uint8_t *p;
	size_t n, cap;
};

static int buf_add(struct buf *b, const void *p, size_t n)
{
	if (b->n + n > b->cap) {
		size_t nc = b->cap ? b->cap : 4096;
		uint8_t *t;

		while (nc < b->n + n)
			nc *= 2;
		t = realloc(b->p, nc);
		if (!t)
			return 0;
		b->p = t;
		b->cap = nc;
	}
	if (n)
		memcpy(b->p + b->n, p, n);
	b->n += n;
	return 1;
}

static char dir[64];

static void put_file(const char *name, const uint8_t *p, size_t n, char *path, size_t cap)
{
	FILE *f;

	snprintf(path, cap, "%s/%s", dir, name);
	f = fopen(path, "wb");
	if (f) {
		if (n)
			(void)fwrite(p, 1, n, f);
		fclose(f);
	}
}

/* what a command writes to stdout, and its exit status (-1: not run) */
static int run_read(const char *cmd, struct buf *out)
{
	FILE *f = popen(cmd, "r");
	uint8_t tmp[65536];
	size_t got;
	int st;

	out->n = 0;
	if (!f)
		return -1;
	while ((got = fread(tmp, 1, sizeof tmp, f)) > 0)
		if (!buf_add(out, tmp, got))
			break;
	st = pclose(f);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* data of one segment: text with the segment number and a counter, compressible and not a format */
static void make_data(struct buf *d, unsigned seg, size_t len)
{
	char line[48];
	size_t i = 0;

	d->n = 0;
	while (d->n < len) {
		int k = snprintf(line, sizeof line, "seg%u-line%08zx\n", seg, i++);

		if (!buf_add(d, line, (size_t)k))
			break;
	}
	d->n = len;
}

/* one xz stream of `len` bytes of segment `seg`; check is the tool's name for it, bs the block size */
static int make_stream(struct buf *out, unsigned seg, size_t len, const char *check, unsigned bs)
{
	struct buf d = { 0 };
	char in[128], cmd[512];
	int rc;

	make_data(&d, seg, len);
	put_file("in.dat", d.p, d.n, in, sizeof in);
	snprintf(cmd, sizeof cmd, "xz -c -T1 -F xz --check=%s --block-size=%u '%s' 2>/dev/null", check, bs ? bs : 0u, in);
	if (!bs)
		snprintf(cmd, sizeof cmd, "xz -c -T1 -F xz --check=%s '%s' 2>/dev/null", check, in);
	rc = run_read(cmd, out);
	free(d.p);
	unlink(in);
	return rc == 0;
}

struct seg {
	size_t len;
	const char *check;
	unsigned bs;
	unsigned pad;      /* zero bytes after the stream, a multiple of four for a valid file */
	int junk;          /* bytes of 'J' instead of zeros: a chain that cannot be walked */
};

struct seen {
	struct buf kids;   /* the direct children, concatenated in the order they came */
	unsigned n_kids;
	unsigned top_broken;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;
	const char *p, *q;

	if (!s->n_kids && !s->kids.n && !strstr(name, "//")) {
		s->top_broken = res->broken;
		return 0;
	}
	/* a direct child is "<root>//<n>:<label>": one separator */
	p = strstr(name, "//");
	q = p ? strstr(p + 2, "//") : NULL;
	if (p && !q && bytes) {
		(void)buf_add(&s->kids, bytes, (size_t)len);
		s->n_kids++;
	}
	return 0;
}

static void scan(kof_scanner *sc, const uint8_t *p, size_t n, struct seen *s)
{
	struct kof_scan_option opt;

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	opt.max_object_depth = 4;
	opt.emu_forbidden = 1;
	(void)kscan_bytes(sc, p, n, "t.xz", &opt, on_object, s);
}

/* the file and the data it holds: `segs` joined, each followed by its padding */
static int build(const struct seg *segs, unsigned n, struct buf *file, struct buf *want, unsigned first_seg)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		struct buf st = { 0 }, d = { 0 };
		uint8_t pad[64];

		if (!make_stream(&st, first_seg + i, segs[i].len, segs[i].check, segs[i].bs)) {
			free(st.p);
			return 0;
		}
		buf_add(file, st.p, st.n);
		make_data(&d, first_seg + i, segs[i].len);
		buf_add(want, d.p, d.n);
		free(st.p);
		free(d.p);
		memset(pad, segs[i].junk ? 'J' : 0, sizeof pad);
		buf_add(file, pad, segs[i].pad > sizeof pad ? sizeof pad : segs[i].pad);
	}
	return 1;
}

/* the differential: xz -dc over the file (and Python's lzma when it can be) against the data */
static void reference(const char *name, const struct buf *file, const struct buf *want, int padded)
{
	char path[128], cmd[512];
	struct buf out = { 0 };
	int rc;

	put_file("f.xz", file->p, file->n, path, sizeof path);
	snprintf(cmd, sizeof cmd, "xz -dc '%s' 2>/dev/null", path);
	rc = run_read(cmd, &out);
	CK(rc == 0 && out.n == want->n && (!want->n || memcmp(out.p, want->p, want->n) == 0),
	   "%s: `xz -dc` rc %d gave %zu bytes, the data is %zu (the case is not valid xz)", name, rc, out.n, want->n);
	snprintf(cmd, sizeof cmd,
		 "python3 -I -c 'import lzma,sys; sys.stdout.buffer.write(lzma.open(sys.argv[1]).read())' '%s' 2>/dev/null", path);
	rc = run_read(cmd, &out);
	if (rc == 0) {
		int same = out.n == want->n && (!want->n || memcmp(out.p, want->p, want->n) == 0);

		if (!padded)
			CK(same, "%s: python lzma gave %zu bytes, the data is %zu", name, out.n, want->n);
		else
			printf("  %s: python lzma %s on the padded file (%zu of %zu bytes)\n", name,
			       same ? "agrees" : "differs - it reads stream padding wrongly", out.n, want->n);
	}
	free(out.p);
	unlink(path);
}

static void good(kof_scanner *sc, const char *name, const struct seg *segs, unsigned n, unsigned want_kids_min)
{
	struct buf file = { 0 }, want = { 0 };
	struct seen s;
	unsigned i, padded = 0;

	for (i = 0; i < n; i++)
		padded |= segs[i].pad != 0;
	CK(build(segs, n, &file, &want, 1), "%s: the xz tool made no stream", name);
	reference(name, &file, &want, (int)padded);
	scan(sc, file.p, file.n, &s);
	printf("  %-34s %2u streams, %6zu bytes -> %2u children, %6zu bytes, broken %u\n", name, n, file.n, s.n_kids, s.kids.n, s.top_broken);
	CK(s.kids.n == want.n && (!want.n || memcmp(s.kids.p, want.p, want.n) == 0),
	   "%s: the children hold %zu bytes, `xz -dc` gives %zu (or the order differs)", name, s.kids.n, want.n);
	CK(s.n_kids >= want_kids_min, "%s: %u children, at least %u expected", name, s.n_kids, want_kids_min);
	CK(s.top_broken == 0, "%s: a valid file said broken=%u", name, s.top_broken);
	free(s.kids.p);
	free(file.p);
	free(want.p);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	kof_engine *eng;
	kof_scanner *sc;
	struct buf probe = { 0 };
	unsigned i;

	snprintf(dir, sizeof dir, "build/kof_xzm_XXXXXX");
	if (!mkdtemp(dir)) {
		printf("xz_multistream: no scratch directory under build/\n");
		return 1;
	}
	if (run_read("xz --version", &probe) != 0) {
		printf("xz_multistream: the xz tool is not installed: nothing tested\n");
		rmdir(dir);
		return 1;
	}
	free(probe.p);
	eng = keng_open(db);
	if (!eng) {
		printf("xz_multistream: no database at %s\n", db);
		rmdir(dir);
		return 1;
	}
	sc = kscan_new(eng);
	CK(sc != NULL, "scanner");
	if (!sc)
		return 1;

	printf("== xz: concatenated streams, stream padding\n");
	{
		const struct seg two[] = { { 6000, "crc64", 0, 0, 0 }, { 9000, "crc64", 0, 0, 0 } };
		const struct seg pad[] = { { 5000, "crc32", 0, 4, 0 }, { 7000, "crc64", 0, 8, 0 }, { 3000, "sha256", 0, 4, 0 } };
		const struct seg checks[] = { { 4000, "none", 0, 0, 0 }, { 4000, "crc32", 0, 0, 0 },
					      { 4000, "crc64", 0, 0, 0 }, { 4000, "sha256", 0, 0, 0 } };
		const struct seg blocks[] = { { 20000, "crc64", 4096, 0, 0 }, { 30000, "crc32", 8192, 4, 0 } };
		const struct seg empty_first[] = { { 0, "crc64", 0, 0, 0 }, { 5000, "crc64", 0, 0, 0 } };
		const struct seg empty_mid[] = { { 5000, "crc64", 0, 0, 0 }, { 0, "crc32", 0, 4, 0 }, { 6000, "crc64", 0, 0, 0 } };
		const struct seg one_padded[] = { { 5000, "crc64", 0, 12, 0 } };
		struct seg many[40];

		good(sc, "two streams", two, 2, 2);
		good(sc, "three streams, padding 4/8/4", pad, 3, 3);
		good(sc, "four checks none/crc32/crc64/sha256", checks, 4, 4);
		good(sc, "two multi-block streams", blocks, 2, 5 + 4);
		good(sc, "empty first stream", empty_first, 2, 1);
		good(sc, "empty stream in the middle", empty_mid, 3, 2);
		good(sc, "one stream and trailing padding", one_padded, 1, 1);
		for (i = 0; i < 40; i++) {
			many[i].len = 300u + i * 17u;
			many[i].check = i % 2 ? "crc32" : "crc64";
			many[i].bs = 0;
			many[i].pad = i % 5 == 0 ? 4u : 0u;
			many[i].junk = 0;
		}
		good(sc, "forty streams", many, 40, 40);
	}

	printf("== xz: a stream the walk cannot account for is said\n");
	{
		const struct seg junk_between[] = { { 5000, "crc64", 0, 4, 1 }, { 6000, "crc64", 0, 0, 0 } };
		const struct seg odd_pad[] = { { 5000, "crc64", 0, 2, 0 }, { 6000, "crc64", 0, 0, 0 } };
		const struct seg *cases[] = { junk_between, odd_pad };
		static const char *const names[] = { "garbage between streams", "padding of 2 bytes (not a multiple of 4)" };

		for (i = 0; i < 2; i++) {
			struct buf file = { 0 }, want = { 0 }, last = { 0 };
			struct seen s;

			CK(build(cases[i], 2, &file, &want, 1), "%s: no streams", names[i]);
			make_data(&last, 2, cases[i][1].len);
			scan(sc, file.p, file.n, &s);
			printf("  %-40s -> %u children, %zu bytes, broken %u\n", names[i], s.n_kids, s.kids.n, s.top_broken);
			/* what can be walked is opened (the last stream), and the rest is not clean: Damaged */
			CK(s.kids.n == last.n && (!last.n || memcmp(s.kids.p, last.p, last.n) == 0),
			   "%s: the stream that can be walked was not opened whole (%zu bytes)", names[i], s.kids.n);
			CK(s.top_broken == KOF_BROKEN_DAMAGED, "%s: said broken=%u, not Damaged", names[i], s.top_broken);
			free(s.kids.p);
			free(file.p);
			free(want.p);
			free(last.p);
		}
	}

	printf("== xz: more blocks than the table holds: the first ones kept, in order, and Limit said\n");
	{
		/* 300 one-block streams: the table holds KOF_XZ_MAX_BLOCKS (256); the engine must say so, and
		 * what it opened must be the FIRST streams in file order, not the last ones */
		struct seg *many = calloc(300, sizeof *many);
		struct buf file = { 0 }, want = { 0 };
		struct seen s;
		unsigned k;

		for (k = 0; many && k < 300; k++) {
			many[k].len = 200u + k;
			many[k].check = "crc32";
		}
		CK(many && build(many, 300, &file, &want, 1), "300 streams");
		scan(sc, file.p, file.n, &s);
		printf("  300 streams: %u children, %zu of %zu bytes, broken %u\n", s.n_kids, s.kids.n, want.n, s.top_broken);
		CK(s.top_broken == KOF_BROKEN_LIMIT, "300 streams: broken=%u, not Limit", s.top_broken);
		CK(s.n_kids == 256u, "300 streams: %u children, the table holds 256", s.n_kids);
		CK(s.kids.n <= want.n && s.kids.n && memcmp(s.kids.p, want.p, s.kids.n) == 0,
		   "300 streams: the children are not the first streams of the file, in order");
		free(s.kids.p);
		free(file.p);
		free(want.p);
		free(many);
	}

	kscan_free(sc);
	keng_close(eng);
	rmdir(dir);
	if (fails) {
		printf("xz_multistream: %d check(s) FAILED\n", fails);
		return 1;
	}
	printf("xz_multistream: every stream opened in order, bad ones said - ok\n");
	return 0;
}
