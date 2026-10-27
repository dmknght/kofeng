/*
 * kx_dump - writing an object out: kof_dump_dir_for, kof_dump_object, kof_dump_walk (kofexamine/kofinspect_dump.c) and the
 * paths and disks they meet.
 *
 * Suites, by function: dir_for (names and room), object (what the files hold, against an oracle that resolves the regions
 * itself), clip (an extent that is not a promise), walk (where the tree puts a child), hostile paths (a file where the
 * directory goes, a read-only directory, a planted link, a planted FIFO, paths past the room), disk full (RLIMIT_FSIZE:
 * the write fails the way ENOSPC does, without a wrap).
 *
 * Defects pinned as KM_CHECK (green until fixed, red the day they are):
 *   EX-5  kof_dump_walk keeps a ".." segment of the object's name, so a name "f//..//x" is written above the dump root
 *   EX-6 a FIFO planted at <dump dir>/00.KOF_SCAN_ALL makes the dump block forever (the open has no O_NONBLOCK)
 *   EX-7  the dump functions keep their working arrays in function-local statics (rule: no writable global state):
 *         two threads dumping at once share them. Listed, not testable without a race.
 * Files are made under build/ (beside the build output), never /tmp.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../kofexamine/kofinspect_private.h"
#include "../lib/genome/hk.h"
#include "known_miss.h"

static int fails, checks;

#undef CK
#define CK(cond) do { checks++; if (!(cond)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

static char base[256];

static int rm_cb(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	(void)st; (void)flag; (void)f;
	(void)chmod(p, 0700);
	return remove(p);
}

static void rm_rf(const char *dir)
{
	(void)nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static uint8_t *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *p = NULL;
	long sz;

	*n = 0;
	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	p = malloc(sz > 0 ? (size_t)sz : 1u);
	if (p && sz > 0 && fread(p, 1, (size_t)sz, f) != (size_t)sz) {
		free(p);
		p = NULL;
	}
	fclose(f);
	*n = p && sz > 0 ? (size_t)sz : 0;
	return p;
}

static int exists(const char *p)
{
	struct stat st;

	return lstat(p, &st) == 0;
}

/* ---------------------------------------------------------------------------------- kof_dump_dir_for */

static void dir_for_suite(void)
{
	char out[KOF_DUMP_PATH_ROOM + 64];
	static const struct { const char *in, *out; } r[] = {
		{ "/a/b/sample.exe", "/a/b/_sample.exe_dump" },
		{ "sample", "_sample_dump" },
		{ "/x/", "/x/__dump" },
		{ "", "__dump" },
		{ "/a/b/with space", "/a/b/_with-%08x_dump" },     /* the checksum is checked below, not spelled here */
	};
	char path[600], *name;
	unsigned i, k;

	CK(kof_dump_dir_for(r[0].in, out, sizeof out) && !strcmp(out, r[0].out));
	CK(kof_dump_dir_for(r[1].in, out, sizeof out) && !strcmp(out, r[1].out));
	CK(kof_dump_dir_for(r[2].in, out, sizeof out) && !strcmp(out, r[2].out));
	CK(kof_dump_dir_for(r[3].in, out, sizeof out) && !strcmp(out, r[3].out));
	/* a name with a byte outside [A-Za-z0-9._-]: the readable prefix, a dash, the checksum of the whole name */
	CK(kof_dump_dir_for("/a/b/with space", out, sizeof out));
	CK(!strncmp(out, "/a/b/_with-", 11) && strlen(out) == strlen("/a/b/_with-") + 8 + strlen("_dump") &&
	   !strcmp(out + strlen(out) - 5, "_dump"));
	{
		char o2[256];

		/* two different dirty names never share a directory (the checksum differs) */
		CK(kof_dump_dir_for("/a/b/with space", out, sizeof out) && kof_dump_dir_for("/a/b/with spacf", o2, sizeof o2));
		CK(strcmp(out, o2) != 0);
		CK(kof_dump_dir_for("/a/b/a b", out, sizeof out) && kof_dump_dir_for("/a/b/a\tb", o2, sizeof o2) && strcmp(out, o2) != 0);
	}
	/* the readable prefix kept when a name is made safe is 48 bytes: not the whole name, not fewer */
	{
		char nm[200];

		memset(nm, 'a', 60);
		memcpy(nm + 60, " tail", 6);
		snprintf(path, sizeof path, "/d/%s", nm);
		CK(kof_dump_dir_for(path, out, sizeof out));
		name = strrchr(out, '/');
		CK(name && !strncmp(name + 1, "_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-", 50) && name[50] == '-');
	}
	/* the room: exact fit, one short, zero */
	CK(kof_dump_dir_for("/a/b/sample.exe", out, 22));
	CK(!kof_dump_dir_for("/a/b/sample.exe", out, 21));
	CK(!kof_dump_dir_for("/a/b/sample.exe", out, 0));
	/* hostile names: every byte value, a name of every length around the 255 limit, no separator ever survives into the component */
	for (k = 1; k < 256; k++) {
		snprintf(path, sizeof path, "/d/n%cx", (char)k);
		if (k == '/')
			continue;
		CK(kof_dump_dir_for(path, out, sizeof out));
		name = strrchr(out, '/');
		CK(name && !strchr(name + 1, '/') && !strchr(name + 1, '\\') && strlen(name + 1) <= 255);
		for (i = 0; name && name[1 + i]; i++) {
			unsigned char c = (unsigned char)name[1 + i];

			CK((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_');
		}
	}
	for (k = 240; k < 300; k++) {
		char nm[400];

		memset(nm, 'a', k);
		nm[k] = 0;
		snprintf(path, sizeof path, "/d/%s", nm);
		CK(kof_dump_dir_for(path, out, sizeof out));
		name = strrchr(out, '/');
		CK(name && strlen(name + 1) <= 255);
		memset(nm, 'a', k);
		nm[k / 2] = '\xe9';
		nm[k] = 0;
		snprintf(path, sizeof path, "/d/%s", nm);
		CK(kof_dump_dir_for(path, out, sizeof out));
		name = strrchr(out, '/');
		CK(name && strlen(name + 1) <= 255 && strstr(name, "_dump"));
	}
	/* a very long directory part: refused by the room, never written past it */
	{
		char big[8192], tiny[16];

		memset(big, 'd', sizeof big);
		big[sizeof big - 20] = '/';
		memcpy(big + sizeof big - 19, "sample\0", 7);
		memset(tiny, 0x5a, sizeof tiny);
		CK(!kof_dump_dir_for(big, tiny, 16));
		CK(tiny[15] == 0x5a);
		CK(kof_dump_dir_for(big, out, sizeof out) == 0);
	}
}

/* ------------------------------------------------------------------------- kof_dump_object */

struct made {
	struct hk_elf e;
	struct kof_obj_ctx ctx;
	void *view;
	const struct kof_parser *p;
};

static int make_elf(struct made *m, int is64, int be, int rel)
{
	hk_elf(&m->e, is64, be, rel);
	m->p = kof_inspect_identify(kof_buf_make(m->e.b, m->e.n), &m->ctx, &m->view);
	return m->p != NULL;
}

static void names_in(const char *dir, char names[64][256], unsigned *n)
{
	DIR *d = opendir(dir);
	struct dirent *e;

	*n = 0;
	if (!d)
		return;
	while ((e = readdir(d)) && *n < 64)
		if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
			snprintf(names[(*n)++], 256, "%s", e->d_name);
	closedir(d);
}

static void object_suite(void)
{
	unsigned variant;

	for (variant = 0; variant < 4; variant++) {
		static struct made m;
		char dir[300], path[600], names[64][256], err[200];
		struct kof_dump_stat st;
		uint32_t k, e, n_files = 0, rank, want_regions = 0;
		uint64_t want_bytes = 0, whole;
		unsigned i, nn;
		struct kof_range ext[256];
		struct { uint64_t first; uint32_t idx; } ord[16];

		CK(make_elf(&m, (int)(variant & 1u), 0, (int)(variant >> 1)));
		if (!m.p)
			continue;
		snprintf(dir, sizeof dir, "%s/obj%u", base, variant);
		CK(kof_dump_object(dir, kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, err, sizeof err));
		CK(err[0] == 0);
		/* the oracle: resolve every region here, order by first extent, stable */
		for (k = 0; k < m.p->n_regions && n_files < 16; k++) {
			uint32_t n = m.ctx.resolve_scan(&m.ctx, m.p->regions[k], ext, 256);

			if (!n)
				continue;
			ord[n_files].first = ext[0].off;
			ord[n_files].idx = k;
			n_files++;
		}
		for (i = 1; i < n_files; i++) {
			uint64_t f = ord[i].first;
			uint32_t id = ord[i].idx;
			unsigned j;

			for (j = i; j > 0 && ord[j - 1].first > f; j--)
				ord[j] = ord[j - 1];
			ord[j].first = f;
			ord[j].idx = id;
		}
		CK(n_files >= 2);
		/* the whole object, byte for byte */
		snprintf(path, sizeof path, "%s/00.KOF_SCAN_ALL", dir);
		{
			size_t got;
			uint8_t *b = slurp(path, &got);

			CK(b && got == m.e.n && !memcmp(b, m.e.b, m.e.n));
			free(b);
		}
		CK(st.whole_bytes == m.e.n);
		/* every region file: exactly the clipped extents joined, under the number its rank gives */
		for (rank = 0; rank < n_files; rank++) {
			uint32_t bit = m.p->regions[ord[rank].idx];
			uint32_t n = m.ctx.resolve_scan(&m.ctx, bit, ext, 256);
			uint8_t want[HK_ELF_MAX * 4];
			size_t wn = 0, got;
			uint8_t *b;

			snprintf(path, sizeof path, "%s/%02u.%s", dir, rank + 1, m.p->region_name(bit));
			for (e = 0; e < n; e++) {
				uint64_t len = kof_clip_len(m.e.n, ext[e].off, ext[e].len);

				if (len && wn + len <= sizeof want) {
					memcpy(want + wn, m.e.b + ext[e].off, (size_t)len);
					wn += (size_t)len;
				}
			}
			b = slurp(path, &got);
			if (!(b || exists(path))) {
				printf("  FAIL region file %s missing\n", path);
				fails++;
			} else {
				CK(got == wn && (!wn || !memcmp(b, want, wn)));
			}
			free(b);
			if (wn) {
				want_regions++;
				want_bytes += wn;
			}
		}
		CK(st.regions == want_regions && st.region_bytes == want_bytes);
		whole = st.whole_bytes;
		CK(whole == m.e.n);
		/* nothing else is in the directory but LAYOUT */
		names_in(dir, names, &nn);
		CK(nn == 1 + n_files + 1);
		for (i = 0; i < nn; i++)
			CK(!strcmp(names[i], "LAYOUT") || !strcmp(names[i], "00.KOF_SCAN_ALL") ||
			   (strlen(names[i]) > 3 && names[i][2] == '.'));
		/* LAYOUT: a header, then rows sorted by offset, each inside the object */
		snprintf(path, sizeof path, "%s/LAYOUT", dir);
		{
			size_t got;
			uint8_t *b = slurp(path, &got);
			char *txt, *line, *save = NULL;
			unsigned long long prev = 0, off, len;
			unsigned rows = 0;
			char reg[64];

			CK(b != NULL);
			txt = b ? calloc(got + 1, 1) : NULL;
			if (txt) {
				memcpy(txt, b, got);
				line = strtok_r(txt, "\n", &save);
				CK(line && !strncmp(line, "offset", 6));
				while ((line = strtok_r(NULL, "\n", &save))) {
					CK(sscanf(line, "%llu %llu %63s", &off, &len, reg) == 3);
					CK(off >= prev && off <= m.e.n && len <= m.e.n - off);
					prev = off;
					rows++;
				}
				CK(rows >= n_files);
				free(txt);
			}
			free(b);
		}
		/* a second dump over the first overwrites, it does not fail */
		CK(kof_dump_object(dir, kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, err, sizeof err));
		kof_inspect_free(m.p, m.view);
	}
	/* no parser, no context: the whole object only; no bytes: no whole file */
	{
		char dir[300], path[600], err[100];
		struct kof_dump_stat st;
		static const uint8_t b[] = "hello";

		snprintf(dir, sizeof dir, "%s/plain", base);
		CK(kof_dump_object(dir, kof_buf_make(b, 5), NULL, NULL, &st, err, sizeof err) && st.whole_bytes == 5 && st.regions == 0);
		snprintf(dir, sizeof dir, "%s/empty", base);
		CK(kof_dump_object(dir, kof_buf_make(NULL, 0), NULL, NULL, NULL, NULL, 0));
		snprintf(path, sizeof path, "%s/00.KOF_SCAN_ALL", dir);
		CK(!exists(path));
	}
}

/* An extent is not a promise: a parser that bounded nothing must not make the dump read past the object. */

static uint32_t fake_resolve(const struct kof_obj_ctx *ctx, uint32_t mask, struct kof_range *out, uint32_t max)
{
	(void)ctx; (void)mask;
	if (max < 5)
		return 0;
	out[0].off = 10; out[0].len = 5;                 /* inside */
	out[1].off = 90; out[1].len = 1000;              /* runs past the end */
	out[2].off = ~0ull - 2; out[2].len = 10;         /* an offset that wraps when added */
	out[3].off = 500; out[3].len = 4;                /* wholly past */
	out[4].off = 0; out[4].len = 0;                  /* empty */
	return 5;
}

static const char *fake_name(uint32_t bit)
{
	(void)bit;
	return "FAKE_REGION";
}

static void clip_suite(void)
{
	static const uint32_t regs[] = { 1u };
	struct kof_parser p;
	struct kof_obj_ctx ctx;
	uint8_t obj[100];
	char dir[300], path[600], err[100];
	struct kof_dump_stat st;
	size_t got;
	uint8_t *b;
	unsigned i;

	for (i = 0; i < sizeof obj; i++)
		obj[i] = (uint8_t)(i + 1);
	memset(&p, 0, sizeof p);
	p.regions = regs;
	p.n_regions = 1;
	p.region_name = fake_name;
	memset(&ctx, 0, sizeof ctx);
	ctx.resolve_scan = fake_resolve;
	snprintf(dir, sizeof dir, "%s/clip", base);
	CK(kof_dump_object(dir, kof_buf_make(obj, sizeof obj), &p, &ctx, &st, err, sizeof err));
	snprintf(path, sizeof path, "%s/01.FAKE_REGION", dir);
	b = slurp(path, &got);
	CK(b && got == 5 + 10);                         /* [10,15) and [90,100) */
	CK(b && !memcmp(b, obj + 10, 5) && !memcmp(b + 5, obj + 90, 10));
	free(b);
	CK(st.region_bytes == 15 && st.regions == 1);
}

static uint32_t past_resolve(const struct kof_obj_ctx *ctx, uint32_t mask, struct kof_range *out, uint32_t max)
{
	(void)ctx; (void)mask;
	if (!max)
		return 0;
	out[0].off = 500;
	out[0].len = 10;
	return 1;
}

/* A region with extents that all fall outside the object: its file is made (empty) and it is NOT counted as a region written. */
static void empty_region_suite(void)
{
	static const uint32_t regs[] = { 1u };
	struct kof_parser p;
	struct kof_obj_ctx ctx;
	uint8_t obj[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	char dir[300], path[600], err[100];
	struct kof_dump_stat st;
	struct stat sb;

	memset(&p, 0, sizeof p);
	p.regions = regs;
	p.n_regions = 1;
	p.region_name = fake_name;
	memset(&ctx, 0, sizeof ctx);
	ctx.resolve_scan = past_resolve;
	snprintf(dir, sizeof dir, "%s/emptyregion", base);
	CK(kof_dump_object(dir, kof_buf_make(obj, sizeof obj), &p, &ctx, &st, err, sizeof err));
	CK(st.regions == 0 && st.region_bytes == 0 && st.whole_bytes == 8);
	snprintf(path, sizeof path, "%s/01.FAKE_REGION", dir);
	CK(stat(path, &sb) == 0 && sb.st_size == 0);
}

/* ---------------------------------------------------------------------------------- kof_dump_walk */

static void walk_suite(void)
{
	static const uint8_t b[] = "data";
	char root[300], dir[600], err[200], path[700];
	static const struct { const char *name; const char *rel; } rows[] = {
		{ "f", "" },
		{ "f//0", "0" },
		{ "f//0//1:norm", "0/1.norm" },
		{ "f//3:bin/x86", "3.bin_x86" },
		{ "f//a\\b", "a_b" },
		{ "f//x\x01y", "x_y" },
		{ "f//x\xe9y", "x_y" },
		{ "dir/file.zip//0//2:norm", "0/2.norm" },
	};
	unsigned i;
	struct kof_dump_stat st;

	snprintf(root, sizeof root, "%s/walk", base);
	for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
		char want[700];

		dir[0] = 0;
		CK(kof_dump_walk(root, rows[i].name, kof_buf_make(b, 4), NULL, NULL, &st, dir, sizeof dir, err, sizeof err));
		snprintf(want, sizeof want, rows[i].rel[0] ? "%s/%s" : "%s", root, rows[i].rel);
		if (strcmp(dir, want)) {
			printf("  FAIL walk(\"%s\") -> \"%s\" wanted \"%s\"\n", rows[i].name, dir, want);
			fails++;
		}
		if (rows[i].rel[0]) {
			snprintf(path, sizeof path, "%s/object", dir);
			CK(exists(path));
		}
	}
	/* a path that does not fit: refused by name, and the room it was given is respected */
	{
		char tiny[8];

		memset(tiny, 0x5a, sizeof tiny);
		CK(!kof_dump_walk(root, "f//0", kof_buf_make(b, 4), NULL, NULL, &st, tiny, sizeof tiny, err, sizeof err));
		CK(strstr(err, "too long") != NULL);
	}
	CK(!kof_dump_walk(NULL, "f", kof_buf_make(b, 4), NULL, NULL, &st, NULL, 0, err, sizeof err));
	CK(!kof_dump_walk(root, NULL, kof_buf_make(b, 4), NULL, NULL, &st, NULL, 0, err, sizeof err));
	/* a name with a thousand levels does not overflow the path room */
	{
		static char deep[8192];
		size_t n = 0;
		unsigned k;

		deep[n++] = 'f';
		for (k = 0; k < 1500 && n + 8 < sizeof deep; k++) {
			memcpy(deep + n, "//abc", 5);
			n += 5;
		}
		deep[n] = 0;
		CK(!kof_dump_walk(root, deep, kof_buf_make(b, 4), NULL, NULL, &st, dir, sizeof dir, err, sizeof err));
	}
	/* EX-5 (2026-10-27, M) [sev M]: the segment ".." is kept as it is (only ':', separators, controls and bytes above 0x7e are
	 * replaced), so the name an archive entry can carry puts the object ABOVE the dump root. Trigger: an object named
	 * "f//..//..//x". Effect: the examiner writes `object` and the regions outside the directory the user chose; the dump
	 * directory's own name was made safe (kof_dump_dir_for) and this path was not. Fix: map a segment of dots to '_'. */
	{
		char esc[300], rr[PATH_MAX], er[PATH_MAX], d2[400];
		int inside = 0;

		snprintf(esc, sizeof esc, "%s/escape", base);
		mkdir(esc, 0777);
		snprintf(d2, sizeof d2, "%s/deep", esc);
		mkdir(d2, 0777);
		dir[0] = 0;
		kof_dump_walk(d2, "f//..//..//hit", kof_buf_make(b, 4), NULL, NULL, &st, dir, sizeof dir, err, sizeof err);
		if (realpath(d2, rr) && realpath(dir[0] ? dir : d2, er))
			inside = !strncmp(er, rr, strlen(rr));
		KM_CHECK(inside, "kof_dump_walk writes the object above the dump root for a name with '..' segments", "EX-5");
	}
}

/* -------------------------------------------------------------------- hostile paths and disks */

/* Runs fn in a child with a time limit; returns 0 finished ok, 1 failed, 2 hung (killed by the alarm), 3 other signal. */
static int in_child(int (*fn)(void *), void *arg, unsigned secs)
{
	pid_t pid = fork();
	int st;

	if (pid < 0)
		return 3;
	if (pid == 0) {
		alarm(secs);
		signal(SIGXFSZ, SIG_IGN);
		_exit(fn(arg));
	}
	if (waitpid(pid, &st, 0) < 0)
		return 3;
	if (WIFSIGNALED(st))
		return WTERMSIG(st) == SIGALRM ? 2 : 3;
	return WEXITSTATUS(st) ? 1 : 0;
}

struct hostile {
	char          dir[300];
	struct made  *m;
	unsigned long fsize;
};

static int child_dump(void *a)
{
	struct hostile *h = a;
	char err[200];
	struct kof_dump_stat st;
	int r;

	if (h->fsize) {
		struct rlimit rl;

		rl.rlim_cur = rl.rlim_max = h->fsize;
		setrlimit(RLIMIT_FSIZE, &rl);
	}
	r = kof_dump_object(h->dir, kof_buf_make(h->m->e.b, h->m->e.n), h->m->p, &h->m->ctx, &st, err, sizeof err);
	/* the answer is "failed, with a sentence", never a crash and never a success that wrote nothing */
	if (h->fsize)
		return !r && err[0] ? 0 : 1;
	return r ? 0 : 1;
}

static void hostile_suite(void)
{
	static struct made m;
	struct hostile h;
	char path[600], err[200];
	struct kof_dump_stat st;
	int r;
	size_t got;
	uint8_t *b;

	CK(make_elf(&m, 1, 0, 0));
	if (!m.p)
		return;
	h.m = &m;
	h.fsize = 0;

	/* a FILE where the directory goes: the mkdir sees EEXIST, the write fails with a sentence */
	snprintf(h.dir, sizeof h.dir, "%s/afile", base);
	{
		FILE *f = fopen(h.dir, "wb");

		CK(f != NULL);
		if (f) {
			fputs("x", f);
			fclose(f);
		}
	}
	CK(!kof_dump_object(h.dir, kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, err, sizeof err));
	CK(strstr(err, "cannot") != NULL);
	/* the directory's parent does not exist */
	snprintf(path, sizeof path, "%s/no/such/parent/dir", base);
	CK(!kof_dump_object(path, kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, err, sizeof err) && strstr(err, "cannot create"));
	/* a directory with no write permission (skipped for root, which ignores the mode) */
	if (geteuid() != 0) {
		snprintf(h.dir, sizeof h.dir, "%s/ro", base);
		mkdir(h.dir, 0500);
		CK(!kof_dump_object(h.dir, kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, err, sizeof err) && strstr(err, "cannot write"));
	}
	/* a path longer than the room: refused by name, not written into */
	{
		char longp[KOF_DUMP_PATH_ROOM + 200];

		memset(longp, 'p', sizeof longp);
		memcpy(longp, base, strlen(base));
		longp[strlen(base)] = '/';
		longp[sizeof longp - 1] = 0;
		CK(!kof_dump_object(longp, kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, err, sizeof err));
		CK(err[0] != 0);
		CK(!kof_dump_walk(longp, "f//0", kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, NULL, 0, err, sizeof err));
	}
	/* a symlink planted at a file the dump writes (O_NOFOLLOW): refused, and the link's target is not written */
	snprintf(h.dir, sizeof h.dir, "%s/planted", base);
	mkdir(h.dir, 0777);
	{
		char target[2 * PATH_MAX];
		FILE *f;

		/* the link's target is ABSOLUTE: a relative one is read from the link's own directory and would not exist */
		{
			char cwd[PATH_MAX];

			CK(getcwd(cwd, sizeof cwd) != NULL);
			snprintf(target, sizeof target, "%s/%s/victim", cwd, base);
		}
		f = fopen(target, "wb");
		if (f) {
			fputs("original", f);
			fclose(f);
		}
		snprintf(path, sizeof path, "%s/00.KOF_SCAN_ALL", h.dir);
		CK(symlink(target, path) == 0);
		CK(!kof_dump_object(h.dir, kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, err, sizeof err));
		CK(strstr(err, "cannot write") != NULL);
		b = slurp(target, &got);
		CK(b && got == 8 && !memcmp(b, "original", 8));
		free(b);
	}
	/* a dangling symlink at the LAYOUT file: also refused, nothing created at its target */
	snprintf(h.dir, sizeof h.dir, "%s/planted2", base);
	mkdir(h.dir, 0777);
	{
		char target[2 * PATH_MAX];

		{
			char cwd[PATH_MAX];

			CK(getcwd(cwd, sizeof cwd) != NULL);
			snprintf(target, sizeof target, "%s/%s/created_by_link", cwd, base);
		}
		snprintf(path, sizeof path, "%s/LAYOUT", h.dir);
		CK(symlink(target, path) == 0);
		CK(!kof_dump_object(h.dir, kof_buf_make(m.e.b, m.e.n), m.p, &m.ctx, &st, err, sizeof err));
		CK(!exists(target));
	}
	/* EX-6: a FIFO at the name of the first file. The open blocks until a reader comes; the dump never returns. */
	snprintf(h.dir, sizeof h.dir, "%s/fifo", base);
	mkdir(h.dir, 0777);
	snprintf(path, sizeof path, "%s/00.KOF_SCAN_ALL", h.dir);
	CK(mkfifo(path, 0600) == 0);
	r = in_child(child_dump, &h, 3);
	/* EX-6 (2026-10-27, M) [sev M]: kof_fopen_trunc opens with O_CREAT|O_TRUNC|O_NOFOLLOW and no O_NONBLOCK, so a FIFO planted
	 * at a predictable name in the dump directory (named from the sample: kof_dump_dir_for) blocks the examiner for as long as
	 * nobody reads it. Trigger: a sample shipped with a directory `_<name>_dump` holding a FIFO `00.KOF_SCAN_ALL`.
	 * Effect: kofexaminer --dump and the viewer's dump hang. Fix: open O_NONBLOCK and refuse a non-regular file with fstat. */
	KM_CHECK(r != 2, "a FIFO planted at <dump dir>/00.KOF_SCAN_ALL makes the dump block forever", "EX-6");
	unlink(path);

	/* the disk is full: RLIMIT_FSIZE makes the write fail the way ENOSPC does. 0, a sentence, no crash, for every limit
	 * from nothing to most of the object */
	{
		unsigned long lim[] = { 1, 7, 64, 100, 300 };
		unsigned i;

		for (i = 0; i < sizeof lim / sizeof lim[0]; i++) {
			snprintf(h.dir, sizeof h.dir, "%s/full%u", base, i);
			h.fsize = lim[i];
			CK(in_child(child_dump, &h, 20) == 0);
		}
		h.fsize = 0;
	}
	/* the same dump with room: it works (the control for the rows above) */
	snprintf(h.dir, sizeof h.dir, "%s/control", base);
	CK(in_child(child_dump, &h, 20) == 0);
	kof_inspect_free(m.p, m.view);
}

int main(void)
{
	char tmpl[64];

	snprintf(tmpl, sizeof tmpl, "build/kof_kx_dump_XXXXXX");
	if (!mkdtemp(tmpl)) {
		printf("  FAIL no scratch directory under build/: %s\n", strerror(errno));
		return 1;
	}
	snprintf(base, sizeof base, "%s", tmpl);
	dir_for_suite();
	object_suite();
	clip_suite();
	empty_region_suite();
	walk_suite();
	hostile_suite();
	rm_rf(base);
	printf("kx_dump: %d checks, %s\n", checks, fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
