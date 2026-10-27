/*
 * ctr_resources - what the container walk does when the SYSTEM goes wrong under it (hostile matrix, columns 3-5), for every
 * container format the writers (tests/lib/ctr_writers.h) make.
 *
 *   SHORT READS   the file is read through the engine's read seam (kof_scan_read_hook) one, three and 512 bytes at a time: the
 *                 children are exactly the ones of the plain read
 *   READ ERRORS   the read fails (EIO) after 1 byte, a third, a half and all but one byte of the file: the root says it is
 *                 damaged (a broken reason) or is not reported at all, never opened as a good file, and every child is
 *                 either a child of the whole file or itself reported broken; no descriptor stays open
 *   DISK FULL     the spill file takes 0.3, 1.5 and 2.8 MB of a 3 MB member and then answers ENOSPC (zip member deflated, gzip
 *                 stream, 7z folder, through kof_scan_spill_hook): the object is DROPPED, not cut (no child of a wrong
 *                 length), the loss is said (a LIMIT object; spill_full counts it), no descriptor leaks, and the next
 *                 scan, the disk freed, is the plain one again (mem_spill.c does this for ONE zip; this is the format list)
 *   ALLOC FAILURE the k-th allocation of a whole scan refused, for k = 1 .. the number a scan makes (every k up to 150, then a
 *                 stride that keeps each format under 400 scans), the archive of each format: no crash; every child is
 *                 a child of the plain run unless the root or the child says it is cut (never other bytes silently); and a member missing
 *                 from the answer is SAID (a broken object, a limit hit, or an error code from the scan): the sweep counts the answers that lose a member and report nothing.
 *                 Not run under a sanitiser (it owns malloc: failalloc.h)
 *   FD LIMIT      RLIMIT_NOFILE lowered so that the file's own open, then a spill descriptor, cannot be made: no crash, an
 *                 error or a degraded answer, no descriptor leaked, and the plain answer again when the limit is back
 *
 * Every phase runs in a forked child with an alarm. Files are made under build/kof_ctr_res_XXXXXX and removed at the end;
 * they are made read-only (the scanner never writes one, and the habit is cheaper than the next mistake).
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"
#include "failalloc.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"
#include "../../libkofeng/scanners/objctx_int.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>

#define MB (1024ull * 1024ull)

static char scratch[PATH_MAX];

static int count_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int n = 0;

	if (!d)
		return -1;
	while ((e = readdir(d)))
		n++;
	closedir(d);
	return n;
}

/* What a scan answered, as a comparable thing: the children (name excluded: the walk's index names are positional) and the reports. */
struct sig {
	unsigned n, broken, limit;
	uint64_t h[64];             /* the hash of each child, in the order reported */
	uint64_t len[64];
	uint32_t br[64];
	int      root_broken;
};

static void sig_of(const struct cs_run *r, struct sig *s)
{
	unsigned i;

	memset(s, 0, sizeof *s);
	s->n = r->n > 1 ? r->n - 1u : 0u;
	s->broken = (unsigned)r->broken;
	s->limit = (unsigned)r->broken_limit;
	s->root_broken = r->n ? (int)r->o[0].broken : 0;
	for (i = 1; i < r->n && i <= 64u && i < CS_MAXOBJ; i++) {
		s->h[i - 1u] = r->o[i].hash;
		s->len[i - 1u] = r->o[i].len;
		s->br[i - 1u] = r->o[i].broken;
	}
}

static int in_base(const struct sig *base, uint64_t h, uint64_t len)
{
	unsigned i;

	for (i = 0; i < base->n && i < 64u; i++)
		if (base->h[i] == h && base->len[i] == len)
			return 1;
	return 0;
}

static int sig_same(const struct sig *a, const struct sig *b)
{
	return a->n == b->n && !memcmp(a->h, b->h, sizeof(uint64_t) * (a->n < 64u ? a->n : 64u)) &&
	       !memcmp(a->len, b->len, sizeof(uint64_t) * (a->n < 64u ? a->n : 64u)) && a->root_broken == b->root_broken;
}

/* ---- scanning a path, with seams --------------------------------------------------------------------- */

struct seams {
	const struct kof_src_read_io *rd;
	const struct kof_spill_io *sp;
	struct kof_scan_option opt;
};

struct pscan {
	struct cs_run r;
	uint64_t spill_full, spill_unavailable;
	int rc;
};

static int scan_path(const char *path, const struct seams *sm, struct pscan *p)
{
	kof_scanner *sc;
	struct kof_scan_option o = sm && sm->opt.max_resident_bytes ? sm->opt : cs_opt();

	memset(p, 0, sizeof *p);
	p->r.o = (struct cs_obj *)calloc(CS_MAXOBJ, sizeof *p->r.o);
	if (!p->r.o)
		return -1;
	if (!cs_eng)
		cs_eng = keng_open(HE_DB);
	sc = cs_eng ? kscan_new(cs_eng) : NULL;
	if (!sc)
		return -1;
	o.scratch_dir = scratch;
	if (sm && sm->rd)
		kof_scan_read_hook(sc, sm->rd);
	if (sm && sm->sp)
		kof_scan_spill_hook(sc, sm->sp);
	p->rc = kscan_path(sc, path, &o, cs_on, &p->r);
	p->r.limit_hits = kscan_stats(sc)->limit_hits;
	p->spill_full = kscan_stats(sc)->spill_full;
	p->spill_unavailable = kscan_stats(sc)->spill_unavailable;
	kscan_free(sc);
	return 0;
}

static int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return -1;
	if (fwrite(p, 1, n, f) != n) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return chmod(path, 0444);
}

static uint8_t mem[3][3000];
static const unsigned msz[3] = { 1000, 2000, 3000 };

static void make_many(unsigned f, struct cw *w, unsigned n_many)
{
	struct cw_ent *e = (struct cw_ent *)calloc(n_many, sizeof *e);
	static char nm[64][8];
	unsigned k, n = cw_formats[f].max_members == 1 ? 1u : n_many;

	if (!e) {
		w->oom = 1;
		return;
	}
	for (k = 0; k < n_many && k < 64u; k++) {
		snprintf(nm[k], sizeof nm[k], "f%u", k);
		e[k].name = nm[k];
		e[k].data = mem[k % 3u];
		e[k].len = 50u + k;
	}
	cw_formats[f].write(w, e, n, NULL, NULL);
	free(e);
}

static void make_archive(unsigned f, struct cw *w)
{
	struct cw_ent e[3];
	unsigned k, n = cw_formats[f].max_members == 1 ? 1u : 3u;
	static const char *const nm[3] = { "m0", "m1", "m2" };

	memset(e, 0, sizeof e);
	for (k = 0; k < 3; k++) {
		cs_fill(mem[k], sizeof mem[k], k);
		e[k].name = nm[k];
		e[k].data = mem[k];
		e[k].len = msz[k];
	}
	cw_formats[f].write(w, e, n, NULL, NULL);
}

/* ---- short reads and read errors ----------------------------------------------------------------------- */

struct rd {
	uint32_t short_max;
	uint64_t fail_after;
	uint64_t bytes;
};

static int64_t rd_read(void *u, int fd, void *buf, uint64_t n)
{
	struct rd *r = (struct rd *)u;
	ssize_t got;

	if (r->fail_after && r->bytes >= r->fail_after) {
		errno = EIO;
		return -1;
	}
	if (r->short_max && n > r->short_max)
		n = r->short_max;
	if (r->fail_after && r->bytes + n > r->fail_after)
		n = r->fail_after - r->bytes;
	got = read(fd, buf, (size_t)n);
	if (got > 0)
		r->bytes += (uint64_t)got;
	return (int64_t)got;
}

static int reads(void *p)
{
	unsigned f = (unsigned)(uintptr_t)p, k;
	const struct cw_format *F = &cw_formats[f];
	struct cw w = { 0 };
	char path[PATH_MAX + 32];
	struct pscan base, got;
	struct sig sb, sg;
	static const uint32_t shorts[] = { 1, 3, 512 };

	make_archive(f, &w);
	snprintf(path, sizeof path, "%s/r.%s", scratch, F->name);
	if (write_file(path, w.p, w.n))
		return 9;
	if (scan_path(path, NULL, &base))
		return 9;
	sig_of(&base.r, &sb);
	CK(sb.n >= 1 && sb.root_broken == 0, "%s: the plain read opens the archive (%u children)", F->name, sb.n);
	for (k = 0; k < 3; k++) {
		struct rd r = { shorts[k], 0, 0 };
		struct kof_src_read_io io = { rd_read, &r };
		struct seams sm;

		memset(&sm, 0, sizeof sm);
		sm.rd = &io;
		if (scan_path(path, &sm, &got))
			return 9;
		sig_of(&got.r, &sg);
		CK(sig_same(&sb, &sg), "%s: reads of at most %u bytes give the plain children (%u, wanted %u)", F->name, shorts[k], sg.n, sb.n);
		cs_free(&got.r);
	}
	{
		const uint64_t at[4] = { 1, w.n / 3, w.n / 2, w.n - 1u };
		int fds = count_fds();

		for (k = 0; k < 4; k++) {
			struct rd r = { 0, at[k], 0 };
			struct kof_src_read_io io = { rd_read, &r };
			struct seams sm;
			unsigned i;

			memset(&sm, 0, sizeof sm);
			sm.rd = &io;
			if (scan_path(path, &sm, &got))
				return 9;
			sig_of(&got.r, &sg);
			CK(got.r.n == 0 || sg.root_broken != 0, "%s: an EIO after %llu bytes is not opened as a good file (root broken %d)", F->name,
			   (unsigned long long)at[k], sg.root_broken);
			for (i = 0; i < sg.n && i < 64u; i++)
				CK(in_base(&sb, sg.h[i], sg.len[i]) || sg.br[i] != 0, "%s: after an EIO at %llu a child of %llu bytes is neither a child of the whole file nor reported", F->name,
				   (unsigned long long)at[k], (unsigned long long)sg.len[i]);
			cs_free(&got.r);
		}
		CK(count_fds() == fds, "%s: no descriptor left open by a failed read (%d -> %d)", F->name, fds, count_fds());
	}
	cs_free(&base.r);
	cw_free(&w);
	return he_fails != 0 ? 1 : 0;
}

/* ---- disk full ------------------------------------------------------------------------------------- */

struct sim {
	int64_t  fail_after;       /* bytes accepted before every write fails; < 0 never */
	uint64_t written, opens, writes;
};

static int s_open(void *u, const char *first)
{
	struct sim *s = (struct sim *)u;

	(void)first;
	s->opens++;
	return memfd_create("kofctr", 0);
}

static int s_write(void *u, int fd, const void *p, uint64_t n)
{
	struct sim *s = (struct sim *)u;

	s->writes++;
	if (s->fail_after >= 0 && s->written + n > (uint64_t)s->fail_after) {
		errno = ENOSPC;
		return 0;
	}
	s->written += n;
	return write(fd, p, (size_t)n) == (ssize_t)n;
}

static int s_space(void *u, int fd, uint64_t *avail, int *ram)
{
	(void)u;
	(void)fd;
	*avail = 1ull << 40;
	*ram = 0;
	return 1;
}

static uint8_t bigm[3u << 20];

static int spill_full(void *p)
{
	static const char *const fmts[] = { "zip", "gzip", "7z" };
	unsigned fi, k;

	(void)p;
	cs_fill(bigm, sizeof bigm, 4);
	for (fi = 0; fi < 3; fi++) {
		unsigned f = cw_find(fmts[fi]);
		struct cw w = { 0 }, df = { 0 };
		struct cw_ent e[2];
		struct pscan base, got;
		struct sig sb, sg;
		struct sim sm0 = { -1, 0, 0, 0 };
		struct kof_spill_io io = { s_open, s_write, s_space, &sm0 };
		struct seams sm;
		char path[PATH_MAX + 32];
		int fds;
		static const int64_t at[3] = { 300000, 1500000, 2800000 };

		memset(e, 0, sizeof e);
		e[0].name = "big.bin"; e[0].data = bigm; e[0].len = sizeof bigm;
		e[1].name = "after";   e[1].data = mem[0]; e[1].len = 500;
		if (!strcmp(fmts[fi], "zip")) {
			cw_deflate_stored(&df, bigm, sizeof bigm);
			e[0].data = df.p; e[0].len = df.n; e[0].method = 8; e[0].claimed = 1; e[0].claim_packed = df.n; e[0].claim_unpacked = sizeof bigm;
		}
		cw_formats[f].write(&w, e, cw_formats[f].max_members == 1 ? 1u : 2u, NULL, NULL);
		snprintf(path, sizeof path, "%s/s.%s", scratch, fmts[fi]);
		if (write_file(path, w.p, w.n))
			return 9;
		memset(&sm, 0, sizeof sm);
		sm.sp = &io;
		sm.opt = cs_opt();
		if (scan_path(path, &sm, &base))
			return 9;
		sig_of(&base.r, &sb);
		CK(sm0.writes > 0, "%s: the 3 MiB member spills (%llu writes): the rows below mean something", fmts[fi], (unsigned long long)sm0.writes);
		CK(sb.n >= 1 && sb.broken == 0, "%s: the plain scan with a working spill is clean (%u children, %u broken)", fmts[fi], sb.n, sb.broken);
		fds = count_fds();
		for (k = 0; k < 3; k++) {
			struct sim s1 = { at[k], 0, 0, 0 };
			unsigned i;

			io.user = &s1;
			if (scan_path(path, &sm, &got))
				return 9;
			sig_of(&got.r, &sg);
			for (i = 0; i < sg.n && i < 64u; i++)
				CK(in_base(&sb, sg.h[i], sg.len[i]) || sg.br[i] != 0, "%s: ENOSPC after %lld bytes left a child of %llu bytes that is neither whole nor reported", fmts[fi], (long long)at[k],
				   (unsigned long long)sg.len[i]);
			CK(got.r.broken_limit >= 1 && got.spill_full >= 1, "%s: ENOSPC after %lld bytes is said (LIMIT objects %llu, spill_full %llu)", fmts[fi], (long long)at[k],
			   (unsigned long long)got.r.broken_limit, (unsigned long long)got.spill_full);
			CK(count_fds() == fds, "%s: ENOSPC after %lld bytes leaked a descriptor (%d -> %d)", fmts[fi], (long long)at[k], fds, count_fds());
			cs_free(&got.r);
		}
		{
			struct sim s2 = { -1, 0, 0, 0 };

			io.user = &s2;
			if (scan_path(path, &sm, &got))
				return 9;
			sig_of(&got.r, &sg);
			CK(sig_same(&sb, &sg), "%s: with the disk freed the next scan is the plain one again (%u children, wanted %u)", fmts[fi], sg.n, sb.n);
			cs_free(&got.r);
		}
		cs_free(&base.r);
		cw_free(&w);
		cw_free(&df);
	}
	return he_fails != 0 ? 1 : 0;
}

/* ---- allocation failure ------------------------------------------------------------------------------ */

static int alloc_sweep_one(unsigned f, unsigned many);

static int alloc_sweep(void *p)
{
	unsigned f = (unsigned)(uintptr_t)p;

	if (alloc_sweep_one(f, 0))
		return 1;
	return alloc_sweep_one(f, 60) ? 1 : 0;
}

static int alloc_sweep_one(unsigned f, unsigned many)
{
	const struct cw_format *F = &cw_formats[f];
	struct cw w = { 0 };
	struct cs_run r;
	struct sig sb, sg;
	struct kof_scan_option o = cs_opt();
	long total, k, stride, swept = 0, silent = 0, wrong = 0;
	char root[24];

	if (!FA_AVAILABLE)
		return 0;
	fa_init();
	if (many)
		make_many(f, &w, many);
	else
		make_archive(f, &w);
	snprintf(root, sizeof root, "a.%s", F->name);
	if (cs_scan(w.p, w.n, root, &o, &r))                 /* the first scan builds the one-time state outside the sweep */
		return 9;
	cs_free(&r);
	fa_arm_nth(0);
	if (cs_scan(w.p, w.n, root, &o, &r))
		return 9;
	total = fa_count();
	(void)fa_disarm_hit();
	sig_of(&r, &sb);
	cs_free(&r);
	CK(total > 10 && sb.n >= 1, "%s: a scan makes %ld allocations and opens %u children", F->name, total, sb.n);
	stride = total > 400 ? (total - 150) / 250 + 1 : 1;
	for (k = 1; k <= total; k += k < 150 ? 1 : stride) {
		int rc;
		unsigned i;

		fa_arm_nth(k);
		rc = cs_scan(w.p, w.n, root, &o, &r);
		(void)fa_disarm_hit();
		if (rc) {                                         /* no scanner or no table for the answer: the allocation was refused and said so */
			continue;
		}
		swept++;
		sig_of(&r, &sg);
		for (i = 0; i < sg.n && i < 64u; i++)
			if (!in_base(&sb, sg.h[i], sg.len[i]) && sg.br[i] == 0 && r.broken == 0 && r.limit_hits == 0) {
				wrong++;
				printf("  WRONG %s k=%ld: child %u len %llu broken %u; root broken %u; objects %u; rc %d; limit_hits %llu\n", F->name, k, i, (unsigned long long)sg.len[i], sg.br[i], r.o[0].broken, r.n, r.rc, (unsigned long long)r.limit_hits);
				CK(0, "%s: allocation %ld refused: a child of %llu bytes is not a child of the plain run", F->name, k, (unsigned long long)sg.len[i]);
			}
		if (sg.n < sb.n && r.broken == 0 && r.limit_hits == 0 && r.rc >= 0) {
			silent++;
			printf("  SILENT %s: allocation %ld/%ld refused: %u of %u children, nothing reported (rc %d)\n", F->name, k, total, sg.n, sb.n, r.rc);
		}
		cs_free(&r);
	}
	printf("  %s (%u members): %ld allocations, %ld refused one at a time, %ld answers lost a child with nothing said, %ld wrong\n", F->name, many ? many : 3u, total, swept, silent, wrong);
	CK(silent == 0, "%s: %ld of %ld refused allocations lost a member with nothing said", F->name, silent, swept);
	cw_free(&w);
	return he_fails != 0 ? 1 : 0;
}

/* ---- fd limit ---------------------------------------------------------------------------------------- */

static int fd_limit(void *p)
{
	unsigned f = (unsigned)(uintptr_t)p, spare;
	const struct cw_format *F = &cw_formats[f];
	struct cw w = { 0 };
	char path[PATH_MAX + 32];
	struct pscan base, got;
	struct sig sb, sg;
	struct rlimit rl, saved;
	int fds;

	make_archive(f, &w);
	snprintf(path, sizeof path, "%s/f.%s", scratch, F->name);
	if (write_file(path, w.p, w.n))
		return 9;
	if (scan_path(path, NULL, &base))
		return 9;
	sig_of(&base.r, &sb);
	cs_free(&base.r);
	fds = count_fds();
	getrlimit(RLIMIT_NOFILE, &saved);
	for (spare = 0; spare < 4; spare++) {
		rl = saved;
		rl.rlim_cur = (rlim_t)fds + spare;                /* the fds in use already count: the file's open is the (spare+1)th */
		if (setrlimit(RLIMIT_NOFILE, &rl))
			return 9;
		(void)scan_path(path, NULL, &got);
		setrlimit(RLIMIT_NOFILE, &saved);
		if (got.r.o) {
			sig_of(&got.r, &sg);
			CK(sg.n == 0 || sg.root_broken != 0 || sig_same(&sb, &sg), "%s: with %u spare descriptors the answer is the plain one, or nothing, or reported (%u children, root %d)", F->name,
			   spare, sg.n, sg.root_broken);
			cs_free(&got.r);
		}
		CK(count_fds() == fds, "%s: %u spare descriptors: none leaked (%d -> %d)", F->name, spare, fds, count_fds());
	}
	if (scan_path(path, NULL, &got))
		return 9;
	sig_of(&got.r, &sg);
	CK(sig_same(&sb, &sg), "%s: with the limit back the plain answer returns (%u children)", F->name, sg.n);
	cs_free(&got.r);
	cw_free(&w);
	return he_fails != 0 ? 1 : 0;
}

/* ---- the PPMd arena (WP2-D12) ---------------------------------------------------------------------------- */

/*
 * A RAR3 member of 100 bytes whose packed stream is a PPMd block header and nothing else: MaxOrder with the PPM bit and the reset
 * bit set, then MaxMB = 63, so the model asks for a 64 MiB arena. The scan's resident ceiling is 24 MiB. A scan that charges
 * what it allocates would refuse the model (LIMIT) before it made it; the library's calloc (libuncoat ppmd.c
 * kuncoat_ppmd_start_asked) does not ask: one allocation of 64 MiB is made for a 1 KB file and peak_resident says 4 KB.
 * Found by the fuzz adapter container/walk (allocation cap reached), reproducer tests_wp2/findings/D12_rar3_ppmd_arena.bin.
 */
static int ppmd_arena(void *p)
{
	struct cw w = { 0 };
	struct cw_ent e;
	uint8_t packed[16];
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	int hit = 0;
	long count = 0;

	(void)p;
	if (!FA_AVAILABLE) {
		printf("  (a sanitiser owns malloc: the PPMd arena row is skipped)\n");
		return 0;
	}
	memset(packed, 0, sizeof packed);
	packed[0] = 0xa5;                      /* PPM block, reset, order 6 */
	packed[1] = 63;                        /* MaxMB: 64 MiB */
	memset(&e, 0, sizeof e);
	e.name = "p.bin"; e.data = packed; e.len = sizeof packed; e.method = 0x33;
	e.claimed = 1; e.claim_packed = sizeof packed; e.claim_unpacked = 100;
	cw_rar(&w, &e, 1, NULL, NULL);
	o.max_resident_bytes = 24 * MB;
	if (cs_scan(w.p, w.n, "p.rar", &o, &r))               /* the first scan builds the one-time state */
		return 9;
	cs_free(&r);
	fa_init();
	fa_arm_min((size_t)(32 * MB), 1);
	if (cs_scan(w.p, w.n, "p.rar", &o, &r))
		return 9;
	hit = fa_disarm_hit();
	count = fa_count();
	printf("  ppmd arena: a %zu byte rar, ceiling %llu MiB: %ld allocations of 32 MiB or more, peak_resident %llu\n", w.n, (unsigned long long)(o.max_resident_bytes / MB), count,
	       (unsigned long long)r.peak);
	/* KNOWN DEFECT WP2-D12 (2026-10-24, M): this row pins it, green until fixed. */
	KM_CHECK(!hit, "rar3/ppmd: a stream asks for a 64 MiB arena under a 24 MiB ceiling and the library allocates it without asking the ledger", "WP2-D12");
	cs_free(&r);
	cw_free(&w);
	return km_failed() ? 1 : 0;
}

/* ---- driver ---------------------------------------------------------------------------------------------- */

static int make_scratch(void)
{
	char tmpl[] = "build/kof_ctr_res_XXXXXX";
	char *r = mkdtemp(tmpl);

	if (!r || !realpath(r, scratch))
		return -1;
	return 0;
}

int main(void)
{
	unsigned f, bad = 0;
	struct he_status st;
	char cmd[PATH_MAX];
	static const struct { int (*fn)(void *); const char *what; unsigned secs; int per_format; } phases[] = {
		{ reads, "short reads + EIO", 120, 1 }, { alloc_sweep, "allocation failure", 300, 1 }, { fd_limit, "fd limit", 120, 1 }, { spill_full, "disk full (spill)", 240, 0 },
		{ ppmd_arena, "ppmd arena (D12)", 60, 0 }
	};
	unsigned ph;

	cs_eng = keng_open(HE_DB);
	if (!cs_eng || make_scratch()) {
		printf("ctr_resources: no engine or scratch\n");
		return 1;
	}
	for (ph = 0; ph < sizeof phases / sizeof phases[0]; ph++) {
		if (phases[ph].per_format) {
			for (f = 0; f < CW_NFORMATS; f++) {
				st = he_child(phases[ph].fn, (void *)(uintptr_t)f, phases[ph].secs);
				printf("%-20s %-5s %s\n", phases[ph].what, cw_formats[f].name, he_how(st));
				bad |= !he_ok(st);
			}
		} else {
			st = he_child(phases[ph].fn, NULL, phases[ph].secs);
			printf("%-20s %s\n", phases[ph].what, he_how(st));
			bad |= !he_ok(st);
		}
	}
	snprintf(cmd, sizeof cmd, "%s", scratch);
	he_rmtree(cmd);
	printf("ctr_resources: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
